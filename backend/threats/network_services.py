import base64
import hashlib
import ipaddress
import os
import re
import socket
import subprocess
import tempfile
import telnetlib
import time
from contextlib import closing
from xml.sax.saxutils import escape

import paramiko
import requests
from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from pysnmp.hlapi import CommunityData, ContextData, ObjectIdentity, ObjectType, SnmpEngine, UdpTransportTarget, getCmd


class PartialScanError(Exception):
    def __init__(self, message: str, result: dict | None = None):
        super().__init__(message)
        self.result = result or {}


def _run_command(args):
    try:
        return subprocess.check_output(args, text=True, encoding='utf-8', errors='ignore')
    except Exception:
        return ''


def _run_command_result(args):
    try:
        completed = subprocess.run(args, capture_output=True, text=True, encoding='utf-8', errors='ignore')
        output = '\n'.join(part for part in [completed.stdout.strip(), completed.stderr.strip()] if part).strip()
        return completed.returncode, output
    except Exception as exc:
        return 1, str(exc)


def _build_fernet():
    digest = hashlib.sha256(settings.SECRET_KEY.encode('utf-8')).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_secret(secret: str) -> str:
    if not secret:
        return ''
    return _build_fernet().encrypt(secret.encode('utf-8')).decode('utf-8')


def decrypt_secret(token: str) -> str:
    if not token:
        return ''
    try:
        return _build_fernet().decrypt(token.encode('utf-8')).decode('utf-8')
    except InvalidToken as exc:
        raise ValueError('Saqlangan credentialni ochib bo‘lmadi.') from exc


def list_network_interfaces() -> list:
    interfaces = _parse_ipconfig_all()
    wifi_map = _parse_wifi_interfaces()
    for item in interfaces:
        wifi = wifi_map.get(item['name'])
        if wifi:
            item['ssid'] = wifi.get('ssid', '')
            item['state'] = wifi.get('state', '')
        item['subnet_cidr'] = _mask_to_cidr(item.get('ip', ''), item.get('subnet_mask', ''))
    return interfaces


def _parse_ipconfig_all() -> list:
    output = _run_command(['ipconfig', '/all'])
    if not output:
        return []

    interfaces = []
    current = None

    for raw_line in output.splitlines():
        header_match = re.match(r'^(Ethernet|Wireless LAN|Unknown|Tunnel) adapter (.+):$', raw_line.strip())
        if header_match:
            if current:
                interfaces.append(current)
            adapter_type, name = header_match.groups()
            current = {
                'name': name.strip(),
                'adapter_type': adapter_type.strip(),
                'ip': '',
                'subnet_mask': '',
                'gateway': '',
                'gateways': [],
                'ssid': '',
                'state': '',
                'dns_suffix': '',
                'ipv6_addresses': [],
                'temporary_ipv6_addresses': [],
                'link_local_ipv6': '',
            }
            continue

        if not current:
            continue

        line = raw_line.strip()
        if not line:
            continue

        if 'Media State' in line and 'disconnected' in line.lower():
            current['state'] = 'disconnected'
        else:
            current['state'] = current.get('state') or 'connected'

        ip_match = re.search(r'IPv4 Address.*?:\s*([0-9.]+)', line)
        if ip_match:
            current['ip'] = ip_match.group(1)
            continue

        ipv6_match = re.search(r'^IPv6 Address.*?:\s*([0-9a-f:]+)', line, re.IGNORECASE)
        if ipv6_match:
            current['ipv6_addresses'].append(ipv6_match.group(1))
            continue

        temp_ipv6_match = re.search(r'^Temporary IPv6 Address.*?:\s*([0-9a-f:]+)', line, re.IGNORECASE)
        if temp_ipv6_match:
            current['temporary_ipv6_addresses'].append(temp_ipv6_match.group(1))
            continue

        link_local_match = re.search(r'^Link-local IPv6 Address.*?:\s*([0-9a-f:]+)', line, re.IGNORECASE)
        if link_local_match:
            current['link_local_ipv6'] = link_local_match.group(1)
            continue

        mask_match = re.search(r'Subnet Mask.*?:\s*([0-9.]+)', line)
        if mask_match:
            current['subnet_mask'] = mask_match.group(1)
            continue

        gateway_match = re.search(r'Default Gateway.*?:\s*(\d{1,3}(?:\.\d{1,3}){3})', line)
        if gateway_match:
            current['gateway'] = gateway_match.group(1)
            current['gateways'].append(gateway_match.group(1))
            continue

        if re.fullmatch(r'([0-9a-f:]+%\d+)|(\d{1,3}(?:\.\d{1,3}){3})', line, re.IGNORECASE):
            if not current.get('gateway') and re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', line):
                current['gateway'] = line
            current['gateways'].append(line)
            continue

        dns_match = re.search(r'DNS Servers.*?:\s*(.+)$', line)
        if dns_match:
            current['dns_servers'] = [dns_match.group(1).strip()]
            continue

        suffix_match = re.search(r'Connection-specific DNS Suffix.*?:\s*(.+)$', line)
        if suffix_match:
            current['dns_suffix'] = suffix_match.group(1).strip()

        if current.get('dns_servers') and re.fullmatch(r'([0-9a-f:]+%\d+)|(\d{1,3}(?:\.\d{1,3}){3})', line, re.IGNORECASE):
            current['dns_servers'].append(line)

    if current:
        interfaces.append(current)

    for item in interfaces:
        item['gateways'] = list(dict.fromkeys([value for value in item.get('gateways', []) if value]))
        item['dns_servers'] = list(dict.fromkeys([value for value in item.get('dns_servers', []) if value]))

    return [item for item in interfaces if item.get('ip') or item.get('ssid') or item.get('gateway')]


def _parse_wifi_interfaces() -> dict:
    code, output = _run_command_result(['netsh', 'wlan', 'show', 'interfaces'])
    if code != 0 or not output:
        return {}

    wifi_map = {}
    current = {}

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            if current.get('name'):
                wifi_map[current['name']] = current
            current = {}
            continue

        name_match = re.match(r'^Name\s*:\s*(.+)$', line)
        if name_match:
            current['name'] = name_match.group(1).strip()
            continue

        state_match = re.match(r'^State\s*:\s*(.+)$', line)
        if state_match:
            current['state'] = state_match.group(1).strip()
            continue

        ssid_match = re.match(r'^SSID\s*:\s*(.+)$', line)
        if ssid_match and 'BSSID' not in line:
            current['ssid'] = ssid_match.group(1).strip()

    if current.get('name'):
        wifi_map[current['name']] = current

    return wifi_map


def get_wifi_status() -> dict:
    interfaces = list_network_interfaces()
    wifi_interfaces = [item for item in interfaces if item['adapter_type'].lower() == 'wireless lan']
    service_running = _is_wlan_service_running()
    available_networks = _parse_wifi_networks() if service_running and wifi_interfaces else []

    if not wifi_interfaces:
        message = "Wi-Fi adapter yo'q."
    elif not service_running:
        message = "Wi-Fi adapter bor, lekin Wireless AutoConfig xizmati o'chirilgan."
    elif available_networks:
        message = 'Wi-Fi tarmoqlar topildi.'
    else:
        message = 'Wi-Fi tarmoqlar topilmadi yoki interfeys ulanmagan.'

    connected_interface = next((item for item in wifi_interfaces if item.get('ssid')), None)

    return {
        'wifi_adapter_available': bool(wifi_interfaces),
        'service_running': service_running,
        'message': message,
        'connected_ssid': connected_interface.get('ssid', '') if connected_interface else '',
        'connected_interface': connected_interface.get('name', '') if connected_interface else '',
        'connected_state': connected_interface.get('state', '') if connected_interface else '',
        'available_networks': available_networks,
    }


def _is_wlan_service_running() -> bool:
    code, output = _run_command_result(['cmd', '/c', 'sc', 'query', 'wlansvc'])
    return code == 0 and 'RUNNING' in output.upper()


def _parse_wifi_networks() -> list:
    code, output = _run_command_result(['netsh', 'wlan', 'show', 'networks', 'mode=bssid'])
    if code != 0 or not output:
        return []

    networks = []
    current = None
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        ssid_match = re.match(r'^SSID\s+\d+\s*:\s*(.*)$', line)
        if ssid_match:
            if current and current.get('ssid'):
                networks.append(current)
            current = {
                'ssid': ssid_match.group(1).strip(),
                'authentication': '',
                'encryption': '',
                'signal': '',
                'network_type': '',
                'bssid_count': 0,
            }
            continue

        if not current:
            continue

        bssid_match = re.match(r'^BSSID\s+\d+\s*:\s*(.+)$', line)
        if bssid_match:
            current['bssid_count'] += 1
            continue

        auth_match = re.match(r'^Authentication\s*:\s*(.+)$', line)
        if auth_match:
            current['authentication'] = auth_match.group(1).strip()
            continue

        enc_match = re.match(r'^Encryption\s*:\s*(.+)$', line)
        if enc_match:
            current['encryption'] = enc_match.group(1).strip()
            continue

        signal_match = re.match(r'^Signal\s*:\s*(.+)$', line)
        if signal_match:
            current['signal'] = signal_match.group(1).strip()
            continue

        type_match = re.match(r'^Network type\s*:\s*(.+)$', line)
        if type_match:
            current['network_type'] = type_match.group(1).strip()

    if current and current.get('ssid'):
        networks.append(current)

    return networks


def connect_to_wifi(ssid: str, password: str, interface_name: str = '', authentication: str = '', encryption: str = '') -> dict:
    status = get_wifi_status()
    if not status['wifi_adapter_available']:
        raise ValueError("Wi-Fi adapter yo'q.")
    if not status['service_running']:
        raise ValueError("Wireless AutoConfig xizmati ishlamayapti.")
    if not ssid:
        raise ValueError('SSID majburiy.')

    auth_value, encryption_value, key_type = _normalize_wifi_security(authentication, encryption, password)
    profile_xml = _build_wifi_profile_xml(ssid, password, auth_value, encryption_value, key_type)

    temp_path = ''
    try:
        with tempfile.NamedTemporaryFile('w', delete=False, suffix='.xml', encoding='utf-8') as handle:
            handle.write(profile_xml)
            temp_path = handle.name

        code, output = _run_command_result(['netsh', 'wlan', 'add', 'profile', f'filename={temp_path}', 'user=current'])
        if code != 0:
            raise ValueError(output or 'Wi-Fi profilini qo‘shib bo‘lmadi.')

        connect_cmd = ['netsh', 'wlan', 'connect', f'name={ssid}']
        if interface_name:
            connect_cmd.append(f'interface={interface_name}')
        code, output = _run_command_result(connect_cmd)
        if code != 0:
            raise ValueError(output or 'Wi-Fi ga ulanib bo‘lmadi.')

        time.sleep(4)
        refreshed = get_wifi_status()
        refreshed['connect_message'] = output
        refreshed['requested_ssid'] = ssid
        return refreshed
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass


def _normalize_wifi_security(authentication: str, encryption: str, password: str) -> tuple[str, str, str]:
    auth = (authentication or '').strip().lower()
    enc = (encryption or '').strip().lower()

    if not password:
        return 'open', 'none', ''

    if 'wpa3' in auth:
        return 'WPA2PSK', 'AES', 'passPhrase'
    if 'wpa2' in auth:
        return 'WPA2PSK', 'AES' if enc in ('ccmp', 'aes', '') else 'TKIP', 'passPhrase'
    if 'wpa' in auth:
        return 'WPAPSK', 'TKIP' if enc in ('tkip', '') else 'AES', 'passPhrase'
    return 'WPA2PSK', 'AES', 'passPhrase'


def _build_wifi_profile_xml(ssid: str, password: str, authentication: str, encryption: str, key_type: str) -> str:
    escaped_ssid = escape(ssid)
    if authentication == 'open':
        return f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{escaped_ssid}</name>
    <SSIDConfig>
        <SSID>
            <name>{escaped_ssid}</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>manual</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>open</authentication>
                <encryption>none</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
        </security>
    </MSM>
</WLANProfile>"""

    escaped_password = escape(password)
    return f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{escaped_ssid}</name>
    <SSIDConfig>
        <SSID>
            <name>{escaped_ssid}</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>manual</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>{authentication}</authentication>
                <encryption>{encryption}</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>{key_type}</keyType>
                <protected>false</protected>
                <keyMaterial>{escaped_password}</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
</WLANProfile>"""


def _mask_to_cidr(ip: str, mask: str) -> str:
    if not ip or not mask:
        return ''
    try:
        network = ipaddress.IPv4Network(f'{ip}/{mask}', strict=False)
        return str(network)
    except Exception:
        return ''


def run_profile_scan(profile, interface_name: str = '', network_name: str = '') -> dict:
    if profile.profile_type == 'ssh':
        result = _run_ssh_scan(profile)
    elif profile.profile_type == 'telnet':
        result = _run_telnet_scan(profile)
    elif profile.profile_type == 'snmp':
        result = _run_snmp_scan(profile)
    elif profile.profile_type == 'web':
        result = _run_web_scan(profile)
    else:
        raise ValueError('Qo‘llab-quvvatlanmagan profile type.')

    result['network_name'] = network_name or profile.network_label or ''
    result['interface_name'] = interface_name or ''
    return result


def _run_ssh_scan(profile) -> dict:
    password = decrypt_secret(profile.secret_encrypted)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=profile.target_host,
            port=profile.port or 22,
            username=profile.username,
            password=password,
            timeout=8,
            banner_timeout=8,
            auth_timeout=8,
            look_for_keys=False,
            allow_agent=False,
        )

        hostname = _ssh_exec_first(client, ['hostname', 'echo $env:COMPUTERNAME', 'uname -n'])
        identity = _ssh_exec_first(client, ['whoami', 'echo %USERNAME%'])
        os_info = _ssh_exec_first(client, ['uname -a', 'ver', 'systeminfo | findstr /B /C:"OS Name" /C:"OS Version"'])
        ip_info = _ssh_exec_first(client, ['ip addr', 'ifconfig', 'ipconfig'])
        services = _ssh_exec_first(client, ['ss -tulpn', 'netstat -tulpn', 'netstat -ano'])

        return {
            'protocol': 'ssh',
            'target': profile.target_host,
            'hostname': hostname.strip(),
            'identity': identity.strip(),
            'os_info': os_info.strip(),
            'ip_info': ip_info.strip()[:4000],
            'services': services.strip()[:4000],
            'open_ports_detected': _extract_ports(services),
            'reachable': True,
        }
    finally:
        client.close()


def _ssh_exec_first(client, commands: list[str]) -> str:
    for command in commands:
        try:
            _, stdout, stderr = client.exec_command(command, timeout=8)
            output = (stdout.read() or b'').decode('utf-8', errors='ignore').strip()
            error = (stderr.read() or b'').decode('utf-8', errors='ignore').strip()
            if output:
                return output
            if error and 'not found' not in error.lower():
                return error
        except Exception:
            continue
    return ''


def _run_snmp_scan(profile) -> dict:
    community = decrypt_secret(profile.secret_encrypted)
    if profile.snmp_version != '2c':
        raise ValueError('Hozircha faqat SNMP v2c qo‘llab-quvvatlanadi.')

    oid_map = {
        'sys_name': '1.3.6.1.2.1.1.5.0',
        'sys_descr': '1.3.6.1.2.1.1.1.0',
        'sys_uptime': '1.3.6.1.2.1.1.3.0',
        'sys_contact': '1.3.6.1.2.1.1.4.0',
        'sys_location': '1.3.6.1.2.1.1.6.0',
    }
    result = {}

    for key, oid in oid_map.items():
        iterator = getCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=1),
            UdpTransportTarget((profile.target_host, profile.port or 161), timeout=2, retries=1),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
        )
        error_indication, error_status, _, var_binds = next(iterator)
        if error_indication:
            raise ValueError(str(error_indication))
        if error_status:
            raise ValueError(str(error_status))
        result[key] = str(var_binds[0][1])

    return {
        'protocol': 'snmp',
        'target': profile.target_host,
        'hostname': result.get('sys_name', ''),
        'device_description': result.get('sys_descr', ''),
        'uptime': result.get('sys_uptime', ''),
        'contact': result.get('sys_contact', ''),
        'location': result.get('sys_location', ''),
        'reachable': True,
    }


def _run_telnet_scan(profile) -> dict:
    password = decrypt_secret(profile.secret_encrypted)
    partial = {
        'protocol': 'telnet',
        'target': profile.target_host,
        'reachable': True,
        'summary': 'Telnet sessiya qisman o‘qildi',
    }

    try:
        with telnetlib.Telnet(profile.target_host, profile.port or 23, timeout=8) as client:
            login_text, prompt = _telnet_login(client, profile.username, password)
            partial['login_transcript'] = login_text
            partial['prompt'] = prompt
            command_results = _telnet_collect_info(client, prompt)
            device_text = '\n\n'.join(part for part in [login_text, command_results] if part).strip()

            return {
                **partial,
                'hostname': _infer_telnet_hostname(device_text, profile.target_host),
                'device_description': _clip_text(device_text or 'Telnet session ochildi.', 4000),
                'prompt': prompt,
                'reachable': True,
            }
    except PartialScanError as exc:
        partial.update(exc.result)
        raise PartialScanError(str(exc), _build_telnet_partial_result(profile, partial, str(exc))) from exc
    except Exception as exc:
        raise PartialScanError(str(exc), _build_telnet_partial_result(profile, partial, str(exc))) from exc


def _telnet_login(client, username: str, password: str) -> tuple[str, str]:
    patterns = [
        re.compile(br'(?i)(login|username|user name)\s*[:>]\s*$'),
        re.compile(br'(?i)password\s*[:>]\s*$'),
        re.compile(br'(?m)[^\r\n]*[>#\$\]]\s*$'),
    ]
    transcript = []
    prompt = ''
    username_sent = False
    password_sent = False

    client.write(b'\n')
    time.sleep(0.6)
    initial = _decode_telnet(client.read_very_eager())
    if initial:
        transcript.append(initial)
    if not initial and username:
        client.write(f'{username}\n'.encode('utf-8'))
        username_sent = True

    for _ in range(6):
        idx, _, data = client.expect(patterns, timeout=3)
        chunk = _decode_telnet(data)
        if chunk:
            transcript.append(chunk)

        combined = ''.join(transcript).lower()
        if any(token in combined for token in ('incorrect', 'invalid', 'failed', 'denied')):
            raise PartialScanError('Telnet login muvaffaqiyatsiz.', {
                'login_transcript': _clip_text(''.join(transcript).strip(), 2000),
            })

        if idx == 0 and not password_sent:
            client.write(f'{username or ""}\n'.encode('utf-8'))
            username_sent = True
            continue

        if idx == 1 and not password_sent:
            client.write(f'{password or ""}\n'.encode('utf-8'))
            password_sent = True
            continue

        prompt = _extract_telnet_prompt(chunk or ''.join(transcript))
        if prompt and (password_sent or not password):
            break

        client.write(b'\n')

    if not prompt:
        extra = _decode_telnet(client.read_very_eager())
        if extra:
            transcript.append(extra)
            prompt = _extract_telnet_prompt(extra)

    if not prompt:
        raise PartialScanError('Telnet prompt aniqlanmadi.', {
            'login_transcript': _clip_text(''.join(transcript).strip(), 2000),
        })

    return _clip_text(''.join(transcript).strip(), 2000), prompt


def _telnet_collect_info(client, prompt: str) -> str:
    outputs = []
    for command in ['\n', 'help', '?', 'show status', 'show version', 'show system', 'exit']:
        result = _telnet_run_command(client, command, prompt)
        cleaned = _clean_telnet_command_output(result, command, prompt)
        if cleaned and cleaned.lower() not in ('unknown command', 'invalid command'):
            outputs.append(f'$ {command}\n{cleaned}')
            if len('\n\n'.join(outputs)) >= 3500:
                break
    return _clip_text('\n\n'.join(outputs).strip(), 4000)


def _telnet_run_command(client, command: str, prompt: str) -> str:
    client.write(f'{command}\n'.encode('utf-8'))
    patterns = []
    if prompt:
        escaped = re.escape(prompt.encode('utf-8'))
        patterns.append(re.compile(escaped + br'\s*$'))
    patterns.extend([
        re.compile(br'(?i)(login|username|user name)\s*[:>]\s*$'),
        re.compile(br'(?i)password\s*[:>]\s*$'),
    ])
    idx, _, data = client.expect(patterns, timeout=2)
    if idx != -1:
        return _decode_telnet(data)

    time.sleep(0.6)
    return _decode_telnet(client.read_very_eager())


def _clean_telnet_command_output(text: str, command: str, prompt: str) -> str:
    lines = [line.rstrip() for line in (text or '').replace('\r', '').split('\n')]
    cleaned = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped == command:
            continue
        if prompt and stripped == prompt.strip():
            continue
        cleaned.append(line)
    return '\n'.join(cleaned).strip()


def _extract_telnet_prompt(text: str) -> str:
    for line in reversed((text or '').replace('\r', '').split('\n')):
        stripped = line.strip()
        if stripped and stripped[-1] in ('>', '#', '$', ']'):
            return stripped
    return ''


def _infer_telnet_hostname(text: str, fallback: str) -> str:
    for line in (text or '').splitlines():
        lowered = line.lower()
        if 'device name' in lowered and ':' in line:
            return line.split(':', 1)[1].strip()
        if 'hostname' in lowered and ':' in line:
            return line.split(':', 1)[1].strip()
    return fallback


def _decode_telnet(data: bytes | None) -> str:
    if not data:
        return ''
    return data.decode('utf-8', errors='ignore')


def _clip_text(text: str, limit: int) -> str:
    return (text or '')[:limit]


def _build_telnet_partial_result(profile, partial: dict, error_message: str) -> dict:
    login_text = partial.get('login_transcript', '')
    prompt = partial.get('prompt', '')
    body = partial.get('device_description') or login_text or f'Telnet xato: {error_message}'
    return {
        'protocol': 'telnet',
        'target': profile.target_host,
        'hostname': partial.get('hostname') or _infer_telnet_hostname(body, profile.target_host),
        'device_description': _clip_text(body, 4000),
        'login_transcript': _clip_text(login_text, 2000),
        'prompt': prompt,
        'reachable': True,
        'summary': partial.get('summary') or 'Telnet orqali qisman ma’lumot olindi',
    }


def _run_web_scan(profile) -> dict:
    username = profile.username or ''
    password = decrypt_secret(profile.secret_encrypted)
    auth = (username, password) if username or password else None
    port = profile.port or 80
    schemes = ['https', 'http'] if port in (443, 8443) else ['http', 'https']
    errors = []

    with requests.Session() as session:
        session.headers.update({'User-Agent': 'CyberGuard-WebProbe/1.0'})
        for scheme in schemes:
            url = _build_profile_url(profile.target_host, port, scheme)
            try:
                probe = _probe_web_endpoint(session, url, auth=auth)
                lines = [
                    f'Endpoint: {probe["final_url"]}',
                    f'Status: {probe["status_code"]}',
                    f'Title: {probe.get("title") or "-"}',
                    f'Server: {probe.get("server") or "-"}',
                    f'Content-Type: {probe.get("content_type") or "-"}',
                    f'Auth required: {"yes" if probe.get("auth_required") else "no"}',
                    f'Latency avg: {probe.get("avg_latency_ms", 0)} ms',
                ]
                if probe.get('header_snapshot'):
                    lines.append('Headers:')
                    lines.extend(f'  {line}' for line in probe['header_snapshot'])

                return {
                    'protocol': 'web',
                    'target': profile.target_host,
                    'hostname': profile.target_host,
                    'endpoint': probe['final_url'],
                    'scheme': scheme,
                    'status_code': probe['status_code'],
                    'title': probe.get('title', ''),
                    'server': probe.get('server', ''),
                    'content_type': probe.get('content_type', ''),
                    'auth_required': probe.get('auth_required', False),
                    'latency_samples_ms': probe.get('latency_samples_ms', []),
                    'avg_latency_ms': probe.get('avg_latency_ms', 0),
                    'device_description': '\n'.join(lines),
                    'reachable': True,
                }
            except Exception as exc:
                errors.append(f'{scheme.upper()}: {exc}')

    raise ValueError(' | '.join(errors) or 'Web probe muvaffaqiyatsiz tugadi.')


def _build_profile_url(host: str, port: int, scheme: str) -> str:
    default_port = 443 if scheme == 'https' else 80
    suffix = '' if port == default_port else f':{port}'
    return f'{scheme}://{host}{suffix}/'


def _probe_web_endpoint(session, url: str, auth=None) -> dict:
    latencies = []
    response = None

    for _ in range(3):
        started = time.perf_counter()
        current = session.get(url, timeout=4, allow_redirects=True, verify=False, auth=auth)
        latencies.append(round((time.perf_counter() - started) * 1000, 1))
        response = current

    if response is None:
        raise ValueError('Javob olinmadi.')

    title_match = re.search(r'<title[^>]*>(.*?)</title>', response.text or '', re.IGNORECASE | re.DOTALL)
    title = re.sub(r'\s+', ' ', title_match.group(1)).strip() if title_match else ''
    headers = response.headers
    header_snapshot = []
    for key in ('Server', 'Content-Type', 'WWW-Authenticate', 'Location'):
        value = headers.get(key)
        if value:
            header_snapshot.append(f'{key}: {value}')

    return {
        'final_url': response.url,
        'status_code': response.status_code,
        'title': title,
        'server': headers.get('Server', ''),
        'content_type': headers.get('Content-Type', ''),
        'auth_required': response.status_code in (401, 403) or bool(headers.get('WWW-Authenticate')),
        'latency_samples_ms': latencies,
        'avg_latency_ms': round(sum(latencies) / len(latencies), 1) if latencies else 0,
        'header_snapshot': header_snapshot,
    }


def _extract_ports(text: str) -> list[int]:
    ports = set()
    for match in re.findall(r':(\d{1,5})', text or ''):
        port = int(match)
        if 0 < port <= 65535:
            ports.add(port)
    return sorted(ports)[:50]


def quick_tcp_probe(host: str, port: int, timeout: float = 1.5) -> bool:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((host, port)) == 0
