import ipaddress
import math
import re
import socket
import ssl
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from random import Random
from urllib.parse import urlparse

import numpy as np
import requests
from django.conf import settings
from django.db.models import Count
from django.utils import timezone
from sklearn.ensemble import GradientBoostingClassifier, IsolationForest, RandomForestClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC


RISK_LEVEL_MAP = {'unknown': 0.2, 'low': 0.35, 'medium': 0.58, 'high': 0.82, 'critical': 1.0}
COMMON_PORTS = [21, 22, 23, 53, 80, 110, 135, 139, 1433, 3306, 3389, 443, 445, 5432, 5900, 6379, 8080, 8443]
REMOTE_ADMIN_PORTS = {22, 3389, 5900}
DATABASE_PORTS = {1433, 3306, 5432, 6379}
WEB_PORTS = {80, 443, 8080, 8443}
RISKY_PORTS = {21, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379}
SCAN_TTL_SECONDS = 90
THREAT_ORDER = ['ddos', 'sqli', 'brute_force', 'phishing', 'ransomware', 'mitm', 'zero_day', 'apt', 'port_scan']

KEYWORD_GROUPS = {
    'ddos': ['ddos', 'flood', 'traffic', 'bandwidth', 'packet', 'udp', 'syn'],
    'sqli': ['sql', 'union', 'select', 'injection', 'database', 'query', 'payload'],
    'brute_force': ['brute', 'login', 'password', 'ssh', 'rdp', 'auth', 'attempt'],
    'phishing': ['phishing', 'email', 'credential', 'domain', 'url', 'redirect', 'spoof'],
    'ransomware': ['ransom', 'encrypt', 'locker', 'payload', 'malware', 'backup'],
    'mitm': ['arp', 'spoof', 'certificate', 'proxy', 'mitm', 'ssl'],
    'zero_day': ['zero-day', 'zeroday', 'unknown', 'exploit', 'cve', 'anomaly'],
    'apt': ['apt', 'lateral', 'persistence', 'stealth', 'beacon', 'exfiltration'],
    'port_scan': ['scan', 'nmap', 'syn', 'probe', 'enumeration', 'port'],
}

FEATURE_NAMES = [
    'is_local',
    'is_loopback',
    'known_risk',
    'open_port_count',
    'risky_port_count',
    'web_port_count',
    'db_port_count',
    'remote_admin',
    'abuse_score',
    'reports',
    'context_intensity',
    'ddos_kw',
    'sqli_kw',
    'brute_force_kw',
    'phishing_kw',
    'ransomware_kw',
    'mitm_kw',
    'zero_day_kw',
    'apt_kw',
    'port_scan_kw',
]

THREAT_SIGNATURES = {
    'ddos': {
        'name': 'DDoS hujumi',
        'indicators': ['Yuqori paket hajmi', "Bir manbadan ko'p so'rov", 'UDP/SYN flood signallari'],
        'severity': 'critical',
        'mitigation': ['Rate limiting yoqing', 'WAF/CDN orqali filtrlash', 'Shubhali manbalarni vaqtincha bloklang'],
    },
    'sqli': {
        'name': 'SQL Injection',
        'indicators': ["SQL kalit so'zlari", 'Web va DB portlari faolligi', "So'rov tarkibida injection pattern"],
        'severity': 'critical',
        'mitigation': ["Parametrlangan so'rovlar ishlating", 'WAF qoidasini kuchaytiring', 'DB loglarini tekshiring'],
    },
    'brute_force': {
        'name': 'Brute Force',
        'indicators': ['SSH/RDP portlari ochiq', 'Login/auth konteksti', 'Takroriy urinish patterni'],
        'severity': 'high',
        'mitigation': ['2FA yoqing', "Fail2ban yoki rate limit qo'llang", 'Remote access ACL ni toraytiring'],
    },
    'phishing': {
        'name': 'Phishing',
        'indicators': ["Domen/URL kalit so'zlari", 'Credential va redirect patternlari', 'Tashqi IP riski'],
        'severity': 'high',
        'mitigation': ['Shubhali domenlarni bloklang', 'Mail gateway filtrlashni kuchaytiring', 'User awareness yuboring'],
    },
    'ransomware': {
        'name': 'Ransomware',
        'indicators': ["Malware/encrypt kalit so'zlari", 'Ichki hostdagi xavfli portlar', 'Endpoint izolatsiyasi ehtiyoji'],
        'severity': 'critical',
        'mitigation': ['Hostni darhol izolyatsiya qiling', 'Backup tiklash rejimini tayyorlang', 'EDR forensics boshlang'],
    },
    'mitm': {
        'name': 'Man-in-the-Middle',
        'indicators': ["ARP/certificate kalit so'zlari", 'Ichki tarmoq xostlari', 'Proxy/spoofing signallari'],
        'severity': 'high',
        'mitigation': ['ARP monitoring yoqing', 'TLS inspeksiyasini tekshiring', 'Switch port security ni yoqing'],
    },
    'zero_day': {
        'name': 'Zero-Day',
        'indicators': ["Noma'lum exploit/anomaly kalit so'zlari", "Benign profilidan katta og'ish", "Noaniq lekin xavfli xatti-harakat"],
        'severity': 'critical',
        'mitigation': ['Qurilmani segmentatsiya qiling', "EDR/IDS qo'shimcha log yigsin", 'Patch va IOC tekshiruvini boshlang'],
    },
    'apt': {
        'name': 'APT',
        'indicators': ['Persistence va lateral movement patternlari', 'Uzoq muddatli yashirin alomatlar', "Ma'lumot chiqarish xavfi"],
        'severity': 'critical',
        'mitigation': ['Incident response jarayonini boshlang', 'Segmentlararo trafigini tekshiring', 'C2 indikatorlarini qidiring'],
    },
    'port_scan': {
        'name': 'Port Skanerlash',
        'indicators': ["Ko'p port aktivligi", 'Common admin portlar aniqlangan', 'Enumeration ehtimoli'],
        'severity': 'medium',
        'mitigation': ['Firewall rulelarni toraytiring', 'Keraksiz portlarni yoping', 'Source IP ni kuzatib boring'],
    },
}

_PORT_SCAN_CACHE = {}


def classify_ip(ip: str) -> dict:
    """IP manzilni local/public deb aniqlaydi va mavjud ma'lumotlarni qaytaradi."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {'valid': False, 'error': "Noto'g'ri IP format"}

    is_local = addr.is_private or addr.is_loopback or addr.is_link_local
    known_device = _get_known_device(ip)

    return {
        'valid': True,
        'ip': ip,
        'is_local': is_local,
        'is_loopback': addr.is_loopback,
        'network_type': _get_network_type(addr),
        'device_name': known_device.get('name') or ("Noma'lum lokal qurilma" if is_local else 'Tashqi IP'),
        'mac_address': known_device.get('mac', 'N/A'),
        'known_risk': known_device.get('risk', 'unknown'),
    }


def _get_known_device(ip: str) -> dict:
    try:
        from .models import NetworkDevice
        device = NetworkDevice.objects.filter(ip_address=ip).values(
            'device_name', 'mac_address', 'risk_level'
        ).first()
        if device:
            return {
                'name': device['device_name'],
                'mac': device['mac_address'] or 'N/A',
                'risk': device['risk_level'] or 'unknown',
            }
    except Exception:
        pass

    return {}


def _get_network_type(addr: ipaddress._BaseAddress) -> str:
    if addr.version == 6:
        return 'IPv6'
    if addr in ipaddress.ip_network('192.168.0.0/16'):
        return "LAN (uy/ofis tarmogi)"
    if addr in ipaddress.ip_network('10.0.0.0/8'):
        return 'LAN (korporativ tarmoq)'
    if addr in ipaddress.ip_network('172.16.0.0/12'):
        return 'LAN (virtual tarmoq)'
    if addr.is_loopback:
        return 'Loopback (localhost)'
    if addr.is_link_local:
        return 'Link-local'
    return 'WAN (internet)'


def discover_local_devices(limit: int = 24) -> list:
    interfaces = _parse_ipconfig()
    arp_entries = _parse_arp_table()
    candidates = {}

    for iface in interfaces:
        ip = iface['ip']
        candidates[ip] = {
            'ip': ip,
            'mac': 'N/A',
            'hint_name': 'Analyst Workstation',
            'hint_risk': 'medium',
            'status': 'online',
        }
        gateway = iface.get('gateway')
        if gateway:
            candidates[gateway] = {
                'ip': gateway,
                'mac': arp_entries.get(gateway, {}).get('mac', 'N/A'),
                'hint_name': 'Gateway/Router',
                'hint_risk': 'low',
                'status': 'online',
            }

    for ip, entry in arp_entries.items():
        if _is_candidate_host_ip(ip):
            candidates.setdefault(
                ip,
                {
                    'ip': ip,
                    'mac': entry.get('mac', 'N/A'),
                    'hint_name': None,
                    'hint_risk': None,
                    'status': 'online',
                },
            )

    private_ips = [ip for ip in candidates.keys() if _is_candidate_host_ip(ip)]
    private_ips = sorted(private_ips, key=lambda value: tuple(int(part) for part in value.split('.')))
    private_ips = private_ips[:limit]

    devices = []
    with ThreadPoolExecutor(max_workers=min(16, max(len(private_ips), 1))) as executor:
        futures = {
            executor.submit(_scan_host, ip, candidates[ip]): ip
            for ip in private_ips
        }
        for future in as_completed(futures):
            device = future.result()
            if device:
                devices.append(device)

    return sorted(devices, key=lambda item: (_risk_sort(item['risk']), item['ip']))


def _scan_host(ip: str, candidate: dict) -> dict | None:
    open_ports = _get_open_ports(ip)
    known = _get_known_device(ip)
    risk = known.get('risk') or candidate.get('hint_risk') or _assess_risk(open_ports, ip)
    name = known.get('name') or candidate.get('hint_name') or _infer_device_name(ip, open_ports)
    mac = known.get('mac') or candidate.get('mac', 'N/A')
    ip_info = classify_ip(ip)

    if not open_ports and candidate.get('status') != 'online' and ip != candidate.get('ip'):
        return None

    return {
        'ip': ip,
        'name': name,
        'mac': mac,
        'risk': risk,
        'network_type': ip_info['network_type'],
        'status': candidate.get('status', 'online'),
        'open_ports': open_ports,
        'last_seen': timezone.now().isoformat(),
        'source': 'live',
    }


def _get_open_ports(ip: str) -> list:
    now = time.time()
    cached = _PORT_SCAN_CACHE.get(ip)
    if cached and cached['expires_at'] > now:
        return cached['ports']

    open_ports = []
    for port in COMMON_PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.18)
        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
        except OSError:
            continue
        finally:
            sock.close()

    _PORT_SCAN_CACHE[ip] = {'ports': open_ports, 'expires_at': now + SCAN_TTL_SECONDS}
    return open_ports


def _parse_ipconfig() -> list:
    try:
        output = subprocess.check_output(['ipconfig'], text=True, encoding='utf-8', errors='ignore')
    except Exception:
        return []

    interfaces = []
    current = {}
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        ip_match = re.search(r'IPv4 Address.*?:\s*([0-9.]+)', line)
        mask_match = re.search(r'Subnet Mask.*?:\s*([0-9.]+)', line)
        gateway_match = re.search(r'Default Gateway.*?:\s*([0-9.]+)', line)

        if ip_match:
            current['ip'] = ip_match.group(1)
        elif mask_match:
            current['mask'] = mask_match.group(1)
        elif gateway_match:
            current['gateway'] = gateway_match.group(1)

        if current.get('ip') and current.get('mask'):
            if _is_private_ipv4(current['ip']):
                interfaces.append(current.copy())
            current = {}

    return interfaces


def _parse_arp_table() -> dict:
    try:
        output = subprocess.check_output(['arp', '-a'], text=True, encoding='utf-8', errors='ignore')
    except Exception:
        return {}

    entries = {}
    for raw_line in output.splitlines():
        match = re.search(r'^\s*([0-9.]+)\s+([0-9a-f-]{17})\s+\w+', raw_line.strip(), re.IGNORECASE)
        if not match:
            continue
        ip, mac = match.groups()
        entries[ip] = {'mac': mac.replace('-', ':').upper()}
    return entries


def _is_private_ipv4(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.version == 4 and (addr.is_private or addr.is_loopback or addr.is_link_local)
    except ValueError:
        return False


def _is_candidate_host_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.version != 4:
        return False
    if addr.is_multicast or addr.is_unspecified or addr.is_reserved:
        return False
    if str(addr) == '255.255.255.255':
        return False
    if not (addr.is_private or addr.is_loopback or addr.is_link_local):
        return False
    return not str(addr).endswith('.255')


def _risk_sort(risk: str) -> int:
    return {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}.get(risk, 4)


def _assess_risk(open_ports: list, ip: str) -> str:
    score = 0
    score += min(len(open_ports), 6) * 0.12
    score += sum(0.16 for port in open_ports if port in RISKY_PORTS)
    score += 0.18 if any(port in REMOTE_ADMIN_PORTS for port in open_ports) else 0
    score += 0.14 if any(port in DATABASE_PORTS for port in open_ports) else 0
    score += 0.08 if ip.endswith('.1') else 0

    if score >= 0.95:
        return 'critical'
    if score >= 0.65:
        return 'high'
    if score >= 0.35:
        return 'medium'
    return 'low'


def _infer_device_name(ip: str, open_ports: list) -> str:
    if ip.endswith('.1') or (80 in open_ports and 443 in open_ports and 22 not in open_ports):
        return 'Gateway/Router'
    if any(port in DATABASE_PORTS for port in open_ports):
        return 'Database Host'
    if any(port in REMOTE_ADMIN_PORTS for port in open_ports):
        return 'Server/Remote Host'
    if any(port in WEB_PORTS for port in open_ports):
        return 'Web Device'
    return 'Detected Host'


def get_ip_reputation(ip: str) -> dict:
    ip_info = classify_ip(ip)
    if not ip_info['valid']:
        return {'error': "Noto'g'ri IP"}

    if ip_info['is_local']:
        ports = _get_open_ports(ip)
        return {
            'ip': ip,
            'is_local': True,
            'message': 'Local IP uchun reputatsiya lokal scan va host xususiyatlari asosida koвЂrsatildi.',
            'local_info': ip_info,
            'abuse_score': _local_risk_to_abuse(ip_info['known_risk'], ports),
            'reports': len(ports),
        }

    api_key = settings.ABUSEIPDB_API_KEY
    if api_key == 'YOUR_API_KEY_HERE':
        return {
            'ip': ip,
            'is_local': False,
            'message': 'AbuseIPDB API key sozlanmagan. Hozircha external reputation tekshiruvi oвЂchiq.',
            'abuse_score': 0,
            'reports': 0,
        }

    resp = requests.get(
        'https://api.abuseipdb.com/api/v2/check',
        headers={'Key': api_key, 'Accept': 'application/json'},
        params={'ipAddress': ip, 'maxAgeInDays': 90},
        timeout=5,
    )
    resp.raise_for_status()
    data = resp.json().get('data', {})
    return {
        'ip': ip,
        'is_local': False,
        'abuse_score': data.get('abuseConfidenceScore', 0),
        'reports': data.get('totalReports', 0),
        'country': data.get('countryCode', 'N/A'),
        'isp': data.get('isp', 'N/A'),
        'domain': data.get('domain', 'N/A'),
        'last_reported': data.get('lastReportedAt', 'N/A'),
    }


def _local_risk_to_abuse(risk: str, open_ports: list) -> int:
    base = {'unknown': 12, 'low': 18, 'medium': 38, 'high': 67, 'critical': 88}.get(risk, 10)
    return min(100, base + len([port for port in open_ports if port in RISKY_PORTS]) * 4)


def get_target_intel(target: str) -> dict:
    host = _normalize_target(target)
    if not host:
        raise ValueError('Target majburiy.')

    is_ip = _is_ip_value(host)
    resolved_ips = [host] if is_ip else _resolve_host_ips(host)
    primary_ip = resolved_ips[0] if resolved_ips else ''
    ip_info = classify_ip(primary_ip) if primary_ip else None
    open_ports = _limited_port_probe(host, [80, 443, 8080, 8443, 22, 23, 53])
    web_checks = _collect_web_checks(host, open_ports)
    tls_info = _fetch_tls_info(host) if any(item['port'] in (443, 8443) and item['open'] for item in open_ports) else {}

    recommendations = []
    if any(item['open'] and item['port'] in (22, 23) for item in open_ports):
        recommendations.append('Remote admin portlari ochiq: access ACL va parollarni tekshiring.')
    if any(item.get('auth_required') for item in web_checks):
        recommendations.append("Web login mavjud: 2FA yoki IP cheklov qo'llash tavsiya etiladi.")
    if not web_checks and any(item['open'] for item in open_ports):
        recommendations.append('Servis portlari ochiq, lekin HTTP javob qaytmadi. Maxsus servis yoki firewall ehtimoli bor.')
    if ip_info and ip_info.get('valid'):
        recommendations.append(f"Tarmoq turi: {ip_info.get('network_type')}.")

    return {
        'target': target,
        'normalized_target': host,
        'target_type': 'ip' if is_ip else 'domain',
        'resolved_ips': resolved_ips,
        'primary_ip': primary_ip,
        'ip_info': ip_info,
        'service_ports': open_ports,
        'web_checks': web_checks,
        'tls_info': tls_info,
        'safe_probe': {
            'mode': 'limited-safe-diagnostics',
            'request_count_per_endpoint': 3,
            'note': "Bu yerda cheklangan diagnostik probe ishlatiladi, hujum yoki DDoS yuborilmaydi.",
        },
        'recommendations': recommendations[:5],
    }


def _normalize_target(target: str) -> str:
    raw = (target or '').strip()
    if not raw:
        return ''
    parsed = urlparse(raw if '://' in raw else f'//{raw}')
    return (parsed.hostname or raw).strip().strip('/')


def _is_ip_value(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _resolve_host_ips(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return []
    ips = []
    for info in infos:
        candidate = info[4][0]
        if candidate not in ips:
            ips.append(candidate)
    return ips[:8]


def _limited_port_probe(host: str, ports: list[int]) -> list[dict]:
    results = []
    for port in ports:
        started = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.45)
        is_open = False
        try:
            is_open = sock.connect_ex((host, port)) == 0
        except OSError:
            is_open = False
        finally:
            sock.close()

        results.append({
            'port': port,
            'open': is_open,
            'latency_ms': round((time.perf_counter() - started) * 1000, 1),
            'label': {
                80: 'HTTP',
                443: 'HTTPS',
                8080: 'HTTP Alt',
                8443: 'HTTPS Alt',
                22: 'SSH',
                23: 'Telnet',
                53: 'DNS',
            }.get(port, 'TCP'),
        })
    return results


def _collect_web_checks(host: str, open_ports: list[dict]) -> list[dict]:
    candidates = []
    for item in open_ports:
        if not item['open']:
            continue
        if item['port'] in (80, 8080):
            candidates.append(('http', item['port']))
        if item['port'] in (443, 8443):
            candidates.append(('https', item['port']))

    if not candidates:
        candidates = [('https', 443), ('http', 80)]

    checks = []
    with requests.Session() as session:
        session.headers.update({'User-Agent': 'CyberGuard-Intel/1.0'})
        for scheme, port in candidates[:4]:
            try:
                checks.append(_probe_http_endpoint(session, host, scheme, port))
            except Exception:
                continue
    return checks


def _probe_http_endpoint(session, host: str, scheme: str, port: int) -> dict:
    default_port = 443 if scheme == 'https' else 80
    suffix = '' if port == default_port else f':{port}'
    url = f'{scheme}://{host}{suffix}/'
    latencies = []
    response = None

    for _ in range(3):
        started = time.perf_counter()
        current = session.get(url, timeout=4, allow_redirects=True, verify=False)
        latencies.append(round((time.perf_counter() - started) * 1000, 1))
        response = current

    title_match = re.search(r'<title[^>]*>(.*?)</title>', response.text or '', re.IGNORECASE | re.DOTALL)
    title = re.sub(r'\s+', ' ', title_match.group(1)).strip() if title_match else ''

    return {
        'scheme': scheme,
        'port': port,
        'url': response.url,
        'status_code': response.status_code,
        'title': title,
        'server': response.headers.get('Server', ''),
        'content_type': response.headers.get('Content-Type', ''),
        'auth_required': response.status_code in (401, 403) or bool(response.headers.get('WWW-Authenticate')),
        'latency_samples_ms': latencies,
        'avg_latency_ms': round(sum(latencies) / len(latencies), 1) if latencies else 0,
    }


def _fetch_tls_info(host: str) -> dict:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        return {
            'subject': dict(item[0] for item in cert.get('subject', [])).get('commonName', ''),
            'issuer': dict(item[0] for item in cert.get('issuer', [])).get('commonName', ''),
            'expires_at': cert.get('notAfter', ''),
        }
    except Exception:
        return {}


def analyze_threat(ip: str, threat_type: str, algorithms: list, context: str = '') -> dict:
    ip_info = classify_ip(ip)
    if not ip_info['valid']:
        return {'error': ip_info['error']}

    sig = THREAT_SIGNATURES.get(threat_type, THREAT_SIGNATURES['port_scan'])
    telemetry = _collect_ip_telemetry(ip, ip_info)
    features = _build_feature_vector(ip_info, telemetry, context)
    feature_array = np.array([features[name] for name in FEATURE_NAMES], dtype=float)
    algo_scores = _score_algorithms(feature_array, features, threat_type, algorithms)

    if not algo_scores:
        return {'error': 'Kamida bitta algoritm tanlanishi kerak'}

    final_prob = round(sum(algo_scores.values()) / len(algo_scores), 3)
    severity = _probability_to_severity(final_prob, sig['severity'])

    indicators = list(sig['indicators'])
    indicators.extend(_dynamic_indicators(telemetry, context))
    mitigation = list(sig['mitigation'])
    mitigation.extend(_dynamic_mitigation(telemetry, severity))

    local_context = _build_local_context(ip_info, telemetry)
    recommendation = _get_recommendation(severity, ip_info['is_local'], telemetry)

    return {
        'ip': ip,
        'ip_info': ip_info,
        'threat_type': threat_type,
        'threat_name': sig['name'],
        'probability': final_prob,
        'probability_pct': f'{round(final_prob * 100, 1)}%',
        'severity': severity,
        'indicators': indicators[:6],
        'mitigation': mitigation[:6],
        'algorithm_scores': algo_scores,
        'local_context': local_context,
        'context': context,
        'recommendation': recommendation,
        'telemetry': telemetry,
        'model_version': 'cyberguard-local-ml-v1',
    }


def _collect_ip_telemetry(ip: str, ip_info: dict) -> dict:
    reputation = {'abuse_score': 0, 'reports': 0}
    if ip_info['is_local']:
        open_ports = _get_open_ports(ip)
    else:
        open_ports = []
        try:
            reputation = get_ip_reputation(ip)
        except Exception:
            reputation = {'abuse_score': 0, 'reports': 0}

    return {
        'open_ports': open_ports,
        'open_port_count': len(open_ports),
        'risky_port_count': len([port for port in open_ports if port in RISKY_PORTS]),
        'web_port_count': len([port for port in open_ports if port in WEB_PORTS]),
        'db_port_count': len([port for port in open_ports if port in DATABASE_PORTS]),
        'remote_admin_exposed': any(port in REMOTE_ADMIN_PORTS for port in open_ports),
        'abuse_score': int(reputation.get('abuse_score') or 0),
        'reports': int(reputation.get('reports') or 0),
    }


def _build_feature_vector(ip_info: dict, telemetry: dict, context: str) -> dict:
    context_lower = (context or '').lower()
    features = {
        'is_local': 1.0 if ip_info['is_local'] else 0.0,
        'is_loopback': 1.0 if ip_info['is_loopback'] else 0.0,
        'known_risk': RISK_LEVEL_MAP.get(ip_info['known_risk'], 0.2),
        'open_port_count': min(telemetry['open_port_count'], 12) / 12,
        'risky_port_count': min(telemetry['risky_port_count'], 8) / 8,
        'web_port_count': min(telemetry['web_port_count'], 4) / 4,
        'db_port_count': min(telemetry['db_port_count'], 4) / 4,
        'remote_admin': 1.0 if telemetry['remote_admin_exposed'] else 0.0,
        'abuse_score': min(telemetry['abuse_score'], 100) / 100,
        'reports': min(telemetry['reports'], 100) / 100,
        'context_intensity': min(len(context.split()), 30) / 30 if context else 0.0,
    }
    for threat in THREAT_ORDER:
        features[f'{threat}_kw'] = _keyword_score(context_lower, KEYWORD_GROUPS[threat])
    return features


def _keyword_score(context: str, keywords: list) -> float:
    if not context:
        return 0.0
    hits = sum(1 for keyword in keywords if keyword in context)
    return min(hits, 4) / 4


@lru_cache(maxsize=1)
def _get_ml_bundle() -> dict:
    X, y, benign_X = _generate_training_data()

    rf = RandomForestClassifier(n_estimators=120, max_depth=7, random_state=42)
    gb = GradientBoostingClassifier(random_state=42)
    nb = GaussianNB()
    svm = make_pipeline(StandardScaler(), SVC(probability=True, random_state=42, gamma='scale'))
    iso = IsolationForest(random_state=42, contamination=0.18)

    rf.fit(X, y)
    gb.fit(X, y)
    nb.fit(X, y)
    svm.fit(X, y)
    iso.fit(benign_X)

    prototypes = {}
    for threat in THREAT_ORDER:
        mask = y == threat
        prototypes[threat] = X[mask].mean(axis=0)

    benign_centroid = benign_X.mean(axis=0)

    return {
        'rf': rf,
        'gb': gb,
        'nb': nb,
        'svm': svm,
        'iso': iso,
        'classes': list(rf.classes_),
        'prototypes': prototypes,
        'benign_centroid': benign_centroid,
    }


def _generate_training_data() -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    rng = Random(42)
    samples = []
    labels = []
    benign_samples = []

    for _ in range(220):
        benign = _sample_profile(rng, None)
        benign_samples.append(benign)

    for threat in THREAT_ORDER:
        for _ in range(180):
            samples.append(_sample_profile(rng, threat))
            labels.append(threat)

    return np.array(samples, dtype=float), np.array(labels), np.array(benign_samples, dtype=float)


def _sample_profile(rng: Random, threat: str | None) -> list[float]:
    base = {
        'is_local': rng.choice([0.0, 1.0]),
        'is_loopback': 0.0,
        'known_risk': rng.uniform(0.18, 0.45),
        'open_port_count': rng.uniform(0.0, 0.35),
        'risky_port_count': rng.uniform(0.0, 0.2),
        'web_port_count': rng.uniform(0.0, 0.3),
        'db_port_count': rng.uniform(0.0, 0.2),
        'remote_admin': rng.choice([0.0, 0.0, 1.0]),
        'abuse_score': rng.uniform(0.0, 0.25),
        'reports': rng.uniform(0.0, 0.15),
        'context_intensity': rng.uniform(0.0, 0.2),
    }
    for name in THREAT_ORDER:
        base[f'{name}_kw'] = rng.uniform(0.0, 0.1)

    if threat == 'ddos':
        base.update({
            'is_local': rng.choice([0.0, 0.0, 1.0]),
            'open_port_count': rng.uniform(0.35, 0.8),
            'web_port_count': rng.uniform(0.45, 1.0),
            'abuse_score': rng.uniform(0.45, 0.95),
            'reports': rng.uniform(0.35, 1.0),
            'context_intensity': rng.uniform(0.25, 0.8),
            'ddos_kw': rng.uniform(0.55, 1.0),
        })
    elif threat == 'sqli':
        base.update({
            'web_port_count': rng.uniform(0.4, 1.0),
            'db_port_count': rng.uniform(0.35, 0.9),
            'abuse_score': rng.uniform(0.25, 0.8),
            'reports': rng.uniform(0.15, 0.7),
            'context_intensity': rng.uniform(0.25, 0.9),
            'sqli_kw': rng.uniform(0.65, 1.0),
        })
    elif threat == 'brute_force':
        base.update({
            'open_port_count': rng.uniform(0.2, 0.55),
            'risky_port_count': rng.uniform(0.25, 0.7),
            'remote_admin': 1.0,
            'abuse_score': rng.uniform(0.15, 0.75),
            'reports': rng.uniform(0.2, 0.85),
            'brute_force_kw': rng.uniform(0.6, 1.0),
        })
    elif threat == 'phishing':
        base.update({
            'is_local': 0.0,
            'web_port_count': rng.uniform(0.25, 0.75),
            'abuse_score': rng.uniform(0.15, 0.7),
            'reports': rng.uniform(0.2, 0.75),
            'context_intensity': rng.uniform(0.35, 0.9),
            'phishing_kw': rng.uniform(0.65, 1.0),
        })
    elif threat == 'ransomware':
        base.update({
            'is_local': 1.0,
            'known_risk': rng.uniform(0.55, 1.0),
            'risky_port_count': rng.uniform(0.2, 0.65),
            'db_port_count': rng.uniform(0.1, 0.6),
            'context_intensity': rng.uniform(0.2, 0.9),
            'ransomware_kw': rng.uniform(0.65, 1.0),
        })
    elif threat == 'mitm':
        base.update({
            'is_local': 1.0,
            'known_risk': rng.uniform(0.35, 0.8),
            'remote_admin': rng.choice([0.0, 1.0]),
            'context_intensity': rng.uniform(0.25, 0.8),
            'mitm_kw': rng.uniform(0.65, 1.0),
        })
    elif threat == 'zero_day':
        base.update({
            'known_risk': rng.uniform(0.45, 1.0),
            'open_port_count': rng.uniform(0.15, 0.6),
            'risky_port_count': rng.uniform(0.15, 0.6),
            'abuse_score': rng.uniform(0.2, 0.8),
            'context_intensity': rng.uniform(0.35, 1.0),
            'zero_day_kw': rng.uniform(0.7, 1.0),
        })
    elif threat == 'apt':
        base.update({
            'is_local': rng.choice([0.0, 1.0]),
            'known_risk': rng.uniform(0.45, 1.0),
            'abuse_score': rng.uniform(0.2, 0.8),
            'reports': rng.uniform(0.15, 0.55),
            'context_intensity': rng.uniform(0.5, 1.0),
            'apt_kw': rng.uniform(0.7, 1.0),
        })
    elif threat == 'port_scan':
        base.update({
            'open_port_count': rng.uniform(0.45, 1.0),
            'risky_port_count': rng.uniform(0.25, 0.9),
            'remote_admin': rng.choice([0.0, 1.0]),
            'reports': rng.uniform(0.05, 0.45),
            'context_intensity': rng.uniform(0.15, 0.65),
            'port_scan_kw': rng.uniform(0.65, 1.0),
        })

    return [min(max(base[name], 0.0), 1.0) for name in FEATURE_NAMES]


def _score_algorithms(feature_array: np.ndarray, features: dict, threat_type: str, algorithms: list) -> dict:
    bundle = _get_ml_bundle()
    class_index = bundle['classes'].index(threat_type)
    prototype = bundle['prototypes'][threat_type]
    benign_centroid = bundle['benign_centroid']

    scores = {}
    for algorithm in algorithms:
        if algorithm == 'Random Forest':
            score = bundle['rf'].predict_proba([feature_array])[0][class_index]
        elif algorithm == 'XGBoost':
            score = bundle['gb'].predict_proba([feature_array])[0][class_index]
        elif algorithm == 'SVM':
            score = bundle['svm'].predict_proba([feature_array])[0][class_index]
        elif algorithm == 'Naive Bayes':
            score = bundle['nb'].predict_proba([feature_array])[0][class_index]
        elif algorithm == 'Isolation Forest':
            anomaly = 1 - _normalize(bundle['iso'].decision_function([feature_array])[0], -0.25, 0.2)
            affinity = _prototype_affinity(feature_array, prototype, benign_centroid)
            score = 0.6 * anomaly + 0.4 * affinity
        elif algorithm == 'LSTM':
            keyword = features[f'{threat_type}_kw']
            score = _sigmoid(-1.2 + 2.1 * features['context_intensity'] + 2.4 * keyword + 1.3 * features['reports'])
        elif algorithm == 'Autoencoder':
            anomaly = _distance_score(feature_array, benign_centroid)
            affinity = _prototype_affinity(feature_array, prototype, benign_centroid)
            score = 0.55 * anomaly + 0.45 * affinity
        elif algorithm == 'CNN':
            port_pattern = max(features['web_port_count'], features['db_port_count'], features['risky_port_count'])
            keyword = features[f'{threat_type}_kw']
            score = _sigmoid(-1.4 + 2.5 * port_pattern + 1.9 * keyword + 0.8 * features['known_risk'])
        else:
            keyword = features[f'{threat_type}_kw']
            score = _sigmoid(-1.0 + 1.7 * keyword + 1.1 * features['risky_port_count'] + 0.9 * features['abuse_score'])

        scores[algorithm] = round(float(min(max(score, 0.01), 0.99)), 3)
    return scores


def _prototype_affinity(feature_array: np.ndarray, prototype: np.ndarray, benign_centroid: np.ndarray) -> float:
    threat_distance = np.linalg.norm(feature_array - prototype)
    benign_distance = np.linalg.norm(feature_array - benign_centroid)
    ratio = benign_distance / max(threat_distance + benign_distance, 1e-6)
    return float(min(max(ratio, 0.0), 1.0))


def _distance_score(feature_array: np.ndarray, centroid: np.ndarray) -> float:
    distance = float(np.linalg.norm(feature_array - centroid))
    return min(distance / 2.4, 1.0)


def _normalize(value: float, lower: float, upper: float) -> float:
    if upper <= lower:
        return 0.0
    return min(max((value - lower) / (upper - lower), 0.0), 1.0)


def _sigmoid(value: float) -> float:
    return 1 / (1 + math.exp(-value))


def _probability_to_severity(probability: float, baseline: str) -> str:
    if probability >= 0.9:
        return 'critical'
    if probability >= 0.75:
        return 'high'
    if probability >= 0.55:
        return 'medium'
    if baseline == 'critical' and probability >= 0.48:
        return 'medium'
    return 'low'


def _dynamic_indicators(telemetry: dict, context: str) -> list:
    indicators = []
    if telemetry['open_ports']:
        indicators.append(f"Ochiq portlar: {', '.join(str(port) for port in telemetry['open_ports'][:6])}")
    if telemetry['abuse_score']:
        indicators.append(f'External reputation: {telemetry["abuse_score"]}/100')
    if telemetry['remote_admin_exposed']:
        indicators.append('Remote admin portlari ochiq (SSH/RDP/VNC)')
    if context:
        indicators.append("Kiritilgan kontekst threat kalit so'zlari bilan tahlil qilindi")
    return indicators


def _dynamic_mitigation(telemetry: dict, severity: str) -> list:
    steps = []
    if telemetry['remote_admin_exposed']:
        steps.append('Remote admin portlarini faqat trusted IP lar uchun qoldiring')
    if telemetry['db_port_count']:
        steps.append('DB portlarini internetdan yoki umumiy LANdan yoping')
    if severity in ('high', 'critical'):
        steps.append("SIEM/EDR da shu IP uchun watchlist qo'ying")
    return steps


def _build_local_context(ip_info: dict, telemetry: dict) -> str:
    if ip_info['is_local']:
        if telemetry['open_ports']:
            return f"Ichki host skan qilindi. {len(telemetry['open_ports'])} ta ochiq common port aniqlandi."
        return f"Ichki tarmoq hosti: {ip_info['device_name']}"
    return 'Tashqi IP reputatsiya va kontekst asosida baholandi.'


def _get_recommendation(severity: str, is_local: bool, telemetry: dict) -> str:
    prefix = 'Ichki tarmoq: ' if is_local else 'Tashqi IP: '
    if severity == 'critical':
        return prefix + 'darhol containment, bloklash va incident ticket ochish tavsiya etiladi.'
    if severity == 'high':
        return prefix + "tezkor tekshiruv, monitoring va vaqtinchalik cheklovlar qo'llang."
    if severity == 'medium':
        return prefix + 'kuzatuvni kuchaytiring va host konfiguratsiyasini tekshiring.'
    if telemetry['open_port_count'] > 0:
        return prefix + 'host exposure past, lekin ochiq portlar periodik audit qilinsin.'
    return prefix + 'hozircha oddiy monitoring yetarli.'


def build_live_logs(limit: int = 10) -> list:
    from .models import ThreatLog

    recent_logs = list(ThreatLog.objects.order_by('-created_at')[:limit])
    entries = []
    for log in recent_logs:
        level = 'error' if log.severity in ('critical', 'high') else 'warn' if log.severity == 'medium' else 'info'
        entries.append({
            'id': log.id,
            'level': level,
            'message': f'{log.get_threat_type_display()} aniqlandi - {log.get_severity_display()}',
            'timestamp': log.created_at.isoformat(),
            'ip': log.ip_address,
        })
    return entries


def get_dashboard_stats(logs) -> dict:
    total = logs.count()
    blocked = logs.filter(is_blocked=True).count()
    critical = logs.filter(severity='critical').count()
    threat_dist = dict(logs.values('threat_type').annotate(total=Count('id')).values_list('threat_type', 'total'))

    now = timezone.now()
    hourly_trend = []
    for hours_ago in range(22, -2, -2):
        slot_start = now - timezone.timedelta(hours=hours_ago)
        slot_end = slot_start + timezone.timedelta(hours=2)
        slot_logs = logs.filter(created_at__gte=slot_start, created_at__lt=slot_end)
        hourly_trend.append({
            'hour': slot_start.strftime('%H:%M'),
            'threats': slot_logs.count(),
            'blocked': slot_logs.filter(is_blocked=True).count(),
        })

    return {
        'total_threats': total,
        'blocked': blocked,
        'critical': critical,
        'block_rate': round(blocked / total * 100, 1) if total else 0.0,
        'threat_distribution': threat_dist,
        'accuracy': 0.0,
        'f1_score': 0.0,
        'response_ms': 0,
        'false_positive_rate': 0.0,
        'hourly_trend': hourly_trend,
    }
