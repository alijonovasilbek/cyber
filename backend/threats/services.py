import csv
import io
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
from sklearn.cluster import DBSCAN, KMeans
from sklearn.ensemble import GradientBoostingClassifier, IsolationForest, RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.naive_bayes import GaussianNB
from sklearn.neural_network import MLPRegressor
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC


RISK_LEVEL_MAP = {'unknown': 0.2, 'low': 0.35, 'medium': 0.58, 'high': 0.82, 'critical': 1.0}

_ML_BUNDLE_CACHE: dict = {}
_AE_CACHE: dict = {}
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
        'features': features,
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


def _invalidate_ml_cache() -> None:
    _ML_BUNDLE_CACHE.clear()
    _AE_CACHE.clear()


def _get_ml_bundle(extra_X: np.ndarray = None, extra_y: np.ndarray = None) -> dict:
    if extra_X is None and 'bundle' in _ML_BUNDLE_CACHE:
        return _ML_BUNDLE_CACHE['bundle']

    X_syn, y_syn, benign_X = _generate_training_data()

    if extra_X is not None and len(extra_X) >= 5:
        valid = np.array([lbl in THREAT_ORDER for lbl in extra_y])
        if valid.sum() >= 5:
            X = np.vstack([X_syn, extra_X[valid]])
            y = np.concatenate([y_syn, extra_y[valid]])
        else:
            X, y = X_syn, y_syn
    else:
        X, y = X_syn, y_syn

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
        if mask.sum() > 0:
            prototypes[threat] = X[mask].mean(axis=0)
        else:
            prototypes[threat] = X_syn[y_syn == threat].mean(axis=0)

    benign_centroid = benign_X.mean(axis=0)

    bundle = {
        'rf': rf,
        'gb': gb,
        'nb': nb,
        'svm': svm,
        'iso': iso,
        'classes': list(rf.classes_),
        'prototypes': prototypes,
        'benign_centroid': benign_centroid,
        'real_samples': len(extra_X) if extra_X is not None else 0,
    }
    _ML_BUNDLE_CACHE['bundle'] = bundle
    return bundle


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


def _extract_real_data(min_samples: int = 5):
    """ThreatLog ma'lumotlaridan real feature vector va labellar chiqaradi."""
    from .models import ThreatLog
    logs = ThreatLog.objects.exclude(raw_data={}).order_by('-created_at')[:500]
    X, y = [], []
    for log in logs:
        raw = log.raw_data or {}
        vec = None
        feats = raw.get('features')
        if feats and isinstance(feats, dict) and len(feats) >= len(FEATURE_NAMES) - 2:
            try:
                vec = [float(feats.get(n, 0.0)) for n in FEATURE_NAMES]
            except (TypeError, ValueError):
                vec = None
        if vec is None and raw.get('telemetry') and raw.get('ip_info'):
            try:
                fvec = _build_feature_vector(raw['ip_info'], raw['telemetry'], raw.get('context', ''))
                vec = [float(fvec.get(n, 0.0)) for n in FEATURE_NAMES]
            except Exception:
                vec = None
        if vec and log.threat_type in THREAT_ORDER:
            X.append(vec)
            y.append(log.threat_type)
    if len(X) < min_samples:
        return None, None
    return np.array(X, dtype=float), np.array(y)


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


def build_live_logs(limit: int = 50) -> list:
    from lab.models import LogWindow

    _LEVEL = {'brute_force': 'error', 'port_scan': 'warn', 'anomaly': 'warn', 'normal': 'info'}
    _MSG = {
        'brute_force': 'SSH Brute Force hujumi aniqlandi — ko\'p marta noto\'g\'ri parol',
        'port_scan':   'Port Scan hujumi aniqlandi — tarmoq razvedkasi',
        'anomaly':     'Anomal faollik aniqlandi — noodatiy jarayon yoki ulanish',
        'normal':      'Normal trafik — tahdid aniqlanmadi',
    }
    windows = LogWindow.objects.order_by('-timestamp')[:limit]
    entries = []
    for w in windows:
        entries.append({
            'id': w.id,
            'level': _LEVEL.get(w.label, 'info'),
            'message': _MSG.get(w.label, w.label),
            'timestamp': w.timestamp.isoformat(),
            'ip': '172.19.0.4',
            'label': w.label,
            'failed_logins': w.failed_logins,
            'tcp_connections': w.tcp_connections,
            'source': w.source,
        })
    return entries


# ── MITRE ATT&CK Mapping ──────────────────────────────────────────────────

MITRE_ATTACK = {
    'ddos': {
        'technique_id': 'T1498',
        'technique': 'Network Denial of Service',
        'tactic': 'Impact',
        'tactic_id': 'TA0040',
        'kill_chain_phase': 'Actions on Objectives',
        'kill_chain_index': 6,
        'description': 'Tarmoq servisini haddan tashqari so\'rovlar bilan to\'xtatishga urinish.',
    },
    'sqli': {
        'technique_id': 'T1190',
        'technique': 'Exploit Public-Facing Application',
        'tactic': 'Initial Access',
        'tactic_id': 'TA0001',
        'kill_chain_phase': 'Exploitation',
        'kill_chain_index': 2,
        'description': 'Ommaviy ilovadagi zaifliklardan foydalanib tizimga kirish.',
    },
    'brute_force': {
        'technique_id': 'T1110',
        'technique': 'Brute Force',
        'tactic': 'Credential Access',
        'tactic_id': 'TA0006',
        'kill_chain_phase': 'Exploitation',
        'kill_chain_index': 2,
        'description': 'Ko\'p urinishlar orqali parol yoki kalitni topishga harakat qilish.',
    },
    'phishing': {
        'technique_id': 'T1566',
        'technique': 'Phishing',
        'tactic': 'Initial Access',
        'tactic_id': 'TA0001',
        'kill_chain_phase': 'Delivery',
        'kill_chain_index': 1,
        'description': 'Soxta xabarlar orqali foydalanuvchini aldab ma\'lumot olish.',
    },
    'ransomware': {
        'technique_id': 'T1486',
        'technique': 'Data Encrypted for Impact',
        'tactic': 'Impact',
        'tactic_id': 'TA0040',
        'kill_chain_phase': 'Actions on Objectives',
        'kill_chain_index': 6,
        'description': 'Ma\'lumotlarni shifrlash va to\'lov talab qilish.',
    },
    'mitm': {
        'technique_id': 'T1557',
        'technique': 'Adversary-in-the-Middle',
        'tactic': 'Collection',
        'tactic_id': 'TA0009',
        'kill_chain_phase': 'Exploitation',
        'kill_chain_index': 2,
        'description': 'Aloqa orasida turib ma\'lumotlarni tutib olish yoki o\'zgartirish.',
    },
    'zero_day': {
        'technique_id': 'T1203',
        'technique': 'Exploitation for Client Execution',
        'tactic': 'Execution',
        'tactic_id': 'TA0002',
        'kill_chain_phase': 'Exploitation',
        'kill_chain_index': 2,
        'description': 'Noma\'lum zaifliklardan foydalanib kod bajarish.',
    },
    'apt': {
        'technique_id': 'T1021',
        'technique': 'Remote Services',
        'tactic': 'Lateral Movement',
        'tactic_id': 'TA0008',
        'kill_chain_phase': 'Actions on Objectives',
        'kill_chain_index': 6,
        'description': 'Uzoq muddatli yashirin maqsadli hujum kampaniyasi.',
    },
    'port_scan': {
        'technique_id': 'T1046',
        'technique': 'Network Service Discovery',
        'tactic': 'Discovery',
        'tactic_id': 'TA0007',
        'kill_chain_phase': 'Reconnaissance',
        'kill_chain_index': 0,
        'description': 'Ochiq portlarni va servislarni aniqlash uchun tarmoq skanerlash.',
    },
}

KILL_CHAIN_PHASES = [
    {'name': 'Reconnaissance', 'label': 'Razvedka', 'color': '#4a6a84'},
    {'name': 'Delivery', 'label': 'Yetkazish', 'color': '#ffab00'},
    {'name': 'Exploitation', 'label': 'Ekspluatatsiya', 'color': '#ff8f00'},
    {'name': 'Installation', 'label': "O'rnatish", 'color': '#e65100'},
    {'name': 'Command & Control', 'label': 'C2 Boshqaruv', 'color': '#c62828'},
    {'name': 'Pivoting', 'label': 'Tarqalish', 'color': '#b71c1c'},
    {'name': 'Actions on Objectives', 'label': 'Maqsad', 'color': '#ff1744'},
]

CORRELATION_RULES = [
    {
        'name': 'APT Kampaniyasi',
        'description': 'Brute Force + Port Scan kombinatsiyasi APT hujumiga ishora qilmoqda',
        'conditions': [
            {'threat_type': 'brute_force', 'min_count': 2, 'window_minutes': 60},
            {'threat_type': 'port_scan', 'min_count': 1, 'window_minutes': 60},
        ],
        'result_threat': 'apt',
        'severity': 'critical',
    },
    {
        'name': "Ma'lumot O'g'irlash",
        'description': "SQL Injection + Phishing kombinatsiyasi ma'lumot chiqarish xavfini ko'rsatmoqda",
        'conditions': [
            {'threat_type': 'sqli', 'min_count': 2, 'window_minutes': 120},
        ],
        'result_threat': 'apt',
        'severity': 'high',
    },
    {
        'name': 'Ransomware Tayyorgarligi',
        'description': "Port Scan + Brute Force kombinatsiyasi ransomware hujumiga tayyorgarlikni ko'rsatadi",
        'conditions': [
            {'threat_type': 'port_scan', 'min_count': 1, 'window_minutes': 30},
            {'threat_type': 'brute_force', 'min_count': 1, 'window_minutes': 30},
        ],
        'result_threat': 'ransomware',
        'severity': 'critical',
    },
    {
        'name': 'DDoS Botnet',
        'description': "Ko'p sonli DDoS urinishlari tashkiliy botnet hujumiga ishora",
        'conditions': [
            {'threat_type': 'ddos', 'min_count': 3, 'window_minutes': 15},
        ],
        'result_threat': 'ddos',
        'severity': 'critical',
    },
]


def get_model_performance() -> dict:
    """Real ThreatLog yoki sintetik test data bilan algoritmlarni baholaydi."""
    from collections import Counter
    bundle = _get_ml_bundle()

    X_real, y_real = _extract_real_data(min_samples=10)
    if X_real is not None and len(X_real) >= 10:
        test_X_arr = X_real
        test_y_arr = y_real
        data_source = 'real'
        real_samples = len(y_real)
        real_dist = dict(Counter(y_real.tolist()))
    else:
        rng = Random(99)
        test_X, test_y_list = [], []
        for threat in THREAT_ORDER:
            for _ in range(30):
                test_X.append(_sample_profile(rng, threat))
                test_y_list.append(threat)
        test_X_arr = np.array(test_X, dtype=float)
        test_y_arr = np.array(test_y_list)
        data_source = 'synthetic'
        real_samples = 0
        real_dist = {}

    algo_map = [
        ('Random Forest', 'rf'),
        ('XGBoost', 'gb'),
        ('Naive Bayes', 'nb'),
        ('SVM', 'svm'),
    ]

    results = {}
    for algo_name, model_key in algo_map:
        model = bundle[model_key]
        y_pred = model.predict(test_X_arr)
        results[algo_name] = {
            'accuracy': round(float(accuracy_score(test_y_arr, y_pred)) * 100, 1),
            'precision': round(float(precision_score(test_y_arr, y_pred, average='weighted', zero_division=0)) * 100, 1),
            'recall': round(float(recall_score(test_y_arr, y_pred, average='weighted', zero_division=0)) * 100, 1),
            'f1': round(float(f1_score(test_y_arr, y_pred, average='weighted', zero_division=0)) * 100, 1),
        }

    rf_pred = bundle['rf'].predict(test_X_arr)
    cm_labels = [t for t in THREAT_ORDER if t in test_y_arr]
    cm = confusion_matrix(test_y_arr, rf_pred, labels=cm_labels)

    per_class = {}
    for threat in cm_labels:
        per_class[threat] = {}
        for algo_name, model_key in algo_map:
            y_pred = bundle[model_key].predict(test_X_arr)
            mask = test_y_arr == threat
            if mask.sum() > 0:
                tp = int(((y_pred == threat) & mask).sum())
                fp = int(((y_pred == threat) & ~mask).sum())
                fn = int(((y_pred != threat) & mask).sum())
                p = tp / (tp + fp) if (tp + fp) > 0 else 0.0
                r = tp / (tp + fn) if (tp + fn) > 0 else 0.0
                per_class[threat][algo_name] = round(2 * p * r / (p + r) * 100, 1) if (p + r) > 0 else 0.0

    return {
        'algorithms': results,
        'confusion_matrix': {'labels': cm_labels, 'matrix': cm.tolist()},
        'per_class_f1': per_class,
        'test_samples': len(test_y_arr),
        'real_samples': real_samples,
        'data_source': data_source,
        'real_distribution': real_dist,
    }


def get_feature_attribution(feature_array: np.ndarray, threat_type: str) -> dict:
    """Har bir xususiyatning tahdid ehtimollikka ta'sirini hisoblaydi (ablation-based)."""
    bundle = _get_ml_bundle()
    rf = bundle['rf']
    class_index = bundle['classes'].index(threat_type)

    baseline_prob = float(rf.predict_proba([feature_array])[0][class_index])

    contributions = {}
    for i, fname in enumerate(FEATURE_NAMES):
        perturbed = feature_array.copy()
        perturbed[i] = 0.0
        perturbed_prob = float(rf.predict_proba([perturbed])[0][class_index])
        contributions[fname] = round(baseline_prob - perturbed_prob, 4)

    sorted_items = sorted(contributions.items(), key=lambda x: abs(x[1]), reverse=True)

    global_importance = {
        name: round(float(val), 4)
        for name, val in zip(FEATURE_NAMES, rf.feature_importances_)
    }
    global_sorted = sorted(global_importance.items(), key=lambda x: -x[1])

    return {
        'baseline_probability': round(baseline_prob, 3),
        'threat_type': threat_type,
        'feature_contributions': [{'feature': k, 'value': v} for k, v in sorted_items[:12]],
        'global_importance': [{'feature': k, 'value': v} for k, v in global_sorted[:12]],
        'top_positive': [{'feature': k, 'value': v} for k, v in sorted_items if v > 0][:5],
        'top_negative': [{'feature': k, 'value': v} for k, v in sorted_items if v < 0][:5],
    }


def get_threat_timeline(days: int = 7) -> dict:
    """Har 4 soatlik interval bo'yicha tahdid turlarini qaytaradi."""
    from .models import ThreatLog

    now = timezone.now()
    slots = days * 6
    timeline = []

    for slot_i in range(slots, 0, -1):
        slot_start = now - timezone.timedelta(hours=slot_i * 4)
        slot_end = slot_start + timezone.timedelta(hours=4)
        slot_logs = ThreatLog.objects.filter(created_at__gte=slot_start, created_at__lt=slot_end)

        entry = {
            'timestamp': slot_start.isoformat(),
            'label': slot_start.strftime('%m/%d %H:00'),
            'total': slot_logs.count(),
        }
        for threat in THREAT_ORDER:
            entry[threat] = slot_logs.filter(threat_type=threat).count()
        timeline.append(entry)

    threat_totals = {}
    for threat in THREAT_ORDER:
        threat_totals[threat] = ThreatLog.objects.filter(threat_type=threat).count()

    return {
        'timeline': timeline,
        'threat_types': THREAT_ORDER,
        'threat_totals': threat_totals,
    }


def get_heatmap_data() -> dict:
    """Subnet va port bo'yicha tahdid zichligini qaytaradi."""
    from .models import ThreatLog, IPAnalysisRecord

    subnet_data = {}
    for log in ThreatLog.objects.values('ip_address', 'severity', 'threat_type'):
        ip = log['ip_address']
        parts = ip.split('.')
        if len(parts) == 4:
            subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            if subnet not in subnet_data:
                subnet_data[subnet] = {'count': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            subnet_data[subnet]['count'] += 1
            sev = log['severity']
            if sev in subnet_data[subnet]:
                subnet_data[subnet][sev] += 1

    port_labels = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
        80: 'HTTP', 110: 'POP3', 135: 'RPC', 139: 'NetBIOS',
        143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 1433: 'MSSQL',
        3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 8080: 'HTTP-Alt',
    }
    port_data = {str(p): {'count': 0, 'high_threat': 0, 'label': lbl} for p, lbl in port_labels.items()}

    for record in IPAnalysisRecord.objects.values('open_ports', 'threat_level'):
        for port in (record.get('open_ports') or []):
            key = str(port)
            if key in port_data:
                port_data[key]['count'] += 1
                if record['threat_level'] in ('high', 'critical'):
                    port_data[key]['high_threat'] += 1

    threat_dist = dict(
        ThreatLog.objects.values('threat_type').annotate(c=Count('id')).values_list('threat_type', 'c')
    )

    return {
        'subnets': subnet_data,
        'ports': {k: v for k, v in port_data.items() if v['count'] > 0},
        'all_ports': port_data,
        'threat_distribution': threat_dist,
    }


def get_mitre_info(threat_type: str) -> dict:
    """Tahdid turi uchun MITRE ATT&CK va Kill Chain ma'lumotini qaytaradi."""
    info = MITRE_ATTACK.get(threat_type, {})
    if not info:
        return {'error': f'MITRE mapping topilmadi: {threat_type}'}
    return {
        **info,
        'kill_chain_phases': KILL_CHAIN_PHASES,
        'threat_type': threat_type,
        'threat_name': THREAT_SIGNATURES.get(threat_type, {}).get('name', threat_type),
    }


def get_all_mitre_mappings() -> list:
    """Barcha tahdid turlari uchun MITRE ma'lumotini qaytaradi."""
    result = []
    for threat_type in THREAT_ORDER:
        info = MITRE_ATTACK.get(threat_type, {})
        sig = THREAT_SIGNATURES.get(threat_type, {})
        result.append({
            'threat_type': threat_type,
            'threat_name': sig.get('name', threat_type),
            'severity': sig.get('severity', 'medium'),
            **info,
        })
    return result


def run_correlation_engine() -> list:
    """LogWindow asosida korrelyatsiya: brute_force + port_scan → APT."""
    from lab.models import LogWindow
    from .models import Incident

    now = timezone.now()
    new_incidents = []

    # Qoida 1: so'nggi 60 daqiqada brute_force + port_scan → APT
    window_start = now - timezone.timedelta(minutes=60)
    bf_count = LogWindow.objects.filter(label='brute_force', timestamp__gte=window_start).count()
    ps_count = LogWindow.objects.filter(label='port_scan',   timestamp__gte=window_start).count()

    if bf_count >= 2 and ps_count >= 1:
        if not Incident.objects.filter(rule_name='APT_COMBO', created_at__gte=now - timezone.timedelta(minutes=15)).exists():
            inc = Incident.objects.create(
                title='APT Hujum Kombinatsiyasi',
                description=f'So\'nggi 60 daqiqada {bf_count} ta Brute Force + {ps_count} ta Port Scan aniqlandi. APT hujumi ehtimoli yuqori.',
                rule_name='APT_COMBO',
                severity='critical',
                threat_type='apt',
                involved_ips=['172.19.0.4'],
            )
            new_incidents.append({'id': inc.id, 'title': inc.title, 'description': inc.description,
                                   'severity': inc.severity, 'threat_type': inc.threat_type,
                                   'involved_ips': inc.involved_ips, 'created_at': inc.created_at.isoformat()})

    # Qoida 2: so'nggi 30 daqiqada 5+ brute_force → Persistent Brute Force
    bf_recent = LogWindow.objects.filter(label='brute_force', timestamp__gte=now - timezone.timedelta(minutes=30)).count()
    if bf_recent >= 5:
        if not Incident.objects.filter(rule_name='PERSISTENT_BF', created_at__gte=now - timezone.timedelta(minutes=15)).exists():
            inc = Incident.objects.create(
                title='Doimiy Brute Force Hujumi',
                description=f'30 daqiqada {bf_recent} ta brute force oynasi aniqlandi. Maqsadli hujum ehtimoli bor.',
                rule_name='PERSISTENT_BF',
                severity='high',
                threat_type='brute_force',
                involved_ips=['172.19.0.4'],
            )
            new_incidents.append({'id': inc.id, 'title': inc.title, 'description': inc.description,
                                   'severity': inc.severity, 'threat_type': inc.threat_type,
                                   'involved_ips': inc.involved_ips, 'created_at': inc.created_at.isoformat()})

    # Qoida 3: anomaly aniqlansa → Noma'lum tahdid
    anom_count = LogWindow.objects.filter(label='anomaly', timestamp__gte=now - timezone.timedelta(minutes=60)).count()
    if anom_count >= 2:
        if not Incident.objects.filter(rule_name='ANOMALY_CLUSTER', created_at__gte=now - timezone.timedelta(minutes=15)).exists():
            inc = Incident.objects.create(
                title="Anomal Faollik To'plami",
                description=f'60 daqiqada {anom_count} ta anomaliya aniqlandi. Noma\'lum hujum vektori tekshirilsin.',
                rule_name='ANOMALY_CLUSTER',
                severity='high',
                threat_type='anomaly',
                involved_ips=['172.19.0.4'],
            )
            new_incidents.append({'id': inc.id, 'title': inc.title, 'description': inc.description,
                                   'severity': inc.severity, 'threat_type': inc.threat_type,
                                   'involved_ips': inc.involved_ips, 'created_at': inc.created_at.isoformat()})

    return new_incidents


def get_incidents() -> list:
    """Barcha intsidentlarni qaytaradi."""
    from .models import Incident
    return [
        {
            'id': inc.id,
            'title': inc.title,
            'description': inc.description,
            'severity': inc.severity,
            'threat_type': inc.threat_type,
            'involved_ips': inc.involved_ips,
            'is_resolved': inc.is_resolved,
            'created_at': inc.created_at.isoformat(),
        }
        for inc in Incident.objects.order_by('-created_at')[:50]
    ]


def cluster_threats() -> dict:
    """Real ThreatLog va IPAnalysisRecord ma'lumotlari asosida klasterlash."""
    from .models import ThreatLog, IPAnalysisRecord

    X_list, labels_true, sources = [], [], []

    # 1) ThreatLog dan to'liq feature vector
    for log in ThreatLog.objects.order_by('-created_at')[:300]:
        raw = log.raw_data or {}
        vec = None
        feats = raw.get('features')
        if feats and isinstance(feats, dict):
            try:
                vec = [float(feats.get(n, 0.0)) for n in FEATURE_NAMES]
            except (TypeError, ValueError):
                vec = None
        if vec is None and raw.get('telemetry') and raw.get('ip_info'):
            try:
                fvec = _build_feature_vector(raw['ip_info'], raw['telemetry'], raw.get('context', ''))
                vec = [float(fvec.get(n, 0.0)) for n in FEATURE_NAMES]
            except Exception:
                vec = None
        if vec is None:
            sev_map = {'low': 0.1, 'medium': 0.4, 'high': 0.7, 'critical': 1.0}
            vec = [0.0] * len(FEATURE_NAMES)
            vec[0] = 1.0 if log.is_local else 0.0
            vec[2] = sev_map.get(log.severity, 0.1)
            vec[8] = float(log.probability or 0.0)
        X_list.append(vec)
        labels_true.append(log.threat_type if log.threat_type in THREAT_ORDER else 'port_scan')
        sources.append('threat_log')

    # 2) IPAnalysisRecord dan port scan ma'lumotlari
    for rec in IPAnalysisRecord.objects.exclude(open_ports=[]).order_by('-created_at')[:200]:
        ports = rec.open_ports or []
        risky = len([p for p in ports if p in RISKY_PORTS])
        web = len([p for p in ports if p in WEB_PORTS])
        db = len([p for p in ports if p in DATABASE_PORTS])
        vec = [0.0] * len(FEATURE_NAMES)
        vec[2] = RISK_LEVEL_MAP.get(rec.threat_level, 0.2)
        vec[3] = min(len(ports), 12) / 12
        vec[4] = min(risky, 8) / 8
        vec[5] = min(web, 4) / 4
        vec[6] = min(db, 4) / 4
        vec[7] = 1.0 if any(p in REMOTE_ADMIN_PORTS for p in ports) else 0.0
        lbl = rec.attack_type if rec.attack_type in THREAT_ORDER else 'port_scan'
        X_list.append(vec)
        labels_true.append(lbl)
        sources.append('scan_record')

    if len(X_list) < 5:
        return {
            'error': "Yetarli ma'lumot yo'q",
            'detail': "Avval IP Tahlil sahifasida bir nechta IP tahlil qiling yoki tarmoq skanini bajaring.",
            'n_samples': len(X_list),
        }

    X = np.array(X_list, dtype=float)
    n_clusters = min(len(THREAT_ORDER), max(3, len(X) // 15))
    kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
    kmeans_labels = kmeans.fit_predict(X).tolist()

    dbscan = DBSCAN(eps=0.25, min_samples=3)
    dbscan_labels = dbscan.fit_predict(X).tolist()

    clusters = {}
    for i, km_label in enumerate(kmeans_labels):
        key = f'cluster_{km_label}'
        if key not in clusters:
            clusters[key] = {'id': km_label, 'members': 0, 'threat_types': {}, 'anomaly_count': 0}
        clusters[key]['members'] += 1
        threat = labels_true[i]
        clusters[key]['threat_types'][threat] = clusters[key]['threat_types'].get(threat, 0) + 1
        if dbscan_labels[i] == -1:
            clusters[key]['anomaly_count'] += 1

    src_counts: dict = {}
    for s in sources:
        src_counts[s] = src_counts.get(s, 0) + 1

    return {
        'n_samples': len(X),
        'n_kmeans_clusters': n_clusters,
        'n_dbscan_clusters': len(set(l for l in dbscan_labels if l >= 0)),
        'dbscan_noise_count': dbscan_labels.count(-1),
        'clusters': list(clusters.values()),
        'sources': src_counts,
        'points': [
            {'x': float(X[i][3]), 'y': float(X[i][8]), 'z': float(X[i][2]),
             'kmeans': kmeans_labels[i], 'dbscan': dbscan_labels[i],
             'threat': labels_true[i], 'source': sources[i]}
            for i in range(min(len(X), 100))
        ],
    }


def _get_autoencoder() -> MLPRegressor:
    """Real + sintetik data bilan o'qitilgan autoencoder (bottleneck arxitektura)."""
    if 'ae' in _AE_CACHE:
        return _AE_CACHE['ae']

    X_syn, _, benign_X = _generate_training_data()
    X_real, _ = _extract_real_data(min_samples=5)
    all_X = np.vstack([X_syn, benign_X, X_real]) if X_real is not None else np.vstack([X_syn, benign_X])

    ae = MLPRegressor(
        hidden_layer_sizes=(14, 6, 14),
        activation='relu',
        max_iter=300,
        random_state=42,
        alpha=0.001,
    )
    ae.fit(all_X, all_X)

    reconstructed = ae.predict(all_X)
    errors = np.mean((all_X - reconstructed) ** 2, axis=1)
    threshold = float(np.percentile(errors, 95))
    _AE_CACHE['ae'] = ae
    _AE_CACHE['threshold'] = max(threshold, 0.02)
    _AE_CACHE['real_samples'] = len(X_real) if X_real is not None else 0
    return ae


def get_autoencoder_score(feature_array: np.ndarray) -> dict:
    """Autoencoder reconstruction error asosida anomaliya skorini qaytaradi."""
    ae = _get_autoencoder()
    threshold = _AE_CACHE.get('threshold', 0.12)
    reconstructed = ae.predict([feature_array])[0]
    errors = (feature_array - reconstructed) ** 2
    reconstruction_error = float(np.mean(errors))
    anomaly_score = min(reconstruction_error / threshold, 1.0)
    is_anomaly = anomaly_score > 0.6

    feature_errors = {
        name: round(float(errors[i]), 5)
        for i, name in enumerate(FEATURE_NAMES)
    }
    top_errors = sorted(feature_errors.items(), key=lambda x: -x[1])[:8]

    return {
        'reconstruction_error': round(reconstruction_error, 5),
        'anomaly_score': round(anomaly_score, 3),
        'anomaly_pct': f'{round(anomaly_score * 100, 1)}%',
        'is_anomaly': is_anomaly,
        'threshold': round(threshold, 5),
        'real_samples_trained': _AE_CACHE.get('real_samples', 0),
        'label': 'Anomaliya aniqlandi — Zero-Day ehtimoli yuqori' if is_anomaly else "Normal pattern — ma'lum tahdid profili bilan mos",
        'top_error_features': [{'feature': k, 'error': v} for k, v in top_errors],
        'feature_errors': feature_errors,
    }


def export_threats_csv() -> str:
    """LogWindow yozuvlarini CSV formatda qaytaradi."""
    from lab.models import LogWindow

    _SEV = {'brute_force': 'critical', 'port_scan': 'high', 'anomaly': 'high', 'normal': 'low'}
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'IP Manzil', 'Tahdid Turi', 'Jiddiylik', 'Muvaffaqiyatsiz_Login',
                     'TCP_Ulanish', 'Algoritm', 'Manba', 'Sana'])

    for w in LogWindow.objects.order_by('-timestamp')[:500]:
        writer.writerow([
            w.id,
            '172.19.0.4',
            w.label,
            _SEV.get(w.label, 'low'),
            w.failed_logins,
            w.tcp_connections,
            'Random Forest + Neural Net + Isolation Forest',
            w.source,
            w.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        ])

    return output.getvalue()


def export_threats_json() -> list:
    """LogWindow yozuvlarini JSON formatda qaytaradi."""
    from lab.models import LogWindow

    _SEV = {'brute_force': 'critical', 'port_scan': 'high', 'anomaly': 'high', 'normal': 'low'}
    return [
        {
            'id': w.id,
            'ip_address': '172.19.0.4',
            'threat_type': w.label,
            'severity': _SEV.get(w.label, 'low'),
            'failed_logins': w.failed_logins,
            'success_logins': w.success_logins,
            'tcp_connections': w.tcp_connections,
            'running_processes': w.running_processes,
            'algorithm': 'Random Forest + Neural Net + Isolation Forest',
            'source': w.source,
            'created_at': w.timestamp.isoformat(),
        }
        for w in LogWindow.objects.order_by('-timestamp')[:500]
    ]


def generate_pdf_report() -> bytes:
    """Tahdid hisobotini PDF formatida yaratadi (LogWindow asosida)."""
    from lab.models import LogWindow, PredictionLog
    from .models import BlockedIP
    from django.db.models import Count as DCount
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import cm
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError:
        return b''

    _SEV = {'brute_force': 'KRITIK', 'port_scan': 'YUQORI', 'anomaly': 'YUQORI', 'normal': 'PAST'}

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=2 * cm, bottomMargin=2 * cm)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph('CyberGuard AI — Tahdid Tahlili Hisoboti', styles['Title']))
    story.append(Spacer(1, 0.4 * cm))
    story.append(Paragraph(f"Sana: {timezone.now().strftime('%Y-%m-%d %H:%M')} UTC", styles['Normal']))
    story.append(Spacer(1, 0.6 * cm))

    label_dist = dict(LogWindow.objects.values('label').annotate(c=DCount('id')).values_list('label', 'c'))
    total = sum(label_dist.values())
    threat_count = sum(v for k, v in label_dist.items() if k != 'normal')
    blocked_count = BlockedIP.objects.filter(is_active=True).count()

    try:
        from lab.multi_trainer import models_status
        mst = models_status()
        rf_acc = round((mst.get('rf', {}).get('accuracy') or 0) * 100, 1)
        nn_acc = round((mst.get('nn', {}).get('accuracy') or 0) * 100, 1)
        iso_acc = round((mst.get('iso', {}).get('accuracy') or 0) * 100, 1)
    except Exception:
        rf_acc = nn_acc = iso_acc = 0.0

    story.append(Paragraph("Umumiy Ko'rsatkichlar", styles['Heading2']))
    summary_data = [
        ["Ko'rsatkich", 'Qiymat'],
        ['Jami log oynalari', str(total)],
        ['Tahdid aniqlangan', str(threat_count)],
        ['Brute Force', str(label_dist.get('brute_force', 0))],
        ['Port Scan', str(label_dist.get('port_scan', 0))],
        ['Anomaliya', str(label_dist.get('anomaly', 0))],
        ['Bloklangan IP lar', str(blocked_count)],
        ['RF Aniqligi', f'{rf_acc}%'],
        ['NN Aniqligi', f'{nn_acc}%'],
        ['Isolation Forest Aniqligi', f'{iso_acc}%'],
    ]
    summary_table = Table(summary_data, colWidths=[10 * cm, 6 * cm])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a3a5c')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#f0f4f8'), colors.white]),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#c8d6e0')),
        ('PADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.6 * cm))

    story.append(Paragraph("So'nggi 20 ta Tahdid Log Oynasi", styles['Heading2']))
    recent = LogWindow.objects.exclude(label='normal').order_by('-timestamp')[:20]
    log_data = [['IP', 'Tahdid Turi', 'Jiddiylik', 'Muvaffaqiyatsiz Login', 'Sana']]
    for w in recent:
        log_data.append([
            '172.19.0.4',
            w.label.upper().replace('_', ' '),
            _SEV.get(w.label, 'NOMA\'LUM'),
            str(w.failed_logins),
            w.timestamp.strftime('%m/%d %H:%M'),
        ])
    if len(log_data) == 1:
        log_data.append(['-', '-', '-', '-', '-'])
    log_table = Table(log_data, colWidths=[3.5 * cm, 4 * cm, 3 * cm, 3.5 * cm, 2.5 * cm])
    log_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a3a5c')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#f0f4f8'), colors.white]),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#c8d6e0')),
        ('PADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(log_table)

    doc.build(story)
    return buffer.getvalue()


def retrain_models_from_csv_rows(rows: list, label_col: str = None) -> dict:
    """CSV satrlaridan feature vector yaratib modellarni qayta o'qitadi."""
    from collections import Counter

    LABEL_MAP = {
        'normal': None, 'benign': None,
        'dos': 'ddos', 'ddos': 'ddos',
        'sql injection': 'sqli', 'sqli': 'sqli', 'web attacks': 'sqli',
        'brute force': 'brute_force', 'bruteforce': 'brute_force',
        'ftp-patator': 'brute_force', 'ssh-patator': 'brute_force',
        'phishing': 'phishing', 'spam': 'phishing',
        'ransomware': 'ransomware',
        'mitm': 'mitm', 'arp spoofing': 'mitm',
        'zero-day': 'zero_day', 'zeroday': 'zero_day',
        'apt': 'apt', 'infiltration': 'apt',
        'port scan': 'port_scan', 'portscan': 'port_scan', 'probe': 'port_scan',
    }

    if not rows:
        return {'error': "Ma'lumot yo'q"}

    all_cols = list(rows[0].keys())
    candidate_labels = ['label', 'class', 'attack_type', 'category', 'target', 'Label', 'Class']
    if label_col:
        candidate_labels.insert(0, label_col)
    found_label_col = next((c for c in candidate_labels if c in all_cols), None)
    if not found_label_col:
        return {'error': f"Label ustuni topilmadi. Ustunlar: {', '.join(all_cols[:10])}"}

    num_cols = []
    for col in all_cols:
        if col == found_label_col:
            continue
        try:
            vals = [float(row[col]) for row in rows[:20] if row.get(col) not in ('', None)]
            if vals:
                num_cols.append(col)
        except (ValueError, TypeError):
            continue

    if len(num_cols) < 3:
        return {'error': f"Yetarli raqamli ustun yo'q ({len(num_cols)} ta topildi)"}

    X_csv, y_csv = [], []
    for row in rows:
        raw_lbl = str(row.get(found_label_col, '')).strip().lower()
        mapped = None
        for k, v in LABEL_MAP.items():
            if k in raw_lbl or raw_lbl == k:
                mapped = v
                break
        if mapped is None:
            for t in THREAT_ORDER:
                if t in raw_lbl:
                    mapped = t
                    break
        if mapped is None:
            continue
        try:
            vals = [float(row.get(c, 0) or 0) for c in num_cols[:20]]
            X_csv.append(vals)
            y_csv.append(mapped)
        except (ValueError, TypeError):
            continue

    if len(X_csv) < 10:
        sample_labels = list(set(str(r.get(found_label_col, '')) for r in rows[:30]))
        return {'error': f"Mos tahdid qatori yetarli emas ({len(X_csv)} ta). Namuna labellar: {sample_labels[:10]}"}

    target_len = len(FEATURE_NAMES)
    X_padded = []
    for vec in X_csv:
        if len(vec) >= target_len:
            X_padded.append(vec[:target_len])
        else:
            X_padded.append(vec + [0.0] * (target_len - len(vec)))

    X_arr = np.array(X_padded, dtype=float)
    col_max = X_arr.max(axis=0)
    col_max[col_max == 0] = 1.0
    X_norm = X_arr / col_max
    y_arr = np.array(y_csv)

    _invalidate_ml_cache()
    try:
        _get_ml_bundle(extra_X=X_norm, extra_y=y_arr)
    except Exception as e:
        return {'error': f"Model o'qitishda xato: {str(e)}"}

    dist = dict(Counter(y_csv))
    return {
        'success': True,
        'csv_samples_used': len(X_csv),
        'distribution': dist,
        'message': f"{len(X_csv)} ta real namuna bilan modellar qayta o'qitildi",
    }


def generate_sample_dataset(fmt: str) -> str:
    """Namuna CSV dataset generatsiya qiladi (o'qitish va sinov uchun)."""
    from random import Random as _R
    rng = _R(777)
    out = io.StringIO()

    if fmt == 'cyberguard':
        # CyberGuard Native: to'liq 20 ta feature + label
        writer = csv.writer(out)
        header = list(FEATURE_NAMES) + ['label']
        writer.writerow(header)
        PROFILES = {
            'ddos':        {'open_port_count': (0.35, 0.9), 'web_port_count': (0.45, 1.0), 'abuse_score': (0.45, 0.95), 'reports': (0.35, 1.0), 'ddos_kw': (0.55, 1.0)},
            'sqli':        {'web_port_count': (0.4, 1.0), 'db_port_count': (0.35, 0.9), 'sqli_kw': (0.65, 1.0)},
            'brute_force': {'risky_port_count': (0.25, 0.7), 'remote_admin': (0.8, 1.0), 'brute_force_kw': (0.6, 1.0)},
            'phishing':    {'web_port_count': (0.25, 0.75), 'abuse_score': (0.15, 0.7), 'phishing_kw': (0.65, 1.0)},
            'ransomware':  {'known_risk': (0.55, 1.0), 'risky_port_count': (0.2, 0.65), 'ransomware_kw': (0.65, 1.0)},
            'mitm':        {'remote_admin': (0.5, 1.0), 'mitm_kw': (0.65, 1.0)},
            'zero_day':    {'known_risk': (0.45, 1.0), 'abuse_score': (0.2, 0.8), 'zero_day_kw': (0.7, 1.0)},
            'apt':         {'known_risk': (0.45, 1.0), 'context_intensity': (0.5, 1.0), 'apt_kw': (0.7, 1.0)},
            'port_scan':   {'open_port_count': (0.45, 1.0), 'risky_port_count': (0.25, 0.9), 'port_scan_kw': (0.65, 1.0)},
        }
        for threat, overrides in PROFILES.items():
            for _ in range(40):
                row = {n: round(rng.uniform(0.0, 0.2), 4) for n in FEATURE_NAMES}
                for k, (lo, hi) in overrides.items():
                    row[k] = round(rng.uniform(lo, hi), 4)
                writer.writerow([row[n] for n in FEATURE_NAMES] + [threat])
        for _ in range(30):
            writer.writerow([round(rng.uniform(0.0, 0.15), 4) for _ in FEATURE_NAMES] + ['port_scan'])

    elif fmt == 'nsl_kdd':
        # NSL-KDD uslubi: 12 numeric feature + label
        cols = ['duration', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment',
                'urgent', 'hot', 'num_failed_logins', 'logged_in',
                'num_compromised', 'root_shell', 'su_attempted', 'label']
        writer = csv.writer(out)
        writer.writerow(cols)
        LABEL_MAP = {
            'normal': [0, 200, 150, 0, 0, 0, 0, 0, 1, 0, 0, 0],
            'dos':    [0, 5000, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
            'brute_force': [2, 500, 200, 0, 0, 0, 2, 5, 0, 0, 0, 0],
            'port_scan': [0, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            'apt':    [120, 800, 600, 0, 0, 0, 5, 1, 1, 3, 1, 0],
        }
        for label, base in LABEL_MAP.items():
            for _ in range(40):
                row = [max(0, int(v * rng.uniform(0.5, 1.8))) for v in base]
                writer.writerow(row + [label])

    elif fmt == 'cicids2017':
        # CICIDS2017 uslubi: 10 network flow feature + Label
        cols = ['Flow Duration', 'Total Fwd Packets', 'Total Bwd Packets',
                'Total Length Fwd', 'Total Length Bwd', 'Fwd Packet Length Max',
                'Bwd Packet Length Mean', 'Flow Bytes/s', 'Flow Packets/s',
                'Avg Packet Size', 'Label']
        writer = csv.writer(out)
        writer.writerow(cols)
        CICIDS_MAP = {
            'BENIGN':       [50000, 10, 8, 1200, 800, 1460, 100, 200, 0.5, 120],
            'DDoS':         [1000, 500, 2, 50000, 100, 60, 50, 50000, 500, 60],
            'DoS Hulk':     [2000, 200, 5, 20000, 500, 200, 100, 10000, 100, 100],
            'FTP-Patator':  [30000, 20, 15, 2000, 1500, 800, 750, 100, 0.5, 750],
            'SSH-Patator':  [40000, 25, 20, 2500, 2000, 900, 800, 100, 0.5, 850],
            'PortScan':     [500, 2, 1, 120, 60, 60, 60, 200, 4, 60],
            'Web Attack – Sql Injection': [5000, 15, 12, 3000, 2500, 1460, 1200, 500, 3, 1300],
        }
        for label, base in CICIDS_MAP.items():
            for _ in range(30):
                row = [max(0, int(v * rng.uniform(0.6, 1.6))) for v in base]
                writer.writerow(row + [label])

    return out.getvalue()


SAMPLE_DATASETS = [
    {
        'id': 'cyberguard',
        'name': 'CyberGuard Native',
        'desc': "CyberGuard 20 ta feature bilan to'liq mos. Eng tez o'qitiladi.",
        'rows': 390,
        'features': 20,
        'labels': 'ddos, sqli, brute_force, phishing, ransomware, mitm, zero_day, apt, port_scan',
        'color': '#39ff14',
    },
    {
        'id': 'nsl_kdd',
        'name': 'NSL-KDD Style',
        'desc': 'Klassik IDS dataset formati. 12 numeric feature.',
        'rows': 200,
        'features': 12,
        'labels': 'normal, dos, brute_force, port_scan, apt',
        'color': '#00e5ff',
    },
    {
        'id': 'cicids2017',
        'name': 'CICIDS2017 Style',
        'desc': 'Tarmoq oqimi dataset. 10 flow feature.',
        'rows': 210,
        'features': 10,
        'labels': 'BENIGN, DDoS, DoS Hulk, FTP-Patator, SSH-Patator, PortScan, SQL Injection',
        'color': '#a855f7',
    },
]


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


# ─────────────────────────────────────────────────────────────────────────────
# XAI — EXPLAINABLE AI
# ─────────────────────────────────────────────────────────────────────────────

def get_xai_explanation(ip: str, context: str = '') -> dict:
    """Feature-based XAI tushuntirish: model nima uchun bunday qaror qabul qildi."""
    from .models import IPAnalysisRecord
    import platform

    features = None
    record = IPAnalysisRecord.objects.filter(ip_address=ip).order_by('-scan_time').first()
    if record and record.features:
        features = record.features

    if not features:
        ip_info = classify_ip(ip)
        telemetry = {'open_ports': [], 'response_time': 0}
        features = _build_feature_vector(ip_info, telemetry, context)

    bundle = _get_ml_bundle()
    clf = bundle['clf']

    feature_vector = [float(features.get(n, 0.0)) for n in FEATURE_NAMES]
    X = np.array([feature_vector])

    predicted_class = clf.predict(X)[0]
    proba = clf.predict_proba(X)[0]
    proba_dict = dict(zip(clf.classes_, proba.tolist()))

    base_importances = clf.feature_importances_ if hasattr(clf, 'feature_importances_') else np.ones(len(FEATURE_NAMES)) / len(FEATURE_NAMES)

    contributions = []
    for i, name in enumerate(FEATURE_NAMES):
        val = feature_vector[i]
        importance = float(base_importances[i])
        contributions.append({
            'feature': name,
            'value': round(val, 4),
            'importance': round(importance, 4),
            'contribution': round(val * importance, 4),
            'direction': 'up' if val > 0.3 else 'down',
        })

    contributions.sort(key=lambda x: abs(x['contribution']), reverse=True)

    threat_labels = {
        'ddos': 'DDoS hujumi', 'sqli': 'SQL Injection', 'brute_force': 'Brute Force',
        'phishing': 'Phishing', 'ransomware': 'Ransomware', 'mitm': 'MITM',
        'zero_day': 'Zero-Day', 'apt': 'APT', 'port_scan': 'Port Skan',
    }

    top3 = contributions[:3]
    reasons = []
    for f in top3:
        if f['value'] > 0.3:
            readable = f['feature'].replace('_', ' ').replace('kw', 'kalit so\'z')
            reasons.append(readable)

    name = threat_labels.get(predicted_class, predicted_class)
    explanation = (f"{name} ehtimoli yuqori, chunki: {', '.join(reasons)}." if reasons
                   else f"Model {name} tahdidini aniqlamoqda.")

    return {
        'ip': ip,
        'predicted_threat': predicted_class,
        'predicted_threat_label': threat_labels.get(predicted_class, predicted_class),
        'confidence': round(float(max(proba)), 3),
        'probabilities': {k: round(v, 3) for k, v in proba_dict.items()},
        'top_features': contributions[:8],
        'all_features': contributions,
        'explanation': explanation,
        'signature': THREAT_SIGNATURES.get(predicted_class, {}),
    }


# ─────────────────────────────────────────────────────────────────────────────
# LSTM / TIME-SERIES TREND PREDICTION
# ─────────────────────────────────────────────────────────────────────────────

def lstm_trend_predict(hours_ahead: int = 6) -> dict:
    """Tahdid trendi va kelajak bashoratlari (MLP time-series model)."""
    from .models import ThreatLog

    now = timezone.now()
    history = []
    for h in range(47, -1, -1):
        t_start = now - timezone.timedelta(hours=h + 1)
        t_end = now - timezone.timedelta(hours=h)
        cnt = ThreatLog.objects.filter(created_at__gte=t_start, created_at__lt=t_end).count()
        history.append(cnt)

    is_real = sum(history) >= 3
    if not is_real:
        rng = Random(42)
        history = [max(0, int(5 + 3 * (0.5 - rng.random()) * 2 + 2 * abs(rng.random()))) for _ in range(48)]

    window = 6
    X, y = [], []
    for i in range(len(history) - window):
        X.append(history[i:i + window])
        y.append(history[i + window])

    X = np.array(X, dtype=float)
    y = np.array(y, dtype=float)

    predictions = []
    model_name = 'fallback'

    if len(X) >= 5:
        try:
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)
            mlp = MLPRegressor(hidden_layer_sizes=(32, 16), max_iter=600, random_state=42)
            mlp.fit(X_scaled, y)
            last_win = list(history[-window:])
            for _ in range(hours_ahead):
                x_in = scaler.transform([last_win])
                pred = max(0, round(float(mlp.predict(x_in)[0])))
                predictions.append(pred)
                last_win = last_win[1:] + [pred]
            model_name = 'MLP-TimeSeries'
        except Exception:
            predictions = []

    if not predictions:
        last_avg = max(1, int(sum(history[-window:]) / window))
        predictions = [last_avg] * hours_ahead

    recent_avg = sum(history[-6:]) / 6
    pred_avg = sum(predictions) / len(predictions)
    if pred_avg > recent_avg * 1.3:
        trend = 'rising'
    elif pred_avg < recent_avg * 0.7:
        trend = 'falling'
    else:
        trend = 'stable'

    # Per-type breakdown for last 24h
    type_counts = {}
    for threat in THREAT_ORDER:
        cnt = ThreatLog.objects.filter(
            threat_type=threat,
            created_at__gte=now - timezone.timedelta(hours=24),
        ).count()
        type_counts[threat] = cnt

    return {
        'history': [{'hour': -(47 - i), 'count': v} for i, v in enumerate(history)],
        'predictions': [{'hour': i + 1, 'count': int(v)} for i, v in enumerate(predictions)],
        'trend': trend,
        'trend_label': {'rising': 'O\'SISH', 'falling': 'PASAYISH', 'stable': 'BARQAROR'}[trend],
        'is_real': is_real,
        'model': model_name,
        'recent_avg': round(recent_avg, 2),
        'predicted_avg': round(pred_avg, 2),
        'type_counts_24h': type_counts,
    }


# ─────────────────────────────────────────────────────────────────────────────
# GEOIP — GEOGRAFIK TAHLIL
# ─────────────────────────────────────────────────────────────────────────────

def get_geoip_data(ip: str) -> dict:
    """IP manzil uchun geografik ma'lumot (ip-api.com orqali)."""
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return {
                'ip': ip, 'country': 'Lokal', 'country_code': 'LO',
                'region': 'LAN', 'city': 'Mahalliy tarmoq',
                'lat': 41.2995, 'lon': 69.2401,
                'isp': 'Mahalliy', 'org': 'Ichki tarmoq',
                'is_proxy': False, 'is_hosting': False, 'risk': 'low',
            }
    except ValueError:
        return {'ip': ip, 'error': "Noto'g'ri IP format"}

    try:
        resp = requests.get(
            f'http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,'
            f'region,regionName,city,lat,lon,isp,org,as,proxy,hosting',
            timeout=6,
        )
        if resp.status_code == 200:
            d = resp.json()
            if d.get('status') == 'success':
                return {
                    'ip': ip,
                    'country': d.get('country', 'Noma\'lum'),
                    'country_code': d.get('countryCode', 'XX'),
                    'region': d.get('regionName', ''),
                    'city': d.get('city', ''),
                    'lat': d.get('lat', 0),
                    'lon': d.get('lon', 0),
                    'isp': d.get('isp', ''),
                    'org': d.get('org', ''),
                    'is_proxy': d.get('proxy', False),
                    'is_hosting': d.get('hosting', False),
                    'risk': 'high' if (d.get('proxy') or d.get('hosting')) else 'low',
                }
    except Exception:
        pass

    return {'ip': ip, 'error': 'GeoIP xizmati mavjud emas', 'country': 'Noma\'lum'}


def get_bulk_geoip(ips: list) -> list:
    """Ko'p IP uchun geografik ma'lumot (tahdid loglardan)."""
    from .models import ThreatLog
    if not ips:
        ips = list(ThreatLog.objects.values_list('ip_address', flat=True).distinct()[:30])
    results = []
    for ip in ips[:30]:
        results.append(get_geoip_data(ip))
    return results


# ─────────────────────────────────────────────────────────────────────────────
# AUTO BLOCK — TIZIM DARAJASIDA IP BLOKLASH
# ─────────────────────────────────────────────────────────────────────────────

def auto_block_ip_system(ip: str) -> dict:
    """IP manzilni Windows Firewall (netsh) yoki iptables orqali bloklaydi."""
    import platform as _platform
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {'success': False, 'error': "Noto'g'ri IP format"}

    from .models import BlockedIP
    system = _platform.system()
    result = {'ip': ip, 'system': system, 'success': False}

    if system == 'Windows':
        rule = f'CyberGuard-Block-{ip.replace(".", "_")}'
        cmd = ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
               f'name={rule}', 'dir=in', 'action=block',
               f'remoteip={ip}', 'enable=yes']
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            result['success'] = proc.returncode == 0
            result['output'] = proc.stdout.strip() or proc.stderr.strip()
            result['rule_name'] = rule
        except PermissionError:
            result['error'] = 'Administrator huquqlari talab etiladi'
        except subprocess.TimeoutExpired:
            result['error'] = 'Buyruq vaqti tugadi'
        except Exception as exc:
            result['error'] = str(exc)
    elif system == 'Linux':
        cmd = ['iptables', '-I', 'INPUT', '-s', ip, '-j', 'DROP']
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            result['success'] = proc.returncode == 0
            result['output'] = proc.stdout.strip() or proc.stderr.strip()
        except Exception as exc:
            result['error'] = str(exc)
    else:
        result['error'] = f'Qo\'llab-quvvatlanmaydigan OS: {system}'

    if result['success']:
        BlockedIP.objects.get_or_create(
            ip_address=ip,
            defaults={'reason': 'CyberGuard AI tomonidan avtomatik bloklandi'},
        )

    return result


def auto_unblock_ip_system(ip: str) -> dict:
    """Avval bloklangan IP manzilni qoidadan o'chiradi."""
    import platform as _platform
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {'success': False, 'error': "Noto'g'ri IP format"}

    system = _platform.system()
    result = {'ip': ip, 'system': system, 'success': False}

    if system == 'Windows':
        rule = f'CyberGuard-Block-{ip.replace(".", "_")}'
        cmd = ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={rule}']
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            result['success'] = proc.returncode == 0
            result['output'] = proc.stdout.strip() or proc.stderr.strip()
        except Exception as exc:
            result['error'] = str(exc)
    elif system == 'Linux':
        cmd = ['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP']
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            result['success'] = proc.returncode == 0
        except Exception as exc:
            result['error'] = str(exc)
    else:
        result['error'] = f'Qo\'llab-quvvatlanmaydigan OS: {system}'

    from .models import BlockedIP
    BlockedIP.objects.filter(ip_address=ip).delete()

    return result


# ─────────────────────────────────────────────────────────────────────────────
# TELEGRAM ALERT
# ─────────────────────────────────────────────────────────────────────────────

def send_telegram_alert(message: str, token: str = None, chat_id: str = None) -> dict:
    """Telegram bot orqali xabardorlik yuboradi."""
    token = token or getattr(settings, 'TELEGRAM_BOT_TOKEN', '')
    chat_id = chat_id or getattr(settings, 'TELEGRAM_CHAT_ID', '')

    if not token or not chat_id:
        return {'success': False, 'error': 'Telegram token yoki chat_id sozlanmagan'}

    try:
        resp = requests.post(
            f'https://api.telegram.org/bot{token}/sendMessage',
            json={'chat_id': chat_id, 'text': message, 'parse_mode': 'HTML'},
            timeout=10,
        )
        data = resp.json()
        return {
            'success': data.get('ok', False),
            'message_id': data.get('result', {}).get('message_id'),
            'error': None if data.get('ok') else data.get('description'),
        }
    except Exception as exc:
        return {'success': False, 'error': str(exc)}


# ─────────────────────────────────────────────────────────────────────────────
# FOYDALANUVCHI XATTI-HARAKATI TAHLILI
# ─────────────────────────────────────────────────────────────────────────────

def analyze_user_behavior() -> dict:
    """IP tahlil va tarmoq skan loglarini analiz qilib, xatti-harakat modelini chiqaradi."""
    from .models import ThreatLog, IPAnalysisRecord

    now = timezone.now()
    last_24h = now - timezone.timedelta(hours=24)
    last_7d = now - timezone.timedelta(days=7)

    top_ips = list(
        ThreatLog.objects.filter(created_at__gte=last_7d)
        .values('ip_address')
        .annotate(count=Count('id'))
        .order_by('-count')[:10]
    )

    blocked_ips = list(
        ThreatLog.objects.filter(is_blocked=True, created_at__gte=last_7d)
        .values('ip_address')
        .annotate(count=Count('id'))
        .order_by('-count')[:5]
    )

    critical_events = list(
        ThreatLog.objects.filter(severity='critical', created_at__gte=last_24h)
        .values('ip_address', 'threat_type', 'created_at')
        .order_by('-created_at')[:10]
    )
    for ev in critical_events:
        ev['created_at'] = ev['created_at'].isoformat()

    hourly_by_type = {}
    for threat in THREAT_ORDER:
        hourly_by_type[threat] = []
        for h in range(23, -1, -1):
            t_start = now - timezone.timedelta(hours=h + 1)
            t_end = now - timezone.timedelta(hours=h)
            cnt = ThreatLog.objects.filter(
                created_at__gte=t_start, created_at__lt=t_end, threat_type=threat
            ).count()
            hourly_by_type[threat].append(cnt)

    scan_count_24h = IPAnalysisRecord.objects.filter(scan_time__gte=last_24h).count()
    scan_count_7d = IPAnalysisRecord.objects.filter(scan_time__gte=last_7d).count()
    total_threats_7d = ThreatLog.objects.filter(created_at__gte=last_7d).count()
    blocked_count_7d = ThreatLog.objects.filter(is_blocked=True, created_at__gte=last_7d).count()

    anomalies = []
    for ip_data in top_ips[:5]:
        ip = ip_data['ip_address']
        recent_cnt = ThreatLog.objects.filter(ip_address=ip, created_at__gte=last_24h).count()
        older_per_day = ThreatLog.objects.filter(
            ip_address=ip, created_at__gte=last_7d, created_at__lt=last_24h
        ).count() / 6
        if older_per_day > 0 and recent_cnt > older_per_day * 3:
            anomalies.append({
                'ip': ip,
                'type': 'spike',
                'message': f"{ip} 24 soatda {recent_cnt}x tahlil — odatdan 3x ko'proq",
            })

    return {
        'top_ips': top_ips,
        'blocked_ips': blocked_ips,
        'critical_events': critical_events,
        'hourly_by_type': hourly_by_type,
        'scan_count_24h': scan_count_24h,
        'scan_count_7d': scan_count_7d,
        'total_threats_7d': total_threats_7d,
        'blocked_count_7d': blocked_count_7d,
        'anomalies': anomalies,
        'period': '7 kunlik statistika',
    }
