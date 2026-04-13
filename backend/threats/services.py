import random
import ipaddress
from django.conf import settings

# ---------------------------------------------------------------
# IP manzilni tahlil qilish
# ---------------------------------------------------------------

def classify_ip(ip: str) -> dict:
    """IP manzilni local/public deb aniqlaydi va asosiy ma'lumot qaytaradi."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {'valid': False, 'error': 'Noto\'g\'ri IP format'}

    is_local = addr.is_private or addr.is_loopback or addr.is_link_local

    # Demo local qurilmalar ro'yxatidan tekshirish
    local_info = settings.LOCAL_DEMO_IPS.get(ip, {})

    return {
        'valid': True,
        'ip': ip,
        'is_local': is_local,
        'is_loopback': addr.is_loopback,
        'network_type': _get_network_type(ip),
        'device_name': local_info.get('name', 'Noma\'lum qurilma' if is_local else 'Tashqi IP'),
        'mac_address': local_info.get('mac', 'N/A'),
        'known_risk': local_info.get('risk', 'unknown'),
    }


def _get_network_type(ip: str) -> str:
    """Tarmoq turini qaytaradi."""
    if ip.startswith('192.168.'):
        return 'LAN (uy/ofis tarmoqi)'
    elif ip.startswith('10.'):
        return 'LAN (korporativ tarmoq)'
    elif ip.startswith('172.16.') or ip.startswith('172.31.'):
        return 'LAN (virtual tarmoq)'
    elif ip.startswith('127.'):
        return 'Loopback (localhost)'
    else:
        return 'WAN (internet)'


# ---------------------------------------------------------------
# ML model simulyatsiyasi (haqiqiy sklearn o'rniga demo)
# ---------------------------------------------------------------

ALGORITHM_ACCURACY = {
    'Random Forest':    0.964,
    'XGBoost':          0.951,
    'LSTM':             0.941,
    'SVM':              0.912,
    'Isolation Forest': 0.874,
    'Autoencoder':      0.889,
    'Naive Bayes':      0.821,
    'CNN':              0.931,
}

THREAT_SIGNATURES = {
    'ddos': {
        'name': 'DDoS hujumi',
        'indicators': ['Yuqori paket hajmi', 'Bir manbadan ko\'p so\'rov', 'UDP flood'],
        'base_prob': 0.85,
        'severity': 'critical',
        'mitigation': ['Rate limiting yoqing', 'IP ni bloklang', 'CDN / Anycast ishlatish'],
    },
    'sqli': {
        'name': 'SQL Injection',
        'indicators': ["Maxsus belgilar (', --, ;)", 'G\'ayrioddiy DB so\'rovlari', 'Katta chiqish hajmi'],
        'base_prob': 0.91,
        'severity': 'critical',
        'mitigation': ['WAF qoidasi qo\'shing', 'Parametrlangan so\'rovlar', 'DB loglarini tekshiring'],
    },
    'brute_force': {
        'name': 'Brute Force',
        'indicators': ['Ko\'p muvaffaqiyatsiz login', 'Bir IP dan ketma-ket urinish', 'SSH/RDP portlari'],
        'base_prob': 0.88,
        'severity': 'high',
        'mitigation': ['IP ni 24 soat bloklang', 'Fail2ban sozlang', '2FA yoqing'],
    },
    'phishing': {
        'name': 'Phishing',
        'indicators': ['Noma\'lum domen', 'SSL sertifikat muammo', 'Redirect zanjiri'],
        'base_prob': 0.79,
        'severity': 'high',
        'mitigation': ['Domenni bloklang', 'Foydalanuvchilarni ogohlantiring', 'DNS blacklist yangilang'],
    },
    'ransomware': {
        'name': 'Ransomware',
        'indicators': ['Ommaviy fayl shifrlash', 'CPU/disk oshishi', '.locked kengaytmalar'],
        'base_prob': 0.93,
        'severity': 'critical',
        'mitigation': ['Tizimni darhol izolyatsiya qiling', 'Backup dan tiklang', 'Forensics boshlang'],
    },
    'port_scan': {
        'name': 'Port Skanerlash',
        'indicators': ['Ko\'p port ulanish urinishi', 'SYN paketlar', 'Nmap imzosi'],
        'base_prob': 0.76,
        'severity': 'medium',
        'mitigation': ['IP ni vaqtinchalik bloklang', 'Firewall loglarini tekshiring', 'IDS qoidasini qo\'shing'],
    },
    'mitm': {
        'name': 'Man-in-the-Middle',
        'indicators': ['ARP spoofing', 'SSL strip', 'Noodatiy sertifikat'],
        'base_prob': 0.72,
        'severity': 'high',
        'mitigation': ['ARP monitoring yoqing', 'HTTPS majburiy qiling', 'Tarmoq segmentatsiya'],
    },
    'apt': {
        'name': 'APT (Murakkab doimiy tahdid)',
        'indicators': ['Uzoq muddatli yashirin faollik', 'Noma\'lum protokol', 'Kichik anomaliyalar'],
        'base_prob': 0.81,
        'severity': 'critical',
        'mitigation': ['Chuqur forensik tahlil', 'Tarmoqni izolyatsiya', 'Incident response jarayoni'],
    },
}


def analyze_threat(ip: str, threat_type: str, algorithms: list, context: str = '') -> dict:
    """
    Asosiy tahlil funksiyasi.
    Local IP lar uchun qo'shimcha kontekst beradi.
    """
    ip_info = classify_ip(ip)
    if not ip_info['valid']:
        return {'error': ip_info['error']}

    sig = THREAT_SIGNATURES.get(threat_type, THREAT_SIGNATURES['port_scan'])

    # Local IP ga xos xavf hisoblash
    risk_boost = 0.0
    local_context = ''
    if ip_info['is_local']:
        known_risk = ip_info.get('known_risk', 'low')
        if known_risk == 'critical':
            risk_boost = 0.12
            local_context = f"⚠ Bu qurilma ({ip_info['device_name']}) avval KRITIK xavfli deb belgilangan!"
        elif known_risk == 'high':
            risk_boost = 0.07
            local_context = f"Bu qurilma ({ip_info['device_name']}) yuqori xavf ro'yxatida."
        else:
            local_context = f"Ichki tarmoq qurilmasi: {ip_info['device_name']}"

    # Algoritmlar yig'indi ehtimolligi
    algo_scores = {}
    for algo in algorithms:
        acc = ALGORITHM_ACCURACY.get(algo, 0.80)
        noise = random.uniform(-0.03, 0.03)
        score = min(0.99, sig['base_prob'] + risk_boost + noise)
        algo_scores[algo] = round(score * acc, 3)

    final_prob = round(sum(algo_scores.values()) / max(len(algo_scores), 1), 3) if algo_scores else sig['base_prob']

    # Xavf darajasini ehtimolga qarab aniqlash
    if final_prob >= 0.90:
        severity = 'critical'
    elif final_prob >= 0.75:
        severity = 'high'
    elif final_prob >= 0.55:
        severity = 'medium'
    else:
        severity = 'low'

    return {
        'ip': ip,
        'ip_info': ip_info,
        'threat_type': threat_type,
        'threat_name': sig['name'],
        'probability': final_prob,
        'probability_pct': f"{round(final_prob * 100, 1)}%",
        'severity': severity,
        'indicators': sig['indicators'],
        'mitigation': sig['mitigation'],
        'algorithm_scores': algo_scores,
        'local_context': local_context,
        'context': context,
        'recommendation': _get_recommendation(severity, ip_info['is_local']),
    }


def _get_recommendation(severity: str, is_local: bool) -> str:
    prefix = "Ichki tarmoq: " if is_local else "Tashqi IP: "
    recs = {
        'critical': prefix + "Darhol bloklash va incident yaratish tavsiya etiladi.",
        'high':     prefix + "Kuchaytirilgan monitoring va tezkor tekshiruv kerak.",
        'medium':   prefix + "Monitoring kuchaytiring, qo'shimcha tahlil o'tkazing.",
        'low':      prefix + "Oddiy monitoring yetarli, loglarda kuzatib boring.",
    }
    return recs.get(severity, "Qo'shimcha tahlil tavsiya etiladi.")


def get_dashboard_stats(logs) -> dict:
    """Dashboard uchun statistika."""
    total = logs.count()
    blocked = logs.filter(is_blocked=True).count()
    critical = logs.filter(severity='critical').count()

    threat_dist = {}
    for log in logs:
        threat_dist[log.threat_type] = threat_dist.get(log.threat_type, 0) + 1

    return {
        'total_threats': total,
        'blocked': blocked,
        'critical': critical,
        'block_rate': round(blocked / total * 100, 1) if total else 0,
        'threat_distribution': threat_dist,
    }
