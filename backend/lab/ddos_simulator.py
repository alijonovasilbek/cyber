"""
DDoS trafik simulyatori.
Haqiqiy paket yuborish emas — realistic feature qiymatlarini generatsiya qiladi.
Bu machine learning uchun labeled training data hosil qiladi.
"""
import random
from datetime import datetime, timedelta


# ── NORMAL TRAFIK ─────────────────────────────────────────────────────────────
def _normal_sample():
    """Oddiy, kutilgan tarmoq trafik namunasi."""
    return {
        'requests_per_sec':    random.randint(5, 120),
        'bytes_per_sec':       random.randint(5_000, 80_000),
        'unique_src_ips':      random.randint(30, 500),
        'avg_packet_size':     random.randint(300, 1400),
        'syn_flag_ratio':      round(random.uniform(0.01, 0.12), 4),
        'connection_rate':     random.randint(2, 40),
        'tcp_ratio':           round(random.uniform(0.35, 0.70), 4),
        'duration_sec':        random.randint(5, 120),
        'icmp_ratio':          round(random.uniform(0.0, 0.05), 4),
        'avg_flow_duration':   round(random.uniform(0.5, 30.0), 3),
        'label': 0,
    }


# ── HUJUM TURLARI ─────────────────────────────────────────────────────────────
def _syn_flood():
    """
    SYN Flood: serverga ko'p SYN paketi yuborib half-open connection
    to'ldirish. Kichik paketlar, 1-5 manba IP, deyarli barchasi SYN.
    """
    return {
        'requests_per_sec':    random.randint(10_000, 500_000),
        'bytes_per_sec':       random.randint(600_000, 40_000_000),
        'unique_src_ips':      random.randint(1, 8),
        'avg_packet_size':     random.randint(40, 78),
        'syn_flag_ratio':      round(random.uniform(0.90, 1.00), 4),
        'connection_rate':     random.randint(5_000, 200_000),
        'tcp_ratio':           round(random.uniform(0.97, 1.00), 4),
        'duration_sec':        random.randint(1, 15),
        'icmp_ratio':          round(random.uniform(0.0, 0.01), 4),
        'avg_flow_duration':   round(random.uniform(0.001, 0.05), 4),
        'label': 1,
    }


def _udp_flood():
    """
    UDP Flood: katta hajmli UDP datagramlar bilan bandwidth to'ldirish.
    Juda katta bytes/sec, SYN yo'q, ko'p manbalar.
    """
    return {
        'requests_per_sec':    random.randint(50_000, 2_000_000),
        'bytes_per_sec':       random.randint(50_000_000, 1_000_000_000),
        'unique_src_ips':      random.randint(1, 60),
        'avg_packet_size':     random.randint(500, 1500),
        'syn_flag_ratio':      round(random.uniform(0.0, 0.01), 4),
        'connection_rate':     random.randint(10_000, 500_000),
        'tcp_ratio':           round(random.uniform(0.0, 0.05), 4),
        'duration_sec':        random.randint(1, 8),
        'icmp_ratio':          round(random.uniform(0.0, 0.02), 4),
        'avg_flow_duration':   round(random.uniform(0.0001, 0.01), 5),
        'label': 1,
    }


def _http_flood():
    """
    HTTP Flood: botnet orqali ko'p HTTP GET/POST yuborish.
    Ko'p manbalar (botnet), o'rtacha paket hajmi, SYN past.
    """
    return {
        'requests_per_sec':    random.randint(800, 20_000),
        'bytes_per_sec':       random.randint(200_000, 8_000_000),
        'unique_src_ips':      random.randint(100, 2000),
        'avg_packet_size':     random.randint(250, 900),
        'syn_flag_ratio':      round(random.uniform(0.08, 0.30), 4),
        'connection_rate':     random.randint(200, 5_000),
        'tcp_ratio':           round(random.uniform(0.88, 1.00), 4),
        'duration_sec':        random.randint(10, 60),
        'icmp_ratio':          round(random.uniform(0.0, 0.01), 4),
        'avg_flow_duration':   round(random.uniform(0.1, 2.0), 3),
        'label': 1,
    }


def _icmp_flood():
    """
    ICMP (Ping) Flood: katta ping paketlari bilan bandwidth to'ldirish.
    """
    return {
        'requests_per_sec':    random.randint(5_000, 100_000),
        'bytes_per_sec':       random.randint(5_000_000, 500_000_000),
        'unique_src_ips':      random.randint(1, 10),
        'avg_packet_size':     random.randint(64, 1500),
        'syn_flag_ratio':      round(random.uniform(0.0, 0.01), 4),
        'connection_rate':     random.randint(1_000, 50_000),
        'tcp_ratio':           round(random.uniform(0.0, 0.03), 4),
        'duration_sec':        random.randint(1, 20),
        'icmp_ratio':          round(random.uniform(0.85, 1.00), 4),
        'avg_flow_duration':   round(random.uniform(0.001, 0.1), 4),
        'label': 1,
    }


_ATTACK_MAP = {
    'syn_flood':  _syn_flood,
    'udp_flood':  _udp_flood,
    'http_flood': _http_flood,
    'icmp_flood': _icmp_flood,
}


def simulate(mode='normal', count=100, attack_type='syn_flood'):
    """
    DDoS training data generatsiya qilish.

    Parametrlar:
        mode:        'normal' | 'attack' | 'mixed'
        count:       nechta namuna (max 2000)
        attack_type: 'syn_flood' | 'udp_flood' | 'http_flood' | 'icmp_flood'

    Qaytaradi:
        list[dict] — har biri ML feature + label (0/1) + timestamp
    """
    attack_fn = _ATTACK_MAP.get(attack_type, _syn_flood)
    samples = []
    base_time = datetime.now()

    for i in range(min(count, 2000)):
        if mode == 'normal':
            s = _normal_sample()
        elif mode == 'attack':
            s = attack_fn()
        else:  # mixed — 50/50
            s = attack_fn() if random.random() > 0.5 else _normal_sample()

        s['attack_subtype'] = attack_type if s['label'] == 1 else 'normal'
        s['timestamp'] = (base_time + timedelta(milliseconds=i * 15)).isoformat()
        samples.append(s)

    return samples


# Feature nomlari (ML uchun tartib muhim)
FEATURE_NAMES = [
    'requests_per_sec', 'bytes_per_sec', 'unique_src_ips',
    'avg_packet_size', 'syn_flag_ratio', 'connection_rate',
    'tcp_ratio', 'duration_sec', 'icmp_ratio', 'avg_flow_duration',
]
