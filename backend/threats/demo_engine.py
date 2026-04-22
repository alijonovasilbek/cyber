import ipaddress
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from functools import lru_cache
from random import Random

import numpy as np
from django.conf import settings
from django.core.cache import cache
from django.utils import timezone
from sklearn.ensemble import IsolationForest, RandomForestClassifier


SAFE_COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389]
FEATURE_COLUMNS = [
    'request_rate',
    'unique_ports',
    'failed_ratio',
    'packet_size_avg',
    'connection_frequency',
]


def scan_ip_safe(ip: str, ports: list[int] | None = None, timeout: float = 0.35) -> dict:
    target = str(ipaddress.ip_address(ip))
    selected_ports = _normalize_ports(ports)
    selected_timeout = _normalize_timeout(timeout)
    cache_key = f'safe-scan:{target}:{",".join(str(port) for port in selected_ports)}:{selected_timeout:.2f}'
    cached = cache.get(cache_key)
    if cached:
        return {**cached, 'cached': True}

    details = []
    with ThreadPoolExecutor(max_workers=min(len(selected_ports), 10) or 1) as executor:
        futures = {
            executor.submit(_probe_port, target, port, selected_timeout): port
            for port in selected_ports
        }
        for future in as_completed(futures):
            details.append(future.result())

    details.sort(key=lambda item: item['port'])
    payload = {
        'ip': target,
        'requested_ports': selected_ports,
        'open_ports': [item['port'] for item in details if item['open']],
        'port_details': details,
        'timeout_seconds': selected_timeout,
        'scanned_at': timezone.now().isoformat(),
        'cached': False,
    }
    cache.set(payload_key(cache_key), payload, timeout=getattr(settings, 'SAFE_SCAN_CACHE_TTL', 120))
    return payload


def payload_key(cache_key: str) -> str:
    return cache_key


def _probe_port(ip: str, port: int, timeout: float) -> dict:
    import socket

    started = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    is_open = False
    try:
        is_open = sock.connect_ex((ip, port)) == 0
    except OSError:
        is_open = False
    finally:
        sock.close()

    return {
        'port': port,
        'open': is_open,
        'latency_ms': round((time.perf_counter() - started) * 1000, 2),
    }


def _normalize_ports(ports: list[int] | None) -> list[int]:
    if not ports:
        return SAFE_COMMON_PORTS[:10]

    cleaned = []
    for port in ports:
        port_int = int(port)
        if port_int not in SAFE_COMMON_PORTS:
            raise ValueError(f'Port {port_int} safe-scan ro‘yxatida yo‘q.')
        if port_int not in cleaned:
            cleaned.append(port_int)

    if len(cleaned) > 10:
        raise ValueError('Bir so‘rovda maksimal 10 ta port skan qilinadi.')
    return cleaned


def _normalize_timeout(timeout: float) -> float:
    timeout_value = float(timeout)
    if timeout_value <= 0:
        timeout_value = 0.35
    return min(timeout_value, 0.5)


def simulate_traffic(simulation_type: str, ip: str, port: int | None = None, samples: int = 12) -> list[dict]:
    target = str(ipaddress.ip_address(ip))
    profile = simulation_type.strip().lower()
    if profile not in {'ddos', 'brute_force', 'normal'}:
        raise ValueError('Simulation turi normal, ddos yoki brute_force bo‘lishi kerak.')

    sample_count = max(4, min(int(samples), 24))
    seed = f'{target}:{profile}:{timezone.now().strftime("%Y%m%d%H%M")}'
    rng = Random(seed)
    base_time = timezone.now() - timedelta(seconds=sample_count * 5)
    chosen_port = int(port or _default_port_for(profile, rng))

    events = []
    for index in range(sample_count):
        event_time = base_time + timedelta(seconds=index * 5)
        if profile == 'ddos':
            request_count = rng.randint(180, 340)
            failed_attempts = rng.randint(0, max(3, request_count // 18))
            packet_size_avg = round(rng.uniform(720, 1400), 2)
            connection_frequency = round(rng.uniform(18, 40), 2)
        elif profile == 'brute_force':
            request_count = rng.randint(24, 64)
            failed_attempts = rng.randint(max(8, request_count // 2), request_count)
            packet_size_avg = round(rng.uniform(180, 420), 2)
            connection_frequency = round(rng.uniform(4, 12), 2)
        else:
            request_count = rng.randint(6, 24)
            failed_attempts = rng.randint(0, 3)
            packet_size_avg = round(rng.uniform(220, 760), 2)
            connection_frequency = round(rng.uniform(0.8, 4.5), 2)

        events.append({
            'ip': target,
            'port': chosen_port,
            'request_count': request_count,
            'failed_attempts': min(failed_attempts, request_count),
            'packet_size_avg': packet_size_avg,
            'connection_frequency': connection_frequency,
            'traffic_type': profile,
            'timestamp': event_time.isoformat(),
            'source': 'simulator',
        })
    return events


def _default_port_for(profile: str, rng: Random) -> int:
    if profile == 'ddos':
        return rng.choice([80, 443, 53])
    if profile == 'brute_force':
        return rng.choice([22, 23, 3389, 445])
    return rng.choice([53, 80, 110, 143, 443])


def engineer_features(logs: list[dict]) -> dict:
    if not logs:
        raise ValueError('Feature extraction uchun kamida bitta log kerak.')

    ordered = sorted(logs, key=lambda item: item['timestamp'])
    timestamps = [datetime.fromisoformat(item['timestamp']) for item in ordered]
    seconds_span = max((timestamps[-1] - timestamps[0]).total_seconds(), 5)
    total_requests = sum(int(item['request_count']) for item in ordered)
    total_failed = sum(int(item['failed_attempts']) for item in ordered)
    packet_sizes = [float(item.get('packet_size_avg', 0)) for item in ordered]
    frequencies = [float(item.get('connection_frequency', 0)) for item in ordered]
    unique_ports = len({int(item['port']) for item in ordered})

    return {
        'request_rate': round(total_requests / seconds_span, 4),
        'unique_ports': float(unique_ports),
        'failed_ratio': round(total_failed / max(total_requests, 1), 4),
        'packet_size_avg': round(statistics.fmean(packet_sizes), 2),
        'connection_frequency': round(statistics.fmean(frequencies), 2),
        'total_requests': total_requests,
        'total_failed_attempts': total_failed,
        'event_count': len(ordered),
        'window_seconds': seconds_span,
    }


@lru_cache(maxsize=1)
def get_behavior_models() -> dict:
    rng = Random(1337)
    feature_rows = []
    labels = []
    normal_rows = []

    for _ in range(420):
        row = _synthetic_feature_row(rng, 'normal')
        feature_rows.append(row)
        labels.append('normal')
        normal_rows.append(row)

    for attack_type in ('ddos', 'brute_force'):
        for _ in range(320):
            row = _synthetic_feature_row(rng, attack_type)
            feature_rows.append(row)
            labels.append(attack_type)

    x_train = np.array(feature_rows, dtype=float)
    y_train = np.array(labels)
    normal_train = np.array(normal_rows, dtype=float)

    forest = RandomForestClassifier(n_estimators=160, max_depth=8, random_state=42)
    anomaly = IsolationForest(random_state=42, contamination=0.18)
    forest.fit(x_train, y_train)
    anomaly.fit(normal_train)
    return {'forest': forest, 'anomaly': anomaly, 'classes': list(forest.classes_)}


def _synthetic_feature_row(rng: Random, label: str) -> list[float]:
    if label == 'ddos':
        return [
            rng.uniform(18, 52),
            rng.uniform(1, 3),
            rng.uniform(0.0, 0.18),
            rng.uniform(700, 1450),
            rng.uniform(14, 42),
        ]
    if label == 'brute_force':
        return [
            rng.uniform(3, 10),
            rng.uniform(1, 2),
            rng.uniform(0.45, 0.98),
            rng.uniform(140, 480),
            rng.uniform(3.5, 14),
        ]
    return [
        rng.uniform(0.15, 2.5),
        rng.uniform(1, 4),
        rng.uniform(0.0, 0.2),
        rng.uniform(180, 820),
        rng.uniform(0.2, 4.8),
    ]


def analyze_traffic(logs: list[dict]) -> dict:
    features = engineer_features(logs)
    feature_vector = np.array([[float(features[column]) for column in FEATURE_COLUMNS]], dtype=float)
    models = get_behavior_models()
    probabilities = models['forest'].predict_proba(feature_vector)[0]
    classes = models['classes']
    predicted_idx = int(np.argmax(probabilities))
    attack_type = classes[predicted_idx]
    rf_confidence = float(probabilities[predicted_idx])

    anomaly_raw = float(models['anomaly'].decision_function(feature_vector)[0])
    anomaly_score = round(1 - _normalize(anomaly_raw, -0.35, 0.22), 4)

    if attack_type == 'normal' and anomaly_score > 0.68:
        if features['failed_ratio'] > 0.45:
            attack_type = 'brute_force'
        elif features['request_rate'] > 8:
            attack_type = 'ddos'
        else:
            attack_type = 'anomaly'

    confidence = round(min(0.99, 0.72 * rf_confidence + 0.28 * anomaly_score) * 100, 2)
    threat_level = _threat_level_for(features, attack_type, confidence)

    return {
        'threat_level': threat_level.upper(),
        'attack_type': _display_attack_type(attack_type),
        'confidence': confidence,
        'features': features,
        'model_scores': {
            'random_forest': round(rf_confidence, 4),
            'isolation_forest': anomaly_score,
        },
        'signals': _build_signals(features, attack_type),
    }


def _normalize(value: float, lower: float, upper: float) -> float:
    if upper <= lower:
        return 0.0
    return min(max((value - lower) / (upper - lower), 0.0), 1.0)


def _threat_level_for(features: dict, attack_type: str, confidence: float) -> str:
    if attack_type == 'ddos' and (features['request_rate'] > 12 or confidence >= 80):
        return 'high'
    if attack_type == 'brute_force' and (features['failed_ratio'] > 0.55 or confidence >= 75):
        return 'high'
    if attack_type == 'anomaly':
        return 'medium'
    if attack_type == 'normal' and confidence < 55:
        return 'low'
    return 'medium'


def _display_attack_type(attack_type: str) -> str:
    mapping = {
        'normal': 'Normal',
        'ddos': 'DDoS',
        'brute_force': 'BruteForce',
        'anomaly': 'Anomaly',
    }
    return mapping.get(attack_type, attack_type.title())


def _build_signals(features: dict, attack_type: str) -> list[str]:
    signals = [
        f"Request rate: {features['request_rate']}/s",
        f"Unique ports: {int(features['unique_ports'])}",
        f"Failed ratio: {round(features['failed_ratio'] * 100, 1)}%",
    ]
    if attack_type == 'ddos':
        signals.append('Burst traffic va yuqori connection frequency kuzatildi.')
    if attack_type == 'brute_force':
        signals.append('Authentication failure patterni brute-forcega mos.')
    if attack_type == 'anomaly':
        signals.append('Normal profilga nisbatan statistik og‘ish aniqlandi.')
    return signals


def get_cached_reputation(ip: str) -> dict:
    target = str(ipaddress.ip_address(ip))
    cache_key = f'intel:abuse:{target}'
    cached = cache.get(cache_key)
    if cached:
        return {**cached, 'cached': True}

    from .services import get_ip_reputation

    data = get_ip_reputation(target)
    cache.set(cache_key, data, timeout=getattr(settings, 'THREAT_INTEL_CACHE_TTL', 900))
    return {**data, 'cached': False}


def predict_next_window(ip: str | None = None) -> dict:
    from .models import ThreatLog, TrafficEventLog

    now = timezone.now()
    window_start = now - timedelta(minutes=30)
    traffic_logs = TrafficEventLog.objects.filter(created_at__gte=window_start)
    threat_logs = ThreatLog.objects.filter(created_at__gte=window_start)

    if ip:
        target = str(ipaddress.ip_address(ip))
        traffic_logs = traffic_logs.filter(ip_address=target)
        threat_logs = threat_logs.filter(ip_address=target)
    else:
        target = 'global'

    traffic_rows = list(
        traffic_logs.values('traffic_type', 'request_count', 'failed_attempts', 'packet_size_avg', 'connection_frequency', 'port')
    )

    if not traffic_rows:
        return {
            'scope': target,
            'predicted_threat_level': 'LOW',
            'predicted_attack_type': 'Normal',
            'confidence': 52.0,
            'next_window_minutes': 5,
            'reasoning': ['Yetarli recent traffic yo‘q, baseline xavf past deb olindi.'],
        }

    synthetic_logs = [
        {
            'ip': target if target != 'global' else '127.0.0.1',
            'port': row['port'],
            'request_count': row['request_count'],
            'failed_attempts': row['failed_attempts'],
            'packet_size_avg': row['packet_size_avg'],
            'connection_frequency': row['connection_frequency'],
            'timestamp': (now - timedelta(seconds=index * 5)).isoformat(),
        }
        for index, row in enumerate(traffic_rows[:30], start=1)
    ]
    analysis = analyze_traffic(synthetic_logs)
    recent_severity = _recent_severity_score(threat_logs)
    confidence = round(min(99.0, analysis['confidence'] * 0.7 + recent_severity * 30), 2)
    predicted_level = _promote_level(analysis['threat_level'], recent_severity)

    reasoning = list(analysis['signals'])
    if recent_severity > 0.5:
        reasoning.append('So‘nggi threat loglarda high/critical holatlar ko‘paygan.')

    return {
        'scope': target,
        'predicted_threat_level': predicted_level,
        'predicted_attack_type': analysis['attack_type'],
        'confidence': confidence,
        'next_window_minutes': 5,
        'reasoning': reasoning[:5],
    }


def _recent_severity_score(threat_logs) -> float:
    score_map = {'critical': 1.0, 'high': 0.75, 'medium': 0.45, 'low': 0.2}
    scores = [score_map.get(item.severity, 0.2) for item in threat_logs[:20]]
    return round(statistics.fmean(scores), 4) if scores else 0.0


def _promote_level(current_level: str, recent_severity: float) -> str:
    level = current_level.upper()
    if recent_severity >= 0.7:
        return 'HIGH'
    if recent_severity >= 0.45 and level == 'LOW':
        return 'MEDIUM'
    return level
