import random
from django.conf import settings
from django.utils import timezone
from rest_framework import viewsets, status
from rest_framework.decorators import api_view, action
from rest_framework.response import Response

from .models import ThreatLog, BlockedIP, NetworkDevice
from .serializers import ThreatLogSerializer, BlockedIPSerializer, NetworkDeviceSerializer, AnalyzeRequestSerializer
from .services import analyze_threat, classify_ip, get_dashboard_stats, THREAT_SIGNATURES


# ---------------------------------------------------------------
# Dashboard statistikasi
# ---------------------------------------------------------------
@api_view(['GET'])
def dashboard_stats(request):
    logs = ThreatLog.objects.all()
    stats = get_dashboard_stats(logs)

    # Soatlik trend (oxirgi 12 soat)
    hourly = []
    for i in range(12):
        hourly.append({
            'hour': f"{str(i*2).zfill(2)}:00",
            'threats': random.randint(5, 70),
            'blocked': random.randint(3, 55),
        })

    return Response({
        **stats,
        'accuracy': 96.4,
        'f1_score': 0.949,
        'response_ms': 12,
        'false_positive_rate': 3.6,
        'hourly_trend': hourly,
    })


# ---------------------------------------------------------------
# IP tahlil qilish — asosiy endpoint
# ---------------------------------------------------------------
@api_view(['POST'])
def analyze_ip(request):
    ser = AnalyzeRequestSerializer(data=request.data)
    if not ser.is_valid():
        return Response(ser.errors, status=status.HTTP_400_BAD_REQUEST)

    d = ser.validated_data
    result = analyze_threat(
        ip=d['ip_address'],
        threat_type=d['threat_type'],
        algorithms=d['algorithms'],
        context=d.get('context', ''),
    )

    if 'error' in result:
        return Response(result, status=status.HTTP_400_BAD_REQUEST)

    # Natijani DBga yozish
    log = ThreatLog.objects.create(
        ip_address=d['ip_address'],
        threat_type=d['threat_type'],
        severity=result['severity'],
        probability=result['probability'],
        description=result['recommendation'],
        is_local=result['ip_info']['is_local'],
        device_name=result['ip_info']['device_name'],
        algorithm=', '.join(d['algorithms']),
        raw_data=result,
    )

    return Response({**result, 'log_id': log.id})


# ---------------------------------------------------------------
# Local tarmoq qurilmalarini skanerlash (demo)
# ---------------------------------------------------------------
@api_view(['GET'])
def scan_local_network(request):
    """
    Demo: settings.LOCAL_DEMO_IPS ro'yxatini qaytaradi.
    Haqiqiy loyihada: python-nmap yoki scapy ishlatiladi.
    """
    devices = []
    for ip, info in settings.LOCAL_DEMO_IPS.items():
        ip_data = classify_ip(ip)
        devices.append({
            'ip': ip,
            'name': info['name'],
            'mac': info['mac'],
            'risk': info['risk'],
            'network_type': ip_data['network_type'],
            'status': 'online' if random.random() > 0.2 else 'offline',
            'open_ports': _demo_open_ports(info['risk']),
            'last_seen': timezone.now().isoformat(),
        })
    return Response({'devices': devices, 'total': len(devices)})


def _demo_open_ports(risk: str) -> list:
    base = [22, 80, 443]
    if risk in ('high', 'critical'):
        base += random.sample([8080, 3389, 21, 23, 445, 1433, 3306], k=random.randint(2, 4))
    return sorted(base)


# ---------------------------------------------------------------
# IP reputatsiyasi (AbuseIPDB — faqat public IP lar uchun)
# ---------------------------------------------------------------
@api_view(['GET'])
def ip_reputation(request, ip):
    ip_info = classify_ip(ip)
    if not ip_info['valid']:
        return Response({'error': 'Noto\'g\'ri IP'}, status=400)

    if ip_info['is_local']:
        return Response({
            'ip': ip,
            'is_local': True,
            'message': 'Local IP — AbuseIPDB faqat public IP lar uchun ishlaydi.',
            'local_info': ip_info,
            'abuse_score': 0,
            'reports': 0,
        })

    # Public IP — AbuseIPDB so'rov (real API key kerak)
    api_key = settings.ABUSEIPDB_API_KEY
    if api_key == 'YOUR_API_KEY_HERE':
        return Response({
            'ip': ip,
            'is_local': False,
            'message': 'AbuseIPDB API key sozlanmagan. settings.py da ABUSEIPDB_API_KEY ni kiriting.',
            'demo_abuse_score': random.randint(0, 100),
        })

    try:
        import requests
        resp = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            headers={'Key': api_key, 'Accept': 'application/json'},
            params={'ipAddress': ip, 'maxAgeInDays': 90},
            timeout=5,
        )
        data = resp.json().get('data', {})
        return Response({
            'ip': ip,
            'is_local': False,
            'abuse_score': data.get('abuseConfidenceScore', 0),
            'reports': data.get('totalReports', 0),
            'country': data.get('countryCode', 'N/A'),
            'isp': data.get('isp', 'N/A'),
            'domain': data.get('domain', 'N/A'),
            'last_reported': data.get('lastReportedAt', 'N/A'),
        })
    except Exception as e:
        return Response({'error': str(e)}, status=500)


# ---------------------------------------------------------------
# Tahdid loglari
# ---------------------------------------------------------------
class ThreatLogViewSet(viewsets.ModelViewSet):
    queryset = ThreatLog.objects.all()[:100]
    serializer_class = ThreatLogSerializer

    @action(detail=True, methods=['post'])
    def block(self, request, pk=None):
        log = self.get_object()
        log.is_blocked = True
        log.save()
        BlockedIP.objects.get_or_create(
            ip_address=log.ip_address,
            defaults={'reason': f"Auto-blocked: {log.threat_type} ({log.severity})"},
        )
        return Response({'status': 'blocked', 'ip': log.ip_address})


# ---------------------------------------------------------------
# Bloklangan IP lar
# ---------------------------------------------------------------
class BlockedIPViewSet(viewsets.ModelViewSet):
    queryset = BlockedIP.objects.all()
    serializer_class = BlockedIPSerializer


# ---------------------------------------------------------------
# Real vaqt log generatsiya (demo stream)
# ---------------------------------------------------------------
@api_view(['GET'])
def live_logs(request):
    log_templates = [
        {'level': 'info',  'msg': 'Tarmoq trafigi normal — 2.3 Gbps'},
        {'level': 'warn',  'msg': f"Noodatiy so'rov: {random.choice(list(settings.LOCAL_DEMO_IPS.keys()))} — {random.randint(100,1500)}/min"},
        {'level': 'error', 'msg': f"SQL Injection bloklandi — src: {random.choice(list(settings.LOCAL_DEMO_IPS.keys()))}"},
        {'level': 'info',  'msg': 'Autentifikatsiya muvaffaqiyatli'},
        {'level': 'warn',  'msg': f"Port skanerlash: {random.choice(list(settings.LOCAL_DEMO_IPS.keys()))}"},
        {'level': 'error', 'msg': 'Brute-force hujumi aniqlandi — 500+ urinish'},
        {'level': 'info',  'msg': 'Firewall qoidalari yangilandi'},
        {'level': 'warn',  'msg': 'DDoS anomaliya — trafik 4x yuqori'},
    ]
    logs = []
    for i in range(10):
        t = random.choice(log_templates)
        logs.append({
            'id': i,
            'level': t['level'],
            'message': t['msg'],
            'timestamp': timezone.now().isoformat(),
            'ip': random.choice(list(settings.LOCAL_DEMO_IPS.keys())),
        })
    return Response({'logs': logs})
