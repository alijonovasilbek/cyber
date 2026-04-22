from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import viewsets, status
from rest_framework.decorators import api_view, action
from rest_framework.response import Response
from django.utils import timezone

from .models import BlockedIP, ConnectionProfile, NetworkDevice, ScanSession, ThreatLog
from .network_services import connect_to_wifi, encrypt_secret, get_wifi_status, list_network_interfaces, run_profile_scan
from .serializers import (
    AnalyzeRequestSerializer,
    AnalyzeResponseSerializer,
    BlockedIPSerializer,
    ConnectionProfileSerializer,
    ConnectionProfileWriteSerializer,
    DashboardStatsSerializer,
    IPReputationSerializer,
    LiveLogsResponseSerializer,
    NetworkDeviceSerializer,
    NetworkInterfacesResponseSerializer,
    NetworkScanResponseSerializer,
    RunScanRequestSerializer,
    ScanSessionSerializer,
    ThreatLogSerializer,
    WifiConnectRequestSerializer,
    WifiStatusSerializer,
)
from .services import (
    analyze_threat,
    build_live_logs,
    discover_local_devices,
    get_dashboard_stats,
    get_ip_reputation,
)


# ---------------------------------------------------------------
# Dashboard statistikasi
# ---------------------------------------------------------------
@extend_schema(
    tags=['Dashboard'],
    responses=DashboardStatsSerializer,
)
@api_view(['GET'])
def dashboard_stats(request):
    logs = ThreatLog.objects.all()
    stats = get_dashboard_stats(logs)
    return Response(stats)


# ---------------------------------------------------------------
# IP tahlil qilish — asosiy endpoint
# ---------------------------------------------------------------
@extend_schema(
    tags=['Analysis'],
    request=AnalyzeRequestSerializer,
    responses={200: AnalyzeResponseSerializer},
)
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
# Local tarmoq qurilmalarini skanerlash
# ---------------------------------------------------------------
@extend_schema(
    tags=['Network'],
    responses=NetworkScanResponseSerializer,
)
@api_view(['GET'])
def scan_local_network(request):
    devices = discover_local_devices()

    for device in devices:
        NetworkDevice.objects.update_or_create(
            ip_address=device['ip'],
            defaults={
                'mac_address': device.get('mac', '')[:17],
                'device_name': device['name'][:100],
                'risk_level': device['risk'],
                'is_trusted': device['risk'] in ('low', 'medium'),
            },
        )

    return Response({'devices': devices, 'total': len(devices)})


@extend_schema(
    tags=['Network'],
    responses=NetworkInterfacesResponseSerializer,
)
@api_view(['GET'])
def network_interfaces(request):
    interfaces = list_network_interfaces()
    return Response({'interfaces': interfaces, 'total': len(interfaces)})


@extend_schema(
    tags=['Network'],
    responses=WifiStatusSerializer,
)
@api_view(['GET'])
def wifi_status(request):
    return Response(get_wifi_status())


@extend_schema(
    tags=['Network'],
    request=WifiConnectRequestSerializer,
    responses=WifiStatusSerializer,
)
@api_view(['POST'])
def wifi_connect(request):
    serializer = WifiConnectRequestSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    try:
        data = connect_to_wifi(**serializer.validated_data)
        return Response(data)
    except Exception as exc:
        return Response({'error': str(exc)}, status=status.HTTP_400_BAD_REQUEST)


# ---------------------------------------------------------------
# IP reputatsiyasi (AbuseIPDB — faqat public IP lar uchun)
# ---------------------------------------------------------------
@extend_schema(
    tags=['Reputation'],
    parameters=[
        OpenApiParameter(
            name='ip',
            location=OpenApiParameter.PATH,
            required=True,
            type=str,
            description='Tekshiriladigan IP manzil',
        )
    ],
    responses=IPReputationSerializer,
)
@api_view(['GET'])
def ip_reputation(request, ip):
    try:
        data = get_ip_reputation(ip)
        if 'error' in data:
            return Response(data, status=400)
        return Response(data)
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


class ConnectionProfileViewSet(viewsets.ModelViewSet):
    queryset = ConnectionProfile.objects.all()

    def get_serializer_class(self):
        if self.action in ('create', 'update', 'partial_update'):
            return ConnectionProfileWriteSerializer
        return ConnectionProfileSerializer

    def perform_create(self, serializer):
        secret = serializer.validated_data.pop('secret', '')
        serializer.save(secret_encrypted=encrypt_secret(secret))

    def perform_update(self, serializer):
        secret = serializer.validated_data.pop('secret', None)
        instance = serializer.save()
        if secret is not None:
            instance.secret_encrypted = encrypt_secret(secret)
            instance.save(update_fields=['secret_encrypted', 'updated_at'])

    @extend_schema(
        request=RunScanRequestSerializer,
        responses=ScanSessionSerializer,
    )
    @action(detail=True, methods=['post'])
    def scan(self, request, pk=None):
        profile = self.get_object()
        serializer = RunScanRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        payload = serializer.validated_data

        session = ScanSession.objects.create(
            profile=profile,
            status='running',
            network_name=payload.get('network_name', ''),
            interface_name=payload.get('interface_name', ''),
            started_at=timezone.now(),
        )

        try:
            result = run_profile_scan(
                profile,
                interface_name=payload.get('interface_name', ''),
                network_name=payload.get('network_name', ''),
            )
            session.status = 'success'
            session.summary = result.get('hostname') or result.get('device_description') or f'{profile.profile_type.upper()} scan bajarildi'
            session.result = result
            profile.last_used_at = timezone.now()
            profile.save(update_fields=['last_used_at'])
        except Exception as exc:
            session.status = 'failed'
            partial_result = getattr(exc, 'result', {}) or {}
            session.summary = partial_result.get('summary') or partial_result.get('hostname') or 'Scan xatolik bilan tugadi'
            session.result = partial_result
            session.error_message = str(exc)

        session.finished_at = timezone.now()
        session.save()
        return Response(ScanSessionSerializer(session).data)


class ScanSessionViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = ScanSession.objects.select_related('profile').all()[:100]
    serializer_class = ScanSessionSerializer


# ---------------------------------------------------------------
# Real vaqt log oqimi
# ---------------------------------------------------------------
@extend_schema(
    tags=['Logs'],
    responses=LiveLogsResponseSerializer,
)
@api_view(['GET'])
def live_logs(request):
    logs = build_live_logs()
    return Response({'logs': logs})
