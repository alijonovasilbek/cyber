from django.utils import timezone
from django.utils.dateparse import parse_datetime
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import status, viewsets
from rest_framework.decorators import action, api_view
from rest_framework.response import Response

from .demo_engine import (
    analyze_traffic,
    get_cached_reputation,
    predict_next_window,
    scan_ip_safe,
    simulate_traffic,
)
from .models import (
    BlockedIP,
    ConnectionProfile,
    IPAnalysisRecord,
    NetworkDevice,
    ScanSession,
    ThreatLog,
    TrafficEventLog,
)
from .network_services import (
    connect_to_wifi,
    encrypt_secret,
    get_wifi_status,
    list_network_interfaces,
    run_profile_scan,
)
from .realtime import get_recent_events, publish_event
from .security import guard_request
from .serializers import (
    AnalyzeRequestSerializer,
    AnalyzeResponseSerializer,
    BehaviorAnalyzeRequestSerializer,
    BlockedIPSerializer,
    ConnectionProfileSerializer,
    ConnectionProfileWriteSerializer,
    DashboardStatsSerializer,
    IPAnalysisRecordSerializer,
    IPReputationSerializer,
    LiveLogsResponseSerializer,
    NetworkInterfacesResponseSerializer,
    NetworkScanResponseSerializer,
    RunScanRequestSerializer,
    SafeScanRequestSerializer,
    SafeScanResponseSerializer,
    ScanSessionSerializer,
    SimulateTrafficRequestSerializer,
    SimulateTrafficResponseSerializer,
    TargetIntelRequestSerializer,
    ThreatLogSerializer,
    ThreatPredictionRequestSerializer,
    ThreatPredictionResponseSerializer,
    TrafficAnalysisSerializer,
    TrafficEventLogSerializer,
    WifiConnectRequestSerializer,
    WifiStatusSerializer,
)
from .services import (
    analyze_threat,
    build_live_logs,
    discover_local_devices,
    get_dashboard_stats,
    get_ip_reputation,
    get_target_intel,
)


THREAT_TYPE_MAP = {
    'DDoS': 'ddos',
    'BruteForce': 'brute_force',
    'Normal': 'anomaly',
    'Anomaly': 'anomaly',
}


@extend_schema(tags=['Dashboard'], responses=DashboardStatsSerializer)
@api_view(['GET'])
def dashboard_stats(request):
    logs = ThreatLog.objects.all()
    stats = get_dashboard_stats(logs)
    return Response(stats)


@extend_schema(
    tags=['Analysis'],
    request=AnalyzeRequestSerializer,
    responses={200: AnalyzeResponseSerializer},
)
@api_view(['POST'])
def analyze_ip(request):
    if 'threat_type' in request.data:
        serializer = AnalyzeRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        data = serializer.validated_data
        result = analyze_threat(
            ip=data['ip_address'],
            threat_type=data['threat_type'],
            algorithms=data['algorithms'],
            context=data.get('context', ''),
        )
        if 'error' in result:
            return Response(result, status=status.HTTP_400_BAD_REQUEST)

        log = ThreatLog.objects.create(
            ip_address=data['ip_address'],
            threat_type=data['threat_type'],
            severity=result['severity'],
            probability=result['probability'],
            description=result['recommendation'],
            is_local=result['ip_info']['is_local'],
            device_name=result['ip_info']['device_name'],
            algorithm=', '.join(data['algorithms']),
            raw_data=result,
        )
        payload = {**result, 'log_id': log.id}
        publish_event('threat.detected', payload)
        return Response(payload)

    guard_error = guard_request(request, 'analyze-behavior')
    if guard_error:
        return guard_error

    serializer = BehaviorAnalyzeRequestSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    data = serializer.validated_data

    logs_qs = TrafficEventLog.objects.all()
    if data.get('event_ids'):
        logs_qs = logs_qs.filter(id__in=data['event_ids'])
    if data.get('ip_address'):
        logs_qs = logs_qs.filter(ip_address=data['ip_address'])
    logs_qs = logs_qs.order_by('-created_at')[:24]

    logs = [_serialize_traffic_row(row) for row in reversed(list(logs_qs))]
    if not logs:
        return Response({'detail': 'Tahlil uchun traffic log topilmadi.'}, status=status.HTTP_404_NOT_FOUND)

    analysis = analyze_traffic(logs)
    threat_log = _create_behavior_threat_log(data.get('ip_address') or logs[0]['ip'], analysis, logs)
    blocked = False
    if data.get('auto_response'):
        blocked = _simulate_block(threat_log.ip_address, threat_log, analysis)

    payload = {**analysis, 'log_id': threat_log.id, 'blocked': blocked}
    publish_event('threat.detected', payload)
    return Response(payload)


@extend_schema(tags=['Network'], responses=NetworkScanResponseSerializer)
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


@extend_schema(tags=['Network'], responses=NetworkInterfacesResponseSerializer)
@api_view(['GET'])
def network_interfaces(request):
    interfaces = list_network_interfaces()
    return Response({'interfaces': interfaces, 'total': len(interfaces)})


@extend_schema(tags=['Network'], responses=WifiStatusSerializer)
@api_view(['GET'])
def wifi_status(request):
    return Response(get_wifi_status())


@extend_schema(tags=['Network'], request=WifiConnectRequestSerializer, responses=WifiStatusSerializer)
@api_view(['POST'])
def wifi_connect(request):
    serializer = WifiConnectRequestSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    try:
        data = connect_to_wifi(**serializer.validated_data)
        return Response(data)
    except Exception as exc:
        return Response({'error': str(exc)}, status=status.HTTP_400_BAD_REQUEST)


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
    except Exception as exc:
        return Response({'error': str(exc)}, status=500)


@extend_schema(tags=['Analysis'], request=TargetIntelRequestSerializer)
@api_view(['POST'])
def target_intel(request):
    serializer = TargetIntelRequestSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    try:
        data = get_target_intel(serializer.validated_data['target'])
        return Response(data)
    except ValueError as exc:
        return Response({'error': str(exc)}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as exc:
        return Response({'error': str(exc)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema(tags=['Collector'], request=SafeScanRequestSerializer, responses=SafeScanResponseSerializer)
@api_view(['POST'])
def safe_scan_ip(request):
    guard_error = guard_request(request, 'scan-ip')
    if guard_error:
        return guard_error

    serializer = SafeScanRequestSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    payload = scan_ip_safe(
        ip=serializer.validated_data['ip_address'],
        ports=serializer.validated_data.get('ports'),
        timeout=serializer.validated_data.get('timeout', 0.35),
    )
    reputation = get_cached_reputation(serializer.validated_data['ip_address'])
    record = IPAnalysisRecord.objects.create(
        ip_address=payload['ip'],
        requested_ports=payload['requested_ports'],
        open_ports=payload['open_ports'],
        timeout_seconds=payload['timeout_seconds'],
        features={},
        threat_level='low',
        attack_type='normal',
        confidence=0.0,
        intel=reputation,
        notes='Safe scan collector natijasi',
    )
    payload['analysis_id'] = record.id
    publish_event('scan.completed', payload)
    return Response(payload)


@extend_schema(tags=['Simulator'], request=SimulateTrafficRequestSerializer, responses=SimulateTrafficResponseSerializer)
@api_view(['POST'])
def simulate_traffic_view(request):
    guard_error = guard_request(request, 'simulate-traffic')
    if guard_error:
        return guard_error

    serializer = SimulateTrafficRequestSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    data = serializer.validated_data

    logs = simulate_traffic(
        simulation_type=data['simulation_type'],
        ip=data['ip_address'],
        port=data.get('port'),
        samples=data.get('samples', 12),
    )
    created_rows = [
        TrafficEventLog(
            ip_address=item['ip'],
            port=item['port'],
            traffic_type=item['traffic_type'],
            request_count=item['request_count'],
            failed_attempts=item['failed_attempts'],
            packet_size_avg=item['packet_size_avg'],
            connection_frequency=item['connection_frequency'],
            source=item['source'],
            metadata={'timestamp': item['timestamp']},
            created_at=parse_datetime(item['timestamp']) or timezone.now(),
        )
        for item in logs
    ]
    TrafficEventLog.objects.bulk_create(created_rows)

    analysis = analyze_traffic(logs)
    threat_log = _create_behavior_threat_log(data['ip_address'], analysis, logs)
    blocked = _simulate_block(data['ip_address'], threat_log, analysis) if data.get('auto_response') else False
    reputation = get_cached_reputation(data['ip_address'])

    publish_event('traffic.simulated', {'logs': logs[:5], 'count': len(logs), 'ip': data['ip_address']})
    publish_event('threat.detected', {**analysis, 'ip': data['ip_address'], 'blocked': blocked})

    return Response({
        'logs': logs,
        'analysis': {**analysis, 'log_id': threat_log.id, 'blocked': blocked},
        'reputation': reputation,
        'blocked': blocked,
    })


@extend_schema(tags=['Prediction'], request=ThreatPredictionRequestSerializer, responses=ThreatPredictionResponseSerializer)
@api_view(['POST'])
def predict_threat(request):
    guard_error = guard_request(request, 'predict')
    if guard_error:
        return guard_error

    serializer = ThreatPredictionRequestSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    payload = predict_next_window(serializer.validated_data.get('ip_address'))
    publish_event('prediction.ready', payload)
    return Response(payload)


class ThreatLogViewSet(viewsets.ModelViewSet):
    queryset = ThreatLog.objects.all().order_by('-created_at')
    serializer_class = ThreatLogSerializer

    @action(detail=True, methods=['post'])
    def block(self, request, pk=None):
        log = self.get_object()
        log.is_blocked = True
        log.save(update_fields=['is_blocked'])
        BlockedIP.objects.get_or_create(
            ip_address=log.ip_address,
            defaults={'reason': f"Auto-blocked: {log.threat_type} ({log.severity})"},
        )
        payload = {'status': 'blocked', 'ip': log.ip_address, 'threat_log_id': log.id}
        publish_event('response.blocked', payload)
        return Response(payload)


class TrafficEventLogViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = TrafficEventLog.objects.all().order_by('-created_at')
    serializer_class = TrafficEventLogSerializer


class IPAnalysisRecordViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = IPAnalysisRecord.objects.all().order_by('-created_at')
    serializer_class = IPAnalysisRecordSerializer


class BlockedIPViewSet(viewsets.ModelViewSet):
    queryset = BlockedIP.objects.all().order_by('-blocked_at')
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

    @extend_schema(request=RunScanRequestSerializer, responses=ScanSessionSerializer)
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
            publish_event('profile.scan.success', {'session_id': session.id, 'result': result})
        except Exception as exc:
            session.status = 'failed'
            partial_result = getattr(exc, 'result', {}) or {}
            session.summary = partial_result.get('summary') or partial_result.get('hostname') or 'Scan xatolik bilan tugadi'
            session.result = partial_result
            session.error_message = str(exc)
            publish_event('profile.scan.failed', {
                'session_id': session.id,
                'summary': session.summary,
                'error': session.error_message,
            })

        session.finished_at = timezone.now()
        session.save()
        return Response(ScanSessionSerializer(session).data)


class ScanSessionViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = ScanSession.objects.select_related('profile').all().order_by('-created_at')
    serializer_class = ScanSessionSerializer


@extend_schema(tags=['Logs'], responses=LiveLogsResponseSerializer)
@api_view(['GET'])
def live_logs(request):
    logs = build_live_logs()
    return Response({'logs': logs, 'events': get_recent_events(20)})


def _serialize_traffic_row(row: TrafficEventLog) -> dict:
    source_timestamp = row.metadata.get('timestamp') if isinstance(row.metadata, dict) else None
    return {
        'ip': row.ip_address,
        'port': row.port,
        'request_count': row.request_count,
        'failed_attempts': row.failed_attempts,
        'packet_size_avg': row.packet_size_avg,
        'connection_frequency': row.connection_frequency,
        'traffic_type': row.traffic_type,
        'timestamp': source_timestamp or row.created_at.isoformat(),
        'source': row.source,
    }


def _create_behavior_threat_log(ip_address: str, analysis: dict, logs: list[dict]) -> ThreatLog:
    severity = analysis['threat_level'].lower()
    attack_type = THREAT_TYPE_MAP.get(analysis['attack_type'], 'anomaly')
    description = '; '.join(analysis.get('signals', [])[:3])
    return ThreatLog.objects.create(
        ip_address=ip_address,
        threat_type=attack_type,
        severity=severity if severity in {'critical', 'high', 'medium', 'low'} else 'medium',
        probability=round(float(analysis['confidence']) / 100, 4),
        description=description,
        is_local=True,
        device_name='Behavior Engine',
        algorithm='IsolationForest, RandomForest',
        raw_data={'analysis': analysis, 'logs': logs[:12]},
    )


def _simulate_block(ip_address: str, threat_log: ThreatLog, analysis: dict) -> bool:
    if analysis['threat_level'] not in {'HIGH', 'MEDIUM'}:
        return False

    BlockedIP.objects.get_or_create(
        ip_address=ip_address,
        defaults={'reason': f"SAFE MODE simulated response for {analysis['attack_type']}"},
    )
    threat_log.is_blocked = True
    threat_log.save(update_fields=['is_blocked'])
    publish_event('response.blocked', {'ip': ip_address, 'mode': 'safe-simulated'})
    return True
