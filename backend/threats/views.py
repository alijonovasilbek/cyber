from textwrap import dedent

from django.utils import timezone

from django.http import HttpResponse
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import status, viewsets
from rest_framework.decorators import action, api_view
from rest_framework.response import Response

from .demo_engine import (
    analyze_traffic,
    get_cached_reputation,
    predict_next_window,
    scan_ip_safe,
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


LOCAL_AGENT_SCRIPT_LABELS = {
    'install_local_scan_protocol.bat': 'local-agent-install.bat',
    'start_local_agent.bat': 'local-agent-start.bat',
    'enable_local_scan.bat': 'local-agent-enable.bat',
    'launch_local_agent.ps1': 'launch_local_agent.ps1',
}


LOCAL_AGENT_LAUNCHER_SCRIPT = dedent(
    r"""
    param(
        [string]$Uri = ''
    )

    $ErrorActionPreference = 'Stop'
    $healthUrl = 'http://127.0.0.1:8765/health'

    try {
        Invoke-WebRequest -Uri $healthUrl -UseBasicParsing -TimeoutSec 2 | Out-Null
        exit 0
    } catch {
    }

    function Send-Json {
        param(
            [System.Net.HttpListenerResponse]$Response,
            [int]$StatusCode,
            [object]$Payload
        )

        $json = $Payload | ConvertTo-Json -Depth 8 -Compress
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        $Response.StatusCode = $StatusCode
        $Response.ContentType = 'application/json; charset=utf-8'
        $Response.ContentEncoding = [System.Text.Encoding]::UTF8
        $Response.Headers['Access-Control-Allow-Origin'] = '*'
        $Response.Headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        $Response.Headers['Access-Control-Allow-Headers'] = 'content-type, x-api-key'
        $Response.OutputStream.Write($bytes, 0, $bytes.Length)
        $Response.OutputStream.Close()
    }

    function Get-DefaultGateway {
        try {
            $gateway = Get-CimInstance Win32_NetworkAdapterConfiguration |
                Where-Object { $_.IPEnabled -and $_.DefaultIPGateway } |
                Select-Object -First 1
            if ($gateway -and $gateway.DefaultIPGateway.Count -gt 0) {
                return $gateway.DefaultIPGateway[0]
            }
        } catch {
        }
        return $null
    }

    function Get-InterfaceRows {
        $rows = @()
        try {
            $configs = Get-NetIPConfiguration | Where-Object { $_.IPv4Address -and $_.NetAdapter.Status -eq 'Up' }
            foreach ($cfg in $configs) {
                $rows += [ordered]@{
                    name = $cfg.InterfaceAlias
                    ssid = ''
                    gateway = ($cfg.IPv4DefaultGateway.NextHop | Select-Object -First 1)
                    subnet_cidr = ($cfg.IPv4Address | Select-Object -First 1).IPAddress
                    ipv4 = ($cfg.IPv4Address | Select-Object -First 1).IPAddress
                    source = 'local-agent'
                }
            }
        } catch {
            try {
                $configs = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -and $_.IPAddress }
                foreach ($cfg in $configs) {
                    $ipv4 = $cfg.IPAddress | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } | Select-Object -First 1
                    if ($ipv4) {
                        $rows += [ordered]@{
                            name = $cfg.Description
                            ssid = ''
                            gateway = ($cfg.DefaultIPGateway | Select-Object -First 1)
                            subnet_cidr = $ipv4
                            ipv4 = $ipv4
                            source = 'local-agent'
                        }
                    }
                }
            } catch {
            }
        }
        return @($rows)
    }

    function Get-WifiStatusRow {
        $interfaces = Get-InterfaceRows
        $primary = $interfaces | Select-Object -First 1
        return [ordered]@{
            connected = [bool]$primary
            ssid = ''
            interface_name = if ($primary) { $primary.name } else { '' }
            ipv4 = if ($primary) { $primary.ipv4 } else { '' }
            gateway = if ($primary) { $primary.gateway } else { '' }
            source = 'local-agent'
        }
    }

    function Get-OpenPorts {
        param([string]$Ip)

        $portsToCheck = @(53, 80, 135, 139, 443, 445, 3389, 5432)
        $open = @()
        foreach ($port in $portsToCheck) {
            try {
                $client = New-Object System.Net.Sockets.TcpClient
                $async = $client.BeginConnect($Ip, $port, $null, $null)
                if ($async.AsyncWaitHandle.WaitOne(180, $false) -and $client.Connected) {
                    $open += $port
                }
                $client.Close()
            } catch {
            }
        }
        return @($open)
    }

    function Get-RiskLevel {
        param(
            [string]$Ip,
            [int[]]$OpenPorts
        )

        $score = 0
        $score += [Math]::Min($OpenPorts.Count, 6) * 12
        foreach ($port in $OpenPorts) {
            if ($port -in @(135, 139, 445, 3389, 5432)) {
                $score += 14
            }
        }
        if ($Ip.EndsWith('.1')) {
            $score += 10
        }
        if ($score -ge 85) { return 'critical' }
        if ($score -ge 55) { return 'high' }
        if ($score -ge 28) { return 'medium' }
        return 'low'
    }

    function Get-DeviceName {
        param(
            [string]$Ip,
            [int[]]$OpenPorts,
            [bool]$IsGateway = $false,
            [bool]$IsWorkstation = $false
        )

        if ($IsGateway -or $Ip.EndsWith('.1')) { return 'Gateway/Router' }
        if ($IsWorkstation) { return 'Analyst Workstation' }
        if ($OpenPorts -contains 5432) { return 'Database Host' }
        if (($OpenPorts -contains 80) -or ($OpenPorts -contains 443)) { return 'Web Device' }
        if ($OpenPorts.Count -gt 0) { return 'Server/Remote Host' }
        return 'Detected Host'
    }

    function Get-NetworkType {
        param([string]$Ip)
        if ($Ip -like '192.168.*') { return 'LAN (uy/ofis tarmogi)' }
        if ($Ip -like '10.*') { return 'LAN (korporativ tarmoq)' }
        if ($Ip -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.') { return 'LAN (virtual tarmoq)' }
        if ($Ip -eq '127.0.0.1') { return 'Loopback (localhost)' }
        return 'WAN (internet)'
    }

    function Get-NetworkDevices {
        $interfaces = Get-InterfaceRows
        $gateway = Get-DefaultGateway
        $arpText = ''
        try {
            $arpText = arp -a | Out-String
        } catch {
        }

        $candidateIps = New-Object 'System.Collections.Generic.List[string]'
        foreach ($iface in $interfaces) {
            if ($iface.ipv4) { [void]$candidateIps.Add($iface.ipv4) }
            if ($iface.gateway) { [void]$candidateIps.Add($iface.gateway) }
        }

        foreach ($match in ([regex]'\b\d{1,3}(?:\.\d{1,3}){3}\b').Matches($arpText)) {
            $ip = $match.Value
            if ($ip -ne '255.255.255.255' -and $ip -notlike '224.*' -and $ip -notlike '239.*') {
                [void]$candidateIps.Add($ip)
            }
        }

        $deviceMap = @{}
        foreach ($ip in $candidateIps | Select-Object -Unique) {
            if ($ip -notmatch '^\d+\.\d+\.\d+\.\d+$') { continue }
            $openPorts = Get-OpenPorts -Ip $ip
            $isGateway = $gateway -and $ip -eq $gateway
            $isWorkstation = ($interfaces | Where-Object { $_.ipv4 -eq $ip }).Count -gt 0
            $deviceMap[$ip] = [ordered]@{
                ip = $ip
                name = Get-DeviceName -Ip $ip -OpenPorts $openPorts -IsGateway:$isGateway -IsWorkstation:$isWorkstation
                mac = 'N/A'
                risk = Get-RiskLevel -Ip $ip -OpenPorts $openPorts
                network_type = Get-NetworkType -Ip $ip
                status = 'online'
                open_ports = @($openPorts)
                source = 'local-agent'
            }
        }

        return @($deviceMap.Values | Sort-Object ip)
    }

    function Read-RequestBody {
        param([System.Net.HttpListenerRequest]$Request)
        if (-not $Request.HasEntityBody) { return @{} }
        $reader = New-Object System.IO.StreamReader($Request.InputStream, $Request.ContentEncoding)
        $body = $reader.ReadToEnd()
        $reader.Close()
        if ([string]::IsNullOrWhiteSpace($body)) { return @{} }
        try {
            return $body | ConvertFrom-Json -AsHashtable
        } catch {
            return @{}
        }
    }

    $listener = [System.Net.HttpListener]::new()
    $listener.Prefixes.Add('http://127.0.0.1:8765/')
    $listener.Start()

    while ($listener.IsListening) {
        try {
            $context = $listener.GetContext()
            $request = $context.Request
            $response = $context.Response
            $path = $request.Url.AbsolutePath.TrimEnd('/')
            if ([string]::IsNullOrEmpty($path)) { $path = '/' }

            if ($request.HttpMethod -eq 'OPTIONS') {
                Send-Json -Response $response -StatusCode 200 -Payload @{ ok = $true }
                continue
            }

            if ($request.HttpMethod -eq 'GET' -and $path -eq '/health') {
                Send-Json -Response $response -StatusCode 200 -Payload @{
                    status = 'ok'
                    agent = 'cyberguard-local-agent'
                    mode = 'portable-powershell'
                }
                continue
            }

            if ($request.HttpMethod -eq 'GET' -and $path -eq '/network/interfaces') {
                $items = Get-InterfaceRows
                Send-Json -Response $response -StatusCode 200 -Payload @{
                    interfaces = $items
                    total = $items.Count
                    source = 'local-agent'
                }
                continue
            }

            if ($request.HttpMethod -eq 'GET' -and $path -eq '/network/wifi/status') {
                Send-Json -Response $response -StatusCode 200 -Payload (Get-WifiStatusRow)
                continue
            }

            if ($request.HttpMethod -eq 'GET' -and $path -eq '/network/scan') {
                $devices = Get-NetworkDevices
                Send-Json -Response $response -StatusCode 200 -Payload @{
                    devices = $devices
                    total = $devices.Count
                    source = 'local-agent'
                }
                continue
            }

            if ($path -eq '/network/wifi/connect') {
                Send-Json -Response $response -StatusCode 501 -Payload @{
                    error = 'Wi-Fi connect portable agentda hozircha yoq.'
                }
                continue
            }

            if ($path -eq '/scan-ip') {
                $targetIp = ''
                if ($request.HttpMethod -eq 'GET') {
                    $targetIp = $request.QueryString['ip']
                } elseif ($request.HttpMethod -eq 'POST') {
                    $payload = Read-RequestBody -Request $request
                    $targetIp = $payload['ip_address']
                }

                if (-not $targetIp) {
                    Send-Json -Response $response -StatusCode 400 -Payload @{ error = 'IP kiritilmadi.' }
                    continue
                }

                $openPorts = Get-OpenPorts -Ip $targetIp
                Send-Json -Response $response -StatusCode 200 -Payload @{
                    ip = $targetIp
                    open_ports = @($openPorts)
                    requested_ports = @()
                    timeout_seconds = 0.18
                    source = 'local-agent'
                }
                continue
            }

            Send-Json -Response $response -StatusCode 404 -Payload @{ error = 'Not found' }
        } catch {
            if ($context -and $context.Response) {
                Send-Json -Response $context.Response -StatusCode 500 -Payload @{ error = $_.Exception.Message }
            }
        }
    }
    """
).strip()


def _local_agent_download_base(request) -> str:
    if request.headers.get('X-Forwarded-Proto'):
        proto = request.headers['X-Forwarded-Proto'].split(',')[0].strip()
        host = request.headers.get('X-Forwarded-Host') or request.get_host()
        return f'{proto}://{host}'
    return request.build_absolute_uri('/').rstrip('/')


def _build_install_script(base_url: str) -> str:
    launcher_url = f'{base_url}/api/local-agent/download/launch_local_agent.ps1/'
    return '\r\n'.join([
        '@echo off',
        'setlocal',
        'set "APPDIR=%LOCALAPPDATA%\\CyberGuardLocalAgent"',
        'if not exist "%APPDIR%" mkdir "%APPDIR%"',
        f'powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest -UseBasicParsing -Uri \\"{launcher_url}\\" -OutFile \\"%APPDIR%\\launch_local_agent.ps1\\""',
        'if errorlevel 1 (',
        '  echo launch_local_agent.ps1 yuklab olinmadi.',
        '  exit /b 1',
        ')',
        'powershell -NoProfile -ExecutionPolicy Bypass -Command "$launcher = Join-Path $env:LOCALAPPDATA \'CyberGuardLocalAgent\\launch_local_agent.ps1\'; $baseKey = \'HKCU:\\Software\\Classes\\cyberguard-agent\'; $commandKey = Join-Path $baseKey \'shell\\open\\command\'; $commandValue = \'powershell.exe -ExecutionPolicy Bypass -File `"\'+$launcher+\'`" `"%1`"\'; New-Item -Path $baseKey -Force | Out-Null; New-ItemProperty -Path $baseKey -Name \'URL Protocol\' -Value \'\' -PropertyType String -Force | Out-Null; New-Item -Path $commandKey -Force | Out-Null; Set-ItemProperty -Path $baseKey -Name \'(default)\' -Value \'URL:CyberGuard Local Agent\' -Force; Set-ItemProperty -Path $commandKey -Name \'(default)\' -Value $commandValue -Force"',
        'echo cyberguard-agent:// protokoli ornatildi.',
        'echo Endi RUN LOCAL SCAN tugmasi local agentni ishga tushira oladi.',
        'endlocal',
    ]) + '\r\n'


def _build_start_script(base_url: str) -> str:
    launcher_url = f'{base_url}/api/local-agent/download/launch_local_agent.ps1/'
    return '\r\n'.join([
        '@echo off',
        'setlocal',
        'set "APPDIR=%LOCALAPPDATA%\\CyberGuardLocalAgent"',
        'if not exist "%APPDIR%" mkdir "%APPDIR%"',
        'if not exist "%APPDIR%\\launch_local_agent.ps1" (',
        f'  powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest -UseBasicParsing -Uri \\"{launcher_url}\\" -OutFile \\"%APPDIR%\\launch_local_agent.ps1\\""',
        ')',
        'if not exist "%APPDIR%\\launch_local_agent.ps1" (',
        '  echo launch_local_agent.ps1 topilmadi.',
        '  exit /b 1',
        ')',
        'start "CyberGuard Local Agent" powershell -NoProfile -ExecutionPolicy Bypass -File "%APPDIR%\\launch_local_agent.ps1"',
        'echo Local agent ishga tushirildi. 3-5 soniya kutib RUN LOCAL SCAN bosing.',
        'endlocal',
    ]) + '\r\n'


def _build_enable_script(base_url: str) -> str:
    install_url = f'{base_url}/api/local-agent/download/install_local_scan_protocol.bat/'
    start_url = f'{base_url}/api/local-agent/download/start_local_agent.bat/'
    return '\r\n'.join([
        '@echo off',
        'setlocal',
        'set "APPDIR=%LOCALAPPDATA%\\CyberGuardLocalAgent"',
        'if not exist "%APPDIR%" mkdir "%APPDIR%"',
        f'powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest -UseBasicParsing -Uri \\"{install_url}\\" -OutFile \\"%APPDIR%\\install_local_scan_protocol.bat\\""',
        f'powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest -UseBasicParsing -Uri \\"{start_url}\\" -OutFile \\"%APPDIR%\\start_local_agent.bat\\""',
        'if not exist "%APPDIR%\\install_local_scan_protocol.bat" (',
        '  echo install_local_scan_protocol.bat yuklab olinmadi.',
        '  exit /b 1',
        ')',
        'if not exist "%APPDIR%\\start_local_agent.bat" (',
        '  echo start_local_agent.bat yuklab olinmadi.',
        '  exit /b 1',
        ')',
        'call "%APPDIR%\\install_local_scan_protocol.bat"',
        'call "%APPDIR%\\start_local_agent.bat"',
        'endlocal',
    ]) + '\r\n'


def _get_local_agent_script_content(request, script_name: str) -> tuple[str | None, str | None]:
    if script_name not in LOCAL_AGENT_SCRIPT_LABELS:
        return None, None

    if script_name == 'launch_local_agent.ps1':
        return LOCAL_AGENT_LAUNCHER_SCRIPT.replace('\n', '\r\n') + '\r\n', 'text/plain; charset=utf-8'

    base_url = _local_agent_download_base(request)
    if script_name == 'install_local_scan_protocol.bat':
        return _build_install_script(base_url), 'application/x-bat'
    if script_name == 'start_local_agent.bat':
        return _build_start_script(base_url), 'application/x-bat'
    if script_name == 'enable_local_scan.bat':
        return _build_enable_script(base_url), 'application/x-bat'
    return None, None


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


@extend_schema(exclude=True)
@api_view(['GET'])
def download_local_agent_script(request, script_name):
    content, content_type = _get_local_agent_script_content(request, script_name)
    download_name = LOCAL_AGENT_SCRIPT_LABELS.get(script_name)
    if not content or not download_name:
        return Response({'error': 'Script topilmadi.'}, status=status.HTTP_404_NOT_FOUND)

    response = HttpResponse(content, content_type=content_type)
    response['Content-Disposition'] = f'attachment; filename="{download_name}"'
    return response


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
