import json
import numpy as np
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
    cluster_threats,
    discover_local_devices,
    export_threats_csv,
    export_threats_json,
    generate_pdf_report,
    get_all_mitre_mappings,
    get_autoencoder_score,
    get_dashboard_stats,
    get_feature_attribution,
    get_heatmap_data,
    get_incidents,
    get_ip_reputation,
    get_mitre_info,
    get_model_performance,
    get_target_intel,
    get_threat_timeline,
    run_correlation_engine,
    retrain_models_from_csv_rows,
    generate_sample_dataset,
    SAMPLE_DATASETS,
    FEATURE_NAMES,
    RISKY_PORTS,
    WEB_PORTS,
    DATABASE_PORTS,
    REMOTE_ADMIN_PORTS,
    # ── Yangi xususiyatlar ───────────────────────────────────────────────────
    get_xai_explanation,
    lstm_trend_predict,
    get_geoip_data,
    get_bulk_geoip,
    auto_block_ip_system,
    auto_unblock_ip_system,
    send_telegram_alert,
    analyze_user_behavior,
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
    open_ports = payload['open_ports']

    from .services import classify_ip, _build_feature_vector
    ip_info = classify_ip(serializer.validated_data['ip_address'])
    features = {}
    threat_level = 'low'
    if ip_info.get('valid'):
        telemetry = {
            'open_ports': open_ports,
            'open_port_count': len(open_ports),
            'risky_port_count': len([p for p in open_ports if p in RISKY_PORTS]),
            'web_port_count': len([p for p in open_ports if p in WEB_PORTS]),
            'db_port_count': len([p for p in open_ports if p in DATABASE_PORTS]),
            'remote_admin_exposed': any(p in REMOTE_ADMIN_PORTS for p in open_ports),
            'abuse_score': int(reputation.get('abuse_score') or 0),
            'reports': int(reputation.get('reports') or 0),
        }
        features = _build_feature_vector(ip_info, telemetry, '')
        risky = telemetry['risky_port_count']
        threat_level = 'high' if risky >= 3 else 'medium' if risky >= 1 else 'low'

    record = IPAnalysisRecord.objects.create(
        ip_address=payload['ip'],
        requested_ports=payload['requested_ports'],
        open_ports=open_ports,
        timeout_seconds=payload['timeout_seconds'],
        features=features,
        threat_level=threat_level,
        attack_type='port_scan' if open_ports else 'normal',
        confidence=round(min(len(open_ports) / 5, 1.0), 2) if open_ports else 0.0,
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


# ── YANGI ENDPOINTLAR ─────────────────────────────────────────────────────────

@api_view(['GET'])
def model_performance(request):
    """Har bir ML algoritm uchun aniqlik metrikalarini qaytaradi."""
    try:
        data = get_model_performance()
        return Response(data)
    except Exception as exc:
        return Response({'error': str(exc)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
def feature_attribution(request):
    """IP tahlil natijasi uchun feature attribution (SHAP-like) hisoblaydi."""
    ip = request.data.get('ip_address', '127.0.0.1')
    threat_type = request.data.get('threat_type', 'port_scan')
    context = request.data.get('context', '')

    from .services import classify_ip, _collect_ip_telemetry, _build_feature_vector

    ip_info = classify_ip(ip)
    if not ip_info.get('valid'):
        return Response({'error': "Noto'g'ri IP"}, status=400)

    telemetry = _collect_ip_telemetry(ip, ip_info)
    features = _build_feature_vector(ip_info, telemetry, context)
    feature_array = np.array([features[name] for name in FEATURE_NAMES], dtype=float)

    IPAnalysisRecord.objects.update_or_create(
        ip_address=ip,
        defaults={
            'open_ports': telemetry.get('open_ports', []),
            'features': features,
            'threat_level': 'high' if telemetry.get('risky_port_count', 0) >= 3 else 'medium' if telemetry.get('risky_port_count', 0) >= 1 else 'low',
            'attack_type': threat_type if threat_type in ['ddos', 'sqli', 'brute_force', 'phishing', 'ransomware', 'mitm', 'zero_day', 'apt', 'port_scan'] else 'normal',
            'confidence': 0.0,
            'intel': {},
            'notes': f'Feature attribution tahlili: {threat_type}',
        },
    )

    try:
        data = get_feature_attribution(feature_array, threat_type)
        return Response(data)
    except Exception as exc:
        return Response({'error': str(exc)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
def autoencoder_analysis(request):
    """Autoencoder yordamida anomaliya/zero-day ehtimolini hisoblaydi."""
    ip = request.data.get('ip_address', '127.0.0.1')
    context = request.data.get('context', '')

    from .services import classify_ip, _collect_ip_telemetry, _build_feature_vector

    ip_info = classify_ip(ip)
    if not ip_info.get('valid'):
        return Response({'error': "Noto'g'ri IP"}, status=400)

    telemetry = _collect_ip_telemetry(ip, ip_info)
    features = _build_feature_vector(ip_info, telemetry, context)
    feature_array = np.array([features[name] for name in FEATURE_NAMES], dtype=float)

    IPAnalysisRecord.objects.update_or_create(
        ip_address=ip,
        defaults={
            'open_ports': telemetry.get('open_ports', []),
            'features': features,
            'threat_level': 'high' if telemetry.get('risky_port_count', 0) >= 3 else 'medium' if telemetry.get('risky_port_count', 0) >= 1 else 'low',
            'attack_type': 'anomaly',
            'confidence': 0.0,
            'intel': {},
            'notes': 'Autoencoder anomaly tahlili',
        },
    )

    try:
        data = get_autoencoder_score(feature_array)
        data['ip'] = ip
        data['features'] = features
        return Response(data)
    except Exception as exc:
        return Response({'error': str(exc)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
def dataset_upload(request):
    """CSV dataset yuklash, parsing va modellarni qayta o'qitish."""
    from .models import DatasetUpload
    import csv
    import io as _io

    uploaded_file = request.FILES.get('file')
    if not uploaded_file:
        return Response({'error': 'Fayl yuklanmadi'}, status=400)

    dataset_name = request.data.get('name', uploaded_file.name)
    format_type = request.data.get('format_type', 'custom')
    label_col = request.data.get('label_col', None)

    try:
        content = uploaded_file.read().decode('utf-8', errors='ignore')
        reader = csv.DictReader(_io.StringIO(content))
        rows = list(reader)
        if not rows:
            return Response({'error': "Fayl bo'sh yoki noto'g'ri format"}, status=400)

        col_names = list(rows[0].keys())
        classes = list(set(
            row.get('label', row.get('class', row.get('attack_type', row.get('Label', 'unknown'))))
            for row in rows[:100]
        ))

        retrain_result = retrain_models_from_csv_rows(rows, label_col=label_col)
        trained = retrain_result.get('success', False)

        record = DatasetUpload.objects.create(
            name=dataset_name,
            format_type=format_type,
            row_count=len(rows),
            feature_count=len(col_names),
            classes=classes[:20],
            is_trained=trained,
            trained_at=timezone.now() if trained else None,
            metrics=retrain_result if trained else {},
        )

        return Response({
            'id': record.id,
            'name': dataset_name,
            'row_count': len(rows),
            'feature_count': len(col_names),
            'features': col_names[:20],
            'classes': classes[:20],
            'format_type': format_type,
            'trained': trained,
            'retrain': retrain_result,
            'message': retrain_result.get('message') if trained else f"{len(rows)} ta yozuv yuklandi. " + retrain_result.get('error', ''),
        })
    except Exception as exc:
        return Response({'error': f'Parsing xatosi: {str(exc)}'}, status=400)


@api_view(['GET'])
def sample_datasets_list(request):
    """Namuna datasetlar metadatasini qaytaradi."""
    return Response({'samples': SAMPLE_DATASETS})


@api_view(['GET'])
def sample_dataset_download(request, dataset_id):
    """Namuna CSV dataset faylini yuklab olish."""
    allowed = {d['id'] for d in SAMPLE_DATASETS}
    if dataset_id not in allowed:
        return Response({'error': "Noma'lum dataset ID"}, status=400)
    try:
        content = generate_sample_dataset(dataset_id)
        resp = HttpResponse(content, content_type='text/csv; charset=utf-8')
        resp['Content-Disposition'] = f'attachment; filename="sample_{dataset_id}.csv"'
        return resp
    except Exception as exc:
        return Response({'error': str(exc)}, status=500)


@api_view(['GET'])
def dataset_list(request):
    """Yuklangan datasetlar ro'yxatini qaytaradi."""
    from .models import DatasetUpload
    datasets = DatasetUpload.objects.order_by('-created_at')[:20]
    return Response([
        {
            'id': d.id,
            'name': d.name,
            'format_type': d.format_type,
            'row_count': d.row_count,
            'feature_count': d.feature_count,
            'classes': d.classes,
            'is_trained': d.is_trained,
            'created_at': d.created_at.isoformat(),
        }
        for d in datasets
    ])


@api_view(['GET'])
def threat_timeline(request):
    """Hujum vaqt chizig'i ma'lumotini qaytaradi."""
    days = int(request.query_params.get('days', 7))
    try:
        data = get_threat_timeline(days=min(days, 30))
        return Response(data)
    except Exception as exc:
        return Response({'error': str(exc)}, status=500)


@api_view(['GET'])
def heatmap_data(request):
    """Port va subnet heatmap ma'lumotini qaytaradi."""
    try:
        data = get_heatmap_data()
        return Response(data)
    except Exception as exc:
        return Response({'error': str(exc)}, status=500)


@api_view(['GET'])
def mitre_list(request):
    """Barcha tahdid turlari uchun MITRE ATT&CK ma'lumotini qaytaradi."""
    return Response({'mappings': get_all_mitre_mappings(), 'kill_chain_phases': [
        {'name': 'Reconnaissance', 'label': 'Razvedka'},
        {'name': 'Delivery', 'label': 'Yetkazish'},
        {'name': 'Exploitation', 'label': 'Ekspluatatsiya'},
        {'name': 'Installation', 'label': "O'rnatish"},
        {'name': 'Command & Control', 'label': 'C2 Boshqaruv'},
        {'name': 'Pivoting', 'label': 'Tarqalish'},
        {'name': 'Actions on Objectives', 'label': 'Maqsad'},
    ]})


@api_view(['GET', 'POST'])
def incidents(request):
    """Intsidentlar ro'yxati va korrelyatsiya dvigatelni ishlatish."""
    if request.method == 'POST':
        new_incidents = run_correlation_engine()
        existing = get_incidents()
        publish_event('incident.checked', {'new': len(new_incidents)})
        return Response({'new_incidents': new_incidents, 'all_incidents': existing})
    return Response({'incidents': get_incidents()})


@api_view(['GET'])
def cluster_view(request):
    """K-Means va DBSCAN klasterlash natijasini qaytaradi."""
    try:
        data = cluster_threats()
        return Response(data)
    except Exception as exc:
        return Response({'error': str(exc)}, status=500)


@api_view(['GET'])
def export_csv(request):
    """Tahdid loglarini CSV formatda yuklab olish."""
    try:
        content = export_threats_csv()
        response = HttpResponse(content, content_type='text/csv; charset=utf-8')
        response['Content-Disposition'] = 'attachment; filename="cyberguard_threats.csv"'
        return response
    except Exception as exc:
        return Response({'error': str(exc)}, status=500)


@api_view(['GET'])
def export_json_data(request):
    """Tahdid loglarini JSON formatda yuklab olish."""
    try:
        data = export_threats_json()
        content = json.dumps(data, ensure_ascii=False, indent=2)
        response = HttpResponse(content, content_type='application/json; charset=utf-8')
        response['Content-Disposition'] = 'attachment; filename="cyberguard_threats.json"'
        return response
    except Exception as exc:
        return Response({'error': str(exc)}, status=500)


@api_view(['GET'])
def export_pdf(request):
    """Tahdid hisobotini PDF formatda yuklab olish."""
    try:
        pdf_bytes = generate_pdf_report()
        if not pdf_bytes:
            return Response({'error': 'reportlab kutubxonasi o\'rnatilmagan. pip install reportlab'}, status=500)
        response = HttpResponse(pdf_bytes, content_type='application/pdf')
        response['Content-Disposition'] = 'attachment; filename="cyberguard_report.pdf"'
        return response
    except Exception as exc:
        return Response({'error': str(exc)}, status=500)


# ── XAI — EXPLAINABLE AI ──────────────────────────────────────────────────────
@api_view(['GET', 'POST'])
def xai_explanation(request):
    """IP uchun model nima uchun bunday qaror qabul qildi — XAI tushuntirish."""
    try:
        if request.method == 'POST':
            ip = request.data.get('ip_address', '').strip()
            context = request.data.get('context', '')
        else:
            ip = request.GET.get('ip', '').strip()
            context = request.GET.get('context', '')
        if not ip:
            return Response({'error': 'ip_address talab etiladi'}, status=400)
        data = get_xai_explanation(ip, context)
        return Response(data)
    except Exception as exc:
        return Response({'error': str(exc)}, status=500)


# ── LSTM / TIME-SERIES TREND ──────────────────────────────────────────────────
@api_view(['GET'])
def lstm_predict(request):
    """Tahdid trendi va MLP time-series bashorat."""
    try:
        hours = int(request.GET.get('hours', 6))
        hours = max(1, min(hours, 24))
        data = lstm_trend_predict(hours_ahead=hours)
        return Response(data)
    except Exception as exc:
        return Response({'error': str(exc)}, status=500)


# ── GEOIP ─────────────────────────────────────────────────────────────────────
@api_view(['GET'])
def geoip_lookup(request):
    """Bitta IP yoki barcha tahdid IP larining geografik ma'lumoti."""
    try:
        ip = request.GET.get('ip', '').strip()
        if ip:
            data = get_geoip_data(ip)
            return Response(data)
        # Bulk: tahdid loglaridagi IP lar
        ips_param = request.GET.get('ips', '')
        ips = [i.strip() for i in ips_param.split(',') if i.strip()] if ips_param else []
        data = get_bulk_geoip(ips)
        return Response({'results': data})
    except Exception as exc:
        return Response({'error': str(exc)}, status=500)


# ── AUTO BLOCK ────────────────────────────────────────────────────────────────
@api_view(['POST'])
def auto_block_view(request):
    """IP manzilni tizim Firewall orqali bloklaydi."""
    try:
        ip = request.data.get('ip_address', '').strip()
        if not ip:
            return Response({'error': 'ip_address talab etiladi'}, status=400)
        result = auto_block_ip_system(ip)
        status_code = 200 if result.get('success') else 400
        return Response(result, status=status_code)
    except Exception as exc:
        return Response({'error': str(exc)}, status=500)


@api_view(['POST'])
def auto_unblock_view(request):
    """Tizim Firewall dan IP manzil blokirovkasini olib tashlaydi."""
    try:
        ip = request.data.get('ip_address', '').strip()
        if not ip:
            return Response({'error': 'ip_address talab etiladi'}, status=400)
        result = auto_unblock_ip_system(ip)
        return Response(result)
    except Exception as exc:
        return Response({'error': str(exc)}, status=500)


# ── TELEGRAM ALERT ────────────────────────────────────────────────────────────
@api_view(['POST'])
def telegram_test_view(request):
    """Telegram botni sinash uchun test xabar yuboradi."""
    try:
        token = request.data.get('token', '').strip()
        chat_id = request.data.get('chat_id', '').strip()
        message = request.data.get('message', '').strip() or (
            '🔔 <b>CyberGuard AI</b> — Test xabari\n'
            'Telegram integratsiyasi muvaffaqiyatli sozlandi!'
        )
        result = send_telegram_alert(message, token=token or None, chat_id=chat_id or None)
        return Response(result)
    except Exception as exc:
        return Response({'error': str(exc)}, status=500)


# ── USER BEHAVIOR ANALYSIS ────────────────────────────────────────────────────
@api_view(['GET'])
def user_behavior_view(request):
    """IP tahlil va skan loglaridan foydalanuvchi xatti-harakati tahlili."""
    try:
        data = analyze_user_behavior()
        return Response(data)
    except Exception as exc:
        return Response({'error': str(exc)}, status=500)


# ── MIGRATION TRIGGER (bir martalik ishlatish uchun) ──────────────────────────
@api_view(['POST'])
def run_pending_migrations(request):
    """Kutilayotgan migration larni qo'llaydi (bir martalik foydalanish uchun)."""
    from django.core.management import call_command
    from io import StringIO
    try:
        out = StringIO()
        call_command('migrate', '--noinput', stdout=out, stderr=out)
        output = out.getvalue()
        return Response({'success': True, 'output': output})
    except Exception as exc:
        return Response({'success': False, 'error': str(exc)}, status=500)
