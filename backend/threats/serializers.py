from rest_framework import serializers
from .models import BlockedIP, ConnectionProfile, NetworkDevice, ScanSession, ThreatLog


class ThreatLogSerializer(serializers.ModelSerializer):
    severity_display = serializers.CharField(source='get_severity_display', read_only=True)
    threat_display   = serializers.CharField(source='get_threat_type_display', read_only=True)

    class Meta:
        model  = ThreatLog
        fields = '__all__'


class BlockedIPSerializer(serializers.ModelSerializer):
    class Meta:
        model  = BlockedIP
        fields = '__all__'


class NetworkDeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model  = NetworkDevice
        fields = '__all__'


class AnalyzeRequestSerializer(serializers.Serializer):
    ip_address  = serializers.IPAddressField()
    threat_type = serializers.ChoiceField(choices=[
        'ddos', 'sqli', 'brute_force', 'phishing',
        'ransomware', 'mitm', 'apt', 'port_scan', 'zero_day',
    ])
    algorithms  = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        default=['Random Forest', 'XGBoost'],
    )
    context     = serializers.CharField(required=False, allow_blank=True, default='')


class IPInfoSerializer(serializers.Serializer):
    valid = serializers.BooleanField()
    ip = serializers.IPAddressField()
    is_local = serializers.BooleanField()
    is_loopback = serializers.BooleanField()
    network_type = serializers.CharField()
    device_name = serializers.CharField()
    mac_address = serializers.CharField()
    known_risk = serializers.CharField()


class AnalyzeResponseSerializer(serializers.Serializer):
    ip = serializers.IPAddressField()
    ip_info = IPInfoSerializer()
    threat_type = serializers.CharField()
    threat_name = serializers.CharField()
    probability = serializers.FloatField()
    probability_pct = serializers.CharField()
    severity = serializers.CharField()
    indicators = serializers.ListField(child=serializers.CharField())
    mitigation = serializers.ListField(child=serializers.CharField())
    algorithm_scores = serializers.DictField(child=serializers.FloatField())
    local_context = serializers.CharField(allow_blank=True)
    context = serializers.CharField(allow_blank=True)
    recommendation = serializers.CharField()
    log_id = serializers.IntegerField(required=False)
    telemetry = serializers.DictField(required=False)
    model_version = serializers.CharField(required=False)


class DashboardTrendPointSerializer(serializers.Serializer):
    hour = serializers.CharField()
    threats = serializers.IntegerField()
    blocked = serializers.IntegerField()


class DashboardStatsSerializer(serializers.Serializer):
    total_threats = serializers.IntegerField()
    blocked = serializers.IntegerField()
    critical = serializers.IntegerField()
    block_rate = serializers.FloatField()
    accuracy = serializers.FloatField()
    f1_score = serializers.FloatField()
    response_ms = serializers.IntegerField()
    false_positive_rate = serializers.FloatField()
    hourly_trend = DashboardTrendPointSerializer(many=True)


class NetworkScanDeviceSerializer(serializers.Serializer):
    ip = serializers.IPAddressField()
    name = serializers.CharField()
    mac = serializers.CharField()
    risk = serializers.CharField()
    network_type = serializers.CharField()
    status = serializers.CharField()
    open_ports = serializers.ListField(child=serializers.IntegerField())
    last_seen = serializers.DateTimeField()
    source = serializers.CharField(required=False)


class NetworkScanResponseSerializer(serializers.Serializer):
    devices = NetworkScanDeviceSerializer(many=True)
    total = serializers.IntegerField()


class IPReputationSerializer(serializers.Serializer):
    ip = serializers.IPAddressField()
    is_local = serializers.BooleanField()
    message = serializers.CharField(required=False)
    local_info = IPInfoSerializer(required=False)
    abuse_score = serializers.IntegerField(required=False)
    reports = serializers.IntegerField(required=False)
    country = serializers.CharField(required=False)
    isp = serializers.CharField(required=False)
    domain = serializers.CharField(required=False)
    last_reported = serializers.CharField(required=False)


class LiveLogEntrySerializer(serializers.Serializer):
    id = serializers.IntegerField()
    level = serializers.CharField()
    message = serializers.CharField()
    timestamp = serializers.DateTimeField()
    ip = serializers.IPAddressField()


class LiveLogsResponseSerializer(serializers.Serializer):
    logs = LiveLogEntrySerializer(many=True)


class NetworkInterfaceSerializer(serializers.Serializer):
    name = serializers.CharField()
    adapter_type = serializers.CharField()
    ip = serializers.CharField(allow_blank=True)
    subnet_mask = serializers.CharField(allow_blank=True)
    subnet_cidr = serializers.CharField(allow_blank=True)
    gateway = serializers.CharField(allow_blank=True)
    gateways = serializers.ListField(child=serializers.CharField(), required=False)
    ssid = serializers.CharField(allow_blank=True)
    state = serializers.CharField(allow_blank=True)
    dns_suffix = serializers.CharField(allow_blank=True)
    ipv6_addresses = serializers.ListField(child=serializers.CharField(), required=False)
    temporary_ipv6_addresses = serializers.ListField(child=serializers.CharField(), required=False)
    link_local_ipv6 = serializers.CharField(allow_blank=True, required=False)
    dns_servers = serializers.ListField(child=serializers.CharField(), required=False)


class NetworkInterfacesResponseSerializer(serializers.Serializer):
    interfaces = NetworkInterfaceSerializer(many=True)
    total = serializers.IntegerField()


class WifiNetworkSerializer(serializers.Serializer):
    ssid = serializers.CharField()
    authentication = serializers.CharField(allow_blank=True)
    encryption = serializers.CharField(allow_blank=True)
    signal = serializers.CharField(allow_blank=True)
    network_type = serializers.CharField(allow_blank=True)
    bssid_count = serializers.IntegerField()


class WifiStatusSerializer(serializers.Serializer):
    wifi_adapter_available = serializers.BooleanField()
    service_running = serializers.BooleanField()
    message = serializers.CharField()
    connected_ssid = serializers.CharField(allow_blank=True)
    connected_interface = serializers.CharField(allow_blank=True)
    connected_state = serializers.CharField(allow_blank=True)
    available_networks = WifiNetworkSerializer(many=True)
    connect_message = serializers.CharField(required=False)
    requested_ssid = serializers.CharField(required=False)


class WifiConnectRequestSerializer(serializers.Serializer):
    ssid = serializers.CharField()
    password = serializers.CharField(required=False, allow_blank=True, default='')
    interface_name = serializers.CharField(required=False, allow_blank=True, default='')
    authentication = serializers.CharField(required=False, allow_blank=True, default='')
    encryption = serializers.CharField(required=False, allow_blank=True, default='')


class ConnectionProfileSerializer(serializers.ModelSerializer):
    has_secret = serializers.SerializerMethodField()

    class Meta:
        model = ConnectionProfile
        fields = [
            'id', 'name', 'profile_type', 'target_host', 'port', 'username',
            'snmp_version', 'network_label', 'notes', 'is_active', 'last_used_at',
            'created_at', 'updated_at', 'has_secret',
        ]

    def get_has_secret(self, obj):
        return bool(obj.secret_encrypted)


class ConnectionProfileWriteSerializer(serializers.ModelSerializer):
    secret = serializers.CharField(write_only=True, required=False, allow_blank=True)

    class Meta:
        model = ConnectionProfile
        fields = [
            'id', 'name', 'profile_type', 'target_host', 'port', 'username',
            'secret', 'snmp_version', 'network_label', 'notes', 'is_active',
        ]

    def validate(self, attrs):
        profile_type = attrs.get('profile_type', getattr(self.instance, 'profile_type', ''))
        port = attrs.get('port', getattr(self.instance, 'port', None))
        username = attrs.get('username', getattr(self.instance, 'username', ''))
        secret = attrs.get('secret', None)

        if profile_type == 'ssh':
            if not username:
                raise serializers.ValidationError({'username': 'SSH uchun username majburiy.'})
            if port in (None, 0):
                attrs['port'] = 22
        elif profile_type == 'telnet':
            if port in (None, 0):
                attrs['port'] = 23
        elif profile_type == 'snmp':
            if port in (None, 0):
                attrs['port'] = 161
            if attrs.get('snmp_version', getattr(self.instance, 'snmp_version', '2c')) != '2c':
                raise serializers.ValidationError({'snmp_version': "Hozircha faqat SNMP v2c qo'llab-quvvatlanadi."})
        else:
            raise serializers.ValidationError({'profile_type': "Qo'llab-quvvatlanadigan tur: ssh, telnet yoki snmp."})

        if not self.instance and not secret:
            raise serializers.ValidationError({'secret': 'Password/community majburiy.'})
        return attrs


class ScanSessionSerializer(serializers.ModelSerializer):
    profile_name = serializers.CharField(source='profile.name', read_only=True)
    profile_type = serializers.CharField(source='profile.profile_type', read_only=True)
    target_host = serializers.CharField(source='profile.target_host', read_only=True)

    class Meta:
        model = ScanSession
        fields = [
            'id', 'profile', 'profile_name', 'profile_type', 'target_host',
            'status', 'summary', 'network_name', 'interface_name', 'started_at',
            'finished_at', 'result', 'error_message', 'created_at',
        ]


class RunScanRequestSerializer(serializers.Serializer):
    interface_name = serializers.CharField(required=False, allow_blank=True, default='')
    network_name = serializers.CharField(required=False, allow_blank=True, default='')

