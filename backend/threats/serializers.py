from rest_framework import serializers
from .models import ThreatLog, BlockedIP, NetworkDevice


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
