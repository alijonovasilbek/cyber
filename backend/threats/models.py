from django.db import models

class ThreatLog(models.Model):
    SEVERITY_CHOICES = [
        ('critical', 'Kritik'),
        ('high', 'Yuqori'),
        ('medium', "O'rta"),
        ('low', 'Past'),
    ]
    THREAT_TYPES = [
        ('ddos', 'DDoS'),
        ('sqli', 'SQL Injection'),
        ('brute_force', 'Brute Force'),
        ('phishing', 'Phishing'),
        ('ransomware', 'Ransomware'),
        ('mitm', 'MITM'),
        ('zero_day', 'Zero-Day'),
        ('apt', 'APT'),
        ('port_scan', 'Port Scan'),
        ('anomaly', 'Anomaliya'),
    ]

    ip_address   = models.GenericIPAddressField()
    threat_type  = models.CharField(max_length=50, choices=THREAT_TYPES)
    severity     = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    probability  = models.FloatField(default=0.0)   # 0.0 - 1.0
    description  = models.TextField(blank=True)
    is_blocked   = models.BooleanField(default=False)
    is_local     = models.BooleanField(default=False)
    device_name  = models.CharField(max_length=100, blank=True)
    algorithm    = models.CharField(max_length=100, blank=True)
    created_at   = models.DateTimeField(auto_now_add=True)
    raw_data     = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.ip_address} - {self.threat_type} ({self.severity})"


class BlockedIP(models.Model):
    ip_address  = models.GenericIPAddressField(unique=True)
    reason      = models.TextField()
    blocked_at  = models.DateTimeField(auto_now_add=True)
    is_active   = models.BooleanField(default=True)

    def __str__(self):
        return f"Bloklangan: {self.ip_address}"


class NetworkDevice(models.Model):
    ip_address  = models.GenericIPAddressField(unique=True)
    mac_address = models.CharField(max_length=17, blank=True)
    device_name = models.CharField(max_length=100)
    risk_level  = models.CharField(max_length=20, default='low')
    last_seen   = models.DateTimeField(auto_now=True)
    is_trusted  = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.device_name} ({self.ip_address})"


class ConnectionProfile(models.Model):
    PROFILE_TYPES = [
        ('ssh', 'SSH'),
        ('telnet', 'Telnet'),
        ('snmp', 'SNMP'),
    ]
    SNMP_VERSIONS = [
        ('2c', 'SNMP v2c'),
        ('3', 'SNMP v3'),
    ]

    name = models.CharField(max_length=100)
    profile_type = models.CharField(max_length=20, choices=PROFILE_TYPES)
    target_host = models.CharField(max_length=255)
    port = models.PositiveIntegerField(default=22)
    username = models.CharField(max_length=100, blank=True)
    secret_encrypted = models.TextField(blank=True)
    snmp_version = models.CharField(max_length=10, choices=SNMP_VERSIONS, default='2c')
    network_label = models.CharField(max_length=120, blank=True)
    notes = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name', 'target_host']

    def __str__(self):
        return f"{self.name} [{self.profile_type}] -> {self.target_host}:{self.port}"


class ScanSession(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('success', 'Success'),
        ('failed', 'Failed'),
    ]

    profile = models.ForeignKey(ConnectionProfile, on_delete=models.CASCADE, related_name='sessions')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    summary = models.CharField(max_length=255, blank=True)
    network_name = models.CharField(max_length=120, blank=True)
    interface_name = models.CharField(max_length=120, blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    result = models.JSONField(default=dict, blank=True)
    error_message = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Scan #{self.pk} {self.profile.name} ({self.status})"

