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
        ('web', 'Web'),
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


class TrafficEventLog(models.Model):
    TRAFFIC_TYPES = [
        ('normal', 'Normal'),
        ('ddos', 'DDoS Simulation'),
        ('brute_force', 'Brute Force Simulation'),
    ]

    ip_address = models.GenericIPAddressField()
    port = models.PositiveIntegerField()
    traffic_type = models.CharField(max_length=20, choices=TRAFFIC_TYPES)
    request_count = models.PositiveIntegerField(default=0)
    failed_attempts = models.PositiveIntegerField(default=0)
    packet_size_avg = models.FloatField(default=0.0)
    connection_frequency = models.FloatField(default=0.0)
    source = models.CharField(max_length=50, default='simulator')
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.ip_address}:{self.port} [{self.traffic_type}]"


class IPAnalysisRecord(models.Model):
    THREAT_LEVELS = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
    ]
    ATTACK_TYPES = [
        ('normal', 'Normal'),
        ('ddos', 'DDoS'),
        ('brute_force', 'Brute Force'),
        ('anomaly', 'Anomaly'),
    ]

    ip_address = models.GenericIPAddressField()
    requested_ports = models.JSONField(default=list, blank=True)
    open_ports = models.JSONField(default=list, blank=True)
    timeout_seconds = models.FloatField(default=0.35)
    features = models.JSONField(default=dict, blank=True)
    threat_level = models.CharField(max_length=10, choices=THREAT_LEVELS, default='low')
    attack_type = models.CharField(max_length=20, choices=ATTACK_TYPES, default='normal')
    confidence = models.FloatField(default=0.0)
    intel = models.JSONField(default=dict, blank=True)
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.ip_address} -> {self.attack_type} ({self.threat_level})"


class Incident(models.Model):
    SEVERITY_CHOICES = [
        ('critical', 'Kritik'),
        ('high', 'Yuqori'),
        ('medium', "O'rta"),
        ('low', 'Past'),
    ]

    title = models.CharField(max_length=200)
    description = models.TextField()
    rule_name = models.CharField(max_length=100)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='medium')
    threat_type = models.CharField(max_length=50, default='anomaly')
    involved_ips = models.JSONField(default=list)
    is_resolved = models.BooleanField(default=False)
    resolved_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Incident: {self.title} ({self.severity})"


class DatasetUpload(models.Model):
    FORMAT_CHOICES = [
        ('nsl_kdd', 'NSL-KDD'),
        ('cicids2017', 'CICIDS2017'),
        ('unsw_nb15', 'UNSW-NB15'),
        ('custom', 'Custom CSV'),
    ]

    name = models.CharField(max_length=200)
    format_type = models.CharField(max_length=20, choices=FORMAT_CHOICES, default='custom')
    file_path = models.CharField(max_length=500, blank=True)
    row_count = models.PositiveIntegerField(default=0)
    feature_count = models.PositiveIntegerField(default=0)
    classes = models.JSONField(default=list)
    is_trained = models.BooleanField(default=False)
    trained_at = models.DateTimeField(null=True, blank=True)
    metrics = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.name} [{self.format_type}] {self.row_count} rows"

