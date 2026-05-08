from django.db import models


class LogWindow(models.Model):
    """5 daqiqalik vaqt oynasi — Windows Event Log agregatsiyasi."""

    LABEL_CHOICES = [
        ('normal',      'Normal'),
        ('brute_force', 'Brute Force'),
        ('port_scan',   'Port Scan'),
        ('anomaly',     'Anomaly'),
    ]

    timestamp        = models.DateTimeField(db_index=True)
    failed_logins    = models.IntegerField(default=0)   # Event 4625
    success_logins   = models.IntegerField(default=0)   # Event 4624
    new_processes    = models.IntegerField(default=0)   # Event 4688
    policy_changes   = models.IntegerField(default=0)   # Event 4719
    service_events   = models.IntegerField(default=0)   # Event 7036
    tcp_connections    = models.IntegerField(default=0)   # netstat ESTABLISHED count
    running_processes  = models.IntegerField(default=0)   # tasklist count
    label              = models.CharField(max_length=20, choices=LABEL_CHOICES, default='normal')
    source             = models.CharField(max_length=20, default='collector')  # 'collector' | 'simulator'

    class Meta:
        ordering = ['timestamp']

    def __str__(self):
        return f"{self.timestamp:%Y-%m-%d %H:%M} | {self.label} | fails={self.failed_logins}"

    def to_feature_vector(self):
        return [
            self.failed_logins,
            self.success_logins,
            self.new_processes,
            self.policy_changes,
            self.service_events,
            self.tcp_connections,
            self.running_processes,
        ]

    FEATURE_NAMES = [
        'failed_logins', 'success_logins', 'new_processes',
        'policy_changes', 'service_events', 'tcp_connections', 'running_processes',
    ]


class PredictionLog(models.Model):
    """Har bashorat natijasi saqlanadi — tarix uchun."""
    timestamp       = models.DateTimeField(db_index=True)
    prediction      = models.CharField(max_length=20)
    confidence      = models.FloatField()
    prob_normal     = models.FloatField(default=0)
    prob_brute_force= models.FloatField(default=0)
    prob_port_scan  = models.FloatField(default=0)
    prob_anomaly    = models.FloatField(default=0)
    triggered_by    = models.CharField(max_length=20, default='auto')  # 'auto' | 'manual' | 'sim'

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.timestamp:%H:%M} | {self.prediction} ({self.confidence:.0%})"


class TrainSession(models.Model):
    """Har bir model trening sessiyasi."""

    STATUS_CHOICES = [
        ('pending',   'Pending'),
        ('running',   'Running'),
        ('done',      'Done'),
        ('failed',    'Failed'),
    ]

    created_at  = models.DateTimeField(auto_now_add=True)
    status      = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    accuracy    = models.FloatField(null=True, blank=True)
    f1          = models.FloatField(null=True, blank=True)
    precision   = models.FloatField(null=True, blank=True)
    recall      = models.FloatField(null=True, blank=True)
    roc_auc     = models.FloatField(null=True, blank=True)
    train_rows        = models.IntegerField(default=0)
    model_path        = models.CharField(max_length=255, blank=True)
    error_msg         = models.TextField(blank=True)
    confusion_matrix  = models.JSONField(null=True, blank=True)
    classes           = models.JSONField(null=True, blank=True)
    per_class         = models.JSONField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"TrainSession #{self.pk} | {self.status} | acc={self.accuracy}"
