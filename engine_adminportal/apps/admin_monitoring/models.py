"""
Models for admin monitoring app.
"""
from django.db import models
from django.contrib.postgres.fields import JSONField
from django.utils import timezone


class AdminMetric(models.Model):
    """Real-time metrics cache for tenants."""
    METRIC_TYPES = [
        ('active_scans', 'Active Scans'),
        ('compliance_score', 'Compliance Score'),
        ('findings_critical', 'Critical Findings'),
        ('findings_high', 'High Findings'),
        ('findings_medium', 'Medium Findings'),
        ('findings_low', 'Low Findings'),
        ('resources_count', 'Resources Count'),
        ('scan_success_rate', 'Scan Success Rate'),
        ('last_scan_timestamp', 'Last Scan Timestamp'),
    ]
    
    tenant_id = models.CharField(max_length=255, db_index=True)
    metric_type = models.CharField(max_length=50, choices=METRIC_TYPES)
    metric_value = models.FloatField()
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    metadata = models.JSONField(default=dict, blank=True)
    
    class Meta:
        db_table = 'admin_metrics'
        indexes = [
            models.Index(fields=['tenant_id', 'metric_type', '-timestamp']),
            models.Index(fields=['-timestamp']),
        ]
        get_latest_by = 'timestamp'
    
    def __str__(self):
        return f"{self.tenant_id} - {self.metric_type}: {self.metric_value}"
