"""
Models for admin audit app.
"""
from django.db import models
from django.contrib.postgres.fields import JSONField
from django.utils import timezone


class AdminAuditLog(models.Model):
    """Admin action audit trail."""
    ACTION_TYPES = [
        ('user_create', 'User Created'),
        ('user_update', 'User Updated'),
        ('user_delete', 'User Deleted'),
        ('tenant_create', 'Tenant Created'),
        ('tenant_update', 'Tenant Updated'),
        ('tenant_suspend', 'Tenant Suspended'),
        ('tenant_activate', 'Tenant Activated'),
        ('role_assign', 'Role Assigned'),
        ('role_remove', 'Role Removed'),
        ('permission_modify', 'Permission Modified'),
        ('data_export', 'Data Exported'),
        ('config_change', 'Configuration Changed'),
    ]
    
    admin_user_id = models.CharField(max_length=255, db_index=True)
    action_type = models.CharField(max_length=50, choices=ACTION_TYPES)
    resource_type = models.CharField(max_length=50)  # 'user', 'tenant', 'role', etc.
    resource_id = models.CharField(max_length=255, null=True, blank=True)
    details = models.JSONField(default=dict, blank=True)
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    
    class Meta:
        db_table = 'admin_audit_logs'
        indexes = [
            models.Index(fields=['admin_user_id', '-timestamp']),
            models.Index(fields=['resource_type', 'resource_id']),
            models.Index(fields=['-timestamp']),
        ]
        get_latest_by = 'timestamp'
    
    def __str__(self):
        return f"{self.action_type} - {self.resource_type} - {self.timestamp}"


class AdminAlert(models.Model):
    """System alerts and notifications."""
    ALERT_TYPES = [
        ('engine_down', 'Engine Down'),
        ('high_error_rate', 'High Error Rate'),
        ('scan_failure', 'Scan Failure'),
        ('quota_exceeded', 'Quota Exceeded'),
        ('security_breach', 'Security Breach'),
    ]
    
    SEVERITY_LEVELS = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
    ]
    
    STATUS_CHOICES = [
        ('open', 'Open'),
        ('acknowledged', 'Acknowledged'),
        ('resolved', 'Resolved'),
    ]
    
    alert_type = models.CharField(max_length=50, choices=ALERT_TYPES)
    severity = models.CharField(max_length=20, choices=SEVERITY_LEVELS)
    tenant_id = models.CharField(max_length=255, null=True, blank=True, db_index=True)
    message = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='open')
    created_at = models.DateTimeField(default=timezone.now, db_index=True)
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    acknowledged_by = models.CharField(max_length=255, null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    
    class Meta:
        db_table = 'admin_alerts'
        indexes = [
            models.Index(fields=['status', '-created_at']),
            models.Index(fields=['tenant_id', '-created_at']),
            models.Index(fields=['severity', '-created_at']),
        ]
    
    def __str__(self):
        return f"{self.alert_type} - {self.severity} - {self.created_at}"
