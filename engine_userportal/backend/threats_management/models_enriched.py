"""
Enriched Threat Management Models
Mapped to Threat Engine API endpoints
Based on UI mockups and threat_report_schema
"""
import uuid
from django.db import models
from django.contrib.postgres.fields import ArrayField, JSONField
from tenant_management.models import Tenants


class ThreatReport(models.Model):
    """
    Threat report model mapped to Threat Engine API
    API: GET /api/v1/threat/reports/{scan_run_id}
    """
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_run_id = models.TextField(unique=True, db_index=True)
    tenant = models.ForeignKey(
        Tenants,
        on_delete=models.CASCADE,
        related_name="threat_reports",
        null=True,
        blank=True
    )
    
    # Scan context
    cloud = models.CharField(max_length=50)  # aws, azure, gcp, etc.
    trigger_type = models.CharField(max_length=50)  # manual, scheduled, api
    accounts = ArrayField(models.CharField(max_length=255), default=list)
    regions = ArrayField(models.CharField(max_length=100), default=list)
    services = ArrayField(models.CharField(max_length=100), default=list)
    
    # Timestamps
    started_at = models.DateTimeField()
    completed_at = models.DateTimeField(blank=True, null=True)
    generated_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'threat_reports'
        indexes = [
            models.Index(fields=['tenant', 'scan_run_id']),
            models.Index(fields=['cloud']),
        ]

    def __str__(self):
        return f"Threat Report {self.scan_run_id}"


class Threat(models.Model):
    """
    Threat model mapped to Threat Engine API
    API: GET /api/v1/threat/list, GET /api/v1/threat/{threat_id}
    """
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Info'),
    ]
    
    THREAT_TYPE_CHOICES = [
        ('exposure', 'Exposure'),
        ('identity', 'Identity'),
        ('lateral_movement', 'Lateral Movement'),
        ('data_exfiltration', 'Data Exfiltration'),
        ('privilege_escalation', 'Privilege Escalation'),
        ('data_breach', 'Data Breach'),
    ]
    
    STATUS_CHOICES = [
        ('open', 'Open'),
        ('resolved', 'Resolved'),
        ('suppressed', 'Suppressed'),
        ('false_positive', 'False Positive'),
    ]
    
    CONFIDENCE_CHOICES = [
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
    ]
    
    # Primary identifiers
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    threat_id = models.TextField(unique=True, db_index=True)  # Stable threat identifier from engine
    tenant = models.ForeignKey(
        Tenants,
        on_delete=models.CASCADE,
        related_name="threats",
        null=True,
        blank=True
    )
    report = models.ForeignKey(
        ThreatReport,
        on_delete=models.CASCADE,
        related_name="threats",
        null=True,
        blank=True
    )
    
    # Threat details
    threat_type = models.CharField(max_length=50, choices=THREAT_TYPE_CHOICES, db_index=True)
    title = models.TextField()
    description = models.TextField(blank=True, null=True)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, db_index=True)
    confidence = models.CharField(max_length=20, choices=CONFIDENCE_CHOICES, default='high')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='open', db_index=True)
    
    # Timestamps
    first_seen_at = models.DateTimeField(db_index=True)
    last_seen_at = models.DateTimeField(db_index=True)
    
    # Correlations
    misconfig_finding_refs = ArrayField(models.CharField(max_length=255), default=list)
    affected_assets = JSONField(default=list)  # List of asset objects
    evidence_refs = ArrayField(models.CharField(max_length=255), default=list)
    
    # Remediation
    remediation = JSONField(default=dict, blank=True)  # Remediation steps and guidance
    
    # Metadata
    notes = models.TextField(blank=True, null=True)
    assignee = models.CharField(max_length=255, blank=True, null=True)
    status_updated_at = models.DateTimeField(blank=True, null=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'threats'
        indexes = [
            models.Index(fields=['tenant', 'severity']),
            models.Index(fields=['tenant', 'status']),
            models.Index(fields=['tenant', 'threat_type']),
            models.Index(fields=['threat_id']),
            models.Index(fields=['first_seen_at']),
            models.Index(fields=['last_seen_at']),
        ]

    def __str__(self):
        return f"{self.title} ({self.severity})"


class ThreatSummary(models.Model):
    """
    Threat summary statistics model
    API: GET /api/v1/threat/summary
    """
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_run_id = models.TextField(db_index=True)
    tenant = models.ForeignKey(
        Tenants,
        on_delete=models.CASCADE,
        related_name="threat_summaries",
        null=True,
        blank=True
    )
    
    # Summary statistics
    total_threats = models.IntegerField(default=0)
    threats_by_severity = JSONField(default=dict)  # {"critical": 47, "high": 23}
    threats_by_category = JSONField(default=dict)  # {"exposure": 18, "identity": 12}
    threats_by_status = JSONField(default=dict)  # {"open": 70, "resolved": 10}
    coverage_percentage = models.FloatField(default=0.0)
    
    generated_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'threat_summaries'
        indexes = [
            models.Index(fields=['tenant', 'scan_run_id']),
        ]

    def __str__(self):
        return f"Summary for {self.scan_run_id} - {self.total_threats} threats"


class ThreatTrend(models.Model):
    """
    Threat trend data model
    API: GET /api/v1/threat/analytics/trend
    """
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(
        Tenants,
        on_delete=models.CASCADE,
        related_name="threat_trends",
        null=True,
        blank=True
    )
    
    date = models.DateField(db_index=True)
    total_threats = models.IntegerField(default=0)
    by_severity = JSONField(default=dict)  # {"critical": 47, "high": 23}
    by_category = JSONField(default=dict)  # {"exposure": 18}
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'threat_trends'
        indexes = [
            models.Index(fields=['tenant', 'date']),
        ]
        unique_together = ('tenant', 'date')

    def __str__(self):
        return f"Trend {self.date} - {self.total_threats} threats"
