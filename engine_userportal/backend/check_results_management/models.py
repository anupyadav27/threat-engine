"""
Check Results Management Models
Mapped to Check Results API endpoints
Based on UI mockups
"""
import uuid
from django.db import models
from django.contrib.postgres.fields import ArrayField, JSONField
from tenant_management.models import Tenants


class CheckScan(models.Model):
    """
    Check scan model
    API: GET /api/v1/checks/scans, GET /api/v1/checks/scans/{id}
    """
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_id = models.TextField(unique=True, db_index=True)
    tenant = models.ForeignKey(
        Tenants,
        on_delete=models.CASCADE,
        related_name="check_scans",
        null=True,
        blank=True
    )
    
    # Scan details
    account_id = models.CharField(max_length=255, db_index=True)
    region = models.CharField(max_length=100, db_index=True)
    provider = models.CharField(max_length=50, db_index=True)  # aws, azure, gcp, etc.
    
    # Status
    status = models.CharField(max_length=50, db_index=True)  # running, completed, failed
    scanned_at = models.DateTimeField(db_index=True)
    
    # Summary
    total_checks = models.IntegerField(default=0)
    passed_checks = models.IntegerField(default=0)
    failed_checks = models.IntegerField(default=0)
    error_checks = models.IntegerField(default=0)
    skipped_checks = models.IntegerField(default=0)
    
    # Service breakdown
    services = JSONField(default=dict)  # Service-level statistics
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'check_scans'
        indexes = [
            models.Index(fields=['tenant', 'scan_id']),
            models.Index(fields=['account_id', 'region']),
            models.Index(fields=['status']),
        ]

    def __str__(self):
        return f"Check Scan {self.scan_id}"


class CheckFinding(models.Model):
    """
    Check finding model
    API: GET /api/v1/checks/scans/{id}/findings, GET /api/v1/checks/findings/search
    """
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Info'),
    ]
    
    STATUS_CHOICES = [
        ('PASS', 'Pass'),
        ('FAIL', 'Fail'),
        ('ERROR', 'Error'),
        ('SKIP', 'Skip'),
    ]
    
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    finding_id = models.TextField(unique=True, db_index=True)
    scan = models.ForeignKey(
        CheckScan,
        on_delete=models.CASCADE,
        related_name="findings",
        null=True,
        blank=True
    )
    tenant = models.ForeignKey(
        Tenants,
        on_delete=models.CASCADE,
        related_name="check_findings",
        null=True,
        blank=True
    )
    
    # Finding details
    rule_id = models.TextField(db_index=True)
    rule_name = models.TextField(blank=True, null=True)
    check_id = models.TextField(db_index=True)
    check_name = models.TextField(blank=True, null=True)
    check_category = models.CharField(max_length=100, blank=True, null=True)
    
    # Resource details
    service = models.CharField(max_length=100, db_index=True)  # s3, ec2, iam, etc.
    resource_id = models.TextField(blank=True, null=True)
    resource_arn = models.TextField(db_index=True, blank=True, null=True)
    resource_type = models.CharField(max_length=100, blank=True, null=True)
    region = models.CharField(max_length=100, db_index=True)
    account_id = models.CharField(max_length=255, db_index=True)
    
    # Status
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, db_index=True)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, blank=True, null=True, db_index=True)
    
    # Details
    finding_message = models.TextField(blank=True, null=True)
    remediation_steps = JSONField(default=list, blank=True)
    evidence = JSONField(default=dict, blank=True)
    compliance_frameworks = ArrayField(models.CharField(max_length=100), default=list)
    tags = JSONField(default=dict, blank=True)
    
    # Timestamps
    first_seen_at = models.DateTimeField(blank=True, null=True)
    last_seen_at = models.DateTimeField(blank=True, null=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'check_findings'
        indexes = [
            models.Index(fields=['tenant', 'scan', 'status']),
            models.Index(fields=['tenant', 'rule_id']),
            models.Index(fields=['tenant', 'severity']),
            models.Index(fields=['resource_arn']),
            models.Index(fields=['service']),
        ]

    def __str__(self):
        return f"Finding {self.check_id} - {self.status}"


class CheckDashboard(models.Model):
    """
    Check dashboard statistics model
    API: GET /api/v1/checks/dashboard
    """
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(
        Tenants,
        on_delete=models.CASCADE,
        related_name="check_dashboards",
        null=True,
        blank=True
    )
    
    # Summary statistics
    total_checks = models.IntegerField(default=0)
    passed = models.IntegerField(default=0)
    failed = models.IntegerField(default=0)
    errors = models.IntegerField(default=0)
    skipped = models.IntegerField(default=0)
    pass_rate = models.FloatField(default=0.0)
    
    # Top failing services
    top_failing_services = JSONField(default=list)
    
    # Timestamps
    last_updated = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'check_dashboards'
        indexes = [
            models.Index(fields=['tenant']),
        ]

    def __str__(self):
        return f"Check Dashboard for {self.tenant}"
