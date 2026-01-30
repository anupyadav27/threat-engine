"""
Compliance Management Models
Mapped to Compliance Engine API endpoints
Based on UI mockups and enterprise_report_schema
"""
import uuid
from django.db import models
from django.contrib.postgres.fields import ArrayField, JSONField
from tenant_management.models import Tenants


class ComplianceReport(models.Model):
    """
    Compliance report model mapped to Compliance Engine API
    API: POST /api/v1/compliance/generate, GET /api/v1/compliance/report/{report_id}
    """
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    report_id = models.TextField(unique=True, db_index=True)
    scan_id = models.TextField(db_index=True)
    tenant = models.ForeignKey(
        Tenants,
        on_delete=models.CASCADE,
        related_name="compliance_reports",
        null=True,
        blank=True
    )
    
    # Scan context
    csp = models.CharField(max_length=50)  # aws, azure, gcp, etc.
    account_id = models.CharField(max_length=255, blank=True, null=True)
    
    # Report metadata
    generated_at = models.DateTimeField(auto_now_add=True)
    scanned_at = models.DateTimeField(blank=True, null=True)
    
    class Meta:
        db_table = 'compliance_reports'
        indexes = [
            models.Index(fields=['tenant', 'scan_id']),
            models.Index(fields=['csp']),
        ]

    def __str__(self):
        return f"Compliance Report {self.report_id}"


class ComplianceFramework(models.Model):
    """
    Framework compliance status model
    API: GET /api/v1/compliance/framework/{framework}/status
    """
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    report = models.ForeignKey(
        ComplianceReport,
        on_delete=models.CASCADE,
        related_name="frameworks",
        null=True,
        blank=True
    )
    tenant = models.ForeignKey(
        Tenants,
        on_delete=models.CASCADE,
        related_name="compliance_frameworks",
        null=True,
        blank=True
    )
    
    # Framework details
    framework = models.CharField(max_length=255, db_index=True)  # CIS AWS Foundations Benchmark
    version = models.CharField(max_length=50, blank=True, null=True)
    
    # Compliance status
    compliance_score = models.FloatField(default=0.0)
    status = models.CharField(max_length=20, db_index=True)  # PASS, PARTIAL, FAIL
    
    # Control counts
    controls_total = models.IntegerField(default=0)
    controls_passed = models.IntegerField(default=0)
    controls_failed = models.IntegerField(default=0)
    controls_not_applicable = models.IntegerField(default=0)
    
    # Controls list (stored as JSON for flexibility)
    controls = JSONField(default=list)  # Full control details
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'compliance_frameworks'
        indexes = [
            models.Index(fields=['tenant', 'framework']),
            models.Index(fields=['status']),
            models.Index(fields=['compliance_score']),
        ]
        unique_together = ('report', 'framework')

    def __str__(self):
        return f"{self.framework} - {self.compliance_score}%"


class ComplianceControl(models.Model):
    """
    Individual compliance control model
    API: GET /api/v1/compliance/framework/{framework}/control/{control_id}
    """
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    framework = models.ForeignKey(
        ComplianceFramework,
        on_delete=models.CASCADE,
        related_name="controls",
        null=True,
        blank=True
    )
    tenant = models.ForeignKey(
        Tenants,
        on_delete=models.CASCADE,
        related_name="compliance_controls",
        null=True,
        blank=True
    )
    
    # Control details
    control_id = models.CharField(max_length=100, db_index=True)  # e.g., "2.1.1"
    control_title = models.TextField()
    category = models.CharField(max_length=255, blank=True, null=True)
    
    # Status
    status = models.CharField(max_length=20, db_index=True)  # PASS, FAIL, NOT_APPLICABLE
    compliance_percentage = models.FloatField(default=0.0)
    
    # Resources
    total_resources = models.IntegerField(default=0)
    passed_resources = models.IntegerField(default=0)
    failed_resources = models.IntegerField(default=0)
    
    # Details
    affected_resources = JSONField(default=list)  # List of resource details
    checks = JSONField(default=list)  # Check results
    evidence = JSONField(default=list)  # Evidence references
    remediation_steps = ArrayField(models.TextField(), default=list)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'compliance_controls'
        indexes = [
            models.Index(fields=['tenant', 'framework', 'control_id']),
            models.Index(fields=['status']),
            models.Index(fields=['category']),
        ]
        unique_together = ('framework', 'control_id')

    def __str__(self):
        return f"{self.control_id} - {self.control_title}"


class ComplianceTrend(models.Model):
    """
    Compliance trend data model
    API: GET /api/v1/compliance/trends
    """
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(
        Tenants,
        on_delete=models.CASCADE,
        related_name="compliance_trends",
        null=True,
        blank=True
    )
    
    date = models.DateField(db_index=True)
    csp = models.CharField(max_length=50, db_index=True)
    account_id = models.CharField(max_length=255, blank=True, null=True)
    framework = models.CharField(max_length=255, blank=True, null=True)
    
    overall_score = models.FloatField(default=0.0)
    frameworks = JSONField(default=dict)  # Framework scores by name
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'compliance_trends'
        indexes = [
            models.Index(fields=['tenant', 'date']),
            models.Index(fields=['csp', 'account_id']),
        ]
        unique_together = ('tenant', 'date', 'csp', 'account_id', 'framework')

    def __str__(self):
        return f"Trend {self.date} - {self.overall_score}%"


class ComplianceFinding(models.Model):
    """
    Compliance finding model (from enterprise report)
    API: POST /api/v1/compliance/generate/enterprise
    """
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Info'),
    ]
    
    STATUS_CHOICES = [
        ('open', 'Open'),
        ('resolved', 'Resolved'),
        ('suppressed', 'Suppressed'),
        ('exception', 'Exception'),
    ]
    
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    finding_id = models.TextField(unique=True, db_index=True)  # Stable finding ID from engine
    report = models.ForeignKey(
        ComplianceReport,
        on_delete=models.CASCADE,
        related_name="findings",
        null=True,
        blank=True
    )
    tenant = models.ForeignKey(
        Tenants,
        on_delete=models.CASCADE,
        related_name="compliance_findings",
        null=True,
        blank=True
    )
    
    # Finding details
    rule_id = models.TextField(db_index=True)
    rule_version = models.CharField(max_length=50, blank=True, null=True)
    category = models.CharField(max_length=255, blank=True, null=True)
    title = models.TextField()
    description = models.TextField(blank=True, null=True)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, db_index=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='open', db_index=True)
    
    # Timestamps
    first_seen_at = models.DateTimeField(db_index=True)
    last_seen_at = models.DateTimeField(db_index=True)
    
    # Compliance mappings
    compliance_mappings = JSONField(default=list)  # Framework control mappings
    affected_assets = JSONField(default=list)  # Affected asset details
    evidence = JSONField(default=list)  # Evidence references
    remediation = JSONField(default=dict, blank=True)  # Remediation steps
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'compliance_findings'
        indexes = [
            models.Index(fields=['tenant', 'rule_id']),
            models.Index(fields=['tenant', 'severity']),
            models.Index(fields=['tenant', 'status']),
            models.Index(fields=['finding_id']),
        ]

    def __str__(self):
        return f"{self.title} ({self.severity})"
