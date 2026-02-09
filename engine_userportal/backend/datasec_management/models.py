"""
Data Security Management Models
Mapped to DataSec Engine API endpoints
Based on UI mockups
"""
import uuid
from django.db import models
from django.contrib.postgres.fields import ArrayField, JSONField
from tenant_management.models import Tenants


class DataSecurityReport(models.Model):
    """
    Data security report model
    API: POST /api/v1/data-security/scan
    """
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_id = models.TextField(db_index=True)
    tenant = models.ForeignKey(
        Tenants,
        on_delete=models.CASCADE,
        related_name="datasec_reports",
        null=True,
        blank=True
    )
    
    # Scan context
    csp = models.CharField(max_length=50)  # aws, azure, gcp, etc.
    account_id = models.CharField(max_length=255, blank=True, null=True)
    
    # Summary
    total_data_stores = models.IntegerField(default=0)
    total_findings = models.IntegerField(default=0)
    security_score = models.FloatField(default=0.0)
    
    # Findings by module
    findings_by_module = JSONField(default=dict)  # {"data_protection_encryption": 1791}
    
    generated_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'datasec_reports'
        indexes = [
            models.Index(fields=['tenant', 'scan_id']),
            models.Index(fields=['csp']),
        ]

    def __str__(self):
        return f"DataSec Report {self.scan_id}"


class DataCatalog(models.Model):
    """
    Data catalog model
    API: GET /api/v1/data-security/catalog
    """
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    resource_uid = models.TextField(unique=True, db_index=True)  # ARN or resource identifier
    tenant = models.ForeignKey(
        Tenants,
        on_delete=models.CASCADE,
        related_name="datasec_catalog",
        null=True,
        blank=True
    )
    report = models.ForeignKey(
        DataSecurityReport,
        on_delete=models.CASCADE,
        related_name="catalog_items",
        null=True,
        blank=True
    )
    
    # Resource details
    resource_id = models.TextField()
    resource_arn = models.TextField(blank=True, null=True)
    resource_type = models.CharField(max_length=255, db_index=True)
    service = models.CharField(max_length=100, db_index=True)  # s3, dynamodb, rds, etc.
    region = models.CharField(max_length=100, db_index=True)
    account_id = models.CharField(max_length=255, db_index=True)
    name = models.TextField(blank=True, null=True)
    
    # Status
    lifecycle_state = models.CharField(max_length=50, blank=True, null=True)
    health_status = models.CharField(max_length=50, blank=True, null=True)
    
    # Tags
    tags = JSONField(default=dict, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'datasec_catalog'
        indexes = [
            models.Index(fields=['tenant', 'service']),
            models.Index(fields=['tenant', 'account_id']),
            models.Index(fields=['tenant', 'region']),
            models.Index(fields=['resource_uid']),
        ]

    def __str__(self):
        return f"{self.name or self.resource_id} ({self.service})"


class DataSecurityFinding(models.Model):
    """
    Data security finding model
    API: GET /api/v1/data-security/findings
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
        ('WARN', 'Warning'),
        ('SKIP', 'Skipped'),
    ]
    
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    finding_id = models.TextField(unique=True, db_index=True)
    tenant = models.ForeignKey(
        Tenants,
        on_delete=models.CASCADE,
        related_name="datasec_findings",
        null=True,
        blank=True
    )
    report = models.ForeignKey(
        DataSecurityReport,
        on_delete=models.CASCADE,
        related_name="findings",
        null=True,
        blank=True
    )
    catalog_item = models.ForeignKey(
        DataCatalog,
        on_delete=models.CASCADE,
        related_name="findings",
        null=True,
        blank=True
    )
    
    # Finding details
    scan_run_id = models.TextField(db_index=True)
    rule_id = models.TextField(db_index=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, db_index=True)
    resource_arn = models.TextField(db_index=True)
    service = models.CharField(max_length=100, db_index=True)
    region = models.CharField(max_length=100)
    account_id = models.CharField(max_length=255)
    
    # Data security context
    data_security_modules = ArrayField(models.CharField(max_length=100), default=list)
    is_data_security_relevant = models.BooleanField(default=True)
    data_security_context = JSONField(default=dict)  # Modules, categories, priority, impact
    
    # Compliance impact
    compliance_impact = JSONField(default=dict)  # GDPR, PCI, HIPAA mappings
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'datasec_findings'
        indexes = [
            models.Index(fields=['tenant', 'rule_id']),
            models.Index(fields=['tenant', 'status']),
            models.Index(fields=['tenant', 'service']),
            models.Index(fields=['resource_arn']),
        ]

    def __str__(self):
        return f"Finding {self.rule_id} - {self.status}"


class DataClassification(models.Model):
    """
    Data classification model
    API: GET /api/v1/data-security/classification
    """
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    resource_arn = models.TextField(unique=True, db_index=True)
    tenant = models.ForeignKey(
        Tenants,
        on_delete=models.CASCADE,
        related_name="datasec_classifications",
        null=True,
        blank=True
    )
    
    # Classification
    classification = ArrayField(models.CharField(max_length=100), default=list)  # PII, SENSITIVE, etc.
    confidence = models.FloatField(default=0.0)
    matched_patterns = ArrayField(models.TextField(), default=list)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'datasec_classifications'
        indexes = [
            models.Index(fields=['tenant', 'resource_arn']),
        ]

    def __str__(self):
        return f"Classification for {self.resource_arn}"


class DataResidency(models.Model):
    """
    Data residency model
    API: GET /api/v1/data-security/residency
    """
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    resource_arn = models.TextField(unique=True, db_index=True)
    tenant = models.ForeignKey(
        Tenants,
        on_delete=models.CASCADE,
        related_name="datasec_residency",
        null=True,
        blank=True
    )
    
    # Residency details
    primary_region = models.CharField(max_length=100)
    replication_regions = ArrayField(models.CharField(max_length=100), default=list)
    policy_name = models.CharField(max_length=255, blank=True, null=True)
    compliance_status = models.CharField(max_length=50, db_index=True)  # compliant, non_compliant
    violations = JSONField(default=list)  # List of violations
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'datasec_residency'
        indexes = [
            models.Index(fields=['tenant', 'resource_arn']),
            models.Index(fields=['compliance_status']),
        ]

    def __str__(self):
        return f"Residency for {self.resource_arn} - {self.compliance_status}"
