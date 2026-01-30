"""
Scan Results Management Models
DEPRECATED: These models are being replaced by engine API-based models:
- ScanResult → Use CheckScan (check_results_management) or engine APIs
- ScanFinding → Use CheckFinding (check_results_management) or ComplianceFinding (compliance_management)
- ComplianceSummary → Use ComplianceFramework (compliance_management)

Migration path: Use engine API clients instead of these models
"""
import uuid
from django.db import models
from django.contrib.postgres.fields import ArrayField
from tenant_management.models import Tenants
from onboarding_management.models import OnboardingAccount, OnboardingExecution

# DEPRECATED: Use CheckScan from check_results_management or Check Results API
class ScanResult(models.Model):
    """Main scan results table - stores scan metadata"""
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_id = models.TextField(unique=True, default='pending')  # External scan ID from threat engine
    account = models.ForeignKey(
        OnboardingAccount,
        on_delete=models.CASCADE,
        related_name='scan_results',
        db_column='account_id'
    )
    execution = models.ForeignKey(
        OnboardingExecution,
        on_delete=models.SET_NULL,
        related_name='scan_results',
        db_column='execution_id',
        blank=True,
        null=True
    )
    tenant = models.ForeignKey(
        Tenants,
        on_delete=models.CASCADE,
        related_name='scan_results',
        db_column='tenant_id'
    )
    provider = models.CharField(max_length=50, default='unknown')  # aws, azure, gcp, etc.
    scan_type = models.CharField(max_length=50, default='manual')  # scheduled, manual, on-demand
    status = models.CharField(max_length=50, default='pending')  # running, completed, failed, cancelled
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(blank=True, null=True)
    total_checks = models.IntegerField(default=0)
    passed_checks = models.IntegerField(default=0)
    failed_checks = models.IntegerField(default=0)
    error_checks = models.IntegerField(default=0)
    skipped_checks = models.IntegerField(default=0)
    result_storage_path = models.TextField(blank=True, null=True)  # S3 path
    metadata = models.JSONField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'scan_results'
        verbose_name = 'Scan Result'
        verbose_name_plural = 'Scan Results'
        indexes = [
            models.Index(fields=['account']),
            models.Index(fields=['tenant']),
            models.Index(fields=['execution']),
            models.Index(fields=['status']),
            models.Index(fields=['started_at']),
            models.Index(fields=['provider']),
            models.Index(fields=['scan_id']),
        ]

    def __str__(self):
        return f"Scan {self.scan_id} - {self.status}"


# DEPRECATED: Use CheckFinding (check_results_management) or ComplianceFinding (compliance_management)
class ScanFinding(models.Model):
    """Individual check findings from scans"""
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_result = models.ForeignKey(
        ScanResult,
        on_delete=models.CASCADE,
        related_name='findings',
        db_column='scan_result_id'
    )
    check_id = models.TextField(default='unknown')  # Compliance check identifier
    check_name = models.TextField(default='unknown')
    check_category = models.CharField(max_length=100, blank=True, null=True)
    service = models.CharField(max_length=100, default='unknown')  # ec2, s3, rds, etc.
    resource_id = models.TextField(blank=True, null=True)
    resource_type = models.CharField(max_length=100, blank=True, null=True)
    region = models.CharField(max_length=100, blank=True, null=True)
    status = models.CharField(max_length=50, default='pending')  # passed, failed, error, skipped
    severity = models.CharField(max_length=50, blank=True, null=True)  # critical, high, medium, low, info
    rule_id = models.TextField(blank=True, null=True)
    rule_name = models.TextField(blank=True, null=True)
    rule_description = models.TextField(blank=True, null=True)
    finding_message = models.TextField(blank=True, null=True)
    remediation_steps = models.JSONField(blank=True, null=True)
    evidence = models.JSONField(blank=True, null=True)
    compliance_frameworks = ArrayField(models.CharField(max_length=100), blank=True, null=True)
    tags = models.JSONField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'scan_findings'
        verbose_name = 'Scan Finding'
        verbose_name_plural = 'Scan Findings'
        indexes = [
            models.Index(fields=['scan_result']),
            models.Index(fields=['status']),
            models.Index(fields=['severity']),
            models.Index(fields=['service']),
            models.Index(fields=['check_id']),
            models.Index(fields=['resource_id']),
        ]

    def __str__(self):
        return f"Finding {self.check_id} - {self.status}"


class ScanFindingAsset(models.Model):
    """Links scan findings to assets"""
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    finding = models.ForeignKey(
        ScanFinding,
        on_delete=models.CASCADE,
        related_name='asset_links',
        db_column='finding_id'
    )
    asset = models.ForeignKey(
        'assets_management.Asset',
        on_delete=models.CASCADE,
        related_name='finding_links',
        db_column='asset_id'
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'scan_findings_assets'
        verbose_name = 'Scan Finding Asset'
        verbose_name_plural = 'Scan Finding Assets'
        unique_together = ('finding', 'asset')
        indexes = [
            models.Index(fields=['finding']),
            models.Index(fields=['asset']),
        ]

    def __str__(self):
        return f"Finding {self.finding.check_id} → Asset {self.asset.name}"


# DEPRECATED: Use ComplianceFramework from compliance_management or ComplianceEngineClient
class ComplianceSummary(models.Model):
    """Compliance summary by framework"""
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_result = models.ForeignKey(
        ScanResult,
        on_delete=models.CASCADE,
        related_name='compliance_summaries',
        db_column='scan_result_id'
    )
    tenant = models.ForeignKey(
        Tenants,
        on_delete=models.CASCADE,
        related_name='compliance_summaries',
        db_column='tenant_id'
    )
    account = models.ForeignKey(
        OnboardingAccount,
        on_delete=models.CASCADE,
        related_name='compliance_summaries',
        db_column='account_id'
    )
    framework = models.CharField(max_length=100, default='CIS')  # CIS, PCI-DSS, HIPAA, SOC2, etc.
    framework_version = models.CharField(max_length=50, blank=True, null=True)
    total_controls = models.IntegerField(default=0)
    passed_controls = models.IntegerField(default=0)
    failed_controls = models.IntegerField(default=0)
    not_applicable_controls = models.IntegerField(default=0)
    compliance_score = models.DecimalField(max_digits=5, decimal_places=2, blank=True, null=True)
    last_updated = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'compliance_summary'
        verbose_name = 'Compliance Summary'
        verbose_name_plural = 'Compliance Summaries'
        unique_together = ('scan_result', 'framework')
        indexes = [
            models.Index(fields=['tenant']),
            models.Index(fields=['account']),
            models.Index(fields=['framework']),
            models.Index(fields=['scan_result']),
        ]

    def __str__(self):
        return f"{self.framework} - {self.compliance_score}%"

