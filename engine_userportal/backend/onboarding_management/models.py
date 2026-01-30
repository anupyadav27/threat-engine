"""
Onboarding Management Models
These models replace DynamoDB tables for onboarding data
"""
import uuid
from django.db import models
from django.contrib.postgres.fields import ArrayField
from tenant_management.models import Tenants


class OnboardingTenant(models.Model):
    """Onboarding tenant - maps to threat-engine-tenants DynamoDB table"""
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant_name = models.CharField(max_length=255, unique=True)
    description = models.TextField(blank=True, null=True)
    status = models.CharField(max_length=50, default='active')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'onboarding_tenants'
        verbose_name = 'Onboarding Tenant'
        verbose_name_plural = 'Onboarding Tenants'
        indexes = [
            models.Index(fields=['tenant_name']),
            models.Index(fields=['status']),
        ]

    def __str__(self):
        return self.tenant_name


class OnboardingProvider(models.Model):
    """Cloud provider configuration - maps to threat-engine-providers DynamoDB table"""
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(
        OnboardingTenant,
        on_delete=models.CASCADE,
        related_name='providers',
        db_column='tenant_id'
    )
    provider_type = models.CharField(max_length=50)  # aws, azure, gcp, alicloud, oci, ibm
    status = models.CharField(max_length=50, default='active')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'onboarding_providers'
        verbose_name = 'Onboarding Provider'
        verbose_name_plural = 'Onboarding Providers'
        indexes = [
            models.Index(fields=['tenant', 'provider_type']),
            models.Index(fields=['provider_type']),
        ]
        unique_together = ('tenant', 'provider_type')

    def __str__(self):
        return f"{self.tenant.tenant_name} - {self.provider_type}"


class OnboardingAccount(models.Model):
    """Account metadata - maps to threat-engine-accounts DynamoDB table
    API: GET /api/v1/onboarding/accounts, GET /api/v1/onboarding/accounts/{account_id}
    """
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    provider = models.ForeignKey(
        OnboardingProvider,
        on_delete=models.CASCADE,
        related_name='accounts',
        db_column='provider_id'
    )
    tenant = models.ForeignKey(
        OnboardingTenant,
        on_delete=models.CASCADE,
        related_name='accounts',
        db_column='tenant_id'
    )
    account_name = models.CharField(max_length=255)
    account_number = models.CharField(max_length=100, blank=True, null=True)
    status = models.CharField(max_length=50, default='pending', db_index=True)  # active, inactive, error
    onboarding_status = models.CharField(max_length=50, default='pending', db_index=True)  # pending, completed, failed
    last_validated_at = models.DateTimeField(blank=True, null=True)
    
    # Health and statistics (from API: GET /api/v1/accounts/{account_id}/health)
    health_status = models.CharField(max_length=50, blank=True, null=True)  # healthy, degraded, unhealthy
    credentials_valid = models.BooleanField(default=False)
    last_scan = models.DateTimeField(blank=True, null=True)
    last_scan_status = models.CharField(max_length=50, blank=True, null=True)  # success, failed, running
    
    # Statistics (from API: GET /api/v1/accounts/{account_id}/statistics)
    total_scans = models.IntegerField(default=0)
    successful_scans = models.IntegerField(default=0)
    failed_scans = models.IntegerField(default=0)
    success_rate = models.FloatField(default=0.0)
    average_scan_duration_seconds = models.FloatField(default=0.0)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'onboarding_accounts'
        verbose_name = 'Onboarding Account'
        verbose_name_plural = 'Onboarding Accounts'
        indexes = [
            models.Index(fields=['tenant', 'status']),
            models.Index(fields=['provider', 'status']),
            models.Index(fields=['account_number']),
        ]

    def __str__(self):
        return f"{self.account_name} ({self.account_number})"


class OnboardingSchedule(models.Model):
    """Scan schedule - maps to threat-engine-schedules DynamoDB table"""
    SCHEDULE_TYPES = [
        ('cron', 'Cron'),
        ('interval', 'Interval'),
        ('one_time', 'One Time'),
    ]

    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(
        OnboardingTenant,
        on_delete=models.CASCADE,
        related_name='schedules',
        db_column='tenant_id'
    )
    account = models.ForeignKey(
        OnboardingAccount,
        on_delete=models.CASCADE,
        related_name='schedules',
        db_column='account_id'
    )
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    schedule_type = models.CharField(max_length=20, choices=SCHEDULE_TYPES)
    cron_expression = models.CharField(max_length=255, blank=True, null=True)
    interval_seconds = models.IntegerField(blank=True, null=True)
    timezone = models.CharField(max_length=50, default='UTC')
    regions = ArrayField(models.CharField(max_length=100), blank=True, null=True)
    services = ArrayField(models.CharField(max_length=100), blank=True, null=True)
    exclude_services = ArrayField(models.CharField(max_length=100), blank=True, null=True)
    status = models.CharField(max_length=50, default='active')
    enabled = models.BooleanField(default=True)
    last_run_at = models.DateTimeField(blank=True, null=True)
    next_run_at = models.DateTimeField(blank=True, null=True)
    run_count = models.IntegerField(default=0)
    success_count = models.IntegerField(default=0)
    failure_count = models.IntegerField(default=0)
    notify_on_success = models.BooleanField(default=False)
    notify_on_failure = models.BooleanField(default=True)
    notification_channels = ArrayField(models.CharField(max_length=255), blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'onboarding_schedules'
        verbose_name = 'Onboarding Schedule'
        verbose_name_plural = 'Onboarding Schedules'
        indexes = [
            models.Index(fields=['tenant', 'id']),
            models.Index(fields=['account', 'id']),
            models.Index(fields=['enabled', 'next_run_at']),
            models.Index(fields=['status']),
        ]

    def __str__(self):
        return f"{self.name} ({self.schedule_type})"


class OnboardingExecution(models.Model):
    """Schedule execution history - maps to threat-engine-executions DynamoDB table"""
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    schedule = models.ForeignKey(
        OnboardingSchedule,
        on_delete=models.CASCADE,
        related_name='executions',
        db_column='schedule_id'
    )
    account = models.ForeignKey(
        OnboardingAccount,
        on_delete=models.CASCADE,
        related_name='executions',
        db_column='account_id'
    )
    started_at = models.DateTimeField()
    completed_at = models.DateTimeField(blank=True, null=True)
    status = models.CharField(max_length=50, default='running')
    scan_id = models.CharField(max_length=255, blank=True, null=True)
    total_checks = models.IntegerField(blank=True, null=True)
    passed_checks = models.IntegerField(blank=True, null=True)
    failed_checks = models.IntegerField(blank=True, null=True)
    error_message = models.TextField(blank=True, null=True)
    triggered_by = models.CharField(max_length=50, default='scheduler')
    execution_time_seconds = models.IntegerField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'onboarding_executions'
        verbose_name = 'Onboarding Execution'
        verbose_name_plural = 'Onboarding Executions'
        indexes = [
            models.Index(fields=['schedule', 'started_at']),
            models.Index(fields=['account', 'started_at']),
            models.Index(fields=['status']),
            models.Index(fields=['scan_id']),
        ]

    def __str__(self):
        return f"Execution {self.id} - {self.status}"


class OnboardingScanResult(models.Model):
    """Scan result metadata - maps to threat-engine-scan-results DynamoDB table"""
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    account = models.ForeignKey(
        OnboardingAccount,
        on_delete=models.CASCADE,
        related_name='onboarding_scan_results',
        db_column='account_id'
    )
    execution = models.ForeignKey(
        OnboardingExecution,
        on_delete=models.SET_NULL,
        related_name='onboarding_scan_results',
        db_column='execution_id',
        blank=True,
        null=True
    )
    status = models.CharField(max_length=50, default='pending')
    started_at = models.DateTimeField()
    completed_at = models.DateTimeField(blank=True, null=True)
    metadata = models.JSONField(blank=True, null=True)  # Store additional scan metadata
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'onboarding_scan_results'
        verbose_name = 'Onboarding Scan Result'
        verbose_name_plural = 'Onboarding Scan Results'
        indexes = [
            models.Index(fields=['account', 'started_at']),
            models.Index(fields=['status', 'started_at']),
            models.Index(fields=['execution']),
        ]

    def __str__(self):
        return f"Scan {self.id} - {self.status}"

