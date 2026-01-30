"""
Discovery Results Management Models
Mapped to Discovery Results API endpoints
Based on UI mockups
"""
import uuid
from django.db import models
from django.contrib.postgres.fields import ArrayField, JSONField
from tenant_management.models import Tenants


class DiscoveryScan(models.Model):
    """
    Discovery scan model
    API: GET /api/v1/discoveries/scans, GET /api/v1/discoveries/scans/{id}
    """
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_id = models.TextField(unique=True, db_index=True)
    tenant = models.ForeignKey(
        Tenants,
        on_delete=models.CASCADE,
        related_name="discovery_scans",
        null=True,
        blank=True
    )
    
    # Scan details
    account_id = models.CharField(max_length=255, db_index=True)
    region = models.CharField(max_length=100, db_index=True)
    provider = models.CharField(max_length=50, db_index=True)
    
    # Status
    status = models.CharField(max_length=50, db_index=True)
    scanned_at = models.DateTimeField(db_index=True)
    
    # Summary
    total_discoveries = models.IntegerField(default=0)
    unique_resources = models.IntegerField(default=0)
    services_scanned = models.IntegerField(default=0)
    
    # Service breakdown
    services = JSONField(default=dict)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'discovery_scans'
        indexes = [
            models.Index(fields=['tenant', 'scan_id']),
            models.Index(fields=['account_id', 'region']),
            models.Index(fields=['status']),
        ]

    def __str__(self):
        return f"Discovery Scan {self.scan_id}"


class Discovery(models.Model):
    """
    Discovery model
    API: GET /api/v1/discoveries/scans/{id}/discoveries, GET /api/v1/discoveries/discoveries/search
    """
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    discovery_id = models.TextField(unique=True, db_index=True)
    scan = models.ForeignKey(
        DiscoveryScan,
        on_delete=models.CASCADE,
        related_name="discoveries",
        null=True,
        blank=True
    )
    tenant = models.ForeignKey(
        Tenants,
        on_delete=models.CASCADE,
        related_name="discoveries",
        null=True,
        blank=True
    )
    
    # Discovery details
    resource_id = models.TextField()
    resource_arn = models.TextField(db_index=True, blank=True, null=True)
    resource_type = models.CharField(max_length=255, db_index=True)
    resource_uid = models.TextField(db_index=True, blank=True, null=True)
    service = models.CharField(max_length=100, db_index=True)
    region = models.CharField(max_length=100, db_index=True)
    account_id = models.CharField(max_length=255, db_index=True)
    name = models.TextField(blank=True, null=True)
    
    # Metadata
    tags = JSONField(default=dict, blank=True)
    lifecycle_state = models.CharField(max_length=50, blank=True, null=True)
    health_status = models.CharField(max_length=50, blank=True, null=True)
    
    # Function details (for serverless)
    function_details = JSONField(default=dict, blank=True)  # For Lambda, Cloud Functions, etc.
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'discoveries'
        indexes = [
            models.Index(fields=['tenant', 'scan', 'service']),
            models.Index(fields=['resource_arn']),
            models.Index(fields=['resource_type']),
        ]

    def __str__(self):
        return f"Discovery {self.resource_id} ({self.service})"


class DiscoveryDashboard(models.Model):
    """
    Discovery dashboard statistics model
    API: GET /api/v1/discoveries/dashboard
    """
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(
        Tenants,
        on_delete=models.CASCADE,
        related_name="discovery_dashboards",
        null=True,
        blank=True
    )
    
    # Summary statistics
    total_discoveries = models.IntegerField(default=0)
    unique_resources = models.IntegerField(default=0)
    services_scanned = models.IntegerField(default=0)
    
    # Top services
    top_services = JSONField(default=list)
    
    # Timestamps
    last_updated = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'discovery_dashboards'
        indexes = [
            models.Index(fields=['tenant']),
        ]

    def __str__(self):
        return f"Discovery Dashboard for {self.tenant}"
