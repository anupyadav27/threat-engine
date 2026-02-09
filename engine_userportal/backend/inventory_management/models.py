"""
Inventory Management Models
Mapped to Inventory Engine API endpoints
Based on UI mockups and engine API responses
"""
import uuid
from django.db import models
from django.contrib.postgres.fields import ArrayField
from tenant_management.models import Tenants


class InventoryAsset(models.Model):
    """
    Asset model mapped to Inventory Engine API
    API: GET /api/v1/inventory/assets
    """
    # Primary identifiers
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    resource_uid = models.TextField(unique=True, db_index=True)  # ARN or resource identifier
    tenant = models.ForeignKey(
        Tenants,
        on_delete=models.CASCADE,
        related_name="inventory_assets",
        null=True,
        blank=True
    )
    
    # Scan context
    scan_run_id = models.TextField(db_index=True)
    
    # Provider and location
    provider = models.CharField(max_length=50, db_index=True)  # aws, azure, gcp, etc.
    account_id = models.CharField(max_length=255, db_index=True)
    region = models.CharField(max_length=100, db_index=True, blank=True, null=True)
    scope = models.CharField(max_length=20, default="regional")  # global, regional
    
    # Resource details
    resource_type = models.CharField(max_length=255, db_index=True)  # s3.bucket, ec2.instance, etc.
    resource_id = models.TextField()
    name = models.TextField(blank=True, null=True)
    
    # Metadata
    tags = models.JSONField(default=dict, blank=True)
    metadata = models.JSONField(default=dict, blank=True)  # versioning, encryption, etc.
    hash_sha256 = models.TextField(blank=True, null=True)  # For drift detection
    
    # Timestamps
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_scanned_at = models.DateTimeField(blank=True, null=True)
    
    class Meta:
        db_table = 'inventory_assets'
        indexes = [
            models.Index(fields=['tenant', 'provider']),
            models.Index(fields=['tenant', 'resource_type']),
            models.Index(fields=['tenant', 'account_id']),
            models.Index(fields=['tenant', 'region']),
            models.Index(fields=['scan_run_id']),
            models.Index(fields=['resource_uid']),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=['tenant', 'resource_uid', 'scan_run_id'],
                name='unique_asset_scan'
            )
        ]

    def __str__(self):
        return f"{self.name or self.resource_id} ({self.resource_type})"


class InventoryRelationship(models.Model):
    """
    Asset relationship model mapped to Inventory Engine API
    API: GET /api/v1/inventory/assets/{resource_uid}/relationships
    """
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(
        Tenants,
        on_delete=models.CASCADE,
        related_name="inventory_relationships",
        null=True,
        blank=True
    )
    scan_run_id = models.TextField(db_index=True)
    
    # Relationship details
    provider = models.CharField(max_length=50)
    account_id = models.CharField(max_length=255)
    region = models.CharField(max_length=100, blank=True, null=True)
    relation_type = models.CharField(max_length=100, db_index=True)  # encrypted_by, contains, etc.
    
    # Connected assets
    from_uid = models.TextField(db_index=True)  # Source asset UID
    to_uid = models.TextField(db_index=True)  # Target asset UID
    
    # Relationship properties
    properties = models.JSONField(default=dict, blank=True)  # Additional relationship metadata
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'inventory_relationships'
        indexes = [
            models.Index(fields=['tenant', 'scan_run_id']),
            models.Index(fields=['from_uid']),
            models.Index(fields=['to_uid']),
            models.Index(fields=['relation_type']),
        ]

    def __str__(self):
        return f"{self.from_uid} → {self.to_uid} ({self.relation_type})"


class InventoryDrift(models.Model):
    """
    Drift detection model mapped to Inventory Engine API
    API: GET /api/v1/inventory/drift
    """
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(
        Tenants,
        on_delete=models.CASCADE,
        related_name="inventory_drift",
        null=True,
        blank=True
    )
    
    # Scan comparison
    baseline_scan = models.TextField(db_index=True)
    compare_scan = models.TextField(db_index=True)
    
    # Drift details
    change_type = models.CharField(max_length=50, db_index=True)  # asset_added, asset_removed, asset_changed
    resource_uid = models.TextField(db_index=True)
    resource_type = models.CharField(max_length=255)
    provider = models.CharField(max_length=50)
    account_id = models.CharField(max_length=255)
    region = models.CharField(max_length=100, blank=True, null=True)
    
    # Change details
    diff = models.JSONField(default=dict, blank=True)  # What changed
    
    detected_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'inventory_drift'
        indexes = [
            models.Index(fields=['tenant', 'baseline_scan', 'compare_scan']),
            models.Index(fields=['change_type']),
            models.Index(fields=['resource_uid']),
        ]

    def __str__(self):
        return f"{self.change_type} - {self.resource_uid}"


class InventoryScanSummary(models.Model):
    """
    Scan summary model mapped to Inventory Engine API
    API: GET /api/v1/inventory/runs/latest/summary
    """
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_run_id = models.TextField(unique=True, db_index=True)
    tenant = models.ForeignKey(
        Tenants,
        on_delete=models.CASCADE,
        related_name="inventory_scans",
        null=True,
        blank=True
    )
    
    # Scan metadata
    started_at = models.DateTimeField()
    completed_at = models.DateTimeField(blank=True, null=True)
    status = models.CharField(max_length=50, default="running")
    
    # Summary statistics
    total_assets = models.IntegerField(default=0)
    total_relationships = models.IntegerField(default=0)
    
    # Breakdowns
    assets_by_provider = models.JSONField(default=dict)  # {"aws": 12450, "azure": 2100}
    assets_by_resource_type = models.JSONField(default=dict)  # {"s3.bucket": 4523}
    assets_by_region = models.JSONField(default=dict)  # {"ap-south-1": 1856}
    
    # Scan scope
    providers_scanned = ArrayField(models.CharField(max_length=50), default=list)
    accounts_scanned = ArrayField(models.CharField(max_length=255), default=list)
    regions_scanned = ArrayField(models.CharField(max_length=100), default=list)
    
    errors_count = models.IntegerField(default=0)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'inventory_scan_summary'
        indexes = [
            models.Index(fields=['tenant', 'scan_run_id']),
            models.Index(fields=['status']),
            models.Index(fields=['completed_at']),
        ]

    def __str__(self):
        return f"Scan {self.scan_run_id} - {self.total_assets} assets"
