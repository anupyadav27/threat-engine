import uuid
from django.db import models
from tenant_management.models import Tenants
# DEPRECATED: Remove import when Threat model is migrated
# from threats_management.models import Threat

# DEPRECATED: This model is being replaced by InventoryAsset in inventory_management
# Migration path: Use InventoryEngineClient from utils.engine_clients
# Old: Asset.objects.filter(tenant_id=tenant_id)
# New: InventoryEngineClient().get_assets(tenant_id=tenant_id)
class Asset(models.Model):
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(
        Tenants,
        on_delete=models.CASCADE,
        related_name="assets",
        null=True,
        blank=True
    )
    name = models.TextField()
    resource_id = models.TextField()
    resource_type = models.TextField()
    provider = models.TextField(blank=True, null=True)
    region = models.TextField(blank=True, null=True)
    environment = models.TextField(blank=True, null=True)
    category = models.TextField(blank=True, null=True)
    lifecycle_state = models.TextField(blank=True, null=True)
    health_status = models.TextField(blank=True, null=True)
    metadata = models.JSONField(blank=True, null=True)
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        db_table = 'assets'
        indexes = [
            models.Index(fields=['tenant', 'resource_type']),
            models.Index(fields=['tenant', 'environment']),
            models.Index(fields=['resource_id']),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=['tenant', 'resource_id'],
                name='unique_tenant_resource'
            )
        ]

    def __str__(self):
        return f"{self.name} ({self.resource_id})"


# DEPRECATED: AssetTag - Tags are now stored as JSON in InventoryAsset.tags
# Migration path: Use InventoryAsset.tags (JSONField) instead
class AssetTag(models.Model):
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    asset = models.ForeignKey(
        Asset,
        on_delete=models.CASCADE,
        related_name="tags"
    )
    tag_key = models.TextField()
    tag_value = models.TextField()
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        db_table = 'asset_tags'
        indexes = [
            models.Index(fields=['asset', 'tag_key']),
            models.Index(fields=['tag_key', 'tag_value']),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=['asset', 'tag_key'],
                name='unique_asset_tag_key'
            )
        ]

    def __str__(self):
        return f"{self.asset.name}: {self.tag_key}={self.tag_value}"


# DEPRECATED: AssetCompliance - Replaced by compliance_management models
# Use ComplianceEngineClient to get compliance data from Compliance Engine API
# class AssetCompliance(models.Model):
#     ...


# DEPRECATED: AssetThreat - Replaced by engine API relationships
# Use ThreatEngineClient to get threat data and InventoryEngineClient for relationships
# class AssetThreat(models.Model):
#     ...


# DEPRECATED: Agent - Not used, can be removed
# class Agent(models.Model):
#     ...