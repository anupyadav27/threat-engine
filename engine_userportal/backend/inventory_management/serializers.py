"""
Serializers for Inventory Management models
Maps to Inventory Engine API responses
"""
from rest_framework import serializers


class InventoryAssetSerializer(serializers.Serializer):
    """Serializer for Inventory Asset (from API)"""
    resource_uid = serializers.CharField()
    resource_type = serializers.CharField()
    resource_id = serializers.CharField()
    name = serializers.CharField(required=False, allow_null=True)
    provider = serializers.CharField()
    account_id = serializers.CharField()
    region = serializers.CharField(required=False, allow_null=True)
    scope = serializers.CharField(default="regional")
    tags = serializers.DictField(default=dict)
    metadata = serializers.DictField(default=dict)
    hash_sha256 = serializers.CharField(required=False, allow_null=True)
    created_at = serializers.DateTimeField(required=False, allow_null=True)
    updated_at = serializers.DateTimeField(required=False, allow_null=True)
    last_scanned_at = serializers.DateTimeField(required=False, allow_null=True)


class InventoryRelationshipSerializer(serializers.Serializer):
    """Serializer for Inventory Relationship (from API)"""
    relation_type = serializers.CharField()
    from_uid = serializers.CharField()
    to_uid = serializers.CharField()
    properties = serializers.DictField(default=dict)


class InventoryDriftSerializer(serializers.Serializer):
    """Serializer for Inventory Drift (from API)"""
    change_type = serializers.CharField()
    resource_uid = serializers.CharField()
    resource_type = serializers.CharField()
    provider = serializers.CharField()
    account_id = serializers.CharField()
    region = serializers.CharField(required=False, allow_null=True)
    diff = serializers.DictField(default=dict)
    detected_at = serializers.DateTimeField()


class InventoryScanSummarySerializer(serializers.Serializer):
    """Serializer for Inventory Scan Summary (from API)"""
    scan_run_id = serializers.CharField()
    started_at = serializers.DateTimeField()
    completed_at = serializers.DateTimeField(required=False, allow_null=True)
    status = serializers.CharField()
    total_assets = serializers.IntegerField()
    total_relationships = serializers.IntegerField()
    assets_by_provider = serializers.DictField(default=dict)
    assets_by_resource_type = serializers.DictField(default=dict)
    assets_by_region = serializers.DictField(default=dict)
    providers_scanned = serializers.ListField(child=serializers.CharField(), default=list)
    accounts_scanned = serializers.ListField(child=serializers.CharField(), default=list)
    regions_scanned = serializers.ListField(child=serializers.CharField(), default=list)
    errors_count = serializers.IntegerField(default=0)
