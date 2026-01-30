"""
Serializers for DataSec Management
Maps to DataSec Engine API responses
"""
from rest_framework import serializers


class DataCatalogSerializer(serializers.Serializer):
    """Serializer for Data Catalog (from API)"""
    resource_uid = serializers.CharField()
    resource_id = serializers.CharField()
    resource_arn = serializers.CharField(required=False, allow_null=True)
    resource_type = serializers.CharField()
    service = serializers.CharField()
    region = serializers.CharField()
    account_id = serializers.CharField()
    name = serializers.CharField(required=False, allow_null=True)
    lifecycle_state = serializers.CharField(required=False, allow_null=True)
    health_status = serializers.CharField(required=False, allow_null=True)
    tags = serializers.DictField(default=dict)


class DataSecurityFindingSerializer(serializers.Serializer):
    """Serializer for Data Security Finding (from API)"""
    finding_id = serializers.CharField()
    scan_run_id = serializers.CharField()
    rule_id = serializers.CharField()
    status = serializers.CharField()
    resource_arn = serializers.CharField()
    service = serializers.CharField()
    region = serializers.CharField()
    account_id = serializers.CharField()
    data_security_modules = serializers.ListField(child=serializers.CharField(), default=list)
    is_data_security_relevant = serializers.BooleanField()
    data_security_context = serializers.DictField(default=dict)
    compliance_impact = serializers.DictField(default=dict)


class DataClassificationSerializer(serializers.Serializer):
    """Serializer for Data Classification (from API)"""
    resource_arn = serializers.CharField()
    classification = serializers.ListField(child=serializers.CharField(), default=list)
    confidence = serializers.FloatField()
    matched_patterns = serializers.ListField(child=serializers.CharField(), default=list)


class DataResidencySerializer(serializers.Serializer):
    """Serializer for Data Residency (from API)"""
    resource_arn = serializers.CharField()
    primary_region = serializers.CharField()
    replication_regions = serializers.ListField(child=serializers.CharField(), default=list)
    policy_name = serializers.CharField(required=False, allow_null=True)
    compliance_status = serializers.CharField()
    violations = serializers.ListField(default=list)
