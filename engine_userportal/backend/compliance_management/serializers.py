"""
Serializers for Compliance Management
Maps to Compliance Engine API responses
"""
from rest_framework import serializers


class ComplianceFrameworkSerializer(serializers.Serializer):
    """Serializer for Compliance Framework (from API)"""
    framework = serializers.CharField()
    version = serializers.CharField(required=False, allow_null=True)
    compliance_score = serializers.FloatField()
    status = serializers.CharField()
    controls_total = serializers.IntegerField()
    controls_passed = serializers.IntegerField()
    controls_failed = serializers.IntegerField()
    controls_not_applicable = serializers.IntegerField()
    controls = serializers.ListField(required=False, default=list)


class ComplianceControlSerializer(serializers.Serializer):
    """Serializer for Compliance Control (from API)"""
    control_id = serializers.CharField()
    control_title = serializers.CharField()
    category = serializers.CharField(required=False, allow_null=True)
    status = serializers.CharField()
    compliance_percentage = serializers.FloatField()
    total_resources = serializers.IntegerField()
    passed_resources = serializers.IntegerField()
    failed_resources = serializers.IntegerField()
    affected_resources = serializers.ListField(default=list)
    checks = serializers.ListField(default=list)
    evidence = serializers.ListField(default=list)
    remediation_steps = serializers.ListField(child=serializers.CharField(), default=list)


class ComplianceFindingSerializer(serializers.Serializer):
    """Serializer for Compliance Finding (from API)"""
    finding_id = serializers.CharField()
    rule_id = serializers.CharField()
    rule_version = serializers.CharField(required=False, allow_null=True)
    category = serializers.CharField(required=False, allow_null=True)
    title = serializers.CharField()
    description = serializers.CharField(required=False, allow_null=True)
    severity = serializers.CharField()
    status = serializers.CharField()
    first_seen_at = serializers.DateTimeField()
    last_seen_at = serializers.DateTimeField()
    compliance_mappings = serializers.ListField(default=list)
    affected_assets = serializers.ListField(default=list)
    evidence = serializers.ListField(default=list)
    remediation = serializers.DictField(required=False, allow_null=True)


class ComplianceTrendSerializer(serializers.Serializer):
    """Serializer for Compliance Trend (from API)"""
    date = serializers.DateField()
    csp = serializers.CharField()
    account_id = serializers.CharField(required=False, allow_null=True)
    framework = serializers.CharField(required=False, allow_null=True)
    overall_score = serializers.FloatField()
    frameworks = serializers.DictField(default=dict)
