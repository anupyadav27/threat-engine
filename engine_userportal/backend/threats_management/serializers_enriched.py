"""
Enriched Serializers for Threat Management
Maps to Threat Engine API responses
"""
from rest_framework import serializers


class ThreatSerializer(serializers.Serializer):
    """Serializer for Threat (from API)"""
    threat_id = serializers.CharField()
    threat_type = serializers.CharField()
    title = serializers.CharField()
    description = serializers.CharField(required=False, allow_null=True)
    severity = serializers.CharField()
    confidence = serializers.CharField()
    status = serializers.CharField()
    first_seen_at = serializers.DateTimeField()
    last_seen_at = serializers.DateTimeField()
    misconfig_finding_refs = serializers.ListField(child=serializers.CharField(), default=list)
    affected_assets = serializers.ListField(required=False, default=list)
    evidence_refs = serializers.ListField(child=serializers.CharField(), default=list)
    remediation = serializers.DictField(required=False, allow_null=True)


class ThreatSummarySerializer(serializers.Serializer):
    """Serializer for Threat Summary (from API)"""
    total_threats = serializers.IntegerField()
    threats_by_severity = serializers.DictField(default=dict)
    threats_by_category = serializers.DictField(default=dict)
    threats_by_status = serializers.DictField(default=dict)
    top_threat_categories = serializers.ListField(required=False, default=list)
    coverage_percentage = serializers.FloatField(required=False, default=0.0)


class ThreatTrendSerializer(serializers.Serializer):
    """Serializer for Threat Trend (from API)"""
    date = serializers.DateField()
    total_threats = serializers.IntegerField()
    by_severity = serializers.DictField(default=dict)
    by_category = serializers.DictField(default=dict)


class ThreatReportSerializer(serializers.Serializer):
    """Serializer for Threat Report (from API)"""
    scan_run_id = serializers.CharField()
    cloud = serializers.CharField()
    trigger_type = serializers.CharField()
    accounts = serializers.ListField(child=serializers.CharField(), default=list)
    regions = serializers.ListField(child=serializers.CharField(), default=list)
    services = serializers.ListField(child=serializers.CharField(), default=list)
    started_at = serializers.DateTimeField()
    completed_at = serializers.DateTimeField(required=False, allow_null=True)
    generated_at = serializers.DateTimeField()
