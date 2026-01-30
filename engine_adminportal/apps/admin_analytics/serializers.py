"""
Serializers for admin analytics app.
"""
from rest_framework import serializers


class AnalyticsOverviewSerializer(serializers.Serializer):
    """Serializer for analytics overview."""
    total_tenants = serializers.IntegerField()
    active_tenants = serializers.IntegerField()
    inactive_tenants = serializers.IntegerField()
    total_scans_24h = serializers.IntegerField()
    total_scans_7d = serializers.IntegerField()
    total_scans_30d = serializers.IntegerField()
    average_compliance_score = serializers.FloatField()
    top_failing_rules = serializers.ListField()
    resource_distribution = serializers.DictField()
    scan_success_rate = serializers.FloatField()
    findings_distribution = serializers.DictField()


class ComplianceAnalyticsSerializer(serializers.Serializer):
    """Serializer for compliance analytics."""
    overall_average = serializers.FloatField()
    by_framework = serializers.DictField()
    by_tenant = serializers.ListField()
    trends = serializers.ListField()


class ScanAnalyticsSerializer(serializers.Serializer):
    """Serializer for scan analytics."""
    total_scans = serializers.IntegerField()
    successful_scans = serializers.IntegerField()
    failed_scans = serializers.IntegerField()
    success_rate = serializers.FloatField()
    average_duration = serializers.FloatField()
    scans_by_provider = serializers.DictField()
    scans_by_tenant = serializers.ListField()


class TrendDataSerializer(serializers.Serializer):
    """Serializer for trend data."""
    metric_name = serializers.CharField()
    data_points = serializers.ListField()
    period = serializers.CharField()


class TenantComparisonSerializer(serializers.Serializer):
    """Serializer for tenant comparison."""
    tenants = serializers.ListField()
    metrics = serializers.DictField()
    comparison_data = serializers.ListField()
