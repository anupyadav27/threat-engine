"""
Serializers for admin monitoring app.
"""
from rest_framework import serializers
from .models import AdminMetric


class AdminMetricSerializer(serializers.ModelSerializer):
    """Serializer for admin metrics."""
    
    class Meta:
        model = AdminMetric
        fields = ['id', 'tenant_id', 'metric_type', 'metric_value', 'timestamp', 'metadata']


class TenantStatusSerializer(serializers.Serializer):
    """Serializer for tenant status."""
    tenant_id = serializers.CharField()
    status = serializers.CharField()
    active_scans = serializers.IntegerField()
    compliance_score = serializers.FloatField()
    findings_critical = serializers.IntegerField()
    findings_high = serializers.IntegerField()
    findings_medium = serializers.IntegerField()
    findings_low = serializers.IntegerField()
    resources_count = serializers.IntegerField()
    scan_success_rate = serializers.FloatField()
    last_scan_timestamp = serializers.DateTimeField(allow_null=True)
    providers = serializers.ListField(child=serializers.CharField())


class TenantMetricsSerializer(serializers.Serializer):
    """Serializer for tenant metrics."""
    tenant_id = serializers.CharField()
    metrics = serializers.DictField()


class DashboardOverviewSerializer(serializers.Serializer):
    """Serializer for dashboard overview."""
    total_tenants = serializers.IntegerField()
    active_tenants = serializers.IntegerField()
    total_scans_24h = serializers.IntegerField()
    total_scans_7d = serializers.IntegerField()
    total_scans_30d = serializers.IntegerField()
    average_compliance_score = serializers.FloatField()
    total_findings_critical = serializers.IntegerField()
    total_findings_high = serializers.IntegerField()
    recent_tenants = serializers.ListField()
