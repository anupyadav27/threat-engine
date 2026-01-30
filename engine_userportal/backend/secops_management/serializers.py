from rest_framework import serializers


class SecOpsScanSerializer(serializers.Serializer):
    scan_id = serializers.CharField()
    tenant_id = serializers.CharField()
    customer_id = serializers.CharField(allow_null=True)
    project_name = serializers.CharField()
    status = serializers.CharField()
    started_at = serializers.CharField(allow_null=True)
    completed_at = serializers.CharField(allow_null=True)
    metadata = serializers.JSONField(allow_null=True)


class SecOpsFindingSerializer(serializers.Serializer):
    id = serializers.IntegerField(allow_null=True)
    scan_id = serializers.CharField()
    tenant_id = serializers.CharField()
    customer_id = serializers.CharField(allow_null=True)
    rule_id = serializers.CharField(allow_null=True)
    severity = serializers.CharField(allow_null=True)
    file_path = serializers.CharField(allow_null=True)
    message = serializers.CharField(allow_null=True)
    metadata = serializers.JSONField(allow_null=True)
    created_at = serializers.CharField(allow_null=True)
