from rest_framework import serializers
from .models import Asset

class AssetSerializer(serializers.ModelSerializer):
    class Meta:
        model = Asset
        fields = [
            "id", "tenant_id", "name", "resource_id", "resource_type",
            "provider", "region", "environment", "category",
            "lifecycle_state", "health_status", "metadata",
            "created_at", "updated_at"
        ]
        read_only_fields = ["id", "created_at", "updated_at"]