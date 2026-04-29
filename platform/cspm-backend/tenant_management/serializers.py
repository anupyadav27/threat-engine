# your_app/serializers.py
from rest_framework import serializers
from .models import Tenants

class TenantSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tenants
        fields = [
            "id", "name", "description", "status", "plan",
            "contact_email", "region", "created_at", "updated_at"
        ]
        read_only_fields = ["id", "created_at", "updated_at"]