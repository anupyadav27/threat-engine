"""
Serializers for admin management app.
"""
from rest_framework import serializers


class UserSerializer(serializers.Serializer):
    """Serializer for user data."""
    user_id = serializers.CharField()
    email = serializers.EmailField()
    first_name = serializers.CharField(required=False, allow_blank=True)
    last_name = serializers.CharField(required=False, allow_blank=True)
    is_active = serializers.BooleanField()
    is_superuser = serializers.BooleanField()
    created_at = serializers.DateTimeField()
    last_login = serializers.DateTimeField(allow_null=True)


class TenantSerializer(serializers.Serializer):
    """Serializer for tenant data."""
    tenant_id = serializers.CharField()
    tenant_name = serializers.CharField()
    status = serializers.CharField()
    created_at = serializers.DateTimeField()
    updated_at = serializers.DateTimeField(allow_null=True)


class CreateUserSerializer(serializers.Serializer):
    """Serializer for creating users."""
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    first_name = serializers.CharField(required=False, allow_blank=True)
    last_name = serializers.CharField(required=False, allow_blank=True)
    is_active = serializers.BooleanField(default=True)
    roles = serializers.ListField(child=serializers.CharField(), required=False)


class UpdateUserSerializer(serializers.Serializer):
    """Serializer for updating users."""
    email = serializers.EmailField(required=False)
    first_name = serializers.CharField(required=False, allow_blank=True)
    last_name = serializers.CharField(required=False, allow_blank=True)
    is_active = serializers.BooleanField(required=False)
    roles = serializers.ListField(child=serializers.CharField(), required=False)


class CreateTenantSerializer(serializers.Serializer):
    """Serializer for creating tenants."""
    tenant_name = serializers.CharField()
    status = serializers.CharField(default='active')
    description = serializers.CharField(required=False, allow_blank=True)


class UpdateTenantSerializer(serializers.Serializer):
    """Serializer for updating tenants."""
    tenant_name = serializers.CharField(required=False)
    status = serializers.CharField(required=False)
    description = serializers.CharField(required=False, allow_blank=True)


class AssignTenantSerializer(serializers.Serializer):
    """Serializer for assigning tenant to user."""
    tenant_id = serializers.CharField()
    role = serializers.CharField(required=False, default='member')
