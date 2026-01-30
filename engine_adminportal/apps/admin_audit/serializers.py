"""
Serializers for admin audit app.
"""
from rest_framework import serializers
from .models import AdminAuditLog, AdminAlert


class AdminAuditLogSerializer(serializers.ModelSerializer):
    """Serializer for audit logs."""
    
    class Meta:
        model = AdminAuditLog
        fields = [
            'id', 'admin_user_id', 'action_type', 'resource_type',
            'resource_id', 'details', 'timestamp', 'ip_address'
        ]


class AdminAlertSerializer(serializers.ModelSerializer):
    """Serializer for admin alerts."""
    
    class Meta:
        model = AdminAlert
        fields = [
            'id', 'alert_type', 'severity', 'tenant_id', 'message',
            'status', 'created_at', 'acknowledged_at', 'acknowledged_by', 'metadata'
        ]
