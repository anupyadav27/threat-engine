"""
Views for admin audit app.
"""
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from django.db import connection
from common.permissions import IsAdmin
from .models import AdminAuditLog, AdminAlert
from .serializers import AdminAuditLogSerializer, AdminAlertSerializer


class AuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for audit logs."""
    permission_classes = [IsAdmin]
    queryset = AdminAuditLog.objects.all()
    serializer_class = AdminAuditLogSerializer
    
    def get_queryset(self):
        """Filter audit logs based on query parameters."""
        queryset = AdminAuditLog.objects.all()
        
        # Filter by admin user
        admin_user_id = self.request.query_params.get('admin_user_id')
        if admin_user_id:
            queryset = queryset.filter(admin_user_id=admin_user_id)
        
        # Filter by resource type
        resource_type = self.request.query_params.get('resource_type')
        if resource_type:
            queryset = queryset.filter(resource_type=resource_type)
        
        # Filter by resource ID
        resource_id = self.request.query_params.get('resource_id')
        if resource_id:
            queryset = queryset.filter(resource_id=resource_id)
        
        # Filter by action type
        action_type = self.request.query_params.get('action_type')
        if action_type:
            queryset = queryset.filter(action_type=action_type)
        
        # Filter by date range
        date_from = self.request.query_params.get('date_from')
        if date_from:
            queryset = queryset.filter(timestamp__gte=date_from)
        
        date_to = self.request.query_params.get('date_to')
        if date_to:
            queryset = queryset.filter(timestamp__lte=date_to)
        
        return queryset.order_by('-timestamp')
    
    @action(detail=False, methods=['get'])
    def users(self, request, user_id=None):
        """Get audit logs for a specific user."""
        user_id = request.query_params.get('user_id') or user_id
        if not user_id:
            return Response(
                {'error': 'user_id parameter required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        logs = AdminAuditLog.objects.filter(
            resource_type='user',
            resource_id=user_id
        ).order_by('-timestamp')
        
        serializer = self.get_serializer(logs, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    def tenants(self, request, tenant_id=None):
        """Get audit logs for a specific tenant."""
        tenant_id = request.query_params.get('tenant_id') or tenant_id
        if not tenant_id:
            return Response(
                {'error': 'tenant_id parameter required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        logs = AdminAuditLog.objects.filter(
            resource_type='tenant',
            resource_id=tenant_id
        ).order_by('-timestamp')
        
        serializer = self.get_serializer(logs, many=True)
        return Response(serializer.data)


class AlertViewSet(viewsets.ModelViewSet):
    """ViewSet for admin alerts."""
    permission_classes = [IsAdmin]
    queryset = AdminAlert.objects.all()
    serializer_class = AdminAlertSerializer
    
    def get_queryset(self):
        """Filter alerts based on query parameters."""
        queryset = AdminAlert.objects.all()
        
        # Filter by status
        status_filter = self.request.query_params.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        
        # Filter by severity
        severity = self.request.query_params.get('severity')
        if severity:
            queryset = queryset.filter(severity=severity)
        
        # Filter by tenant
        tenant_id = self.request.query_params.get('tenant_id')
        if tenant_id:
            queryset = queryset.filter(tenant_id=tenant_id)
        
        return queryset.order_by('-created_at')
    
    @action(detail=True, methods=['post'])
    def acknowledge(self, request, pk=None):
        """Acknowledge an alert."""
        from django.utils import timezone
        
        alert = self.get_object()
        alert.status = 'acknowledged'
        alert.acknowledged_at = timezone.now()
        alert.acknowledged_by = str(request.user.id)
        alert.save()
        
        serializer = self.get_serializer(alert)
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def resolve(self, request, pk=None):
        """Resolve an alert."""
        alert = self.get_object()
        alert.status = 'resolved'
        alert.save()
        
        serializer = self.get_serializer(alert)
        return Response(serializer.data)
