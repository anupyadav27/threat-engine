"""
Views for admin monitoring app.
"""
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from django.db import connection
from django.core.cache import cache
from common.permissions import IsAdmin
from .models import AdminMetric
from .serializers import (
    AdminMetricSerializer,
    TenantStatusSerializer,
    TenantMetricsSerializer,
    DashboardOverviewSerializer
)
from apps.engine_integration.aggregators import metrics_aggregator


class TenantViewSet(viewsets.ViewSet):
    """ViewSet for tenant monitoring."""
    permission_classes = [IsAdmin]
    
    def list(self, request):
        """List all tenants with status."""
        # Query tenants from database
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT tenant_id, tenant_name, status, created_at
                FROM tenants
                ORDER BY created_at DESC
            """)
            columns = [col[0] for col in cursor.description]
            tenants = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        # Get metrics for each tenant
        tenant_list = []
        for tenant in tenants:
            metrics = metrics_aggregator.aggregate_tenant_metrics(tenant['tenant_id'])
            tenant_data = {
                'tenant_id': tenant['tenant_id'],
                'tenant_name': tenant.get('tenant_name'),
                'status': tenant.get('status', 'active'),
                'created_at': tenant.get('created_at'),
                'metrics': metrics
            }
            tenant_list.append(tenant_data)
        
        serializer = TenantStatusSerializer(tenant_list, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['get'])
    def status(self, request, pk=None):
        """Get real-time tenant status."""
        tenant_id = pk
        metrics = metrics_aggregator.aggregate_tenant_metrics(tenant_id)
        
        # Determine status
        status_value = 'active'
        if metrics.get('active_scans', 0) > 0:
            status_value = 'scanning'
        elif metrics.get('compliance_score', 0) < 50:
            status_value = 'at_risk'
        
        data = {
            'tenant_id': tenant_id,
            'status': status_value,
            **metrics
        }
        serializer = TenantStatusSerializer(data)
        return Response(serializer.data)
    
    @action(detail=True, methods=['get'])
    def metrics(self, request, pk=None):
        """Get tenant metrics."""
        tenant_id = pk
        metrics = metrics_aggregator.aggregate_tenant_metrics(tenant_id)
        
        data = {
            'tenant_id': tenant_id,
            'metrics': metrics
        }
        serializer = TenantMetricsSerializer(data)
        return Response(serializer.data)


class DashboardOverviewView(APIView):
    """Dashboard overview endpoint."""
    permission_classes = [IsAdmin]
    
    def get(self, request):
        """Get platform-wide dashboard overview."""
        cache_key = 'dashboard_overview'
        cached = cache.get(cache_key)
        if cached:
            return Response(cached)
        
        # Query database for statistics
        with connection.cursor() as cursor:
            # Total tenants
            cursor.execute("SELECT COUNT(*) FROM tenants")
            total_tenants = cursor.fetchone()[0]
            
            # Active tenants
            cursor.execute("SELECT COUNT(*) FROM tenants WHERE status = 'active'")
            active_tenants = cursor.fetchone()[0]
            
            # Scans in last 24h, 7d, 30d
            cursor.execute("""
                SELECT 
                    COUNT(*) FILTER (WHERE started_at >= NOW() - INTERVAL '24 hours') as scans_24h,
                    COUNT(*) FILTER (WHERE started_at >= NOW() - INTERVAL '7 days') as scans_7d,
                    COUNT(*) FILTER (WHERE started_at >= NOW() - INTERVAL '30 days') as scans_30d
                FROM onboarding_executions
            """)
            scan_stats = cursor.fetchone()
            scans_24h = scan_stats[0] or 0
            scans_7d = scan_stats[1] or 0
            scans_30d = scan_stats[2] or 0
            
            # Average compliance score
            cursor.execute("""
                SELECT AVG(score) 
                FROM compliance_summary 
                WHERE created_at >= NOW() - INTERVAL '30 days'
            """)
            avg_compliance = cursor.fetchone()[0] or 0.0
            
            # Total findings
            cursor.execute("""
                SELECT 
                    COUNT(*) FILTER (WHERE severity = 'critical') as critical,
                    COUNT(*) FILTER (WHERE severity = 'high') as high
                FROM scan_findings
                WHERE created_at >= NOW() - INTERVAL '30 days'
            """)
            finding_stats = cursor.fetchone()
            findings_critical = finding_stats[0] or 0
            findings_high = finding_stats[1] or 0
            
            # Recent tenants
            cursor.execute("""
                SELECT tenant_id, tenant_name, created_at
                FROM tenants
                ORDER BY created_at DESC
                LIMIT 10
            """)
            columns = [col[0] for col in cursor.description]
            recent_tenants = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        overview = {
            'total_tenants': total_tenants,
            'active_tenants': active_tenants,
            'total_scans_24h': scans_24h,
            'total_scans_7d': scans_7d,
            'total_scans_30d': scans_30d,
            'average_compliance_score': round(float(avg_compliance), 2),
            'total_findings_critical': findings_critical,
            'total_findings_high': findings_high,
            'recent_tenants': recent_tenants
        }
        
        # Cache for 1 minute
        cache.set(cache_key, overview, 60)
        
        serializer = DashboardOverviewSerializer(overview)
        return Response(serializer.data)
