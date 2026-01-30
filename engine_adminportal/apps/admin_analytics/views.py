"""
Views for admin analytics app.
"""
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from common.permissions import IsAdmin
from .serializers import (
    AnalyticsOverviewSerializer,
    ComplianceAnalyticsSerializer,
    ScanAnalyticsSerializer,
    TrendDataSerializer,
    TenantComparisonSerializer
)
from .calculators import analytics_calculator


class AnalyticsOverviewView(APIView):
    """Platform-wide analytics overview."""
    permission_classes = [IsAdmin]
    
    def get(self, request):
        overview = analytics_calculator.calculate_overview()
        serializer = AnalyticsOverviewSerializer(overview)
        return Response(serializer.data)


class ComplianceAnalyticsView(APIView):
    """Compliance analytics."""
    permission_classes = [IsAdmin]
    
    def get(self, request):
        analytics = analytics_calculator.calculate_compliance_analytics()
        serializer = ComplianceAnalyticsSerializer(analytics)
        return Response(serializer.data)


class ScanAnalyticsView(APIView):
    """Scan statistics analytics."""
    permission_classes = [IsAdmin]
    
    def get(self, request):
        analytics = analytics_calculator.calculate_scan_analytics()
        serializer = ScanAnalyticsSerializer(analytics)
        return Response(serializer.data)


class TrendsView(APIView):
    """Time-series trends."""
    permission_classes = [IsAdmin]
    
    def get(self, request):
        metric_name = request.query_params.get('metric', 'scans')
        days = int(request.query_params.get('days', 30))
        
        trends = analytics_calculator.calculate_trends(metric_name, days)
        serializer = TrendDataSerializer(trends)
        return Response(serializer.data)


class TenantComparisonView(APIView):
    """Compare tenants."""
    permission_classes = [IsAdmin]
    
    def get(self, request):
        tenant_ids = request.query_params.getlist('tenant_id')
        if not tenant_ids:
            return Response(
                {'error': 'tenant_id parameter required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        comparison = analytics_calculator.compare_tenants(tenant_ids)
        serializer = TenantComparisonSerializer(comparison)
        return Response(serializer.data)
