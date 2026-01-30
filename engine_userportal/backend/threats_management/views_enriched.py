"""
Enriched Views for Threat Management
Proxies to Threat Engine API
"""
import hashlib
import json
from django.http import HttpResponseNotModified
from django.utils.encoding import force_bytes
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.pagination import PageNumberPagination
from rest_framework.exceptions import ValidationError

from user_auth.auth import CookieTokenAuthentication
from user_auth.permissions import TenantScopedRequiredTenant
from utils.engine_clients import ThreatEngineClient
from .serializers_enriched import (
    ThreatSerializer,
    ThreatSummarySerializer,
    ThreatTrendSerializer,
    ThreatReportSerializer
)


class ThreatsPagination(PageNumberPagination):
    page_size = 50
    page_size_query_param = "pageSize"
    max_page_size = 500


def _tenant_id(request):
    return getattr(request, "tenant_id", None) or request.query_params.get("tenant_id")


class ThreatViewSetEnriched(viewsets.ViewSet):
    """ViewSet for Threats - proxies to Threat Engine API"""
    authentication_classes = [CookieTokenAuthentication]
    permission_classes = [TenantScopedRequiredTenant]
    serializer_class = ThreatSerializer
    pagination_class = ThreatsPagination

    def list(self, request):
        """List threats from Threat Engine"""
        tenant_id = _tenant_id(request)
        if not tenant_id:
            raise ValidationError({"tenant_id": "This field is required"})

        client = ThreatEngineClient()
        
        try:
            result = client.get_threats(
                tenant_id=str(tenant_id),
                scan_run_id=request.query_params.get('scan_run_id', 'latest'),
                severity=request.query_params.get('severity'),
                threat_type=request.query_params.get('threat_type'),
                status=request.query_params.get('status'),
                page=int(request.query_params.get('page', 1)),
                page_size=int(request.query_params.get('pageSize', 50))
            )
            
            threats = result.get('threats', [])
            total = result.get('total', len(threats))
            
            # Pagination
            paginator = self.pagination_class()
            page = paginator.paginate_queryset(threats, request)
            
            serializer = self.serializer_class(page if page else threats, many=True)
            
            response_data = {
                "success": True,
                "message": "Threats fetched successfully",
                "data": serializer.data,
            }
            
            if page is not None:
                response_data["pagination"] = {
                    "page": paginator.page.number,
                    "pageSize": paginator.page_size,
                    "total": total,
                }
            
            # ETag caching
            json_str = json.dumps(response_data, sort_keys=True, separators=(',', ':'), default=str)
            etag = hashlib.sha256(force_bytes(json_str)).hexdigest()
            
            if request.headers.get("If-None-Match") == etag:
                return HttpResponseNotModified()
            
            response = Response(response_data)
            response["ETag"] = etag
            response["Cache-Control"] = "private, max-age=180, stale-while-revalidate=60"
            return response
            
        except Exception as e:
            return Response({
                "success": False,
                "message": f"Failed to fetch threats: {str(e)}"
            }, status=500)

    def retrieve(self, request, pk=None):
        """Get single threat from Threat Engine"""
        tenant_id = request.query_params.get('tenant_id')
        if not tenant_id:
            raise ValidationError({"tenant_id": "This field is required"})

        client = ThreatEngineClient()
        
        try:
            threat = client.get_threat(
                threat_id=pk,
                tenant_id=tenant_id
            )
            
            serializer = self.serializer_class(threat)
            return Response({
                "success": True,
                "message": "Threat fetched successfully",
                "data": serializer.data
            })
        except Exception as e:
            return Response({
                "success": False,
                "message": f"Failed to fetch threat: {str(e)}"
            }, status=500)

    def partial_update(self, request, pk=None):
        """Update threat status"""
        tenant_id = _tenant_id(request)
        if not tenant_id:
            raise ValidationError({"tenant_id": "This field is required"})

        client = ThreatEngineClient()
        
        try:
            updates = request.data
            threat = client.update_threat(
                threat_id=pk,
                tenant_id=str(tenant_id),
                updates=updates
            )
            
            serializer = self.serializer_class(threat)
            return Response({
                "success": True,
                "message": "Threat updated successfully",
                "data": serializer.data
            })
        except Exception as e:
            return Response({
                "success": False,
                "message": f"Failed to update threat: {str(e)}"
            }, status=500)

    @action(detail=False, methods=['get'])
    def summary(self, request):
        """Get threat summary"""
        tenant_id = request.query_params.get('tenant_id')
        if not tenant_id:
            raise ValidationError({"tenant_id": "This field is required"})

        client = ThreatEngineClient()
        
        try:
            summary = client.get_threat_summary(
                tenant_id=tenant_id,
                scan_run_id=request.query_params.get('scan_run_id', 'latest')
            )
            
            serializer = ThreatSummarySerializer(summary.get('threat_summary', {}))
            return Response({
                "success": True,
                "message": "Summary fetched successfully",
                "data": serializer.data
            })
        except Exception as e:
            return Response({
                "success": False,
                "message": f"Failed to fetch summary: {str(e)}"
            }, status=500)

    @action(detail=False, methods=['get'])
    def trend(self, request):
        """Get threat trends"""
        tenant_id = _tenant_id(request)
        if not tenant_id:
            raise ValidationError({"tenant_id": "This field is required"})

        client = ThreatEngineClient()
        
        try:
            trend_data = client.get_threat_trend(
                tenant_id=str(tenant_id),
                days=int(request.query_params.get('days', 30)),
                scan_run_id=request.query_params.get('scan_run_id'),
                severity=request.query_params.get('severity')
            )
            
            trends = trend_data.get('trend_data', [])
            serializer = ThreatTrendSerializer(trends, many=True)
            return Response({
                "success": True,
                "message": "Trends fetched successfully",
                "data": serializer.data
            })
        except Exception as e:
            return Response({
                "success": False,
                "message": f"Failed to fetch trends: {str(e)}"
            }, status=500)

    @action(detail=False, methods=['get'])
    def patterns(self, request):
        """Get threat patterns"""
        tenant_id = _tenant_id(request)
        scan_run_id = request.query_params.get('scan_run_id')
        if not tenant_id or not scan_run_id:
            raise ValidationError({"tenant_id": "This field is required", "scan_run_id": "This field is required"})

        client = ThreatEngineClient()
        
        try:
            patterns = client.get_threat_patterns(
                scan_run_id=scan_run_id,
                tenant_id=str(tenant_id),
                limit=int(request.query_params.get('limit', 10))
            )
            
            return Response({
                "success": True,
                "message": "Patterns fetched successfully",
                "data": patterns
            })
        except Exception as e:
            return Response({
                "success": False,
                "message": f"Failed to fetch patterns: {str(e)}"
            }, status=500)

    @action(detail=False, methods=['get'])
    def remediation_queue(self, request):
        """Get remediation queue"""
        tenant_id = _tenant_id(request)
        if not tenant_id:
            raise ValidationError({"tenant_id": "This field is required"})

        client = ThreatEngineClient()
        
        try:
            queue = client.get_remediation_queue(
                tenant_id=str(tenant_id),
                status=request.query_params.get('status'),
                limit=int(request.query_params.get('limit', 100))
            )
            
            return Response({
                "success": True,
                "message": "Remediation queue fetched successfully",
                "data": queue
            })
        except Exception as e:
            return Response({
                "success": False,
                "message": f"Failed to fetch remediation queue: {str(e)}"
            }, status=500)
