"""
Views for Inventory Management
Proxies to Inventory Engine API
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
from utils.engine_clients import InventoryEngineClient
from .serializers import (
    InventoryAssetSerializer,
    InventoryRelationshipSerializer,
    InventoryDriftSerializer,
    InventoryScanSummarySerializer
)


class InventoryPagination(PageNumberPagination):
    page_size = 100
    page_size_query_param = "pageSize"
    max_page_size = 1000


class InventoryAssetViewSet(viewsets.ViewSet):
    """ViewSet for Inventory Assets - proxies to Inventory Engine API"""
    authentication_classes = [CookieTokenAuthentication]
    permission_classes = [TenantScopedRequiredTenant]
    serializer_class = InventoryAssetSerializer
    pagination_class = InventoryPagination

    def list(self, request):
        """List assets from Inventory Engine"""
        tenant_id = getattr(request, "tenant_id", None) or request.query_params.get("tenant_id")
        if not tenant_id:
            raise ValidationError({"tenant_id": "This field is required"})

        client = InventoryEngineClient()
        
        try:
            assets = client.get_assets(
                tenant_id=tenant_id,
                scan_run_id=request.query_params.get('scan_run_id'),
                provider=request.query_params.get('provider'),
                region=request.query_params.get('region'),
                resource_type=request.query_params.get('resource_type'),
                account_id=request.query_params.get('account_id'),
                limit=int(request.query_params.get('limit', 100)),
                offset=int(request.query_params.get('offset', 0))
            )
            
            # Pagination
            paginator = self.pagination_class()
            page = paginator.paginate_queryset(assets, request)
            
            serializer = self.serializer_class(page if page else assets, many=True)
            
            response_data = {
                "success": True,
                "message": "Assets fetched successfully",
                "data": serializer.data,
            }
            
            if page is not None:
                response_data["pagination"] = {
                    "page": paginator.page.number,
                    "pageSize": paginator.page_size,
                    "total": len(assets),
                }
            
            # ETag caching
            json_str = json.dumps(response_data, sort_keys=True, separators=(',', ':'), default=str)
            etag = hashlib.sha256(force_bytes(json_str)).hexdigest()
            
            if request.headers.get("If-None-Match") == etag:
                return HttpResponseNotModified()
            
            response = Response(response_data)
            response["ETag"] = etag
            response["Cache-Control"] = "private, max-age=300, stale-while-revalidate=120"
            return response
            
        except Exception as e:
            return Response({
                "success": False,
                "message": f"Failed to fetch assets: {str(e)}"
            }, status=500)

    def retrieve(self, request, pk=None):
        """Get single asset from Inventory Engine"""
        tenant_id = getattr(request, "tenant_id", None) or request.query_params.get("tenant_id")
        if not tenant_id:
            raise ValidationError({"tenant_id": "This field is required"})

        client = InventoryEngineClient()
        
        try:
            asset = client.get_asset(
                resource_uid=pk,
                tenant_id=tenant_id,
                scan_run_id=request.query_params.get('scan_run_id')
            )
            
            serializer = self.serializer_class(asset)
            return Response({
                "success": True,
                "message": "Asset fetched successfully",
                "data": serializer.data
            })
        except Exception as e:
            return Response({
                "success": False,
                "message": f"Failed to fetch asset: {str(e)}"
            }, status=500)

    @action(detail=True, methods=['get'])
    def relationships(self, request, pk=None):
        """Get asset relationships"""
        tenant_id = getattr(request, "tenant_id", None) or request.query_params.get("tenant_id")
        if not tenant_id:
            raise ValidationError({"tenant_id": "This field is required"})

        client = InventoryEngineClient()
        
        try:
            relationships = client.get_relationships(
                resource_uid=pk,
                tenant_id=str(tenant_id),
                scan_run_id=request.query_params.get('scan_run_id'),
                depth=int(request.query_params.get('depth', 1)),
                relation_type=request.query_params.get('relation_type'),
                direction=request.query_params.get('direction')
            )
            
            serializer = InventoryRelationshipSerializer(relationships, many=True)
            return Response({
                "success": True,
                "message": "Relationships fetched successfully",
                "data": serializer.data
            })
        except Exception as e:
            return Response({
                "success": False,
                "message": f"Failed to fetch relationships: {str(e)}"
            }, status=500)

    @action(detail=False, methods=['get'])
    def summary(self, request):
        """Get scan summary"""
        tenant_id = getattr(request, "tenant_id", None) or request.query_params.get("tenant_id")
        if not tenant_id:
            raise ValidationError({"tenant_id": "This field is required"})

        client = InventoryEngineClient()
        
        try:
            summary = client.get_scan_summary(
                tenant_id=str(tenant_id),
                scan_run_id=request.query_params.get('scan_run_id')
            )
            
            serializer = InventoryScanSummarySerializer(summary)
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
    def drift(self, request):
        """Get drift records"""
        tenant_id = getattr(request, "tenant_id", None) or request.query_params.get("tenant_id")
        if not tenant_id:
            raise ValidationError({"tenant_id": "This field is required"})

        client = InventoryEngineClient()
        
        try:
            drift_data = client.get_drift(
                tenant_id=str(tenant_id),
                baseline_scan=request.query_params.get('baseline_scan'),
                compare_scan=request.query_params.get('compare_scan'),
                change_type=request.query_params.get('change_type')
            )
            
            drift_records = drift_data.get('drift_records', [])
            serializer = InventoryDriftSerializer(drift_records, many=True)
            return Response({
                "success": True,
                "message": "Drift records fetched successfully",
                "data": serializer.data
            })
        except Exception as e:
            return Response({
                "success": False,
                "message": f"Failed to fetch drift: {str(e)}"
            }, status=500)
