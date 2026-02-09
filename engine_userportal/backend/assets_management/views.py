import hashlib
import json
from django.http import HttpResponse, HttpResponseNotModified
from django.utils.encoding import force_bytes
from rest_framework import status, viewsets, mixins
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.pagination import PageNumberPagination

from user_auth.auth import CookieTokenAuthentication
from user_auth.permissions import TenantScoped
from .models import Asset
from .serializers import AssetSerializer
from .filters import build_asset_query


class AssetsPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = "pageSize"
    max_page_size = 100


class AssetViewSet(
    mixins.ListModelMixin,
    viewsets.GenericViewSet,
):
    authentication_classes = [CookieTokenAuthentication]
    permission_classes = [TenantScoped]
    serializer_class = AssetSerializer
    pagination_class = AssetsPagination

    def get_queryset(self):
        qs = build_asset_query(self.request.query_params)
        scope = getattr(self.request, "scope", None)
        if not scope:
            return qs.none()
        if scope.get("is_super_landlord"):
            return qs
        allowed = scope.get("allowed_tenant_ids")
        if allowed is None:
            return qs
        if not allowed:
            return qs.none()
        return qs.filter(tenant_id__in=allowed)

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())

        sort_by = request.query_params.get("sort_by", "created_at")
        order = request.query_params.get("order", "desc")
        valid_fields = {f.name for f in Asset._meta.fields}

        if sort_by in valid_fields:
            sort_field = f"-{sort_by}" if order == "desc" else sort_by
            queryset = queryset.order_by(sort_field)
        else:
            queryset = queryset.order_by("-created_at")

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            response_data = {
                "success": True,
                "message": "Assets fetched successfully",
                "data": serializer.data,
                "pagination": {
                    "page": self.paginator.page.number,
                    "pageSize": self.paginator.page_size,
                    "total": self.paginator.page.paginator.count,
                },
            }
        else:
            serializer = self.get_serializer(queryset, many=True)
            response_data = {
                "success": True,
                "message": "Assets fetched successfully",
                "data": serializer.data,
            }

        json_str = json.dumps(response_data, sort_keys=True, separators=(',', ':'), default=str)
        etag = hashlib.sha256(force_bytes(json_str)).hexdigest()

        if request.headers.get("If-None-Match") == etag:
            return HttpResponseNotModified()

        response = Response(response_data)
        response["ETag"] = etag
        response["Cache-Control"] = "private, max-age=300, stale-while-revalidate=120"
        response["Vary"] = "Cookie"
        return response

    @action(detail=False, methods=["get"])
    def export(self, request):
        queryset = self.filter_queryset(self.get_queryset())

        sort_by = request.query_params.get("sort_by", "created_at")
        order = request.query_params.get("order", "desc")
        valid_fields = {f.name for f in Asset._meta.fields}
        if sort_by in valid_fields:
            sort_field = f"-{sort_by}" if order == "desc" else sort_by
            queryset = queryset.order_by(sort_field)

        data = list(queryset.values(
            "id", "tenant_id", "name", "resource_id", "resource_type",
            "provider", "region", "environment", "category",
            "lifecycle_state", "health_status", "created_at", "updated_at"
        )[:1000])

        doctype = request.query_params.get("doctype", "xlsx")
        labels = {
            "name": "Asset Name",
            "resource_id": "Resource ID",
            "resource_type": "Type",
            "provider": "Provider",
            "region": "Region",
            "environment": "Environment",
            "category": "Category",
            "lifecycle_state": "Lifecycle",
            "health_status": "Health",
            "created_at": "Created At"
        }

        try:
            if doctype == "xlsx":
                from utils.exporters import export_to_excel
                buffer = export_to_excel(data, labels)
                response = HttpResponse(
                    buffer,
                    content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                )
                response["Content-Disposition"] = 'attachment; filename="assets.xlsx"'
                return response

            elif doctype == "pdf":
                from utils.exporters import export_to_pdf
                buffer = export_to_pdf(data, labels)
                if not buffer:
                    return Response({"error": "PDF generation failed"}, status=500)
                response = HttpResponse(buffer, content_type="application/pdf")
                response["Content-Disposition"] = 'attachment; filename="assets.pdf"'
                return response

            else:
                return Response(
                    {"error": "Format must be 'xlsx' or 'pdf'"},
                    status=status.HTTP_400_BAD_REQUEST
                )

        except Exception as e:
            return Response(
                {"error": "Export failed", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )