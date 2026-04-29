import hashlib
import json
from django.http import HttpResponse, HttpResponseNotModified
from django.utils.encoding import force_bytes
from rest_framework import status, viewsets, mixins
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.pagination import PageNumberPagination

from .models import Tenants
from .serializers import TenantSerializer
from .filters import build_tenant_query


class TenantsPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = "pageSize"
    max_page_size = 100


class TenantViewSet(
    mixins.ListModelMixin,
    mixins.CreateModelMixin,
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    mixins.DestroyModelMixin,
    viewsets.GenericViewSet,
):
    serializer_class = TenantSerializer
    pagination_class = TenantsPagination

    def get_queryset(self):
        return build_tenant_query(self.request.query_params, user=self.request.user)

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())

        sort_by = request.query_params.get("sort_by", "created_at")
        order = request.query_params.get("order", "desc")
        valid_fields = {f.name for f in Tenants._meta.fields}

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
                "message": "Tenants fetched successfully",
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
                "message": "Tenants fetched successfully",
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
        valid_fields = {f.name for f in Tenants._meta.fields}
        if sort_by in valid_fields:
            sort_field = f"-{sort_by}" if order == "desc" else sort_by
            queryset = queryset.order_by(sort_field)

        data = list(queryset.values(
            "id", "name", "description", "status", "plan",
            "contact_email", "region", "created_at", "updated_at"
        )[:1000])

        doctype = request.query_params.get("doctype", "xlsx")
        labels = {
            "id": "ID",
            "name": "Tenant Name",
            "status": "Status",
            "plan": "Plan",
            "contact_email": "Contact Email",
            "region": "Region",
            "created_at": "Created At",
            "updated_at": "Updated At",
        }

        try:
            if doctype == "xlsx":
                from utils.exporters import export_to_excel
                buffer = export_to_excel(data, labels)
                response = HttpResponse(
                    buffer,
                    content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                )
                response["Content-Disposition"] = 'attachment; filename="tenants.xlsx"'
                return response

            elif doctype == "pdf":
                from utils.exporters import export_to_pdf
                buffer = export_to_pdf(data, labels)
                if not buffer:
                    return Response({"error": "PDF generation failed"}, status=500)
                response = HttpResponse(buffer, content_type="application/pdf")
                response["Content-Disposition"] = 'attachment; filename="tenants.pdf"'
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