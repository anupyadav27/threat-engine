import hashlib
import json
import logging
from typing import Optional

import requests as http_requests
from django.http import HttpResponse, HttpResponseNotModified, JsonResponse
from django.utils import timezone
from django.utils.encoding import force_bytes
from rest_framework import status, viewsets, mixins
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.pagination import PageNumberPagination
from rest_framework.views import APIView

from .models import Tenants, TenantIDPConfig
from .serializers import TenantSerializer, TenantIDPConfigSerializer
from .filters import build_tenant_query
from user_auth.utils.audit_utils import log_auth_event
from user_auth.utils.idp_validation import validate_idp_config

logger = logging.getLogger(__name__)


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


# ── IDP Config CRUD (AUTH-05) ─────────────────────────────────────────────────

def _resolve_request_user(request):
    """Return authenticated Users instance from access_token cookie, or None."""
    from user_auth.models import Users, UserSessions
    from user_auth.utils.auth_utils import verify_token

    access_token = request.COOKIES.get("access_token")
    if not access_token:
        return None
    sessions = UserSessions.objects.filter(revoked=False).select_related("user")
    for session in sessions:
        if session.expires_at < timezone.now():
            continue
        if verify_token(access_token, session.token):
            return session.user
    return None


def _user_tenant_ids(user) -> list[str]:
    """Return list of tenant UUIDs the user is an active member of."""
    from .models import TenantUsers
    return list(
        TenantUsers.objects.filter(user=user, is_active=True).values_list(
            "tenant_id", flat=True
        )
    )


def _secret_ref(tenant_id: str, idp_type: str) -> str:
    return f"platform/idp/{tenant_id}/{idp_type}"


class TenantIDPConfigListCreateView(APIView):
    """List and create IDP configurations for the authenticated user's tenants.

    GET  /api/v1/tenants/idp/
    POST /api/v1/tenants/idp/
    """

    def get(self, request) -> JsonResponse:
        user = _resolve_request_user(request)
        if not user:
            return JsonResponse({"message": "Not authenticated"}, status=401)

        tenant_ids = _user_tenant_ids(user)
        configs = TenantIDPConfig.objects.filter(tenant_id__in=tenant_ids).order_by("created_at")
        serializer = TenantIDPConfigSerializer(configs, many=True)
        return JsonResponse({"idp_configs": serializer.data}, status=200)

    def post(self, request) -> JsonResponse:
        user = _resolve_request_user(request)
        if not user:
            return JsonResponse({"message": "Not authenticated"}, status=401)

        try:
            body = json.loads(request.body)
        except (json.JSONDecodeError, AttributeError):
            return JsonResponse({"message": "Invalid JSON"}, status=400)

        tenant_id = body.get("tenant_id", "")
        if tenant_id not in [str(t) for t in _user_tenant_ids(user)]:
            return JsonResponse({"message": "Forbidden — not a member of this tenant"}, status=403)

        idp_type = body.get("idp_type", "")
        config = dict(body.get("config", {}))

        # Extract and store client_secret out of DB
        client_secret = config.pop("client_secret", None)
        if client_secret:
            from user_auth.utils.secrets_utils import store_idp_secret
            secret_ref = _secret_ref(tenant_id, idp_type)
            store_idp_secret(secret_ref, client_secret)
            config["client_secret_ref"] = secret_ref

        # Generate SP keypair for new SAML configs
        if idp_type == "saml":
            existing = TenantIDPConfig.objects.filter(tenant_id=tenant_id, idp_type="saml").exists()
            if not existing:
                from user_auth.utils.saml_utils import generate_sp_keypair
                generate_sp_keypair(tenant_id)

        body["config"] = config
        # DRF FK field is named "tenant", but API accepts "tenant_id"
        body["tenant"] = body.pop("tenant_id", tenant_id)
        serializer = TenantIDPConfigSerializer(data=body)
        if not serializer.is_valid():
            return JsonResponse({"errors": serializer.errors}, status=400)

        idp_config = serializer.save(created_by=user)
        log_auth_event(
            "idp_config.create",
            request=request,
            user=user,
            tenant_id=tenant_id,
            extra={"idp_type": idp_type, "idp_name": body.get("idp_name", "")},
        )
        return JsonResponse(TenantIDPConfigSerializer(idp_config).data, status=201)


class TenantIDPConfigDetailView(APIView):
    """Retrieve, update, or deactivate a single IDP config.

    GET    /api/v1/tenants/idp/{pk}/
    PATCH  /api/v1/tenants/idp/{pk}/
    DELETE /api/v1/tenants/idp/{pk}/
    """

    def _get_config(self, request, pk: str) -> tuple:
        """Return (user, config) or (None, JsonResponse) on error."""
        user = _resolve_request_user(request)
        if not user:
            return None, JsonResponse({"message": "Not authenticated"}, status=401)

        try:
            config = TenantIDPConfig.objects.get(id=pk)
        except TenantIDPConfig.DoesNotExist:
            return None, JsonResponse({"message": "Not found"}, status=404)

        if str(config.tenant_id) not in [str(t) for t in _user_tenant_ids(user)]:
            return None, JsonResponse({"message": "Forbidden"}, status=403)

        return user, config

    def get(self, request, pk: str) -> JsonResponse:
        user, result = self._get_config(request, pk)
        if user is None:
            return result
        return JsonResponse(TenantIDPConfigSerializer(result).data, status=200)

    def patch(self, request, pk: str) -> JsonResponse:
        user, result = self._get_config(request, pk)
        if user is None:
            return result

        try:
            body = json.loads(request.body)
        except (json.JSONDecodeError, AttributeError):
            return JsonResponse({"message": "Invalid JSON"}, status=400)

        # Re-store secret if provided
        new_config = dict(body.get("config", result.config))
        client_secret = new_config.pop("client_secret", None)
        if client_secret:
            from user_auth.utils.secrets_utils import store_idp_secret
            secret_ref = _secret_ref(str(result.tenant_id), result.idp_type)
            store_idp_secret(secret_ref, client_secret)
            new_config["client_secret_ref"] = secret_ref

        body["config"] = new_config
        serializer = TenantIDPConfigSerializer(result, data=body, partial=True)
        if not serializer.is_valid():
            return JsonResponse({"errors": serializer.errors}, status=400)

        serializer.save()
        log_auth_event(
            "idp_config.update",
            request=request,
            user=user,
            tenant_id=str(result.tenant_id),
            extra={"idp_config_id": pk},
        )
        return JsonResponse(TenantIDPConfigSerializer(result).data, status=200)

    def delete(self, request, pk: str) -> JsonResponse:
        user, result = self._get_config(request, pk)
        if user is None:
            return result

        result.is_active = False
        result.save(update_fields=["is_active", "updated_at"])
        log_auth_event(
            "idp_config.delete",
            request=request,
            user=user,
            tenant_id=str(result.tenant_id),
            extra={"idp_config_id": pk},
        )
        return JsonResponse({"message": f"IDP config {pk} deactivated"}, status=200)


class TenantIDPConfigActivateView(APIView):
    """Validate IDP reachability and activate the config.

    POST /api/v1/tenants/idp/{pk}/activate/
    """

    def post(self, request, pk: str) -> JsonResponse:
        user = _resolve_request_user(request)
        if not user:
            return JsonResponse({"message": "Not authenticated"}, status=401)

        try:
            idp_config = TenantIDPConfig.objects.get(id=pk)
        except TenantIDPConfig.DoesNotExist:
            return JsonResponse({"message": "Not found"}, status=404)

        if str(idp_config.tenant_id) not in [str(t) for t in _user_tenant_ids(user)]:
            return JsonResponse({"message": "Forbidden"}, status=403)

        config = idp_config.config
        validation_error: Optional[str] = validate_idp_config(idp_config.idp_type, config)

        if validation_error:
            logger.warning(f"IDP activation validation failed for {pk}: {validation_error}")
            return JsonResponse(
                {"status": "validation_failed", "reason": validation_error},
                status=200,
            )

        # Deactivate any other configs of the same type for this tenant
        TenantIDPConfig.objects.filter(
            tenant_id=idp_config.tenant_id,
            idp_type=idp_config.idp_type,
            is_active=True,
        ).exclude(id=pk).update(is_active=False)

        idp_config.is_active = True
        idp_config.save(update_fields=["is_active", "updated_at"])

        logger.info(f"Activated IDP config {pk} ({idp_config.idp_name}) for tenant {idp_config.tenant_id}")
        log_auth_event(
            "idp_config.activate",
            request=request,
            user=_resolve_request_user(request),
            tenant_id=str(idp_config.tenant_id),
            extra={"idp_config_id": pk, "idp_name": idp_config.idp_name},
        )
        return JsonResponse({"status": "activated", "idp_name": idp_config.idp_name}, status=200)


class TenantIDPByDomainView(APIView):
    """Public endpoint — look up the active IDP for an email domain.

    GET /api/v1/tenants/idp-by-domain/?domain=acme.com

    Returns {"tenant_id": "<uuid>", "idp_type": "...", "idp_name": "..."} when found,
    or {"tenant_id": null} when no match.  No authentication required — callers
    use the result to redirect to the correct SSO flow.
    """

    def get(self, request) -> JsonResponse:
        domain = request.GET.get("domain", "").strip().lower()
        if not domain:
            return JsonResponse({"tenant_id": None}, status=200)

        config = (
            TenantIDPConfig.objects.filter(
                is_active=True,
                allowed_domains__contains=[domain],
            )
            .select_related("tenant")
            .first()
        )
        if not config:
            return JsonResponse({"tenant_id": None}, status=200)

        return JsonResponse(
            {
                "tenant_id": str(config.tenant_id),
                "idp_type": config.idp_type,
                "idp_name": config.idp_name,
            },
            status=200,
        )