import hashlib
import json
import logging
import os
from typing import Optional

import requests as http_requests
from django.http import HttpResponse, HttpResponseNotModified, JsonResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.utils.encoding import force_bytes
from rest_framework import status, viewsets, mixins
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.pagination import PageNumberPagination
from rest_framework.views import APIView

from .models import Tenants, TenantIDPConfig, CsmGroups, GroupMembers, TenantGroupAccess, AccountGroupAccess
from .serializers import (
    TenantSerializer, TenantIDPConfigSerializer,
    GroupSerializer, GroupMemberSerializer,
    TenantGroupAccessSerializer, AccountGroupAccessSerializer,
    TenantAssignSerializer, AccountAssignSerializer,
    OrgProfilePatch, TenantTypePatch,
)
from .filters import build_tenant_query
from shared.permissions import OrgScopedPermission
from user_auth.drf_auth import CookieTokenAuthentication
from user_auth.drf_permissions import HasPermission
from user_auth.throttles import IDPByDomainRateThrottle
from user_auth.utils.audit_utils import log_auth_event
from user_auth.utils.idp_validation import validate_idp_config
from utils.rbac import enforce_org_boundary, is_platform_admin

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
    authentication_classes = [CookieTokenAuthentication]
    permission_classes = [HasPermission("tenants:read"), OrgScopedPermission]

    def get_permissions(self):
        write_actions = {"create", "update", "partial_update", "destroy"}
        if self.action in write_actions:
            return [HasPermission("tenants:write")(), OrgScopedPermission()]
        return [HasPermission("tenants:read")(), OrgScopedPermission()]

    def get_queryset(self):
        # build_tenant_query applies field-level filters (status, plan, search terms).
        # enforce_org_boundary is the canonical AC7 utility: scopes org_admin to their
        # own customer_id and lets platform_admin see all tenants.
        base_qs = build_tenant_query(self.request.query_params, user=self.request.user)
        return enforce_org_boundary(self.request.user, base_qs)

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
        # Double-filter: queryset already scoped by role; also limit to explicitly
        # allowed tenant IDs so CSV/XLSX never leaks rows from a concurrent write race.
        allowed_ids = _user_tenant_ids(request.user) if request.user else []
        queryset = self.filter_queryset(self.get_queryset()).filter(id__in=allowed_ids)

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
    sessions = UserSessions.objects.filter(
        revoked=False, token_hint=access_token[:8]
    ).select_related("user")
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

        # Cross-org check: org_admin may not configure IDPs for tenants in another org
        try:
            target_tenant = Tenants.objects.get(id=tenant_id)
            user_customer_id = getattr(user, "customer_id", None) or str(user.id)
            from user_auth.models import UserRoles
            user_role_name = (
                UserRoles.objects.filter(user=user)
                .select_related("role")
                .order_by("role__level")
                .values_list("role__name", flat=True)
                .first()
            )
            if user_role_name != "platform_admin":
                if target_tenant.customer_id and target_tenant.customer_id != user_customer_id:
                    return JsonResponse({"message": "Forbidden — cross-org IDP configuration"}, status=403)
        except Tenants.DoesNotExist:
            return JsonResponse({"message": "Tenant not found"}, status=404)

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

    Returns {"redirect_url": "...", "idp_type": "...", "idp_name": "..."} when found,
    or {"redirect_url": null} when no match.  No authentication required.
    tenant_id is intentionally omitted — callers must use redirect_url directly.
    """

    throttle_classes = [IDPByDomainRateThrottle]

    def get(self, request) -> JsonResponse:
        domain = request.GET.get("domain", "").strip().lower()
        if not domain:
            return JsonResponse({"redirect_url": None}, status=200)

        config = (
            TenantIDPConfig.objects.filter(
                is_active=True,
                allowed_domains__contains=[domain],
            )
            .select_related("tenant")
            .first()
        )
        if not config:
            return JsonResponse({"redirect_url": None}, status=200)

        tid = str(config.tenant_id)
        idp_type = config.idp_type
        if idp_type == "saml":
            redirect_url = f"/api/auth/saml/{tid}/login/"
        elif idp_type in ("oidc", "google_oauth"):
            redirect_url = f"/api/auth/oidc/login/?tenant={tid}"
        elif idp_type == "microsoft":
            redirect_url = "/api/auth/microsoft/login/"
        else:
            redirect_url = f"/api/auth/oidc/login/?tenant={tid}"

        return JsonResponse(
            {
                "redirect_url": redirect_url,
                "idp_type": idp_type,
                "idp_name": config.idp_name,
            },
            status=200,
        )


class ResyncTenantView(APIView):
    """POST /api/v1/tenants/{tenant_id}/resync/

    Re-enqueue the onboarding sync task for the given tenant.
    Restricted to platform_admin only (AC5). Returns 202 with task_id (AC6).
    Allows resync regardless of current tenant status so admins can force
    re-sync after config changes (AC7 — failure is logged, not raised).
    """

    def post(self, request, tenant_id: str) -> JsonResponse:
        user = _resolve_request_user(request)
        if user is None:
            return JsonResponse({"message": "Authentication required"}, status=401)

        from user_auth.models import UserRoles
        user_role = (
            UserRoles.objects.filter(user=user)
            .select_related("role")
            .order_by("role__level")
            .first()
        )
        if not user_role or user_role.role.name != "platform_admin":
            return JsonResponse({"message": "Forbidden"}, status=403)

        try:
            tenant = Tenants.objects.get(id=tenant_id)
        except Tenants.DoesNotExist:
            return JsonResponse({"message": "Not found"}, status=404)

        from user_auth.celery_tasks import sync_tenant_to_onboarding
        async_result = sync_tenant_to_onboarding.apply_async(
            args=[tenant_id, str(tenant.customer_id or tenant_id)],
            queue="tenant-sync",
        )
        log_auth_event(
            "tenant.resync_enqueued",
            request=request,
            user=user,
            tenant_id=tenant_id,
        )
        return JsonResponse(
            {"task_id": async_result.id, "tenant_id": tenant_id},
            status=202,
        )


# ── D-4: Org profile ──────────────────────────────────────────────────────────

class OrgProfileView(APIView):
    """GET /api/org/profile/ — read org profile (AC1).
    PATCH /api/org/profile/ — update org_name and contact_email (AC2, AC3).

    Org profile is derived from the first Tenants row for the caller's
    customer_id.  plan and customer_id are read-only (AC3).
    platform_admin sees any org (AC9).
    """

    authentication_classes = [CookieTokenAuthentication]
    permission_classes = [HasPermission("orgs:read")]

    def _get_customer_id(self, request) -> str:
        """Return caller's customer_id, or raise 403 if absent."""
        if is_platform_admin(request.user):
            # platform_admin: if a ?customer_id= query param is supplied, honour it;
            # otherwise fall back to their own customer_id.
            cid = request.query_params.get("customer_id") or getattr(request.user, "customer_id", None)
        else:
            cid = getattr(request.user, "customer_id", None)
        return cid or str(request.user.id)

    def get(self, request):
        """AC1: return org profile for the caller's customer_id."""
        customer_id = self._get_customer_id(request)
        # Use the first tenant for the org-level fields (name, contact_email, plan).
        # All tenants under the same customer_id share the same org.
        tenant = Tenants.objects.filter(customer_id=customer_id).order_by("created_at").first()
        return Response({
            "customer_id": customer_id,
            "org_name": tenant.name if tenant else "",
            "contact_email": tenant.contact_email if tenant else "",
            "plan": tenant.plan if tenant else "",
        })

    def patch(self, request):
        """AC2/AC3: update org_name and/or contact_email; reject customer_id/plan/billing_org_id."""
        # Require orgs:write — fail fast with 403 if missing.
        if not HasPermission("orgs:write")().has_permission(request, self):
            return Response({"detail": "You do not have permission to perform this action."}, status=403)

        # Reject attempts to modify read-only fields (AC3).
        read_only_fields = {"customer_id", "plan", "billing_org_id"}
        forbidden = read_only_fields & set(request.data.keys())
        if forbidden:
            return Response(
                {"detail": f"Fields are read-only and cannot be modified: {sorted(forbidden)}"},
                status=400,
            )

        serializer = OrgProfilePatch(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=422)

        customer_id = self._get_customer_id(request)
        update_kwargs: dict = {}
        if "org_name" in serializer.validated_data:
            update_kwargs["name"] = serializer.validated_data["org_name"]
        if "contact_email" in serializer.validated_data:
            update_kwargs["contact_email"] = serializer.validated_data["contact_email"]

        if update_kwargs:
            Tenants.objects.filter(customer_id=customer_id).update(**update_kwargs)

        return Response({"updated": True, "customer_id": customer_id})


class TenantTypeView(APIView):
    """GET /api/tenants/{id}/type/ — read tenant_type (AC4).
    PATCH /api/tenants/{id}/type/ — update tenant_type (AC5, AC6).

    Tenant must belong to the caller's org (AC8).
    platform_admin can access any tenant (AC9).
    """

    authentication_classes = [CookieTokenAuthentication]
    permission_classes = [HasPermission("orgs:read")]

    def _get_tenant(self, request, tenant_id: str) -> Tenants:
        """Return tenant scoped to caller's org, or raise 404."""
        qs = Tenants.objects.filter(id=tenant_id)
        if not is_platform_admin(request.user):
            customer_id = getattr(request.user, "customer_id", None)
            if not customer_id:
                raise Tenants.DoesNotExist
            qs = qs.filter(customer_id=customer_id)
        return get_object_or_404(qs)

    def get(self, request, tenant_id: str):
        """AC4: return tenant_type; 404 if cross-org."""
        tenant = self._get_tenant(request, tenant_id)
        return Response({"tenant_id": str(tenant.id), "tenant_type": tenant.tenant_type})

    def patch(self, request, tenant_id: str):
        """AC5/AC6: update tenant_type; 422 on invalid value; 404 on cross-org."""
        if not HasPermission("orgs:write")().has_permission(request, self):
            return Response({"detail": "You do not have permission to perform this action."}, status=403)

        serializer = TenantTypePatch(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=422)

        tenant = self._get_tenant(request, tenant_id)
        tenant.tenant_type = serializer.validated_data["tenant_type"]
        tenant.save(update_fields=["tenant_type"])
        return Response({"tenant_id": str(tenant.id), "tenant_type": tenant.tenant_type})


class InternalTenantTypeView(APIView):
    """GET /internal/tenants/{id}/type — internal endpoint for onboarding engine (AC7).

    Authentication: X-Internal-Secret header only.  No cookie/session auth.
    Used by onboarding-C5 to validate account_type against tenant_type.
    """

    authentication_classes = []
    permission_classes = []

    def get(self, request, tenant_id: str):
        """AC7: return tenant_type for any tenant; requires X-Internal-Secret."""
        secret = request.headers.get("X-Internal-Secret", "")
        expected = os.environ.get("X_INTERNAL_SECRET", "")
        if not expected or secret != expected:
            return Response({"detail": "Unauthorized"}, status=401)

        tenant = get_object_or_404(Tenants, id=tenant_id)
        return Response({"tenant_type": tenant.tenant_type})


# ── D-1: Group management ─────────────────────────────────────────────────────

def _user_customer_id(user) -> str:
    return getattr(user, "customer_id", None) or str(user.id)


class GroupViewSet(viewsets.ModelViewSet):
    """CRUD for customer-scoped groups. customer_id is ALWAYS server-side.

    Permission matrix (AC8):
      GET /api/groups/         → users:read
      GET /api/groups/{id}/    → users:read
      POST /api/groups/        → users:write  (org_admin / platform_admin)
      PATCH /api/groups/{id}/  → users:write  (org_admin / platform_admin)
      DELETE /api/groups/{id}/ → users:write  (org_admin / platform_admin)

    Org boundary (AC1, AC9): enforced by get_queryset() + OrgScopedPermission.
    customer_id is set server-side on create — never trusted from request body.
    """

    authentication_classes = [CookieTokenAuthentication]
    permission_classes     = [HasPermission("users:read"), OrgScopedPermission]
    serializer_class       = GroupSerializer

    def get_queryset(self):
        from utils.rbac import enforce_org_boundary
        return enforce_org_boundary(self.request.user, CsmGroups.objects.all()).order_by("name")

    def get_permissions(self):
        write_actions = {"create", "update", "partial_update", "destroy"}
        if self.action in write_actions:
            return [HasPermission("users:write")(), OrgScopedPermission()]
        return [HasPermission("users:read")(), OrgScopedPermission()]

    def perform_create(self, serializer):
        # customer_id is always set from authenticated user — never from request body (AC2, security checklist)
        serializer.save(
            customer_id=_user_customer_id(self.request.user),
            created_by=self.request.user,
        )


class GroupMemberViewSet(viewsets.ModelViewSet):
    """Nested under /groups/{group_pk}/members/.

    AC6: POST /api/groups/{id}/members/ — add a user (users:write)
    AC7: DELETE /api/groups/{id}/members/{user_id}/ — remove a user (users:write)
    """

    authentication_classes = [CookieTokenAuthentication]
    permission_classes     = [HasPermission("users:write")]
    serializer_class       = GroupMemberSerializer
    http_method_names      = ["get", "post", "delete", "head", "options"]

    def _get_group(self):
        """Return the group only if it belongs to the caller's org (AC9)."""
        from django.shortcuts import get_object_or_404
        from utils.rbac import enforce_org_boundary
        scoped_qs = enforce_org_boundary(self.request.user, CsmGroups.objects.all())
        return get_object_or_404(scoped_qs, pk=self.kwargs["group_pk"])

    def get_queryset(self):
        return GroupMembers.objects.filter(group=self._get_group()).select_related("user")

    def perform_create(self, serializer):
        from django.shortcuts import get_object_or_404
        from user_auth.models import Users
        group   = self._get_group()
        user_id = self.request.data.get("user_id")
        user    = get_object_or_404(Users, id=user_id)
        serializer.save(group=group, user=user)


# ── D-2: Invite flow ─────────────────────────────────────────────────────────

class InviteCreateView(APIView):
    """POST /api/v1/invites/ — create an invite for an email to a tenant with a role."""
    authentication_classes = [CookieTokenAuthentication]
    permission_classes     = [HasPermission("users:write")]

    def post(self, request):
        import secrets as _secrets
        from datetime import timedelta
        from django.shortcuts import get_object_or_404
        from user_auth.models import Roles, InviteTokens
        from user_auth.utils.email_utils import send_invite_email
        from user_auth.utils.audit_utils import log_auth_event

        email     = (request.data.get("email") or "").strip().lower()
        tenant_id = request.data.get("tenant_id")
        role_name = request.data.get("role", "viewer")

        if not email or not tenant_id:
            return Response({"error": "email and tenant_id are required"}, status=400)

        customer_id = _user_customer_id(request.user)
        tenant = get_object_or_404(Tenants, id=tenant_id, customer_id=customer_id)

        # Cap role — inviter cannot grant higher than their own level
        from user_auth.models import UserRoles
        inviter_role = (
            UserRoles.objects.filter(user=request.user)
            .select_related("role")
            .order_by("role__level")
            .first()
        )
        inviter_level = inviter_role.role.level if inviter_role else 99
        target_role = Roles.objects.filter(name=role_name).first()
        if not target_role or target_role.level < inviter_level:
            # Silently cap to viewer
            target_role = Roles.objects.filter(name="viewer").first()

        # Optional group assignment — scoped to the inviter's own org (BILL-S06)
        group_id = request.data.get("group_id")
        group = None
        if group_id:
            try:
                group = CsmGroups.objects.get(id=group_id, customer_id=customer_id)
            except CsmGroups.DoesNotExist:
                return Response({"error": "Group not found or not in your organisation"}, status=404)

        raw_token = _secrets.token_urlsafe(32)
        invite = InviteTokens.objects.create(
            token=raw_token,
            email=email,
            tenant=tenant,
            role=target_role,
            invited_by=request.user,
            expires_at=timezone.now() + timedelta(hours=48),
            used=False,
            group=group,
        )
        try:
            # Legacy path-based accept URL (/auth/invite/{token}/) used by
            # ValidateInviteView / AcceptInviteView (user_auth/views/invite.py).
            from user_auth.utils.email_utils import FRONTEND_URL as _FRONTEND_URL
            send_invite_email(
                email,
                invite_token=raw_token,
                tenant_name=tenant.name,
                invited_by=request.user.email,
                ttl_hours=48,
                accept_url=f"{_FRONTEND_URL}/auth/invite/{raw_token}",
            )
        except Exception:
            pass  # non-fatal — invite record created, email may be queued

        log_auth_event("invite.created", request=request, user=request.user, tenant_id=tenant_id)
        return Response({"id": str(invite.id), "email": email, "expires_at": invite.expires_at.isoformat()}, status=201)


class InviteDetailView(APIView):
    """GET /api/v1/invites/{token}/ — validate invite token (public endpoint for UI pre-check)."""

    def get(self, request, token: str):
        from user_auth.models import InviteTokens
        try:
            invite = InviteTokens.objects.select_related("tenant", "role").get(token=token)
        except InviteTokens.DoesNotExist:
            return Response({"valid": False, "reason": "not_found"}, status=404)
        if invite.used:
            return Response({"valid": False, "reason": "already_used"}, status=410)
        if invite.expires_at < timezone.now():
            return Response({"valid": False, "reason": "expired"}, status=410)
        return Response({
            "valid":       True,
            "email":       invite.email,
            "tenant_name": invite.tenant.name if invite.tenant else None,
            "role":        invite.role.name if invite.role else "viewer",
            "expires_at":  invite.expires_at.isoformat(),
        })


class InviteAcceptView(APIView):
    """POST /api/v1/invites/{token}/accept/ — accept invite (authenticated user)."""
    authentication_classes = [CookieTokenAuthentication]

    def post(self, request, token: str):
        from user_auth.models import InviteTokens
        from user_auth.utils.tenant_utils import accept_invite_membership
        from user_auth.utils.audit_utils import log_auth_event

        try:
            invite = InviteTokens.objects.select_related("tenant").get(token=token)
        except InviteTokens.DoesNotExist:
            return Response({"error": "Invite not found"}, status=404)
        if invite.used:
            return Response({"error": "Invite already used"}, status=409)
        if invite.expires_at < timezone.now():
            return Response({"error": "Invite expired"}, status=410)

        from user_auth.models import InviteTokens as _InviteTokens
        try:
            accept_invite_membership(user=request.user, invite=invite)
        except _InviteTokens.DoesNotExist:
            # Concurrent request already consumed this token — the atomic
            # SELECT FOR UPDATE guard in accept_invite_membership raised
            # DoesNotExist after the other transaction committed.
            return Response({"error": "This invite has already been used"}, status=409)

        # invite.used = True is handled atomically inside accept_invite_membership;
        # the redundant save has been removed (BILL-S01).

        return Response({"joined": True})


# ── D-3: Group access assignment ──────────────────────────────────────────────

class TenantGroupAccessView(APIView):
    """POST/GET /api/v1/tenants/{tenant_id}/group-access/ and DELETE /{access_id}/"""
    authentication_classes = [CookieTokenAuthentication]
    permission_classes     = [HasPermission("tenants:write")]

    def _get_tenant(self, request, tenant_id: str):
        from django.shortcuts import get_object_or_404
        return get_object_or_404(Tenants, id=tenant_id, customer_id=_user_customer_id(request.user))

    def get(self, request, tenant_id: str):
        self.permission_classes = [HasPermission("tenants:read")]
        tenant  = self._get_tenant(request, tenant_id)
        accesses = TenantGroupAccess.objects.filter(tenant=tenant).select_related("group", "role")
        return Response(TenantGroupAccessSerializer(accesses, many=True).data)

    def post(self, request, tenant_id: str):
        from django.shortcuts import get_object_or_404
        from user_auth.models import Roles
        tenant   = self._get_tenant(request, tenant_id)
        group    = get_object_or_404(CsmGroups, id=request.data.get("group_id"), customer_id=_user_customer_id(request.user))
        role     = get_object_or_404(Roles, name=request.data.get("role", "viewer"))
        access, created = TenantGroupAccess.objects.get_or_create(
            group=group, tenant=tenant, defaults={"role": role}
        )
        if not created:
            access.role = role
            access.save(update_fields=["role"])
        return Response(TenantGroupAccessSerializer(access).data, status=201 if created else 200)

    def delete(self, request, tenant_id: str, access_id: str):
        from django.shortcuts import get_object_or_404
        tenant = self._get_tenant(request, tenant_id)
        access = get_object_or_404(TenantGroupAccess, id=access_id, tenant=tenant)
        access.delete()
        return Response(status=204)


class AccountGroupAccessView(APIView):
    """POST/GET/DELETE for /api/v1/tenants/{tenant_id}/accounts/{account_id}/group-access/"""
    authentication_classes = [CookieTokenAuthentication]
    permission_classes     = [HasPermission("tenants:write")]

    def _get_tenant(self, request, tenant_id: str):
        from django.shortcuts import get_object_or_404
        return get_object_or_404(Tenants, id=tenant_id, customer_id=_user_customer_id(request.user))

    def get(self, request, tenant_id: str, account_id: str):
        self.permission_classes = [HasPermission("tenants:read")]
        tenant   = self._get_tenant(request, tenant_id)
        accesses = AccountGroupAccess.objects.filter(tenant=tenant, account_id=account_id).select_related("group", "role")
        return Response(AccountGroupAccessSerializer(accesses, many=True).data)

    def post(self, request, tenant_id: str, account_id: str):
        from django.shortcuts import get_object_or_404
        from user_auth.models import Roles
        tenant   = self._get_tenant(request, tenant_id)
        group    = get_object_or_404(CsmGroups, id=request.data.get("group_id"), customer_id=_user_customer_id(request.user))
        role     = get_object_or_404(Roles, name=request.data.get("role", "viewer"))
        access, created = AccountGroupAccess.objects.get_or_create(
            group=group, tenant=tenant, account_id=account_id, defaults={"role": role}
        )
        if not created:
            access.role = role
            access.save(update_fields=["role"])
        return Response(AccountGroupAccessSerializer(access).data, status=201 if created else 200)

    def delete(self, request, tenant_id: str, account_id: str, access_id: str):
        from django.shortcuts import get_object_or_404
        tenant = self._get_tenant(request, tenant_id)
        access = get_object_or_404(AccountGroupAccess, id=access_id, tenant=tenant, account_id=account_id)
        access.delete()
        return Response(status=204)


# ── D-3: Group-centric access assignment (onboarding-D3) ─────────────────────


def _get_group_org_scoped(request, group_id: str) -> CsmGroups:
    """Return group scoped to caller's org.

    platform_admin bypasses the customer_id filter (AC9).
    Raises Http404 if the group does not exist or belongs to a different org.
    This prevents cross-org group lookups from leaking existence (AC5).
    """
    qs = CsmGroups.objects.filter(id=group_id)
    if not is_platform_admin(request.user):
        qs = qs.filter(customer_id=_user_customer_id(request.user))
    return get_object_or_404(qs)


def _get_tenant_org_scoped(request, tenant_id: str) -> Tenants:
    """Return tenant scoped to caller's org.

    platform_admin bypasses the customer_id filter (AC9).
    Raises Http404 if tenant does not exist or belongs to another org (AC6).
    """
    qs = Tenants.objects.filter(id=tenant_id)
    if not is_platform_admin(request.user):
        qs = qs.filter(customer_id=_user_customer_id(request.user))
    return get_object_or_404(qs)


class GroupTenantAssignView(APIView):
    """Assign or remove a tenant from a group (group-centric direction).

    POST   /api/groups/{group_id}/tenants/
        Body: {"tenant_id": "<uuid>", "role": "tenant_admin"}
        Returns 201 on create, 200 on idempotent re-assign (role updated).

    GET    /api/groups/{group_id}/tenants/
        Returns list of TenantGroupAccess rows for this group.

    DELETE /api/groups/{group_id}/tenants/{tenant_id}/
        Removes the group-tenant assignment. Returns 204.

    Permission: users:write for POST/DELETE, users:read for GET (AC8).
    Org boundary enforced on group (AC5) and tenant (AC6) separately.
    platform_admin bypasses org boundary checks (AC9).
    """

    authentication_classes = [CookieTokenAuthentication]
    permission_classes = [HasPermission("users:write"), OrgScopedPermission]

    def get_permissions(self):
        if self.request.method in ("GET", "HEAD", "OPTIONS"):
            return [HasPermission("users:read")(), OrgScopedPermission()]
        return [HasPermission("users:write")(), OrgScopedPermission()]

    def get(self, request, group_id: str):
        """AC1-list: return all tenant assignments for this group."""
        group = _get_group_org_scoped(request, group_id)
        accesses = (
            TenantGroupAccess.objects
            .filter(group=group)
            .select_related("tenant", "role")
        )
        return Response(TenantGroupAccessSerializer(accesses, many=True).data)

    def post(self, request, group_id: str):
        """AC1: assign a tenant to a group; idempotent via get_or_create."""
        from user_auth.models import Roles

        ser = TenantAssignSerializer(data=request.data)
        if not ser.is_valid():
            return Response(ser.errors, status=status.HTTP_400_BAD_REQUEST)

        group = _get_group_org_scoped(request, group_id)
        tenant = _get_tenant_org_scoped(request, ser.validated_data["tenant_id"])
        role = get_object_or_404(Roles, name=ser.validated_data["role"])

        access, created = TenantGroupAccess.objects.get_or_create(
            group=group,
            tenant=tenant,
            defaults={"role": role},
        )
        if not created:
            # Idempotent: update role on duplicate (AC — duplicate returns 200)
            access.role = role
            access.save(update_fields=["role"])

        return Response(
            TenantGroupAccessSerializer(access).data,
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )


class GroupTenantDeleteView(APIView):
    """DELETE /api/groups/{group_id}/tenants/{tenant_id}/ — remove group-tenant assignment (AC2).

    Permission: users:write (AC8).
    Org boundary enforced on group (AC5) and tenant (AC6).
    Returns 204 on success; 404 if assignment does not exist.
    """

    authentication_classes = [CookieTokenAuthentication]
    permission_classes = [HasPermission("users:write"), OrgScopedPermission]

    def delete(self, request, group_id: str, tenant_id: str):
        group = _get_group_org_scoped(request, group_id)
        tenant = _get_tenant_org_scoped(request, tenant_id)
        access = get_object_or_404(TenantGroupAccess, group=group, tenant=tenant)
        access.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class GroupAccountAssignView(APIView):
    """Assign or remove a cloud account from a group (group-centric direction).

    POST   /api/groups/{group_id}/accounts/
        Body: {"account_id": "<id>", "tenant_id": "<uuid>", "role": "analyst"}
        Returns 201 on create, 200 on idempotent re-assign.

    GET    /api/groups/{group_id}/accounts/
        Returns list of AccountGroupAccess rows for this group.

    DELETE /api/groups/{group_id}/accounts/{account_id}/
        Removes the group-account assignment. Returns 204.

    Permission: users:write for POST/DELETE, users:read for GET (AC8).
    Org boundary enforced on group (AC5) and tenant/account's tenant (AC7).
    platform_admin bypasses org boundary checks (AC9).
    """

    authentication_classes = [CookieTokenAuthentication]
    permission_classes = [HasPermission("users:write"), OrgScopedPermission]

    def get_permissions(self):
        if self.request.method in ("GET", "HEAD", "OPTIONS"):
            return [HasPermission("users:read")(), OrgScopedPermission()]
        return [HasPermission("users:write")(), OrgScopedPermission()]

    def get(self, request, group_id: str):
        """List all account assignments for this group."""
        group = _get_group_org_scoped(request, group_id)
        accesses = (
            AccountGroupAccess.objects
            .filter(group=group)
            .select_related("tenant", "role")
        )
        return Response(AccountGroupAccessSerializer(accesses, many=True).data)

    def post(self, request, group_id: str):
        """AC3: assign a cloud account (scoped to a tenant) to a group; idempotent."""
        from user_auth.models import Roles

        ser = AccountAssignSerializer(data=request.data)
        if not ser.is_valid():
            return Response(ser.errors, status=status.HTTP_400_BAD_REQUEST)

        group = _get_group_org_scoped(request, group_id)
        # AC7: verify the account's owning tenant belongs to the caller's org
        tenant = _get_tenant_org_scoped(request, ser.validated_data["tenant_id"])
        role = get_object_or_404(Roles, name=ser.validated_data["role"])
        account_id = ser.validated_data["account_id"]

        access, created = AccountGroupAccess.objects.get_or_create(
            group=group,
            tenant=tenant,
            account_id=account_id,
            defaults={"role": role},
        )
        if not created:
            access.role = role
            access.save(update_fields=["role"])

        return Response(
            AccountGroupAccessSerializer(access).data,
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )


class GroupAccountDeleteView(APIView):
    """DELETE /api/groups/{group_id}/accounts/{account_id}/ — remove group-account assignment (AC4).

    Requires tenant_id query param to resolve the correct AccountGroupAccess row
    (unique_together: group, tenant, account_id).
    Permission: users:write (AC8).
    Returns 204 on success; 404 if assignment does not exist.
    """

    authentication_classes = [CookieTokenAuthentication]
    permission_classes = [HasPermission("users:write"), OrgScopedPermission]

    def delete(self, request, group_id: str, account_id: str):
        group = _get_group_org_scoped(request, group_id)
        tenant_id = request.query_params.get("tenant_id") or request.data.get("tenant_id")
        if not tenant_id:
            return Response(
                {"detail": "tenant_id query param is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        tenant = _get_tenant_org_scoped(request, tenant_id)
        access = get_object_or_404(
            AccountGroupAccess, group=group, tenant=tenant, account_id=account_id
        )
        access.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)