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

from .models import Tenants, TenantIDPConfig, CsmGroups, GroupMembers, TenantGroupAccess, AccountGroupAccess
from .serializers import (
    TenantSerializer, TenantIDPConfigSerializer,
    GroupSerializer, GroupMemberSerializer,
    TenantGroupAccessSerializer, AccountGroupAccessSerializer,
)
from .filters import build_tenant_query
from user_auth.drf_auth import CookieTokenAuthentication
from user_auth.drf_permissions import HasPermission
from user_auth.throttles import IDPByDomainRateThrottle
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
    authentication_classes = [CookieTokenAuthentication]
    permission_classes = [HasPermission("tenants:read")]

    def get_permissions(self):
        write_actions = {"create", "update", "partial_update", "destroy"}
        if self.action in write_actions:
            return [HasPermission("tenants:write")()]
        return [HasPermission("tenants:read")()]

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

    Re-enqueue the onboarding sync task for a tenant whose status is 'sync_failed'.
    Restricted to platform_admin only.
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

        if tenant.status == "active":
            return JsonResponse({"message": "Tenant is already active"}, status=409)

        from user_auth.celery_tasks import sync_tenant_to_onboarding
        sync_tenant_to_onboarding.apply_async(
            args=[tenant_id, str(tenant.customer_id or tenant_id)],
            queue="tenant-sync",
        )
        log_auth_event(
            "tenant.resync_enqueued",
            request=request,
            user=user,
            tenant_id=tenant_id,
        )
        return JsonResponse({"message": "Resync enqueued"}, status=200)


# ── D-4: Org profile ──────────────────────────────────────────────────────────

class OrgProfileView(APIView):
    """GET/PATCH /api/v1/org/profile/ — read/update org display name."""
    authentication_classes = [CookieTokenAuthentication]
    permission_classes     = [HasPermission("orgs:read")]

    def get(self, request):
        user = request.user
        customer_id = getattr(user, "customer_id", None) or str(user.id)
        tenants = list(
            Tenants.objects.filter(customer_id=customer_id)
            .values("id", "name", "status", "tenant_type")
        )
        return Response({
            "customer_id":   customer_id,
            "email":         user.email,
            "display_name":  user.get_full_name() or user.email,
            "tenants":       tenants,
        })

    def patch(self, request):
        from user_auth.drf_permissions import HasPermission as _HP
        _HP("orgs:write")().has_permission(request, self)
        name = (request.data.get("display_name") or "").strip()
        if name:
            parts = name.split(" ", 1)
            request.user.first_name = parts[0]
            request.user.last_name  = parts[1] if len(parts) > 1 else ""
            request.user.save(update_fields=["first_name", "last_name"])
        return Response({"updated": True})


# ── D-1: Group management ─────────────────────────────────────────────────────

def _user_customer_id(user) -> str:
    return getattr(user, "customer_id", None) or str(user.id)


class GroupViewSet(viewsets.ModelViewSet):
    """CRUD for customer-scoped groups. customer_id is ALWAYS server-side."""
    authentication_classes = [CookieTokenAuthentication]
    permission_classes     = [HasPermission("groups:read")]
    serializer_class       = GroupSerializer

    def get_queryset(self):
        customer_id = _user_customer_id(self.request.user)
        if not customer_id:
            return CsmGroups.objects.none()
        from user_auth.models import UserRoles
        role = UserRoles.objects.filter(user=self.request.user).select_related("role").order_by("role__level").first()
        if role and role.role.level == 1:  # platform_admin — see all
            return CsmGroups.objects.all().order_by("name")
        return CsmGroups.objects.filter(customer_id=customer_id).order_by("name")

    def get_permissions(self):
        if self.action in ("create", "update", "partial_update", "destroy"):
            return [HasPermission("groups:write")()]
        return super().get_permissions()

    def perform_create(self, serializer):
        serializer.save(
            customer_id=_user_customer_id(self.request.user),
            created_by=self.request.user,
        )


class GroupMemberViewSet(viewsets.ModelViewSet):
    """Nested under /groups/{group_pk}/members/."""
    authentication_classes = [CookieTokenAuthentication]
    permission_classes     = [HasPermission("groups:write")]
    serializer_class       = GroupMemberSerializer
    http_method_names      = ["get", "post", "delete", "head", "options"]

    def _get_group(self):
        from django.shortcuts import get_object_or_404
        return get_object_or_404(
            CsmGroups,
            pk=self.kwargs["group_pk"],
            customer_id=_user_customer_id(self.request.user),
        )

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
            send_invite_email(email, invite_token=raw_token, tenant_name=tenant.name, invited_by=request.user.email)
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