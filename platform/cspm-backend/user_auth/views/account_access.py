"""
UserAccountAccess API — grant/revoke per-user cloud account access within a tenant.

GET  /api/users/<userId>/accounts/?tenant_id=X  → list all accounts with granted flag
PUT  /api/users/<userId>/accounts/              → replace full grant set (array of account_ids)
"""
import logging
from typing import Any

import httpx
from django.http import JsonResponse
from django.utils import timezone
from rest_framework.views import APIView

from user_auth.models import Users, UserSessions
from user_auth.utils.auth_utils import verify_token

logger = logging.getLogger(__name__)

ONBOARDING_BASE = "http://engine-onboarding.threat-engine-engines.svc.cluster.local/api/v1"


def _resolve_session(request):
    """Return (user, error_response) from access_token cookie."""
    token = request.COOKIES.get("access_token")
    if not token:
        return None, JsonResponse({"message": "Not authenticated"}, status=401)
    for session in UserSessions.objects.filter(revoked=False).select_related("user"):
        if session.expires_at < timezone.now():
            continue
        if verify_token(token, session.token):
            return session.user, None
    return None, JsonResponse({"message": "Invalid or expired session"}, status=401)


def _require_admin(caller, tenant_id: str):
    """Return None if caller is tenant_admin+ for tenant, else JsonResponse 403."""
    from tenant_management.models import TenantUsers
    try:
        m = TenantUsers.objects.select_related("role").get(
            user=caller, tenant__id=tenant_id, is_active=True,
        )
    except TenantUsers.DoesNotExist:
        return JsonResponse({"error": "Forbidden"}, status=403)
    if not m.role or m.role.name not in ("platform_admin", "org_admin", "tenant_admin"):
        return JsonResponse({"error": "Forbidden"}, status=403)
    return None


def _fetch_tenant_accounts(tenant_id: str) -> list[dict[str, Any]]:
    """Fetch cloud accounts from onboarding engine for a tenant."""
    try:
        resp = httpx.get(
            f"{ONBOARDING_BASE}/cloud-accounts",
            params={"tenant_id": tenant_id, "limit": 500},
            timeout=5.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            return data.get("accounts", data) if isinstance(data, dict) else data
    except Exception as exc:
        logger.warning("Failed to fetch cloud accounts from onboarding: %s", exc)
    return []


class UserAccountAccessView(APIView):
    """
    GET  ?tenant_id=X  → list all tenant cloud accounts with granted:bool per user
    PUT  body={account_ids:[...], tenant_id:X}  → replace user's grant set
    """

    def get(self, request, user_id: str):
        caller, err = _resolve_session(request)
        if err:
            return err

        tenant_id = request.GET.get("tenant_id")
        if not tenant_id:
            return JsonResponse({"error": "tenant_id is required"}, status=400)

        err = _require_admin(caller, tenant_id)
        if err:
            return err

        try:
            target_user = Users.objects.get(id=user_id)
        except Users.DoesNotExist:
            return JsonResponse({"error": "User not found"}, status=404)

        # Existing grants for this user+tenant
        from tenant_management.models import UserAccountAccess, Tenants
        try:
            tenant = Tenants.objects.get(id=tenant_id)
        except Tenants.DoesNotExist:
            return JsonResponse({"error": "Tenant not found"}, status=404)

        granted_ids = set(
            UserAccountAccess.objects.filter(user=target_user, tenant=tenant)
            .values_list("account_id", flat=True)
        )

        # All accounts for this tenant from onboarding engine
        all_accounts = _fetch_tenant_accounts(tenant_id)

        # If no accounts from engine, show at least the granted ones
        if not all_accounts:
            all_accounts = [{"account_id": aid} for aid in granted_ids]

        result = []
        for acct in all_accounts:
            aid = acct.get("account_id", "")
            result.append({
                "account_id":   aid,
                "account_name": acct.get("account_name") or acct.get("display_name") or aid,
                "provider":     acct.get("provider", ""),
                "status":       acct.get("status", "active"),
                "granted":      aid in granted_ids,
            })

        return JsonResponse({
            "user_id":   user_id,
            "user_email": target_user.email,
            "tenant_id": tenant_id,
            "accounts":  result,
        })

    def put(self, request, user_id: str):
        caller, err = _resolve_session(request)
        if err:
            return err

        import json as _json
        try:
            body = _json.loads(request.body)
        except Exception:
            return JsonResponse({"error": "Invalid JSON"}, status=400)

        tenant_id = body.get("tenant_id")
        account_ids = body.get("account_ids", [])
        if not tenant_id:
            return JsonResponse({"error": "tenant_id is required"}, status=400)
        if not isinstance(account_ids, list):
            return JsonResponse({"error": "account_ids must be an array"}, status=400)

        err = _require_admin(caller, tenant_id)
        if err:
            return err

        try:
            target_user = Users.objects.get(id=user_id)
        except Users.DoesNotExist:
            return JsonResponse({"error": "User not found"}, status=404)

        from tenant_management.models import UserAccountAccess, Tenants
        try:
            tenant = Tenants.objects.get(id=tenant_id)
        except Tenants.DoesNotExist:
            return JsonResponse({"error": "Tenant not found"}, status=404)

        # Replace entire grant set atomically
        from django.db import transaction
        with transaction.atomic():
            UserAccountAccess.objects.filter(user=target_user, tenant=tenant).delete()
            for aid in account_ids:
                aid = str(aid).strip()
                if aid:
                    UserAccountAccess.objects.create(
                        user=target_user,
                        tenant=tenant,
                        account_id=aid,
                        granted_by=caller,
                    )

        logger.info(
            "UserAccountAccess updated user=%s tenant=%s grants=%d by=%s",
            user_id, tenant_id, len(account_ids), caller.email,
        )
        return JsonResponse({"granted": len(account_ids), "tenant_id": tenant_id})
