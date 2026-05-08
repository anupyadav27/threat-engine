"""
Invite flow (token-based accept — email link handlers):
  GET  /api/auth/invite/{token}/             — validate invite (public)
  GET  /api/auth/invite/{token}/sso/         — redirect to SSO for invite acceptance (AUTH-09)
  POST /api/auth/invite/{token}/accept/      — accept invite via password or SSO (public)

  Invite creation (POST) is handled by /gateway/api/v1/invites/
  (tenant_management.views.InviteCreateView).  The old /api/auth/invite/create/ endpoint
  was removed in BILL-S07 — it lacked customer_id scoping, DRF RBAC (HasPermission), and
  inviter-level role-cap enforcement.
"""
import json
import uuid
from datetime import timedelta

from django.conf import settings
from django.http import JsonResponse, HttpResponseRedirect
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import ensure_csrf_cookie
from rest_framework.views import APIView

from user_auth.models import Users, UserSessions, InviteTokens
from user_auth.utils.auth_utils import compute_auth_caches, generate_token, hash_token, verify_token
from user_auth.utils.cookie_utils import set_auth_cookies
from user_auth.utils.tenant_utils import accept_invite_membership


def _current_user(request):
    """Resolve Users from access_token cookie. Returns None if invalid."""
    access_token = request.COOKIES.get("access_token")
    if not access_token:
        return None
    for session in UserSessions.objects.filter(revoked=False).select_related('user'):
        if session.expires_at < timezone.now():
            continue
        if verify_token(access_token, session.token):
            return session.user
    return None


def _invite_idp(tenant_id: str):
    """Return the first active SSO IDP for a tenant, or None."""
    from tenant_management.models import TenantIDPConfig
    return (
        TenantIDPConfig.objects.filter(
            tenant_id=tenant_id,
            idp_type__in=("oidc", "google_oauth", "saml"),
            is_active=True,
        )
        .first()
    )


class ValidateInviteView(APIView):
    """Check if an invite token is valid (not used/expired). Public."""

    def get(self, request, token):
        try:
            invite = InviteTokens.objects.select_related('tenant', 'role', 'group').get(token=token)
        except InviteTokens.DoesNotExist:
            return JsonResponse({"message": "Invalid invite link"}, status=404)

        if invite.used:
            return JsonResponse({"message": "This invite has already been used"}, status=410)

        if invite.expires_at < timezone.now():
            return JsonResponse({"message": "This invite has expired"}, status=410)

        idp = _invite_idp(str(invite.tenant_id))

        return JsonResponse({
            "email": invite.email,
            "tenant_name": invite.tenant.name,
            "tenant_id": str(invite.tenant.id),
            "role": invite.role.name if invite.role else "Member",
            "expires_at": invite.expires_at.isoformat(),
            "idp_available": idp is not None,
            "idp_type": idp.idp_type if idp else None,
            # group_name only — group_id (internal PK) is never sent to this public endpoint
            "group_name": invite.group.name if invite.group_id else None,
        })


class InviteSSORedirectView(APIView):
    """Store invite token in session, then redirect to SSO login (AUTH-09).

    GET /api/auth/invite/{token}/sso/
    """

    def get(self, request, token):
        try:
            invite = InviteTokens.objects.select_related("tenant").get(token=token)
        except InviteTokens.DoesNotExist:
            return JsonResponse({"message": "Invalid invite link"}, status=404)

        if invite.used:
            return JsonResponse({"message": "This invite has already been used"}, status=410)

        if invite.expires_at < timezone.now():
            return JsonResponse({"message": "This invite has expired"}, status=410)

        idp = _invite_idp(str(invite.tenant_id))
        if not idp:
            return JsonResponse({"message": "No SSO configured for this tenant"}, status=404)

        # Stash invite token so OIDC/SAML callbacks can consume it
        request.session["pending_invite_token"] = token

        if idp.idp_type == "saml":
            return HttpResponseRedirect(f"/api/auth/saml/{invite.tenant_id}/login/")

        return HttpResponseRedirect(
            f"/api/auth/oidc/login/?tenant={invite.tenant_id}&redirect_after=/dashboard"
        )


@method_decorator(ensure_csrf_cookie, name='dispatch')
class AcceptInviteView(APIView):
    """Accept invite: create account (or link existing) + join tenant.

    Password is optional when the tenant has an active SSO IDP — in that case
    the invite can be accepted via the SSO redirect flow instead.
    """

    def post(self, request, token):
        try:
            invite = InviteTokens.objects.select_related('tenant', 'role').get(token=token)
        except InviteTokens.DoesNotExist:
            return JsonResponse({"message": "Invalid invite link"}, status=404)

        if invite.used:
            return JsonResponse({"message": "This invite has already been used"}, status=410)

        if invite.expires_at < timezone.now():
            return JsonResponse({"message": "This invite has expired"}, status=410)

        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"message": "Invalid JSON"}, status=400)

        password = data.get("password") or ""
        first_name = (data.get("first_name") or data.get("firstName") or "").strip()
        last_name = (data.get("last_name") or data.get("lastName") or "").strip()

        has_sso = _invite_idp(str(invite.tenant_id)) is not None

        try:
            user = Users.objects.get(email=invite.email)
        except Users.DoesNotExist:
            # New user — require password unless SSO is available
            if not has_sso and len(password) < 8:
                return JsonResponse({"message": "Password must be at least 8 characters"}, status=400)
            user = Users.objects.create_user(
                email=invite.email,
                password=password or None,
                first_name=first_name,
                last_name=last_name,
                status="active",
            )

        try:
            accept_invite_membership(user, invite)
        except InviteTokens.DoesNotExist:
            # A concurrent request already consumed this token inside the
            # atomic block — the SELECT FOR UPDATE / used=False filter raised
            # DoesNotExist after the other transaction committed.
            return JsonResponse(
                {"message": "This invite has already been used"},
                status=409,
            )

        UserSessions.objects.filter(user=user).delete()
        access_token = generate_token()
        refresh_token = generate_token()
        expires_at = timezone.now() + timedelta(
            days=getattr(settings, "REFRESH_TOKEN_LIFETIME_DAYS", 7)
        )
        permissions_cache, scope_cache = compute_auth_caches(user)
        UserSessions.objects.create(
            id=uuid.uuid4(),
            user=user,
            token=hash_token(access_token),
            refresh_token=hash_token(refresh_token),
            login_method="invite",
            expires_at=expires_at,
            ip_address=request.META.get("REMOTE_ADDR", ""),
            user_agent=request.META.get("HTTP_USER_AGENT", ""),
            token_hint=access_token[:8],
            permissions_cache=permissions_cache,
            scope_cache=scope_cache,
        )

        response = JsonResponse({
            "message": "Welcome! Your account is ready.",
            "user": {
                "id": str(user.id),
                "email": user.email,
                "name": f"{user.first_name or ''} {user.last_name or ''}".strip(),
            },
        }, status=201)
        set_auth_cookies(response, access_token, refresh_token)
        response["Cache-Control"] = "no-store"
        return response
