"""
Invite flow:
  POST /api/auth/invite/create/              — admin creates invite
  GET  /api/auth/invite/{token}/             — validate invite (public)
  GET  /api/auth/invite/{token}/sso/         — redirect to SSO for invite acceptance (AUTH-09)
  POST /api/auth/invite/{token}/accept/      — accept invite via password or SSO (public)
"""
import json
import uuid
import secrets
from datetime import timedelta

from django.conf import settings
from django.http import JsonResponse, HttpResponseRedirect
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import ensure_csrf_cookie
from rest_framework.views import APIView

from user_auth.models import Users, UserSessions, InviteTokens
from user_auth.utils.auth_utils import generate_token, hash_token, verify_token
from user_auth.utils.cookie_utils import set_auth_cookies
from user_auth.utils.email_utils import send_invite_email
from user_auth.utils.audit_utils import log_auth_event


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


class CreateInviteView(APIView):
    """Admin creates an invite link for a given email."""

    def post(self, request):
        user = _current_user(request)
        if not user:
            return JsonResponse({"message": "Authentication required"}, status=401)

        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"message": "Invalid JSON"}, status=400)

        email = (data.get("email") or "").strip().lower()
        tenant_id = data.get("tenant_id") or ""
        role_id = data.get("role_id") or None

        if not email or not tenant_id:
            return JsonResponse({"message": "email and tenant_id are required"}, status=400)

        from tenant_management.models import Tenants, TenantUsers
        try:
            tenant = Tenants.objects.get(id=tenant_id)
        except Tenants.DoesNotExist:
            return JsonResponse({"message": "Tenant not found"}, status=404)

        if not TenantUsers.objects.filter(user=user, tenant=tenant, is_active=True).exists():
            return JsonResponse({"message": "Not authorized for this tenant"}, status=403)

        role = None
        if role_id:
            from user_auth.models import Roles
            try:
                role = Roles.objects.get(id=role_id)
            except Roles.DoesNotExist:
                pass

        token = secrets.token_urlsafe(32)
        expires_at = timezone.now() + timedelta(hours=48)

        InviteTokens.objects.create(
            id=str(uuid.uuid4()),
            token=token,
            email=email,
            tenant=tenant,
            role=role,
            invited_by=user,
            expires_at=expires_at,
        )

        invited_by_name = f"{user.first_name or ''} {user.last_name or ''}".strip() or user.email
        send_invite_email(email, token, tenant.name, invited_by_name)

        log_auth_event(
            "invite.create",
            request=request,
            user=user,
            tenant_id=tenant_id,
            extra={"invited_email": email},
        )

        return JsonResponse({
            "message": "Invite sent",
            "email": email,
            "expires_at": expires_at.isoformat(),
        }, status=201)


class ValidateInviteView(APIView):
    """Check if an invite token is valid (not used/expired). Public."""

    def get(self, request, token):
        try:
            invite = InviteTokens.objects.select_related('tenant', 'role').get(token=token)
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

        from tenant_management.models import TenantUsers
        if not TenantUsers.objects.filter(user=user, tenant=invite.tenant).exists():
            from user_auth.utils.tenant_utils import get_or_create_admin_role
            role = invite.role or get_or_create_admin_role()
            TenantUsers.objects.create(
                id=str(uuid.uuid4()),
                tenant=invite.tenant,
                user=user,
                role=role,
                is_active=True,
            )

        invite.used = True
        invite.save(update_fields=["used"])

        log_auth_event(
            "invite.accept",
            request=request,
            user=user,
            tenant_id=str(invite.tenant_id),
            extra={"method": "password"},
        )

        UserSessions.objects.filter(user=user).delete()
        access_token = generate_token()
        refresh_token = generate_token()
        expires_at = timezone.now() + timedelta(
            days=getattr(settings, "REFRESH_TOKEN_LIFETIME_DAYS", 7)
        )
        UserSessions.objects.create(
            id=uuid.uuid4(),
            user=user,
            token=hash_token(access_token),
            refresh_token=hash_token(refresh_token),
            login_method="invite",
            expires_at=expires_at,
            ip_address=request.META.get("REMOTE_ADDR", ""),
            user_agent=request.META.get("HTTP_USER_AGENT", ""),
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
