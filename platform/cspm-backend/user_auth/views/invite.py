"""
Invite flow:
  POST /api/auth/invite/create/           — admin creates invite (requires access_token cookie)
  GET  /api/auth/invite/{token}/          — validate invite (public)
  POST /api/auth/invite/{token}/accept/   — accept invite, create account (public)
"""
import json
import uuid
import secrets
from datetime import timedelta

from django.conf import settings
from django.http import JsonResponse
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import ensure_csrf_cookie
from rest_framework.views import APIView

from user_auth.models import Users, UserSessions, InviteTokens
from user_auth.utils.auth_utils import generate_token, hash_token, verify_token
from user_auth.utils.cookie_utils import set_auth_cookies
from user_auth.utils.email_utils import send_invite_email


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

        # Validate tenant exists and user belongs to it
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

        return JsonResponse({
            "email": invite.email,
            "tenant_name": invite.tenant.name,
            "tenant_id": str(invite.tenant.id),
            "role": invite.role.name if invite.role else "Member",
            "expires_at": invite.expires_at.isoformat(),
        })


@method_decorator(ensure_csrf_cookie, name='dispatch')
class AcceptInviteView(APIView):
    """Accept invite: create account (or link existing) + join tenant."""

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

        # Check if account exists already
        try:
            user = Users.objects.get(email=invite.email)
        except Users.DoesNotExist:
            if len(password) < 8:
                return JsonResponse({"message": "Password must be at least 8 characters"}, status=400)
            user = Users.objects.create_user(
                email=invite.email,
                password=password,
                first_name=first_name,
                last_name=last_name,
                status="active",
            )

        # Add user to tenant (if not already)
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

        # Mark invite used
        invite.used = True
        invite.save(update_fields=["used"])

        # Issue session
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
