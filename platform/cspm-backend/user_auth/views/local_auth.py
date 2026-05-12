import json
import logging
import os
import re
import uuid
from datetime import timedelta

import requests as http_requests
from django.conf import settings
from django.contrib.auth.hashers import check_password
from django.http import JsonResponse
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_GET
from rest_framework.views import APIView

from user_auth.models import Users, UserRoles, UserSessions
from user_auth.throttles import (
    LoginRateThrottle,
    PasswordResetRateThrottle,
    RefreshRateThrottle,
    RegisterRateThrottle,
    SignupRateThrottle,
)
from user_auth.utils.audit_utils import log_auth_event
from user_auth.utils.auth_utils import compute_auth_caches, generate_token, hash_token, verify_token
from user_auth.utils.captcha import validate_captcha
from user_auth.utils.cookie_utils import set_auth_cookies, clear_auth_cookies
from user_auth.utils.tenant_utils import provision_tenant_for_new_user

logger = logging.getLogger(__name__)

_HCAPTCHA_VERIFY_URL = "https://hcaptcha.com/siteverify"


def _verify_hcaptcha(token: str) -> bool:
    secret = getattr(settings, "HCAPTCHA_SECRET_KEY", None)
    if not secret:
        logger.warning("CAPTCHA disabled — set HCAPTCHA_SECRET_KEY in production")
        return True
    try:
        resp = http_requests.post(
            _HCAPTCHA_VERIFY_URL,
            data={"secret": secret, "response": token},
            timeout=5.0,
        )
        return bool(resp.json().get("success", False))
    except Exception:
        return False  # fail closed


BILLING_ENGINE_URL = os.environ.get(
    "BILLING_ENGINE_URL", "http://engine-billing:8040"
)


def _get_subscription_for_org(org_id: str, user_permissions: list) -> dict | None:
    """Fetch subscription context for the org from engine-billing.

    Args:
        org_id: The organization/tenant ID to look up.
        user_permissions: The user's permission key list from the session cache.

    Returns:
        Subscription dict if the user has ``billing:read``, otherwise ``None``.
        Returns ``None`` (not an error) when engine-billing is unreachable so
        that the ``/api/auth/me`` endpoint is never blocked by billing downtime.
    """
    if "billing:read" not in user_permissions:
        return None

    from django.core.cache import cache

    cache_key = f"billing_sub_{org_id}"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    try:
        import httpx

        with httpx.Client(timeout=3.0) as client:
            resp = client.get(
                f"{BILLING_ENGINE_URL}/api/v1/billing/subscription",
                params={"org_id": org_id},
                headers={"X-Internal-Call": "django-backend"},
            )
            if resp.status_code == 200:
                data = resp.json()
                plan = data.get("plan", {})
                sub = {
                    "tier": plan.get("plan_name", "unknown"),
                    "status": data.get("status", "unknown"),
                    "trial_days_remaining": data.get("trial_days_remaining", 0),
                    "accounts_connected": data.get("accounts_connected", 0),
                    "max_accounts": plan.get("max_accounts", -1),
                    "current_period_end": data.get("current_period_end"),
                    "is_overridden": data.get("is_overridden", False),
                }
                cache.set(cache_key, sub, timeout=60)
                return sub
            else:
                logger.warning(
                    "engine-billing returned %s for org %s — subscription omitted",
                    resp.status_code,
                    org_id,
                )
    except Exception as exc:
        logger.warning(
            "engine-billing unreachable for org %s (%s) — subscription field omitted",
            org_id,
            exc,
        )
    return None

@require_GET
@ensure_csrf_cookie
def csrf(request):
    return JsonResponse({"detail": "CSRF cookie set"})


@method_decorator(ensure_csrf_cookie, name='dispatch')
class LoginView(APIView):
    throttle_classes = [LoginRateThrottle]

    def post(self, request):
        # Parse JSON body
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"message": "Invalid JSON"}, status=400)

        email = data.get("email")
        password = data.get("password")
        remember_me = data.get("rememberMe", False)

        if not email or not password:
            return JsonResponse({"message": "Email and password are required."}, status=400)

        # BLOCK-01: fetch user without leaking whether the email exists.
        # Both "email not found" and "wrong password" return 401 with the same
        # body so an attacker cannot enumerate valid addresses by comparing
        # response status codes or messages.
        _invalid_credentials = JsonResponse(
            {"detail": "Invalid credentials"}, status=401
        )
        try:
            user = Users.objects.get(email=email)
        except Users.DoesNotExist:
            return _invalid_credentials

        # Use Django's constant-time check_password (AC8) to avoid timing oracle.
        if not user.password or not check_password(password, user.password):
            return _invalid_credentials

        # Revoke all existing sessions for this user
        UserSessions.objects.filter(user=user).delete()

        # Generate raw tokens
        access_token = generate_token()
        refresh_token = generate_token() if remember_me else None

        # Hash tokens for secure storage
        hashed_access = hash_token(access_token)
        hashed_refresh = hash_token(refresh_token) if refresh_token else None

        # Calculate expiry
        expires_at = timezone.now() + (
            timedelta(days=getattr(settings, 'REFRESH_TOKEN_LIFETIME_DAYS', 1))
            if remember_me
            else timedelta(minutes=getattr(settings, 'ACCESS_TOKEN_LIFETIME_MINUTES', 60))
        )

        # Compute permission/scope caches from server-side DB joins only.
        # SECURITY: no client-supplied data is used here.
        permissions_cache, scope_cache = compute_auth_caches(user)

        # Save session with hashed tokens and auth caches.
        # token_hint is the first 8 chars of the RAW (pre-hash) access token.
        UserSessions.objects.create(
            id=uuid.uuid4(),
            user=user,
            token=hashed_access,
            refresh_token=hashed_refresh,
            login_method="local",
            expires_at=expires_at,
            ip_address=request.META.get('REMOTE_ADDR', ''),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            token_hint=access_token[:8],
            permissions_cache=permissions_cache,
            scope_cache=scope_cache,
        )

        # Update last login
        user.last_login = timezone.now()
        user.save(update_fields=['last_login'])

        log_auth_event("login.local", request=request, user=user)

        # Resolve primary role name for response (lowest level number = highest privilege)
        user_role_qs = (
            UserRoles.objects.filter(user=user)
            .select_related('role')
            .order_by('role__level')
        )
        role_names = [ur.role.name for ur in user_role_qs]
        primary_role = role_names[0] if role_names else None

        # Build tenant list (same as MeView) so frontend has engine_tenant_id immediately
        from tenant_management.models import TenantUsers as TUModel
        tenant_memberships = TUModel.objects.filter(
            user=user, is_active=True
        ).select_related('tenant', 'role')
        tenants_list = []
        for tm in tenant_memberships:
            tenants_list.append({
                "tenant_id": str(tm.tenant.id),
                "engine_tenant_id": tm.tenant.engine_tenant_id or str(tm.tenant.id),
                "tenant_name": tm.tenant.name,
                "role": tm.role.name if tm.role else "member",
                "status": tm.tenant.status,
            })

        # Prepare response
        full_name = f"{user.first_name or ''} {user.last_name or ''}".strip()
        response_data = {
            "message": "Login successful",
            "expiresIn": f"{getattr(settings, 'ACCESS_TOKEN_LIFETIME_MINUTES', 60)}m",
            "user": {
                "id": str(user.id),
                "email": user.email,
                "name": full_name,
                "role": primary_role,
                "roles": role_names,
                "permissions": permissions_cache,
                "tenants": tenants_list,
            },
        }

        response = JsonResponse(response_data)
        set_auth_cookies(response, access_token, refresh_token)
        response["Cache-Control"] = "no-store"
        return response


_ALLOW_LOCAL_SIGNUP = os.getenv("ALLOW_LOCAL_SIGNUP", "false").lower() in ("true", "1", "yes")


@method_decorator(ensure_csrf_cookie, name='dispatch')
class SignupView(APIView):
    throttle_classes = [RegisterRateThrottle]

    def post(self, request):
        if not _ALLOW_LOCAL_SIGNUP:
            return JsonResponse(
                {"message": "Local account creation is disabled. Use SSO to sign in."},
                status=403,
            )

        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"message": "Invalid JSON"}, status=400)

        email = (data.get("email") or "").strip().lower()
        password = data.get("password") or ""
        first_name = (data.get("first_name") or data.get("firstName") or "").strip()
        last_name = (data.get("last_name") or data.get("lastName") or "").strip()
        company_name = (data.get("company_name") or data.get("companyName") or "").strip()

        if not email or not password:
            return JsonResponse({"message": "Email and password are required."}, status=400)

        if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            return JsonResponse({"message": "Invalid email address."}, status=400)

        if len(password) < 8:
            return JsonResponse({"message": "Password must be at least 8 characters."}, status=400)

        # AC7: call the centralised CAPTCHA hook from utils/captcha.py.
        # Returns True immediately when CAPTCHA_SECRET_KEY is not configured.
        if not validate_captcha(data.get("hcaptcha_token", "")):
            return JsonResponse({"message": "CAPTCHA verification failed."}, status=400)

        if Users.objects.filter(email=email).exists():
            return JsonResponse(
                {"message": "If an account exists with this email, a verification email will be sent."},
                status=200,
            )

        user = Users.objects.create_user(
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name,
            status="active",
        )

        # Auto-provision first tenant
        provision_tenant_for_new_user(user)

        # Create session
        access_token = generate_token()
        refresh_token = generate_token()
        expires_at = timezone.now() + timedelta(
            days=getattr(settings, 'REFRESH_TOKEN_LIFETIME_DAYS', 7)
        )
        signup_permissions, signup_scope = compute_auth_caches(user)
        UserSessions.objects.create(
            id=uuid.uuid4(),
            user=user,
            token=hash_token(access_token),
            refresh_token=hash_token(refresh_token),
            login_method="local",
            expires_at=expires_at,
            ip_address=request.META.get('REMOTE_ADDR', ''),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            token_hint=access_token[:8],
            permissions_cache=signup_permissions,
            scope_cache=signup_scope,
        )

        full_name = f"{first_name} {last_name}".strip()
        response = JsonResponse({
            "message": "Account created successfully",
            "user": {
                "id": str(user.id),
                "email": user.email,
                "name": full_name,
            },
        }, status=201)
        set_auth_cookies(response, access_token, refresh_token)
        response["Cache-Control"] = "no-store"
        return response


class MeView(APIView):
    """Return current authenticated user info from cookie session."""

    def _get_user_response(self, user, session: UserSessions | None = None):
        from tenant_management.models import TenantUsers

        # Resolve permissions from the active session cache, or fall back to
        # recomputing from the DB if the session has no cache (old sessions).
        if session is not None and session.permissions_cache:
            permissions = session.permissions_cache
        else:
            permissions, _ = compute_auth_caches(user)

        # Resolve primary role name (lowest level = highest privilege)
        user_role_qs = (
            UserRoles.objects.filter(user=user)
            .select_related('role')
            .order_by('role__level')
        )
        role_names = [ur.role.name for ur in user_role_qs]

        # Build per-tenant permissions list from the TenantUsers role assignment
        tenant_memberships = TenantUsers.objects.filter(
            user=user, is_active=True
        ).select_related('tenant', 'role').prefetch_related('role__permissions')
        tenants = []
        # Use the first tenant's ID as the org_id for subscription lookup.
        # All tenants for a user belong to the same org in the current model.
        first_tenant_id = None
        for tm in tenant_memberships:
            if first_tenant_id is None:
                first_tenant_id = str(tm.tenant.id)
            tenant_perm_keys: list = []
            if tm.role:
                tenant_perm_keys = sorted(
                    tm.role.permissions.values_list('key', flat=True)
                )
            tenants.append({
                "tenant_id": str(tm.tenant.id),
                "engine_tenant_id": tm.tenant.engine_tenant_id or str(tm.tenant.id),
                "tenant_name": tm.tenant.name,
                "role": tm.role.name if tm.role else "member",
                "permissions": list(tenant_perm_keys),
                "status": tm.tenant.status,
            })

        # Fetch subscription tier from engine-billing (cached per org, 60 s TTL).
        # Returns None for users without billing:read (e.g. viewer).
        subscription = _get_subscription_for_org(
            org_id=first_tenant_id or str(user.id),
            user_permissions=permissions,
        )

        return JsonResponse({
            "id": str(user.id),
            "customer_id": str(user.id),
            "email": user.email,
            "name": f"{user.first_name or ''} {user.last_name or ''}".strip(),
            "sso_provider": user.sso_provider,
            "role": role_names[0] if role_names else None,
            "roles": role_names,
            "permissions": permissions,
            "tenants": tenants,
            "subscription": subscription,
        })

    def _resolve_user_and_session(self, request):
        """Return (user, session) tuple or (None, None) if not authenticated."""
        access_token = request.COOKIES.get("access_token")
        if not access_token:
            return None, None
        sessions = UserSessions.objects.filter(
            revoked=False, token_hint=access_token[:8]
        ).select_related('user')
        for session in sessions:
            if session.expires_at < timezone.now():
                continue
            if verify_token(access_token, session.token):
                return session.user, session
        return None, None

    def get(self, request):
        user, session = self._resolve_user_and_session(request)
        if not user:
            return JsonResponse({"message": "Not authenticated"}, status=401)
        return self._get_user_response(user, session)

    def patch(self, request):
        user, session = self._resolve_user_and_session(request)
        if not user:
            return JsonResponse({"message": "Not authenticated"}, status=401)

        try:
            data = json.loads(request.body)
        except (json.JSONDecodeError, AttributeError):
            data = request.data if hasattr(request, 'data') else {}

        allowed_fields = {'first_name', 'last_name'}
        update_data = {k: v for k, v in data.items() if k in allowed_fields}

        if not update_data:
            return JsonResponse(
                {"error": "No valid fields provided. Accepted: first_name, last_name"},
                status=400,
            )

        for field, value in update_data.items():
            if not isinstance(value, str) or not value.strip():
                return JsonResponse(
                    {"error": f"{field} must be a non-empty string"},
                    status=400,
                )

        for field, value in update_data.items():
            setattr(user, field, value.strip())
        user.save(update_fields=list(update_data.keys()))

        return self._get_user_response(user, session)


@method_decorator(ensure_csrf_cookie, name='dispatch')
class RefreshTokenView(APIView):
    throttle_classes = [RefreshRateThrottle]

    def post(self, request):
        refresh_token = request.COOKIES.get("refresh_token")
        if not refresh_token:
            response = JsonResponse({"message": "No refresh token found"}, status=401)
            clear_auth_cookies(response)
            return response

        # Find session by hashed refresh token
        sessions = UserSessions.objects.filter(refresh_token__isnull=False)
        valid_session = None
        user = None

        for session in sessions:
            if verify_token(refresh_token, session.refresh_token):
                if session.expires_at < timezone.now():
                    session.delete()  # auto-cleanup expired
                    continue
                valid_session = session
                user = session.user
                break

        if not valid_session:
            response = JsonResponse({"message": "Invalid or expired refresh token"}, status=401)
            clear_auth_cookies(response)
            return response

        # Issue new access token
        new_access_token = generate_token()
        hashed_new_access = hash_token(new_access_token)

        # Update token and backfill token_hint on the refreshed session
        valid_session.token = hashed_new_access
        valid_session.token_hint = new_access_token[:8]
        valid_session.save(update_fields=["token", "token_hint"])

        # Resolve roles for the refreshed user
        user_role_qs = (
            UserRoles.objects.filter(user=user)
            .select_related('role')
            .order_by('role__level')
        )
        role_names = [ur.role.name for ur in user_role_qs]
        permissions = valid_session.permissions_cache or []

        response = JsonResponse({
            "message": "Access token refreshed successfully",
            "expiresIn": f"{getattr(settings, 'ACCESS_TOKEN_LIFETIME_MINUTES', 60)}m",
            "user": {
                "id": str(user.id),
                "email": user.email,
                "name": f"{user.first_name or ''} {user.last_name or ''}".strip(),
                "role": role_names[0] if role_names else None,
                "roles": role_names,
                "permissions": permissions,
            },
        })
        set_auth_cookies(response, new_access_token)  # do NOT reissue refresh token
        return response

@method_decorator(ensure_csrf_cookie, name='dispatch')
class LogoutView(APIView):
    def post(self, request):
        access_token = request.COOKIES.get("access_token")
        refresh_token = request.COOKIES.get("refresh_token")

        user = None
        login_method = "local"
        deleted = False

        # Try to find session by access token
        if access_token:
            sessions = UserSessions.objects.filter(
                token__isnull=False, token_hint=access_token[:8]
            )
            for session in sessions:
                if verify_token(access_token, session.token):
                    user = session.user
                    login_method = session.login_method
                    session.delete()
                    deleted = True
                    break

        # If not found, try refresh token
        if not deleted and refresh_token:
            sessions = UserSessions.objects.filter(refresh_token__isnull=False)
            for session in sessions:
                if verify_token(refresh_token, session.refresh_token):
                    user = session.user
                    login_method = session.login_method
                    session.delete()
                    deleted = True
                    break

        # TODO: Later, handle SAML SLO if login_method == "saml"

        log_auth_event("logout", request=request, user=user)

        response = JsonResponse({
            "message": "Logout successful",
            "sso": login_method == "saml"
        })
        clear_auth_cookies(response)
        return response


class ChangePasswordView(APIView):
    """POST /api/auth/change-password/ — authenticated password change."""

    def post(self, request):
        access_token = request.COOKIES.get("access_token")
        if not access_token:
            return JsonResponse({"message": "Not authenticated"}, status=401)

        user = None
        current_session = None
        sessions = UserSessions.objects.filter(
            revoked=False, token_hint=access_token[:8]
        ).select_related('user')
        for session in sessions:
            if session.expires_at < timezone.now():
                continue
            if verify_token(access_token, session.token):
                user = session.user
                current_session = session
                break

        if not user:
            return JsonResponse({"message": "Invalid or expired session"}, status=401)

        try:
            data = json.loads(request.body)
        except (json.JSONDecodeError, AttributeError):
            data = {}

        current_password = data.get('current_password', '')
        new_password = data.get('new_password', '')

        if not current_password or not new_password:
            return JsonResponse(
                {"error": "current_password and new_password are required"},
                status=400,
            )

        if len(new_password) < 8:
            return JsonResponse(
                {"error": "new_password must be at least 8 characters"},
                status=400,
            )

        if not user.check_password(current_password):
            return JsonResponse({"error": "Current password incorrect"}, status=400)

        user.set_password(new_password)
        user.save()

        # Invalidate all sessions so old tokens stop working
        UserSessions.objects.filter(user=user).delete()

        return JsonResponse(
            {"message": "Password changed successfully. Please log in again."},
            status=200,
        )


class UserListView(APIView):
    """GET /api/users/?tenant_id=X — list members of a tenant (admin only)."""

    def get(self, request):
        access_token = request.COOKIES.get("access_token")
        if not access_token:
            return JsonResponse({"message": "Not authenticated"}, status=401)

        user = None
        sessions = UserSessions.objects.filter(
            revoked=False, token_hint=access_token[:8]
        ).select_related('user')
        for session in sessions:
            if session.expires_at < timezone.now():
                continue
            if verify_token(access_token, session.token):
                user = session.user
                break

        if not user:
            return JsonResponse({"message": "Invalid or expired session"}, status=401)

        tenant_id = request.GET.get('tenant_id')
        if not tenant_id:
            return JsonResponse(
                {"error": "tenant_id query parameter is required"},
                status=400,
            )

        from tenant_management.models import TenantUsers
        try:
            requester_membership = TenantUsers.objects.select_related('role').get(
                user=user,
                tenant__id=tenant_id,
                is_active=True,
            )
        except TenantUsers.DoesNotExist:
            return JsonResponse({"error": "Forbidden"}, status=403)

        if not requester_membership.role or requester_membership.role.name not in ('platform_admin', 'org_admin', 'tenant_admin'):
            return JsonResponse({"error": "Forbidden"}, status=403)

        memberships = TenantUsers.objects.filter(
            tenant__id=tenant_id,
            is_active=True,
        ).select_related('user', 'role')

        users = []
        for m in memberships:
            u = m.user
            name = f"{u.first_name or ''} {u.last_name or ''}".strip() or u.email
            users.append({
                "id": str(u.id),
                "email": u.email,
                "name": name,
                "role": m.role.name if m.role else "member",
                "status": u.status or "active",
                "last_login": u.last_login.isoformat() if u.last_login else None,
            })

        return JsonResponse({"users": users}, status=200)