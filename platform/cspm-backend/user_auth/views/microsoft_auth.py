"""
Microsoft OIDC (Azure AD) multi-tenant login.

One app registration covers every Azure AD org + on-prem AD synced via Azure AD Connect.

Flow:
  1. GET /api/auth/microsoft/login/           → redirect to Microsoft consent screen
  2. GET /api/auth/microsoft/callback/?code=  → exchange code, upsert user, set cookies, redirect

Register at portal.azure.com:
  - Supported account types: "Accounts in any organizational directory (Multi-tenant)"
  - Redirect URI: https://<your-domain>/api/auth/microsoft/callback/
"""
import os
import secrets
import uuid
import logging
from datetime import timedelta
from urllib.parse import urlencode

import requests as http_requests
from django.conf import settings
from django.http import HttpResponseRedirect, JsonResponse
from django.utils import timezone
from rest_framework.views import APIView

from user_auth.models import Users, UserSessions
from user_auth.throttles import IDPCallbackRateThrottle
from user_auth.utils.auth_utils import compute_auth_caches, generate_token, hash_token
from user_auth.utils.audit_utils import log_auth_event
from user_auth.utils.cookie_utils import set_auth_cookies
from user_auth.utils.tenant_utils import accept_invite_membership, provision_tenant_for_new_user

logger = logging.getLogger(__name__)

MS_CLIENT_ID = os.getenv("MICROSOFT_CLIENT_ID", "")
MS_CLIENT_SECRET = os.getenv("MICROSOFT_CLIENT_SECRET", "")
MS_REDIRECT_URI = os.getenv(
    "MICROSOFT_REDIRECT_URI",
    "http://localhost:8000/api/auth/microsoft/callback/",
)

# /common/ = multi-tenant: accepts tokens from any Azure AD org
MS_AUTH_URL   = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
MS_TOKEN_URL  = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
MS_GRAPH_ME   = "https://graph.microsoft.com/v1.0/me"


class MicrosoftLoginView(APIView):
    """Redirect browser to Microsoft consent screen."""

    def get(self, request):
        if not MS_CLIENT_ID:
            return JsonResponse({"message": "Microsoft OAuth not configured"}, status=501)

        state = secrets.token_urlsafe(32)
        request.session["microsoft_oauth_state"] = state

        params = {
            "client_id": MS_CLIENT_ID,
            "redirect_uri": MS_REDIRECT_URI,
            "response_type": "code",
            "scope": "openid email profile User.Read",
            "response_mode": "query",
            "state": state,
        }

        # domain_hint speeds up routing for known work domains (SSO shortcut)
        domain_hint = request.GET.get("domain_hint", "").strip()
        if domain_hint:
            params["domain_hint"] = domain_hint

        return HttpResponseRedirect(f"{MS_AUTH_URL}?{urlencode(params)}")


class MicrosoftCallbackView(APIView):
    """Handle Microsoft OAuth code, upsert user, issue session cookies, redirect."""

    throttle_classes = [IDPCallbackRateThrottle]

    def get(self, request):
        frontend_url = getattr(settings, "FRONTEND_URL", "http://localhost:3000")

        # CSRF state check
        expected_state = request.session.pop("microsoft_oauth_state", None)
        if not expected_state or request.GET.get("state") != expected_state:
            logger.warning("Microsoft OAuth state mismatch — possible CSRF attempt")
            return HttpResponseRedirect(f"{frontend_url}/auth/login?error=csrf_detected")

        error = request.GET.get("error")
        code  = request.GET.get("code")
        if error or not code:
            logger.info("Microsoft OAuth cancelled: %s", error)
            return HttpResponseRedirect(f"{frontend_url}/auth/login?error=microsoft_cancelled")

        # Exchange authorization code for tokens
        try:
            token_resp = http_requests.post(MS_TOKEN_URL, data={
                "code": code,
                "client_id": MS_CLIENT_ID,
                "client_secret": MS_CLIENT_SECRET,
                "redirect_uri": MS_REDIRECT_URI,
                "grant_type": "authorization_code",
            }, timeout=15)
            token_resp.raise_for_status()
            token_data = token_resp.json()
        except Exception as exc:
            logger.error("Microsoft token exchange failed: %s", exc)
            return HttpResponseRedirect(f"{frontend_url}/auth/login?error=microsoft_failed")

        access_token_ms = token_data.get("access_token", "")

        # Fetch user profile from Microsoft Graph
        try:
            me_resp = http_requests.get(
                MS_GRAPH_ME,
                headers={"Authorization": f"Bearer {access_token_ms}"},
                params={"$select": "id,mail,userPrincipalName,givenName,surname,displayName"},
                timeout=10,
            )
            me_resp.raise_for_status()
            profile = me_resp.json()
        except Exception as exc:
            logger.error("Microsoft Graph /me failed: %s", exc)
            return HttpResponseRedirect(f"{frontend_url}/auth/login?error=microsoft_failed")

        # mail is the primary SMTP address; userPrincipalName is the UPN (fallback)
        email = (profile.get("mail") or profile.get("userPrincipalName") or "").lower().strip()
        ms_id = profile.get("id", "")
        first_name = profile.get("givenName") or profile.get("displayName", "").split()[0]
        last_name  = profile.get("surname", "")

        if not email:
            logger.warning("Microsoft profile returned no email: %s", profile)
            return HttpResponseRedirect(f"{frontend_url}/auth/login?error=microsoft_no_email")

        # Upsert user
        is_new_user = False
        try:
            user = Users.objects.get(email=email)
            changed = []
            if not user.sso_provider:
                user.sso_provider = "microsoft"
                changed.append("sso_provider")
            if not user.sso_id:
                user.sso_id = ms_id
                changed.append("sso_id")
            if changed:
                user.save(update_fields=changed)
        except Users.DoesNotExist:
            is_new_user = True
            user = Users.objects.create_user(
                email=email,
                first_name=first_name,
                last_name=last_name,
                status="active",
                sso_provider="microsoft",
                sso_id=ms_id,
            )
            provision_tenant_for_new_user(user)

        user.last_login = timezone.now()
        user.save(update_fields=["last_login"])

        # Consume pending invite (set by InviteSSORedirectView)
        pending_invite = request.session.pop("pending_invite_token", None)
        if pending_invite:
            try:
                from user_auth.models import InviteTokens
                invite = InviteTokens.objects.select_related("tenant", "role").get(
                    token=pending_invite, used=False
                )
                if invite.expires_at >= timezone.now() and invite.email == email:
                    accept_invite_membership(user, invite)
                    log_auth_event("invite.accept", request=request, user=user,
                                   tenant_id=str(invite.tenant_id),
                                   extra={"method": "microsoft", "email": email})
            except Exception as exc:
                logger.warning("Invite consumption failed (microsoft): %s", exc)

        # Issue session
        UserSessions.objects.filter(user=user).delete()
        raw_access  = generate_token()
        raw_refresh = generate_token()
        expires_at  = timezone.now() + timedelta(
            days=getattr(settings, "REFRESH_TOKEN_LIFETIME_DAYS", 7)
        )
        permissions_cache, scope_cache = compute_auth_caches(user)
        UserSessions.objects.create(
            id=uuid.uuid4(),
            user=user,
            token=hash_token(raw_access),
            refresh_token=hash_token(raw_refresh),
            login_method="microsoft",
            expires_at=expires_at,
            ip_address=request.META.get("REMOTE_ADDR", ""),
            user_agent=request.META.get("HTTP_USER_AGENT", ""),
            token_hint=raw_access[:8],
            permissions_cache=permissions_cache,
            scope_cache=scope_cache,
        )

        log_auth_event("login.microsoft", request=request, user=user,
                       extra={"email": email, "new_user": is_new_user})

        response = HttpResponseRedirect(f"{frontend_url}/dashboard")
        set_auth_cookies(response, raw_access, raw_refresh)

        if is_new_user:
            response.set_cookie(
                "onboarding_pending", "1",
                max_age=3600, httponly=True, samesite="Lax",  # WARN-04: httponly
            )

        return response
