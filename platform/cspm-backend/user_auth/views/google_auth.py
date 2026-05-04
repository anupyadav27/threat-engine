"""
Google OAuth 2.0 login — no heavy dependency, pure requests-based code exchange.

Flow:
  1. GET /api/auth/google/login/  → redirect to Google consent screen
  2. GET /api/auth/google/callback/?code=... → exchange code, upsert user, set cookies, redirect
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
from user_auth.utils.auth_utils import compute_auth_caches, generate_token, hash_token
from user_auth.utils.audit_utils import log_auth_event
from user_auth.utils.cookie_utils import set_auth_cookies
from user_auth.utils.tenant_utils import accept_invite_membership, provision_first_tenant

logger = logging.getLogger(__name__)

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URI = os.getenv(
    "GOOGLE_REDIRECT_URI",
    "http://localhost:8000/api/auth/google/callback/",
)
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"


class GoogleLoginView(APIView):
    """Redirect browser to Google OAuth consent screen."""

    def get(self, request):
        if not GOOGLE_CLIENT_ID:
            return JsonResponse({"message": "Google OAuth not configured"}, status=501)

        state = secrets.token_urlsafe(32)
        request.session['google_oauth_state'] = state
        hd = request.GET.get("hd", "").strip()
        if hd:
            # Store requested domain in session so callback can validate it
            request.session['google_oauth_hd'] = hd

        params = {
            "client_id": GOOGLE_CLIENT_ID,
            "redirect_uri": GOOGLE_REDIRECT_URI,
            "response_type": "code",
            "scope": "openid email profile",
            "access_type": "offline",
            "prompt": "select_account",
            "state": state,
        }
        if hd:
            params["hd"] = hd

        return HttpResponseRedirect(f"{GOOGLE_AUTH_URL}?{urlencode(params)}")


class GoogleCallbackView(APIView):
    """Handle Google OAuth code, upsert user, issue session cookies, redirect."""

    def get(self, request):
        frontend_url = getattr(settings, "FRONTEND_URL", "http://localhost:3000")

        expected_state = request.session.pop('google_oauth_state', None)
        requested_hd = request.session.pop('google_oauth_hd', None)
        if not expected_state or request.GET.get('state') != expected_state:
            logger.warning("Google OAuth state mismatch — possible CSRF attempt")
            return HttpResponseRedirect(f"{frontend_url}/auth/login?error=csrf_detected")

        error = request.GET.get("error")
        code = request.GET.get("code")

        if error or not code:
            return HttpResponseRedirect(f"{frontend_url}/auth/login?error=google_cancelled")

        # Exchange code for tokens
        try:
            token_resp = http_requests.post(GOOGLE_TOKEN_URL, data={
                "code": code,
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "redirect_uri": GOOGLE_REDIRECT_URI,
                "grant_type": "authorization_code",
            }, timeout=10)
            token_resp.raise_for_status()
            token_data = token_resp.json()
        except Exception as e:
            logger.error(f"Google token exchange failed: {e}")
            return HttpResponseRedirect(f"{frontend_url}/auth/login?error=google_failed")

        # Fetch user profile
        try:
            userinfo_resp = http_requests.get(
                GOOGLE_USERINFO_URL,
                headers={"Authorization": f"Bearer {token_data['access_token']}"},
                timeout=10,
            )
            userinfo_resp.raise_for_status()
            profile = userinfo_resp.json()
        except Exception as e:
            logger.error(f"Google userinfo fetch failed: {e}")
            return HttpResponseRedirect(f"{frontend_url}/auth/login?error=google_failed")

        email = (profile.get("email") or "").lower()
        google_id = profile.get("sub", "")
        first_name = profile.get("given_name", "")
        last_name = profile.get("family_name", "")

        if not email:
            return HttpResponseRedirect(f"{frontend_url}/auth/login?error=google_no_email")

        # BLOCK-03: validate hosted domain from session (not from profile — profile.hd can be spoofed)
        if requested_hd:
            email_domain = email.split("@")[-1]
            if email_domain != requested_hd:
                logger.warning("Google OAuth hd mismatch: expected=%s got=%s", requested_hd, email_domain)
                return HttpResponseRedirect(f"{frontend_url}/auth/login?error=domain_mismatch")

        # Upsert user
        is_new_user = False
        try:
            user = Users.objects.get(email=email)
            updated = False
            if not user.sso_provider:
                user.sso_provider = "google"
                updated = True
            if not user.sso_id:
                user.sso_id = google_id
                updated = True
            if updated:
                user.save(update_fields=["sso_provider", "sso_id"])
        except Users.DoesNotExist:
            is_new_user = True
            user = Users.objects.create_user(
                email=email,
                first_name=first_name,
                last_name=last_name,
                status="active",
                sso_provider="google",
                sso_id=google_id,
            )
            provision_first_tenant(user)

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
                                   extra={"method": "google", "email": email})
            except Exception as exc:
                logger.warning("Invite consumption failed (google): %s", exc)

        # Issue session
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
            login_method="google",
            expires_at=expires_at,
            ip_address=request.META.get("REMOTE_ADDR", ""),
            user_agent=request.META.get("HTTP_USER_AGENT", ""),
            token_hint=access_token[:8],
            permissions_cache=permissions_cache,
            scope_cache=scope_cache,
        )

        log_auth_event("login.google", request=request, user=user,
                       extra={"email": email, "new_user": is_new_user})

        response = HttpResponseRedirect(f"{frontend_url}/dashboard")
        set_auth_cookies(response, access_token, refresh_token)

        if is_new_user:
            response.set_cookie(
                "onboarding_pending", "1",
                max_age=3600, httponly=True, samesite="Lax",  # WARN-04: httponly
            )

        return response
