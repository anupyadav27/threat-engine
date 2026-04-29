"""
Google OAuth 2.0 login — no heavy dependency, pure requests-based code exchange.

Flow:
  1. GET /api/auth/google/login/  → redirect to Google consent screen
  2. GET /api/auth/google/callback/?code=... → exchange code, upsert user, set cookies, redirect
"""
import json
import os
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
from user_auth.utils.auth_utils import generate_token, hash_token
from user_auth.utils.cookie_utils import set_auth_cookies
from user_auth.utils.tenant_utils import provision_first_tenant

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

        params = {
            "client_id": GOOGLE_CLIENT_ID,
            "redirect_uri": GOOGLE_REDIRECT_URI,
            "response_type": "code",
            "scope": "openid email profile",
            "access_type": "offline",
            "prompt": "select_account",
        }
        return HttpResponseRedirect(f"{GOOGLE_AUTH_URL}?{urlencode(params)}")


class GoogleCallbackView(APIView):
    """Handle Google OAuth code, upsert user, issue session cookies, redirect."""

    def get(self, request):
        frontend_url = getattr(settings, "FRONTEND_URL", "http://localhost:3000")
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

        # Upsert user
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
            login_method="google",
            expires_at=expires_at,
            ip_address=request.META.get("REMOTE_ADDR", ""),
            user_agent=request.META.get("HTTP_USER_AGENT", ""),
        )

        response = HttpResponseRedirect(f"{frontend_url}/dashboard")
        set_auth_cookies(response, access_token, refresh_token)
        return response
