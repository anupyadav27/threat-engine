"""
DRF authentication: cookie-based access token.
Resolves access_token cookie -> User via UserSessions.
"""

from django.utils import timezone
from rest_framework import authentication
from rest_framework import exceptions

from user_auth.models import UserSessions
from user_auth.utils.auth_utils import verify_token


class CookieTokenAuthentication(authentication.BaseAuthentication):
    """
    Authenticate using access_token cookie.
    Sets request.user from UserSessions; 401 if missing/invalid/expired.
    """

    keyword = "Bearer"
    cookie_name = "access_token"

    def authenticate(self, request):
        raw = request.COOKIES.get(self.cookie_name)
        if not raw:
            return None

        sessions = UserSessions.objects.filter(token__isnull=False).select_related("user")
        for session in sessions:
            if not verify_token(raw, session.token):
                continue
            if session.expires_at and session.expires_at < timezone.now():
                raise exceptions.AuthenticationFailed("Token expired.")
            if session.revoked:
                raise exceptions.AuthenticationFailed("Token revoked.")
            return (session.user, None)
        raise exceptions.AuthenticationFailed("Invalid or expired token.")

    def authenticate_header(self, request):
        return self.keyword
