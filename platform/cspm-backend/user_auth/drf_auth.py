"""DRF authentication backend — cookie-based session token."""
from django.utils import timezone
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed


class CookieTokenAuthentication(BaseAuthentication):
    """Authenticate via the httpOnly access_token cookie.

    Returns (user, session) on success.  Returns None when no cookie is present
    (so other authenticators can run).  Raises AuthenticationFailed when a cookie
    is present but invalid/expired — this terminates the auth chain.
    """

    def authenticate(self, request):
        access_token = request.COOKIES.get("access_token")
        if not access_token:
            return None

        from user_auth.models import UserSessions
        from user_auth.utils.auth_utils import verify_token

        sessions = UserSessions.objects.filter(
            revoked=False, token_hint=access_token[:8]
        ).select_related("user")

        for session in sessions:
            if session.expires_at < timezone.now():
                continue
            if verify_token(access_token, session.token):
                return (session.user, session)

        raise AuthenticationFailed("Invalid or expired session")

    def authenticate_header(self, request):
        return "Cookie"
