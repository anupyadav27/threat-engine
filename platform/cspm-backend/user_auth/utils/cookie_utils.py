import os
from datetime import timedelta
from django.conf import settings
from django.utils import timezone

ACCESS_TOKEN_LIFETIME = timedelta(
    minutes=int(getattr(settings, "ACCESS_TOKEN_LIFETIME_MINUTES", 60))
)
REFRESH_TOKEN_LIFETIME = timedelta(
    days=int(getattr(settings, "REFRESH_TOKEN_LIFETIME_DAYS", 1))
)


def set_auth_cookies(response, access_token=None, refresh_token=None):
    """
    Set HTTP-only cookies for tokens.
    COOKIE_SECURE env var overrides the default (True in prod, False in dev).
    """
    now = timezone.now()
    _env = os.environ.get("COOKIE_SECURE", "").strip().lower()
    if _env in ("true", "1"):
        secure = True
    elif _env in ("false", "0"):
        secure = False
    else:
        secure = not settings.DEBUG

    if access_token:
        response.set_cookie(
            key="access_token",
            value=access_token,
            expires=now + ACCESS_TOKEN_LIFETIME,
            httponly=True,
            secure=secure,
            samesite="Lax",
            path="/",
        )

    if refresh_token:
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            expires=now + REFRESH_TOKEN_LIFETIME,
            httponly=True,
            secure=secure,
            samesite="Lax",
            path="/",
        )


def clear_auth_cookies(response):
    """
    Clear authentication cookies.
    """
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/")