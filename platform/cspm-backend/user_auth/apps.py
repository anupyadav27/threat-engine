from django.apps import AppConfig


class UserAuthConfig(AppConfig):
    name = 'user_auth'

    def ready(self):
        from user_auth import signals  # noqa: F401
        signals._connect()
        self._validate_frontend_url()

    def _validate_frontend_url(self):
        from urllib.parse import urlparse
        from django.conf import settings
        from django.core.exceptions import ImproperlyConfigured

        frontend_url = getattr(settings, "FRONTEND_URL", None)
        if not frontend_url:
            return  # not set in test/migrate contexts — skip

        allowed = getattr(settings, "ALLOWED_REDIRECT_HOSTS", ["localhost"])
        try:
            host = urlparse(frontend_url).hostname or ""
        except Exception:
            host = ""

        if host not in allowed:
            raise ImproperlyConfigured(
                f"FRONTEND_URL host '{host}' is not in ALLOWED_REDIRECT_HOSTS={allowed}. "
                "Set ALLOWED_REDIRECT_HOSTS env var to include this host."
            )
