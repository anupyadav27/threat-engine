import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
CONF_DIR = BASE_DIR / ".config"

load_dotenv(CONF_DIR / ".env")

SECRET_KEY = os.getenv("SECRET_KEY")

ACCESS_TOKEN_LIFETIME_MINUTES = int(os.getenv("ACCESS_TOKEN_LIFETIME_MINUTES", "15"))  # Changed from 60 to 15 per WARN-06
REFRESH_TOKEN_LIFETIME_DAYS = int(os.getenv("REFRESH_TOKEN_LIFETIME_DAYS", 7))
FRONTEND_URL = os.getenv("FRONTEND_URL")

# ── Google OAuth ──────────────────────────────────────────────────────────────
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URI = os.getenv(
    "GOOGLE_REDIRECT_URI",
    "http://localhost:8000/api/auth/google/callback/",
)

# ── Generic OIDC ──────────────────────────────────────────────────────────────
OIDC_CALLBACK_URL = os.getenv("OIDC_CALLBACK_URL", "http://localhost:8000/api/auth/oidc/callback/")
OIDC_DISCOVERY_CACHE_TTL = int(os.getenv("OIDC_DISCOVERY_CACHE_TTL", 300))

# ── AWS ───────────────────────────────────────────────────────────────────────
SES_FROM_EMAIL = os.getenv("SES_FROM_EMAIL", "noreply@threatengine.io")
AWS_REGION = os.getenv("AWS_REGION", "ap-south-1")

# ── Local auth (break-glass only in prod) ─────────────────────────────────────
ALLOW_LOCAL_SIGNUP = os.getenv("ALLOW_LOCAL_SIGNUP", "false").lower() in ("true", "1", "yes")

# ── Onboarding engine (internal cluster URL) ──────────────────────────────────
ONBOARDING_ENGINE_URL = os.getenv(
    "ONBOARDING_ENGINE_URL",
    "http://engine-onboarding.threat-engine-engines.svc.cluster.local/api/v1",
)

# ── Billing internal service secret (BILL-S11) ────────────────────────────────
# Shared secret used by the Celery worker when calling the billing engine's
# internal provisioning endpoint. Must match BILLING_INTERNAL_SECRET on the
# billing engine pod. Never log this value — log len() or bool() only.
# To rotate: update the K8s secret and rollout both billing + cspm-backend.
BILLING_INTERNAL_SECRET = os.environ.get("BILLING_INTERNAL_SECRET", "")

DEBUG = os.getenv("DEBUG", "False").lower() in ("true", "1", "yes")
ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", "localhost").split(",")

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "corsheaders",
    "rest_framework",
    "user_auth",
    "django_extensions",
    "tenant_management",
    "audit_logs",
]

REST_FRAMEWORK = {
    "DEFAULT_RENDERER_CLASSES": (
        "rest_framework.renderers.JSONRenderer",
    ),
    "UNAUTHENTICATED_USER": None,
    "DEFAULT_AUTHENTICATION_CLASSES": [],
    "DEFAULT_THROTTLE_CLASSES": [],
    "DEFAULT_THROTTLE_RATES": {
        "signup": "10/hour",
        "login": "20/hour",
        "refresh": "60/hour",
        "idp_domain": "5/minute",
    },
}

MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

AUTH_USER_MODEL = "user_auth.Users"

AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
]

CORS_ALLOW_CREDENTIALS = True

# Build origin lists from base + env var overrides (comma-separated)
_extra_origins = [o.strip() for o in os.getenv("CORS_EXTRA_ORIGINS", "").split(",") if o.strip()]
CORS_ALLOWED_ORIGINS = ["http://localhost:3000"] + _extra_origins

_extra_csrf = [o.strip() for o in os.getenv("CSRF_EXTRA_TRUSTED_ORIGINS", "").split(",") if o.strip()]
CSRF_TRUSTED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
] + _extra_csrf

# Trust X-Forwarded-Proto from nginx ingress so Django sees HTTPS scheme correctly
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
CORS_ALLOW_HEADERS = [
    "accept",
    "authorization",
    "content-type",
    "user-agent",
    "x-csrftoken",
    "x-requested-with",
]

ROOT_URLCONF = "config.urls"
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

MEDIA_ROOT = os.getenv("MEDIA_ROOT", os.path.join(BASE_DIR, "media"))
MEDIA_URL = os.getenv("MEDIA_URL", "/media/")

DB_SCHEMA = os.getenv("DB_SCHEMA")

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.getenv("DB_NAME"),
        "USER": os.getenv("DB_USER"),
        "PASSWORD": os.getenv("DB_PASSWORD"),
        "HOST": os.getenv("DB_HOST", "localhost"),
        "PORT": os.getenv("DB_PORT", "5432"),
        "OPTIONS": {
            "options": "-c search_path=public"
        },
    }
}

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True
STATIC_URL = "static/"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

SESSION_SERIALIZER = "django.contrib.sessions.serializers.JSONSerializer"

# ── hCaptcha — required in production; if unset, CAPTCHA is skipped (dev only) ──
HCAPTCHA_SECRET_KEY = os.getenv("HCAPTCHA_SECRET_KEY", "")

# ── Redirect allowlist — FRONTEND_URL host must be in this list (validated at startup) ──
ALLOWED_REDIRECT_HOSTS = [h.strip() for h in os.getenv("ALLOWED_REDIRECT_HOSTS", "localhost").split(",") if h.strip()]

# ── Celery ────────────────────────────────────────────────────────────────────
CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", "redis://redis:6379/0")
CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", "redis://redis:6379/1")
CELERY_TASK_SERIALIZER = "json"
CELERY_RESULT_SERIALIZER = "json"
CELERY_ACCEPT_CONTENT = ["json"]
CELERY_TIMEZONE = "UTC"
