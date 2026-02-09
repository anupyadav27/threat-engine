import os
from pathlib import Path

import django.contrib.sessions.serializers
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.getenv("SECRET_KEY")

ACCESS_TOKEN_LIFETIME_MINUTES = int(os.getenv("ACCESS_TOKEN_LIFETIME_MINUTES", 15))
REFRESH_TOKEN_LIFETIME_DAYS = int(os.getenv("REFRESH_TOKEN_LIFETIME_DAYS", 7))
FRONTEND_URL = os.getenv("FRONTEND_URL")

DEBUG = os.getenv("DEBUG", "False").lower() in ("true", "1", "yes")
ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", "localhost,*").split(",")

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.postgres",  # For JSONField and ArrayField
    "corsheaders",
    "rest_framework",
    "user_auth",
    "djangosaml2",
    "django_extensions",
    "tenant_management",
    "access_management",
    "audit_logs",
    "assets_management",
    "threats_management",
    "onboarding_management",  # Onboarding tables
    "scan_results_management",  # Scan results and findings
    "inventory_management",  # Inventory Engine models
    "compliance_management",  # Compliance Engine models
    "datasec_management",  # DataSec Engine models
    "check_results_management",  # Check Results models
    "discovery_results_management",  # Discovery Results models
    "secops_management",  # SecOps Engine – scans/findings (scan_id, customer_id, tenant_id)
]

REST_FRAMEWORK = {
    "DEFAULT_RENDERER_CLASSES": (
        "rest_framework.renderers.JSONRenderer",
    ),
    "UNAUTHENTICATED_USER": None,
    "DEFAULT_AUTHENTICATION_CLASSES": [],
}

MIDDLEWARE = [
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'djangosaml2.middleware.SessionMiddleware',
    'djangosaml2.middleware.SamlSessionMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

AUTH_USER_MODEL="user_auth.Users"

CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_ALL_ORIGINS = True  # Allow all origins for dev
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://ae2469ab99eff40b88109662102164e2-618626780.ap-south-1.elb.amazonaws.com",
]

CSRF_TRUSTED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://ae2469ab99eff40b88109662102164e2-618626780.ap-south-1.elb.amazonaws.com",
]
CORS_ALLOW_HEADERS = [
    "accept",
    "authorization",
    "content-type",
    "user-agent",
    "x-csrftoken",
    "x-requested-with",
]

ROOT_URLCONF = 'cspm.urls'
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

MEDIA_ROOT = os.getenv("MEDIA_ROOT", os.path.join(BASE_DIR, "media"))
MEDIA_URL = os.getenv("MEDIA_URL", "/media/")

DB_SCHEMA = os.getenv("DB_SCHEMA", "public")
DB_SSLMODE = os.getenv("DB_SSLMODE", "require")
_DATABASE_URL = os.getenv("DATABASE_URL")

if _DATABASE_URL:
    from urllib.parse import urlparse
    _u = urlparse(_DATABASE_URL)
    _db_name = (_u.path or "").lstrip("/") or "postgres"
    _db_config = {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": _db_name,
        "USER": _u.username or "postgres",
        "PASSWORD": _u.password or "",
        "HOST": _u.hostname or "localhost",
        "PORT": str(_u.port or 5432),
        "OPTIONS": {
            "options": f"-c search_path={DB_SCHEMA}",
            "sslmode": DB_SSLMODE,
        },
    }
else:
    _db_config = {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.getenv("DB_NAME"),
        "USER": os.getenv("DB_USER"),
        "PASSWORD": os.getenv("DB_PASSWORD"),
        "HOST": os.getenv("DB_HOST", "localhost"),
        "PORT": os.getenv("DB_PORT", "5432"),
        "OPTIONS": {
            "options": f"-c search_path={DB_SCHEMA}",
            "sslmode": DB_SSLMODE,
        },
    }

DATABASES = {"default": _db_config}

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True
STATIC_URL = 'static/'
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Consolidated Architecture: Single API Gateway URL
API_GATEWAY_URL = os.getenv("API_GATEWAY_URL", "http://api-gateway:8000")

# Engine API URLs (routed through API Gateway for consolidated architecture)
THREAT_ENGINE_URL = os.getenv("THREAT_ENGINE_URL", f"{API_GATEWAY_URL}/api/v1/threat")
COMPLIANCE_ENGINE_URL = os.getenv("COMPLIANCE_ENGINE_URL", f"{API_GATEWAY_URL}/api/v1/compliance")
DATASEC_ENGINE_URL = os.getenv("DATASEC_ENGINE_URL", f"{API_GATEWAY_URL}/api/v1/datasec")
INVENTORY_ENGINE_URL = os.getenv("INVENTORY_ENGINE_URL", f"{API_GATEWAY_URL}/api/v1/inventory")
ONBOARDING_ENGINE_URL = os.getenv("ONBOARDING_ENGINE_URL", f"{API_GATEWAY_URL}/api/v1/onboarding")
SECOPS_ENGINE_URL = os.getenv("SECOPS_ENGINE_URL", f"{API_GATEWAY_URL}/api/v1/secops")

# Direct service URLs (uniform naming - matches K8s service names)
DISCOVERIES_ENGINE_URL = os.getenv("DISCOVERIES_ENGINE_URL", "http://engine-discoveries:8001")
CHECK_ENGINE_URL = os.getenv("CHECK_ENGINE_URL", "http://engine-check:8002")
IAM_ENGINE_URL = os.getenv("IAM_ENGINE_URL", "http://engine-iam:8003")
RULE_ENGINE_URL = os.getenv("RULE_ENGINE_URL", "http://engine-rule:8000")

# Feature flags for gradual migration
USE_API_GATEWAY = os.getenv("USE_API_GATEWAY", "true").lower() == "true"
MIGRATION_MODE = os.getenv("MIGRATION_MODE", "gateway")  # "gateway" or "direct"

SAML_CONFIG = {
    'debug': True,
    "xmlsec_binary": r"C:\Program Files\xmlsec\bin\xmlsec1.exe",
    'entityid': os.getenv('SAML_AUDIENCE'),
    'description': 'CSPM SAML Service Provider',

    'service': {
        'sp': {
            'name': 'CSPM SP',
            'endpoints': {
                'assertion_consumer_service': [
                    (os.getenv('SAML_CALLBACK_URL'), 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'),
                ],
                'single_logout_service': [
                    (os.getenv('SAML_LOGOUT_CALLBACK_URL'), 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'),
                ],
            },
            'required_attributes': ['email'],
            'optional_attributes': [],
            'idp': {
                os.getenv('OKTA_ISSUER'): {
                    'single_sign_on_service': {
                        os.getenv('OKTA_ENTRYPOINT'): 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                    },
                    'single_logout_service': {
                        os.getenv('OKTA_LOGOUT'): 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                    },
                    'cert_file': os.path.join(BASE_DIR, './okta.cert'),
                },
            },
        },
    },
    "metadata": {
        "remote": [
            {
                "url": os.getenv('OKTA_METADATA'),
                "cert": None,
            }
        ]
    },
    'key_file': None,
    'cert_file': None,
    'encryption_keypairs': [],
    'accepted_time_diff': 60,
}
SAML_CONFIG['service']['sp']['relay_state'] = os.getenv('FRONTEND_URL', 'http://localhost:3000')
SAML_DJANGO_USER_MAIN_ATTRIBUTE = 'email'
SAML_USE_NAME_ID_AS_USERNAME = False
SAML_CREATE_UNKNOWN_USER = False


SESSION_SERIALIZER = 'django.contrib.sessions.serializers.JSONSerializer'

XMLSEC_BINARY = r"C:\Program Files\xmlsec\bin\xmlsec1.exe"
