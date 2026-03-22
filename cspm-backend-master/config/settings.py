import os
from pathlib import Path

import os
import saml2
import django.contrib.sessions.serializers
from dotenv import load_dotenv



BASE_DIR = Path(__file__).resolve().parent.parent
CONF_DIR = BASE_DIR / ".config"

load_dotenv(CONF_DIR / ".env")

SECRET_KEY = os.getenv("SECRET_KEY")

ACCESS_TOKEN_LIFETIME_MINUTES = int(os.getenv("ACCESS_TOKEN_LIFETIME_MINUTES", 15))
REFRESH_TOKEN_LIFETIME_DAYS = int(os.getenv("REFRESH_TOKEN_LIFETIME_DAYS", 7))
FRONTEND_URL = os.getenv("FRONTEND_URL")

DEBUG = os.getenv("DEBUG", "False").lower() in ("true", "1", "yes")
ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", "localhost").split(",")

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "corsheaders",
    "rest_framework",
    "user_auth",
    "djangosaml2",
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
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
]

CSRF_TRUSTED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
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
            "options": f"-c search_path=public"
        },
    }
}

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True
STATIC_URL = 'static/'
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


AUTHENTICATION_BACKENDS = (
    'django.contrib.auth.backends.ModelBackend',
    'djangosaml2.backends.Saml2Backend',
)

SAML_DJANGO_USER_MAIN_ATTRIBUTE = 'email'
SAML_USE_NAME_ID_AS_USERNAME = True
SAML_CREATE_UNKNOWN_USER = True
SAML_ATTRIBUTE_MAPPING = {
    'uid': ('email',),
    'firstName': ('first_name',),
    'lastName': ('last_name',),
}
XMLSEC_BINARY=BASE_DIR/os.getenv("XMLSEC_BINARY")

SAML_CONFIG = {
    'debug': DEBUG,
    'xmlsec_binary': str(XMLSEC_BINARY),
    'entityid': os.getenv('SAML_AUDIENCE'),
    'allow_unknown_attributes': True,

    'key_file': os.path.join(CONF_DIR, 'sp_key.pem'),
    'cert_file': os.path.join(CONF_DIR, 'sp_cert.pem'),

    'service': {
        'sp': {
            'name': 'CSPM SP',
            'name_id_format': saml2.NAMEID_FORMAT_EMAILADDRESS,
            'endpoints': {
                'assertion_consumer_service': [
                    (os.getenv('SAML_CALLBACK_URL'), saml2.BINDING_HTTP_POST),
                ],
                'single_logout_service': [
                    (os.getenv('SAML_LOGOUT_CALLBACK_URL'), saml2.BINDING_HTTP_POST),
                    (os.getenv('SAML_LOGOUT_CALLBACK_URL'), saml2.BINDING_HTTP_REDIRECT),
                ],
            },
            'allow_unsolicited': True,
            'authn_requests_signed': False,
            'logout_requests_signed': True,
            'want_assertions_signed': False,
            'want_response_signed': False,

        },
    },
    'metadata': {
        'remote': [{'url': os.getenv('OKTA_METADATA')}],
    },
}

SAML_CONFIG['service']['sp']['relay_state'] = 'http://localhost:8000/api/auth/saml/success/'
SAML_CSP_HANDLER = ''
SESSION_SERIALIZER = 'django.contrib.sessions.serializers.JSONSerializer'

