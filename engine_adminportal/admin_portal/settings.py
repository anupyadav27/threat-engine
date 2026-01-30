"""
Django settings for admin_portal project.
"""
import os
from pathlib import Path
from datetime import timedelta

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get('ADMIN_SECRET_KEY', 'django-insecure-admin-portal-change-in-production')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.environ.get('DEBUG', 'False') == 'True'

ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', '*').split(',')

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'corsheaders',
    'django_filters',
    'apps.admin_monitoring',
    'apps.admin_analytics',
    'apps.admin_management',
    'apps.admin_audit',
    'apps.engine_integration',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'apps.admin_audit.middleware.AuditLoggingMiddleware',
]

ROOT_URLCONF = 'admin_portal.urls'

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

WSGI_APPLICATION = 'admin_portal.wsgi.application'

# Database — consolidated: DATABASE_URL + DB_SCHEMA (engine_shared, engine_adminportal)
DB_SCHEMA = os.environ.get('DB_SCHEMA', 'engine_adminportal,engine_shared')
_DATABASE_URL = os.environ.get('DATABASE_URL')
if _DATABASE_URL:
    from urllib.parse import urlparse
    _u = urlparse(_DATABASE_URL)
    _db_name = (_u.path or '').lstrip('/') or 'postgres'
    _db_config = {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': _db_name,
        'USER': _u.username or 'postgres',
        'PASSWORD': _u.password or '',
        'HOST': _u.hostname or 'localhost',
        'PORT': str(_u.port or 5432),
        'OPTIONS': {'options': f'-c search_path={DB_SCHEMA}'},
    }
else:
    _db_config = {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.environ.get('DB_NAME', 'cspm'),
        'USER': os.environ.get('DB_USER', 'postgres'),
        'PASSWORD': os.environ.get('DB_PASSWORD', ''),
        'HOST': os.environ.get('DB_HOST', 'localhost'),
        'PORT': os.environ.get('DB_PORT', '5432'),
        'OPTIONS': {'options': f'-c search_path={DB_SCHEMA}'},
    }
DATABASES = {'default': _db_config}

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
STATIC_URL = 'static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# REST Framework
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.TokenAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_PAGINATION_CLASS': 'common.pagination.AdminPagination',
    'PAGE_SIZE': 50,
    'DEFAULT_FILTER_BACKENDS': [
        'rest_framework.filters.SearchFilter',
        'rest_framework.filters.OrderingFilter',
    ],
}

# CORS
CORS_ALLOWED_ORIGINS = os.environ.get('CORS_ALLOWED_ORIGINS', '').split(',') if os.environ.get('CORS_ALLOWED_ORIGINS') else []
CORS_ALLOW_CREDENTIALS = True

# Redis Cache
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': os.environ.get('REDIS_URL', 'redis://localhost:6379/1'),
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        },
        'KEY_PREFIX': 'admin_portal',
        'TIMEOUT': 300,  # 5 minutes default
    }
}

# Celery Configuration
CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL', os.environ.get('REDIS_URL', 'redis://localhost:6379/0'))
CELERY_RESULT_BACKEND = os.environ.get('CELERY_RESULT_BACKEND', os.environ.get('REDIS_URL', 'redis://localhost:6379/0'))
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = TIME_ZONE
CELERY_BEAT_SCHEDULE = {
    'aggregate-tenant-metrics': {
        'task': 'apps.admin_monitoring.tasks.aggregate_tenant_metrics',
        'schedule': timedelta(seconds=30),
    },
    'health-check-engines': {
        'task': 'apps.engine_integration.tasks.health_check_engines',
        'schedule': timedelta(seconds=60),
    },
    'calculate-analytics': {
        'task': 'apps.admin_analytics.tasks.calculate_analytics',
        'schedule': timedelta(minutes=5),
    },
    'cleanup-old-metrics': {
        'task': 'apps.admin_monitoring.tasks.cleanup_old_metrics',
        'schedule': timedelta(days=1),
    },
}

# Engine Endpoints Configuration
ENGINE_ENDPOINTS = {
    'configscan_aws': os.environ.get('CONFIGSCAN_AWS_URL', 'http://aws-configscan-engine:8000'),
    'configscan_azure': os.environ.get('CONFIGSCAN_AZURE_URL', 'http://azure-configscan-engine:8000'),
    'configscan_gcp': os.environ.get('CONFIGSCAN_GCP_URL', 'http://gcp-configscan-engine:8000'),
    'configscan_alicloud': os.environ.get('CONFIGSCAN_ALICLOUD_URL', 'http://alicloud-configscan-engine:8000'),
    'configscan_oci': os.environ.get('CONFIGSCAN_OCI_URL', 'http://oci-configscan-engine:8000'),
    'configscan_ibm': os.environ.get('CONFIGSCAN_IBM_URL', 'http://ibm-configscan-engine:8000'),
    'compliance': os.environ.get('COMPLIANCE_ENGINE_URL', 'http://engine-compliance:8000'),
    'threat': os.environ.get('THREAT_ENGINE_URL', 'http://engine-threat:8000'),
    'inventory': os.environ.get('INVENTORY_ENGINE_URL', 'http://engine-inventory:8000'),
    'datasec': os.environ.get('DATASEC_ENGINE_URL', 'http://engine-datasec:8000'),
    'onboarding': os.environ.get('ONBOARDING_ENGINE_URL', 'http://onboarding-engine:8000'),
}

# Logging
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
    'loggers': {
        'apps': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}
