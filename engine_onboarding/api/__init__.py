"""
API endpoints for onboarding
"""
from engine_onboarding.api.cloud_accounts import router as cloud_accounts_router
from engine_onboarding.api.credentials import router as credentials_router
from engine_onboarding.api.health import router as health_router

__all__ = [
    'cloud_accounts_router',
    'credentials_router',
    'health_router'
]

