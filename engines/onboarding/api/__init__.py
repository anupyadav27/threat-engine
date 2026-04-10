"""
API endpoints for onboarding
"""
from engine_onboarding.api.cloud_accounts import router as cloud_accounts_router
from engine_onboarding.api.credentials import router as credentials_router
from engine_onboarding.api.health import router as health_router
from engine_onboarding.api.tenants import router as tenants_router
from engine_onboarding.api.schedules import router as schedules_router
from engine_onboarding.api.scan_runs import router as scan_runs_router

__all__ = [
    'cloud_accounts_router',
    'credentials_router',
    'health_router',
    'tenants_router',
    'schedules_router',
    'scan_runs_router',
]

