"""
API endpoints for onboarding
"""
from engine_onboarding.api.cloud_accounts import router as cloud_accounts_router
from engine_onboarding.api.health import router as health_router
from engine_onboarding.api.internal import router as internal_router
from engine_onboarding.api.tenants import router as tenants_router
from engine_onboarding.api.schedules import router as schedules_router
from engine_onboarding.api.scan_runs import router as scan_runs_router
from engine_onboarding.api.scans_adhoc import router as scans_adhoc_router

__all__ = [
    'cloud_accounts_router',
    'health_router',
    'internal_router',
    'tenants_router',
    'schedules_router',
    'scan_runs_router',
    'scans_adhoc_router',
]

