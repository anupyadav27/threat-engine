"""
API endpoints for onboarding
"""
from engine_onboarding.api.onboarding import router as onboarding_router
from engine_onboarding.api.credentials import router as credentials_router
from engine_onboarding.api.schedules import router as schedules_router
from engine_onboarding.api.health import router as health_router

__all__ = [
    'onboarding_router',
    'credentials_router',
    'schedules_router',
    'health_router'
]

