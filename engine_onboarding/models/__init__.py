"""
Pydantic models for API requests/responses
"""
from engine_onboarding.models.tenant import TenantCreate, TenantResponse
from engine_onboarding.models.provider import ProviderCreate, ProviderResponse
from engine_onboarding.models.account import AccountCreate, AccountResponse, AccountUpdate, OnboardingInitRequest
from engine_onboarding.models.credential import (
    CredentialSubmit, CredentialResponse, AWSAccessKeyCredentials,
    AWSIAMRoleCredentials, AzureServicePrincipalCredentials,
    GCPServiceAccountCredentials, AliCloudAccessKeyCredentials
)
from engine_onboarding.models.schedule import (
    ScheduleCreate, ScheduleUpdate, ScheduleResponse, ScheduleExecutionResponse
)

__all__ = [
    'TenantCreate',
    'TenantResponse',
    'ProviderCreate',
    'ProviderResponse',
    'AccountCreate',
    'AccountResponse',
    'AccountUpdate',
    'OnboardingInitRequest',
    'CredentialSubmit',
    'CredentialResponse',
    'AWSAccessKeyCredentials',
    'AWSIAMRoleCredentials',
    'AzureServicePrincipalCredentials',
    'GCPServiceAccountCredentials',
    'AliCloudAccessKeyCredentials',
    'ScheduleCreate',
    'ScheduleUpdate',
    'ScheduleResponse',
    'ScheduleExecutionResponse'
]

