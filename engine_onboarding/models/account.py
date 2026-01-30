"""
Account models
"""
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from uuid import UUID


class AccountCreate(BaseModel):
    """Create account request"""
    provider_id: UUID
    tenant_id: UUID
    account_name: str


class AccountUpdate(BaseModel):
    """Update account request"""
    account_name: Optional[str] = None
    status: Optional[str] = None


class AccountResponse(BaseModel):
    """Account response"""
    account_id: UUID
    provider_id: UUID
    tenant_id: UUID
    account_name: str
    account_number: Optional[str]
    status: str
    onboarding_status: str
    created_at: datetime
    updated_at: datetime
    last_validated_at: Optional[datetime]
    
    class Config:
        from_attributes = True


class OnboardingInitRequest(BaseModel):
    """Initialize onboarding request"""
    tenant_id: str
    provider_id: Optional[str] = None  # Optional - will be created if not provided
    account_name: str
    auth_method: Optional[str] = None  # Defaults based on provider

