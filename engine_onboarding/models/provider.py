"""
Provider models
"""
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from uuid import UUID


class ProviderCreate(BaseModel):
    """Create provider request"""
    tenant_id: UUID
    provider_type: str  # 'aws', 'azure', 'gcp', etc.


class ProviderResponse(BaseModel):
    """Provider response"""
    provider_id: UUID
    tenant_id: UUID
    provider_type: str
    status: str
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True

