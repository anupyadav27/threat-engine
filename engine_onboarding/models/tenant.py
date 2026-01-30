"""
Tenant models
"""
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from uuid import UUID


class TenantCreate(BaseModel):
    """Create tenant request"""
    tenant_name: str
    description: Optional[str] = None


class TenantResponse(BaseModel):
    """Tenant response"""
    tenant_id: UUID
    tenant_name: str
    description: Optional[str]
    status: str
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True

