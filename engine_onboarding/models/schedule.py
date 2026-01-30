"""
Schedule models
"""
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
from uuid import UUID


class ScheduleCreate(BaseModel):
    """Create schedule request"""
    tenant_id: UUID
    account_id: UUID
    name: str
    description: Optional[str] = None
    schedule_type: str  # 'cron', 'interval', 'one_time'
    cron_expression: Optional[str] = None
    interval_seconds: Optional[int] = None
    timezone: str = 'UTC'
    regions: Optional[List[str]] = None
    services: Optional[List[str]] = None
    exclude_services: Optional[List[str]] = None
    notify_on_success: bool = False
    notify_on_failure: bool = True
    notification_channels: Optional[List[str]] = None


class ScheduleUpdate(BaseModel):
    """Update schedule request"""
    name: Optional[str] = None
    description: Optional[str] = None
    schedule_type: Optional[str] = None
    cron_expression: Optional[str] = None
    interval_seconds: Optional[int] = None
    enabled: Optional[bool] = None
    status: Optional[str] = None
    regions: Optional[List[str]] = None
    services: Optional[List[str]] = None


class ScheduleResponse(BaseModel):
    """Schedule response"""
    schedule_id: UUID
    tenant_id: UUID
    account_id: UUID
    name: str
    description: Optional[str]
    schedule_type: str
    cron_expression: Optional[str]
    interval_seconds: Optional[int]
    timezone: str
    regions: Optional[List[str]]
    services: Optional[List[str]]
    exclude_services: Optional[List[str]]
    status: str
    enabled: bool
    last_run_at: Optional[datetime]
    next_run_at: Optional[datetime]
    run_count: int
    success_count: int
    failure_count: int
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class ScheduleExecutionResponse(BaseModel):
    """Schedule execution response"""
    execution_id: UUID
    schedule_id: UUID
    account_id: UUID
    started_at: datetime
    completed_at: Optional[datetime]
    status: str
    scan_id: Optional[str]
    total_checks: Optional[int]
    passed_checks: Optional[int]
    failed_checks: Optional[int]
    error_message: Optional[str]
    triggered_by: Optional[str]
    execution_time_seconds: Optional[int]
    created_at: datetime
    
    class Config:
        from_attributes = True

