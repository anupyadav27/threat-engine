"""
Shared API models for consistent responses across all engines
"""
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime


class HealthResponse(BaseModel):
    """Standardized health check response"""
    status: str = Field(default="healthy", description="Service status")
    version: Optional[str] = Field(default=None, description="Service version")
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat(), description="Response timestamp")
    details: Optional[Dict[str, Any]] = Field(default=None, description="Additional health details")


class ErrorResponse(BaseModel):
    """Standardized error response"""
    error: str = Field(description="Error message")
    error_code: Optional[str] = Field(default=None, description="Error code")
    details: Optional[Dict[str, Any]] = Field(default=None, description="Additional error details")
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat(), description="Error timestamp")


class ScanMetadata(BaseModel):
    """Unified scan metadata"""
    scan_run_id: str = Field(description="Unified scan identifier")
    tenant_id: str = Field(description="Tenant identifier")
    account_id: str = Field(description="Account identifier")
    provider: str = Field(description="Cloud provider")
    scan_id: Optional[str] = Field(default=None, description="Engine-specific scan ID")
    status: str = Field(description="Scan status")
    started_at: str = Field(description="Scan start time")
    completed_at: Optional[str] = Field(default=None, description="Scan completion time")


class OrchestrationStatus(BaseModel):
    """Orchestration status for downstream engines"""
    scan_run_id: str = Field(description="Unified scan identifier")
    engine: str = Field(description="Engine name")
    status: str = Field(description="Orchestration status")
    started_at: str = Field(description="Orchestration start time")
    completed_at: Optional[str] = Field(default=None, description="Orchestration completion time")
    error: Optional[str] = Field(default=None, description="Error message if failed")
