"""
Health check endpoints
"""
import os
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional
from sqlalchemy import text
import boto3

from engine_onboarding.database.connection import check_connection, engine
from engine_onboarding.database.connection_config.database_config import get_shared_config

router = APIRouter(prefix="/api/v1/health", tags=["health"])


class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    database: str
    database_details: Optional[dict] = None
    secrets_manager: str = "optional"
    version: str = "1.0.0"
    service: str = "onboarding"


@router.get("", response_model=HealthResponse)
async def health_check():
    """Health check endpoint with database connectivity verification"""
    db_status = "disconnected"
    db_details = None
    
    # Check PostgreSQL connectivity
    try:
        if check_connection():
            db_status = "connected"
            try:
                db_config = get_shared_config()
                with engine.connect() as conn:
                    result = conn.execute(text("SELECT version()"))
                    version = result.fetchone()[0]
                    db_details = {
                        "status": "connected",
                        "database": db_config.database,
                        "host": db_config.host,
                        "version": version.split(',')[0] if version else "unknown",
                        "using": "local_database_config"
                    }
            except Exception as e:
                db_details = {"status": "connected", "error": str(e), "using": "local_database_config"}
        else:
            db_status = "disconnected"
            db_details = {"status": "disconnected", "error": "Connection check failed", "using": "local_database_config"}
    except Exception as e:
        db_status = "disconnected"
        db_details = {"status": "disconnected", "error": str(e), "using": "local_database_config"}
    
    # Check Secrets Manager connectivity (optional - for credential storage)
    secrets_status = "optional"
    try:
        aws_region = os.getenv('AWS_REGION', 'ap-south-1')
        secrets = boto3.client('secretsmanager', region_name=aws_region)
        secrets.list_secrets(MaxResults=1)  # Minimal call
        secrets_status = "connected"
    except Exception:
        secrets_status = "disconnected (optional)"
    
    # Overall health: healthy only if database is connected
    overall_status = "healthy" if db_status == "connected" else "unhealthy"
    
    return HealthResponse(
        status=overall_status,
        database=db_status,
        database_details=db_details,
        secrets_manager=secrets_status
    )


@router.get("/ready")
async def readiness_check():
    """Kubernetes readiness probe - checks if service is ready to accept traffic"""
    try:
        if check_connection():
            return {"status": "ready", "database": "connected", "using": "local_database_config"}
        else:
            return {"status": "not_ready", "database": "disconnected"}, 503
    except Exception as e:
        return {"status": "not_ready", "error": str(e)}, 503


@router.get("/live")
async def liveness_check():
    """Kubernetes liveness probe - checks if service is alive"""
    return {"status": "alive", "service": "onboarding"}

