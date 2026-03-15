"""
External Collector API Server — Task 0.3.14 [Seq 38 | AD]

FastAPI server on port 8031 for on-demand collection requests.
Supports triggering specific sources or all sources in parallel.

Endpoints:
  POST /api/v1/collect/{source_type}  → trigger refresh for specific source
  POST /api/v1/collect/all            → trigger all collection tasks
  GET  /api/v1/cache/status           → cache freshness per source
  GET  /api/v1/collection/{task_id}/status → poll task status
  GET  /api/v1/health/live            → liveness probe
  GET  /api/v1/health/ready           → readiness probe

Dependencies:
  - Tasks 0.3.3-0.3.13 (all adapters, cache, rate limiter)
"""

import asyncio
import json
import logging
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import asyncpg
import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from shared.external_collector.cache_manager import CacheManager
from shared.external_collector.credential_manager import CredentialManager
from shared.external_collector.rate_limiter import RateLimiter

logger = logging.getLogger("external_collector.api_server")

# In-memory task tracking
_tasks: Dict[str, Dict[str, Any]] = {}


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------
class CollectionRequest(BaseModel):
    """Request to trigger a collection."""
    source_type: Optional[str] = None
    options: Optional[Dict[str, Any]] = None


class CollectionResponse(BaseModel):
    """Response after triggering a collection."""
    task_id: str
    status: str
    message: str


class TaskStatusResponse(BaseModel):
    """Status of a collection task."""
    task_id: str
    status: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class CacheStatusResponse(BaseModel):
    """Cache freshness status."""
    sources: Dict[str, Any]
    rate_limits: Dict[str, Any]


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    service: str = "external_collector"
    timestamp: str


# ---------------------------------------------------------------------------
# Application state
# ---------------------------------------------------------------------------
class AppState:
    """Holds shared application state."""
    pool: Optional[asyncpg.Pool] = None
    credential_manager: Optional[CredentialManager] = None
    cache_manager: Optional[CacheManager] = None
    rate_limiter: Optional[RateLimiter] = None
    ready: bool = False


state = AppState()

VALID_SOURCES = {
    "registry", "github", "gitlab", "nvd", "epss", "kev",
    "npm", "pypi", "maven", "crates", "docker_hub",
    "threat_intel", "lambda_zip",
}


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize DB pool and services on startup, cleanup on shutdown."""
    db_host = os.environ.get("TH_DB_HOST", "localhost")
    db_port = int(os.environ.get("TH_DB_PORT", "5432"))
    db_name = os.environ.get("TH_DB_EXTERNAL_NAME", "threat_engine_external")
    db_user = os.environ.get("TH_DB_USER", "postgres")
    db_pass = os.environ.get("TH_DB_PASSWORD", "")

    try:
        state.pool = await asyncpg.create_pool(
            host=db_host,
            port=db_port,
            database=db_name,
            user=db_user,
            password=db_pass,
            min_size=2,
            max_size=10,
        )
        logger.info("Database pool created for %s", db_name)

        # Initialize services
        state.credential_manager = CredentialManager()
        state.credential_manager.load_all()

        state.rate_limiter = RateLimiter()
        state.cache_manager = CacheManager(state.pool)

        # Register refresh callbacks (adapters initialized lazily)
        # In production, register actual adapter.refresh() methods here

        state.ready = True
        logger.info("External collector API server ready")

        yield
    finally:
        if state.cache_manager:
            await state.cache_manager.stop_scheduler()
        if state.pool:
            await state.pool.close()
        logger.info("External collector shutdown complete")


app = FastAPI(
    title="Threat Engine External Collector",
    version="0.3.0",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.post(
    "/api/v1/collect/{source_type}",
    response_model=CollectionResponse,
    status_code=202,
)
async def collect_source(source_type: str):
    """Trigger collection for a specific source type.

    Returns 202 Accepted with a task_id for polling.
    """
    if source_type not in VALID_SOURCES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid source_type '{source_type}'. Valid: {sorted(VALID_SOURCES)}",
        )

    task_id = str(uuid.uuid4())
    _tasks[task_id] = {
        "status": "running",
        "source_type": source_type,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": None,
        "result": None,
        "error": None,
    }

    # Spawn background task
    asyncio.create_task(_run_collection(task_id, source_type))

    return CollectionResponse(
        task_id=task_id,
        status="accepted",
        message=f"Collection for '{source_type}' started",
    )


@app.post(
    "/api/v1/collect/all",
    response_model=CollectionResponse,
    status_code=202,
)
async def collect_all():
    """Trigger collection for all sources in parallel."""
    task_id = str(uuid.uuid4())
    _tasks[task_id] = {
        "status": "running",
        "source_type": "all",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": None,
        "result": None,
        "error": None,
    }

    asyncio.create_task(_run_all_collections(task_id))

    return CollectionResponse(
        task_id=task_id,
        status="accepted",
        message="Collection for all sources started",
    )


@app.get("/api/v1/collection/{task_id}/status", response_model=TaskStatusResponse)
async def get_task_status(task_id: str):
    """Poll the status of a collection task."""
    task = _tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail=f"Task '{task_id}' not found")

    return TaskStatusResponse(
        task_id=task_id,
        status=task["status"],
        started_at=task["started_at"],
        completed_at=task["completed_at"],
        result=task["result"],
        error=task["error"],
    )


@app.get("/api/v1/cache/status", response_model=CacheStatusResponse)
async def get_cache_status():
    """Return cache freshness per source and rate limit status."""
    cache_status = {}
    rate_status = {}

    if state.cache_manager:
        cache_status = await state.cache_manager.get_cache_status()

    if state.rate_limiter:
        rate_status = state.rate_limiter.get_status()

    return CacheStatusResponse(
        sources=cache_status,
        rate_limits=rate_status,
    )


@app.get("/api/v1/health/live", response_model=HealthResponse)
async def health_live():
    """Liveness probe — returns 200 if the process is running."""
    return HealthResponse(
        status="ok",
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@app.get("/api/v1/health/ready", response_model=HealthResponse)
async def health_ready():
    """Readiness probe — returns 200 if the service is ready to accept work."""
    if not state.ready or not state.pool:
        raise HTTPException(status_code=503, detail="Service not ready")

    return HealthResponse(
        status="ready",
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


# ---------------------------------------------------------------------------
# Background task runners
# ---------------------------------------------------------------------------
async def _run_collection(task_id: str, source_type: str) -> None:
    """Run a collection for a single source type."""
    try:
        if state.cache_manager:
            result = await state.cache_manager.refresh_source(source_type)
        else:
            result = {"warning": "cache_manager not initialized"}

        _tasks[task_id]["status"] = "completed"
        _tasks[task_id]["result"] = result
        _tasks[task_id]["completed_at"] = datetime.now(timezone.utc).isoformat()

    except Exception as exc:
        _tasks[task_id]["status"] = "failed"
        _tasks[task_id]["error"] = str(exc)
        _tasks[task_id]["completed_at"] = datetime.now(timezone.utc).isoformat()
        logger.error("Collection task %s failed: %s", task_id, exc, exc_info=True)


async def _run_all_collections(task_id: str) -> None:
    """Run collections for all sources in parallel."""
    try:
        if state.cache_manager:
            result = await state.cache_manager.refresh_all()
        else:
            result = {"warning": "cache_manager not initialized"}

        _tasks[task_id]["status"] = "completed"
        _tasks[task_id]["result"] = result
        _tasks[task_id]["completed_at"] = datetime.now(timezone.utc).isoformat()

    except Exception as exc:
        _tasks[task_id]["status"] = "failed"
        _tasks[task_id]["error"] = str(exc)
        _tasks[task_id]["completed_at"] = datetime.now(timezone.utc).isoformat()
        logger.error("Collect-all task %s failed: %s", task_id, exc, exc_info=True)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    port = int(os.environ.get("TH_EXTERNAL_COLLECTOR_PORT", "8031"))
    uvicorn.run(
        "shared.external_collector.api_server:app",
        host="0.0.0.0",
        port=port,
        log_level="info",
    )
