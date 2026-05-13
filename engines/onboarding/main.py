"""
Main FastAPI application for onboarding service
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html, get_swagger_ui_oauth2_redirect_html
from fastapi.openapi.utils import get_openapi
import uvicorn
import asyncio
import os

from engine_onboarding.api import cloud_accounts_router, health_router, internal_router, tenants_router, schedules_router, scan_runs_router, scans_adhoc_router, reference_router
try:
    from engine_onboarding.api.agents import router as agents_router
    _AGENTS_ROUTER_AVAILABLE = True
except Exception:
    _AGENTS_ROUTER_AVAILABLE = False
    agents_router = None

# AC9 (onboarding-C4): agent heartbeat router — Bearer token auth, no cookie required.
try:
    from engine_onboarding.routers.agent import router as agent_heartbeat_router
    _AGENT_HEARTBEAT_ROUTER_AVAILABLE = True
except Exception:
    _AGENT_HEARTBEAT_ROUTER_AVAILABLE = False
    agent_heartbeat_router = None

# onboarding-C9: bulk run-all scans router (POST /api/v1/scans/run-all).
try:
    from engine_onboarding.routers.bulk_scans import router as bulk_scans_router
    _BULK_SCANS_ROUTER_AVAILABLE = True
except Exception:
    _BULK_SCANS_ROUTER_AVAILABLE = False
    bulk_scans_router = None
from engine_onboarding.config import settings
from engine_onboarding.database.connection import init_db, check_connection
try:
    from engine_common.telemetry import configure_telemetry as _configure_telemetry
except ImportError:
    _configure_telemetry = None
from engine_onboarding.scheduler.scheduler_service import SchedulerService

# Auth middleware (engine_auth is COPY shared/auth/ ./engine_auth/ in Dockerfile)
try:
    from engine_auth.fastapi.middleware import AuthMiddleware
    _AUTH_AVAILABLE = True
except ImportError:
    AuthMiddleware = None
    _AUTH_AVAILABLE = False

# Path prefix when running behind ingress rewrite (/onboarding -> /)
ROOT_PATH = (os.getenv("ROOT_PATH", "") or "").rstrip("/")

# Create FastAPI app
app = FastAPI(
    title="Threat Engine Onboarding API",
    description="API for account onboarding, credential management, and scheduling",
    version="1.0.0",
    docs_url=None,
    redoc_url=None
)
if _configure_telemetry:
    _configure_telemetry("engine-onboarding", app)

# Inject root_path as OpenAPI server so Swagger calls include /onboarding.
def _custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    if ROOT_PATH:
        schema["servers"] = [{"url": ROOT_PATH}]
    app.openapi_schema = schema
    return app.openapi_schema

app.openapi = _custom_openapi


@app.get("/docs", include_in_schema=False)
def _swagger_ui():
    openapi_url = f"{ROOT_PATH}{app.openapi_url}" if ROOT_PATH else app.openapi_url
    oauth2_redirect_url = f"{ROOT_PATH}/docs/oauth2-redirect" if ROOT_PATH else app.swagger_ui_oauth2_redirect_url
    return get_swagger_ui_html(
        openapi_url=openapi_url,
        title=f"{app.title} - Swagger UI",
        oauth2_redirect_url=oauth2_redirect_url,
    )


@app.get("/docs/oauth2-redirect", include_in_schema=False)
def _swagger_ui_redirect():
    return get_swagger_ui_oauth2_redirect_html()


# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# AuthMiddleware validates X-Auth-Context on every non-health route
if _AUTH_AVAILABLE and AuthMiddleware:
    app.add_middleware(AuthMiddleware)

# Include routers
app.include_router(health_router)
app.include_router(internal_router)
app.include_router(reference_router)
app.include_router(tenants_router)
app.include_router(cloud_accounts_router)
app.include_router(schedules_router)
app.include_router(scan_runs_router)
app.include_router(scans_adhoc_router)
if _AGENTS_ROUTER_AVAILABLE and agents_router:
    app.include_router(agents_router)

# AC9 (onboarding-C4): agent heartbeat — Bearer token auth, no platform cookie.
if _AGENT_HEARTBEAT_ROUTER_AVAILABLE and agent_heartbeat_router:
    app.include_router(agent_heartbeat_router)

# onboarding-C9: bulk run-all scans — POST /api/v1/scans/run-all.
if _BULK_SCANS_ROUTER_AVAILABLE and bulk_scans_router:
    app.include_router(bulk_scans_router)

# Include unified UI data router
try:
    from engine_onboarding.api.ui_data_router import router as ui_data_router
    app.include_router(ui_data_router)
except Exception as e:
    print(f"UI data router not available: {e}")

# Global scheduler instance
scheduler_service = None
scheduler_task = None


@app.on_event("startup")
async def startup_event():
    """Initialize PostgreSQL database and start scheduler on startup"""
    global scheduler_service, scheduler_task
    
    # Initialize database
    try:
        if not check_connection():
            print("⚠️  Database connection check failed - tables may not be created")
            return
        
        # Initialize database tables
        init_db()
        print("✅ PostgreSQL database initialized successfully")
    except Exception as e:
        print(f"❌ Database initialization error: {e}")
        import traceback
        traceback.print_exc()
        return
    
    # Start scheduler
    try:
        scheduler_service = SchedulerService()
        scheduler_task = asyncio.create_task(scheduler_service.run())
        print("✅ Scheduler started")
    except Exception as e:
        print(f"⚠️  Scheduler failed to start: {e}")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    global scheduler_service, scheduler_task
    if scheduler_service:
        scheduler_service.stop()
    if scheduler_task and not scheduler_task.done():
        scheduler_task.cancel()
    print("✅ Onboarding API shutdown complete")


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "Threat Engine Onboarding API",
        "version": "1.0.0",
        "status": "running",
        "scheduler": "integrated"
    }


if __name__ == "__main__":
    uvicorn.run(
        "engine_onboarding.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=True
    )

