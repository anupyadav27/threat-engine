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

from engine_onboarding.api import cloud_accounts_router, health_router, credentials_router
from engine_onboarding.config import settings
from engine_onboarding.database.connection import init_db, check_connection
try:
    from engine_common.telemetry import configure_telemetry as _configure_telemetry
except ImportError:
    _configure_telemetry = None
# from engine_onboarding.database import mark_stale_running_executions_as_failed  # REMOVED - old schema
# from engine_onboarding.scheduler.scheduler_service import SchedulerService  # REMOVED - uses old schema

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

# Include routers
app.include_router(health_router)
app.include_router(cloud_accounts_router)
app.include_router(credentials_router)

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
    
    # TODO: Re-implement scheduler using cloud_accounts table schedule fields
    print("⚠️  Scheduler disabled - needs reimplementation for cloud_accounts schema")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
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

