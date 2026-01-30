"""
Main FastAPI application for onboarding service
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import asyncio

from engine_onboarding.api import onboarding_router, credentials_router, schedules_router, health_router
from engine_onboarding.config import settings
from engine_onboarding.database.connection import init_db, check_connection
from engine_onboarding.database import mark_stale_running_executions_as_failed
from engine_onboarding.scheduler.scheduler_service import SchedulerService

# Create FastAPI app
app = FastAPI(
    title="Threat Engine Onboarding API",
    description="API for account onboarding, credential management, and scheduling",
    version="1.0.0"
)

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
app.include_router(onboarding_router)
app.include_router(credentials_router)
app.include_router(schedules_router)

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

        # Clean up stale executions from previous pod restarts
        stale_count = mark_stale_running_executions_as_failed(max_age_minutes=30)
        if stale_count:
            print(f"🧹 Marked {stale_count} stale 'running' executions as failed")
    except Exception as e:
        print(f"❌ Database initialization error: {e}")
        import traceback
        traceback.print_exc()
        return
    
    # Start scheduler as background task
    try:
        scheduler_service = SchedulerService()
        # Start scheduler in background (non-blocking)
        scheduler_task = asyncio.create_task(scheduler_service.start())
        print("✅ Scheduler started as background task")
    except Exception as e:
        print(f"⚠️  Scheduler startup error: {e}")
        import traceback
        traceback.print_exc()


@app.on_event("shutdown")
async def shutdown_event():
    """Stop scheduler on shutdown"""
    global scheduler_service, scheduler_task
    
    if scheduler_service:
        scheduler_service.stop()
        print("✅ Scheduler stopped")
    
    if scheduler_task:
        scheduler_task.cancel()
        try:
            await scheduler_task
        except asyncio.CancelledError:
            pass
        print("✅ Scheduler task cancelled")


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

