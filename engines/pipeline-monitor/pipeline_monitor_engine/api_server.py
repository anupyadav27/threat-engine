"""
Pipeline Monitor Engine — API server.

Exposes:
  /api/v1/pipeline/*       real-time scan status + SSE stream + history
  /api/v1/admin/logs/*     CloudWatch Insights queries for admin portal
  /api/v1/health/*         liveness + readiness probes
"""

import logging
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api.status_router import router as status_router
from .api.logs_router import router as logs_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-8s] %(name)s %(message)s",
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Pipeline Monitor",
    description="Real-time scan pipeline status and CloudWatch log analysis",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

app.include_router(status_router)
app.include_router(logs_router)


@app.get("/api/v1/health/live")
def liveness():
    return {"status": "ok"}


@app.get("/api/v1/health/ready")
def readiness():
    """Check DB connectivity for readiness."""
    try:
        from engine_common.db_connections import get_discoveries_conn
        conn = get_discoveries_conn()
        conn.close()
        return {"status": "ready"}
    except Exception as e:
        from fastapi import Response
        logger.warning("Readiness check failed: %s", e)
        return Response(
            content='{"status":"not_ready","error":"' + str(e)[:100] + '"}',
            status_code=503,
            media_type="application/json",
        )


@app.get("/api/v1/metrics")
def metrics():
    return {"engine": "pipeline-monitor", "status": "ok"}


@app.on_event("startup")
async def startup():
    logger.info("Pipeline Monitor started on port %s", os.getenv("PORT", "8012"))
