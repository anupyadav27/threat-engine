#!/usr/bin/env python3
"""
SBOM Engine - Standalone FastAPI Service for SecOps SBOM Platform

Capabilities:
  - Ingest CycloneDX / SPDX SBOMs from Syft, Trivy, cdxgen
  - Generate CycloneDX 1.5 SBOMs from raw package lists
  - Enrich with vulnerability data (osv_advisory + cves tables)
  - Full component inventory with license tracking
  - VEX (Vulnerability Exploitability eXchange) statements
  - SBOM diff/versioning between scans
  - Compliance reporting with configurable policy engine

Zero dependency on osv_engine or vul_engine — fully standalone.
"""

import sys
sys.path.append("/app")

import uvicorn
import logging
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import sbom, vex, compliance, alerts
from core.config import settings
from core.database import SBOMDatabaseManager
from core.vuln_enricher import VulnEnricher
from core.threat_intel import ThreatIntelProvider
from core.background_monitor import BackgroundMonitor

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("sbom_engine.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger(__name__)
logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

# ── Globals ───────────────────────────────────────────────────────────────────
db_manager:           SBOMDatabaseManager = None
vuln_enricher:        VulnEnricher        = None
threat_intel_provider: ThreatIntelProvider = None
bg_monitor:           BackgroundMonitor   = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global db_manager, vuln_enricher, threat_intel_provider, bg_monitor

    logger.info("Starting SBOM Engine...")
    db_manager = SBOMDatabaseManager()
    await db_manager.initialize()

    # Threat intel provider (EPSS + CISA KEV) — Feature 1
    threat_intel_provider = ThreatIntelProvider(db_manager)

    # Vulnerability enricher with threat intel wired in — Features 1 + 5
    vuln_enricher = VulnEnricher(db_manager, threat_intel=threat_intel_provider)

    # Background CVE watch — Feature 2
    bg_monitor = BackgroundMonitor(db_manager, threat_intel_provider)
    await bg_monitor.start()

    logger.info("SBOM Engine started successfully")

    yield

    logger.info("Shutting down SBOM Engine...")
    if threat_intel_provider:
        await threat_intel_provider.close()
    if db_manager:
        await db_manager.close()


app = FastAPI(
    title="SBOM Engine",
    description=(
        "SecOps SBOM Platform — ingest, generate, enrich and analyse "
        "Software Bill of Materials with CycloneDX 1.5 output."
    ),
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routes ────────────────────────────────────────────────────────────────────
app.include_router(sbom.router,        prefix="/api/v1/sbom",        tags=["SBOM"])
app.include_router(vex.router,         prefix="/api/v1/vex",          tags=["VEX"])
app.include_router(compliance.router,  prefix="/api/v1/compliance",   tags=["Compliance"])
app.include_router(alerts.router,      prefix="/api/v1/alerts",        tags=["Alerts & Threat Intel"])


# ── Health ────────────────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {
        "service":   "SBOM Engine",
        "version":   "1.0.0",
        "status":    "running",
        "timestamp": datetime.utcnow().isoformat(),
        "endpoints": {
            "docs":         "/api/docs",
            "sbom":         "/api/v1/sbom",
            "vex":          "/api/v1/vex",
            "compliance":   "/api/v1/compliance",
            "alerts":       "/api/v1/alerts",
            "threat_intel": "/api/v1/alerts/threat-intel/{cve_id}",
        },
    }


@app.get("/health")
async def health():
    db_ok = await db_manager.check_connection() if db_manager else False
    return {
        "status":    "healthy" if db_ok else "unhealthy",
        "database":  "connected" if db_ok else "disconnected",
        "timestamp": datetime.utcnow().isoformat(),
        "version":   "1.0.0",
    }


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level="info",
        timeout_keep_alive=300,
    )
