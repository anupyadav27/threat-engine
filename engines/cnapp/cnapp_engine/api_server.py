"""
CNAPP Engine — Unified Cloud-Native Application Protection Platform API.
Port: 8015

This engine is a pure aggregation layer — it has no database of its own.
It calls sibling engine APIs to collect data for each CNAPP pillar and
returns a unified posture view.

CNAPP Pillars covered:
  CSPM    — Cloud Security Posture Management   (check + compliance engines)
  CIEM    — Cloud Identity & Entitlement Mgmt   (ciem + iam engines)
  CWPP    — Cloud Workload Protection Platform  (container-sec + vul_engine)
  DSPM    — Data Security Posture Management    (datasec engine)
  Network — Network Security (7-layer)          (network-security engine)
  Threat  — Threat Detection & Attack Paths     (threat engine)
  AppSec  — Application Security (shift-left)   (secops engine)

Endpoints:
  GET /api/v1/cnapp/dashboard          — full unified dashboard (all pillars)
  GET /api/v1/cnapp/pillars/{pillar}   — single pillar data
  GET /api/v1/cnapp/posture            — CNAPP posture score only (fast)
  GET /api/v1/health/live
  GET /api/v1/health/ready
  GET /api/v1/health
"""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from .pillars import cspm, ciem, cwpp, dspm, network, threat, appsec
from .core.aggregator import compute_cnapp_score, risk_band

try:
    import sys as _sys
    _sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "shared"))
    from engine_common.telemetry import configure_telemetry
    from engine_common.middleware import RequestLoggingMiddleware, CorrelationIDMiddleware
except ImportError:
    configure_telemetry = None
    RequestLoggingMiddleware = None
    CorrelationIDMiddleware = None

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("cnapp.api_server")

app = FastAPI(
    title="CNAPP Engine API",
    description=(
        "Cloud-Native Application Protection Platform — unified posture across "
        "CSPM, CIEM, CWPP, DSPM, Network Security, Threat Detection, and AppSec."
    ),
    version="1.0.0",
)

if configure_telemetry:
    configure_telemetry("engine-cnapp", app)
if CorrelationIDMiddleware:
    app.add_middleware(CorrelationIDMiddleware)
if RequestLoggingMiddleware:
    app.add_middleware(RequestLoggingMiddleware, engine_name="engine-cnapp")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Pillar registry ───────────────────────────────────────────────────────────

PILLARS = {
    "cspm":    cspm.fetch,
    "ciem":    ciem.fetch,
    "cwpp":    cwpp.fetch,
    "dspm":    dspm.fetch,
    "network": network.fetch,
    "threat":  threat.fetch,
    "appsec":  appsec.fetch,
}

PILLAR_META = {
    "cspm":    {"name": "Cloud Security Posture Management", "engines": ["check", "compliance"]},
    "ciem":    {"name": "Cloud Identity & Entitlement Management", "engines": ["ciem", "iam"]},
    "cwpp":    {"name": "Cloud Workload Protection Platform", "engines": ["container-sec", "vul-engine"]},
    "dspm":    {"name": "Data Security Posture Management", "engines": ["datasec"]},
    "network": {"name": "Network Security (7-layer)", "engines": ["network-security"]},
    "threat":  {"name": "Threat Detection & Attack Paths", "engines": ["threat"]},
    "appsec":  {"name": "Application Security (Shift-Left)", "engines": ["secops"]},
}


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/")
@app.get("/health")
async def root():
    return {
        "service": "engine-cnapp",
        "version": "1.0.0",
        "pillars": list(PILLARS.keys()),
        "status": "operational",
    }


@app.get("/api/v1/health/live")
async def liveness():
    return {"status": "alive"}


@app.get("/api/v1/health/ready")
async def readiness():
    # CNAPP has no own DB — just check that we can start coroutines
    return {"status": "ready", "note": "no local DB — aggregation only"}


@app.get("/api/v1/health")
async def health():
    return {
        "status": "healthy",
        "service": "engine-cnapp",
        "version": "1.0.0",
        "pillars": list(PILLARS.keys()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ── Main dashboard ────────────────────────────────────────────────────────────

@app.get("/api/v1/cnapp/dashboard")
async def dashboard(
    scan_run_id: str = Query(..., description="scan_run_id to scope all pillar queries"),
    tenant_id: str = Query(default="default-tenant"),
    pillars: Optional[str] = Query(
        default=None,
        description="Comma-separated pillar names to include (default: all)",
    ),
):
    """
    Fetch all CNAPP pillar data concurrently and return a unified dashboard.

    All pillar calls run in parallel. Unavailable engines are gracefully
    skipped — their pillar returns status='unavailable' with null score.
    """
    requested = (
        [p.strip() for p in pillars.split(",") if p.strip() in PILLARS]
        if pillars
        else list(PILLARS.keys())
    )

    tasks = [PILLARS[p](scan_run_id, tenant_id) for p in requested]
    results: List[Dict[str, Any]] = await asyncio.gather(*tasks)

    cnapp_score = compute_cnapp_score(results)
    band = risk_band(cnapp_score)

    available = [r for r in results if r.get("status") == "ok"]
    unavailable = [r for r in results if r.get("status") == "unavailable"]
    no_data = [r for r in results if r.get("status") == "no_data"]
    available_count = len(available)
    total_count = len(requested)
    scoring_note = (
        f"Score based on {available_count} of {total_count} pillars"
        if available_count < total_count
        else "Score based on all pillars"
    )

    return {
        "scan_run_id": scan_run_id,
        "tenant_id": tenant_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "cnapp_posture_score": cnapp_score,
        "overall_score": cnapp_score,
        "risk_band": band,
        "available_pillars": available_count,
        "total_pillars": total_count,
        "scoring_note": scoring_note,
        "pillars_requested": requested,
        "pillars_available": [r["pillar"] for r in available],
        "pillars_unavailable": [r["pillar"] for r in unavailable],
        "pillars_no_data": [r["pillar"] for r in no_data],
        "pillars": {r["pillar"]: r for r in results},
    }


# ── Single pillar ─────────────────────────────────────────────────────────────

@app.get("/api/v1/cnapp/pillars/{pillar_name}")
async def get_pillar(
    pillar_name: str,
    scan_run_id: str = Query(...),
    tenant_id: str = Query(default="default-tenant"),
):
    """Fetch data for a single CNAPP pillar."""
    if pillar_name not in PILLARS:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown pillar '{pillar_name}'. Valid: {list(PILLARS.keys())}",
        )
    result = await PILLARS[pillar_name](scan_run_id, tenant_id)
    meta = PILLAR_META.get(pillar_name, {})
    return {**result, "meta": meta}


# ── Posture score only (fast) ─────────────────────────────────────────────────

@app.get("/api/v1/cnapp/posture")
async def posture_score(
    scan_run_id: str = Query(...),
    tenant_id: str = Query(default="default-tenant"),
):
    """
    Returns only the CNAPP posture score (all pillars, parallel).
    Faster than /dashboard because it only extracts scores, not full data.
    """
    tasks = [fn(scan_run_id, tenant_id) for fn in PILLARS.values()]
    results = await asyncio.gather(*tasks)

    cnapp_score = compute_cnapp_score(results)
    band = risk_band(cnapp_score)

    available_count = len([r for r in results if r.get("status") == "ok"])
    total_count = len(results)
    scoring_note = (
        f"Score based on {available_count} of {total_count} pillars"
        if available_count < total_count
        else "Score based on all pillars"
    )

    return {
        "scan_run_id": scan_run_id,
        "cnapp_posture_score": cnapp_score,
        "overall_score": cnapp_score,
        "risk_band": band,
        "available_pillars": available_count,
        "total_pillars": total_count,
        "scoring_note": scoring_note,
        "pillars_no_data": [r["pillar"] for r in results if r.get("status") == "no_data"],
        "pillars": {
            r["pillar"]: {
                "score": r.get("posture_score"),
                "status": r.get("status"),
                "reason": r.get("reason"),
            }
            for r in results
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


# ── Pillar catalog ────────────────────────────────────────────────────────────

@app.get("/api/v1/cnapp/pillars")
async def list_pillars():
    """List all CNAPP pillars with metadata about which engines they call."""
    return {
        "pillars": [
            {
                "id": pid,
                "name": meta["name"],
                "engines": meta["engines"],
                "endpoint": f"/api/v1/cnapp/pillars/{pid}",
            }
            for pid, meta in PILLAR_META.items()
        ]
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("CNAPP_PORT", "8015"))
    uvicorn.run(app, host="0.0.0.0", port=port)
