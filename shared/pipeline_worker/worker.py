"""
Threat-Engine Pipeline Worker (HTTP)
=====================================

Stateless orchestrator — all state lives in scan_orchestration (PostgreSQL).
orchestration_id is the sole identifier. No pipeline_id, no in-memory state.

    POST /api/v1/pipeline/run  {"orchestration_id": "..."}

Pipeline stages (sequential/parallel):
    discovery → check + inventory (parallel) → threat → compliance + IAM + datasec (parallel)

Each stage is triggered via HTTP to the respective engine service.
Each engine writes its scan_id back to scan_orchestration via update_orchestration_scan_id().

Run
---
    uvicorn shared.pipeline_worker.worker:app --host 0.0.0.0 --port 8050
"""
from __future__ import annotations

import asyncio
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from shared.pipeline_worker import handlers

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
logger = logging.getLogger("pipeline_worker")

app = FastAPI(
    title="Threat Engine Pipeline Worker",
    description="Stateless orchestrator — all state in scan_orchestration (PostgreSQL)",
    version="3.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── DB helpers ───────────────────────────────────────────────────────────────

def _get_orch_conn():
    """Connect to threat_engine_onboarding (scan_orchestration table)."""
    import psycopg2
    return psycopg2.connect(
        host=os.getenv("ONBOARDING_DB_HOST"),
        port=int(os.getenv("ONBOARDING_DB_PORT", "5432")),
        database=os.getenv("ONBOARDING_DB_NAME", "threat_engine_onboarding"),
        user=os.getenv("ONBOARDING_DB_USER", "postgres"),
        password=os.getenv("ONBOARDING_DB_PASSWORD"),
    )


def _update_orchestration(orchestration_id: str, **kwargs) -> None:
    """Update scan_orchestration columns. Only updates provided kwargs."""
    if not kwargs:
        return
    set_clauses = ", ".join(f"{k} = %s" for k in kwargs)
    values = list(kwargs.values()) + [orchestration_id]
    try:
        conn = _get_orch_conn()
        with conn.cursor() as cur:
            cur.execute(
                f"UPDATE scan_orchestration SET {set_clauses} WHERE orchestration_id = %s::uuid",
                values,
            )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning(f"Failed to update orchestration {orchestration_id}: {e}")


def _get_orchestration(orchestration_id: str) -> Optional[Dict[str, Any]]:
    """Read full scan_orchestration row."""
    try:
        conn = _get_orch_conn()
        from psycopg2.extras import RealDictCursor
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM scan_orchestration WHERE orchestration_id = %s::uuid",
                (orchestration_id,),
            )
            row = cur.fetchone()
        conn.close()
        return dict(row) if row else None
    except Exception as e:
        logger.error(f"Failed to read orchestration {orchestration_id}: {e}")
        return None


def _add_engine_completed(orchestration_id: str, engine: str) -> None:
    """Append engine name to engines_completed JSONB array."""
    try:
        conn = _get_orch_conn()
        with conn.cursor() as cur:
            cur.execute(
                """UPDATE scan_orchestration
                   SET engines_completed = COALESCE(engines_completed, '[]'::jsonb) || %s::jsonb
                   WHERE orchestration_id = %s::uuid""",
                (f'["{engine}"]', orchestration_id),
            )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning(f"Failed to add {engine} to engines_completed: {e}")


# ── Models ───────────────────────────────────────────────────────────────────

class PipelineRequest(BaseModel):
    orchestration_id: str


class PipelineResponse(BaseModel):
    orchestration_id: str
    status: str
    message: str


# ── Pipeline runner ──────────────────────────────────────────────────────────


async def run_pipeline(orchestration_id: str) -> None:
    """Execute the full pipeline for one scan.

    All state is read/written to scan_orchestration in PostgreSQL.
    This function is stateless — safe to run from any worker replica.

    Stages:
      0. discovery
      1. check + inventory  (parallel)
      2. threat             (needs check_scan_id)
      3. compliance + iam + datasec  (parallel)
    """
    _update_orchestration(orchestration_id, overall_status="running")

    # ── Stage 0: Discovery ────────────────────────────────────────────
    logger.info("[%s] Stage 0: discovery", orchestration_id[:8])
    try:
        resp = await handlers.trigger_discovery(orchestration_id)
        disc_scan_id = resp.get("discovery_scan_id", "")
        logger.info("[%s] discovery complete scan_id=%s", orchestration_id[:8], disc_scan_id)
        _add_engine_completed(orchestration_id, "discovery")
    except Exception as exc:
        logger.error("[%s] discovery FAILED: %s", orchestration_id[:8], exc)
        _update_orchestration(
            orchestration_id,
            overall_status="failed",
            error_details=f'{{"stage": "discovery", "error": "{exc}"}}',
            completed_at=datetime.now(timezone.utc),
        )
        return

    # ── Stage 1: Check + Inventory (parallel) ─────────────────────────
    logger.info("[%s] Stage 1: check + inventory", orchestration_id[:8])
    stage1_results = await asyncio.gather(
        handlers.trigger_check(orchestration_id),
        handlers.trigger_inventory(orchestration_id),
        return_exceptions=True,
    )

    check_result = stage1_results[0]
    if isinstance(check_result, Exception):
        logger.error("[%s] check FAILED: %s", orchestration_id[:8], check_result)
    else:
        logger.info("[%s] check complete scan_id=%s", orchestration_id[:8],
                    check_result.get("check_scan_id"))
        _add_engine_completed(orchestration_id, "check")

    inv_result = stage1_results[1]
    if isinstance(inv_result, Exception):
        logger.error("[%s] inventory FAILED: %s", orchestration_id[:8], inv_result)
    else:
        logger.info("[%s] inventory complete scan_id=%s", orchestration_id[:8],
                    inv_result.get("inventory_scan_id"))
        _add_engine_completed(orchestration_id, "inventory")

    # If check failed, we can't run threat/compliance — abort
    if isinstance(check_result, Exception):
        _update_orchestration(
            orchestration_id,
            overall_status="failed",
            error_details=f'{{"stage": "check", "error": "{check_result}"}}',
            completed_at=datetime.now(timezone.utc),
        )
        return

    # ── Stage 2: Threat ───────────────────────────────────────────────
    logger.info("[%s] Stage 2: threat", orchestration_id[:8])
    try:
        resp = await handlers.trigger_threat(orchestration_id)
        logger.info("[%s] threat complete scan_id=%s", orchestration_id[:8],
                    resp.get("threat_scan_id"))
        _add_engine_completed(orchestration_id, "threat")
    except Exception as exc:
        logger.error("[%s] threat FAILED: %s", orchestration_id[:8], exc)
        # Continue to compliance anyway — it only needs check_scan_id

    # ── Stage 3: Compliance + IAM + DataSec (parallel) ────────────────
    logger.info("[%s] Stage 3: compliance + iam + datasec", orchestration_id[:8])

    # Read orchestration to get provider for iam/datasec
    orch = _get_orchestration(orchestration_id)
    provider = (orch or {}).get("provider", "aws")

    stage3_results = await asyncio.gather(
        handlers.trigger_compliance(orchestration_id),
        handlers.trigger_iam(orchestration_id, csp=provider),
        handlers.trigger_datasec(orchestration_id, csp=provider),
        return_exceptions=True,
    )

    stage3_names = ["compliance", "iam", "datasec"]
    for name, result in zip(stage3_names, stage3_results):
        if isinstance(result, Exception):
            logger.error("[%s] %s FAILED: %s", orchestration_id[:8], name, result)
        else:
            logger.info("[%s] %s complete scan_id=%s", orchestration_id[:8], name,
                        result.get(f"{name}_scan_id"))
            _add_engine_completed(orchestration_id, name)

    # ── Done ──────────────────────────────────────────────────────────
    _update_orchestration(
        orchestration_id,
        overall_status="completed",
        completed_at=datetime.now(timezone.utc),
    )
    logger.info("[%s] pipeline COMPLETE", orchestration_id[:8])


# ── API Endpoints ────────────────────────────────────────────────────────────


@app.post("/api/v1/pipeline/run", response_model=PipelineResponse)
async def trigger_pipeline(request: PipelineRequest):
    """Trigger the full scan pipeline. Runs in background, returns immediately.

    orchestration_id must already exist in scan_orchestration table
    (created by onboarding engine).
    """
    orch = _get_orchestration(request.orchestration_id)
    if not orch:
        raise HTTPException(
            status_code=404,
            detail=f"orchestration_id {request.orchestration_id} not found in scan_orchestration",
        )

    if orch.get("overall_status") == "running":
        raise HTTPException(
            status_code=409,
            detail=f"Scan {request.orchestration_id} is already running",
        )

    asyncio.create_task(run_pipeline(request.orchestration_id))

    return PipelineResponse(
        orchestration_id=request.orchestration_id,
        status="running",
        message="Pipeline started — discovery → check+inventory → threat → compliance+iam+datasec",
    )


@app.get("/api/v1/pipeline/{orchestration_id}")
async def get_pipeline_status(orchestration_id: str):
    """Get pipeline status from scan_orchestration table."""
    orch = _get_orchestration(orchestration_id)
    if not orch:
        raise HTTPException(status_code=404, detail="Orchestration not found")

    return {
        "orchestration_id": str(orch["orchestration_id"]),
        "overall_status": orch.get("overall_status"),
        "engines_requested": orch.get("engines_requested"),
        "engines_completed": orch.get("engines_completed"),
        "discovery_scan_id": orch.get("discovery_scan_id"),
        "check_scan_id": orch.get("check_scan_id"),
        "inventory_scan_id": orch.get("inventory_scan_id"),
        "threat_scan_id": orch.get("threat_scan_id"),
        "compliance_scan_id": orch.get("compliance_scan_id"),
        "iam_scan_id": orch.get("iam_scan_id"),
        "datasec_scan_id": orch.get("datasec_scan_id"),
        "started_at": str(orch.get("started_at")) if orch.get("started_at") else None,
        "completed_at": str(orch.get("completed_at")) if orch.get("completed_at") else None,
        "error_details": orch.get("error_details"),
    }


@app.get("/api/v1/pipeline/list")
async def list_pipelines():
    """List recent orchestrations from scan_orchestration table."""
    try:
        conn = _get_orch_conn()
        from psycopg2.extras import RealDictCursor
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """SELECT orchestration_id, overall_status, engines_completed,
                          started_at, completed_at
                   FROM scan_orchestration
                   ORDER BY created_at DESC LIMIT 20"""
            )
            rows = cur.fetchall()
        conn.close()
        return [
            {
                "orchestration_id": str(r["orchestration_id"]),
                "status": r["overall_status"],
                "engines_completed": r.get("engines_completed"),
                "started_at": str(r["started_at"]) if r.get("started_at") else None,
                "completed_at": str(r["completed_at"]) if r.get("completed_at") else None,
            }
            for r in rows
        ]
    except Exception as e:
        logger.error(f"Failed to list pipelines: {e}")
        return []


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/api/v1/health/live")
async def liveness():
    return {"status": "alive"}


@app.get("/api/v1/health/ready")
async def readiness():
    return {"status": "ready"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8050)
