"""
tech-check FastAPI app — Port 8032
GET  /api/v1/findings/{scan_run_id}      → list check findings
GET  /api/v1/findings/summary            → PASS/FAIL counts per rule
GET  /api/v1/tech/catalog/{tech_type}    → merged discovery + check rules for agent
POST /api/v1/tech/findings               → receive agent findings (upsert)
GET  /api/v1/health/live
GET  /api/v1/health/ready
"""
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(__file__))

import yaml
from fastapi import FastAPI, Header, HTTPException, Query
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# Catalog root is resolved relative to repo root at runtime.
# In Docker the repo is mounted at /catalog or passed via CATALOG_ROOT env.
_CATALOG_ROOT = Path(os.getenv("CATALOG_ROOT", str(
    Path(__file__).resolve().parent.parent.parent.parent.parent / "catalog"
)))

app = FastAPI(title="tech-check", version="1.0.0")


@app.get("/api/v1/health/live")
def live():
    return {"status": "ok"}


@app.get("/api/v1/health/ready")
def ready():
    return {"status": "ok"}


@app.get("/api/v1/findings/{scan_run_id}")
async def get_findings(
    scan_run_id: str,
    tenant_id:   str = Query(...),
    status:      Optional[str] = Query(None, description="PASS|FAIL|ERROR"),
):
    from common.database.tech_db_manager import TechDBManager
    db = TechDBManager()
    findings = db.list_check_findings(
        scan_run_id=scan_run_id, tenant_id=tenant_id, status=status
    )
    fail_count = sum(1 for f in findings if f.get("status") == "FAIL")
    return {
        "scan_run_id": scan_run_id,
        "total":       len(findings),
        "fail_count":  fail_count,
        "pass_count":  len(findings) - fail_count,
        "findings":    findings,
    }


# ── Agent endpoints ───────────────────────────────────────────────────────────


@app.get("/api/v1/tech/catalog/{tech_type}")
async def get_tech_catalog(tech_type: str) -> Dict[str, Any]:
    """Return merged discovery entries and check rules for a tech_type.

    Used by the tech-scan-agent running on a target host to fetch its catalog
    before running local discovery and rule evaluation.  No auth required
    (internal network endpoint — reachable only from within the cluster).

    Args:
        tech_type: Technology identifier, e.g. ``postgresql``, ``ubuntu``.

    Returns:
        JSON with keys ``tech_type``, ``discovery_entries``, ``check_rules``.
    """
    discovery_entries = _load_discovery_yamls(tech_type)
    check_rules = _load_rule_yamls(tech_type)

    if not discovery_entries and not check_rules:
        raise HTTPException(
            status_code=404,
            detail=f"No catalog data found for tech_type={tech_type!r}",
        )

    return {
        "tech_type": tech_type,
        "discovery_entries": discovery_entries,
        "check_rules": check_rules,
    }


def _load_discovery_yamls(tech_type: str) -> List[Dict[str, Any]]:
    """Glob step6_section_*.discovery.yaml files for *tech_type*.

    Args:
        tech_type: Technology identifier string.

    Returns:
        Merged list of discovery entry dicts.
    """
    entries: List[Dict[str, Any]] = []
    discovery_root = _CATALOG_ROOT / "discovery_generator_data"

    # Prefer per-section files; fall back to legacy single file
    files = sorted(discovery_root.glob(f"*/{tech_type}/step6_section_*.discovery.yaml"))
    if not files:
        files = sorted(discovery_root.glob(f"*/{tech_type}/step6_discovery.yaml"))

    for path in files:
        try:
            with path.open() as fh:
                doc = yaml.safe_load(fh) or {}
            entries.extend(doc.get("discovery", []))
        except Exception as exc:
            logger.warning("Failed to load discovery YAML %s: %s", path, exc)

    return entries


def _load_rule_yamls(tech_type: str) -> List[Dict[str, Any]]:
    """Glob *_cis_section_*.rules.yaml files for *tech_type*.

    Args:
        tech_type: Technology identifier string.

    Returns:
        Merged list of rule dicts.
    """
    rules: List[Dict[str, Any]] = []
    rule_root = _CATALOG_ROOT / "rule"

    files = sorted(rule_root.glob(f"*_rule_check/{tech_type}/*_cis_section_*.rules.yaml"))
    for path in files:
        try:
            with path.open() as fh:
                doc = yaml.safe_load(fh) or {}
            rules.extend(doc.get("rules", []))
        except Exception as exc:
            logger.warning("Failed to load rule YAML %s: %s", path, exc)

    return rules


# ── Agent findings ingestion ──────────────────────────────────────────────────


class AgentFinding(BaseModel):
    """One finding from the tech-scan-agent."""

    finding_id: str
    rule_id: str
    status: str
    severity: str = "medium"
    evidence: Dict[str, Any] = {}
    resource_uid: str
    resource_type: str
    rule_title: str = ""
    remediation: str = ""
    cis_benchmark: str = ""


class AgentFindingsRequest(BaseModel):
    """Request body for POST /api/v1/tech/findings."""

    scan_run_id: str
    account_id: str
    tenant_id: str
    findings: List[AgentFinding]


@app.post("/api/v1/tech/findings")
async def ingest_agent_findings(
    body: AgentFindingsRequest,
    authorization: Optional[str] = Header(None),
) -> Dict[str, Any]:
    """Receive and upsert findings pushed by the tech-scan-agent.

    Requires a non-empty ``Authorization: Bearer <token>`` header.
    Full JWT validation is deferred to Sprint 11.

    Args:
        body: JSON payload with scan_run_id, account_id, tenant_id, findings.
        authorization: Bearer token header.

    Returns:
        JSON ``{"inserted": N}`` where N is the number of upserted rows.

    Raises:
        HTTPException 401: When Authorization header is missing or empty.
        HTTPException 422: On Pydantic validation failure (auto).
    """
    if not authorization or not authorization.strip():
        raise HTTPException(status_code=401, detail="Authorization header required")

    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(status_code=401, detail="Bearer token must be non-empty")

    rows = [
        {
            "finding_id":      f.finding_id,
            "scan_run_id":     body.scan_run_id,
            "tenant_id":       body.tenant_id,
            "account_id":      body.account_id,
            "credential_ref":  None,
            "credential_type": "agent",
            "provider":        f.resource_type,
            "tech_category":   f.resource_type,
            "region":          None,
            "resource_uid":    f.resource_uid,
            "resource_type":   f.resource_type,
            "rule_id":         f.rule_id,
            "rule_title":      f.rule_title,
            "cis_benchmark":   f.cis_benchmark,
            "severity":        f.severity,
            "status":          f.status,
            "evidence":        f.evidence,
            "framework_mappings": {},
            "remediation":     f.remediation,
        }
        for f in body.findings
    ]

    from common.database.tech_db_manager import TechDBManager
    db = TechDBManager()
    inserted = db.upsert_check_findings(rows)
    db.mark_engine_completed(
        scan_run_id=body.scan_run_id,
        engine="tech-agent",
        count=inserted,
    )

    logger.info(
        "Ingested %d agent findings for scan_run_id=%s account_id=%s",
        inserted, body.scan_run_id, body.account_id,
    )
    return {"inserted": inserted}
