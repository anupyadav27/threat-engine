"""
SAST Router — Static Application Security Testing.

Extracted from api_server.py.  All endpoints are relative to the router
prefix (set by the main app as /api/v1/secops/sast).
"""

import json
import logging
import os
import shutil
import subprocess
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from scan_local import scan_path
from scanner_plugin import get_supported_languages

logger = logging.getLogger("secops.sast")

# Folders (shared with main app)
INPUT_FOLDER = os.getenv("SCAN_INPUT_PATH", "/app/scan_input")
OUTPUT_FOLDER = os.getenv("SCAN_OUTPUT_PATH", "/app/scan_output")

# In-memory scan status cache
_scan_status: dict = {}

router = APIRouter()


# ── Models ───────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    """Request to scan a git repository."""
    tenant_id: str = Field(..., description="Tenant identifier")
    repo_url: str = Field(..., description="Git clone URL")
    branch: str = Field(default="main", description="Branch to scan")
    customer_id: Optional[str] = Field(default=None, description="Customer identifier")
    scan_run_id: Optional[str] = Field(default=None, description="Pipeline-wide scan_run_id")
    languages: Optional[List[str]] = Field(default=None, description="Filter to specific languages (null = scan all)")


class ScanResponse(BaseModel):
    secops_scan_id: str
    scan_run_id: Optional[str] = None
    tenant_id: str
    project_name: str
    status: str
    summary: Optional[dict] = None
    findings_count: int = 0


# ── Helpers ──────────────────────────────────────────────────────────────────

def _project_name_from_url(repo_url: str) -> str:
    name = repo_url.rstrip("/").split("/")[-1]
    if name.endswith(".git"):
        name = name[:-4]
    return name


def _clone_repo(repo_url: str, branch: str, dest: str) -> None:
    if os.path.exists(dest):
        shutil.rmtree(dest)
    cmd = [
        "git", "clone", "--depth", "1",
        "--branch", branch, "--single-branch",
        repo_url, dest,
    ]
    logger.info(f"Cloning {repo_url} branch={branch} -> {dest}")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if result.returncode != 0:
        raise RuntimeError(f"git clone failed: {result.stderr.strip()}")
    logger.info(f"Clone complete: {dest}")


def _run_scan_and_persist(
    secops_scan_id: str,
    tenant_id: str,
    customer_id: Optional[str],
    orchestration_id: Optional[str],
    project_name: str,
    repo_url: str,
    branch: str,
    input_path: str,
) -> dict:
    from database.secops_db_writer import (
        persist_scan_report,
        complete_scan_report,
        persist_findings,
    )

    persist_scan_report(
        secops_scan_id=secops_scan_id,
        tenant_id=tenant_id,
        project_name=project_name,
        repo_url=repo_url,
        branch=branch,
        status="running",
        customer_id=customer_id,
        orchestration_id=orchestration_id,
    )
    _scan_status[secops_scan_id] = {"status": "running", "started_at": datetime.now(timezone.utc).isoformat()}

    try:
        logger.info(f"[{secops_scan_id}] Scanning {input_path}")
        scan_result = scan_path(input_path)

        results = scan_result.get("results", [])
        errors = scan_result.get("errors", [])

        total_files = len(results)
        total_findings = sum(len(r.get("findings", [])) for r in results)
        total_errors = len(errors)
        languages_detected = list(set(r.get("language", "unknown") for r in results))

        findings_inserted = persist_findings(
            secops_scan_id=secops_scan_id,
            tenant_id=tenant_id,
            scan_results=results,
            repo_base_path=input_path,
            customer_id=customer_id,
        )

        output_dir = os.path.join(OUTPUT_FOLDER, tenant_id, project_name, secops_scan_id)
        os.makedirs(output_dir, exist_ok=True)
        report = {
            "secops_scan_id": secops_scan_id,
            "tenant_id": tenant_id,
            "project_name": project_name,
            "repo_url": repo_url,
            "branch": branch,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "files_scanned": total_files,
                "total_findings": total_findings,
                "total_errors": total_errors,
                "findings_persisted": findings_inserted,
                "languages": languages_detected,
            },
            "scan_data": scan_result,
        }
        with open(os.path.join(output_dir, "secops_report.json"), "w") as f:
            json.dump(report, f, indent=2, default=str)

        summary = {
            "files_scanned": total_files,
            "total_findings": total_findings,
            "total_errors": total_errors,
            "findings_persisted": findings_inserted,
            "languages": languages_detected,
        }

        complete_scan_report(
            secops_scan_id=secops_scan_id,
            status="completed",
            files_scanned=total_files,
            total_findings=total_findings,
            total_errors=total_errors,
            languages_detected=languages_detected,
            summary=summary,
        )

        _scan_status[secops_scan_id] = {"status": "completed", "summary": summary}
        logger.info(f"[{secops_scan_id}] Scan complete: {total_findings} findings in {total_files} files")
        return summary

    except Exception as e:
        logger.error(f"[{secops_scan_id}] Scan failed: {e}", exc_info=True)
        try:
            complete_scan_report(
                secops_scan_id=secops_scan_id,
                status="failed",
                files_scanned=0,
                total_findings=0,
                total_errors=1,
                languages_detected=[],
                summary={"error": str(e)},
            )
        except Exception:
            pass
        _scan_status[secops_scan_id] = {"status": "failed", "error": str(e)}
        raise


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.post("/scan", response_model=ScanResponse)
async def scan_repo(request: ScanRequest):
    """Clone a git repo and scan for SAST vulnerabilities."""
    secops_scan_id = str(uuid.uuid4())
    project_name = _project_name_from_url(request.repo_url)
    input_path = os.path.join(INPUT_FOLDER, project_name)

    try:
        _clone_repo(request.repo_url, request.branch, input_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to clone repo: {e}")

    try:
        summary = _run_scan_and_persist(
            secops_scan_id=secops_scan_id,
            tenant_id=request.tenant_id,
            customer_id=request.customer_id,
            orchestration_id=request.scan_run_id,
            project_name=project_name,
            repo_url=request.repo_url,
            branch=request.branch,
            input_path=input_path,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {e}")
    finally:
        try:
            shutil.rmtree(input_path, ignore_errors=True)
        except Exception:
            pass

    return ScanResponse(
        secops_scan_id=secops_scan_id,
        scan_run_id=request.scan_run_id,
        tenant_id=request.tenant_id,
        project_name=project_name,
        status="completed",
        summary=summary,
        findings_count=summary.get("total_findings", 0),
    )


@router.get("/scan/{secops_scan_id}/status")
async def get_scan_status(secops_scan_id: str):
    """Poll SAST scan status."""
    if secops_scan_id in _scan_status:
        return {"secops_scan_id": secops_scan_id, **_scan_status[secops_scan_id]}

    try:
        from database.db_config import get_dict_connection
        conn = get_dict_connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT secops_scan_id, status, files_scanned, total_findings, "
                    "total_errors, summary FROM secops_report WHERE secops_scan_id = %s",
                    (secops_scan_id,),
                )
                row = cur.fetchone()
                if not row:
                    raise HTTPException(status_code=404, detail="Scan not found")
                return dict(row)
        finally:
            conn.close()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scan/{secops_scan_id}/findings")
async def get_scan_findings(
    secops_scan_id: str,
    severity: Optional[str] = Query(None, description="Filter by severity"),
    language: Optional[str] = Query(None, description="Filter by language"),
    limit: int = Query(500, description="Max findings to return"),
):
    """Get SAST findings for a scan from DB."""
    try:
        from database.db_config import get_dict_connection
        conn = get_dict_connection()
        try:
            with conn.cursor() as cur:
                query = """
                    SELECT id, secops_scan_id, file_path, language, rule_id,
                           severity, message, line_number, status, resource, metadata
                    FROM secops_findings
                    WHERE secops_scan_id = %s
                """
                params: list = [secops_scan_id]

                if severity:
                    query += " AND severity = %s"
                    params.append(severity.lower())
                if language:
                    query += " AND language = %s"
                    params.append(language.lower())

                query += " ORDER BY severity DESC, file_path, line_number LIMIT %s"
                params.append(limit)

                cur.execute(query, params)
                findings = [dict(r) for r in cur.fetchall()]

                return {
                    "secops_scan_id": secops_scan_id,
                    "total": len(findings),
                    "findings": findings,
                }
        finally:
            conn.close()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scans")
async def list_scans(
    tenant_id: str = Query(..., description="Tenant ID"),
    project_name: Optional[str] = Query(None, description="Filter by project/repo name"),
    limit: int = Query(50, description="Max scans to return"),
):
    """List SAST scans for a tenant."""
    try:
        from database.db_config import get_dict_connection
        conn = get_dict_connection()
        try:
            with conn.cursor() as cur:
                query = """
                    SELECT secops_scan_id, orchestration_id, tenant_id, project_name,
                           repo_url, branch, status, scan_timestamp, completed_at,
                           files_scanned, total_findings, total_errors, languages_detected
                    FROM secops_report
                    WHERE tenant_id = %s AND (scan_type IS NULL OR scan_type = 'sast')
                """
                params: list = [tenant_id]

                if project_name:
                    query += " AND project_name = %s"
                    params.append(project_name)

                query += " ORDER BY scan_timestamp DESC LIMIT %s"
                params.append(limit)

                cur.execute(query, params)
                scans = []
                for row in cur.fetchall():
                    d = dict(row)
                    for k in ("scan_timestamp", "completed_at"):
                        if d.get(k) and hasattr(d[k], "isoformat"):
                            d[k] = d[k].isoformat()
                    scans.append(d)

                return {"tenant_id": tenant_id, "total": len(scans), "scans": scans}
        finally:
            conn.close()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/rules/stats")
async def rule_stats():
    """Get SAST rule metadata statistics from DB."""
    try:
        from database.rule_metadata_loader import get_rule_stats
        return get_rule_stats()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/rules/sync")
async def sync_rules():
    """Trigger incremental SAST rule metadata sync from docs folders into DB."""
    try:
        from database.rule_metadata_loader import seed_all_rules
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        totals = seed_all_rules(base_dir)
        return {"status": "synced", "total_rules": sum(totals.values()), "by_scanner": totals}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
