"""
SecOps Scanner API — FastAPI server for code security scanning.

Endpoints:
  POST /api/v1/secops/scan              — Clone repo + scan + persist to DB
  GET  /api/v1/secops/scan/{id}/status  — Poll scan status
  GET  /api/v1/secops/scan/{id}/findings — Get findings from DB
  GET  /api/v1/secops/scans             — List scans for tenant
  GET  /api/v1/secops/rules/stats       — Rule metadata statistics
  POST /api/v1/secops/rules/sync        — Incremental rule sync
  GET  /health                          — Health check

Legacy (backward compat):
  POST /scan                            — Scan pre-staged project folder
  GET  /results/{project_name}          — Get latest local results
"""

import logging
import os
import json
import shutil
import subprocess
import uuid
from datetime import datetime
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from scan_local import scan_path
from scanner_plugin import get_supported_languages

logger = logging.getLogger("secops")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

# Folders
INPUT_FOLDER = os.getenv("SCAN_INPUT_PATH", "/app/scan_input")
OUTPUT_FOLDER = os.getenv("SCAN_OUTPUT_PATH", "/app/scan_output")
os.makedirs(INPUT_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

# In-memory scan status cache (for status polling between DB writes)
_scan_status: dict = {}

app = FastAPI(
    title="SecOps Scanner Engine API",
    description="Multi-language code security scanner — 14 languages, ~2,900 rules",
    version="3.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==================== Models ====================

class ScanRequest(BaseModel):
    """Request to scan a git repository."""
    tenant_id: str = Field(..., description="Tenant identifier")
    repo_url: str = Field(..., description="Git clone URL")
    branch: str = Field(default="main", description="Branch to scan")
    customer_id: Optional[str] = Field(default=None, description="Customer identifier")
    orchestration_id: Optional[str] = Field(default=None, description="Pipeline-wide orchestration ID")
    languages: Optional[List[str]] = Field(default=None, description="Filter to specific languages (null = scan all)")


class ScanResponse(BaseModel):
    secops_scan_id: str
    orchestration_id: Optional[str] = None
    tenant_id: str
    project_name: str
    status: str
    summary: Optional[dict] = None
    findings_count: int = 0


class LegacyScanRequest(BaseModel):
    """Backward-compatible: scan from pre-staged input folder."""
    project_name: str
    save_results: Optional[bool] = True
    fail_on_findings: Optional[bool] = False


# ==================== Helpers ====================

def _project_name_from_url(repo_url: str) -> str:
    """Extract project name from git URL: https://github.com/org/repo.git -> repo"""
    name = repo_url.rstrip("/").split("/")[-1]
    if name.endswith(".git"):
        name = name[:-4]
    return name


def _clone_repo(repo_url: str, branch: str, dest: str) -> None:
    """Git clone --depth 1 into dest directory."""
    if os.path.exists(dest):
        shutil.rmtree(dest)

    cmd = [
        "git", "clone",
        "--depth", "1",
        "--branch", branch,
        "--single-branch",
        repo_url,
        dest,
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
    """Execute scan, persist to DB, return summary."""
    from database.secops_db_writer import (
        persist_scan_report,
        complete_scan_report,
        persist_findings,
    )

    # 1. Create scan report (status=running)
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
    _scan_status[secops_scan_id] = {"status": "running", "started_at": datetime.utcnow().isoformat()}

    try:
        # 2. Run scan
        logger.info(f"[{secops_scan_id}] Scanning {input_path}")
        scan_result = scan_path(input_path)

        results = scan_result.get("results", [])
        errors = scan_result.get("errors", [])

        total_files = len(results)
        total_findings = sum(len(r.get("findings", [])) for r in results)
        total_errors = len(errors)
        languages_detected = list(set(r.get("language", "unknown") for r in results))

        # 3. Persist findings
        findings_inserted = persist_findings(
            secops_scan_id=secops_scan_id,
            tenant_id=tenant_id,
            scan_results=results,
            repo_base_path=input_path,
            customer_id=customer_id,
        )

        # 4. Save local JSON for S3 sync sidecar
        output_dir = os.path.join(OUTPUT_FOLDER, tenant_id, project_name, secops_scan_id)
        os.makedirs(output_dir, exist_ok=True)
        report = {
            "secops_scan_id": secops_scan_id,
            "tenant_id": tenant_id,
            "project_name": project_name,
            "repo_url": repo_url,
            "branch": branch,
            "timestamp": datetime.utcnow().isoformat(),
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

        # 5. Complete scan report in DB
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


# ==================== New Endpoints ====================

@app.get("/")
async def root():
    return {
        "service": "SecOps Scanner Engine",
        "version": "3.0.0",
        "status": "operational",
        "supported_languages": list(get_supported_languages()),
    }


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "supported_languages": list(get_supported_languages()),
        "input_folder": INPUT_FOLDER,
        "output_folder": OUTPUT_FOLDER,
    }


@app.post("/api/v1/secops/scan", response_model=ScanResponse)
async def scan_repo(request: ScanRequest):
    """
    Clone a git repo and scan it for security vulnerabilities.

    1. Generates secops_scan_id (UUID)
    2. git clone --depth 1 the repo
    3. Scans all supported files
    4. Persists results to secops DB
    5. Returns scan summary
    """
    secops_scan_id = str(uuid.uuid4())
    project_name = _project_name_from_url(request.repo_url)
    input_path = os.path.join(INPUT_FOLDER, project_name)

    # Clone
    try:
        _clone_repo(request.repo_url, request.branch, input_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to clone repo: {e}")

    # Scan + persist
    try:
        summary = _run_scan_and_persist(
            secops_scan_id=secops_scan_id,
            tenant_id=request.tenant_id,
            customer_id=request.customer_id,
            orchestration_id=request.orchestration_id,
            project_name=project_name,
            repo_url=request.repo_url,
            branch=request.branch,
            input_path=input_path,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {e}")
    finally:
        # Clean up cloned repo to save disk
        try:
            shutil.rmtree(input_path, ignore_errors=True)
        except Exception:
            pass

    return ScanResponse(
        secops_scan_id=secops_scan_id,
        orchestration_id=request.orchestration_id,
        tenant_id=request.tenant_id,
        project_name=project_name,
        status="completed",
        summary=summary,
        findings_count=summary.get("total_findings", 0),
    )


@app.get("/api/v1/secops/scan/{secops_scan_id}/status")
async def get_scan_status(secops_scan_id: str):
    """Poll scan status."""
    # Check in-memory first
    if secops_scan_id in _scan_status:
        return {"secops_scan_id": secops_scan_id, **_scan_status[secops_scan_id]}

    # Check DB
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


@app.get("/api/v1/secops/scan/{secops_scan_id}/findings")
async def get_scan_findings(
    secops_scan_id: str,
    severity: Optional[str] = Query(None, description="Filter by severity"),
    language: Optional[str] = Query(None, description="Filter by language"),
    limit: int = Query(500, description="Max findings to return"),
):
    """Get findings for a scan from DB."""
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


@app.get("/api/v1/secops/scans")
async def list_scans(
    tenant_id: str = Query(..., description="Tenant ID"),
    project_name: Optional[str] = Query(None, description="Filter by project/repo name"),
    limit: int = Query(50, description="Max scans to return"),
):
    """List scans for a tenant."""
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
                    WHERE tenant_id = %s
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


@app.get("/api/v1/secops/rules/stats")
async def rule_stats():
    """Get rule metadata statistics from DB."""
    try:
        from database.rule_metadata_loader import get_rule_stats
        return get_rule_stats()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/secops/rules/sync")
async def sync_rules():
    """Trigger incremental rule metadata sync from docs folders into DB."""
    try:
        from database.rule_metadata_loader import seed_all_rules
        base_dir = os.path.dirname(os.path.abspath(__file__))
        totals = seed_all_rules(base_dir)
        return {"status": "synced", "total_rules": sum(totals.values()), "by_scanner": totals}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== Legacy endpoints (backward compat) ====================

@app.post("/scan")
async def scan_project_legacy(request: LegacyScanRequest):
    """Legacy: Scan a project already staged in input folder."""
    project_name = request.project_name.strip()
    if not project_name:
        raise HTTPException(status_code=400, detail="project_name is required")
    if ".." in project_name or "/" in project_name or "\\" in project_name:
        raise HTTPException(status_code=400, detail="Invalid project_name")

    input_path = os.path.join(INPUT_FOLDER, project_name)
    if not os.path.exists(input_path):
        raise HTTPException(status_code=404, detail=f"Project not found: {project_name}")

    try:
        scan_result = scan_path(input_path)
        total_files = len(scan_result.get("results", []))
        total_findings = sum(len(r.get("findings", [])) for r in scan_result.get("results", []))
        total_errors = len(scan_result.get("errors", []))

        response = {
            "success": True,
            "project_name": project_name,
            "timestamp": datetime.utcnow().isoformat(),
            "summary": {
                "files_scanned": total_files,
                "total_findings": total_findings,
                "total_errors": total_errors,
            },
            "scan_data": scan_result,
        }

        if request.save_results:
            output_path = os.path.join(OUTPUT_FOLDER, project_name)
            os.makedirs(output_path, exist_ok=True)
            ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            result_file = os.path.join(output_path, f"scan_results_{ts}.json")
            latest_file = os.path.join(output_path, "scan_results_latest.json")
            with open(result_file, "w") as f:
                json.dump(response, f, indent=2)
            with open(latest_file, "w") as f:
                json.dump(response, f, indent=2)
            response["output_file"] = result_file
            response["latest_file"] = latest_file

        if request.fail_on_findings and total_findings > 0:
            raise HTTPException(status_code=422, detail=f"Found {total_findings} findings")

        return JSONResponse(content=response)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {e}")


@app.get("/results/{project_name}")
async def get_latest_results(project_name: str):
    """Legacy: Get latest scan results from local files."""
    if ".." in project_name or "/" in project_name or "\\" in project_name:
        raise HTTPException(status_code=400, detail="Invalid project_name")
    latest_file = os.path.join(OUTPUT_FOLDER, project_name, "scan_results_latest.json")
    if not os.path.exists(latest_file):
        raise HTTPException(status_code=404, detail=f"No results for: {project_name}")
    with open(latest_file) as f:
        return JSONResponse(content=json.load(f))


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("SECOPS_PORT", "8009"))
    uvicorn.run(app, host="0.0.0.0", port=port)
