"""
DAST Router — Dynamic Application Security Testing.

REST wrapper around the dast_engine CLI pipeline.
Runs the 5-step pipeline (configure → discover → parameters → attack → report)
in a background thread and persists findings to DB.
"""

import hashlib
import json
import logging
import os
import tempfile
import threading
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger("secops.dast")

# In-memory scan status + results cache
_dast_scans: Dict[str, dict] = {}

router = APIRouter()


# ── Models ───────────────────────────────────────────────────────────────────

class DastAuthConfig(BaseModel):
    """Authentication configuration for DAST scan."""
    type: str = Field(default="none", description="Auth type: none, basic, bearer, cookie, oauth2")
    token: Optional[str] = Field(default=None, description="Bearer token")
    username: Optional[str] = Field(default=None, description="Basic auth username")
    password: Optional[str] = Field(default=None, description="Basic auth password")
    cookie: Optional[str] = Field(default=None, description="Session cookie value")
    header_name: Optional[str] = Field(default=None, description="Custom auth header name")
    header_value: Optional[str] = Field(default=None, description="Custom auth header value")


class DastScanRequest(BaseModel):
    """Request to run a DAST scan against a target URL."""
    tenant_id: str = Field(..., description="Tenant identifier")
    target_url: str = Field(..., description="Target URL to scan")
    scan_run_id: Optional[str] = Field(default=None, description="Pipeline-wide scan_run_id")
    customer_id: Optional[str] = Field(default=None, description="Customer identifier")
    profile: str = Field(default="quick", description="Scan profile: quick, normal, deep")
    auth: Optional[DastAuthConfig] = Field(default=None, description="Authentication config")
    scope_include: Optional[List[str]] = Field(default=None, description="URL patterns to include")
    scope_exclude: Optional[List[str]] = Field(default=None, description="URL patterns to exclude")
    environment: str = Field(default="staging", description="Environment: development, staging, production")
    report_formats: List[str] = Field(default=["json"], description="Report formats: json, sarif, html")


class DastScanResponse(BaseModel):
    dast_scan_id: str
    scan_run_id: Optional[str] = None
    tenant_id: str
    target_url: str
    status: str
    message: str


# ── Background runner ────────────────────────────────────────────────────────

def _build_dast_config(req: DastScanRequest) -> dict:
    """Build a config dict matching dast_engine.config.config_parser format."""
    config = {
        "target": {
            "url": req.target_url,
            "scope": {},
        },
        "authentication": {"type": "none"},
        "scan": {
            "intensity": req.profile,
        },
        "safety": {
            "environment": req.environment,
            "require_authorization": False,
        },
        "output": {
            "reports_dir": "",  # set at runtime
            "format": req.report_formats,
        },
    }

    if req.scope_include:
        config["target"]["scope"]["include"] = req.scope_include
    if req.scope_exclude:
        config["target"]["scope"]["exclude"] = req.scope_exclude

    if req.auth:
        auth = {"type": req.auth.type}
        if req.auth.type == "bearer" and req.auth.token:
            auth["bearer"] = {"token": req.auth.token}
        elif req.auth.type == "basic" and req.auth.username:
            auth["basic"] = {"username": req.auth.username, "password": req.auth.password or ""}
        elif req.auth.type == "cookie" and req.auth.cookie:
            auth["cookie"] = {"value": req.auth.cookie}
        elif req.auth.type == "custom" and req.auth.header_name:
            auth["custom"] = {"header": req.auth.header_name, "value": req.auth.header_value or ""}
        config["authentication"] = auth

    return config


def _normalize_severity(sev: str) -> str:
    """Normalize severity to standard: critical, high, medium, low, info."""
    s = sev.lower().strip()
    mapping = {
        "critical": "critical", "high": "high", "medium": "medium",
        "low": "low", "info": "info", "informational": "info",
    }
    return mapping.get(s, "info")


def _run_dast_pipeline(dast_scan_id: str, req: DastScanRequest) -> None:
    """Run the full DAST pipeline in a background thread."""
    import sys
    # Ensure dast_engine package is importable (lives at engines/secops/dast_engine/)
    secops_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "..")
    secops_dir = os.path.abspath(secops_dir)
    if secops_dir not in sys.path:
        sys.path.insert(0, secops_dir)

    _dast_scans[dast_scan_id]["status"] = "running"
    _dast_scans[dast_scan_id]["started_at"] = datetime.now(timezone.utc).isoformat()

    # ── Pre-flight: verify the target URL is reachable ────────────────────────
    import socket
    import urllib.parse
    def _check_target_reachable(url: str, timeout: int = 10) -> Optional[str]:
        """Return None if reachable, or an error message string if not."""
        try:
            parsed = urllib.parse.urlparse(url)
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            if not host:
                return f"Invalid URL — cannot extract hostname from '{url}'"
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.close()
            return None
        except socket.timeout:
            return f"Target '{url}' is not reachable: connection timed out after {timeout}s"
        except socket.gaierror as e:
            return f"Target '{url}' is not reachable: DNS resolution failed ({e})"
        except ConnectionRefusedError:
            return f"Target '{url}' is not reachable: connection refused on port {port}"
        except Exception as e:
            return f"Target '{url}' is not reachable: {e}"

    reachability_error = _check_target_reachable(req.target_url)
    if reachability_error:
        logger.error(f"[{dast_scan_id}] {reachability_error}")
        _dast_scans[dast_scan_id].update({
            "status": "failed",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "error": reachability_error,
        })
        try:
            from database.secops_db_writer import persist_scan_report, complete_scan_report
            persist_scan_report(
                secops_scan_id=dast_scan_id,
                tenant_id=req.tenant_id,
                project_name=req.target_url,
                repo_url=req.target_url,
                branch="",
                status="failed",
                customer_id=req.customer_id,
                orchestration_id=req.scan_run_id,
                scan_type="dast",
            )
            complete_scan_report(
                secops_scan_id=dast_scan_id,
                status="failed",
                files_scanned=0,
                total_findings=0,
                total_errors=1,
                languages_detected=["dast"],
                summary={"error": reachability_error},
            )
        except Exception as db_err:
            logger.warning(f"[{dast_scan_id}] DB update failed: {db_err}")
        return

    # Persist scan report to DB (status=running)
    try:
        from database.secops_db_writer import persist_scan_report
        persist_scan_report(
            secops_scan_id=dast_scan_id,
            tenant_id=req.tenant_id,
            project_name=req.target_url,
            repo_url=req.target_url,
            branch="",
            status="running",
            customer_id=req.customer_id,
            orchestration_id=req.scan_run_id,
            scan_type="dast",
        )
    except Exception as e:
        logger.warning(f"[{dast_scan_id}] DB persist_scan_report failed: {e}")

    reports_dir = tempfile.mkdtemp(prefix=f"dast_{dast_scan_id}_")

    try:
        # Build config
        config_dict = _build_dast_config(req)
        config_dict["output"]["reports_dir"] = reports_dir

        # Step 1: Configure
        logger.info(f"[{dast_scan_id}] Step 1/5: Configuring target {req.target_url}")
        from dast_engine.config.config_parser import TargetConfig
        from dast_engine.auth.auth_manager import AuthenticationManager

        config = TargetConfig(profile=req.profile)
        config.config = config._merge_configs(config.config, config_dict)

        auth_manager = AuthenticationManager(config.get("authentication"))
        session = auth_manager.get_session()

        # Step 2: Discover endpoints
        logger.info(f"[{dast_scan_id}] Step 2/5: Discovering endpoints")
        from dast_engine.crawler import ApplicationDiscoveryEngine
        discovery_engine = ApplicationDiscoveryEngine(config)
        result = discovery_engine.discover(enable_js_rendering=False)
        pages_crawled = discovery_engine.stats.get("web_crawler", {}).get("pages_crawled", 0)
        logger.info(f"[{dast_scan_id}] Discovered {result.total_endpoints} endpoints, {pages_crawled} pages")

        # Step 3: Identify parameters
        logger.info(f"[{dast_scan_id}] Step 3/5: Analyzing parameters")
        from dast_engine.parameters import ParameterEnricher
        enricher = ParameterEnricher()
        enriched_endpoints = enricher.enrich_crawl_result(result)
        param_stats = enricher.get_statistics(enriched_endpoints)
        logger.info(f"[{dast_scan_id}] {param_stats['injectable_parameters']} injectable / {param_stats['total_parameters']} total params")

        # Step 4: Attack
        vulns = []
        atk_stats = {}
        if result.total_endpoints > 0 and param_stats["injectable_parameters"] > 0:
            logger.info(f"[{dast_scan_id}] Step 4/5: Running attacks")
            from dast_engine.attack.attack_executor import AttackExecutor
            executor = AttackExecutor(
                config=config.to_dict(),
                endpoints=enriched_endpoints,
                auth_manager=AuthenticationManager(config.get("authentication")),
            )
            attack_results = executor.execute_attacks()
            vulns = attack_results.get("vulnerabilities", [])
            atk_stats = attack_results.get("stats", {})
            logger.info(f"[{dast_scan_id}] Attack complete: {len(vulns)} vulnerabilities")
        else:
            logger.info(f"[{dast_scan_id}] Step 4/5: Skipped (no injectable params)")

        # Step 5: Reports
        logger.info(f"[{dast_scan_id}] Step 5/5: Generating reports")
        from dast_engine.report.report_generator import ReportGenerator
        report_gen = ReportGenerator(output_dir=reports_dir)
        report_files = report_gen.generate_all_reports(
            vulnerabilities=vulns,
            scan_config=config.to_dict(),
            scan_stats={**atk_stats, "pages_crawled": pages_crawled},
            formats=req.report_formats,
            endpoints=enriched_endpoints,
            parameter_stats=param_stats,
        )

        # Normalize findings for DB persistence
        findings = _vulns_to_findings(vulns, dast_scan_id, req.tenant_id)

        # Persist findings to DB
        findings_persisted = 0
        try:
            findings_persisted = _persist_dast_findings(dast_scan_id, req.tenant_id, findings, req.customer_id)
        except Exception as e:
            logger.warning(f"[{dast_scan_id}] DB persist_findings failed: {e}")

        # Severity breakdown
        sev_counts: Dict[str, int] = {}
        for f in findings:
            s = f.get("severity", "info")
            sev_counts[s] = sev_counts.get(s, 0) + 1

        summary = {
            "target_url": req.target_url,
            "profile": req.profile,
            "endpoints_discovered": result.total_endpoints,
            "pages_crawled": pages_crawled,
            "parameters_found": param_stats["total_parameters"],
            "injectable_parameters": param_stats["injectable_parameters"],
            "attacks_sent": atk_stats.get("total_attacks", 0),
            "total_findings": len(findings),
            "findings_persisted": findings_persisted,
            "by_severity": sev_counts,
            "report_formats": list(report_files.keys()),
        }

        # Complete scan in DB
        try:
            from database.secops_db_writer import complete_scan_report
            complete_scan_report(
                secops_scan_id=dast_scan_id,
                status="completed",
                files_scanned=result.total_endpoints,
                total_findings=len(findings),
                total_errors=0,
                languages_detected=["dast"],
                summary=summary,
            )
        except Exception as e:
            logger.warning(f"[{dast_scan_id}] DB complete_scan_report failed: {e}")

        _dast_scans[dast_scan_id].update({
            "status": "completed",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "summary": summary,
            "findings": findings,
            "report_files": {k: str(v) for k, v in report_files.items()},
        })
        logger.info(f"[{dast_scan_id}] DAST scan complete: {len(findings)} findings")

    except Exception as e:
        logger.error(f"[{dast_scan_id}] DAST pipeline failed: {e}", exc_info=True)
        _dast_scans[dast_scan_id].update({
            "status": "failed",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "error": str(e),
        })
        try:
            from database.secops_db_writer import complete_scan_report
            complete_scan_report(
                secops_scan_id=dast_scan_id,
                status="failed",
                files_scanned=0,
                total_findings=0,
                total_errors=1,
                languages_detected=["dast"],
                summary={"error": str(e)},
            )
        except Exception:
            pass


def _vulns_to_findings(vulns: list, dast_scan_id: str, tenant_id: str) -> List[dict]:
    """Convert DAST vulnerability dicts to normalized finding dicts."""
    findings = []
    for v in vulns:
        if isinstance(v, dict):
            ep = v.get("endpoint", {}) or {}
            param = v.get("parameter", {}) or {}
            url = ep.get("url", "") if isinstance(ep, dict) else str(ep)
            method = ep.get("method", "") if isinstance(ep, dict) else ""
            param_name = param.get("name", "") if isinstance(param, dict) else str(param)

            vtype = (v.get("header_name") or v.get("cookie_name")
                     or v.get("type") or "DAST Finding")
            severity = _normalize_severity(v.get("severity", "info"))

            # Deterministic finding_id
            id_str = f"{vtype}|{url}|{method}|{param_name}|{tenant_id}"
            finding_id = hashlib.sha256(id_str.encode()).hexdigest()[:16]

            findings.append({
                "finding_id": finding_id,
                "dast_scan_id": dast_scan_id,
                "tenant_id": tenant_id,
                "scan_type": "dast",
                "vulnerability_type": vtype,
                "severity": severity,
                "endpoint_url": url,
                "endpoint_method": method,
                "parameter_name": param_name,
                "parameter_location": param.get("location", "") if isinstance(param, dict) else "",
                "payload": v.get("payload", ""),
                "evidence": v.get("evidence", ""),
                "description": v.get("description", ""),
                "remediation": v.get("remediation", ""),
                "confidence": v.get("confidence", 0.0),
                "cvss_score": v.get("cvss", {}).get("base_score") if isinstance(v.get("cvss"), dict) else None,
                "cvss_vector": v.get("cvss", {}).get("vector") if isinstance(v.get("cvss"), dict) else None,
            })
    return findings


def _persist_dast_findings(dast_scan_id: str, tenant_id: str,
                           findings: List[dict], customer_id: Optional[str]) -> int:
    """Write DAST findings to secops_findings table."""
    from database.db_config import get_connection
    conn = get_connection()
    inserted = 0
    try:
        with conn.cursor() as cur:
            for f in findings:
                cur.execute("""
                    INSERT INTO secops_findings
                        (secops_scan_id, tenant_id, customer_id, file_path, language,
                         rule_id, severity, message, line_number, status, resource, metadata, scan_type)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT DO NOTHING
                """, (
                    dast_scan_id,
                    tenant_id,
                    customer_id,
                    f["endpoint_url"],                    # file_path → endpoint URL
                    "dast",                               # language → 'dast'
                    f["vulnerability_type"],              # rule_id → vuln type
                    f["severity"],
                    f["description"],
                    None,                                 # line_number (N/A)
                    "violation",
                    f"{f['endpoint_method']} {f['endpoint_url']}",  # resource
                    json.dumps({
                        "finding_id": f["finding_id"],
                        "scan_type": "dast",
                        "parameter_name": f["parameter_name"],
                        "parameter_location": f["parameter_location"],
                        "payload": f["payload"],
                        "evidence": f["evidence"],
                        "remediation": f["remediation"],
                        "confidence": f["confidence"],
                        "cvss_score": f["cvss_score"],
                        "cvss_vector": f["cvss_vector"],
                    }),
                    "dast",
                ))
                inserted += 1
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return inserted


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.post("/scan", response_model=DastScanResponse)
async def start_dast_scan(request: DastScanRequest):
    """
    Start a DAST scan against a target URL.

    Runs the 5-step pipeline (configure → discover → parameters → attack → report)
    in a background thread.  Poll /scan/{id}/status for progress.
    """
    dast_scan_id = str(uuid.uuid4())

    _dast_scans[dast_scan_id] = {
        "dast_scan_id": dast_scan_id,
        "scan_run_id": request.scan_run_id,
        "tenant_id": request.tenant_id,
        "target_url": request.target_url,
        "profile": request.profile,
        "status": "queued",
        "queued_at": datetime.now(timezone.utc).isoformat(),
    }

    thread = threading.Thread(
        target=_run_dast_pipeline,
        args=(dast_scan_id, request),
        daemon=True,
    )
    thread.start()

    return DastScanResponse(
        dast_scan_id=dast_scan_id,
        scan_run_id=request.scan_run_id,
        tenant_id=request.tenant_id,
        target_url=request.target_url,
        status="queued",
        message="DAST scan queued — poll /scan/{id}/status for progress",
    )


@router.get("/scan/{dast_scan_id}/status")
async def get_dast_status(dast_scan_id: str):
    """Poll DAST scan status."""
    if dast_scan_id in _dast_scans:
        info = _dast_scans[dast_scan_id]
        resp = {
            "dast_scan_id": dast_scan_id,
            "status": info["status"],
            "target_url": info.get("target_url"),
            "profile": info.get("profile"),
        }
        if info["status"] == "completed":
            resp["summary"] = info.get("summary")
        elif info["status"] == "failed":
            resp["error"] = info.get("error")
        return resp

    # Check DB fallback
    try:
        from database.db_config import get_dict_connection
        conn = get_dict_connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT secops_scan_id, status, total_findings, summary "
                    "FROM secops_report WHERE secops_scan_id = %s AND scan_type = 'dast'",
                    (dast_scan_id,),
                )
                row = cur.fetchone()
                if not row:
                    raise HTTPException(status_code=404, detail="DAST scan not found")
                return dict(row)
        finally:
            conn.close()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scan/{dast_scan_id}/findings")
async def get_dast_findings(
    dast_scan_id: str,
    severity: Optional[str] = Query(None, description="Filter by severity"),
    limit: int = Query(500, description="Max findings to return"),
):
    """Get DAST findings — from in-memory cache or DB."""
    # In-memory first (has richer data)
    if dast_scan_id in _dast_scans and _dast_scans[dast_scan_id].get("findings"):
        findings = _dast_scans[dast_scan_id]["findings"]
        if severity:
            findings = [f for f in findings if f["severity"] == severity.lower()]
        return {
            "dast_scan_id": dast_scan_id,
            "total": len(findings[:limit]),
            "findings": findings[:limit],
        }

    # DB fallback
    try:
        from database.db_config import get_dict_connection
        conn = get_dict_connection()
        try:
            with conn.cursor() as cur:
                query = """
                    SELECT id, secops_scan_id, file_path AS endpoint_url, rule_id AS vulnerability_type,
                           severity, message AS description, status, resource, metadata
                    FROM secops_findings
                    WHERE secops_scan_id = %s AND scan_type = 'dast'
                """
                params: list = [dast_scan_id]
                if severity:
                    query += " AND severity = %s"
                    params.append(severity.lower())
                query += " ORDER BY severity DESC LIMIT %s"
                params.append(limit)

                cur.execute(query, params)
                findings = [dict(r) for r in cur.fetchall()]
                return {"dast_scan_id": dast_scan_id, "total": len(findings), "findings": findings}
        finally:
            conn.close()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scan/{dast_scan_id}/report")
async def get_dast_report(
    dast_scan_id: str,
    format: str = Query("json", description="Report format: json, sarif, html"),
):
    """Download the full DAST report in the requested format."""
    if dast_scan_id not in _dast_scans:
        raise HTTPException(status_code=404, detail="DAST scan not found")

    info = _dast_scans[dast_scan_id]
    if info["status"] != "completed":
        raise HTTPException(status_code=409, detail=f"Scan status is '{info['status']}', not completed")

    report_files = info.get("report_files", {})
    if format not in report_files:
        raise HTTPException(
            status_code=404,
            detail=f"Format '{format}' not available. Available: {list(report_files.keys())}",
        )

    report_path = report_files[format]
    if not os.path.exists(report_path):
        raise HTTPException(status_code=404, detail="Report file not found on disk")

    with open(report_path) as f:
        content = f.read()

    if format == "json":
        return json.loads(content)
    else:
        from fastapi.responses import PlainTextResponse
        media = "application/sarif+json" if format == "sarif" else "text/html"
        return PlainTextResponse(content=content, media_type=media)


@router.get("/scans")
async def list_dast_scans(
    tenant_id: str = Query(..., description="Tenant ID"),
    limit: int = Query(50, description="Max scans to return"),
):
    """List DAST scans for a tenant."""
    try:
        from database.db_config import get_dict_connection
        conn = get_dict_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT secops_scan_id AS dast_scan_id, orchestration_id AS scan_run_id,
                           tenant_id, project_name AS target_url, status,
                           scan_timestamp, completed_at, total_findings, summary
                    FROM secops_report
                    WHERE tenant_id = %s AND scan_type = 'dast'
                    ORDER BY scan_timestamp DESC LIMIT %s
                """, (tenant_id, limit))
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
