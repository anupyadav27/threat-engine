"""
SAST Router — Static Application Security Testing.

Extracted from api_server.py.  All endpoints are relative to the router
prefix (set by the main app as /api/v1/secops/sast).
"""

import ipaddress
import json
import json as _json
import logging
import os
import shutil
import socket
import stat
import subprocess
import tempfile
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Any, List, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator

from scan_local import scan_path
from scanner_plugin import get_supported_languages

# ── Auth imports (engine_auth is COPY shared/auth/ ./engine_auth/ in Dockerfile) ──
try:
    from engine_auth.fastapi.dependencies import require_permission
    from engine_auth.core.models import AuthContext
    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False
    AuthContext = None  # type: ignore[assignment,misc]

logger = logging.getLogger("secops.sast")

# ── Onboarding engine URL for account ownership validation ───────────────────
ONBOARDING_ENGINE_URL = os.getenv("ONBOARDING_ENGINE_URL", "http://engine-onboarding")

# ── B-2: Allowed VCS hosts and RFC1918 blocks ────────────────────────────────
_ALLOWED_VCS_HOSTS: frozenset = frozenset(
    h.strip()
    for h in os.getenv("ALLOWED_VCS_HOSTS", "github.com,gitlab.com,bitbucket.org").split(",")
    if h.strip()
)
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local / IMDS
    ipaddress.ip_network("127.0.0.0/8"),     # loopback
]
_K8S_INTERNAL_SUFFIXES = (".svc", ".svc.cluster.local", ".cluster.local")


def _strip_secops_sensitive(data: list, auth: Any) -> list:
    """Remove credential_ref/credential_type for non-platform-admin callers.

    Args:
        data: List of finding/scan dicts.
        auth: AuthContext instance or None.

    Returns:
        New list with sensitive fields removed.
    """
    if not isinstance(data, list):
        return data
    stripped = []
    for row in data:
        r = dict(row) if not isinstance(row, dict) else row.copy()
        if auth is not None and hasattr(auth, "level") and auth.level > 1:
            r.pop("credential_ref", None)
            r.pop("credential_type", None)
        stripped.append(r)
    return stripped

# Folders (shared with main app)
INPUT_FOLDER = os.getenv("SCAN_INPUT_PATH", "/app/scan_input")
OUTPUT_FOLDER = os.getenv("SCAN_OUTPUT_PATH", "/app/scan_output")

# In-memory scan status cache
_scan_status: dict = {}

router = APIRouter()


# ── Models ───────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    """Request to scan a git repository.

    When account_id is provided the engine calls the onboarding engine to
    validate ownership and resolves repo_url from auth_config internally.
    When account_id is absent the caller must supply repo_url directly
    (backward-compat path for direct API callers without onboarded accounts).
    """

    tenant_id: str = Field(..., description="Tenant identifier")
    account_id: Optional[str] = Field(
        default=None,
        description=(
            "Onboarded code_security account ID. When present, repo_url is resolved "
            "from the onboarding engine and the caller-supplied repo_url is ignored."
        ),
    )
    repo_url: Optional[str] = Field(
        default=None,
        description=(
            "Git clone URL (https only; must be an allowed VCS host). "
            "Required when account_id is absent; ignored when account_id is present."
        ),
    )
    branch: str = Field(default="main", description="Branch to scan")
    customer_id: Optional[str] = Field(default=None, description="Customer identifier")
    scan_run_id: Optional[str] = Field(default=None, description="Pipeline-wide scan_run_id")
    languages: Optional[List[str]] = Field(
        default=None, description="Filter to specific languages (null = scan all)"
    )

    @validator("repo_url", always=True)
    def validate_repo_url(cls, v: Optional[str], values: dict) -> Optional[str]:  # noqa: N805
        """Validate repo_url when account_id is absent.

        When account_id is present, repo_url will be resolved from the onboarding
        engine and this value is ignored. When account_id is absent, repo_url is
        required and must pass all security checks.

        Args:
            v: Raw repo_url value from the request body.
            values: Already-validated field values (includes account_id).

        Returns:
            Validated repo_url unchanged, or None when account_id is present.

        Raises:
            ValueError: If repo_url is required but fails any security check.
        """
        account_id = values.get("account_id")
        if account_id:
            # repo_url will be resolved from onboarding — skip validation here.
            return v

        # repo_url is required when account_id is absent.
        if not v:
            raise ValueError("repo_url is required when account_id is not provided")

        parsed = urlparse(v)

        # B-2a: HTTPS only
        if parsed.scheme != "https":
            raise ValueError("repo_url must use https:// scheme")

        host = (parsed.hostname or "").lower().rstrip(".")

        # B-2b: Allowlisted VCS hosts only
        if host not in _ALLOWED_VCS_HOSTS:
            raise ValueError(
                f"repo_url host '{host}' is not in the allowed list: "
                f"{sorted(_ALLOWED_VCS_HOSTS)}"
            )

        # B-2d: Block K8s-internal hostnames
        for suffix in _K8S_INTERNAL_SUFFIXES:
            if host.endswith(suffix):
                raise ValueError(
                    f"repo_url host '{host}' resolves to a K8s-internal address"
                )

        # B-2c: Block RFC1918 / link-local / loopback addresses
        try:
            resolved_ip = ipaddress.ip_address(socket.gethostbyname(host))
            if any(resolved_ip in net for net in _PRIVATE_NETWORKS):
                raise ValueError(
                    f"repo_url resolves to a private/reserved IP address: {resolved_ip}"
                )
        except socket.gaierror:
            # DNS failure at validation time — allow; git clone will fail safely
            pass

        return v


class ScanResponse(BaseModel):
    secops_scan_id: str
    scan_run_id: Optional[str] = None
    tenant_id: str
    project_name: str
    status: str
    summary: Optional[dict] = None
    findings_count: int = 0


# ── Account ownership validation ─────────────────────────────────────────────

def _validate_account_ownership(
    account_id: str,
    tenant_id: str,
    auth_header: Optional[str],
) -> dict:
    """Call onboarding engine to verify account belongs to tenant.

    Fail-closed: any network error or timeout raises 503 rather than allowing
    the scan to proceed with an unverified account_id.

    Args:
        account_id: Account identifier to verify.
        tenant_id: Expected tenant owner from AuthContext.
        auth_header: Value of X-Auth-Context header to forward.

    Returns:
        Cloud account dict from the onboarding engine (includes auth_config
        with repo_url and default_branch).

    Raises:
        HTTPException(404): Account not found in onboarding engine.
        HTTPException(403): Account exists but belongs to a different tenant.
        HTTPException(503): Onboarding engine unreachable, timed out, or returned non-2xx.
    """
    url = f"{ONBOARDING_ENGINE_URL}/api/v1/cloud-accounts/{account_id}"
    req = urllib.request.Request(url)
    if auth_header:
        req.add_header("X-Auth-Context", auth_header)

    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = _json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise HTTPException(
                status_code=404, detail=f"Account {account_id} not found"
            )
        raise HTTPException(
            status_code=503,
            detail=f"Onboarding engine returned HTTP {exc.code} for account {account_id}",
        )
    except (urllib.error.URLError, TimeoutError, OSError):
        raise HTTPException(
            status_code=503,
            detail="Onboarding engine unreachable or timed out — cannot verify account ownership",
        )

    if data.get("tenant_id") != tenant_id:
        raise HTTPException(
            status_code=403,
            detail="Account does not belong to this tenant",
        )

    return data


# ── Helpers ──────────────────────────────────────────────────────────────────

def _project_name_from_url(repo_url: str) -> str:
    name = repo_url.rstrip("/").split("/")[-1]
    if name.endswith(".git"):
        name = name[:-4]
    return name


def _sanitize_url(url: str) -> str:
    """Strip embedded credentials from a URL for safe logging.

    Args:
        url: Raw URL that may contain ``user:password@`` credentials.

    Returns:
        URL with the ``user:password@`` portion removed.
    """
    parsed = urlparse(url)
    # Reconstruct without netloc credentials
    sanitized = parsed._replace(netloc=parsed.hostname or "")
    if parsed.port:
        sanitized = sanitized._replace(
            netloc=f"{parsed.hostname}:{parsed.port}"
        )
    return sanitized.geturl()


def _clone_repo(repo_url: str, branch: str, dest: str, pat: Optional[str] = None) -> None:
    """Clone a git repository; PAT is passed via GIT_ASKPASS, never embedded in the URL.

    Args:
        repo_url: HTTPS clone URL (must not contain credentials).
        branch: Branch name to check out.
        dest: Local destination path for the clone.
        pat: Optional Personal Access Token. Written to a 0700 temp script and
             passed via ``GIT_ASKPASS``; deleted in a ``finally`` block.

    Raises:
        RuntimeError: If ``git clone`` exits with a non-zero return code.
    """
    if os.path.exists(dest):
        shutil.rmtree(dest)

    askpass_path: Optional[str] = None
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"  # B-1: never prompt interactively

    if pat:
        # B-1: Write a minimal GIT_ASKPASS script that echoes the PAT.
        # The script is created with mode 0700 (owner-execute only).
        fd, askpass_path = tempfile.mkstemp(suffix=".sh")
        try:
            # Shell-escape single quotes in PAT to prevent injection.
            safe_pat = pat.replace("'", "'\\''")
            with os.fdopen(fd, "w") as f:
                f.write(f"#!/bin/sh\necho '{safe_pat}'\n")
            os.chmod(askpass_path, stat.S_IRWXU)  # 0700 — owner only
            env["GIT_ASKPASS"] = askpass_path
        except Exception:
            if askpass_path and os.path.exists(askpass_path):
                os.unlink(askpass_path)
            raise

    # B-3: --config core.hooksPath=/dev/null disables all git hooks.
    cmd = [
        "git", "clone", "--depth", "1",
        "--branch", branch, "--single-branch",
        "--config", "core.hooksPath=/dev/null",
        repo_url, dest,
    ]

    # Log sanitized URL only — the PAT must never appear in log output.
    logger.info(f"Cloning {_sanitize_url(repo_url)} branch={branch} -> {dest}")

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300, env=env
        )
        if result.returncode != 0:
            raise RuntimeError(f"git clone failed: {result.stderr.strip()}")
    finally:
        # B-1: Always delete the GIT_ASKPASS script, even on failure.
        if askpass_path and os.path.exists(askpass_path):
            os.unlink(askpass_path)

    logger.info(f"Clone complete: {dest}")


def _emit_secops_findings(secops_scan_id: str, tenant_id: str, scan_run_id: str) -> None:
    """Read secops_findings for this scan and upsert into security_findings (inventory DB).

    Non-fatal — errors are caught by the caller.
    """
    try:
        from database.db_config import get_connection as get_secops_conn
        from engine_common.security_findings_writer import upsert_findings
        from engine_common.db_connections import get_inventory_conn
    except ImportError as e:
        logger.warning("_emit_secops_findings: missing deps (%s) — skipping", e)
        return

    with get_secops_conn() as sconn:
        with sconn.cursor() as cur:
            cur.execute(
                """
                SELECT id, file_path, language, rule_id, severity, message,
                       line_number, status, resource, scan_type, account_id
                FROM secops_findings
                WHERE secops_scan_id = %s AND tenant_id = %s
                  AND severity IN ('critical', 'high', 'medium', 'low')
                  AND (status IS NULL OR status != 'not_applicable')
                """,
                (secops_scan_id, tenant_id),
            )
            cols = [d[0] for d in cur.description]
            rows = cur.fetchall()

    if not rows:
        return

    findings = []
    for row in rows:
        d = dict(zip(cols, row))
        scan_type = d.get("scan_type") or "sast"
        prefix = "dast" if scan_type == "dast" else "sast"
        file_path = d.get("file_path") or ""
        rule_id = d.get("rule_id") or "unknown"
        language = d.get("language") or "unknown"
        message = d.get("message") or ""
        findings.append({
            "source_finding_id": f"{prefix}-{d['id']}",
            "resource_uid":      file_path or f"secops/{secops_scan_id}",
            "finding_type":      "code_security",
            "severity":          (d.get("severity") or "medium").lower(),
            "title":             f"{rule_id}: {message[:200]}" if message else rule_id,
            "account_id":        d.get("account_id") or "",
            "provider":          "code",
            "resource_type":     f"code.{language}",
            "rule_id":           rule_id,
            "description":       message[:2000] if message else None,
            "detail":            {"posture_category": "code_security", "line_number": d.get("line_number"),
                                  "resource": d.get("resource"), "scan_type": scan_type},
            "status":            "open",
        })

    with get_inventory_conn() as iconn:
        written = upsert_findings(
            conn=iconn,
            findings=findings,
            source_engine="secops",
            tenant_id=tenant_id,
            scan_run_id=scan_run_id,
        )
    logger.info("security_findings: wrote %d SecOps rows for scan %s", written, secops_scan_id)


def _run_scan_and_persist(
    secops_scan_id: str,
    tenant_id: str,
    customer_id: Optional[str],
    orchestration_id: Optional[str],
    project_name: str,
    repo_url: str,
    branch: str,
    input_path: str,
    account_id: Optional[str] = None,
    scan_run_id: Optional[str] = None,
) -> dict:
    """Run SAST scan pipeline and persist results.

    Args:
        secops_scan_id: Unique scan identifier.
        tenant_id: Tenant owning this scan.
        customer_id: Customer identifier (defaults to tenant_id in db writer).
        orchestration_id: Legacy orchestration identifier.
        project_name: Human-readable project name derived from repo_url.
        repo_url: Validated git clone URL (resolved from onboarding when account_id present).
        branch: Branch to scan.
        input_path: Local filesystem path where repo has been cloned.
        account_id: Validated cloud account identifier from onboarding engine.
        scan_run_id: Pipeline-wide scan run identifier.

    Returns:
        Summary dict with file/finding counts and severity breakdown.
    """
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
        account_id=account_id,
        scan_run_id=scan_run_id,
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

        # Count severity breakdown from findings
        sev_counts: dict = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for file_result in results:
            for finding in file_result.get("findings", []):
                sev = finding.get("severity", "").lower()
                if sev in sev_counts:
                    sev_counts[sev] += 1

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
            **sev_counts,
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

        try:
            _emit_secops_findings(
                secops_scan_id=secops_scan_id,
                tenant_id=tenant_id,
                scan_run_id=scan_run_id or secops_scan_id,
            )
        except Exception as emit_err:
            logger.warning(f"[{secops_scan_id}] security_findings emit failed (non-fatal): {emit_err}")

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
async def scan_repo(
    request: ScanRequest,
    auth: Any = Depends(require_permission("secops:read") if _AUTH_AVAILABLE else (lambda: None)),
):
    """Clone a git repo and scan for SAST vulnerabilities.

    When account_id is provided:
      1. Calls the onboarding engine to validate account ownership (fail-closed, 5s timeout).
      2. Resolves repo_url from auth_config.repo_url in the onboarding response.
      3. Uses the validated account_id and repo_url for the scan.

    When account_id is absent (legacy / direct-API callers):
      1. Uses request.repo_url directly (must pass VCS allowlist checks).
      2. Derives a stable account_id hash for secops_latest_scan upsert.
    """
    # Resolve tenant_id from AuthContext when available; fall back to request body.
    tenant_id: str = getattr(auth, "engine_tenant_id", None) or request.tenant_id

    # Resolve auth header for forwarding to onboarding engine.
    auth_header: Optional[str] = getattr(auth, "_raw_header", None)

    # Determine repo_url — either validated via onboarding or from request directly.
    resolved_repo_url: str
    resolved_account_id: Optional[str] = request.account_id
    resolved_branch: str = request.branch

    if request.account_id:
        # Validate ownership and resolve repo_url from onboarding engine.
        try:
            account_dict = _validate_account_ownership(
                account_id=request.account_id,
                tenant_id=tenant_id,
                auth_header=auth_header,
            )
        except HTTPException:
            raise

        auth_config = account_dict.get("auth_config") or {}
        resolved_repo_url = auth_config.get("repo_url", "")
        if not resolved_repo_url:
            raise HTTPException(
                status_code=400,
                detail=f"Account {request.account_id} has no repo_url in auth_config",
            )
        # Use default_branch from account if not overridden by caller.
        if auth_config.get("default_branch") and request.branch == "main":
            resolved_branch = auth_config["default_branch"]
        # Use the validated account_id value returned by onboarding (normalized).
        resolved_account_id = account_dict.get("account_id") or request.account_id
    else:
        # Direct API path — repo_url validated in ScanRequest.validate_repo_url.
        if not request.repo_url:
            raise HTTPException(
                status_code=400,
                detail="repo_url is required when account_id is not provided",
            )
        resolved_repo_url = request.repo_url

    secops_scan_id = str(uuid.uuid4())
    project_name = _project_name_from_url(resolved_repo_url)
    input_path = os.path.join(INPUT_FOLDER, project_name)

    try:
        _clone_repo(resolved_repo_url, resolved_branch, input_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to clone repo: {e}")

    try:
        summary = _run_scan_and_persist(
            secops_scan_id=secops_scan_id,
            tenant_id=tenant_id,
            customer_id=tenant_id,  # Always use tenant_id — never request.customer_id
            orchestration_id=request.scan_run_id,
            project_name=project_name,
            repo_url=resolved_repo_url,
            branch=resolved_branch,
            input_path=input_path,
            account_id=resolved_account_id,
            scan_run_id=request.scan_run_id,
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
        tenant_id=tenant_id,
        project_name=project_name,
        status="completed",
        summary=summary,
        findings_count=summary.get("total_findings", 0),
    )


@router.get("/scan/{secops_scan_id}/status")
async def get_scan_status(
    secops_scan_id: str,
    auth: Any = Depends(require_permission("secops:read") if _AUTH_AVAILABLE else (lambda: None)),
):
    """Poll SAST scan status.

    B-4b: Requires secops:read permission. Scans belonging to a different tenant
    return HTTP 404 (not 403) to avoid leaking scan existence.
    """
    tenant_id: Optional[str] = getattr(auth, "engine_tenant_id", None)

    # In-memory cache hit — must still verify tenant ownership when auth is available
    if secops_scan_id in _scan_status:
        cached = _scan_status[secops_scan_id]
        cached_tenant = cached.get("tenant_id")
        if tenant_id and cached_tenant and cached_tenant != tenant_id:
            raise HTTPException(status_code=404, detail="Scan not found")
        return {"secops_scan_id": secops_scan_id, **cached}

    try:
        from database.db_config import get_dict_connection
        conn = get_dict_connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT secops_scan_id, tenant_id, status, files_scanned, total_findings, "
                    "total_errors, summary FROM secops_report WHERE secops_scan_id = %s",
                    (secops_scan_id,),
                )
                row = cur.fetchone()
                if not row:
                    raise HTTPException(status_code=404, detail="Scan not found")
                row_dict = dict(row)
                # B-4b: return 404 (not 403) when scan belongs to a different tenant
                if tenant_id and row_dict.get("tenant_id") != tenant_id:
                    raise HTTPException(status_code=404, detail="Scan not found")
                return row_dict
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
    auth: Any = Depends(require_permission("secops:read") if _AUTH_AVAILABLE else (lambda: None)),
):
    """Get SAST findings for a scan from DB.

    B-4a: All queries are scoped to ``auth.engine_tenant_id``.  A scan that
    exists but belongs to a different tenant returns HTTP 404.
    """
    tenant_id: Optional[str] = getattr(auth, "engine_tenant_id", None)

    try:
        from database.db_config import get_dict_connection
        conn = get_dict_connection()
        try:
            with conn.cursor() as cur:
                # B-4a: Verify scan ownership and resolve tenant_id.
                # Always look up from secops_report so we have a concrete tenant_id
                # for the findings query — even for platform admins where engine_tenant_id
                # is None (they are unrestricted by design, but the query still needs a value).
                cur.execute(
                    "SELECT tenant_id FROM secops_report WHERE secops_scan_id = %s",
                    (secops_scan_id,),
                )
                report_row = cur.fetchone()
                if report_row is None:
                    raise HTTPException(status_code=404, detail="Scan not found")
                scan_tenant_id = dict(report_row)["tenant_id"]

                if tenant_id and scan_tenant_id != tenant_id:
                    # Tenant-scoped user requesting another tenant's scan — return 404
                    raise HTTPException(status_code=404, detail="Scan not found")

                # Use the scan's own tenant_id for the findings filter
                effective_tenant_id = scan_tenant_id

                query = """
                    SELECT id, secops_scan_id, file_path, language, rule_id,
                           severity, message, line_number, status, resource, metadata
                    FROM secops_findings
                    WHERE secops_scan_id = %s AND tenant_id = %s
                """
                params: list = [secops_scan_id, effective_tenant_id]

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
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scans")
async def list_scans(
    tenant_id: str = Query(..., description="Tenant ID"),
    project_name: Optional[str] = Query(None, description="Filter by project/repo name"),
    limit: int = Query(50, description="Max scans to return"),
    auth: Any = Depends(require_permission("secops:read") if _AUTH_AVAILABLE else (lambda: None)),
):
    """List SAST scans for a tenant — one row per (account_id, scan_type) from secops_latest_scan."""
    try:
        from database.db_config import get_dict_connection
        conn = get_dict_connection()
        try:
            with conn.cursor() as cur:
                query = """
                    SELECT tenant_id, account_id, scan_type, repo_url, project_name,
                           default_branch, secops_scan_id, scan_run_id, status,
                           total_findings, critical_count, high_count, medium_count, low_count,
                           files_scanned, languages_detected, scan_timestamp, completed_at,
                           first_seen_at, last_seen_at
                    FROM secops_latest_scan
                    WHERE tenant_id = %s
                      AND (scan_type IS NULL OR scan_type = 'sast')
                """
                params: list = [tenant_id]

                if project_name:
                    query += " AND project_name = %s"
                    params.append(project_name)

                query += " ORDER BY last_seen_at DESC LIMIT %s"
                params.append(limit)

                cur.execute(query, params)
                scans = []
                for row in cur.fetchall():
                    d = dict(row)
                    for k in ("scan_timestamp", "completed_at", "first_seen_at", "last_seen_at"):
                        if d.get(k) and hasattr(d[k], "isoformat"):
                            d[k] = d[k].isoformat()
                    scans.append(d)

                return {"tenant_id": tenant_id, "total": len(scans), "scans": scans}
        finally:
            conn.close()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/latest-scans")
async def list_latest_scans(
    tenant_id: str = Query(..., description="Tenant ID"),
    scan_type: Optional[str] = Query(None, description="Filter by scan_type: sast, dast"),
    limit: int = Query(100, description="Max rows to return"),
    auth: Any = Depends(require_permission("secops:read") if _AUTH_AVAILABLE else (lambda: None)),
):
    """Return all secops_latest_scan rows for the tenant with flattened severity counts.

    Returns one row per (account_id, scan_type) — the most recent completed scan
    per account. Ordered by last_seen_at DESC.
    """
    try:
        from database.db_config import get_dict_connection
        conn = get_dict_connection()
        try:
            with conn.cursor() as cur:
                query = """
                    SELECT tenant_id, account_id, scan_type, repo_url, project_name,
                           default_branch, secops_scan_id, scan_run_id, status,
                           total_findings, critical_count, high_count, medium_count, low_count,
                           files_scanned, languages_detected, scan_timestamp, completed_at,
                           first_seen_at, last_seen_at
                    FROM secops_latest_scan
                    WHERE tenant_id = %s
                """
                params: list = [tenant_id]

                if scan_type:
                    query += " AND scan_type = %s"
                    params.append(scan_type)

                query += " ORDER BY last_seen_at DESC LIMIT %s"
                params.append(limit)

                cur.execute(query, params)
                rows = []
                for row in cur.fetchall():
                    d = dict(row)
                    for k in ("scan_timestamp", "completed_at", "first_seen_at", "last_seen_at"):
                        if d.get(k) and hasattr(d[k], "isoformat"):
                            d[k] = d[k].isoformat()
                    rows.append(d)

                return {"tenant_id": tenant_id, "total": len(rows), "latest_scans": rows}
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
