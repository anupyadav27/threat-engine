"""
SecOps DB Writer — persist scan reports and findings to threat_engine_secops.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .db_config import get_connection

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity normalization
# ---------------------------------------------------------------------------
_SEVERITY_MAP = {
    "blocker": "critical",
    "critical": "critical",
    "major": "high",
    "minor": "medium",
    "info": "low",
    "security hotspot": "medium",
}


def normalize_severity(raw: Optional[str]) -> str:
    """Map scanner defaultSeverity → our 5-tier: critical/high/medium/low/info."""
    if not raw or not raw.strip():
        return "medium"
    return _SEVERITY_MAP.get(raw.strip().lower(), "medium")


# ---------------------------------------------------------------------------
# Scan report persistence
# ---------------------------------------------------------------------------

def persist_scan_report(
    secops_scan_id: str,
    tenant_id: str,
    project_name: str,
    repo_url: str,
    branch: str = "main",
    status: str = "running",
    customer_id: Optional[str] = None,
    orchestration_id: Optional[str] = None,
    first_seen_at: Optional[datetime] = None,
    metadata: Optional[Dict] = None,
    scan_type: str = "sast",
    account_id: Optional[str] = None,
    scan_run_id: Optional[str] = None,
) -> None:
    """Insert or update secops_report row.

    Args:
        secops_scan_id: Unique scan identifier.
        tenant_id: Tenant owning this scan (always from AuthContext, never request body).
        project_name: Repository or target project name.
        repo_url: Git clone URL or target URL.
        branch: Branch name (SAST) or empty string (DAST).
        status: Initial scan status.
        customer_id: Forced to tenant_id when absent (prevents cross-tenant poisoning).
        orchestration_id: Pipeline-wide orchestration identifier.
        first_seen_at: Timestamp override (defaults to now).
        metadata: Arbitrary extra metadata JSONB.
        scan_type: 'sast' or 'dast'.
        account_id: Validated cloud account identifier from onboarding engine.
        scan_run_id: Pipeline-wide scan_run_id (same as orchestration_id for Argo flows).
    """
    # Security: customer_id is ALWAYS derived from tenant_id — never accepted from request body.
    effective_customer_id = customer_id or tenant_id

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO secops_report
                    (secops_scan_id, orchestration_id, tenant_id, customer_id,
                     project_name, repo_url, branch, scan_type, status,
                     scan_timestamp, metadata, account_id, scan_run_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (secops_scan_id) DO UPDATE SET
                    status = EXCLUDED.status,
                    metadata = EXCLUDED.metadata,
                    account_id = EXCLUDED.account_id,
                    scan_run_id = EXCLUDED.scan_run_id
            """, (
                secops_scan_id,
                orchestration_id,
                tenant_id,
                effective_customer_id,
                project_name,
                repo_url,
                branch,
                scan_type,
                status,
                first_seen_at or datetime.now(timezone.utc),
                json.dumps(metadata or {}, default=str),
                account_id,
                scan_run_id,
            ))
        conn.commit()
        logger.info(f"Persisted secops_report: {secops_scan_id} status={status}")
    finally:
        conn.close()


def complete_scan_report(
    secops_scan_id: str,
    status: str,
    files_scanned: int,
    total_findings: int,
    total_errors: int,
    languages_detected: List[str],
    summary: Dict[str, Any],
) -> None:
    """Update scan report with completion data and upsert secops_latest_scan.

    Args:
        secops_scan_id: Unique scan identifier to update.
        status: Final scan status ('completed' or 'failed').
        files_scanned: Number of files or endpoints processed.
        total_findings: Total findings count.
        total_errors: Number of scan errors.
        languages_detected: List of detected languages or ['dast'].
        summary: Summary dict with optional severity counts (critical/high/medium/low).
    """
    completed_at = datetime.now(timezone.utc)
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE secops_report SET
                    status = %s,
                    completed_at = %s,
                    files_scanned = %s,
                    total_findings = %s,
                    total_errors = %s,
                    languages_detected = %s,
                    summary = %s
                WHERE secops_scan_id = %s
            """, (
                status,
                completed_at,
                files_scanned,
                total_findings,
                total_errors,
                json.dumps(languages_detected),
                json.dumps(summary, default=str),
                secops_scan_id,
            ))
        conn.commit()
        logger.info(
            f"Completed secops_report: {secops_scan_id} status={status} findings={total_findings}"
        )
    finally:
        conn.close()

    # Upsert secops_latest_scan — fetch the scan row to get account_id, tenant_id, etc.
    _upsert_latest_scan_from_report(
        secops_scan_id=secops_scan_id,
        status=status,
        files_scanned=files_scanned,
        total_findings=total_findings,
        languages_detected=languages_detected,
        summary=summary,
        completed_at=completed_at,
    )


def _upsert_latest_scan_from_report(
    secops_scan_id: str,
    status: str,
    files_scanned: int,
    total_findings: int,
    languages_detected: List[str],
    summary: Dict[str, Any],
    completed_at: datetime,
) -> None:
    """Read secops_report to get account_id/tenant_id/etc., then call upsert_latest_scan.

    Args:
        secops_scan_id: Scan to fetch context for.
        status: Final status.
        files_scanned: File/endpoint count.
        total_findings: Total findings count.
        languages_detected: Languages list.
        summary: Summary dict (may contain severity counts).
        completed_at: Completion timestamp.
    """
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT tenant_id, account_id, scan_type, customer_id,
                       repo_url, project_name, scan_run_id
                FROM secops_report
                WHERE secops_scan_id = %s
            """, (secops_scan_id,))
            row = cur.fetchone()
    finally:
        conn.close()

    if not row:
        logger.warning(
            f"_upsert_latest_scan_from_report: secops_report row not found for {secops_scan_id}"
        )
        return

    (tenant_id, account_id, scan_type, customer_id,
     repo_url, project_name, scan_run_id) = row

    # Derive stable account_id when not supplied (backward compat for direct-API callers).
    if not account_id:
        import hashlib as _hashlib
        _key = f"{tenant_id}:{repo_url or ''}:{scan_type or 'sast'}"
        account_id = _hashlib.sha256(_key.encode()).hexdigest()[:32]

    upsert_latest_scan(
        tenant_id=tenant_id,
        account_id=account_id,
        scan_type=scan_type or "sast",
        secops_scan_id=secops_scan_id,
        scan_run_id=scan_run_id,
        repo_url=repo_url,
        project_name=project_name,
        default_branch=None,
        status=status,
        files_scanned=files_scanned,
        total_findings=total_findings,
        languages_detected=languages_detected,
        summary=summary,
        completed_at=completed_at,
    )


def upsert_latest_scan(
    tenant_id: str,
    account_id: str,
    scan_type: str,
    secops_scan_id: str,
    scan_run_id: Optional[str],
    repo_url: Optional[str],
    project_name: Optional[str],
    default_branch: Optional[str],
    status: str,
    files_scanned: int,
    total_findings: int,
    languages_detected: List[str],
    summary: Dict[str, Any],
    completed_at: Optional[datetime] = None,
) -> None:
    """Upsert one row into secops_latest_scan for the (tenant, account, scan_type) triple.

    Uses ON CONFLICT (tenant_id, account_id, scan_type) DO UPDATE so every completion
    of a scan for the same account overwrites the previous snapshot. This is the source
    of truth for list_scans and list_dast_scans endpoints.

    Args:
        tenant_id: Tenant identifier (must match the authenticated tenant).
        account_id: Cloud account or derived stable key for backward compat.
        scan_type: 'sast' or 'dast'.
        secops_scan_id: Unique scan identifier for this run.
        scan_run_id: Pipeline-wide scan run identifier.
        repo_url: Repository or target URL.
        project_name: Human-readable project name.
        default_branch: Default branch (None for DAST).
        status: Final scan status.
        files_scanned: File or endpoint count.
        total_findings: Total findings count.
        languages_detected: List of detected languages.
        summary: Summary dict; keys 'critical', 'high', 'medium', 'low' used for counts.
        completed_at: Completion timestamp (defaults to now).
    """
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO secops_latest_scan (
                    tenant_id, account_id, scan_type, repo_url, project_name,
                    default_branch, secops_scan_id, scan_run_id, status,
                    total_findings, critical_count, high_count, medium_count, low_count,
                    files_scanned, languages_detected, scan_timestamp, completed_at,
                    first_seen_at, last_seen_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                          NOW(), %s, NOW(), NOW())
                ON CONFLICT (tenant_id, account_id, scan_type) DO UPDATE SET
                    secops_scan_id     = EXCLUDED.secops_scan_id,
                    scan_run_id        = EXCLUDED.scan_run_id,
                    status             = EXCLUDED.status,
                    total_findings     = EXCLUDED.total_findings,
                    critical_count     = EXCLUDED.critical_count,
                    high_count         = EXCLUDED.high_count,
                    medium_count       = EXCLUDED.medium_count,
                    low_count          = EXCLUDED.low_count,
                    files_scanned      = EXCLUDED.files_scanned,
                    languages_detected = EXCLUDED.languages_detected,
                    scan_timestamp     = EXCLUDED.scan_timestamp,
                    completed_at       = EXCLUDED.completed_at,
                    last_seen_at       = NOW()
            """, (
                tenant_id,
                account_id,
                scan_type,
                repo_url,
                project_name,
                default_branch,
                secops_scan_id,
                scan_run_id,
                status,
                total_findings,
                int(summary.get("critical", 0) or 0),
                int(summary.get("high", 0) or 0),
                int(summary.get("medium", 0) or 0),
                int(summary.get("low", 0) or 0),
                files_scanned,
                json.dumps(languages_detected),
                completed_at or datetime.now(timezone.utc),
            ))
        conn.commit()
        logger.info(
            f"Upserted secops_latest_scan: tenant={tenant_id} account={account_id} "
            f"type={scan_type} status={status} findings={total_findings}"
        )
    except Exception as e:
        logger.error(f"upsert_latest_scan failed for scan {secops_scan_id}: {e}", exc_info=True)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Findings persistence
# ---------------------------------------------------------------------------

def persist_findings(
    secops_scan_id: str,
    tenant_id: str,
    scan_results: List[Dict[str, Any]],
    repo_base_path: str = "",
    customer_id: Optional[str] = None,
) -> int:
    """Persist scan findings to secops_findings.

    Args:
        secops_scan_id: Scan identifier these findings belong to.
        tenant_id: Tenant owning these findings.
        scan_results: List of per-file result dicts from scan engine:
            [{"file": "/path/to/file.py", "language": "python", "findings": [...]}]
        repo_base_path: Base path to strip from file paths to get relative paths.
        customer_id: Customer identifier (defaults to tenant_id if absent).

    Returns:
        Number of findings inserted.
    """
    count = 0
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            for file_result in scan_results:
                file_path = file_result.get("file", "")
                # Make path relative to repo root
                if repo_base_path and file_path.startswith(repo_base_path):
                    file_path = file_path[len(repo_base_path):].lstrip("/")

                language = file_result.get("language", "unknown")
                findings = file_result.get("findings") or []

                for f in findings:
                    # Skip not_applicable findings
                    f_status = f.get("status", "violation")
                    if f_status == "not_applicable":
                        continue

                    rule_id = f.get("rule_id", "unknown")
                    raw_sev = f.get("severity") or f.get("defaultSeverity") or "Major"
                    severity = normalize_severity(raw_sev)
                    message = f.get("message", "")
                    line_number = f.get("line") or f.get("line_number")
                    resource = f.get("resource")

                    # Extra metadata (everything else)
                    meta_keys = {"rule_id", "message", "line", "line_number",
                                 "severity", "defaultSeverity", "status", "resource"}
                    extra = {k: v for k, v in f.items() if k not in meta_keys}

                    cur.execute("""
                        INSERT INTO secops_findings
                            (secops_scan_id, tenant_id, customer_id, file_path,
                             language, rule_id, severity, message, line_number,
                             status, resource, metadata)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, (
                        secops_scan_id,
                        tenant_id,
                        customer_id,
                        file_path,
                        language,
                        rule_id,
                        severity,
                        message,
                        line_number,
                        f_status,
                        resource,
                        json.dumps(extra, default=str) if extra else None,
                    ))
                    count += 1

        conn.commit()
        logger.info(f"Persisted {count} secops_findings for scan {secops_scan_id}")
    finally:
        conn.close()
    return count
