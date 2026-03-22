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
) -> None:
    """Insert or update secops_report row."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO secops_report
                    (secops_scan_id, orchestration_id, tenant_id, customer_id,
                     project_name, repo_url, branch, scan_type, status, first_seen_at, metadata)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (secops_scan_id) DO UPDATE SET
                    status = EXCLUDED.status,
                    metadata = EXCLUDED.metadata
            """, (
                secops_scan_id,
                orchestration_id,
                tenant_id,
                customer_id,
                project_name,
                repo_url,
                branch,
                scan_type,
                status,
                first_seen_at or datetime.now(timezone.utc),
                json.dumps(metadata or {}, default=str),
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
    """Update scan report with completion data."""
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
                datetime.now(timezone.utc),
                files_scanned,
                total_findings,
                total_errors,
                json.dumps(languages_detected),
                json.dumps(summary, default=str),
                secops_scan_id,
            ))
        conn.commit()
        logger.info(f"Completed secops_report: {secops_scan_id} status={status} findings={total_findings}")
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
    """
    Persist scan findings to secops_findings.

    Args:
        scan_results: List of per-file result dicts from scan engine:
            [{"file": "/path/to/file.py", "language": "python", "findings": [...]}]
        repo_base_path: Base path to strip from file paths to get relative paths.

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
