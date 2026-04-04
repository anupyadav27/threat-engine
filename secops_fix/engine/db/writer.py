"""
DB Writer — persists remediation results to secops_remediation table.
"""

import logging
import uuid
from typing import List

from .db_config import get_connection
from models.fix_result import FixResult
from models.remediation import RemediationRequest

logger = logging.getLogger(__name__)


def init_remediation_rows(
    request: RemediationRequest,
    findings_count: int,
    fix_branch: str,
    scan_report,
) -> None:
    """
    Pre-create pending rows for all findings before processing starts.
    Allows status tracking even if engine crashes mid-run.
    """
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO secops_remediation
                    (secops_scan_id, finding_id, orchestration_id, tenant_id,
                     customer_id, repo_url, fix_branch, status)
                SELECT
                    sf.secops_scan_id,
                    sf.id,
                    %s,
                    sf.tenant_id,
                    sf.customer_id,
                    sr.repo_url,
                    %s,
                    'pending'
                FROM secops_findings sf
                JOIN secops_report sr ON sr.secops_scan_id = sf.secops_scan_id
                WHERE sf.secops_scan_id = %s
                  AND sf.status != 'not_applicable'
                  AND (%s IS NULL OR sf.severity = ANY(%s))
                ON CONFLICT DO NOTHING
            """, (
                scan_report.orchestration_id,
                fix_branch,
                request.secops_scan_id,
                request.severity_filter,
                request.severity_filter,
            ))
        conn.commit()
        logger.info(f"Initialised remediation rows for scan {request.secops_scan_id}")
    finally:
        conn.close()


def write_fix_result(fix: FixResult, fix_branch: str, repo_url: str) -> str:
    """
    Upsert a FixResult into secops_remediation.
    Returns the remediation_id.
    """
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE secops_remediation SET
                    rule_id            = %s,
                    file_path          = %s,
                    line_number        = %s,
                    language           = %s,
                    severity           = %s,
                    match_layer        = %s,
                    matched_rule_id    = %s,
                    original_code      = %s,
                    suggested_fix      = %s,
                    fix_explanation    = %s,
                    compliant_example  = %s,
                    repo_url           = %s,
                    fix_branch         = %s,
                    status             = %s,
                    error_message      = NULL
                WHERE finding_id = %s
                RETURNING remediation_id
            """, (
                fix.rule_id,
                fix.file_path,
                fix.line_number,
                fix.language,
                fix.severity,
                fix.match_layer,
                fix.matched_rule_id,
                fix.original_code,
                fix.suggested_fix,
                fix.fix_explanation,
                fix.compliant_example,
                repo_url,
                fix_branch,
                "fix_generated" if fix.suggested_fix else "matched" if fix.matched_rule_id else "skipped",
                fix.finding_id,
            ))
            row = cur.fetchone()
            remediation_id = str(row[0]) if row else str(uuid.uuid4())
        conn.commit()
        return remediation_id
    finally:
        conn.close()


def mark_applied(finding_id: int, fix_branch: str, pr_url: str = None) -> None:
    """Mark a finding's remediation as applied after git patch succeeds."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE secops_remediation
                SET status = 'applied', fix_branch = %s, pr_url = %s
                WHERE finding_id = %s
            """, (fix_branch, pr_url, finding_id))
        conn.commit()
    finally:
        conn.close()


def mark_failed(finding_id: int, error: str) -> None:
    """Mark a finding's remediation as failed with error detail."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE secops_remediation
                SET status = 'failed', error_message = %s
                WHERE finding_id = %s
            """, (error[:1024], finding_id))
        conn.commit()
    finally:
        conn.close()


def get_remediation_summary(secops_scan_id: str) -> dict:
    """Return count breakdown by status for a scan."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    COUNT(*)                                        AS total,
                    COUNT(*) FILTER (WHERE status = 'matched')     AS matched,
                    COUNT(*) FILTER (WHERE status = 'fix_generated') AS fix_generated,
                    COUNT(*) FILTER (WHERE status = 'applied')     AS applied,
                    COUNT(*) FILTER (WHERE status = 'failed')      AS failed,
                    COUNT(*) FILTER (WHERE status = 'skipped')     AS skipped,
                    MAX(fix_branch)                                 AS fix_branch,
                    MAX(pr_url)                                     AS pr_url
                FROM secops_remediation
                WHERE secops_scan_id = %s
            """, (secops_scan_id,))
            row = cur.fetchone()
            if not row:
                return {}
            return {
                "total": row[0], "matched": row[1], "fix_generated": row[2],
                "applied": row[3], "failed": row[4], "skipped": row[5],
                "fix_branch": row[6], "pr_url": row[7],
            }
    finally:
        conn.close()
