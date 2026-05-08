"""
DB Writer — persists remediation results to secops_remediation table.
"""

import logging
import uuid
from typing import List

from .db_config import get_connection, get_dict_connection
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
    Uses INSERT ... ON CONFLICT so it works with or without pre-created rows.
    Returns the remediation_id.
    """
    status = "fix_generated" if fix.suggested_fix else "matched" if fix.matched_rule_id else "skipped"
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO secops_remediation
                    (secops_scan_id, finding_id, tenant_id, customer_id,
                     rule_id, file_path, line_number, language, severity,
                     match_layer, matched_rule_id, original_code,
                     suggested_fix, fix_explanation, compliant_example,
                     repo_url, fix_branch, status, error_message)
                VALUES (%s,%s,%s,%s, %s,%s,%s,%s,%s, %s,%s,%s, %s,%s,%s, %s,%s,%s,NULL)
                ON CONFLICT (finding_id) DO UPDATE SET
                    rule_id           = EXCLUDED.rule_id,
                    file_path         = EXCLUDED.file_path,
                    line_number       = EXCLUDED.line_number,
                    language          = EXCLUDED.language,
                    severity          = EXCLUDED.severity,
                    match_layer       = EXCLUDED.match_layer,
                    matched_rule_id   = EXCLUDED.matched_rule_id,
                    original_code     = EXCLUDED.original_code,
                    suggested_fix     = EXCLUDED.suggested_fix,
                    fix_explanation   = EXCLUDED.fix_explanation,
                    compliant_example = EXCLUDED.compliant_example,
                    repo_url          = EXCLUDED.repo_url,
                    fix_branch        = EXCLUDED.fix_branch,
                    status            = EXCLUDED.status,
                    error_message     = NULL
                RETURNING remediation_id
            """, (
                fix.secops_scan_id, fix.finding_id,
                "system", None,
                fix.rule_id, fix.file_path, fix.line_number,
                fix.language, fix.severity,
                fix.match_layer, fix.matched_rule_id, fix.original_code,
                fix.suggested_fix, fix.fix_explanation, fix.compliant_example,
                repo_url, fix_branch, status,
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


def mark_false_positive(finding_id: int, suppressed_by: str = "user") -> None:
    """
    Mark a finding as a false positive in secops_remediation.

    Effect:
      - Sets status = 'false_positive' in secops_remediation.
      - Future calls to _run_remediation skip this finding_id automatically.
      - The UI can display which findings were suppressed and by whom.

    Args:
        finding_id:    PK of the finding in secops_findings.
        suppressed_by: Identifier of who suppressed it (tenant_id, user email, etc.)
    """
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # Upsert — works whether a remediation row already exists or not
            cur.execute("""
                INSERT INTO secops_remediation (finding_id, secops_scan_id, tenant_id, status, error_message)
                SELECT id, secops_scan_id, tenant_id, 'false_positive', %s
                FROM secops_findings
                WHERE id = %s
                ON CONFLICT (finding_id) DO UPDATE
                    SET status        = 'false_positive',
                        error_message = EXCLUDED.error_message
            """, (f"suppressed_by:{suppressed_by}", finding_id))
        conn.commit()
        logger.info(f"Finding {finding_id} marked false_positive by {suppressed_by!r}")
    finally:
        conn.close()


def mark_open(finding_id: int) -> None:
    """Reset a false-positive finding back to 'pending' so it is included in the next run."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE secops_remediation
                SET status = 'pending', error_message = NULL
                WHERE finding_id = %s AND status = 'false_positive'
            """, (finding_id,))
        conn.commit()
        logger.info(f"Finding {finding_id} reopened (false_positive → pending)")
    finally:
        conn.close()


def get_false_positive_ids(secops_scan_id: str) -> set:
    """Return set of finding_id values marked as false_positive for a scan."""
    conn = get_dict_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT finding_id FROM secops_remediation
                WHERE secops_scan_id = %s AND status = 'false_positive'
            """, (secops_scan_id,))
            return {row["finding_id"] for row in cur.fetchall()}
    finally:
        conn.close()


def get_remediation_summary(secops_scan_id: str) -> dict:
    """Return count breakdown by status for a scan."""
    conn = get_dict_connection()
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
                "total": row["total"], "matched": row["matched"],
                "fix_generated": row["fix_generated"], "applied": row["applied"],
                "failed": row["failed"], "skipped": row["skipped"],
                "fix_branch": row["fix_branch"], "pr_url": row["pr_url"],
            }
    finally:
        conn.close()
