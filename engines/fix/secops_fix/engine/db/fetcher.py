"""
DB Fetcher — reads secops findings and scan report from threat_engine_secops.
"""

import logging
from typing import List, Optional

from .db_config import get_dict_connection
from models.finding import SecOpsFinding, ScanReport

logger = logging.getLogger(__name__)


def get_scan_report(secops_scan_id: str) -> Optional[ScanReport]:
    """Fetch scan report metadata for a given secops_scan_id."""
    conn = get_dict_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT secops_scan_id, orchestration_id, tenant_id, customer_id,
                       project_name, repo_url, branch, status, total_findings
                FROM secops_report
                WHERE secops_scan_id = %s
            """, (secops_scan_id,))
            row = cur.fetchone()
            if not row:
                return None
            return ScanReport(**dict(row))
    finally:
        conn.close()


def get_findings(
    secops_scan_id: str,
    severity_filter: Optional[List[str]] = None,
) -> List[SecOpsFinding]:
    """
    Fetch all findings for a scan.

    Args:
        secops_scan_id: UUID of the scan run.
        severity_filter: Optional list of severities to include, e.g. ["critical","high"].
                         None returns all severities.

    Returns:
        List of SecOpsFinding ordered by severity desc, file_path, line_number.
    """
    conn = get_dict_connection()
    try:
        with conn.cursor() as cur:
            if severity_filter:
                cur.execute("""
                    SELECT id, secops_scan_id, tenant_id, customer_id, file_path,
                           language, rule_id, severity, message, line_number,
                           status, resource, metadata, created_at
                    FROM secops_findings
                    WHERE secops_scan_id = %s
                      AND status != 'not_applicable'
                      AND severity = ANY(%s)
                    ORDER BY
                        CASE severity
                            WHEN 'critical' THEN 1
                            WHEN 'high'     THEN 2
                            WHEN 'medium'   THEN 3
                            WHEN 'low'      THEN 4
                            ELSE 5
                        END,
                        file_path, line_number
                """, (secops_scan_id, severity_filter))
            else:
                cur.execute("""
                    SELECT id, secops_scan_id, tenant_id, customer_id, file_path,
                           language, rule_id, severity, message, line_number,
                           status, resource, metadata, created_at
                    FROM secops_findings
                    WHERE secops_scan_id = %s
                      AND status != 'not_applicable'
                    ORDER BY
                        CASE severity
                            WHEN 'critical' THEN 1
                            WHEN 'high'     THEN 2
                            WHEN 'medium'   THEN 3
                            WHEN 'low'      THEN 4
                            ELSE 5
                        END,
                        file_path, line_number
                """, (secops_scan_id,))

            rows = cur.fetchall()
            return [SecOpsFinding(**dict(r)) for r in rows]
    finally:
        conn.close()


def get_rule_metadata(rule_id: str) -> Optional[dict]:
    """
    Fetch rule metadata from secops_rule_metadata table.

    This is the single source of truth for all rule data — seeded from the
    same JSON docs the SAST scanner uses, kept in sync automatically.
    Returns a dict matching the structure of the JSON doc files, or None.
    """
    if not rule_id:
        return None
    conn = get_dict_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT rule_id, title, description, recommendation, impact,
                       examples, "references", security_mappings, tags,
                       default_severity, category, raw_metadata
                FROM secops_rule_metadata
                WHERE rule_id = %s
                  AND status != 'disabled'
            """, (rule_id,))
            row = cur.fetchone()
            if not row:
                # Try trimming _metadata suffix (scanner stores without it sometimes)
                clean_id = rule_id.lower().removesuffix("_metadata")
                if clean_id != rule_id.lower():
                    cur.execute("""
                        SELECT rule_id, title, description, recommendation, impact,
                               examples, "references", security_mappings, tags,
                               default_severity, category, raw_metadata
                        FROM secops_rule_metadata
                        WHERE rule_id = %s
                          AND status != 'disabled'
                    """, (clean_id,))
                    row = cur.fetchone()
            if not row:
                return None
            return dict(row)
    finally:
        conn.close()


def get_rule_metadata_batch(rule_ids: list) -> dict:
    """
    Fetch multiple rules in a single query.
    Returns {rule_id: rule_dict} for all found rules.
    Used to pre-fetch all rules for a scan in one DB round-trip.
    """
    if not rule_ids:
        return {}
    # Deduplicate and filter None/empty
    ids = list({r.lower() for r in rule_ids if r})
    conn = get_dict_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT rule_id, title, description, recommendation, impact,
                       examples, "references", security_mappings, tags,
                       default_severity, category, raw_metadata
                FROM secops_rule_metadata
                WHERE LOWER(rule_id) = ANY(%s)
                  AND status != 'disabled'
            """, (ids,))
            rows = cur.fetchall()
            return {dict(r)["rule_id"]: dict(r) for r in rows}
    finally:
        conn.close()


def get_finding_by_id(finding_id: int) -> Optional[SecOpsFinding]:
    """Fetch a single finding by its primary key."""
    conn = get_dict_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, secops_scan_id, tenant_id, customer_id, file_path,
                       language, rule_id, severity, message, line_number,
                       status, resource, metadata, created_at
                FROM secops_findings
                WHERE id = %s
            """, (finding_id,))
            row = cur.fetchone()
            if not row:
                return None
            return SecOpsFinding(**dict(row))
    finally:
        conn.close()
