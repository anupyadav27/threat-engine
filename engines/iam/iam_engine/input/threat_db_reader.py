"""
Threat DB Reader for IAM Security Engine

Reads threat findings from the threat_findings table in Threat DB,
filters by IAM-relevant rule IDs, and returns findings for IAM analysis.

Data flow:
  - Threat Engine writes individual findings → threat_findings table
  - Threat Engine writes scan summary → threat_report table (report_data has NO findings)
  - IAM Engine reads from threat_findings table directly (filtered by rule_id/resource_type)
"""

import json
import os
from typing import Dict, List, Optional, Any, Set
import logging

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    PSYCOPG_AVAILABLE = True
except ImportError:
    PSYCOPG_AVAILABLE = False

logger = logging.getLogger(__name__)


def _get_threat_db_connection():
    """Get Threat DB connection using individual parameters to avoid password encoding issues."""
    return psycopg2.connect(
        host=os.getenv('THREAT_DB_HOST', 'localhost'),
        port=int(os.getenv('THREAT_DB_PORT', '5432')),
        database=os.getenv('THREAT_DB_NAME', 'threat_engine_threat'),
        user=os.getenv('THREAT_DB_USER', 'postgres'),
        password=os.getenv('THREAT_DB_PASSWORD', '')
    )


class ThreatDBReader:
    """
    Reads threat findings from Threat DB (threat_findings table).

    The threat_findings table stores individual misconfig findings with columns:
        finding_id, scan_run_id, tenant_id, customer_id,
        rule_id, threat_category, severity, status, resource_type,
        resource_id, resource_uid, account_id, region,
        mitre_tactics (jsonb), mitre_techniques (jsonb),
        evidence (jsonb), finding_data (jsonb),
        first_seen_at, last_seen_at, created_at
    """

    def __init__(self, db_url: Optional[str] = None):
        """
        Initialize Threat DB reader.

        Args:
            db_url: Optional database URL (ignored, uses env vars with individual params)
        """
        self.db_url = None  # Not used
        self._conn = None

    def _get_conn(self):
        """Get database connection, reset if in failed transaction state."""
        if self._conn is not None and not self._conn.closed:
            # Reset connection if it's in a failed transaction state
            if self._conn.info.transaction_status == psycopg2.extensions.TRANSACTION_STATUS_INERROR:
                self._conn.rollback()
            return self._conn
        if not PSYCOPG_AVAILABLE:
            raise RuntimeError("psycopg2 required for ThreatDBReader. Install psycopg2-binary.")
        self._conn = _get_threat_db_connection()
        return self._conn

    def close(self):
        """Close database connection."""
        if self._conn and not self._conn.closed:
            self._conn.close()
            self._conn = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def _resolve_scan_run_id(self, conn, tenant_id: str, scan_run_id: str) -> Optional[str]:
        """
        Resolve scan_run_id. Handles 'latest' by looking up the most recent scan.
        All engines now use the same scan_run_id — no per-engine scan IDs.
        """
        if scan_run_id == "latest":
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT scan_run_id FROM threat_report WHERE tenant_id = %s ORDER BY created_at DESC LIMIT 1",
                        (tenant_id,),
                    )
                    row = cur.fetchone()
                    if row:
                        return row[0]
            except Exception as e:
                logger.error(f"Error resolving latest scan_run_id: {e}")
                conn.rollback()
            return None
        return scan_run_id

    def load_threat_report_summary(self, tenant_id: str, scan_run_id: str) -> Optional[Dict[str, Any]]:
        """
        Load threat report summary from threat_report table.

        Note: report_data JSONB contains only scan_context, schema_version, threat_summary.
              Individual findings are in threat_findings table (use get_misconfig_findings).

        Args:
            tenant_id: Tenant identifier
            scan_run_id: Scan run ID (check_scan_id passed to threat engine)

        Returns:
            Report summary dict or None if not found
        """
        if not PSYCOPG_AVAILABLE:
            return None
        conn = self._get_conn()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT scan_run_id, tenant_id, provider,
                           total_findings, critical_findings, high_findings,
                           medium_findings, low_findings, status,
                           report_data, created_at
                    FROM threat_report
                    WHERE tenant_id = %s AND scan_run_id = %s
                    """,
                    (tenant_id, scan_run_id),
                )
                row = cur.fetchone()
            if not row:
                logger.warning(f"Threat report not found: tenant_id={tenant_id}, scan_run_id={scan_run_id}")
                return None
            return dict(row)
        except Exception as e:
            logger.error(f"Error loading threat report summary: {e}")
            conn.rollback()
            return None

    def get_misconfig_findings(
        self,
        tenant_id: str,
        scan_run_id: str,
        iam_rule_ids: Optional[Set[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get misconfig findings directly from threat_findings table.

        Queries threat_findings table by tenant_id + threat_scan_id,
        optionally filtered by IAM rule IDs.

        Args:
            tenant_id: Tenant identifier
            scan_run_id: Scan run ID (check_scan_id)
            iam_rule_ids: Set of IAM-relevant rule IDs to filter by

        Returns:
            List of finding dicts (IAM-relevant only if iam_rule_ids provided)
        """
        if not PSYCOPG_AVAILABLE:
            return []
        conn = self._get_conn()
        try:
            resolved_id = self._resolve_scan_run_id(conn, tenant_id, scan_run_id)
            if not resolved_id:
                logger.warning(f"Could not resolve scan_run_id={scan_run_id}")
                return []

            # Build query — filter by IAM rule_ids if provided
            if iam_rule_ids:
                # Use rule_id IN (...) filter for IAM-relevant findings
                placeholders = ','.join(['%s'] * len(iam_rule_ids))
                query = f"""
                    SELECT finding_id, scan_run_id, tenant_id, customer_id,
                           rule_id, threat_category,
                           severity, status,
                           resource_type, resource_id, resource_uid,
                           account_id, region,
                           mitre_tactics, mitre_techniques,
                           evidence, finding_data,
                           first_seen_at, last_seen_at, created_at
                    FROM threat_findings
                    WHERE tenant_id = %s AND scan_run_id = %s
                      AND rule_id IN ({placeholders})
                    ORDER BY severity, rule_id
                """
                params = [tenant_id, resolved_id] + list(iam_rule_ids)
            else:
                # Return all findings for this scan
                query = """
                    SELECT finding_id, scan_run_id, tenant_id, customer_id,
                           rule_id, threat_category,
                           severity, status,
                           resource_type, resource_id, resource_uid,
                           account_id, region,
                           mitre_tactics, mitre_techniques,
                           evidence, finding_data,
                           first_seen_at, last_seen_at, created_at
                    FROM threat_findings
                    WHERE tenant_id = %s AND scan_run_id = %s
                    ORDER BY severity, rule_id
                """
                params = [tenant_id, resolved_id]

            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(query, params)
                rows = cur.fetchall()

            # Convert rows to finding dicts compatible with IAM enricher
            findings = []
            for row in rows:
                fd = row.get('finding_data') or {}
                ev = row.get('evidence') or {}
                findings.append({
                    'misconfig_finding_id': row['finding_id'],
                    'finding_key': fd.get('finding_key', ''),
                    'rule_id': row['rule_id'],
                    'severity': row['severity'],
                    'result': row['status'],
                    'status': row['status'],
                    'account': row['account_id'] or '',
                    'account_id': row['account_id'] or '',
                    'hierarchy_id': row['account_id'] or '',
                    'region': row['region'] or '',
                    'service': (row['resource_type'] or ''),
                    'resource_type': row['resource_type'] or '',
                    'resource_id': row['resource_id'] or '',
                    'resource_arn': row['resource_uid'] or '',
                    'resource_uid': row['resource_uid'] or '',
                    'resource': fd.get('resource', {}),
                    'title': fd.get('title', ''),
                    'description': fd.get('description', ''),
                    'remediation': fd.get('remediation'),
                    'domain': fd.get('domain', ''),
                    'risk_score': fd.get('risk_score'),
                    'threat_tags': fd.get('threat_tags', []),
                    'evidence_refs': ev.get('evidence_refs', []),
                    'checked_fields': ev.get('checked_fields', []),
                    'mitre_techniques': row.get('mitre_techniques') or [],
                    'mitre_tactics': row.get('mitre_tactics') or [],
                    'threat_category': row.get('threat_category'),
                    'first_seen_at': row['first_seen_at'].isoformat() if row.get('first_seen_at') else None,
                    'last_seen_at': row['last_seen_at'].isoformat() if row.get('last_seen_at') else None,
                })

            if iam_rule_ids:
                logger.info(f"Loaded {len(findings)} IAM findings from threat_findings table "
                            f"(filtered by {len(iam_rule_ids)} IAM rule IDs)")
            else:
                logger.info(f"Loaded {len(findings)} total findings from threat_findings table")
            return findings

        except Exception as e:
            logger.error(f"Error loading findings from threat_findings: {e}")
            conn.rollback()
            return []

    def get_findings_by_resource(
        self,
        tenant_id: str,
        scan_run_id: str,
        resource_uid: str,
        iam_rule_ids: Optional[Set[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get threat findings for a specific resource from threat_findings table.

        Args:
            tenant_id: Tenant identifier
            scan_run_id: Scan run ID
            resource_uid: Resource UID/ARN
            iam_rule_ids: Optional filter by IAM rule IDs

        Returns:
            List of findings for the resource
        """
        if not PSYCOPG_AVAILABLE:
            return []
        conn = self._get_conn()
        try:
            resolved_id = self._resolve_scan_run_id(conn, tenant_id, scan_run_id)
            if not resolved_id:
                return []

            query = """
                SELECT finding_id, tenant_id, customer_id,
                       scan_run_id, rule_id, threat_category,
                       severity, status,
                       resource_type, resource_id, resource_uid,
                       account_id, region,
                       mitre_tactics, mitre_techniques,
                       evidence, finding_data,
                       first_seen_at, last_seen_at, created_at
                FROM threat_findings
                WHERE tenant_id = %s AND scan_run_id = %s
                  AND resource_uid = %s
            """
            params = [tenant_id, resolved_id, resource_uid]

            if iam_rule_ids:
                placeholders = ','.join(['%s'] * len(iam_rule_ids))
                query += f" AND rule_id IN ({placeholders})"
                params.extend(list(iam_rule_ids))

            query += " ORDER BY severity, rule_id"

            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(query, params)
                rows = cur.fetchall()

            findings = []
            for row in rows:
                fd = row.get('finding_data') or {}
                ev = row.get('evidence') or {}
                findings.append({
                    'misconfig_finding_id': row['finding_id'],
                    'finding_key': fd.get('finding_key', ''),
                    'rule_id': row['rule_id'],
                    'severity': row['severity'],
                    'result': row['status'],
                    'status': row['status'],
                    'account': row['account_id'] or '',
                    'account_id': row['account_id'] or '',
                    'hierarchy_id': row['account_id'] or '',
                    'region': row['region'] or '',
                    'service': (row['resource_type'] or ''),
                    'resource_type': row['resource_type'] or '',
                    'resource_uid': row['resource_uid'] or '',
                    'resource_arn': row['resource_uid'] or '',
                    'resource': fd.get('resource', {}),
                    'title': fd.get('title', ''),
                    'description': fd.get('description', ''),
                    'mitre_techniques': row.get('mitre_techniques') or [],
                    'mitre_tactics': row.get('mitre_tactics') or [],
                    'threat_category': row.get('threat_category'),
                })
            return findings

        except Exception as e:
            logger.error(f"Error loading findings by resource: {e}")
            conn.rollback()
            return []
