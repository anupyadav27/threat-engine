"""
Threat DB Reader for Data Security Engine

Reads threat findings from the threat_findings table in Threat DB,
filters by data-security-relevant rule IDs / resource types, and returns
findings for data security analysis.

Data flow:
  - Threat Engine writes individual findings → threat_findings table
  - Threat Engine writes scan summary → threat_report table (report_data has NO findings)
  - DataSec Engine reads from threat_findings table directly (filtered by resource_type/rule_id)
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

# Fallback hardcoded set (used when datasec DB is unreachable)
_DATA_STORE_SERVICES_FALLBACK: Set[str] = {
    's3', 'rds', 'dynamodb', 'redshift', 'glacier', 'documentdb',
    'neptune', 'glue', 'lakeformation', 'macie', 'ecr',
    'kms', 'elasticache', 'dax', 'efs', 'fsx',
}

# Module-level cache: {csp: frozenset}
_data_store_services_cache: Dict[str, Set[str]] = {}


def _get_datasec_db_connection():
    """Get DataSec DB connection for reading config tables."""
    return psycopg2.connect(
        host=os.getenv("DATASEC_DB_HOST", "localhost"),
        port=int(os.getenv("DATASEC_DB_PORT", "5432")),
        database=os.getenv("DATASEC_DB_NAME", "threat_engine_datasec"),
        user=os.getenv("DATASEC_DB_USER", "postgres"),
        password=os.getenv("DATASEC_DB_PASSWORD", ""),
    )


def load_data_store_services(csp: str = "aws") -> Set[str]:
    """
    Load data store service names from datasec_data_store_services table.

    Falls back to the hardcoded _DATA_STORE_SERVICES_FALLBACK set when the
    datasec DB is not available (e.g. local dev, unit tests).

    Results are module-level cached per CSP for the process lifetime.
    """
    global _data_store_services_cache
    if csp in _data_store_services_cache:
        return _data_store_services_cache[csp]

    if not PSYCOPG_AVAILABLE:
        return _DATA_STORE_SERVICES_FALLBACK

    try:
        conn = _get_datasec_db_connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT service_name FROM datasec_data_store_services "
                    "WHERE csp = %s AND is_active = TRUE",
                    (csp,),
                )
                rows = cur.fetchall()
        finally:
            conn.close()

        if rows:
            services = {row[0] for row in rows}
            _data_store_services_cache[csp] = services
            logger.info(
                f"Loaded {len(services)} data store service names for csp={csp} from datasec DB"
            )
            return services
    except Exception as exc:
        logger.warning(
            f"Could not load data store services from datasec DB (csp={csp}): {exc}. "
            "Using fallback hardcoded set."
        )

    return _DATA_STORE_SERVICES_FALLBACK


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
        finding_id, threat_scan_id, tenant_id, customer_id, scan_run_id,
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

    def _resolve_threat_scan_id(self, conn, tenant_id: str, scan_run_id: str) -> Optional[str]:
        """
        Resolve the threat_scan_id from threat_report table using tenant_id + scan_run_id.

        The threat_findings table uses threat_scan_id as FK, not scan_run_id directly.
        threat_scan_id format is typically 'threat_{scan_run_id}'.

        When called from the pipeline the caller may already pass the threat_scan_id
        (e.g. 'threat_bfed9ebc-...') — detect the prefix early to avoid the
        double-prefix 'threat_threat_...' bug.
        """
        # Already a threat_scan_id — return directly without DB lookup
        if scan_run_id and scan_run_id.startswith("threat_"):
            return scan_run_id

        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT threat_scan_id FROM threat_report WHERE tenant_id = %s AND scan_run_id = %s",
                    (tenant_id, scan_run_id),
                )
                row = cur.fetchone()
                if row:
                    return row[0]
        except Exception as e:
            logger.error(f"Error resolving threat_scan_id: {e}")
            conn.rollback()

        # Fallback: try the conventional format
        return f"threat_{scan_run_id}"

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
                    SELECT threat_scan_id, tenant_id, scan_run_id, provider,
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
        data_security_rule_ids: Optional[Set[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get misconfig findings directly from threat_findings table.

        Queries threat_findings table by tenant_id + threat_scan_id,
        optionally filtered by data security rule IDs.

        Args:
            tenant_id: Tenant identifier
            scan_run_id: Scan run ID (check_scan_id)
            data_security_rule_ids: Set of data-security-relevant rule IDs to filter by

        Returns:
            List of finding dicts (data-security-relevant only if rule_ids provided)
        """
        if not PSYCOPG_AVAILABLE:
            return []
        conn = self._get_conn()
        try:
            # Resolve threat_scan_id from threat_report
            threat_scan_id = self._resolve_threat_scan_id(conn, tenant_id, scan_run_id)
            if not threat_scan_id:
                logger.warning(f"Could not resolve threat_scan_id for scan_run_id={scan_run_id}")
                return []

            # Build query — filter by rule_ids if provided
            if data_security_rule_ids:
                placeholders = ','.join(['%s'] * len(data_security_rule_ids))
                query = f"""
                    SELECT finding_id, threat_scan_id, tenant_id, customer_id,
                           scan_run_id, rule_id, threat_category,
                           severity, status,
                           resource_type, resource_id, resource_uid,
                           account_id, region,
                           mitre_tactics, mitre_techniques,
                           evidence, finding_data,
                           first_seen_at, last_seen_at, created_at
                    FROM threat_findings
                    WHERE tenant_id = %s AND threat_scan_id = %s
                      AND rule_id IN ({placeholders})
                    ORDER BY severity, rule_id
                """
                params = [tenant_id, threat_scan_id] + list(data_security_rule_ids)
            else:
                # Return all findings for this scan
                query = """
                    SELECT finding_id, threat_scan_id, tenant_id, customer_id,
                           scan_run_id, rule_id, threat_category,
                           severity, status,
                           resource_type, resource_id, resource_uid,
                           account_id, region,
                           mitre_tactics, mitre_techniques,
                           evidence, finding_data,
                           first_seen_at, last_seen_at, created_at
                    FROM threat_findings
                    WHERE tenant_id = %s AND threat_scan_id = %s
                    ORDER BY severity, rule_id
                """
                params = [tenant_id, threat_scan_id]

            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(query, params)
                rows = cur.fetchall()

            # Convert rows to finding dicts compatible with DataSec engine
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
                    'region': row['region'] or '',
                    'service': (row['resource_type'] or ''),
                    'resource_type': row['resource_type'] or '',
                    'resource_id': row['resource_id'] or '',
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

            if data_security_rule_ids:
                logger.info(f"Loaded {len(findings)} data security findings from threat_findings table "
                            f"(filtered by {len(data_security_rule_ids)} rule IDs)")
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
        data_security_rule_ids: Optional[Set[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get threat findings for a specific resource from threat_findings table.

        Args:
            tenant_id: Tenant identifier
            scan_run_id: Scan run ID
            resource_uid: Resource UID/ARN
            data_security_rule_ids: Optional filter by data security rule IDs

        Returns:
            List of findings for the resource
        """
        if not PSYCOPG_AVAILABLE:
            return []
        conn = self._get_conn()
        try:
            threat_scan_id = self._resolve_threat_scan_id(conn, tenant_id, scan_run_id)
            if not threat_scan_id:
                return []

            query = """
                SELECT finding_id, threat_scan_id, tenant_id, customer_id,
                       scan_run_id, rule_id, threat_category,
                       severity, status,
                       resource_type, resource_id, resource_uid,
                       account_id, region,
                       mitre_tactics, mitre_techniques,
                       evidence, finding_data,
                       first_seen_at, last_seen_at, created_at
                FROM threat_findings
                WHERE tenant_id = %s AND threat_scan_id = %s
                  AND resource_uid = %s
            """
            params = [tenant_id, threat_scan_id, resource_uid]

            if data_security_rule_ids:
                placeholders = ','.join(['%s'] * len(data_security_rule_ids))
                query += f" AND rule_id IN ({placeholders})"
                params.extend(list(data_security_rule_ids))

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
                    'region': row['region'] or '',
                    'service': (row['resource_type'] or ''),
                    'resource_type': row['resource_type'] or '',
                    'resource_uid': row['resource_uid'] or '',
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

    def filter_data_stores(
        self,
        tenant_id: str,
        scan_run_id: str,
        data_security_rule_ids: Optional[Set[str]] = None,
        csp: str = "aws",
    ) -> List[Dict[str, Any]]:
        """
        Extract data stores from threat_findings table by filtering
        for data-security relevant resource types (s3, rds, dynamodb, etc.).

        Resource type list is loaded from datasec_data_store_services DB table
        (no hardcoded values — multi-CSP aware).

        Args:
            tenant_id: Tenant identifier
            scan_run_id: Scan run ID
            data_security_rule_ids: Optional filter by data security rule IDs
            csp: Cloud provider key (aws | azure | gcp | oci | ibm | alicloud)

        Returns:
            List of unique data store dictionaries
        """
        if not PSYCOPG_AVAILABLE:
            return []
        conn = self._get_conn()
        try:
            threat_scan_id = self._resolve_threat_scan_id(conn, tenant_id, scan_run_id)
            if not threat_scan_id:
                return []

            # Load data store service names from DB (with fallback)
            ds_types = list(load_data_store_services(csp))
            placeholders = ','.join(['%s'] * len(ds_types))
            query = f"""
                SELECT DISTINCT ON (resource_uid)
                       resource_uid, resource_id, resource_type,
                       account_id, region
                FROM threat_findings
                WHERE tenant_id = %s AND threat_scan_id = %s
                  AND resource_type IN ({placeholders})
                ORDER BY resource_uid, created_at DESC
            """
            params = [tenant_id, threat_scan_id] + ds_types

            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(query, params)
                rows = cur.fetchall()

            data_stores = []
            for row in rows:
                data_stores.append({
                    'resource_uid': row['resource_uid'] or '',
                    'resource_id': row['resource_id'],
                    'resource_type': row['resource_type'],
                    'service': row['resource_type'],
                    'account_id': row['account_id'],
                    'region': row['region'],
                })

            logger.info(f"Found {len(data_stores)} unique data stores from threat_findings")
            return data_stores

        except Exception as e:
            logger.error(f"Error filtering data stores: {e}")
            conn.rollback()
            return []
