"""
Metadata Enrichment

Utilities for enriching check results with rule metadata from database.
Uses check_findings table with MITRE ATT&CK enrichment from rule_metadata.
"""

from typing import List, Dict, Any, Optional
import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2 import pool
import os
import logging

logger = logging.getLogger(__name__)

# Connection pool (thread-safe, shared across calls)
_connection_pool = None


def _get_pool():
    """Get or create connection pool for check DB."""
    global _connection_pool
    if _connection_pool is None:
        _connection_pool = pool.ThreadedConnectionPool(
            minconn=2,
            maxconn=int(os.getenv("DB_POOL_SIZE", "10")),
            host=os.getenv("CHECK_DB_HOST", "localhost"),
            port=int(os.getenv("CHECK_DB_PORT", "5432")),
            database=os.getenv("CHECK_DB_NAME", "threat_engine_check"),
            user=os.getenv("CHECK_DB_USER", "check_user"),
            password=os.getenv("CHECK_DB_PASSWORD", "check_password"),
            cursor_factory=RealDictCursor,
        )
    return _connection_pool


def get_postgres_connection(schema=None):
    """Get pooled PostgreSQL connection for check DB."""
    try:
        return _get_pool().getconn()
    except Exception:
        # Fallback to direct connection if pool fails
        return psycopg2.connect(
            host=os.getenv("CHECK_DB_HOST", "localhost"),
            port=int(os.getenv("CHECK_DB_PORT", "5432")),
            database=os.getenv("CHECK_DB_NAME", "threat_engine_check"),
            user=os.getenv("CHECK_DB_USER", "check_user"),
            password=os.getenv("CHECK_DB_PASSWORD", "check_password"),
            cursor_factory=RealDictCursor,
        )


def _return_connection(conn):
    """Return connection to pool."""
    try:
        _get_pool().putconn(conn)
    except Exception:
        try:
            conn.close()
        except Exception:
            pass


def get_enriched_check_results(
    scan_id: str,
    schema: str = 'check_db',
    status_filter: Optional[List[str]] = None,
    tenant_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Get check results enriched with metadata + MITRE ATT&CK from rule_metadata table.

    Reads from check_findings (actual table name) with LEFT JOIN to rule_metadata.
    Returns enriched results including severity, title, threat_category,
    mitre_techniques, mitre_tactics, and risk_score.

    Args:
        scan_id: Check scan ID (check_scan_id in check_findings)
        schema: Ignored (kept for backward compat)
        status_filter: Filter by status (e.g., ['FAIL', 'WARN']). Default: all
        tenant_id: Optional tenant_id filter

    Returns:
        List of enriched check result dicts with MITRE metadata
    """
    conn = get_postgres_connection(schema)

    try:
        with conn.cursor() as cur:
            query = """
                SELECT
                    cf.id,
                    cf.check_scan_id,
                    cf.customer_id,
                    cf.tenant_id,
                    cf.provider,
                    cf.hierarchy_id,
                    cf.hierarchy_type,
                    cf.rule_id,
                    cf.resource_uid AS resource_arn,
                    cf.resource_uid,
                    cf.resource_id,
                    cf.resource_type,
                    cf.status,
                    cf.checked_fields,
                    cf.finding_data,
                    cf.created_at as scan_timestamp,

                    -- Rule metadata
                    rm.service as rule_service,
                    rm.severity,
                    rm.title,
                    rm.description,
                    rm.remediation,
                    rm.rationale,
                    rm.domain,
                    rm.subcategory,
                    rm.compliance_frameworks,
                    rm.data_security,
                    rm."references" as rule_references,
                    rm.metadata_source as rule_metadata_source,

                    -- MITRE ATT&CK enrichment
                    rm.threat_category,
                    rm.threat_tags,
                    rm.risk_score,
                    rm.risk_indicators,
                    rm.mitre_techniques,
                    rm.mitre_tactics

                FROM check_findings cf
                LEFT JOIN rule_metadata rm ON cf.rule_id = rm.rule_id
                WHERE cf.check_scan_id = %s
            """

            params: list = [scan_id]

            if status_filter:
                query += " AND cf.status = ANY(%s)"
                params.append(status_filter)

            if tenant_id:
                query += " AND cf.tenant_id = %s"
                params.append(tenant_id)

            query += " ORDER BY rm.severity DESC, cf.rule_id, cf.resource_uid"

            cur.execute(query, params)

            results = [dict(row) for row in cur.fetchall()]

            logger.info(
                "Enriched check results loaded",
                extra={"extra_fields": {
                    "scan_id": scan_id,
                    "total_results": len(results),
                    "has_mitre": bool(results and results[0].get('mitre_techniques')),
                }}
            )

            return results

    finally:
        _return_connection(conn)


def get_rule_metadata(
    rule_id: str,
    schema: str = 'check_db'
) -> Optional[Dict[str, Any]]:
    """
    Get metadata for a specific rule including MITRE ATT&CK data.

    Args:
        rule_id: Rule ID (e.g., 'aws.s3.bucket.encryption_enabled')
        schema: Ignored (kept for backward compat)

    Returns:
        Dictionary with rule metadata including MITRE fields, or None if not found
    """
    conn = get_postgres_connection(schema)

    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    rule_id,
                    service,
                    provider,
                    resource,
                    severity,
                    title,
                    description,
                    remediation,
                    rationale,
                    domain,
                    subcategory,
                    requirement,
                    assertion_id,
                    compliance_frameworks,
                    data_security,
                    "references",
                    metadata_source,
                    source,
                    generated_by,
                    threat_category,
                    threat_tags,
                    risk_score,
                    risk_indicators,
                    mitre_techniques,
                    mitre_tactics
                FROM rule_metadata
                WHERE rule_id = %s
            """, (rule_id,))

            row = cur.fetchone()
            if not row:
                return None

            return dict(row)

    finally:
        _return_connection(conn)


def get_rules_by_severity(
    severity: str,
    schema: str = 'check_db',
    limit: int = 100
) -> List[Dict[str, Any]]:
    """
    Get rules filtered by severity with MITRE ATT&CK data.

    Args:
        severity: Severity level ('critical', 'high', 'medium', 'low', 'info')
        schema: Ignored (kept for backward compat)
        limit: Maximum number of results

    Returns:
        List of rule metadata dictionaries
    """
    conn = get_postgres_connection(schema)

    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    rule_id,
                    service,
                    provider,
                    severity,
                    title,
                    description,
                    compliance_frameworks,
                    metadata_source,
                    threat_category,
                    mitre_techniques,
                    mitre_tactics,
                    risk_score
                FROM rule_metadata
                WHERE severity = %s
                ORDER BY service, rule_id
                LIMIT %s
            """, (severity.lower(), limit))

            return [dict(row) for row in cur.fetchall()]

    finally:
        _return_connection(conn)


def get_rules_by_service(
    service: str,
    schema: str = 'check_db',
    limit: int = 100
) -> List[Dict[str, Any]]:
    """
    Get rules for a specific service with MITRE ATT&CK data.

    Args:
        service: Service name (e.g., 's3', 'ec2', 'iam')
        schema: Ignored (kept for backward compat)
        limit: Maximum number of results

    Returns:
        List of rule metadata dictionaries
    """
    conn = get_postgres_connection(schema)

    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    rule_id,
                    service,
                    provider,
                    severity,
                    title,
                    description,
                    metadata_source,
                    threat_category,
                    mitre_techniques,
                    mitre_tactics,
                    risk_score
                FROM rule_metadata
                WHERE service = %s
                ORDER BY severity DESC, rule_id
                LIMIT %s
            """, (service.lower(), limit))

            return [dict(row) for row in cur.fetchall()]

    finally:
        _return_connection(conn)


def get_metadata_statistics(schema: str = 'check_db') -> Dict[str, Any]:
    """
    Get statistics about rule metadata including MITRE coverage.

    Args:
        schema: Ignored (kept for backward compat)

    Returns:
        Dictionary with statistics
    """
    conn = get_postgres_connection(schema)

    try:
        with conn.cursor() as cur:
            # Total rules
            cur.execute("SELECT COUNT(*) as cnt FROM rule_metadata")
            total_rules = cur.fetchone()['cnt']

            # By severity
            cur.execute("""
                SELECT severity, COUNT(*) as cnt
                FROM rule_metadata
                GROUP BY severity
                ORDER BY
                    CASE severity
                        WHEN 'critical' THEN 1
                        WHEN 'high' THEN 2
                        WHEN 'medium' THEN 3
                        WHEN 'low' THEN 4
                        WHEN 'info' THEN 5
                        ELSE 6
                    END
            """)
            by_severity = {row['severity']: row['cnt'] for row in cur.fetchall()}

            # By provider
            cur.execute("""
                SELECT provider, COUNT(*) as cnt
                FROM rule_metadata
                GROUP BY provider
                ORDER BY COUNT(*) DESC
            """)
            by_provider = {row['provider']: row['cnt'] for row in cur.fetchall()}

            # By service (top 10)
            cur.execute("""
                SELECT service, COUNT(*) as cnt
                FROM rule_metadata
                GROUP BY service
                ORDER BY COUNT(*) DESC
                LIMIT 10
            """)
            by_service = {row['service']: row['cnt'] for row in cur.fetchall()}

            # By metadata source
            cur.execute("""
                SELECT metadata_source, COUNT(*) as cnt
                FROM rule_metadata
                GROUP BY metadata_source
            """)
            by_source = {row['metadata_source']: row['cnt'] for row in cur.fetchall()}

            # MITRE coverage
            cur.execute("""
                SELECT
                    COUNT(*) FILTER (WHERE mitre_techniques IS NOT NULL) as mitre_mapped,
                    COUNT(*) as total,
                    AVG(CASE WHEN risk_score IS NOT NULL THEN risk_score ELSE NULL END) as avg_risk_score
                FROM rule_metadata
            """)
            mitre_row = cur.fetchone()

            return {
                'total_rules': total_rules,
                'by_severity': by_severity,
                'by_provider': by_provider,
                'top_10_services': by_service,
                'by_metadata_source': by_source,
                'mitre_coverage': {
                    'mapped': mitre_row['mitre_mapped'],
                    'total': mitre_row['total'],
                    'percentage': round(mitre_row['mitre_mapped'] / mitre_row['total'] * 100, 1) if mitre_row['total'] > 0 else 0,
                    'avg_risk_score': round(float(mitre_row['avg_risk_score']), 2) if mitre_row['avg_risk_score'] else 0
                }
            }

    finally:
        _return_connection(conn)


if __name__ == '__main__':
    # Test the enrichment functions
    print("Testing metadata enrichment...")

    # Get statistics
    stats = get_metadata_statistics()
    print(f"\nMetadata Statistics:")
    print(f"Total rules: {stats['total_rules']}")
    print(f"By severity: {stats['by_severity']}")
    print(f"By provider: {stats['by_provider']}")
    print(f"Top services: {list(stats['top_10_services'].keys())[:5]}")
    print(f"By source: {stats['by_metadata_source']}")
    print(f"MITRE coverage: {stats['mitre_coverage']}")