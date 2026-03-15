"""
Common database query functions for engines to fetch data from previous engines' databases.

All engines use these functions to query previous engine data from DATABASE (NOT S3).
"""

from typing import List, Dict, Any, Optional
import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2 import pool
import os
import logging

logger = logging.getLogger(__name__)

# Connection pools for different databases
_check_db_pool = None
_threat_db_pool = None
_discovery_db_pool = None


def _get_check_db_pool():
    """Get or create connection pool for Check DB."""
    global _check_db_pool
    if _check_db_pool is None:
        _check_db_pool = pool.ThreadedConnectionPool(
            minconn=2,
            maxconn=int(os.getenv("DB_POOL_SIZE", "10")),
            host=os.getenv("CHECK_DB_HOST", "localhost"),
            port=int(os.getenv("CHECK_DB_PORT", "5432")),
            database=os.getenv("CHECK_DB_NAME", "threat_engine_check"),
            user=os.getenv("CHECK_DB_USER", "postgres"),
            password=os.getenv("CHECK_DB_PASSWORD", ""),
            cursor_factory=RealDictCursor,
        )
    return _check_db_pool


def _get_threat_db_pool():
    """Get or create connection pool for Threat DB."""
    global _threat_db_pool
    if _threat_db_pool is None:
        _threat_db_pool = pool.ThreadedConnectionPool(
            minconn=2,
            maxconn=int(os.getenv("DB_POOL_SIZE", "10")),
            host=os.getenv("THREAT_DB_HOST", "localhost"),
            port=int(os.getenv("THREAT_DB_PORT", "5432")),
            database=os.getenv("THREAT_DB_NAME", "threat_engine_threat"),
            user=os.getenv("THREAT_DB_USER", "postgres"),
            password=os.getenv("THREAT_DB_PASSWORD", ""),
            cursor_factory=RealDictCursor,
        )
    return _threat_db_pool


def _get_discovery_db_pool():
    """Get or create connection pool for Discovery DB."""
    global _discovery_db_pool
    if _discovery_db_pool is None:
        _discovery_db_pool = pool.ThreadedConnectionPool(
            minconn=2,
            maxconn=int(os.getenv("DB_POOL_SIZE", "10")),
            host=os.getenv("DISCOVERY_DB_HOST", "localhost"),
            port=int(os.getenv("DISCOVERY_DB_PORT", "5432")),
            database=os.getenv("DISCOVERY_DB_NAME", "threat_engine_discovery"),
            user=os.getenv("DISCOVERY_DB_USER", "postgres"),
            password=os.getenv("DISCOVERY_DB_PASSWORD", ""),
            cursor_factory=RealDictCursor,
        )
    return _discovery_db_pool


def get_check_findings_from_db(
    check_scan_id: str,
    tenant_id: str,
    status_filter: Optional[List[str]] = None
) -> List[Dict[str, Any]]:
    """
    Query Check findings from threat_engine_check database.

    Used by: Compliance, Threat engines

    Args:
        check_scan_id: Check scan identifier
        tenant_id: Tenant identifier
        status_filter: Optional list of statuses to filter (e.g., ['FAIL', 'WARN'])

    Returns:
        List of check finding dictionaries with enriched metadata
    """
    conn = None
    try:
        conn = _get_check_db_pool().getconn()

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
                    cf.status,
                    cf.resource_id,
                    cf.resource_name,
                    cf.resource_type,
                    cf.region,
                    cf.account_id,
                    cf.check_result,
                    cf.created_at,
                    cf.updated_at,
                    rm.severity,
                    rm.title,
                    rm.description,
                    rm.threat_category,
                    rm.mitre_attack_techniques,
                    rm.mitre_attack_tactics,
                    rm.risk_score,
                    rm.remediation_guidance
                FROM check_findings cf
                LEFT JOIN rule_metadata rm ON cf.rule_id = rm.rule_id
                WHERE cf.check_scan_id = %s
                  AND cf.tenant_id = %s
            """

            params = [check_scan_id, tenant_id]

            if status_filter:
                query += " AND cf.status = ANY(%s)"
                params.append(status_filter)

            query += " ORDER BY cf.created_at DESC"

            cur.execute(query, params)
            results = cur.fetchall()

            logger.info(f"Retrieved {len(results)} check findings from database for scan_id={check_scan_id}")

            return [dict(row) for row in results]

    except Exception as e:
        logger.error(f"Error querying check findings from database: {e}", exc_info=True)
        raise
    finally:
        if conn:
            _get_check_db_pool().putconn(conn)


def get_threat_findings_from_db(
    threat_scan_id: str,
    tenant_id: str,
    severity_filter: Optional[List[str]] = None
) -> List[Dict[str, Any]]:
    """
    Query Threat findings from threat_engine_threat database.

    Used by: IAM, DataSec engines

    Args:
        threat_scan_id: Threat scan identifier
        tenant_id: Tenant identifier
        severity_filter: Optional list of severities to filter (e.g., ['CRITICAL', 'HIGH'])

    Returns:
        List of threat finding dictionaries
    """
    conn = None
    try:
        conn = _get_threat_db_pool().getconn()

        with conn.cursor() as cur:
            query = """
                SELECT
                    id,
                    scan_run_id,
                    tenant_id,
                    check_id,
                    resource_id,
                    resource_name,
                    resource_type,
                    threat_type,
                    severity,
                    description,
                    threat_data,
                    mitre_techniques,
                    mitre_tactics,
                    risk_score,
                    created_at
                FROM threat_findings
                WHERE scan_run_id = %s
                  AND tenant_id = %s
            """

            params = [threat_scan_id, tenant_id]

            if severity_filter:
                query += " AND severity = ANY(%s)"
                params.append(severity_filter)

            query += " ORDER BY risk_score DESC, created_at DESC"

            cur.execute(query, params)
            results = cur.fetchall()

            logger.info(f"Retrieved {len(results)} threat findings from database for scan_id={threat_scan_id}")

            return [dict(row) for row in results]

    except Exception as e:
        logger.error(f"Error querying threat findings from database: {e}", exc_info=True)
        raise
    finally:
        if conn:
            _get_threat_db_pool().putconn(conn)


def get_discovery_resources_from_db(
    discovery_scan_id: str,
    tenant_id: str,
    resource_type_filter: Optional[List[str]] = None
) -> List[Dict[str, Any]]:
    """
    Query Discovery resources from threat_engine_discovery database.

    Used by: Check, Inventory engines

    Args:
        discovery_scan_id: Discovery scan identifier
        tenant_id: Tenant identifier
        resource_type_filter: Optional list of resource types to filter

    Returns:
        List of discovery resource dictionaries
    """
    conn = None
    try:
        conn = _get_discovery_db_pool().getconn()

        with conn.cursor() as cur:
            query = """
                SELECT
                    id,
                    scan_id,
                    tenant_id,
                    provider,
                    account_id,
                    region,
                    resource_id,
                    resource_name,
                    resource_type,
                    resource_data,
                    created_at
                FROM discoveries
                WHERE scan_id = %s
                  AND tenant_id = %s
            """

            params = [discovery_scan_id, tenant_id]

            if resource_type_filter:
                query += " AND resource_type = ANY(%s)"
                params.append(resource_type_filter)

            query += " ORDER BY created_at DESC"

            cur.execute(query, params)
            results = cur.fetchall()

            logger.info(f"Retrieved {len(results)} discovery resources from database for scan_id={discovery_scan_id}")

            return [dict(row) for row in results]

    except Exception as e:
        logger.error(f"Error querying discovery resources from database: {e}", exc_info=True)
        raise
    finally:
        if conn:
            _get_discovery_db_pool().putconn(conn)


def format_check_findings_for_compliance(check_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Format Check findings from database into the structure expected by Compliance engine.

    Args:
        check_findings: List of check finding dicts from get_check_findings_from_db()

    Returns:
        Dictionary formatted for compliance analysis
    """
    # Group findings by status
    findings_by_status = {
        'PASS': [],
        'FAIL': [],
        'WARN': [],
        'ERROR': [],
        'SKIP': []
    }

    for finding in check_findings:
        status = finding.get('status', 'UNKNOWN')
        if status in findings_by_status:
            findings_by_status[status].append(finding)

    return {
        'scan_id': check_findings[0]['check_scan_id'] if check_findings else None,
        'tenant_id': check_findings[0]['tenant_id'] if check_findings else None,
        'total_checks': len(check_findings),
        'findings_by_status': findings_by_status,
        'findings': check_findings,
        'summary': {
            'total': len(check_findings),
            'passed': len(findings_by_status['PASS']),
            'failed': len(findings_by_status['FAIL']),
            'warnings': len(findings_by_status['WARN']),
            'errors': len(findings_by_status['ERROR']),
            'skipped': len(findings_by_status['SKIP'])
        }
    }


def close_all_pools():
    """Close all database connection pools. Call on shutdown."""
    global _check_db_pool, _threat_db_pool, _discovery_db_pool

    if _check_db_pool:
        _check_db_pool.closeall()
        _check_db_pool = None

    if _threat_db_pool:
        _threat_db_pool.closeall()
        _threat_db_pool = None

    if _discovery_db_pool:
        _discovery_db_pool.closeall()
        _discovery_db_pool = None

    logger.info("All database connection pools closed")
