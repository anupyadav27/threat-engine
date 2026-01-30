"""
Metadata Enrichment

Utilities for enriching check results with rule metadata from database.
This replaces the need to load YAML files for metadata enrichment.
"""

from typing import List, Dict, Any, Optional
import sys
from pathlib import Path

# Add consolidated_services to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

# from consolidated_services.database.connections.postgres_connection import get_postgres_connection
import psycopg2
from psycopg2.extras import RealDictCursor
import os

def get_postgres_connection(schema=None):
    """Simple PostgreSQL connection helper"""
    return psycopg2.connect(
        host=os.getenv("CHECK_DB_HOST", "localhost"),
        port=int(os.getenv("CHECK_DB_PORT", "5432")),
        database=os.getenv("CHECK_DB_NAME", "threat_engine_check"),
        user=os.getenv("CHECK_DB_USER", "check_user"),
        password=os.getenv("CHECK_DB_PASSWORD", "check_password"),
        cursor_factory=RealDictCursor
    )


def get_enriched_check_results(
    scan_id: str,
    schema: str = 'engine_configscan',
    status_filter: Optional[List[str]] = None
) -> List[Dict[str, Any]]:
    """
    Get check results enriched with metadata from rule_metadata table.
    
    Args:
        scan_id: Scan ID to filter results
        schema: Database schema (default: engine_configscan)
        status_filter: Filter by status (e.g., ['FAIL', 'WARN']). Default: all
    
    Returns:
        List of check results with metadata fields (severity, title, description, remediation)
    
    Example:
        results = get_enriched_check_results('scan_123', status_filter=['FAIL', 'WARN'])
        # Each result has: rule_id, status, severity, title, description, remediation, etc.
    """
    conn = get_postgres_connection(schema)
    
    try:
        with conn.cursor() as cur:
            # Build query with metadata JOIN
            query = """
                SELECT 
                    cr.id,
                    cr.scan_id,
                    cr.customer_id,
                    cr.tenant_id,
                    cr.provider,
                    cr.hierarchy_id,
                    cr.hierarchy_type,
                    cr.rule_id,
                    cr.resource_arn,
                    cr.resource_uid,
                    cr.resource_id,
                    cr.resource_type,
                    cr.status,
                    cr.checked_fields,
                    cr.finding_data,
                    cr.created_at as scan_timestamp,
                    NULL::text as check_metadata_source,
                    
                    -- Metadata from rule_metadata table
                    rm.severity,
                    rm.title,
                    rm.description,
                    rm.remediation,
                    rm.compliance_frameworks,
                    rm.data_security,
                    rm.references,
                    rm.metadata_source as rule_metadata_source,
                    -- Threat categorization metadata
                    rm.threat_category,
                    rm.threat_tags,
                    rm.risk_score,
                    rm.risk_indicators
                    
                FROM check_results cr
                LEFT JOIN rule_metadata rm ON cr.rule_id = rm.rule_id
                WHERE cr.scan_id = %s
            """
            
            params = [scan_id]
            
            # Add status filter if provided
            if status_filter:
                query += " AND cr.status = ANY(%s)"
                params.append(status_filter)
            
            query += " ORDER BY cr.rule_id, cr.resource_arn"
            
            cur.execute(query, params)
            
            # Fetch all results (RealDictCursor returns dict-like rows already)
            results = []
            for row in cur.fetchall():
                results.append(dict(row))
            
            return results
            
    finally:
        conn.close()


def get_rule_metadata(
    rule_id: str,
    schema: str = 'engine_configscan'
) -> Optional[Dict[str, Any]]:
    """
    Get metadata for a specific rule.
    
    Args:
        rule_id: Rule ID (e.g., 'aws.s3.bucket.encryption_enabled')
        schema: Database schema (default: engine_configscan)
    
    Returns:
        Dictionary with rule metadata or None if not found
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
                    references,
                    metadata_source,
                    source,
                    generated_by
                FROM rule_metadata
                WHERE rule_id = %s
            """, (rule_id,))
            
            row = cur.fetchone()
            if not row:
                return None
            
            columns = [desc[0] for desc in cur.description]
            return dict(zip(columns, row))
            
    finally:
        conn.close()


def get_rules_by_severity(
    severity: str,
    schema: str = 'engine_configscan',
    limit: int = 100
) -> List[Dict[str, Any]]:
    """
    Get rules filtered by severity.
    
    Args:
        severity: Severity level ('critical', 'high', 'medium', 'low', 'info')
        schema: Database schema (default: engine_configscan)
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
                    severity,
                    title,
                    description,
                    compliance_frameworks,
                    metadata_source
                FROM rule_metadata
                WHERE severity = %s
                ORDER BY service, rule_id
                LIMIT %s
            """, (severity.lower(), limit))
            
            columns = [desc[0] for desc in cur.description]
            results = []
            
            for row in cur.fetchall():
                result = dict(zip(columns, row))
                results.append(result)
            
            return results
            
    finally:
        conn.close()


def get_rules_by_service(
    service: str,
    schema: str = 'engine_configscan',
    limit: int = 100
) -> List[Dict[str, Any]]:
    """
    Get rules for a specific service.
    
    Args:
        service: Service name (e.g., 's3', 'ec2', 'iam')
        schema: Database schema (default: engine_configscan)
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
                    severity,
                    title,
                    description,
                    metadata_source
                FROM rule_metadata
                WHERE service = %s
                ORDER BY severity DESC, rule_id
                LIMIT %s
            """, (service.lower(), limit))
            
            columns = [desc[0] for desc in cur.description]
            results = []
            
            for row in cur.fetchall():
                result = dict(zip(columns, row))
                results.append(result)
            
            return results
            
    finally:
        conn.close()


def get_metadata_statistics(schema: str = 'engine_configscan') -> Dict[str, Any]:
    """
    Get statistics about rule metadata.
    
    Args:
        schema: Database schema (default: engine_configscan)
    
    Returns:
        Dictionary with statistics
    """
    conn = get_postgres_connection(schema)
    
    try:
        with conn.cursor() as cur:
            # Total rules
            cur.execute("SELECT COUNT(*) FROM rule_metadata")
            total_rules = cur.fetchone()[0]
            
            # By severity
            cur.execute("""
                SELECT severity, COUNT(*) 
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
            by_severity = {row[0]: row[1] for row in cur.fetchall()}
            
            # By service
            cur.execute("""
                SELECT service, COUNT(*) 
                FROM rule_metadata 
                GROUP BY service 
                ORDER BY COUNT(*) DESC 
                LIMIT 10
            """)
            by_service = {row[0]: row[1] for row in cur.fetchall()}
            
            # By metadata source
            cur.execute("""
                SELECT metadata_source, COUNT(*) 
                FROM rule_metadata 
                GROUP BY metadata_source
            """)
            by_source = {row[0]: row[1] for row in cur.fetchall()}
            
            return {
                'total_rules': total_rules,
                'by_severity': by_severity,
                'top_10_services': by_service,
                'by_metadata_source': by_source
            }
            
    finally:
        conn.close()


if __name__ == '__main__':
    # Test the enrichment functions
    print("Testing metadata enrichment...")
    
    # Get statistics
    stats = get_metadata_statistics()
    print(f"\nMetadata Statistics:")
    print(f"Total rules: {stats['total_rules']}")
    print(f"By severity: {stats['by_severity']}")
    print(f"Top services: {list(stats['top_10_services'].keys())[:5]}")
    print(f"By source: {stats['by_metadata_source']}")
