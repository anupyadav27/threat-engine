"""
Compliance Database Writer

Writes compliance reports to RDS tables:
- report_index (main report metadata)
- finding_index (individual findings)
"""

import os
import json
import uuid
import psycopg2
from psycopg2.extras import Json
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone


def _get_compliance_db_connection():
    """Get Compliance DB connection using individual parameters to avoid password encoding issues."""
    return psycopg2.connect(
        host=os.getenv("COMPLIANCE_DB_HOST", "localhost"),
        port=int(os.getenv("COMPLIANCE_DB_PORT", "5432")),
        database=os.getenv("COMPLIANCE_DB_NAME", "threat_engine_compliance"),
        user=os.getenv("COMPLIANCE_DB_USER", "postgres"),
        password=os.getenv("COMPLIANCE_DB_PASSWORD", "")
    )


def save_compliance_report_to_db(compliance_report: Dict[str, Any]) -> str:
    """
    Save compliance report to database (report_index + finding_index).
    
    Args:
        compliance_report: Full compliance report dict
    
    Returns:
        report_id (UUID string)
    """
    try:
        import psycopg2
        from psycopg2.extras import Json
    except ImportError:
        raise RuntimeError("psycopg2 is required for compliance DB writer.")
    
    conn = _get_compliance_db_connection()
    
    try:
        # Extract metadata
        report_id_str = compliance_report.get('report_id', str(uuid.uuid4()))
        scan_id = compliance_report.get('scan_id', '')
        tenant_id = compliance_report.get('tenant_id', '')
        csp = compliance_report.get('csp', 'aws')
        generated_at_str = compliance_report.get('generated_at', '')
        
        # Parse timestamps
        try:
            generated_at = datetime.fromisoformat(generated_at_str.replace('Z', '+00:00'))
        except:
            generated_at = datetime.now(timezone.utc)
        
        started_at = generated_at
        completed_at = generated_at
        
        # Calculate totals from framework_reports
        framework_reports = compliance_report.get('framework_reports', {})
        total_controls = 0
        controls_passed = 0
        controls_failed = 0
        
        for fw_report in framework_reports.values():
            stats = fw_report.get('statistics', {})
            total_controls += stats.get('controls_total', 0)
            controls_passed += stats.get('controls_passed', 0)
            controls_failed += stats.get('controls_failed', 0)
        
        # Count total findings (all checks from scan_results)
        dashboard = compliance_report.get('executive_dashboard', {})
        summary = dashboard.get('summary', {})
        total_findings = summary.get('total_checks', 0)
        
        # 1. Upsert tenant
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO tenants (tenant_id, tenant_name)
                VALUES (%s, %s)
                ON CONFLICT (tenant_id) DO NOTHING
            """, (tenant_id or 'default', tenant_id))
        
        # 2. Insert into report_index
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO report_index (
                    report_id, tenant_id, scan_run_id, cloud,
                    trigger_type, collection_mode,
                    started_at, completed_at,
                    total_controls, controls_passed, controls_failed,
                    total_findings, report_data
                )
                VALUES (%s::uuid, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)
                ON CONFLICT (report_id) DO UPDATE SET
                    completed_at = EXCLUDED.completed_at,
                    total_controls = EXCLUDED.total_controls,
                    controls_passed = EXCLUDED.controls_passed,
                    controls_failed = EXCLUDED.controls_failed,
                    total_findings = EXCLUDED.total_findings,
                    report_data = EXCLUDED.report_data
            """, (
                str(report_id_str) if report_id_str else str(uuid.uuid4()),
                tenant_id or 'default',
                scan_id,
                csp,
                'manual',
                'full',
                started_at,
                completed_at,
                total_controls,
                controls_passed,
                controls_failed,
                total_findings,
                json.dumps(compliance_report, default=str)
            ))
        
        # 3. Insert findings (extract from framework_reports)
        findings_inserted = 0
        for fw_name, fw_report in framework_reports.items():
            controls = fw_report.get('controls', [])
            
            for control in controls:
                checks = control.get('checks', [])
                
                for check in checks:
                    if check.get('check_result') == 'FAIL':
                        finding_id = str(uuid.uuid4())
                        resource = check.get('resource', {})
                        
                        with conn.cursor() as cur:
                            cur.execute("""
                                INSERT INTO finding_index (
                                    finding_id, report_id, tenant_id, scan_run_id,
                                    rule_id, rule_version, category,
                                    severity, confidence, status,
                                    first_seen_at, last_seen_at,
                                    resource_type, resource_id, resource_arn, region,
                                    finding_data
                                )
                                VALUES (%s, %s::uuid, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)
                                ON CONFLICT (finding_id) DO NOTHING
                            """, (
                                finding_id,
                                str(report_id_str) if report_id_str else str(uuid.uuid4()),
                                tenant_id or 'default',
                                scan_id,
                                check.get('rule_id'),
                                None,  # rule_version
                                check.get('service'),
                                check.get('severity', 'medium'),
                                'high',  # confidence
                                'open',  # status
                                generated_at,
                                generated_at,
                                resource.get('type'),
                                resource.get('id'),
                                resource.get('arn'),
                                check.get('region'),
                                json.dumps({
                                    'framework': fw_name,
                                    'control_id': control.get('control_id'),
                                    'control_title': control.get('control_title'),
                                    'check': check
                                }, default=str)
                            ))
                        findings_inserted += 1
        
        conn.commit()
        print(f"✅ Saved to DB: 1 report, {findings_inserted} findings")
        return report_id_str
        
    except Exception as e:
        conn.rollback()
        raise RuntimeError(f"Failed to save compliance report to DB: {e}") from e
    finally:
        conn.close()


def get_compliance_scan_summary(tenant_id: str, report_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve compliance report from database."""
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
    except ImportError:
        return None
    
    conn = _get_compliance_db_connection()
    
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT * FROM report_index
                WHERE report_id = %s AND tenant_id = %s
            """, (report_id, tenant_id))
            report = cur.fetchone()
        
        if not report:
            return None
        
        return dict(report)
        
    finally:
        conn.close()


def list_compliance_scans(tenant_id: str, limit: int = 100) -> List[Dict[str, Any]]:
    """List compliance reports for a tenant."""
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
    except ImportError:
        return []
    
    conn = _get_compliance_db_connection()
    
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT 
                    report_id,
                    scan_run_id,
                    cloud,
                    total_controls,
                    controls_passed,
                    controls_failed,
                    total_findings,
                    completed_at
                FROM report_index
                WHERE tenant_id = %s
                ORDER BY completed_at DESC
                LIMIT %s
            """, (tenant_id, limit))
            
            return [dict(row) for row in cur.fetchall()]
        
    finally:
        conn.close()
