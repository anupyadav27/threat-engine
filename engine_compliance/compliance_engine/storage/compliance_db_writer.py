"""
Compliance Database Writer

Writes compliance report results to normalized PostgreSQL tables:
- compliance_scans (scan summary)
- framework_scores (per-framework scores)
- control_results (individual control results)
"""

import os
import json
import psycopg2
from psycopg2.extras import Json
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone


def _compliance_db_connection_string() -> str:
    """Build Compliance DB connection string."""
    host = os.getenv("COMPLIANCE_DB_HOST", "localhost")
    port = os.getenv("COMPLIANCE_DB_PORT", "5432")
    db = os.getenv("COMPLIANCE_DB_NAME", "threat_engine_compliance")
    user = os.getenv("COMPLIANCE_DB_USER", "compliance_user")
    pwd = os.getenv("COMPLIANCE_DB_PASSWORD", "compliance_password")
    return f"postgresql://{user}:{pwd}@{host}:{port}/{db}"


def save_compliance_report_to_db(compliance_report: Dict[str, Any]) -> str:
    """
    Save compliance report to normalized database tables.
    
    Args:
        compliance_report: Full compliance report dict with executive_dashboard and framework_reports
    
    Returns:
        compliance_scan_id
    """
    try:
        import psycopg2
        from psycopg2.extras import Json
    except ImportError:
        raise RuntimeError("psycopg2 is required for compliance DB writer.")
    
    conn = psycopg2.connect(_compliance_db_connection_string())
    
    try:
        # Extract scan metadata
        scan_id = compliance_report.get('scan_id', '')
        tenant_id = compliance_report.get('tenant_id', '')
        csp = compliance_report.get('csp', 'aws')
        generated_at_str = compliance_report.get('generated_at', '')
        
        # Parse timestamp
        try:
            generated_at = datetime.fromisoformat(generated_at_str.replace('Z', '+00:00'))
        except:
            generated_at = datetime.now(timezone.utc)
        
        # Get executive dashboard for summary stats
        dashboard = compliance_report.get('executive_dashboard', {})
        summary = dashboard.get('summary', {})
        
        total_checks = summary.get('total_checks', 0)
        passed_checks = summary.get('passed_checks', 0)
        failed_checks = summary.get('failed_checks', 0)
        
        # Get frameworks evaluated
        framework_reports = compliance_report.get('framework_reports', {})
        frameworks_list = list(framework_reports.keys())
        
        # Calculate total controls across all frameworks
        total_controls = 0
        total_controls_passed = 0
        total_controls_failed = 0
        
        for fw_name, fw_report in framework_reports.items():
            fw_summary = fw_report.get('summary', {})
            total_controls += fw_summary.get('total_controls', 0)
            total_controls_passed += fw_summary.get('passed_controls', 0)
            total_controls_failed += fw_summary.get('failed_controls', 0)
        
        # Use scan_id as compliance_scan_id
        compliance_scan_id = scan_id
        
        # 1. Write to compliance_scans
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO compliance_scans (
                    compliance_scan_id, tenant_id, check_scan_id, cloud, scan_timestamp,
                    total_checks, total_passed, total_failed,
                    total_controls_evaluated, total_controls_passed, total_controls_failed,
                    frameworks_evaluated, generated_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (compliance_scan_id) DO UPDATE SET
                    total_checks = EXCLUDED.total_checks,
                    total_passed = EXCLUDED.total_passed,
                    total_failed = EXCLUDED.total_failed,
                    total_controls_evaluated = EXCLUDED.total_controls_evaluated,
                    total_controls_passed = EXCLUDED.total_controls_passed,
                    total_controls_failed = EXCLUDED.total_controls_failed,
                    frameworks_evaluated = EXCLUDED.frameworks_evaluated,
                    generated_at = EXCLUDED.generated_at
            """, (
                compliance_scan_id,
                tenant_id,
                scan_id,  # check_scan_id
                csp,
                generated_at,
                total_checks,
                passed_checks,
                failed_checks,
                total_controls,
                total_controls_passed,
                total_controls_failed,
                Json(frameworks_list),
                generated_at
            ))
        
        # 2. Write framework scores
        for fw_name, fw_report in framework_reports.items():
            fw_summary = fw_report.get('summary', {})
            fw_version = fw_report.get('framework_version')
            
            fw_total_controls = fw_summary.get('total_controls', 0)
            fw_passed = fw_summary.get('passed_controls', 0)
            fw_failed = fw_summary.get('failed_controls', 0)
            fw_not_applicable = fw_summary.get('not_applicable_controls', 0)
            fw_score = fw_summary.get('compliance_score', 0.0)
            
            # Rule stats
            total_rules_mapped = fw_summary.get('total_rules_mapped', 0)
            rules_passed = fw_summary.get('rules_passed', 0)
            rules_failed = fw_summary.get('rules_failed', 0)
            
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO framework_scores (
                        compliance_scan_id, tenant_id, framework_name, framework_version,
                        total_controls, controls_passed, controls_failed, controls_not_applicable,
                        compliance_score, total_rules_mapped, rules_passed, rules_failed,
                        generated_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (compliance_scan_id, framework_name, framework_version) DO UPDATE SET
                        total_controls = EXCLUDED.total_controls,
                        controls_passed = EXCLUDED.controls_passed,
                        controls_failed = EXCLUDED.controls_failed,
                        controls_not_applicable = EXCLUDED.controls_not_applicable,
                        compliance_score = EXCLUDED.compliance_score,
                        total_rules_mapped = EXCLUDED.total_rules_mapped,
                        rules_passed = EXCLUDED.rules_passed,
                        rules_failed = EXCLUDED.rules_failed,
                        generated_at = EXCLUDED.generated_at
                """, (
                    compliance_scan_id,
                    tenant_id,
                    fw_name,
                    fw_version,
                    fw_total_controls,
                    fw_passed,
                    fw_failed,
                    fw_not_applicable,
                    fw_score,
                    total_rules_mapped,
                    rules_passed,
                    rules_failed,
                    generated_at
                ))
            
            # 3. Write control results (detailed)
            # Get mapped rules from compliance_control_mappings table instead of report
            controls = fw_report.get('controls', [])
            for control in controls:
                control_id = control.get('control_id', '')
                control_title = control.get('control_title', '')
                control_category = control.get('control_category')
                control_status = control.get('status', 'UNKNOWN')
                control_score = control.get('compliance_score', 0.0)
                
                # Query compliance_control_mappings to get rule_ids for this control
                mapped_rule_ids = []
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT rule_ids FROM compliance_control_mappings
                        WHERE compliance_framework = %s AND requirement_id = %s
                        LIMIT 1
                    """, (fw_name, control_id))
                    row = cur.fetchone()
                    if row and row[0]:
                        mapped_rule_ids = row[0]  # PostgreSQL array
                
                # If we have rule_ids, query check DB to get pass/fail and resources
                # For now, use resource_compliance_status which has this data
                passed_rules = []
                failed_rules = []
                failed_resources_list = []
                total_resources = 0
                
                if mapped_rule_ids:
                    with conn.cursor() as cur:
                        cur.execute("""
                            SELECT 
                                array_agg(DISTINCT resource_uid) FILTER (WHERE failed_checks > 0) as failed_res,
                                COUNT(DISTINCT resource_uid) as total_res,
                                SUM(passed_checks) as passed,
                                SUM(failed_checks) as failed
                            FROM resource_compliance_status
                            WHERE compliance_framework = %s 
                              AND requirement_id = %s
                              AND scan_id = %s
                        """, (fw_name, control_id, scan_id))
                        res_row = cur.fetchone()
                        if res_row:
                            failed_resources_list = res_row[0] or []
                            total_resources = res_row[1] or 0
                            # Approximate which rules passed/failed based on control status
                            if control_status == 'PASS':
                                passed_rules = mapped_rule_ids
                            elif control_status == 'FAIL':
                                failed_rules = mapped_rule_ids
                            else:  # PARTIAL
                                # Split based on ratios (simplified)
                                failed_rules = mapped_rule_ids
                
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO control_results (
                            compliance_scan_id, tenant_id, framework_name, framework_version,
                            control_id, control_title, control_category, status,
                            mapped_rule_ids, passed_rules, failed_rules,
                            total_resources, failed_resources, control_score
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (compliance_scan_id, framework_name, control_id) DO UPDATE SET
                            status = EXCLUDED.status,
                            passed_rules = EXCLUDED.passed_rules,
                            failed_rules = EXCLUDED.failed_rules,
                            total_resources = EXCLUDED.total_resources,
                            failed_resources = EXCLUDED.failed_resources,
                            control_score = EXCLUDED.control_score
                    """, (
                        compliance_scan_id,
                        tenant_id,
                        fw_name,
                        fw_version,
                        control_id,
                        control_title,
                        control_category,
                        control_status,
                        Json([r['rule_id'] for r in mapped_rules]),
                        Json(passed_rules),
                        Json(failed_rules),
                        total_resources,
                        Json(failed_resources),
                        control_score
                    ))
        
        conn.commit()
        return compliance_scan_id
        
    finally:
        conn.close()


def get_compliance_scan_summary(tenant_id: str, compliance_scan_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve compliance scan summary from database.
    
    Returns:
        Scan summary dict or None
    """
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
    except ImportError:
        return None
    
    conn = psycopg2.connect(_compliance_db_connection_string())
    
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT * FROM compliance_scans
                WHERE compliance_scan_id = %s AND tenant_id = %s
            """, (compliance_scan_id, tenant_id))
            scan = cur.fetchone()
        
        if not scan:
            return None
        
        # Get framework scores
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT * FROM framework_scores
                WHERE compliance_scan_id = %s AND tenant_id = %s
                ORDER BY compliance_score DESC
            """, (compliance_scan_id, tenant_id))
            frameworks = [dict(row) for row in cur.fetchall()]
        
        return {
            **dict(scan),
            'framework_scores': frameworks
        }
        
    finally:
        conn.close()


def list_compliance_scans(tenant_id: str, limit: int = 100) -> List[Dict[str, Any]]:
    """
    List compliance scans for a tenant.
    
    Returns:
        List of scan summaries
    """
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
    except ImportError:
        return []
    
    conn = psycopg2.connect(_compliance_db_connection_string())
    
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT 
                    compliance_scan_id,
                    check_scan_id,
                    cloud,
                    total_checks,
                    total_passed,
                    total_failed,
                    total_controls_evaluated,
                    frameworks_evaluated,
                    generated_at
                FROM compliance_scans
                WHERE tenant_id = %s
                ORDER BY generated_at DESC
                LIMIT %s
            """, (tenant_id, limit))
            
            return [dict(row) for row in cur.fetchall()]
        
    finally:
        conn.close()
