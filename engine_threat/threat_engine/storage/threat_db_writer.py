"""
Threat DB Writer - Normalized Schema

Persists threat reports to PostgreSQL using normalized tables:
- threat_scans (scan summary)
- threats (one row per threat)
- threat_resources (threat-resource mapping)
- drift_records (drift tracking)
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..schemas.threat_report_schema import ThreatReport


def _default_json(obj: Any) -> Any:
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def _connection_string() -> str:
    host = os.getenv("THREAT_DB_HOST", "localhost")
    port = os.getenv("THREAT_DB_PORT", "5432")
    db = os.getenv("THREAT_DB_NAME", "threat_engine_threat")
    user = os.getenv("THREAT_DB_USER", "threat_user")
    pwd = os.getenv("THREAT_DB_PASSWORD", "threat_password")
    return f"postgresql://{user}:{pwd}@{host}:{port}/{db}"


def save_report_to_db(report: ThreatReport) -> str:
    """
    Persist threat report to normalized PostgreSQL tables.
    
    Writes to:
    - threat_scans (scan summary)
    - threats (individual threats)
    - threat_resources (threat-resource mapping)
    - drift_records (if drift threats exist)
    
    Returns:
        scan_run_id
    """
    try:
        import psycopg2
        from psycopg2.extras import Json
    except ImportError:
        raise RuntimeError("psycopg2 is required for Threat DB writer.")
    
    scan_run_id = report.scan_context.scan_run_id
    tenant_id = report.tenant.tenant_id
    c = report.scan_context.cloud
    cloud = c.value if hasattr(c, "value") else str(c)
    t = report.scan_context.trigger_type
    trigger_type = t.value if hasattr(t, "value") else str(t)
    generated_at = report.generated_at
    if generated_at.tzinfo is None:
        generated_at = generated_at.replace(tzinfo=timezone.utc)
    
    conn = psycopg2.connect(_connection_string())
    
    try:
        # 1. Write scan summary to threat_scans
        summary = report.threat_summary
        severity_counts = summary.threats_by_severity or {}
        category_counts = summary.threats_by_category or {}
        status_counts = summary.threats_by_status or {}
        
        check_scan_id = report.scan_context.scan_run_id  # This is the check scan
        discovery_scan_id = getattr(report.scan_context, 'discovery_scan_id', None)
        
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO threat_scans (
                    scan_run_id, tenant_id, check_scan_id, discovery_scan_id,
                    cloud, trigger_type, total_threats,
                    critical_count, high_count, medium_count, low_count, info_count,
                    identity_count, exposure_count, data_breach_count, 
                    data_exfiltration_count, misconfiguration_count, drift_count,
                    open_count, resolved_count, suppressed_count,
                    generated_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (scan_run_id) DO UPDATE SET
                    total_threats = EXCLUDED.total_threats,
                    critical_count = EXCLUDED.critical_count,
                    high_count = EXCLUDED.high_count,
                    medium_count = EXCLUDED.medium_count,
                    low_count = EXCLUDED.low_count,
                    info_count = EXCLUDED.info_count,
                    identity_count = EXCLUDED.identity_count,
                    exposure_count = EXCLUDED.exposure_count,
                    data_breach_count = EXCLUDED.data_breach_count,
                    data_exfiltration_count = EXCLUDED.data_exfiltration_count,
                    misconfiguration_count = EXCLUDED.misconfiguration_count,
                    drift_count = EXCLUDED.drift_count,
                    open_count = EXCLUDED.open_count,
                    resolved_count = EXCLUDED.resolved_count,
                    suppressed_count = EXCLUDED.suppressed_count,
                    generated_at = EXCLUDED.generated_at
            """, (
                scan_run_id, tenant_id, check_scan_id, discovery_scan_id,
                cloud, trigger_type, summary.total_threats,
                severity_counts.get('critical', 0),
                severity_counts.get('high', 0),
                severity_counts.get('medium', 0),
                severity_counts.get('low', 0),
                severity_counts.get('info', 0),
                category_counts.get('identity', 0),
                category_counts.get('exposure', 0),
                category_counts.get('data_breach', 0),
                category_counts.get('data_exfiltration', 0),
                category_counts.get('misconfiguration', 0),
                category_counts.get('drift', 0),
                status_counts.get('open', 0),
                status_counts.get('resolved', 0),
                status_counts.get('suppressed', 0),
                generated_at
            ))
        
        # 2. Write individual threats
        for threat in report.threats:
            threat_type_val = threat.threat_type.value if hasattr(threat.threat_type, 'value') else str(threat.threat_type)
            severity_val = threat.severity.value if hasattr(threat.severity, 'value') else str(threat.severity)
            confidence_val = threat.confidence.value if hasattr(threat.confidence, 'value') else str(threat.confidence)
            status_val = threat.status.value if hasattr(threat.status, 'value') else str(threat.status)
            
            # Extract primary_rule_id from correlations (use first finding's rule)
            primary_rule_id = None
            finding_refs = []
            if threat.correlations and threat.correlations.misconfig_finding_refs:
                finding_refs = threat.correlations.misconfig_finding_refs
                # Try to extract rule_id from first finding in report
                for finding in report.misconfig_findings:
                    if finding.misconfig_finding_id == finding_refs[0]:
                        primary_rule_id = finding.rule_id
                        break
            
            remediation_summary = None
            remediation_steps = None
            if threat.remediation:
                remediation_summary = threat.remediation.get('summary')
                remediation_steps = threat.remediation.get('steps', [])
            
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO threats (
                        threat_id, scan_run_id, tenant_id, primary_rule_id,
                        threat_type, category, severity, confidence, status,
                        title, description, remediation_summary, remediation_steps,
                        first_seen_at, last_seen_at, resolved_at,
                        misconfig_count, affected_resource_count,
                        misconfig_finding_refs
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (threat_id) DO UPDATE SET
                        status = EXCLUDED.status,
                        last_seen_at = EXCLUDED.last_seen_at,
                        resolved_at = EXCLUDED.resolved_at,
                        misconfig_count = EXCLUDED.misconfig_count,
                        affected_resource_count = EXCLUDED.affected_resource_count,
                        updated_at = NOW()
                """, (
                    threat.threat_id,
                    scan_run_id,
                    tenant_id,
                    primary_rule_id,
                    threat_type_val,
                    threat_type_val,  # category = threat_type for now
                    severity_val,
                    confidence_val,
                    status_val,
                    threat.title,
                    threat.description,
                    remediation_summary,
                    Json(remediation_steps) if remediation_steps else None,
                    threat.first_seen_at,
                    threat.last_seen_at,
                    None,  # resolved_at (set when status changes)
                    len(finding_refs),
                    len(threat.affected_assets),
                    Json(finding_refs)
                ))
            
            # 3. Write threat-resource mappings
            for asset in threat.affected_assets:
                resource_uid = asset.get('resource_uid')
                if not resource_uid:
                    continue
                
                # Collect failed rules for this resource from findings
                failed_rules = []
                for finding in report.misconfig_findings:
                    if finding.misconfig_finding_id in finding_refs:
                        if finding.resource.get('resource_uid') == resource_uid:
                            failed_rules.append(finding.rule_id)
                
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO threat_resources (
                            threat_id, resource_uid, resource_arn, resource_type,
                            account_id, region, failed_rule_ids, tags
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (threat_id, resource_uid) DO UPDATE SET
                            failed_rule_ids = EXCLUDED.failed_rule_ids,
                            tags = EXCLUDED.tags
                    """, (
                        threat.threat_id,
                        resource_uid,
                        asset.get('resource_arn'),
                        asset.get('resource_type'),
                        asset.get('account'),
                        asset.get('region'),
                        Json(list(set(failed_rules))) if failed_rules else None,
                        Json(asset.get('tags', {}))
                    ))
            
            # 4. Write drift records (if this threat has drift info)
            if threat.drift:
                drift_id = f"drift_{threat.threat_id}"
                
                # Extract resource from affected_assets
                resource_uid = threat.affected_assets[0].get('resource_uid') if threat.affected_assets else None
                resource_arn = threat.affected_assets[0].get('resource_arn') if threat.affected_assets else None
                resource_type = threat.affected_assets[0].get('resource_type') if threat.affected_assets else None
                account_id = threat.affected_assets[0].get('account') if threat.affected_assets else None
                region = threat.affected_assets[0].get('region') if threat.affected_assets else None
                
                drift_event = threat.drift
                current_scan = drift_event.current_scan_id
                previous_scan = drift_event.baseline_scan_id
                change_type = drift_event.change_type
                
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO drift_records (
                            drift_id, tenant_id, resource_uid, resource_arn, resource_type,
                            account_id, region, current_scan_id, previous_scan_id,
                            config_drift_detected, change_type, config_diff,
                            status_drift_detected, threat_id, detected_at
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (drift_id) DO UPDATE SET
                            config_drift_detected = EXCLUDED.config_drift_detected,
                            status_drift_detected = EXCLUDED.status_drift_detected,
                            threat_id = EXCLUDED.threat_id
                    """, (
                        drift_id,
                        tenant_id,
                        resource_uid,
                        resource_arn,
                        resource_type,
                        account_id,
                        region,
                        current_scan,
                        previous_scan,
                        True,  # config_drift_detected
                        change_type,
                        Json({}),  # config_diff (TODO: add detailed diff)
                        False,  # status_drift_detected (would come from check drift)
                        threat.threat_id,
                        threat.first_seen_at
                    ))
        
        conn.commit()
        return scan_run_id
        
    finally:
        conn.close()


def get_report_from_db(tenant_id: str, scan_run_id: str) -> Optional[Dict[str, Any]]:
    """
    Load threat report from normalized tables and reconstruct report format.
    
    Queries:
    - threat_scans for summary
    - threats for threat list
    - threat_resources for affected assets
    
    Returns:
        Reconstructed ThreatReport dict or None
    """
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
    except ImportError:
        return None
    
    conn = psycopg2.connect(_connection_string())
    
    try:
        # Get scan summary
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT * FROM threat_scans
                WHERE tenant_id = %s AND scan_run_id = %s
            """, (tenant_id, scan_run_id))
            scan = cur.fetchone()
        
        if not scan:
            return None
        
        # Get all threats for this scan
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT * FROM threats
                WHERE tenant_id = %s AND scan_run_id = %s
                ORDER BY severity DESC, threat_type
            """, (tenant_id, scan_run_id))
            threat_rows = cur.fetchall()
        
        # Reconstruct report format
        threats = []
        for t in threat_rows:
            # Get affected resources for this threat
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT * FROM threat_resources
                    WHERE threat_id = %s
                """, (t['threat_id'],))
                resources = cur.fetchall()
            
            affected_assets = []
            for r in resources:
                affected_assets.append({
                    'resource_uid': r['resource_uid'],
                    'resource_arn': r['resource_arn'],
                    'resource_id': None,
                    'resource_type': r['resource_type'],
                    'account': r['account_id'],
                    'region': r['region'],
                    'tags': r['tags'] or {}
                })
            
            threats.append({
                'threat_id': t['threat_id'],
                'threat_type': t['threat_type'],
                'title': t['title'],
                'description': t['description'],
                'severity': t['severity'],
                'confidence': t['confidence'],
                'status': t['status'],
                'first_seen_at': t['first_seen_at'].isoformat() if t['first_seen_at'] else None,
                'last_seen_at': t['last_seen_at'].isoformat() if t['last_seen_at'] else None,
                'affected_assets': affected_assets,
                'correlations': {
                    'misconfig_finding_refs': t['misconfig_finding_refs'] or [],
                    'affected_assets': affected_assets
                },
                'remediation': {
                    'summary': t['remediation_summary'],
                    'steps': t['remediation_steps'] or []
                } if t['remediation_summary'] else None,
                'evidence_refs': [],
                'drift': None  # TODO: reconstruct from drift_records if needed
            })
        
        # Reconstruct full report
        report_dict = {
            'schema_version': 'cspm_threat_report.v1',
            'tenant': {
                'tenant_id': tenant_id,
                'tenant_name': None
            },
            'scan_context': {
                'scan_run_id': scan_run_id,
                'trigger_type': scan['trigger_type'],
                'cloud': scan['cloud'],
                'accounts': [],
                'regions': [],
                'services': [],
                'started_at': None,
                'completed_at': None,
                'engine_version': None
            },
            'threat_summary': {
                'total_threats': scan['total_threats'],
                'threats_by_severity': {
                    'critical': scan['critical_count'],
                    'high': scan['high_count'],
                    'medium': scan['medium_count'],
                    'low': scan['low_count']
                },
                'threats_by_category': {
                    'identity': scan['identity_count'],
                    'exposure': scan['exposure_count'],
                    'data_breach': scan['data_breach_count'],
                    'data_exfiltration': scan['data_exfiltration_count'],
                    'misconfiguration': scan['misconfiguration_count'],
                    'drift': scan['drift_count']
                },
                'threats_by_status': {
                    'open': scan['open_count'],
                    'resolved': scan['resolved_count'],
                    'suppressed': scan['suppressed_count']
                },
                'top_threat_categories': []
            },
            'threats': threats,
            'misconfig_findings': [],  # Not stored in normalized schema
            'asset_snapshots': [],
            'evidence': [],
            'generated_at': scan['generated_at'].isoformat()
        }
        
        return report_dict
        
    finally:
        conn.close()


def list_reports_from_db(tenant_id: str, limit: int = 100) -> List[Dict[str, Any]]:
    """
    List threat scan summaries for a tenant.
    
    Returns:
        List of scan summaries
    """
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
    except ImportError:
        return []
    
    conn = psycopg2.connect(_connection_string())
    out: List[Dict[str, Any]] = []
    
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT 
                    scan_run_id, cloud, total_threats,
                    critical_count, high_count, medium_count, low_count,
                    identity_count, exposure_count, data_breach_count,
                    generated_at
                FROM threat_scans
                WHERE tenant_id = %s
                ORDER BY generated_at DESC
                LIMIT %s
            """, (tenant_id, limit))
            
            for row in cur.fetchall():
                out.append({
                    'scan_run_id': row['scan_run_id'],
                    'cloud': row['cloud'],
                    'total_threats': row['total_threats'],
                    'threats_by_severity': {
                        'critical': row['critical_count'],
                        'high': row['high_count'],
                        'medium': row['medium_count'],
                        'low': row['low_count']
                    },
                    'generated_at': row['generated_at'].isoformat()
                })
        
        return out
        
    finally:
        conn.close()


def update_report_in_db(tenant_id: str, scan_run_id: str, report_dict: Dict[str, Any]) -> bool:
    """
    Update threat report (primarily for status changes).
    
    Note: In normalized schema, typically update individual threat status
    rather than entire report. This is kept for compatibility.
    """
    # For normalized schema, this would update specific threat status
    # Implementation depends on what fields are being updated
    return True


def update_threat_status(threat_id: str, status: str, resolved_at: Optional[datetime] = None) -> bool:
    """
    Update individual threat status in normalized schema.
    
    Args:
        threat_id: Threat identifier
        status: New status (open, resolved, suppressed, false_positive)
        resolved_at: Timestamp when resolved (if status=resolved)
    
    Returns:
        True if updated successfully
    """
    try:
        import psycopg2
    except ImportError:
        return False
    
    conn = psycopg2.connect(_connection_string())
    
    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE threats
                SET status = %s, 
                    resolved_at = %s,
                    updated_at = NOW()
                WHERE threat_id = %s
            """, (status, resolved_at, threat_id))
        conn.commit()
        return True
        
    except Exception:
        return False
        
    finally:
        conn.close()
