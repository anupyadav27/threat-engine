"""
Threat DB Writer - Writes to actual threat_engine_threat tables.

Persists threat reports to PostgreSQL using:
- threat_report (scan summary with report_data JSONB)
- threat_detections (individual threat detections with MITRE ATT&CK)
- threat_findings (individual findings with MITRE mapping)
"""

from __future__ import annotations

import json
import os
import uuid
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..schemas.threat_report_schema import ThreatReport

logger = logging.getLogger(__name__)


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


def _ensure_tenant(conn, tenant_id: str):
    """Upsert tenant into threat DB's tenants table to satisfy FK constraints."""
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO tenants (tenant_id, tenant_name)
            VALUES (%s, %s)
            ON CONFLICT (tenant_id) DO NOTHING
        """, (tenant_id, tenant_id))


def _ts_with_tz(dt: Optional[datetime]) -> Optional[datetime]:
    """Ensure datetime has timezone info (UTC if missing)."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def save_report_to_db(report: ThreatReport) -> str:
    """
    Persist threat report to threat_engine_threat PostgreSQL tables.

    Writes to:
    - threat_report (scan summary + full report_data JSONB)
    - threat_detections (individual threats with MITRE ATT&CK)
    - threat_findings (individual misconfig findings with MITRE mapping)

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
    customer_id = getattr(report.tenant, 'customer_id', None)
    c = report.scan_context.cloud
    cloud = c.value if hasattr(c, "value") else str(c)
    generated_at = _ts_with_tz(report.generated_at)

    # Use scan_run_id directly as threat_scan_id (set by caller / orchestration)
    threat_scan_id = scan_run_id

    conn = psycopg2.connect(_connection_string())

    try:
        # Ensure tenant exists
        _ensure_tenant(conn, tenant_id)

        # Build severity counts from summary
        summary = report.threat_summary
        severity_counts = summary.threats_by_severity or {}

        # Build report_data JSONB (full summary + scan context)
        report_data = {
            "schema_version": report.schema_version,
            "threat_summary": summary.dict() if hasattr(summary, 'dict') else dict(summary),
            "scan_context": report.scan_context.dict() if hasattr(report.scan_context, 'dict') else {},
        }

        # 1. Write to threat_report
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO threat_report (
                    threat_scan_id, tenant_id, customer_id, provider,
                    scan_run_id, check_scan_id,
                    started_at, completed_at, status,
                    total_findings, critical_findings, high_findings,
                    medium_findings, low_findings, threat_score,
                    report_data
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (threat_scan_id) DO UPDATE SET
                    total_findings = EXCLUDED.total_findings,
                    critical_findings = EXCLUDED.critical_findings,
                    high_findings = EXCLUDED.high_findings,
                    medium_findings = EXCLUDED.medium_findings,
                    low_findings = EXCLUDED.low_findings,
                    threat_score = EXCLUDED.threat_score,
                    report_data = EXCLUDED.report_data,
                    completed_at = EXCLUDED.completed_at,
                    status = EXCLUDED.status
            """, (
                threat_scan_id,
                tenant_id,
                customer_id,
                cloud,
                scan_run_id,
                scan_run_id,  # check_scan_id = scan_run_id
                _ts_with_tz(report.scan_context.started_at),
                _ts_with_tz(report.scan_context.completed_at) or generated_at,
                "completed",
                summary.total_threats,
                severity_counts.get('critical', 0),
                severity_counts.get('high', 0),
                severity_counts.get('medium', 0),
                severity_counts.get('low', 0),
                0,  # threat_score
                Json(report_data, dumps=lambda o: json.dumps(o, default=_default_json)),
            ))

        # 2. Write individual threat detections
        for threat in report.threats:
            threat_type_val = threat.threat_type.value if hasattr(threat.threat_type, 'value') else str(threat.threat_type)
            severity_val = threat.severity.value if hasattr(threat.severity, 'value') else str(threat.severity)
            confidence_val = threat.confidence.value if hasattr(threat.confidence, 'value') else str(threat.confidence)
            status_val = threat.status.value if hasattr(threat.status, 'value') else str(threat.status)

            # Extract primary rule_id from correlations
            primary_rule_id = None
            finding_refs = []
            if threat.correlations and threat.correlations.misconfig_finding_refs:
                finding_refs = threat.correlations.misconfig_finding_refs
                for finding in report.misconfig_findings:
                    if finding.misconfig_finding_id == finding_refs[0]:
                        primary_rule_id = finding.rule_id
                        break

            # Extract resource info from first affected asset
            resource_uid = None
            resource_id = None
            resource_type = None
            account_id = None
            region = None
            if threat.affected_assets:
                asset = threat.affected_assets[0]
                resource_uid = asset.get('resource_uid') or asset.get('resource_arn')
                resource_id = asset.get('resource_id')
                resource_type = asset.get('resource_type')
                account_id = asset.get('account')
                region = asset.get('region')

            # MITRE ATT&CK data from threat
            mitre_techniques = threat.mitre_techniques or []
            mitre_tactics = threat.mitre_tactics or []

            # Build evidence JSONB
            evidence = {
                "finding_refs": finding_refs,
                "affected_assets": threat.affected_assets,
                "remediation": threat.remediation,
            }

            # Build context JSONB
            context = {
                "threat_scan_id": threat_scan_id,
                "risk_score": threat.risk_score,
                "correlations": {
                    "misconfig_finding_refs": finding_refs,
                    "affected_assets": threat.affected_assets,
                },
            }

            # Generate deterministic UUID from threat_id
            detection_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, threat.threat_id))

            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO threat_detections (
                        detection_id, tenant_id, scan_id,
                        detection_type, rule_id, rule_name,
                        resource_uid, resource_id, resource_type,
                        account_id, region, provider,
                        severity, confidence, status,
                        threat_category,
                        mitre_tactics, mitre_techniques,
                        indicators, evidence, context,
                        detection_timestamp, first_seen_at, last_seen_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (detection_id) DO UPDATE SET
                        status = EXCLUDED.status,
                        last_seen_at = EXCLUDED.last_seen_at,
                        mitre_tactics = EXCLUDED.mitre_tactics,
                        mitre_techniques = EXCLUDED.mitre_techniques,
                        evidence = EXCLUDED.evidence,
                        context = EXCLUDED.context
                """, (
                    detection_uuid,
                    tenant_id,
                    scan_run_id,
                    threat_type_val,
                    primary_rule_id,
                    threat.title,
                    resource_uid,
                    resource_id,
                    resource_type,
                    account_id,
                    region,
                    cloud,
                    severity_val,
                    confidence_val,
                    status_val,
                    threat_type_val,
                    Json(mitre_tactics),
                    Json(mitre_techniques),
                    Json([]),
                    Json(evidence, dumps=lambda o: json.dumps(o, default=_default_json)),
                    Json(context, dumps=lambda o: json.dumps(o, default=_default_json)),
                    generated_at,
                    _ts_with_tz(threat.first_seen_at),
                    _ts_with_tz(threat.last_seen_at),
                ))

        # 3. Write individual findings to threat_findings
        # Delete existing findings for this threat_scan_id first (ensures clean re-run
        # and fixes any stale rows from old account_id representations)
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM threat_findings WHERE threat_scan_id = %s",
                (threat_scan_id,)
            )

        for finding in report.misconfig_findings:
            severity_val = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)

            # MITRE data from finding
            mitre_techniques = finding.mitre_techniques or []
            mitre_tactics = finding.mitre_tactics or []
            threat_category = finding.threat_category

            # Build evidence and finding_data JSONB
            evidence_data = {
                "checked_fields": finding.checked_fields,
                "evidence_refs": finding.evidence_refs,
            }
            finding_data = {
                "resource": finding.resource,
                "finding_key": finding.finding_key,
                "title": finding.title,
                "description": finding.description,
                "remediation": finding.remediation,
                "domain": finding.domain,
                "risk_score": finding.risk_score,
                "threat_tags": finding.threat_tags,
            }

            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO threat_findings (
                        finding_id, threat_scan_id, tenant_id, customer_id,
                        scan_run_id, rule_id, threat_category,
                        severity, status,
                        resource_type, resource_id, resource_uid,
                        account_id, region,
                        mitre_tactics, mitre_techniques,
                        evidence, finding_data,
                        first_seen_at, last_seen_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (finding_id) DO UPDATE SET
                        threat_scan_id = EXCLUDED.threat_scan_id,
                        scan_run_id = EXCLUDED.scan_run_id,
                        tenant_id = EXCLUDED.tenant_id,
                        status = EXCLUDED.status,
                        last_seen_at = EXCLUDED.last_seen_at,
                        mitre_tactics = EXCLUDED.mitre_tactics,
                        mitre_techniques = EXCLUDED.mitre_techniques,
                        finding_data = EXCLUDED.finding_data
                """, (
                    finding.misconfig_finding_id,
                    threat_scan_id,
                    tenant_id,
                    customer_id,
                    scan_run_id,
                    finding.rule_id,
                    threat_category,
                    severity_val,
                    finding.result,
                    finding.resource.get('resource_type'),
                    finding.resource.get('resource_id'),
                    finding.resource.get('resource_uid') or finding.resource.get('resource_arn'),
                    finding.account,
                    finding.region,
                    Json(mitre_tactics),
                    Json(mitre_techniques),
                    Json(evidence_data, dumps=lambda o: json.dumps(o, default=_default_json)),
                    Json(finding_data, dumps=lambda o: json.dumps(o, default=_default_json)),
                    _ts_with_tz(finding.first_seen_at),
                    _ts_with_tz(finding.last_seen_at),
                ))

        conn.commit()
        logger.info("Threat report saved to DB",
                     extra={"extra_fields": {
                         "threat_scan_id": threat_scan_id,
                         "threats": len(report.threats),
                         "findings": len(report.misconfig_findings),
                     }})
        return scan_run_id

    except Exception as e:
        conn.rollback()
        logger.error(f"Failed to save threat report to DB: {e}", exc_info=True)
        raise

    finally:
        conn.close()


def get_report_from_db(tenant_id: str, scan_run_id: str) -> Optional[Dict[str, Any]]:
    """
    Load threat report from threat_report + threat_detections + threat_findings.

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
        # Get report summary — match by scan_run_id or threat_scan_id (both could be the same)
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT * FROM threat_report
                WHERE tenant_id = %s AND (scan_run_id = %s OR threat_scan_id = %s)
            """, (tenant_id, scan_run_id, scan_run_id))
            scan = cur.fetchone()

        if not scan:
            return None

        # Get threat detections
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT * FROM threat_detections
                WHERE tenant_id = %s AND scan_id = %s
                ORDER BY severity, detection_type
            """, (tenant_id, scan_run_id))
            detection_rows = cur.fetchall()

        # Get findings
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT * FROM threat_findings
                WHERE tenant_id = %s AND threat_scan_id = %s
                ORDER BY severity, rule_id
            """, (tenant_id, scan['threat_scan_id']))
            finding_rows = cur.fetchall()

        # Reconstruct threats
        threats = []
        for d in detection_rows:
            evidence_data = d.get('evidence') or {}
            context_data = d.get('context') or {}
            threats.append({
                'threat_id': str(d['detection_id']),
                'threat_type': d['detection_type'],
                'title': d['rule_name'] or d['detection_type'],
                'description': '',
                'severity': d['severity'],
                'confidence': d['confidence'],
                'status': d['status'],
                'first_seen_at': d['first_seen_at'].isoformat() if d['first_seen_at'] else None,
                'last_seen_at': d['last_seen_at'].isoformat() if d['last_seen_at'] else None,
                'affected_assets': evidence_data.get('affected_assets', []),
                'correlations': context_data.get('correlations', {}),
                'remediation': evidence_data.get('remediation'),
                'evidence_refs': [],
                'drift': None,
                'mitre_techniques': d.get('mitre_techniques') or [],
                'mitre_tactics': d.get('mitre_tactics') or [],
                'risk_score': context_data.get('risk_score'),
            })

        # Reconstruct findings
        misconfig_findings = []
        for f in finding_rows:
            fd = f.get('finding_data') or {}
            misconfig_findings.append({
                'misconfig_finding_id': f['finding_id'],
                'finding_key': fd.get('finding_key', ''),
                'rule_id': f['rule_id'],
                'severity': f['severity'],
                'result': f['status'],
                'account': f['account_id'] or '',
                'region': f['region'] or '',
                'service': '',
                'resource': fd.get('resource', {}),
                'evidence_refs': [],
                'checked_fields': (f.get('evidence') or {}).get('checked_fields', []),
                'mitre_techniques': f.get('mitre_techniques') or [],
                'mitre_tactics': f.get('mitre_tactics') or [],
                'threat_category': f.get('threat_category'),
            })

        # Build report using stored report_data or reconstruct
        stored_data = scan.get('report_data') or {}

        report_dict = {
            'schema_version': 'cspm_threat_report.v1',
            'tenant': {
                'tenant_id': tenant_id,
                'tenant_name': None
            },
            'scan_context': stored_data.get('scan_context', {
                'scan_run_id': scan_run_id,
                'trigger_type': 'manual',
                'cloud': scan['provider'],
                'accounts': [],
                'regions': [],
                'services': [],
                'started_at': scan['started_at'].isoformat() if scan.get('started_at') else None,
                'completed_at': scan['completed_at'].isoformat() if scan.get('completed_at') else None,
                'engine_version': None
            }),
            'threat_summary': stored_data.get('threat_summary', {
                'total_threats': scan['total_findings'],
                'threats_by_severity': {
                    'critical': scan['critical_findings'],
                    'high': scan['high_findings'],
                    'medium': scan['medium_findings'],
                    'low': scan['low_findings']
                },
                'threats_by_category': {},
                'threats_by_status': {},
                'top_threat_categories': []
            }),
            'threats': threats,
            'misconfig_findings': misconfig_findings,
            'asset_snapshots': [],
            'evidence': [],
            'generated_at': scan['created_at'].isoformat() if scan.get('created_at') else None,
        }

        return report_dict

    finally:
        conn.close()


def list_reports_from_db(tenant_id: str, limit: int = 100) -> List[Dict[str, Any]]:
    """
    List threat report summaries for a tenant.

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
                    scan_run_id, provider as cloud, total_findings as total_threats,
                    critical_findings as critical_count,
                    high_findings as high_count,
                    medium_findings as medium_count,
                    low_findings as low_count,
                    created_at as generated_at
                FROM threat_report
                WHERE tenant_id = %s
                ORDER BY created_at DESC
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
                    'generated_at': row['generated_at'].isoformat() if row['generated_at'] else None,
                })

        return out

    finally:
        conn.close()


def update_report_in_db(tenant_id: str, scan_run_id: str, report_dict: Dict[str, Any]) -> bool:
    """
    Update threat report data (primarily for status changes).
    Updates report_data JSONB in threat_report table.
    """
    try:
        import psycopg2
        from psycopg2.extras import Json
    except ImportError:
        return False

    conn = psycopg2.connect(_connection_string())

    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE threat_report
                SET report_data = %s
                WHERE tenant_id = %s AND (threat_scan_id = %s OR scan_run_id = %s)
            """, (
                Json(report_dict, dumps=lambda o: json.dumps(o, default=_default_json)),
                tenant_id,
                scan_run_id,
                scan_run_id,
            ))
        conn.commit()
        return True

    except Exception:
        return False

    finally:
        conn.close()


def save_analyses_to_db(
    analyses: List[Dict[str, Any]],
) -> int:
    """
    Persist threat analysis results to threat_analysis table.

    Args:
        analyses: List of analysis dicts from ThreatAnalyzer.analyze_scan()

    Returns:
        Number of rows upserted.
    """
    if not analyses:
        return 0

    try:
        import psycopg2
        from psycopg2.extras import Json
    except ImportError:
        raise RuntimeError("psycopg2 is required for Threat DB writer.")

    conn = psycopg2.connect(_connection_string())
    count = 0

    try:
        tenant_id = analyses[0].get("tenant_id")
        _ensure_tenant(conn, tenant_id)

        for row in analyses:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO threat_analysis (
                        detection_id, tenant_id,
                        analysis_type, analyzer, analysis_status,
                        risk_score, verdict,
                        analysis_results, recommendations,
                        related_threats, attack_chain,
                        started_at, completed_at
                    )
                    VALUES (
                        %s::uuid, %s,
                        %s, %s, %s,
                        %s, %s,
                        %s, %s,
                        %s, %s,
                        %s, %s
                    )
                    ON CONFLICT (detection_id, analysis_type) DO UPDATE SET
                        analysis_status = EXCLUDED.analysis_status,
                        analyzer = EXCLUDED.analyzer,
                        risk_score = EXCLUDED.risk_score,
                        verdict = EXCLUDED.verdict,
                        analysis_results = EXCLUDED.analysis_results,
                        recommendations = EXCLUDED.recommendations,
                        related_threats = EXCLUDED.related_threats,
                        attack_chain = EXCLUDED.attack_chain,
                        started_at = EXCLUDED.started_at,
                        completed_at = EXCLUDED.completed_at
                """, (
                    row["detection_id"],
                    row["tenant_id"],
                    row.get("analysis_type", "risk_triage"),
                    row.get("analyzer", "threat_analyzer.v1"),
                    row.get("analysis_status", "completed"),
                    row.get("risk_score"),
                    row.get("verdict"),
                    Json(row.get("analysis_results", {}), dumps=lambda o: json.dumps(o, default=_default_json)),
                    Json(row.get("recommendations", []), dumps=lambda o: json.dumps(o, default=_default_json)),
                    Json(row.get("related_threats", []), dumps=lambda o: json.dumps(o, default=_default_json)),
                    Json(row.get("attack_chain", []), dumps=lambda o: json.dumps(o, default=_default_json)),
                    _ts_with_tz(row.get("started_at")),
                    _ts_with_tz(row.get("completed_at")),
                ))
                count += 1

        conn.commit()
        logger.info(f"Saved {count} threat analyses to DB")
        return count

    except Exception as e:
        conn.rollback()
        logger.error(f"Failed to save threat analyses to DB: {e}", exc_info=True)
        raise

    finally:
        conn.close()


def get_analyses_from_db(
    tenant_id: str,
    scan_run_id: Optional[str] = None,
    detection_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Load threat analysis rows.

    Filter by scan_run_id (via JOIN to threat_detections)
    or by detection_id directly.
    """
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
    except ImportError:
        return []

    conn = psycopg2.connect(_connection_string())

    try:
        if detection_id:
            # Direct lookup by detection_id
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT
                        a.analysis_id, a.detection_id, a.tenant_id,
                        a.analysis_type, a.analyzer, a.analysis_status,
                        a.risk_score, a.verdict,
                        a.analysis_results, a.recommendations,
                        a.related_threats, a.attack_chain,
                        a.started_at, a.completed_at, a.created_at
                    FROM threat_analysis a
                    WHERE a.tenant_id = %s AND a.detection_id = %s::uuid
                    ORDER BY a.created_at DESC
                """, (tenant_id, detection_id))
                return [dict(row) for row in cur.fetchall()]

        elif scan_run_id:
            # JOIN to threat_detections to filter by scan
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT
                        a.analysis_id, a.detection_id, a.tenant_id,
                        a.analysis_type, a.analyzer, a.analysis_status,
                        a.risk_score, a.verdict,
                        a.analysis_results, a.recommendations,
                        a.related_threats, a.attack_chain,
                        a.started_at, a.completed_at, a.created_at,
                        d.resource_uid, d.resource_type, d.severity as detection_severity,
                        d.rule_name, d.rule_id, d.threat_category,
                        d.mitre_techniques, d.mitre_tactics
                    FROM threat_analysis a
                    JOIN threat_detections d ON a.detection_id = d.detection_id
                    WHERE a.tenant_id = %s AND d.scan_id = %s
                    ORDER BY a.risk_score DESC NULLS LAST
                """, (tenant_id, scan_run_id))
                return [dict(row) for row in cur.fetchall()]

        else:
            # All analyses for tenant (capped)
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT
                        a.analysis_id, a.detection_id, a.tenant_id,
                        a.analysis_type, a.analyzer, a.analysis_status,
                        a.risk_score, a.verdict,
                        a.analysis_results, a.recommendations,
                        a.related_threats, a.attack_chain,
                        a.started_at, a.completed_at, a.created_at
                    FROM threat_analysis a
                    WHERE a.tenant_id = %s
                    ORDER BY a.risk_score DESC NULLS LAST
                    LIMIT 500
                """, (tenant_id,))
                return [dict(row) for row in cur.fetchall()]

    finally:
        conn.close()


def update_threat_status(threat_id: str, status: str, resolved_at: Optional[datetime] = None) -> bool:
    """
    Update individual threat detection status.

    Args:
        threat_id: Detection UUID
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
                UPDATE threat_detections
                SET status = %s,
                    resolved_at = %s
                WHERE detection_id = %s::uuid
            """, (status, resolved_at, threat_id))
        conn.commit()
        return True

    except Exception:
        return False

    finally:
        conn.close()
