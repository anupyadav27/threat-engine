"""
DataSec Database Writer

Writes data security reports to RDS:
- datasec_reports (main report)
- datasec_findings (individual data security findings)
"""

import os
import json
import uuid
from typing import Dict, Any, List
from datetime import datetime, timezone

import psycopg2
from psycopg2.extras import Json


def _get_datasec_db_connection():
    """Get DataSec DB connection using individual parameters."""
    return psycopg2.connect(
        host=os.getenv("DATASEC_DB_HOST", "localhost"),
        port=int(os.getenv("DATASEC_DB_PORT", "5432")),
        database=os.getenv("DATASEC_DB_NAME", "threat_engine_datasec"),
        user=os.getenv("DATASEC_DB_USER", "postgres"),
        password=os.getenv("DATASEC_DB_PASSWORD", "")
    )


def save_datasec_report_to_db(report: Dict[str, Any]) -> str:
    """
    Save data security report to database.
    
    Args:
        report: Full data security report dict
    
    Returns:
        report_id (UUID string)
    """
    report_id_str = str(report.get("report_id") or uuid.uuid4())
    tenant_id = report.get("tenant_id", "default")
    scan_context = report.get("scan_context", {})
    scan_run_id = scan_context.get("threat_scan_run_id", "")
    cloud = scan_context.get("csp", "aws")
    
    # Parse timestamp
    generated_at_str = scan_context.get("generated_at", "")
    try:
        generated_at = datetime.fromisoformat(generated_at_str.replace('Z', '+00:00'))
    except:
        generated_at = datetime.now(timezone.utc)
    
    # Extract summary
    summary = report.get("summary", {})
    total_findings = summary.get("total_findings", 0)
    datasec_relevant = summary.get("data_security_relevant_findings", 0)
    findings_by_module = summary.get("findings_by_module", {})
    
    classification_summary = summary.get("classification", {})
    classified_resources = classification_summary.get("classified_resources", 0)
    classification_types = classification_summary.get("classification_types", {})
    
    residency_summary = summary.get("residency", {})
    
    total_data_stores = scan_context.get("total_data_stores", 0)
    
    conn = _get_datasec_db_connection()
    
    try:
        with conn.cursor() as cur:
            # Upsert tenant
            cur.execute("""
                INSERT INTO tenants (tenant_id, tenant_name)
                VALUES (%s, %s)
                ON CONFLICT (tenant_id) DO NOTHING
            """, (tenant_id, tenant_id))
            
            # Insert report
            cur.execute("""
                INSERT INTO datasec_reports (
                    report_id, tenant_id, scan_run_id, cloud, generated_at,
                    total_findings, datasec_relevant_findings, 
                    classified_resources, total_data_stores,
                    findings_by_module, classification_summary, residency_summary,
                    report_data
                )
                VALUES (%s::uuid, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb)
                ON CONFLICT (report_id) DO UPDATE SET
                    generated_at = EXCLUDED.generated_at,
                    total_findings = EXCLUDED.total_findings,
                    datasec_relevant_findings = EXCLUDED.datasec_relevant_findings,
                    classified_resources = EXCLUDED.classified_resources,
                    total_data_stores = EXCLUDED.total_data_stores,
                    findings_by_module = EXCLUDED.findings_by_module,
                    classification_summary = EXCLUDED.classification_summary,
                    residency_summary = EXCLUDED.residency_summary,
                    report_data = EXCLUDED.report_data
            """, (
                str(report_id_str),
                tenant_id,
                scan_run_id,
                cloud,
                generated_at,
                total_findings,
                datasec_relevant,
                classified_resources,
                total_data_stores,
                json.dumps(findings_by_module),
                json.dumps(classification_types),
                json.dumps(residency_summary),
                json.dumps(report, default=str)
            ))
            
            # Insert findings
            findings = report.get("findings", [])
            classification = report.get("classification", [])
            
            # Create classification lookup
            classification_map = {}
            for cls in classification:
                resource_id = cls.get("resource_id")
                if resource_id:
                    classification_map[resource_id] = {
                        "types": cls.get("classification", []),
                        "confidence": cls.get("confidence", 0.0)
                    }
            
            for finding in findings:
                if finding.get("status") == "FAIL":  # Only store failures
                    finding_id = str(uuid.uuid4())
                    resource_id = finding.get("resource", {}).get("id") or finding.get("resource", {}).get("arn")
                    
                    # Get classification for this resource
                    cls_info = classification_map.get(resource_id, {})
                    data_classification = cls_info.get("types", [])
                    sensitivity = cls_info.get("confidence", 0.0)
                    
                    cur.execute("""
                        INSERT INTO datasec_findings (
                            finding_id, report_id, tenant_id, scan_run_id,
                            rule_id, datasec_modules, severity, status,
                            resource_type, resource_id, resource_arn, account_id, region,
                            data_classification, sensitivity_score,
                            finding_data, first_seen_at, last_seen_at
                        )
                        VALUES (%s, %s::uuid, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s)
                        ON CONFLICT (finding_id) DO NOTHING
                    """, (
                        finding_id,
                        str(report_id_str),
                        tenant_id,
                        scan_run_id,
                        finding.get("rule_id"),
                        finding.get("data_security_modules", []),
                        finding.get("severity", "medium"),
                        finding.get("status"),
                        finding.get("resource", {}).get("type"),
                        finding.get("resource", {}).get("id"),
                        finding.get("resource", {}).get("arn"),
                        finding.get("account_id"),
                        finding.get("region"),
                        data_classification,
                        sensitivity,
                        json.dumps(finding, default=str),
                        generated_at,
                        generated_at
                    ))
        
        conn.commit()
        return report_id_str
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
