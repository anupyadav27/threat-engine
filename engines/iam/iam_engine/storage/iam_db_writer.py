"""
IAM Database Writer

Writes IAM reports to RDS:
- iam_report (main report, PK: iam_scan_id)
- iam_findings (individual IAM findings)
"""

import os
import json
import uuid
from typing import Dict, Any, List
from datetime import datetime, timezone

import psycopg2
from psycopg2.extras import Json


def _get_iam_db_connection():
    """Get IAM DB connection using individual parameters."""
    return psycopg2.connect(
        host=os.getenv("IAM_DB_HOST", "localhost"),
        port=int(os.getenv("IAM_DB_PORT", "5432")),
        database=os.getenv("IAM_DB_NAME", "threat_engine_iam"),
        user=os.getenv("IAM_DB_USER", "postgres"),
        password=os.getenv("IAM_DB_PASSWORD", "")
    )


def save_iam_report_to_db(report: Dict[str, Any]) -> str:
    """
    Save IAM report to database.

    Args:
        report: Full IAM report dict

    Returns:
        iam_scan_id string
    """
    iam_scan_id = str(report.get("iam_scan_id") or report.get("report_id") or uuid.uuid4())
    tenant_id = report.get("tenant_id", "default")
    scan_context = report.get("scan_context", {})
    scan_run_id = scan_context.get("threat_scan_run_id", "")
    cloud = scan_context.get("csp", "aws")

    # Parse timestamp
    generated_at_str = scan_context.get("generated_at", "")
    try:
        generated_at = datetime.fromisoformat(generated_at_str.replace('Z', '+00:00'))
    except Exception:
        generated_at = datetime.now(timezone.utc)

    # Extract summary
    summary = report.get("summary", {})
    total_findings = summary.get("total_findings", 0)
    iam_relevant = summary.get("iam_relevant_findings", 0)
    findings_by_module = summary.get("findings_by_module", {})
    findings_by_status = summary.get("findings_by_status", {})

    # Count severity
    findings = report.get("findings", [])
    critical = sum(1 for f in findings if f.get("severity") == "critical")
    high = sum(1 for f in findings if f.get("severity") == "high")

    conn = _get_iam_db_connection()

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
                INSERT INTO iam_report (
                    iam_scan_id, tenant_id, scan_run_id, cloud, generated_at,
                    total_findings, iam_relevant_findings, critical_findings, high_findings,
                    findings_by_module, findings_by_status, report_data
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb)
                ON CONFLICT (iam_scan_id) DO UPDATE SET
                    generated_at = EXCLUDED.generated_at,
                    total_findings = EXCLUDED.total_findings,
                    iam_relevant_findings = EXCLUDED.iam_relevant_findings,
                    critical_findings = EXCLUDED.critical_findings,
                    high_findings = EXCLUDED.high_findings,
                    findings_by_module = EXCLUDED.findings_by_module,
                    findings_by_status = EXCLUDED.findings_by_status,
                    report_data = EXCLUDED.report_data
            """, (
                iam_scan_id,
                tenant_id,
                scan_run_id,
                cloud,
                generated_at,
                total_findings,
                iam_relevant,
                critical,
                high,
                json.dumps(findings_by_module),
                json.dumps(findings_by_status),
                json.dumps(report, default=str)
            ))

            # Insert findings
            for finding in findings:
                if finding.get("status") == "FAIL":  # Only store failures
                    finding_id = str(uuid.uuid4())

                    cur.execute("""
                        INSERT INTO iam_findings (
                            finding_id, iam_scan_id, tenant_id, scan_run_id,
                            rule_id, iam_modules, severity, status,
                            resource_type, resource_id, resource_uid,
                            account_id, region, hierarchy_id, provider,
                            finding_data, first_seen_at, last_seen_at
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s)
                        ON CONFLICT (finding_id) DO NOTHING
                    """, (
                        finding_id,
                        iam_scan_id,
                        tenant_id,
                        scan_run_id,
                        finding.get("rule_id"),
                        finding.get("iam_security_modules", []),
                        finding.get("severity", "medium"),
                        finding.get("status"),
                        finding.get("resource_type"),
                        finding.get("resource_id"),
                        finding.get("resource_uid") or finding.get("resource_arn"),
                        finding.get("account_id"),
                        finding.get("region"),
                        finding.get("hierarchy_id") or finding.get("account_id"),
                        cloud,
                        json.dumps(finding, default=str),
                        generated_at,
                        generated_at
                    ))

        conn.commit()
        return iam_scan_id
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
