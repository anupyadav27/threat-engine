"""
IAM Database Writer

Writes IAM reports to RDS:
- iam_report (main report, PK: scan_run_id)
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
    iam_scan_id = str(report.get("scan_run_id") or report.get("iam_scan_id") or report.get("report_id") or uuid.uuid4())
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

    # Count access keys that need rotation — FAIL findings whose rule_id references
    # key age / rotation policy (e.g. aws.iam.access_key.rotation, credential.age, etc.)
    _KEY_ROTATION_TERMS = ("rotation", "key_age", "access_key", "rotate", "credential_age")
    key_rotation_count = sum(
        1 for f in findings
        if f.get("status") == "FAIL"
        and any(term in (f.get("rule_id") or "").lower() for term in _KEY_ROTATION_TERMS)
    )

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
                    scan_run_id, tenant_id, cloud, generated_at,
                    total_findings, iam_relevant_findings, critical_findings, high_findings,
                    key_rotation_count,
                    findings_by_module, findings_by_status, report_data
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb)
                ON CONFLICT (scan_run_id) DO UPDATE SET
                    generated_at = EXCLUDED.generated_at,
                    total_findings = EXCLUDED.total_findings,
                    iam_relevant_findings = EXCLUDED.iam_relevant_findings,
                    critical_findings = EXCLUDED.critical_findings,
                    high_findings = EXCLUDED.high_findings,
                    key_rotation_count = EXCLUDED.key_rotation_count,
                    findings_by_module = EXCLUDED.findings_by_module,
                    findings_by_status = EXCLUDED.findings_by_status,
                    report_data = EXCLUDED.report_data
            """, (
                iam_scan_id,
                tenant_id,
                cloud,
                generated_at,
                total_findings,
                iam_relevant,
                critical,
                high,
                key_rotation_count,
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
                            finding_id, scan_run_id, tenant_id,
                            rule_id, iam_modules, severity, status,
                            resource_type, resource_id, resource_uid,
                            account_id, region, provider,
                            finding_data, first_seen_at, last_seen_at
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s)
                        ON CONFLICT (finding_id) DO NOTHING
                    """, (
                        finding_id,
                        iam_scan_id,
                        tenant_id,
                        finding.get("rule_id"),
                        finding.get("iam_security_modules", []),
                        finding.get("severity", "medium"),
                        finding.get("status"),
                        finding.get("resource_type"),
                        finding.get("resource_id"),
                        finding.get("resource_uid") or finding.get("resource_arn"),
                        finding.get("account_id"),
                        finding.get("region"),
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


def save_policy_statements(
    scan_run_id: str,
    tenant_id: str,
    statements: List[Dict[str, Any]],
) -> int:
    """
    Save parsed IAM policy statements to iam_policy_statements table.

    Args:
        scan_run_id: Scan run identifier
        tenant_id: Tenant identifier
        statements: List of statement dicts from policy_parser.policies_to_db_rows()

    Returns:
        Number of rows inserted
    """
    if not statements:
        return 0

    conn = _get_iam_db_connection()
    count = 0
    try:
        with conn.cursor() as cur:
            # Upsert tenant
            cur.execute("""
                INSERT INTO tenants (tenant_id, tenant_name)
                VALUES (%s, %s)
                ON CONFLICT (tenant_id) DO NOTHING
            """, (tenant_id, tenant_id))

            # Ensure table exists (idempotent DDL)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS iam_policy_statements (
                    statement_id VARCHAR(255) PRIMARY KEY,
                    scan_run_id VARCHAR(255) NOT NULL,
                    tenant_id VARCHAR(255) NOT NULL,
                    account_id VARCHAR(50),
                    policy_arn TEXT,
                    policy_name VARCHAR(255),
                    policy_type VARCHAR(20) NOT NULL,
                    is_aws_managed BOOLEAN DEFAULT FALSE,
                    attached_to_arn TEXT,
                    attached_to_type VARCHAR(20),
                    sid VARCHAR(255),
                    effect VARCHAR(10) NOT NULL,
                    actions TEXT[] NOT NULL,
                    resources TEXT[] NOT NULL,
                    conditions JSONB,
                    principals TEXT[],
                    is_admin BOOLEAN DEFAULT FALSE,
                    is_wildcard_principal BOOLEAN DEFAULT FALSE,
                    has_external_id BOOLEAN,
                    is_cross_account BOOLEAN,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                    CONSTRAINT fk_tenant_stmt FOREIGN KEY (tenant_id)
                        REFERENCES tenants(tenant_id) ON DELETE CASCADE
                )
            """)

            for stmt in statements:
                cur.execute("""
                    INSERT INTO iam_policy_statements (
                        statement_id, scan_run_id, tenant_id, account_id,
                        policy_arn, policy_name, policy_type, is_aws_managed,
                        attached_to_arn, attached_to_type,
                        sid, effect, actions, resources,
                        conditions, principals,
                        is_admin, is_wildcard_principal, has_external_id, is_cross_account
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s::jsonb, %s,
                        %s, %s, %s, %s
                    )
                    ON CONFLICT (statement_id) DO NOTHING
                """, (
                    stmt["statement_id"],
                    stmt["scan_run_id"],
                    stmt["tenant_id"],
                    stmt.get("account_id"),
                    stmt.get("policy_arn"),
                    stmt.get("policy_name"),
                    stmt["policy_type"],
                    stmt.get("is_aws_managed", False),
                    stmt.get("attached_to_arn"),
                    stmt.get("attached_to_type"),
                    stmt.get("sid"),
                    stmt["effect"],
                    stmt.get("actions", []),
                    stmt.get("resources", []),
                    json.dumps(stmt["conditions"]) if stmt.get("conditions") else None,
                    stmt.get("principals"),
                    stmt.get("is_admin", False),
                    stmt.get("is_wildcard_principal", False),
                    stmt.get("has_external_id"),
                    stmt.get("is_cross_account"),
                ))
                count += 1

        conn.commit()
        return count
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
