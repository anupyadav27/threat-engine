"""
Database Security DB Writer.

Writes dbsec_report, dbsec_findings, and dbsec_inventory tables
to the threat_engine_database_security database.
"""

import os
import json
import hashlib
import logging
from typing import Dict, Any, List
from datetime import datetime, timezone

import psycopg2

logger = logging.getLogger(__name__)


def _get_dbsec_conn():
    """Get connection to the Database Security database."""
    return psycopg2.connect(
        host=os.getenv("DBSEC_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("DBSEC_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("DBSEC_DB_NAME", "threat_engine_database_security"),
        user=os.getenv("DBSEC_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("DBSEC_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
    )


def generate_finding_id(rule_id: str, resource_uid: str, account_id: str, region: str) -> str:
    """Deterministic finding_id: db_{sha256(rule_id|resource_uid|account|region)[:16]}."""
    raw = f"{rule_id}|{resource_uid}|{account_id}|{region}"
    return f"db_{hashlib.sha256(raw.encode()).hexdigest()[:16]}"


def save_findings_to_db(
    scan_run_id: str,
    tenant_id: str,
    provider: str,
    findings: List[Dict[str, Any]],
    summary: Dict[str, Any],
) -> int:
    """Save database security findings and update report summary.

    Args:
        scan_run_id: Pipeline scan run identifier.
        tenant_id: Tenant identifier.
        provider: Cloud provider (aws, azure, gcp).
        findings: List of database security finding dicts.
        summary: Report summary dict with scores and breakdowns.

    Returns:
        Number of findings written.
    """
    conn = _get_dbsec_conn()
    now = datetime.now(timezone.utc)
    count = 0

    try:
        with conn.cursor() as cur:
            # Ensure tenant exists
            cur.execute(
                "INSERT INTO tenants (tenant_id, tenant_name) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                (tenant_id, tenant_id),
            )

            # Update report with summary
            cur.execute("""
                UPDATE dbsec_report SET
                    status = 'completed',
                    posture_score = %s,
                    total_databases = %s,
                    total_findings = %s,
                    critical_findings = %s,
                    high_findings = %s,
                    medium_findings = %s,
                    low_findings = %s,
                    encryption_score = %s,
                    access_control_score = %s,
                    backup_score = %s,
                    network_score = %s,
                    severity_breakdown = %s::jsonb,
                    service_breakdown = %s::jsonb,
                    domain_breakdown = %s::jsonb,
                    report_data = %s::jsonb,
                    completed_at = %s
                WHERE scan_run_id = %s
            """, (
                summary.get("posture_score", 0),
                summary.get("total_databases", 0),
                summary.get("total_findings", 0),
                summary.get("critical_findings", 0),
                summary.get("high_findings", 0),
                summary.get("medium_findings", 0),
                summary.get("low_findings", 0),
                summary.get("encryption_score", 0),
                summary.get("access_control_score", 0),
                summary.get("backup_score", 0),
                summary.get("network_score", 0),
                json.dumps(summary.get("severity_breakdown", {})),
                json.dumps(summary.get("service_breakdown", {})),
                json.dumps(summary.get("domain_breakdown", {})),
                json.dumps(summary, default=str),
                now,
                scan_run_id,
            ))

            # Insert findings
            for f in findings:
                cur.execute("""
                    INSERT INTO dbsec_findings (
                        finding_id, scan_run_id, tenant_id, account_id,
                        credential_ref, credential_type, provider, region,
                        resource_uid, resource_type,
                        db_engine, db_service, security_domain,
                        severity, status, rule_id, finding_data,
                        first_seen_at, last_seen_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s)
                    ON CONFLICT (finding_id) DO UPDATE SET
                        last_seen_at = EXCLUDED.last_seen_at,
                        status = EXCLUDED.status,
                        severity = EXCLUDED.severity,
                        finding_data = EXCLUDED.finding_data
                """, (
                    f["finding_id"],
                    scan_run_id,
                    tenant_id,
                    f.get("account_id"),
                    f.get("credential_ref"),
                    f.get("credential_type"),
                    provider,
                    f.get("region"),
                    f["resource_uid"],
                    f["resource_type"],
                    f.get("db_engine"),
                    f.get("db_service"),
                    f.get("security_domain"),
                    f["severity"],
                    f["status"],
                    f.get("rule_id"),
                    json.dumps(f.get("finding_data", {}), default=str),
                    now,
                    now,
                ))
                count += 1

        conn.commit()
        logger.info(f"Saved {count} database security findings to DB for scan {scan_run_id}")
        return count
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def save_db_inventory(
    scan_run_id: str,
    tenant_id: str,
    inventory: List[Dict[str, Any]],
) -> int:
    """Save database inventory entries.

    Args:
        scan_run_id: Pipeline scan run identifier.
        tenant_id: Tenant identifier.
        inventory: List of database inventory dicts.

    Returns:
        Number of inventory entries written.
    """
    conn = _get_dbsec_conn()
    count = 0
    try:
        with conn.cursor() as cur:
            # Clear previous inventory for this scan
            cur.execute(
                "DELETE FROM dbsec_inventory WHERE scan_run_id = %s AND tenant_id = %s",
                (scan_run_id, tenant_id),
            )
            for db in inventory:
                cur.execute("""
                    INSERT INTO dbsec_inventory (
                        scan_run_id, tenant_id, account_id, provider, region,
                        resource_uid, resource_type, db_identifier,
                        db_engine, db_engine_version, db_service,
                        instance_class, storage_type, storage_encrypted,
                        kms_key_id, multi_az, publicly_accessible,
                        backup_retention_days, auto_minor_upgrade,
                        deletion_protection, iam_auth_enabled,
                        ssl_enforced, tls_version,
                        vpc_id, subnet_group, security_groups,
                        data_classification, sensitivity_score,
                        tags, raw_data
                    )
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s,%s::jsonb,%s::jsonb)
                """, (
                    scan_run_id, tenant_id,
                    db.get("account_id"), db.get("provider", "aws"), db.get("region"),
                    db["resource_uid"], db.get("resource_type"), db.get("db_identifier"),
                    db.get("db_engine"), db.get("db_engine_version"), db.get("db_service"),
                    db.get("instance_class"), db.get("storage_type"),
                    db.get("storage_encrypted", False),
                    db.get("kms_key_id"), db.get("multi_az", False),
                    db.get("publicly_accessible", False),
                    db.get("backup_retention_days"),
                    db.get("auto_minor_upgrade", False),
                    db.get("deletion_protection", False),
                    db.get("iam_auth_enabled", False),
                    db.get("ssl_enforced", False), db.get("tls_version"),
                    db.get("vpc_id"), db.get("subnet_group"),
                    json.dumps(db.get("security_groups", []), default=str),
                    db.get("data_classification"), db.get("sensitivity_score"),
                    json.dumps(db.get("tags", {}), default=str),
                    json.dumps(db.get("raw_data", {}), default=str),
                ))
                count += 1
        conn.commit()
        logger.info(f"Saved {count} database inventory entries for scan {scan_run_id}")
        return count
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
