"""
Encryption DB Writer.

Writes encryption_report, encryption_findings, and inventory tables
to the threat_engine_encryption database.
"""

import os
import json
import hashlib
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

import psycopg2

logger = logging.getLogger(__name__)


def _get_encryption_conn():
    """Get connection to the Encryption database."""
    return psycopg2.connect(
        host=os.getenv("ENCRYPTION_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("ENCRYPTION_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("ENCRYPTION_DB_NAME", "threat_engine_encryption"),
        user=os.getenv("ENCRYPTION_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("ENCRYPTION_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
    )


def generate_finding_id(rule_id: str, resource_uid: str, account_id: str, region: str) -> str:
    """Deterministic finding_id: enc_{sha256(rule_id|resource_uid|account|region)[:16]}."""
    raw = f"{rule_id}|{resource_uid}|{account_id}|{region}"
    return f"enc_{hashlib.sha256(raw.encode()).hexdigest()[:16]}"


def save_findings_to_db(
    scan_run_id: str,
    tenant_id: str,
    provider: str,
    findings: List[Dict[str, Any]],
    summary: Dict[str, Any],
) -> int:
    """Save encryption findings and update report summary.

    Args:
        scan_run_id: Pipeline scan run identifier.
        tenant_id: Tenant identifier.
        provider: Cloud provider (aws, azure, gcp).
        findings: List of encryption finding dicts.
        summary: Report summary dict with scores and breakdowns.

    Returns:
        Number of findings written.
    """
    conn = _get_encryption_conn()
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
                UPDATE encryption_report SET
                    status = 'completed',
                    posture_score = %s,
                    coverage_score = %s,
                    rotation_score = %s,
                    algorithm_score = %s,
                    transit_score = %s,
                    total_resources = %s,
                    encrypted_resources = %s,
                    unencrypted_resources = %s,
                    total_keys = %s,
                    total_certificates = %s,
                    total_secrets = %s,
                    total_findings = %s,
                    critical_findings = %s,
                    high_findings = %s,
                    medium_findings = %s,
                    low_findings = %s,
                    coverage_by_service = %s::jsonb,
                    severity_breakdown = %s::jsonb,
                    domain_breakdown = %s::jsonb,
                    report_data = %s::jsonb,
                    completed_at = %s
                WHERE scan_run_id = %s
            """, (
                summary.get("posture_score", 0),
                summary.get("coverage_score", 0),
                summary.get("rotation_score", 0),
                summary.get("algorithm_score", 0),
                summary.get("transit_score", 0),
                summary.get("total_resources", 0),
                summary.get("encrypted_resources", 0),
                summary.get("unencrypted_resources", 0),
                summary.get("total_keys", 0),
                summary.get("total_certificates", 0),
                summary.get("total_secrets", 0),
                summary.get("total_findings", 0),
                summary.get("critical_findings", 0),
                summary.get("high_findings", 0),
                summary.get("medium_findings", 0),
                summary.get("low_findings", 0),
                json.dumps(summary.get("coverage_by_service", {})),
                json.dumps(summary.get("severity_breakdown", {})),
                json.dumps(summary.get("domain_breakdown", {})),
                json.dumps(summary, default=str),
                now,
                scan_run_id,
            ))

            # Insert findings
            for f in findings:
                cur.execute("""
                    INSERT INTO encryption_findings (
                        finding_id, scan_run_id, tenant_id, account_id,
                        credential_ref, credential_type, provider, region,
                        resource_uid, resource_type,
                        encryption_domain, encryption_status, key_type,
                        algorithm, rotation_compliant, transit_enforced,
                        severity, status, rule_id, finding_data,
                        first_seen_at, last_seen_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s)
                    ON CONFLICT (finding_id) DO UPDATE SET
                        last_seen_at = EXCLUDED.last_seen_at,
                        status = EXCLUDED.status,
                        severity = EXCLUDED.severity,
                        encryption_status = EXCLUDED.encryption_status,
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
                    f.get("encryption_domain"),
                    f.get("encryption_status"),
                    f.get("key_type"),
                    f.get("algorithm"),
                    f.get("rotation_compliant"),
                    f.get("transit_enforced"),
                    f["severity"],
                    f["status"],
                    f.get("rule_id"),
                    json.dumps(f.get("finding_data", {}), default=str),
                    now,
                    now,
                ))
                count += 1

        conn.commit()
        logger.info(f"Saved {count} encryption findings to DB for scan {scan_run_id}")
        return count
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def save_key_inventory(
    scan_run_id: str,
    tenant_id: str,
    keys: List[Dict[str, Any]],
) -> int:
    """Save KMS key inventory entries."""
    conn = _get_encryption_conn()
    count = 0
    try:
        with conn.cursor() as cur:
            # Clear previous inventory for this scan
            cur.execute(
                "DELETE FROM encryption_key_inventory WHERE scan_run_id = %s AND tenant_id = %s",
                (scan_run_id, tenant_id),
            )
            for k in keys:
                cur.execute("""
                    INSERT INTO encryption_key_inventory (
                        scan_run_id, tenant_id, account_id, provider, region,
                        key_arn, key_id, key_alias,
                        key_state, key_manager, key_spec, key_usage,
                        encryption_algorithms, origin, multi_region, enabled,
                        rotation_enabled, rotation_interval_days,
                        creation_date, deletion_date, pending_deletion_days,
                        key_policy_principals, grant_count, cross_account_access,
                        dependent_resource_count, tags, raw_data
                    )
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s,%s,%s::jsonb,%s::jsonb)
                """, (
                    scan_run_id, tenant_id,
                    k.get("account_id"), k.get("provider", "aws"), k.get("region"),
                    k["key_arn"], k.get("key_id"), k.get("key_alias"),
                    k.get("key_state"), k.get("key_manager"), k.get("key_spec"), k.get("key_usage"),
                    k.get("encryption_algorithms"), k.get("origin"),
                    k.get("multi_region", False), k.get("enabled", True),
                    k.get("rotation_enabled", False), k.get("rotation_interval_days"),
                    k.get("creation_date"), k.get("deletion_date"), k.get("pending_deletion_days"),
                    json.dumps(k.get("key_policy_principals", []), default=str),
                    k.get("grant_count", 0), k.get("cross_account_access", False),
                    k.get("dependent_resource_count", 0),
                    json.dumps(k.get("tags", {}), default=str),
                    json.dumps(k.get("raw_data", {}), default=str),
                ))
                count += 1
        conn.commit()
        logger.info(f"Saved {count} KMS keys to inventory for scan {scan_run_id}")
        return count
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def save_cert_inventory(
    scan_run_id: str,
    tenant_id: str,
    certs: List[Dict[str, Any]],
) -> int:
    """Save certificate inventory entries."""
    conn = _get_encryption_conn()
    count = 0
    try:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM encryption_cert_inventory WHERE scan_run_id = %s AND tenant_id = %s",
                (scan_run_id, tenant_id),
            )
            for c in certs:
                cur.execute("""
                    INSERT INTO encryption_cert_inventory (
                        scan_run_id, tenant_id, account_id, provider, region,
                        cert_arn, domain_name, subject_alternative_names,
                        cert_status, cert_type, key_algorithm, issuer, serial_number,
                        not_before, not_after, days_until_expiry,
                        renewal_eligibility, in_use,
                        is_wildcard, is_self_signed, chain_valid,
                        tags, raw_data
                    )
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb)
                """, (
                    scan_run_id, tenant_id,
                    c.get("account_id"), c.get("provider", "aws"), c.get("region"),
                    c["cert_arn"], c.get("domain_name"), c.get("subject_alternative_names"),
                    c.get("cert_status"), c.get("cert_type"), c.get("key_algorithm"),
                    c.get("issuer"), c.get("serial_number"),
                    c.get("not_before"), c.get("not_after"), c.get("days_until_expiry"),
                    c.get("renewal_eligibility"), c.get("in_use", False),
                    c.get("is_wildcard", False), c.get("is_self_signed", False), c.get("chain_valid"),
                    json.dumps(c.get("tags", {}), default=str),
                    json.dumps(c.get("raw_data", {}), default=str),
                ))
                count += 1
        conn.commit()
        logger.info(f"Saved {count} certificates to inventory for scan {scan_run_id}")
        return count
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def save_secrets_inventory(
    scan_run_id: str,
    tenant_id: str,
    secrets: List[Dict[str, Any]],
) -> int:
    """Save secrets inventory entries."""
    conn = _get_encryption_conn()
    count = 0
    try:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM encryption_secrets_inventory WHERE scan_run_id = %s AND tenant_id = %s",
                (scan_run_id, tenant_id),
            )
            for s in secrets:
                cur.execute("""
                    INSERT INTO encryption_secrets_inventory (
                        scan_run_id, tenant_id, account_id, provider, region,
                        secret_arn, secret_name,
                        kms_key_id, rotation_enabled, rotation_interval_days,
                        last_rotated_date, last_accessed_date, days_since_rotation,
                        tags, raw_data
                    )
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb)
                """, (
                    scan_run_id, tenant_id,
                    s.get("account_id"), s.get("provider", "aws"), s.get("region"),
                    s["secret_arn"], s.get("secret_name"),
                    s.get("kms_key_id"), s.get("rotation_enabled", False),
                    s.get("rotation_interval_days"),
                    s.get("last_rotated_date"), s.get("last_accessed_date"),
                    s.get("days_since_rotation"),
                    json.dumps(s.get("tags", {}), default=str),
                    json.dumps(s.get("raw_data", {}), default=str),
                ))
                count += 1
        conn.commit()
        logger.info(f"Saved {count} secrets to inventory for scan {scan_run_id}")
        return count
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
