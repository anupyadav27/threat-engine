"""
Container Security DB Writer.

Writes container_sec_report, container_sec_findings, and container_sec_inventory
tables to the threat_engine_container_security database.
"""

import os
import json
import hashlib
import logging
from typing import Dict, Any, List
from datetime import datetime, timezone

import psycopg2

logger = logging.getLogger(__name__)


def _get_csec_conn():
    """Get connection to the Container Security database."""
    return psycopg2.connect(
        host=os.getenv("CSEC_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("CSEC_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("CSEC_DB_NAME", "threat_engine_container_security"),
        user=os.getenv("CSEC_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("CSEC_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
    )


def generate_finding_id(rule_id: str, resource_uid: str, account_id: str, region: str) -> str:
    """Deterministic finding_id: cs_{sha256(rule_id|resource_uid|account|region)[:16]}."""
    raw = f"{rule_id}|{resource_uid}|{account_id}|{region}"
    return f"cs_{hashlib.sha256(raw.encode()).hexdigest()[:16]}"


def save_findings_to_db(
    scan_run_id: str,
    tenant_id: str,
    provider: str,
    findings: List[Dict[str, Any]],
    summary: Dict[str, Any],
) -> int:
    """Save container security findings and update report summary.

    Args:
        scan_run_id: Pipeline scan run identifier.
        tenant_id: Tenant identifier.
        provider: Cloud provider (aws, azure, gcp).
        findings: List of container security finding dicts.
        summary: Report summary dict with scores and breakdowns.

    Returns:
        Number of findings written.
    """
    conn = _get_csec_conn()
    now = datetime.now(timezone.utc)
    count = 0

    # Count distinct resources running with elevated privileges.
    # Privileged findings are written with security_domain='workload_security' and
    # rule_id containing 'privileged', or risk_type='privileged_containers' in finding_data.
    _PRIVILEGED_TERMS = ("privileged", "host_network", "hostnetwork", "host_pid", "host_ipc")
    privileged_resource_uids = {
        f["resource_uid"]
        for f in findings
        if f.get("status") == "FAIL"
        and f.get("security_domain") == "workload_security"
        and (
            any(term in (f.get("rule_id") or "").lower() for term in _PRIVILEGED_TERMS)
            or (f.get("finding_data") or {}).get("risk_type") == "privileged_containers"
        )
    }
    privileged_container_count = len(privileged_resource_uids)

    try:
        with conn.cursor() as cur:
            # Ensure tenant exists
            cur.execute(
                "INSERT INTO tenants (tenant_id, tenant_name) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                (tenant_id, tenant_id),
            )

            # Update report with summary
            cur.execute("""
                UPDATE container_sec_report SET
                    status = 'completed',
                    posture_score = %s,
                    total_containers = %s,
                    total_findings = %s,
                    critical_findings = %s,
                    high_findings = %s,
                    medium_findings = %s,
                    low_findings = %s,
                    cluster_security_score = %s,
                    workload_security_score = %s,
                    image_security_score = %s,
                    network_exposure_score = %s,
                    privileged_container_count = %s,
                    severity_breakdown = %s::jsonb,
                    service_breakdown = %s::jsonb,
                    domain_breakdown = %s::jsonb,
                    report_data = %s::jsonb,
                    completed_at = %s
                WHERE scan_run_id = %s
            """, (
                summary.get("posture_score", 0),
                summary.get("total_containers", 0),
                summary.get("total_findings", 0),
                summary.get("critical_findings", 0),
                summary.get("high_findings", 0),
                summary.get("medium_findings", 0),
                summary.get("low_findings", 0),
                summary.get("cluster_security_score", 0),
                summary.get("workload_security_score", 0),
                summary.get("image_security_score", 0),
                summary.get("network_exposure_score", 0),
                privileged_container_count,
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
                    INSERT INTO container_sec_findings (
                        finding_id, scan_run_id, tenant_id, account_id,
                        credential_ref, credential_type, provider, region,
                        resource_uid, resource_type,
                        container_service, security_domain,
                        severity, status, rule_id, finding_data,
                        first_seen_at, last_seen_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s::jsonb, %s, %s)
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
                    f.get("container_service"),
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
        logger.info(f"Saved {count} container security findings to DB for scan {scan_run_id}")
        return count
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def save_container_inventory(
    scan_run_id: str,
    tenant_id: str,
    inventory: List[Dict[str, Any]],
) -> int:
    """Save container inventory entries.

    Args:
        scan_run_id: Pipeline scan run identifier.
        tenant_id: Tenant identifier.
        inventory: List of container inventory dicts.

    Returns:
        Number of inventory entries written.
    """
    conn = _get_csec_conn()
    count = 0
    try:
        with conn.cursor() as cur:
            # Clear previous inventory for this scan
            cur.execute(
                "DELETE FROM container_sec_inventory WHERE scan_run_id = %s AND tenant_id = %s",
                (scan_run_id, tenant_id),
            )
            for c in inventory:
                cur.execute("""
                    INSERT INTO container_sec_inventory (
                        scan_run_id, tenant_id, account_id, provider, region,
                        resource_uid, resource_type, resource_name,
                        container_service, k8s_version, platform_version,
                        endpoint_public, encryption_enabled,
                        logging_enabled, network_policy_enabled,
                        vpc_id, security_groups,
                        check_pass_count, check_fail_count,
                        tags, raw_data
                    )
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s,%s::jsonb,%s::jsonb)
                """, (
                    scan_run_id, tenant_id,
                    c.get("account_id"), c.get("provider", "aws"), c.get("region"),
                    c["resource_uid"], c.get("resource_type"), c.get("resource_name"),
                    c.get("container_service"), c.get("k8s_version"), c.get("platform_version"),
                    c.get("endpoint_public", False),
                    c.get("encryption_enabled", False),
                    c.get("logging_enabled", False),
                    c.get("network_policy_enabled", False),
                    c.get("vpc_id"),
                    json.dumps(c.get("security_groups", []), default=str),
                    c.get("check_pass_count", 0),
                    c.get("check_fail_count", 0),
                    json.dumps(c.get("tags", {}), default=str),
                    json.dumps(c.get("raw_data", {}), default=str),
                ))
                count += 1
        conn.commit()
        logger.info(f"Saved {count} container inventory entries for scan {scan_run_id}")
        return count
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
