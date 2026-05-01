"""DBSec findings persistence layer."""

import json
import logging
from typing import Any, Dict, List

import psycopg2

logger = logging.getLogger(__name__)


def save_findings_to_db(findings: List[Dict[str, Any]], conn: psycopg2.extensions.connection) -> int:
    """Upsert DBSec findings to dbsec_findings table.

    Uses ON CONFLICT (finding_id) DO UPDATE to handle re-runs of the same
    scan_run_id. ``blast_radius_score`` is always 0 — risk engine owns
    non-zero values.

    Args:
        findings: List of finding dicts from provider.analyze().
        conn: psycopg2 connection to threat_engine_database_security.

    Returns:
        Number of findings processed (not necessarily inserted — some may
        be updates).
    """
    if not findings:
        return 0

    inserted = 0
    with conn.cursor() as cur:
        # Upsert tenant first (FK constraint)
        tenant_ids = {f["tenant_id"] for f in findings}
        for tid in tenant_ids:
            cur.execute(
                "INSERT INTO tenants (tenant_id) VALUES (%s) ON CONFLICT (tenant_id) DO NOTHING",
                (tid,),
            )

        for f in findings:
            pillar_detail = f.get("pillar_detail", {})
            # Ensure pillar_detail is a dict (never json.loads needed — psycopg2 handles JSONB)
            if not isinstance(pillar_detail, dict):
                pillar_detail = {}

            cur.execute(
                """
                INSERT INTO dbsec_findings (
                    finding_id, scan_run_id, tenant_id, account_id,
                    credential_ref, credential_type,
                    provider, region, resource_uid, resource_type,
                    severity, status, pillar, pillar_detail,
                    blast_radius_score, first_seen_at, last_seen_at,
                    rule_id, title, description, remediation, finding_data,
                    db_engine, db_service, security_domain
                ) VALUES (
                    %(finding_id)s, %(scan_run_id)s, %(tenant_id)s, %(account_id)s,
                    %(credential_ref)s, %(credential_type)s,
                    %(provider)s, %(region)s, %(resource_uid)s, %(resource_type)s,
                    %(severity)s, %(status)s, %(pillar)s, %(pillar_detail)s::jsonb,
                    0, NOW(), NOW(),
                    %(rule_id)s, %(title)s, %(description)s, %(remediation)s,
                    %(finding_data)s::jsonb,
                    %(db_engine)s, %(db_service)s, %(security_domain)s
                )
                ON CONFLICT (finding_id)
                DO UPDATE SET
                    last_seen_at = NOW(),
                    status = EXCLUDED.status,
                    pillar_detail = EXCLUDED.pillar_detail,
                    scan_run_id = EXCLUDED.scan_run_id
                """,
                {
                    "finding_id": f["finding_id"],
                    "scan_run_id": f["scan_run_id"],
                    "tenant_id": f["tenant_id"],
                    "account_id": f.get("account_id", ""),
                    "credential_ref": f.get("credential_ref", ""),
                    "credential_type": f.get("credential_type", ""),
                    "provider": f["provider"],
                    "region": f.get("region", ""),
                    "resource_uid": f["resource_uid"],
                    "resource_type": f["resource_type"],
                    "severity": f["severity"],
                    "status": f["status"],
                    "pillar": f.get("pillar", ""),
                    "pillar_detail": json.dumps(pillar_detail),
                    "rule_id": f.get("rule_id", ""),
                    "title": _pillar_title(f),
                    "description": _pillar_description(f),
                    "remediation": _pillar_remediation(f),
                    "finding_data": json.dumps(pillar_detail),
                    "db_engine": f.get("db_engine", ""),
                    "db_service": f.get("db_service", f.get("resource_type", "")),
                    "security_domain": f.get("pillar", ""),
                },
            )
            inserted += 1

    conn.commit()
    logger.info("DBSec writer: committed %d findings", inserted)
    return inserted


def _pillar_title(f: Dict[str, Any]) -> str:
    """Generate a human-readable title from the finding's pillar and check."""
    pillar = f.get("pillar", "")
    detail = f.get("pillar_detail", {}) or {}
    check = detail.get("check", "")
    rtype = f.get("resource_type", "")

    titles = {
        "network_exposure": f"Network Exposure: {rtype} — public access check",
        "encryption": f"Encryption: {rtype} — encryption at rest/transit",
        "authentication": f"Authentication: {rtype} — auth configuration",
        "audit_activity": f"Audit & Activity: {rtype} — logging configuration",
        "compliance_posture": f"Compliance: {rtype} — {check}",
    }
    return titles.get(pillar, f"{pillar}: {rtype}")


def _pillar_description(f: Dict[str, Any]) -> str:
    """Generate description from finding context."""
    pillar = f.get("pillar", "")
    status = f.get("status", "")
    detail = f.get("pillar_detail", {}) or {}
    check = detail.get("check", "")

    if status == "PASS":
        return f"{check} is compliant for {f.get('resource_uid', '')}"
    return (
        f"{check} failed for {f.get('resource_uid', '')}: "
        f"severity={f.get('severity', '')} pillar={pillar}"
    )


def _pillar_remediation(f: Dict[str, Any]) -> str:
    """Return remediation guidance per pillar."""
    pillar = f.get("pillar", "")
    provider = f.get("provider", "")

    remediation_map = {
        "network_exposure": (
            "Restrict database access to private subnets only. "
            "Disable public accessibility and enforce VPC-only access."
        ),
        "encryption": (
            "Enable encryption at rest using managed or customer-managed keys. "
            "Enable TLS 1.2+ for data in transit."
        ),
        "authentication": (
            "Enable IAM-based authentication. "
            "Rename default admin users. Enforce strong password policies."
        ),
        "audit_activity": (
            "Enable database audit logging and CloudWatch/monitoring integration. "
            "Configure performance insights and query logging."
        ),
        "compliance_posture": (
            "Enable automated backups with retention >= 7 days. "
            "Enable deletion protection and multi-AZ for production databases."
        ),
    }
    return remediation_map.get(pillar, f"Remediate {pillar} finding for {provider} database.")
