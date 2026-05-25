"""
Phase 2 — Relationship Writer

Derives asset_relationships from emitted_fields after Phase 0/1 writes.
Column names are identical to inventory_relationships for zero downstream changes.

Relationship types:
  PLACED_IN           — resource → region/VPC (network containment)
  BELONGS_TO          — resource → account/subscription/project
  PROTECTED_BY        — EC2/RDS/Lambda → security group
  ATTACHED_TO         — network interface → instance, volume → instance, etc.
  INTERNET_ACCESSIBLE — resource → pseudo:internet:global sentinel
  ROUTES_VIA          — subnet → route table / internet gateway
  SPANS               — cross-region/cross-account resource
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List

import psycopg2
import psycopg2.extras

logger = logging.getLogger("di.phase2.relationship_writer")

# Sentinel UID for the internet
INTERNET_UID = "pseudo:internet:global"

_BATCH_SIZE = 500


def _get_di_conn() -> psycopg2.extensions.connection:
    return psycopg2.connect(
        host=os.getenv("DI_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("DI_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("DI_DB_NAME", "threat_engine_di"),
        user=os.getenv("DI_DB_USER", os.getenv("DB_USER", "postgres")),
        password=(
            os.getenv("DI_DB_PASSWORD")
            or os.getenv("DB_PASSWORD")
            or os.getenv("DISCOVERIES_DB_PASSWORD", "")
        ),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
        connect_timeout=10,
    )


def derive_and_write_relationships(
    rows: List[Dict[str, Any]],
    scan_run_id: str,
    tenant_id: str,
) -> int:
    """Derive relationships from emitted_fields and write to asset_relationships.

    Returns:
        Number of relationship rows written.
    """
    relationships: List[Dict[str, Any]] = []

    for row in rows:
        uid = row["resource_uid"]
        provider = row["provider"]
        account_id = row["account_id"]
        region = row.get("region", "global")
        emitted = row.get("emitted_fields") or {}

        new_rels = _derive_relationships(
            uid=uid,
            provider=provider,
            account_id=account_id,
            region=region,
            emitted=emitted,
            scan_run_id=scan_run_id,
            tenant_id=tenant_id,
        )
        relationships.extend(new_rels)

    if not relationships:
        return 0

    return _write_relationships(relationships)


def _derive_relationships(
    uid: str,
    provider: str,
    account_id: str,
    region: str,
    emitted: Dict[str, Any],
    scan_run_id: str,
    tenant_id: str,
) -> List[Dict[str, Any]]:
    """Extract relationships from emitted_fields for one resource."""
    rels: List[Dict[str, Any]] = []

    def rel(target_uid: str, relation_type: str, meta: Dict = None) -> Dict:
        return {
            "scan_run_id": scan_run_id,
            "tenant_id": tenant_id,
            "account_id": account_id,
            "provider": provider,
            "source_uid": uid,
            "source_type": None,
            "target_uid": target_uid,
            "target_type": None,
            "relation_type": relation_type,
            "relation_metadata": meta or {},
        }

    # ── BELONGS_TO: all resources belong to their account ────────────────────
    if account_id:
        rels.append(rel(f"account:{provider}:{account_id}", "BELONGS_TO"))

    # ── PLACED_IN: resource in a VPC ─────────────────────────────────────────
    vpc_id = emitted.get("VpcId") or emitted.get("vpc_id")
    if vpc_id and provider == "aws":
        vpc_uid = f"arn:aws:ec2:{region}:{account_id}:vpc/{vpc_id}"
        rels.append(rel(vpc_uid, "PLACED_IN", {"vpc_id": vpc_id}))

    subnet_id = emitted.get("SubnetId") or emitted.get("subnet_id")
    if subnet_id and provider == "aws":
        subnet_uid = f"arn:aws:ec2:{region}:{account_id}:subnet/{subnet_id}"
        rels.append(rel(subnet_uid, "PLACED_IN", {"subnet_id": subnet_id}))

    # ── PROTECTED_BY: security groups ────────────────────────────────────────
    sg_ids = _extract_sg_ids(emitted)
    for sg_id in sg_ids:
        if provider == "aws":
            sg_uid = f"arn:aws:ec2:{region}:{account_id}:security-group/{sg_id}"
        else:
            sg_uid = f"{provider}:{account_id}:security-group:{sg_id}"
        rels.append(rel(sg_uid, "PROTECTED_BY", {"sg_id": sg_id}))

    # ── INTERNET_ACCESSIBLE ───────────────────────────────────────────────────
    if _is_internet_facing(emitted, provider):
        rels.append(rel(INTERNET_UID, "INTERNET_ACCESSIBLE", {
            "detected_via": _internet_exposure_reason(emitted, provider)
        }))

    # ── ATTACHED_TO: volume → instance, ENI → instance ────────────────────────
    attachments = emitted.get("Attachments")
    first_attach = next(iter(attachments), {}) if isinstance(attachments, list) else {}
    instance_id = emitted.get("InstanceId") or first_attach.get("InstanceId")
    if instance_id and provider == "aws":
        inst_uid = f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}"
        rels.append(rel(inst_uid, "ATTACHED_TO", {"instance_id": instance_id}))

    # ── ROUTES_VIA: subnet → route table / IGW ───────────────────────────────
    igw_id = emitted.get("InternetGatewayId")
    if igw_id and provider == "aws":
        igw_uid = f"arn:aws:ec2:{region}:{account_id}:internet-gateway/{igw_id}"
        rels.append(rel(igw_uid, "ROUTES_VIA", {"igw_id": igw_id}))

    return rels


def _extract_sg_ids(emitted: Dict[str, Any]) -> List[str]:
    """Extract security group IDs from various emitted_fields formats."""
    sg_ids = []

    # Direct list: [{"GroupId": "sg-xxx"}, ...]
    sgs = emitted.get("SecurityGroups") or emitted.get("SecurityGroupIds") or []
    if isinstance(sgs, list):
        for sg in sgs:
            if isinstance(sg, dict):
                gid = sg.get("GroupId") or sg.get("SecurityGroupId")
                if gid:
                    sg_ids.append(gid)
            elif isinstance(sg, str) and sg.startswith("sg-"):
                sg_ids.append(sg)

    # Direct string
    direct = emitted.get("SecurityGroupId")
    if direct and isinstance(direct, str):
        sg_ids.append(direct)

    return list(set(sg_ids))


def _is_internet_facing(emitted: Dict[str, Any], provider: str) -> bool:
    """Detect internet-facing resources from emitted_fields."""
    # AWS: explicit public IP / PubliclyAccessible flag
    if emitted.get("PublicIpAddress"):
        return True
    if emitted.get("PubliclyAccessible") is True:
        return True
    if str(emitted.get("PubliclyAccessible", "")).lower() == "true":
        return True
    if emitted.get("Scheme") == "internet-facing":
        return True

    # AWS: S3 public ACL
    if emitted.get("PublicAccessBlockConfiguration", {}).get("BlockPublicAcls") is False:
        return True

    # GCP: external IP
    if provider == "gcp":
        for iface in emitted.get("networkInterfaces", []):
            if iface.get("accessConfigs"):
                return True

    # Azure: public IP reference
    if provider == "azure" and emitted.get("publicIPAddress"):
        return True

    return False


def _internet_exposure_reason(emitted: Dict[str, Any], provider: str) -> str:
    if emitted.get("PublicIpAddress"):
        return "PublicIpAddress"
    if emitted.get("PubliclyAccessible"):
        return "PubliclyAccessible"
    if emitted.get("Scheme") == "internet-facing":
        return "Scheme=internet-facing"
    return "detected"


def _write_relationships(rels: List[Dict[str, Any]]) -> int:
    """Write relationship rows to asset_relationships in batches."""
    conn = _get_di_conn()
    written = 0
    try:
        for i in range(0, len(rels), _BATCH_SIZE):
            batch = rels[i: i + _BATCH_SIZE]
            with conn.cursor() as cur:
                psycopg2.extras.execute_values(
                    cur,
                    """
                    INSERT INTO asset_relationships (
                        scan_run_id, tenant_id, account_id, provider,
                        source_uid, source_type, target_uid, target_type,
                        relation_type, relation_metadata,
                        first_seen_at, last_seen_at
                    )
                    VALUES %s
                    ON CONFLICT DO NOTHING
                    """,
                    [
                        (
                            r["scan_run_id"],
                            r["tenant_id"],
                            r.get("account_id"),
                            r.get("provider"),
                            r["source_uid"],
                            r.get("source_type"),
                            r["target_uid"],
                            r.get("target_type"),
                            r["relation_type"],
                            json.dumps(r.get("relation_metadata") or {}),
                        )
                        for r in batch
                    ],
                    template=(
                        "(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, NOW(), NOW())"
                    ),
                )
            conn.commit()
            written += len(batch)

        logger.info("Wrote %d relationships to asset_relationships", written)
        return written
    finally:
        conn.close()
