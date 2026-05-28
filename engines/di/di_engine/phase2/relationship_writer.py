"""
Phase 2 — Relationship Writer

Derives asset_relationships from emitted_fields after Phase 0/1 writes.
Column names are identical to inventory_relationships for zero downstream changes.

Relationship types written:

Topology edges (hardcoded):
  PLACED_IN           — resource → VPC / subnet
  BELONGS_TO          — resource → account / subscription / project
  PROTECTED_BY        — EC2/RDS/Lambda → security group
  ATTACHED_TO         — network interface → instance, volume → instance, etc.
  INTERNET_ACCESSIBLE — resource → pseudo:internet:global sentinel
  ROUTES_VIA          — subnet → route table / internet gateway

Security edges (from di_relationship_rules — 1,747 multi-CSP rules):
  assumes, has_role, uses   — resource → IAM role / service account
  routes_to                 — API GW / LB → backend target
  member_of                 — EKS nodegroup → cluster
  encrypted_by              — resource → KMS key
  subscribes_to             — Lambda → Kinesis / SQS event source
  ... and more
"""
from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple

import psycopg2
import psycopg2.extras

logger = logging.getLogger("di.phase2.relationship_writer")

# Sentinel UID for the internet
INTERNET_UID = "pseudo:internet:global"

_BATCH_SIZE = 500

# Process-level cache for rules — loaded once, reused across batches
_RULES_CACHE: Optional[Dict[str, List[Dict[str, Any]]]] = None

# API Gateway resource types that are always internet-facing
_API_GW_RESOURCE_TYPES = frozenset({
    "apigateway.rest_api",
    "apigateway.rest-api",
    "apigateway.httpapi",
    "apigateway.v2api",
    "apigatewayv2.api",
})


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


def _load_security_relationship_rules() -> Dict[str, List[Dict[str, Any]]]:
    """Load active security relationship rules grouped by 'csp:from_resource_type'.

    Excludes __topology__ source_field rules — those require JOIN-based logic.
    Results are cached for the process lifetime.
    """
    global _RULES_CACHE
    if _RULES_CACHE is not None:
        return _RULES_CACHE

    rules: Dict[str, List[Dict[str, Any]]] = {}
    conn = _get_di_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT csp, from_resource_type, to_resource_type, relation_type,
                       source_field, source_field_item, target_uid_pattern, attack_path_category
                FROM di_relationship_rules
                WHERE is_active = true
                  AND source_field IS NOT NULL
                  AND source_field != '__topology__'
                ORDER BY csp, from_resource_type
                """
            )
            for row in cur.fetchall():
                csp, from_type, to_type, rel_type, src_field, src_field_item, pattern, category = row
                key = f"{csp}:{from_type}"
                rules.setdefault(key, []).append({
                    "to_type": to_type or "",
                    "relation_type": rel_type,
                    "source_field": src_field,
                    "source_field_item": src_field_item,
                    "target_uid_pattern": pattern or "{value}",
                    "attack_path_category": category,
                })
        # Add underscore-format aliases so rules match asset_inventory resource_type values.
        # asset_inventory uses _derive_resource_type() which outputs "lambda_function",
        # "ec2_instance" etc. (underscore), while di_relationship_rules uses "lambda.function",
        # "ec2.instance" (dot notation). Build both-direction lookup.
        alias_keys: Dict[str, List[Dict[str, Any]]] = {}
        for key, rule_list in rules.items():
            csp_part, _, type_part = key.partition(":")
            # "aws:lambda.function" → "aws:lambda_function"
            # "aws:ec2.security-group" → "aws:ec2_security_group" (dot→_ AND hyphen→_)
            normalized = f"{csp_part}:{type_part.replace('.', '_').replace('-', '_')}"
            if normalized != key and normalized not in rules:
                alias_keys[normalized] = rule_list
        rules.update(alias_keys)
        total = sum(len(v) for v in rules.values())
        logger.info("Loaded %d security relationship rules across %d resource types (incl. aliases)", total, len(rules))
        _RULES_CACHE = rules
    except Exception as exc:
        logger.warning("Could not load di_relationship_rules — security edges will be skipped: %s", exc)
        _RULES_CACHE = {}
    finally:
        conn.close()
    return _RULES_CACHE


def _get_emitted_value(emitted: Dict[str, Any], field_path: str) -> Any:
    """Extract a value using dot-notation path from emitted_fields.

    Falls back to the nested emitted_fields.emitted_fields dict (Lambda nesting pattern).
    """
    def _dig(data: Any, parts: List[str]) -> Any:
        val: Any = data
        for part in parts:
            if not isinstance(val, dict):
                return None
            val = val.get(part)
        return val

    parts = field_path.split(".")
    val = _dig(emitted, parts)
    if val is not None:
        return val
    # Lambda and some resources double-nest data under emitted_fields.emitted_fields
    inner = emitted.get("emitted_fields")
    if isinstance(inner, dict):
        val = _dig(inner, parts)
    return val


def _substitute_pattern(
    pattern: str,
    scalar_value: str,
    item_dict: Optional[Dict[str, Any]],
    emitted: Dict[str, Any],
    region: str,
    account_id: str,
) -> Optional[str]:
    """Substitute placeholders in a target_uid_pattern to produce a target UID.

    Placeholders:
      {value}       — the extracted scalar value
      {item}        — alias for {value} (for list iteration)
      {region}      — row region
      {account_id}  — row account_id
      {FieldName}   — extract FieldName from item_dict, then from emitted
    """
    result = pattern
    result = result.replace("{value}", scalar_value)
    result = result.replace("{item}", scalar_value)
    result = result.replace("{region}", region or "")
    result = result.replace("{account_id}", account_id or "")

    remaining = re.findall(r"\{([^}]+)\}", result)
    for token in remaining:
        token_val: Any = None
        # Try item_dict first (for list rules where each item is a dict)
        if item_dict and isinstance(item_dict, dict):
            token_val = item_dict.get(token)
        # Fall back to emitted fields
        if token_val is None:
            token_val = _get_emitted_value(emitted, token)
        if token_val is None:
            return None  # Required substitution missing — skip this edge
        result = result.replace(f"{{{token}}}", str(token_val))

    return result or None


def _apply_security_relationship_rules(
    uid: str,
    provider: str,
    resource_type: str,
    account_id: str,
    region: str,
    emitted: Dict[str, Any],
    scan_run_id: str,
    tenant_id: str,
    rules_cache: Dict[str, List[Dict[str, Any]]],
) -> List[Dict[str, Any]]:
    """Apply di_relationship_rules to extract security edges for one asset.

    Returns a list of relationship dicts ready for _write_relationships().
    """
    matching_rules = rules_cache.get(f"{provider}:{resource_type}", [])
    if not matching_rules:
        return []

    rels: List[Dict[str, Any]] = []

    def make_rel(
        target_uid: str,
        rel_type: str,
        to_type: str,
        category: Optional[str],
    ) -> Dict[str, Any]:
        return {
            "scan_run_id": scan_run_id,
            "tenant_id": tenant_id,
            "account_id": account_id,
            "provider": provider,
            "source_uid": uid,
            "source_type": resource_type,
            "target_uid": target_uid,
            "target_type": to_type,
            "relation_type": rel_type,
            "relation_metadata": {"attack_path_category": category} if category else {},
        }

    for rule in matching_rules:
        src_field: str = rule["source_field"]
        pattern: str = rule["target_uid_pattern"]
        to_type: str = rule["to_type"]
        rel_type: str = rule["relation_type"]
        category: Optional[str] = rule["attack_path_category"]
        field_item_key: Optional[str] = rule.get("source_field_item")

        raw_value = _get_emitted_value(emitted, src_field)
        if raw_value is None:
            continue

        # Build (scalar_value, item_dict) pairs for pattern substitution
        candidates: List[Tuple[str, Optional[Dict[str, Any]]]] = []

        if isinstance(raw_value, list):
            for item in raw_value:
                if isinstance(item, dict):
                    scalar: Optional[str] = None
                    if field_item_key:
                        scalar = str(item[field_item_key]) if field_item_key in item else None
                    if scalar is None:
                        # Infer scalar from common key names
                        for key_try in (
                            "Arn", "arn", "Id", "id", "Name", "name",
                            "GroupId", "EventSourceArn", "NetworkInterfaceId", "VolumeId",
                        ):
                            if key_try in item:
                                scalar = str(item[key_try])
                                break
                    if scalar:
                        candidates.append((scalar, item))
                    elif "{value}" not in pattern and "{item}" not in pattern:
                        # Pattern uses named {Token} substitutions (e.g. {RoleArn}) —
                        # no scalar needed; pass empty string and let _substitute_pattern
                        # resolve each {Token} from the item dict.
                        candidates.append(("", item))
                elif isinstance(item, str) and item:
                    candidates.append((item, None))
        elif isinstance(raw_value, (str, int, float, bool)):
            scalar_str = str(raw_value)
            if scalar_str:
                candidates.append((scalar_str, None))

        for scalar_val, item_dict in candidates:
            target_uid = _substitute_pattern(
                pattern, scalar_val, item_dict, emitted, region, account_id
            )
            if not target_uid:
                continue

            # Instance-profile ARN → role ARN when the target is typed as iam.role
            if to_type == "iam.role" and ":instance-profile/" in target_uid:
                target_uid = target_uid.replace(":instance-profile/", ":role/")

            rels.append(make_rel(target_uid, rel_type, to_type, category))

    return rels


def derive_and_write_relationships(
    rows: List[Dict[str, Any]],
    scan_run_id: str,
    tenant_id: str,
) -> int:
    """Derive relationships from emitted_fields and write to asset_relationships.

    Combines topology edges (hardcoded) and security edges (from di_relationship_rules).

    Returns:
        Number of relationship rows written.
    """
    rules_cache = _load_security_relationship_rules()
    relationships: List[Dict[str, Any]] = []

    for row in rows:
        uid = row["resource_uid"]
        provider = row["provider"]
        resource_type = row.get("resource_type", "")
        account_id = row["account_id"]
        region = row.get("region", "global")
        emitted = row.get("emitted_fields") or {}

        # Topology edges (network containment, account membership, SGs, internet exposure)
        relationships.extend(
            _derive_relationships(
                uid=uid,
                provider=provider,
                resource_type=resource_type,
                account_id=account_id,
                region=region,
                emitted=emitted,
                scan_run_id=scan_run_id,
                tenant_id=tenant_id,
            )
        )

        # Security edges from di_relationship_rules (IAM roles, routes_to, etc.)
        if resource_type and rules_cache:
            relationships.extend(
                _apply_security_relationship_rules(
                    uid=uid,
                    provider=provider,
                    resource_type=resource_type,
                    account_id=account_id,
                    region=region,
                    emitted=emitted,
                    scan_run_id=scan_run_id,
                    tenant_id=tenant_id,
                    rules_cache=rules_cache,
                )
            )

    if not relationships:
        return 0

    return _write_relationships(relationships)


def _derive_relationships(
    uid: str,
    provider: str,
    resource_type: str,
    account_id: str,
    region: str,
    emitted: Dict[str, Any],
    scan_run_id: str,
    tenant_id: str,
) -> List[Dict[str, Any]]:
    """Extract topology relationships from emitted_fields for one resource."""
    rels: List[Dict[str, Any]] = []

    def rel(target_uid: str, relation_type: str, meta: Optional[Dict] = None) -> Dict[str, Any]:
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
        rels.append(rel(
            f"arn:aws:ec2:{region}:{account_id}:vpc/{vpc_id}",
            "PLACED_IN",
            {"vpc_id": vpc_id},
        ))

    subnet_id = emitted.get("SubnetId") or emitted.get("subnet_id")
    if subnet_id and provider == "aws":
        rels.append(rel(
            f"arn:aws:ec2:{region}:{account_id}:subnet/{subnet_id}",
            "PLACED_IN",
            {"subnet_id": subnet_id},
        ))

    # ── PROTECTED_BY: security groups ────────────────────────────────────────
    for sg_id in _extract_sg_ids(emitted):
        sg_uid = (
            f"arn:aws:ec2:{region}:{account_id}:security-group/{sg_id}"
            if provider == "aws"
            else f"{provider}:{account_id}:security-group:{sg_id}"
        )
        rels.append(rel(sg_uid, "PROTECTED_BY", {"sg_id": sg_id}))

    # ── INTERNET_ACCESSIBLE ───────────────────────────────────────────────────
    if _is_internet_facing(emitted, provider, resource_type):
        rels.append(rel(INTERNET_UID, "INTERNET_ACCESSIBLE", {
            "detected_via": _internet_exposure_reason(emitted, resource_type),
        }))

    # ── ATTACHED_TO: volume → instance, ENI → instance ────────────────────────
    attachments = emitted.get("Attachments")
    first_attach = next(iter(attachments), {}) if isinstance(attachments, list) else {}
    instance_id = emitted.get("InstanceId") or first_attach.get("InstanceId")
    if instance_id and provider == "aws":
        rels.append(rel(
            f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}",
            "ATTACHED_TO",
            {"instance_id": instance_id},
        ))

    # ── ROUTES_VIA: subnet → internet gateway ────────────────────────────────
    igw_id = emitted.get("InternetGatewayId")
    if igw_id and provider == "aws":
        rels.append(rel(
            f"arn:aws:ec2:{region}:{account_id}:internet-gateway/{igw_id}",
            "ROUTES_VIA",
            {"igw_id": igw_id},
        ))

    return rels


def _extract_sg_ids(emitted: Dict[str, Any]) -> List[str]:
    """Extract security group IDs from various emitted_fields formats."""
    sg_ids = []

    sgs = emitted.get("SecurityGroups") or emitted.get("SecurityGroupIds") or []
    if isinstance(sgs, list):
        for sg in sgs:
            if isinstance(sg, dict):
                gid = sg.get("GroupId") or sg.get("SecurityGroupId")
                if gid:
                    sg_ids.append(gid)
            elif isinstance(sg, str) and sg.startswith("sg-"):
                sg_ids.append(sg)

    direct = emitted.get("SecurityGroupId")
    if direct and isinstance(direct, str):
        sg_ids.append(direct)

    return list(set(sg_ids))


def _normalize_resource_type(resource_type: str) -> str:
    """Normalize underscore/hyphen format to dot notation for canonical comparisons.

    asset_inventory stores "apigateway_rest_api" (from _derive_resource_type), while
    canonical names use "apigateway.rest_api". Normalize once at check boundaries.
    """
    return resource_type.replace("_", ".", 1).replace("-", "_")


def _is_internet_facing(emitted: Dict[str, Any], provider: str, resource_type: str = "") -> bool:
    """Detect internet-facing resources from emitted_fields."""
    # API Gateway is always internet-facing by definition
    canonical = _normalize_resource_type(resource_type)
    if resource_type in _API_GW_RESOURCE_TYPES or canonical in _API_GW_RESOURCE_TYPES:
        return True

    # AWS: explicit public IP / PubliclyAccessible flag
    if emitted.get("PublicIpAddress"):
        return True
    if emitted.get("PubliclyAccessible") is True:
        return True
    if str(emitted.get("PubliclyAccessible", "")).lower() == "true":
        return True
    if emitted.get("Scheme") == "internet-facing":
        return True

    # Lambda with a public Function URL
    func_url = emitted.get("FunctionUrl")
    if func_url is None:
        inner = emitted.get("emitted_fields") or {}
        func_url = inner.get("FunctionUrl") if isinstance(inner, dict) else None
    if func_url:
        return True

    # AWS: S3 public ACL
    if emitted.get("PublicAccessBlockConfiguration", {}).get("BlockPublicAcls") is False:
        return True

    # GCP: external IP via access config
    if provider == "gcp":
        for iface in emitted.get("networkInterfaces", []):
            if iface.get("accessConfigs"):
                return True

    # Azure: public IP reference
    if provider == "azure" and emitted.get("publicIPAddress"):
        return True

    return False


def _internet_exposure_reason(
    emitted: Dict[str, Any], resource_type: str = ""
) -> str:
    canonical = _normalize_resource_type(resource_type)
    if resource_type in _API_GW_RESOURCE_TYPES or canonical in _API_GW_RESOURCE_TYPES:
        return "api_gateway_always_public"
    if emitted.get("PublicIpAddress"):
        return "PublicIpAddress"
    if emitted.get("PubliclyAccessible"):
        return "PubliclyAccessible"
    if emitted.get("Scheme") == "internet-facing":
        return "Scheme=internet-facing"
    func_url = emitted.get("FunctionUrl") or (emitted.get("emitted_fields") or {}).get("FunctionUrl")
    if func_url:
        return "FunctionUrl"
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
