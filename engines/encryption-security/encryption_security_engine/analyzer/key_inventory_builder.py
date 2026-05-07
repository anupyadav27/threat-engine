"""
KMS Key Inventory Builder.

Aggregates KMS key data from discovery_findings into structured
key inventory records for the encryption_key_inventory table.
"""

import json
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from dateutil import parser as dateparser

logger = logging.getLogger(__name__)


def build_key_inventory(
    kms_resources: List[Dict[str, Any]],
    kms_relationships: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Build KMS key inventory from discovery resources.

    Args:
        kms_resources: KMS discovery_findings rows from DiscoveryReader.
        kms_relationships: Optional inventory relationships for dependency counts.

    Returns:
        List of key inventory dicts ready for save_key_inventory().
    """
    # Build dependency count map from relationships
    dep_counts = {}
    if kms_relationships:
        for rel in kms_relationships:
            target = rel.get("target_uid", "")
            if target:
                dep_counts[target] = dep_counts.get(target, 0) + 1
            source = rel.get("source_uid", "")
            if source:
                dep_counts[source] = dep_counts.get(source, 0) + 1

    # Deduplicate by key_arn (multiple discovery_ids per key)
    key_map = {}

    for r in kms_resources:
        emitted = r.get("emitted_fields") or {}
        if not isinstance(emitted, dict):
            continue

        # AWS DescribeKey nests its detail fields under "KeyMetadata".
        # Earlier code looked at the top level only, so KeySpec/Origin/
        # CreationDate/KeyState landed as None for every row. Merge nested
        # KeyMetadata into a flat view before extraction.
        meta = emitted.get("KeyMetadata")
        if isinstance(meta, dict):
            merged = {**meta, **{k: v for k, v in emitted.items() if k != "KeyMetadata"}}
            emitted = merged

        key_arn = emitted.get("KeyArn") or emitted.get("Arn") or r.get("resource_uid", "")
        if not key_arn or key_arn in key_map:
            # Merge additional data into existing entry
            if key_arn and key_arn in key_map:
                _merge_emitted(key_map[key_arn], emitted)
            continue

        key_id = emitted.get("KeyId", "")

        # Parse creation date
        creation_date = _parse_date(emitted.get("CreationDate"))

        # Parse encryption algorithms
        algorithms = emitted.get("EncryptionAlgorithms")
        if isinstance(algorithms, list):
            algorithms = [str(a) for a in algorithms]
        else:
            algorithms = None

        # Detect alias from resource_type or separate alias discovery
        key_alias = emitted.get("AliasName") or emitted.get("AliasArn")

        # Key policy principals (from get_key_policy discovery)
        principals = _extract_policy_principals(emitted.get("Policy"))

        # Grants
        grants = emitted.get("Grants") or []
        grant_count = len(grants) if isinstance(grants, list) else 0

        # Cross-account access detection
        cross_account = _detect_cross_account(principals, r.get("account_id", ""))

        entry = {
            "key_arn": key_arn,
            "key_id": key_id,
            "key_alias": key_alias,
            "account_id": r.get("account_id", ""),
            "provider": r.get("provider", "aws"),
            "region": r.get("region", ""),
            "key_state": emitted.get("KeyState", "Unknown"),
            "key_manager": emitted.get("KeyManager", "AWS"),
            "key_spec": emitted.get("KeySpec"),
            "key_usage": emitted.get("KeyUsage"),
            "encryption_algorithms": algorithms,
            "origin": emitted.get("Origin"),
            "multi_region": emitted.get("MultiRegion", False),
            "enabled": emitted.get("Enabled", True),
            "rotation_enabled": emitted.get("KeyRotationEnabled", False),
            "rotation_interval_days": emitted.get("RotationPeriodInDays"),
            "creation_date": creation_date,
            "deletion_date": _parse_date(emitted.get("DeletionDate")),
            "pending_deletion_days": emitted.get("PendingDeletionWindowInDays"),
            "key_policy_principals": principals,
            "grant_count": grant_count,
            "cross_account_access": cross_account,
            "dependent_resource_count": dep_counts.get(key_arn, 0),
            "tags": emitted.get("Tags") or {},
            "raw_data": emitted,
        }
        key_map[key_arn] = entry

    keys = list(key_map.values())
    logger.info(f"Built inventory for {len(keys)} KMS keys")
    return keys


def _merge_emitted(entry: Dict, emitted: Dict):
    """Merge additional emitted fields into an existing key entry.

    Each KMS key produces multiple discovery_ids (list_keys, describe_key,
    get_key_policy, get_key_rotation_status, list_aliases, list_grants).
    The first one to populate the entry wins via the create path; later ones
    fall through here. Previously this only merged 3 fields, which silently
    dropped KeySpec/KeyUsage/KeyState/Origin/CreationDate when describe_key
    arrived AFTER list_keys (sparse parent). Fix: fill any field that the
    existing entry has as None/missing using the new emitted's value.
    """
    # AWS DescribeKey nests detail fields under KeyMetadata. Same flattening
    # logic as the create path at line 54.
    meta = emitted.get("KeyMetadata")
    if isinstance(meta, dict):
        emitted = {**meta, **{k: v for k, v in emitted.items() if k != "KeyMetadata"}}

    # Field mapping: emitted.<src> → entry.<target>. Only fill if entry's
    # current value is None/empty so the richer source (e.g. describe_key)
    # doesn't get clobbered by the sparser one (e.g. list_keys) on second
    # pass.
    field_map = (
        ("KeyId",                "key_id"),
        ("KeyState",             "key_state"),
        ("KeyManager",           "key_manager"),
        ("KeySpec",              "key_spec"),
        ("KeyUsage",             "key_usage"),
        ("Origin",               "origin"),
        ("MultiRegion",          "multi_region"),
        ("Enabled",              "enabled"),
        ("KeyRotationEnabled",   "rotation_enabled"),
        ("RotationPeriodInDays", "rotation_interval_days"),
        ("PendingDeletionWindowInDays", "pending_deletion_days"),
    )
    for src, tgt in field_map:
        val = emitted.get(src)
        if val is not None and entry.get(tgt) in (None, "", "Unknown"):
            entry[tgt] = val

    # Date fields — only fill if entry's is None
    if emitted.get("CreationDate") and not entry.get("creation_date"):
        entry["creation_date"] = _parse_date(emitted["CreationDate"])
    if emitted.get("DeletionDate") and not entry.get("deletion_date"):
        entry["deletion_date"] = _parse_date(emitted["DeletionDate"])

    # EncryptionAlgorithms can be a list — fill if entry's is None
    algs = emitted.get("EncryptionAlgorithms")
    if isinstance(algs, list) and algs and not entry.get("encryption_algorithms"):
        entry["encryption_algorithms"] = [str(a) for a in algs]

    # Aliases (separate discovery_id)
    if emitted.get("AliasName") and not entry.get("key_alias"):
        entry["key_alias"] = emitted["AliasName"]
    if emitted.get("AliasArn") and not entry.get("key_alias"):
        entry["key_alias"] = emitted["AliasArn"]

    # Grants count
    if emitted.get("Grants"):
        grants = emitted["Grants"]
        if isinstance(grants, list):
            entry["grant_count"] = max(entry.get("grant_count", 0), len(grants))

    # Tags (merge dict)
    tags = emitted.get("Tags")
    if isinstance(tags, dict) and tags:
        existing_tags = entry.get("tags") or {}
        if isinstance(existing_tags, dict):
            existing_tags.update(tags)
            entry["tags"] = existing_tags

    # Policy principals — merge from get_key_policy
    if emitted.get("Policy"):
        new_principals = _extract_policy_principals(emitted["Policy"])
        if new_principals:
            existing = entry.get("key_policy_principals") or []
            if isinstance(existing, list):
                merged_principals = list({*existing, *new_principals})
                entry["key_policy_principals"] = merged_principals
                # Recompute cross-account flag
                entry["cross_account_access"] = _detect_cross_account(
                    merged_principals, entry.get("account_id", "")
                )


def _parse_date(val) -> Optional[datetime]:
    """Parse a date string or return None."""
    if not val:
        return None
    if isinstance(val, datetime):
        return val
    try:
        return dateparser.parse(str(val))
    except Exception:
        return None


def _extract_policy_principals(policy_str) -> List[str]:
    """Extract principal ARNs from a KMS key policy JSON string."""
    if not policy_str:
        return []
    try:
        policy = json.loads(policy_str) if isinstance(policy_str, str) else policy_str
        principals = []
        for stmt in policy.get("Statement", []):
            principal = stmt.get("Principal", {})
            if isinstance(principal, str):
                principals.append(principal)
            elif isinstance(principal, dict):
                for val in principal.values():
                    if isinstance(val, list):
                        principals.extend(val)
                    elif isinstance(val, str):
                        principals.append(val)
        return list(set(principals))
    except Exception:
        return []


def _detect_cross_account(principals: List[str], account_id: str) -> bool:
    """Check if any principal ARN belongs to a different account."""
    if not account_id or not principals:
        return False
    for p in principals:
        if "::" in p and account_id not in p and p != "*":
            return True
    return False
