"""
Secrets Inventory Builder.

Aggregates Secrets Manager entries from discovery_findings into structured
inventory records for the encryption_secrets_inventory table.
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from dateutil import parser as dateparser

logger = logging.getLogger(__name__)


def build_secrets_inventory(
    secrets_resources: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Build secrets inventory from Secrets Manager discovery resources.

    Args:
        secrets_resources: SecretsManager discovery_findings rows.

    Returns:
        List of secrets inventory dicts ready for save_secrets_inventory().
    """
    secret_map = {}
    now = datetime.now(timezone.utc)

    for r in secrets_resources:
        emitted = r.get("emitted_fields") or {}
        if not isinstance(emitted, dict):
            continue

        secret_arn = emitted.get("ARN") or r.get("resource_uid", "")
        if not secret_arn or secret_arn in secret_map:
            if secret_arn and secret_arn in secret_map:
                _merge_secret_emitted(secret_map[secret_arn], emitted)
            continue

        last_rotated = _parse_date(emitted.get("LastRotatedDate"))
        last_accessed = _parse_date(emitted.get("LastAccessedDate"))

        days_since_rotation = None
        if last_rotated:
            days_since_rotation = (now - last_rotated).days

        rotation_rules = emitted.get("RotationRules") or {}
        rotation_interval = None
        if isinstance(rotation_rules, dict):
            rotation_interval = rotation_rules.get("AutomaticallyAfterDays")

        entry = {
            "secret_arn": secret_arn,
            "secret_name": emitted.get("Name", ""),
            "account_id": r.get("account_id", ""),
            "provider": r.get("provider", "aws"),
            "region": r.get("region", ""),
            "kms_key_id": emitted.get("KmsKeyId"),
            "rotation_enabled": emitted.get("RotationEnabled", False),
            "rotation_interval_days": rotation_interval,
            "last_rotated_date": last_rotated,
            "last_accessed_date": last_accessed,
            "days_since_rotation": days_since_rotation,
            "tags": emitted.get("Tags") or {},
            "raw_data": emitted,
        }
        secret_map[secret_arn] = entry

    secrets = list(secret_map.values())
    logger.info(f"Built inventory for {len(secrets)} secrets")
    return secrets


def _merge_secret_emitted(entry: Dict, emitted: Dict):
    """Merge additional emitted fields into existing secret entry.

    Same bug class as key/cert mappers: fill any missing target field from
    the newer emitted source so list+describe data converges.
    """
    field_map = (
        ("Name",                  "secret_name"),
        ("KmsKeyId",              "kms_key_id"),
        ("RotationEnabled",       "rotation_enabled"),
    )
    for src, tgt in field_map:
        val = emitted.get(src)
        if val is not None and entry.get(tgt) in (None, "", False):
            entry[tgt] = val

    if emitted.get("LastRotatedDate") and not entry.get("last_rotated_date"):
        entry["last_rotated_date"] = _parse_date(emitted["LastRotatedDate"])
    if emitted.get("LastAccessedDate") and not entry.get("last_accessed_date"):
        entry["last_accessed_date"] = _parse_date(emitted["LastAccessedDate"])

    rotation_rules = emitted.get("RotationRules")
    if isinstance(rotation_rules, dict) and rotation_rules:
        if not entry.get("rotation_interval_days"):
            entry["rotation_interval_days"] = rotation_rules.get(
                "AutomaticallyAfterDays"
            )

    tags = emitted.get("Tags")
    if isinstance(tags, dict) and tags:
        existing_tags = entry.get("tags") or {}
        if isinstance(existing_tags, dict):
            existing_tags.update(tags)
            entry["tags"] = existing_tags


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
