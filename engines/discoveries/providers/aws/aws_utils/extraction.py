"""
AWS resource extraction utilities.

Functions for extracting values from nested API responses, name auto-detection,
basic resource identification, and checked field enumeration.

SIMPLIFIED in Phase 7 refactor:
- Discovery engine ONLY collects raw data
- NO ARN construction (moved to inventory engine)
- NO identifier table lookup (moved to inventory engine)
- NO complex resource_type inference
- Basic resource_uid: raw ARN from API response or simple composite key
"""
import logging
import os
from typing import Any, Dict, Optional

logger = logging.getLogger('compliance-boto3')


# ═══════════════════════════════════════════════════════════════════
# extract_value — navigate nested API response structures
# ═══════════════════════════════════════════════════════════════════

def extract_value(obj: Any, path: str):
    """Extract value from nested object using dot notation and array syntax.

    Examples:
        extract_value(data, "response.Reservations[].Instances")
        extract_value(data, "item.Tags")
    """
    if obj is None:
        return None

    parts = path.split('.')
    current = obj
    for idx, part in enumerate(parts):
        if isinstance(current, list) and part.isdigit():
            index = int(part)
            if 0 <= index < len(current):
                current = current[index]
            else:
                return None
        elif part.endswith('[]'):
            key = part[:-2]
            arr = current.get(key, []) if isinstance(current, dict) else []
            if not parts[idx+1:]:
                return arr
            result = []
            for item in arr:
                sub = extract_value(item, '.'.join(parts[idx+1:]))
                if isinstance(sub, list):
                    result.extend(sub)
                elif sub is not None:
                    result.append(sub)
            return result
        elif isinstance(current, list):
            result = []
            for item in current:
                sub = extract_value(item, '.'.join(parts[idx:]))
                if isinstance(sub, list):
                    result.extend(sub)
                elif sub is not None:
                    result.append(sub)
            return result
        else:
            if isinstance(current, dict):
                current = current.get(part)
            else:
                return None
            if current is None:
                return None
    return current


# ═══════════════════════════════════════════════════════════════════
# Emit trace — debug utility
# ═══════════════════════════════════════════════════════════════════

def _emit_trace_enabled(discovery_id: str) -> bool:
    """Check if emit tracing is enabled for a specific discovery_id."""
    wanted = os.getenv("EMIT_TRACE_DISCOVERY_ID", "").strip()
    return bool(wanted) and wanted == discovery_id


# ═══════════════════════════════════════════════════════════════════
# extract_checked_fields — for check engine condition evaluation
# ═══════════════════════════════════════════════════════════════════

def extract_checked_fields(cond_config: Dict[str, Any]) -> set:
    """Extract all field names referenced in check conditions."""
    fields = set()

    if isinstance(cond_config, dict):
        if 'all' in cond_config:
            for sub_cond in cond_config['all']:
                fields.update(extract_checked_fields(sub_cond))
        elif 'any' in cond_config:
            for sub_cond in cond_config['any']:
                fields.update(extract_checked_fields(sub_cond))
        else:
            var = cond_config.get('var', '')
            if var:
                field_name = var.replace('item.', '') if var.startswith('item.') else var
                fields.add(field_name)

    return fields


# ═══════════════════════════════════════════════════════════════════
# auto_emit_arn_and_name — SIMPLIFIED
# Only extracts Name field and passes through ARN if present in response
# NO identifier table, NO ARN construction
# ═══════════════════════════════════════════════════════════════════

def auto_emit_arn_and_name(item: Dict[str, Any], service: str = None,
                           region: str = None, account_id: str = None) -> Dict[str, Any]:
    """Extract Name and passthrough ARN from AWS API response item.

    SIMPLIFIED: No ARN construction. If the API response contains an ARN
    field, pass it through. Otherwise, no resource_arn is set — the inventory
    engine will construct the canonical ARN using the identifier table.
    """
    auto_fields = {}

    if not isinstance(item, dict):
        return auto_fields

    for key, value in item.items():
        if not isinstance(key, str) or not isinstance(value, str):
            continue

        key_lower = key.lower()

        # Pass through ARN if present at top level (e.g. Arn, ARN, ResourceArn)
        if key_lower in ('arn', 'resourcearn') and value.startswith('arn:'):
            if 'resource_arn' not in auto_fields:
                auto_fields['resource_arn'] = value
        elif key_lower.endswith('arn') and value.startswith('arn:') and 'resource_arn' not in auto_fields:
            # Only use if the ARN service matches our service (avoid nested ARNs)
            arn_parts = value.split(':')
            if len(arn_parts) >= 3 and (not service or arn_parts[2] == service or service in arn_parts[2]):
                auto_fields['resource_arn'] = value

        # Extract Name field
        elif ('name' in key_lower) and value and value.strip():
            if key_lower == 'name':
                # Generic 'Name' field — use directly
                if 'resource_name' not in auto_fields:
                    auto_fields['resource_name'] = value
            elif 'resource_name' not in auto_fields:
                auto_fields['resource_name'] = value

    return auto_fields


# ═══════════════════════════════════════════════════════════════════
# extract_resource_identifier — SIMPLIFIED
# Basic resource_id extraction, NO ARN construction
# ═══════════════════════════════════════════════════════════════════

def extract_resource_identifier(item: Dict[str, Any], service: str,
                                 region: Optional[str], account_id: Optional[str],
                                 discovery_id: Optional[str] = None) -> Dict[str, Any]:
    """Extract basic resource identifiers from API response item.

    SIMPLIFIED: No ARN construction, no identifier table lookup.
    Returns:
        resource_id:   extracted ID value (InstanceId, BucketName, etc.)
        resource_type: inferred from discovery_id (describe_instances → instance)
        resource_arn:  only if already in item (passthrough from API)
        resource_uid:  resource_arn if available, else composite key
    """
    resource_id = None
    resource_type = _infer_type_from_discovery_id(discovery_id) if discovery_id else 'resource'
    resource_arn = item.get('resource_arn')

    # Extract resource_id from common field patterns
    # Priority: *Identifier > *Id > *Name > *Arn
    for key, value in item.items():
        if not isinstance(key, str) or not value:
            continue
        if isinstance(value, (dict, list)):
            continue

        key_lower = key.lower()
        value_str = str(value).strip()
        if not value_str:
            continue

        # Skip internal/metadata fields
        if key.startswith('_') or key.startswith('resource_'):
            continue

        if key_lower.endswith('identifier') and not resource_id:
            resource_id = value_str
            break
        elif key_lower.endswith('id') and 'arn' not in key_lower and not resource_id:
            resource_id = value_str
            break

    # Fallback: try common name fields
    if not resource_id:
        for key in ('Name', 'name', 'BucketName', 'RoleName', 'UserName',
                     'FunctionName', 'TableName', 'ClusterName', 'DomainName'):
            val = item.get(key)
            if val and isinstance(val, str):
                resource_id = val
                break

    # Build resource_uid: prefer ARN, fallback to composite key
    if resource_arn and resource_arn.startswith('arn:'):
        resource_uid = resource_arn
    elif resource_id:
        resource_uid = f"{service}:{region or 'global'}:{account_id or 'unknown'}:{resource_id}"
    else:
        resource_uid = f"{service}:{region or 'global'}:{discovery_id or 'unknown'}"

    return {
        'resource_id': resource_id,
        'resource_type': resource_type,
        'resource_arn': resource_arn,
        'resource_uid': resource_uid,
    }


# ═══════════════════════════════════════════════════════════════════
# _infer_type_from_discovery_id — simple heuristic
# ═══════════════════════════════════════════════════════════════════

def _infer_type_from_discovery_id(discovery_id: str) -> str:
    """Infer resource type from discovery_id.

    Examples:
        aws.ec2.describe_instances → instance
        aws.s3.list_buckets → bucket
        aws.iam.list_roles → role
    """
    if not discovery_id:
        return 'resource'

    parts = discovery_id.split('.')
    if len(parts) < 3:
        return 'resource'

    action = parts[-1]  # describe_instances, list_buckets, etc.

    # Strip prefix: describe_, list_, get_
    for prefix in ('describe_', 'list_', 'get_'):
        if action.startswith(prefix):
            noun = action[len(prefix):]
            break
    else:
        noun = action

    # Singularize: instances → instance, buckets → bucket
    if noun.endswith('ies'):
        return noun[:-3] + 'y'  # policies → policy
    elif noun.endswith('ses'):
        return noun[:-2]  # addresses → address
    elif noun.endswith('s') and not noun.endswith('ss') and not noun.endswith('us'):
        return noun[:-1]  # instances → instance
    return noun
