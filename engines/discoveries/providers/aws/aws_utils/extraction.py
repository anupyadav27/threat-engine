"""
AWS resource extraction utilities.

Functions for extracting values from nested API responses, ARN/name auto-detection,
resource identifier extraction, and checked field enumeration.

Extracted from service_scanner.py for maintainability.
"""
import ast
import logging
import os
import re
from typing import Any, Dict, List, Optional

# ARN normalizer — converts short-form UIDs to canonical ARN format
try:
    from shared.common.arn import normalize_resource_uid, is_arn
except ImportError:
    from engine_common.arn import normalize_resource_uid, is_arn

logger = logging.getLogger('compliance-boto3')


def extract_value(obj: Any, path: str):
    """Extract value from nested object using dot notation and array syntax"""
    if obj is None:
        return None

    parts = path.split('.')
    current = obj
    for idx, part in enumerate(parts):
        # Handle numeric array indices first
        if isinstance(current, list) and part.isdigit():
            index = int(part)
            if 0 <= index < len(current):
                current = current[index]
            else:
                return None
        elif part.endswith('[]'):
            key = part[:-2]
            arr = current.get(key, []) if isinstance(current, dict) else []
            if not parts[idx+1:]:  # Last part
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
                if current is None:
                    return None
            else:
                return None
    return current


def _emit_trace_enabled(discovery_id: str) -> bool:
    """
    Enable emit tracing for a specific discovery via env var:
      EMIT_TRACE_DISCOVERY_ID=aws.s3.get_bucket_acl
    This is intentionally service-agnostic and only used for debugging hangs.
    """
    wanted = os.getenv("EMIT_TRACE_DISCOVERY_ID", "").strip()
    return bool(wanted) and wanted == discovery_id

def extract_checked_fields(cond_config: Dict[str, Any]) -> set:
    """Extract all field names referenced in check conditions"""
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
                # Extract field name from 'item.field' or just 'field'
                field_name = var.replace('item.', '') if var.startswith('item.') else var
                fields.add(field_name)

    return fields


def auto_emit_arn_and_name(item: Dict[str, Any], service: str = None,
                           region: str = None, account_id: str = None) -> Dict[str, Any]:
    """
    Automatically extract ARN and Name fields from AWS API response item.
    If ARN is not found, generate it using service_list.json pattern.
    Returns dict with additional fields: resource_arn, resource_name

    This function searches for ARN and Name fields in the item and automatically
    includes them in the emitted data, even if not explicitly configured in YAML.
    """
    auto_fields = {}

    if not isinstance(item, dict):
        return auto_fields

    # First, do a direct search in top-level keys (most common case)
    for key, value in item.items():
        if not isinstance(key, str) or not isinstance(value, str):
            continue

        key_lower = key.lower()

        # Check for ARN fields (case-insensitive, must start with arn:aws:)
        if ('arn' in key_lower) and value.startswith('arn:aws:'):
            if 'resource_arn' not in auto_fields:  # Use first ARN found
                auto_fields['resource_arn'] = value
                # Also preserve original field name for reference
                auto_fields[f'_original_{key}'] = value

        # Check for Name fields (case-insensitive, must be non-empty string)
        elif ('name' in key_lower) and value and value.strip() and key_lower != 'name':
            # Prefer specific name fields (e.g., SecurityGroupName) over generic 'name'
            if 'resource_name' not in auto_fields:
                auto_fields['resource_name'] = value
                auto_fields[f'_original_{key}'] = value
            elif 'name' in key_lower and key_lower != 'name':
                # If we already have a name, prefer more specific ones
                existing_key = [k for k in auto_fields.keys() if k.startswith('_original_') and 'name' in k.lower()]
                if existing_key:
                    existing_name_key = existing_key[0].replace('_original_', '')
                    if len(key) > len(existing_name_key):  # More specific = longer key name
                        auto_fields['resource_name'] = value
                        auto_fields[f'_original_{key}'] = value

    # If not found in top level, search nested structures (depth 1 only for performance)
    if 'resource_arn' not in auto_fields or 'resource_name' not in auto_fields:
        def find_in_nested(obj, depth=0, max_depth=1):
            if depth > max_depth or not isinstance(obj, dict):
                return None, None

            found_arn = None
            found_name = None

            for key, value in obj.items():
                if isinstance(key, str) and isinstance(value, str):
                    key_lower = key.lower()
                    if 'arn' in key_lower and value.startswith('arn:aws:') and not found_arn:
                        found_arn = value
                    elif 'name' in key_lower and value and value.strip() and key_lower != 'name' and not found_name:
                        found_name = value
                elif isinstance(value, dict) and depth < max_depth:
                    nested_arn, nested_name = find_in_nested(value, depth + 1, max_depth)
                    if nested_arn and not found_arn:
                        found_arn = nested_arn
                    if nested_name and not found_name:
                        found_name = nested_name

            return found_arn, found_name

        nested_arn, nested_name = find_in_nested(item)
        if nested_arn and 'resource_arn' not in auto_fields:
            auto_fields['resource_arn'] = nested_arn
        if nested_name and 'resource_name' not in auto_fields:
            auto_fields['resource_name'] = nested_name

    # FALLBACK: Generate ARN using service_list.json if not found and we have service/account_id
    if 'resource_arn' not in auto_fields and service and account_id:
        try:
            from common.utils.reporting_manager import generate_arn

            # Try to extract resource_id and resource_type from item
            resource_id = None
            resource_type = None

            # Look for common resource identifier fields
            for key, value in item.items():
                if isinstance(value, (str, int)) and value:
                    key_lower = key.lower()
                    # IAM-specific: UserName, RoleName, GroupName, PolicyName, InstanceProfileName
                    if key_lower in ['username', 'rolename', 'groupname', 'policyname', 'instanceprofilename']:
                        resource_id = str(value)
                        resource_type = key_lower.replace('name', '')
                        # Handle path prefix for IAM resources (e.g., /service-role/role-name)
                        if '/' in resource_id:
                            resource_id = resource_id.split('/')[-1]
                        break
                    # Generic: *Id, *Identifier (but prefer Name fields for IAM)
                    elif (key_lower.endswith('id') or key_lower.endswith('identifier')) and not resource_id:
                        resource_id = str(value)
                        break

            if resource_id:
                # Generate ARN using service_list.json pattern
                generated_arn = generate_arn(service, region or '', account_id, resource_id, resource_type)
                auto_fields['resource_arn'] = generated_arn
                auto_fields['_generated_arn'] = True  # Flag to indicate it was generated
                logger.debug(f"[ARN-GEN] Generated ARN for {service}: {generated_arn[:80]}")
        except Exception as e:
            logger.debug(f"[ARN-GEN] Failed to generate ARN for {service}: {e}")

    return auto_fields


def extract_resource_identifier(item: Dict[str, Any], service: str, region: Optional[str], account_id: Optional[str], discovery_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Extract resource identifier and generate ARN for a check item.
    Returns dict with resource_id, resource_type, resource_arn, resource_uid.

    PRIORITY ORDER:
    1. Parse ARN from item (if present) → extract resource_type from ARN
    2. Infer resource_type from resource_id prefix (before generating ARN)
    3. Generate ARN with inferred type → parse generated ARN to confirm type

    This function is resource-agnostic and uses ARN structure as primary source of truth.
    """
    from common.utils.reporting_manager import generate_arn, is_global_service

    resource_id = None
    resource_type = None
    resource_arn = None

    # Pre-process: Handle malformed data (string representations of dicts)
    # This is a fallback for when YAML emit configuration is incorrect
    processed_item = {}
    for key, value in item.items():
        if isinstance(value, str) and value.startswith("{") and value.endswith("}"):
            # Try to parse string representation of dict
            try:
                # Use ast.literal_eval for safe parsing
                parsed = ast.literal_eval(value)
                if isinstance(parsed, dict):
                    # Merge parsed dict into item
                    processed_item.update(parsed)
                    continue
            except (ValueError, SyntaxError):
                pass
        processed_item[key] = value

    # Use processed item (with parsed nested structures)
    item = processed_item

    # GENERIC PATTERN-BASED EXTRACTION (resource-agnostic)
    # Step 1: Try to extract ARN from any field (pattern: *Arn, *ARN, *arn, or common names)
    if not resource_arn:
        # Check common ARN field names first
        resource_arn = (item.get("arn") or item.get("Arn") or item.get("resource_arn") or
                       item.get("ResourceArn") or item.get("ARN"))

        # If not found, search for any field ending with "Arn" containing a valid ARN
        if not resource_arn:
            for key, value in item.items():
                if isinstance(key, str) and isinstance(value, str):
                    # Check if key suggests ARN (ends with Arn/ARN/arn or contains "arn")
                    if ((key.lower().endswith("arn") or "arn" in key.lower()) and
                        value.startswith("arn:")):
                        resource_arn = value
                        break

    # Step 2: Extract resource_id using pattern matching (generic approach)
    # Priority: Identifier fields > Name fields > Id fields > common names
    resource_id = None
    resource_type = "resource"  # Default, can be refined if we find type hints

    # Pattern 1: Look for fields ending with "Identifier" (most specific)
    for key, value in item.items():
        if isinstance(key, str) and isinstance(value, (str, int)) and value:
            key_lower = key.lower()
            if key_lower.endswith("identifier") and value:
                resource_id = str(value)
                # Infer resource type from field name (e.g., DBInstanceIdentifier -> db-instance)
                if "instance" in key_lower:
                    resource_type = "instance" if "db" not in key_lower else "db"
                elif "cluster" in key_lower:
                    resource_type = "cluster"
                elif "security" in key_lower and "group" in key_lower:
                    resource_type = "security-group"
                elif "parameter" in key_lower and "group" in key_lower:
                    resource_type = "parameter-group"
                elif "option" in key_lower and "group" in key_lower:
                    resource_type = "option-group"
                break

    # Pattern 2: Look for fields ending with "Name" (common pattern)
    if not resource_id:
        for key, value in item.items():
            if isinstance(key, str) and isinstance(value, (str, int)) and value:
                key_lower = key.lower()
                # Skip generic "name" field, prefer specific ones (e.g., BucketName, UserName)
                if (key_lower.endswith("name") and key_lower != "name" and
                    value and str(value).strip()):
                    resource_id = str(value)
                    # Infer type from field name
                    if "bucket" in key_lower:
                        resource_type = "bucket"
                    elif "user" in key_lower:
                        resource_type = "user"
                    elif "role" in key_lower:
                        resource_type = "role"
                    elif "group" in key_lower:
                        resource_type = "group" if "security" not in key_lower else "security-group"
                    break

    # Pattern 3: Look for fields ending with "Id" (but not ARN-related)
    if not resource_id:
        for key, value in item.items():
            if isinstance(key, str) and isinstance(value, (str, int)) and value:
                key_lower = key.lower()
                # Skip ARN-related fields
                if (key_lower.endswith("id") and "arn" not in key_lower and
                    value and str(value).strip()):
                    resource_id = str(value)
                    # Infer type from field name
                    if "instance" in key_lower:
                        resource_type = "instance"
                    elif "volume" in key_lower:
                        resource_type = "volume"
                    elif "key" in key_lower:
                        resource_type = "key"
                    break

    # Pattern 4: Fallback to common field names (generic)
    if not resource_id:
        resource_id = (item.get("resource_id") or item.get("resource_name") or
                     item.get("name") or item.get("Name") or
                     item.get("KeyName") or item.get("key_name") or
                     item.get("BucketName") or item.get("bucket_name") or
                     item.get("UserName") or item.get("user_name") or
                     item.get("RoleName") or item.get("role_name") or
                     item.get("id") or item.get("Id") or
                     item.get("Identifier") or item.get("identifier") or
                     item.get("ResourceId") or item.get("ResourceName"))

        # If we got an ARN as resource_id, try to extract the actual ID from it
        if resource_id and isinstance(resource_id, str) and resource_id.startswith("arn:aws:"):
            try:
                arn_parts = resource_id.split(":")
                if len(arn_parts) >= 6:
                    resource_part = arn_parts[5]
                    if "/" in resource_part:
                        extracted_id = resource_part.split("/", 1)[1]
                        if extracted_id and extracted_id != "resource":
                            resource_id = extracted_id
                        else:
                            resource_id = (item.get("KeyName") or item.get("key_name") or
                                         item.get("BucketName") or item.get("bucket_name") or
                                         item.get("UserName") or item.get("user_name") or
                                         item.get("RoleName") or item.get("role_name") or
                                         None)
            except Exception:
                pass

    # Fix array stringification in resource_id (generic validation)
    if resource_id:
        if isinstance(resource_id, (list, dict)):
            resource_id = None
        else:
            resource_id_str = str(resource_id).strip()

            # Remove array/list notation if present (generic pattern)
            if (resource_id_str.startswith("['") and resource_id_str.endswith("']")) or \
               (resource_id_str.startswith('["') and resource_id_str.endswith('"]')):
                resource_id_str = resource_id_str[2:-2]  # Remove [' and ']

            # Skip invalid resource_ids (generic patterns)
            invalid_patterns = ["[]", "{}", "", "None", "null"]
            if resource_id_str in invalid_patterns:
                resource_id = None
            elif resource_id_str.startswith("/dev/"):  # Skip block device paths
                resource_id = None
            elif len(resource_id_str) > 100:  # Likely not a resource ID if too long
                resource_id = None
            else:
                resource_id = resource_id_str

    # Step 3: Extract resource_type from ARN if available (PRIMARY - most reliable)
    if resource_arn:
        try:
            arn_parts = resource_arn.split(":")
            if len(arn_parts) >= 6:
                resource_part = arn_parts[5]

                if "/" in resource_part:
                    extracted_type = resource_part.split("/")[0]
                    arn_aliases = {
                        "secgrp": "security-group",
                    }
                    extracted_type = arn_aliases.get(extracted_type, extracted_type)

                    if extracted_type == "resource" and discovery_id:
                        resource_type = _infer_type_from_discovery_id(discovery_id)
                    else:
                        resource_type = extracted_type

                elif ":" in resource_part:
                    resource_type = resource_part.split(":")[0]

                elif len(arn_parts) >= 7:
                    resource_type = arn_parts[5]

                elif service.lower() == "s3" and len(arn_parts) == 6:
                    resource_type = "bucket"
        except Exception:
            pass

    # Step 3b: Infer resource_type from resource_id prefix BEFORE generating ARN
    if resource_type in ("resource", None) and resource_id:
        resource_id_str = str(resource_id).strip()

        prefix_patterns = [
            ("sg-", "security-group"),
            ("sgr-", "security-group-rule"),
            ("i-", "instance"),
            ("ami-", "image"),
            ("vol-", "volume"),
            ("snap-", "snapshot"),
            ("vpc-", "vpc"),
            ("subnet-", "subnet"),
            ("rtb-", "route-table"),
            ("acl-", "network-acl"),
            ("eni-", "network-interface"),
            ("nat-", "nat-gateway"),
            ("igw-", "internet-gateway"),
            ("vgw-", "vpn-gateway"),
            ("cgw-", "customer-gateway"),
            ("lt-", "launch-template"),
            ("vai-", "verified-access-instance"),
            ("tgw-", "transit-gateway"),
            ("db-", "db-instance"),
            ("cluster-", "db-cluster"),
            ("function:", "function"),
        ]

        for prefix, res_type in prefix_patterns:
            if resource_id_str.startswith(prefix):
                resource_type = res_type
                break

    # Step 3c: Generate ARN if not present (now with inferred resource_type)
    if not resource_arn and resource_id and str(resource_id).strip() and account_id:
        try:
            service_region = region if not is_global_service(service) else None
            resource_arn = generate_arn(
                service,
                service_region,
                account_id,
                str(resource_id),
                resource_type
            )

            # Step 3d: Parse the generated ARN to extract/confirm resource_type
            if resource_arn and resource_type in ("resource", None):
                try:
                    arn_parts = resource_arn.split(":")
                    if len(arn_parts) >= 6:
                        resource_part = arn_parts[5]
                        if "/" in resource_part:
                            extracted_type = resource_part.split("/")[0]
                            arn_aliases = {"secgrp": "security-group"}
                            extracted_type = arn_aliases.get(extracted_type, extracted_type)

                            if extracted_type == "resource" and discovery_id:
                                resource_type = _infer_type_from_discovery_id(discovery_id)
                            else:
                                resource_type = extracted_type
                except Exception:
                    pass
        except Exception as e:
            logger.debug(f"Could not generate ARN for {service}/{resource_id}: {e}")
            resource_arn = None

    # Use ARN as resource_uid if available, otherwise normalize short-form to ARN
    if resource_arn and is_arn(resource_arn):
        resource_uid = resource_arn
    elif resource_id and account_id:
        short_uid = f"{service}:{region or 'global'}:{account_id}:{resource_id}"
        resource_uid = normalize_resource_uid(
            resource_uid=short_uid,
            resource_type=f"{service}.{resource_type}" if resource_type else "",
            provider="aws",
            region=region or "global",
            account_id=account_id,
            resource_arn=resource_arn or "",
        )
    elif resource_id:
        resource_uid = f"{service}:{region or 'global'}:{resource_id}"
    else:
        resource_uid = f"{service}:{region or 'global'}:unknown"

    # Determine if resource is AWS-managed
    name = item.get('name') or item.get('Name') or ''
    is_aws_managed = (
        'alias/aws/' in str(resource_id) or 'alias/aws/' in str(name) or
        str(name).startswith('AWS-') or
        str(name).startswith('system_') or
        str(name) in ['primary', 'default'] or
        'product/' in str(resource_id) or
        'SageMaker Public Hub' in str(name)
    )

    # Unify: resource_uid IS the ARN. No separate UID format.
    return {
        "resource_id": resource_id,
        "resource_type": resource_type or "resource",
        "resource_arn": resource_uid,
        "resource_uid": resource_uid,
        "is_aws_managed": is_aws_managed,
    }


def _infer_type_from_discovery_id(discovery_id: str) -> str:
    """Infer resource type from discovery_id (e.g., 'aws.ec2.describe_key_pairs' → 'key-pair')."""
    disc_parts = discovery_id.split(".")
    if len(disc_parts) >= 3:
        last_part = disc_parts[-1]
        if last_part.startswith("describe_"):
            last_part = last_part[9:]
        elif last_part.startswith("list_"):
            last_part = last_part[5:]
        elif last_part.startswith("get_"):
            last_part = last_part[4:]

        if "_" in last_part:
            parts = last_part.split("_")
            if parts[-1] in ("pairs", "groups", "rules", "tables", "instances", "images", "snapshots", "volumes", "gateways", "connections", "endpoints"):
                parts[-1] = parts[-1][:-1] if parts[-1].endswith("s") else parts[-1]
            return "-".join(parts)
        else:
            return last_part
    return "resource"
