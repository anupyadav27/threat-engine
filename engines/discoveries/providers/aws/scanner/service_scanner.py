import asyncio
import json
import os
import boto3
import yaml
import logging
import time
from typing import Any, List, Dict, Optional, Tuple
from time import sleep
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError
import sys
import re
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pathlib import Path

# ARN normalizer — converts short-form UIDs to canonical ARN format
try:
    from shared.common.arn import normalize_resource_uid, is_arn
except ImportError:
    from engine_common.arn import normalize_resource_uid, is_arn

def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent.parent

_DEBUG_LOG_PATH = _project_root() / ".cursor" / "debug.log"

from common.utils.reporting_manager import save_reporting_bundle
from providers.aws.auth.aws_auth import get_boto3_session, get_session_for_account
# NOTE: get_boto3_client_name is now provided by config_loader (database-driven)

# Database-driven configuration (Phase 4: Unified Service Execution)
sys.path.append(str(_project_root() / "engine_discoveries"))
from utils.config_loader import DiscoveryConfigLoader
from utils.filter_engine import FilterEngine
from utils.pagination_engine import PaginationEngine

# Initialize database-driven configuration loaders (cached for performance)
_config_loader = None
_filter_engine = None
_pagination_engine = None

def _get_config_loader():
    """Get singleton DiscoveryConfigLoader instance"""
    global _config_loader, _filter_engine, _pagination_engine
    if _config_loader is None:
        _config_loader = DiscoveryConfigLoader(provider='aws')
        _filter_engine = FilterEngine(_config_loader)
        _pagination_engine = PaginationEngine(_config_loader)
    return _config_loader, _filter_engine, _pagination_engine

# Logging will be configured per-scan in output/scan_TIMESTAMP/logs/
# This allows each scan to have its own log file
logging.basicConfig(level=os.getenv('LOG_LEVEL', 'INFO'))
logger = logging.getLogger('compliance-boto3')

# Retry/backoff settings
MAX_RETRIES = int(os.getenv('COMPLIANCE_MAX_RETRIES', '5'))
BASE_DELAY = float(os.getenv('COMPLIANCE_BASE_DELAY', '0.8'))
BACKOFF_FACTOR = float(os.getenv('COMPLIANCE_BACKOFF_FACTOR', '2.0'))

# Botocore retry/timeout config
BOTO_CONFIG = BotoConfig(
    retries={'max_attempts': int(os.getenv('BOTO_MAX_ATTEMPTS', '5')), 'mode': os.getenv('BOTO_RETRY_MODE', 'adaptive')},
    read_timeout=int(os.getenv('BOTO_READ_TIMEOUT', '120')),  # Increased for slow operations
    connect_timeout=int(os.getenv('BOTO_CONNECT_TIMEOUT', '10')),
    max_pool_connections=int(os.getenv('BOTO_MAX_POOL_CONNECTIONS', '100')),
)

# Operation-level timeout (max time per API call/operation)
OPERATION_TIMEOUT = int(os.getenv('OPERATION_TIMEOUT', '60'))   # 60s default (was 600s)
MAX_ITEMS_PER_DISCOVERY = int(os.getenv('MAX_ITEMS_PER_DISCOVERY', '100000'))  # Safety limit

# Dedicated thread pool for concurrent service-region scans.
# run_in_executor(None) uses Python's default pool: min(32, cpu+4) = 8 on t3.xlarge.
# With 10 services × 5 regions = 50 concurrent scan tasks, the default pool starves.
# This pool is sized explicitly so all 50 tasks run in parallel.
import concurrent.futures as _cf
_SCAN_EXECUTOR = _cf.ThreadPoolExecutor(
    max_workers=int(os.getenv('SCAN_EXECUTOR_THREADS', '100')),
    thread_name_prefix='disc-scan',
)


def _normalize_action(action: str) -> str:
    """Convert camelCase action names to snake_case for boto3 compatibility.
    e.g. 'describeAccountAttributes' -> 'describe_account_attributes'
    """
    import re
    # Already snake_case - return as-is
    if '_' in action:
        return action
    # Convert camelCase to snake_case
    s = re.sub(r'([A-Z]+)([A-Z][a-z])', r'\1_\2', action)
    return re.sub(r'([a-z\d])([A-Z])', r'\1_\2', s).lower()


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
    import ast
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
    # Priority: Prefer non-ARN identifiers (e.g., KeyName over KeyPairId which is an ARN)
    if not resource_id:
        # First try non-ARN fields
        resource_id = (item.get("resource_id") or item.get("resource_name") or 
                     item.get("name") or item.get("Name") or
                     item.get("KeyName") or item.get("key_name") or  # Key pairs: prefer KeyName over KeyPairId
                     item.get("BucketName") or item.get("bucket_name") or  # S3: prefer BucketName
                     item.get("UserName") or item.get("user_name") or  # IAM: prefer UserName
                     item.get("RoleName") or item.get("role_name") or  # IAM: prefer RoleName
                     item.get("id") or item.get("Id") or
                     item.get("Identifier") or item.get("identifier") or
                     item.get("ResourceId") or item.get("ResourceName"))
        
        # If we got an ARN as resource_id, try to extract the actual ID from it
        if resource_id and isinstance(resource_id, str) and resource_id.startswith("arn:aws:"):
            # Try to extract resource ID from ARN
            try:
                arn_parts = resource_id.split(":")
                if len(arn_parts) >= 6:
                    resource_part = arn_parts[5]
                    if "/" in resource_part:
                        # Extract the part after the slash (actual resource ID)
                        extracted_id = resource_part.split("/", 1)[1]
                        # Only use if it's not too generic
                        if extracted_id and extracted_id != "resource":
                            resource_id = extracted_id
                        else:
                            # ARN doesn't have useful ID, try to find non-ARN field
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
    # AWS ARN format: arn:aws:service:region:account-id:resource-type/resource-id
    # Examples:
    #   arn:aws:ec2:us-east-1:123456:instance/i-123 → resource-type = "instance"
    #   arn:aws:ec2:us-east-1:123456:security-group/sg-123 → resource-type = "security-group"
    # ARN parsing should ALWAYS take precedence over earlier inferences (e.g., "group" → "security-group")
    if resource_arn:
        try:
            arn_parts = resource_arn.split(":")
            if len(arn_parts) >= 6:
                resource_part = arn_parts[5]  # Everything after account-id
                
                # Handle format: resource-type/resource-id (most common)
                if "/" in resource_part:
                    extracted_type = resource_part.split("/")[0]
                    # Normalize known ARN format aliases (AWS ARN variations, not service-specific)
                    arn_aliases = {
                        "secgrp": "security-group",  # EC2 uses "secgrp" in some ARN formats
                    }
                    extracted_type = arn_aliases.get(extracted_type, extracted_type)
                    
                    # If ARN has generic "resource" type, try to infer from discovery_id
                    # Otherwise, use the extracted type from ARN (this overrides any earlier inference)
                    if extracted_type == "resource" and discovery_id:
                        # Extract resource type from discovery_id (e.g., "aws.ec2.describe_key_pairs" → "key-pair")
                        disc_parts = discovery_id.split(".")
                        if len(disc_parts) >= 3:
                            # Get the last part and convert to resource type
                            last_part = disc_parts[-1]  # e.g., "describe_key_pairs"
                            # Remove "describe_" or "list_" prefix
                            if last_part.startswith("describe_"):
                                last_part = last_part[9:]  # Remove "describe_"
                            elif last_part.startswith("list_"):
                                last_part = last_part[5:]  # Remove "list_"
                            elif last_part.startswith("get_"):
                                last_part = last_part[4:]  # Remove "get_"
                            
                            # Convert snake_case to hyphenated (generic pattern)
                            # "key_pairs" → "key-pair", "security_groups" → "security-group"
                            if "_" in last_part:
                                parts = last_part.split("_")
                                # Remove common plural suffixes
                                if parts[-1] in ("pairs", "groups", "rules", "tables", "instances", "images", "snapshots", "volumes", "gateways", "connections", "endpoints"):
                                    parts[-1] = parts[-1][:-1] if parts[-1].endswith("s") else parts[-1]
                                resource_type = "-".join(parts)
                            else:
                                resource_type = last_part
                    else:
                        resource_type = extracted_type
                
                # Handle format: resource-type:resource-id (less common, e.g., RDS snapshots)
                elif ":" in resource_part:
                    resource_type = resource_part.split(":")[0]
                
                # Handle format where resource-type is in arn_parts[5] and resource-id is in arn_parts[6]
                # (e.g., RDS: arn:aws:rds:region:account:snapshot:name)
                elif len(arn_parts) >= 7:
                    # arn_parts[5] is the resource type, arn_parts[6] is the resource ID
                    resource_type = arn_parts[5]
                
                # Handle S3 special case: arn:aws:s3:::bucket-name (no resource-type segment)
                elif service.lower() == "s3" and len(arn_parts) == 6:
                    resource_type = "bucket"
        except Exception:
            pass
    
    # Step 3b: Infer resource_type from resource_id prefix BEFORE generating ARN
    # This ensures generated ARN has correct resource_type
    # Generic AWS resource ID prefix patterns (cross-service, not EC2-specific)
    if resource_type in ("resource", None) and resource_id:
        resource_id_str = str(resource_id).strip()
        
        # Generic AWS resource ID prefix patterns (AWS naming conventions)
        # Format: prefix-identifier (e.g., sg-xxx, i-xxx, ami-xxx, db-xxx)
        prefix_patterns = [
            # EC2 patterns
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
            # RDS patterns
            ("db-", "db-instance"),
            ("cluster-", "db-cluster"),
            # Lambda patterns (ARN format: function:name)
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
                resource_type  # Now has inferred type if available
            )
            
            # Step 3d: Parse the generated ARN to extract/confirm resource_type
            # This is critical for cases where ARN was generated with generic "resource" type
            if resource_arn and resource_type in ("resource", None):
                try:
                    arn_parts = resource_arn.split(":")
                    if len(arn_parts) >= 6:
                        resource_part = arn_parts[5]
                        if "/" in resource_part:
                            extracted_type = resource_part.split("/")[0]
                            arn_aliases = {"secgrp": "security-group"}
                            extracted_type = arn_aliases.get(extracted_type, extracted_type)
                            
                            # If generated ARN has generic "resource" type, use discovery_id to infer
                            if extracted_type == "resource" and discovery_id:
                                # Extract resource type from discovery_id (e.g., "aws.ec2.describe_key_pairs" → "key-pair")
                                disc_parts = discovery_id.split(".")
                                if len(disc_parts) >= 3:
                                    last_part = disc_parts[-1]  # e.g., "describe_key_pairs"
                                    # Remove "describe_" or "list_" prefix
                                    if last_part.startswith("describe_"):
                                        last_part = last_part[9:]
                                    elif last_part.startswith("list_"):
                                        last_part = last_part[5:]
                                    elif last_part.startswith("get_"):
                                        last_part = last_part[4:]
                                    
                                    # Convert snake_case to hyphenated (generic pattern)
                                    if "_" in last_part:
                                        parts = last_part.split("_")
                                        # Remove common plural suffixes
                                        if parts[-1] in ("pairs", "groups", "rules", "tables", "instances", "images", "snapshots", "volumes", "gateways", "connections", "endpoints"):
                                            parts[-1] = parts[-1][:-1] if parts[-1].endswith("s") else parts[-1]
                                        resource_type = "-".join(parts)
                                    else:
                                        resource_type = last_part
                            else:
                                resource_type = extracted_type
                except Exception:
                    pass
        except Exception as e:
            logger.debug(f"Could not generate ARN for {service}/{resource_id}: {e}")
            # Don't create invalid fallback ARN - leave it None
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
        'alias/aws/' in str(resource_id) or 'alias/aws/' in str(name) or  # KMS AWS aliases
        str(name).startswith('AWS-') or  # SSM AWS documents/nodes
        str(name).startswith('system_') or  # Keyspaces system tables
        str(name) in ['primary', 'default'] or  # Default resources
        'product/' in str(resource_id) or  # SecurityHub products (marketplace)
        'SageMaker Public Hub' in str(name)  # SageMaker public hub
    )
    
    # Unify: resource_uid IS the ARN. No separate UID format.
    # resource_arn is kept for backward compat but always equals resource_uid.
    return {
        "resource_id": resource_id,
        "resource_type": resource_type or "resource",
        "resource_arn": resource_uid,
        "resource_uid": resource_uid,
        "is_aws_managed": is_aws_managed,
    }

def evaluate_condition(value: Any, operator: str, expected: Any = None) -> bool:
    """Evaluate a condition with the given operator and expected value
    
    Supported operators:
    - exists, not_exists: Check if value exists/doesn't exist
    - equals, not_equals: Equality checks
    - gt, gte, lt, lte: Numeric comparisons
    - contains, not_contains: List/string membership
    - in, not_in: Value in/not in list (for enum checks)
    - is_empty, not_empty: Empty checks
    - length_gte, length_gt, length_lt, length_lte: Length comparisons
    """
    # Existence checks
    if operator == 'exists':
        return value is not None and value != '' and value != []
    elif operator == 'not_exists':
        return value is None or value == '' or value == []
    elif operator == 'is_empty':
        return value is None or value == '' or value == []
    elif operator == 'not_empty':
        return value is not None and value != '' and value != []
    
    # Equality checks
    elif operator == 'equals':
        return value == expected
    elif operator == 'not_equals':
        return value != expected
    
    # Numeric comparisons
    elif operator == 'gt':
        try:
            return float(value) > float(expected) if value is not None and expected is not None else False
        except (ValueError, TypeError):
            return False
    elif operator == 'gte':
        try:
            return float(value) >= float(expected) if value is not None and expected is not None else False
        except (ValueError, TypeError):
            return False
    elif operator == 'lt':
        try:
            return float(value) < float(expected) if value is not None and expected is not None else False
        except (ValueError, TypeError):
            return False
    elif operator == 'lte':
        try:
            return float(value) <= float(expected) if value is not None and expected is not None else False
        except (ValueError, TypeError):
            return False
    
    # List/string membership
    elif operator == 'contains':
        if isinstance(value, (list, str)):
            return expected in value
        return False
    elif operator == 'not_contains':
        if isinstance(value, (list, str)):
            return expected not in value
        return False
    
    # Enum/list membership (value in/not in expected list)
    elif operator == 'in':
        if isinstance(expected, list):
            return value in expected
        return False
    elif operator == 'not_in':
        if isinstance(expected, list):
            return value not in expected
        return False
    
    # Length comparisons
    elif operator == 'length_gte':
        if isinstance(value, (list, str)):
            try:
                return len(value) >= int(expected)
            except (ValueError, TypeError):
                return False
        return False
    elif operator == 'length_gt':
        if isinstance(value, (list, str)):
            try:
                return len(value) > int(expected)
            except (ValueError, TypeError):
                return False
        return False
    elif operator == 'length_lt':
        if isinstance(value, (list, str)):
            try:
                return len(value) < int(expected)
            except (ValueError, TypeError):
                return False
        return False
    elif operator == 'length_lte':
        if isinstance(value, (list, str)):
            try:
                return len(value) <= int(expected)
            except (ValueError, TypeError):
                return False
        return False
    
    # Operator aliases (for backward compatibility)
    elif operator == 'greater_than':
        try:
            return float(value) > float(expected) if value is not None and expected is not None else False
        except (ValueError, TypeError):
            return False
    elif operator == 'less_than':
        try:
            return float(value) < float(expected) if value is not None and expected is not None else False
        except (ValueError, TypeError):
            return False
    elif operator == 'greater_than_or_equal':
        try:
            return float(value) >= float(expected) if value is not None and expected is not None else False
        except (ValueError, TypeError):
            return False
    elif operator == 'less_than_or_equal':
        try:
            return float(value) <= float(expected) if value is not None and expected is not None else False
        except (ValueError, TypeError):
            return False
    
    else:
        logger.warning(f"Unknown operator: {operator}")
        return False

def resolve_template(text: str, context: Dict[str, Any]) -> Any:
    """Resolve template variables like {{ variable }} in text"""
    if not isinstance(text, str) or '{{' not in text:
        return text
    
    def replace_var(match):
        var_path = match.group(1).strip()
        
        # Handle special functions
        if var_path.startswith('exists('):
            path = var_path[7:-1]  # Remove 'exists(' and ')'
            value = extract_value(context, path)
            exists_result = value is not None and value != '' and value != []
            return str(exists_result)
        
        # Handle complex expressions with dynamic keys like user_details[u.UserName].User.PasswordLastUsed
        if '[' in var_path and ']' in var_path:
            # Find the dynamic key part like [u.UserName]
            start_bracket = var_path.find('[')
            end_bracket = var_path.find(']')
            if start_bracket != -1 and end_bracket != -1:
                # Extract the base path and dynamic key
                base_path = var_path[:start_bracket]
                dynamic_key_expr = var_path[start_bracket+1:end_bracket]
                remaining_path = var_path[end_bracket+1:]
                
                # Resolve the dynamic key (e.g., u.UserName)
                # For simple expressions like u.UserName, we need to handle them directly
                if '.' in dynamic_key_expr and not dynamic_key_expr.startswith('{{'):
                    # Simple dot notation like u.UserName
                    dynamic_key = extract_value(context, dynamic_key_expr)
                else:
                    # Complex expression that needs template resolution
                    dynamic_key = resolve_template(dynamic_key_expr, context)
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug("Dynamic key expression: %s -> %s", dynamic_key_expr, dynamic_key)
                
                # Build the full path - the data is stored as user_details.administrator, not user_details.administrator.User.PasswordLastUsed
                # For complex keys with dots, we need to access them as nested dictionaries
                if '.' in dynamic_key:
                    # If the dynamic key contains dots, we need to access it as a nested dictionary
                    full_key = base_path
                    # We'll handle the nested access in the extract_value call
                else:
                    full_key = f"{base_path}.{dynamic_key}"
                
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug("Complex template: %s -> %s", var_path, full_key)
                # Check if the full key exists in context
                if full_key in context:
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.debug("Full key %s exists in context", full_key)
                    # The data is stored directly under the full key, so we need to extract the remaining path from it
                    if remaining_path:
                        # Remove the leading dot from remaining_path and handle array indices
                        remaining_path_clean = remaining_path.lstrip('.')
                        # Convert [0] to 0 for array access
                        remaining_path_clean = remaining_path_clean.replace('[', '').replace(']', '')
                        if logger.isEnabledFor(logging.DEBUG):
                            logger.debug("Extracting from %s with path: %s", full_key, remaining_path_clean)
                        value = extract_value(context[full_key], remaining_path_clean)
                    else:
                        value = context[full_key]
                else:
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.debug("Full key %s not found in context (keys=%s)", full_key, list(context.keys()))
                    value = None
                
                # Handle nested access for complex keys
                if '.' in dynamic_key and full_key in context:
                    # Build the full path with the dynamic key
                    full_path = f"{dynamic_key}.{remaining_path_clean}" if remaining_path else dynamic_key
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.debug("Extracting from %s with nested path: %s", full_key, full_path)
                    value = extract_value(context[full_key], full_path)
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug("Complex template result: %s", value)
                return str(value) if value is not None else ''
        
        # Debug logging (guarded to avoid expensive stringification at INFO level)
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("Resolving template variable: %s", var_path)
            logger.debug("Context keys: %s", list(context.keys()))
            if 'u' in context:
                logger.debug("Context 'u' object present")
        
        value = extract_value(context, var_path)
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("Extracted value: %s", value)
        
        # Return as string, but preserve numeric strings for account IDs
        if value is not None:
            # If value is an empty list, return empty string (not '[]')
            # This handles cases where extract_value returns [] for missing nested paths
            if isinstance(value, list) and len(value) == 0:
                return ''
            # If it's a number, convert to string (important for account IDs)
            if isinstance(value, (int, float)):
                return str(value)
            # If it's a list with items, join them or return first item (for single-item lists)
            if isinstance(value, list):
                # For single-item lists, return the item (common case for API responses)
                if len(value) == 1:
                    return str(value[0])
                # For multi-item lists, return as string representation (preserve for arrays)
                return str(value)
            return str(value)
        return ''
    
    resolved = re.sub(r'\{\{\s*([^}]+)\s*\}\}', replace_var, text)
    
    # For account IDs and similar numeric strings that should stay as strings,
    # check if the original template variable path suggests it should be a string
    # (e.g., account_info.Account, AccountId, etc.)
    if 'Account' in text or 'AccountId' in text or 'account_id' in text:
        # Keep as string for account IDs
        return resolved
    
    # Try to convert to appropriate type
    if resolved.isdigit():
        return int(resolved)
    elif resolved.replace('.', '', 1).isdigit():
        return float(resolved)
    elif resolved.lower() in ('true', 'false'):
        return resolved.lower() == 'true'
    
    return resolved

def load_enabled_services_with_scope():
    config_path = os.path.join(os.path.dirname(__file__), "..", "config", "service_list.json")
    with open(config_path) as f:
        data = json.load(f)
    return [(s["name"], s.get("scope", "regional")) for s in data["services"] if s.get("enabled")]

def load_service_rules(service_name):
    """
    Load service rules YAML file.
    Handles service name mapping from config names to folder names.
    Each service has its own folder and YAML file.
    The boto3 client mapping (SERVICE_TO_BOTO3_CLIENT) handles SDK client selection.
    """
    base_path = os.path.join(os.path.dirname(__file__), "..", "services")
    
    # Original logic - load from service folder
    # Try multiple name variations
    possible_names = [
        service_name,  # Exact match
        service_name.replace('_', ''),  # Remove underscores (api_gateway -> apigateway)
    ]
    
    # Also try with common variations
    if '_' in service_name:
        # Try with different underscore positions
        parts = service_name.split('_')
        possible_names.append(''.join(parts))  # api_gateway -> apigateway
        if len(parts) == 2:
            possible_names.append(parts[0] + parts[1].capitalize())  # api_gateway -> apiGateway
    
    # Try each possible name
    rules_path = None
    for name in possible_names:
        test_path = os.path.join(base_path, name, "rules", f"{name}.yaml")
        if os.path.exists(test_path):
            rules_path = test_path
            break
    
    # If still not found, try to find by scanning folders
    if not rules_path:
        service_norm = service_name.replace('_', '').lower()
        if os.path.exists(base_path):
            for folder_name in os.listdir(base_path):
                folder_path = os.path.join(base_path, folder_name)
                if os.path.isdir(folder_path):
                    folder_norm = folder_name.replace('_', '').lower()
                    if folder_norm == service_norm:
                        test_path = os.path.join(folder_path, "rules", f"{folder_name}.yaml")
                        if os.path.exists(test_path):
                            rules_path = test_path
                            break
    
    if not rules_path:
        raise FileNotFoundError(f"Service rules not found for '{service_name}'. Tried: {possible_names}")
    
    with open(rules_path) as f:
        rules = yaml.safe_load(f)
    
    base_rules = normalize_to_phase2_format(rules)

    # Optionally merge user-defined rules (synced into the pod by sidecar)
    # Expected layout: {USER_RULES_DIR}/{service}/{service}.yaml (e.g., /user-rules/s3/s3.yaml)
    user_rules_dir = os.getenv("USER_RULES_DIR")
    if user_rules_dir:
        try:
            user_path = os.path.join(user_rules_dir, service_name, f"{service_name}.yaml")
            if os.path.exists(user_path):
                with open(user_path) as uf:
                    user_rules_raw = yaml.safe_load(uf)
                user_rules = normalize_to_phase2_format(user_rules_raw)
                base_rules = merge_service_rules(base_rules, user_rules)
        except Exception as e:
            logger.warning(f"Failed to load user rules for {service_name}: {e}")

    return base_rules


def merge_service_rules(base_rules: Dict[str, Any], user_rules: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge two Phase-2 service rule documents.
    - Discovery: de-dupe by discovery_id (prefer base definition on conflict)
    - Checks: merge by rule_id (user overrides base on conflict)
    """
    if not base_rules:
        return user_rules or base_rules
    if not user_rules:
        return base_rules

    merged = dict(base_rules)

    # Merge discovery
    base_discovery = merged.get("discovery") or []
    user_discovery = user_rules.get("discovery") or []
    disc_by_id = {d.get("discovery_id"): d for d in base_discovery if isinstance(d, dict) and d.get("discovery_id")}
    for d in user_discovery:
        if not isinstance(d, dict):
            continue
        did = d.get("discovery_id")
        if not did:
            continue
        if did not in disc_by_id:
            disc_by_id[did] = d
        else:
            # Keep base discovery on conflict to avoid user rules changing scan semantics
            pass
    merged["discovery"] = list(disc_by_id.values())

    # Merge checks
    base_checks = merged.get("checks") or []
    user_checks = user_rules.get("checks") or []
    checks_by_id = {c.get("rule_id"): c for c in base_checks if isinstance(c, dict) and c.get("rule_id")}
    base_order = [c.get("rule_id") for c in base_checks if isinstance(c, dict) and c.get("rule_id")]
    for c in user_checks:
        if not isinstance(c, dict):
            continue
        rid = c.get("rule_id")
        if not rid:
            continue
        checks_by_id[rid] = c  # user overrides
        if rid not in base_order:
            base_order.append(rid)
    merged["checks"] = [checks_by_id[rid] for rid in base_order if rid in checks_by_id]

    return merged

def convert_assert_to_conditions(assertion):
    """
    Convert Phase 3 assert to Phase 2 conditions
    
    Examples:
      assert: item.exists → {var: item.exists, op: exists}
      assert: {item.status: ACTIVE} → {var: item.status, op: equals, value: ACTIVE}
    """
    if isinstance(assertion, str):
        # Simple assertion: assert: item.exists
        return {'var': assertion, 'op': 'exists'}
    
    elif isinstance(assertion, dict):
        # Dict assertion: assert: {item.status: ACTIVE}
        # Take first key-value pair
        for var, value in assertion.items():
            return {'var': var, 'op': 'equals', 'value': value}
    
    # Fallback - return as-is
    return assertion

def convert_phase3_to_phase2(rules):
    """
    Convert Phase 3 ultra-simplified format to Phase 2 format
    
    Phase 3 format:
      service: account
      resources:
        alternate_contacts:
          actions:
          - get_alternate_contact: {AlternateContactType: SECURITY}
      checks:
        contact.configured:
          resource: alternate_contacts
          assert: item.exists
    
    Phase 2 format:
      service: account
      discovery:
      - discovery_id: aws.account.alternate_contacts
        calls:
        - action: get_alternate_contact
          params: {AlternateContactType: SECURITY}
      checks:
      - rule_id: aws.account.contact.configured
        for_each: aws.account.alternate_contacts
        conditions: {var: item.exists, op: exists}
    """
    service_name = rules.get('service', 'unknown')
    
    normalized = {
        'version': rules.get('version', '1.0'),
        'provider': rules.get('provider', 'aws'),
        'service': service_name
    }
    
    # Convert resources to discovery
    if 'resources' in rules:
        discoveries = []
        
        for resource_name, resource_def in rules['resources'].items():
            discovery_id = f'aws.{service_name}.{resource_name}'
            
            calls = []
            emit = None
            
            # Handle different resource definition formats
            if isinstance(resource_def, dict):
                # Extract emit if present at resource level
                if 'emit' in resource_def:
                    emit = resource_def['emit']
                
                # Handle 'actions' list (multiple actions)
                if 'actions' in resource_def:
                    for action_item in resource_def['actions']:
                        if isinstance(action_item, dict):
                            # {action_name: params_dict}
                            for action_name, params in action_item.items():
                                call = {'action': action_name}
                                if params and isinstance(params, dict):
                                    # Check if params are at top level or nested
                                    if 'params' in params:
                                        call['params'] = params['params']
                                    else:
                                        call['params'] = params
                                calls.append(call)
                        elif isinstance(action_item, str):
                            # Just action name
                            calls.append({'action': action_item})
                
                # Handle single action format: {action_name: {...}}
                else:
                    for key, value in resource_def.items():
                        if key != 'emit':
                            # This is an action
                            call = {'action': key}
                            if isinstance(value, dict):
                                if 'params' in value:
                                    call['params'] = value['params']
                                elif value:
                                    # Top-level dict is the params
                                    call['params'] = value
                                if 'extract' in value:
                                    call['fields'] = value['extract'] if isinstance(value['extract'], list) else [value['extract']]
                                if 'emit' in value:
                                    emit = value['emit']
                            calls.append(call)
            
            # Create discovery entry
            discovery = {
                'discovery_id': discovery_id,
                'calls': calls
            }
            
            if emit:
                discovery['emit'] = emit
            
            discoveries.append(discovery)
        
        normalized['discovery'] = discoveries
    
    # Copy discovery section if exists (Phase 2 format)
    elif 'discovery' in rules:
        normalized['discovery'] = rules['discovery']
    
    # Convert checks
    if 'checks' in rules:
        checks_list = []
        
        # Phase 3 format: checks is a dict
        if isinstance(rules['checks'], dict):
            for check_name, check_def in rules['checks'].items():
                rule_id = f'aws.{service_name}.{check_name}'
                
                check_entry = {
                    'rule_id': rule_id
                }
                
                # Convert resource reference to for_each
                if 'resource' in check_def:
                    resource_ref = check_def['resource']
                    check_entry['for_each'] = f'aws.{service_name}.{resource_ref}'
                
                # Convert assert to conditions
                if 'assert' in check_def:
                    check_entry['conditions'] = convert_assert_to_conditions(check_def['assert'])
                elif 'conditions' in check_def:
                    check_entry['conditions'] = check_def['conditions']
                
                # Copy other fields
                for key in ['params', 'assertion_id']:
                    if key in check_def:
                        check_entry[key] = check_def[key]
                
                checks_list.append(check_entry)
        
        # Phase 2 format: checks is a list
        elif isinstance(rules['checks'], list):
            checks_list = rules['checks']
        
        normalized['checks'] = checks_list
    
    return normalized

def normalize_to_phase2_format(rules):
    """
    Detect YAML format version and normalize to Phase 2 format for processing
    
    Supports:
    - Phase 2: discovery/checks (current) - returns as-is
    - Phase 3: resources/checks (ultra-simplified) - converts to Phase 2
    """
    if not rules:
        return rules
    
    # Detect format version
    if 'resources' in rules:
        # Phase 3 format - needs conversion
        logger.debug(f"Detected Phase 3 format, converting to Phase 2")
        return convert_phase3_to_phase2(rules)
    else:
        # Phase 2 or earlier - return as-is
        logger.debug(f"Detected Phase 2 format, using directly")
        return rules

def _is_expected_aws_error(error: Exception) -> bool:
    """
    Check if an AWS error is an expected error (like NoSuchBucketPolicy, NoSuchCORSConfiguration, etc.)
    These are normal when optional configurations don't exist, so we shouldn't log warnings for them.
    """
    if not isinstance(error, ClientError):
        return False
    
    error_code = error.response.get('Error', {}).get('Code', '') if hasattr(error, 'response') else ''
    
    # Common expected error patterns for missing optional configurations
    expected_patterns = [
        'NoSuch',          # NoSuchBucketPolicy, NoSuchCORSConfiguration, NoSuchLifecycleConfiguration
        'NotFound',        # ObjectLockConfigurationNotFoundError
        'MissingParameter', # MissingParameter for optional params
    ]
    
    return any(pattern in error_code for pattern in expected_patterns)

def _is_permanent_error(e: Exception) -> bool:
    """Return True for errors that should never be retried (fail fast).

    Checks both:
    - Exception class name  (botocore raises typed exceptions)
    - String representation (catch-all for wrapped or unknown types)
    """
    err_type = type(e).__name__
    err_str = str(e)

    # ── Boto3 / botocore typed exceptions ──────────────────────────────────
    # EndpointConnectionError  : service not available in this region
    # ConnectTimeoutError      : connect timeout (already short via BOTO_CONNECT_TIMEOUT)
    # ReadTimeoutError         : read timeout (already short via BOTO_READ_TIMEOUT)
    if err_type in ('EndpointConnectionError', 'ConnectTimeoutError', 'ReadTimeoutError'):
        return True

    # ── String-based checks (covers ClientError payloads + wrapped errors) ─
    # Boto3 parameter validation - bad call signature, not a transient issue
    if 'Parameter validation failed' in err_str:
        return True
    # Unknown/invalid parameter names - same as above
    if 'Unknown parameter in input' in err_str:
        return True
    # Access denied / auth - retrying won't help
    if 'AccessDenied' in err_str or 'AuthFailure' in err_str:
        return True
    # Service not available in this region - endpoint doesn't exist
    if 'Could not connect to the endpoint URL' in err_str:
        return True
    # Botocore EndpointConnectionError message form
    if 'Could not connect to the endpoint' in err_str:
        return True
    # InvalidClientTokenId - credentials issue
    if 'InvalidClientTokenId' in err_str:
        return True
    return False

def _retry_call(func, *args, **kwargs):
    for attempt in range(MAX_RETRIES):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            # Don't retry expected AWS errors (NoSuch*, NotFound, MissingParameter)
            # These are normal when optional configurations don't exist
            if _is_expected_aws_error(e):
                logger.debug(f"Skipping retry for expected error: {e}")
                raise  # Re-raise immediately without retrying

            # Don't retry permanent errors (bad params, auth, unavailable endpoints)
            if _is_permanent_error(e):
                logger.debug(f"Skipping retry for permanent error: {type(e).__name__}: {str(e)[:120]}")
                raise  # Re-raise immediately without retrying

            # Check if this is a throttling error - use longer delays
            error_code = ''
            error_message = str(e).lower()
            if hasattr(e, 'response'):
                error_code = e.response.get('Error', {}).get('Code', '') if hasattr(e, 'response') else ''

            is_throttling = (
                'ThrottlingException' in str(type(e).__name__) or
                'ThrottlingException' in error_code or
                'throttling' in error_message or
                'rate exceeded' in error_message
            )

            if attempt == MAX_RETRIES - 1:
                raise

            # Use longer delay for throttling errors (exponential backoff with higher multiplier)
            if is_throttling:
                delay = max(BASE_DELAY * 2, BASE_DELAY * (BACKOFF_FACTOR ** attempt) * 2)
                logger.debug(f"Throttling detected, using longer delay: {delay:.2f}s (attempt {attempt+1}/{MAX_RETRIES})")
            else:
                delay = BASE_DELAY * (BACKOFF_FACTOR ** attempt)
                logger.debug(f"Retrying after error: {e} (attempt {attempt+1}/{MAX_RETRIES}, sleep {delay:.2f}s)")

            sleep(delay)

def _call_with_timeout(client, action: str, params: Dict[str, Any], timeout: int = OPERATION_TIMEOUT) -> Dict[str, Any]:
    """
    Make API call with timeout protection for non-paginated operations.

    Args:
        client: Boto3 client
        action: API action name (camelCase or snake_case)
        params: API parameters
        timeout: Maximum time in seconds (default: OPERATION_TIMEOUT)

    Returns:
        API response dict

    Raises:
        TimeoutError: If operation exceeds timeout
    """
    import time
    from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError

    action = _normalize_action(action)
    start_time = time.time()

    def _make_call():
        return _retry_call(getattr(client, action), **params)
    
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_make_call)
            result = future.result(timeout=timeout)
            
            elapsed = time.time() - start_time
            if elapsed > 60:  # Log slow operations
                logger.info(f"Slow operation {action}: {elapsed:.1f}s")
            
            return result
            
    except FutureTimeoutError:
        elapsed = time.time() - start_time
        logger.error(f"{action} timed out after {timeout}s (elapsed: {elapsed:.1f}s)")
        raise TimeoutError(f"{action} exceeded {timeout}s timeout")


def _paginate_api_call(client, action: str, params: Dict[str, Any], 
                       discovery_config: Optional[Dict] = None,
                       max_pages: int = 100,
                       operation_timeout: int = OPERATION_TIMEOUT) -> Dict[str, Any]:
    """
    Robust pagination with multiple safeguards against stuck cases.
    
    Uses boto3 paginators when available (AWS-recommended), with fallbacks.
    Includes timeout protection, circular token detection, and item limits.
    
    Args:
        client: Boto3 client
        action: API action name (e.g., 'describe_snapshots')
        params: API parameters (MaxResults sets page size, not total limit)
        discovery_config: Optional discovery config from YAML (with pagination metadata)
        max_pages: Maximum number of pages (safety limit)
        operation_timeout: Maximum time per operation in seconds
    
    Returns:
        Combined response dict with all items from all pages
    """
    import time
    from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError

    action = _normalize_action(action)
    start_time = time.time()
    service_name = client.meta.service_model.service_name

    def _execute_pagination():
        # Layer 1: Check if boto3 paginator is available (most reliable)
        try:
            if client.can_paginate(action):
                # Use boto3 paginator (AWS-recommended)
                paginator = client.get_paginator(action)
                
                # Auto-add MaxResults for page size optimization if not specified
                has_max_results = any(k.lower() in ['maxresults', 'maxrecords', 'limit', 'maxitems'] 
                                     for k in params.keys())
                
                if not has_max_results:
                    # Service-specific optimal page sizes
                    if service_name == 'sagemaker':
                        default_page_size = 100
                    elif service_name in ['cognito-idp', 'cognito']:
                        default_page_size = 60
                    elif service_name == 'kafka':
                        default_page_size = 100
                    else:
                        default_page_size = 1000
                    
                    params['MaxResults'] = default_page_size
                    logger.debug(f"Auto-added MaxResults={default_page_size} for {action} (service: {service_name})")
                
                # Use PaginationConfig for explicit control
                page_size = params.get('MaxResults', 1000)
                pagination_config = {
                    'PageSize': min(page_size, 1000),  # Cap at 1000
                    'MaxItems': None  # No total limit - get all pages
                }
                
                # Remove MaxResults from params (PaginationConfig handles it)
                page_params = {k: v for k, v in params.items() 
                              if k not in ['MaxResults', 'MaxRecords', 'Limit', 'MaxItems']}
                
                page_iterator = paginator.paginate(**page_params, PaginationConfig=pagination_config)
                
                # Collect all pages with safeguards
                all_items = []
                result_array_key = None
                first_page = None
                page_count = 0
                seen_tokens = set()
                total_items = 0
                
                for page in page_iterator:
                    if first_page is None:
                        first_page = page
                        # Auto-detect result array
                        for key, value in page.items():
                            if isinstance(value, list) and key not in ['NextToken', 'Marker', 'NextMarker', 'ContinuationToken']:
                                result_array_key = key
                                all_items.extend(value)
                                total_items += len(value)
                                break
                    else:
                        if result_array_key and result_array_key in page:
                            items = page[result_array_key]
                            all_items.extend(items)
                            total_items += len(items)
                    
                    # Safeguards
                    current_token = page.get('NextToken') or page.get('Marker')
                    if current_token:
                        if current_token in seen_tokens:
                            logger.error(f"Circular pagination token detected for {action} - breaking")
                            break
                        seen_tokens.add(current_token)
                    
                    page_count += 1
                    if page_count >= max_pages:
                        logger.error(f"Hit max pages limit ({max_pages}) for {action} - possible infinite loop")
                        break
                    
                    if total_items > MAX_ITEMS_PER_DISCOVERY:
                        logger.warning(
                            f"{action} returned {total_items} items (limit: {MAX_ITEMS_PER_DISCOVERY}). "
                            f"Consider using Filters to reduce result set."
                        )
                        break
                
                if first_page and result_array_key:
                    combined = first_page.copy()
                    combined[result_array_key] = all_items
                    # Remove pagination tokens
                    for token in ['NextToken', 'Marker', 'NextMarker', 'ContinuationToken']:
                        combined.pop(token, None)
                    
                    if page_count > 1:
                        logger.debug(f"Paginated {action}: {page_count} pages, {total_items} items")
                    return combined
                
                return first_page if first_page else {}
                
        except (ValueError, AttributeError) as e:
            # Paginator doesn't exist - check for manual pagination
            logger.debug(f"Paginator not available for {action}: {e}")
            
            # Layer 2: Try manual pagination (check for tokens in first response)
            first_response = _retry_call(getattr(client, action), **params)
            
            # Check if response has pagination tokens
            pagination_tokens = ['NextToken', 'Marker', 'NextMarker', 'ContinuationToken']
            has_token = any(token in first_response for token in pagination_tokens)
            
            if not has_token:
                # No pagination - single call complete
                return first_response
            
            # Manual pagination needed
            return _manual_paginate_with_token(client, action, params, first_response, max_pages)
        
        except Exception as e:
            logger.debug(f"Pagination error for {action}, using single call: {e}")
            # Fallback: single call with timeout
            return _call_with_timeout(client, action, params, timeout=300)
    
    # Execute with operation-level timeout
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_execute_pagination)
            result = future.result(timeout=operation_timeout)
            
            elapsed = time.time() - start_time
            if elapsed > 300:  # More than 5 minutes
                logger.warning(
                    f"{action} took {elapsed/60:.1f} minutes. "
                    f"Consider optimizing with Filters or reducing scope."
                )
            
            return result
            
    except FutureTimeoutError:
        elapsed = time.time() - start_time
        logger.error(
            f"{action} exceeded {operation_timeout}s timeout after {elapsed:.1f}s. "
            f"This operation may be stuck or returning too many results."
        )
        raise TimeoutError(f"{action} exceeded {operation_timeout}s timeout")


def _manual_paginate_with_token(client, action: str, params: Dict[str, Any], 
                                first_response: Dict[str, Any], max_pages: int = 100) -> Dict[str, Any]:
    """
    Manual pagination using NextToken/Marker tokens.
    
    Args:
        client: Boto3 client
        action: API action name
        params: API parameters
        first_response: First page response
        max_pages: Maximum pages to fetch
    
    Returns:
        Combined response with all pages
    """
    pagination_tokens = ['NextToken', 'Marker', 'NextMarker', 'ContinuationToken']
    result_arrays = ['Snapshots', 'Images', 'Volumes', 'Instances', 'Buckets', 
                     'Policies', 'Roles', 'Users', 'Groups', 'Functions', 'Tables',
                     'Queues', 'Topics', 'Subscriptions', 'Clusters', 'Streams',
                     'Keys', 'Aliases', 'Grants', 'Secrets', 'Domains', 'Zones',
                     'Distributions', 'Items', 'Results', 'Resources']
    
    # Find result array
    result_array_key = None
    for key in result_arrays:
        if key in first_response and isinstance(first_response[key], list):
            result_array_key = key
            break
    
    if not result_array_key:
        for key, value in first_response.items():
            if isinstance(value, list) and key not in pagination_tokens:
                result_array_key = key
                break
    
    if not result_array_key:
        return first_response
    
    all_items = list(first_response[result_array_key])
    seen_tokens = set()
    page_count = 0
    original_params = params.copy()
    
    # Find pagination token
    token_field = None
    next_token = None
    for token_key in pagination_tokens:
        if token_key in first_response and first_response[token_key]:
            next_token = first_response[token_key]
            token_field = token_key
            break
    
    # Paginate
    while next_token and page_count < max_pages:
        if next_token in seen_tokens:
            logger.error(f"Circular pagination token detected for {action} - breaking")
            break
        seen_tokens.add(next_token)
        
        page_params = original_params.copy()
        page_params[token_field] = next_token
        
        try:
            page_response = _retry_call(getattr(client, action), **page_params)
            
            if result_array_key in page_response:
                all_items.extend(page_response[result_array_key])
            
            next_token = page_response.get(token_field)
            page_count += 1
            
            if not next_token:
                break
                
        except Exception as e:
            logger.warning(f"Pagination stopped at page {page_count + 1} for {action}: {e}")
            break
    
    combined = first_response.copy()
    combined[result_array_key] = all_items
    for token_key in pagination_tokens:
        combined.pop(token_key, None)
    
    if page_count > 0:
        logger.debug(f"Manual pagination {action}: {page_count + 1} pages, {len(all_items)} items")
    
    return combined
    # Common pagination token field names across AWS services
    pagination_tokens = ['NextToken', 'Marker', 'NextMarker', 'ContinuationToken']
    # Common result array field names (service-specific)
    result_arrays = ['Snapshots', 'Images', 'Volumes', 'Instances', 'Buckets', 
                     'Policies', 'Roles', 'Users', 'Groups', 'Functions', 'Tables',
                     'Queues', 'Topics', 'Subscriptions', 'Clusters', 'Streams',
                     'Keys', 'Aliases', 'Grants', 'Secrets', 'Domains', 'Zones',
                     'Distributions', 'Items', 'Results', 'Resources']
    
    all_items = []
    next_token = None
    seen_tokens = set()  # Prevent circular references
    page_count = 0
    original_params = params.copy()
    
    # Determine which field contains the result array
    # Try first API call to see response structure
    first_response = _retry_call(getattr(client, action), **original_params)
    
    # Find the result array field
    result_array_key = None
    for key in result_arrays:
        if key in first_response and isinstance(first_response[key], list):
            result_array_key = key
            break
    
    # If no standard field found, try to find any list field
    if not result_array_key:
        for key, value in first_response.items():
            if isinstance(value, list) and key not in pagination_tokens:
                result_array_key = key
                break
    
    if result_array_key:
        all_items.extend(first_response[result_array_key])
    else:
        # If no array found, return first response as-is (no pagination needed)
        return first_response
    
    # Check for pagination token in first response
    token_field_used = None
    for token_key in pagination_tokens:
        if token_key in first_response and first_response[token_key]:
            next_token = first_response[token_key]
            token_field_used = token_key
            break
    
    # Paginate if there's a next token
    while next_token and page_count < max_pages:
        if next_token in seen_tokens:
            logger.warning(f"Circular pagination token detected for {action} - breaking pagination")
            break
        seen_tokens.add(next_token)
        
        # Add pagination token to params
        page_params = original_params.copy()
        # Use the token field we identified from first response
        if token_field_used:
            page_params[token_field_used] = next_token
        else:
            # Fallback: try common token names
            for token_key in pagination_tokens:
                if token_key in first_response:
                    page_params[token_key] = next_token
                    token_field_used = token_key
                    break
        
        try:
            page_response = _retry_call(getattr(client, action), **page_params)
            
            if result_array_key and result_array_key in page_response:
                all_items.extend(page_response[result_array_key])
            
            # Check for next page (use same token field as first response)
            next_token = None
            if token_field_used and token_field_used in page_response:
                next_token = page_response[token_field_used]
            else:
                # Fallback: check all token fields
                for token_key in pagination_tokens:
                    if token_key in page_response and page_response[token_key]:
                        next_token = page_response[token_key]
                        token_field_used = token_key
                        break
            
            page_count += 1
            
            # If no more pages, break
            if not next_token:
                break
                
        except Exception as e:
            logger.warning(f"Pagination stopped at page {page_count + 1} for {action}: {e}")
            break
    
    # Build combined response
    combined_response = first_response.copy()
    if result_array_key:
        combined_response[result_array_key] = all_items
    # Remove pagination tokens from final response
    for token_key in pagination_tokens:
        combined_response.pop(token_key, None)
    
    if page_count > 0:
        logger.debug(f"Paginated {action}: {page_count + 1} pages, {len(all_items)} total items")
    
    return combined_response

def _build_dependency_graph(discoveries: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Build complete dependency graph with multi-level support.
    
    Returns:
    {
        'independent': [disc1, disc2, ...],  # Discoveries with no for_each
        'dependent_groups': {
            'source_disc_id': [dependent1, dependent2, ...],  # Direct dependents only (backward compat)
            ...
        },
        'dependency_tree': {
            'independent_id': {
                'direct_dependents': [dep1, dep2, ...],
                'all_dependents': [dep1, dep2, dep3, ...],  # Direct + indirect
                'enrichment_order': [deepest_dep, ..., dep1, dep2]  # Topological order
            }
        },
        'dependency_map': {
            'discovery_id': 'depends_on_id'  # Maps each discovery to what it depends on
        }
    }
    """
    independent = []
    dependent_by_source = {}
    dependency_map = {}  # Maps discovery_id -> what it depends on
    discovery_by_id = {}  # Maps discovery_id -> discovery config
    
    # First pass: identify all discoveries and their dependencies
    for disc in discoveries:
        discovery_id = disc.get('discovery_id')
        if not discovery_id:
            continue
        
        discovery_by_id[discovery_id] = disc
        
        # Check for for_each at discovery level or call level
        for_each = disc.get('for_each')
        if not for_each:
            # Check call level
            for call in disc.get('calls', []):
                for_each = call.get('for_each')
                if for_each:
                    break
        
        if not for_each:
            # Independent discovery - no dependencies
            independent.append(disc)
            dependency_map[discovery_id] = None
        else:
            # Dependent discovery - extract source discovery ID
            items_ref = for_each.replace('{{ ', '').replace(' }}', '')
            dependency_map[discovery_id] = items_ref
            
            # Build backward compatibility structure
            if items_ref not in dependent_by_source:
                dependent_by_source[items_ref] = []
            dependent_by_source[items_ref].append(disc)
    
    # Build complete dependency tree for each independent discovery
    dependency_tree = {}
    
    def _resolve_dependency_chain(discovery_id: str, visited: set = None) -> List[str]:
        """
        Recursively find all dependents (direct + indirect) for a discovery.
        Returns list ordered from deepest to shallowest (topological order).
        """
        if visited is None:
            visited = set()
        
        if discovery_id in visited:
            # Circular dependency detected
            logger.warning(f"Circular dependency detected involving {discovery_id}")
            return []
        
        visited.add(discovery_id)
        all_dependents = []
        
        # Get direct dependents
        direct_dependents = dependent_by_source.get(discovery_id, [])
        
        for dep_disc in direct_dependents:
            dep_id = dep_disc.get('discovery_id')
            if not dep_id:
                continue
            
            # Recursively get dependents of this dependent (multi-level)
            nested_dependents = _resolve_dependency_chain(dep_id, visited.copy())
            
            # Add nested dependents first (deepest first)
            all_dependents.extend(nested_dependents)
            
            # Then add this dependent
            if dep_id not in all_dependents:
                all_dependents.append(dep_id)
        
        return all_dependents
    
    # Build dependency tree for each independent discovery
    for indep_disc in independent:
        indep_id = indep_disc.get('discovery_id')
        if not indep_id:
            continue
        
        direct_dependents = [d.get('discovery_id') for d in dependent_by_source.get(indep_id, [])]
        all_dependents = _resolve_dependency_chain(indep_id)
        
        # Enrichment order is already topological (deepest first) from _resolve_dependency_chain
        dependency_tree[indep_id] = {
            'direct_dependents': direct_dependents,
            'all_dependents': all_dependents,
            'enrichment_order': all_dependents  # Already in correct order (deepest first)
        }
    
    return {
        'independent': independent,
        'dependent_groups': dependent_by_source,  # Backward compatibility
        'dependency_tree': dependency_tree,
        'dependency_map': dependency_map,
        'discovery_by_id': discovery_by_id
    }

def _enrich_inventory_with_dependent_discoveries(
    discovery_results: Dict[str, List[Dict]],
    service_rules: Dict[str, Any],
    dependency_graph: Dict[str, Any]
) -> Dict[str, List[Dict]]:
    """
    Enrich inventory by merging dependent discovery results into independent discovery items.
    Supports multi-level dependencies (dependent → dependent → independent).
    
    Strategy:
    1. Independent discoveries create base inventory items with standard template fields
    2. Dependent discoveries enrich these items by adding their fields
    3. Multi-level: Dependent discoveries can enrich other dependent discoveries first
    4. Enrichment happens in topological order (deepest → independent)
    5. Preserve standard fields (resource_arn, resource_id, resource_type, name, tags)
    6. Add dependent fields as additional top-level fields (enrichment)
    
    This function does NOT modify checks or scan collection - only enriches inventory data.
    
    Args:
        discovery_results: Dictionary of discovery_id -> emitted items
        service_rules: Service rules YAML containing discovery configs
        dependency_graph: Dependency graph from _build_dependency_graph()
    
    Returns:
        Enriched discovery_results with dependent data merged into independent items
    """
    from common.utils.reporting_manager import is_cspm_inventory_resource
    
    # CRITICAL: Use deep copy to avoid modifying original discovery_results
    # But we need to modify items in place, so we'll do a shallow copy of the dict
    # but ensure we're modifying the same list objects
    enriched_results = discovery_results.copy()  # Shallow copy - lists are shared references
    dependency_tree = dependency_graph.get('dependency_tree', {})
    dependent_groups = dependency_graph.get('dependent_groups', {})  # Fallback for backward compat
    discovery_by_id = dependency_graph.get('discovery_by_id', {})
    
    # Standard template fields that should NOT be overwritten by dependent discoveries
    PROTECTED_FIELDS = {
        'resource_arn', 'resource_id', 'resource_type', 'resource_name', 
        'resource_uid', 'name', 'tags', 'Name'  # Name is matching key but also protected
    }
    
    # Match keys vary by service - try common patterns
    # Order matters: try most specific first, then fall back to generic
    def _merge_dependent_data(source_items: List[Dict], target_items: List[Dict], 
                              dependent_id: str, target_id: str) -> int:
        """
        Merge dependent discovery data into target items using ARN-based matching.
        Returns number of items successfully enriched.
        """
        if not source_items or not target_items:
            return 0
        
        matched_count = 0
        for target_item in target_items:
            # Debug: Log ARN availability for first few items
            if matched_count < 2:
                target_arn = target_item.get('resource_arn')
                if target_arn:
                    logger.info(f"[MATCH-DEBUG] {dependent_id} -> {target_id}: Target item has resource_arn: {target_arn[:80]}")
                else:
                    logger.warning(f"[MATCH-DEBUG] {dependent_id} -> {target_id}: Target item has NO resource_arn! Available keys: {list(target_item.keys())[:15]}")
            
            # Use ARN-based matching (universal across all services)
            # For items_for discoveries, there may be multiple source items per target (e.g., multiple policies per user)
            # Collect ALL matching items, not just the first one
            target_arn = target_item.get('resource_arn')
            if not target_arn:
                target_arn_str = 'N/A'
                logger.debug(f"No match for item ARN: {target_arn_str[:80]} (no ARN in target)")
                continue
            
            # Find ALL source items that match this target ARN
            matching_sources = []
            for source_item in source_items:
                source_arn = source_item.get('resource_arn')
                if source_arn and source_arn == target_arn:
                    matching_sources.append(source_item)
            
            if matching_sources:
                matched_count += 1
                target_arn_str = target_arn[:80]
                logger.debug(f"Matched {len(matching_sources)} item(s) by ARN: {target_arn_str} with {dependent_id}")
                
                # Extract discovery name from dependent_id (e.g., "aws.s3.get_bucket_versioning" -> "get_bucket_versioning")
                discovery_name = dependent_id.split('.')[-1] if '.' in dependent_id else dependent_id
                
                # Handle multiple matches (items_for case) vs single match (bundle case)
                if len(matching_sources) == 1:
                    # Single match - could be bundle approach or single item
                    matched_source = matching_sources[0]
                    dependent_data = {}
                    if discovery_name in matched_source and isinstance(matched_source[discovery_name], dict):
                        # Bundle approach: entire response is stored under discovery_name
                        dependent_data = matched_source[discovery_name]
                        logger.debug(f"Using entire response from {discovery_name} ({len(dependent_data)} fields)")
                    else:
                        # items_for or individual fields: extract all non-protected fields
                        for key, value in matched_source.items():
                            if key in PROTECTED_FIELDS or key == 'resource_arn':
                                continue
                            if value is None or (isinstance(value, str) and (value == '' or value == '[]')):
                                continue
                            dependent_data[key] = value
                else:
                    # Multiple matches - items_for case (e.g., multiple policies per user)
                    # Collect all items into a list
                    dependent_data_list = []
                    for matched_source in matching_sources:
                        item_data = {}
                        # Extract all non-protected fields from each matched item
                        for key, value in matched_source.items():
                            if key in PROTECTED_FIELDS or key == 'resource_arn':
                                continue
                            if value is None or (isinstance(value, str) and (value == '' or value == '[]')):
                                continue
                            item_data[key] = value
                        if item_data:  # Only add non-empty items
                            dependent_data_list.append(item_data)
                    
                    # Store as list if multiple items, or as single dict if one item
                    if len(dependent_data_list) == 1:
                        dependent_data = dependent_data_list[0]
                    elif len(dependent_data_list) > 1:
                        dependent_data = {'items': dependent_data_list, 'count': len(dependent_data_list)}
                    else:
                        dependent_data = {}
                    
                    logger.debug(f"Collected {len(matching_sources)} items from {discovery_name} into {len(dependent_data_list)} enriched items")
                
                # Store dependent discovery data under discovery name (nested approach)
                # Always store, even if empty, to track which discoveries were attempted
                if '_dependent_data' not in target_item:
                    target_item['_dependent_data'] = {}
                target_item['_dependent_data'][discovery_name] = dependent_data
                if dependent_data:
                    if isinstance(dependent_data, dict) and 'count' in dependent_data:
                        logger.debug(f"Enriched ARN {target_arn_str} with {discovery_name}: {dependent_data['count']} items")
                    else:
                        logger.debug(f"Enriched ARN {target_arn_str} with {discovery_name}: {len(dependent_data) if isinstance(dependent_data, dict) else 1} fields")
                else:
                    logger.debug(f"No data to enrich for ARN {target_arn_str} from {discovery_name} (all fields skipped or empty)")
                
                # Track which dependent discovery enriched this item (for backward compatibility)
                if '_enriched_from' not in target_item:
                    target_item['_enriched_from'] = []
                if dependent_id not in target_item['_enriched_from']:
                    target_item['_enriched_from'].append(dependent_id)
            else:
                target_arn_str = target_arn[:80]
                logger.debug(f"No match for item ARN: {target_arn_str} (ARN-based matching)")
        
        return matched_count
    
    # For each independent discovery that's an inventory resource
    for independent_disc in dependency_graph.get('independent', []):
        independent_id = independent_disc.get('discovery_id')
        if not independent_id:
            continue
        
        # Check if this independent discovery is an inventory resource
        if not is_cspm_inventory_resource(independent_id, discovery_config=independent_disc):
            continue
        
        independent_items = enriched_results.get(independent_id, [])
        if not independent_items:
            continue
        
        # Get dependency tree entry for this independent discovery
        tree_entry = dependency_tree.get(independent_id)
        
        if tree_entry:
            # Use new dependency tree structure (supports multi-level)
            all_dependents = tree_entry.get('all_dependents', [])
            enrichment_order = tree_entry.get('enrichment_order', [])
            
            if not all_dependents:
                continue
            
            logger.info(f"Enriching {independent_id} with {len(all_dependents)} dependent discoveries (multi-level support)")
            
            # Track which dependent discoveries enriched each item (for metadata)
            for independent_item in independent_items:
                if '_enriched_from' not in independent_item:
                    independent_item['_enriched_from'] = []
            
            # Enrich in topological order (deepest dependent → independent)
            # Strategy: Each dependent enriches the items it depends on (which may be another dependent or independent)
            # By processing deepest first, when we enrich a dependent, its nested dependents have already enriched it
            dependency_map = dependency_graph.get('dependency_map', {})
            
            for dependent_id in enrichment_order:
                dependent_disc = discovery_by_id.get(dependent_id)
                if not dependent_disc:
                    continue
                
                dependent_items = enriched_results.get(dependent_id, [])
                if not dependent_items:
                    logger.debug(f"No items found for dependent discovery {dependent_id}")
                    continue
                
                # Find what this dependent depends on
                depends_on = dependency_map.get(dependent_id)
                
                if not depends_on:
                    # Shouldn't happen, but skip if no dependency
                    continue
                
                # Get the target items to enrich (could be another dependent or the independent)
                if depends_on == independent_id:
                    # Direct dependent of independent - enrich independent directly
                    target_items = independent_items
                    target_id = independent_id
                else:
                    # This dependent depends on another dependent - enrich that dependent
                    # This creates a chain: dependent2 enriches dependent1, then dependent1 enriches independent
                    target_items = enriched_results.get(depends_on, [])
                    target_id = depends_on
                
                if not target_items:
                    logger.debug(f"No target items found for {dependent_id} -> {target_id}")
                    continue
                
                # Merge this dependent's data into its target
                matched = _merge_dependent_data(dependent_items, target_items, dependent_id, target_id)
                if matched > 0:
                    logger.info(f"Merged {dependent_id} into {target_id}: {matched}/{len(target_items)} items enriched")
                else:
                    logger.debug(f"No matches found for {dependent_id} -> {target_id} (dependent_items={len(dependent_items)}, target_items={len(target_items)})")
            
            # After all dependents have enriched their targets, merge all enriched intermediate dependents into independent
            # This ensures that if dependent2 enriched dependent1, dependent1's enriched data (including dependent2's data) gets into independent
            for dependent_id in enrichment_order:
                depends_on = dependency_map.get(dependent_id)
                if depends_on and depends_on != independent_id:
                    # This dependent enriched an intermediate dependent, now merge that intermediate into independent
                    intermediate_items = enriched_results.get(depends_on, [])
                    if intermediate_items:
                        # Merge enriched intermediate into independent
                        matched = _merge_dependent_data(intermediate_items, independent_items, depends_on, independent_id)
                        if matched > 0:
                            logger.info(f"Merged enriched {depends_on} (contains {dependent_id} data) into {independent_id}: {matched}/{len(independent_items)} items enriched")
        else:
            # Fallback to old behavior (backward compatibility)
            dependent_discs = dependent_groups.get(independent_id, [])
            if not dependent_discs:
                continue
            
            logger.info(f"Enriching {independent_id} with {len(dependent_discs)} dependent discoveries (legacy mode)")
            
            # Track which dependent discoveries enriched each item (for metadata)
            for independent_item in independent_items:
                if '_enriched_from' not in independent_item:
                    independent_item['_enriched_from'] = []
            
            # For each dependent discovery, merge its results into independent items
            for dependent_disc in dependent_discs:
                dependent_id = dependent_disc.get('discovery_id')
                if not dependent_id:
                    continue
                
                dependent_items = enriched_results.get(dependent_id, [])
                if not dependent_items:
                    logger.info(f"No items found for dependent discovery {dependent_id}")
                    continue
                
                logger.info(f"Found {len(dependent_items)} items in {dependent_id}, {len(independent_items)} items in {independent_id}")
                if dependent_items and independent_items:
                    logger.info(f"Sample independent item: Name={independent_items[0].get('Name')}, name={independent_items[0].get('name')}, resource_name={independent_items[0].get('resource_name')}")
                    logger.info(f"Sample dependent item: Name={dependent_items[0].get('Name')}, name={dependent_items[0].get('name')}")
                
                matched = _merge_dependent_data(dependent_items, independent_items, dependent_id, independent_id)
                if matched > 0:
                    logger.info(f"Merged {dependent_id} into {independent_id}: {matched}/{len(independent_items)} items enriched")
                else:
                    logger.debug(f"No matches found for {dependent_id} -> {independent_id} (dependent_items={len(dependent_items)}, independent_items={len(independent_items)})")
    
    # Clean up temporary tracking field (or keep it in metadata if useful)
    # For now, we'll keep _enriched_from as it's useful for debugging/tracking
    
    # Debug: verify enriched fields are in results before returning
    for disc_id, items in enriched_results.items():
        if disc_id == 'aws.s3.list_buckets' and items:
            sample = items[0]
            enriched = [k for k in sample.keys() if k not in PROTECTED_FIELDS and k != 'resource_arn' and not k.startswith('_')]
            if enriched:
                logger.info(f"[ENRICH-FINAL] {disc_id} has enriched fields: {enriched[:5]}")
                logger.info(f"[ENRICH-FINAL] Sample item keys: {list(sample.keys())[:20]}")
            else:
                logger.warning(f"[ENRICH-FINAL] {disc_id} has NO enriched fields! Item keys: {list(sample.keys())[:20]}")
            break
    
    return enriched_results

def _resolve_check_dependencies(
    check_for_each: str,
    service_rules: Dict[str, Any],
    discovery_results: Dict[str, List[Dict]]
) -> Tuple[str, Optional[str]]:
    """
    Resolve check's for_each back to independent discovery by following dependency chain.
    Loops until we find an independent discovery (one with no for_each).
    
    Args:
        check_for_each: Check's for_each value (e.g., 'aws.s3.get_bucket_versioning')
        service_rules: Loaded service rules YAML
        discovery_results: Dictionary of discovery_id -> emitted items
    
    Returns:
        (independent_discovery_id, dependent_discovery_id)
        - If check_for_each is independent, returns (check_for_each, None)
        - If check_for_each is dependent, returns (independent_id, check_for_each)
        - If no dependency found or circular, returns (None, None)
    """
    visited = set()
    current = check_for_each
    
    # Follow dependency chain backwards until we find independent discovery
    while current:
        if current in visited:
            # Circular dependency detected
            logger.warning(f"Circular dependency detected in check for_each: {check_for_each}")
            return (None, None)
        visited.add(current)
        
        # Find discovery config for current
        discovery_config = None
        for disc in service_rules.get('discovery', []):
            if disc.get('discovery_id') == current:
                discovery_config = disc
                break
        
        if not discovery_config:
            # Discovery not found in config - treat as independent if it has results
            if current in discovery_results and discovery_results[current]:
                return (current, None)
            return (None, None)
        
        # Check if this discovery has for_each (is dependent)
        for_each = discovery_config.get('for_each')
        if not for_each:
            # Check call level
            for call in discovery_config.get('calls', []):
                for_each = call.get('for_each')
                if for_each:
                    break
        
        if not for_each:
            # Independent discovery found (no for_each at discovery or call level)
            if current == check_for_each:
                # Check's for_each is already independent
                return (current, None)
            else:
                # Found independent source - return it with the original dependent
                return (current, check_for_each)
        
        # Extract discovery_id from for_each (could be string or dict)
        if isinstance(for_each, dict):
            current = for_each.get('discovery')
        else:
            current = str(for_each)
    
    return (None, None)

def _match_items(
    primary_item: Dict,
    dependent_items: List[Dict],
    match_keys: List[str] = None  # Deprecated - now uses ARN only
) -> Optional[Dict]:
    """
    Match a primary item with a corresponding item in dependent discovery using ARN.
    
    ARN-based matching is universal across all AWS services and eliminates the need
    for service-specific matching keys.
    
    Args:
        primary_item: Item from independent discovery (e.g., bucket from list_buckets)
        dependent_items: Items from dependent discovery (e.g., items from get_bucket_versioning)
        match_keys: Deprecated - kept for backward compatibility but not used
    
    Returns:
        Matching item from dependent_items, or None if not found
    """
    # Use resource_arn as the universal matching key
    primary_arn = primary_item.get('resource_arn')
    if not primary_arn:
        logger.debug(f"No resource_arn in primary item, available keys: {list(primary_item.keys())[:10]}")
        return None
    
    for dep_item in dependent_items:
        dep_arn = dep_item.get('resource_arn')
        if dep_arn and dep_arn == primary_arn:
            return dep_item
    
    return None

def _run_single_check(
    check: Dict[str, Any],
    service_name: str,
    region: str,
    account_id: Optional[str],
    discovery_results: Dict[str, List[Dict]],
    service_rules: Dict[str, Any],
    primary_items: Optional[List[Dict]] = None
) -> List[Dict[str, Any]]:
    """
    Run a single check - can be executed in parallel with other checks.
    
    All checks share the same discovery_results (reference, not copy).
    Checks are independent - they only depend on discoveries, not each other.
    
    Args:
        check: Check configuration from YAML
        service_name: Service name (e.g., 'ec2')
        region: Region (or 'us-east-1' for global services)
        account_id: AWS account ID
        discovery_results: All discovery results (shared reference)
        service_rules: Service rules YAML (for dependency resolution)
        primary_items: Primary inventory items (fallback)
    
    Returns:
        List of check result records (one per item checked)
    """
    check_id = check['rule_id']
    title = check.get('title', '')
    severity = check.get('severity', 'medium')
    assertion_id = check.get('assertion_id', '')
    for_each = check.get('for_each')
    params = check.get('params', {})
    conditions = check.get('conditions', {})
    
    # Determine if this is an account-level check
    is_account_level_check = '.account.' in check_id or check_id.endswith('.account')
    
    # Get items to check - resolve dependencies to independent discovery
    if for_each and isinstance(for_each, dict):
        discovery_id = for_each.get('discovery')
        if discovery_id:
            independent_disc_id, dependent_disc_id = _resolve_check_dependencies(
                discovery_id, service_rules, discovery_results
            )
        else:
            independent_disc_id, dependent_disc_id = None, None
    elif for_each:
        independent_disc_id, dependent_disc_id = _resolve_check_dependencies(
            for_each, service_rules, discovery_results
        )
    else:
        independent_disc_id, dependent_disc_id = None, None
    
    # Build items list based on dependency resolution
    if independent_disc_id:
        primary_items_from_independent = discovery_results.get(independent_disc_id, [])
        
        if dependent_disc_id:
            dependent_items = discovery_results.get(dependent_disc_id, [])
            items = []
            
            for primary_item in primary_items_from_independent:
                matched_item = _match_items(primary_item, dependent_items)
                if matched_item:
                    combined_item = {**primary_item, **matched_item}
                    items.append(combined_item)
                else:
                    items.append(primary_item)
        else:
            items = primary_items_from_independent
    else:
        # Fall back to original for_each lookup
        if for_each and isinstance(for_each, dict):
            discovery_id = for_each.get('discovery')
            if discovery_id:
                items = discovery_results.get(discovery_id, [])
            elif discovery_results:
                first_discovery_id = list(discovery_results.keys())[0]
                items = discovery_results.get(first_discovery_id, [])
            else:
                items = [{}] if is_account_level_check else []
        elif for_each:
            items = discovery_results.get(for_each, [])
        else:
            items = [{}] if is_account_level_check else []
    
    # Fallback: if still no items and we have primary inventory, use that
    if (not items) and primary_items:
        items = primary_items
    
    # Only run checks if there are items (don't create checks for empty infrastructure)
    # Exception: Account-level checks run once even if no inventory items
    if not items:
        if is_account_level_check:
            items = [{}]
        else:
            return []  # Skip check if no resources found
    
    # Run check for each item
    check_results = []
    for item in items:
        context = {'item': item, 'params': params}
        
        # Evaluate conditions
        def eval_conditions(cond_config):
            if 'all' in cond_config:
                return all(eval_conditions(sub_cond) for sub_cond in cond_config['all'])
            elif 'any' in cond_config:
                return any(eval_conditions(sub_cond) for sub_cond in cond_config['any'])
            else:
                var = cond_config.get('var')
                op = cond_config.get('op')
                value = cond_config.get('value')
                
                if isinstance(value, str) and '{{' in value:
                    value = resolve_template(value, context)
                
                actual_value = extract_value(context, var) if var else None
                return evaluate_condition(actual_value, op, value)
        
        try:
            result = eval_conditions(conditions)
            status = 'PASS' if result else 'FAIL'
        except Exception as e:
            logger.warning(f"Error evaluating {check_id}: {e}")
            status = 'ERROR'
        
        # Extract checked fields from conditions
        checked_fields = extract_checked_fields(conditions)
        
        # Get scan timestamp
        from datetime import datetime
        created_at = datetime.utcnow().isoformat() + 'Z'
        
        results_mode = os.getenv("RESULTS_NDJSON_MODE", "finding").strip().lower()
        is_verbose = results_mode in ("legacy",)
        
        record = {
            'rule_id': check_id,
            'result': status,
            'status': status,
            'service': service_name,
            'region': region,
            'created_at': created_at,
            '_checked_fields': list(checked_fields),
        }
        
        if is_verbose:
            record.update({
                'title': title,
                'severity': severity,
                'assertion_id': assertion_id,
            })
        
        # Extract resource identifiers
        if item:
            check_discovery_id = independent_disc_id if independent_disc_id else (
                for_each.get('discovery') if isinstance(for_each, dict) else (
                    str(for_each) if for_each else None
                )
            )
            
            resource_info = extract_resource_identifier(item, service_name, region, account_id, discovery_id=check_discovery_id)
            
            record['resource_uid'] = resource_info['resource_uid']
            record['resource_arn'] = resource_info['resource_arn']
            record['resource_id'] = resource_info['resource_id']
            record['resource_type'] = resource_info['resource_type']
            record['resource_name'] = item.get('Name') or item.get('name') or resource_info.get('resource_id') or ''
        
        check_results.append(record)
    
    return check_results

def run_service(
    service_name: str,
    region: Optional[str] = None,
    session_override: Optional[boto3.session.Session] = None,
    service_rules_override: Optional[Dict[str, Any]] = None,
    skip_checks: bool = False
):
    """
    Unified service execution for both global and regional services.

    This function replaces the duplicated run_global_service() and run_regional_service() functions,
    eliminating 1,756 lines of code duplication by parametrizing the region.

    Args:
        service_name: Service name (e.g., 'iam', 'ec2')
        region: AWS region. If None, determined from database scope column:
                - scope='global' → uses 'us-east-1'
                - scope='regional' → raises error (must provide region)
        session_override: Optional boto3 session
        service_rules_override: Optional service rules override (for regional services)
        skip_checks: If True, skip check phase (discovery only)

    Returns:
        Dict containing:
            - inventory: discovery results
            - checks: check results (empty if skip_checks=True)
            - service: service name
            - scope: 'global' or 'regional'
            - region: execution region (always present)
            - _raw_data: raw API responses

    Raises:
        ValueError: If region is None for a regional service

    Examples:
        >>> # Global service (IAM) - region auto-determined from database
        >>> result = run_service('iam')
        >>> result['scope']  # 'global'
        >>> result['region']  # 'us-east-1'

        >>> # Regional service (EC2) - region must be provided
        >>> result = run_service('ec2', region='us-west-2')
        >>> result['scope']  # 'regional'
        >>> result['region']  # 'us-west-2'
    """
    # Track scan attempt metadata
    scan_start_time = time.time()
    scan_result = {
        'service': service_name,
        'region': region or 'auto',
        'status': 'pending',
        'discoveries': 0,
        'error': None,
        'error_message': None
    }

    try:
        # Load database-driven configuration
        config_loader, filter_engine, pagination_engine = _get_config_loader()

        # Determine scope from database
        scope = config_loader.get_scope(service_name)

        # Determine execution region
        if region is None:
            if scope == 'global':
                execution_region = 'us-east-1'
                logger.info(f"[UNIFIED] {service_name}: Global service, using region=us-east-1")
            else:
                raise ValueError(
                    f"Service '{service_name}' has scope='{scope}' (regional), "
                    f"but no region was provided. Regional services require explicit region parameter."
                )
        else:
            execution_region = region
            logger.info(f"[UNIFIED] {service_name}: Using provided region={execution_region}")

        # Get boto3 client name from database (replaces hardcoded discovery_helper mapping)
        boto3_client_name = config_loader.get_boto3_client_name(service_name)
        logger.info(f"[UNIFIED] {service_name}: boto3_client_name={boto3_client_name} (from database)")

        # Load service rules
        service_rules = service_rules_override or load_service_rules(service_name)

        # Create session with execution region
        session = session_override or get_boto3_session(default_region=execution_region)
        client = session.client(boto3_client_name, region_name=execution_region, config=BOTO_CONFIG)

        # Extract account_id for resource identifier generation
        account_id = None
        try:
            sts_client = session.client('sts', region_name=execution_region, config=BOTO_CONFIG)
            account_id = sts_client.get_caller_identity().get('Account')
        except Exception as e:
            logger.debug(f"Could not get account ID for resource identifiers: {e}")

        discovery_results = {}
        saved_data = {}

        # Build dependency graph for parallel processing of independent discoveries
        all_discoveries = service_rules.get('discovery', [])
        dependency_graph = _build_dependency_graph(all_discoveries)
        independent_discoveries = dependency_graph['independent']
        dependent_groups = dependency_graph['dependent_groups']

        # Thread-safe locks for shared state
        saved_data_lock = Lock()
        discovery_results_lock = Lock()

        # ============================================================
        # PHASE 1: DISCOVERY - Run ALL discoveries, store in memory
        # ============================================================
        discovery_start_time = time.time()

        # Process independent discoveries in parallel, then dependent sequentially.
        # A single shared semaphore bounds ALL concurrent API calls for this service:
        # both the outer discovery threads AND inner for_each expansions share it.
        # This prevents the nested-threadpool OOM where 50 outer * 50 inner = 2500 threads.
        max_discovery_workers = int(os.getenv('MAX_DISCOVERY_WORKERS', '20'))
        for_each_max_workers = int(os.getenv('FOR_EACH_MAX_WORKERS', '10'))

        if independent_discoveries:
            logger.info(f"Processing {len(independent_discoveries)} independent discoveries in parallel (max {max_discovery_workers} workers)")
            discovery_futures = {}

            def process_independent_discovery(discovery):
                """Process a single independent discovery (called in parallel) - uses same logic as dependent discoveries"""
                discovery_id = discovery['discovery_id']
                disc_start = time.time()
                logger.info(f"Processing discovery: {discovery_id}")

                # Create thread-local client for this discovery
                local_client = session.client(boto3_client_name, region_name=execution_region, config=BOTO_CONFIG)

                # Track save_as for emit processing (use first call's save_as)
                discovery_save_as = None

                # Process calls in order
                for call in discovery.get('calls', []):
                    action = _normalize_action(call['action'])
                    params = call.get('params', {})
                    save_as = call.get('save_as', f'{action}_response')
                    if discovery_save_as is None:
                        discovery_save_as = save_as
                    for_each = discovery.get('for_each') or call.get('for_each')
                    as_var = call.get('as', 'item')
                    on_error = discovery.get('on_error') or call.get('on_error', 'continue')

                    try:
                        if for_each:
                            # Dependent discoveries only - skip for independent
                            items_ref = for_each.replace('{{ ', '').replace(' }}', '')
                            with saved_data_lock:
                                items = discovery_results.get(items_ref)
                                if items is None:
                                    items = extract_value(saved_data, items_ref)
                            # Independent discoveries shouldn't have for_each - log warning
                            if items:
                                logger.warning(f"Independent discovery {discovery_id} has for_each - treating as dependent")
                        else:
                            # Regular call - thread-safe access to saved_data
                            call_client = local_client
                            specified_client = call.get('client', service_name)
                            if specified_client != service_name:
                                call_client = session.client(specified_client, region_name=execution_region, config=BOTO_CONFIG)

                            # Thread-safe read of saved_data
                            with saved_data_lock:
                                context = saved_data.copy()

                            def resolve_params_recursive(obj, context):
                                """Recursively resolve template variables in params, with validation for QuickSight AwsAccountId"""
                                if isinstance(obj, dict):
                                    resolved = {}
                                    for key, value in obj.items():
                                        resolved_value = resolve_params_recursive(value, context)
                                        # Validate QuickSight AwsAccountId - ensure it's not 0 or empty
                                        if key == 'AwsAccountId' and service_name == 'quicksight':
                                            if resolved_value == '0' or resolved_value == 0 or resolved_value == '':
                                                # Try to get account ID from STS if account_info is invalid
                                                try:
                                                    sts_client = session.client('sts', region_name=execution_region, config=BOTO_CONFIG)
                                                    account_id_from_sts = sts_client.get_caller_identity().get('Account')
                                                    if account_id_from_sts:
                                                        resolved_value = str(account_id_from_sts)
                                                        logger.debug(f"QuickSight: Fixed invalid AwsAccountId (was {obj.get('AwsAccountId')}), using {resolved_value}")
                                                except Exception as e:
                                                    logger.warning(f"QuickSight: Could not get account ID from STS: {e}")
                                        resolved[key] = resolved_value
                                    return resolved
                                elif isinstance(obj, list):
                                    return [resolve_params_recursive(item, context) for item in obj]
                                elif isinstance(obj, str):
                                    return resolve_template(obj, context)
                                else:
                                    return obj

                            resolved_params = resolve_params_recursive(params, context)

                            # Apply AWS-managed resource filters at API level (before API call)
                            # Using database-driven FilterEngine
                            resolved_params = filter_engine.apply_api_filters(
                                discovery_id, resolved_params, service_name, account_id
                            )

                            # Check if operation supports pagination using can_paginate (no hardcoding)
                            is_list_or_describe = (
                                action.startswith('list_') or
                                action.startswith('describe_') or
                                action.startswith('get_')
                            )

                            # Use pagination for list/describe operations (independent discoveries only)
                            if not for_each and is_list_or_describe:
                                # Check if boto3 paginator is available (most reliable method)
                                try:
                                    if call_client.can_paginate(action):
                                        # Use robust pagination with safeguards
                                        response = _paginate_api_call(
                                            call_client,
                                            action,
                                            resolved_params,
                                            discovery_config=discovery,
                                            operation_timeout=OPERATION_TIMEOUT
                                        )
                                    else:
                                        # No paginator - use single call with timeout protection
                                        logger.debug(f"{action} doesn't support boto3 paginator, using single call with timeout")
                                        response = _call_with_timeout(call_client, action, resolved_params, timeout=300)
                                except Exception as e:
                                    # Fallback: single call with timeout
                                    logger.debug(f"Error checking pagination for {action}, using single call: {e}")
                                    response = _call_with_timeout(call_client, action, resolved_params, timeout=300)
                            else:
                                # Single API call (no pagination) with timeout protection
                                response = _call_with_timeout(call_client, action, resolved_params, timeout=300)

                            if save_as:
                                # Thread-safe write to saved_data
                                with saved_data_lock:
                                    if 'fields' in call:
                                        extracted_data = {}
                                        for field in call['fields']:
                                            value = extract_value(response, field)
                                            if value is not None:
                                                if field.endswith('[]'):
                                                    extracted_data = value
                                                else:
                                                    parts = field.split('.')
                                                    current = extracted_data
                                                    for part in parts[:-1]:
                                                        if part not in current:
                                                            current[part] = {}
                                                        current = current[part]
                                                    current[parts[-1]] = value
                                        saved_data[save_as] = extracted_data
                                    else:
                                        saved_data[save_as] = response
                                    saved_data[f'_discovery_{save_as}'] = discovery_id
                    except Exception as e:
                        if on_error == 'continue':
                            if _is_expected_aws_error(e):
                                logger.debug(f"Skipped {action}: {e}")
                            else:
                                logger.warning(f"Failed {action}: {e}")
                            continue
                        else:
                            raise

                # Process emit - thread-safe read/write
                emit_config = discovery.get('emit', {})
                discovery_for_each = discovery.get('for_each')

                # Read saved_data thread-safely
                with saved_data_lock:
                    saved_data_copy = saved_data.copy()

                # Process emit logic
                if discovery_for_each and discovery_save_as and f'{discovery_save_as}_contexts' in saved_data_copy:
                    accumulated_contexts = saved_data_copy[f'{discovery_save_as}_contexts']
                    results = []
                    if 'items_for' in emit_config:
                        items_path = emit_config['items_for'].replace('{{ ', '').replace(' }}', '')
                        as_var = emit_config.get('as', 'r')
                        for acc_data in accumulated_contexts:
                            response = acc_data['response']
                            item = acc_data['item']
                            context = acc_data['context']
                            response_items = extract_value(response, items_path)

                            # Filter out AWS-managed resources (customer-managed only)
                            # Using database-driven FilterEngine
                            response_items = filter_engine.apply_response_filters(
                                discovery_id, response_items, service_name, account_id
                            )

                            if response_items:
                                for response_item in response_items:
                                    if isinstance(response_item, dict):
                                        item_data = response_item.copy()
                                        auto_fields = auto_emit_arn_and_name(response_item, service=service_name, region=execution_region, account_id=account_id)
                                        for key, value in auto_fields.items():
                                            if key not in item_data:
                                                item_data[key] = value
                                    else:
                                        item_data = {'_raw_item': response_item}

                                    # Preserve resource_arn from parent item
                                    if isinstance(item, dict):
                                        parent_arn = item.get('resource_arn') or item.get('Arn') or item.get('arn')
                                        if parent_arn and isinstance(parent_arn, str) and parent_arn.startswith('arn:aws:'):
                                            item_data['resource_arn'] = parent_arn

                                    results.append(item_data)
                    else:
                        for acc_data in accumulated_contexts:
                            response = acc_data['response']
                            item = acc_data['item']

                            if not isinstance(response, dict):
                                logger.warning(f"[EMIT] {discovery_id}: response is not a dict, skipping emit")
                                continue

                            item_data = {k: v for k, v in response.items() if k != 'ResponseMetadata'}

                            if isinstance(item, dict):
                                parent_arn = item.get('resource_arn') or item.get('Arn') or item.get('arn')
                                if parent_arn and isinstance(parent_arn, str) and parent_arn.startswith('arn:aws:'):
                                    item_data['resource_arn'] = parent_arn

                            results.append(item_data)

                    with discovery_results_lock:
                        discovery_results[discovery_id] = results
                elif 'items_for' in emit_config:
                    items_path = emit_config['items_for'].replace('{{ ', '').replace(' }}', '')
                    items = extract_value(saved_data_copy, items_path)

                    # Filter out AWS-managed resources using database-driven FilterEngine
                    items = filter_engine.apply_response_filters(discovery_id, items, service_name, account_id)

                    results = []
                    if items:
                        for item in items:
                            if isinstance(item, dict):
                                item_data = item.copy()
                                auto_fields = auto_emit_arn_and_name(item, service=service_name, region=execution_region, account_id=account_id)
                                for key, value in auto_fields.items():
                                    if key not in item_data:
                                        item_data[key] = value
                                # Extract resource identifiers (resource_id, resource_type, resource_arn, resource_uid)
                                resource_info = extract_resource_identifier(item_data, service_name, execution_region, account_id, discovery_id=discovery_id)
                                for key in ('resource_id', 'resource_type', 'resource_arn', 'resource_uid'):
                                    if resource_info.get(key) and not item_data.get(key):
                                        item_data[key] = resource_info[key]
                                # Store raw response for DB raw_response column
                                if '_raw_response' not in item_data:
                                    item_data['_raw_response'] = {k: v for k, v in item_data.items()
                                                                   if not k.startswith('_') and k not in ('resource_arn', 'resource_uid', 'resource_id', 'resource_type', 'resource_name')}
                            else:
                                item_data = {'_raw_item': item}

                            results.append(item_data)

                    with discovery_results_lock:
                        discovery_results[discovery_id] = results
                elif 'item' in emit_config:
                    response = saved_data_copy.get('response', {})
                    if isinstance(response, dict):
                        item_data = {k: v for k, v in response.items() if k != 'ResponseMetadata'}
                        # Store raw response for DB raw_response column
                        item_data['_raw_response'] = dict(item_data)
                    else:
                        item_data = {'_raw_response': response}

                    auto_fields = auto_emit_arn_and_name(saved_data_copy, service=service_name, region=execution_region, account_id=account_id)
                    for key, value in auto_fields.items():
                        if key not in item_data:
                            item_data[key] = value
                    # Extract resource identifiers (resource_id, resource_type, resource_arn, resource_uid)
                    resource_info = extract_resource_identifier(item_data, service_name, execution_region, account_id, discovery_id=discovery_id)
                    for key in ('resource_id', 'resource_type', 'resource_arn', 'resource_uid'):
                        if resource_info.get(key) and not item_data.get(key):
                            item_data[key] = resource_info[key]

                    with discovery_results_lock:
                        discovery_results[discovery_id] = [item_data]

                disc_elapsed = time.time() - disc_start
                logger.info(f"Completed discovery {discovery_id}: {disc_elapsed:.2f}s")

            # Process independent discoveries in parallel.
            # max_workers here controls queue depth; actual concurrency is
            # further gated by _service_semaphore acquired inside each task.
            with ThreadPoolExecutor(max_workers=min(len(independent_discoveries), max_discovery_workers)) as executor:
                for discovery in independent_discoveries:
                    future = executor.submit(process_independent_discovery, discovery)
                    discovery_futures[future] = discovery.get('discovery_id')

                for future in as_completed(discovery_futures):
                    discovery_id = discovery_futures[future]
                    try:
                        future.result()
                    except Exception as e:
                        logger.error(f"Failed to process independent discovery {discovery_id}: {e}")

        # Process dependent discoveries sequentially
        processed_ids = {disc.get('discovery_id') for disc in independent_discoveries}
        remaining_discoveries = [disc for disc in all_discoveries if disc.get('discovery_id') not in processed_ids]

        for discovery in remaining_discoveries:
            discovery_id = discovery['discovery_id']
            disc_start = time.time()
            logger.info(f"Processing discovery: {discovery_id}")

            discovery_save_as = None

            for call in discovery.get('calls', []):
                action = _normalize_action(call['action'])
                params = call.get('params', {})
                save_as = call.get('save_as', f'{action}_response')
                if discovery_save_as is None:
                    discovery_save_as = save_as
                for_each = discovery.get('for_each') or call.get('for_each')
                as_var = call.get('as', 'item')
                on_error = discovery.get('on_error') or call.get('on_error', 'continue')

                try:
                    if for_each:
                        items_ref = for_each.replace('{{ ', '').replace(' }}', '')
                        items = discovery_results.get(items_ref)
                        if items is None:
                            items = extract_value(saved_data, items_ref)

                        if items:
                            accumulated_responses = []
                            accumulated_responses_lock = Lock()

                            def process_item(item):
                                item_context = {as_var: item}
                                item_context.update(saved_data)

                                def resolve_params_recursive(obj, context):
                                    if isinstance(obj, dict):
                                        return {k: resolve_params_recursive(v, context) for k, v in obj.items()}
                                    elif isinstance(obj, list):
                                        return [resolve_params_recursive(item, context) for item in obj]
                                    elif isinstance(obj, str):
                                        return resolve_template(obj, context)
                                    else:
                                        return obj

                                resolved_params = resolve_params_recursive(params, item_context)

                                specified_client = call.get('client', service_name)
                                if specified_client != service_name:
                                    call_client = session.client(specified_client, region_name=execution_region, config=BOTO_CONFIG)
                                else:
                                    call_client = session.client(boto3_client_name, region_name=execution_region, config=BOTO_CONFIG)

                                try:
                                    response = _retry_call(getattr(call_client, action), **resolved_params)
                                    return {'response': response, 'item': item, 'context': item_context}
                                except Exception as api_error:
                                    if on_error == 'continue':
                                        if _is_expected_aws_error(api_error):
                                            logger.debug(f"Skipped {action}: {api_error}")
                                        else:
                                            logger.warning(f"Failed {action}: {api_error}")
                                        return None
                                    else:
                                        raise

                            max_workers = min(len(items), for_each_max_workers)
                            logger.info(f"Starting parallel execution for {discovery_id}: {len(items)} items with {max_workers} workers")

                            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                                futures = [executor.submit(process_item, item) for item in items]
                                for future in as_completed(futures):
                                    try:
                                        result = future.result()
                                        if result:
                                            with accumulated_responses_lock:
                                                accumulated_responses.append(result)
                                    except Exception as e:
                                        if on_error == 'continue':
                                            logger.warning(f"Unexpected error in parallel execution: {e}")
                                        else:
                                            raise

                            if save_as and accumulated_responses:
                                saved_data[save_as] = [r['response'] for r in accumulated_responses]
                                saved_data[f'{save_as}_contexts'] = accumulated_responses
                                saved_data[f'_discovery_{save_as}'] = discovery_id
                    else:
                        # Regular call
                        call_client = client
                        specified_client = call.get('client', service_name)
                        if specified_client != service_name:
                            call_client = session.client(specified_client, region_name=execution_region, config=BOTO_CONFIG)

                        context = saved_data.copy()
                        def resolve_params_recursive(obj, context):
                            if isinstance(obj, dict):
                                return {k: resolve_params_recursive(v, context) for k, v in obj.items()}
                            elif isinstance(obj, list):
                                return [resolve_params_recursive(item, context) for item in obj]
                            elif isinstance(obj, str):
                                return resolve_template(obj, context)
                            else:
                                return obj

                        resolved_params = resolve_params_recursive(params, context)
                        # Apply API-level filters using database-driven FilterEngine
                        resolved_params = filter_engine.apply_api_filters(discovery_id, resolved_params, service_name, account_id)

                        is_list_or_describe = (action.startswith('list_') or action.startswith('describe_') or action.startswith('get_'))

                        if not for_each and is_list_or_describe:
                            try:
                                if call_client.can_paginate(action):
                                    response = _paginate_api_call(call_client, action, resolved_params, discovery_config=discovery, operation_timeout=OPERATION_TIMEOUT)
                                else:
                                    response = _call_with_timeout(call_client, action, resolved_params, timeout=300)
                            except Exception as e:
                                response = _call_with_timeout(call_client, action, resolved_params, timeout=300)
                        else:
                            response = _call_with_timeout(call_client, action, resolved_params, timeout=300)

                        if save_as:
                            if 'fields' in call:
                                extracted_data = {}
                                for field in call['fields']:
                                    value = extract_value(response, field)
                                    if value is not None:
                                        if field.endswith('[]'):
                                            extracted_data = value
                                        else:
                                            parts = field.split('.')
                                            current = extracted_data
                                            for part in parts[:-1]:
                                                if part not in current:
                                                    current[part] = {}
                                                current = current[part]
                                            current[parts[-1]] = value
                                saved_data[save_as] = extracted_data
                            else:
                                saved_data[save_as] = response
                            saved_data[f'_discovery_{save_as}'] = discovery_id
                except Exception as e:
                    if on_error == 'continue':
                        if _is_expected_aws_error(e):
                            logger.debug(f"Skipped {action}: {e}")
                        else:
                            logger.warning(f"Failed {action}: {e}")
                        continue
                    else:
                        raise

            # Process emit
            emit_config = discovery.get('emit', {})
            discovery_for_each = discovery.get('for_each')

            if discovery_for_each and discovery_save_as and f'{discovery_save_as}_contexts' in saved_data:
                accumulated_contexts = saved_data[f'{discovery_save_as}_contexts']
                results = []

                if 'items_for' in emit_config:
                    items_path = emit_config['items_for'].replace('{{ ', '').replace(' }}', '')
                    for acc_data in accumulated_contexts:
                        response = acc_data['response']
                        item = acc_data['item']
                        response_items = extract_value(response, items_path)
                        # Apply response filters using database-driven FilterEngine
                        response_items = filter_engine.apply_response_filters(discovery_id, response_items, service_name, account_id)

                        if response_items:
                            for response_item in response_items:
                                if isinstance(response_item, dict):
                                    item_data = response_item.copy()
                                    auto_fields = auto_emit_arn_and_name(response_item, service=service_name, region=execution_region, account_id=account_id)
                                    for key, value in auto_fields.items():
                                        if key not in item_data:
                                            item_data[key] = value
                                else:
                                    item_data = {'_raw_item': response_item}

                                if isinstance(item, dict):
                                    parent_arn = item.get('resource_arn') or item.get('Arn') or item.get('arn')
                                    if parent_arn and isinstance(parent_arn, str) and parent_arn.startswith('arn:aws:'):
                                        item_data['resource_arn'] = parent_arn

                                results.append(item_data)
                else:
                    for acc_data in accumulated_contexts:
                        response = acc_data['response']
                        item = acc_data['item']

                        if not isinstance(response, dict):
                            continue

                        item_data = {k: v for k, v in response.items() if k != 'ResponseMetadata'}

                        if isinstance(item, dict):
                            parent_arn = item.get('resource_arn') or item.get('Arn') or item.get('arn')
                            if parent_arn and isinstance(parent_arn, str) and parent_arn.startswith('arn:aws:'):
                                item_data['resource_arn'] = parent_arn

                        results.append(item_data)

                discovery_results[discovery_id] = results
            elif 'items_for' in emit_config:
                items_path = emit_config['items_for'].replace('{{ ', '').replace(' }}', '')
                items = extract_value(saved_data, items_path)
                # Apply response filters using database-driven FilterEngine
                items = filter_engine.apply_response_filters(discovery_id, items, service_name, account_id)

                results = []
                if items:
                    for item in items:
                        if isinstance(item, dict):
                            item_data = item.copy()
                            auto_fields = auto_emit_arn_and_name(item, service=service_name, region=execution_region, account_id=account_id)
                            for key, value in auto_fields.items():
                                if key not in item_data:
                                    item_data[key] = value
                            # Extract resource identifiers (resource_id, resource_type, resource_arn, resource_uid)
                            resource_info = extract_resource_identifier(item_data, service_name, execution_region, account_id, discovery_id=discovery_id)
                            for key in ('resource_id', 'resource_type', 'resource_arn', 'resource_uid'):
                                if resource_info.get(key) and not item_data.get(key):
                                    item_data[key] = resource_info[key]
                            # Store raw response for DB raw_response column
                            if '_raw_response' not in item_data:
                                item_data['_raw_response'] = {k: v for k, v in item_data.items()
                                                               if not k.startswith('_') and k not in ('resource_arn', 'resource_uid', 'resource_id', 'resource_type', 'resource_name')}
                        else:
                            item_data = {'_raw_item': item}
                        results.append(item_data)

                discovery_results[discovery_id] = results
            elif 'item' in emit_config:
                response = saved_data.get('response', {})
                if isinstance(response, dict):
                    item_data = {k: v for k, v in response.items() if k != 'ResponseMetadata'}
                    # Store raw response for DB raw_response column
                    item_data['_raw_response'] = dict(item_data)
                else:
                    item_data = {'_raw_response': response}

                auto_fields = auto_emit_arn_and_name(saved_data, service=service_name, region=execution_region, account_id=account_id)
                for key, value in auto_fields.items():
                    if key not in item_data:
                        item_data[key] = value
                # Extract resource identifiers (resource_id, resource_type, resource_arn, resource_uid)
                resource_info = extract_resource_identifier(item_data, service_name, execution_region, account_id, discovery_id=discovery_id)
                for key in ('resource_id', 'resource_type', 'resource_arn', 'resource_uid'):
                    if resource_info.get(key) and not item_data.get(key):
                        item_data[key] = resource_info[key]

                discovery_results[discovery_id] = [item_data]

            disc_elapsed = time.time() - disc_start
            logger.info(f"Completed discovery {discovery_id}: {disc_elapsed:.2f}s")

        # ============================================================
        # PHASE 2: BUILD INVENTORY
        # ============================================================
        try:
            discovery_results = _enrich_inventory_with_dependent_discoveries(
                discovery_results, service_rules, dependency_graph
            )
        except Exception as e:
            logger.warning(f"Failed to enrich inventory: {e}")

        # Compute primary inventory items
        primary_items = None
        try:
            from common.utils.reporting_manager import is_cspm_inventory_resource
            for disc in service_rules.get("discovery", []) or []:
                did = disc.get("discovery_id")
                if not did:
                    continue
                items_candidate = discovery_results.get(did)
                if not (isinstance(items_candidate, list) and items_candidate):
                    continue
                if not is_cspm_inventory_resource(did, discovery_config=disc):
                    continue
                primary_items = items_candidate
                break
        except Exception:
            primary_items = None

        # ============================================================
        # PHASE 3: CHECKS - Run ALL checks in parallel
        # ============================================================
        all_checks = service_rules.get('checks', [])
        checks_output = []

        if skip_checks:
            logger.info("Skipping checks (discovery-only mode)")
            all_checks = []
        else:
            max_check_workers = int(os.getenv('MAX_CHECK_WORKERS', '50'))

        if all_checks:
            logger.info(f"Running {len(all_checks)} checks in parallel (max {max_check_workers} workers)")

            with ThreadPoolExecutor(max_workers=max_check_workers) as executor:
                futures = {
                    executor.submit(
                        _run_single_check,
                        check,
                        service_name,
                        execution_region,
                        account_id,
                        discovery_results,
                        service_rules,
                        primary_items
                    ): check
                    for check in all_checks
                }

                for future in as_completed(futures):
                    check = futures[future]
                    try:
                        results = future.result()
                        checks_output.extend(results)
                    except Exception as e:
                        logger.error(f"Check {check.get('rule_id', 'unknown')} failed: {e}")

        # Calculate total discoveries
        total_discoveries = sum(len(items) for items in discovery_results.values() if isinstance(items, list))

        # Update scan result metadata
        scan_result['status'] = 'scanned'
        scan_result['discoveries'] = total_discoveries
        scan_result['region'] = execution_region
        scan_result['duration_ms'] = int((time.time() - scan_start_time) * 1000)

        return {
            'inventory': discovery_results,
            'checks': checks_output,
            'service': service_name,
            'scope': scope,
            'region': execution_region,
            '_raw_data': saved_data,
            '_scan_metadata': scan_result  # NEW: Scan attempt tracking
        }

    except Exception as e:
        import traceback
        from botocore.exceptions import ClientError

        # Determine error type and categorize scan status
        error_code = None
        error_message = str(e)

        if isinstance(e, ClientError):
            error_code = e.response['Error']['Code']
            error_message = e.response['Error'].get('Message', str(e))

            # Categorize AWS error codes
            if error_code in ('OptInRequired', 'SubscriptionRequiredException', 'InvalidAction'):
                # Service not enabled - this is NORMAL, not an error
                scan_result['status'] = 'unavailable'
                scan_result['error'] = error_code
                scan_result['error_message'] = error_message
                logger.info(f"Service {service_name} not enabled in {region or 'auto'}: {error_code}")
            elif error_code in ('AccessDenied', 'UnauthorizedOperation', 'AccessDeniedException'):
                # Permission issue - record but don't fail the overall scan
                scan_result['status'] = 'access_denied'
                scan_result['error'] = error_code
                scan_result['error_message'] = error_message
                logger.warning(f"No permission for {service_name} in {region or 'auto'}: {error_code}")
            else:
                # Unexpected AWS error
                scan_result['status'] = 'failed'
                scan_result['error'] = error_code
                scan_result['error_message'] = error_message
                logger.error(f"Service {service_name} (region={region}) failed: {e}")
                logger.error(f"Traceback: {traceback.format_exc()}")
        else:
            # Non-AWS error (timeout, network, etc.)
            scan_result['status'] = 'failed'
            scan_result['error'] = type(e).__name__
            scan_result['error_message'] = error_message
            logger.error(f"Service {service_name} (region={region}) failed: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")

        # Finalize scan metadata
        scan_result['region'] = region or 'us-east-1'
        scan_result['duration_ms'] = int((time.time() - scan_start_time) * 1000)

        return {
            'inventory': {},
            'checks': [],
            'service': service_name,
            'scope': scope if 'scope' in locals() else 'unknown',
            'region': region or 'us-east-1',
            'unavailable': True,
            'error': error_code or str(e),
            '_scan_metadata': scan_result  # NEW: Scan attempt tracking
        }
def run_global_service(service_name, session_override: Optional[boto3.session.Session] = None, skip_checks: bool = False):
    """
    Legacy wrapper for backward compatibility.
    
    Calls unified run_service() with region=None (auto-determined from database scope).
    
    Args:
        service_name: Service name (e.g., 'iam')
        session_override: Optional boto3 session
        skip_checks: If True, skip check phase (discovery only)
    
    Returns:
        Same format as run_service()
    
    Deprecated: Use run_service() directly for new code.
    """
    logger.info(f"[WRAPPER] run_global_service() → run_service(service_name='{service_name}', region=None)")
    return run_service(
        service_name=service_name,
        region=None,  # Auto-determined from database (global services use us-east-1)
        session_override=session_override,
        service_rules_override=None,
        skip_checks=skip_checks
    )


def run_regional_service(service_name, region, session_override: Optional[boto3.session.Session] = None, service_rules_override: Optional[Dict[str, Any]] = None, skip_checks: bool = False):
    """
    Legacy wrapper for backward compatibility.
    
    Calls unified run_service() with explicit region parameter.
    
    Args:
        service_name: Service name (e.g., 'ec2')
        region: AWS region (e.g., 'us-east-1')
        session_override: Optional boto3 session
        service_rules_override: Optional service rules override
        skip_checks: If True, skip check phase (discovery only)
    
    Returns:
        Same format as run_service()
    
    Deprecated: Use run_service() directly for new code.
    """
    logger.info(f"[WRAPPER] run_regional_service() → run_service(service_name='{service_name}', region='{region}')")
    return run_service(
        service_name=service_name,
        region=region,  # Explicit region for regional services
        session_override=session_override,
        service_rules_override=service_rules_override,
        skip_checks=skip_checks
    )


# ============================================================================
# AWS Discovery Scanner - DiscoveryScanner Interface Implementation
# ============================================================================

class AWSDiscoveryScanner:
    """
    AWS implementation of the DiscoveryScanner interface.

    This scanner wraps the existing AWS discovery logic (run_service function)
    and provides a consistent interface for the common discovery engine.

    It handles:
    - AWS authentication via boto3
    - Service discovery execution
    - Resource identification
    - Scan tracking metadata
    """

    def __init__(self, credentials: Dict[str, Any], **kwargs):
        """
        Initialize AWS scanner with credentials.

        Args:
            credentials: AWS credentials dictionary with:
                - role_arn: IAM role ARN to assume
                - external_id: External ID for AssumeRole
                - access_key_id: (optional) AWS access key
                - secret_access_key: (optional) AWS secret key
                - session_token: (optional) AWS session token
            **kwargs: Additional configuration:
                - provider: 'aws' (default)
                - default_region: Default region for global services
        """
        self.credentials = credentials
        self.provider = kwargs.get('provider', 'aws')
        self.default_region = kwargs.get('default_region', 'us-east-1')
        self.session = None
        self.account_id = None

    def authenticate(self):
        """
        Authenticate to AWS using provided credentials.

        Creates a boto3 session using IAM role assumption or access keys.

        Returns:
            boto3.Session: Authenticated session

        Raises:
            AuthenticationError: If authentication fails
        """
        from common.models.provider_interface import AuthenticationError

        try:
            role_arn = self.credentials.get('role_arn')
            external_id = self.credentials.get('external_id')

            # Credentials may be nested under 'credentials' key (Secrets Manager format)
            nested_creds = self.credentials.get('credentials', {}) or {}
            access_key_id = self.credentials.get('access_key_id') or nested_creds.get('access_key_id')
            secret_access_key = self.credentials.get('secret_access_key') or nested_creds.get('secret_access_key')
            session_token = self.credentials.get('session_token') or nested_creds.get('session_token')

            if role_arn:
                # Use role assumption (preferred)
                self.session = get_session_for_account(
                    role_arn=role_arn,
                    external_id=external_id,
                    region_name=self.default_region
                )
            elif access_key_id and secret_access_key:
                # Use explicit access keys from Secrets Manager
                import boto3
                self.session = boto3.Session(
                    aws_access_key_id=access_key_id,
                    aws_secret_access_key=secret_access_key,
                    aws_session_token=session_token,
                    region_name=self.default_region
                )
                logger.info(f"Authenticated to AWS using access key (key_id ending: ...{access_key_id[-4:]})")
            else:
                # Use default credentials (pod IAM role)
                self.session = get_boto3_session(default_region=self.default_region)

            # Get account ID
            try:
                sts = self.session.client('sts', region_name=self.default_region)
                self.account_id = sts.get_caller_identity()['Account']
                logger.info(f"Authenticated to AWS account: {self.account_id}")
            except Exception as e:
                logger.warning(f"Could not get AWS account ID: {e}")
                self.account_id = 'unknown'

            return self.session

        except Exception as e:
            logger.error(f"AWS authentication failed: {e}")
            raise AuthenticationError(f"Failed to authenticate to AWS: {e}")

    async def list_available_regions(self) -> List[str]:
        """
        Return all opted-in regions for this AWS account via ec2:describe_regions.

        Called once before the service scan loop to determine which regions to scan
        when include_regions is not specified in scan_orchestration.

        Returns:
            Sorted list of enabled region names (opt-in-not-required + opted-in)
        """
        import functools
        if not self.session:
            self.authenticate()
        loop = asyncio.get_event_loop()

        def _describe_regions():
            ec2 = self.session.client('ec2', region_name='us-east-1', config=BOTO_CONFIG)
            resp = ec2.describe_regions(
                Filters=[{'Name': 'opt-in-status', 'Values': ['opt-in-not-required', 'opted-in']}]
            )
            return sorted(r['RegionName'] for r in resp['Regions'])

        regions = await loop.run_in_executor(None, _describe_regions)
        logger.info(f"Discovered {len(regions)} available AWS regions: {regions}")
        return regions

    async def scan_service(
        self,
        service: str,
        region: str,
        config: Dict[str, Any]
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Execute service discovery for an AWS service.

        This method wraps the existing run_service() function and extracts:
        - Discovered resources from 'inventory' key
        - Scan metadata from '_scan_metadata' key

        Args:
            service: AWS service name (e.g., 'ec2', 'iam', 's3')
            region: AWS region (e.g., 'us-east-1')
            config: Discovery configuration from rule_discoveries.discoveries_data

        Returns:
            Tuple of (discoveries, scan_metadata):
            - discoveries: List of discovered resources
            - scan_metadata: Scan tracking metadata (status, discoveries count, etc.)

        Raises:
            DiscoveryError: If discovery fails
        """
        from common.models.provider_interface import DiscoveryError

        try:
            # Ensure authenticated
            if not self.session:
                self.authenticate()

            # Run the CPU/IO-bound run_service() in a thread pool executor so the
            # asyncio event loop stays free to handle health check probes during
            # heavy scans. Without this, the liveness probe times out and the
            # kubelet kills the pod mid-scan (exit code 137).
            import asyncio, functools
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                _SCAN_EXECUTOR,  # dedicated pool: 100 threads vs default ~8
                functools.partial(
                    run_service,
                    service_name=service,
                    region=region,
                    session_override=self.session,
                    service_rules_override=config,
                    skip_checks=True
                )
            )

            # Extract discoveries from 'inventory' key
            inventory = result.get('inventory', {})
            all_discoveries = []

            # Flatten all discovery results, tagging each item with its operation discovery_id
            # and extracting resource_type from the item's ARN / ID patterns.
            account_id = self.account_id or 'unknown'
            for discovery_id, items in inventory.items():
                if isinstance(items, list):
                    for item in items:
                        if not isinstance(item, dict):
                            continue
                        if '_discovery_id' not in item:
                            item['_discovery_id'] = discovery_id
                        if not item.get('resource_type'):
                            try:
                                rinfo = extract_resource_identifier(
                                    item, service, region, account_id,
                                    discovery_id=discovery_id
                                )
                                rtype = rinfo.get('resource_type')
                                if rtype and rtype != 'resource':
                                    item['resource_type'] = rtype
                            except Exception:
                                pass
                    all_discoveries.extend(items)

            # Extract scan metadata
            scan_metadata = result.get('_scan_metadata', {
                'service': service,
                'region': region,
                'status': 'scanned',
                'discoveries': len(all_discoveries),
                'error': None
            })

            logger.info(
                f"AWS discovery completed: service={service}, region={region}, "
                f"discoveries={scan_metadata['discoveries']}, status={scan_metadata['status']}"
            )

            return all_discoveries, scan_metadata

        except Exception as e:
            logger.error(f"AWS discovery failed for service={service}, region={region}: {e}")
            raise DiscoveryError(f"AWS discovery failed: {e}")

    def get_client(self, service: str, region: str):
        """
        Get AWS boto3 client for specific service and region.

        Args:
            service: AWS service name (e.g., 'ec2', 's3')
            region: AWS region

        Returns:
            boto3.client: Authenticated client instance
        """
        if not self.session:
            self.authenticate()

        client_name = self.get_service_client_name(service)
        return self.session.client(client_name, region_name=region, config=BOTO_CONFIG)

    def extract_resource_identifier(
        self,
        item: Dict[str, Any],
        service: str,
        region: str,
        account_id: str,
        resource_type: Optional[str] = None
    ) -> Dict[str, str]:
        """
        Extract resource identifiers (ARN, ID, name) from AWS resource.

        Uses the existing auto_emit_arn_and_name() function for consistency.

        Args:
            item: AWS API response item (single resource)
            service: AWS service name
            region: AWS region
            account_id: AWS account ID
            resource_type: Optional resource type

        Returns:
            Dict with extracted identifiers:
            {
                'resource_arn': 'arn:aws:...',
                'resource_id': 'i-123...',
                'resource_name': 'my-resource',
                'resource_uid': 'arn:aws:...'
            }
        """
        # Use existing auto_emit_arn_and_name function
        identifiers = auto_emit_arn_and_name(
            item=item,
            service=service,
            region=region,
            account_id=account_id
        )

        # Ensure resource_uid is set (fallback to resource_arn)
        if 'resource_uid' not in identifiers and 'resource_arn' in identifiers:
            identifiers['resource_uid'] = identifiers['resource_arn']

        return identifiers

    def get_service_client_name(self, service: str) -> str:
        """
        Map service name to boto3 client name.

        Uses the existing get_boto3_client_name() function.

        Args:
            service: Service name from rule_discoveries table

        Returns:
            Boto3 client name
        """
        return get_boto3_client_name(service)

    def get_account_id(self) -> str:
        """
        Get AWS account ID from authenticated session.

        Returns:
            AWS account ID string
        """
        if not self.account_id:
            if not self.session:
                self.authenticate()

            try:
                sts = self.session.client('sts', region_name=self.default_region)
                self.account_id = sts.get_caller_identity()['Account']
            except Exception as e:
                logger.error(f"Could not get AWS account ID: {e}")
                self.account_id = 'unknown'

        return self.account_id


# ============================================================================
# Main entry point (for testing)
# ============================================================================

if __name__ == '__main__':
    main()
