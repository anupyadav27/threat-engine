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

from utils.reporting_manager import save_reporting_bundle
from auth.aws_auth import get_boto3_session, get_session_for_account
from engine.discovery_helper import get_boto3_client_name
from utils.metadata_loader import get_metadata_loader

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
OPERATION_TIMEOUT = int(os.getenv('OPERATION_TIMEOUT', '600'))  # 10 minutes max per operation
MAX_ITEMS_PER_DISCOVERY = int(os.getenv('MAX_ITEMS_PER_DISCOVERY', '100000'))  # Safety limit

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


def _apply_aws_managed_filters_at_api_level(discovery_id: str, params: Dict[str, Any], account_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Apply AWS-managed resource filters at API level (before API call).
    This prevents fetching AWS-managed resources in the first place.
    
    Args:
        discovery_id: The discovery operation ID (e.g., 'aws.ec2.describe_snapshots')
        params: API parameters (will be modified in-place)
        account_id: Current account ID (for owner checks)
    
    Returns:
        Modified params dict with filters applied
    """
    # EBS Snapshots - only customer-owned
    if discovery_id == 'aws.ec2.describe_snapshots':
        if 'OwnerIds' not in params:
            params['OwnerIds'] = ['self']  # Only customer snapshots
        logger.debug(f"Applied OwnerIds filter for {discovery_id}")
    
    # EC2 AMIs - only customer-owned
    elif discovery_id == 'aws.ec2.describe_images':
        if 'Owners' not in params:
            params['Owners'] = ['self']  # Only customer AMIs
        logger.debug(f"Applied Owners filter for {discovery_id}")
    
    # RDS Cluster Snapshots - exclude shared/public
    elif discovery_id == 'aws.rds.describe_db_cluster_snapshots':
        if 'IncludeShared' not in params:
            params['IncludeShared'] = False
        if 'IncludePublic' not in params:
            params['IncludePublic'] = False
        if 'MaxRecords' not in params:
            params['MaxRecords'] = 100  # RDS max
        logger.debug(f"Applied IncludeShared/IncludePublic filters for {discovery_id}")
    
    # DocDB Cluster Snapshots - exclude shared/public
    elif discovery_id == 'aws.docdb.describe_d_b_cluster_snapshots':
        if 'IncludeShared' not in params:
            params['IncludeShared'] = False
        if 'IncludePublic' not in params:
            params['IncludePublic'] = False
        if 'MaxRecords' not in params:
            params['MaxRecords'] = 100  # DocDB max
        logger.debug(f"Applied IncludeShared/IncludePublic filters for {discovery_id}")
    
    # Neptune Cluster Snapshots - exclude shared/public
    elif discovery_id == 'aws.neptune.describe_d_b_cluster_snapshots':
        if 'IncludeShared' not in params:
            params['IncludeShared'] = False
        if 'IncludePublic' not in params:
            params['IncludePublic'] = False
        if 'MaxRecords' not in params:
            params['MaxRecords'] = 100  # Neptune max
        logger.debug(f"Applied IncludeShared/IncludePublic filters for {discovery_id}")
    
    # IAM Policies - only customer-managed (already in YAML, but ensure it's there)
    elif discovery_id == 'aws.iam.list_policies':
        if 'Scope' not in params:
            params['Scope'] = 'Local'  # Only customer-managed policies
        logger.debug(f"Applied Scope: Local filter for {discovery_id}")
    
    # SSM Documents - only customer-managed
    elif discovery_id == 'aws.ssm.list_documents':
        if 'Owner' not in params:
            params['Owner'] = 'Self'  # Only customer documents
        logger.debug(f"Applied Owner: Self filter for {discovery_id}")
    
    # SSM Patch Baselines - only customer-managed
    elif discovery_id == 'aws.ssm.describe_patch_baselines':
        if 'Owner' not in params:
            params['Owner'] = 'Self'  # Only customer baselines
        logger.debug(f"Applied Owner: Self filter for {discovery_id}")
    
    # CloudFormation Stacks - only active stacks
    elif discovery_id == 'aws.cloudformation.list_stacks':
        if 'StackStatusFilter' not in params:
            params['StackStatusFilter'] = [
                'CREATE_COMPLETE',
                'UPDATE_COMPLETE',
                'UPDATE_ROLLBACK_COMPLETE',
                'ROLLBACK_COMPLETE',
            ]
        logger.debug(f"Applied StackStatusFilter for {discovery_id}")
    
    return params


def _filter_aws_managed_resources(discovery_id: str, items: list, account_id: Optional[str] = None) -> list:
    """Filter out AWS-managed resources to only keep customer-managed resources
    
    Args:
        discovery_id: The discovery operation ID (e.g., 'aws.kms.list_aliases')
        items: List of resource items to filter
        account_id: Current account ID (for owner checks)
    
    Returns:
        Filtered list containing only customer-managed resources
    """
    if not isinstance(items, list):
        return items
    
    original_count = len(items)
    filtered_items = []
    
    for item in items:
        # KMS Aliases - exclude alias/aws/*
        if discovery_id == 'aws.kms.list_aliases':
            alias_name = item.get('AliasName', '')
            if alias_name and not alias_name.startswith('alias/aws/'):
                filtered_items.append(item)
        
        # Secrets Manager - exclude aws/* and rds!* prefixes
        elif discovery_id == 'aws.secretsmanager.list_secrets':
            name = item.get('Name', '')
            arn = item.get('ARN', '')
            if name and not name.startswith('aws/') and not name.startswith('rds!'):
                filtered_items.append(item)
            elif arn and '/aws/' not in arn and '/rds!' not in arn:
                filtered_items.append(item)
        
        # EventBridge - exclude 'default' event bus
        elif discovery_id == 'aws.events.list_event_buses':
            name = item.get('Name', '')
            if name and name != 'default':
                filtered_items.append(item)
        
        # Athena - exclude 'primary' workgroup
        elif discovery_id == 'aws.athena.list_work_groups':
            name = item.get('Name', '')
            if name and name != 'primary':
                filtered_items.append(item)
        
        # Keyspaces - exclude system_* keyspaces
        elif discovery_id == 'aws.keyspaces.list_keyspaces':
            keyspace_name = item.get('keyspaceName', '')
            if keyspace_name and not keyspace_name.startswith('system_'):
                filtered_items.append(item)
        
        # EC2 FPGA Images - exclude public or other-account images
        elif discovery_id == 'aws.ec2.describe_fpga_images':
            if account_id and not item.get('Public', False) and item.get('OwnerId') == account_id:
                filtered_items.append(item)
        
        # SSM Parameters - exclude /aws/* paths (AWS-managed parameters)
        elif discovery_id == 'aws.ssm.describe_parameters':
            name = item.get('Name', '')
            if name and not name.startswith('/aws/'):
                filtered_items.append(item)
        
        # SSM Automation Executions - exclude AWS-* documents (AWS-managed automations)
        elif discovery_id in ['aws.ssm.list_commands', 'aws.ssm.describe_automation_executions']:
            document_name = item.get('DocumentName', '')
            if document_name and not document_name.startswith('AWS-'):
                filtered_items.append(item)
        
        # CloudWatch Log Groups - exclude /aws/* prefixes (AWS service logs)
        elif discovery_id == 'aws.logs.describe_log_groups':
            log_group_name = item.get('logGroupName', '')
            if log_group_name and not log_group_name.startswith('/aws/'):
                filtered_items.append(item)
        
        # IAM Policies - already filtered at API level with Scope: Local, but double-check
        elif discovery_id == 'aws.iam.list_policies':
            # Policies with Scope: Local are already filtered in YAML, but ensure no AWS-managed slip through
            policy_name = item.get('PolicyName', '')
            arn = item.get('Arn', '')
            # AWS-managed policies have 'aws' in ARN path or start with specific prefixes
            if not (arn and '/aws-service-role/' in arn) and not (policy_name and policy_name.startswith('aws-')):
                filtered_items.append(item)
        
        # Default: include all items (no filter)
        else:
            filtered_items.append(item)
    
    filtered_count = len(filtered_items)
    if filtered_count < original_count:
        logger.debug(f"Filtered {original_count - filtered_count} AWS-managed resources from {discovery_id}, keeping {filtered_count} customer-managed")
    
    return filtered_items

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
            from utils.reporting_manager import generate_arn
            
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
    from utils.reporting_manager import generate_arn, is_global_service
    
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
    
    # Use ARN as resource_uid if available, otherwise construct from available data
    if resource_arn:
        resource_uid = resource_arn
    elif resource_id and account_id:
        resource_uid = f"{service}:{region or 'global'}:{account_id}:{resource_id}"
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
    
    return {
        "resource_id": resource_id,
        "resource_type": resource_type or "resource",
        "resource_arn": resource_arn,
        "resource_uid": resource_uid,
        "is_aws_managed": is_aws_managed  # NEW: Flag for AWS-managed resources
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
            if attempt == MAX_RETRIES - 1:
                raise
            delay = BASE_DELAY * (BACKOFF_FACTOR ** attempt)
            logger.debug(f"Retrying after error: {e} (attempt {attempt+1}/{MAX_RETRIES}, sleep {delay:.2f}s)")
            sleep(delay)

def _call_with_timeout(client, action: str, params: Dict[str, Any], timeout: int = OPERATION_TIMEOUT) -> Dict[str, Any]:
    """
    Make API call with timeout protection for non-paginated operations.
    
    Args:
        client: Boto3 client
        action: API action name
        params: API parameters
        timeout: Maximum time in seconds (default: OPERATION_TIMEOUT)
    
    Returns:
        API response dict
    
    Raises:
        TimeoutError: If operation exceeds timeout
    """
    import time
    from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
    
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
    from utils.reporting_manager import is_cspm_inventory_resource
    
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

def run_global_service(service_name, session_override: Optional[boto3.session.Session] = None):
    """Run compliance checks for a global service"""
    try:
        service_rules = load_service_rules(service_name)
        session = session_override or get_boto3_session(default_region='us-east-1')
        boto3_client_name = get_boto3_client_name(service_name)
        client = session.client(boto3_client_name, region_name='us-east-1', config=BOTO_CONFIG)
        
        # Extract account_id for resource identifier generation
        account_id = None
        try:
            sts_client = session.client('sts', region_name='us-east-1', config=BOTO_CONFIG)
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
        import time
        discovery_start_time = time.time()
        
        # Process independent discoveries in parallel, then dependent sequentially
        max_discovery_workers = int(os.getenv('MAX_DISCOVERY_WORKERS', '50'))
        
        if independent_discoveries:
            logger.info(f"Processing {len(independent_discoveries)} independent discoveries in parallel (max {max_discovery_workers} workers)")
            discovery_futures = {}
            
            def process_independent_discovery(discovery):
                """Process a single independent discovery (called in parallel) - uses same logic as dependent discoveries"""
                # Use the same processing logic as dependent discoveries but with thread-safe locks
                # Import the discovery processing inline (shared with dependent discoveries loop below)
                discovery_id = discovery['discovery_id']
                disc_start = time.time()
                logger.info(f"Processing discovery: {discovery_id}")
                
                # Create thread-local client for this discovery
                local_client = session.client(boto3_client_name, region_name='us-east-1', config=BOTO_CONFIG)
                
                # Track save_as for emit processing (use first call's save_as)
                discovery_save_as = None
                
                # Process calls in order
                for call in discovery.get('calls', []):
                    action = call['action']
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
                                call_client = session.client(specified_client, region_name='us-east-1', config=BOTO_CONFIG)
                            
                            # Thread-safe read of saved_data
                            with saved_data_lock:
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
                            
                            # Apply AWS-managed resource filters at API level (before API call)
                            resolved_params = _apply_aws_managed_filters_at_api_level(
                                discovery_id, resolved_params, account_id
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
                
                # Process emit logic (simplified - full logic in dependent discoveries)
                if discovery_for_each and discovery_save_as and f'{discovery_save_as}_contexts' in saved_data_copy:
                    accumulated_contexts = saved_data_copy[f'{discovery_save_as}_contexts']
                    results = []
                    # ... emit processing logic (see dependent discoveries for full version)
                    if 'items_for' in emit_config:
                        items_path = emit_config['items_for'].replace('{{ ', '').replace(' }}', '')
                        as_var = emit_config.get('as', 'r')
                        for acc_data in accumulated_contexts:
                            response = acc_data['response']
                            item = acc_data['item']
                            context = acc_data['context']
                            response_items = extract_value(response, items_path)
                            
                            # Filter out AWS-managed resources (customer-managed only)
                            response_items = _filter_aws_managed_resources(discovery_id, response_items, account_id)
                            
                            if response_items:
                                for response_item in response_items:
                                    emit_context = {'item': item, 'response': response, as_var: response_item}
                                    emit_context.update(context)
                                    item_data = {}
                                    for field_name, field_template in emit_config.get('item', {}).items():
                                        item_data[field_name] = resolve_template(field_template, emit_context)
                                    
                                    # CRITICAL: Preserve resource_arn from parent item for ARN-based matching (GLOBAL)
                                    # ARN is the universal matching key across all AWS services
                                    # Check multiple possible ARN field names (resource_arn, Arn, arn)
                                    if isinstance(item, dict):
                                        parent_arn = item.get('resource_arn') or item.get('Arn') or item.get('arn')
                                        if parent_arn and isinstance(parent_arn, str) and parent_arn.startswith('arn:aws:'):
                                            item_data['resource_arn'] = parent_arn
                                            logger.debug(f"[EMIT-ARN] {discovery_id}: Preserved parent ARN for items_for emit: {parent_arn[:80]}")
                                    
                                    results.append(item_data)
                    else:
                        for acc_data in accumulated_contexts:
                            response = acc_data['response']
                            item = acc_data['item']
                            context = acc_data['context']
                            
                            # Validate response structure (generic check for all services)
                            if not isinstance(response, dict):
                                logger.warning(f"[EMIT] {discovery_id}: response is not a dict (type={type(response).__name__}), skipping emit")
                                continue
                            
                            item_data = {}
                            emit_context = {'response': response, 'item': item}
                            emit_context.update(context)
                            for field_name, field_template in emit_config.get('item', {}).items():
                                resolved_value = resolve_template(field_template, emit_context)
                                
                                # Handle empty list results (generic fix for all services)
                                if resolved_value == '[]':
                                    # Try direct access as fallback (for simple paths like response.Status)
                                    if field_template.startswith('{{ response.') and field_template.endswith(' }}'):
                                        field_path = field_template.replace('{{ response.', '').replace(' }}', '').strip()
                                        if field_path in response:
                                            resolved_value = str(response[field_path]) if response[field_path] is not None else ''
                                        else:
                                            resolved_value = ''  # Field doesn't exist in response
                                
                                item_data[field_name] = resolved_value
                            results.append(item_data)
                    
                    # Thread-safe write to discovery_results
                    with discovery_results_lock:
                        discovery_results[discovery_id] = results
                elif 'items_for' in emit_config:
                    items_path = emit_config['items_for'].replace('{{ ', '').replace(' }}', '')
                    as_var = emit_config.get('as', 'r')
                    items = extract_value(saved_data_copy, items_path)
                    
                    # Filter out AWS-managed resources (customer-managed only)
                    items = _filter_aws_managed_resources(discovery_id, items, account_id)
                    
                    results = []
                    if items:
                        for item in items:
                            context = {as_var: item}
                            context.update(saved_data_copy)
                            item_data = {}
                            for field_name, field_template in emit_config.get('item', {}).items():
                                resolved_value = resolve_template(field_template, context)
                                item_data[field_name] = resolved_value
                                # #region agent log
                                if discovery_id == 'aws.kms.list_keys' and field_name == 'KeyId' and len(results) < 2:
                                    with open('/Users/apple/Desktop/threat-engine/.cursor/debug.log', 'a') as f:
                                        f.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"A","location":"service_scanner.py:2668","message":"Independent emit: KeyId resolved","data":{"discovery_id":discovery_id,"field_name":field_name,"resolved_value":str(resolved_value)[:100],"item_has_KeyId":'KeyId' in item if isinstance(item, dict) else False,"item_keys":list(item.keys())[:10] if isinstance(item, dict) else "not_dict"},"timestamp":int(time.time()*1000)}) + '\n')
                                # #endregion
                            if isinstance(item, dict):
                                auto_fields = auto_emit_arn_and_name(item, service=service_name, region=None, account_id=account_id)
                                for key, value in auto_fields.items():
                                    if key not in item_data:
                                        item_data[key] = value
                            # #region agent log
                            if discovery_id == 'aws.kms.list_keys' and len(results) < 2:
                                with open('/Users/apple/Desktop/threat-engine/.cursor/debug.log', 'a') as f:
                                    f.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"A","location":"service_scanner.py:2674","message":"Independent emit: item_data before append","data":{"discovery_id":discovery_id,"item_data_keys":list(item_data.keys()),"has_KeyId":"KeyId" in item_data,"KeyId_value":str(item_data.get('KeyId', 'MISSING'))[:100]},"timestamp":int(time.time()*1000)}) + '\n')
                            # #endregion
                            results.append(item_data)
                    # #region agent log
                    if discovery_id == 'aws.kms.list_keys':
                        sample_result = results[0] if results else {}
                        with open('/Users/apple/Desktop/threat-engine/.cursor/debug.log', 'a') as f:
                            f.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"A","location":"service_scanner.py:2676","message":"Independent emit: storing in discovery_results","data":{"discovery_id":discovery_id,"results_count":len(results),"sample_keys":list(sample_result.keys())[:15],"sample_has_KeyId":"KeyId" in sample_result,"sample_KeyId":str(sample_result.get('KeyId', 'MISSING'))[:100]},"timestamp":int(time.time()*1000)}) + '\n')
                    # #endregion
                    with discovery_results_lock:
                        discovery_results[discovery_id] = results
                elif 'item' in emit_config:
                    item_data = {}
                    for field_name, field_template in emit_config['item'].items():
                        item_data[field_name] = resolve_template(field_template, saved_data_copy)
                    auto_fields = auto_emit_arn_and_name(saved_data_copy, service=service_name, region=None, account_id=account_id)
                    for key, value in auto_fields.items():
                        if key not in item_data:
                            item_data[key] = value
                    with discovery_results_lock:
                        discovery_results[discovery_id] = [item_data]
                
                disc_elapsed = time.time() - disc_start
                logger.info(f"Completed discovery {discovery_id}: {disc_elapsed:.2f}s")
            
            # Process independent discoveries in parallel
            with ThreadPoolExecutor(max_workers=min(len(independent_discoveries), max_discovery_workers)) as executor:
                for discovery in independent_discoveries:
                    future = executor.submit(process_independent_discovery, discovery)
                    discovery_futures[future] = discovery.get('discovery_id')
                
                # Wait for all independent discoveries to complete
                for future in as_completed(discovery_futures):
                    discovery_id = discovery_futures[future]
                    try:
                        future.result()
                    except Exception as e:
                        logger.error(f"Failed to process independent discovery {discovery_id}: {e}")
        
        # Process dependent discoveries sequentially (they need parent results)
        processed_ids = {disc.get('discovery_id') for disc in independent_discoveries}
        remaining_discoveries = [disc for disc in all_discoveries if disc.get('discovery_id') not in processed_ids]
        
        for discovery in remaining_discoveries:
            discovery_id = discovery['discovery_id']
            disc_start = time.time()
            logger.info(f"Processing discovery: {discovery_id}")
            
            # Track save_as for emit processing (use first call's save_as)
            discovery_save_as = None
            
            # Process calls in order
            for call in discovery.get('calls', []):
                action = call['action']
                params = call.get('params', {})
                # Auto-generate save_as if not provided
                save_as = call.get('save_as', f'{action}_response')
                # Track the save_as for this discovery (use first call's save_as)
                if discovery_save_as is None:
                    discovery_save_as = save_as
                # Read for_each from discovery level first, then fall back to call level
                for_each = discovery.get('for_each') or call.get('for_each')
                as_var = call.get('as', 'item')
                # Default to 'continue' for better resilience
                on_error = discovery.get('on_error') or call.get('on_error', 'continue')
                
                try:
                    if for_each:
                        # Get the items to iterate over
                        items_ref = for_each.replace('{{ ', '').replace(' }}', '')
                        
                        # Try to get items from discovery_results first (processed items)
                        # If not found, try saved_data (raw API responses)
                        items = discovery_results.get(items_ref)
                        source = 'discovery_results' if items else None
                        if items is None:
                            items = extract_value(saved_data, items_ref)
                            source = 'saved_data' if items else None
                        
                        # #region agent log
                        if items_ref == 'aws.kms.list_keys' and items and len(items) > 0:
                            sample_item = items[0] if isinstance(items, list) else items
                            with open('/Users/apple/Desktop/threat-engine/.cursor/debug.log', 'a') as f:
                                f.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"B","location":"service_scanner.py:2738","message":"Dependent for_each: retrieved items","data":{"discovery_id":discovery_id,"items_ref":items_ref,"source":source,"items_count":len(items) if isinstance(items, list) else 1,"sample_keys":list(sample_item.keys())[:15] if isinstance(sample_item, dict) else "not_dict","has_KeyId":"KeyId" in sample_item if isinstance(sample_item, dict) else False,"KeyId_value":str(sample_item.get('KeyId', 'MISSING'))[:100] if isinstance(sample_item, dict) else "not_dict"},"timestamp":int(time.time()*1000)}) + '\n')
                        # #endregion
                        
                        # Debug logging - check if items have matching keys
                        if items and len(items) > 0:
                            sample_item = items[0] if isinstance(items, list) else items
                            if isinstance(sample_item, dict):
                                # Generic check for common matching keys (for logging only)
                                # The actual matching logic uses a comprehensive list in _match_items()
                                matching_keys_check = ['Name', 'name', 'resource_id', 'resource_name']
                                found_keys = [k for k in matching_keys_check if k in sample_item]
                                if found_keys:
                                    logger.info(f"[FOR_EACH] {discovery_id}: Parent items from {items_ref} have matching keys: {found_keys}")
                                else:
                                    logger.warning(f"[FOR_EACH] {discovery_id}: Parent items from {items_ref} have NO matching keys! Sample keys: {list(sample_item.keys())[:10]}")
                        
                        # Debug logging
                        logger.debug(f"Looking for items in: {items_ref}")
                        logger.debug(f"Discovery results keys: {list(discovery_results.keys())}")
                        logger.debug(f"Saved data keys: {list(saved_data.keys())}")
                        logger.debug(f"Extracted items count: {len(items) if items else 0}")
                        
                        if items:
                            # Accumulate responses from all iterations - PARALLEL EXECUTION
                            accumulated_responses = []
                            accumulated_responses_lock = Lock()
                            
                            # Helper function to process a single item (for parallel execution)
                            def process_item(item):
                                # #region agent log
                                if items_ref == 'aws.kms.list_keys' and len(accumulated_responses) < 2:
                                    with open('/Users/apple/Desktop/threat-engine/.cursor/debug.log', 'a') as f:
                                        f.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"C","location":"service_scanner.py:2792","message":"Dependent process_item: item received","data":{"discovery_id":discovery_id,"item_keys":list(item.keys())[:15] if isinstance(item, dict) else "not_dict","has_KeyId":"KeyId" in item if isinstance(item, dict) else False,"KeyId_value":str(item.get('KeyId', 'MISSING'))[:100] if isinstance(item, dict) else "not_dict"},"timestamp":int(time.time()*1000)}) + '\n')
                                # #endregion
                                # Create context for this item
                                item_context = {as_var: item}
                                item_context.update(saved_data)
                                
                                # Resolve parameters recursively
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
                                
                                logger.debug(f"Calling {action} with params: {resolved_params}")
                                
                                # Create thread-safe client (each thread gets its own client)
                                specified_client = call.get('client', service_name)
                                if specified_client != service_name:
                                    call_client = session.client(specified_client, region_name='us-east-1', config=BOTO_CONFIG)
                                else:
                                    # Use service client - create a new one for thread safety
                                    call_client = session.client(boto3_client_name, region_name='us-east-1', config=BOTO_CONFIG)
                                
                                try:
                                    response = _retry_call(getattr(call_client, action), **resolved_params)
                                    
                                    # Store response with item context for emit processing
                                    result = {
                                        'response': response,
                                        'item': item,
                                        'context': item_context
                                    }
                                    # #region agent log
                                    if items_ref == 'aws.kms.list_keys' and len(accumulated_responses) < 2:
                                        with open('/Users/apple/Desktop/threat-engine/.cursor/debug.log', 'a') as f:
                                            f.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"C","location":"service_scanner.py:2824","message":"Dependent process_item: storing in acc_data","data":{"discovery_id":discovery_id,"result_item_keys":list(item.keys())[:15] if isinstance(item, dict) else "not_dict","result_has_KeyId":"KeyId" in item if isinstance(item, dict) else False,"result_KeyId":str(item.get('KeyId', 'MISSING'))[:100] if isinstance(item, dict) else "not_dict"},"timestamp":int(time.time()*1000)}) + '\n')
                                    # #endregion
                                    return result
                                except Exception as api_error:
                                    if on_error == 'continue':
                                        # Only log warning for unexpected errors
                                        # Expected AWS errors (NoSuch*, NotFound, MissingParameter) are logged at debug level
                                        if _is_expected_aws_error(api_error):
                                            logger.debug(f"Skipped {action}: {api_error}")
                                        else:
                                            logger.warning(f"Failed {action}: {api_error}")
                                        return None  # Return None on error with continue
                                    else:
                                        raise
                            
                            # Parallelize execution across all items
                            # Use ThreadPoolExecutor to process all items concurrently
                            max_workers = min(len(items), int(os.getenv('FOR_EACH_MAX_WORKERS', '50')))
                            logger.info(f"Starting parallel execution for {discovery_id}: {len(items)} items with {max_workers} workers")
                            
                            import time
                            parallel_start = time.time()
                            
                            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                                # Submit all items for parallel processing
                                futures = [executor.submit(process_item, item) for item in items]
                                logger.debug(f"Submitted {len(futures)} tasks for parallel execution")
                                
                                # Collect results as they complete
                                completed_count = 0
                                success_count = 0
                                for future in as_completed(futures):
                                    try:
                                        result = future.result()
                                        if result:  # Only add non-None results
                                            with accumulated_responses_lock:
                                                accumulated_responses.append(result)
                                            success_count += 1
                                        completed_count += 1
                                        # Log progress every 10% or every 5 items (whichever is smaller)
                                        progress_interval = max(1, min(5, len(futures) // 10))
                                        if completed_count % progress_interval == 0 or completed_count == len(futures):
                                            elapsed = time.time() - parallel_start
                                            rate = completed_count / elapsed if elapsed > 0 else 0
                                            eta = (len(futures) - completed_count) / rate if rate > 0 else 0
                                            logger.info(f"Progress: {completed_count}/{len(futures)} items ({success_count} successful) - {rate:.1f} items/sec - ETA: {eta:.0f}s")
                                    except Exception as e:
                                        completed_count += 1
                                        # Handle unexpected errors from futures
                                        if on_error == 'continue':
                                            logger.warning(f"Unexpected error in parallel execution: {e}")
                                        else:
                                            raise
                            
                            parallel_time = time.time() - parallel_start
                            logger.info(f"Completed parallel execution for {discovery_id}: {len(accumulated_responses)} successful responses out of {len(items)} items in {parallel_time:.2f}s")
                            
                            # Save accumulated responses for emit processing
                            if save_as and accumulated_responses:
                                # Store all responses in a list, keyed by save_as (flat for template resolution)
                                # Structure will be organized by discovery_id when saving to disk
                                if save_as not in saved_data:
                                    saved_data[save_as] = []
                                saved_data[save_as] = [r['response'] for r in accumulated_responses]
                                # Store full context for emit processing
                                saved_data[f'{save_as}_contexts'] = accumulated_responses
                                # Store discovery_id mapping for disk save (non-conflicting key)
                                saved_data[f'_discovery_{save_as}'] = discovery_id
                    else:
                        # Regular call - use service client or specified client
                        call_client = client
                        if 'client' in call and call['client'] != service_name:
                            # Only create new client if different from service
                            call_client = session.client(call['client'], region_name='us-east-1', config=BOTO_CONFIG)
                        
                        # Use service client by default, or specified client if different
                        specified_client = call.get('client', service_name)
                        if specified_client != service_name:
                            # Only create new client if different from service
                            call_client = session.client(specified_client, region_name='us-east-1', config=BOTO_CONFIG)
                        
                        # Resolve template variables in params using saved_data context
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
                        
                        # Apply AWS-managed resource filters at API level (before API call)
                        resolved_params = _apply_aws_managed_filters_at_api_level(
                            discovery_id, resolved_params, account_id
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
                            # Apply field extraction if specified
                            if 'fields' in call:
                                extracted_data = {}
                                for field in call['fields']:
                                    value = extract_value(response, field)
                                    if value is not None:
                                        # For array fields like Keys[], store the array directly
                                        if field.endswith('[]'):
                                            extracted_data = value
                                        else:
                                            # For other fields, store in a nested structure
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
                            # Store discovery_id mapping for disk save (non-conflicting key)
                            saved_data[f'_discovery_{save_as}'] = discovery_id
                            
                except Exception as e:
                    if on_error == 'continue':
                        # Only log warning for unexpected errors
                        # Expected AWS errors (NoSuch*, NotFound, MissingParameter) are logged at debug level
                        if _is_expected_aws_error(e):
                            logger.debug(f"Skipped {action}: {e}")
                        else:
                            logger.warning(f"Failed {action}: {e}")
                        continue
                    else:
                        raise
            
            # Process emit
            emit_config = discovery.get('emit', {})
            logger.info(f"[EMIT] {discovery_id}: Starting emit phase (emit_config keys: {list(emit_config.keys())})")
            if _emit_trace_enabled(discovery_id):
                logger.info(f"[EMIT-TRACE] {discovery_id}: starting emit phase")
            
            # Check if this discovery had for_each and accumulated responses
            discovery_for_each = discovery.get('for_each')
            for_each_from_call = None
            for call in discovery.get('calls', []):
                if call.get('for_each'):
                    for_each_from_call = call.get('for_each')
                    break
            
            actual_for_each = discovery_for_each or for_each_from_call
            logger.info(f"[EMIT] {discovery_id}: actual_for_each={actual_for_each}, discovery_save_as={discovery_save_as}")
            
            if actual_for_each and discovery_save_as:
                contexts_key = f'{discovery_save_as}_contexts'
                has_contexts = contexts_key in saved_data
                logger.info(f"[EMIT] {discovery_id}: Checking for {contexts_key} in saved_data: {has_contexts}")
                if has_contexts:
                    logger.info(f"[EMIT] {discovery_id}: Found {contexts_key}, proceeding with emit")
            
            if actual_for_each and discovery_save_as and f'{discovery_save_as}_contexts' in saved_data:
                # This discovery used for_each - process accumulated responses
                accumulated_contexts = saved_data[f'{discovery_save_as}_contexts']
                results = []
                logger.info(f"[EMIT] {discovery_id}: Processing {len(accumulated_contexts)} accumulated responses (save_as={discovery_save_as}, for_each={actual_for_each})")
                if _emit_trace_enabled(discovery_id):
                    logger.info(f"[EMIT-TRACE] {discovery_id}: using accumulated_contexts path, contexts={len(accumulated_contexts)} save_as={discovery_save_as}")
                
                # Check if emit ALSO has items_for (nested iteration: for_each + items_for)
                if 'items_for' in emit_config:
                    items_path = emit_config['items_for'].replace('{{ ', '').replace(' }}', '')
                    as_var = emit_config.get('as', 'r')
                    if _emit_trace_enabled(discovery_id):
                        logger.info(f"[EMIT-TRACE] {discovery_id}: nested items_for path={items_path} as={as_var}")
                    
                    # For each accumulated response, extract items and emit
                    for i, acc_data in enumerate(accumulated_contexts):
                        response = acc_data['response']
                        item = acc_data['item']
                        context = acc_data['context']
                        
                        # Extract items from this specific response (e.g., response.Grants)
                        response_items = extract_value(response, items_path)
                        
                        # Filter out AWS-managed resources (customer-managed only)
                        response_items = _filter_aws_managed_resources(discovery_id, response_items, account_id)
                        
                        if _emit_trace_enabled(discovery_id) and i < 2:
                            # Only trace a couple to avoid log spam
                            n = len(response_items) if isinstance(response_items, list) else (1 if response_items else 0)
                            logger.info(f"[EMIT-TRACE] {discovery_id}: response[{i}] extracted_items_count={n} (type={type(response_items).__name__})")
                        
                        if response_items:
                            for response_item in response_items:
                                # Build context with both original item and response item
                                emit_context = {
                                    'item': item,  # Original for_each item (e.g., bucket)
                                    'response': response,
                                    as_var: response_item  # Item from items_for (e.g., grant)
                                }
                                emit_context.update(context)
                                
                                # Build item data from emit config
                                item_data = {}
                                for field_name, field_template in emit_config.get('item', {}).items():
                                    resolved_value = resolve_template(field_template, emit_context)
                                    item_data[field_name] = resolved_value
                                
                                # CRITICAL: Preserve resource_arn from parent item for ARN-based matching (GLOBAL - items_for)
                                # ARN is the universal matching key across all AWS services
                                # Check multiple possible ARN field names (resource_arn, Arn, arn)
                                if isinstance(item, dict):
                                    parent_arn = item.get('resource_arn') or item.get('Arn') or item.get('arn')
                                    if parent_arn and isinstance(parent_arn, str) and parent_arn.startswith('arn:aws:'):
                                        item_data['resource_arn'] = parent_arn
                                        logger.debug(f"[EMIT-ARN] {discovery_id}: Preserved parent ARN for items_for emit: {parent_arn[:80]}")
                                
                                results.append(item_data)
                else:
                    # No items_for, just emit one item per accumulated response
                    # NEW APPROACH: Store entire response as JSON under discovery name
                    # This avoids template resolution issues and is more robust
                    for idx, acc_data in enumerate(accumulated_contexts):
                        response = acc_data['response']
                        item = acc_data['item']
                        context = acc_data['context']
                        
                        # #region agent log
                        if discovery_id == 'aws.kms.describe_key' and idx < 2:
                            with open('/Users/apple/Desktop/threat-engine/.cursor/debug.log', 'a') as f:
                                f.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"E","location":"service_scanner.py:3047","message":"Dependent emit: item from acc_data","data":{"discovery_id":discovery_id,"idx":idx,"item_type":type(item).__name__,"item_keys":list(item.keys())[:15] if isinstance(item, dict) else "not_dict","has_KeyId":"KeyId" in item if isinstance(item, dict) else False,"KeyId_value":str(item.get('KeyId', 'MISSING'))[:100] if isinstance(item, dict) else "not_dict","KeyId_type":type(item.get('KeyId')).__name__ if isinstance(item, dict) and 'KeyId' in item else "N/A"},"timestamp":int(time.time()*1000)}) + '\n')
                        # #endregion
                        
                        # Validate response structure (generic check for all services)
                        if not isinstance(response, dict):
                            logger.warning(f"[EMIT] {discovery_id}: response is not a dict (type={type(response).__name__}), skipping emit")
                            continue
                        
                        # Extract discovery name (e.g., "aws.s3.get_bucket_versioning" -> "get_bucket_versioning")
                        discovery_name = discovery_id.split('.')[-1] if '.' in discovery_id else discovery_id
                        
                        # Store entire response (excluding ResponseMetadata) as JSON under discovery name
                        # This is much simpler than trying to extract individual fields
                        item_data = {}
                        
                        # CRITICAL: Preserve resource_arn from parent item for ARN-based matching (bundle approach - GLOBAL)
                        # ARN is the universal matching key across all AWS services
                        # Check multiple possible ARN field names (resource_arn, Arn, arn)
                        if isinstance(item, dict):
                            parent_arn = item.get('resource_arn') or item.get('Arn') or item.get('arn')
                            if parent_arn and isinstance(parent_arn, str) and parent_arn.startswith('arn:aws:'):
                                item_data['resource_arn'] = parent_arn
                                logger.debug(f"[EMIT-ARN] {discovery_id}[{idx}]: Preserved parent ARN for bundle emit: {parent_arn[:80]}")
                            elif idx < 2:
                                # Debug: Log if ARN is missing
                                logger.warning(f"[EMIT-ARN] {discovery_id}[{idx}]: Parent item has NO ARN! Available keys: {list(item.keys())[:15]}")
                        else:
                            if idx < 2:
                                logger.warning(f"[EMIT-ARN] {discovery_id}[{idx}]: Parent item is not a dict (type: {type(item).__name__})")
                        
                        # Debug: Log full response structure for first few items
                        if idx < 2:
                            logger.info(f"[EMIT-BUNDLE] {discovery_id}[{idx}]: Full response keys: {list(response.keys())}")
                            logger.info(f"[EMIT-BUNDLE] {discovery_id}[{idx}]: Response type: {type(response).__name__}")
                            # Log response contents (excluding ResponseMetadata)
                            for key, value in response.items():
                                if key != 'ResponseMetadata':
                                    logger.info(f"[EMIT-BUNDLE] {discovery_id}[{idx}]: response[{key}]={value}")
                        
                        # Store entire response data (excluding ResponseMetadata) under discovery name
                        response_data = {k: v for k, v in response.items() if k != 'ResponseMetadata'}
                        if response_data:
                            item_data[discovery_name] = response_data
                            logger.debug(f"[EMIT] {discovery_id}[{idx}]: Stored entire response under '{discovery_name}' with {len(response_data)} fields: {list(response_data.keys())}")
                        else:
                            # Response only had ResponseMetadata - this might be normal for some APIs
                            # Store empty dict to track attempt, but log at debug level (not warning)
                            item_data[discovery_name] = {}
                            logger.debug(f"[EMIT] {discovery_id}[{idx}]: Response only contains ResponseMetadata (no data fields), storing empty dict")
                        
                        results.append(item_data)
                
                discovery_results[discovery_id] = results
                if _emit_trace_enabled(discovery_id):
                    logger.info(f"[EMIT-TRACE] {discovery_id}: emit done, emitted_count={len(results)}")
            
            elif 'items_for' in emit_config:
                items_path = emit_config['items_for'].replace('{{ ', '').replace(' }}', '')
                as_var = emit_config.get('as', 'r')
                if _emit_trace_enabled(discovery_id):
                    logger.info(f"[EMIT-TRACE] {discovery_id}: using saved_data items_for path={items_path} as={as_var}")
                
                # Extract items from saved data
                items = extract_value(saved_data, items_path)
                
                results = []
                
                if items:
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.debug("Processing %d items for %s", len(items), discovery_id)
                    for item in items:
                        context = {as_var: item}
                        context.update(saved_data)
                        # Avoid expensive stringification of full context at INFO level
                        if logger.isEnabledFor(logging.DEBUG):
                            logger.debug("Emit context var=%s keys=%s", as_var, list(context.keys()))
                            logger.debug("Saved data keys: %s", list(saved_data.keys()))
                        
                        item_data = {}
                        # First, emit explicitly configured fields
                        for field_name, field_template in emit_config.get('item', {}).items():
                            if logger.isEnabledFor(logging.DEBUG):
                                logger.debug("Processing field %s with template: %s", field_name, field_template)
                            resolved_value = resolve_template(field_template, context)
                            item_data[field_name] = resolved_value
                            if logger.isEnabledFor(logging.DEBUG):
                                logger.debug("Resolved %s: %s", field_name, resolved_value)
                        
                        # Then, automatically add ARN and Name fields if they exist in the item
                        if isinstance(item, dict):
                            auto_fields = auto_emit_arn_and_name(item, service=service_name, region=None, account_id=account_id)
                            # Only add if not already explicitly configured
                            for key, value in auto_fields.items():
                                if key not in item_data:
                                    item_data[key] = value
                        
                        # CRITICAL: Ensure resource_arn is always present for ARN-based matching
                        # auto_emit_arn_and_name() should have added it, but ensure it's present
                        if isinstance(item, dict):
                            # Ensure resource_arn is preserved (auto_emit_arn_and_name should have added it)
                            if 'resource_arn' not in item_data:
                                # Try to get from auto_fields or item
                                arn = item.get('resource_arn') or item.get('Arn') or item.get('arn')
                                if arn and isinstance(arn, str) and arn.startswith('arn:aws:'):
                                    item_data['resource_arn'] = arn
                                    logger.debug(f"[EMIT-ARN] {discovery_id}: Added resource_arn for independent discovery: {arn[:80]}")
                        
                        results.append(item_data)
                
                discovery_results[discovery_id] = results
                if _emit_trace_enabled(discovery_id):
                    logger.info(f"[EMIT-TRACE] {discovery_id}: emit done, emitted_count={len(results)}")
            
            elif 'item' in emit_config:
                # Single item
                item_data = {}
                # First, emit explicitly configured fields
                for field_name, field_template in emit_config['item'].items():
                    resolved_value = resolve_template(field_template, saved_data)
                    item_data[field_name] = resolved_value
                
                # Then, automatically add ARN and Name fields if they exist
                auto_fields = auto_emit_arn_and_name(saved_data, service=service_name, region=None, account_id=account_id)
                # Only add if not already explicitly configured
                for key, value in auto_fields.items():
                    if key not in item_data:
                        item_data[key] = value
                
                discovery_results[discovery_id] = [item_data]
                if _emit_trace_enabled(discovery_id):
                    logger.info(f"[EMIT-TRACE] {discovery_id}: emit done, emitted_count=1")
            
            # Log discovery completion time
            disc_elapsed = time.time() - disc_start
            logger.info(f"Completed discovery {discovery_id}: {disc_elapsed:.2f}s")
        
        # ============================================================
        # PHASE 2: BUILD INVENTORY (optional - for reporting)
        # ============================================================
        # Enrich inventory by merging dependent discoveries into independent ones
        try:
            discovery_results = _enrich_inventory_with_dependent_discoveries(
                discovery_results, service_rules, dependency_graph
            )
        except Exception as e:
            logger.warning(f"Failed to enrich inventory with dependent discoveries: {e}")
            import traceback
            logger.debug(traceback.format_exc())
        
        # Compute primary inventory items (fallback for checks)
        primary_items = None
        try:
            from utils.reporting_manager import is_cspm_inventory_resource
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
        # All checks share the same discovery_results (reference, not copy)
        # Checks are independent - they only depend on discoveries, not each other
        all_checks = service_rules.get('checks', [])
        checks_output = []
        
        # Skip checks if MAX_CHECK_WORKERS is set to 0 (for raw data collection)
        max_check_workers = int(os.getenv('MAX_CHECK_WORKERS', '50'))
        if max_check_workers == 0:
            logger.info("Skipping checks (MAX_CHECK_WORKERS=0 - discovery data collection only)")
            all_checks = []
        
        if all_checks:
            logger.info(f"Running {len(all_checks)} checks in parallel (max {max_check_workers} workers)")
            
            # Run all checks in parallel
            with ThreadPoolExecutor(max_workers=max_check_workers) as executor:
                futures = {
                    executor.submit(
                        _run_single_check,
                        check,
                        service_name,
                        'us-east-1',  # Global services use us-east-1
                        account_id,
                        discovery_results,  # Shared reference - all checks read from same data
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
                        import traceback
                        logger.debug(traceback.format_exc())
        
        return {
            'inventory': discovery_results,
            'checks': checks_output,
            'service': service_name,
            'scope': 'global',
            '_raw_data': saved_data  # Include raw API responses for saving to disk
        }
        
    except Exception as e:
        import traceback
        logger.error(f"Global service {service_name} failed: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return {
            'inventory': {},
            'checks': [],
            'service': service_name,
            'scope': 'global',
            'unavailable': True,
            'error': str(e)
        }

def run_regional_service(service_name, region, session_override: Optional[boto3.session.Session] = None):
    """Run compliance checks for a regional service"""
    try:
        service_rules = load_service_rules(service_name)
        session = session_override or get_boto3_session(default_region=region)
        boto3_client_name = get_boto3_client_name(service_name)
        client = session.client(boto3_client_name, region_name=region, config=BOTO_CONFIG)
        
        # Extract account_id for resource identifier generation
        account_id = None
        try:
            sts_client = session.client('sts', region_name=region, config=BOTO_CONFIG)
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
        import time
        discovery_start_time = time.time()
        
        # Process independent discoveries in parallel, then dependent sequentially
        max_discovery_workers = int(os.getenv('MAX_DISCOVERY_WORKERS', '50'))
        
        if independent_discoveries:
            logger.info(f"Processing {len(independent_discoveries)} independent discoveries in parallel (max {max_discovery_workers} workers)")
            discovery_futures = {}
            
            def process_independent_discovery(discovery):
                """Process a single independent discovery (called in parallel) - uses same logic as dependent discoveries"""
                discovery_id = discovery['discovery_id']
                disc_start = time.time()
                logger.info(f"Processing discovery: {discovery_id}")
                
                # Create thread-local client for this discovery
                local_client = session.client(boto3_client_name, region_name=region, config=BOTO_CONFIG)
                
                # Track save_as for emit processing (use first call's save_as)
                discovery_save_as = None
                
                # Process calls in order
                for call in discovery.get('calls', []):
                    action = call['action']
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
                                call_client = session.client(specified_client, region_name=region, config=BOTO_CONFIG)
                            
                            # Thread-safe read of saved_data
                            with saved_data_lock:
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
                            
                            # Check if this is a list/describe operation that should be paginated
                            is_list_or_describe = (
                                action.startswith('list_') or 
                                (action.startswith('describe_') and any(x in action for x in 
                                    ['snapshots', 'images', 'volumes', 'instances', 'policies', 'roles', 
                                     'users', 'groups', 'functions', 'tables', 'queues', 'topics', 
                                     'clusters', 'streams', 'keys', 'aliases', 'grants', 'secrets', 
                                     'domains', 'zones', 'distributions', 'backups', 'vaults', 'plans',
                                     'jobs', 'tasks', 'services', 'definitions', 'zones', 'configs']))
                            )
                            
                            # Apply AWS-managed resource filters at API level (before API call)
                            resolved_params = _apply_aws_managed_filters_at_api_level(
                                discovery_id, resolved_params, account_id
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
                
                # Process emit - thread-safe read/write (same logic as global service)
                emit_config = discovery.get('emit', {})
                discovery_for_each = discovery.get('for_each')
                
                # Read saved_data thread-safely
                with saved_data_lock:
                    saved_data_copy = saved_data.copy()
                
                # Process emit logic (simplified - full logic in dependent discoveries)
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
                            if response_items:
                                for response_item in response_items:
                                    emit_context = {'item': item, 'response': response, as_var: response_item}
                                    emit_context.update(context)
                                    item_data = {}
                                    for field_name, field_template in emit_config.get('item', {}).items():
                                        item_data[field_name] = resolve_template(field_template, emit_context)
                                    results.append(item_data)
                    else:
                        for acc_data in accumulated_contexts:
                            response = acc_data['response']
                            item = acc_data['item']
                            context = acc_data['context']
                            item_data = {}
                            emit_context = {'response': response, 'item': item}
                            emit_context.update(context)
                            for field_name, field_template in emit_config.get('item', {}).items():
                                item_data[field_name] = resolve_template(field_template, emit_context)
                            results.append(item_data)
                    with discovery_results_lock:
                        discovery_results[discovery_id] = results
                elif 'items_for' in emit_config:
                    items_path = emit_config['items_for'].replace('{{ ', '').replace(' }}', '')
                    as_var = emit_config.get('as', 'r')
                    items = extract_value(saved_data_copy, items_path)
                    results = []
                    if items:
                        for item in items:
                            context = {as_var: item}
                            context.update(saved_data_copy)
                            item_data = {}
                            for field_name, field_template in emit_config.get('item', {}).items():
                                resolved_value = resolve_template(field_template, context)
                                item_data[field_name] = resolved_value
                                # #region agent log
                                if discovery_id == 'aws.kms.list_keys' and field_name == 'KeyId' and len(results) < 2:
                                    with open('/Users/apple/Desktop/threat-engine/.cursor/debug.log', 'a') as f:
                                        f.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"A","location":"service_scanner.py:3607","message":"Independent emit (REGIONAL): KeyId resolved","data":{"discovery_id":discovery_id,"field_name":field_name,"resolved_value":str(resolved_value)[:100],"item_has_KeyId":'KeyId' in item if isinstance(item, dict) else False,"item_keys":list(item.keys())[:10] if isinstance(item, dict) else "not_dict"},"timestamp":int(time.time()*1000)}) + '\n')
                                # #endregion
                            if isinstance(item, dict):
                                auto_fields = auto_emit_arn_and_name(item, service=service_name, region=None, account_id=account_id)
                                for key, value in auto_fields.items():
                                    if key not in item_data:
                                        item_data[key] = value
                            # #region agent log
                            if discovery_id == 'aws.kms.list_keys' and len(results) < 2:
                                with open('/Users/apple/Desktop/threat-engine/.cursor/debug.log', 'a') as f:
                                    f.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"A","location":"service_scanner.py:3613","message":"Independent emit (REGIONAL): item_data before append","data":{"discovery_id":discovery_id,"item_data_keys":list(item_data.keys()),"has_KeyId":"KeyId" in item_data,"KeyId_value":str(item_data.get('KeyId', 'MISSING'))[:100]},"timestamp":int(time.time()*1000)}) + '\n')
                            # #endregion
                            results.append(item_data)
                    # #region agent log
                    if discovery_id == 'aws.kms.list_keys':
                        sample_result = results[0] if results else {}
                        with open('/Users/apple/Desktop/threat-engine/.cursor/debug.log', 'a') as f:
                            f.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"A","location":"service_scanner.py:3615","message":"Independent emit (REGIONAL): storing in discovery_results","data":{"discovery_id":discovery_id,"results_count":len(results),"sample_keys":list(sample_result.keys())[:15],"sample_has_KeyId":"KeyId" in sample_result,"sample_KeyId":str(sample_result.get('KeyId', 'MISSING'))[:100]},"timestamp":int(time.time()*1000)}) + '\n')
                    # #endregion
                    with discovery_results_lock:
                        discovery_results[discovery_id] = results
                elif 'item' in emit_config:
                    item_data = {}
                    for field_name, field_template in emit_config['item'].items():
                        item_data[field_name] = resolve_template(field_template, saved_data_copy)
                    auto_fields = auto_emit_arn_and_name(saved_data_copy, service=service_name, region=None, account_id=account_id)
                    for key, value in auto_fields.items():
                        if key not in item_data:
                            item_data[key] = value
                    with discovery_results_lock:
                        discovery_results[discovery_id] = [item_data]
                
                disc_elapsed = time.time() - disc_start
                logger.info(f"Completed discovery {discovery_id}: {disc_elapsed:.2f}s")
            
            # Process independent discoveries in parallel
            with ThreadPoolExecutor(max_workers=min(len(independent_discoveries), max_discovery_workers)) as executor:
                for discovery in independent_discoveries:
                    future = executor.submit(process_independent_discovery, discovery)
                    discovery_futures[future] = discovery.get('discovery_id')
                
                # Wait for all independent discoveries to complete
                for future in as_completed(discovery_futures):
                    discovery_id = discovery_futures[future]
                    try:
                        future.result()
                    except Exception as e:
                        logger.error(f"Failed to process independent discovery {discovery_id}: {e}")
        
        # Process dependent discoveries sequentially (they need parent results)
        processed_ids = {disc.get('discovery_id') for disc in independent_discoveries}
        remaining_discoveries = [disc for disc in all_discoveries if disc.get('discovery_id') not in processed_ids]
        
        for discovery in remaining_discoveries:
            discovery_id = discovery['discovery_id']
            disc_start = time.time()
            logger.info(f"Processing discovery: {discovery_id}")
            
            # Track save_as for emit processing (use first call's save_as)
            discovery_save_as = None
            
            # Process calls in order
            for call in discovery.get('calls', []):
                action = call['action']
                params = call.get('params', {})
                # Auto-generate save_as if not provided
                save_as = call.get('save_as', f'{action}_response')
                # Track the save_as for this discovery (use first call's save_as)
                if discovery_save_as is None:
                    discovery_save_as = save_as
                # Read for_each from discovery level first, then fall back to call level
                for_each = discovery.get('for_each') or call.get('for_each')
                as_var = call.get('as', 'item')
                # Default to 'continue' for better resilience
                on_error = discovery.get('on_error') or call.get('on_error', 'continue')
                
                try:
                    if for_each:
                        # Get the items to iterate over
                        items_ref = for_each.replace('{{ ', '').replace(' }}', '')
                        # Try to get items from discovery_results first (processed items)
                        # If not found, try saved_data (raw API responses)
                        items = discovery_results.get(items_ref)
                        if items is None:
                            items = extract_value(saved_data, items_ref)
                        
                        if items:
                            # Accumulate responses from all iterations - PARALLEL EXECUTION
                            accumulated_responses = []
                            accumulated_responses_lock = Lock()
                            
                            # Helper function to process a single item (for parallel execution)
                            def process_item(item):
                                # Create context for this item
                                item_context = {as_var: item}
                                item_context.update(saved_data)
                                
                                # Resolve parameters recursively
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
                                
                                logger.debug(f"Calling {action} with params: {resolved_params}")
                                
                                # Create thread-safe client (each thread gets its own client)
                                specified_client = call.get('client', service_name)
                                if specified_client != service_name:
                                    call_client = session.client(specified_client, region_name=region, config=BOTO_CONFIG)
                                else:
                                    # Use service client - create a new one for thread safety
                                    call_client = session.client(boto3_client_name, region_name=region, config=BOTO_CONFIG)
                                
                                try:
                                    response = _retry_call(getattr(call_client, action), **resolved_params)
                                    
                                    # Store response with item context for emit processing
                                    result = {
                                        'response': response,
                                        'item': item,
                                        'context': item_context
                                    }
                                    # #region agent log
                                    if items_ref == 'aws.kms.list_keys' and len(accumulated_responses) < 2:
                                        with open('/Users/apple/Desktop/threat-engine/.cursor/debug.log', 'a') as f:
                                            f.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"C","location":"service_scanner.py:3736","message":"Dependent process_item (REGIONAL): storing in acc_data","data":{"discovery_id":discovery_id,"result_item_keys":list(item.keys())[:15] if isinstance(item, dict) else "not_dict","result_has_KeyId":"KeyId" in item if isinstance(item, dict) else False,"result_KeyId":str(item.get('KeyId', 'MISSING'))[:100] if isinstance(item, dict) else "not_dict"},"timestamp":int(time.time()*1000)}) + '\n')
                                    # #endregion
                                    return result
                                except Exception as api_error:
                                    if on_error == 'continue':
                                        # Only log warning for unexpected errors
                                        # Expected AWS errors (NoSuch*, NotFound, MissingParameter) are logged at debug level
                                        if _is_expected_aws_error(api_error):
                                            logger.debug(f"Skipped {action}: {api_error}")
                                        else:
                                            logger.warning(f"Failed {action}: {api_error}")
                                        return None  # Return None on error with continue
                                    else:
                                        raise
                            
                            # Parallelize execution across all items
                            # Use ThreadPoolExecutor to process all items concurrently
                            max_workers = min(len(items), int(os.getenv('FOR_EACH_MAX_WORKERS', '50')))
                            logger.info(f"Starting parallel execution for {discovery_id}: {len(items)} items with {max_workers} workers")
                            
                            import time
                            parallel_start = time.time()
                            
                            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                                # Submit all items for parallel processing
                                futures = [executor.submit(process_item, item) for item in items]
                                logger.debug(f"Submitted {len(futures)} tasks for parallel execution")
                                
                                # Collect results as they complete
                                completed_count = 0
                                success_count = 0
                                for future in as_completed(futures):
                                    try:
                                        result = future.result()
                                        if result:  # Only add non-None results
                                            with accumulated_responses_lock:
                                                accumulated_responses.append(result)
                                            success_count += 1
                                        completed_count += 1
                                        # Log progress every 10% or every 5 items (whichever is smaller)
                                        progress_interval = max(1, min(5, len(futures) // 10))
                                        if completed_count % progress_interval == 0 or completed_count == len(futures):
                                            elapsed = time.time() - parallel_start
                                            rate = completed_count / elapsed if elapsed > 0 else 0
                                            eta = (len(futures) - completed_count) / rate if rate > 0 else 0
                                            logger.info(f"Progress: {completed_count}/{len(futures)} items ({success_count} successful) - {rate:.1f} items/sec - ETA: {eta:.0f}s")
                                    except Exception as e:
                                        completed_count += 1
                                        # Handle unexpected errors from futures
                                        if on_error == 'continue':
                                            logger.warning(f"Unexpected error in parallel execution: {e}")
                                        else:
                                            raise
                            
                            parallel_time = time.time() - parallel_start
                            logger.info(f"Completed parallel execution for {discovery_id}: {len(accumulated_responses)} successful responses out of {len(items)} items in {parallel_time:.2f}s")
                            
                            # Save accumulated responses for emit processing
                            if save_as and accumulated_responses:
                                # Store all responses in a list, keyed by save_as (flat for template resolution)
                                # Structure will be organized by discovery_id when saving to disk
                                if save_as not in saved_data:
                                    saved_data[save_as] = []
                                saved_data[save_as] = [r['response'] for r in accumulated_responses]
                                # Store full context for emit processing
                                saved_data[f'{save_as}_contexts'] = accumulated_responses
                                # Store discovery_id mapping for disk save (non-conflicting key)
                                saved_data[f'_discovery_{save_as}'] = discovery_id
                    else:
                        # Regular call - use service client or specified client
                        call_client = client
                        specified_client = call.get('client', service_name)
                        if specified_client != service_name:
                            # Only create new client if different from service
                            call_client = session.client(specified_client, region_name=region, config=BOTO_CONFIG)
                        
                        # Resolve template variables in params using saved_data context
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
                        
                        # Check if this is a list/describe operation that should be paginated
                        is_list_or_describe = (
                            action.startswith('list_') or 
                            (action.startswith('describe_') and any(x in action for x in 
                                ['snapshots', 'images', 'volumes', 'instances', 'policies', 'roles', 
                                 'users', 'groups', 'functions', 'tables', 'queues', 'topics', 
                                 'clusters', 'streams', 'keys', 'aliases', 'grants', 'secrets', 
                                 'domains', 'zones', 'distributions', 'backups', 'vaults', 'plans',
                                 'jobs', 'tasks', 'services', 'definitions', 'zones', 'configs']))
                        )
                        
                        # Always attempt pagination for list/describe operations (independent discoveries only)
                        if not for_each and is_list_or_describe:
                            # Add default pagination param if not specified in YAML
                            has_pagination_param = any(key in resolved_params for key in 
                                ['MaxResults', 'MaxRecords', 'Limit', 'MaxItems'])
                            
                            if not has_pagination_param:
                                # Default: MaxResults 1000 (YAML can override if service has lower limit)
                                resolved_params['MaxResults'] = 1000
                                logger.debug(f"Added default MaxResults: 1000 for {action}")
                            
                            # Use pagination helper (gracefully handles if pagination not supported)
                            response = _paginate_api_call(call_client, action, resolved_params)
                        else:
                            # Single API call (no pagination)
                            response = _retry_call(getattr(call_client, action), **resolved_params)
                        if save_as:
                            saved_data[save_as] = response
                            # Store discovery_id mapping for disk save (non-conflicting key)
                            saved_data[f'_discovery_{save_as}'] = discovery_id
                            
                except Exception as e:
                    if on_error == 'continue':
                        # Only log warning for unexpected errors
                        # Expected AWS errors (NoSuch*, NotFound, MissingParameter) are logged at debug level
                        if _is_expected_aws_error(e):
                            logger.debug(f"Skipped {action}: {e}")
                        else:
                            logger.warning(f"Failed {action}: {e}")
                        continue
                    else:
                        raise
            
            # Process emit
            emit_config = discovery.get('emit', {})
            
            # Check if this discovery had for_each and accumulated responses
            discovery_for_each = discovery.get('for_each')
            if discovery_for_each and discovery_save_as and f'{discovery_save_as}_contexts' in saved_data:
                # This discovery used for_each - process accumulated responses
                accumulated_contexts = saved_data[f'{discovery_save_as}_contexts']
                results = []
                
                # Check if emit ALSO has items_for (nested iteration: for_each + items_for)
                if 'items_for' in emit_config:
                    items_path = emit_config['items_for'].replace('{{ ', '').replace(' }}', '')
                    as_var = emit_config.get('as', 'r')
                    
                    # For each accumulated response, extract items and emit
                    for acc_data in accumulated_contexts:
                        response = acc_data['response']
                        item = acc_data['item']
                        context = acc_data['context']
                        
                        # Extract items from this specific response (e.g., response.Grants)
                        response_items = extract_value(response, items_path)
                        
                        # Filter out AWS-managed resources (customer-managed only)
                        response_items = _filter_aws_managed_resources(discovery_id, response_items, account_id)
                        
                        if response_items:
                            for response_item in response_items:
                                # Build context with both original item and response item
                                emit_context = {
                                    'item': item,  # Original for_each item (e.g., bucket)
                                    'response': response,
                                    as_var: response_item  # Item from items_for (e.g., grant)
                                }
                                emit_context.update(context)
                                
                                # Build item data from emit config
                                item_data = {}
                                for field_name, field_template in emit_config.get('item', {}).items():
                                    resolved_value = resolve_template(field_template, emit_context)
                                    item_data[field_name] = resolved_value
                                
                                # CRITICAL: Preserve resource_arn from parent item for ARN-based matching (REGIONAL)
                                # ARN is the universal matching key across all AWS services
                                # Check multiple possible ARN field names (resource_arn, Arn, arn)
                                if isinstance(item, dict):
                                    parent_arn = item.get('resource_arn') or item.get('Arn') or item.get('arn')
                                    if parent_arn and isinstance(parent_arn, str) and parent_arn.startswith('arn:aws:'):
                                        item_data['resource_arn'] = parent_arn
                                        logger.debug(f"[EMIT-ARN] {discovery_id}: Preserved parent ARN for items_for emit: {parent_arn[:80]}")
                                
                                results.append(item_data)
                else:
                    # No items_for, just emit one item per accumulated response
                    for idx, acc_data in enumerate(accumulated_contexts):
                        response = acc_data['response']
                        item = acc_data['item']
                        context = acc_data['context']
                        
                        # #region agent log
                        if discovery_id == 'aws.kms.describe_key' and idx < 2:
                            with open('/Users/apple/Desktop/threat-engine/.cursor/debug.log', 'a') as f:
                                f.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"E","location":"service_scanner.py:3924","message":"Dependent emit (REGIONAL): item from acc_data","data":{"discovery_id":discovery_id,"idx":idx,"item_type":type(item).__name__,"item_keys":list(item.keys())[:15] if isinstance(item, dict) else "not_dict","has_KeyId":"KeyId" in item if isinstance(item, dict) else False,"KeyId_value":str(item.get('KeyId', 'MISSING'))[:100] if isinstance(item, dict) else "not_dict","KeyId_type":type(item.get('KeyId')).__name__ if isinstance(item, dict) and 'KeyId' in item else "N/A"},"timestamp":int(time.time()*1000)}) + '\n')
                        # #endregion
                        
                        # Build item data from emit config
                        item_data = {}
                        # #region agent log
                        if discovery_id == 'aws.kms.describe_key' and idx < 2:
                            # Check if emit_config is empty (bundle approach)
                            with open('/Users/apple/Desktop/threat-engine/.cursor/debug.log', 'a') as f:
                                f.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"D","location":"service_scanner.py:3930","message":"Dependent emit (REGIONAL): emit_config check","data":{"discovery_id":discovery_id,"idx":idx,"emit_config_keys":list(emit_config.keys()),"emit_config_empty":len(emit_config) == 0},"timestamp":int(time.time()*1000)}) + '\n')
                        # #endregion
                        for field_name, field_template in emit_config.get('item', {}).items():
                            # Create context with response and item
                            emit_context = {'response': response, 'item': item}
                            emit_context.update(context)
                            resolved_value = resolve_template(field_template, emit_context)
                            item_data[field_name] = resolved_value
                        
                        # CRITICAL: Preserve resource_arn from parent item for ARN-based matching (bundle approach)
                        # When emit_config is empty (bundle approach), we still need to preserve
                        # the resource_arn from the parent item so that enrichment can match dependent items
                        # Check multiple possible ARN field names (resource_arn, Arn, arn)
                        if not emit_config.get('item') and isinstance(item, dict):
                            parent_arn = item.get('resource_arn') or item.get('Arn') or item.get('arn')
                            if parent_arn and isinstance(parent_arn, str) and parent_arn.startswith('arn:aws:'):
                                item_data['resource_arn'] = parent_arn
                                logger.debug(f"[EMIT-ARN] {discovery_id}: Preserved parent ARN for bundle emit: {parent_arn[:80]}")
                        
                        results.append(item_data)
                
                discovery_results[discovery_id] = results
            
            elif 'items_for' in emit_config:
                items_path = emit_config['items_for'].replace('{{ ', '').replace(' }}', '')
                as_var = emit_config.get('as', 'r')
                items = extract_value(saved_data, items_path)
                results = []
                
                if items:
                    # Keep debug logging cheap (no giant f-strings / context dumps)
                    for item in items:
                        context = {as_var: item}
                        context.update(saved_data)
                        item_data = {}
                        # First, emit explicitly configured fields
                        for field_name, field_template in emit_config.get('item', {}).items():
                            resolved_value = resolve_template(field_template, context)
                            item_data[field_name] = resolved_value
                        
                        # Then, automatically add ARN and Name fields if they exist in the item
                        if isinstance(item, dict):
                            auto_fields = auto_emit_arn_and_name(item, service=service_name, region=region, account_id=account_id)
                            # Only add if not already explicitly configured
                            for key, value in auto_fields.items():
                                if key not in item_data:
                                    item_data[key] = value
                        
                        results.append(item_data)
                
                discovery_results[discovery_id] = results
            
            elif 'item' in emit_config:
                item_data = {}
                # First, emit explicitly configured fields
                for field_name, field_template in emit_config['item'].items():
                    resolved_value = resolve_template(field_template, saved_data)
                    item_data[field_name] = resolved_value
                
                # Then, automatically add ARN and Name fields if they exist
                auto_fields = auto_emit_arn_and_name(saved_data, service=service_name, region=region, account_id=account_id)
                # Only add if not already explicitly configured
                for key, value in auto_fields.items():
                    if key not in item_data:
                        item_data[key] = value
                
                discovery_results[discovery_id] = [item_data]
            
            # Log discovery completion time
            disc_elapsed = time.time() - disc_start
            logger.info(f"Completed discovery {discovery_id}: {disc_elapsed:.2f}s")
        
        # ============================================================
        # PHASE 2: BUILD INVENTORY (optional - for reporting)
        # ============================================================
        # Enrich inventory by merging dependent discoveries into independent ones
        try:
            discovery_results = _enrich_inventory_with_dependent_discoveries(
                discovery_results, service_rules, dependency_graph
            )
        except Exception as e:
            logger.warning(f"Failed to enrich inventory with dependent discoveries: {e}")
            import traceback
            logger.debug(traceback.format_exc())
        
        # Compute primary inventory items (fallback for checks)
        primary_items = None
        try:
            from utils.reporting_manager import is_cspm_inventory_resource
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
        # All checks share the same discovery_results (reference, not copy)
        # Checks are independent - they only depend on discoveries, not each other
        all_checks = service_rules.get('checks', [])
        checks_output = []
        
        # Skip checks if MAX_CHECK_WORKERS is set to 0 (for raw data collection)
        max_check_workers = int(os.getenv('MAX_CHECK_WORKERS', '50'))
        if max_check_workers == 0:
            logger.info("Skipping checks (MAX_CHECK_WORKERS=0 - discovery data collection only)")
            all_checks = []
        
        if all_checks:
            logger.info(f"Running {len(all_checks)} checks in parallel (max {max_check_workers} workers)")
            
            # Run all checks in parallel
            with ThreadPoolExecutor(max_workers=max_check_workers) as executor:
                futures = {
                    executor.submit(
                        _run_single_check,
                        check,
                        service_name,
                        region,
                        account_id,
                        discovery_results,  # Shared reference - all checks read from same data
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
                        import traceback
                        logger.debug(traceback.format_exc())
        
        return {
            'inventory': discovery_results,
            'checks': checks_output,
            'service': service_name,
            'scope': 'regional',
            'region': region,
            '_raw_data': saved_data  # Include raw API responses for saving to disk
        }
        
    except Exception as e:
        import traceback
        logger.error(f"Regional service {service_name} in {region} failed: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return {
            'inventory': {},
            'checks': [],
            'service': service_name,
            'scope': 'regional',
            'region': region,
            'unavailable': True,
            'error': str(e)
        }

def main():
    """Main entry point for the compliance engine"""
    enabled_services = load_enabled_services_with_scope()
    
    if not enabled_services:
        logger.warning("No enabled services found")
        return
    
    logger.info(f"Running compliance checks for {len(enabled_services)} services")
    
    all_results = []
    
    for service_name, scope in enabled_services:
        logger.info(f"Processing {service_name} ({scope})")
        
        if scope == 'global':
            result = run_global_service(service_name)
        else:
            result = run_regional_service(service_name, 'us-east-1')
        
        all_results.append(result)
        
        # Print summary
        if result.get('checks'):
            passed = sum(1 for c in result['checks'] if c['result'] == 'PASS')
            failed = sum(1 for c in result['checks'] if c['result'] == 'FAIL')
            errors = sum(1 for c in result['checks'] if c['result'] == 'ERROR')
            logger.info(f"  Results: {passed} PASS, {failed} FAIL, {errors} ERROR")
    
    logger.info("Compliance check completed")
    
    # Save results to reporting folder
    try:
        # Get account ID for reporting
        account_id = None
        try:
            sts_client = get_boto3_session().client('sts')
            account_id = sts_client.get_caller_identity().get('Account')
        except Exception as e:
            logger.warning(f"Could not get account ID: {e}")
        
        # Save reporting bundle with ARN generation and hierarchical structure
        report_folder = save_reporting_bundle(all_results, account_id)
        logger.info(f"Results saved to reporting folder: {report_folder}")
        
        # Print summary
        total_passed = sum(sum(1 for c in result.get('checks', []) if c['result'] == 'PASS') for result in all_results)
        total_failed = sum(sum(1 for c in result.get('checks', []) if c['result'] == 'FAIL') for result in all_results)
        total_errors = sum(sum(1 for c in result.get('checks', []) if c['result'] == 'ERROR') for result in all_results)
        
        logger.info(f"TOTAL RESULTS: {total_passed} PASS, {total_failed} FAIL, {total_errors} ERROR")
        
    except Exception as e:
        logger.error(f"Failed to save reporting bundle: {e}")
    
    return all_results

if __name__ == "__main__":
    main()
