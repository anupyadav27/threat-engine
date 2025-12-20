#!/usr/bin/env python3
"""
Build dependency graph artifacts for ALL Azure services.
Generates operation_registry.json, adjacency.json, validation_report.json, manual_review.json
and overrides.json per service, following Azure SDK patterns.

Based on AWS implementation but adapted for Azure:
- Azure uses azure.mgmt.* clients
- Azure has begin_* prefix for async operations
- ARM identity exceptions (subscriptionId, resourceGroupName, etc.)
- Operations organized by category (operations_by_category)
"""

import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Any, Set, Tuple, Optional
from collections import defaultdict

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def compact_json_dumps(obj, indent=2):
    """Custom JSON formatter for more compact, human-readable output."""
    def is_simple_value(val):
        return isinstance(val, (str, int, float, bool)) or val is None
    
    def format_value(val, level=0, in_array=False, force_single_line=False):
        if isinstance(val, dict):
            if not val:
                return "{}"
            items = []
            for k, v in val.items():
                force_single = (k in ['consumes', 'produces'] and isinstance(v, list))
                formatted_val = format_value(v, level + 1, False, force_single)
                items.append(f'"{k}": {formatted_val}')
            
            content = ", ".join(items)
            if in_array or (len(content) < 100 and level > 0):
                return "{" + content + "}"
            else:
                sep = f",\n{' ' * indent * (level + 1)}"
                return "{\n" + (' ' * indent * (level + 1)) + sep.join(items) + "\n" + (' ' * indent * level) + "}"
        
        elif isinstance(val, list):
            if not val:
                return "[]"
            
            all_strings = all(isinstance(item, str) for item in val)
            if all_strings:
                items_str = ", ".join(json.dumps(item) for item in val)
                return "[" + items_str + "]"
            
            formatted_items = [format_value(item, level + 1, True, force_single_line) for item in val]
            content = ", ".join(formatted_items)
            
            if force_single_line or len(content) < 250:
                return "[" + content + "]"
            
            sep = f",\n{' ' * indent * (level + 1)}"
            return "[\n" + (' ' * indent * (level + 1)) + sep.join(formatted_items) + "\n" + (' ' * indent * level) + "]"
        
        elif isinstance(val, str):
            return json.dumps(val)
        elif isinstance(val, bool):
            return "true" if val else "false"
        elif val is None:
            return "null"
        else:
            return str(val)
    
    return format_value(obj, 0, False)

def to_snake_case(name: str) -> str:
    """Convert camelCase/PascalCase to snake_case."""
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()

def singularize(word: str) -> str:
    """Singularize word - best effort."""
    if word.endswith('ies'):
        return word[:-3] + 'y'
    elif word.endswith('ses') and len(word) > 3:
        return word[:-2]
    elif word.endswith('es') and len(word) > 3:
        return word[:-2]
    elif word.endswith('s') and not word.endswith('ss') and len(word) > 1:
        return word[:-1]
    return word

def extract_meaningful_parent(path: str) -> Optional[str]:
    """
    Extract the nearest meaningful parent segment from a path.
    Skips generic containers like "resource", "item", "data", "details", "info".
    """
    generic_containers = {'resource', 'item', 'data', 'details', 'detail', 'info', 'information', 
                          'result', 'response', 'output', 'response_metadata', 'value', 'items'}
    
    # Split path into segments
    if '[]' in path:
        list_part, rest = path.split('[]', 1)
        segments = [list_part]
        if rest:
            segments.extend(rest.lstrip('.').split('.'))
    else:
        segments = path.split('.')
    
    # Find the last meaningful segment before the leaf
    if len(segments) < 2:
        return None
    
    # Leaf is the last segment
    # Parent candidates are segments before the leaf
    for i in range(len(segments) - 2, -1, -1):
        segment = segments[i]
        segment_lower = segment.lower()
        
        # Skip generic containers
        if segment_lower not in generic_containers:
            return segment
    
    # If all parents are generic, return the immediate parent anyway
    return segments[-2] if len(segments) >= 2 else None

# ============================================================================
# KIND ASSIGNMENT (Azure-aware with begin_ prefix handling)
# ============================================================================

def assign_kind_azure(python_method: str) -> str:
    """
    Auto-assign kind using python_method (Azure SDK style).
    Strips "begin_" prefix before matching as per prompt.
    """
    # Strip begin_ prefix
    method = python_method.replace('begin_', '') if python_method.startswith('begin_') else python_method
    
    # Priority order (first match wins):
    # 1. List operations
    if method.startswith('list') or 'list_by_' in method or 'list_' in method:
        return 'read_list'
    
    # 2. Get operations
    if method.startswith('get') or method.startswith('get_'):
        return 'read_get'
    
    # 3. Delete operations
    if method.startswith('delete') or method.endswith('_delete') or '.delete' in method:
        return 'write_delete'
    
    # 4. Update operations
    if any(x in method for x in ['update', 'patch', 'modify', 'set']):
        return 'write_update'
    
    # 5. Create operations
    if any(x in method for x in ['create', 'create_or_update', 'put', 'provision', 'enable', 'register', 'import']):
        return 'write_create'
    
    # 6. Apply operations
    if any(x in method for x in ['attach', 'associate', 'add', 'grant', 'revoke', 'tag', 'authorize', 'unauthorize']):
        return 'write_apply'
    
    # Default
    return 'other'

def has_side_effect(kind: str) -> bool:
    """Determine if operation has side effects."""
    return not kind.startswith('read_')

# ============================================================================
# ENTITY NAMING (Azure-specific with ARM identity exceptions)
# ============================================================================

# ARM identity exceptions - DO NOT service-prefix these
ARM_IDENTITY_EXCEPTIONS = {
    'subscriptionid': 'azure.subscription_id',
    'subscription_id': 'azure.subscription_id',
    'tenantid': 'azure.tenant_id',
    'tenant_id': 'azure.tenant_id',
    'resourcegroupname': 'azure.resource_group_name',
    'resource_group_name': 'azure.resource_group_name',
    'resourceid': 'azure.resource_id',
    'resource_id': 'azure.resource_id',
    'location': 'azure.location',
}

def is_arm_resource_id(value: str) -> bool:
    """Check if a value looks like an ARM resource ID."""
    # ARM resource IDs typically start with /subscriptions/ or contain resource groups
    return value.startswith('/subscriptions/') or '/resourceGroups/' in value

def normalize_consumes_entity_azure(service: str, param: str, operation_name: str, 
                                   operation_group: Optional[str] = None, 
                                   main_output_field: Optional[str] = None,
                                   category: Optional[str] = None) -> str:
    """
    Normalize entity for consumes (input params) - Azure-specific.
    CRITICAL: Never create generic <service>.name/id/status entities.
    """
    param_lower = param.lower()
    
    # Check ARM identity exceptions first
    if param_lower in ARM_IDENTITY_EXCEPTIONS:
        return ARM_IDENTITY_EXCEPTIONS[param_lower]
    
    # For generic tokens (id/name/status), derive from operation context
    if param_lower in ['id', 'name', 'status']:
        # Priority 1: Use category to derive resource name
        if category:
            resource_name = to_snake_case(category)
            resource_name = singularize(resource_name)
            # Remove common suffixes
            if resource_name.endswith('s') and len(resource_name) > 1:
                resource_name = resource_name[:-1]
            return f"{service}.{resource_name}_{param_lower}"
        
        # Priority 2: Use operation group (e.g., VirtualMachinesOperations -> virtual_machine)
        noun = None
        if operation_group:
            # Remove "Operations" suffix and convert to snake_case
            noun = to_snake_case(operation_group.replace('Operations', ''))
            noun = singularize(noun)
        
        # Priority 3: Derive from operation name
        if not noun:
            noun = extract_noun_from_operation_azure(operation_name, main_output_field)
        
        return f"{service}.{noun}_{param_lower}"
    
    # For compound params (e.g., vmName, storageAccountName)
    if param_lower.endswith('name'):
        base = param_lower[:-4]  # Remove "name"
        if base and base != 'resourcegroup':  # resourceGroupName already handled
            return f"{service}.{to_snake_case(base)}_name"
        else:
            # Fallback to operation context
            noun = extract_noun_from_operation_azure(operation_name, main_output_field)
            return f"{service}.{noun}_name"
    
    if param_lower.endswith('id'):
        base = param_lower[:-2]  # Remove "id"
        if base and base not in ['subscription', 'tenant', 'resource']:
            return f"{service}.{to_snake_case(base)}_id"
        else:
            noun = extract_noun_from_operation_azure(operation_name, main_output_field)
            return f"{service}.{noun}_id"
    
    if param_lower.endswith('arn'):  # Rare in Azure but handle it
        base = param_lower[:-3]  # Remove "arn"
        if base:
            return f"{service}.{to_snake_case(base)}_arn"
        else:
            noun = extract_noun_from_operation_azure(operation_name, main_output_field)
            return f"{service}.{noun}_arn"
    
    # Default: snake_case of param
    return f"{service}.{to_snake_case(param)}"

def normalize_produces_entity_azure(service: str, path: str, operation_name: str, category: Optional[str] = None) -> str:
    """
    Normalize entity for produces (output fields/paths) - Azure-specific.
    Never produce: <service>.id, <service>.name, <service>.status
    Uses category to derive resource name for better entity naming.
    """
    field_lower = path.split('.')[-1].split('[]')[-1].lower()
    
    # Normalize common Azure field names
    if field_lower in ['displayname', 'display_name']:
        field_lower = 'name'
    elif field_lower in ['provisioningstate', 'provisioning_state', 'lifecyclestate', 'lifecycle_state']:
        field_lower = 'status'
    
    # For generic leaf tokens, find nearest meaningful parent
    if field_lower in ['id', 'status', 'name']:
        # Priority 1: Use category to derive resource name
        if category:
            resource_name = to_snake_case(category)
            resource_name = singularize(resource_name)
            # Remove common suffixes
            if resource_name.endswith('s') and len(resource_name) > 1:
                resource_name = resource_name[:-1]
            return f"{service}.{resource_name}_{field_lower}"
        
        # Priority 2: Use parent from path
        parent = extract_meaningful_parent(path)
        
        if parent:
            parent_snake = to_snake_case(parent)
            parent_snake = singularize(parent_snake)
            
            # Remove wrapper suffixes
            wrapper_suffixes = ['_summary_list', '_summary', '_list', '_details', '_detail', '_info', '_information']
            for suffix in wrapper_suffixes:
                if parent_snake.endswith(suffix):
                    parent_snake = parent_snake[:-len(suffix)]
                    break
            
            # Remove stopwords
            stopwords = {'details', 'detail', 'info', 'information', 'data', 'value', 'items'}
            parts = parent_snake.split('_')
            parts = [p for p in parts if p not in stopwords]
            parent_clean = '_'.join(parts) if parts else parent_snake
            
            return f"{service}.{parent_clean}_{field_lower}"
        
        # Fallback: use operation name context
        noun = extract_noun_from_operation_azure(operation_name)
        return f"{service}.{noun}_{field_lower}"
    
    # For non-generic fields, use parent context if available
    parent = extract_meaningful_parent(path)
    field_name = path.split('.')[-1].split('[]')[-1]
    
    if parent:
        parent_snake = to_snake_case(parent)
        parent_snake = singularize(parent_snake)
        
        # Remove wrapper suffixes
        wrapper_suffixes = ['_summary_list', '_summary', '_list', '_details', '_detail', '_info', '_information']
        for suffix in wrapper_suffixes:
            if parent_snake.endswith(suffix):
                parent_snake = parent_snake[:-len(suffix)]
                break
        
        field_snake = to_snake_case(field_name)
        
        # Avoid duplication
        if parent_snake and field_snake.startswith(parent_snake + '_'):
            return f"{service}.{field_snake}"
        
        return f"{service}.{parent_snake}_{field_snake}"
    else:
        return f"{service}.{to_snake_case(field_name)}"

def extract_noun_from_operation_azure(operation_name: str, main_output_field: Optional[str] = None) -> str:
    """
    Extract noun from operation name by removing verb prefixes.
    Returns snake_case singularized noun.
    """
    # Priority 1: Use main_output_field if meaningful
    generic_tokens = ['arn', 'id', 'name', 'status', 'result', 'response', 'details', 'output', 'token', 'nextlink', 'value']
    if main_output_field and main_output_field.lower() not in generic_tokens:
        noun = main_output_field.replace('[]', '')
        noun = singularize(to_snake_case(noun))
        return noun
    
    # Priority 2: Extract from operation name
    op = operation_name
    
    # Verbs to strip (Azure SDK patterns)
    verbs = [
        'Put', 'Create', 'Update', 'Delete', 'Remove', 'Get', 'List',
        'Start', 'Stop', 'Accept', 'Enable', 'Disable', 'Associate', 'Disassociate',
        'Attach', 'Detach', 'Tag', 'Untag', 'Apply', 'Cancel', 'Renew', 'Request',
        'Resend', 'Modify', 'Set', 'Replace', 'Patch', 'Change', 'Reset', 'Begin'
    ]
    
    for verb in verbs:
        if op.startswith(verb):
            noun = op[len(verb):]
            if noun:
                return singularize(to_snake_case(noun))
    
    # Fallback: use full operation name
    return singularize(to_snake_case(op))

# ============================================================================
# BUILD OPERATION REGISTRY
# ============================================================================

def build_consumes_azure(service: str, required_params: List[str], operation_name: str,
                        operation_group: Optional[str] = None,
                        main_output_field: Optional[str] = None,
                        category: Optional[str] = None) -> List[Dict[str, Any]]:
    """Build consumes list from required_params - Azure-specific."""
    consumes = []
    for param in required_params:
        entity = normalize_consumes_entity_azure(service, param, operation_name, operation_group, main_output_field, category)
        consumes.append({
            "entity": entity,
            "param": param,
            "required": True,
            "source": "either"  # Will be finalized later
        })
    return consumes

def normalize_output_fields_azure(output_fields: Any) -> Dict[str, Any]:
    """
    Normalize output_fields from Azure list format to dict format.
    Azure specs sometimes have output_fields as a list like ["value","next_link"].
    Convert to standard dict schema: {key: {type, description, operators}}
    """
    if isinstance(output_fields, dict):
        # Already in dict format, ensure it has required structure
        normalized = {}
        for key, value in output_fields.items():
            if isinstance(value, dict):
                normalized[key] = value
            else:
                # Convert simple value to dict
                normalized[key] = {
                    "type": "unknown",
                    "description": "",
                    "operators": []
                }
        return normalized
    
    elif isinstance(output_fields, list):
        # Convert list to dict
        normalized = {}
        for key in output_fields:
            if key == "value":
                normalized[key] = {
                    "type": "array",
                    "description": "List of items",
                    "operators": []
                }
            elif "next" in key.lower() or "link" in key.lower():
                normalized[key] = {
                    "type": "string",
                    "description": "Pagination token",
                    "operators": []
                }
            else:
                normalized[key] = {
                    "type": "unknown",
                    "description": "",
                    "operators": []
                }
        return normalized
    
    else:
        # Fallback: empty dict
        return {}

def build_produces_azure(service: str, output_fields: Any, main_output_field: Optional[str], 
                        item_fields: Dict[str, Any], operation_name: str,
                        category: Optional[str] = None) -> List[Dict[str, Any]]:
    """Build produces list from output_fields and item_fields - Azure-specific."""
    produces = []
    is_list_op = operation_name.startswith('list') or assign_kind_azure(operation_name) == 'read_list'
    
    # Normalize output_fields to dict
    output_fields_dict = normalize_output_fields_azure(output_fields)
    
    # Add output_fields
    for field_name in output_fields_dict.keys():
        entity = normalize_produces_entity_azure(service, field_name, operation_name, category)
        produces.append({
            "entity": entity,
            "source": "output",
            "path": field_name
        })
    
    # Add item_fields if main_output_field exists
    if main_output_field and item_fields:
        for field_name in item_fields.keys():
            # Build path
            if is_list_op:
                path = f"{main_output_field}[].{field_name}"
            else:
                path = f"{main_output_field}.{field_name}"
            
            entity = normalize_produces_entity_azure(service, path, operation_name, category)
            produces.append({
                "entity": entity,
                "source": "item",
                "path": path
            })
    
    return produces

def generate_operation_id(service: str, category: str, class_name: str, operation: str) -> str:
    """
    Generate unique operation_id: azure.<service>.<category>.<operation>
    All components are converted to snake_case.
    If category is empty, use "root" as fallback.
    """
    if not category or category.strip() == "":
        category = "root"
    category_snake = to_snake_case(category)
    operation_snake = to_snake_case(operation)
    return f"azure.{service}.{category_snake}.{operation_snake}"

def process_azure_service_spec(spec_file: Path) -> Dict[str, Any]:
    """
    Process Azure service spec JSON and generate operation_registry.json.
    Azure format: {service_name: {operations_by_category: {...}, independent: [...], dependent: [...]}}
    """
    with open(spec_file, 'r') as f:
        data = json.load(f)
    
    # Get service name and data
    service_name = list(data.keys())[0]
    service_data = data[service_name]
    
    operations = {}
    operation_id_to_key = {}  # Track operation_id -> operation_key for debugging
    seen_operation_ids = set()
    duplicates_removed = 0
    
    # Process operations_by_category
    if 'operations_by_category' in service_data:
        for category, cat_data in service_data['operations_by_category'].items():
            # Normalize empty category to "root"
            if not category or category.strip() == "":
                category = "root"
            class_name = cat_data.get('class_name', '')
            operation_group = class_name.replace('Operations', '') if class_name else ''
            
            # Process independent operations
            for op in cat_data.get('independent', []):
                op_name = op.get('operation', '')
                python_method = op.get('python_method', op_name)
                
                # Generate unique operation_id
                operation_id = generate_operation_id(service_name, category, class_name, python_method)
                operation_key = f"{category}::{class_name}::{op_name}"
                
                # Check for duplicates
                if operation_id in seen_operation_ids:
                    duplicates_removed += 1
                    continue
                seen_operation_ids.add(operation_id)
                operation_id_to_key[operation_id] = operation_key
                
                required_params = op.get('required_params', [])
                optional_params = op.get('optional_params', [])
                output_fields_raw = op.get('output_fields', [])
                
                # Normalize output_fields to dict
                output_fields_dict = normalize_output_fields_azure(output_fields_raw)
                
                # Infer main_output_field if missing
                main_output_field = op.get('main_output_field')
                if not main_output_field and 'value' in output_fields_dict:
                    main_output_field = 'value'
                
                item_fields = op.get('item_fields', {})
                
                kind = assign_kind_azure(python_method)
                consumes = build_consumes_azure(service_name, required_params, op_name, operation_group, main_output_field, category)
                produces = build_produces_azure(service_name, output_fields_dict, main_output_field, item_fields, op_name, category)
                
                operations[operation_id] = {
                    "operation_id": operation_id,
                    "operation_key": operation_key,
                    "operation": op_name,
                    "python_method": python_method,
                    "yaml_action": op.get('yaml_action', python_method),
                    "category": category,
                    "class_name": class_name,
                    "kind": kind,
                    "required_params": required_params,
                    "optional_params": optional_params if isinstance(optional_params, list) else list(optional_params.keys()) if isinstance(optional_params, dict) else [],
                    "output_fields": output_fields_dict,
                    "main_output_field": main_output_field,
                    "consumes": consumes,
                    "produces": produces,
                    "side_effect": has_side_effect(kind)
                }
            
            # Process dependent operations
            for op in cat_data.get('dependent', []):
                op_name = op.get('operation', '')
                python_method = op.get('python_method', op_name)
                
                # Generate unique operation_id
                operation_id = generate_operation_id(service_name, category, class_name, python_method)
                operation_key = f"{category}::{class_name}::{op_name}"
                
                # Check for duplicates
                if operation_id in seen_operation_ids:
                    duplicates_removed += 1
                    continue
                seen_operation_ids.add(operation_id)
                operation_id_to_key[operation_id] = operation_key
                
                required_params = op.get('required_params', [])
                optional_params = op.get('optional_params', [])
                output_fields_raw = op.get('output_fields', [])
                
                # Normalize output_fields to dict
                output_fields_dict = normalize_output_fields_azure(output_fields_raw)
                
                # Infer main_output_field if missing
                main_output_field = op.get('main_output_field')
                if not main_output_field and 'value' in output_fields_dict:
                    main_output_field = 'value'
                
                item_fields = op.get('item_fields', {})
                
                kind = assign_kind_azure(python_method)
                consumes = build_consumes_azure(service_name, required_params, op_name, operation_group, main_output_field, category)
                produces = build_produces_azure(service_name, output_fields_dict, main_output_field, item_fields, op_name, category)
                
                operations[operation_id] = {
                    "operation_id": operation_id,
                    "operation_key": operation_key,
                    "operation": op_name,
                    "python_method": python_method,
                    "yaml_action": op.get('yaml_action', python_method),
                    "category": category,
                    "class_name": class_name,
                    "kind": kind,
                    "required_params": required_params,
                    "optional_params": optional_params if isinstance(optional_params, list) else list(optional_params.keys()) if isinstance(optional_params, dict) else [],
                    "output_fields": output_fields_dict,
                    "main_output_field": main_output_field,
                    "consumes": consumes,
                    "produces": produces,
                    "side_effect": has_side_effect(kind)
                }
    
    # Process top-level independent and dependent (if present)
    # Use "root" as category for top-level operations
    for op_list_key in ['independent', 'dependent']:
        if op_list_key in service_data:
            for op in service_data[op_list_key]:
                op_name = op.get('operation', '')
                python_method = op.get('python_method', op_name)
                
                # Generate unique operation_id with "root" category
                operation_id = generate_operation_id(service_name, "root", "", python_method)
                operation_key = f"root::::{op_name}"
                
                # Check for duplicates
                if operation_id in seen_operation_ids:
                    duplicates_removed += 1
                    continue
                seen_operation_ids.add(operation_id)
                operation_id_to_key[operation_id] = operation_key
                
                required_params = op.get('required_params', [])
                optional_params = op.get('optional_params', [])
                output_fields_raw = op.get('output_fields', [])
                
                # Normalize output_fields to dict
                output_fields_dict = normalize_output_fields_azure(output_fields_raw)
                
                # Infer main_output_field if missing
                main_output_field = op.get('main_output_field')
                if not main_output_field and 'value' in output_fields_dict:
                    main_output_field = 'value'
                
                item_fields = op.get('item_fields', {})
                
                kind = assign_kind_azure(python_method)
                consumes = build_consumes_azure(service_name, required_params, op_name, None, main_output_field, "root")
                produces = build_produces_azure(service_name, output_fields_dict, main_output_field, item_fields, op_name, "root")
                
                # For top-level operations, use "root" as category
                inferred_category = "root"
                inferred_class_name = op.get('class_name', '')
                
                operations[operation_id] = {
                    "operation_id": operation_id,
                    "operation_key": operation_key,
                    "operation": op_name,
                    "python_method": python_method,
                    "yaml_action": op.get('yaml_action', python_method),
                    "category": inferred_category,
                    "class_name": inferred_class_name,
                    "kind": kind,
                    "required_params": required_params,
                    "optional_params": optional_params if isinstance(optional_params, list) else list(optional_params.keys()) if isinstance(optional_params, dict) else [],
                    "output_fields": output_fields_dict,
                    "main_output_field": main_output_field,
                    "consumes": consumes,
                    "produces": produces,
                    "side_effect": has_side_effect(kind)
                }
    
    # Generate entity aliases (simplified version - can be enhanced)
    entity_aliases = generate_safe_aliases_azure(operations, service_name)
    
    # Build registry
    registry = {
        "service": service_name,
        "version": "1.0",
        "module": service_data.get('module', f'azure.mgmt.{service_name}'),
        "kind_rules": {
            "read_list": ["list", "list_by_", "list_"],
            "read_get": ["get", "get_"],
            "write_create": ["create", "create_or_update", "put", "provision", "enable", "register", "import"],
            "write_update": ["update", "patch", "modify", "set"],
            "write_delete": ["delete", "_delete", ".delete"],
            "write_apply": ["attach", "associate", "add", "grant", "revoke", "tag", "authorize", "unauthorize"],
            "other": ["default"]
        },
        "entity_aliases": entity_aliases,
        "overrides": {
            "param_aliases": {},
            "consumes": {},
            "produces": {}
        },
        "operations": operations,
        "_metadata": {
            "duplicates_removed": duplicates_removed,
            "total_operations": len(operations),
            "operation_id_to_key": operation_id_to_key
        }
    }
    
    return registry

def generate_safe_aliases_azure(operations: Dict[str, Any], service: str) -> Dict[str, str]:
    """
    Generate safe alias candidates for Azure.
    Simplified version - can be enhanced with more heuristics.
    """
    alias_map = {}
    entity_usage = defaultdict(lambda: {'consumes': [], 'produces': [], 'params': set(), 'paths': set()})
    
    # Collect usage patterns (use operation_id now)
    for op_id, op_data in operations.items():
        for consume in op_data.get('consumes', []):
            entity = consume['entity']
            param = consume['param']
            entity_usage[entity]['consumes'].append(op_id)
            entity_usage[entity]['params'].add(param)
        
        for produce in op_data.get('produces', []):
            entity = produce['entity']
            path = produce['path']
            entity_usage[entity]['produces'].append(op_id)
            entity_usage[entity]['paths'].add(path)
    
    # Simple alias: if same field appears as input and output with different entities
    # Prefer the consume entity as canonical
    for op_id, op_data in operations.items():
        consumes = op_data.get('consumes', [])
        produces = op_data.get('produces', [])
        
        for consume in consumes:
            consume_entity = consume['entity']
            param = consume['param']
            param_lower = param.lower()
            
            for produce in produces:
                produce_entity = produce['entity']
                path = produce['path']
                field_lower = path.split('.')[-1].split('[]')[-1].lower()
                
                # If param and field match but entities differ, alias produce to consume
                if (param_lower == field_lower or 
                    (param_lower.endswith('id') and field_lower.endswith('id')) or
                    (param_lower.endswith('name') and field_lower.endswith('name'))) and \
                   consume_entity != produce_entity and \
                   not produce_entity.startswith('azure.'):  # Don't alias ARM entities
                    # Prefer consume entity as canonical
                    if produce_entity not in alias_map:
                        alias_map[produce_entity] = consume_entity
    
    return alias_map

# ============================================================================
# BUILD ADJACENCY
# ============================================================================

def build_adjacency_azure(registry: Dict[str, Any]) -> Dict[str, Any]:
    """Build adjacency.json from registry - Azure-specific. Uses operation_id."""
    service = registry['service']
    operations = registry['operations']
    entity_aliases = registry.get('entity_aliases', {})
    
    def resolve_entity(entity: str) -> str:
        """Resolve entity through alias chain."""
        visited = set()
        current = entity
        while current in entity_aliases and current not in visited:
            visited.add(current)
            current = entity_aliases[current]
        return current
    
    # Build entity consumers and producers
    entity_consumers = defaultdict(list)
    entity_producers = defaultdict(list)
    op_consumes = {}
    op_produces = {}
    
    for op_id, op_data in operations.items():
        # Resolve consumes
        consumes_entities = []
        for consume in op_data.get('consumes', []):
            entity = resolve_entity(consume['entity'])
            consumes_entities.append(entity)
            entity_consumers[entity].append(op_id)
        op_consumes[op_id] = consumes_entities
        
        # Resolve produces
        produces_entities = []
        for produce in op_data.get('produces', []):
            entity = resolve_entity(produce['entity'])
            produces_entities.append(entity)
            entity_producers[entity].append(op_id)
        op_produces[op_id] = produces_entities
    
    # Find external entities (azure.* and missing producers)
    all_entities = set(entity_consumers.keys()) | set(entity_producers.keys())
    external_entities = {e for e in all_entities if e.startswith('azure.') or e not in entity_producers}
    
    adjacency = {
        "service": service,
        "op_consumes": op_consumes,
        "op_produces": op_produces,
        "entity_consumers": dict(entity_consumers),
        "entity_producers": dict(entity_producers),
        "external_entities": sorted(list(external_entities))
    }
    
    return adjacency

# ============================================================================
# VALIDATION
# ============================================================================

def validate_service_azure(registry: Dict[str, Any], adjacency: Dict[str, Any]) -> Dict[str, Any]:
    """Validate service and generate validation report - Azure-specific."""
    operations = registry['operations']
    
    # Validation checks
    duplicate_operation_ids = []
    missing_category_ops = []
    invalid_output_fields_ops = []
    seen_ids = set()
    
    for op_id, op_data in operations.items():
        # Check for duplicate operation_ids
        if op_id in seen_ids:
            duplicate_operation_ids.append(op_id)
        seen_ids.add(op_id)
        
        # Check for missing category (empty string or None)
        category = op_data.get('category')
        if not category or category.strip() == "":
            missing_category_ops.append(op_id)
        
        # Check output_fields is dict
        output_fields = op_data.get('output_fields', {})
        if not isinstance(output_fields, dict):
            invalid_output_fields_ops.append(op_id)
    
    # Count operations
    total_ops = len(operations)
    independent_ops = [op_id for op_id, data in operations.items() if not data.get('required_params', [])]
    dependent_ops = [op_id for op_id, data in operations.items() if data.get('required_params', [])]
    
    # Find satisfiable operations (those whose consumes are satisfied)
    satisfiable = 0
    unsatisfiable = 0
    
    entity_producers_set = set(adjacency.get('entity_producers', {}).keys())
    
    for op_id, op_data in operations.items():
        if not op_data.get('required_params', []):
            satisfiable += 1
        else:
            # Check if all consumes are satisfied
            all_satisfied = True
            for consume in op_data.get('consumes', []):
                entity = consume['entity']
                # Check if entity is produced or is external
                if entity not in entity_producers_set and not entity.startswith('azure.'):
                    all_satisfied = False
                    break
            
            if all_satisfied:
                satisfiable += 1
            else:
                unsatisfiable += 1
    
    # Find generic entities
    generic_entities = {}
    for op_id, op_data in operations.items():
        for consume in op_data.get('consumes', []):
            entity = consume['entity']
            # Check if generic (ends with just .id, .name, .status without meaningful prefix)
            if entity.count('.') == 1:  # service.field format
                field = entity.split('.')[1]
                if field in ['id', 'name', 'status']:
                    generic_entities[entity] = generic_entities.get(entity, 0) + 1
        
        for produce in op_data.get('produces', []):
            entity = produce['entity']
            if entity.count('.') == 1:
                field = entity.split('.')[1]
                if field in ['id', 'name', 'status']:
                    generic_entities[entity] = generic_entities.get(entity, 0) + 1
    
    # Determine validation status
    has_duplicates = len(duplicate_operation_ids) > 0
    has_missing_category = len(missing_category_ops) > 0
    has_invalid_output_fields = len(invalid_output_fields_ops) > 0
    has_generic = len(generic_entities) > 0
    
    if has_duplicates or has_missing_category or has_invalid_output_fields:
        validation_status = "FAIL"
    elif unsatisfiable == 0 and not has_generic:
        validation_status = "PASS"
    elif unsatisfiable < total_ops * 0.1:
        validation_status = "WARN"
    else:
        validation_status = "FAIL"
    
    validation_report = {
        "service": registry['service'],
        "validation_status": validation_status,
        "summary": {
            "total_operations": total_ops,
            "independent_operations": len(independent_ops),
            "dependent_operations": len(dependent_ops),
            "satisfiable_operations": satisfiable,
            "unsatisfiable_operations": unsatisfiable,
            "satisfiable_percent": (satisfiable / total_ops * 100) if total_ops > 0 else 0,
            "total_entities": len(set(adjacency.get('entity_consumers', {}).keys()) | set(adjacency.get('entity_producers', {}).keys())),
            "external_entities": len(adjacency.get('external_entities', [])),
            "duplicates_removed": registry.get('_metadata', {}).get('duplicates_removed', 0)
        },
        "validation_errors": {
            "duplicate_operation_ids": duplicate_operation_ids,
            "missing_category_operations": missing_category_ops,
            "invalid_output_fields_operations": invalid_output_fields_ops
        },
        "generic_entities_found": generic_entities,
        "cycles_detected": []  # Can be enhanced with cycle detection
    }
    
    return validation_report

# ============================================================================
# MANUAL REVIEW
# ============================================================================

def generate_manual_review_azure(registry: Dict[str, Any], validation_report: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Generate manual_review.json - Azure-specific."""
    issues = []
    
    # Collect validation errors (collisions, missing category, etc.)
    validation_errors = validation_report.get('validation_errors', {})
    if validation_errors.get('duplicate_operation_ids'):
        issues.append({
            "type": "collision_errors",
            "description": "Duplicate operation_ids found",
            "duplicate_operation_ids": validation_errors['duplicate_operation_ids']
        })
    
    if validation_errors.get('missing_category_operations'):
        issues.append({
            "type": "missing_category",
            "description": "Operations missing category",
            "operations": validation_errors['missing_category_operations']
        })
    
    if validation_errors.get('invalid_output_fields_operations'):
        issues.append({
            "type": "invalid_output_fields",
            "description": "Operations with invalid output_fields format",
            "operations": validation_errors['invalid_output_fields_operations']
        })
    
    # Collect generic entities
    if validation_report['generic_entities_found']:
        issues.append({
            "type": "generic_entities",
            "entities": list(validation_report['generic_entities_found'].keys())
        })
    
    # Collect unsatisfiable operations
    if validation_report['summary']['unsatisfiable_operations'] > 0:
        operations = registry['operations']
        adjacency = build_adjacency_azure(registry)  # Rebuild to get entity_producers
        entity_producers_set = set(adjacency.get('entity_producers', {}).keys())
        unsatisfiable_ops = []
        for op_id, op_data in operations.items():
            if op_data.get('required_params', []):
                missing = []
                for consume in op_data.get('consumes', []):
                    entity = consume['entity']
                    # Check if entity is produced or is external
                    if entity not in entity_producers_set and not entity.startswith('azure.'):
                        missing.append(entity)
                if missing:
                    unsatisfiable_ops.append({
                        "operation_id": op_id,
                        "operation": op_data.get('operation', ''),
                        "missing_entities": missing
                    })
        
        if unsatisfiable_ops:
            issues.append({
                "type": "unsatisfiable_operations",
                "operations": unsatisfiable_ops
            })
    
    if not issues:
        return None
    
    review = {
        "service": registry['service'],
        "issues": issues,
        "alias_candidates_not_applied": [],
        "suggested_overrides": []
    }
    
    return review

# ============================================================================
# MAIN PROCESSING
# ============================================================================

def process_azure_service_folder(service_folder: Path, azure_root: Path) -> Dict[str, Any]:
    """Process a single Azure service folder."""
    service_name = service_folder.name
    
    # Find service spec JSON
    spec_file = service_folder / "azure_dependencies_with_python_names_fully_enriched.json"
    
    if not spec_file.exists():
        return {
            "service": service_name,
            "status": "SKIP",
            "reason": "No service spec JSON found"
        }
    
    try:
        print(f"  Processing {service_name}...")
        
        # Generate operation_registry.json
        registry = process_azure_service_spec(spec_file)
        
        # Generate adjacency.json
        adjacency = build_adjacency_azure(registry)
        
        # Run validation
        validation_report = validate_service_azure(registry, adjacency)
        
        # Generate manual_review.json if needed
        manual_review = generate_manual_review_azure(registry, validation_report)
        
        # Write files (with backup)
        registry_file = service_folder / "operation_registry.json"
        if registry_file.exists():
            registry_file.rename(registry_file.with_suffix('.json.bak'))
        with open(registry_file, 'w') as f:
            formatted = compact_json_dumps(registry, indent=2)
            f.write(formatted)
        
        adjacency_file = service_folder / "adjacency.json"
        if adjacency_file.exists():
            adjacency_file.rename(adjacency_file.with_suffix('.json.bak'))
        with open(adjacency_file, 'w') as f:
            formatted = compact_json_dumps(adjacency, indent=2)
            f.write(formatted)
        
        validation_file = service_folder / "validation_report.json"
        if validation_file.exists():
            validation_file.rename(validation_file.with_suffix('.json.bak'))
        with open(validation_file, 'w') as f:
            json.dump(validation_report, f, indent=2, sort_keys=True)
        
        if manual_review:
            review_file = service_folder / "manual_review.json"
            if review_file.exists():
                review_file.rename(review_file.with_suffix('.json.bak'))
            with open(review_file, 'w') as f:
                json.dump(manual_review, f, indent=2, sort_keys=True)
        
        return {
            "service": service_name,
            "status": validation_report['validation_status'],
            "operations": validation_report['summary']['total_operations'],
            "entities": validation_report['summary']['total_entities'],
            "generic_entities": len(validation_report['generic_entities_found']),
            "unsatisfiable_ops": validation_report['summary']['unsatisfiable_operations'],
            "duplicates_removed": validation_report['summary'].get('duplicates_removed', 0),
            "has_manual_review": manual_review is not None
        }
    
    except Exception as e:
        import traceback
        return {
            "service": service_name,
            "status": "ERROR",
            "error": str(e),
            "traceback": traceback.format_exc()
        }

def main():
    """Main entry point."""
    script_dir = Path(__file__).parent
    azure_root = script_dir.parent
    
    print(f"Azure Root: {azure_root}")
    print("Scanning service folders...")
    
    # Find all service folders
    service_folders = []
    for item in azure_root.iterdir():
        if item.is_dir() and not item.name.startswith('.') and item.name != 'tools':
            # Check if it looks like a service folder (has JSON files)
            spec_file = item / "azure_dependencies_with_python_names_fully_enriched.json"
            if spec_file.exists():
                service_folders.append(item)
    
    service_folders.sort()
    print(f"Found {len(service_folders)} service folders\n")
    
    # Process each service
    results = []
    for service_folder in service_folders:
        result = process_azure_service_folder(service_folder, azure_root)
        results.append(result)
        status_icon = "✓" if result['status'] == 'PASS' else "⚠" if result['status'] == 'WARN' else "✗" if result['status'] == 'FAIL' else "?" if result['status'] == 'ERROR' else "-"
        print(f"  {status_icon} {result['service']}: {result['status']}")
    
    # Generate global summary
    print("\nGenerating global summary...")
    
    passed = [r['service'] for r in results if r['status'] == 'PASS']
    warn = [r['service'] for r in results if r['status'] == 'WARN']
    failed = [r['service'] for r in results if r['status'] == 'FAIL']
    errors = [r['service'] for r in results if r['status'] == 'ERROR']
    skipped = [r['service'] for r in results if r['status'] == 'SKIP']
    
    # Aggregate issues
    generic_entities_services = [r['service'] for r in results if r.get('generic_entities', 0) > 0]
    unsatisfiable_ops_services = [r['service'] for r in results if r.get('unsatisfiable_ops', 0) > 0]
    
    global_summary = {
        "total_services": len(service_folders),
        "passed": passed,
        "warn": warn,
        "failed": failed,
        "errors": errors,
        "skipped": skipped,
        "top_issues": {
            "generic_entities": {
                "count": len(generic_entities_services),
                "services": generic_entities_services[:20]
            },
            "unsatisfiable_operations": {
                "count": len(unsatisfiable_ops_services),
                "services": unsatisfiable_ops_services[:20]
            }
        },
        "summary_stats": {
            "total_operations": sum(r.get('operations', 0) for r in results),
            "total_entities": sum(r.get('entities', 0) for r in results),
            "services_with_manual_review": len([r for r in results if r.get('has_manual_review', False)])
        }
    }
    
    summary_file = azure_root / "manual_review_global_summary.json"
    with open(summary_file, 'w') as f:
        json.dump(global_summary, f, indent=2, sort_keys=True)
    
    total_duplicates_removed = sum(r.get('duplicates_removed', 0) for r in results)
    
    print(f"\n{'='*60}")
    print("GLOBAL SUMMARY")
    print(f"{'='*60}")
    print(f"Total services: {len(service_folders)}")
    print(f"  ✓ PASSED: {len(passed)}")
    print(f"  ⚠ WARN: {len(warn)}")
    print(f"  ✗ FAILED: {len(failed)}")
    print(f"  ? ERRORS: {len(errors)}")
    print(f"  - SKIPPED: {len(skipped)}")
    print(f"\nIssues:")
    print(f"  Generic entities: {len(generic_entities_services)} services")
    print(f"  Unsatisfiable operations: {len(unsatisfiable_ops_services)} services")
    print(f"  Duplicates removed: {total_duplicates_removed} operations")
    print(f"\nGlobal summary saved to: {summary_file}")
    print(f"{'='*60}\n")

if __name__ == "__main__":
    main()

