#!/usr/bin/env python3
"""
Build dependency graph artifacts for ALL GCP services.

Generates operation_registry.json, adjacency.json, validation_report.json, and manual_review.json
per service, following the pattern used by AWS/Azure.

GCP-specific considerations:
- GCP uses Discovery API structure: resources -> independent/dependent operations
- Operations have required_params, optional_params, item_fields
- Entity naming: gcp.{service}.{resource}.{field}
- Operations are organized by resource within services
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
    """Custom JSON formatter for more compact output."""
    return json.dumps(obj, indent=indent, ensure_ascii=False)


def assign_kind_gcp(operation: str) -> str:
    """Assign operation kind based on GCP operation name."""
    op_lower = operation.lower()
    
    if any(kw in op_lower for kw in ['list', 'aggregatedlist']):
        return 'read_list'
    elif any(kw in op_lower for kw in ['get', 'describe']):
        return 'read_get'
    elif any(kw in op_lower for kw in ['create', 'insert', 'provision', 'enable', 'register']):
        return 'write_create'
    elif any(kw in op_lower for kw in ['update', 'patch', 'modify', 'set', 'change', 'reset']):
        return 'write_update'
    elif any(kw in op_lower for kw in ['delete', 'remove', 'terminate', 'destroy', 'disable']):
        return 'write_delete'
    elif any(kw in op_lower for kw in ['attach', 'associate', 'add', 'grant', 'revoke', 'tag', 'authorize']):
        return 'write_apply'
    else:
        return 'other'


def has_side_effect(kind: str) -> bool:
    """Determine if operation has side effects."""
    return kind.startswith('write_')


def normalize_entity_name(service: str, resource: str, field: str) -> str:
    """Normalize entity name to gcp.{service}.{resource}.{field} format."""
    # Clean field name (remove special chars, normalize)
    field_clean = field.replace('_', '_').lower()
    
    # Build entity name
    if resource:
        entity = f"gcp.{service}.{resource}.{field_clean}"
    else:
        entity = f"gcp.{service}.{field_clean}"
    
    return entity


def extract_entities_from_item_fields(service: str, resource: str, item_fields: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract entity list from item_fields."""
    entities = []
    
    for field_name, field_data in item_fields.items():
        entity_name = normalize_entity_name(service, resource, field_name)
        
        # Determine source (usually 'item' for list/get operations)
        source = 'item'
        path = field_name
        
        entities.append({
            'entity': entity_name,
            'source': source,
            'path': path
        })
    
    return entities


def build_consumes_gcp(service: str, required_params: List[str], resource: str, operation: str) -> List[Dict[str, Any]]:
    """Build consumes list from required parameters."""
    consumes = []
    
    for param in required_params:
        # Skip GCP-specific identity params (project, projectId, etc.)
        if param.lower() in ['project', 'projectid', 'project_id']:
            continue
        
        # Create entity name from parameter
        entity_name = normalize_entity_name(service, resource, param)
        
        consumes.append({
            'entity': entity_name,
            'param': param,
            'required': True,
            'source': 'internal'  # Could be enhanced to detect external
        })
    
    return consumes


def build_produces_gcp(service: str, resource: str, operation: str, item_fields: Dict[str, Any], operation_name: str) -> List[Dict[str, Any]]:
    """Build produces list from item_fields."""
    produces = []
    
    # Extract entities from item_fields
    if item_fields:
        field_entities = extract_entities_from_item_fields(service, resource, item_fields)
        produces.extend(field_entities)
    
    # Add resource-level entity if this is a get operation
    if 'get' in operation.lower() and resource:
        resource_entity = normalize_entity_name(service, resource, resource)
        produces.insert(0, {
            'entity': resource_entity,
            'source': 'output',
            'path': resource
        })
    
    # Add list entity if this is a list operation
    if 'list' in operation.lower() and resource:
        # Don't double the 's' if resource already ends with 's'
        list_resource_name = f"{resource}s" if not resource.endswith('s') else resource
        list_entity = normalize_entity_name(service, resource, list_resource_name)
        produces.insert(0, {
            'entity': list_entity,
            'source': 'output',
            'path': list_resource_name
        })
    
    return produces


def generate_operation_id_gcp(service: str, resource: str, operation: str) -> str:
    """Generate operation ID for GCP."""
    # Format: gcp.{service}.{resource}.{operation} or gcp.{service}.{operation}
    if resource:
        return f"gcp.{service}.{resource}.{operation}"
    else:
        return f"gcp.{service}.{operation}"


def process_gcp_service_spec(spec_file: Path) -> Dict[str, Any]:
    """Process GCP service spec JSON and generate operation_registry.json."""
    with open(spec_file, 'r') as f:
        data = json.load(f)
    
    # Get service name and data
    service_name = list(data.keys())[0]
    service_data = data[service_name]
    
    operations = {}
    entity_producers = defaultdict(list)
    
    # Process resources
    resources = service_data.get('resources', {})
    
    for resource_name, resource_data in resources.items():
        # Process independent operations (read operations)
        for op_spec in resource_data.get('independent', []):
            op_name = op_spec.get('operation', '')
            operation_id = generate_operation_id_gcp(service_name, resource_name, op_name)
            
            kind = assign_kind_gcp(op_name)
            side_effect = has_side_effect(kind)
            
            # Build consumes and produces
            required_params = op_spec.get('required_params', [])
            consumes = build_consumes_gcp(service_name, required_params, resource_name, op_name)
            
            item_fields = op_spec.get('item_fields', {})
            produces = build_produces_gcp(service_name, resource_name, op_name, item_fields, operation_id)
            
            # Track entity producers
            for produce in produces:
                entity_producers[produce['entity']].append(operation_id)
            
            operations[operation_id] = {
                'kind': kind,
                'side_effect': side_effect,
                'sdk': {
                    'client': service_name,
                    'method': op_spec.get('python_method', op_name)
                },
                'consumes': consumes,
                'produces': produces,
                'notes': ''
            }
        
        # Process dependent operations (write operations)
        for op_spec in resource_data.get('dependent', []):
            op_name = op_spec.get('operation', '')
            operation_id = generate_operation_id_gcp(service_name, resource_name, op_name)
            
            kind = assign_kind_gcp(op_name)
            side_effect = has_side_effect(kind)
            
            # Build consumes and produces
            required_params = op_spec.get('required_params', [])
            consumes = build_consumes_gcp(service_name, required_params, resource_name, op_name)
            
            # Get operations may also have item_fields
            item_fields = op_spec.get('item_fields', {})
            produces = build_produces_gcp(service_name, resource_name, op_name, item_fields, operation_id)
            
            # Track entity producers
            for produce in produces:
                entity_producers[produce['entity']].append(operation_id)
            
            operations[operation_id] = {
                'kind': kind,
                'side_effect': side_effect,
                'sdk': {
                    'client': service_name,
                    'method': op_spec.get('python_method', op_name)
                },
                'consumes': consumes,
                'produces': produces,
                'notes': ''
            }
    
    # Generate entity aliases (simplified - can be enhanced)
    entity_aliases = {}
    
    # Build registry
    registry = {
        'service': service_name,
        'version': service_data.get('version', '1.0'),
        'kind_rules': {
            'read_list': ['list', 'aggregatedlist'],
            'read_get': ['get', 'describe'],
            'write_create': ['create', 'insert', 'provision', 'enable', 'register'],
            'write_update': ['update', 'patch', 'modify', 'set', 'change', 'reset'],
            'write_delete': ['delete', 'remove', 'terminate', 'destroy', 'disable'],
            'write_apply': ['attach', 'associate', 'add', 'grant', 'revoke', 'tag', 'authorize'],
            'other': ['default']
        },
        'entity_aliases': entity_aliases,
        'overrides': {
            'param_aliases': {},
            'consumes': {},
            'produces': {}
        },
        'operations': operations,
        '_metadata': {
            'total_operations': len(operations)
        }
    }
    
    return registry


def build_adjacency_gcp(registry: Dict[str, Any]) -> Dict[str, Any]:
    """Build adjacency.json from registry - GCP-specific."""
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
    
    # Find external entities (gcp.* from other services or missing producers)
    all_entities = set(entity_consumers.keys()) | set(entity_producers.keys())
    external_entities = {e for e in all_entities if (e.startswith('gcp.') and not e.startswith(f'gcp.{service}.')) or e not in entity_producers}
    
    adjacency = {
        'service': service,
        'op_consumes': op_consumes,
        'op_produces': op_produces,
        'entity_consumers': dict(entity_consumers),
        'entity_producers': dict(entity_producers),
        'external_entities': sorted(list(external_entities))
    }
    
    return adjacency


def validate_service_gcp(registry: Dict[str, Any], adjacency: Dict[str, Any]) -> Dict[str, Any]:
    """Basic validation - can be enhanced."""
    operations = registry['operations']
    op_consumes = adjacency['op_consumes']
    op_produces = adjacency['op_produces']
    entity_producers = adjacency.get('entity_producers', {})
    
    # Basic validation
    issues = []
    
    # Check all operations have consumes/produces
    for op_id in operations.keys():
        if op_id not in op_consumes:
            issues.append(f"Operation {op_id} missing in op_consumes")
        if op_id not in op_produces:
            issues.append(f"Operation {op_id} missing in op_produces")
    
    # Count unique entities (from entity_producers keys)
    total_entities = len(entity_producers)
    
    validation_report = {
        'validation_status': 'PASS' if not issues else 'ISSUES',
        'summary': {
            'total_operations': len(operations),
            'total_entities': total_entities
        },
        'issues': issues
    }
    
    return validation_report


# ============================================================================
# MAIN PROCESSING
# ============================================================================

def process_gcp_service_folder(service_folder: Path, gcp_root: Path) -> Dict[str, Any]:
    """Process a single GCP service folder."""
    service_name = service_folder.name
    
    # Find service spec JSON
    spec_file = service_folder / "gcp_dependencies_with_python_names_fully_enriched.json"
    
    if not spec_file.exists():
        return {
            'service': service_name,
            'status': 'SKIP',
            'reason': 'No service spec JSON found'
        }
    
    try:
        print(f"  Processing {service_name}...")
        
        # Generate operation_registry.json
        registry = process_gcp_service_spec(spec_file)
        
        # Generate adjacency.json
        adjacency = build_adjacency_gcp(registry)
        
        # Run validation
        validation_report = validate_service_gcp(registry, adjacency)
        
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
            json.dump(validation_report, f, indent=2)
        
        return {
            'service': service_name,
            'status': validation_report['validation_status'],
            'operations': validation_report['summary']['total_operations'],
            'entities': validation_report['summary']['total_entities']
        }
    
    except Exception as e:
        import traceback
        error_msg = str(e)
        error_tb = traceback.format_exc()
        print(f"    ERROR: {error_msg}")
        print(f"    {error_tb[:500]}")  # Print first 500 chars of traceback
        return {
            'service': service_name,
            'status': 'ERROR',
            'error': error_msg,
            'traceback': error_tb
        }


def main():
    """Process all GCP services."""
    script_dir = Path(__file__).parent
    gcp_root = script_dir.parent
    
    if not gcp_root.exists():
        print(f"Error: GCP root directory not found: {gcp_root}")
        sys.exit(1)
    
    # Allow processing a single service if provided as argument
    target_service = None
    if len(sys.argv) > 1:
        target_service = sys.argv[1]
    
    print("=" * 80)
    print("Building GCP Dependency Graphs")
    print("=" * 80)
    print()
    
    # Find all service folders
    service_folders = [d for d in gcp_root.iterdir() if d.is_dir() and (d / 'gcp_dependencies_with_python_names_fully_enriched.json').exists()]
    
    # Filter to target service if specified
    if target_service:
        service_folders = [d for d in service_folders if d.name == target_service]
        if not service_folders:
            print(f"Error: Service '{target_service}' not found")
            sys.exit(1)
    
    service_folders.sort()
    
    print(f"Found {len(service_folders)} GCP service(s) to process\n")
    
    results = []
    for service_folder in service_folders:
        result = process_gcp_service_folder(service_folder, gcp_root)
        results.append(result)
        status_symbol = '✅' if result['status'] == 'PASS' else '⚠️' if result['status'] == 'ISSUES' else '❌' if result['status'] == 'ERROR' else '⏭️'
        print(f"  {status_symbol} {result['service']}: {result['status']}")
        if 'operations' in result:
            print(f"     Operations: {result['operations']}, Entities: {result.get('entities', 'N/A')}")
    
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    
    passed = sum(1 for r in results if r['status'] == 'PASS')
    issues = sum(1 for r in results if r['status'] == 'ISSUES')
    errors = sum(1 for r in results if r['status'] == 'ERROR')
    skipped = sum(1 for r in results if r['status'] == 'SKIP')
    
    print(f"Passed:  {passed}")
    print(f"Issues:  {issues}")
    print(f"Errors:  {errors}")
    print(f"Skipped: {skipped}")
    print("=" * 80)


if __name__ == '__main__':
    main()

