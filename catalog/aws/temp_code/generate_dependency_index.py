#!/usr/bin/env python3
"""
Generate dependency_index.json for all services using:
1. aws_fields_reference.csv - for fields and dependency_index_entity
2. boto3_dependencies_with_python_names_fully_enriched.json - for operations and outputs

Test on one service first before running for all.
"""

import json
import csv
import re
from pathlib import Path
from typing import Dict, List, Any, Set, Optional
from collections import defaultdict

def is_read_operation(operation_name: str) -> bool:
    """Check if operation is a read operation"""
    read_prefixes = ['List', 'Get', 'Describe', 'Search', 'Lookup']
    return any(operation_name.startswith(prefix) for prefix in read_prefixes)

def camel_to_snake(name: str) -> str:
    """Convert camelCase to snake_case"""
    # Insert underscore before uppercase letters (except first)
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()

def normalize_field_name(name: str) -> str:
    """Normalize field name for matching (remove underscores, hyphens, lowercase)"""
    return re.sub(r'[_-]', '', name.lower())

def load_csv_fields(csv_path: Path) -> Dict[str, List[Dict[str, Any]]]:
    """
    Load fields from CSV grouped by service
    Returns: {service: [field_rows]}
    """
    fields_by_service = defaultdict(list)
    
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            service = row['service']
            fields_by_service[service].append(row)
    
    return dict(fields_by_service)

def build_field_to_entity_map(service_fields: List[Dict], service_name: str) -> Dict[str, str]:
    """
    Build map from field_name to entity
    Returns: {field_name: entity}
    """
    field_to_entity = {}
    
    for field_row in service_fields:
        field_name = field_row['field_name']
        entity = field_row.get('dependency_index_entity', '').strip()
        
        if entity:
            field_to_entity[field_name] = entity
            # Also add normalized versions for matching
            normalized = normalize_field_name(field_name)
            if normalized != field_name.lower():
                field_to_entity[normalized] = entity
    
    return field_to_entity

def build_entity_to_fields_map(service_fields: List[Dict]) -> Dict[str, List[str]]:
    """
    Map entity names to field names that produce them
    Returns: {entity: [field_names]}
    """
    entity_to_fields = defaultdict(list)
    
    for field_row in service_fields:
        entity = field_row.get('dependency_index_entity', '').strip()
        if entity:
            field_name = field_row['field_name']
            entity_to_fields[entity].append(field_name)
    
    return dict(entity_to_fields)

def map_param_to_entity(param_name: str, service_name: str, 
                        all_entities: Set[str], 
                        field_to_entity: Dict[str, str],
                        entity_to_fields: Dict[str, List[str]]) -> Optional[str]:
    """
    Map a parameter name to an entity using multiple strategies
    """
    # Strategy 1: Direct entity match (param is already an entity)
    direct_entity = f"{service_name}.{param_name}"
    if direct_entity in all_entities:
        return direct_entity
    
    # Strategy 2: Convert camelCase to snake_case and match
    param_snake = camel_to_snake(param_name)
    snake_entity = f"{service_name}.{param_snake}"
    if snake_entity in all_entities:
        return snake_entity
    
    # Strategy 3: Try matching against field names in CSV
    # Check if param matches a field name (case-insensitive, normalized)
    param_normalized = normalize_field_name(param_name)
    
    # Direct field name match
    if param_name in field_to_entity:
        return field_to_entity[param_name]
    
    # Normalized field name match
    if param_normalized in field_to_entity:
        return field_to_entity[param_normalized]
    
    # Strategy 4: Try common patterns
    # analyzerArn -> analyzer_arn -> accessanalyzer.analyzer_arn
    # accessPreviewId -> access_preview_id -> accessanalyzer.access_preview_id
    # analyzerName -> analyzer_name -> accessanalyzer.analyzer_name
    
    # Try with common suffixes
    for suffix in ['_id', '_arn', '_name', '_arn']:
        candidate = f"{service_name}.{param_snake}{suffix}"
        if candidate in all_entities:
            return candidate
    
    # Strategy 5: Search entity_to_fields for partial matches
    # Look for entities whose field names contain the param
    for entity, fields in entity_to_fields.items():
        for field in fields:
            field_normalized = normalize_field_name(field)
            # Check if param is contained in field or vice versa
            if (param_normalized in field_normalized or 
                field_normalized in param_normalized):
                # Prefer exact matches
                if param_normalized == field_normalized:
                    return entity
    
    # Strategy 6: Try removing common prefixes/suffixes
    # Remove common prefixes
    for prefix in ['get', 'list', 'describe', 'search', 'lookup']:
        if param_name.lower().startswith(prefix):
            remaining = param_name[len(prefix):]
            if remaining:
                return map_param_to_entity(remaining, service_name, all_entities, 
                                          field_to_entity, entity_to_fields)
    
    return None

def find_operations_producing_entity(entity: str, service_data: Dict, 
                                     entity_to_fields: Dict[str, List[str]]) -> List[Dict[str, Any]]:
    """
    Find all read operations that produce a given entity
    Returns list of operation info with produces/consumes
    """
    operations_info = []
    field_names = entity_to_fields.get(entity, [])
    
    if not field_names:
        return []
    
    # Check both independent and dependent operations (read ops only)
    all_operations = service_data.get("independent", []) + service_data.get("dependent", [])
    read_operations = [op for op in all_operations if is_read_operation(op.get("operation", ""))]
    
    for op in read_operations:
        op_name = op.get("operation", "")
        produces_entity = False
        
        # Check if operation produces this entity via item_fields
        item_fields = op.get("item_fields", {})
        if isinstance(item_fields, dict):
            for field_name in field_names:
                if field_name in item_fields:
                    produces_entity = True
                    break
        
        # Check output_fields
        if not produces_entity:
            output_fields = op.get("output_fields", {})
            if isinstance(output_fields, dict):
                for field_name in field_names:
                    if field_name in output_fields:
                        produces_entity = True
                        break
        
        if produces_entity:
            # Get required params (these need to be mapped to entities)
            required_params = op.get("required_params", [])
            
            operations_info.append({
                "operation": op_name,
                "produces": [entity],
                "required_params": required_params,
                "is_independent": len(required_params) == 0
            })
    
    return operations_info

def build_entity_paths_entry(operations_info: List[Dict], all_entities: Set[str], 
                              service_name: str,
                              field_to_entity: Dict[str, str],
                              entity_to_fields: Dict[str, List[str]]) -> Optional[Dict[str, Any]]:
    """
    Build entity_paths entry from operations info
    """
    if not operations_info:
        return None
    
    # Group by operation
    ops_by_name = defaultdict(lambda: {"produces": [], "consumes": []})
    
    for op_info in operations_info:
        op_name = op_info["operation"]
        ops_by_name[op_name]["produces"].extend(op_info["produces"])
        
        # Map params to entities
        params = op_info["required_params"]
        consumed_entities = []
        for param in params:
            entity = map_param_to_entity(param, service_name, all_entities, 
                                        field_to_entity, entity_to_fields)
            if entity:
                consumed_entities.append(entity)
        
        ops_by_name[op_name]["consumes"].extend(consumed_entities)
    
    # Build entry
    entry = {
        "operations": sorted(ops_by_name.keys()),
        "produces": {},
        "consumes": {},
        "external_inputs": []
    }
    
    for op_name in sorted(ops_by_name.keys()):
        entry["produces"][op_name] = sorted(list(set(ops_by_name[op_name]["produces"])))
        entry["consumes"][op_name] = sorted(list(set(ops_by_name[op_name]["consumes"])))
    
    return entry

def build_roots(service_data: Dict, entity_to_fields: Dict[str, List[str]], 
                service_name: str) -> List[Dict[str, Any]]:
    """
    Build roots array from independent read operations
    """
    roots = []
    independent_ops = service_data.get("independent", [])
    
    for op in independent_ops:
        op_name = op.get("operation", "")
        if not is_read_operation(op_name):
            continue
        
        # Find entities produced by this operation
        produces = []
        
        # Match item_fields to entities
        item_fields = op.get("item_fields", {})
        if isinstance(item_fields, dict):
            for field_name in item_fields.keys():
                # Find entity for this field
                for entity, fields in entity_to_fields.items():
                    if field_name in fields:
                        if entity not in produces:
                            produces.append(entity)
        
        # Match output_fields to entities
        output_fields = op.get("output_fields", {})
        if isinstance(output_fields, dict):
            for field_name in output_fields.keys():
                for entity, fields in entity_to_fields.items():
                    if field_name in fields:
                        if entity not in produces:
                            produces.append(entity)
        
        if produces:
            roots.append({
                "op": op_name,
                "produces": sorted(produces)
            })
    
    return roots

def generate_dependency_index(service_name: str, service_fields: List[Dict], 
                             service_data: Dict) -> Dict[str, Any]:
    """
    Generate dependency_index.json for a service
    """
    # Build maps
    entity_to_fields = build_entity_to_fields_map(service_fields)
    field_to_entity = build_field_to_entity_map(service_fields, service_name)
    all_entities = set(entity_to_fields.keys())
    
    # Build entity_paths
    entity_paths = {}
    
    for entity in sorted(all_entities):
        operations_info = find_operations_producing_entity(entity, service_data, entity_to_fields)
        
        if operations_info:
            entry = build_entity_paths_entry(operations_info, all_entities, service_name,
                                           field_to_entity, entity_to_fields)
            if entry:
                entity_paths[entity] = [entry]
    
    # Build roots (independent read operations)
    roots = build_roots(service_data, entity_to_fields, service_name)
    
    return {
        "service": service_name,
        "read_only": True,
        "roots": roots,
        "entity_paths": entity_paths
    }

def test_service(service_name: str, csv_path: Path, boto3_path: Path, output_dir: Path):
    """Test generation for a single service"""
    print(f"\n{'='*80}")
    print(f"Testing: {service_name}")
    print(f"{'='*80}")
    
    # Load CSV fields for this service
    fields_by_service = load_csv_fields(csv_path)
    service_fields = fields_by_service.get(service_name, [])
    
    if not service_fields:
        print(f"  ✗ No fields found in CSV for {service_name}")
        return False
    
    print(f"  Found {len(service_fields)} fields in CSV")
    
    # Load boto3 dependencies
    with open(boto3_path, 'r', encoding='utf-8') as f:
        boto3_deps = json.load(f)
    
    service_data = boto3_deps.get(service_name, {})
    
    if not service_data or not isinstance(service_data, dict) or 'error' in service_data:
        print(f"  ✗ No boto3 data found for {service_name}")
        return False
    
    print(f"  Found boto3 data: {len(service_data.get('independent', []))} independent, "
          f"{len(service_data.get('dependent', []))} dependent operations")
    
    try:
        dependency_index = generate_dependency_index(service_name, service_fields, service_data)
        
        roots_count = len(dependency_index.get('roots', []))
        entities_count = len(dependency_index.get('entity_paths', {}))
        
        print(f"\n  Results:")
        print(f"    Roots: {roots_count}")
        print(f"    Entities: {entities_count}")
        
        # Show sample entity
        if entities_count > 0:
            sample_entity = list(dependency_index['entity_paths'].keys())[0]
            sample_entry = dependency_index['entity_paths'][sample_entity][0]
            print(f"\n  Sample entity: {sample_entity}")
            print(f"    Operations: {sample_entry['operations']}")
            print(f"    Produces: {list(sample_entry['produces'].keys())[:2]}...")
            print(f"    Consumes: {list(sample_entry['consumes'].keys())[:2]}...")
        
        # Save to service directory
        service_dir = output_dir / service_name
        service_dir.mkdir(parents=True, exist_ok=True)
        
        output_path = service_dir / 'dependency_index.json'
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(dependency_index, f, indent=2, ensure_ascii=False)
        
        print(f"\n  ✓ Saved to: {output_path}")
        
        return True
        
    except Exception as e:
        print(f"  ✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

def generate_all_services(csv_path: Path, boto3_path: Path, output_dir: Path):
    """Generate dependency_index.json for all services"""
    print("\n" + "="*80)
    print("GENERATING DEPENDENCY_INDEX FOR ALL SERVICES")
    print("="*80)
    
    # Load CSV fields
    fields_by_service = load_csv_fields(csv_path)
    print(f"Loaded fields for {len(fields_by_service)} services")
    
    # Load boto3 dependencies
    with open(boto3_path, 'r', encoding='utf-8') as f:
        boto3_deps = json.load(f)
    print(f"Loaded boto3 dependencies for {len(boto3_deps)} services")
    
    services_processed = 0
    services_with_errors = []
    
    for service_name in sorted(fields_by_service.keys()):
        service_fields = fields_by_service[service_name]
        service_data = boto3_deps.get(service_name, {})
        
        if not service_data or not isinstance(service_data, dict) or 'error' in service_data:
            services_with_errors.append((service_name, "No boto3 data"))
            continue
        
        try:
            dependency_index = generate_dependency_index(service_name, service_fields, service_data)
            
            # Save to service directory
            service_dir = output_dir / service_name
            service_dir.mkdir(parents=True, exist_ok=True)
            
            output_path = service_dir / 'dependency_index.json'
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(dependency_index, f, indent=2, ensure_ascii=False)
            
            roots_count = len(dependency_index.get('roots', []))
            entities_count = len(dependency_index.get('entity_paths', {}))
            
            print(f"  ✓ {service_name}: {roots_count} roots, {entities_count} entities")
            services_processed += 1
            
        except Exception as e:
            services_with_errors.append((service_name, str(e)))
            print(f"  ✗ {service_name}: Error - {e}")
    
    print(f"\n{'='*80}")
    print("GENERATION COMPLETE")
    print(f"{'='*80}")
    print(f"Services processed: {services_processed}")
    print(f"Services with errors: {len(services_with_errors)}")
    
    if services_with_errors:
        print(f"\nServices with errors (first 10):")
        for service, error in services_with_errors[:10]:
            print(f"  - {service}: {error}")

def main():
    base_dir = Path('/Users/apple/Desktop/threat-engine/pythonsdk-database/aws')
    csv_path = base_dir / 'aws_fields_reference.csv'
    boto3_path = base_dir / 'boto3_dependencies_with_python_names_fully_enriched.json'
    
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == '--all':
        # Generate for all services
        generate_all_services(csv_path, boto3_path, base_dir)
    else:
        # Test on accessanalyzer first
        test_service_name = 'accessanalyzer'
        
        print("Testing dependency_index generation on single service...")
        success = test_service(test_service_name, csv_path, boto3_path, base_dir)
        
        if success:
            print(f"\n{'='*80}")
            print("TEST PASSED - Ready to generate for all services")
            print("Run with --all flag to generate for all services")
            print(f"{'='*80}")
        else:
            print(f"\n{'='*80}")
            print("TEST FAILED - Please review errors above")
            print(f"{'='*80}")

if __name__ == '__main__':
    main()

