"""
Generate minimal list of independent and dependent operations needed to produce all fields.
Prioritizes independent (root) operations over dependent operations.
Adapted for Azure structure.
"""

import json
from pathlib import Path
from typing import Dict, List, Set, Optional
from collections import defaultdict
from datetime import datetime

def get_all_fields_from_direct_vars(direct_vars_file: Path) -> Dict[str, Dict]:
    """Extract all fields and their producing operations from direct_vars.json."""
    
    if not direct_vars_file.exists():
        return {}
    
    try:
        with open(direct_vars_file, 'r') as f:
            data = json.load(f)
    except Exception as e:
        return {}
    
    fields = data.get("fields", {})
    field_info = {}
    
    for field_name, field_data in fields.items():
        operations = field_data.get("operations", [])
        dependency_entity = field_data.get("dependency_index_entity", "")
        produces = field_data.get("produces", [])
        
        field_info[field_name] = {
            "operations": operations,
            "dependency_index_entity": dependency_entity,
            "produces": produces,
            "field_name": field_name
        }
    
    return field_info

def get_entity_to_operations_mapping(dependency_index: Dict) -> Dict[str, Set[str]]:
    """Map each entity to all operations that produce it."""
    
    entity_to_ops = defaultdict(set)
    entity_paths = dependency_index.get("entity_paths", {})
    
    for entity_name, paths in entity_paths.items():
        for path_data in paths:
            operations = path_data.get("operations", [])
            entity_to_ops[entity_name].update(operations)
    
    # Also add root operations
    roots = dependency_index.get("roots", [])
    for root in roots:
        op = root.get("op")
        produces = root.get("produces", [])
        for entity in produces:
            entity_to_ops[entity].add(op)
    
    return dict(entity_to_ops)

def get_operation_entities(operation: str, dependency_index: Dict) -> Set[str]:
    """Get all entities produced by an operation."""
    
    entities = set()
    
    # Check root operations
    roots = dependency_index.get("roots", [])
    for root in roots:
        if root.get("op") == operation:
            entities.update(root.get("produces", []))
    
    # Check entity_paths
    entity_paths = dependency_index.get("entity_paths", {})
    for entity_name, paths in entity_paths.items():
        for path_data in paths:
            if operation in path_data.get("operations", []):
                produces = path_data.get("produces", {})
                if isinstance(produces, dict) and operation in produces:
                    entities.update(produces[operation])
                # Also add the entity itself if operation produces it
                entities.add(entity_name)
    
    return entities

def get_operation_dependencies(operation: str, dependency_index: Dict) -> Set[str]:
    """Get all entities that an operation consumes (dependencies)."""
    
    dependencies = set()
    entity_paths = dependency_index.get("entity_paths", {})
    
    for entity_name, paths in entity_paths.items():
        for path_data in paths:
            if operation in path_data.get("operations", []):
                consumes = path_data.get("consumes", {})
                if isinstance(consumes, dict) and operation in consumes:
                    dependencies.update(consumes[operation])
    
    return dependencies

def find_minimal_operations(
    all_fields: Dict[str, Dict],
    dependency_index: Dict,
    root_operations: List[str]
) -> Dict:
    """Find minimal set of operations to cover all entities, preferring root operations."""
    
    # Get all entities from dependency_index (roots and entity_paths)
    # Only count entities that actually exist in dependency_index
    all_entities_needed = set()
    
    # From roots
    roots = dependency_index.get("roots", [])
    for root in roots:
        all_entities_needed.update(root.get("produces", []))
    
    # From entity_paths
    entity_paths = dependency_index.get("entity_paths", {})
    all_entities_needed.update(entity_paths.keys())
    
    # Build set of valid entities (those that exist in dependency_index)
    valid_entities = all_entities_needed.copy()
    
    # Also try to get entities from fields if they exist, but only if they're valid
    field_to_entities = {}
    for field_name, field_data in all_fields.items():
        entities = set()
        if field_data.get("dependency_index_entity"):
            entity = field_data["dependency_index_entity"]
            # Only add if it's a valid entity (exists in dependency_index)
            if entity in valid_entities:
                entities.add(entity)
        # Add produces only if they're valid
        for prod in field_data.get("produces", []):
            if prod in valid_entities:
                entities.add(prod)
        field_to_entities[field_name] = entities
        all_entities_needed.update(entities)
    
    # Build entity to operations mapping
    entity_to_ops = get_entity_to_operations_mapping(dependency_index)
    
    # Separate root and dependent operations
    root_ops_set = set(root_operations)
    
    # Build operation coverage map
    operation_coverage = {}
    all_ops = set()
    for ops in entity_to_ops.values():
        all_ops.update(ops)
    
    for op in all_ops:
        entities_produced = get_operation_entities(op, dependency_index)
        dependencies = get_operation_dependencies(op, dependency_index)
        is_root = op in root_ops_set
        
        operation_coverage[op] = {
            "entities_produced": entities_produced,
            "dependencies": dependencies,
            "is_root": is_root,
            "coverage_count": len(entities_produced & all_entities_needed)
        }
    
    # Greedy algorithm: prefer root operations first
    selected_operations = []
    covered_entities = set()
    remaining_entities = all_entities_needed.copy()
    
    # Phase 1: Select root operations
    root_ops_available = [op for op, info in operation_coverage.items() if info["is_root"]]
    root_ops_available.sort(key=lambda op: operation_coverage[op]["coverage_count"], reverse=True)
    
    for op in root_ops_available:
        entities = operation_coverage[op]["entities_produced"]
        new_entities = entities & remaining_entities
        
        if new_entities:
            deps = operation_coverage[op]["dependencies"]
            selected_operations.append({
                "operation": op,
                "type": "INDEPENDENT",
                "entities_covered": sorted(new_entities),
                "dependencies": sorted(deps),
                "arns_produced": [],
                "arn_count": 0,
                "primary_arn_count": 0,
                "priority": "INDEPENDENT",
                "dependencies_logic": "NONE" if not deps else "AND",
                "dependencies_required": "NONE" if not deps else "ALL",
                "dependencies_count": len(deps),
                "dependencies_note": "No dependencies - can be called independently" if not deps else f"Requires {len(deps)} dependencies"
            })
            covered_entities.update(new_entities)
            remaining_entities -= new_entities
    
    # Phase 2: Select dependent operations for remaining entities
    dependent_ops_available = [op for op, info in operation_coverage.items() if not info["is_root"]]
    dependent_ops_available.sort(key=lambda op: operation_coverage[op]["coverage_count"], reverse=True)
    
    # Track which entities we can produce (considering dependencies)
    available_entities = covered_entities.copy()
    
    while remaining_entities:
        best_op = None
        best_new_entities = set()
        best_deps_satisfied = True
        
        for op in dependent_ops_available:
            if op in [s["operation"] for s in selected_operations]:
                continue
            
            entities = operation_coverage[op]["entities_produced"]
            deps = operation_coverage[op]["dependencies"]
            
            # Check if dependencies are satisfied
            deps_satisfied = deps.issubset(available_entities)
            new_entities = entities & remaining_entities
            
            if new_entities and deps_satisfied:
                if len(new_entities) > len(best_new_entities):
                    best_op = op
                    best_new_entities = new_entities
                    best_deps_satisfied = True
            elif new_entities and not deps_satisfied:
                # Track operations that could work if dependencies are met
                if not best_op:
                    best_op = op
                    best_new_entities = new_entities
                    best_deps_satisfied = False
        
        if best_op and best_deps_satisfied:
            deps = operation_coverage[best_op]["dependencies"]
            selected_operations.append({
                "operation": best_op,
                "type": "DEPENDENT",
                "entities_covered": sorted(best_new_entities),
                "dependencies": sorted(deps),
                "requires": sorted(deps & available_entities),
                "arns_produced": [],
                "arn_count": 0,
                "primary_arn_count": 0,
                "priority": "OTHER",
                "dependencies_logic": "AND",
                "dependencies_required": "ALL",
                "dependencies_count": len(deps),
                "dependencies_note": f"Requires {len(deps)} dependencies" if deps else "No dependencies"
            })
            available_entities.update(operation_coverage[best_op]["entities_produced"])
            remaining_entities -= best_new_entities
        else:
            # No more operations can cover remaining entities (might have unsatisfied dependencies)
            break
    
    return {
        "selected_operations": selected_operations,
        "total_entities_needed": len(all_entities_needed),
        "entities_covered": len(covered_entities),
        "entities_remaining": len(remaining_entities),
        "coverage_percentage": (len(covered_entities) / len(all_entities_needed) * 100) if all_entities_needed else 0
    }

def generate_operations_report(service_name: str, service_dir: Path) -> Optional[Dict]:
    """Generate minimal operations report for a service."""
    
    direct_vars_file = service_dir / "direct_vars.json"
    dependency_index_file = service_dir / "dependency_index.json"
    
    if not direct_vars_file.exists() or not dependency_index_file.exists():
        return None
    
    try:
        with open(direct_vars_file, 'r') as f:
            direct_vars = json.load(f)
        
        with open(dependency_index_file, 'r') as f:
            dependency_index = json.load(f)
    except Exception as e:
        return {"error": str(e)}
    
    # Get all fields
    all_fields = get_all_fields_from_direct_vars(direct_vars_file)
    
    # Get root operations
    roots = dependency_index.get("roots", [])
    root_operations = [r.get("op") for r in roots]
    
    # Find minimal operations
    minimal_ops = find_minimal_operations(all_fields, dependency_index, root_operations)
    
    report = {
        "service": service_name,
        "generated_at": datetime.now().isoformat(),
        "total_fields": len(all_fields),
        "root_operations_available": root_operations,
        "minimal_operations": minimal_ops,
        "arn_summary": {
            "total_arns_produced": 0,
            "primary_resource_arns": 0,
            "other_arns": 0,
            "total_unique_arns": 0,
            "deduplicated": True
        },
        "arn_deduplication": {},
        "summary": {
            "total_operations_needed": len(minimal_ops["selected_operations"]),
            "independent_operations": sum(1 for op in minimal_ops["selected_operations"] if op["type"] == "INDEPENDENT"),
            "dependent_operations": sum(1 for op in minimal_ops["selected_operations"] if op["type"] == "DEPENDENT"),
            "coverage_percentage": minimal_ops["coverage_percentage"]
        }
    }
    
    return report

def generate_all_services(base_dir: Path):
    """Generate minimal operations list for all services."""
    
    print("="*80)
    print("GENERATING MINIMAL OPERATIONS LIST FOR ALL AZURE SERVICES")
    print("="*80)
    
    # Get all service directories
    service_dirs = [d for d in base_dir.iterdir() 
                    if d.is_dir() and not d.name.startswith('.') 
                    and (d / 'direct_vars.json').exists() 
                    and (d / 'dependency_index.json').exists()]
    
    print(f"Found {len(service_dirs)} service directories")
    
    services_processed = 0
    services_with_errors = []
    
    for service_dir in sorted(service_dirs):
        service_name = service_dir.name
        try:
            report = generate_operations_report(service_name, service_dir)
            
            if not report:
                services_with_errors.append((service_name, "Missing files"))
                continue
            
            if "error" in report:
                services_with_errors.append((service_name, report["error"]))
                continue
            
            # Save JSON report
            json_file = service_dir / "minimal_operations_list.json"
            with open(json_file, 'w') as f:
                json.dump(report, f, indent=2)
            
            print(f"✓ {service_name}: {report['summary']['total_operations_needed']} operations, "
                  f"{report['summary']['coverage_percentage']:.1f}% coverage")
            
            services_processed += 1
            
            if services_processed % 20 == 0:
                print(f"  Progress: {services_processed} services processed...")
                
        except Exception as e:
            services_with_errors.append((service_name, str(e)))
            print(f"  ✗ {service_name}: Error - {e}")
    
    print(f"\n{'='*80}")
    print("GENERATION COMPLETE")
    print(f"{'='*80}")
    print(f"Services processed: {services_processed}")
    
    if services_with_errors:
        print(f"\nServices with errors: {len(services_with_errors)}")
        for service, error in services_with_errors[:10]:
            print(f"  - {service}: {error}")

def main():
    base_dir = Path('/Users/apple/Desktop/threat-engine/pythonsdk-database/azure')
    
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == '--all':
        generate_all_services(base_dir)
    else:
        # Generate for single service (compute) as test
        service_name = 'compute'
        service_dir = base_dir / service_name
        
        print(f"Generating minimal operations list for: {service_name}")
        print("="*80)
        
        report = generate_operations_report(service_name, service_dir)
        
        if report and "error" not in report:
            json_file = service_dir / "minimal_operations_list.json"
            with open(json_file, 'w') as f:
                json.dump(report, f, indent=2)
            
            print(f"\n✓ Saved to: {json_file}")
            print(f"\nSummary:")
            print(f"  Total Fields: {report['total_fields']}")
            print(f"  Root Operations Available: {len(report['root_operations_available'])}")
            print(f"  Minimal Operations Needed: {report['summary']['total_operations_needed']}")
            print(f"    - Independent: {report['summary']['independent_operations']}")
            print(f"    - Dependent: {report['summary']['dependent_operations']}")
            print(f"  Coverage: {report['summary']['coverage_percentage']:.1f}%")
            
            # Show first few operations
            print(f"\nFirst 5 operations:")
            for i, op in enumerate(report['minimal_operations']['selected_operations'][:5], 1):
                print(f"  {i}. {op['operation']} ({op['type']}) - {len(op['entities_covered'])} entities")
        else:
            print(f"Error: {report.get('error', 'Unknown error')}")

if __name__ == '__main__':
    main()

