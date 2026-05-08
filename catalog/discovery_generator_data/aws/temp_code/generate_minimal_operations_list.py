"""
Generate minimal list of independent and dependent operations needed to produce all fields.
Prioritizes independent (root) operations over dependent operations.
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
                if operation in produces:
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
                if operation in consumes:
                    dependencies.update(consumes[operation])
    
    return dependencies

def find_minimal_operations(
    all_fields: Dict[str, Dict],
    dependency_index: Dict,
    root_operations: List[str]
) -> Dict:
    """Find minimal set of operations to cover all fields, preferring root operations."""
    
    # Build field to entities mapping
    field_to_entities = {}
    for field_name, field_data in all_fields.items():
        entities = set()
        if field_data.get("dependency_index_entity"):
            entities.add(field_data["dependency_index_entity"])
        entities.update(field_data.get("produces", []))
        field_to_entities[field_name] = entities
    
    # Get all entities that need to be covered
    all_entities_needed = set()
    for entities in field_to_entities.values():
        all_entities_needed.update(entities)
    
    # Build entity to operations mapping
    entity_to_ops = get_entity_to_operations_mapping(dependency_index)
    
    # Separate root and dependent operations
    root_ops_set = set(root_operations)
    
    # Build operation coverage map
    operation_coverage = {}
    for op in set().union(*[ops for ops in entity_to_ops.values()]):
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
            selected_operations.append({
                "operation": op,
                "type": "INDEPENDENT",
                "entities_covered": sorted(new_entities),
                "dependencies": sorted(operation_coverage[op]["dependencies"])
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
                    best_deps_satisfied = deps_satisfied
        
        if best_op:
            selected_operations.append({
                "operation": best_op,
                "type": "DEPENDENT",
                "entities_covered": sorted(best_new_entities),
                "dependencies": sorted(operation_coverage[best_op]["dependencies"]),
                "requires": sorted(operation_coverage[best_op]["dependencies"] & available_entities)
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
        "summary": {
            "total_operations_needed": len(minimal_ops["selected_operations"]),
            "independent_operations": sum(1 for op in minimal_ops["selected_operations"] if op["type"] == "INDEPENDENT"),
            "dependent_operations": sum(1 for op in minimal_ops["selected_operations"] if op["type"] == "DEPENDENT"),
            "coverage_percentage": minimal_ops["coverage_percentage"]
        }
    }
    
    return report

def generate_markdown_operations_report(report: Dict) -> str:
    """Generate markdown formatted operations report."""
    
    lines = []
    lines.append(f"# {report['service'].upper()} - Minimal Operations List")
    lines.append("")
    lines.append(f"**Generated:** {report['generated_at']}")
    lines.append("")
    lines.append(f"**Total Fields:** {report['total_fields']}")
    lines.append(f"**Total Operations Needed:** {report['summary']['total_operations_needed']}")
    lines.append(f"**Independent Operations:** {report['summary']['independent_operations']}")
    lines.append(f"**Dependent Operations:** {report['summary']['dependent_operations']}")
    lines.append(f"**Coverage:** {report['summary']['coverage_percentage']:.1f}%")
    lines.append("")
    lines.append("---")
    lines.append("")
    
    # Group by type
    independent_ops = [op for op in report['minimal_operations']['selected_operations'] if op['type'] == 'INDEPENDENT']
    dependent_ops = [op for op in report['minimal_operations']['selected_operations'] if op['type'] == 'DEPENDENT']
    
    lines.append("## ✅ Independent Operations (Root Operations)")
    lines.append("")
    lines.append("These operations can be called without any dependencies:")
    lines.append("")
    
    for i, op_info in enumerate(independent_ops, 1):
        lines.append(f"### {i}. {op_info['operation']}")
        lines.append("")
        lines.append(f"- **Type:** Independent (Root)")
        lines.append(f"- **Entities Covered:** {len(op_info['entities_covered'])}")
        if op_info['entities_covered']:
            lines.append(f"- **Covers:** {', '.join(op_info['entities_covered'][:5])}{'...' if len(op_info['entities_covered']) > 5 else ''}")
        lines.append("")
    
    if dependent_ops:
        lines.append("## ⚠️  Dependent Operations")
        lines.append("")
        lines.append("These operations require inputs from other operations:")
        lines.append("")
        
        for i, op_info in enumerate(dependent_ops, 1):
            lines.append(f"### {i}. {op_info['operation']}")
            lines.append("")
            lines.append(f"- **Type:** Dependent")
            lines.append(f"- **Entities Covered:** {len(op_info['entities_covered'])}")
            if op_info['entities_covered']:
                lines.append(f"- **Covers:** {', '.join(op_info['entities_covered'][:5])}{'...' if len(op_info['entities_covered']) > 5 else ''}")
            if op_info.get('requires'):
                lines.append(f"- **Requires:** {', '.join(op_info['requires'])}")
            if op_info.get('dependencies'):
                lines.append(f"- **Dependencies:** {', '.join(op_info['dependencies'][:3])}{'...' if len(op_info['dependencies']) > 3 else ''}")
            lines.append("")
    
    # Summary list
    lines.append("---")
    lines.append("")
    lines.append("## 📋 Complete Operations List (In Order)")
    lines.append("")
    lines.append("### Independent Operations:")
    for op_info in independent_ops:
        lines.append(f"1. `{op_info['operation']}`")
    lines.append("")
    
    if dependent_ops:
        lines.append("### Dependent Operations:")
        for op_info in dependent_ops:
            lines.append(f"1. `{op_info['operation']}`")
        lines.append("")
    
    return "\n".join(lines)

def generate_csv_operations_report(report: Dict) -> str:
    """Generate CSV formatted operations report."""
    
    lines = []
    lines.append("Operation,Type,Entities Covered Count,Dependencies,Requires")
    
    for op_info in report['minimal_operations']['selected_operations']:
        row = [
            op_info['operation'],
            op_info['type'],
            len(op_info['entities_covered']),
            "; ".join(op_info.get('dependencies', [])) or "None",
            "; ".join(op_info.get('requires', [])) or "None"
        ]
        lines.append(",".join(f'"{str(cell)}"' for cell in row))
    
    return "\n".join(lines)

def generate_all_operations_reports(aws_dir: str, services: List[str]):
    """Generate operations reports for all specified services."""
    
    aws_path = Path(aws_dir)
    all_reports = {}
    
    print("=" * 80)
    print("GENERATING MINIMAL OPERATIONS LIST REPORTS")
    print("=" * 80)
    
    for service_name in services:
        print(f"\n{'='*80}")
        print(f"Processing: {service_name.upper()}")
        print(f"{'='*80}")
        
        service_dir = aws_path / service_name
        
        report = generate_operations_report(service_name, service_dir)
        
        if not report:
            print(f"  ⚠️  Could not generate report (missing files)")
            continue
        
        if "error" in report:
            print(f"  ❌ Error: {report['error']}")
            continue
        
        # Save JSON report
        json_file = service_dir / "minimal_operations_list.json"
        with open(json_file, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"  ✅ JSON report saved: {json_file}")
        
        # Save Markdown report
        md_content = generate_markdown_operations_report(report)
        md_file = service_dir / "minimal_operations_list.md"
        with open(md_file, 'w') as f:
            f.write(md_content)
        print(f"  ✅ Markdown report saved: {md_file}")
        
        # Save CSV report
        csv_content = generate_csv_operations_report(report)
        csv_file = service_dir / "minimal_operations_list.csv"
        with open(csv_file, 'w') as f:
            f.write(csv_content)
        print(f"  ✅ CSV report saved: {csv_file}")
        
        # Print summary
        print(f"\n  Summary:")
        print(f"    Total Fields: {report['total_fields']}")
        print(f"    Operations Needed: {report['summary']['total_operations_needed']}")
        print(f"    Independent: {report['summary']['independent_operations']}")
        print(f"    Dependent: {report['summary']['dependent_operations']}")
        print(f"    Coverage: {report['summary']['coverage_percentage']:.1f}%")
        
        all_reports[service_name] = report
    
    return all_reports

if __name__ == "__main__":
    aws_dir = "/Users/apple/Desktop/threat-engine/pythonsdk-database/aws"
    services_to_report = ["accessanalyzer", "ec2", "s3", "iam"]
    
    reports = generate_all_operations_reports(aws_dir, services_to_report)
    
    print(f"\n\n{'='*80}")
    print("OPERATIONS LIST GENERATION COMPLETE")
    print(f"{'='*80}")
    print(f"\nGenerated reports for {len(reports)} services:")
    for service_name in reports.keys():
        print(f"  - {service_name}")
        print(f"    - minimal_operations_list.json")
        print(f"    - minimal_operations_list.md")
        print(f"    - minimal_operations_list.csv")

