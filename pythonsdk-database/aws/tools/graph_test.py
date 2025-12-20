#!/usr/bin/env python3
"""
Test harness for AWS service dependency graphs.

Checks whether each operation is "chain-satisfiable" - meaning all required
consumes can be produced by some chain of operations starting from independent
ops or external entities.
"""

import json
import argparse
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any
from collections import defaultdict, deque
import time

# ============================================================================
# DATA LOADING
# ============================================================================

def load_service_data(service_dir: Path) -> Tuple[Dict[str, Any], Dict[str, Any], Optional[Dict[str, Any]]]:
    """Load adjacency.json, operation_registry.json, and optional manual_review.json."""
    adjacency_file = service_dir / "adjacency.json"
    registry_file = service_dir / "operation_registry.json"
    manual_review_file = service_dir / "manual_review.json"
    
    if not adjacency_file.exists():
        raise FileNotFoundError(f"adjacency.json not found in {service_dir}")
    if not registry_file.exists():
        raise FileNotFoundError(f"operation_registry.json not found in {service_dir}")
    
    with open(adjacency_file, 'r') as f:
        adjacency = json.load(f)
    
    with open(registry_file, 'r') as f:
        registry = json.load(f)
    
    manual_review = None
    if manual_review_file.exists():
        with open(manual_review_file, 'r') as f:
            manual_review = json.load(f)
    
    return adjacency, registry, manual_review

# ============================================================================
# SATISFIABILITY CHECKING
# ============================================================================

def find_operation_chain(
    target_op: str,
    required_entities: Set[str],
    entity_producers: Dict[str, List[str]],
    op_consumes: Dict[str, List[str]],
    op_produces: Dict[str, List[str]],
    external_entities: Set[str],
    all_ops: Set[str],
    max_depth: int = 20
) -> Tuple[bool, Optional[List[str]], str, Set[str]]:
    """
    Find a chain of operations that can satisfy all required entities.
    Uses backward BFS to find producers.
    
    Returns:
        (is_satisfiable, chain, reason, missing_entities)
    """
    # Separate external and internal entities
    external_needed = required_entities & external_entities
    internal_needed = required_entities - external_entities
    
    if not internal_needed:
        # All entities are external - satisfied
        return True, [target_op], "external", set()
    
    # Track which entities are satisfied and by which ops
    satisfied_entities = set(external_needed)
    op_chain = []  # Operations in dependency order
    op_produces_map = {}  # op -> set of entities it produces
    
    # Build produces map
    for op, entities in op_produces.items():
        op_produces_map[op] = set(entities)
    
    # Backward BFS: start from target_op and work backwards
    # State: (op, depth, path_to_op, entities_still_needed)
    queue = deque([(target_op, 0, [], internal_needed.copy())])
    visited = set()  # (op, frozenset(needed_entities)) to avoid revisiting same state
    
    best_chain = None
    best_satisfied = set(external_needed)
    
    while queue:
        current_op, depth, path, needed = queue.popleft()
        
        if depth > max_depth:
            continue
        
        # Check for cycles
        if current_op in path:
            continue  # Skip cycles
        
        # Create state key
        state_key = (current_op, frozenset(needed))
        if state_key in visited:
            continue
        visited.add(state_key)
        
        # Check what this op produces
        produces = op_produces_map.get(current_op, set())
        newly_satisfied = needed & produces
        still_needed = needed - produces
        
        # Update satisfied entities
        current_satisfied = satisfied_entities | newly_satisfied
        
        # If all needed entities are satisfied, we found a chain
        if not still_needed:
            # Build chain: path + current_op + target_op
            chain = path + [current_op]
            if target_op not in chain:
                chain.append(target_op)
            # Remove duplicates while preserving order
            seen = set()
            final_chain = []
            for op in chain:
                if op not in seen:
                    final_chain.append(op)
                    seen.add(op)
            return True, final_chain, "satisfied", set()
        
        # Find producers for unmet entities
        producers_to_add = set()
        missing_entities = set()
        
        for entity in still_needed:
            producers = entity_producers.get(entity, [])
            
            if not producers:
                # Check for derivation candidate
                if '_' in entity:
                    base_entity = entity.rsplit('_', 1)[0]
                    base_producers = entity_producers.get(base_entity, [])
                    if base_producers:
                        return False, None, "needs_derivation", {entity}
                
                missing_entities.add(entity)
            else:
                # Pick first producer (prefer ops with fewer dependencies)
                producer = min(producers, key=lambda p: len(op_consumes.get(p, [])))
                producers_to_add.add(producer)
        
        # If we have missing entities with no producers, this path fails
        if missing_entities:
            # Continue to see if we can find a better path, but track missing
            if best_chain is None or len(missing_entities) < len(needed - best_satisfied):
                best_chain = path + [current_op]
                best_satisfied = current_satisfied
        
        # Add producers to queue
        for producer in producers_to_add:
            producer_needs = set(op_consumes.get(producer, []))
            # Only need entities that aren't already satisfied
            producer_still_needed = producer_needs - current_satisfied - external_entities
            
            new_path = path + [current_op]
            queue.append((producer, depth + 1, new_path, producer_still_needed | still_needed))
    
    # If we didn't find a complete chain, return best attempt
    if missing_entities:
        return False, None, "no_producer", missing_entities
    
    # Fallback: return best chain if we found one
    if best_chain:
        return False, best_chain, "no_producer", internal_needed - best_satisfied
    
    return False, None, "no_producer", internal_needed

def check_operation_satisfiability(
    op_name: str,
    adjacency: Dict[str, Any],
    registry: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Check if an operation is satisfiable.
    
    Returns:
        {
            "operation": op_name,
            "satisfiable": bool,
            "reason": str,
            "chain": List[str] | None,
            "missing_entities": List[str],
            "external_entities_used": List[str]
        }
    """
    op_consumes = adjacency.get("op_consumes", {})
    op_produces = adjacency.get("op_produces", {})
    entity_producers = adjacency.get("entity_producers", {})
    external_entities = set(adjacency.get("external_entities", []))
    
    # Get required entities for this operation
    required_entities = set(op_consumes.get(op_name, []))
    
    if not required_entities:
        # No dependencies - always satisfiable
        return {
            "operation": op_name,
            "satisfiable": True,
            "reason": "no_dependencies",
            "chain": [op_name],
            "missing_entities": [],
            "external_entities_used": []
        }
    
    # Get all operations
    all_ops = set(op_consumes.keys()) | set(op_produces.keys())
    
    # Find chain
    is_sat, chain, reason, missing = find_operation_chain(
        op_name,
        required_entities,
        entity_producers,
        op_consumes,
        op_produces,
        external_entities,
        all_ops
    )
    
    # Identify external entities used
    external_used = list(required_entities & external_entities)
    
    return {
        "operation": op_name,
        "satisfiable": is_sat,
        "reason": reason,
        "chain": chain if is_sat else None,
        "missing_entities": list(missing),
        "external_entities_used": external_used
    }

# ============================================================================
# REPORT GENERATION
# ============================================================================

def generate_service_report(
    service_name: str,
    adjacency: Dict[str, Any],
    registry: Dict[str, Any],
    manual_review: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Generate test report for a single service."""
    operations = registry.get("operations", {})
    op_consumes = adjacency.get("op_consumes", {})
    entity_producers = adjacency.get("entity_producers", {})
    external_entities = set(adjacency.get("external_entities", []))
    
    # Check satisfiability for each operation
    results = []
    for op_name in op_consumes.keys():
        result = check_operation_satisfiability(op_name, adjacency, registry)
        results.append(result)
    
    # Calculate statistics
    total_ops = len(results)
    satisfiable_ops = [r for r in results if r["satisfiable"]]
    unsatisfiable_ops = [r for r in results if not r["satisfiable"]]
    
    satisfiable_count = len(satisfiable_ops)
    satisfiable_percent = (satisfiable_count / total_ops * 100) if total_ops > 0 else 0
    
    # Breakdown by kind
    breakdown_by_kind = defaultdict(lambda: {"total": 0, "satisfiable": 0})
    
    for result in results:
        op_name = result["operation"]
        op_data = operations.get(op_name, {})
        kind = op_data.get("kind", "other")
        
        breakdown_by_kind[kind]["total"] += 1
        if result["satisfiable"]:
            breakdown_by_kind[kind]["satisfiable"] += 1
    
    # Calculate percentages
    for kind_data in breakdown_by_kind.values():
        total = kind_data["total"]
        kind_data["percent"] = (kind_data["satisfiable"] / total * 100) if total > 0 else 0
    
    # Top missing entities
    missing_entity_counts = defaultdict(int)
    for result in unsatisfiable_ops:
        for entity in result["missing_entities"]:
            missing_entity_counts[entity] += 1
    
    top_missing_entities = sorted(
        missing_entity_counts.items(),
        key=lambda x: x[1],
        reverse=True
    )[:20]
    
    # Top external entities used
    external_entity_counts = defaultdict(int)
    for result in results:
        for entity in result["external_entities_used"]:
            external_entity_counts[entity] += 1
    
    top_external_entities = sorted(
        external_entity_counts.items(),
        key=lambda x: x[1],
        reverse=True
    )[:20]
    
    # Unsatisfiable examples
    unsat_examples = sorted(
        unsatisfiable_ops,
        key=lambda x: len(x["missing_entities"]),
        reverse=True
    )[:10]
    
    # Satisfiable examples with chains
    sat_examples = sorted(
        satisfiable_ops,
        key=lambda x: len(x.get("chain", [])),
        reverse=True
    )[:10]
    
    report = {
        "service_name": service_name,
        "total_ops": total_ops,
        "satisfiable_ops_count": satisfiable_count,
        "satisfiable_ops_percent": round(satisfiable_percent, 2),
        "unsatisfiable_ops_count": len(unsatisfiable_ops),
        "breakdown_by_kind": dict(breakdown_by_kind),
        "top_missing_entities": [{"entity": e, "count": c} for e, c in top_missing_entities],
        "top_external_entities_used": [{"entity": e, "count": c} for e, c in top_external_entities],
        "unsat_examples": [
            {
                "operation": ex["operation"],
                "reason": ex["reason"],
                "missing_entities": ex["missing_entities"][:5]  # Limit to 5
            }
            for ex in unsat_examples
        ],
        "sat_examples": [
            {
                "operation": ex["operation"],
                "chain": ex["chain"],
                "external_entities_used": ex["external_entities_used"]
            }
            for ex in sat_examples
        ]
    }
    
    # Add suspicious paths if manual_review exists
    if manual_review:
        suspicious_paths = manual_review.get("issues", {}).get("suspicious_paths", [])
        if suspicious_paths:
            report["suspicious_paths_count"] = len(suspicious_paths)
            report["suspicious_paths_examples"] = suspicious_paths[:10]
    
    return report

def generate_global_summary(reports: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate global summary across all services."""
    total_services = len(reports)
    total_ops = sum(r["total_ops"] for r in reports)
    total_satisfiable = sum(r["satisfiable_ops_count"] for r in reports)
    total_unsatisfiable = sum(r["unsatisfiable_ops_count"] for r in reports)
    
    global_satisfiable_percent = (total_satisfiable / total_ops * 100) if total_ops > 0 else 0
    
    # Aggregate missing entities
    missing_entity_counts = defaultdict(int)
    for report in reports:
        for item in report.get("top_missing_entities", []):
            missing_entity_counts[item["entity"]] += item["count"]
    
    most_common_missing = sorted(
        missing_entity_counts.items(),
        key=lambda x: x[1],
        reverse=True
    )[:30]
    
    # Aggregate external entities
    external_entity_counts = defaultdict(int)
    for report in reports:
        for item in report.get("top_external_entities_used", []):
            external_entity_counts[item["entity"]] += item["count"]
    
    most_common_external = sorted(
        external_entity_counts.items(),
        key=lambda x: x[1],
        reverse=True
    )[:30]
    
    # Services ranked by satisfiability
    services_ranked = sorted(
        reports,
        key=lambda x: x["satisfiable_ops_percent"],
        reverse=True
    )
    
    # Aggregate suspicious paths
    suspicious_patterns = defaultdict(int)
    for report in reports:
        for path_info in report.get("suspicious_paths_examples", []):
            issue = path_info.get("issue", "")
            if issue:
                suspicious_patterns[issue] += 1
    
    summary = {
        "total_services": total_services,
        "total_operations": total_ops,
        "total_satisfiable": total_satisfiable,
        "total_unsatisfiable": total_unsatisfiable,
        "global_satisfiable_percent": round(global_satisfiable_percent, 2),
        "most_common_missing_entities": [{"entity": e, "count": c} for e, c in most_common_missing],
        "most_common_external_entities": [{"entity": e, "count": c} for e, c in most_common_external],
        "services_ranked_by_satisfiability": [
            {
                "service": r["service_name"],
                "satisfiable_percent": r["satisfiable_ops_percent"],
                "total_ops": r["total_ops"],
                "unsatisfiable_count": r["unsatisfiable_ops_count"]
            }
            for r in services_ranked
        ],
        "suspicious_paths_patterns": [
            {"pattern": p, "count": c}
            for p, c in sorted(suspicious_patterns.items(), key=lambda x: x[1], reverse=True)[:20]
        ]
    }
    
    return summary

# ============================================================================
# CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Test harness for AWS service dependency graphs"
    )
    parser.add_argument(
        "--service-dir",
        type=str,
        help="Path to a single service folder"
    )
    parser.add_argument(
        "--root",
        type=str,
        help="Path to root directory containing all service folders"
    )
    parser.add_argument(
        "--out",
        type=str,
        default="reports",
        help="Output directory for reports (default: reports)"
    )
    
    args = parser.parse_args()
    
    if not args.service_dir and not args.root:
        parser.error("Must specify either --service-dir or --root")
    
    output_dir = Path(args.out)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    start_time = time.time()
    reports = []
    
    if args.service_dir:
        # Single service mode
        service_dir = Path(args.service_dir)
        service_name = service_dir.name
        
        print(f"Testing service: {service_name}")
        try:
            adjacency, registry, manual_review = load_service_data(service_dir)
            report = generate_service_report(service_name, adjacency, registry, manual_review)
            reports.append(report)
            
            # Write report
            report_file = output_dir / f"{service_name}_graph_test_report.json"
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2)
            
            print(f"  ✓ Total ops: {report['total_ops']}")
            print(f"  ✓ Satisfiable: {report['satisfiable_ops_count']} ({report['satisfiable_ops_percent']}%)")
            print(f"  ✓ Unsatisfiable: {report['unsatisfiable_ops_count']}")
            print(f"  ✓ Report written to {report_file}")
            
        except Exception as e:
            print(f"  ✗ Error: {e}")
            sys.exit(1)
    
    else:
        # Multi-service mode
        root_dir = Path(args.root)
        service_dirs = [d for d in root_dir.iterdir() if d.is_dir() and not d.name.startswith('.')]
        
        print(f"Testing {len(service_dirs)} services...")
        
        for service_dir in sorted(service_dirs):
            service_name = service_dir.name
            try:
                adjacency, registry, manual_review = load_service_data(service_dir)
                report = generate_service_report(service_name, adjacency, registry, manual_review)
                reports.append(report)
                
                # Write individual report
                report_file = output_dir / f"{service_name}_graph_test_report.json"
                with open(report_file, 'w') as f:
                    json.dump(report, f, indent=2)
                
                status = "✓" if report['satisfiable_ops_percent'] >= 90 else "⚠" if report['satisfiable_ops_percent'] >= 50 else "✗"
                print(f"  {status} {service_name}: {report['satisfiable_ops_percent']:.1f}% ({report['satisfiable_ops_count']}/{report['total_ops']})")
                
            except FileNotFoundError as e:
                print(f"  ✗ {service_name}: Missing files - {e}")
            except Exception as e:
                print(f"  ✗ {service_name}: Error - {e}")
        
        # Generate global summary
        if reports:
            summary = generate_global_summary(reports)
            summary_file = output_dir / "global_graph_test_summary.json"
            with open(summary_file, 'w') as f:
                json.dump(summary, f, indent=2)
            
            print(f"\nGlobal Summary:")
            print(f"  Total services: {summary['total_services']}")
            print(f"  Total operations: {summary['total_operations']}")
            print(f"  Global satisfiable: {summary['global_satisfiable_percent']:.2f}%")
            print(f"  Summary written to {summary_file}")
    
    elapsed = time.time() - start_time
    print(f"\nCompleted in {elapsed:.2f} seconds")

if __name__ == "__main__":
    main()

