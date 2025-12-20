#!/usr/bin/env python3
"""
Finalize a single AWS service by merging AI suggestions and regenerating final artifacts.

This script:
1. Loads source spec and existing overrides
2. Merges suggestions from fixes_applied.json and manual_review.json
3. Applies confidence-based filtering
4. Regenerates operation_registry.json, adjacency.json, validation_report.json, manual_review.json
5. Cleans up intermediate files
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple
from collections import defaultdict
import shutil
from datetime import datetime

# Add parent directory to path to import from tools
sys.path.insert(0, str(Path(__file__).parent.parent / "pythonsdk-database" / "aws" / "tools"))

try:
    from build_dependency_graph import (
        process_service_spec,
        build_adjacency,
        validate_service,
        generate_manual_review
    )
except ImportError:
    # Fallback: define minimal versions if import fails
    def process_service_spec(spec_file: Path) -> Dict[str, Any]:
        """Minimal implementation - should be replaced with actual import"""
        raise NotImplementedError("Need to import from build_dependency_graph.py")
    
    def build_adjacency(registry: Dict[str, Any]) -> Dict[str, Any]:
        """Minimal implementation"""
        raise NotImplementedError("Need to import from build_dependency_graph.py")
    
    def validate_service(registry: Dict[str, Any], adjacency: Dict[str, Any]) -> Dict[str, Any]:
        """Minimal implementation"""
        raise NotImplementedError("Need to import from build_dependency_graph.py")
    
    def generate_manual_review(registry: Dict[str, Any], validation_report: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Minimal implementation"""
        raise NotImplementedError("Need to import from build_dependency_graph.py")


CONFIDENCE_THRESHOLDS = {
    'HIGH': 0.90,
    'MEDIUM': 0.80,
    'LOW': 0.70
}


def load_json_file(file_path: Path) -> Optional[Dict[str, Any]]:
    """Load JSON file, return None if not found."""
    if not file_path.exists():
        return None
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"  ⚠️  Error loading {file_path.name}: {e}")
        return None


def save_json_file(file_path: Path, data: Any, backup: bool = True) -> bool:
    """Save JSON file with optional backup."""
    try:
        if backup and file_path.exists():
            backup_path = file_path.with_suffix(file_path.suffix + '.bak')
            shutil.copy2(file_path, backup_path)
        
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2, sort_keys=True)
        return True
    except Exception as e:
        print(f"  ❌ Error saving {file_path.name}: {e}")
        return False


def load_or_create_overrides(service_path: Path, service_name: str) -> Dict[str, Any]:
    """Load existing overrides.json or create empty structure."""
    overrides_file = service_path / "overrides.json"
    
    if overrides_file.exists():
        overrides = load_json_file(overrides_file)
        if overrides:
            return overrides
    
    # Create empty structure
    return {
        "service": service_name,
        "entity_aliases": {},
        "overrides": {
            "param_aliases": {},
            "consumes": {},
            "produces": {}
        }
    }


def is_structured_evidence(evidence: str) -> bool:
    """Check if evidence is structured (contains List/Get/Describe and key has Id/Arn/Name)."""
    if not evidence:
        return False
    
    # Check for operation prefixes
    has_operation = any(prefix in evidence for prefix in ['List', 'Get', 'Describe', 'Search', 'Lookup'])
    
    # Check for common entity identifiers
    has_identifier = any(key in evidence for key in ['Id', 'Arn', 'Name', 'Key', 'Tag'])
    
    return has_operation and has_identifier


def merge_entity_aliases(
    target: Dict[str, str],
    source: Dict[str, str],
    conflicts: List[str]
) -> int:
    """Merge entity aliases, tracking conflicts. Returns count of merged items."""
    merged_count = 0
    
    for alias, canonical in source.items():
        if alias in target:
            if target[alias] != canonical:
                conflicts.append(f"Entity alias conflict: {alias} -> {target[alias]} vs {canonical}")
            # Keep existing (don't overwrite)
        else:
            target[alias] = canonical
            merged_count += 1
    
    return merged_count


def merge_param_aliases(
    target: Dict[str, List[str]],
    source: Dict[str, List[str]],
    conflicts: List[str]
) -> int:
    """Merge param aliases, tracking conflicts. Returns count of merged items."""
    merged_count = 0
    
    for param, candidates in source.items():
        if param in target:
            # Merge candidate lists
            existing = set(target[param])
            new_candidates = set(candidates)
            if existing != new_candidates:
                # Union of candidates
                target[param] = sorted(list(existing | new_candidates))
                merged_count += 1
        else:
            target[param] = sorted(candidates)
            merged_count += 1
    
    return merged_count


def get_confidence_level(confidence: float) -> str:
    """Get confidence level from numeric value."""
    if confidence >= CONFIDENCE_THRESHOLDS['HIGH']:
        return 'HIGH'
    elif confidence >= CONFIDENCE_THRESHOLDS['MEDIUM']:
        return 'MEDIUM'
    else:
        return 'LOW'


def merge_fixes_applied(
    overrides: Dict[str, Any],
    fixes_applied: Dict[str, Any],
    accepted: List[Dict[str, Any]],
    rejected: List[Dict[str, Any]]
) -> Tuple[int, List[str]]:
    """Merge suggestions from fixes_applied.json. Returns (merged_count, conflicts)."""
    merged_count = 0
    conflicts = []
    
    fixes = fixes_applied.get('fixes', [])
    if not fixes:
        return 0, []
    
    for fix in fixes:
        confidence = fix.get('confidence', 0.0)
        confidence_level = get_confidence_level(confidence)
        suggested_aliases = fix.get('suggested_aliases', {})
        
        # Always accept HIGH confidence
        if confidence_level == 'HIGH':
            # Merge entity aliases
            entity_aliases = suggested_aliases.get('entity_aliases', {})
            if entity_aliases:
                count = merge_entity_aliases(
                    overrides['entity_aliases'],
                    entity_aliases,
                    conflicts
                )
                merged_count += count
            
            # Merge param aliases
            param_aliases = suggested_aliases.get('param_aliases', {})
            if param_aliases:
                count = merge_param_aliases(
                    overrides['overrides']['param_aliases'],
                    param_aliases,
                    conflicts
                )
                merged_count += count
            
            accepted.append({
                'source': 'fixes_applied',
                'rule_id': fix.get('rule_id', 'unknown'),
                'confidence': confidence,
                'confidence_level': confidence_level,
                'type': 'auto_accepted_high'
            })
        
        # MEDIUM confidence: accept only if it reduces issues (check later)
        elif confidence_level == 'MEDIUM':
            # Store for conditional acceptance
            accepted.append({
                'source': 'fixes_applied',
                'rule_id': fix.get('rule_id', 'unknown'),
                'confidence': confidence,
                'confidence_level': confidence_level,
                'type': 'conditional_medium',
                'suggested_aliases': suggested_aliases
            })
        
        # LOW confidence: reject
        else:
            rejected.append({
                'source': 'fixes_applied',
                'rule_id': fix.get('rule_id', 'unknown'),
                'confidence': confidence,
                'confidence_level': confidence_level,
                'reason': 'Below threshold'
            })
    
    return merged_count, conflicts


def merge_manual_review(
    overrides: Dict[str, Any],
    manual_review: Dict[str, Any],
    accepted: List[Dict[str, Any]],
    rejected: List[Dict[str, Any]]
) -> Tuple[int, List[str]]:
    """Merge suggestions from manual_review.json. Returns (merged_count, conflicts)."""
    merged_count = 0
    conflicts = []
    
    # Merge suggested_overrides if present
    suggested_overrides = manual_review.get('suggested_overrides', [])
    if suggested_overrides:
        for override in suggested_overrides:
            # This would need to be merged into overrides.overrides.produces/consumes
            # For now, just track it
            accepted.append({
                'source': 'manual_review',
                'type': 'suggested_override',
                'override': override
            })
    
    # Process unresolved_items with structured evidence
    issues = manual_review.get('issues', {})
    ambiguous_tokens = issues.get('ambiguous_tokens', {})
    
    for token, mappings in ambiguous_tokens.items():
        for mapping in mappings:
            evidence = mapping.get('evidence', '')
            entity = mapping.get('entity', '')
            
            if is_structured_evidence(evidence):
                # Extract param from evidence (e.g., "ListBuckets.Buckets[].Name" -> "Name")
                parts = evidence.split('.')
                if len(parts) > 0:
                    param = parts[-1]
                    
                    # Add to param_aliases
                    if param not in overrides['overrides']['param_aliases']:
                        overrides['overrides']['param_aliases'][param] = []
                    
                    if evidence not in overrides['overrides']['param_aliases'][param]:
                        overrides['overrides']['param_aliases'][param].append(evidence)
                        merged_count += 1
                    
                    accepted.append({
                        'source': 'manual_review',
                        'type': 'structured_evidence',
                        'evidence': evidence,
                        'entity': entity,
                        'param': param
                    })
    
    return merged_count, conflicts


def evaluate_medium_confidence_suggestions(
    overrides: Dict[str, Any],
    accepted: List[Dict[str, Any]],
    rejected: List[Dict[str, Any]],
    validation_before: Optional[Dict[str, Any]],
    validation_after: Optional[Dict[str, Any]]
) -> int:
    """Evaluate MEDIUM confidence suggestions based on validation improvement."""
    if not validation_before or not validation_after:
        # Can't evaluate, reject all MEDIUM
        medium_items = [a for a in accepted if a.get('confidence_level') == 'MEDIUM']
        for item in medium_items:
            accepted.remove(item)
            rejected.append({
                **item,
                'reason': 'Cannot evaluate - no validation comparison'
            })
        return 0
    
    # Compare validation metrics
    before_issues = (
        sum(len(v) if isinstance(v, (list, dict)) else 0 
            for v in validation_before.get('generic_entities_found', {}).values()) +
        len(validation_before.get('ambiguous_tokens_found', {}))
    )
    
    after_issues = (
        sum(len(v) if isinstance(v, (list, dict)) else 0 
            for v in validation_after.get('generic_entities_found', {}).values()) +
        len(validation_after.get('ambiguous_tokens_found', {}))
    )
    
    # If issues reduced, accept MEDIUM suggestions
    if after_issues < before_issues:
        medium_items = [a for a in accepted if a.get('confidence_level') == 'MEDIUM']
        for item in medium_items:
            suggested_aliases = item.get('suggested_aliases', {})
            
            # Apply the suggestions
            entity_aliases = suggested_aliases.get('entity_aliases', {})
            if entity_aliases:
                merge_entity_aliases(overrides['entity_aliases'], entity_aliases, [])
            
            param_aliases = suggested_aliases.get('param_aliases', {})
            if param_aliases:
                merge_param_aliases(overrides['overrides']['param_aliases'], param_aliases, [])
            
            item['type'] = 'accepted_medium_improves'
            item['issues_reduced'] = before_issues - after_issues
        
        return len(medium_items)
    else:
        # Reject MEDIUM suggestions
        medium_items = [a for a in accepted if a.get('confidence_level') == 'MEDIUM']
        for item in medium_items:
            accepted.remove(item)
            rejected.append({
                **item,
                'reason': f'Does not reduce issues (before: {before_issues}, after: {after_issues})'
            })
        return 0


def find_source_spec(service_path: Path, service_name: str) -> Optional[Path]:
    """Find source spec JSON file."""
    # Try common patterns
    patterns = [
        f"boto3_dependencies_with_python_names_fully_enriched.json",
        f"{service_name}_dependencies_with_python_names_fully_enriched.json",
        f"{service_name}_spec.json"
    ]
    
    for pattern in patterns:
        spec_file = service_path / pattern
        if spec_file.exists():
            return spec_file
    
    return None


def finalize_service(service_path: Path) -> Dict[str, Any]:
    """
    Finalize a single service by merging suggestions and regenerating artifacts.
    
    Returns result dictionary with status and statistics.
    """
    service_name = service_path.name
    result = {
        'service': service_name,
        'status': 'unknown',
        'merged_aliases': 0,
        'merged_params': 0,
        'conflicts': [],
        'accepted_suggestions': 0,
        'rejected_suggestions': 0,
        'errors': []
    }
    
    print(f"\n{'='*70}")
    print(f"Finalizing service: {service_name}")
    print(f"{'='*70}")
    
    try:
        # Step 1: Load source spec
        source_spec = find_source_spec(service_path, service_name)
        if not source_spec:
            result['status'] = 'error'
            result['errors'].append('Source spec JSON not found')
            print(f"  ❌ Source spec not found")
            return result
        
        print(f"  ✓ Source spec: {source_spec.name}")
        
        # Step 2: Load or create overrides
        overrides = load_or_create_overrides(service_path, service_name)
        print(f"  ✓ Overrides loaded/created")
        
        # Step 3: Load fixes_applied.json and manual_review.json
        fixes_applied = load_json_file(service_path / "fixes_applied.json")
        manual_review = load_json_file(service_path / "manual_review.json")
        
        accepted_suggestions = []
        rejected_suggestions = []
        all_conflicts = []
        
        # Step 4: Merge AI suggestions
        if fixes_applied:
            print(f"  📝 Merging fixes_applied.json...")
            merged_count, conflicts = merge_fixes_applied(
                overrides, fixes_applied, accepted_suggestions, rejected_suggestions
            )
            result['merged_aliases'] += merged_count
            all_conflicts.extend(conflicts)
            print(f"     Merged {merged_count} items, {len(conflicts)} conflicts")
        
        if manual_review:
            print(f"  📝 Merging manual_review.json...")
            merged_count, conflicts = merge_manual_review(
                overrides, manual_review, accepted_suggestions, rejected_suggestions
            )
            result['merged_params'] += merged_count
            all_conflicts.extend(conflicts)
            print(f"     Merged {merged_count} items, {len(conflicts)} conflicts")
        
        result['conflicts'] = all_conflicts
        
        # Step 5: Save overrides.json
        if not save_json_file(service_path / "overrides.json", overrides):
            result['status'] = 'error'
            result['errors'].append('Failed to save overrides.json')
            return result
        print(f"  ✓ Saved overrides.json")
        
        # Step 6: Regenerate final artifacts
        print(f"  🔄 Regenerating artifacts...")
        
        # Load validation before (for MEDIUM evaluation)
        validation_before = load_json_file(service_path / "validation_report.json")
        
        # Regenerate operation_registry.json using source spec + overrides
        try:
            # Load existing operation_registry.json if it exists, otherwise generate from source
            existing_registry = load_json_file(service_path / "operation_registry.json")
            
            if existing_registry:
                # Apply overrides to existing registry
                registry = existing_registry.copy()
                
                # Merge entity_aliases
                if 'entity_aliases' in overrides:
                    registry.setdefault('entity_aliases', {}).update(overrides['entity_aliases'])
                
                # Apply operation-level overrides
                if 'overrides' in overrides and overrides['overrides']:
                    # Apply consumes/produces overrides if present
                    if 'consumes' in overrides['overrides']:
                        for op_name, consumes_override in overrides['overrides']['consumes'].items():
                            if op_name in registry.get('operations', {}):
                                registry['operations'][op_name]['consumes'] = consumes_override
                    
                    if 'produces' in overrides['overrides']:
                        for op_name, produces_override in overrides['overrides']['produces'].items():
                            if op_name in registry.get('operations', {}):
                                registry['operations'][op_name]['produces'] = produces_override
            else:
                # Generate from source spec
                registry = process_service_spec(source_spec)
                
                # Apply overrides
                if 'entity_aliases' in overrides:
                    registry['entity_aliases'].update(overrides['entity_aliases'])
                
                if 'overrides' in overrides and overrides['overrides']:
                    if 'consumes' in overrides['overrides']:
                        for op_name, consumes_override in overrides['overrides']['consumes'].items():
                            if op_name in registry.get('operations', {}):
                                registry['operations'][op_name]['consumes'] = consumes_override
                    
                    if 'produces' in overrides['overrides']:
                        for op_name, produces_override in overrides['overrides']['produces'].items():
                            if op_name in registry.get('operations', {}):
                                registry['operations'][op_name]['produces'] = produces_override
            
            # Save operation_registry.json
            save_json_file(service_path / "operation_registry.json", registry)
            print(f"     ✓ Regenerated operation_registry.json")
            
            # Generate adjacency.json
            adjacency = build_adjacency(registry)
            save_json_file(service_path / "adjacency.json", adjacency)
            print(f"     ✓ Regenerated adjacency.json")
            
            # Generate validation_report.json
            validation_after = validate_service(registry, adjacency)
            save_json_file(service_path / "validation_report.json", validation_after)
            print(f"     ✓ Regenerated validation_report.json")
            
            # Generate manual_review.json (only remaining issues)
            manual_review_new = generate_manual_review(registry, validation_after)
            if manual_review_new:
                save_json_file(service_path / "manual_review.json", manual_review_new)
                print(f"     ✓ Regenerated manual_review.json")
            else:
                # No manual review needed
                mr_file = service_path / "manual_review.json"
                if mr_file.exists():
                    mr_file.unlink()
                print(f"     ✓ No manual_review.json needed")
        
        except Exception as e:
            print(f"     ⚠️  Warning: Could not regenerate artifacts: {e}")
            print(f"     Continuing with existing files...")
            import traceback
            traceback.print_exc()
            validation_after = validation_before
        
        # Step 7: Evaluate MEDIUM confidence suggestions
        validation_after = validation_after or load_json_file(service_path / "validation_report.json")
        medium_accepted = evaluate_medium_confidence_suggestions(
            overrides, accepted_suggestions, rejected_suggestions,
            validation_before, validation_after
        )
        
        result['accepted_suggestions'] = len([a for a in accepted_suggestions if a.get('type', '').startswith('accepted')])
        result['rejected_suggestions'] = len(rejected_suggestions)
        
        # Step 8: Save audit files
        if accepted_suggestions:
            save_json_file(service_path / "accepted_suggestions.json", accepted_suggestions, backup=False)
        if rejected_suggestions:
            save_json_file(service_path / "rejected_suggestions.json", rejected_suggestions, backup=False)
        
        # Step 9: Cleanup (only if successful)
        if result['status'] != 'error':
            fixes_file = service_path / "fixes_applied.json"
            if fixes_file.exists():
                # Keep backup, delete original
                backup_file = fixes_file.with_suffix('.bak')
                if not backup_file.exists():
                    shutil.copy2(fixes_file, backup_file)
                fixes_file.unlink()
                print(f"  🗑️  Cleaned up fixes_applied.json")
        
        result['status'] = 'success'
        print(f"  ✅ Finalization complete")
        
        # Save result for batch processing
        save_json_file(service_path / "finalize_result.json", result, backup=False)
        
    except Exception as e:
        result['status'] = 'error'
        result['errors'].append(str(e))
        print(f"  ❌ Error: {e}")
        import traceback
        traceback.print_exc()
    
    return result


def main():
    """CLI entry point."""
    if len(sys.argv) < 2:
        print("Usage: finalize_service.py <service_path>")
        print("Example: finalize_service.py pythonsdk-database/aws/s3")
        sys.exit(1)
    
    service_path = Path(sys.argv[1])
    if not service_path.exists():
        print(f"Error: Service path not found: {service_path}")
        sys.exit(1)
    
    result = finalize_service(service_path)
    
    # Print summary
    print(f"\n{'='*70}")
    print(f"Summary for {result['service']}:")
    print(f"  Status: {result['status']}")
    print(f"  Merged aliases: {result['merged_aliases']}")
    print(f"  Merged params: {result['merged_params']}")
    print(f"  Accepted suggestions: {result['accepted_suggestions']}")
    print(f"  Rejected suggestions: {result['rejected_suggestions']}")
    print(f"  Conflicts: {len(result['conflicts'])}")
    if result['errors']:
        print(f"  Errors: {len(result['errors'])}")
        for error in result['errors']:
            print(f"    - {error}")
    print(f"{'='*70}\n")
    
    sys.exit(0 if result['status'] == 'success' else 1)


if __name__ == '__main__':
    main()

