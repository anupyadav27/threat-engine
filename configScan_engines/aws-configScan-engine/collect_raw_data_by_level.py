#!/usr/bin/env python3
"""
Collect raw data from all discoveries in dependency order.
Organizes by level: Independent (level 0) → 1st level dependent → 2nd level → etc.
"""

import json
import os
import sys
from datetime import datetime
from typing import Dict, List, Any, Set
from collections import defaultdict

# Add engine to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine.service_scanner import (
    load_service_rules,
    _build_dependency_graph,
    run_global_service,
    run_regional_service
)
from auth.aws_auth import get_boto3_session
from engine.discovery_helper import get_boto3_client_name

def organize_discoveries_by_level(dependency_graph: Dict[str, Any]) -> Dict[int, List[str]]:
    """
    Organize discoveries by dependency level.
    Level 0: Independent discoveries
    Level 1: Dependents of level 0
    Level 2: Dependents of level 1
    etc.
    """
    dependency_map = dependency_graph.get('dependency_map', {})
    discovery_by_id = dependency_graph.get('discovery_by_id', {})
    
    # Find all discovery IDs
    all_discovery_ids = set(discovery_by_id.keys())
    
    # Level 0: Independent discoveries
    level_0 = [disc['discovery_id'] for disc in dependency_graph.get('independent', [])]
    
    # Build level map
    level_map = {}
    for disc_id in level_0:
        level_map[disc_id] = 0
    
    # Recursively assign levels
    def assign_level(discovery_id: str, visited: Set[str] = None) -> int:
        if visited is None:
            visited = set()
        if discovery_id in visited:
            return level_map.get(discovery_id, 999)  # Circular dependency
        
        visited.add(discovery_id)
        
        if discovery_id in level_map:
            return level_map[discovery_id]
        
        depends_on = dependency_map.get(discovery_id)
        if not depends_on:
            level_map[discovery_id] = 0
            return 0
        
        parent_level = assign_level(depends_on, visited)
        my_level = parent_level + 1
        level_map[discovery_id] = my_level
        return my_level
    
    # Assign levels to all discoveries
    for disc_id in all_discovery_ids:
        if disc_id not in level_map:
            assign_level(disc_id)
    
    # Organize by level
    by_level = defaultdict(list)
    for disc_id, level in level_map.items():
        by_level[level].append(disc_id)
    
    return dict(by_level)

def collect_raw_data_by_level(service_name: str, scope: str = 'global', region: str = None):
    """
    Collect raw data from all discoveries organized by dependency level.
    """
    print(f"\n{'='*80}")
    print(f"Collecting raw data for {service_name} ({scope})")
    print(f"{'='*80}\n")
    
    # Load service rules
    service_rules = load_service_rules(service_name)
    all_discoveries = service_rules.get('discovery', [])
    
    # Build dependency graph
    dependency_graph = _build_dependency_graph(all_discoveries)
    
    # Organize by level
    by_level = organize_discoveries_by_level(dependency_graph)
    
    print("Dependency Structure:")
    print("-" * 80)
    for level in sorted(by_level.keys()):
        disc_ids = by_level[level]
        print(f"Level {level}: {len(disc_ids)} discoveries")
        for disc_id in disc_ids:
            depends_on = dependency_graph.get('dependency_map', {}).get(disc_id)
            if depends_on:
                print(f"  - {disc_id} (depends on: {depends_on})")
            else:
                print(f"  - {disc_id} (independent)")
    print()
    
    # Run the actual service scan to get raw data
    print("Running service scan to collect raw data...")
    print("NOTE: This will run ALL discoveries including dependent ones (for_each loops)")
    print("      For S3 with 21 buckets, this may take 1-2 minutes due to many API calls...")
    print("      SKIPPING CHECKS - only collecting discovery data")
    print()
    
    import time
    import os
    start_time = time.time()
    
    # Set environment variable to skip checks (more reliable than modifying service_rules)
    original_check_workers = os.environ.get('MAX_CHECK_WORKERS')
    os.environ['MAX_CHECK_WORKERS'] = '0'  # This will make checks skip
    
    # Also modify service_rules directly
    original_checks = service_rules.get('checks', [])
    service_rules['checks'] = []  # Skip checks - we only need discovery data
    
    try:
        if scope == 'global':
            result = run_global_service(service_name)
        else:
            result = run_regional_service(service_name, region or 'us-east-1')
    finally:
        # Restore original checks
        service_rules['checks'] = original_checks
        if original_check_workers:
            os.environ['MAX_CHECK_WORKERS'] = original_check_workers
        elif 'MAX_CHECK_WORKERS' in os.environ:
            del os.environ['MAX_CHECK_WORKERS']
    
    elapsed = time.time() - start_time
    print(f"\n✅ Service scan completed in {elapsed:.1f} seconds (discovery only, no checks)")
    
    if not result:
        print("ERROR: Service scan returned no results")
        return None
    
    # Debug: Check what result contains
    print(f"\n[DEBUG] Result keys: {list(result.keys())}")
    print(f"[DEBUG] Result has 'inventory': {'inventory' in result}")
    print(f"[DEBUG] Result has '_raw_data': {'_raw_data' in result}")
    
    # Get raw data and discovery results
    raw_data = result.get('_raw_data', {})
    discovery_results = result.get('inventory', {})
    
    print(f"[DEBUG] raw_data type: {type(raw_data)}, keys: {list(raw_data.keys())[:5] if isinstance(raw_data, dict) else 'N/A'}")
    print(f"[DEBUG] discovery_results type: {type(discovery_results)}, keys: {list(discovery_results.keys())[:5] if isinstance(discovery_results, dict) else 'N/A'}")
    
    if discovery_results:
        print(f"[DEBUG] Sample discovery_results entry: {list(discovery_results.items())[0] if discovery_results else 'N/A'}")
    
    # Organize raw data by level
    organized_data = {
        'service': service_name,
        'scope': scope,
        'region': region,
        'timestamp': datetime.now().isoformat(),
        'dependency_structure': {
            level: {
                'discoveries': disc_ids,
                'count': len(disc_ids)
            }
            for level, disc_ids in by_level.items()
        },
        'raw_data_by_level': {}
    }
    
    # Organize discovery results by level
    organized_data['discovery_results_by_level'] = {}
    
    for level in sorted(by_level.keys()):
        level_disc_ids = by_level[level]
        level_raw_data = {}
        level_discovery_results = {}
        
        for disc_id in level_disc_ids:
            # Get raw data for this discovery
            if disc_id in raw_data:
                level_raw_data[disc_id] = raw_data[disc_id]
            
            # Get discovery results (emitted items) for this discovery
            if disc_id in discovery_results:
                level_discovery_results[disc_id] = discovery_results[disc_id]
        
        organized_data['raw_data_by_level'][f'level_{level}'] = level_raw_data
        organized_data['discovery_results_by_level'][f'level_{level}'] = level_discovery_results
    
    # Also include full raw data and discovery results for reference
    organized_data['full_raw_data'] = raw_data
    organized_data['full_discovery_results'] = discovery_results
    
    # Save to file
    output_dir = 'engines-output/aws-configScan-engine/raw_data_analysis'
    os.makedirs(output_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{service_name}_{scope}_{timestamp}_raw_data.json"
    filepath = os.path.join(output_dir, filename)
    
    # Convert to JSON-serializable format
    def make_serializable(obj):
        if isinstance(obj, dict):
            return {k: make_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [make_serializable(item) for item in obj]
        elif isinstance(obj, (str, int, float, bool, type(None))):
            return obj
        else:
            return str(obj)
    
    serializable_data = make_serializable(organized_data)
    
    with open(filepath, 'w') as f:
        json.dump(serializable_data, f, indent=2, default=str)
    
    print(f"\n✅ Raw data collected and saved to: {filepath}")
    print(f"\nSummary:")
    print(f"  - Total discoveries: {len(all_discoveries)}")
    print(f"  - Levels: {len(by_level)}")
    for level in sorted(by_level.keys()):
        print(f"  - Level {level}: {len(by_level[level])} discoveries")
    
    # Print sample data structure
    print(f"\n📊 Sample Data Structure:")
    if organized_data['discovery_results_by_level'].get('level_0'):
        level_0_results = organized_data['discovery_results_by_level']['level_0']
        if level_0_results:
            first_disc_id = list(level_0_results.keys())[0]
            first_items = level_0_results[first_disc_id]
            if first_items:
                print(f"  Level 0 ({first_disc_id}): {len(first_items)} items")
                print(f"    Sample item keys: {list(first_items[0].keys())[:10]}")
                print(f"    Sample item (first 3 fields): {dict(list(first_items[0].items())[:3])}")
    
    if organized_data['discovery_results_by_level'].get('level_1'):
        level_1_results = organized_data['discovery_results_by_level']['level_1']
        if level_1_results:
            first_disc_id = list(level_1_results.keys())[0]
            first_items = level_1_results[first_disc_id]
            if first_items:
                print(f"  Level 1 ({first_disc_id}): {len(first_items)} items")
                print(f"    Sample item keys: {list(first_items[0].keys())[:10]}")
                print(f"    Sample item (first 3 fields): {dict(list(first_items[0].items())[:3])}")
    
    return filepath

if __name__ == '__main__':
    # Test with S3
    service_name = 's3'
    scope = 'global'
    
    print("Collecting raw data for S3 service...")
    filepath = collect_raw_data_by_level(service_name, scope)
    
    if filepath:
        print(f"\n✅ Success! Check the file: {filepath}")
        print(f"\nYou can now analyze the raw data to understand:")
        print(f"  1. How independent discoveries structure their data")
        print(f"  2. How dependent discoveries link to independent (matching keys)")
        print(f"  3. Multi-level dependency chains")
        print(f"  4. How to properly enrich data across levels")

