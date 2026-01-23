#!/usr/bin/env python3
"""
Collect RAW discovery outputs (before enrichment) from services using nested YAML
This script collects pure API responses without any filtering or enrichment
"""
import os
import sys
import json
import yaml
from datetime import datetime
from pathlib import Path

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from auth.aws_auth import get_boto3_session
from engine.service_scanner import load_service_rules

def load_nested_yaml(service_name: str):
    """Load nested YAML file instead of regular one"""
    config_dir = os.path.join(os.path.dirname(__file__), "services", service_name, "rules")
    nested_file = os.path.join(config_dir, f"{service_name}.nested.yaml")
    
    if os.path.exists(nested_file):
        with open(nested_file, 'r') as f:
            return yaml.safe_load(f)
    else:
        # Fallback to regular file
        return load_service_rules(service_name)

def get_service_scope(service_name: str) -> str:
    """Determine if service is global or regional"""
    global_services = ['iam', 'organizations', 'budgets', 'ce', 'artifact', 
                      'trustedadvisor', 'wellarchitected', 'tag', 'route53',
                      'cloudfront', 'accessanalyzer', 'account']
    return 'global' if service_name in global_services else 'regional'

def collect_raw_discoveries(service_name: str = "s3", region: str = None):
    """Run service scan and collect RAW discovery outputs (no enrichment)"""
    print("=" * 80)
    print(f"Collecting RAW Discovery Outputs for {service_name}")
    print("=" * 80)
    print()
    
    # Load nested YAML
    print(f"Loading nested YAML for {service_name}...")
    service_rules = load_nested_yaml(service_name)
    
    if not service_rules:
        print(f"Error: Could not load service rules for {service_name}")
        return None
    
    discoveries = service_rules.get('discovery', [])
    print(f"Found {len(discoveries)} discoveries")
    print()
    
    # Get AWS session
    print("Getting AWS session...")
    session = get_boto3_session()
    account_id = session.client('sts').get_caller_identity()['Account']
    print(f"Account ID: {account_id}")
    
    # Determine service scope
    scope = get_service_scope(service_name)
    if not region and scope == 'regional':
        # Default to us-east-1 for regional services
        region = 'us-east-1'
    print(f"Scope: {scope}" + (f" (region: {region})" if region else ""))
    print()
    
    # Import and run the discovery phase ONLY (no enrichment, no checks)
    print("Running discoveries (RAW mode - no enrichment)...")
    print("-" * 80)
    
    try:
        # Import the necessary functions from service_scanner
        from engine.service_scanner import (
            get_boto3_client_name, BOTO_CONFIG, _build_dependency_graph,
            _run_single_discovery, _retry_call, resolve_template, extract_value,
            auto_emit_arn_and_name, _filter_aws_managed_resources
        )
        from concurrent.futures import ThreadPoolExecutor, as_completed
        from threading import Lock
        import boto3
        import logging
        
        logger = logging.getLogger('compliance-boto3')
        
        # Get boto3 client
        boto3_client_name = get_boto3_client_name(service_name)
        client = session.client(boto3_client_name, region_name=region, config=BOTO_CONFIG)
        
        discovery_results = {}
        saved_data = {}
        
        # Build dependency graph for parallel processing
        all_discoveries = service_rules.get('discovery', [])
        dependency_graph = _build_dependency_graph(all_discoveries)
        independent_discoveries = dependency_graph['independent']
        dependent_groups = dependency_graph['dependent_groups']
        
        # Thread-safe locks
        saved_data_lock = Lock()
        discovery_results_lock = Lock()
        
        # Run independent discoveries first
        max_discovery_workers = 50
        if independent_discoveries:
            logger.info(f"Processing {len(independent_discoveries)} independent discoveries in parallel (max {max_discovery_workers} workers)")
            
            with ThreadPoolExecutor(max_workers=min(len(independent_discoveries), max_discovery_workers)) as executor:
                futures = {}
                for discovery in independent_discoveries:
                    future = executor.submit(
                        _run_single_discovery,
                        discovery, service_name, client, None, None,
                        saved_data, saved_data_lock, discovery_results,
                        discovery_results_lock, account_id, region, session
                    )
                    futures[future] = discovery.get('discovery_id')
                
                for future in as_completed(futures):
                    discovery_id = futures[future]
                    try:
                        future.result()
                    except Exception as e:
                        logger.error(f"Discovery {discovery_id} failed: {e}")
        
        # Run dependent discoveries sequentially (in dependency order)
        for level, dependent_discs in sorted(dependent_groups.items()):
            logger.info(f"Processing {len(dependent_discs)} dependent discoveries at level {level}")
            for discovery in dependent_discs:
                try:
                    _run_single_discovery(
                        discovery, service_name, client, None, None,
                        saved_data, saved_data_lock, discovery_results,
                        discovery_results_lock, account_id, region, session
                    )
                except Exception as e:
                    logger.error(f"Discovery {discovery.get('discovery_id')} failed: {e}")
        
        print()
        print("=" * 80)
        print("RAW Discovery Results Summary")
        print("=" * 80)
        
        for discovery_id, items in discovery_results.items():
            count = len(items) if isinstance(items, list) else 1
            print(f"  {discovery_id}: {count} item(s)")
            
            # Show a sample of what we collected
            if items and isinstance(items, list) and len(items) > 0:
                sample = items[0]
                if isinstance(sample, dict):
                    fields = list(sample.keys())
                    print(f"    Sample fields: {fields[:10]}{'...' if len(fields) > 10 else ''}")
        
        # Save to disk
        output_dir = Path("output/discovery_collection")
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save individual discovery files
        individual_dir = output_dir / f"{service_name}_RAW_{timestamp}_individual"
        individual_dir.mkdir(parents=True, exist_ok=True)
        
        for discovery_id, items in discovery_results.items():
            safe_name = discovery_id.replace('.', '_').replace('/', '_')
            individual_file = individual_dir / f"{safe_name}.json"
            
            with open(individual_file, 'w') as f:
                json.dump({
                    "discovery_id": discovery_id,
                    "item_count": len(items) if isinstance(items, list) else 1,
                    "items": items
                }, f, indent=2, default=str)
        
        print()
        print("=" * 80)
        print("Output Saved")
        print("=" * 80)
        print(f"Directory: {individual_dir}")
        print(f"Total discoveries: {len(discovery_results)}")
        print(f"Total items: {sum(len(v) if isinstance(v, list) else 1 for v in discovery_results.values())}")
        print()
        
        return discovery_results
        
    except Exception as e:
        import traceback
        print(f"Error running service scan: {e}")
        print(traceback.format_exc())
        return None

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Collect RAW discovery outputs (no enrichment)')
    parser.add_argument('service', help='Service name to collect (e.g., s3, ec2, iam)')
    parser.add_argument('--region', help='Region for regional services (default: us-east-1)')
    
    args = parser.parse_args()
    
    result = collect_raw_discoveries(args.service, region=args.region)
    if result:
        print(f"✓ {args.service} RAW collection complete!")
        sys.exit(0)
    else:
        print(f"✗ {args.service} RAW collection failed!")
        sys.exit(1)

