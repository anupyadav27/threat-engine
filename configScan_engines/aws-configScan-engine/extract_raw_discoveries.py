#!/usr/bin/env python3
"""
Simple script to extract RAW JSON from all discoveries
No enrichment, no filtering - just pure API responses
"""
import os
import sys
import json
import yaml
from datetime import datetime
from pathlib import Path
from threading import Lock
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from auth.aws_auth import get_boto3_session
from engine.service_scanner import (
    load_service_rules, get_boto3_client_name, BOTO_CONFIG,
    _build_dependency_graph, _retry_call, resolve_template, extract_value,
    auto_emit_arn_and_name, _filter_aws_managed_resources
)
import logging

logger = logging.getLogger('compliance-boto3')

def extract_items_from_response(response, items_for_path):
    """
    Generic function to extract items from API response.
    Works for all services - path comes from YAML.
    
    Args:
        response: The API response dict
        items_for_path: Path from YAML like '{{ response.Buckets }}'
    
    Returns:
        List of items (or empty list)
    """
    # Parse path: '{{ response.Buckets }}' → 'Buckets'
    path = items_for_path.replace('{{ ', '').replace(' }}', '').strip()
    
    # Remove 'response.' prefix if present (we're passing response directly)
    if path.startswith('response.'):
        path = path.replace('response.', '', 1)
    
    # For simple single-key paths, use direct access (faster, more reliable)
    if '.' not in path and '[' not in path:
        # Simple path like 'Buckets', 'analyzers', 'accessPreview'
        items = response.get(path, []) if isinstance(response, dict) else []
        # Ensure we return a list
        if items is None:
            return []
        return items if isinstance(items, list) else [items]
    
    # For complex paths, use extract_value
    items = extract_value(response, path)
    if items is None:
        return []
    return items if isinstance(items, list) else [items]

def load_nested_yaml(service_name: str):
    """Load nested YAML file"""
    config_dir = os.path.join(os.path.dirname(__file__), "services", service_name, "rules")
    nested_file = os.path.join(config_dir, f"{service_name}.nested.yaml")
    
    if os.path.exists(nested_file):
        with open(nested_file, 'r') as f:
            return yaml.safe_load(f)
    else:
        return load_service_rules(service_name)

def get_service_scope(service_name: str) -> str:
    """Determine if service is global or regional"""
    global_services = ['iam', 'organizations', 'budgets', 'ce', 'artifact', 
                      'trustedadvisor', 'wellarchitected', 'tag', 'route53',
                      'cloudfront', 'accessanalyzer', 'account']
    return 'global' if service_name in global_services else 'regional'

def run_single_discovery_raw(discovery, service_name, client, saved_data, saved_data_lock, 
                             discovery_results, discovery_results_lock, account_id, region, session):
    """Run a single discovery and store RAW results"""
    discovery_id = discovery.get('discovery_id')
    if not discovery_id:
        return
    
    logger.info(f"Processing discovery: {discovery_id}")
    
    calls = discovery.get('calls', [])
    if not calls:
        return
    
    # Check if this is a dependent discovery (has for_each)
    for_each = discovery.get('for_each')
    
    if for_each:
        # Dependent discovery - iterate over parent items
        parent_id = for_each
        with saved_data_lock:
            parent_items = saved_data.get(f'{parent_id}_items', [])
        
        if not parent_items:
            logger.warning(f"No parent items found for {discovery_id} (depends on {parent_id})")
            return
        
        # Process each parent item
        accumulated_contexts = []
        
        for item in parent_items:
            # Resolve parameters from parent item
            call = calls[0]
            params = call.get('params', {})
            resolved_params = {}
            
            for param_name, param_template in params.items():
                context = {'item': item, 'response': saved_data.get(f'{parent_id}_response', {})}
                resolved_value = resolve_template(param_template, context)
                resolved_params[param_name] = resolved_value
            
            # Make API call
            action = call.get('action')
            try:
                response = _retry_call(getattr(client, action), **resolved_params)
                accumulated_contexts.append({
                    'response': response,
                    'item': item,
                    'context': {'item': item}
                })
            except Exception as e:
                logger.warning(f"Failed {action}: {e}")
                continue
        
        # Emit phase - store FULL response
        emit_config = discovery.get('emit', {})
        
        if 'items_for' in emit_config:
            # Extract items from response using generic helper
            results = []
            
            for acc_data in accumulated_contexts:
                response = acc_data['response']
                item = acc_data['item']
                
                response_items = extract_items_from_response(response, emit_config['items_for'])
                if response_items:
                    for response_item in response_items:
                        # Store FULL item object
                        if isinstance(response_item, dict):
                            item_data = response_item.copy()
                            # Preserve parent ARN if available
                            if isinstance(item, dict):
                                parent_arn = item.get('resource_arn') or item.get('Arn') or item.get('arn')
                                if parent_arn and isinstance(parent_arn, str) and parent_arn.startswith('arn:aws:'):
                                    item_data['resource_arn'] = parent_arn
                        else:
                            item_data = {'_raw_item': response_item}
                        results.append(item_data)
        else:
            # No items_for - store full response for each accumulated context
            results = []
            for acc_data in accumulated_contexts:
                response = acc_data['response']
                item = acc_data['item']
                
                # Store FULL response (excluding ResponseMetadata)
                if isinstance(response, dict):
                    item_data = {k: v for k, v in response.items() if k != 'ResponseMetadata'}
                    # Preserve parent ARN if available
                    if isinstance(item, dict):
                        parent_arn = item.get('resource_arn') or item.get('Arn') or item.get('arn')
                        if parent_arn and isinstance(parent_arn, str) and parent_arn.startswith('arn:aws:'):
                            item_data['resource_arn'] = parent_arn
                else:
                    item_data = {'_raw_response': response}
                results.append(item_data)
        
        with discovery_results_lock:
            discovery_results[discovery_id] = results
        
    else:
        # Independent discovery
        call = calls[0]
        action = call.get('action')
        params = call.get('params', {})
        
        try:
            response = _retry_call(getattr(client, action), **params)
            
            # Store response
            with saved_data_lock:
                saved_data[f'{discovery_id}_response'] = response
            
            # Emit phase - store FULL response
            emit_config = discovery.get('emit', {})
            
            if 'items_for' in emit_config:
                # Extract items from response using generic helper
                items = extract_items_from_response(response, emit_config['items_for'])
                
                logger.info(f"{discovery_id}: Extracted {len(items)} items from path '{emit_config['items_for']}'")
                
                # Filter AWS-managed resources
                items_before = len(items) if isinstance(items, list) else (1 if items else 0)
                items = _filter_aws_managed_resources(discovery_id, items, account_id)
                items_after = len(items) if isinstance(items, list) else (1 if items else 0)
                
                logger.info(f"{discovery_id}: After filtering: {items_before} -> {items_after} items")
                
                results = []
                if items:
                    for item in items:
                        # Store FULL item object
                        if isinstance(item, dict):
                            item_data = item.copy()
                            # Add ARN if not present
                            auto_fields = auto_emit_arn_and_name(item, service=service_name, region=region, account_id=account_id)
                            for key, value in auto_fields.items():
                                if key not in item_data:
                                    item_data[key] = value
                        else:
                            item_data = {'_raw_item': item}
                        results.append(item_data)
                
                logger.info(f"{discovery_id}: Storing {len(results)} items")
                
                # Store items for dependent discoveries (CRITICAL: must be stored before dependent discoveries run)
                with saved_data_lock:
                    saved_data[f'{discovery_id}_items'] = results
                    logger.debug(f"Stored {len(results)} items for {discovery_id} (for dependent discoveries)")
                
                with discovery_results_lock:
                    discovery_results[discovery_id] = results
            else:
                # No items_for - store full response
                if isinstance(response, dict):
                    item_data = {k: v for k, v in response.items() if k != 'ResponseMetadata'}
                    # Add ARN if not present
                    auto_fields = auto_emit_arn_and_name(response, service=service_name, region=region, account_id=account_id)
                    for key, value in auto_fields.items():
                        if key not in item_data:
                            item_data[key] = value
                else:
                    item_data = {'_raw_response': response}
                
                with discovery_results_lock:
                    discovery_results[discovery_id] = [item_data]
        
        except Exception as e:
            logger.error(f"Discovery {discovery_id} failed: {e}")

def extract_raw_discoveries(service_name: str, region: str = None):
    """Extract RAW JSON from all discoveries"""
    print("=" * 80)
    print(f"Extracting RAW Discoveries for {service_name}")
    print("=" * 80)
    print()
    
    # Load YAML
    service_rules = load_nested_yaml(service_name)
    if not service_rules:
        print(f"Error: Could not load service rules for {service_name}")
        return None
    
    discoveries = service_rules.get('discovery', [])
    print(f"Found {len(discoveries)} discoveries")
    print()
    
    # Get AWS session
    session = get_boto3_session()
    account_id = session.client('sts').get_caller_identity()['Account']
    print(f"Account ID: {account_id}")
    
    # Determine scope
    scope = get_service_scope(service_name)
    if not region and scope == 'regional':
        region = 'us-east-1'
    print(f"Scope: {scope}" + (f" (region: {region})" if region else ""))
    print()
    
    # Get boto3 client
    boto3_client_name = get_boto3_client_name(service_name)
    client = session.client(boto3_client_name, region_name=region, config=BOTO_CONFIG)
    
    # Build dependency graph
    dependency_graph = _build_dependency_graph(discoveries)
    independent_discoveries = dependency_graph['independent']
    dependent_groups = dependency_graph['dependent_groups']
    
    # Storage
    discovery_results = {}
    saved_data = {}
    saved_data_lock = Lock()
    discovery_results_lock = Lock()
    
    print("Running independent discoveries...")
    print("-" * 80)
    
    # Run independent discoveries in parallel
    max_workers = 50
    if independent_discoveries:
        with ThreadPoolExecutor(max_workers=min(len(independent_discoveries), max_workers)) as executor:
            futures = {}
            for discovery in independent_discoveries:
                future = executor.submit(
                    run_single_discovery_raw,
                    discovery, service_name, client, saved_data, saved_data_lock,
                    discovery_results, discovery_results_lock, account_id, region, session
                )
                futures[future] = discovery.get('discovery_id')
            
            # Wait for ALL independent discoveries to complete
            for future in as_completed(futures):
                discovery_id = futures[future]
                try:
                    future.result()
                    logger.info(f"Completed discovery {discovery_id}")
                except Exception as e:
                    logger.error(f"Discovery {discovery_id} failed: {e}")
    
    print()
    print("Running dependent discoveries...")
    print("-" * 80)
    
    # Run dependent discoveries sequentially (by level)
    for level, dependent_discs in sorted(dependent_groups.items()):
        logger.info(f"Processing {len(dependent_discs)} dependent discoveries at level {level}")
        for discovery in dependent_discs:
            try:
                run_single_discovery_raw(
                    discovery, service_name, client, saved_data, saved_data_lock,
                    discovery_results, discovery_results_lock, account_id, region, session
                )
            except Exception as e:
                logger.error(f"Discovery {discovery.get('discovery_id')} failed: {e}")
    
    print()
    print("=" * 80)
    print("Results Summary")
    print("=" * 80)
    
    for discovery_id, items in discovery_results.items():
        count = len(items) if isinstance(items, list) else 1
        print(f"  {discovery_id}: {count} item(s)")
        if items and isinstance(items, list) and len(items) > 0:
            sample = items[0]
            if isinstance(sample, dict):
                fields = list(sample.keys())
                print(f"    Fields: {fields[:15]}{'...' if len(fields) > 15 else ''}")
    
    # Save to disk
    output_dir = Path("output/discovery_collection")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    individual_dir = output_dir / f"{service_name}_RAW_{account_id}_{region or 'global'}_{timestamp}_individual"
    individual_dir.mkdir(parents=True, exist_ok=True)
    
    for discovery_id, items in discovery_results.items():
        safe_name = discovery_id.replace('.', '_').replace('/', '_')
        individual_file = individual_dir / f"{safe_name}.json"
        
        with open(individual_file, 'w') as f:
            json.dump({
                "discovery_id": discovery_id,
                "account_id": account_id,
                "region": region or "global",
                "service": service_name,
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

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Extract RAW JSON from all discoveries')
    parser.add_argument('service', help='Service name (e.g., s3, ec2, iam)')
    parser.add_argument('--region', help='Region for regional services')
    
    args = parser.parse_args()
    
    result = extract_raw_discoveries(args.service, region=args.region)
    if result:
        print(f"✓ {args.service} extraction complete!")
        sys.exit(0)
    else:
        print(f"✗ {args.service} extraction failed!")
        sys.exit(1)

