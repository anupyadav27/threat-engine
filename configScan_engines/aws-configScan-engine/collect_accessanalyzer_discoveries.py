#!/usr/bin/env python3
"""
Collect all discovery outputs from services using nested YAML
Supports: accessanalyzer, ec2, s3, and other services
"""
import os
import sys
import json
import yaml
from datetime import datetime
from pathlib import Path

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from auth.aws_auth import get_boto3_session
from engine.service_scanner import run_global_service, run_regional_service, load_service_rules

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

def collect_discoveries(service_name: str = "accessanalyzer", region: str = None):
    """Run service scan and collect all discovery outputs"""
    print("=" * 80)
    print(f"Collecting Discovery Outputs for {service_name}")
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
    
    # Run the service scan
    print("Running service scan...")
    print("-" * 80)
    
    # Set environment variable to collect RAW discoveries (before enrichment)
    os.environ['COLLECT_RAW_DISCOVERIES'] = '1'
    
    try:
        if scope == 'global':
            result = run_global_service(service_name, session_override=session)
        else:
            result = run_regional_service(service_name, region, session_override=session, service_rules_override=service_rules)
        
        if not result:
            print("Error: Service scan returned no results")
            return None
        
        # Get RAW discovery results (before enrichment)
        discovery_results = result.get('_raw_discoveries') or result.get('inventory', {})
        
        print()
        print("=" * 80)
        print("Discovery Results Summary")
        print("=" * 80)
        
        all_discoveries_data = {}
        
        for discovery_id, items in discovery_results.items():
            count = len(items) if isinstance(items, list) else 1
            print(f"  {discovery_id}: {count} item(s)")
            all_discoveries_data[discovery_id] = items
        
        # Create output directory
        output_dir = Path("output/discovery_collection")
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = output_dir / f"{service_name}_discoveries_{timestamp}.json"
        
        # Save all discoveries to JSON
        output_data = {
            "service": service_name,
            "account_id": account_id,
            "region": region or "global",
            "scope": scope,
            "timestamp": timestamp,
            "discoveries_count": len(all_discoveries_data),
            "discoveries": all_discoveries_data
        }
        
        with open(output_file, 'w') as f:
            json.dump(output_data, f, indent=2, default=str)
        
        print()
        print("=" * 80)
        print("Output Saved")
        print("=" * 80)
        print(f"File: {output_file}")
        print(f"Total discoveries: {len(all_discoveries_data)}")
        print(f"Total items: {sum(len(v) if isinstance(v, list) else 1 for v in all_discoveries_data.values())}")
        print()
        
        # Also save individual discovery files for easier inspection
        individual_dir = output_dir / f"{service_name}_discoveries_{timestamp}_individual"
        individual_dir.mkdir(parents=True, exist_ok=True)
        
        for discovery_id, items in all_discoveries_data.items():
            # Sanitize filename
            safe_name = discovery_id.replace('.', '_').replace('/', '_')
            individual_file = individual_dir / f"{safe_name}.json"
            
            with open(individual_file, 'w') as f:
                json.dump({
                    "discovery_id": discovery_id,
                    "item_count": len(items) if isinstance(items, list) else 1,
                    "items": items
                }, f, indent=2, default=str)
        
        print(f"Individual discovery files saved to: {individual_dir}")
        print()
        
        return output_data
        
    except Exception as e:
        import traceback
        print(f"Error running service scan: {e}")
        print(traceback.format_exc())
        return None

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Collect discovery outputs from services')
    parser.add_argument('services', nargs='+', help='Service names to collect (e.g., accessanalyzer ec2 s3)')
    parser.add_argument('--region', help='Region for regional services (default: us-east-1)')
    
    args = parser.parse_args()
    
    results = []
    for service in args.services:
        print("\n" + "=" * 80)
        result = collect_discoveries(service, region=args.region)
        if result:
            results.append(result)
            print(f"✓ {service} collection complete!")
        else:
            print(f"✗ {service} collection failed!")
    
    print("\n" + "=" * 80)
    print(f"Summary: {len(results)}/{len(args.services)} services collected successfully")
    
    if len(results) < len(args.services):
        sys.exit(1)

