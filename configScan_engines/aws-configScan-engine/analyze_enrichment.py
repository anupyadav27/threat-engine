#!/usr/bin/env python3
"""
Analyze enrichment results after bundle approach conversion.
"""

import json
import os
import sys
from pathlib import Path

def analyze_scan(scan_id):
    """Analyze enrichment results for a scan."""
    inventory_path = Path(f"output/{scan_id}/inventory.ndjson")
    
    if not inventory_path.exists():
        print(f"Error: Inventory file not found: {inventory_path}")
        return
    
    print("="*100)
    print("CSPM SERVICES ENRICHMENT ANALYSIS")
    print("="*100)
    print()
    
    # CSPM Important Services
    cspm_services = {
        's3': {'independent': 'aws.s3.list_buckets', 'expected_deps': 8},
        'dynamodb': {'independent': 'aws.dynamodb.list_tables', 'expected_deps': 2},
        'kms': {'independent': 'aws.kms.list_keys', 'expected_deps': 4},
        'lambda': {'independent': 'aws.lambda.list_functions', 'expected_deps': 6},
        'ecs': {'independent': 'aws.ecs.list_services', 'expected_deps': 1},
        'cloudtrail': {'independent': 'aws.cloudtrail.describe_trails', 'expected_deps': 3},
        'cloudfront': {'independent': 'aws.cloudfront.list_distributions', 'expected_deps': 1},
        'iam': {'independent': 'aws.iam.list_roles', 'expected_deps': 1},
        'ec2': {'independent': 'aws.ec2.describe_instances', 'expected_deps': 3},
        'eks': {'independent': 'aws.eks.list_clusters', 'expected_deps': 8},
        'ecr': {'independent': 'aws.ecr.describe_repositories', 'expected_deps': 2},
        'sns': {'independent': 'aws.sns.list_topics', 'expected_deps': 2},
        'sqs': {'independent': 'aws.sqs.list_queues', 'expected_deps': 1}
    }
    
    results = {}
    all_services = {}
    
    with open(inventory_path, 'r') as f:
        for line in f:
            item = json.loads(line)
            service = item.get('service')
            if service:
                if service not in all_services:
                    all_services[service] = {'total': 0, 'enriched': 0}
                all_services[service]['total'] += 1
                
                if '_dependent_data' in item:
                    all_services[service]['enriched'] += 1
                
                if service in cspm_services:
                    if service not in results:
                        results[service] = {
                            'total': 0,
                            'enriched': 0,
                            'independent_disc': cspm_services[service]['independent'],
                            'expected_deps': cspm_services[service]['expected_deps'],
                            'actual_deps': set(),
                            'samples': []
                        }
                    results[service]['total'] += 1
                    disc_op = item.get('metadata', {}).get('discovery_operation', '')
                    if results[service]['independent_disc'] in disc_op:
                        if '_dependent_data' in item:
                            results[service]['enriched'] += 1
                            for dep_name in item.get('_dependent_data', {}).keys():
                                results[service]['actual_deps'].add(dep_name)
                            if len(results[service]['samples']) < 2:
                                results[service]['samples'].append(item)
    
    # CSPM Services Summary
    print(f"{'Service':<15} {'Resources':<12} {'Enriched':<12} {'%':<8} {'Expected':<10} {'Actual':<10} {'Status'}")
    print("-" * 100)
    
    for service in sorted(cspm_services.keys()):
        if service in results:
            r = results[service]
            total = r['total']
            enriched = r['enriched']
            pct = (enriched / total * 100) if total > 0 else 0
            expected = r['expected_deps']
            actual = len(r['actual_deps'])
            
            if expected == 0:
                status = "⚪ No deps"
            elif actual == 0 and expected > 0:
                status = "❌ MISSING"
            elif actual < expected:
                status = f"⚠️ Partial"
            else:
                status = "✅ Perfect"
            
            print(f"{service:<15} {total:<12} {enriched:<12} {pct:>5.1f}%  {expected:<10} {actual:<10} {status}")
        else:
            print(f"{service:<15} {'0':<12} {'0':<12} {'0.0%':<8} {cspm_services[service]['expected_deps']:<10} {'0':<10} ⚪ No resources")
    
    print()
    print("="*100)
    print("ALL SERVICES SUMMARY")
    print("="*100)
    
    enriched_services = {s: d for s, d in all_services.items() if d['enriched'] > 0}
    print(f"\nServices with enrichment: {len(enriched_services)}/{len(all_services)}")
    print(f"Total resources: {sum(d['total'] for d in all_services.values())}")
    print(f"Enriched resources: {sum(d['enriched'] for d in all_services.values())}")
    
    print()
    print("Top 10 services by enrichment:")
    sorted_services = sorted(enriched_services.items(), key=lambda x: x[1]['enriched'], reverse=True)[:10]
    for service, data in sorted_services:
        pct = (data['enriched'] / data['total'] * 100) if data['total'] > 0 else 0
        print(f"  {service:<20} {data['enriched']}/{data['total']} ({pct:.1f}%)")
    
    print()
    print("="*100)
    print("DETAILED ANALYSIS FOR CSPM SERVICES")
    print("="*100)
    
    for service in sorted(results.keys()):
        r = results[service]
        if r['expected_deps'] > 0:
            print(f"\n📋 {service.upper()}")
            print(f"   Resources: {r['total']}, Enriched: {r['enriched']} ({r['enriched']/r['total']*100:.1f}%)")
            print(f"   Expected: {r['expected_deps']} dependent discoveries")
            print(f"   Actual: {len(r['actual_deps'])} dependent discoveries")
            if r['actual_deps']:
                print(f"   Discoveries: {', '.join(sorted(r['actual_deps']))}")
            if r['samples']:
                sample = r['samples'][0]
                print(f"   Sample: {sample.get('name')} ({sample.get('resource_type')})")
                deps = sample.get('_dependent_data', {})
                if deps:
                    print(f"   Dependent data keys: {list(deps.keys())[:5]}")
    
    print()
    print("="*100)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        scan_id = sys.argv[1]
    else:
        # Find latest scan
        output_dir = Path("output")
        if output_dir.exists():
            scans = sorted([d for d in output_dir.iterdir() if d.is_dir() and d.name.startswith("test_bundle")], 
                          key=lambda x: x.stat().st_mtime, reverse=True)
            if scans:
                scan_id = scans[0].name
                print(f"Using latest scan: {scan_id}\n")
            else:
                print("Error: No test_bundle scans found")
                sys.exit(1)
        else:
            print("Error: Output directory not found")
            sys.exit(1)
    
    analyze_scan(scan_id)

