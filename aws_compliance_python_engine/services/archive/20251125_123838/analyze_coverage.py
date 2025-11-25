#!/usr/bin/env python3
"""
Analyze coverage: compare metadata rule_ids vs implemented checks for each service.
"""

import yaml
from pathlib import Path
from collections import defaultdict

def get_metadata_rule_ids(service_name):
    """Get all rule_ids from metadata files"""
    metadata_dir = Path(f"/Users/apple/Desktop/threat-engine/aws_compliance_python_engine/services/{service_name}/metadata")
    
    if not metadata_dir.exists():
        return []
    
    rule_ids = []
    for yaml_file in metadata_dir.glob("*.yaml"):
        with open(yaml_file, 'r') as f:
            data = yaml.safe_load(f)
            if data and 'rule_id' in data:
                rule_ids.append(data['rule_id'])
    
    return sorted(rule_ids)

def get_implemented_checks(service_name):
    """Get all rule_ids from implemented checks"""
    checks_file = Path(f"/Users/apple/Desktop/threat-engine/aws_compliance_python_engine/services/{service_name}/rules/{service_name}.yaml")
    
    if not checks_file.exists():
        return []
    
    try:
        with open(checks_file, 'r') as f:
            data = yaml.safe_load(f)
            checks = data.get('checks', [])
            return sorted([check.get('rule_id') for check in checks if check.get('rule_id')])
    except:
        return []

def analyze_service_coverage(service_name):
    """Analyze coverage for a single service"""
    metadata_rules = get_metadata_rule_ids(service_name)
    implemented_checks = get_implemented_checks(service_name)
    
    if not metadata_rules:
        return None
    
    implemented_set = set(implemented_checks)
    metadata_set = set(metadata_rules)
    
    missing = metadata_set - implemented_set
    extra = implemented_set - metadata_set
    
    coverage_pct = (len(implemented_set) / len(metadata_set) * 100) if metadata_set else 0
    
    return {
        'total_metadata': len(metadata_rules),
        'total_implemented': len(implemented_checks),
        'coverage_pct': coverage_pct,
        'missing': sorted(missing),
        'extra': sorted(extra),
        'metadata_rules': metadata_rules,
        'implemented_checks': implemented_checks
    }

def analyze_all_services():
    """Analyze coverage for all services"""
    
    print("="*80)
    print("RULE COVERAGE ANALYSIS")
    print("="*80)
    
    services_dir = Path("/Users/apple/Desktop/threat-engine/aws_compliance_python_engine/services")
    
    results = {}
    total_metadata = 0
    total_implemented = 0
    
    # Analyze each service
    for service_dir in sorted(services_dir.iterdir()):
        if not service_dir.is_dir():
            continue
        
        service_name = service_dir.name
        metadata_dir = service_dir / "metadata"
        
        if metadata_dir.exists() and any(metadata_dir.glob("*.yaml")):
            result = analyze_service_coverage(service_name)
            if result:
                results[service_name] = result
                total_metadata += result['total_metadata']
                total_implemented += result['total_implemented']
    
    # Overall summary
    print(f"\n📊 OVERALL SUMMARY:")
    print(f"  Services with metadata: {len(results)}")
    print(f"  Total metadata rules: {total_metadata}")
    print(f"  Total implemented checks: {total_implemented}")
    print(f"  Overall coverage: {(total_implemented/total_metadata*100):.1f}%")
    
    # Categorize services
    complete = []
    partial = []
    not_started = []
    
    for service, data in results.items():
        if data['coverage_pct'] == 100:
            complete.append(service)
        elif data['coverage_pct'] > 0:
            partial.append(service)
        else:
            not_started.append(service)
    
    print(f"\n  ✅ Complete (100%): {len(complete)}")
    print(f"  🔄 Partial: {len(partial)}")
    print(f"  ⏳ Not started (0%): {len(not_started)}")
    
    # Show services with implementations
    if partial:
        print("\n" + "="*80)
        print("🔄 PARTIALLY IMPLEMENTED SERVICES")
        print("="*80)
        
        for service in partial:
            data = results[service]
            print(f"\n{service}:")
            print(f"  Metadata rules: {data['total_metadata']}")
            print(f"  Implemented: {data['total_implemented']}")
            print(f"  Coverage: {data['coverage_pct']:.1f}%")
            print(f"  Missing: {len(data['missing'])} rules")
            
            if len(data['missing']) <= 10:
                print(f"  Missing rules:")
                for rule_id in data['missing']:
                    print(f"    • {rule_id}")
            else:
                print(f"  Missing rules (first 10):")
                for rule_id in data['missing'][:10]:
                    print(f"    • {rule_id}")
                print(f"    ... and {len(data['missing']) - 10} more")
    
    # Priority services (top 10 by metadata count)
    print("\n" + "="*80)
    print("📋 TOP 10 SERVICES BY RULE COUNT")
    print("="*80)
    
    sorted_services = sorted(results.items(), key=lambda x: x[1]['total_metadata'], reverse=True)[:10]
    
    for service, data in sorted_services:
        coverage_icon = "✅" if data['coverage_pct'] == 100 else "🔄" if data['coverage_pct'] > 0 else "⏳"
        print(f"{coverage_icon} {service:20s} - {data['total_metadata']:3d} rules ({data['coverage_pct']:5.1f}% coverage)")
    
    # Save detailed report
    report_file = services_dir / "COVERAGE_REPORT.txt"
    with open(report_file, 'w') as f:
        f.write("="*80 + "\n")
        f.write("RULE COVERAGE REPORT\n")
        f.write("="*80 + "\n\n")
        
        f.write(f"Total services: {len(results)}\n")
        f.write(f"Total metadata rules: {total_metadata}\n")
        f.write(f"Total implemented checks: {total_implemented}\n")
        f.write(f"Overall coverage: {(total_implemented/total_metadata*100):.1f}%\n\n")
        
        for service in sorted(results.keys()):
            data = results[service]
            f.write(f"\n{'='*80}\n")
            f.write(f"Service: {service}\n")
            f.write(f"{'='*80}\n")
            f.write(f"Metadata rules: {data['total_metadata']}\n")
            f.write(f"Implemented checks: {data['total_implemented']}\n")
            f.write(f"Coverage: {data['coverage_pct']:.1f}%\n")
            
            if data['missing']:
                f.write(f"\nMissing rules ({len(data['missing'])}):\n")
                for rule_id in data['missing']:
                    f.write(f"  • {rule_id}\n")
            
            if data['extra']:
                f.write(f"\nExtra checks not in metadata ({len(data['extra'])}):\n")
                for rule_id in data['extra']:
                    f.write(f"  • {rule_id}\n")
    
    print(f"\n📄 Detailed report saved to: {report_file}")
    
    # Create TODO list for S3
    if 's3' in results and results['s3']['missing']:
        todo_file = services_dir / "s3" / "TODO_MISSING_CHECKS.txt"
        with open(todo_file, 'w') as f:
            f.write("="*80 + "\n")
            f.write("S3 MISSING CHECKS - TODO LIST\n")
            f.write("="*80 + "\n\n")
            f.write(f"Implemented: {results['s3']['total_implemented']}/{results['s3']['total_metadata']} ({results['s3']['coverage_pct']:.1f}%)\n")
            f.write(f"Missing: {len(results['s3']['missing'])} checks\n\n")
            
            f.write("MISSING RULE IDs:\n")
            f.write("-" * 80 + "\n\n")
            for i, rule_id in enumerate(results['s3']['missing'], 1):
                f.write(f"{i:3d}. {rule_id}\n")
        
        print(f"📝 S3 TODO list saved to: {todo_file}")
    
    print("\n" + "="*80)
    print("RECOMMENDATION")
    print("="*80)
    print("\nFor S3 service:")
    print(f"  • Implemented: {results.get('s3', {}).get('total_implemented', 0)}")
    print(f"  • Total needed: {results.get('s3', {}).get('total_metadata', 0)}")
    print(f"  • Missing: {len(results.get('s3', {}).get('missing', []))}")
    print("\nWe need to create checks for ALL metadata rules to achieve 100% coverage.")
    
    return results

if __name__ == '__main__':
    analyze_all_services()

