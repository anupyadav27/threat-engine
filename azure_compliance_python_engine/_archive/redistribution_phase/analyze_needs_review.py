#!/usr/bin/env python3
"""
Analyze rules needing review and suggest redistribution
"""

import yaml
import os
from pathlib import Path
from collections import defaultdict
import json

def analyze_rule(rule_file):
    """Extract key information from a rule for classification"""
    with open(rule_file, 'r') as f:
        rule = yaml.safe_load(f)
    
    rule_id = rule.get('rule_id', '')
    resource = rule.get('resource', '')
    scope = rule.get('scope', '')
    domain = rule.get('domain', '')
    subcategory = rule.get('subcategory', '')
    
    # Extract service hint from rule_id or resource
    parts = rule_id.split('.')
    
    return {
        'file': rule_file.name,
        'rule_id': rule_id,
        'resource': resource,
        'scope': scope,
        'domain': domain,
        'subcategory': subcategory,
        'parts': parts,
        'full_rule': rule
    }


def suggest_service_from_rule(rule_info):
    """Suggest target service based on rule analysis"""
    rule_id = rule_info['rule_id']
    resource = rule_info['resource']
    scope = rule_info['scope']
    domain = rule_info['domain']
    
    # Keyword-based mapping
    mappings = {
        # Identity & AAD
        'directory': 'aad',
        'directory_app': 'aad',
        'directory_group': 'aad',
        'directory_user': 'aad',
        'identity_access': 'aad',
        'saml': 'aad',
        'oidc': 'aad',
        'oauth': 'aad',
        
        # Key Vault & Crypto
        'crypto': 'keyvault',
        'secrets': 'keyvault',
        'certificate': 'certificates',
        'private_ca': 'keyvault',
        'kms': 'keyvault',
        'key_vault': 'keyvault',
        
        # Storage
        'bucket': 'storage',
        'blob': 'blob',
        'storage': 'storage',
        
        # Compute
        'instance': 'compute',
        'vm': 'compute',
        'virtual_machine': 'compute',
        'ebs': 'compute',
        'disk': 'compute',
        
        # Networking
        'vpc': 'network',
        'network': 'network',
        'subnet': 'network',
        'securitygroup': 'network',
        'firewall': 'network',
        'load_balancer': 'network',
        
        # Databases
        'rds': 'sql',
        'database': 'sql',
        'sql': 'sql',
        'db_instance': 'sql',
        
        # Disaster Recovery
        'dr_': 'backup',
        'backup': 'backup',
        'recovery': 'backup',
        
        # DevOps
        'devops': 'devops',
        'pipeline': 'devops',
        
        # Functions
        'function': 'function',
        'lambda': 'function',
        
        # Monitoring
        'log': 'monitor',
        'monitoring': 'monitor',
        'cloudwatch': 'monitor',
        
        # Security
        'security': 'security',
        'defender': 'security',
        
        # IAM
        'iam': 'iam',
        'role': 'rbac',
        'policy': 'policy',
        
        # API
        'api': 'api',
        'restapi': 'api',
    }
    
    # Check resource field
    resource_lower = resource.lower()
    for keyword, service in mappings.items():
        if keyword in resource_lower:
            return service, f"resource contains '{keyword}'"
    
    # Check rule_id
    rule_id_lower = rule_id.lower()
    for keyword, service in mappings.items():
        if keyword in rule_id_lower:
            return service, f"rule_id contains '{keyword}'"
    
    # Check scope
    scope_lower = scope.lower()
    for keyword, service in mappings.items():
        if keyword in scope_lower:
            return service, f"scope contains '{keyword}'"
    
    # Domain-based suggestions
    domain_mapping = {
        'identity_and_access_management': 'aad',
        'data_protection_and_privacy': 'keyvault',
        'network_security_and_connectivity': 'network',
        'compute_and_workload_security': 'compute',
    }
    
    if domain in domain_mapping:
        return domain_mapping[domain], f"domain is '{domain}'"
    
    return None, "No clear match"


def analyze_service_folder(service_name, services_dir):
    """Analyze all rules in a service folder"""
    service_dir = services_dir / service_name / 'metadata'
    
    if not service_dir.exists():
        return []
    
    results = []
    for rule_file in service_dir.glob('*.yaml'):
        try:
            rule_info = analyze_rule(rule_file)
            suggested_service, reason = suggest_service_from_rule(rule_info)
            
            results.append({
                'current_service': service_name,
                'rule_id': rule_info['rule_id'],
                'resource': rule_info['resource'],
                'domain': rule_info['domain'],
                'suggested_service': suggested_service,
                'reason': reason,
                'confidence': 'high' if suggested_service else 'low',
                'file': rule_file.name
            })
        except Exception as e:
            print(f"Error processing {rule_file}: {e}")
    
    return results


def generate_redistribution_plan(results):
    """Generate a redistribution plan"""
    by_target = defaultdict(list)
    unmapped = []
    
    for result in results:
        if result['suggested_service']:
            by_target[result['suggested_service']].append(result)
        else:
            unmapped.append(result)
    
    return by_target, unmapped


def create_csv_mapping(results, output_file):
    """Create CSV file for compliance tracking"""
    import csv
    
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=[
            'rule_id', 'current_service', 'suggested_service', 
            'resource', 'domain', 'reason', 'confidence', 'status'
        ])
        writer.writeheader()
        
        for result in results:
            writer.writerow({
                'rule_id': result['rule_id'],
                'current_service': result['current_service'],
                'suggested_service': result['suggested_service'] or 'UNMAPPED',
                'resource': result['resource'],
                'domain': result['domain'],
                'reason': result['reason'],
                'confidence': result['confidence'],
                'status': 'PENDING_REVIEW'
            })


def main():
    print("=" * 80)
    print(" ANALYZING RULES NEEDING REVIEW")
    print("=" * 80)
    
    script_dir = Path(__file__).parent
    services_dir = script_dir / 'services'
    
    # Services to analyze
    services_to_review = ['azure', 'active', 'managed']
    
    all_results = []
    
    for service_name in services_to_review:
        print(f"\n📁 Analyzing: {service_name}")
        results = analyze_service_folder(service_name, services_dir)
        all_results.extend(results)
        print(f"   Found {len(results)} rules")
    
    # Generate redistribution plan
    by_target, unmapped = generate_redistribution_plan(all_results)
    
    print("\n" + "=" * 80)
    print(" REDISTRIBUTION SUGGESTIONS")
    print("=" * 80)
    
    for target_service, rules in sorted(by_target.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"\n→ {target_service:20s} {len(rules):3d} rules")
        
        # Show breakdown by current service
        by_current = defaultdict(int)
        for rule in rules:
            by_current[rule['current_service']] += 1
        
        for current, count in by_current.items():
            print(f"     from {current:10s}: {count:3d} rules")
    
    if unmapped:
        print(f"\n⚠️  UNMAPPED: {len(unmapped)} rules need manual review")
        print("\nSample unmapped rules:")
        for rule in unmapped[:5]:
            print(f"  - {rule['rule_id'][:80]}...")
            print(f"    Resource: {rule['resource']}, Domain: {rule['domain']}")
    
    # Create detailed report
    report = {
        'total_analyzed': len(all_results),
        'mapped': len(all_results) - len(unmapped),
        'unmapped': len(unmapped),
        'redistribution_plan': {
            target: len(rules) for target, rules in by_target.items()
        },
        'by_current_service': {}
    }
    
    for current in services_to_review:
        report['by_current_service'][current] = {
            'total': len([r for r in all_results if r['current_service'] == current]),
            'mapped': len([r for r in all_results if r['current_service'] == current and r['suggested_service']]),
            'unmapped': len([r for r in all_results if r['current_service'] == current and not r['suggested_service']])
        }
    
    # Save reports
    report_file = script_dir / 'redistribution_plan.json'
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    csv_file = script_dir / 'redistribution_mapping.csv'
    create_csv_mapping(all_results, csv_file)
    
    detailed_file = script_dir / 'redistribution_detailed.json'
    with open(detailed_file, 'w') as f:
        json.dump(all_results, f, indent=2)
    
    print("\n" + "=" * 80)
    print(" SUMMARY")
    print("=" * 80)
    print(f"Total rules analyzed:     {len(all_results)}")
    print(f"Successfully mapped:      {len(all_results) - len(unmapped)} ({100*(len(all_results) - len(unmapped))/len(all_results):.1f}%)")
    print(f"Need manual review:       {len(unmapped)} ({100*len(unmapped)/len(all_results):.1f}%)")
    
    print(f"\n📄 Reports saved:")
    print(f"  • {report_file}       - Summary statistics")
    print(f"  • {csv_file}          - CSV for tracking")
    print(f"  • {detailed_file}     - Detailed analysis")
    
    print("\n" + "=" * 80)


if __name__ == "__main__":
    main()

