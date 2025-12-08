#!/usr/bin/env python3
"""IBM Cloud Engine Placeholder Analyzer - finds issues that need fixing"""
import os
import yaml
from pathlib import Path

def analyze_service_issues():
    """Analyze IBM service files for placeholder issues"""
    services_dir = Path(__file__).parent / "services"
    issues = []
    total_services = 0
    total_checks = 0
    
    for service_dir in sorted(services_dir.iterdir()):
        if not service_dir.is_dir():
            continue
            
        rules_dir = service_dir / "rules" 
        if not rules_dir.exists():
            continue
            
        for rules_file in rules_dir.glob("*.yaml"):
            total_services += 1
            try:
                with open(rules_file, 'r') as f:
                    data = yaml.safe_load(f)
                
                service_name = rules_file.stem
                service_issues = []
                
                # Check discovery placeholders
                if data and isinstance(data, dict):
                    for service_key, service_data in data.items():
                        discovery = service_data.get('discovery', [])
                        checks = service_data.get('checks', [])
                        total_checks += len(checks)
                        
                        # Check discovery calls
                        for disc in discovery:
                            calls = disc.get('calls', [])
                            for call in calls:
                                if call.get('action') == 'self':
                                    service_issues.append({
                                        'type': 'discovery_placeholder',
                                        'discovery_id': disc.get('discovery_id'),
                                        'issue': 'action: self needs real IBM SDK method',
                                        'note': call.get('note', '')
                                    })
                                
                                if 'MANUAL_REVIEW_REQUIRED' in call.get('note', ''):
                                    service_issues.append({
                                        'type': 'manual_review_needed', 
                                        'discovery_id': disc.get('discovery_id'),
                                        'issue': 'Manual review required for SDK method',
                                        'note': call.get('note', '')
                                    })
                        
                        # Check field path placeholders
                        for check in checks:
                            calls = check.get('calls', [])
                            for call in calls:
                                if call.get('action') == 'self':
                                    fields = call.get('fields', [])
                                    for field in fields:
                                        path = field.get('path', '')
                                        if path in ['enabled', 'status', 'state']:  # Generic paths
                                            service_issues.append({
                                                'type': 'generic_field_path',
                                                'check_id': check.get('check_id'),
                                                'issue': f'Generic field path "{path}" needs real IBM API field',
                                                'path': path
                                            })
                
                if service_issues:
                    issues.append({
                        'service': service_name,
                        'file': str(rules_file),
                        'issues': service_issues,
                        'issue_count': len(service_issues)
                    })
                    
            except Exception as e:
                print(f"Error analyzing {rules_file}: {e}")
    
    return issues, total_services, total_checks

def main():
    issues, total_services, total_checks = analyze_service_issues()
    
    total_issues = sum(s['issue_count'] for s in issues)
    services_with_issues = len(issues)
    
    print("🔍 IBM Cloud Engine Placeholder Analysis")
    print("=" * 50)
    print(f"📊 Analyzed: {total_services} services, {total_checks} checks")
    print(f"🔧 Services with issues: {services_with_issues}")
    print(f"⚠️  Total placeholder issues: {total_issues}")
    print()
    
    if issues:
        print("📋 Services needing fixes:")
        print()
        
        for service in issues:
            print(f"  🔸 {service['service']}: {service['issue_count']} issues")
            
            # Group by issue type
            by_type = {}
            for issue in service['issues']:
                issue_type = issue['type']
                if issue_type not in by_type:
                    by_type[issue_type] = []
                by_type[issue_type].append(issue)
            
            for issue_type, type_issues in by_type.items():
                print(f"    • {issue_type}: {len(type_issues)} issues")
                # Show first few examples
                for issue in type_issues[:2]:
                    if issue_type == 'discovery_placeholder':
                        print(f"      - {issue['discovery_id']}: {issue['issue']}")
                    elif issue_type == 'generic_field_path':
                        print(f"      - {issue['check_id']}: {issue['issue']}")
                if len(type_issues) > 2:
                    print(f"      ... and {len(type_issues) - 2} more")
            print()
    
    return total_issues == 0

if __name__ == '__main__':
    success = main()
    exit(0 if success else 1)