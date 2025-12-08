#!/usr/bin/env python3
"""Find and report placeholder checks that need fixing"""
import os
import yaml
from pathlib import Path

def analyze_service(service_dir):
    """Analyze a service YAML for placeholder checks"""
    rules_file = service_dir / f"{service_dir.name}_rules.yaml"
    if not rules_file.exists():
        yaml_files = list(service_dir.glob("*_rules.yaml"))
        if yaml_files:
            rules_file = yaml_files[0]
        else:
            return None
    
    with open(rules_file, 'r') as f:
        data = yaml.safe_load(f)
    
    issues = []
    checks = data.get('checks', [])
    
    for check in checks:
        check_id = check.get('check_id', 'unknown')
        calls = check.get('calls', [])
        
        for call in calls:
            fields = call.get('fields', [])
            for field in fields:
                path = field.get('path', '')
                operator = field.get('operator', '')
                expected = field.get('expected')
                
                # Flag placeholder logic
                if path == 'item.name' and operator == 'equals' and expected is True:
                    issues.append({
                        'check_id': check_id,
                        'issue': 'Placeholder: item.name equals true (should check actual pod fields)',
                        'path': path,
                        'operator': operator,
                        'expected': expected
                    })
                elif path == 'item.name' and operator == 'not_equals' and expected is True:
                    issues.append({
                        'check_id': check_id,
                        'issue': 'Placeholder: item.name not_equals true (should check actual pod fields)',
                        'path': path,
                        'operator': operator,
                        'expected': expected
                    })
                elif path == 'item.policy_types' and operator in ['equals', 'not_equals'] and expected is True:
                    issues.append({
                        'check_id': check_id,
                        'issue': f'Placeholder: item.policy_types {operator} true (policy_types is a list, not boolean)',
                        'path': path,
                        'operator': operator,
                        'expected': expected
                    })
    
    return {
        'service': service_dir.name,
        'file': str(rules_file),
        'check_count': len(checks),
        'issues': issues,
        'issue_count': len(issues)
    }

def main():
    services_dir = Path(__file__).parent / 'services'
    results = []
    
    for service_dir in sorted(services_dir.iterdir()):
        if not service_dir.is_dir():
            continue
        result = analyze_service(service_dir)
        if result:
            results.append(result)
    
    # Print summary
    total_issues = sum(r['issue_count'] for r in results)
    services_with_issues = [r for r in results if r['issue_count'] > 0]
    
    print(f"Analyzed {len(results)} services")
    print(f"Total checks: {sum(r['check_count'] for r in results)}")
    print(f"Services with placeholder issues: {len(services_with_issues)}")
    print(f"Total placeholder issues: {total_issues}\n")
    
    if services_with_issues:
        print("Services needing fixes:")
        for r in services_with_issues:
            print(f"\n  {r['service']}: {r['issue_count']} issues out of {r['check_count']} checks")
            for issue in r['issues'][:3]:  # Show first 3
                print(f"    - {issue['check_id']}: {issue['issue']}")
            if len(r['issues']) > 3:
                print(f"    ... and {len(r['issues']) - 3} more")
    
    return 0 if total_issues == 0 else 1

if __name__ == '__main__':
    import sys
    sys.exit(main())

