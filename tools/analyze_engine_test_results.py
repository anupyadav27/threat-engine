#!/usr/bin/env python3
"""
Analyze engine test results and provide feedback for improving the agentic AI solution.

This script:
1. Runs the engine on a service
2. Analyzes the results
3. Identifies issues with generated rules
4. Provides feedback for improvement
"""

import sys
import os
import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

# Add engine to path
engine_dir = Path(__file__).parent.parent / "aws_compliance_python_engine"
sys.path.insert(0, str(engine_dir))

from engine.main_scanner import scan_account_scope
from auth.aws_auth import get_boto3_session
import boto3
import yaml


def analyze_discovery_issues(result: Dict[str, Any], service_name: str) -> List[Dict[str, Any]]:
    """Analyze discovery execution and identify issues."""
    issues = []
    
    inventory = result.get('inventory', {})
    checks = result.get('checks', [])
    
    # Check for empty discoveries
    for disc_id, items in inventory.items():
        if not items:
            issues.append({
                'type': 'empty_discovery',
                'discovery_id': disc_id,
                'severity': 'warning',
                'message': f'Discovery {disc_id} returned no items',
                'suggestion': 'Check if discovery depends on another that returned empty results'
            })
        elif items and all(not v or v == '' for v in items[0].values() if isinstance(v, str)):
            issues.append({
                'type': 'empty_fields',
                'discovery_id': disc_id,
                'severity': 'error',
                'message': f'Discovery {disc_id} returned items but all fields are empty',
                'suggestion': 'Check emit template - field paths may be incorrect'
            })
    
    # Check for failed API calls (from logs)
    # This would need to parse logs, but for now we check results
    
    return issues


def analyze_check_issues(checks: List[Dict[str, Any]], inventory: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Analyze check execution and identify issues."""
    issues = []
    
    for check in checks:
        rule_id = check.get('rule_id', '')
        result_status = check.get('result', '')
        for_each = check.get('for_each_discovery', '')
        var = check.get('conditions', {}).get('var', '')
        
        # Check if for_each discovery exists
        if for_each and for_each not in inventory:
            issues.append({
                'type': 'missing_discovery',
                'rule_id': rule_id,
                'severity': 'error',
                'message': f'Check {rule_id} references non-existent discovery: {for_each}',
                'suggestion': f'Ensure discovery {for_each} is defined in discovery section'
            })
        
        # Check if field exists in discovery
        if for_each and for_each in inventory:
            items = inventory[for_each]
            if items:
                field_name = var.replace('item.', '') if var.startswith('item.') else var
                sample_item = items[0]
                
                # Check if field exists (case-insensitive)
                field_found = any(
                    field_name.lower() in k.lower() or k.lower() in field_name.lower()
                    for k in sample_item.keys()
                )
                
                if not field_found:
                    issues.append({
                        'type': 'missing_field',
                        'rule_id': rule_id,
                        'severity': 'error',
                        'message': f'Check {rule_id} references field "{var}" not found in discovery {for_each}',
                        'suggestion': f'Available fields: {list(sample_item.keys())[:5]}...',
                        'available_fields': list(sample_item.keys())
                    })
    
    return issues


def analyze_dependency_chain_issues(service_rules: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Analyze dependency chains in discovery."""
    issues = []
    
    discoveries = service_rules.get('discovery', [])
    discovery_ids = {d['discovery_id'] for d in discoveries}
    
    for discovery in discoveries:
        disc_id = discovery['discovery_id']
        for_each = discovery.get('for_each')
        
        if for_each:
            if for_each not in discovery_ids:
                issues.append({
                    'type': 'broken_dependency',
                    'discovery_id': disc_id,
                    'severity': 'error',
                    'message': f'Discovery {disc_id} depends on {for_each} which does not exist',
                    'suggestion': f'Add discovery {for_each} or fix for_each reference'
                })
            
            # Check if dependency is defined before this discovery
            dep_index = next((i for i, d in enumerate(discoveries) if d['discovery_id'] == for_each), -1)
            current_index = next((i for i, d in enumerate(discoveries) if d['discovery_id'] == disc_id), -1)
            
            if dep_index > current_index:
                issues.append({
                    'type': 'dependency_order',
                    'discovery_id': disc_id,
                    'severity': 'warning',
                    'message': f'Discovery {disc_id} depends on {for_each} which is defined later',
                    'suggestion': 'Reorder discoveries so dependencies come first'
                })
    
    return issues


def test_service_with_engine(service_name: str, region: str = 'us-east-1') -> Dict[str, Any]:
    """Test a service using the main scanner engine."""
    # Get current account
    try:
        sts = boto3.client('sts')
        account_id = sts.get_caller_identity()['Account']
    except:
        account_id = 'unknown'
    
    account = {
        'account_id': account_id,
        'account_name': 'test-account'
    }
    
    # Determine service scope
    # ACM is global, but most services are regional
    scope = 'global' if service_name in ['acm', 'iam', 'cloudfront'] else 'regional'
    
    # Run scan
    results = scan_account_scope(
        account=account,
        regions=[region],
        services=[(service_name, scope)],
        resource_filter=None,
        role_name=None,
        external_id=None,
        max_workers=1
    )
    
    # Find the result for this service
    for result in results:
        if result.get('service') == service_name:
            return result
    
    return {}


def analyze_and_report(service_name: str) -> Dict[str, Any]:
    """Run engine test and analyze results."""
    print("=" * 70)
    print(f"ANALYZING ENGINE TEST RESULTS FOR: {service_name.upper()}")
    print("=" * 70)
    
    # Load service rules
    rules_file = Path(f"aws_compliance_python_engine/services/{service_name}/rules/{service_name}.yaml")
    if not rules_file.exists():
        return {'error': f'Rules file not found: {rules_file}'}
    
    with open(rules_file, 'r') as f:
        service_rules = yaml.safe_load(f)
    
    # Run engine test
    print(f"\n🔍 Running engine test...")
    result = test_service_with_engine(service_name)
    
    if not result:
        return {'error': 'No results returned from engine'}
    
    # Analyze issues
    print(f"\n📊 Analyzing results...")
    
    discovery_issues = analyze_discovery_issues(result, service_name)
    check_issues = analyze_check_issues(result.get('checks', []), result.get('inventory', {}))
    dependency_issues = analyze_dependency_chain_issues(service_rules)
    
    all_issues = discovery_issues + check_issues + dependency_issues
    
    # Generate report
    report = {
        'service': service_name,
        'timestamp': datetime.now().isoformat(),
        'test_results': {
            'checks_executed': len(result.get('checks', [])),
            'checks_passed': sum(1 for c in result.get('checks', []) if c.get('result') == 'PASS'),
            'checks_failed': sum(1 for c in result.get('checks', []) if c.get('result') == 'FAIL'),
            'checks_errors': sum(1 for c in result.get('checks', []) if c.get('result') == 'ERROR'),
            'discoveries_executed': len(result.get('inventory', {})),
            'discoveries_with_data': sum(1 for items in result.get('inventory', {}).values() if items)
        },
        'issues': {
            'total': len(all_issues),
            'errors': len([i for i in all_issues if i['severity'] == 'error']),
            'warnings': len([i for i in all_issues if i['severity'] == 'warning']),
            'details': all_issues
        },
        'improvements': generate_improvements(all_issues, service_rules)
    }
    
    return report


def generate_improvements(issues: List[Dict[str, Any]], service_rules: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Generate improvement suggestions based on issues."""
    improvements = []
    
    # Group issues by type
    by_type = {}
    for issue in issues:
        issue_type = issue['type']
        if issue_type not in by_type:
            by_type[issue_type] = []
        by_type[issue_type].append(issue)
    
    # Generate improvements
    if 'missing_field' in by_type:
        improvements.append({
            'category': 'field_mapping',
            'priority': 'high',
            'issue': 'Field names in checks do not match discovery emit fields',
            'suggestions': [
                'Use exact field names from emit.item',
                'Match case (camelCase vs snake_case)',
                'Verify field paths in emit templates'
            ],
            'affected_checks': [i['rule_id'] for i in by_type['missing_field']]
        })
    
    if 'broken_dependency' in by_type:
        improvements.append({
            'category': 'dependency_chain',
            'priority': 'high',
            'issue': 'Discovery dependencies reference non-existent discoveries',
            'suggestions': [
                'Ensure all for_each references point to valid discovery_id',
                'Check discovery_id format matches exactly',
                'Verify discovery ordering (dependencies first)'
            ],
            'affected_discoveries': [i['discovery_id'] for i in by_type['broken_dependency']]
        })
    
    if 'empty_fields' in by_type:
        improvements.append({
            'category': 'emit_template',
            'priority': 'high',
            'issue': 'Discovery emit templates are not extracting data correctly',
            'suggestions': [
                'Verify template paths match API response structure',
                'Check if response field names are correct',
                'Test template resolution with actual API responses'
            ],
            'affected_discoveries': [i['discovery_id'] for i in by_type['empty_fields']]
        })
    
    return improvements


def main():
    """CLI entry point."""
    if len(sys.argv) < 2:
        print("Usage: analyze_engine_test_results.py <service_name>")
        print("Example: analyze_engine_test_results.py acm")
        sys.exit(1)
    
    service_name = sys.argv[1]
    
    report = analyze_and_report(service_name)
    
    if 'error' in report:
        print(f"❌ Error: {report['error']}")
        sys.exit(1)
    
    # Print report
    print(f"\n📊 Test Results Summary:")
    test_results = report['test_results']
    print(f"   Checks executed: {test_results['checks_executed']}")
    print(f"   ✅ PASS: {test_results['checks_passed']}")
    print(f"   ❌ FAIL: {test_results['checks_failed']}")
    print(f"   ⚠️  ERROR: {test_results['checks_errors']}")
    print(f"   Discoveries: {test_results['discoveries_executed']} ({test_results['discoveries_with_data']} with data)")
    
    print(f"\n🔍 Issues Found: {report['issues']['total']}")
    print(f"   Errors: {report['issues']['errors']}")
    print(f"   Warnings: {report['issues']['warnings']}")
    
    if report['issues']['details']:
        print(f"\n   Details:")
        for issue in report['issues']['details'][:10]:
            icon = '❌' if issue['severity'] == 'error' else '⚠️'
            print(f"     {icon} [{issue['type']}] {issue['message']}")
            if 'suggestion' in issue:
                print(f"        → {issue['suggestion']}")
    
    if report['improvements']:
        print(f"\n💡 Improvement Suggestions:")
        for imp in report['improvements']:
            print(f"\n   [{imp['priority'].upper()}] {imp['category']}:")
            print(f"      Issue: {imp['issue']}")
            print(f"      Suggestions:")
            for sug in imp['suggestions']:
                print(f"        - {sug}")
    
    # Save report
    report_file = Path(f"tools/test_analysis_{service_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    print(f"\n📁 Full report saved to: {report_file}")
    print("=" * 70)
    
    sys.exit(0 if report['issues']['errors'] == 0 else 1)


if __name__ == '__main__':
    main()

