#!/usr/bin/env python3
"""
Analyze engine output and provide feedback for improving the agentic AI solution.

This script:
1. Finds the latest engine scan output
2. Analyzes results for a specific service
3. Identifies issues with generated rules
4. Provides actionable feedback for improvement
"""

import sys
import os
import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import yaml


def find_latest_scan_output() -> Optional[Path]:
    """Find the latest scan output directory."""
    output_base = Path("aws_compliance_python_engine/output")
    
    if not output_base.exists():
        return None
    
    # Check for latest symlink
    latest_link = output_base / "latest"
    if latest_link.exists() and latest_link.is_symlink():
        return latest_link.resolve()
    
    # Find most recent scan directory
    scan_dirs = sorted(
        [d for d in output_base.iterdir() if d.is_dir() and d.name.startswith('scan_')],
        key=lambda x: x.stat().st_mtime,
        reverse=True
    )
    
    return scan_dirs[0] if scan_dirs else None


def load_service_results(scan_dir: Path, service_name: str) -> Dict[str, Any]:
    """Load results for a specific service from scan output."""
    results = {
        'checks': [],
        'inventory': {},
        'errors': [],
        'accounts_scanned': []
    }
    
    # Find account folders
    account_dirs = [d for d in scan_dir.iterdir() if d.is_dir() and d.name.startswith('account_')]
    
    if not account_dirs:
        results['errors'].append(f"No account folders found in {scan_dir}")
        return results
    
    for account_dir in account_dirs:
        account_id = account_dir.name.replace('account_', '')
        
        # Look for service result files - check both regional and global patterns
        patterns = [
            f"{account_id}_*_{service_name}_checks.json",  # Regional: account_region_service_checks.json
            f"{account_id}_global_{service_name}_checks.json"  # Global: account_global_service_checks.json
        ]
        
        result_files = []
        for pattern in patterns:
            result_files.extend(list(account_dir.glob(pattern)))
        
        if not result_files:
            # Try wildcard pattern as fallback
            result_files = list(account_dir.glob(f"*{service_name}*checks.json"))
        
        for result_file in result_files:
            try:
                with open(result_file, 'r') as f:
                    data = json.load(f)
                
                # Merge checks
                if isinstance(data, list):
                    results['checks'].extend(data)
                elif isinstance(data, dict):
                    if 'checks' in data:
                        results['checks'].extend(data['checks'])
                        # Extract account/region info
                        if 'account' in data:
                            results['accounts_scanned'].append({
                                'account_id': data.get('account'),
                                'region': data.get('region', 'global'),
                                'scope': data.get('scope', 'unknown')
                            })
                    else:
                        results['checks'].append(data)
            except Exception as e:
                results['errors'].append(f"Error loading {result_file}: {e}")
    
    # Extract inventory from check results
    # Checks may contain evidence fields that reference discovery items
    # Group by discovery_id if available in check metadata
    discovery_items = {}
    for check in results['checks']:
        # Try to extract discovery context from check
        for_each = check.get('for_each_discovery') or check.get('for_each')
        if for_each:
            if for_each not in discovery_items:
                discovery_items[for_each] = []
            
            # Extract item data from evidence
            evidence = check.get('evidence', {})
            if evidence:
                # Create a representative item from evidence
                item = {k: v for k, v in evidence.items() 
                       if k not in ['rule_id', 'result', 'message', 'timestamp']}
                if item:
                    discovery_items[for_each].append(item)
    
    # Deduplicate items by creating a set of unique items
    for disc_id, items in discovery_items.items():
        # Simple deduplication by converting to tuple of sorted items
        unique_items = []
        seen = set()
        for item in items:
            # Create a hashable representation
            item_key = tuple(sorted(item.items()))
            if item_key not in seen:
                seen.add(item_key)
                unique_items.append(item)
        discovery_items[disc_id] = unique_items
    
    results['inventory'] = discovery_items
    
    return results


def analyze_discovery_issues(inventory: Dict[str, Any], service_rules: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Analyze discovery execution issues."""
    issues = []
    
    discoveries = service_rules.get('discovery', [])
    discovery_ids = {d['discovery_id'] for d in discoveries}
    
    # Check for discoveries that returned no data
    for disc_id, items in inventory.items():
        if not items:
            # Check if this discovery has dependencies
            discovery = next((d for d in discoveries if d['discovery_id'] == disc_id), None)
            if discovery and 'for_each' in discovery:
                dep_id = discovery['for_each']
                dep_items = inventory.get(dep_id, [])
                if not dep_items:
                    issues.append({
                        'type': 'empty_dependency',
                        'discovery_id': disc_id,
                        'severity': 'warning',
                        'message': f'Discovery {disc_id} returned empty because dependency {dep_id} is empty',
                        'suggestion': 'This is expected if the dependency has no resources'
                    })
                else:
                    issues.append({
                        'type': 'dependency_data_issue',
                        'discovery_id': disc_id,
                        'severity': 'error',
                        'message': f'Discovery {disc_id} returned empty despite dependency {dep_id} having {len(dep_items)} items',
                        'suggestion': 'Check parameter mapping in params - field names may be incorrect'
                    })
            else:
                issues.append({
                    'type': 'empty_discovery',
                    'discovery_id': disc_id,
                    'severity': 'info',
                    'message': f'Discovery {disc_id} returned no items',
                    'suggestion': 'This may be normal if account has no resources of this type'
                })
        elif items:
            # Check if items have empty fields
            sample = items[0] if items else {}
            empty_fields = [k for k, v in sample.items() if not v or v == '']
            if len(empty_fields) > len(sample) * 0.5:  # More than 50% empty
                issues.append({
                    'type': 'empty_fields',
                    'discovery_id': disc_id,
                    'severity': 'error',
                    'message': f'Discovery {disc_id} returned items but {len(empty_fields)}/{len(sample)} fields are empty',
                    'suggestion': 'Check emit template - field paths may be incorrect or API response structure differs',
                    'sample_fields': dict(list(sample.items())[:5])
                })
    
    # Check for discoveries not in inventory (not executed)
    executed_ids = set(inventory.keys())
    missing = discovery_ids - executed_ids
    if missing:
        for disc_id in missing:
            issues.append({
                'type': 'not_executed',
                'discovery_id': disc_id,
                'severity': 'error',
                'message': f'Discovery {disc_id} was not executed',
                'suggestion': 'Check discovery structure - may have syntax errors or missing required fields'
            })
    
    return issues


def analyze_check_issues(checks: List[Dict[str, Any]], inventory: Dict[str, Any], service_rules: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Analyze check execution issues."""
    issues = []
    
    discoveries = {d['discovery_id']: d for d in service_rules.get('discovery', [])}
    
    for check in checks:
        rule_id = check.get('rule_id', '')
        result_status = check.get('result', '')
        for_each = check.get('for_each_discovery', '')
        var = check.get('conditions', {}).get('var', '')
        
        # Check if for_each discovery exists
        if for_each:
            if for_each not in discoveries:
                issues.append({
                    'type': 'missing_discovery',
                    'rule_id': rule_id,
                    'severity': 'error',
                    'message': f'Check {rule_id} references non-existent discovery: {for_each}',
                    'suggestion': f'Add discovery {for_each} or fix for_each reference in rules file'
                })
            elif for_each not in inventory:
                issues.append({
                    'type': 'discovery_not_executed',
                    'rule_id': rule_id,
                    'severity': 'error',
                    'message': f'Check {rule_id} depends on discovery {for_each} which was not executed',
                    'suggestion': 'Check why discovery was not executed - may have errors'
                })
            else:
                # Check if field exists
                items = inventory.get(for_each, [])
                if items:
                    field_name = var.replace('item.', '') if var.startswith('item.') else var
                    sample_item = items[0]
                    
                    # Check field existence
                    field_found = any(
                        field_name.lower().replace('_', '') == k.lower().replace('_', '') or
                        field_name.lower() in k.lower() or k.lower() in field_name.lower()
                        for k in sample_item.keys()
                    )
                    
                    if not field_found:
                        issues.append({
                            'type': 'missing_field',
                            'rule_id': rule_id,
                            'severity': 'error',
                            'message': f'Check {rule_id} references field "{var}" not found in discovery {for_each}',
                            'suggestion': f'Available fields: {", ".join(list(sample_item.keys())[:10])}',
                            'available_fields': list(sample_item.keys()),
                            'requested_field': var
                        })
        
        # Check result patterns
        if result_status == 'ERROR':
            message = check.get('message', '')
            issues.append({
                'type': 'check_error',
                'rule_id': rule_id,
                'severity': 'error',
                'message': f'Check {rule_id} resulted in ERROR',
                'error_message': message,
                'suggestion': 'Review check conditions and field references'
            })
    
    return issues


def analyze_dependency_chains(service_rules: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Analyze dependency chain structure."""
    issues = []
    
    discoveries = service_rules.get('discovery', [])
    discovery_ids = {d['discovery_id'] for d in discoveries}
    
    # Build dependency graph
    dependencies = {}
    for discovery in discoveries:
        disc_id = discovery['discovery_id']
        for_each = discovery.get('for_each')
        if for_each:
            dependencies[disc_id] = for_each
    
    # Check for circular dependencies
    visited = set()
    rec_stack = set()
    
    def has_cycle(node):
        visited.add(node)
        rec_stack.add(node)
        
        if node in dependencies:
            dep = dependencies[node]
            if dep not in visited:
                if has_cycle(dep):
                    return True
            elif dep in rec_stack:
                return True
        
        rec_stack.remove(node)
        return False
    
    for disc_id in discovery_ids:
        if disc_id not in visited:
            if has_cycle(disc_id):
                issues.append({
                    'type': 'circular_dependency',
                    'severity': 'error',
                    'message': f'Circular dependency detected involving {disc_id}',
                    'suggestion': 'Review dependency chain - ensure dependencies form a DAG'
                })
    
    # Check dependency order
    for discovery in discoveries:
        disc_id = discovery['discovery_id']
        for_each = discovery.get('for_each')
        
        if for_each:
            # Find indices
            dep_index = next((i for i, d in enumerate(discoveries) if d['discovery_id'] == for_each), -1)
            current_index = next((i for i, d in enumerate(discoveries) if d['discovery_id'] == disc_id), -1)
            
            if dep_index > current_index:
                issues.append({
                    'type': 'dependency_order',
                    'discovery_id': disc_id,
                    'severity': 'warning',
                    'message': f'Discovery {disc_id} depends on {for_each} which is defined later',
                    'suggestion': 'Reorder discoveries so dependencies come first (already handled by generator, but verify)'
                })
    
    return issues


def generate_improvements(issues: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate improvement suggestions grouped by category."""
    improvements = {
        'field_mapping': [],
        'dependency_chains': [],
        'emit_templates': [],
        'check_conditions': []
    }
    
    # Group by type
    by_type = {}
    for issue in issues:
        issue_type = issue['type']
        if issue_type not in by_type:
            by_type[issue_type] = []
        by_type[issue_type].append(issue)
    
    # Field mapping issues
    if 'missing_field' in by_type:
        improvements['field_mapping'].append({
            'priority': 'high',
            'issue': 'Field names in checks do not match discovery emit fields',
            'count': len(by_type['missing_field']),
            'examples': by_type['missing_field'][:3],
            'suggestions': [
                'Use exact field names from emit.item in discovery',
                'Match case sensitivity (camelCase vs snake_case)',
                'Verify field paths in emit templates match API response',
                'Consider using field name normalization in generator'
            ]
        })
    
    # Dependency chain issues
    if 'broken_dependency' in by_type or 'dependency_data_issue' in by_type:
        improvements['dependency_chains'].append({
            'priority': 'high',
            'issue': 'Dependency chain issues preventing discovery execution',
            'count': len(by_type.get('broken_dependency', []) + by_type.get('dependency_data_issue', [])),
            'examples': (by_type.get('broken_dependency', []) + by_type.get('dependency_data_issue', []))[:3],
            'suggestions': [
                'Verify parameter mapping from dependency to dependent discovery',
                'Check if field names in params match emit field names',
                'Ensure dependency discovery executes successfully before dependent',
                'Add validation for parameter field existence'
            ]
        })
    
    # Emit template issues
    if 'empty_fields' in by_type:
        improvements['emit_templates'].append({
            'priority': 'high',
            'issue': 'Emit templates not extracting data correctly',
            'count': len(by_type['empty_fields']),
            'examples': by_type['empty_fields'][:3],
            'suggestions': [
                'Verify template paths match actual API response structure',
                'Test templates with real API responses',
                'Check if response field names differ from expected',
                'Consider using source spec field metadata for accurate paths'
            ]
        })
    
    return improvements


def analyze_service(service_name: str) -> Dict[str, Any]:
    """Main analysis function."""
    print("=" * 70)
    print(f"ANALYZING ENGINE OUTPUT FOR: {service_name.upper()}")
    print("=" * 70)
    
    # Find latest scan
    scan_dir = find_latest_scan_output()
    if not scan_dir:
        return {'error': 'No scan output found. Run engine first: python engine/main_scanner.py --service acm'}
    
    print(f"\n📁 Using scan output: {scan_dir.name}")
    
    # Load service rules
    rules_file = Path(f"aws_compliance_python_engine/services/{service_name}/rules/{service_name}.yaml")
    if not rules_file.exists():
        return {'error': f'Rules file not found: {rules_file}'}
    
    with open(rules_file, 'r') as f:
        service_rules = yaml.safe_load(f)
    
    # Load engine results
    print(f"\n🔍 Loading engine results...")
    results = load_service_results(scan_dir, service_name)
    
    if results['errors']:
        print(f"   ⚠️  Warnings: {len(results['errors'])}")
        for err in results['errors'][:3]:
            print(f"      - {err}")
    
    if not results['checks'] and not results['inventory']:
        # Check what services are actually in the scan
        available_services = set()
        for account_dir in scan_dir.iterdir():
            if account_dir.is_dir() and account_dir.name.startswith('account_'):
                for check_file in account_dir.glob("*_checks.json"):
                    # Extract service name from filename: account_region_service_checks.json
                    parts = check_file.stem.split('_')
                    if len(parts) >= 3:
                        # Service is typically the last part before '_checks'
                        service = parts[-2] if parts[-1] == 'checks' else None
                        if service:
                            available_services.add(service)
        
        error_msg = f'No results found for {service_name} in scan output'
        if available_services:
            error_msg += f'\n\nAvailable services in this scan: {", ".join(sorted(available_services))}'
            error_msg += f'\n\nTo scan {service_name}, run:'
            error_msg += f'\n  cd aws_compliance_python_engine'
            error_msg += f'\n  source venv/bin/activate'
            error_msg += f'\n  export PYTHONPATH=$(pwd):$PYTHONPATH'
            error_msg += f'\n  python engine/main_scanner.py --service {service_name} --region us-east-1'
        
        return {'error': error_msg}
    
    print(f"   Checks: {len(results['checks'])}")
    print(f"   Discoveries: {len(results['inventory'])}")
    if results['accounts_scanned']:
        print(f"   Accounts scanned: {len(set(a['account_id'] for a in results['accounts_scanned']))}")
        for acc_info in results['accounts_scanned'][:3]:
            print(f"      - {acc_info['account_id']} ({acc_info.get('region', 'global')})")
    
    # Analyze issues
    print(f"\n📊 Analyzing issues...")
    
    discovery_issues = analyze_discovery_issues(results['inventory'], service_rules)
    check_issues = analyze_check_issues(results['checks'], results['inventory'], service_rules)
    dependency_issues = analyze_dependency_chains(service_rules)
    
    all_issues = discovery_issues + check_issues + dependency_issues
    
    # Generate improvements
    improvements = generate_improvements(all_issues)
    
    # Build report
    report = {
        'service': service_name,
        'scan_dir': str(scan_dir),
        'timestamp': datetime.now().isoformat(),
        'test_results': {
            'checks_total': len(results['checks']),
            'checks_passed': sum(1 for c in results['checks'] if c.get('result') == 'PASS'),
            'checks_failed': sum(1 for c in results['checks'] if c.get('result') == 'FAIL'),
            'checks_errors': sum(1 for c in results['checks'] if c.get('result') == 'ERROR'),
            'discoveries_executed': len(results['inventory']),
            'discoveries_with_data': sum(1 for items in results['inventory'].values() if items)
        },
        'issues': {
            'total': len(all_issues),
            'errors': len([i for i in all_issues if i['severity'] == 'error']),
            'warnings': len([i for i in all_issues if i['severity'] == 'warning']),
            'info': len([i for i in all_issues if i['severity'] == 'info']),
            'by_type': {}
        },
        'improvements': improvements
    }
    
    # Group issues by type
    for issue in all_issues:
        issue_type = issue['type']
        if issue_type not in report['issues']['by_type']:
            report['issues']['by_type'][issue_type] = []
        report['issues']['by_type'][issue_type].append(issue)
    
    return report


def main():
    """CLI entry point."""
    if len(sys.argv) < 2:
        print("Usage: analyze_engine_output.py <service_name>")
        print("Example: analyze_engine_output.py acm")
        print("\nFirst run the engine:")
        print("  cd aws_compliance_python_engine")
        print("  source venv/bin/activate")
        print("  export PYTHONPATH=$(pwd):$PYTHONPATH")
        print("  python engine/main_scanner.py --service acm --region us-east-1")
        sys.exit(1)
    
    service_name = sys.argv[1]
    
    report = analyze_service(service_name)
    
    if 'error' in report:
        print(f"\n❌ Error: {report['error']}")
        sys.exit(1)
    
    # Print summary
    print(f"\n📊 Test Results:")
    tr = report['test_results']
    print(f"   Checks: {tr['checks_total']} total")
    print(f"     ✅ PASS:   {tr['checks_passed']}")
    print(f"     ❌ FAIL:   {tr['checks_failed']}")
    print(f"     ⚠️  ERROR:  {tr['checks_errors']}")
    print(f"   Discoveries: {tr['discoveries_executed']} executed, {tr['discoveries_with_data']} with data")
    
    print(f"\n🔍 Issues Found: {report['issues']['total']}")
    print(f"   ❌ Errors:   {report['issues']['errors']}")
    print(f"   ⚠️  Warnings: {report['issues']['warnings']}")
    print(f"   ℹ️  Info:     {report['issues']['info']}")
    
    # Show top issues
    if report['issues']['by_type']:
        print(f"\n   Top Issues by Type:")
        for issue_type, issues_list in sorted(report['issues']['by_type'].items(), key=lambda x: len(x[1]), reverse=True)[:5]:
            print(f"     {issue_type}: {len(issues_list)}")
            for issue in issues_list[:2]:
                icon = '❌' if issue['severity'] == 'error' else '⚠️' if issue['severity'] == 'warning' else 'ℹ️'
                print(f"       {icon} {issue['message']}")
    
    # Show improvements
    if any(improvements['field_mapping'] + improvements['dependency_chains'] + improvements['emit_templates'] 
           for improvements in [report['improvements']]):
        print(f"\n💡 Improvement Suggestions:")
        
        for category, items in report['improvements'].items():
            if items:
                for item in items:
                    print(f"\n   [{item['priority'].upper()}] {category.replace('_', ' ').title()}:")
                    print(f"      Issue: {item['issue']}")
                    print(f"      Count: {item['count']} occurrences")
                    print(f"      Suggestions:")
                    for sug in item['suggestions']:
                        print(f"        - {sug}")
    
    # Save report
    report_file = Path(f"tools/engine_analysis_{service_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    print(f"\n📁 Full report saved to: {report_file}")
    print("=" * 70)
    
    sys.exit(0 if report['issues']['errors'] == 0 else 1)


if __name__ == '__main__':
    main()

