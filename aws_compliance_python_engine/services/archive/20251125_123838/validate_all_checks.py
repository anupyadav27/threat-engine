#!/usr/bin/env python3
"""
Comprehensive validation for all service check files.
Tests structure without requiring AWS credentials.
"""

import yaml
import sys
from pathlib import Path
from collections import defaultdict

def validate_service_checks(service_name):
    """Validate a single service's check file"""
    
    rules_file = Path(f"/Users/apple/Desktop/threat-engine/aws_compliance_python_engine/services/{service_name}/rules/{service_name}.yaml")
    
    if not rules_file.exists():
        return None, f"File not found: {rules_file}"
    
    try:
        with open(rules_file, 'r') as f:
            data = yaml.safe_load(f)
    except Exception as e:
        return None, f"YAML error: {e}"
    
    errors = []
    warnings = []
    stats = {
        'discovery_steps': 0,
        'checks': 0,
        'rule_ids': []
    }
    
    # Check required fields
    if 'version' not in data:
        errors.append("Missing 'version' field")
    if 'provider' not in data or data.get('provider') != 'aws':
        errors.append("Missing or invalid 'provider' field")
    if 'service' not in data or data.get('service') != service_name:
        errors.append(f"Service name mismatch: expected {service_name}, got {data.get('service')}")
    
    # Validate discovery
    discovery = data.get('discovery', [])
    if not isinstance(discovery, list):
        errors.append("Discovery must be an array")
    else:
        stats['discovery_steps'] = len(discovery)
        discovery_ids = set()
        
        for disc in discovery:
            disc_id = disc.get('discovery_id')
            if disc_id:
                discovery_ids.add(disc_id)
            
            if 'calls' not in disc or not isinstance(disc.get('calls'), list):
                errors.append(f"Discovery {disc_id} missing or invalid 'calls'")
            else:
                for call in disc['calls']:
                    if 'client' not in call or 'action' not in call:
                        errors.append(f"Discovery {disc_id} call missing client/action")
            
            if 'emit' not in disc:
                errors.append(f"Discovery {disc_id} missing 'emit'")
    
    # Validate checks
    checks = data.get('checks', [])
    if not isinstance(checks, list):
        errors.append("Checks must be an array")
    else:
        stats['checks'] = len(checks)
        
        for check in checks:
            rule_id = check.get('rule_id')
            if rule_id:
                stats['rule_ids'].append(rule_id)
            
            # Check required fields
            if not check.get('title'):
                errors.append(f"Check missing title")
            if not check.get('severity'):
                errors.append(f"Check {rule_id} missing severity")
            elif check['severity'] not in ['critical', 'high', 'medium', 'low']:
                warnings.append(f"Check {rule_id} has unusual severity: {check['severity']}")
            
            if 'for_each' not in check:
                errors.append(f"Check {rule_id} missing for_each")
            else:
                disc_ref = check['for_each'].get('discovery')
                if disc_ref and disc_ref not in discovery_ids:
                    errors.append(f"Check {rule_id} references non-existent discovery: {disc_ref}")
            
            if 'conditions' not in check:
                errors.append(f"Check {rule_id} missing conditions")
            
            if not check.get('remediation'):
                warnings.append(f"Check {rule_id} missing remediation")
            if not check.get('references'):
                warnings.append(f"Check {rule_id} missing references")
    
    return {
        'success': len(errors) == 0,
        'stats': stats,
        'errors': errors,
        'warnings': warnings
    }, None

def validate_all_services():
    """Validate all services with check files"""
    
    print("="*80)
    print("VALIDATING ALL SERVICE CHECK FILES")
    print("="*80)
    
    services_dir = Path("/Users/apple/Desktop/threat-engine/aws_compliance_python_engine/services")
    
    results = {}
    total_checks = 0
    total_discovery = 0
    
    # Find all services with rules
    for service_dir in sorted(services_dir.iterdir()):
        if not service_dir.is_dir():
            continue
        
        service_name = service_dir.name
        rules_file = service_dir / "rules" / f"{service_name}.yaml"
        
        if rules_file.exists():
            result, error = validate_service_checks(service_name)
            
            if error:
                results[service_name] = {'error': error}
            else:
                results[service_name] = result
                if result['success']:
                    total_checks += result['stats']['checks']
                    total_discovery += result['stats']['discovery_steps']
    
    # Print results
    print(f"\n📊 SUMMARY:")
    print(f"  Services with checks: {len(results)}")
    print(f"  Total discovery steps: {total_discovery}")
    print(f"  Total checks: {total_checks}")
    
    # Categorize results
    passed = [s for s, r in results.items() if 'error' not in r and r['success']]
    failed = [s for s, r in results.items() if 'error' not in r and not r['success']]
    errored = [s for s, r in results.items() if 'error' in r]
    
    print(f"\n✅ Passed: {len(passed)}")
    print(f"❌ Failed: {len(failed)}")
    print(f"⚠️  Errors: {len(errored)}")
    
    # Detailed results
    if passed:
        print("\n" + "="*80)
        print("✅ PASSED SERVICES")
        print("="*80)
        for service in passed:
            stats = results[service]['stats']
            warnings = results[service]['warnings']
            print(f"\n{service}:")
            print(f"  ✓ Discovery steps: {stats['discovery_steps']}")
            print(f"  ✓ Checks: {stats['checks']}")
            if warnings:
                print(f"  ⚠️  Warnings: {len(warnings)}")
    
    if failed:
        print("\n" + "="*80)
        print("❌ FAILED SERVICES")
        print("="*80)
        for service in failed:
            errors = results[service]['errors']
            print(f"\n{service}:")
            for error in errors[:5]:  # Show first 5 errors
                print(f"  • {error}")
            if len(errors) > 5:
                print(f"  ... and {len(errors) - 5} more errors")
    
    if errored:
        print("\n" + "="*80)
        print("⚠️  ERRORED SERVICES")
        print("="*80)
        for service in errored:
            print(f"{service}: {results[service]['error']}")
    
    # Save detailed report
    report_file = services_dir / "VALIDATION_REPORT.txt"
    with open(report_file, 'w') as f:
        f.write("="*80 + "\n")
        f.write("SERVICE CHECKS VALIDATION REPORT\n")
        f.write("="*80 + "\n\n")
        
        for service in sorted(results.keys()):
            result = results[service]
            f.write(f"\n{'='*80}\n")
            f.write(f"Service: {service}\n")
            f.write(f"{'='*80}\n")
            
            if 'error' in result:
                f.write(f"ERROR: {result['error']}\n")
            else:
                f.write(f"Status: {'✅ PASSED' if result['success'] else '❌ FAILED'}\n")
                f.write(f"Discovery steps: {result['stats']['discovery_steps']}\n")
                f.write(f"Checks: {result['stats']['checks']}\n")
                
                if result['errors']:
                    f.write(f"\nErrors ({len(result['errors'])}):\n")
                    for error in result['errors']:
                        f.write(f"  • {error}\n")
                
                if result['warnings']:
                    f.write(f"\nWarnings ({len(result['warnings'])}):\n")
                    for warning in result['warnings']:
                        f.write(f"  • {warning}\n")
                
                if result['stats']['rule_ids']:
                    f.write(f"\nRule IDs ({len(result['stats']['rule_ids'])}):\n")
                    for rule_id in result['stats']['rule_ids'][:10]:
                        f.write(f"  • {rule_id}\n")
                    if len(result['stats']['rule_ids']) > 10:
                        f.write(f"  ... and {len(result['stats']['rule_ids']) - 10} more\n")
    
    print(f"\n📄 Detailed report saved to: {report_file}")
    
    print("\n" + "="*80)
    print("NEXT STEPS")
    print("="*80)
    print("\n1. Fix any failed validations")
    print("2. Configure valid AWS credentials:")
    print("   aws configure")
    print("3. Test with real AWS:")
    print("   cd aws_compliance_python_engine")
    print("   source venv/bin/activate")
    print("   python3 engine/boto3_engine_simple.py")
    print("4. Check results in output/ and logs/ directories")
    
    return len(failed) == 0 and len(errored) == 0

if __name__ == '__main__':
    success = validate_all_services()
    sys.exit(0 if success else 1)

