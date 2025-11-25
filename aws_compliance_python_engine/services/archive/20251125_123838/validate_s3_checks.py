#!/usr/bin/env python3
"""
Validate S3 checks file structure without calling AWS APIs.
This tests the YAML structure, discovery logic, and check definitions.
"""

import yaml
import sys
from pathlib import Path

def validate_s3_checks():
    """Validate the S3 checks file structure"""
    
    print("="*80)
    print("S3 CHECKS VALIDATION")
    print("="*80)
    
    checks_file = Path("/Users/apple/Desktop/threat-engine/aws_compliance_python_engine/services/s3/rules/s3.yaml")
    
    if not checks_file.exists():
        print(f"\n❌ ERROR: File not found: {checks_file}")
        return False
    
    print(f"\n✓ File exists: {checks_file}")
    
    # Load YAML
    try:
        with open(checks_file, 'r') as f:
            data = yaml.safe_load(f)
        print("✓ YAML syntax is valid")
    except yaml.YAMLError as e:
        print(f"❌ YAML syntax error: {e}")
        return False
    
    # Validate structure
    print("\n" + "="*80)
    print("STRUCTURE VALIDATION")
    print("="*80)
    
    errors = []
    warnings = []
    
    # Check required top-level fields
    required_fields = ['version', 'provider', 'service', 'discovery', 'checks']
    for field in required_fields:
        if field not in data:
            errors.append(f"Missing required field: {field}")
        else:
            print(f"✓ Has {field} field")
    
    # Validate version
    if data.get('version') != '1.0':
        warnings.append(f"Version is {data.get('version')}, expected '1.0'")
    
    # Validate provider
    if data.get('provider') != 'aws':
        errors.append(f"Provider is {data.get('provider')}, must be 'aws'")
    
    # Validate service
    if data.get('service') != 's3':
        errors.append(f"Service is {data.get('service')}, must be 's3'")
    
    # Validate discovery
    print("\n" + "="*80)
    print("DISCOVERY VALIDATION")
    print("="*80)
    
    discovery = data.get('discovery', [])
    if not isinstance(discovery, list):
        errors.append("Discovery must be an array")
    else:
        print(f"✓ Discovery has {len(discovery)} steps")
        
        discovery_ids = set()
        for idx, disc in enumerate(discovery):
            disc_id = disc.get('discovery_id')
            if not disc_id:
                errors.append(f"Discovery step {idx} missing discovery_id")
            else:
                print(f"  • {disc_id}")
                if disc_id in discovery_ids:
                    errors.append(f"Duplicate discovery_id: {disc_id}")
                discovery_ids.add(disc_id)
            
            # Check calls
            if 'calls' not in disc:
                errors.append(f"Discovery {disc_id} missing 'calls'")
            elif not isinstance(disc['calls'], list):
                errors.append(f"Discovery {disc_id} 'calls' must be an array")
            else:
                for call in disc['calls']:
                    if 'client' not in call:
                        errors.append(f"Discovery {disc_id} call missing 'client'")
                    if 'action' not in call:
                        errors.append(f"Discovery {disc_id} call missing 'action'")
            
            # Check emit
            if 'emit' not in disc:
                errors.append(f"Discovery {disc_id} missing 'emit'")
    
    # Validate checks
    print("\n" + "="*80)
    print("CHECKS VALIDATION")
    print("="*80)
    
    checks = data.get('checks', [])
    if not isinstance(checks, list):
        errors.append("Checks must be an array")
    else:
        print(f"✓ Found {len(checks)} checks")
        
        check_ids = set()
        for idx, check in enumerate(checks):
            title = check.get('title', f'Check {idx}')
            rule_id = check.get('rule_id')
            
            if not rule_id:
                errors.append(f"Check '{title}' missing rule_id")
            else:
                print(f"\n  Check {idx+1}: {title}")
                print(f"    Rule ID: {rule_id}")
                
                if rule_id in check_ids:
                    errors.append(f"Duplicate rule_id: {rule_id}")
                check_ids.add(rule_id)
            
            # Validate required check fields
            if 'severity' not in check:
                errors.append(f"Check '{title}' missing severity")
            elif check['severity'] not in ['critical', 'high', 'medium', 'low']:
                warnings.append(f"Check '{title}' has unusual severity: {check['severity']}")
            else:
                print(f"    Severity: {check['severity']}")
            
            if 'for_each' not in check:
                errors.append(f"Check '{title}' missing for_each")
            else:
                discovery_ref = check['for_each'].get('discovery')
                if not discovery_ref:
                    errors.append(f"Check '{title}' for_each missing discovery")
                elif discovery_ref not in discovery_ids:
                    errors.append(f"Check '{title}' references non-existent discovery: {discovery_ref}")
                else:
                    print(f"    Discovery: {discovery_ref}")
            
            if 'conditions' not in check:
                errors.append(f"Check '{title}' missing conditions")
            else:
                cond = check['conditions']
                if isinstance(cond, dict):
                    if 'var' in cond:
                        print(f"    Condition: {cond.get('op', '?')} on {cond.get('var')}")
                    elif 'all' in cond or 'any' in cond:
                        cond_type = 'all' if 'all' in cond else 'any'
                        print(f"    Condition: {cond_type} with {len(cond[cond_type])} sub-conditions")
            
            if 'remediation' not in check:
                warnings.append(f"Check '{title}' missing remediation")
            
            if 'references' not in check:
                warnings.append(f"Check '{title}' missing references")
            elif len(check['references']) == 0:
                warnings.append(f"Check '{title}' has empty references")
    
    # Print summary
    print("\n" + "="*80)
    print("VALIDATION SUMMARY")
    print("="*80)
    
    print(f"\n✓ Discovery Steps: {len(discovery)}")
    print(f"✓ Checks Defined: {len(checks)}")
    
    if errors:
        print(f"\n❌ ERRORS ({len(errors)}):")
        for error in errors:
            print(f"  • {error}")
    
    if warnings:
        print(f"\n⚠️  WARNINGS ({len(warnings)}):")
        for warning in warnings:
            print(f"  • {warning}")
    
    if not errors:
        print("\n" + "="*80)
        print("✅ VALIDATION PASSED - FILE STRUCTURE IS CORRECT")
        print("="*80)
        print("\nNext steps:")
        print("1. Configure valid AWS credentials")
        print("2. Run: cd aws_compliance_python_engine && source venv/bin/activate")
        print("3. Run: python3 engine/boto3_engine_simple.py")
        print("4. Check output in logs/ and output/ directories")
        return True
    else:
        print("\n" + "="*80)
        print("❌ VALIDATION FAILED")
        print("="*80)
        return False

if __name__ == '__main__':
    success = validate_s3_checks()
    sys.exit(0 if success else 1)

