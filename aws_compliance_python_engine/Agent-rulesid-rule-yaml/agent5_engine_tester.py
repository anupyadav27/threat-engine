"""
Agent 5: Engine Tester

Tests generated YAML files with the engine and captures errors.

Flow:
1. Copy generated YAML to services/*/rules/
2. Run engine for each service (if AWS creds available)
3. Capture errors from logs
4. Output error report for Agent 6

Output: output/engine_test_results.json
"""

import json
import os
import subprocess
import shutil
from pathlib import Path


def get_services_with_generated_yamls():
    """Get list of services that have generated YAMLs"""
    services = []
    if os.path.exists('output'):
        for file in os.listdir('output'):
            if file.endswith('_generated.yaml'):
                service = file.replace('_generated.yaml', '')
                services.append(service)
    return sorted(services)


def copy_generated_yaml_to_service(service: str):
    """Copy generated YAML to service rules folder"""
    source = f'output/{service}_generated.yaml'
    dest = f'../services/{service}/rules/{service}.yaml'
    
    if not os.path.exists(source):
        return False, "No generated YAML"
    
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    
    # Backup existing
    if os.path.exists(dest):
        shutil.copy(dest, f'{dest}.backup')
    
    # Copy generated
    try:
        shutil.copy(source, dest)
        return True, "Copied successfully"
    except Exception as e:
        return False, str(e)


def run_engine_for_service(service: str, account: str = '588989875114', region: str = 'us-east-1'):
    """
    Run engine for a service and capture results.
    
    Returns:
        (success, checks_count, errors)
    """
    cmd = f'PYTHONPATH=/Users/apple/Desktop/threat-engine python3 engine/main_scanner.py --service {service} --region {region} --account {account}'
    
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=300,  # Increased from 120 to 300 seconds for large services
            cwd='/Users/apple/Desktop/threat-engine/aws_compliance_python_engine'
        )
        
        output = result.stdout + result.stderr
        
        # Parse output for results
        checks_count = 0
        errors = []
        
        # Look for "Total checks:"
        for line in output.split('\n'):
            if 'Total checks:' in line:
                try:
                    checks_count = int(line.split(':')[1].strip())
                except:
                    pass
            
            # Capture errors
            if 'ERROR' in line or 'Failed' in line or 'Traceback' in line:
                errors.append(line)
        
        return {
            'success': result.returncode == 0,
            'checks_count': checks_count,
            'errors': errors[:20],  # Limit errors
            'output': output[-2000:]  # Last 2000 chars
        }
        
    except subprocess.TimeoutExpired:
        return {
            'success': False,
            'checks_count': 0,
            'errors': ['Timeout after 120 seconds'],
            'output': ''
        }
    except Exception as e:
        return {
            'success': False,
            'checks_count': 0,
            'errors': [str(e)],
            'output': ''
        }


def main():
    print("=" * 80)
    print("AGENT 5: Copy YAMLs & Engine Tester")
    print("=" * 80)
    print()
    
    # Get all services with generated YAMLs
    services = get_services_with_generated_yamls()
    print(f"Found {len(services)} generated YAML files")
    print()
    
    # Step 1: Copy all YAMLs
    print("Step 1: Copying YAMLs to service directories...")
    print("-" * 80)
    copied_count = 0
    failed_count = 0
    
    for service in services:
        success, message = copy_generated_yaml_to_service(service)
        if success:
            copied_count += 1
            print(f"✅ {service:30} → ../services/{service}/rules/{service}.yaml")
        else:
            failed_count += 1
            print(f"❌ {service:30} - {message}")
    
    print()
    print(f"Copied: {copied_count}/{len(services)}")
    if failed_count > 0:
        print(f"Failed: {failed_count}")
    print()
    
    # Step 2: Check if AWS credentials available
    print("Step 2: Engine testing...")
    print("-" * 80)
    
    # Check if AWS credentials configured
    try:
        result = subprocess.run(
            'aws sts get-caller-identity',
            shell=True,
            capture_output=True,
            timeout=5
        )
        has_aws_creds = result.returncode == 0
    except:
        has_aws_creds = False
    
    if not has_aws_creds:
        print("⚠️  AWS credentials not configured")
        print("   Skipping engine tests")
        print("   YAMLs have been copied to services/")
        print()
        print("To run engine tests:")
        print("  1. Configure AWS credentials (aws configure)")
        print("  2. Re-run: python3 agent5_engine_tester.py")
        return
    
    print("✅ AWS credentials found")
    print(f"Testing ALL {len(services)} services...")
    print()
    
    test_results = {}
    test_services = services  # Test ALL services
    
    for service in test_services:
        print(f"📦 {service}")
        
        # Run engine
        print(f"   Running engine...", end=' ')
        result = run_engine_for_service(service)
        
        if result['success']:
            print(f"✅ {result['checks_count']} checks")
        else:
            print(f"❌ Errors found")
        
        test_results[service] = result
        
        if result['errors']:
            print(f"   Errors: {len(result['errors'])}")
            for error in result['errors'][:2]:
                print(f"      - {error[:100]}")
    
    # Save results
    with open('output/engine_test_results.json', 'w') as f:
        json.dump(test_results, f, indent=2)
    
    print()
    print("=" * 80)
    print("AGENT 5 COMPLETE")
    print("=" * 80)
    print()
    print(f"✅ Copied {copied_count} YAMLs to ../services/*/rules/")
    
    if test_results:
        successful = sum(1 for r in test_results.values() if r['success'])
        total_checks = sum(r['checks_count'] for r in test_results.values())
        total_errors = sum(len(r['errors']) for r in test_results.values())
        
        print(f"🔬 Tested {len(test_results)} services")
        print(f"   ✅ Successful: {successful}")
        print(f"   ❌ With errors: {len(test_results) - successful}")
        print(f"   Total checks: {total_checks}")
        
        if total_errors > 0:
            print()
            print("Next: Agent 6 will analyze errors")
    
    print()
    print("YAMLs are now in place for engine to use!")


if __name__ == '__main__':
    main()

