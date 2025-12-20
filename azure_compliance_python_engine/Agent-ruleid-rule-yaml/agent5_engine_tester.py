"""
Agent 5: Engine Tester (Azure)

Tests generated YAML files with the Azure engine and captures errors.

Flow:
1. Copy generated YAML to services/*/rules/
2. Run engine for each service (if Azure creds available)
3. Capture errors from logs
4. Output error report for Agent 6

Output: output/engine_test_results.json
"""

import json
import os
import subprocess
import shutil
from pathlib import Path
from agent_logger import get_logger

logger = get_logger('agent5')


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


def run_engine_for_service(service: str, subscription: str = None, location: str = 'eastus'):
    """
    Run Azure engine for a service and capture results.
    
    Returns:
        dict with success, checks_count, errors
    """
    # Build command - run from threat-engine root
    cmd_parts = [
        'cd /Users/apple/Desktop/threat-engine',
        'PYTHONPATH=/Users/apple/Desktop/threat-engine',
        'python3 -m azure_compliance_python_engine.engine.main_scanner',
        '--service', service
    ]
    
    if subscription:
        cmd_parts.extend(['--subscription', subscription])
    
    if location:
        cmd_parts.extend(['--location', location])
    
    cmd = ' '.join(cmd_parts)
    
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minutes timeout
            cwd='/Users/apple/Desktop/threat-engine'
        )
        
        output = result.stdout + result.stderr
        
        # Parse output for results
        checks_count = 0
        errors = []
        capturing_traceback = False
        traceback_lines = []
        lines = output.split('\n')
        
        # Look for check counts or success indicators
        for i, line in enumerate(lines):
            if 'Total checks:' in line or 'checks executed' in line.lower():
                try:
                    # Try to extract number
                    parts = line.split(':')
                    if len(parts) > 1:
                        checks_count = int(''.join(filter(str.isdigit, parts[1])))
                except:
                    pass
            
            # Capture full traceback
            if 'Traceback' in line:
                capturing_traceback = True
                traceback_lines = [line]
            elif capturing_traceback:
                traceback_lines.append(line)
                # Stop capturing after we get the actual error
                if (line.strip() and 
                    not line.startswith(' ') and 
                    not line.startswith('File') and
                    not line.startswith('  File') and
                    ('Error' in line or 'Exception' in line or i == len(lines) - 1)):
                    if len(traceback_lines) > 3:
                        errors.append('\n'.join(traceback_lines))
                    capturing_traceback = False
                    traceback_lines = []
            elif not capturing_traceback and ('ERROR' in line or 'Failed' in line or 'Exception' in line):
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
            'errors': ['Timeout after 300 seconds'],
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
    logger.info("Agent 5 starting - Engine Tester")
    print("=" * 80)
    print("AGENT 5: Copy YAMLs & Engine Tester (Azure)")
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
            logger.info(f"Copied {service} YAML to services folder")
        else:
            failed_count += 1
            print(f"❌ {service:30} - {message}")
            logger.warning(f"Failed to copy {service}: {message}")
    
    print()
    print(f"Copied: {copied_count}/{len(services)}")
    if failed_count > 0:
        print(f"Failed: {failed_count}")
    print()
    
    # Step 2: Check if Azure credentials available
    print("Step 2: Engine testing...")
    print("-" * 80)
    
    # Check if Azure credentials configured
    try:
        result = subprocess.run(
            'az account show',
            shell=True,
            capture_output=True,
            timeout=5
        )
        has_azure_creds = result.returncode == 0
        if has_azure_creds:
            # Try to get subscription ID
            import json as json_module
            account_info = json_module.loads(result.stdout)
            subscription_id = account_info.get('id')
        else:
            subscription_id = None
    except:
        has_azure_creds = False
        subscription_id = None
    
    if not has_azure_creds:
        print("⚠️  Azure credentials not configured")
        print("   Skipping engine tests")
        print("   YAMLs have been copied to services/")
        print()
        print("To run engine tests:")
        print("  1. Configure Azure credentials (az login)")
        print("  2. Re-run: python3 agent5_engine_tester.py")
        print()
        print("=" * 80)
        print("AGENT 5 COMPLETE (Copy Only)")
        print("=" * 80)
        print(f"✅ Copied {copied_count} YAMLs to ../services/*/rules/")
        return
    
    print("✅ Azure credentials found")
    if subscription_id:
        print(f"   Subscription: {subscription_id}")
    print(f"Testing services...")
    print()
    
    # Test a sample of services first (to avoid long runtime)
    test_services = services[:10]  # Test first 10 services
    print(f"Testing {len(test_services)} services (sample)...")
    print()
    
    test_results = {}
    
    for service in test_services:
        print(f"📦 {service}")
        
        # Run engine
        print(f"   Running engine...", end=' ', flush=True)
        result = run_engine_for_service(service, subscription_id)
        
        if result['success']:
            print(f"✅ {result['checks_count']} checks")
        else:
            print(f"❌ Errors found")
        
        test_results[service] = result
        
        if result['errors']:
            print(f"   Errors: {len(result['errors'])}")
            for error in result['errors'][:2]:
                error_preview = error[:100].replace('\n', ' ')
                print(f"      - {error_preview}")
    
    # Save results
    os.makedirs('output', exist_ok=True)
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
    logger.info(f"Agent 5 complete: {copied_count} YAMLs copied, {len(test_results)} services tested")


if __name__ == '__main__':
    main()
