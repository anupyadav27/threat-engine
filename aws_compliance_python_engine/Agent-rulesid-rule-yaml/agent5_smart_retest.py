"""
Agent 5 Smart Re-test: Re-test only failed services, preserve working ones

This script:
1. Loads working services from backup
2. Re-tests only failed services with fixed import path
3. Merges results preserving working services
"""

import json
import os
import subprocess
from pathlib import Path


def load_working_services():
    """Load working services from backup"""
    backup_file = 'output/working_services_backup.json'
    if os.path.exists(backup_file):
        with open(backup_file, 'r') as f:
            return json.load(f)
    return {}


def get_failed_services():
    """Get list of services that failed (not in working backup)"""
    working = load_working_services()
    
    # Get all services with generated YAMLs
    services = []
    if os.path.exists('output'):
        for file in os.listdir('output'):
            if file.endswith('_generated.yaml'):
                service = file.replace('_generated.yaml', '')
                services.append(service)
    
    # Return services not in working list
    failed = [s for s in sorted(services) if s not in working]
    return failed


def run_engine_for_service(service: str, account: str = '588989875114', region: str = 'us-east-1'):
    """Run engine for a service with fixed import path"""
    # Run as module from threat-engine root to fix import paths
    cmd = f'cd /Users/apple/Desktop/threat-engine && PYTHONPATH=/Users/apple/Desktop/threat-engine python3 -m aws_compliance_python_engine.engine.main_scanner --service {service} --region {region} --account {account}'
    
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=300,
            cwd='/Users/apple/Desktop/threat-engine'
        )
        
        output = result.stdout + result.stderr
        
        # Parse output for results
        checks_count = 0
        errors = []
        capturing_traceback = False
        traceback_lines = []
        
        # Look for "Total checks:"
        lines = output.split('\n')
        for i, line in enumerate(lines):
            if 'Total checks:' in line:
                try:
                    checks_count = int(line.split(':')[1].strip())
                except:
                    pass
            
            # Capture full traceback, not just first line
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
            elif not capturing_traceback and ('ERROR' in line or 'Failed' in line):
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
    print("=" * 80)
    print("AGENT 5: Smart Re-test (Preserve Working, Re-test Failed)")
    print("=" * 80)
    print()
    
    # Load working services
    working_services = load_working_services()
    print(f"✅ Loaded {len(working_services)} working services from backup")
    print()
    
    # Get failed services to re-test
    failed_services = get_failed_services()
    print(f"🔄 Re-testing {len(failed_services)} failed services...")
    print()
    
    # Check AWS credentials
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
        return
    
    print("✅ AWS credentials found")
    print()
    
    # Re-test failed services
    new_results = {}
    for service in failed_services:
        print(f"📦 {service}")
        print(f"   Re-testing...", end=' ')
        result = run_engine_for_service(service)
        
        if result['success']:
            print(f"✅ {result['checks_count']} checks")
        else:
            print(f"❌ Errors found")
        
        new_results[service] = result
        
        if result['errors']:
            print(f"   Errors: {len(result['errors'])}")
            for error in result['errors'][:1]:  # Show first error
                if isinstance(error, str):
                    # Show first line of error
                    first_line = error.split('\n')[0] if '\n' in error else error
                    print(f"      - {first_line[:100]}")
    
    print()
    print("=" * 80)
    print("MERGING RESULTS")
    print("=" * 80)
    
    # Merge: working services + new results
    merged_results = {}
    merged_results.update(working_services)  # Preserve working
    merged_results.update(new_results)  # Add new results
    
    # Save merged results
    with open('output/engine_test_results.json', 'w') as f:
        json.dump(merged_results, f, indent=2)
    
    # Statistics
    total = len(merged_results)
    successful = sum(1 for r in merged_results.values() if r.get('checks_count', 0) > 0 and not any('Traceback' in str(e) for e in r.get('errors', [])))
    with_errors = total - successful
    
    print(f"✅ Merged results saved")
    print(f"   Total services: {total}")
    print(f"   ✅ Successful: {successful}")
    print(f"   ❌ With errors: {with_errors}")
    print(f"   📊 Preserved working: {len(working_services)}")
    print(f"   🔄 Re-tested: {len(failed_services)}")
    print()
    print("Results saved to: output/engine_test_results.json")


if __name__ == '__main__':
    main()
