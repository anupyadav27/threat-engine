"""
Agent 5: Test Previously Failed Services

Tests only the 36 services that were previously failing (now enabled).
"""

import json
import os
import subprocess
from pathlib import Path


def load_failed_services():
    """Load list of previously failed services"""
    with open('output/services_to_test.json', 'r') as f:
        return json.load(f)


def run_engine_for_service(service: str, account: str = '588989875114', region: str = 'us-east-1'):
    """Run engine for a service with fixed import path"""
    # Run as module from threat-engine root to fix import paths
    cmd = f'cd /Users/apple/Desktop/threat-engine && PYTHONPATH=/Users/apple/Desktop/threat-engine python3 -m aws_compliance_python_engine.engine.main_scanner --service {service} --region {region} --account {account}'
    
    # EC2 has many resources and needs more time (544K+ checks, takes ~35+ minutes)
    timeout = 2400 if service == 'ec2' else 600  # 40 min for EC2, 10 min for others
    
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
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
    print("AGENT 5: Testing Previously Failed Services (Now Enabled)")
    print("=" * 80)
    print()
    
    # Load failed services
    services = load_failed_services()
    print(f"Testing {len(services)} previously failed services...")
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
    
    # Test services
    test_results = {}
    
    for service in services:
        print(f"📦 {service}")
        print(f"   Testing...", end=' ')
        result = run_engine_for_service(service)
        
        if result['success']:
            print(f"✅ {result['checks_count']} checks")
        else:
            print(f"❌ Errors found")
        
        test_results[service] = result
        
        if result['errors']:
            print(f"   Errors: {len(result['errors'])}")
            for error in result['errors'][:1]:  # Show first error
                if isinstance(error, str):
                    # Show first line of error
                    first_line = error.split('\n')[0] if '\n' in error else error
                    print(f"      - {first_line[:100]}")
    
    # Save results
    os.makedirs('output', exist_ok=True)
    with open('output/engine_test_results_failed_services.json', 'w') as f:
        json.dump(test_results, f, indent=2)
    
    # Statistics
    total = len(test_results)
    successful = sum(1 for r in test_results.values() if r.get('checks_count', 0) > 0 and not any('Traceback' in str(e) for e in r.get('errors', [])))
    with_errors = total - successful
    
    print()
    print("=" * 80)
    print("AGENT 5 COMPLETE")
    print("=" * 80)
    print(f"✅ Tested: {total} services")
    print(f"   ✅ Successful: {successful}")
    print(f"   ❌ With errors: {with_errors}")
    print()
    print("Results saved to: output/engine_test_results_failed_services.json")
    print()
    print("Next: Run Agent 6 to analyze errors")


if __name__ == '__main__':
    main()
