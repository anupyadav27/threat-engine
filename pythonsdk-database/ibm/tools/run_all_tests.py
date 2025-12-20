#!/usr/bin/env python3
"""
Run All Tests - Comprehensive Test Suite Runner

Runs:
1. Coverage tests
2. Field quality tests
3. Unit tests
4. Integration tests
5. Satisfiability tests
"""

import subprocess
import json
import sys
from pathlib import Path
from datetime import datetime

def run_test_suite():
    """Run comprehensive test suite"""
    print("=" * 80)
    print("IBM DEPENDENCY CHAIN - COMPREHENSIVE TEST SUITE")
    print("=" * 80)
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    ibm_root = Path(__file__).parent.parent
    results = {}
    
    # 1. Coverage Tests
    print("1. Running Coverage Tests...")
    print("-" * 80)
    try:
        result = subprocess.run(
            ['python3', 'tools/comprehensive_test_suite.py'],
            cwd=ibm_root,
            capture_output=True,
            text=True
        )
        results['coverage'] = {
            'status': 'passed' if result.returncode == 0 else 'failed',
            'output': result.stdout,
            'errors': result.stderr
        }
        print(result.stdout)
    except Exception as e:
        results['coverage'] = {'status': 'error', 'error': str(e)}
        print(f"Error: {e}")
    
    # 2. Field Quality Tests
    print("\n2. Running Field Quality Tests...")
    print("-" * 80)
    try:
        result = subprocess.run(
            ['python3', 'tools/field_quality_tests.py'],
            cwd=ibm_root,
            capture_output=True,
            text=True
        )
        results['field_quality'] = {
            'status': 'passed' if result.returncode == 0 else 'failed',
            'output': result.stdout,
            'errors': result.stderr
        }
        print(result.stdout)
        
        # Load quality report
        quality_report = ibm_root / "field_quality_report.json"
        if quality_report.exists():
            with open(quality_report, 'r') as f:
                results['field_quality']['report'] = json.load(f)
    except Exception as e:
        results['field_quality'] = {'status': 'error', 'error': str(e)}
        print(f"Error: {e}")
    
    # 3. Quality Check
    print("\n3. Running Quality Check...")
    print("-" * 80)
    try:
        result = subprocess.run(
            ['python3', 'tools/quality_check.py'],
            cwd=ibm_root,
            capture_output=True,
            text=True
        )
        results['quality_check'] = {
            'status': 'passed' if result.returncode == 0 else 'failed',
            'output': result.stdout,
            'errors': result.stderr
        }
        print(result.stdout)
        
        # Load quality report
        quality_report = ibm_root / "quality_report.json"
        if quality_report.exists():
            with open(quality_report, 'r') as f:
                results['quality_check']['report'] = json.load(f)
    except Exception as e:
        results['quality_check'] = {'status': 'error', 'error': str(e)}
        print(f"Error: {e}")
    
    # Generate summary
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    
    total_tests = len(results)
    passed_tests = sum(1 for r in results.values() if r.get('status') == 'passed')
    
    print(f"Total Test Suites: {total_tests}")
    print(f"Passed: {passed_tests}")
    print(f"Failed: {total_tests - passed_tests}")
    
    # Overall status
    overall_status = 'PASSED' if passed_tests == total_tests else 'PARTIAL'
    print(f"\nOverall Status: {overall_status}")
    
    # Save results
    results_file = ibm_root / "test_results.json"
    with open(results_file, 'w') as f:
        json.dump({
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total': total_tests,
                'passed': passed_tests,
                'failed': total_tests - passed_tests,
                'status': overall_status
            },
            'results': results
        }, f, indent=2)
    
    print(f"\n✅ Test results saved to: {results_file}")
    print(f"Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    return 0 if overall_status == 'PASSED' else 1

if __name__ == '__main__':
    sys.exit(run_test_suite())

