#!/usr/bin/env python3
"""Calculate success rate of agentic AI rule generation."""

import json
import sys
from pathlib import Path
from typing import Dict, Any

def calculate_success_rate(analysis_file: Path) -> Dict[str, Any]:
    """Calculate success rate from analysis JSON."""
    with open(analysis_file, 'r') as f:
        data = json.load(f)
    
    test_results = data.get('test_results', {})
    issues = data.get('issues', {})
    
    total_checks = test_results.get('checks_total', 0)
    checks_passed = test_results.get('checks_passed', 0)
    checks_failed = test_results.get('checks_failed', 0)
    checks_errors = test_results.get('checks_errors', 0)
    
    discoveries_executed = test_results.get('discoveries_executed', 0)
    discoveries_with_data = test_results.get('discoveries_with_data', 0)
    
    total_errors = issues.get('errors', 0)
    total_warnings = issues.get('warnings', 0)
    
    # Calculate success rates
    check_success_rate = (checks_passed / total_checks * 100) if total_checks > 0 else 0
    discovery_execution_rate = (discoveries_executed / 5 * 100) if discoveries_executed > 0 else 0  # Assuming 5 discoveries for ACM
    
    # Overall success rate (weighted: 50% checks, 50% discoveries)
    overall_success = (check_success_rate * 0.5 + discovery_execution_rate * 0.5) if discoveries_executed > 0 else check_success_rate
    
    return {
        'service': data.get('service', 'unknown'),
        'check_success_rate': round(check_success_rate, 2),
        'discovery_execution_rate': round(discovery_execution_rate, 2),
        'overall_success_rate': round(overall_success, 2),
        'total_checks': total_checks,
        'checks_passed': checks_passed,
        'checks_failed': checks_failed,
        'checks_errors': checks_errors,
        'discoveries_executed': discoveries_executed,
        'discoveries_with_data': discoveries_with_data,
        'total_errors': total_errors,
        'total_warnings': total_warnings
    }

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: calculate_success_rate.py <analysis_json_file>")
        sys.exit(1)
    
    analysis_file = Path(sys.argv[1])
    if not analysis_file.exists():
        print(f"Error: File not found: {analysis_file}")
        sys.exit(1)
    
    result = calculate_success_rate(analysis_file)
    
    print(f"\n{'='*70}")
    print(f"SUCCESS RATE ANALYSIS: {result['service'].upper()}")
    print(f"{'='*70}")
    print(f"Check Success Rate:     {result['check_success_rate']}%")
    print(f"Discovery Execution:    {result['discovery_execution_rate']}%")
    print(f"Overall Success Rate:   {result['overall_success_rate']}%")
    print(f"\nDetails:")
    print(f"  Checks: {result['checks_passed']}/{result['total_checks']} passed")
    print(f"  Discoveries: {result['discoveries_executed']} executed, {result['discoveries_with_data']} with data")
    print(f"  Errors: {result['total_errors']}, Warnings: {result['total_warnings']}")
    print(f"{'='*70}\n")

