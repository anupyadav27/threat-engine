"""
Agent 6: Error Analyzer (Azure)

Analyzes engine test errors and determines fixes needed.

Input: output/engine_test_results.json
Output: output/error_analysis_and_fixes.json
"""

import json
import re
import os
from typing import Dict, List
from agent_logger import get_logger

logger = get_logger('agent6')


def analyze_errors(test_results: Dict) -> Dict:
    """
    Analyze errors from engine tests.
    
    Returns:
        Dict of fixes needed per service
    """
    fixes_needed = {}
    
    for service, result in test_results.items():
        if not result.get('errors'):
            continue
        
        service_fixes = []
        
        for error in result['errors']:
            # Parse common error patterns
            fix = analyze_error_pattern(error, service)
            if fix:
                service_fixes.append(fix)
        
        if service_fixes:
            fixes_needed[service] = service_fixes
    
    return fixes_needed


def analyze_error_pattern(error: str, service: str) -> Dict:
    """
    Analyze error pattern and suggest fix.
    
    Common patterns:
    - Parameter validation failed
    - Missing required parameter
    - Field not found
    - Template not resolved
    - Azure SDK specific errors
    """
    error_lower = error.lower()
    
    # Pattern 1: Missing parameter
    if 'missing required parameter' in error_lower or 'missing' in error_lower and 'parameter' in error_lower:
        match = re.search(r"parameter.*['\"](\w+)['\"]", error)
        if match:
            param = match.group(1)
            return {
                'error_type': 'missing_parameter',
                'parameter': param,
                'fix': f'Add {param} parameter to discovery call'
            }
    
    # Pattern 2: Parameter validation failed
    if 'parameter validation failed' in error_lower or 'invalid' in error_lower and 'parameter' in error_lower:
        match = re.search(r"parameter\s+['\"]?(\w+)['\"]?", error, re.IGNORECASE)
        if match:
            param = match.group(1)
            return {
                'error_type': 'invalid_parameter',
                'parameter': param,
                'fix': f'Check {param} parameter value/format'
            }
    
    # Pattern 3: Template not resolved
    if '{{' in error and '}}' in error:
        return {
            'error_type': 'template_not_resolved',
            'fix': 'Template variable not resolving - check for_each linkage'
        }
    
    # Pattern 4: Field/attribute error
    if 'attributeerror' in error_lower or 'keyerror' in error_lower or 'has no attribute' in error_lower:
        return {
            'error_type': 'field_access_error',
            'fix': 'Field access error - check emit field names'
        }
    
    # Pattern 5: Azure SDK specific - ResourceNotFound
    if 'resourcenotfound' in error_lower or 'not found' in error_lower:
        return {
            'error_type': 'resource_not_found',
            'fix': 'Resource not found - check subscription/resource group'
        }
    
    # Pattern 6: Authentication errors
    if 'authentication' in error_lower or 'unauthorized' in error_lower or 'credential' in error_lower:
        return {
            'error_type': 'authentication_error',
            'fix': 'Authentication issue - check Azure credentials'
        }
    
    # Generic error
    return {
        'error_type': 'unknown',
        'error_text': error[:200],
        'fix': 'Needs manual review'
    }


def main():
    logger.info("Agent 6 starting - Error Analyzer")
    print("=" * 80)
    print("AGENT 6: Error Analyzer (Azure)")
    print("=" * 80)
    
    # Check if test results exist
    test_results_file = 'output/engine_test_results.json'
    if not os.path.exists(test_results_file):
        print("❌ engine_test_results.json not found")
        print("Run Agent 5 first: python3 agent5_engine_tester.py")
        return
    
    # Load test results
    with open(test_results_file) as f:
        test_results = json.load(f)
    
    # Analyze
    fixes = analyze_errors(test_results)
    
    if not fixes:
        print("\n✅ No errors found - all tests passed!")
        print("No fixes needed.")
        return
    
    print(f"\nServices with errors: {len(fixes)}")
    
    for service, service_fixes in fixes.items():
        print(f"\n📦 {service}: {len(service_fixes)} issues")
        for fix in service_fixes[:5]:
            print(f"   - {fix['error_type']}: {fix['fix']}")
    
    # Save
    os.makedirs('output', exist_ok=True)
    with open('output/error_analysis_and_fixes.json', 'w') as f:
        json.dump(fixes, f, indent=2)
    
    print(f"\n✅ Saved to: output/error_analysis_and_fixes.json")
    print(f"\nNext: Run Agent 7 to apply fixes")
    logger.info(f"Agent 6 complete: {len(fixes)} services with errors")


if __name__ == '__main__':
    main()
