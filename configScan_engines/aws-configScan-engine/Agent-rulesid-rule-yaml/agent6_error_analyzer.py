"""
Agent 6: Error Analyzer

Analyzes engine test errors and determines fixes needed.

Input: output/engine_test_results.json
Output: output/error_analysis_and_fixes.json
"""

import json
import re
from typing import Dict, List


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
    """
    error_lower = error.lower()
    
    # Pattern 1: Missing parameter
    if 'missing required parameter' in error_lower:
        match = re.search(r"parameter.*'(\w+)'", error)
        if match:
            param = match.group(1)
            return {
                'error_type': 'missing_parameter',
                'parameter': param,
                'fix': f'Add {param} parameter to discovery call'
            }
    
    # Pattern 2: Parameter validation failed
    if 'parameter validation failed' in error_lower:
        match = re.search(r"parameter\s+(\w+)", error, re.IGNORECASE)
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
    if 'attributeerror' in error_lower or 'keyerror' in error_lower:
        return {
            'error_type': 'field_access_error',
            'fix': 'Field access error - check emit field names'
        }
    
    # Generic error
    return {
        'error_type': 'unknown',
        'error_text': error[:200],
        'fix': 'Needs manual review'
    }


def main():
    print("=" * 80)
    print("AGENT 6: Error Analyzer")
    print("=" * 80)
    
    # Load test results
    with open('output/engine_test_results.json') as f:
        test_results = json.load(f)
    
    # Analyze
    fixes = analyze_errors(test_results)
    
    print(f"\nServices with errors: {len(fixes)}")
    
    for service, service_fixes in fixes.items():
        print(f"\n📦 {service}: {len(service_fixes)} issues")
        for fix in service_fixes[:5]:
            print(f"   - {fix['error_type']}: {fix['fix']}")
    
    # Save
    with open('output/error_analysis_and_fixes.json', 'w') as f:
        json.dump(fixes, f, indent=2)
    
    print(f"\n✅ Saved to: output/error_analysis_and_fixes.json")
    print(f"\nNext: Run Agent 7 to apply fixes")


if __name__ == '__main__':
    main()

