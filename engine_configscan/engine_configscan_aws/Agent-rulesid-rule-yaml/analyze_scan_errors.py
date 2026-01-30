#!/usr/bin/env python3
"""
Analyze scan errors from scan.log

Categorizes and summarizes all errors found in the scan log.
"""

import re
import json
from collections import defaultdict
from pathlib import Path


def parse_scan_log(log_file: str):
    """Parse scan log and extract errors"""
    
    errors = {
        'template_not_resolved': [],
        'validation_errors': [],
        'check_evaluation_errors': [],
        'access_denied': [],
        'not_found': [],
        'other_errors': []
    }
    
    error_patterns = {
        'template_not_resolved': [
            r'{{ item\.',
            r'Invalid.*{{ item',
            r'Failed.*{{ item'
        ],
        'validation_errors': [
            r'ValidationException',
            r'failed to satisfy constraint',
            r'Invalid.*Arn',
            r'Invalid.*Id',
            r'Invalid.*Name'
        ],
        'check_evaluation_errors': [
            r'Error evaluating',
            r'could not convert',
            r'TypeError',
            r'ValueError'
        ],
        'access_denied': [
            r'AccessDenied',
            r'UnauthorizedOperation',
            r'Forbidden'
        ],
        'not_found': [
            r'NotFoundException',
            r'ResourceNotFoundException',
            r'does not exist'
        ]
    }
    
    service_action_pattern = r'Failed (\w+):'
    check_pattern = r'Error evaluating ([^:]+):'
    
    with open(log_file, 'r') as f:
        for line in f:
            if 'WARNING' not in line and 'ERROR' not in line:
                continue
            
            # Extract service and action
            service_action_match = re.search(service_action_pattern, line)
            check_match = re.search(check_pattern, line)
            
            error_info = {
                'line': line.strip(),
                'service': None,
                'action': None,
                'check_id': None,
                'error_message': line.split(':', 2)[-1].strip() if ':' in line else line.strip()
            }
            
            if service_action_match:
                error_info['action'] = service_action_match.group(1)
                # Try to infer service from action
                if 'get_access_preview' in error_info['action']:
                    error_info['service'] = 'accessanalyzer'
                elif 'get_authorizers' in error_info['action'] or 'get_stages' in error_info['action']:
                    error_info['service'] = 'apigateway'
                elif 'describe_certificate' in error_info['action']:
                    error_info['service'] = 'acm'
            
            if check_match:
                error_info['check_id'] = check_match.group(1)
            
            # Categorize error
            categorized = False
            for category, patterns in error_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        errors[category].append(error_info)
                        categorized = True
                        break
                if categorized:
                    break
            
            if not categorized:
                errors['other_errors'].append(error_info)
    
    return errors


def summarize_errors(errors: dict):
    """Create summary of errors"""
    
    summary = {
        'total_errors': sum(len(v) for v in errors.values()),
        'by_category': {k: len(v) for k, v in errors.items()},
        'by_service': defaultdict(int),
        'by_action': defaultdict(int),
        'by_check': defaultdict(int),
        'unique_errors': defaultdict(int)
    }
    
    # Count by service and action
    for category, error_list in errors.items():
        for error in error_list:
            if error.get('service'):
                summary['by_service'][error['service']] += 1
            if error.get('action'):
                summary['by_action'][error['action']] += 1
            if error.get('check_id'):
                summary['by_check'][error['check_id']] += 1
            
            # Count unique error messages
            error_msg = error.get('error_message', '')
            if error_msg:
                # Normalize error message (remove account IDs, etc.)
                normalized = re.sub(r'\d{12}', 'ACCOUNT_ID', error_msg)
                normalized = re.sub(r'{{ item\.\w+ }}', '{{ item.FIELD }}', normalized)
                summary['unique_errors'][normalized] += 1
    
    return summary


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Analyze scan errors')
    parser.add_argument('--log-file', type=str, 
                       default='../output/latest/logs/scan.log',
                       help='Path to scan.log file')
    parser.add_argument('--output', type=str,
                       default='output/scan_error_analysis.json',
                       help='Output JSON file')
    
    args = parser.parse_args()
    
    log_file = Path(args.log_file)
    if not log_file.exists():
        print(f"❌ Log file not found: {log_file}")
        return
    
    print("=" * 80)
    print("ANALYZING SCAN ERRORS")
    print("=" * 80)
    print()
    print(f"Reading log file: {log_file}")
    print()
    
    # Parse errors
    errors = parse_scan_log(str(log_file))
    summary = summarize_errors(errors)
    
    # Print summary
    print("=" * 80)
    print("ERROR SUMMARY")
    print("=" * 80)
    print()
    print(f"Total errors: {summary['total_errors']}")
    print()
    print("By category:")
    for category, count in sorted(summary['by_category'].items(), key=lambda x: x[1], reverse=True):
        print(f"  {category}: {count}")
    print()
    
    if summary['by_service']:
        print("Top services with errors:")
        for service, count in sorted(summary['by_service'].items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {service}: {count}")
        print()
    
    if summary['by_action']:
        print("Top actions with errors:")
        for action, count in sorted(summary['by_action'].items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {action}: {count}")
        print()
    
    if summary['by_check']:
        print("Top checks with errors:")
        for check, count in sorted(summary['by_check'].items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {check}: {count}")
        print()
    
    # Save detailed analysis
    output_file = Path(args.output)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    analysis = {
        'summary': summary,
        'errors': {k: v[:100] for k, v in errors.items()}  # Limit to first 100 per category
    }
    
    with open(output_file, 'w') as f:
        json.dump(analysis, f, indent=2)
    
    print(f"✅ Detailed analysis saved to: {output_file}")
    print()
    print("Next steps:")
    print("  1. Review template_not_resolved errors (need Agent 4 fix)")
    print("  2. Review validation_errors (parameter matching issues)")
    print("  3. Review check_evaluation_errors (check logic issues)")


if __name__ == '__main__':
    main()

