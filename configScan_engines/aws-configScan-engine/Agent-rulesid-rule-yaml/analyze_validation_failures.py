#!/usr/bin/env python3
"""
Analyze why 336 rules failed validation
"""
import json
from collections import defaultdict

def analyze_failures():
    with open('output/requirements_validated.json') as f:
        data = json.load(f)
    
    print("=" * 80)
    print("VALIDATION FAILURE ANALYSIS")
    print("=" * 80)
    print()
    
    # Statistics
    total_rules = 0
    validated_rules = 0
    failed_rules = []
    failure_reasons = defaultdict(int)
    service_stats = {}
    
    for service, rules in data.items():
        service_failed = 0
        service_total = len(rules)
        
        for rule in rules:
            total_rules += 1
            
            if rule.get('all_fields_valid'):
                validated_rules += 1
            else:
                failed_rules.append(rule)
                service_failed += 1
                
                # Analyze failure reason
                if rule.get('validation_status') == 'no_function_found':
                    failure_reasons['no_boto3_function'] += 1
                elif 'field_validation' in rule:
                    has_missing_fields = False
                    for field, val in rule['field_validation'].items():
                        if not val.get('exists', True):
                            failure_reasons['field_not_in_boto3'] += 1
                            has_missing_fields = True
                    if not has_missing_fields:
                        failure_reasons['other_validation_issue'] += 1
                else:
                    failure_reasons['unknown'] += 1
        
        if service_total > 0:
            service_stats[service] = {
                'total': service_total,
                'failed': service_failed,
                'success_rate': (service_total - service_failed) / service_total * 100
            }
    
    # Print results
    print(f"📊 OVERALL STATISTICS")
    print(f"{'─' * 80}")
    print(f"Total rules: {total_rules}")
    print(f"✅ Validated: {validated_rules} ({validated_rules/total_rules*100:.1f}%)")
    print(f"❌ Failed: {len(failed_rules)} ({len(failed_rules)/total_rules*100:.1f}%)")
    print()
    
    print(f"🔍 FAILURE REASONS")
    print(f"{'─' * 80}")
    for reason, count in sorted(failure_reasons.items(), key=lambda x: x[1], reverse=True):
        pct = count / len(failed_rules) * 100 if failed_rules else 0
        print(f"  {reason:40} {count:4} ({pct:.1f}%)")
    print()
    
    print(f"📉 SERVICES WITH LOWEST SUCCESS RATES")
    print(f"{'─' * 80}")
    worst_services = sorted(service_stats.items(), key=lambda x: x[1]['success_rate'])[:20]
    for service, stats in worst_services:
        if stats['failed'] > 0:
            print(f"  {service:30} {stats['failed']:3}/{stats['total']:3} failed ({stats['success_rate']:.1f}% success)")
    print()
    
    print(f"💡 EXAMPLE FAILED RULES (First 10)")
    print(f"{'─' * 80}")
    for i, rule in enumerate(failed_rules[:10], 1):
        print(f"\n{i}. ❌ {rule['rule_id']}")
        print(f"   Service: {rule.get('service', 'unknown')}")
        
        if rule.get('validation_status') == 'no_function_found':
            print(f"   ⚠️  No boto3 function found for this rule")
        
        if 'field_validation' in rule:
            missing_fields = [f for f, v in rule['field_validation'].items() if not v.get('exists', True)]
            if missing_fields:
                print(f"   ⚠️  Missing fields: {', '.join(missing_fields)}")
        
        if 'ai_generated_requirements' in rule and 'fields' in rule['ai_generated_requirements']:
            ai_fields = rule['ai_generated_requirements']['fields']
            print(f"   AI wanted: {len(ai_fields)} fields")
            field_names = [f.get('boto3_python_field', 'unknown') for f in ai_fields]
            print(f"   Fields: {', '.join(field_names[:5])}")
    
    print()
    print("=" * 80)
    print("RECOMMENDATIONS")
    print("=" * 80)
    print()
    print("1. Field Not Found Issues:")
    print("   - AI generated field names that don't exist in boto3")
    print("   - Solution: Improve Agent 3 field validation")
    print()
    print("2. No Function Found:")
    print("   - No boto3 operation provides needed data")
    print("   - Solution: Skip these rules or use alternative approaches")
    print()
    print("3. To fix: Run validation improvement cycle")
    print("   - Update Agent 1 prompts with better boto3 context")
    print("   - Enhance Agent 3 to suggest similar fields")
    print("   - Re-process failed services")

if __name__ == '__main__':
    analyze_failures()

