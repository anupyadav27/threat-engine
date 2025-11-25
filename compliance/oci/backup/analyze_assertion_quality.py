#!/usr/bin/env python3
"""
CSPM Security Assertion Quality Analysis
Analyze assertion naming from a security expert perspective
"""

import yaml
from collections import Counter, defaultdict
import re

print("=" * 100)
print("CSPM SECURITY ASSERTION QUALITY ANALYSIS")
print("=" * 100)

# Load rules
with open('rule_ids.yaml', 'r') as f:
    data = yaml.safe_load(f)

rules = data['rule_ids']
print(f"\nTotal Rules: {len(rules)}")

# Assertion quality categories
assertion_analysis = {
    'enterprise_grade': [],      # Clear: what + desired_state
    'good': [],                   # Has desired state but could be clearer
    'needs_improvement': [],      # Unclear or too verbose
    'redundant': [],              # Repeats service/resource name
    'too_generic': [],            # Like "configured", "enabled" without context
}

# Desired state indicators (enterprise-grade)
desired_states = [
    'enabled', 'disabled', 'configured', 'required', 'blocked', 'restricted',
    'enforced', 'validated', 'encrypted', 'protected', 'monitored', 'logged',
    'allowed', 'denied', 'present', 'absent', 'compliant', 'secure'
]

# Security control categories
security_categories = {
    'encryption': 0,
    'authentication': 0,
    'authorization': 0,
    'access_control': 0,
    'logging': 0,
    'monitoring': 0,
    'network_security': 0,
    'data_protection': 0,
    'compliance': 0,
    'vulnerability': 0,
    'backup': 0,
    'disaster_recovery': 0,
}

def analyze_assertion(assertion: str) -> dict:
    """Analyze assertion quality from CSPM perspective"""
    result = {
        'quality': 'needs_improvement',
        'has_desired_state': False,
        'has_clear_parameter': False,
        'is_redundant': False,
        'length': len(assertion),
        'word_count': len(assertion.split('_')),
        'ends_with_state': False,
        'security_category': None
    }
    
    assertion_lower = assertion.lower()
    parts = assertion.split('.')
    actual_assertion = parts[-1] if len(parts) > 0 else assertion
    
    # Check for desired state at end
    for state in desired_states:
        if actual_assertion.endswith(state) or actual_assertion.endswith(state + 'd') or actual_assertion.endswith(state + '_required'):
            result['has_desired_state'] = True
            result['ends_with_state'] = True
            break
    
    # Check for clear parameter/configuration mention
    clear_params = ['mfa', 'encryption', 'tls', 'ssl', 'logging', 'monitoring', 
                   'backup', 'versioning', 'deletion', 'public', 'private',
                   'audit', 'policy', 'key', 'certificate', 'authentication',
                   'authorization', 'access', 'network', 'firewall', 'port']
    
    for param in clear_params:
        if param in assertion_lower:
            result['has_clear_parameter'] = True
            break
    
    # Check for redundancy (assertion repeats service/resource info)
    redundant_patterns = ['security_', '_security', 'governance_', '_governance']
    if any(pattern in assertion_lower for pattern in redundant_patterns):
        # This is categorization, not necessarily bad
        pass
    
    # Categorize security domain
    if 'encrypt' in assertion_lower or 'cmk' in assertion_lower or 'kms' in assertion_lower:
        result['security_category'] = 'encryption'
    elif 'mfa' in assertion_lower or 'authentication' in assertion_lower or 'login' in assertion_lower:
        result['security_category'] = 'authentication'
    elif 'authorization' in assertion_lower or 'rbac' in assertion_lower or 'policy' in assertion_lower or 'permission' in assertion_lower:
        result['security_category'] = 'authorization'
    elif 'access' in assertion_lower or 'public' in assertion_lower or 'private' in assertion_lower:
        result['security_category'] = 'access_control'
    elif 'log' in assertion_lower or 'audit' in assertion_lower:
        result['security_category'] = 'logging'
    elif 'monitor' in assertion_lower or 'alarm' in assertion_lower or 'alert' in assertion_lower:
        result['security_category'] = 'monitoring'
    elif 'network' in assertion_lower or 'firewall' in assertion_lower or 'vpc' in assertion_lower or 'subnet' in assertion_lower:
        result['security_category'] = 'network_security'
    elif 'backup' in assertion_lower or 'snapshot' in assertion_lower or 'retention' in assertion_lower:
        result['security_category'] = 'backup'
    elif 'dr_' in assertion_lower or 'disaster' in assertion_lower or 'recovery' in assertion_lower:
        result['security_category'] = 'disaster_recovery'
    elif 'vuln' in assertion_lower or 'patch' in assertion_lower or 'vulnerability' in assertion_lower:
        result['security_category'] = 'vulnerability'
    elif 'compliance' in assertion_lower or 'cis' in assertion_lower:
        result['security_category'] = 'compliance'
    else:
        result['security_category'] = 'data_protection'
    
    # Determine quality
    if result['has_desired_state'] and result['has_clear_parameter'] and result['word_count'] <= 10:
        result['quality'] = 'enterprise_grade'
    elif result['has_desired_state'] and result['word_count'] <= 15:
        result['quality'] = 'good'
    elif result['word_count'] > 20:
        result['quality'] = 'too_verbose'
    else:
        result['quality'] = 'needs_improvement'
    
    return result

# Analyze all assertions
assertion_stats = defaultdict(list)
category_distribution = Counter()
quality_distribution = Counter()

for rule in rules:
    parts = rule.split('.')
    if len(parts) >= 4:
        service = parts[1]
        resource = parts[2]
        assertion = '.'.join(parts[3:])
        
        analysis = analyze_assertion(assertion)
        quality_distribution[analysis['quality']] += 1
        
        if analysis['security_category']:
            category_distribution[analysis['security_category']] += 1
        
        assertion_stats[analysis['quality']].append({
            'rule': rule,
            'service': service,
            'resource': resource,
            'assertion': assertion,
            'analysis': analysis
        })

print(f"\n{'=' * 100}")
print("ASSERTION QUALITY DISTRIBUTION")
print(f"{'=' * 100}")

for quality, count in quality_distribution.most_common():
    percentage = (count / len(rules)) * 100
    print(f"{quality:30s} {count:4d} rules ({percentage:5.1f}%)")

print(f"\n{'=' * 100}")
print("SECURITY CATEGORY DISTRIBUTION")
print(f"{'=' * 100}")

for category, count in category_distribution.most_common():
    percentage = (count / len(rules)) * 100
    print(f"{category:30s} {count:4d} rules ({percentage:5.1f}%)")

print(f"\n{'=' * 100}")
print("ENTERPRISE-GRADE ASSERTIONS (Examples)")
print(f"{'=' * 100}")

for item in assertion_stats['enterprise_grade'][:20]:
    print(f"\n✅ {item['service']:20s} | {item['resource']:25s}")
    print(f"   Assertion: {item['assertion']}")
    print(f"   Security: {item['analysis']['security_category']}")

print(f"\n{'=' * 100}")
print("NEEDS IMPROVEMENT (Examples)")
print(f"{'=' * 100}")

needs_improvement = assertion_stats.get('needs_improvement', [])
for item in needs_improvement[:15]:
    print(f"\n⚠️  {item['service']:20s} | {item['resource']:25s}")
    print(f"   Current: {item['assertion']}")
    print(f"   Issue: No clear desired state or parameter")

print(f"\n{'=' * 100}")
print("TOO VERBOSE ASSERTIONS (Examples)")
print(f"{'=' * 100}")

too_verbose = assertion_stats.get('too_verbose', [])
for item in too_verbose[:15]:
    print(f"\n⚠️  {item['service']:20s} | {item['resource']:25s}")
    print(f"   Current: {item['assertion']}")
    print(f"   Words: {item['analysis']['word_count']}")

# Identify patterns for improvement
print(f"\n{'=' * 100}")
print("IMPROVEMENT RECOMMENDATIONS")
print(f"{'=' * 100}")

print("""
CSPM ASSERTION BEST PRACTICES:

1. STRUCTURE: [security_domain]_[parameter]_[desired_state]
   ✅ Good: encryption_at_rest_enabled
   ✅ Good: mfa_required
   ✅ Good: public_access_blocked
   ❌ Bad: ensure_encryption_is_enabled_for_data

2. CLEAR DESIRED STATE:
   - Use: enabled, disabled, required, blocked, restricted, enforced
   - Avoid: should_be, must_have, needs_to_be

3. CONCISE:
   - Target: 3-6 words (separated by underscores)
   - Maximum: 10 words
   - Avoid: Repeating service/resource name in assertion

4. SECURITY DOMAIN PREFIX (Optional but recommended):
   - data_protection_
   - network_security_
   - identity_access_
   - compliance_

5. EXAMPLES OF ENTERPRISE-GRADE ASSERTIONS:
   ✅ encryption_at_rest_cmk_enabled
   ✅ mfa_required
   ✅ public_access_blocked
   ✅ tls_1_2_minimum_enforced
   ✅ logging_enabled
   ✅ backup_retention_configured
   ✅ deletion_protection_enabled
   ✅ network_isolation_enforced
   ✅ rbac_least_privilege_required
   ✅ audit_logging_enabled
""")

print(f"\n{'=' * 100}")
print("SUMMARY")
print(f"{'=' * 100}")
print(f"Total Rules: {len(rules)}")
print(f"Enterprise Grade: {quality_distribution.get('enterprise_grade', 0)} ({quality_distribution.get('enterprise_grade', 0)/len(rules)*100:.1f}%)")
print(f"Good Quality: {quality_distribution.get('good', 0)} ({quality_distribution.get('good', 0)/len(rules)*100:.1f}%)")
print(f"Needs Improvement: {quality_distribution.get('needs_improvement', 0)} ({quality_distribution.get('needs_improvement', 0)/len(rules)*100:.1f}%)")
print(f"Too Verbose: {quality_distribution.get('too_verbose', 0)} ({quality_distribution.get('too_verbose', 0)/len(rules)*100:.1f}%)")
print(f"\n{'=' * 100}")

