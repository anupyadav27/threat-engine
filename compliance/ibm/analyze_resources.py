#!/usr/bin/env python3
"""
Analyze IBM Cloud Resources
Identify resources that need normalization to IBM SDK types
"""

import yaml
from collections import Counter, defaultdict
import json

print("=" * 100)
print("IBM CLOUD RESOURCE ANALYSIS")
print("=" * 100)

# Load rules
with open('rule_ids.yaml', 'r') as f:
    data = yaml.safe_load(f)

rules = data['rule_ids']
print(f"\nTotal Rules: {len(rules)}")

# Analyze resources by service
service_resources = defaultdict(lambda: Counter())
resource_usage = Counter()

for rule in rules:
    parts = rule.split('.')
    if len(parts) >= 3:
        service = parts[1]
        resource = parts[2]
        
        service_resources[service][resource] += 1
        resource_usage[resource] += 1

# Generic 'resource' usage
generic_resources = []
for rule in rules:
    parts = rule.split('.')
    if len(parts) >= 3 and parts[2] == 'resource':
        generic_resources.append(rule)

print(f"\n{'=' * 100}")
print("RESOURCE SUMMARY")
print(f"{'=' * 100}")
print(f"Total Unique Resources: {len(resource_usage)}")
print(f"Generic 'resource' entries: {resource_usage['resource']} ({resource_usage['resource']/len(rules)*100:.1f}%)")

# Top resources
print(f"\n{'=' * 100}")
print("TOP 30 MOST USED RESOURCES")
print(f"{'=' * 100}")
for resource, count in resource_usage.most_common(30):
    print(f"{resource:60s} {count:4d} rules")

# Resources by service
print(f"\n{'=' * 100}")
print("RESOURCES BY SERVICE (Top 15 services)")
print(f"{'=' * 100}")

for service in sorted(service_resources.keys(), 
                     key=lambda x: sum(service_resources[x].values()), 
                     reverse=True)[:15]:
    resources = service_resources[service]
    print(f"\n{service.upper()} ({sum(resources.values())} rules)")
    print(f"{'─' * 100}")
    for resource, count in resources.most_common(10):
        print(f"  {resource:58s} {count:4d} rules")

# Identify problematic resource names
print(f"\n{'=' * 100}")
print("RESOURCES NEEDING NORMALIZATION")
print(f"{'=' * 100}")

# Resources that look like assertions (contain verbs, very long names, etc.)
assertion_like = []
for resource in resource_usage.keys():
    # Check if resource name looks like an assertion
    if ('_enabled' in resource or '_disabled' in resource or 
        '_required' in resource or '_configured' in resource or
        '_protected' in resource or '_blocked' in resource or
        len(resource.split('_')) > 5):
        assertion_like.append(resource)

print(f"\nAssertion-like resources: {len(assertion_like)}")
for resource in sorted(assertion_like, key=lambda x: resource_usage[x], reverse=True)[:20]:
    print(f"  {resource:60s} {resource_usage[resource]:4d} rules")

# Generic resources
print(f"\n{'=' * 100}")
print("GENERIC 'resource' ENTRIES (Need specific resource types)")
print(f"{'=' * 100}")
print(f"Total: {len(generic_resources)} rules ({len(generic_resources)/len(rules)*100:.1f}%)")
print("\nExamples:")
for rule in generic_resources[:10]:
    print(f"  {rule}")

# Save detailed report
report = {
    'total_rules': len(rules),
    'total_unique_resources': len(resource_usage),
    'generic_resource_count': resource_usage['resource'],
    'assertion_like_resources': len(assertion_like),
    'resource_usage': dict(resource_usage),
    'service_resources': {
        service: dict(resources) 
        for service, resources in service_resources.items()
    },
    'generic_resource_examples': generic_resources[:50]
}

with open('ibm_resource_analysis.json', 'w') as f:
    json.dump(report, f, indent=2)

print(f"\n{'=' * 100}")
print("ANALYSIS COMPLETE")
print(f"{'=' * 100}")
print(f"✅ Saved: ibm_resource_analysis.json")
print(f"{'=' * 100}")

