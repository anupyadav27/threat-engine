#!/usr/bin/env python3
"""
Identify and Fix Rules Where Resource Field Contains Assertions
700 rules have assertions in the resource field instead of actual OCI resources
"""

import yaml
from datetime import datetime
from collections import defaultdict, Counter
import re

# OCI Service to Default Resource Mapping
SERVICE_DEFAULT_RESOURCES = {
    'compute': 'instance',
    'database': 'autonomous_database',
    'object_storage': 'bucket',
    'block_storage': 'volume',
    'virtual_network': 'vcn',
    'load_balancer': 'load_balancer',
    'identity': 'user',
    'apigateway': 'gateway',
    'functions': 'application',
    'container_engine': 'cluster',
    'key_management': 'vault',
    'vault': 'secret',
    'monitoring': 'alarm',
    'logging': 'log_group',
    'audit': 'configuration',
    'cloud_guard': 'target',
    'file_storage': 'file_system',
    'dns': 'zone',
    'streaming': 'stream',
    'nosql': 'table',
    'mysql': 'db_system',
    'data_catalog': 'catalog',
    'data_science': 'project',
    'data_flow': 'application',
    'data_integration': 'workspace',
    'events': 'rule',
    'ons': 'topic',
    'queue': 'queue',
    'waf': 'web_app_firewall',
    'network_firewall': 'network_firewall',
    'analytics': 'analytics_instance',
    'devops': 'project',
    'resource_manager': 'stack',
    'certificates': 'certificate',
    'bds': 'bds_instance',
    'data_safe': 'data_safe_configuration',
    'edge_services': 'distribution',
    'redis': 'cluster',
    'ai_anomaly_detection': 'detector',
    'ai_language': 'project',
    'ai_vision': 'project',
}

# Keywords that indicate a field is an assertion, not a resource
ASSERTION_KEYWORDS = [
    'security', 'governance', 'compliance', 'privacy', 'threat',
    'resilience', 'incident', 'vulnerability', 'vuln', 'backup',
    'dr_', 'lineage', 'datalake', 'data_catalog', 'data_warehouse',
    'data_analytics', 'data_protection', 'data_governance',
    'machine_learning', 'ml_ops', 'ai_services', 'platform',
    'serverless', 'containers', 'network_', 'compute_',
    'identity_', 'logging_', 'monitoring_', 'streaming_',
    'cost_', 'supply_chain', 'paas_', 'configuration_management'
]

def is_assertion_like_resource(resource: str) -> bool:
    """Check if resource name looks like an assertion"""
    return any(keyword in resource.lower() for keyword in ASSERTION_KEYWORDS)

def extract_actual_resource_from_assertion(resource_assertion: str) -> str:
    """Try to extract actual resource name from assertion-like resource"""
    # Common patterns:
    # lineage_security_database_cross_account -> database
    # data_warehouse_security_endpoint_access -> endpoint
    # compute_security_instance_public_ip -> instance
    
    # Try to find resource keywords
    resource_keywords = [
        'database', 'instance', 'bucket', 'volume', 'cluster', 'table',
        'endpoint', 'function', 'application', 'gateway', 'listener',
        'user', 'group', 'policy', 'key', 'secret', 'vault', 'alarm',
        'log', 'rule', 'topic', 'queue', 'stream', 'zone', 'vcn',
        'subnet', 'certificate', 'project', 'workspace', 'catalog',
        'model', 'notebook', 'pipeline', 'stack', 'firewall'
    ]
    
    parts = resource_assertion.lower().split('_')
    for keyword in resource_keywords:
        if keyword in parts:
            return keyword
    
    return None

print("=" * 100)
print("RESOURCE vs ASSERTION MISALIGNMENT ANALYSIS")
print("=" * 100)

# Load rules
with open('rule_ids.yaml', 'r') as f:
    data = yaml.safe_load(f)

rules = data['rule_ids']
print(f"\nTotal Rules: {len(rules)}")

# Analyze misaligned rules
misaligned_rules = []
by_service = defaultdict(list)

for rule in rules:
    parts = rule.split('.')
    if len(parts) >= 4:
        service = parts[1]
        resource = parts[2]
        assertion = '.'.join(parts[3:])
        
        if is_assertion_like_resource(resource):
            misaligned_rules.append({
                'original': rule,
                'service': service,
                'resource': resource,
                'assertion': assertion
            })
            by_service[service].append(resource)

print(f"\nMisaligned Rules (assertion in resource field): {len(misaligned_rules)} ({len(misaligned_rules)/len(rules)*100:.1f}%)")

# Show breakdown by service
print(f"\n{'=' * 100}")
print("MISALIGNED RULES BY SERVICE")
print(f"{'=' * 100}")

service_counts = Counter({service: len(resources) for service, resources in by_service.items()})

for service, count in service_counts.most_common(20):
    percentage = (count / len([r for r in rules if r.split('.')[1] == service])) * 100
    print(f"{service:30s} {count:4d} misaligned ({percentage:5.1f}%)")

# Propose fixes
print(f"\n{'=' * 100}")
print("PROPOSED FIXES (Sample)")
print(f"{'=' * 100}")

fixes_proposed = 0
fix_examples = defaultdict(list)

for item in misaligned_rules[:50]:
    service = item['service']
    resource = item['resource']
    assertion = item['assertion']
    
    # Try to extract resource or use default
    extracted = extract_actual_resource_from_assertion(resource)
    if extracted:
        new_resource = extracted
    else:
        new_resource = SERVICE_DEFAULT_RESOURCES.get(service, 'resource')
    
    # Build new assertion: combine old resource + old assertion
    new_assertion = f"{resource}.{assertion}" if assertion else resource
    
    new_rule = f"oci.{service}.{new_resource}.{new_assertion}"
    
    if len(fix_examples[service]) < 3:
        fix_examples[service].append({
            'old': item['original'],
            'new': new_rule,
            'change': f"{resource} → {new_resource}"
        })
    
    fixes_proposed += 1

for service in sorted(fix_examples.keys())[:10]:
    print(f"\n{service.upper()}")
    print(f"{'─' * 100}")
    for example in fix_examples[service]:
        print(f"  Change: {example['change']}")
        print(f"  OLD: {example['old']}")
        print(f"  NEW: {example['new']}")
        print()

print(f"{'=' * 100}")
print("RECOMMENDATION")
print(f"{'=' * 100}")
print(f"""
The issue is that 700 rules have this WRONG format:
  oci.service.assertion_like_name.actual_assertion

They should have this CORRECT format:
  oci.service.actual_oci_resource.assertion

Solutions:
1. OPTION A: Move assertion-like resource into assertion field
   - oci.database.lineage_security_database_cross_account_sharing_restricted.cross_account_sharing_restricted
   → oci.database.autonomous_database.lineage_security_database_cross_account_sharing_restricted

2. OPTION B: Use generic 'resource' and keep full assertion
   - oci.database.lineage_security_database_cross_account_sharing_restricted.cross_account_sharing_restricted
   → oci.database.resource.lineage_security_database_cross_account_sharing_restricted

3. OPTION C: Intelligently extract resource from the assertion-like name
   - oci.database.data_warehouse_security_endpoint_access_private_only.endpoint_access_private_only_restricted
   → oci.database.endpoint.data_warehouse_security_endpoint_access_private_only_restricted

RECOMMENDATION: Use Option A (default resource) or Option C (extract resource) for best alignment.
""")

# Generate detailed report
report_data = {
    'total_rules': len(rules),
    'misaligned_rules': len(misaligned_rules),
    'by_service': {service: len(resources) for service, resources in by_service.items()},
    'examples': [item for item in misaligned_rules[:100]]
}

import json
with open('resource_misalignment_report.json', 'w') as f:
    json.dump(report_data, f, indent=2)

print(f"\n✅ Saved detailed report: resource_misalignment_report.json")
print(f"{'=' * 100}")

