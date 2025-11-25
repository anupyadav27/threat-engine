#!/usr/bin/env python3
"""
Phase 2: Analyze & Map Unknown Services
Deep analysis of the 232 unknown services to create proper OCI SDK mappings
"""

import yaml
import json
from collections import Counter, defaultdict

# Load current rules
with open('rule_ids.yaml', 'r') as f:
    data = yaml.safe_load(f)

rules = data['rule_ids']

# Load previous analysis
with open('oci_service_analysis.json', 'r') as f:
    service_analysis = json.load(f)

# Extract unknown services
unknown_services = {k: v for k, v in service_analysis.items() 
                   if v.get('status') == '❌ Unknown Service'}

print("=" * 100)
print("PHASE 2: UNKNOWN SERVICE ANALYSIS & MAPPING")
print("=" * 100)
print(f"\nTotal Unknown Services: {len(unknown_services)}")

# Categorize unknown services
categories = {
    'oci_prefixed': [],
    'oke_kubernetes': [],
    'cloud_providers': [],
    'composite_descriptive': [],
    'azure_specific': [],
    'gcp_specific': [],
    'aws_specific': [],
    'oracle_specific': [],
    'truly_unknown': []
}

for service in unknown_services.keys():
    if service.startswith('oci_'):
        categories['oci_prefixed'].append(service)
    elif service.startswith('oke_') or 'kubernetes' in service:
        categories['oke_kubernetes'].append(service)
    elif service in ['entra', 'defender', 'keyvault', 'cosmosdb', 'postgresql', 'sqlserver', 'vm']:
        categories['azure_specific'].append(service)
    elif service in ['bigquery', 'cloudsql', 'cloudstorage', 'gcr', 'dataproc', 'gcp']:
        categories['gcp_specific'].append(service)
    elif service in ['cloudtrail', 'awslambda', 'bedrock', 'athena', 'glue']:
        categories['aws_specific'].append(service)
    elif service.startswith('oracle_') or service.startswith('exadata_'):
        categories['oracle_specific'].append(service)
    elif '_' in service and len(service) > 20:
        categories['composite_descriptive'].append(service)
    else:
        categories['truly_unknown'].append(service)

# Display categorization
print(f"\n{'=' * 100}")
print("CATEGORIZATION")
print(f"{'=' * 100}")

for category, services in categories.items():
    if services:
        print(f"\n{category.replace('_', ' ').title()}: {len(services)} services")
        print("-" * 100)
        for service in sorted(services)[:10]:
            rule_count = unknown_services[service]['rules']
            resources = unknown_services[service]['resources'][:3]
            print(f"  {service:50s} {rule_count:3d} rules | Resources: {', '.join(resources)}")
        if len(services) > 10:
            print(f"  ... and {len(services) - 10} more")

# Generate mapping recommendations
print(f"\n{'=' * 100}")
print("MAPPING RECOMMENDATIONS")
print(f"{'=' * 100}")

mappings = {}

# 1. OCI Prefixed Services
print(f"\n1. OCI PREFIXED SERVICES ({len(categories['oci_prefixed'])} services)")
print("-" * 100)
for service in sorted(categories['oci_prefixed'])[:20]:
    # Try to infer mapping from service name
    if 'object_storage' in service:
        target = 'object_storage'
    elif 'api_gateway' in service:
        target = 'apigateway'
    elif 'streaming' in service:
        target = 'streaming'
    elif 'vault' in service or 'hsm' in service:
        target = 'key_management'
    elif 'nosql' in service:
        target = 'nosql'
    elif 'monitoring' in service or 'apm' in service:
        target = 'monitoring'
    elif 'notification' in service:
        target = 'ons'
    elif 'backup' in service:
        target = 'database'  # or appropriate service
    elif 'network' in service or 'load_balancer' in service:
        target = 'load_balancer' if 'load_balancer' in service else 'virtual_network'
    elif 'queue' in service:
        target = 'queue'
    elif 'recovery' in service:
        target = 'database'
    elif 'audit' in service:
        target = 'audit'
    elif 'vulnerability' in service or 'vss' in service:
        target = 'cloud_guard'
    elif 'tenancy' in service or 'compartment' in service:
        target = 'identity'
    elif 'usage' in service or 'budget' in service:
        target = 'identity'  # or usage_api
    elif 'media' in service:
        target = 'streaming'
    elif 'service_connector' in service:
        target = 'events'
    else:
        target = '❓ NEEDS_REVIEW'
    
    mappings[service] = target
    rule_count = unknown_services[service]['rules']
    print(f"  {service:60s} → {target:20s} ({rule_count} rules)")

if len(categories['oci_prefixed']) > 20:
    print(f"  ... and {len(categories['oci_prefixed']) - 20} more")

# 2. OKE/Kubernetes Services
print(f"\n2. OKE/KUBERNETES SERVICES ({len(categories['oke_kubernetes'])} services)")
print("-" * 100)
print("  ALL → container_engine")
for service in sorted(categories['oke_kubernetes'])[:15]:
    mappings[service] = 'container_engine'
    rule_count = unknown_services[service]['rules']
    print(f"  {service:60s} ({rule_count} rules)")
if len(categories['oke_kubernetes']) > 15:
    print(f"  ... and {len(categories['oke_kubernetes']) - 15} more")

# 3. Azure Services
if categories['azure_specific']:
    print(f"\n3. AZURE SERVICES ({len(categories['azure_specific'])} services)")
    print("-" * 100)
    azure_map = {
        'entra': 'identity',
        'defender': 'cloud_guard',
        'keyvault': 'key_management',
        'cosmosdb': 'database',
        'postgresql': 'mysql',
        'sqlserver': 'database',
        'vm': 'compute'
    }
    for service in sorted(categories['azure_specific']):
        target = azure_map.get(service, '❓ NEEDS_REVIEW')
        mappings[service] = target
        rule_count = unknown_services[service]['rules']
        print(f"  {service:60s} → {target:20s} ({rule_count} rules)")

# 4. GCP Services
if categories['gcp_specific']:
    print(f"\n4. GCP SERVICES ({len(categories['gcp_specific'])} services)")
    print("-" * 100)
    gcp_map = {
        'bigquery': 'analytics',
        'cloudsql': 'mysql',
        'cloudstorage': 'object_storage',
        'gcr': 'artifacts',
        'dataproc': 'bds'
    }
    for service in sorted(categories['gcp_specific']):
        target = gcp_map.get(service, '❓ NEEDS_REVIEW')
        mappings[service] = target
        rule_count = unknown_services[service]['rules']
        print(f"  {service:60s} → {target:20s} ({rule_count} rules)")

# 5. AWS Services (remaining)
if categories['aws_specific']:
    print(f"\n5. AWS SERVICES ({len(categories['aws_specific'])} services)")
    print("-" * 100)
    aws_map = {
        'cloudtrail': 'audit',
        'awslambda': 'functions',
        'bedrock': 'ai_language',
        'athena': 'analytics',
        'glue': 'data_catalog'
    }
    for service in sorted(categories['aws_specific']):
        target = aws_map.get(service, '❓ NEEDS_REVIEW')
        mappings[service] = target
        rule_count = unknown_services[service]['rules']
        print(f"  {service:60s} → {target:20s} ({rule_count} rules)")

# Save comprehensive mapping
comprehensive_mapping = {
    'phase_2_mappings': mappings,
    'categories': {k: v for k, v in categories.items() if v},
    'summary': {
        'total_unknown': len(unknown_services),
        'mapped': sum(1 for v in mappings.values() if v != '❓ NEEDS_REVIEW'),
        'needs_review': sum(1 for v in mappings.values() if v == '❓ NEEDS_REVIEW')
    }
}

with open('phase2_service_mappings.json', 'w') as f:
    json.dump(comprehensive_mapping, f, indent=2)

print(f"\n{'=' * 100}")
print("SUMMARY")
print(f"{'=' * 100}")
print(f"Total Unknown Services: {len(unknown_services)}")
print(f"Mapped: {comprehensive_mapping['summary']['mapped']}")
print(f"Needs Review: {comprehensive_mapping['summary']['needs_review']}")
print(f"\n✅ Saved: phase2_service_mappings.json")
print(f"{'=' * 100}")

