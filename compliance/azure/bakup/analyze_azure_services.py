#!/usr/bin/env python3
"""
Azure CSPM Rules - Service & Resource Analysis
Analyze alignment with Azure Python SDK (azure-sdk-for-python)
"""

import yaml
from collections import Counter, defaultdict
import json

# Azure Python SDK Service Mappings
# Based on: https://github.com/Azure/azure-sdk-for-python
AZURE_SDK_SERVICES = {
    # Core/Identity Services
    'active_directory': 'azure.identity / azure.graphrbac',
    'aad': 'azure.identity',  # Azure Active Directory
    'ad': 'azure.identity',
    
    # Compute
    'compute': 'azure.mgmt.compute.ComputeManagementClient',
    'vm': 'azure.mgmt.compute.ComputeManagementClient',
    'vmss': 'azure.mgmt.compute.ComputeManagementClient',
    
    # Storage
    'storage': 'azure.mgmt.storage.StorageManagementClient',
    'blob': 'azure.storage.blob.BlobServiceClient',
    'files': 'azure.storage.file.FileServiceClient',
    'queue': 'azure.storage.queue.QueueServiceClient',
    
    # Networking
    'network': 'azure.mgmt.network.NetworkManagementClient',
    'virtualnetwork': 'azure.mgmt.network.NetworkManagementClient',
    'vnet': 'azure.mgmt.network.NetworkManagementClient',
    'loadbalancer': 'azure.mgmt.network.NetworkManagementClient',
    'applicationgateway': 'azure.mgmt.network.NetworkManagementClient',
    
    # Databases
    'sql': 'azure.mgmt.sql.SqlManagementClient',
    'postgresql': 'azure.mgmt.rdbms.postgresql.PostgreSQLManagementClient',
    'mysql': 'azure.mgmt.rdbms.mysql.MySQLManagementClient',
    'cosmosdb': 'azure.mgmt.cosmosdb.CosmosDBManagementClient',
    'synapse': 'azure.mgmt.synapse.SynapseManagementClient',
    
    # Container Services
    'aks': 'azure.mgmt.containerservice.ContainerServiceClient',
    'containerregistry': 'azure.mgmt.containerregistry.ContainerRegistryManagementClient',
    'acr': 'azure.mgmt.containerregistry.ContainerRegistryManagementClient',
    
    # Security
    'keyvault': 'azure.mgmt.keyvault.KeyVaultManagementClient',
    'security': 'azure.mgmt.security.SecurityCenter',
    'securitycenter': 'azure.mgmt.security.SecurityCenter',
    
    # Monitoring & Logging
    'monitor': 'azure.mgmt.monitor.MonitorManagementClient',
    'loganalytics': 'azure.mgmt.loganalytics.LogAnalyticsManagementClient',
    'applicationinsights': 'azure.mgmt.applicationinsights.ApplicationInsightsManagementClient',
    
    # App Services
    'app': 'azure.mgmt.web.WebSiteManagementClient',
    'appservice': 'azure.mgmt.web.WebSiteManagementClient',
    'functionapp': 'azure.mgmt.web.WebSiteManagementClient',
    
    # API Management
    'api': 'azure.mgmt.apimanagement.ApiManagementClient',
    
    # Machine Learning
    'machinelearning': 'azure.mgmt.machinelearningservices.AzureMachineLearningWorkspaces',
    'ml': 'azure.mgmt.machinelearningservices.AzureMachineLearningWorkspaces',
    
    # Other Services
    'automation': 'azure.mgmt.automation.AutomationClient',
    'recovery': 'azure.mgmt.recoveryservices.RecoveryServicesClient',
    'backup': 'azure.mgmt.recoveryservicesbackup.RecoveryServicesBackupClient',
}

print("=" * 100)
print("AZURE CSPM RULES - SERVICE & RESOURCE ANALYSIS")
print("=" * 100)

# Load rules
with open('rule_ids.yaml', 'r') as f:
    data = yaml.safe_load(f)

rules = data['rule_ids']
print(f"\nTotal Rules: {len(rules)}")

# Analyze services and resources
service_analysis = defaultdict(lambda: {
    'count': 0,
    'resources': Counter(),
    'examples': [],
    'sdk_match': False,
    'sdk_client': None
})

malformed_rules = []

for rule in rules:
    parts = rule.split('.')
    if len(parts) >= 3:
        csp = parts[0]
        service = parts[1]
        resource = parts[2]
        assertion = '.'.join(parts[3:]) if len(parts) > 3 else ''
        
        service_analysis[service]['count'] += 1
        service_analysis[service]['resources'][resource] += 1
        
        if len(service_analysis[service]['examples']) < 3:
            service_analysis[service]['examples'].append(rule)
        
        # Check SDK match
        if service in AZURE_SDK_SERVICES:
            service_analysis[service]['sdk_match'] = True
            service_analysis[service]['sdk_client'] = AZURE_SDK_SERVICES[service]
    else:
        malformed_rules.append(rule)

# Categorize services
valid_azure_services = {}
needs_mapping = {}

for service, info in service_analysis.items():
    if info['sdk_match']:
        valid_azure_services[service] = info
    else:
        needs_mapping[service] = info

print(f"\n{'=' * 100}")
print("SERVICE CATEGORIZATION")
print(f"{'=' * 100}")
print(f"\n✅ Valid Azure SDK Services: {len(valid_azure_services)}")
print(f"❌ Services Needing Mapping: {len(needs_mapping)}")
print(f"⚠️  Malformed Rules: {len(malformed_rules)}")
print(f"\nTotal Unique Services: {len(service_analysis)}")

# Show valid services
print(f"\n{'=' * 100}")
print("VALID AZURE SDK SERVICES")
print(f"{'=' * 100}")

for service in sorted(valid_azure_services.keys(), 
                     key=lambda x: valid_azure_services[x]['count'], 
                     reverse=True)[:20]:
    info = valid_azure_services[service]
    print(f"\n{service.upper()}")
    print(f"{'─' * 100}")
    print(f"SDK Client: {info['sdk_client']}")
    print(f"Rules: {info['count']}")
    print(f"Unique Resources: {len(info['resources'])}")
    print(f"Top Resources: {', '.join([r for r, _ in info['resources'].most_common(5)])}")

# Show services needing mapping
print(f"\n{'=' * 100}")
print("SERVICES NEEDING AZURE SDK MAPPING (Top 40)")
print(f"{'=' * 100}")

for service in sorted(needs_mapping.keys(), 
                     key=lambda x: needs_mapping[x]['count'], 
                     reverse=True)[:40]:
    info = needs_mapping[service]
    print(f"\n❌ {service:50s} {info['count']:4d} rules")
    resources = ', '.join([r for r, _ in info['resources'].most_common(3)])
    print(f"   Resources: {resources[:80]}")
    if info['examples']:
        print(f"   Example: {info['examples'][0][:90]}")

# Analyze generic 'resource' usage
print(f"\n{'=' * 100}")
print("GENERIC 'resource' USAGE")
print(f"{'=' * 100}")

generic_count = 0
total = 0
for service, info in service_analysis.items():
    total += info['count']
    generic_count += info['resources'].get('resource', 0)

print(f"\nRules with generic 'resource': {generic_count} ({generic_count/total*100:.1f}%)")

# Generate JSON report
report = {
    'summary': {
        'total_rules': len(rules),
        'total_services': len(service_analysis),
        'valid_azure_services': len(valid_azure_services),
        'needs_mapping': len(needs_mapping),
        'malformed_rules': len(malformed_rules),
        'generic_resource_count': generic_count,
        'generic_resource_percentage': round(generic_count/total*100, 2) if total > 0 else 0
    },
    'valid_services': {
        service: {
            'sdk_client': info['sdk_client'],
            'rule_count': info['count'],
            'resources': dict(info['resources']),
            'examples': info['examples']
        }
        for service, info in valid_azure_services.items()
    },
    'needs_mapping': {
        service: {
            'rule_count': info['count'],
            'resources': dict(info['resources']),
            'examples': info['examples']
        }
        for service, info in needs_mapping.items()
    },
    'malformed_rules': malformed_rules
}

with open('azure_service_analysis.json', 'w') as f:
    json.dump(report, f, indent=2)

print(f"\n{'=' * 100}")
print("SUMMARY")
print(f"{'=' * 100}")
print(f"Total Rules:               {len(rules)}")
print(f"Malformed Rules:           {len(malformed_rules)}")
print(f"Total Services:            {len(service_analysis)}")
print(f"  ✅ Valid Azure SDK:      {len(valid_azure_services)} ({len(valid_azure_services)/len(service_analysis)*100:.1f}%)")
print(f"  ❌ Need Mapping:         {len(needs_mapping)} ({len(needs_mapping)/len(service_analysis)*100:.1f}%)")
print(f"\nGeneric 'resource':        {generic_count} rules ({generic_count/len(rules)*100:.1f}%)")
print(f"\n✅ Saved: azure_service_analysis.json")
print(f"{'=' * 100}")

