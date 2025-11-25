#!/usr/bin/env python3
"""
IBM Cloud CSPM Rules - Service & Resource Analysis
Analyze alignment with IBM Cloud Python SDK (ibm-cloud-sdk-python)
"""

import yaml
from collections import Counter, defaultdict
import json

# IBM Cloud Python SDK Service Mappings
# Based on: https://github.com/IBM/ibm-cloud-sdk-python
IBM_CLOUD_SDK_SERVICES = {
    # Core Infrastructure Services
    'iam': 'ibm_platform_services.IamIdentityV1',
    'resource_controller': 'ibm_platform_services.ResourceControllerV2',
    'resource_manager': 'ibm_platform_services.ResourceManagerV2',
    'account': 'ibm_platform_services.IamAccessGroupsV2',
    
    # Compute
    'vpc': 'ibm_vpc.VpcV1',
    'virtual_server': 'ibm_vpc.VpcV1',  # Part of VPC
    'bare_metal': 'ibm_vpc.VpcV1',  # Part of VPC
    'code_engine': 'ibm_code_engine.CodeEngineV2',
    'containers': 'ibm_container.ContainerV1',  # Kubernetes/OpenShift
    
    # Storage
    'object_storage': 'ibm_boto3.resource',  # IBM COS (S3-compatible)
    'block_storage': 'ibm_vpc.VpcV1',  # VPC Block Storage
    'file_storage': 'ibm_vpc.VpcV1',  # VPC File Storage
    'backup': 'ibm_backup_recovery.BackupRecoveryV1',  # IBM Backup Recovery
    
    # Networking
    'load_balancer': 'ibm_vpc.VpcV1',  # VPC Load Balancer
    'cdn': 'ibm_networking.DnsSvcsV1',  # CDN services
    'direct_link': 'ibm_networking.DirectLinkV1',
    'transit_gateway': 'ibm_networking.TransitGatewayApisV1',
    'dns': 'ibm_networking.DnsSvcsV1',  # DNS Services
    'internet_services': 'ibm_cis.CisV1',  # Cloud Internet Services
    
    # Security
    'secrets_manager': 'ibm_secrets_manager.SecretsManagerV2',
    'key_protect': 'ibm_key_protect.KeyProtectV2',
    'certificate_manager': 'ibm_certificate_manager.CertificateManagerV2',
    'security_advisor': 'ibm_security_advisor.FindingsV1',
    'security_compliance_center': 'ibm_scc.SecurityAndComplianceCenterV3',
    'app_id': 'ibm_appid.AppIDManagementV4',
    
    # Databases
    'cloudant': 'ibm_cloudant.CloudantV1',
    'databases': 'ibm_cloud_databases.CloudDatabasesV5',  # ICD (PostgreSQL, MySQL, etc.)
    'db2': 'ibm_db2.Db2SaasV1',
    
    # AI/ML
    'watson_assistant': 'ibm_watson.AssistantV2',
    'watson_discovery': 'ibm_watson.DiscoveryV2',
    'watson_ml': 'ibm_watson.WatsonMachineLearningV4',
    'watson_studio': 'ibm_watson.WatsonStudioV1',
    'watson_knowledge_catalog': 'ibm_watson.WatsonKnowledgeCatalogV3',
    'watson_openscale': 'ibm_watson.WatsonOpenScaleV2',
    
    # Logging & Monitoring
    'activity_tracker': 'ibm_platform_services.AtrackerV2',
    'log_analysis': 'ibm_logs.LogsV0',
    'monitoring': 'ibm_platform_services.MetricsRouterV3',
    'logdna': 'ibm_logs.LogsV0',  # IBM Log Analysis
    'sysdig': 'ibm_platform_services.MetricsRouterV3',  # IBM Monitoring
    'billing': 'ibm_platform_services.UsageReportsV4',  # Billing & Usage
    
    # API & Integration
    'api_gateway': 'ibm_apigw.APIGatewayV1',
    'event_streams': 'ibm_event_streams.AdminrestV1',  # Kafka
    'event_notifications': 'ibm_event_notifications.EventNotificationsV1',
    'app_connect': 'ibm_app_connect.AppConnectV1',
    
    # Container Registry
    'container_registry': 'ibm_container_registry.ContainerRegistryV1',
    
    # DevOps
    'continuous_delivery': 'ibm_continuous_delivery.CdToolchainV2',
    'schematics': 'ibm_schematics.SchematicsV1',  # Terraform-as-a-Service
    
    # Cloud Functions
    'functions': 'ibm_cloud_functions.CloudFunctionsV1',
    
    # Data & Analytics
    'data_virtualization': 'ibm_data_virtualization.DataVirtualizationV1',
    'datastage': 'ibm_datastage.DatastageV3',
    'analytics_engine': 'ibm_analytics_engine.AnalyticsEngineV3',
    'cognos_dashboard': 'ibm_cognos.CognosDashboardV1',
}

print("=" * 100)
print("IBM CLOUD CSPM RULES - SERVICE & RESOURCE ANALYSIS")
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
        if service in IBM_CLOUD_SDK_SERVICES:
            service_analysis[service]['sdk_match'] = True
            service_analysis[service]['sdk_client'] = IBM_CLOUD_SDK_SERVICES[service]

# Categorize services
valid_ibm_services = {}
needs_mapping = {}

for service, info in service_analysis.items():
    if info['sdk_match']:
        valid_ibm_services[service] = info
    else:
        needs_mapping[service] = info

print(f"\n{'=' * 100}")
print("SERVICE CATEGORIZATION")
print(f"{'=' * 100}")
print(f"\n✅ Valid IBM SDK Services: {len(valid_ibm_services)}")
print(f"❌ Services Needing Mapping: {len(needs_mapping)}")
print(f"\nTotal Unique Services: {len(service_analysis)}")

# Show valid services
print(f"\n{'=' * 100}")
print("VALID IBM CLOUD SDK SERVICES")
print(f"{'=' * 100}")

for service in sorted(valid_ibm_services.keys(), 
                     key=lambda x: valid_ibm_services[x]['count'], 
                     reverse=True):
    info = valid_ibm_services[service]
    print(f"\n{service.upper()}")
    print(f"{'─' * 100}")
    print(f"SDK Client: {info['sdk_client']}")
    print(f"Rules: {info['count']}")
    print(f"Unique Resources: {len(info['resources'])}")
    print(f"Top Resources: {', '.join([r for r, _ in info['resources'].most_common(5)])}")

# Show services needing mapping
print(f"\n{'=' * 100}")
print("SERVICES NEEDING IBM SDK MAPPING")
print(f"{'=' * 100}")

for service in sorted(needs_mapping.keys(), 
                     key=lambda x: needs_mapping[x]['count'], 
                     reverse=True)[:30]:
    info = needs_mapping[service]
    print(f"\n❌ {service:40s} {info['count']:4d} rules")
    resources = ', '.join([r for r, _ in info['resources'].most_common(3)])
    print(f"   Resources: {resources[:80]}")
    print(f"   Example: {info['examples'][0]}")

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
        'valid_ibm_services': len(valid_ibm_services),
        'needs_mapping': len(needs_mapping),
        'generic_resource_count': generic_count,
        'generic_resource_percentage': round(generic_count/total*100, 2)
    },
    'valid_services': {
        service: {
            'sdk_client': info['sdk_client'],
            'rule_count': info['count'],
            'resources': dict(info['resources']),
            'examples': info['examples']
        }
        for service, info in valid_ibm_services.items()
    },
    'needs_mapping': {
        service: {
            'rule_count': info['count'],
            'resources': dict(info['resources']),
            'examples': info['examples']
        }
        for service, info in needs_mapping.items()
    }
}

with open('ibm_service_analysis.json', 'w') as f:
    json.dump(report, f, indent=2)

print(f"\n{'=' * 100}")
print("SUMMARY")
print(f"{'=' * 100}")
print(f"Total Rules:               {len(rules)}")
print(f"Total Services:            {len(service_analysis)}")
print(f"  ✅ Valid IBM SDK:        {len(valid_ibm_services)} ({len(valid_ibm_services)/len(service_analysis)*100:.1f}%)")
print(f"  ❌ Need Mapping:         {len(needs_mapping)} ({len(needs_mapping)/len(service_analysis)*100:.1f}%)")
print(f"\nGeneric 'resource':        {generic_count} rules ({generic_count/len(rules)*100:.1f}%)")
print(f"\n✅ Saved: ibm_service_analysis.json")
print(f"{'=' * 100}")

