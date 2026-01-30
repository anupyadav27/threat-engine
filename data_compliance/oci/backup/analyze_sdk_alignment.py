#!/usr/bin/env python3
"""
Analyze OCI Services & Resources Alignment with OCI Python SDK
Validates service and resource names against official OCI Python SDK clients
"""

import yaml
from collections import defaultdict, Counter
import json

# Official OCI Python SDK Service Clients
OCI_PYTHON_SDK_SERVICES = {
    'analytics': 'oci.analytics.AnalyticsClient',
    'apigateway': 'oci.apigateway.ApiGatewayClient',
    'artifacts': 'oci.artifacts.ArtifactsClient',
    'audit': 'oci.audit.AuditClient',
    'autoscaling': 'oci.autoscaling.AutoScalingClient',
    'bastion': 'oci.bastion.BastionClient',
    'bds': 'oci.bds.BdsClient',
    'blockchain': 'oci.blockchain.BlockchainPlatformClient',
    'budget': 'oci.budget.BudgetClient',
    'certificates': 'oci.certificates.CertificatesClient',
    'certificates_management': 'oci.certificates_management.CertificatesManagementClient',
    'cloud_guard': 'oci.cloud_guard.CloudGuardClient',
    'container_engine': 'oci.container_engine.ContainerEngineClient',
    'container_instances': 'oci.container_instances.ContainerInstanceClient',
    'core': 'oci.core.ComputeClient',
    'compute': 'oci.core.ComputeClient',
    'block_storage': 'oci.core.BlockstorageClient',
    'virtual_network': 'oci.core.VirtualNetworkClient',
    'data_catalog': 'oci.data_catalog.DataCatalogClient',
    'data_flow': 'oci.data_flow.DataFlowClient',
    'data_integration': 'oci.data_integration.DataIntegrationClient',
    'data_safe': 'oci.data_safe.DataSafeClient',
    'data_science': 'oci.data_science.DataScienceClient',
    'database': 'oci.database.DatabaseClient',
    'devops': 'oci.devops.DevopsClient',
    'dns': 'oci.dns.DnsClient',
    'edge_services': 'oci.waas.WaasClient',  # CDN/Edge is part of WAAS
    'email': 'oci.email.EmailClient',
    'events': 'oci.events.EventsClient',
    'file_storage': 'oci.file_storage.FileStorageClient',
    'functions': 'oci.functions.FunctionsManagementClient',
    'identity': 'oci.identity.IdentityClient',
    'integration': 'oci.integration.IntegrationInstanceClient',
    'key_management': 'oci.key_management.KmsVaultClient',
    'limits': 'oci.limits.LimitsClient',
    'load_balancer': 'oci.load_balancer.LoadBalancerClient',
    'logging': 'oci.logging.LoggingManagementClient',
    'monitoring': 'oci.monitoring.MonitoringClient',
    'mysql': 'oci.mysql.DbSystemClient',
    'network_firewall': 'oci.network_firewall.NetworkFirewallClient',
    'nosql': 'oci.nosql.NosqlClient',
    'object_storage': 'oci.object_storage.ObjectStorageClient',
    'ons': 'oci.ons.NotificationControlPlaneClient',
    'queue': 'oci.queue.QueueAdminClient',
    'resource_manager': 'oci.resource_manager.ResourceManagerClient',
    'streaming': 'oci.streaming.StreamAdminClient',
    'vault': 'oci.vault.VaultsClient',
    'waf': 'oci.waf.WafClient',
    'ai_language': 'oci.ai_language.AIServiceLanguageClient',
    'ai_vision': 'oci.ai_vision.AIServiceVisionClient',
    'ai_anomaly_detection': 'oci.ai_anomaly_detection.AnomalyDetectionClient',
    'redis': 'oci.redis.RedisClusterClient',
}

# Common OCI Resources by Service
OCI_SERVICE_RESOURCES = {
    'compute': ['instance', 'image', 'boot_volume_attachment', 'volume_attachment', 'vnic_attachment'],
    'block_storage': ['volume', 'boot_volume', 'volume_backup', 'volume_group'],
    'virtual_network': ['vcn', 'subnet', 'security_list', 'route_table', 'internet_gateway', 
                        'nat_gateway', 'service_gateway', 'drg', 'local_peering_gateway', 
                        'remote_peering_connection', 'network_security_group', 'vnic'],
    'object_storage': ['bucket', 'object', 'namespace', 'replication_policy'],
    'database': ['db_system', 'autonomous_database', 'db_home', 'database', 'backup', 'pluggable_database'],
    'load_balancer': ['load_balancer', 'backend_set', 'backend', 'listener', 'certificate'],
    'identity': ['user', 'group', 'policy', 'compartment', 'dynamic_group', 'network_source', 
                 'tag_namespace', 'tag', 'domain'],
    'apigateway': ['gateway', 'deployment', 'api', 'certificate'],
    'functions': ['application', 'function', 'invoke'],
    'container_engine': ['cluster', 'node_pool', 'workload', 'addon'],
    'key_management': ['vault', 'key', 'key_version'],
    'vault': ['secret', 'secret_version'],
    'monitoring': ['alarm', 'metric', 'alarm_suppression'],
    'logging': ['log_group', 'log', 'unified_agent_configuration'],
    'audit': ['configuration', 'event'],
    'cloud_guard': ['detector_recipe', 'target', 'responder_recipe', 'managed_list', 'detector_rule'],
    'file_storage': ['file_system', 'mount_target', 'export', 'snapshot'],
    'dns': ['zone', 'record', 'steering_policy', 'tsig_key'],
    'streaming': ['stream', 'stream_pool', 'connect_harness'],
    'nosql': ['table', 'index', 'row'],
    'mysql': ['db_system', 'backup', 'configuration', 'channel'],
    'data_catalog': ['catalog', 'data_asset', 'connection', 'entity', 'attribute'],
    'data_science': ['project', 'notebook_session', 'model', 'model_deployment', 'job', 'job_run'],
    'data_flow': ['application', 'run', 'private_endpoint'],
    'data_integration': ['workspace', 'project', 'application', 'pipeline', 'task', 'data_flow'],
    'events': ['rule', 'action'],
    'ons': ['topic', 'subscription'],
    'queue': ['queue'],
    'waf': ['web_app_firewall', 'web_app_firewall_policy', 'protection_rule'],
    'network_firewall': ['network_firewall', 'network_firewall_policy'],
    'analytics': ['analytics_instance', 'vanity_url'],
    'devops': ['project', 'repository', 'build_pipeline', 'deployment_pipeline', 'deploy_artifact'],
    'resource_manager': ['stack', 'job', 'configuration_source_provider'],
    'certificates': ['certificate', 'certificate_authority', 'ca_bundle'],
    'bds': ['bds_instance', 'api_key', 'metastore_configuration'],
}

print("=" * 100)
print("OCI SERVICES & RESOURCES - PYTHON SDK ALIGNMENT ANALYSIS")
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
    if len(parts) >= 4:
        csp = parts[0]
        service = parts[1]
        resource = parts[2]
        assertion = '.'.join(parts[3:])
        
        service_analysis[service]['count'] += 1
        service_analysis[service]['resources'][resource] += 1
        
        if len(service_analysis[service]['examples']) < 3:
            service_analysis[service]['examples'].append(rule)
        
        # Check SDK match
        if service in OCI_PYTHON_SDK_SERVICES:
            service_analysis[service]['sdk_match'] = True
            service_analysis[service]['sdk_client'] = OCI_PYTHON_SDK_SERVICES[service]

# Categorize services
valid_oci_services = {}
invalid_services = {}

for service, info in service_analysis.items():
    if info['sdk_match']:
        valid_oci_services[service] = info
    else:
        invalid_services[service] = info

print(f"\n{'=' * 100}")
print("SERVICE CATEGORIZATION")
print(f"{'=' * 100}")
print(f"\n✅ Valid OCI SDK Services: {len(valid_oci_services)}")
print(f"❌ Invalid/Non-SDK Services: {len(invalid_services)}")

# Detailed analysis of valid services
print(f"\n{'=' * 100}")
print("VALID OCI SERVICES - RESOURCE ALIGNMENT")
print(f"{'=' * 100}")

resource_issues = []

for service in sorted(valid_oci_services.keys(), key=lambda x: valid_oci_services[x]['count'], reverse=True):
    info = valid_oci_services[service]
    print(f"\n{service.upper()}")
    print(f"{'─' * 100}")
    print(f"SDK Client: {info['sdk_client']}")
    print(f"Rules: {info['count']}")
    print(f"Unique Resources: {len(info['resources'])}")
    
    # Check if resources match expected OCI resources
    expected_resources = OCI_SERVICE_RESOURCES.get(service, [])
    actual_resources = list(info['resources'].keys())
    
    print(f"\nTop Resources:")
    for resource, count in info['resources'].most_common(10):
        status = "✅" if resource in expected_resources or resource == "resource" else "⚠️"
        print(f"  {status} {resource:50s} {count:4d} rules")
        
        if resource not in expected_resources and resource != "resource":
            resource_issues.append({
                'service': service,
                'resource': resource,
                'count': count,
                'expected': expected_resources
            })

# Invalid services analysis
if invalid_services:
    print(f"\n{'=' * 100}")
    print("INVALID/NON-SDK SERVICES (NEED MAPPING)")
    print(f"{'=' * 100}")
    
    for service in sorted(invalid_services.keys(), key=lambda x: invalid_services[x]['count'], reverse=True)[:20]:
        info = invalid_services[service]
        print(f"\n❌ {service:50s} {info['count']:4d} rules")
        top_resources = ', '.join([r for r, _ in info['resources'].most_common(3)])
        print(f"   Resources: {top_resources[:80]}")
        print(f"   Example: {info['examples'][0]}")

# Resource issues summary
if resource_issues:
    print(f"\n{'=' * 100}")
    print("RESOURCE NAMING ISSUES")
    print(f"{'=' * 100}")
    print(f"\nFound {len(resource_issues)} resources that don't match OCI SDK conventions:")
    
    resource_issue_summary = Counter()
    for issue in resource_issues:
        resource_issue_summary[issue['resource']] += issue['count']
    
    print(f"\nTop 20 Non-standard Resources:")
    for resource, count in resource_issue_summary.most_common(20):
        print(f"  {resource:60s} {count:4d} rules")

# Generic "resource" analysis
print(f"\n{'=' * 100}")
print("GENERIC 'resource' USAGE ANALYSIS")
print(f"{'=' * 100}")

generic_resource_count = 0
total_rules = 0
generic_by_service = []

for service, info in valid_oci_services.items():
    total_rules += info['count']
    generic_count = info['resources'].get('resource', 0)
    if generic_count > 0:
        generic_resource_count += generic_count
        generic_by_service.append((service, generic_count, info['count']))

print(f"\nTotal Rules with Generic 'resource': {generic_resource_count} ({generic_resource_count/total_rules*100:.1f}%)")
print(f"\nServices with Most Generic 'resource' Usage:")

for service, generic, total in sorted(generic_by_service, key=lambda x: x[1], reverse=True)[:15]:
    percentage = (generic / total) * 100
    print(f"  {service:40s} {generic:4d}/{total:4d} rules ({percentage:5.1f}%)")

# Generate JSON report
report = {
    'summary': {
        'total_rules': len(rules),
        'total_services': len(service_analysis),
        'valid_oci_services': len(valid_oci_services),
        'invalid_services': len(invalid_services),
        'generic_resource_count': generic_resource_count,
        'generic_resource_percentage': round(generic_resource_count/total_rules*100, 2)
    },
    'valid_services': {
        service: {
            'sdk_client': info['sdk_client'],
            'rule_count': info['count'],
            'resources': dict(info['resources']),
            'examples': info['examples']
        }
        for service, info in valid_oci_services.items()
    },
    'invalid_services': {
        service: {
            'rule_count': info['count'],
            'resources': dict(info['resources']),
            'examples': info['examples']
        }
        for service, info in invalid_services.items()
    },
    'resource_issues': resource_issues
}

with open('oci_sdk_alignment_analysis.json', 'w') as f:
    json.dump(report, f, indent=2)

print(f"\n{'=' * 100}")
print("SUMMARY")
print(f"{'=' * 100}")
print(f"Total Rules:              {len(rules)}")
print(f"Total Services:           {len(service_analysis)}")
print(f"  ✅ Valid OCI SDK:       {len(valid_oci_services)} ({len(valid_oci_services)/len(service_analysis)*100:.1f}%)")
print(f"  ❌ Invalid/Non-SDK:     {len(invalid_services)} ({len(invalid_services)/len(service_analysis)*100:.1f}%)")
print(f"\nGeneric 'resource':       {generic_resource_count} rules ({generic_resource_count/len(rules)*100:.1f}%)")
print(f"Non-standard Resources:   {len(resource_issues)} unique resources")
print(f"\n✅ Saved: oci_sdk_alignment_analysis.json")
print(f"{'=' * 100}")

