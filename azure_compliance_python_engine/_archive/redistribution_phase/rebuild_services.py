#!/usr/bin/env python3
"""
Rebuild Azure Services Folder from rule_ids_ENRICHED_AI_ENHANCED.yaml
This script:
1. Extracts all services from the rules YAML
2. Maps them to Azure SDK packages and clients
3. Creates organized service folders with metadata
4. Generates rules YAML with proper Azure structure
"""

import yaml
import os
import shutil
from pathlib import Path
from collections import defaultdict
import json

# Service to Package/Client mapping (from our planning)
SERVICE_MAPPING = {
    # Core Management
    'resource': {'package': 'azure-mgmt-resource', 'client': 'ResourceManagementClient', 'group': 'core_management'},
    'subscription': {'package': 'azure-mgmt-subscription', 'client': 'SubscriptionClient', 'group': 'core_management'},
    'managementgroup': {'package': 'azure-mgmt-managementgroups', 'client': 'ManagementGroupsAPI', 'group': 'core_management'},
    'management': {'package': 'azure-mgmt-managementgroups', 'client': 'ManagementGroupsAPI', 'group': 'core_management'},
    'policy': {'package': 'azure-mgmt-resource', 'client': 'PolicyClient', 'group': 'core_management'},
    'rbac': {'package': 'azure-mgmt-authorization', 'client': 'AuthorizationManagementClient', 'group': 'core_management'},
    
    # Compute & Containers
    'compute': {'package': 'azure-mgmt-compute', 'client': 'ComputeManagementClient', 'group': 'compute'},
    'vm': {'package': 'azure-mgmt-compute', 'client': 'ComputeManagementClient', 'group': 'compute', 'consolidate_to': 'compute'},
    'virtualmachines': {'package': 'azure-mgmt-compute', 'client': 'ComputeManagementClient', 'group': 'compute', 'consolidate_to': 'compute'},
    'disk': {'package': 'azure-mgmt-compute', 'client': 'ComputeManagementClient', 'group': 'compute', 'consolidate_to': 'compute'},
    'aks': {'package': 'azure-mgmt-containerservice', 'client': 'ContainerServiceClient', 'group': 'containers'},
    'kubernetes': {'package': 'azure-mgmt-containerservice', 'client': 'ContainerServiceClient', 'group': 'containers', 'consolidate_to': 'aks'},
    'container': {'package': 'azure-mgmt-containerinstance', 'client': 'ContainerInstanceManagementClient', 'group': 'containers'},
    'containerregistry': {'package': 'azure-mgmt-containerregistry', 'client': 'ContainerRegistryManagementClient', 'group': 'containers'},
    
    # Storage
    'storage': {'package': 'azure-mgmt-storage', 'client': 'StorageManagementClient', 'group': 'storage'},
    'blob': {'package': 'azure-storage-blob', 'client': 'BlobServiceClient', 'group': 'storage', 'data_plane': True},
    'files': {'package': 'azure-storage-file-share', 'client': 'ShareServiceClient', 'group': 'storage', 'data_plane': True},
    
    # Networking
    'network': {'package': 'azure-mgmt-network', 'client': 'NetworkManagementClient', 'group': 'networking'},
    'networksecuritygroup': {'package': 'azure-mgmt-network', 'client': 'NetworkManagementClient', 'group': 'networking', 'consolidate_to': 'network'},
    'vpn': {'package': 'azure-mgmt-network', 'client': 'NetworkManagementClient', 'group': 'networking', 'consolidate_to': 'network'},
    'loadbalancer': {'package': 'azure-mgmt-network', 'client': 'NetworkManagementClient', 'group': 'networking', 'consolidate_to': 'network'},
    'load': {'package': 'azure-mgmt-network', 'client': 'NetworkManagementClient', 'group': 'networking', 'consolidate_to': 'network'},
    'dns': {'package': 'azure-mgmt-dns', 'client': 'DnsManagementClient', 'group': 'networking'},
    'cdn': {'package': 'azure-mgmt-cdn', 'client': 'CdnManagementClient', 'group': 'networking'},
    'front': {'package': 'azure-mgmt-frontdoor', 'client': 'FrontDoorManagementClient', 'group': 'networking'},
    'traffic': {'package': 'azure-mgmt-trafficmanager', 'client': 'TrafficManagerManagementClient', 'group': 'networking'},
    
    # Databases
    'sql': {'package': 'azure-mgmt-sql', 'client': 'SqlManagementClient', 'group': 'databases'},
    'sqlserver': {'package': 'azure-mgmt-sql', 'client': 'SqlManagementClient', 'group': 'databases', 'consolidate_to': 'sql'},
    'mysql': {'package': 'azure-mgmt-rdbms', 'client': 'MySQLManagementClient', 'group': 'databases'},
    'postgresql': {'package': 'azure-mgmt-rdbms', 'client': 'PostgreSQLManagementClient', 'group': 'databases'},
    'mariadb': {'package': 'azure-mgmt-rdbms', 'client': 'MariaDBManagementClient', 'group': 'databases'},
    'cosmosdb': {'package': 'azure-mgmt-cosmosdb', 'client': 'CosmosDBManagementClient', 'group': 'databases'},
    'cosmos': {'package': 'azure-mgmt-cosmosdb', 'client': 'CosmosDBManagementClient', 'group': 'databases', 'consolidate_to': 'cosmosdb'},
    'redis': {'package': 'azure-mgmt-redis', 'client': 'RedisManagementClient', 'group': 'databases'},
    'cache': {'package': 'azure-mgmt-redis', 'client': 'RedisManagementClient', 'group': 'databases', 'consolidate_to': 'redis'},
    
    # Identity & Security (Microsoft Graph)
    'aad': {'package': 'msgraph-sdk', 'client': 'GraphServiceClient', 'group': 'identity', 'graph_based': True},
    'ad': {'package': 'msgraph-sdk', 'client': 'GraphServiceClient', 'group': 'identity', 'graph_based': True, 'consolidate_to': 'aad'},
    'entra': {'package': 'msgraph-sdk', 'client': 'GraphServiceClient', 'group': 'identity', 'graph_based': True, 'consolidate_to': 'aad'},
    'entrad': {'package': 'msgraph-sdk', 'client': 'GraphServiceClient', 'group': 'identity', 'graph_based': True, 'consolidate_to': 'aad'},
    'graph': {'package': 'msgraph-sdk', 'client': 'GraphServiceClient', 'group': 'identity', 'graph_based': True, 'consolidate_to': 'aad'},
    'intune': {'package': 'msgraph-sdk', 'client': 'GraphServiceClient', 'group': 'identity', 'graph_based': True},
    'iam': {'package': 'azure-mgmt-authorization', 'client': 'AuthorizationManagementClient', 'group': 'identity'},
    
    # Security & Monitoring
    'security': {'package': 'azure-mgmt-security', 'client': 'SecurityCenter', 'group': 'security'},
    'securitycenter': {'package': 'azure-mgmt-security', 'client': 'SecurityCenter', 'group': 'security', 'consolidate_to': 'security'},
    'defender': {'package': 'azure-mgmt-security', 'client': 'SecurityCenter', 'group': 'security', 'consolidate_to': 'security'},
    'monitor': {'package': 'azure-mgmt-monitor', 'client': 'MonitorManagementClient', 'group': 'monitoring'},
    'log': {'package': 'azure-mgmt-loganalytics', 'client': 'LogAnalyticsManagementClient', 'group': 'monitoring'},
    
    # Key Vault
    'keyvault': {'package': 'azure-mgmt-keyvault', 'client': 'KeyVaultManagementClient', 'group': 'keyvault'},
    'key': {'package': 'azure-keyvault-keys', 'client': 'KeyClient', 'group': 'keyvault', 'data_plane': True},
    'certificates': {'package': 'azure-keyvault-certificates', 'client': 'CertificateClient', 'group': 'keyvault', 'data_plane': True},
    
    # App Services
    'app': {'package': 'azure-mgmt-web', 'client': 'WebSiteManagementClient', 'group': 'web_services', 'consolidate_to': 'webapp'},
    'appservice': {'package': 'azure-mgmt-web', 'client': 'WebSiteManagementClient', 'group': 'web_services', 'consolidate_to': 'webapp'},
    'webapp': {'package': 'azure-mgmt-web', 'client': 'WebSiteManagementClient', 'group': 'web_services'},
    'function': {'package': 'azure-mgmt-web', 'client': 'WebSiteManagementClient', 'group': 'web_services'},
    'functionapp': {'package': 'azure-mgmt-web', 'client': 'WebSiteManagementClient', 'group': 'web_services', 'consolidate_to': 'function'},
    'functions': {'package': 'azure-mgmt-web', 'client': 'WebSiteManagementClient', 'group': 'web_services', 'consolidate_to': 'function'},
    'site': {'package': 'azure-mgmt-web', 'client': 'WebSiteManagementClient', 'group': 'web_services', 'consolidate_to': 'webapp'},
    'application': {'package': 'azure-mgmt-web', 'client': 'WebSiteManagementClient', 'group': 'web_services', 'consolidate_to': 'webapp'},
    'api': {'package': 'azure-mgmt-apimanagement', 'client': 'ApiManagementClient', 'group': 'web_services'},
    'logic': {'package': 'azure-mgmt-logic', 'client': 'LogicManagementClient', 'group': 'web_services'},
    
    # Data & Analytics
    'data': {'package': 'azure-mgmt-datafactory', 'client': 'DataFactoryManagementClient', 'group': 'analytics'},
    'databricks': {'package': 'azure-mgmt-databricks', 'client': 'AzureDatabricksManagementClient', 'group': 'analytics'},
    'synapse': {'package': 'azure-mgmt-synapse', 'client': 'SynapseManagementClient', 'group': 'analytics'},
    'hdinsight': {'package': 'azure-mgmt-hdinsight', 'client': 'HDInsightManagementClient', 'group': 'analytics'},
    'search': {'package': 'azure-mgmt-search', 'client': 'SearchManagementClient', 'group': 'analytics'},
    'aisearch': {'package': 'azure-mgmt-search', 'client': 'SearchManagementClient', 'group': 'analytics', 'consolidate_to': 'search'},
    'purview': {'package': 'azure-mgmt-purview', 'client': 'PurviewManagementClient', 'group': 'analytics'},
    'machine': {'package': 'azure-mgmt-machinelearningservices', 'client': 'MachineLearningServicesManagementClient', 'group': 'analytics'},
    
    # Backup & Recovery
    'backup': {'package': 'azure-mgmt-recoveryservices', 'client': 'RecoveryServicesClient', 'group': 'backup'},
    'recoveryservices': {'package': 'azure-mgmt-recoveryservices', 'client': 'RecoveryServicesClient', 'group': 'backup', 'consolidate_to': 'backup'},
    'dataprotection': {'package': 'azure-mgmt-dataprotection', 'client': 'DataProtectionClient', 'group': 'backup'},
    
    # Other Services
    'automation': {'package': 'azure-mgmt-automation', 'client': 'AutomationClient', 'group': 'other'},
    'patch': {'package': 'azure-mgmt-automation', 'client': 'AutomationClient', 'group': 'other', 'consolidate_to': 'automation'},
    'batch': {'package': 'azure-mgmt-batch', 'client': 'BatchManagementClient', 'group': 'other'},
    'billing': {'package': 'azure-mgmt-billing', 'client': 'BillingManagementClient', 'group': 'other'},
    'cost': {'package': 'azure-mgmt-costmanagement', 'client': 'CostManagementClient', 'group': 'other'},
    'event': {'package': 'azure-mgmt-eventgrid', 'client': 'EventGridManagementClient', 'group': 'other'},
    'iot': {'package': 'azure-mgmt-iothub', 'client': 'IotHubClient', 'group': 'other'},
    'notification': {'package': 'azure-mgmt-notificationhubs', 'client': 'NotificationHubsManagementClient', 'group': 'other'},
    'power': {'package': 'azure-mgmt-powerbiembedded', 'client': 'PowerBIEmbeddedManagementClient', 'group': 'other'},
    'netappfiles': {'package': 'azure-mgmt-netapp', 'client': 'NetAppManagementClient', 'group': 'other'},
    'elastic': {'package': 'azure-mgmt-elastic', 'client': 'ElasticManagementClient', 'group': 'other'},
    'config': {'package': 'azure-mgmt-appconfiguration', 'client': 'AppConfigurationManagementClient', 'group': 'other'},
    'devops': {'package': 'azure-devops', 'client': 'DevOpsClient', 'group': 'other'},
    
    # Services to skip or need review
    'azure': {'package': 'NEEDS_REDISTRIBUTION', 'client': 'GENERIC', 'group': 'needs_review'},
    'active': {'package': 'NEEDS_CLARIFICATION', 'client': 'UNKNOWN', 'group': 'needs_review'},
    'managed': {'package': 'TOO_GENERIC', 'client': 'UNKNOWN', 'group': 'needs_review'},
    
    # AWS services (invalid for Azure)
    'eks': {'package': 'INVALID_AWS_SERVICE', 'client': 'N/A', 'group': 'invalid'},
    'lambda': {'package': 'INVALID_AWS_SERVICE', 'client': 'N/A', 'group': 'invalid'},
    's3': {'package': 'INVALID_AWS_SERVICE', 'client': 'N/A', 'group': 'invalid'},
}


def load_rules_yaml(file_path):
    """Load the rules YAML file"""
    print(f"Loading rules from: {file_path}")
    with open(file_path, 'r') as f:
        data = yaml.safe_load(f)
    return data


def extract_services_from_rules(rules_data):
    """Extract all services and their rules"""
    services = defaultdict(list)
    
    for rule in rules_data.get('rules', []):
        service = rule.get('service')
        if service:
            services[service].append(rule)
    
    return services


def get_target_service(service_name):
    """Get the target service after consolidation"""
    if service_name not in SERVICE_MAPPING:
        return service_name, None
    
    mapping = SERVICE_MAPPING[service_name]
    if 'consolidate_to' in mapping:
        return mapping['consolidate_to'], SERVICE_MAPPING[mapping['consolidate_to']]
    
    return service_name, mapping


def create_service_structure(services_by_service, output_dir):
    """Create the new services folder structure"""
    from datetime import datetime
    
    # Backup old services if exists
    if output_dir.exists():
        backup_dir = output_dir.parent / f"services_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        print(f"\n📦 Backing up existing services to: {backup_dir}")
        shutil.move(str(output_dir), str(backup_dir))
    
    output_dir.mkdir(exist_ok=True)
    
    stats = {
        'total_services': 0,
        'consolidated_services': 0,
        'invalid_services': 0,
        'needs_review': 0,
        'total_rules': 0,
        'by_group': defaultdict(int)
    }
    
    # Group rules by target service
    consolidated = defaultdict(list)
    
    for service_name, rules in services_by_service.items():
        target_service, mapping = get_target_service(service_name)
        
        if mapping is None:
            print(f"⚠️  WARNING: Service '{service_name}' not in mapping table!")
            consolidated[service_name].extend(rules)
            stats['needs_review'] += 1
        elif mapping.get('group') == 'invalid':
            print(f"❌ SKIPPING: '{service_name}' is invalid (AWS service)")
            stats['invalid_services'] += 1
            continue
        elif mapping.get('group') == 'needs_review':
            print(f"⚠️  NEEDS REVIEW: '{service_name}' - {mapping.get('package')}")
            consolidated[service_name].extend(rules)
            stats['needs_review'] += 1
        else:
            if target_service != service_name:
                print(f"🔀 Consolidating: '{service_name}' → '{target_service}'")
                stats['consolidated_services'] += 1
            consolidated[target_service].extend(rules)
    
    # Create service folders
    print(f"\n📁 Creating service folders...")
    
    for service_name, rules in consolidated.items():
        target_service, mapping = get_target_service(service_name)
        
        if mapping and mapping.get('group') == 'invalid':
            continue
        
        service_dir = output_dir / service_name
        metadata_dir = service_dir / 'metadata'
        rules_dir = service_dir / 'rules'
        
        service_dir.mkdir(exist_ok=True)
        metadata_dir.mkdir(exist_ok=True)
        rules_dir.mkdir(exist_ok=True)
        
        # Create metadata files for each rule
        for idx, rule in enumerate(rules):
            rule_id = rule.get('rule_id', 'unknown')
            
            # Handle extremely long filenames (max 255 chars)
            if len(rule_id) > 200:
                # Use hash for long names
                import hashlib
                hash_suffix = hashlib.md5(rule_id.encode()).hexdigest()[:8]
                safe_rule_id = rule_id[:180] + f"__{hash_suffix}"
                print(f"  ⚠️  Truncating long rule_id: {rule_id[:50]}... → {safe_rule_id}")
            else:
                safe_rule_id = rule_id
            
            metadata_file = metadata_dir / f"{safe_rule_id}.yaml"
            
            with open(metadata_file, 'w') as f:
                yaml.dump(rule, f, default_flow_style=False, sort_keys=False)
        
        # Create service-level rules.yaml
        rules_yaml = create_service_rules_yaml(service_name, mapping, rules)
        rules_file = rules_dir / f"{service_name}.yaml"
        
        with open(rules_file, 'w') as f:
            yaml.dump(rules_yaml, f, default_flow_style=False, sort_keys=False)
        
        print(f"✓ {service_name:20s} - {len(rules):4d} rules - {mapping.get('package') if mapping else 'UNMAPPED'}")
        
        stats['total_services'] += 1
        stats['total_rules'] += len(rules)
        if mapping:
            stats['by_group'][mapping.get('group', 'unknown')] += len(rules)
    
    return stats


def create_service_rules_yaml(service_name, mapping, rules):
    """Create the rules YAML structure for a service"""
    
    if not mapping:
        mapping = {
            'package': 'UNMAPPED',
            'client': 'UNMAPPED',
            'group': 'unmapped'
        }
    
    rules_yaml = {
        'version': '1.0',
        'provider': 'azure',
        'service': service_name,
        'package': mapping.get('package', 'UNMAPPED'),
        'client_class': mapping.get('client', 'UNMAPPED'),
        'group': mapping.get('group', 'unknown'),
        'total_rules': len(rules),
        'discovery': [],
        'checks': []
    }
    
    # Add special flags
    if mapping.get('data_plane'):
        rules_yaml['data_plane'] = True
    if mapping.get('graph_based'):
        rules_yaml['graph_based'] = True
    
    # Create discovery and checks from rules
    # For now, just add placeholders - will be implemented in Phase 3
    rules_yaml['discovery'].append({
        'discovery_id': f"azure.{service_name}.resources",
        'note': 'TO BE IMPLEMENTED - Discovery logic based on Azure SDK',
        'calls': []
    })
    
    rules_yaml['checks'] = [{
        'check_id': rule.get('rule_id'),
        'note': 'TO BE IMPLEMENTED - Check logic based on rule metadata'
    } for rule in rules[:5]]  # Just first 5 as examples
    
    return rules_yaml


def generate_report(stats, output_file):
    """Generate a comprehensive report"""
    from datetime import datetime
    
    report = {
        'timestamp': datetime.now().isoformat(),
        'summary': stats,
        'next_steps': [
            'Review services in "needs_review" group',
            'Implement discovery logic for each service',
            'Update rules with Azure SDK method calls',
            'Test with actual Azure credentials'
        ]
    }
    
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n📊 Report saved to: {output_file}")


def main():
    print("=" * 80)
    print(" AZURE SERVICES REBUILD TOOL")
    print("=" * 80)
    
    # Paths
    script_dir = Path(__file__).parent
    rules_file = script_dir / 'rule_ids_ENRICHED_AI_ENHANCED.yaml'
    output_dir = script_dir / 'services'
    report_file = script_dir / 'services_rebuild_report.json'
    
    # Load rules
    rules_data = load_rules_yaml(rules_file)
    print(f"✓ Loaded {rules_data.get('metadata', {}).get('total_rules', 0)} rules")
    
    # Extract services
    services_by_service = extract_services_from_rules(rules_data)
    print(f"✓ Found {len(services_by_service)} unique services")
    
    # Show service breakdown
    print(f"\n📋 Service breakdown:")
    for service, rules in sorted(services_by_service.items(), key=lambda x: len(x[1]), reverse=True)[:20]:
        status = "✓" if service in SERVICE_MAPPING else "?"
        print(f"  {status} {service:20s}: {len(rules):4d} rules")
    
    # Create structure
    print(f"\n🏗️  Creating service structure...")
    stats = create_service_structure(services_by_service, output_dir)
    
    # Generate report
    generate_report(stats, report_file)
    
    # Summary
    print("\n" + "=" * 80)
    print(" SUMMARY")
    print("=" * 80)
    print(f"✓ Total services created: {stats['total_services']}")
    print(f"✓ Total rules processed: {stats['total_rules']}")
    print(f"🔀 Services consolidated: {stats['consolidated_services']}")
    print(f"❌ Invalid services skipped: {stats['invalid_services']}")
    print(f"⚠️  Services needing review: {stats['needs_review']}")
    
    print(f"\n📊 Rules by group:")
    for group, count in sorted(stats['by_group'].items(), key=lambda x: x[1], reverse=True):
        print(f"  {group:20s}: {count:4d} rules")
    
    print(f"\n✅ Services folder rebuilt successfully!")
    print(f"📁 Location: {output_dir}")
    print(f"📊 Report: {report_file}")


if __name__ == "__main__":
    main()

