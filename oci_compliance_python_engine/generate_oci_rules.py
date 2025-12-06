"""
OCI Rule Generator

Parses rule_ids.yaml and generates service YAML files with discovery and checks.
Based on GCP engine pattern but adapted for OCI SDK.
"""

import os
import yaml
import json
from collections import defaultdict
from typing import Dict, List, Any


# OCI resource type to SDK mapping
OCI_RESOURCE_SDK_MAPPING = {
    # Identity
    'user': {'client': 'IdentityClient', 'list_method': 'list_users', 'get_method': 'get_user'},
    'group': {'client': 'IdentityClient', 'list_method': 'list_groups', 'get_method': 'get_group'},
    'policy': {'client': 'IdentityClient', 'list_method': 'list_policies', 'get_method': 'get_policy'},
    'compartment': {'client': 'IdentityClient', 'list_method': 'list_compartments', 'get_method': 'get_compartment'},
    'dynamic_group': {'client': 'IdentityClient', 'list_method': 'list_dynamic_groups', 'get_method': 'get_dynamic_group'},
    'tag_namespace': {'client': 'IdentityClient', 'list_method': 'list_tag_namespaces', 'get_method': 'get_tag_namespace'},
    'api_key': {'client': 'IdentityClient', 'list_method': 'list_api_keys', 'get_method': None},
    'auth_token': {'client': 'IdentityClient', 'list_method': 'list_auth_tokens', 'get_method': None},
    'password': {'client': 'IdentityClient', 'list_method': None, 'get_method': None},  # Special handling
    
    # Compute
    'instance': {'client': 'ComputeClient', 'list_method': 'list_instances', 'get_method': 'get_instance'},
    'image': {'client': 'ComputeClient', 'list_method': 'list_images', 'get_method': 'get_image'},
    'boot_volume': {'client': 'BlockstorageClient', 'list_method': 'list_boot_volumes', 'get_method': 'get_boot_volume'},
    'volume': {'client': 'BlockstorageClient', 'list_method': 'list_volumes', 'get_method': 'get_volume'},
    'dedicated_vm_host': {'client': 'ComputeClient', 'list_method': 'list_dedicated_vm_hosts', 'get_method': 'get_dedicated_vm_host'},
    'instance_pool': {'client': 'ComputeClient', 'list_method': 'list_instance_pools', 'get_method': 'get_instance_pool'},
    
    # Database
    'database': {'client': 'DatabaseClient', 'list_method': 'list_databases', 'get_method': 'get_database'},
    'autonomous_database': {'client': 'DatabaseClient', 'list_method': 'list_autonomous_databases', 'get_method': 'get_autonomous_database'},
    'db_system': {'client': 'DatabaseClient', 'list_method': 'list_db_systems', 'get_method': 'get_db_system'},
    
    # Object Storage
    'bucket': {'client': 'ObjectStorageClient', 'list_method': 'list_buckets', 'get_method': 'get_bucket'},
    
    # Virtual Network
    'vcn': {'client': 'VirtualNetworkClient', 'list_method': 'list_vcns', 'get_method': 'get_vcn'},
    'subnet': {'client': 'VirtualNetworkClient', 'list_method': 'list_subnets', 'get_method': 'get_subnet'},
    'security_list': {'client': 'VirtualNetworkClient', 'list_method': 'list_security_lists', 'get_method': 'get_security_list'},
    'network_security_group': {'client': 'VirtualNetworkClient', 'list_method': 'list_network_security_groups', 'get_method': 'get_network_security_group'},
    'route_table': {'client': 'VirtualNetworkClient', 'list_method': 'list_route_tables', 'get_method': 'get_route_table'},
    'drg': {'client': 'VirtualNetworkClient', 'list_method': 'list_drgs', 'get_method': 'get_drg'},
    'internet_gateway': {'client': 'VirtualNetworkClient', 'list_method': 'list_internet_gateways', 'get_method': 'get_internet_gateway'},
    'nat_gateway': {'client': 'VirtualNetworkClient', 'list_method': 'list_nat_gateways', 'get_method': 'get_nat_gateway'},
    'service_gateway': {'client': 'VirtualNetworkClient', 'list_method': 'list_service_gateways', 'get_method': 'get_service_gateway'},
    
    # Container Engine
    'cluster': {'client': 'ContainerEngineClient', 'list_method': 'list_clusters', 'get_method': 'get_cluster'},
    'node_pool': {'client': 'ContainerEngineClient', 'list_method': 'list_node_pools', 'get_method': 'get_node_pool'},
    
    # Key Management
    'vault': {'client': 'KmsVaultClient', 'list_method': 'list_vaults', 'get_method': 'get_vault'},
    'key': {'client': 'KmsManagementClient', 'list_method': 'list_keys', 'get_method': 'get_key'},
}


def generate_discovery_for_resource(service: str, resource: str) -> List[Dict[str, Any]]:
    """Generate discovery section for a resource type"""
    sdk_info = OCI_RESOURCE_SDK_MAPPING.get(resource, {})
    if not sdk_info.get('list_method'):
        return []
    
    discovery_id = f"list_{resource}s" if not resource.endswith('s') else f"list_{resource}"
    
    discovery = [{
        'discovery_id': discovery_id,
        'resource_type': resource,
        'calls': [{
            'action': 'list',
            'client': sdk_info['client'],
            'method': sdk_info['list_method'],
            'fields': [
                {'path': 'id', 'var': f'{resource}_id'},
                {'path': 'display_name', 'var': f'{resource}_name'},
                {'path': 'lifecycle_state', 'var': 'lifecycle_state'},
                {'path': 'compartment_id', 'var': 'compartment_id'},
            ]
        }]
    }]
    
    # Add get details discovery if available
    if sdk_info.get('get_method'):
        discovery.append({
            'discovery_id': f"get_{resource}_details",
            'resource_type': resource,
            'for_each': discovery_id,
            'calls': [{
                'action': 'get',
                'client': sdk_info['client'],
                'method': sdk_info['get_method'],
                'fields': [
                    {'path': 'defined_tags', 'var': 'defined_tags'},
                    {'path': 'freeform_tags', 'var': 'freeform_tags'},
                ]
            }]
        })
    
    return discovery


def generate_check_for_rule(rule: Dict[str, Any]) -> Dict[str, Any]:
    """Generate check definition from rule metadata"""
    rule_id = rule['rule_id']
    resource = rule.get('resource', 'unknown')
    requirement = rule.get('requirement', '')
    
    # Determine discovery to use
    discovery_id = f"list_{resource}s" if not resource.endswith('s') else f"list_{resource}"
    
    # Generate check based on requirement keywords
    requirement_lower = requirement.lower()
    
    check = {
        'check_id': rule_id,
        'title': rule.get('title', ''),
        'severity': rule.get('severity', 'medium'),
        'for_each': discovery_id,
        'logic': 'AND',
        'calls': []
    }
    
    # Pattern-based check generation
    if 'encryption' in requirement_lower and 'enabled' in requirement_lower:
        check['calls'].append({
            'action': 'eval',
            'fields': [{
                'path': 'kms_key_id',
                'operator': 'exists',
                'expected': True
            }]
        })
    
    elif 'mfa' in requirement_lower or 'multi-factor' in requirement_lower:
        check['calls'].append({
            'action': 'eval',
            'fields': [{
                'path': 'is_mfa_activated',
                'operator': 'equals',
                'expected': True
            }]
        })
    
    elif 'public' in requirement_lower and ('access' in requirement_lower or 'ip' in requirement_lower):
        check['calls'].append({
            'action': 'eval',
            'fields': [{
                'path': 'is_public',
                'operator': 'equals',
                'expected': False
            }]
        })
    
    elif 'logging' in requirement_lower and 'enabled' in requirement_lower:
        check['calls'].append({
            'action': 'eval',
            'fields': [{
                'path': 'log_group_id',
                'operator': 'exists',
                'expected': True
            }]
        })
    
    elif 'monitoring' in requirement_lower and 'enabled' in requirement_lower:
        check['calls'].append({
            'action': 'eval',
            'fields': [{
                'path': 'monitoring_enabled',
                'operator': 'equals',
                'expected': True
            }]
        })
    
    elif 'backup' in requirement_lower and 'enabled' in requirement_lower:
        check['calls'].append({
            'action': 'eval',
            'fields': [{
                'path': 'backup_policy_id',
                'operator': 'exists',
                'expected': True
            }]
        })
    
    elif 'tags' in requirement_lower or 'tagged' in requirement_lower:
        check['calls'].append({
            'action': 'eval',
            'fields': [{
                'path': 'defined_tags',
                'operator': 'exists',
                'expected': True
            }]
        })
    
    else:
        # Generic check - just verify resource exists and is active
        check['calls'].append({
            'action': 'eval',
            'fields': [{
                'path': 'lifecycle_state',
                'operator': 'equals',
                'expected': 'ACTIVE'
            }]
        })
    
    return check


def generate_service_yaml(service_name: str, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate complete service YAML structure"""
    
    # Group rules by resource type
    resources_map = defaultdict(list)
    for rule in rules:
        resource = rule.get('resource', 'unknown')
        resources_map[resource].append(rule)
    
    # Generate discovery for all resource types
    all_discovery = []
    seen_discoveries = set()
    for resource in resources_map.keys():
        discovery = generate_discovery_for_resource(service_name, resource)
        for d in discovery:
            disc_id = d['discovery_id']
            if disc_id not in seen_discoveries:
                all_discovery.append(d)
                seen_discoveries.add(disc_id)
    
    # Generate checks
    all_checks = []
    for rule in rules:
        check = generate_check_for_rule(rule)
        all_checks.append(check)
    
    # Build service structure
    service_yaml = {
        service_name: {
            'version': '1.0',
            'provider': 'oci',
            'service': service_name,
            'scope': 'regional',  # Will be overridden by config
            'discovery': all_discovery,
            'checks': all_checks
        }
    }
    
    return service_yaml


def main():
    """Main generator function"""
    print("="*80)
    print("OCI Rule Generator - Creating Service YAML Files")
    print("="*80)
    
    # Load rule_ids.yaml
    rule_ids_path = os.path.join(os.path.dirname(__file__), 'rule_ids.yaml')
    print(f"\n📖 Loading rules from: {rule_ids_path}")
    
    with open(rule_ids_path) as f:
        data = yaml.safe_load(f)
    
    rules = data.get('rules', [])
    print(f"   Found {len(rules)} total rules")
    
    # Group by service
    services_map = defaultdict(list)
    for rule in rules:
        service = rule.get('service', 'unknown')
        services_map[service].append(rule)
    
    print(f"   Grouped into {len(services_map)} services")
    
    # Generate YAML for each service
    services_dir = os.path.join(os.path.dirname(__file__), 'services')
    
    for service_name, service_rules in sorted(services_map.items()):
        print(f"\n🔧 Generating {service_name}...")
        print(f"   {len(service_rules)} rules")
        
        # Create service directory
        service_dir = os.path.join(services_dir, service_name)
        rules_dir = os.path.join(service_dir, 'rules')
        os.makedirs(rules_dir, exist_ok=True)
        
        # Generate service YAML
        service_yaml = generate_service_yaml(service_name, service_rules)
        
        # Save service rules YAML
        rules_file = os.path.join(rules_dir, f'{service_name}.yaml')
        with open(rules_file, 'w') as f:
            yaml.dump(service_yaml, f, default_flow_style=False, sort_keys=False)
        
        print(f"   ✅ Created: {rules_file}")
        print(f"      - {len(service_yaml[service_name]['discovery'])} discovery definitions")
        print(f"      - {len(service_yaml[service_name]['checks'])} checks")
    
    print(f"\n{'='*80}")
    print(f"✅ Generation Complete!")
    print(f"{'='*80}")
    print(f"\nGenerated service YAMLs for {len(services_map)} services")
    print(f"Total checks: {len(rules)}")
    print(f"\nNext steps:")
    print(f"  1. Review generated YAML files in services/*/rules/")
    print(f"  2. Customize discovery and check logic as needed")
    print(f"  3. Run the OCI engine to test")


if __name__ == '__main__':
    main()

