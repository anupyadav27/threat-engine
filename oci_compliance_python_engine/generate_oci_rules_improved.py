"""
OCI Rule Generator - Improved Version

Creates actual OCI SDK-specific checks based on real resource attributes and security requirements.
"""

import os
import yaml
from collections import defaultdict
from typing import Dict, List, Any


# OCI SDK Resource Mappings with ACTUAL field paths
OCI_RESOURCE_MAPPINGS = {
    # Identity & IAM
    'user': {
        'client': 'IdentityClient',
        'list_method': 'list_users',
        'get_method': 'get_user',
        'fields': {
            'mfa': 'is_mfa_activated',
            'email': 'email',
            'lifecycle_state': 'lifecycle_state',
            'time_created': 'time_created',
            'capabilities': 'capabilities',
            'external_identifier': 'external_identifier'
        }
    },
    'group': {
        'client': 'IdentityClient',
        'list_method': 'list_groups',
        'get_method': 'get_group',
        'fields': {
            'name': 'name',
            'description': 'description',
            'lifecycle_state': 'lifecycle_state'
        }
    },
    'policy': {
        'client': 'IdentityClient',
        'list_method': 'list_policies',
        'get_method': 'get_policy',
        'fields': {
            'statements': 'statements',
            'version_date': 'version_date',
            'lifecycle_state': 'lifecycle_state'
        }
    },
    'compartment': {
        'client': 'IdentityClient',
        'list_method': 'list_compartments',
        'get_method': 'get_compartment',
        'fields': {
            'name': 'name',
            'description': 'description',
            'lifecycle_state': 'lifecycle_state',
            'enable_delete': 'enable_delete'
        }
    },
    
    # Compute
    'instance': {
        'client': 'ComputeClient',
        'list_method': 'list_instances',
        'get_method': 'get_instance',
        'fields': {
            'metadata': 'metadata',
            'agent_config': 'agent_config',
            'launch_options': 'launch_options',
            'availability_domain': 'availability_domain',
            'lifecycle_state': 'lifecycle_state',
            'source_details': 'source_details'
        }
    },
    'image': {
        'client': 'ComputeClient',
        'list_method': 'list_images',
        'get_method': 'get_image',
        'fields': {
            'lifecycle_state': 'lifecycle_state',
            'operating_system': 'operating_system',
            'launch_mode': 'launch_mode'
        }
    },
    'boot_volume': {
        'client': 'BlockstorageClient',
        'list_method': 'list_boot_volumes',
        'get_method': 'get_boot_volume',
        'fields': {
            'kms_key_id': 'kms_key_id',
            'is_hydrated': 'is_hydrated',
            'volume_backup_policy_assignment': 'volume_backup_policy_assignment',
            'lifecycle_state': 'lifecycle_state'
        }
    },
    'volume': {
        'client': 'BlockstorageClient',
        'list_method': 'list_volumes',
        'get_method': 'get_volume',
        'fields': {
            'kms_key_id': 'kms_key_id',
            'is_hydrated': 'is_hydrated',
            'volume_backup_policy_assignment': 'volume_backup_policy_assignment',
            'lifecycle_state': 'lifecycle_state'
        }
    },
    
    # Database
    'database': {
        'client': 'DatabaseClient',
        'list_method': 'list_databases',
        'get_method': 'get_database',
        'fields': {
            'kms_key_id': 'kms_key_id',
            'db_backup_config': 'db_backup_config',
            'lifecycle_state': 'lifecycle_state'
        }
    },
    'autonomous_database': {
        'client': 'DatabaseClient',
        'list_method': 'list_autonomous_databases',
        'get_method': 'get_autonomous_database',
        'fields': {
            'kms_key_id': 'kms_key_id',
            'vault_id': 'vault_id',
            'is_mtls_connection_required': 'is_mtls_connection_required',
            'is_data_guard_enabled': 'is_data_guard_enabled',
            'is_auto_scaling_enabled': 'is_auto_scaling_enabled',
            'whitelisted_ips': 'whitelisted_ips',
            'lifecycle_state': 'lifecycle_state'
        }
    },
    'db_system': {
        'client': 'DatabaseClient',
        'list_method': 'list_db_systems',
        'get_method': 'get_db_system',
        'fields': {
            'kms_key_id': 'kms_key_id',
            'backup_network_nsg_ids': 'backup_network_nsg_ids',
            'lifecycle_state': 'lifecycle_state'
        }
    },
    
    # Object Storage
    'bucket': {
        'client': 'ObjectStorageClient',
        'list_method': 'list_buckets',
        'get_method': 'get_bucket',
        'fields': {
            'kms_key_id': 'kms_key_id',
            'public_access_type': 'public_access_type',
            'versioning': 'versioning',
            'object_events_enabled': 'object_events_enabled',
            'replication_enabled': 'replication_enabled'
        }
    },
    
    # Virtual Network
    'vcn': {
        'client': 'VirtualNetworkClient',
        'list_method': 'list_vcns',
        'get_method': 'get_vcn',
        'fields': {
            'cidr_blocks': 'cidr_blocks',
            'ipv6_cidr_blocks': 'ipv6_cidr_blocks',
            'lifecycle_state': 'lifecycle_state'
        }
    },
    'subnet': {
        'client': 'VirtualNetworkClient',
        'list_method': 'list_subnets',
        'get_method': 'get_subnet',
        'fields': {
            'prohibit_public_ip_on_vnic': 'prohibit_public_ip_on_vnic',
            'prohibit_internet_ingress': 'prohibit_internet_ingress',
            'security_list_ids': 'security_list_ids',
            'lifecycle_state': 'lifecycle_state'
        }
    },
    'security_list': {
        'client': 'VirtualNetworkClient',
        'list_method': 'list_security_lists',
        'get_method': 'get_security_list',
        'fields': {
            'ingress_security_rules': 'ingress_security_rules',
            'egress_security_rules': 'egress_security_rules',
            'lifecycle_state': 'lifecycle_state'
        }
    },
    
    # Container Engine
    'cluster': {
        'client': 'ContainerEngineClient',
        'list_method': 'list_clusters',
        'get_method': 'get_cluster',
        'fields': {
            'kms_key_id': 'kms_key_id',
            'options': 'options',
            'endpoint_config': 'endpoint_config',
            'lifecycle_state': 'lifecycle_state'
        }
    },
    'node_pool': {
        'client': 'ContainerEngineClient',
        'list_method': 'list_node_pools',
        'get_method': 'get_node_pool',
        'fields': {
            'node_config_details': 'node_config_details',
            'ssh_public_key': 'ssh_public_key',
            'lifecycle_state': 'lifecycle_state'
        }
    },
    
    # API Gateway
    'gateway': {
        'client': 'ApiGatewayClient',
        'list_method': 'list_gateways',
        'get_method': 'get_gateway',
        'fields': {
            'endpoint_type': 'endpoint_type',
            'subnet_id': 'subnet_id',
            'network_security_group_ids': 'network_security_group_ids',
            'lifecycle_state': 'lifecycle_state'
        }
    },
    'deployment': {
        'client': 'ApiGatewayClient',
        'list_method': 'list_deployments',
        'get_method': 'get_deployment',
        'fields': {
            'specification': 'specification',
            'lifecycle_state': 'lifecycle_state'
        }
    },
}


# Check pattern generators based on security requirements
def generate_check_for_requirement(rule: Dict[str, Any], resource_mapping: Dict[str, Any]) -> Dict[str, Any]:
    """Generate specific check based on requirement and actual OCI SDK fields"""
    
    rule_id = rule['rule_id']
    resource = rule.get('resource', 'unknown')
    requirement = rule.get('requirement', '').lower()
    title = rule.get('title', '')
    severity = rule.get('severity', 'medium')
    
    discovery_id = f"list_{resource}s" if not resource.endswith('s') else f"list_{resource}"
    
    check = {
        'check_id': rule_id,
        'title': title,
        'severity': severity,
        'for_each': discovery_id,
        'logic': 'AND',
        'calls': []
    }
    
    fields = resource_mapping.get('fields', {})
    
    # Pattern matching for actual security checks
    if 'encryption' in requirement and 'enabled' in requirement:
        if 'kms_key_id' in fields:
            check['calls'].append({
                'action': 'eval',
                'fields': [{
                    'path': fields['kms_key_id'],
                    'operator': 'exists',
                    'expected': True,
                    'description': 'Verify KMS encryption key is configured'
                }]
            })
    
    elif 'mfa' in requirement or 'multi-factor' in requirement:
        if 'mfa' in fields:
            check['calls'].append({
                'action': 'eval',
                'fields': [{
                    'path': fields['mfa'],
                    'operator': 'equals',
                    'expected': True,
                    'description': 'Verify MFA is enabled'
                }]
            })
    
    elif 'public' in requirement and ('access' in requirement or 'ip' in requirement):
        if 'public_access_type' in fields:
            check['calls'].append({
                'action': 'eval',
                'fields': [{
                    'path': fields['public_access_type'],
                    'operator': 'equals',
                    'expected': 'NoPublicAccess',
                    'description': 'Verify public access is disabled'
                }]
            })
        elif 'prohibit_public_ip_on_vnic' in fields:
            check['calls'].append({
                'action': 'eval',
                'fields': [{
                    'path': fields['prohibit_public_ip_on_vnic'],
                    'operator': 'equals',
                    'expected': True,
                    'description': 'Verify public IPs are prohibited'
                }]
            })
    
    elif 'backup' in requirement and 'enabled' in requirement:
        if 'db_backup_config' in fields:
            check['calls'].append({
                'action': 'eval',
                'fields': [{
                    'path': fields['db_backup_config'],
                    'operator': 'exists',
                    'expected': True,
                    'description': 'Verify backup configuration exists'
                }]
            })
        elif 'volume_backup_policy_assignment' in fields:
            check['calls'].append({
                'action': 'eval',
                'fields': [{
                    'path': fields['volume_backup_policy_assignment'],
                    'operator': 'exists',
                    'expected': True,
                    'description': 'Verify backup policy is assigned'
                }]
            })
    
    elif 'mtls' in requirement or 'mutual tls' in requirement:
        if 'is_mtls_connection_required' in fields:
            check['calls'].append({
                'action': 'eval',
                'fields': [{
                    'path': fields['is_mtls_connection_required'],
                    'operator': 'equals',
                    'expected': True,
                    'description': 'Verify mTLS is required'
                }]
            })
    
    elif 'auto' in requirement and 'scaling' in requirement:
        if 'is_auto_scaling_enabled' in fields:
            check['calls'].append({
                'action': 'eval',
                'fields': [{
                    'path': fields['is_auto_scaling_enabled'],
                    'operator': 'equals',
                    'expected': True,
                    'description': 'Verify auto-scaling is enabled'
                }]
            })
    
    elif 'versioning' in requirement:
        if 'versioning' in fields:
            check['calls'].append({
                'action': 'eval',
                'fields': [{
                    'path': fields['versioning'],
                    'operator': 'equals',
                    'expected': 'Enabled',
                    'description': 'Verify versioning is enabled'
                }]
            })
    
    elif 'data guard' in requirement:
        if 'is_data_guard_enabled' in fields:
            check['calls'].append({
                'action': 'eval',
                'fields': [{
                    'path': fields['is_data_guard_enabled'],
                    'operator': 'equals',
                    'expected': True,
                    'description': 'Verify Data Guard is enabled'
                }]
            })
    
    elif 'monitoring' in requirement or 'agent' in requirement:
        if 'agent_config' in fields:
            check['calls'].append({
                'action': 'eval',
                'fields': [{
                    'path': f"{fields['agent_config']}.are_all_plugins_disabled",
                    'operator': 'equals',
                    'expected': False,
                    'description': 'Verify monitoring agent is enabled'
                }]
            })
    
    elif 'ssh' in requirement and ('restrict' in requirement or 'ingress' in requirement):
        if 'ingress_security_rules' in fields:
            check['calls'].append({
                'action': 'eval',
                'fields': [{
                    'path': f"{fields['ingress_security_rules']}[].source",
                    'operator': 'not_equals',
                    'expected': '0.0.0.0/0',
                    'description': 'Verify SSH is not open to internet'
                }]
            })
    
    # Default check if no pattern matched - check lifecycle state
    if not check['calls']:
        check['calls'].append({
            'action': 'eval',
            'fields': [{
                'path': fields.get('lifecycle_state', 'lifecycle_state'),
                'operator': 'equals',
                'expected': 'ACTIVE',
                'description': 'Verify resource is in active state (placeholder check)'
            }]
        })
    
    return check


def generate_discovery(service: str, resource: str, resource_mapping: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Generate discovery with actual OCI SDK methods"""
    
    if not resource_mapping:
        return []
    
    discovery = []
    discovery_id = f"list_{resource}s" if not resource.endswith('s') else f"list_{resource}"
    
    # List discovery
    discovery.append({
        'discovery_id': discovery_id,
        'resource_type': resource,
        'calls': [{
            'action': 'list',
            'client': resource_mapping['client'],
            'method': resource_mapping['list_method'],
            'fields': [
                {'path': 'id', 'var': f'{resource}_id'},
                {'path': 'display_name', 'var': 'display_name'},
                {'path': 'lifecycle_state', 'var': 'lifecycle_state'},
                {'path': 'compartment_id', 'var': 'compartment_id'},
            ]
        }]
    })
    
    # Get details discovery if available
    if resource_mapping.get('get_method'):
        get_fields = []
        for field_name, field_path in resource_mapping.get('fields', {}).items():
            if field_name not in ['lifecycle_state']:  # Already captured in list
                get_fields.append({'path': field_path, 'var': field_name})
        
        if get_fields:
            discovery.append({
                'discovery_id': f"get_{resource}_details",
                'resource_type': resource,
                'for_each': discovery_id,
                'calls': [{
                    'action': 'get',
                    'client': resource_mapping['client'],
                    'method': resource_mapping['get_method'],
                    'fields': get_fields
                }]
            })
    
    return discovery


def main():
    """Main generator function"""
    print("="*80)
    print("OCI Rule Generator - IMPROVED (SDK-Specific)")
    print("="*80)
    
    # Load rules
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
    
    # Generate improved YAML for each service
    services_dir = os.path.join(os.path.dirname(__file__), 'services')
    
    for service_name, service_rules in sorted(services_map.items()):
        print(f"\n🔧 Generating {service_name}...")
        print(f"   {len(service_rules)} rules")
        
        # Group by resource
        resources_map = defaultdict(list)
        for rule in service_rules:
            resource = rule.get('resource', 'unknown')
            resources_map[resource].append(rule)
        
        # Generate discovery for all resources
        all_discovery = []
        seen_discoveries = set()
        
        for resource in resources_map.keys():
            resource_mapping = OCI_RESOURCE_MAPPINGS.get(resource)
            if resource_mapping:
                discovery = generate_discovery(service_name, resource, resource_mapping)
                for d in discovery:
                    disc_id = d['discovery_id']
                    if disc_id not in seen_discoveries:
                        all_discovery.append(d)
                        seen_discoveries.add(disc_id)
        
        # Generate checks
        all_checks = []
        sdk_specific_count = 0
        
        for rule in service_rules:
            resource = rule.get('resource', 'unknown')
            resource_mapping = OCI_RESOURCE_MAPPINGS.get(resource, {})
            check = generate_check_for_requirement(rule, resource_mapping)
            all_checks.append(check)
            
            # Count SDK-specific checks
            if check['calls'] and 'placeholder' not in str(check['calls']):
                sdk_specific_count += 1
        
        # Build service YAML
        service_yaml = {
            service_name: {
                'version': '1.0',
                'provider': 'oci',
                'service': service_name,
                'scope': 'regional',
                'discovery': all_discovery,
                'checks': all_checks
            }
        }
        
        # Save
        service_dir = os.path.join(services_dir, service_name)
        rules_dir = os.path.join(service_dir, 'rules')
        os.makedirs(rules_dir, exist_ok=True)
        
        rules_file = os.path.join(rules_dir, f'{service_name}.yaml')
        with open(rules_file, 'w') as f:
            yaml.dump(service_yaml, f, default_flow_style=False, sort_keys=False, width=120)
        
        print(f"   ✅ Created: {rules_file}")
        print(f"      - {len(all_discovery)} discovery definitions")
        print(f"      - {len(all_checks)} checks ({sdk_specific_count} SDK-specific)")
    
    print(f"\n{'='*80}")
    print(f"✅ Generation Complete!")
    print(f"{'='*80}")
    print(f"\nImproved service YAMLs for {len(services_map)} services")
    print(f"Using actual OCI SDK field paths and methods")


if __name__ == '__main__':
    main()

