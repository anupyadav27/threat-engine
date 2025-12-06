"""
IBM Compliance Engine - Enhanced Service File Generator with SDK Mappings

Reads rule_ids_GPT4_ENHANCED.yaml and generates:
1. Service YAML files with real IBM SDK discovery calls
2. Checks with actual SDK validation logic
3. Metadata files for each rule
"""

import os
import yaml
import re
from collections import defaultdict
from typing import Dict, List, Any, Tuple


# IBM Cloud SDK method mappings for each service
IBM_SDK_MAPPINGS = {
    'iam': {
        'discovery': {
            'user': {
                'method': 'list_users',
                'client': 'iam_identity',
                'fields': ['id', 'iam_id', 'firstname', 'lastname', 'email', 'state', 'mfa_traits']
            },
            'policy': {
                'method': 'list_policies',
                'client': 'iam_policy',
                'fields': ['id', 'type', 'subjects', 'roles', 'resources']
            },
            'role': {
                'method': 'list_roles',
                'client': 'iam_policy',
                'fields': ['id', 'display_name', 'actions']
            },
            'access_group': {
                'method': 'list_access_groups',
                'client': 'iam_access_groups',
                'fields': ['id', 'name', 'description']
            },
            'service_id': {
                'method': 'list_service_ids',
                'client': 'iam_identity',
                'fields': ['id', 'name', 'description', 'created_at']
            },
            'api_key': {
                'method': 'list_api_keys',
                'client': 'iam_identity',
                'fields': ['id', 'name', 'created_at', 'locked']
            },
            'account_settings': {
                'method': 'get_account_settings',
                'client': 'iam_identity',
                'fields': ['mfa', 'session_expiration_in_seconds', 'restrict_create_service_id', 'restrict_create_platform_apikey']
            }
        }
    },
    'vpc': {
        'discovery': {
            'instance': {
                'method': 'list_instances',
                'client': 'vpc',
                'fields': ['id', 'name', 'vpc', 'status', 'zone']
            },
            'subnet': {
                'method': 'list_subnets',
                'client': 'vpc',
                'fields': ['id', 'name', 'ipv4_cidr_block', 'available_ipv4_address_count', 'public_gateway']
            },
            'security_group': {
                'method': 'list_security_groups',
                'client': 'vpc',
                'fields': ['id', 'name', 'rules', 'vpc']
            },
            'network_acl': {
                'method': 'list_network_acls',
                'client': 'vpc',
                'fields': ['id', 'name', 'rules']
            },
            'vpc': {
                'method': 'list_vpcs',
                'client': 'vpc',
                'fields': ['id', 'name', 'classic_access', 'default_network_acl', 'default_security_group']
            },
            'floating_ip': {
                'method': 'list_floating_ips',
                'client': 'vpc',
                'fields': ['id', 'name', 'address', 'status', 'target']
            },
            'load_balancer': {
                'method': 'list_load_balancers',
                'client': 'vpc',
                'fields': ['id', 'name', 'is_public', 'listeners', 'pools']
            },
            'vpn': {
                'method': 'list_vpn_gateways',
                'client': 'vpc',
                'fields': ['id', 'name', 'status', 'connections']
            }
        }
    },
    'databases': {
        'discovery': {
            'deployment': {
                'method': 'list_deployments',
                'client': 'cloud_databases',
                'fields': ['id', 'name', 'type', 'version', 'admin_usernames', 'enable_public_endpoints']
            },
            'backup': {
                'method': 'list_backups',
                'client': 'cloud_databases',
                'fields': ['id', 'deployment_id', 'type', 'status', 'created_at']
            }
        }
    },
    'object_storage': {
        'discovery': {
            'bucket': {
                'method': 'list_buckets',
                'client': 'cos',
                'fields': ['Name', 'CreationDate']
            }
        }
    },
    'containers': {
        'discovery': {
            'cluster': {
                'method': 'list_clusters',
                'client': 'container',
                'fields': ['id', 'name', 'state', 'masterKubeVersion', 'workerCount']
            },
            'worker': {
                'method': 'list_workers',
                'client': 'container',
                'fields': ['id', 'state', 'kubeVersion', 'privateVlan', 'publicVlan']
            }
        }
    },
    'key_protect': {
        'discovery': {
            'key': {
                'method': 'list_keys',
                'client': 'key_protect',
                'fields': ['id', 'name', 'state', 'extractable', 'keyRingID']
            }
        }
    },
    'activity_tracker': {
        'discovery': {
            'route': {
                'method': 'list_routes',
                'client': 'activity_tracker',
                'fields': ['id', 'name', 'locations', 'active']
            }
        }
    }
}


def load_rules(rule_file: str) -> Dict[str, Any]:
    """Load rules from YAML file"""
    with open(rule_file, 'r') as f:
        return yaml.safe_load(f)


def group_rules_by_service(rules_data: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    """Group rules by service"""
    service_rules = defaultdict(list)
    
    for rule in rules_data.get('rules', []):
        service = rule.get('service')
        if service:
            service_rules[service].append(rule)
    
    return dict(service_rules)


def parse_rule_id(rule_id: str) -> Dict[str, str]:
    """Parse rule_id to extract components
    
    Format: ibm.service.resource.requirement
    Example: ibm.iam.user.mfa_required
    """
    parts = rule_id.split('.')
    
    result = {
        'provider': parts[0] if len(parts) > 0 else '',
        'service': parts[1] if len(parts) > 1 else '',
        'resource': parts[2] if len(parts) > 2 else '',
        'check': '.'.join(parts[3:]) if len(parts) > 3 else ''
    }
    
    return result


def infer_check_logic(rule: Dict[str, Any]) -> Tuple[str, str, Any]:
    """Infer check logic from rule metadata
    
    Returns: (field_path, operator, expected_value)
    """
    rule_id = rule['rule_id']
    title = rule.get('title', '').lower()
    requirement = rule.get('requirement', '').lower()
    
    # Pattern matching for common security checks
    if 'mfa' in rule_id or 'multi-factor' in title or 'mfa' in requirement:
        return ('mfa_traits.mfa_enabled', 'equals', True)
    
    if 'encryption' in title or 'encrypted' in requirement:
        if 'kms' in title or 'cmk' in title:
            return ('encryption.kms_key_id', 'exists', True)
        return ('encryption_enabled', 'equals', True)
    
    if 'public' in rule_id and 'access' in rule_id:
        return ('public_access', 'equals', False)
    
    if 'logging' in title or 'log' in requirement:
        return ('logging_enabled', 'equals', True)
    
    if 'monitoring' in title:
        return ('monitoring_enabled', 'equals', True)
    
    if 'backup' in title or 'backup' in requirement:
        return ('backup_enabled', 'equals', True)
    
    if 'versioning' in title:
        return ('versioning_enabled', 'equals', True)
    
    if 'rotation' in title:
        if '90' in title:
            return ('last_rotation_date', 'age_days', 90)
        return ('rotation_enabled', 'equals', True)
    
    if 'expired' in title or 'expiration' in title:
        return ('expiration_date', 'not_expired', True)
    
    if 'ssl' in title or 'tls' in title or 'https' in title:
        return ('ssl_enabled', 'equals', True)
    
    if 'least privilege' in title.lower():
        return ('permissions', 'not_contains', '*:*')
    
    if 'admin' in rule_id and 'wildcard' in rule_id:
        return ('actions', 'not_contains', '*')
    
    if 'password' in title:
        if 'length' in title:
            return ('password_policy.min_length', 'greater_than', 14)
        if 'complex' in title or 'strong' in title:
            return ('password_policy.require_uppercase', 'equals', True)
        return ('password_required', 'equals', True)
    
    if 'inactive' in title:
        if '90' in title:
            return ('last_activity', 'age_days', 90)
        return ('state', 'not_equals', 'ACTIVE')
    
    if 'enabled' in requirement:
        return ('enabled', 'equals', True)
    
    if 'disabled' in requirement:
        return ('disabled', 'equals', True)
    
    # Default check
    parsed = parse_rule_id(rule_id)
    check_name = parsed['check'].replace('_', '.')
    return (check_name, 'exists', True)


def create_discovery_for_resource(service: str, resource: str) -> Dict[str, Any]:
    """Create discovery configuration for a resource using SDK mappings"""
    
    # Get SDK mapping for this service/resource
    service_mapping = IBM_SDK_MAPPINGS.get(service, {}).get('discovery', {})
    resource_mapping = service_mapping.get(resource)
    
    if resource_mapping:
        discovery = {
            'discovery_id': f'{service}_{resource}s',
            'calls': [
                {
                    'client': resource_mapping['client'],
                    'action': resource_mapping['method'],
                    'save_as': f'{resource}s',
                    'fields': [{'path': field, 'var': field} for field in resource_mapping['fields']]
                }
            ]
        }
    else:
        # Generic fallback
        discovery = {
            'discovery_id': f'{service}_{resource}s',
            'calls': [
                {
                    'client': service,
                    'action': f'list_{resource}s',
                    'save_as': f'{resource}s',
                    'fields': [
                        {'path': 'id', 'var': f'{resource}_id'},
                        {'path': 'name', 'var': f'{resource}_name'},
                    ]
                }
            ]
        }
    
    return discovery


def create_check_from_rule(rule: Dict[str, Any]) -> Dict[str, Any]:
    """Create a check definition from a rule with SDK-based validation"""
    
    parsed = parse_rule_id(rule['rule_id'])
    resource = parsed['resource']
    service = parsed['service']
    
    # Infer check logic from rule metadata
    field_path, operator, expected = infer_check_logic(rule)
    
    # Build check field
    check_field = {
        'path': field_path,
        'operator': operator,
        'expected': expected
    }
    
    # Get SDK method for getting resource details
    service_mapping = IBM_SDK_MAPPINGS.get(service, {}).get('discovery', {})
    resource_mapping = service_mapping.get(resource, {})
    
    if resource_mapping:
        action = resource_mapping.get('method', f'get_{resource}')
        client = resource_mapping.get('client', service)
    else:
        action = f'get_{resource}'
        client = service
    
    check = {
        'check_id': rule['rule_id'],
        'title': rule.get('title', ''),
        'severity': rule.get('severity', 'medium'),
        'for_each': f"{service}_{resource}s",
        'calls': [
            {
                'client': client,
                'action': action,
                'params': {
                    f'{resource}_id': f'{{{{ {resource}_id }}}}'
                },
                'fields': [check_field]
            }
        ]
    }
    
    return check


def generate_service_yaml(service: str, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate complete service YAML structure with SDK mappings"""
    
    # Group rules by resource
    resources = defaultdict(list)
    for rule in rules:
        parsed = parse_rule_id(rule['rule_id'])
        resource = parsed['resource']
        resources[resource].append(rule)
    
    # Create discoveries for unique resources
    discoveries = []
    discovery_ids = set()
    
    for resource in resources.keys():
        discovery = create_discovery_for_resource(service, resource)
        discovery_id = discovery['discovery_id']
        
        if discovery_id not in discovery_ids:
            discoveries.append(discovery)
            discovery_ids.add(discovery_id)
    
    # Create checks from all rules
    checks = []
    for rule in rules:
        check = create_check_from_rule(rule)
        checks.append(check)
    
    # Determine scope
    scope = 'regional'
    if service in ['iam', 'billing', 'account']:
        scope = 'account'
    
    # Build complete service structure
    service_yaml = {
        service: {
            'version': '1.0',
            'provider': 'ibm',
            'service': service,
            'scope': scope,
            'discovery': discoveries,
            'checks': checks
        }
    }
    
    return service_yaml


def create_metadata_file(rule: Dict[str, Any]) -> Dict[str, Any]:
    """Create metadata file content for a rule"""
    
    metadata = {
        'rule_id': rule['rule_id'],
        'title': rule.get('title', ''),
        'severity': rule.get('severity', 'medium'),
        'domain': rule.get('domain', ''),
        'subcategory': rule.get('subcategory', ''),
        'rationale': rule.get('rationale', ''),
        'description': rule.get('description', ''),
        'references': rule.get('references', [])
    }
    
    return metadata


def main():
    """Main generator function"""
    
    base_dir = os.path.dirname(os.path.abspath(__file__))
    rule_file = os.path.join(base_dir, 'rule_ids_GPT4_ENHANCED.yaml')
    services_dir = os.path.join(base_dir, 'services')
    
    print("=" * 80)
    print("IBM Cloud Compliance Engine - Enhanced Service File Generator")
    print("=" * 80)
    
    # Load rules
    print(f"\n📖 Loading rules from: {rule_file}")
    rules_data = load_rules(rule_file)
    total_rules = len(rules_data.get('rules', []))
    print(f"   ✅ Loaded {total_rules} rules")
    
    # Group by service
    print("\n📊 Grouping rules by service...")
    service_rules = group_rules_by_service(rules_data)
    print(f"   ✅ Found {len(service_rules)} services")
    
    # Display service statistics
    print("\n📈 Service Statistics:")
    for service, rules in sorted(service_rules.items(), key=lambda x: len(x[1]), reverse=True)[:10]:
        print(f"   • {service:30s} : {len(rules):4d} rules")
    print(f"   ... and {len(service_rules) - 10} more services")
    
    # Generate service files
    print("\n🔨 Generating service files with IBM SDK mappings...")
    
    generated_count = 0
    for service, rules in service_rules.items():
        service_path = os.path.join(services_dir, service)
        rules_path = os.path.join(service_path, 'rules')
        metadata_path = os.path.join(service_path, 'metadata')
        
        # Create directories
        os.makedirs(rules_path, exist_ok=True)
        os.makedirs(metadata_path, exist_ok=True)
        
        # Generate service YAML file
        service_yaml = generate_service_yaml(service, rules)
        service_file = os.path.join(rules_path, f'{service}.yaml')
        
        with open(service_file, 'w') as f:
            yaml.dump(service_yaml, f, default_flow_style=False, sort_keys=False, allow_unicode=True, width=120)
        
        generated_count += 1
        if generated_count <= 10:
            print(f"   ✅ {service:30s} : {len(rules):4d} rules")
        
        # Generate metadata files
        for rule in rules:
            metadata = create_metadata_file(rule)
            metadata_file = os.path.join(metadata_path, f"{rule['rule_id']}.yaml")
            
            with open(metadata_file, 'w') as f:
                yaml.dump(metadata, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
    
    print(f"   ... and {generated_count - 10} more services")
    
    print("\n" + "=" * 80)
    print("✅ Service file generation complete!")
    print("=" * 80)
    print(f"\n📁 Generated files in: {services_dir}")
    print(f"   • {len(service_rules)} service YAML files")
    print(f"   • {total_rules} metadata files")
    print(f"   • {sum(len(r) for r in service_rules.values())} total checks")
    print("\n✨ Features:")
    print("   • IBM Cloud SDK method mappings")
    print("   • Smart check logic inference")
    print("   • Proper discovery configurations")
    print("   • Resource-specific validations")
    print("\n⚠️  Next Steps:")
    print("   1. Review generated checks in services/*/rules/*.yaml")
    print("   2. Customize SDK parameters as needed")
    print("   3. Test with IBM Cloud credentials\n")


if __name__ == '__main__':
    main()

