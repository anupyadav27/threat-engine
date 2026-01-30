"""
Auto-generate requirements from Azure metadata using rule-based logic.
Bypasses AI for quick testing of the full pipeline.
"""

import yaml
import json
import os
from typing import Dict, List, Any
from agent_logger import get_logger

logger = get_logger('auto_requirements')

# ALL 58 Azure services with metadata (excluding 6 already completed)
# ✅ = Already done, ⏳ = To process in this run
SERVICES_COMPLETED = ['compute', 'network', 'storage', 'keyvault', 'automation', 'batch']

SERVICES_TO_PROCESS = [
    # ⏳ Large services (100+ rules)
    'machine',  # 194 rules
    'purview',  # 143 rules
    'monitor',  # 101 rules
    'aks',  # 96 rules
    'data',  # 95 rules
    'security',  # 84 rules
    'aad',  # 72 rules
    'sql',  # 65 rules
    'webapp',  # 62 rules
    'policy',  # 51 rules
    'backup',  # 51 rules
    'synapse',  # 41 rules
    'function',  # 41 rules
    'cdn',  # 34 rules
    'api',  # 31 rules
    
    # ⏳ Medium services (10-30 rules)
    'event',  # 14 rules
    'cost',  # 14 rules
    'power',  # 13 rules
    'cosmosdb',  # 13 rules
    'dns',  # 12 rules
    'rbac',  # 10 rules
    
    # ⏳ Small services (1-9 rules)
    'key',  # 9 rules
    'mysql',  # 8 rules
    'databricks',  # 8 rules
    'postgresql',  # 7 rules
    'management',  # 7 rules
    'iam',  # 7 rules
    'containerregistry',  # 7 rules
    'container',  # 7 rules
    'hdinsight',  # 6 rules
    'billing',  # 6 rules
    'search',  # 5 rules
    'resource',  # 5 rules
    'redis',  # 5 rules
    'front',  # 5 rules
    'dataprotection',  # 5 rules
    'traffic',  # 3 rules
    'logic',  # 3 rules
    'log',  # 3 rules
    'files',  # 2 rules
    'elastic',  # 2 rules
    'certificates',  # 2 rules
    'blob',  # 2 rules
    'subscription',  # 1 rules
    'notification',  # 1 rules
    'netappfiles',  # 1 rules
    'mariadb',  # 1 rules
    'managementgroup',  # 1 rules
    'iot',  # 1 rules
    'intune',  # 1 rules
    'devops',  # 1 rules
    'config',  # 1 rules
]


def infer_field_from_rule_id(rule_id: str, requirement: str, description: str) -> Dict[str, Any]:
    """
    Infer field requirements from rule ID and description using patterns.
    """
    rule_lower = rule_id.lower()
    req_lower = requirement.lower()
    desc_lower = description.lower()
    
    # Common patterns
    fields = []
    
    # Encryption checks
    if any(word in rule_lower for word in ['encrypt', 'encryption']):
        if 'soft_delete' in rule_lower:
            fields.append({
                'conceptual_name': 'soft_delete_enabled',
                'azure_sdk_python_field': 'properties.enable_soft_delete',
                'operator': 'equals',
                'azure_sdk_python_field_expected_values': True
            })
        elif 'purge' in rule_lower:
            fields.append({
                'conceptual_name': 'purge_protection',
                'azure_sdk_python_field': 'properties.enable_purge_protection',
                'operator': 'equals',
                'azure_sdk_python_field_expected_values': True
            })
        else:
            fields.append({
                'conceptual_name': 'encryption_enabled',
                'azure_sdk_python_field': 'properties.encryption.enabled',
                'operator': 'equals',
                'azure_sdk_python_field_expected_values': True
            })
    
    # HTTPS/TLS checks
    elif any(word in rule_lower for word in ['https', 'tls', 'ssl']):
        fields.append({
            'conceptual_name': 'https_only',
            'azure_sdk_python_field': 'properties.enable_https_traffic_only',
            'operator': 'equals',
            'azure_sdk_python_field_expected_values': True
        })
    
    # Public access checks
    elif 'public' in rule_lower and 'access' in rule_lower:
        if 'network' in rule_lower or 'firewall' in rule_lower:
            fields.append({
                'conceptual_name': 'public_network_access',
                'azure_sdk_python_field': 'properties.public_network_access',
                'operator': 'equals',
                'azure_sdk_python_field_expected_values': 'Disabled'
            })
        else:
            fields.append({
                'conceptual_name': 'public_access',
                'azure_sdk_python_field': 'properties.allow_blob_public_access',
                'operator': 'equals',
                'azure_sdk_python_field_expected_values': False
            })
    
    # Logging/monitoring checks
    elif any(word in rule_lower for word in ['logging', 'diagnostic', 'audit']):
        fields.append({
            'conceptual_name': 'diagnostic_settings',
            'azure_sdk_python_field': 'properties.diagnostic_settings',
            'operator': 'not_empty',
            'azure_sdk_python_field_expected_values': None
        })
    
    # RBAC/Authorization checks
    elif 'rbac' in rule_lower or 'authorization' in rule_lower:
        fields.append({
            'conceptual_name': 'rbac_enabled',
            'azure_sdk_python_field': 'properties.enable_rbac_authorization',
            'operator': 'equals',
            'azure_sdk_python_field_expected_values': True
        })
    
    # State/Status checks
    elif 'enabled' in rule_lower or 'active' in rule_lower or 'state' in rule_lower:
        if 'subscription' in rule_lower:
            fields.append({
                'conceptual_name': 'subscription_state',
                'azure_sdk_python_field': 'state',
                'operator': 'equals',
                'azure_sdk_python_field_expected_values': 'Enabled'
            })
        else:
            fields.append({
                'conceptual_name': 'provisioning_state',
                'azure_sdk_python_field': 'properties.provisioning_state',
                'operator': 'equals',
                'azure_sdk_python_field_expected_values': 'Succeeded'
            })
    
    # Tag checks
    elif 'tag' in rule_lower:
        fields.append({
            'conceptual_name': 'has_tags',
            'azure_sdk_python_field': 'tags',
            'operator': 'not_empty',
            'azure_sdk_python_field_expected_values': None
        })
    
    # Network/firewall checks
    elif 'firewall' in rule_lower or 'network_rule' in rule_lower:
        fields.append({
            'conceptual_name': 'firewall_configured',
            'azure_sdk_python_field': 'properties.network_rule_set',
            'operator': 'not_empty',
            'azure_sdk_python_field_expected_values': None
        })
    
    # Default: Check if resource exists with basic validation
    else:
        fields.append({
            'conceptual_name': 'resource_exists',
            'azure_sdk_python_field': 'id',
            'operator': 'exists',
            'azure_sdk_python_field_expected_values': None
        })
    
    return {
        'fields': fields,
        'condition_logic': 'single' if len(fields) == 1 else 'all'
    }


def get_metadata_files(service: str):
    """Get all metadata YAML files for a service"""
    metadata_dir = f"../services/{service}/metadata"
    if not os.path.exists(metadata_dir):
        return []
    
    files = []
    for file in os.listdir(metadata_dir):
        if file.endswith('.yaml') and file.startswith('azure.'):
            files.append(os.path.join(metadata_dir, file))
    
    return files


def main():
    logger.info("Starting auto requirements generation")
    print("=" * 80)
    print("AUTO REQUIREMENTS GENERATOR (Rule-Based)")
    print("=" * 80)
    print("Generates requirements from metadata using pattern matching")
    print()
    
    all_requirements = {}
    total_rules = 0
    
    for service in SERVICES_TO_PROCESS:
        logger.info(f"Processing service: {service}")
        print(f"\n📦 {service}")
        
        metadata_files = get_metadata_files(service)
        
        if not metadata_files:
            logger.warning(f"No metadata files for {service}")
            print(f"   ⚠️  No metadata files")
            continue
        
        service_requirements = []
        
        for metadata_file in metadata_files:
            with open(metadata_file) as f:
                metadata = yaml.safe_load(f)
            
            rule_id = metadata.get('rule_id', '')
            requirement = metadata.get('requirement', '')
            description = metadata.get('description', '')
            
            # Generate requirements using pattern matching
            ai_reqs = infer_field_from_rule_id(rule_id, requirement, description)
            
            service_requirements.append({
                'rule_id': rule_id,
                'service': service,
                'requirement': requirement,
                'description': description,
                'severity': metadata.get('severity', 'medium'),
                'ai_generated_requirements': ai_reqs
            })
            
            total_rules += 1
        
        all_requirements[service] = service_requirements
        print(f"   ✅ {len(service_requirements)} rules")
        logger.info(f"Processed {len(service_requirements)} rules for {service}")
    
    # Save
    os.makedirs('output', exist_ok=True)
    output_file = 'output/requirements_initial.json'
    with open(output_file, 'w') as f:
        json.dump(all_requirements, f, indent=2)
    
    print("\n" + "=" * 80)
    print(f"✅ Generated {total_rules} requirements for {len(all_requirements)} services")
    print(f"Saved to: {output_file}")
    print()
    print("Services processed:")
    for service, rules in all_requirements.items():
        print(f"  - {service:20s}: {len(rules):3d} rules")
    print()
    print("Next: Run Agent 2 (Function Validator)")
    print("=" * 80)
    
    logger.info(f"Auto-generation complete: {total_rules} requirements")
    logger.info(f"Output: {output_file}")


if __name__ == '__main__':
    main()

