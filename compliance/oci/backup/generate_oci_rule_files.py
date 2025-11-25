#!/usr/bin/env python3
"""
Generate OCI Rule YAML Files and Metadata
Creates properly structured rule files following the AWS pattern:
- oci_compliance_python_engine/services/{service}/rules/{service}.yaml
- oci_compliance_python_engine/services/{service}/metadata/oci.{rule_id}.yaml
"""

import yaml
import os
from pathlib import Path
from collections import defaultdict
from datetime import datetime

# Load OCI rules
print("Loading OCI rules...")
with open('rule_ids.yaml', 'r') as f:
    data = yaml.safe_load(f)

rules = data['rule_ids']
print(f"Loaded {len(rules)} rules")

# Group rules by service
rules_by_service = defaultdict(list)
for rule in rules:
    parts = rule.split('.')
    if len(parts) >= 4:
        service = parts[1]
        resource = parts[2]
        assertion = '.'.join(parts[3:])
        rules_by_service[service].append({
            'rule_id': rule,
            'service': service,
            'resource': resource,
            'assertion': assertion
        })

print(f"\nGrouped into {len(rules_by_service)} services")

# Create base directory structure
base_dir = Path("../../oci_compliance_python_engine/services")
base_dir.mkdir(parents=True, exist_ok=True)

print("\nGenerating rule files and metadata...")

# OCI SDK client mappings (simplified)
OCI_CLIENT_MAP = {
    'compute': 'ComputeClient',
    'database': 'DatabaseClient',
    'object_storage': 'ObjectStorageClient',
    'block_storage': 'BlockstorageClient',
    'virtual_network': 'VirtualNetworkClient',
    'identity': 'IdentityClient',
    'key_management': 'KmsVaultClient',
    'monitoring': 'MonitoringClient',
    'logging': 'LoggingManagementClient',
    'audit': 'AuditClient',
    'data_science': 'DataScienceClient',
    'data_catalog': 'DataCatalogClient',
    'data_integration': 'DataIntegrationClient',
    'analytics': 'AnalyticsClient',
    'cloud_guard': 'CloudGuardClient',
    'container_engine': 'ContainerEngineClient',
    'functions': 'FunctionsManagementClient',
    'apigateway': 'ApiGatewayClient',
    'waf': 'WafClient',
    'load_balancer': 'LoadBalancerClient',
    'dns': 'DnsClient',
}

# Resource type mappings
RESOURCE_TYPE_MAP = {
    'instance': 'compute.instance',
    'volume': 'storage.volume',
    'bucket': 'storage.bucket',
    'autonomous_database': 'database.autonomous_database',
    'vcn': 'network.vcn',
    'subnet': 'network.subnet',
    'user': 'identity.user',
    'policy': 'identity.policy',
    'vault': 'security.vault',
    'cluster': 'container.cluster',
    'function': 'serverless.function',
    'gateway': 'api.gateway',
    'alarm': 'monitoring.alarm',
    'log_group': 'logging.log_group',
}

# Severity mapping based on assertion keywords
def infer_severity(assertion):
    """Infer severity from assertion keywords"""
    assertion_lower = assertion.lower()
    
    if any(kw in assertion_lower for kw in ['public', 'exposed', 'anonymous', 'unencrypted', 'insecure', 'admin']):
        return 'critical'
    elif any(kw in assertion_lower for kw in ['encryption', 'kms', 'cmek', 'tls', 'ssl', 'mfa', 'rbac']):
        return 'high'
    elif any(kw in assertion_lower for kw in ['logging', 'monitoring', 'audit', 'backup', 'versioning']):
        return 'medium'
    else:
        return 'low'

def generate_rule_yaml(service, service_rules):
    """Generate the main rule YAML file for a service"""
    
    # Get client name
    client = OCI_CLIENT_MAP.get(service, f"{service.title()}Client")
    
    # Build discovery section
    discovery = {
        'discovery_id': f'oci.{service}.resources',
        'calls': [{
            'client': client,
            'action': f'list_{service}_resources',
            'paginate': True,
            'fields': ['id', 'name', 'lifecycle_state']
        }],
        'emit': {
            'items_for': {
                'as': 'resource',
                'item': 'resource_id'
            }
        }
    }
    
    # Build checks section
    checks = []
    for rule_data in service_rules:
        check = {
            'rule_id': rule_data['rule_id'],
            'for_each': f"oci.{service}.resources",
            'conditions': {
                'var': f"resource.{rule_data['assertion'].replace('.', '_')}",
                'op': 'equals',
                'value': True
            }
        }
        checks.append(check)
    
    # Complete rule structure
    rule_yaml = {
        'version': '1.0',
        'provider': 'oci',
        'service': service,
        'discovery': [discovery],
        'checks': checks
    }
    
    return rule_yaml

def generate_metadata_yaml(rule_data, service):
    """Generate metadata YAML for a single rule"""
    
    assertion = rule_data['assertion']
    resource = rule_data['resource']
    rule_id = rule_data['rule_id']
    
    # Infer details from assertion
    severity = infer_severity(assertion)
    
    # Create human-readable title
    title_parts = assertion.replace('_', ' ').title()
    title = f"OCI {service.replace('_', ' ').title()} - {title_parts}"
    
    # Determine resource type
    resource_type = RESOURCE_TYPE_MAP.get(resource, f"{service}.{resource}")
    
    # Build metadata
    metadata = {
        'metadata': {
            'rule_id': rule_id,
            'title': title,
            'description': f"Ensure {assertion.replace('_', ' ')} for OCI {service} {resource}",
            
            # CSPM Categorization
            'cspm_category': infer_category(assertion),
            'cspm_subcategory': infer_subcategory(assertion),
            'security_domain': infer_security_domain(assertion),
            
            # Service & Resource
            'service': service,
            'resource_type': resource_type,
            'resource_scope': 'resource',
            'adapter': f'oci.{service}.{resource}',
            
            # Risk & Severity
            'severity': severity,
            'risk_score': severity_to_score(severity),
            'impact': severity,
            'likelihood': 'medium',
            
            # Detection
            'evidence_type': 'config_read',
            'detection_method': 'static',
            'detection_capability': 'automated',
            
            # Coverage
            'coverage_tier': 'core',
            'priority': severity_to_priority(severity),
            'recommended_frequency': 'continuous',
            
            # Remediation
            'remediation': {
                'description': f"Configure {assertion.replace('_', ' ')} for the {resource}",
                'automated': False,
                'remediation_type': 'config_change',
                'estimated_time': 'minutes',
                'complexity': 'low'
            },
            
            # Context
            'rationale': f"This control ensures {assertion.replace('_', ' ')} is properly configured",
            
            # Timestamps
            'created_at': datetime.now().isoformat(),
            'updated_at': datetime.now().isoformat()
        }
    }
    
    return metadata

def infer_category(assertion):
    """Infer CSPM category from assertion"""
    assertion_lower = assertion.lower()
    
    if any(kw in assertion_lower for kw in ['encrypt', 'kms', 'cmek', 'tls', 'ssl']):
        return 'data_security'
    elif any(kw in assertion_lower for kw in ['rbac', 'policy', 'privilege', 'access', 'iam', 'auth']):
        return 'entitlement'
    elif any(kw in assertion_lower for kw in ['network', 'firewall', 'vpc', 'subnet', 'cidr']):
        return 'network_security'
    elif any(kw in assertion_lower for kw in ['logging', 'monitoring', 'audit', 'alert']):
        return 'monitoring_detection'
    elif any(kw in assertion_lower for kw in ['backup', 'replication', 'snapshot', 'dr']):
        return 'storage_security'
    elif any(kw in assertion_lower for kw in ['key', 'secret', 'certificate', 'vault']):
        return 'secrets_management'
    else:
        return 'compliance_governance'

def infer_subcategory(assertion):
    """Infer CSPM subcategory from assertion"""
    assertion_lower = assertion.lower()
    
    if 'encrypt' in assertion_lower and 'rest' in assertion_lower:
        return 'data_encryption_at_rest'
    elif 'encrypt' in assertion_lower or 'tls' in assertion_lower:
        return 'data_encryption_in_transit'
    elif 'rbac' in assertion_lower or 'privilege' in assertion_lower:
        return 'access_control'
    elif 'logging' in assertion_lower:
        return 'audit_logging'
    elif 'monitor' in assertion_lower:
        return 'security_monitoring'
    elif 'backup' in assertion_lower:
        return 'backup_security'
    else:
        return 'configuration_management'

def infer_security_domain(assertion):
    """Infer security domain from assertion"""
    category = infer_category(assertion)
    
    domain_map = {
        'data_security': 'data_security',
        'entitlement': 'identity_access',
        'network_security': 'network_security',
        'monitoring_detection': 'monitoring_detection',
        'storage_security': 'data_security',
        'secrets_management': 'secrets_management',
        'compliance_governance': 'compliance_governance',
    }
    
    return domain_map.get(category, 'infrastructure_security')

def severity_to_score(severity):
    """Convert severity to risk score"""
    scores = {'critical': 90, 'high': 75, 'medium': 50, 'low': 25}
    return scores.get(severity, 50)

def severity_to_priority(severity):
    """Convert severity to priority"""
    priorities = {'critical': 'p0', 'high': 'p1', 'medium': 'p2', 'low': 'p3'}
    return priorities.get(severity, 'p2')

# Generate files for each service
total_services = 0
total_rules = 0
total_metadata = 0

for service, service_rules in sorted(rules_by_service.items()):
    # Create service directory
    service_dir = base_dir / service
    rules_dir = service_dir / 'rules'
    metadata_dir = service_dir / 'metadata'
    
    rules_dir.mkdir(parents=True, exist_ok=True)
    metadata_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate main rule file
    rule_yaml = generate_rule_yaml(service, service_rules)
    rule_file = rules_dir / f"{service}.yaml"
    
    with open(rule_file, 'w') as f:
        yaml.dump(rule_yaml, f, default_flow_style=False, sort_keys=False, width=120)
    
    total_services += 1
    total_rules += 1
    
    # Generate metadata for each rule
    for rule_data in service_rules:
        metadata_yaml = generate_metadata_yaml(rule_data, service)
        metadata_file = metadata_dir / f"{rule_data['rule_id']}.yaml"
        
        with open(metadata_file, 'w') as f:
            yaml.dump(metadata_yaml, f, default_flow_style=False, sort_keys=False, width=120)
        
        total_metadata += 1
    
    print(f"  ✅ {service}: {len(service_rules)} rules")

print("\n" + "="*80)
print("📊 GENERATION COMPLETE")
print("="*80)
print(f"Services: {total_services}")
print(f"Rule Files: {total_rules}")
print(f"Metadata Files: {total_metadata}")
print(f"Output Directory: {base_dir.absolute()}")
print("="*80)

