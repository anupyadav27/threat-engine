#!/usr/bin/env python3
"""
Kubernetes Rules - Convert to Standard Format
k8s.service.resource.security_check_assertion

Align with Kubernetes API and standard K8s resource types
"""

import yaml
from datetime import datetime
from collections import Counter

print("=" * 100)
print("KUBERNETES RULES - FORMAT CONVERSION")
print("=" * 100)

# Load rules
with open('rule_ids.yaml', 'r') as f:
    data = yaml.safe_load(f)

rules = data['rule_ids']
print(f"\nTotal Rules: {len(rules)}")

# Backup
backup_file = f"rule_ids_BACKUP_FORMAT_CONVERSION_{datetime.now().strftime('%Y%m%d_%H%M%S')}.yaml"
print(f"Creating backup: {backup_file}")
with open(backup_file, 'w') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False)

# Kubernetes Service Mappings (Category → K8s API Service/Component)
K8S_SERVICE_MAPPINGS = {
    # Category-based services → K8s standard components
    'pod_container_security': 'pod',
    'identity_access': 'rbac',  # K8s RBAC
    'secrets_config_mgmt': 'secret',
    'network_security': 'network',
    'cluster_component_security': 'cluster',
    'monitoring_observability': 'monitoring',
    'admission_policy_enforcement': 'admission',
    'workload_security': 'workload',
    'storage_security': 'storage',
    'data_protection': 'data',
    'compliance_governance': 'policy',
    'infrastructure_security': 'node',
    'zero_trust_security': 'security',
    'incident_response': 'security',
    
    # Already standard K8s components (keep as-is)
    'admission': 'admission',
    'api': 'apiserver',
    'apiserver': 'apiserver',
    'pod': 'pod',
    'node': 'node',
    'networkpolicy': 'networkpolicy',
    'service': 'service',
    'deployment': 'deployment',
    'daemonset': 'daemonset',
    'statefulset': 'statefulset',
    'configmap': 'configmap',
    'secret': 'secret',
    'ingress': 'ingress',
    'namespace': 'namespace',
    'serviceaccount': 'serviceaccount',
    'role': 'rbac',
    'rolebinding': 'rbac',
    'clusterrole': 'rbac',
    'clusterrolebinding': 'rbac',
    'psp': 'podsecuritypolicy',
    'pv': 'persistentvolume',
    'pvc': 'persistentvolumeclaim',
    'etcd': 'etcd',
    'kubelet': 'kubelet',
    'kube_proxy': 'kubeproxy',
    'scheduler': 'scheduler',
    'controller_manager': 'controllermanager',
}

# Kubernetes Resource Mappings (descriptive → K8s standard)
K8S_RESOURCE_MAPPINGS = {
    # Generic 'resource' → specific K8s resources
    'resource': 'pod',  # Will be context-specific
    
    # Security-related
    'authentication': 'serviceaccount',
    'rbac_policies': 'role',
    'secret_encryption': 'secret',
    'secret_access_controls': 'secret',
    'api_server_security': 'apiserver',
    'pod_security_standards': 'pod',
    'security_monitoring': 'audit',
    'ingress_security': 'ingress',
    'network_policies': 'networkpolicy',
    
    # Infrastructure
    'etcd_security': 'etcd',
    'kubelet_security': 'kubelet',
    'host_access_controls': 'node',
    'hardware_security': 'node',
    
    # Supply chain & images
    'supply_chain_security': 'image',
    'image_security': 'image',
    
    # Service mesh
    'service_mesh_security': 'servicemesh',
    'zero_trust_networking': 'networkpolicy',
    
    # Policy & Governance
    'policy_governance': 'policy',
    
    # Token & Auth
    'token_management': 'token',
}

# Service-specific default resources
SERVICE_DEFAULT_RESOURCES = {
    'pod': 'container',
    'rbac': 'role',
    'secret': 'secret',
    'network': 'networkpolicy',
    'cluster': 'cluster',
    'monitoring': 'audit',
    'admission': 'admissioncontroller',
    'workload': 'deployment',
    'storage': 'persistentvolume',
    'data': 'secret',
    'policy': 'policy',
    'node': 'node',
    'security': 'policy',
    'apiserver': 'apiserver',
    'networkpolicy': 'networkpolicy',
    'service': 'service',
    'deployment': 'deployment',
    'daemonset': 'daemonset',
    'statefulset': 'statefulset',
    'configmap': 'configmap',
    'ingress': 'ingress',
    'namespace': 'namespace',
    'serviceaccount': 'serviceaccount',
    'podsecuritypolicy': 'podsecuritypolicy',
    'persistentvolume': 'persistentvolume',
    'persistentvolumeclaim': 'persistentvolumeclaim',
    'etcd': 'etcd',
    'kubelet': 'kubelet',
    'kubeproxy': 'kubeproxy',
    'scheduler': 'scheduler',
    'controllermanager': 'controllermanager',
}

def normalize_service(service):
    """Normalize service name to K8s standard"""
    return K8S_SERVICE_MAPPINGS.get(service, service)

def normalize_resource(service, resource):
    """Normalize resource name to K8s standard"""
    # Check if it's generic 'resource'
    if resource == 'resource':
        return SERVICE_DEFAULT_RESOURCES.get(service, 'pod')
    
    # Check if there's a specific mapping
    if resource in K8S_RESOURCE_MAPPINGS:
        return K8S_RESOURCE_MAPPINGS[resource]
    
    return resource

# Apply transformations
updated_rules = []
service_changes = Counter()
resource_changes = Counter()
needs_dev_fixed = 0

for rule in rules:
    if rule == 'NEEDS_DEVELOPMENT' or rule.startswith('NEEDS_'):
        # Skip NEEDS_DEVELOPMENT entries
        needs_dev_fixed += 1
        continue
    
    parts = rule.split('.')
    
    if len(parts) >= 3 and parts[0] == 'k8s':
        csp = parts[0]
        service = parts[1]
        resource = parts[2]
        assertion = '.'.join(parts[3:]) if len(parts) > 3 else ''
        
        # Normalize service
        new_service = normalize_service(service)
        if service != new_service:
            service_changes[f"{service} → {new_service}"] += 1
        
        # Normalize resource
        new_resource = normalize_resource(new_service, resource)
        if resource != new_resource:
            resource_changes[f"{resource} → {new_resource}"] += 1
        
        # Build new rule
        if assertion:
            new_rule = f"{csp}.{new_service}.{new_resource}.{assertion}"
        else:
            new_rule = f"{csp}.{new_service}.{new_resource}"
        
        updated_rules.append(new_rule)
    else:
        updated_rules.append(rule)

# Display results
print(f"\n{'=' * 100}")
print("TRANSFORMATION RESULTS")
print(f"{'=' * 100}")

print(f"\nNEEDS_DEVELOPMENT removed: {needs_dev_fixed}")
print(f"Services normalized: {len(service_changes)}")
print(f"Resources normalized: {len(resource_changes)}")
print(f"\nOriginal Rules:  {len(rules)}")
print(f"Final Rules:     {len(updated_rules)}")
print(f"Rules Changed:   {sum(service_changes.values()) + sum(resource_changes.values())}")

# Top service changes
if service_changes:
    print(f"\n{'=' * 100}")
    print("TOP 20 SERVICE TRANSFORMATIONS")
    print(f"{'=' * 100}")
    
    for change, count in service_changes.most_common(20):
        print(f"{change:70s} {count:3d} rules")

# Top resource changes
if resource_changes:
    print(f"\n{'=' * 100}")
    print("TOP 20 RESOURCE TRANSFORMATIONS")
    print(f"{'=' * 100}")
    
    for change, count in resource_changes.most_common(20):
        print(f"{change:70s} {count:3d} rules")

# Update metadata
data['rule_ids'] = updated_rules
data['metadata']['total_rules'] = len(updated_rules)
data['metadata']['last_format_conversion'] = datetime.now().isoformat()
data['metadata']['format_version'] = 'k8s_standard_v1'
data['metadata']['services_normalized'] = len(service_changes)
data['metadata']['resources_normalized'] = len(resource_changes)
data['metadata']['needs_dev_removed'] = needs_dev_fixed

# Save
print(f"\n{'=' * 100}")
print("SAVING UPDATED RULES")
print(f"{'=' * 100}")

with open('rule_ids.yaml', 'w') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False)

print(f"\n✅ Format Conversion Complete!")
print(f"✅ Services Normalized: {len(service_changes)}")
print(f"✅ Resources Normalized: {len(resource_changes)}")
print(f"✅ NEEDS_DEVELOPMENT Removed: {needs_dev_fixed}")
print(f"✅ Final Rules: {len(updated_rules)}")
print(f"✅ Backup: {backup_file}")
print(f"\n{'=' * 100}")

