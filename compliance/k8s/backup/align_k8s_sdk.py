#!/usr/bin/env python3
"""
Kubernetes Rules - Align with K8s Python SDK
Standardize services and resources to kubernetes-client (Python SDK) naming conventions
Reference: https://github.com/kubernetes-client/python
"""

import yaml
from datetime import datetime
from collections import Counter

print("=" * 100)
print("KUBERNETES - PYTHON SDK ALIGNMENT")
print("=" * 100)

# Load rules
with open('rule_ids.yaml', 'r') as f:
    data = yaml.safe_load(f)

rules = data['rule_ids']
print(f"\nTotal Rules: {len(rules)}")

# Backup
backup_file = f"rule_ids_BACKUP_SDK_ALIGNMENT_{datetime.now().strftime('%Y%m%d_%H%M%S')}.yaml"
print(f"Creating backup: {backup_file}")
with open(backup_file, 'w') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False)

# === Kubernetes Python SDK Service Mappings ===
# Based on kubernetes.client API groups
K8S_SDK_SERVICE_MAPPINGS = {
    # Core Workload Resources (kubernetes.client.CoreV1Api)
    'pod': 'pod',
    'workload': 'deployment',  # workload → deployment (most common)
    'deployment': 'deployment',
    'service': 'service',
    'namespace': 'namespace',
    'configmap': 'configmap',
    'node': 'node',
    
    # RBAC Resources (kubernetes.client.RbacAuthorizationV1Api)
    'rbac': 'rbac',
    'role': 'rbac',
    'rolebinding': 'rbac',
    'clusterrole': 'rbac',
    'clusterrolebinding': 'rbac',
    'serviceaccount': 'serviceaccount',
    
    # Security & Policy (kubernetes.client.PolicyV1Api, AdmissionregistrationV1Api)
    'admission': 'admission',
    'policy': 'policy',
    'security': 'podsecuritypolicy',
    'podsecuritypolicy': 'podsecuritypolicy',
    
    # Networking (kubernetes.client.NetworkingV1Api)
    'network': 'networkpolicy',
    'networkpolicy': 'networkpolicy',
    'ingress': 'ingress',
    
    # Storage (kubernetes.client.StorageV1Api)
    'storage': 'persistentvolume',
    'persistentvolume': 'persistentvolume',
    'persistentvolumeclaim': 'persistentvolumeclaim',
    'storageclass': 'storageclass',
    
    # Secrets & Config (kubernetes.client.CoreV1Api)
    'secret': 'secret',
    'data': 'secret',  # data protection → secret
    
    # Cluster Components (Control Plane)
    'cluster': 'cluster',
    'apiserver': 'apiserver',
    'etcd': 'etcd',
    'kubelet': 'kubelet',
    'kubeproxy': 'kubeproxy',
    'scheduler': 'scheduler',
    'controllermanager': 'controllermanager',
    'kube': 'cluster',  # kube.* → cluster
    
    # Autoscaling (kubernetes.client.AutoscalingV2Api)
    'hpa': 'horizontalpodautoscaler',
    'horizontalpodautoscaler': 'horizontalpodautoscaler',
    'vpa': 'verticalpodautoscaler',
    
    # Batch/Jobs (kubernetes.client.BatchV1Api)
    'job': 'job',
    'cronjob': 'cronjob',
    
    # Apps/Workloads (kubernetes.client.AppsV1Api)
    'daemonset': 'daemonset',
    'statefulset': 'statefulset',
    'replicaset': 'replicaset',
    
    # Monitoring & Observability
    'monitoring': 'monitoring',
    
    # Supply Chain & Images
    'supply_chain_security': 'image',
    'image': 'image',
    
    # Misc
    'certificate': 'certificate',
    'event': 'event',
    'inventory': 'cluster',
    'software': 'pod',
    'worker': 'node',
    'control': 'cluster',
    'config': 'configmap',
    'resource': 'pod',
    'federation': 'cluster',
}

# === Kubernetes Python SDK Resource Mappings ===
K8S_SDK_RESOURCE_MAPPINGS = {
    # Pod-related
    'capabilities_management': 'securitycontext',
    'privilege_escalation': 'securitycontext',
    'image': 'container',
    
    # RBAC-related
    'service_accounts': 'serviceaccount',
    'authorization': 'rolebinding',
    
    # Secret-related
    'configmap_security': 'configmap',
    'key_rotation': 'secret',
    'secret_detection': 'secret',
    'secret_rotation': 'secret',
    
    # Admission-related
    'admissioncontroller': 'validatingwebhookconfiguration',
    'admission_control': 'validatingwebhookconfiguration',
    'admission_controllers': 'validatingwebhookconfiguration',
    'kyverno_policies': 'policy',
    'opa_gatekeeper': 'policy',
    'mutating_admission_webhooks': 'mutatingwebhookconfiguration',
    'validating_admission_webhooks': 'validatingwebhookconfiguration',
    'policy_governance': 'policy',
    
    # Cluster component resources
    'control_plane_security': 'cluster',
    'node_security': 'node',
    'container_runtime_security': 'node',
    'host_level_security': 'node',
    'network_plugin_security': 'node',
    
    # Network-related
    'servicemesh': 'service',
    'dns_security': 'service',
    'egress_controls': 'networkpolicy',
    'micro_segmentation': 'networkpolicy',
    'service_to_service_encryption': 'service',
    
    # Monitoring-related
    'audit_logging': 'audit',
    'monitoring_alerting': 'audit',
    'compliance_reporting': 'audit',
    'log_analysis': 'audit',
    
    # Workload-related
    'daemonset_security': 'daemonset',
    'statefulset_security': 'statefulset',
    'cronjob_security': 'cronjob',
    'deployment_security': 'deployment',
    'job_security': 'job',
    'pod_security_standards': 'podsecuritypolicy',
    
    # Storage-related
    'backup_security': 'persistentvolume',
    'storage_encryption': 'persistentvolume',
    'volume_encryption': 'persistentvolume',
    'volume_mount_security': 'volumemount',
    'persistent_volume_security': 'persistentvolume',
    
    # Data/Policy-related
    'data_loss_prevention': 'networkpolicy',
    'dlp_policies': 'networkpolicy',
    'cross_border_transfer': 'networkpolicy',
    'data_classification': 'label',
    'privacy_controls': 'networkpolicy',
    'namespace_governance': 'namespace',
    'compliance_automation': 'policy',
    'compliance_frameworks': 'policy',
    'policy_as_code': 'policy',
    'risk_management': 'policy',
    
    # Security-related
    'automated_response': 'event',
    'forensic_capabilities': 'audit',
    'zero_trust_networking': 'networkpolicy',
    
    # Network policy specific
    'egress_restricted_to_security_services': 'networkpolicy',
    'internal_traffic_restricted': 'networkpolicy',
    'inventory_documented': 'label',
    'isolate_healthcare_clearinghouse': 'networkpolicy',
    
    # API Server specific
    'server_admission_plugins_always_pull_images_set': 'apiserver',
    
    # Keep standard K8s resources as-is
    'pod': 'pod',
    'container': 'container',
    'serviceaccount': 'serviceaccount',
    'role': 'role',
    'rolebinding': 'rolebinding',
    'clusterrole': 'clusterrole',
    'clusterrolebinding': 'clusterrolebinding',
    'networkpolicy': 'networkpolicy',
    'secret': 'secret',
    'configmap': 'configmap',
    'service': 'service',
    'ingress': 'ingress',
    'deployment': 'deployment',
    'daemonset': 'daemonset',
    'statefulset': 'statefulset',
    'replicaset': 'replicaset',
    'job': 'job',
    'cronjob': 'cronjob',
    'persistentvolume': 'persistentvolume',
    'persistentvolumeclaim': 'persistentvolumeclaim',
    'storageclass': 'storageclass',
    'namespace': 'namespace',
    'node': 'node',
    'apiserver': 'apiserver',
    'etcd': 'etcd',
    'kubelet': 'kubelet',
    'scheduler': 'scheduler',
    'controllermanager': 'controllermanager',
    'audit': 'audit',
    'policy': 'policy',
    'cluster': 'cluster',
    'certificate': 'certificate',
    'token': 'token',
    'event': 'event',
    'label': 'label',
    'annotation': 'annotation',
}

# Service-specific default resources (if resource needs inference)
SERVICE_DEFAULT_RESOURCES = {
    'pod': 'pod',
    'deployment': 'deployment',
    'service': 'service',
    'namespace': 'namespace',
    'configmap': 'configmap',
    'node': 'node',
    'rbac': 'role',
    'serviceaccount': 'serviceaccount',
    'admission': 'validatingwebhookconfiguration',
    'policy': 'policy',
    'podsecuritypolicy': 'podsecuritypolicy',
    'networkpolicy': 'networkpolicy',
    'ingress': 'ingress',
    'persistentvolume': 'persistentvolume',
    'persistentvolumeclaim': 'persistentvolumeclaim',
    'storageclass': 'storageclass',
    'secret': 'secret',
    'cluster': 'cluster',
    'apiserver': 'apiserver',
    'etcd': 'etcd',
    'kubelet': 'kubelet',
    'kubeproxy': 'kubeproxy',
    'scheduler': 'scheduler',
    'controllermanager': 'controllermanager',
    'horizontalpodautoscaler': 'horizontalpodautoscaler',
    'job': 'job',
    'cronjob': 'cronjob',
    'daemonset': 'daemonset',
    'statefulset': 'statefulset',
    'replicaset': 'replicaset',
    'monitoring': 'audit',
    'image': 'container',
    'certificate': 'certificate',
    'event': 'event',
}

def normalize_service(service):
    """Normalize service to K8s Python SDK standard"""
    return K8S_SDK_SERVICE_MAPPINGS.get(service, service)

def normalize_resource(service, resource):
    """Normalize resource to K8s Python SDK standard"""
    # Check if there's a specific mapping
    if resource in K8S_SDK_RESOURCE_MAPPINGS:
        return K8S_SDK_RESOURCE_MAPPINGS[resource]
    
    # If still generic, use service default
    if resource == 'resource' and service in SERVICE_DEFAULT_RESOURCES:
        return SERVICE_DEFAULT_RESOURCES[service]
    
    return resource

# Apply transformations
updated_rules = []
service_changes = Counter()
resource_changes = Counter()

for rule in rules:
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

print(f"\nServices normalized: {len(service_changes)}")
print(f"Resources normalized: {len(resource_changes)}")
print(f"Total transformations: {sum(service_changes.values()) + sum(resource_changes.values())}")

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
    print("TOP 30 RESOURCE TRANSFORMATIONS")
    print(f"{'=' * 100}")
    
    for change, count in resource_changes.most_common(30):
        print(f"{change:70s} {count:3d} rules")

# Update metadata
data['rule_ids'] = updated_rules
data['metadata']['total_rules'] = len(updated_rules)
data['metadata']['last_sdk_alignment'] = datetime.now().isoformat()
data['metadata']['sdk_version'] = 'kubernetes_python_client_v1'
data['metadata']['services_sdk_aligned'] = len(service_changes)
data['metadata']['resources_sdk_aligned'] = len(resource_changes)

# Save
print(f"\n{'=' * 100}")
print("SAVING UPDATED RULES")
print(f"{'=' * 100}")

with open('rule_ids.yaml', 'w') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False)

print(f"\n✅ Kubernetes Python SDK Alignment Complete!")
print(f"✅ Services Aligned: {len(service_changes)}")
print(f"✅ Resources Aligned: {len(resource_changes)}")
print(f"✅ Total Transformations: {sum(service_changes.values()) + sum(resource_changes.values())}")
print(f"✅ Backup: {backup_file}")
print(f"\n{'=' * 100}")

