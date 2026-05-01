#!/usr/bin/env python3
"""
add_missing_k8s_ops.py
Add 51 missing ops (alias variants) to k8s_master_read_ops.csv
"""
import csv
from pathlib import Path
from datetime import timezone, datetime

MASTER = Path('/Users/apple/Desktop/threat-engine/catalog/discovery_generator/k8s/k8s_master_read_ops.csv')
csv.field_size_limit(10_000_000)

rows = list(csv.DictReader(MASTER.open()))
fieldnames = list(rows[0].keys())
master = {r['producing_op'].strip(): r for r in rows}
existing_ops = set(master.keys())
new_ops = []

NOW = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def clone(base_op: str, new_op: str, new_svc: str = None):
    """Clone an existing op row under a new op id (alias)."""
    if new_op in existing_ops:
        return
    base = master.get(base_op)
    if not base:
        print(f"  WARNING: base op not found: {base_op}")
        return
    row = dict(base)
    row['producing_op'] = new_op
    if new_svc:
        row['service'] = new_svc
    row['updated_at'] = NOW
    new_ops.append(row)
    existing_ops.add(new_op)


def add(op: str, service: str, python_call: str,
        op_kind: str = 'read_list', is_independent: str = 'Yes',
        root_op: str = '', produced_fields: str = '',
        resource_id_field: str = '', resource_id_param: str = ''):
    """Add a brand-new op row."""
    if op in existing_ops:
        return
    row = {k: '' for k in fieldnames}
    row.update({
        'csp': 'k8s',
        'service': service,
        'producing_op': op,
        'op_kind': op_kind,
        'is_independent': is_independent,
        'root_op': root_op,
        'python_call': python_call,
        'produced_fields': produced_fields,
        'resource_id_field': resource_id_field,
        'resource_id_param': resource_id_param,
        'is_active': 'true',
        'updated_at': NOW,
    })
    new_ops.append(row)
    existing_ops.add(op)


# ── Deployment aliases ────────────────────────────────────────────────────────
clone('k8s.deployment.list', 'k8s.apps.list_deployments',       'apps')
clone('k8s.deployment.list', 'k8s.deployment.list_deployments',  'deployment')
clone('k8s.deployment.list', 'k8s.deployments.list',             'deployments')

# ── DaemonSet aliases ─────────────────────────────────────────────────────────
clone('k8s.daemonset.list',  'k8s.cluster.list_daemonset',       'cluster')
clone('k8s.daemonset.list',  'k8s.daemonset.list_daemonsets',    'daemonset')
clone('k8s.workload.list_deployment_for_all_namespaces', 'k8s.workload.list_daemonset_for_all_namespaces', 'workload')

# ── Pod aliases ───────────────────────────────────────────────────────────────
clone('k8s.pod.list',        'k8s.pod.list_pods',                'pod')
clone('k8s.pod.list',        'k8s.pods.list',                    'pods')
clone('k8s.pod.list',        'k8s.core.list_pods',               'core')
clone('k8s.pod.list',        'k8s.general.list_pods',            'general')

# ── Secret aliases ────────────────────────────────────────────────────────────
clone('k8s.secret.list',     'k8s.cluster.list_secret',          'cluster')
clone('k8s.secret.list',     'k8s.secret.list_secrets',          'secret')
clone('k8s.secret.list',     'k8s.core.list_secrets',            'core')

# ── ServiceAccount aliases ────────────────────────────────────────────────────
clone('k8s.serviceaccount.list', 'k8s.core.list_service_accounts',       'core')
clone('k8s.serviceaccount.list', 'k8s.core.serviceaccounts.list',        'core')
clone('k8s.serviceaccount.list', 'k8s.serviceaccount.list_service_accounts', 'serviceaccount')

# ── Service aliases ───────────────────────────────────────────────────────────
clone('k8s.service.list',    'k8s.service.list_services',        'service')
clone('k8s.service.list',    'k8s.services.list',                'services')

# ── Namespace aliases ─────────────────────────────────────────────────────────
clone('k8s.namespace.list',  'k8s.namespace.list_namespaces',    'namespace')

# ── CronJob aliases ───────────────────────────────────────────────────────────
clone('k8s.cronjob.list',    'k8s.cronjob.list_cronjobs',        'cronjob')
clone('k8s.cronjob.list',    'k8s.cronjobs.list',                'cronjobs')

# ── NetworkPolicy aliases ─────────────────────────────────────────────────────
clone('k8s.networkpolicy.list', 'k8s.networkpolicies.list',              'networkpolicies')
clone('k8s.networkpolicy.list', 'k8s.networkpolicy.list_network_policies', 'networkpolicy')
clone('k8s.networkpolicy.list', 'k8s.networkpolicy.list_networkpolicies', 'networkpolicy')
clone('k8s.networkpolicy.list', 'k8s.networkpolicy.list_policies',        'networkpolicy')

# ── PersistentVolume aliases ──────────────────────────────────────────────────
clone('k8s.persistentvolume.list', 'k8s.persistentvolume.list_persistentvolumes', 'persistentvolume')
clone('k8s.persistentvolume.list', 'k8s.persistentvolume.persistentvolume.list',  'persistentvolume')

# ── StatefulSet aliases ───────────────────────────────────────────────────────
clone('k8s.statefulset.list', 'k8s.statefulset.list_statefulsets', 'statefulset')
clone('k8s.statefulset.list', 'k8s.statefulsets.list',              'statefulsets')

# ── ReplicaSet aliases ────────────────────────────────────────────────────────
clone('k8s.replicaset.list', 'k8s.replicaset.list_replicasets',  'replicaset')
clone('k8s.replicaset.list', 'k8s.replicasets.list',             'replicasets')

# ── Job aliases ───────────────────────────────────────────────────────────────
clone('k8s.job.list',        'k8s.job.list_jobs',                'job')
clone('k8s.job.list',        'k8s.jobs.list',                    'jobs')

# ── StorageClass aliases ──────────────────────────────────────────────────────
clone('k8s.storageclass.list', 'k8s.storageclass.list_storageclasses', 'storageclass')

# ── Ingress aliases ───────────────────────────────────────────────────────────
clone('k8s.ingress.list',    'k8s.ingress.list_ingresses',       'ingress')

# ── ConfigMap aliases ─────────────────────────────────────────────────────────
clone('k8s.configmap.list',  'k8s.configmap.list_configmaps',    'configmap')

# ── PodTemplate aliases ───────────────────────────────────────────────────────
clone('k8s.podtemplate.list', 'k8s.podtemplate.list_podtemplates', 'podtemplate')

# ── ClusterRole/Binding aliases ───────────────────────────────────────────────
clone('k8s.clusterrole.list',       'k8s.clusterroles.list',                 'clusterroles')
clone('k8s.clusterrolebinding.list', 'k8s.clusterrolebinding.list_cluster_role_bindings', 'clusterrolebinding')

# ── RBAC aliases ──────────────────────────────────────────────────────────────
clone('k8s.rbac.list_role_for_all_namespaces',        'k8s.rbac.roles.list',            'rbac')
clone('k8s.rbac.list_role_binding_for_all_namespaces', 'k8s.rbac.list_role_bindings',   'rbac')
clone('k8s.rbac.list_role_binding_for_all_namespaces', 'k8s.rolebinding.list_role_bindings',  'rolebinding')
clone('k8s.rbac.list_role_binding_for_all_namespaces', 'k8s.rolebinding.list_rolebindings',   'rolebinding')

# ── ResourceQuota alias ───────────────────────────────────────────────────────
clone('k8s.resource.list_resource_quota_for_all_namespaces', 'k8s.policy.list_resource_quota_for_all_namespaces', 'policy')

# ── New ops (no existing alias) ───────────────────────────────────────────────
# API server encryption config
add('k8s.apiserver.describe_encryption_configuration',
    service='apiserver',
    python_call='core_v1_api.read_encryption_config(**params)',
    op_kind='read_get',
    produced_fields='kind|resources|resources[].providers|resources[].resources')

# Pod Disruption Budget
add('k8s.pod.disruption.budget.list',
    service='pod',
    python_call='policy_v1_api.list_namespaced_pod_disruption_budget(**params)',
    op_kind='read_list',
    produced_fields='metadata.name|metadata.namespace|spec.maxUnavailable|spec.minAvailable|status.currentHealthy|status.desiredHealthy')

add('k8s.pod.disruption_budget.list',
    service='pod',
    python_call='policy_v1_api.list_namespaced_pod_disruption_budget(**params)',
    op_kind='read_list',
    produced_fields='metadata.name|metadata.namespace|spec.maxUnavailable|spec.minAvailable|status.currentHealthy|status.desiredHealthy')

# Service mesh (Istio/ASM) ops
add('k8s.service.mesh.list_meshes',
    service='service',
    python_call='custom_objects_api.list_cluster_custom_object(group="networking.istio.io",version="v1alpha3",plural="meshes",**params)',
    op_kind='read_list',
    produced_fields='metadata.name|spec.mtls|spec.outboundTrafficPolicy')

add('k8s.service.mesh.list_mesh_policies',
    service='service',
    python_call='custom_objects_api.list_cluster_custom_object(group="security.istio.io",version="v1beta1",plural="peerauthentications",**params)',
    op_kind='read_list',
    produced_fields='metadata.name|metadata.namespace|spec.mtls|spec.mtls.mode')

add('k8s.service.mesh.list_services',
    service='service',
    python_call='custom_objects_api.list_cluster_custom_object(group="networking.istio.io",version="v1alpha3",plural="virtualservices",**params)',
    op_kind='read_list',
    produced_fields='metadata.name|metadata.namespace|spec.hosts|spec.http|spec.tls')

add('k8s.service.mesh.list_tls_certificates',
    service='service',
    python_call='custom_objects_api.list_cluster_custom_object(group="networking.istio.io",version="v1alpha3",plural="serviceentries",**params)',
    op_kind='read_list',
    produced_fields='metadata.name|metadata.namespace|spec.hosts|spec.ports|spec.resolution|spec.trafficPolicy')

# ─────────────────────────────────────────────────────────────────────────────
# Write back
# ─────────────────────────────────────────────────────────────────────────────
print(f"New ops to add: {len(new_ops)}")

with MASTER.open('w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=fieldnames)
    w.writeheader()
    w.writerows(rows)
    w.writerows(new_ops)

print(f"Total ops in CSV: {len(rows) + len(new_ops)}")
