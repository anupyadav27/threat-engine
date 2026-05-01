#!/usr/bin/env python3
"""
add_missing_ibm_ops.py
Add 27 missing ops to ibm_master_read_ops.csv for IBM check rules.
"""
import csv
from pathlib import Path
from datetime import timezone, datetime

MASTER = Path('/Users/apple/Desktop/threat-engine/catalog/discovery_generator/ibm/ibm_master_read_ops.csv')
csv.field_size_limit(10_000_000)

rows = list(csv.DictReader(MASTER.open()))
fieldnames = list(rows[0].keys())
existing_ops = {r['producing_op'].strip() for r in rows}
new_ops = []

NOW = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def add(op, service, python_call, op_kind='read_list', is_independent='Yes',
        root_op='', produced_fields='', resource_id_field='', resource_id_param='',
        items_for='{{ response.resources }}'):
    if op in existing_ops:
        return
    row = {k: '' for k in fieldnames}
    row.update({
        'csp': 'ibm',
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
        # store items_for hint in check_rule_yaml field as metadata
        'check_rule_yaml': f'items_for={items_for}',
    })
    new_ops.append(row)
    existing_ops.add(op)


# ── COS (Cloud Object Storage) ────────────────────────────────────────────────
add('ibm.cos.list_buckets',
    service='cos',
    python_call='ibm_boto3.resource("s3").buckets.all()',
    produced_fields='Name|CreationDate|LocationConstraint|ActivityTracking|Versioning|PublicAccessBlock|Encryption',
    resource_id_field='Name',
    items_for='{{ response.items }}')

# ── IAM ───────────────────────────────────────────────────────────────────────
add('ibm.iam.list_access_groups',
    service='iam',
    python_call='ibm_platform_services.iam_access_groups.IamAccessGroupsV1().list_access_groups(**params).get_result()',
    produced_fields='groups[].id|groups[].name|groups[].description|groups[].crn|groups[].created_at|groups[].created_by_id',
    resource_id_field='id',
    items_for='{{ response.groups }}')

add('ibm.iam.list_account_settings',
    service='iam',
    python_call='ibm_platform_services.iam_identity.IamIdentityV1().get_account_settings(**params).get_result()',
    op_kind='read_get',
    produced_fields='account_id|restrict_create_service_id|restrict_create_platform_apikey|entity_tag|mfa|session_expiration_in_seconds|session_invalidation_in_seconds|max_sessions_per_identity|system_access_token_expiration_in_seconds|system_refresh_token_expiration_in_seconds',
    resource_id_field='account_id',
    items_for='{{ response }}')

add('ibm.iam.list_mfa_settings',
    service='iam',
    python_call='ibm_platform_services.iam_identity.IamIdentityV1().get_mfa_status(**params).get_result()',
    op_kind='read_get',
    produced_fields='account_id|effective_mfa_type|id_based_mfa|account_based_mfa',
    resource_id_field='account_id',
    items_for='{{ response }}')

add('ibm.iam.list_service_ids',
    service='iam',
    python_call='ibm_platform_services.iam_identity.IamIdentityV1().list_serviceids(**params).get_result()',
    produced_fields='serviceids[].id|serviceids[].name|serviceids[].crn|serviceids[].description|serviceids[].account_id|serviceids[].created_at|serviceids[].locked|serviceids[].apikey',
    resource_id_field='id',
    items_for='{{ response.serviceids }}')

add('ibm.iam.list_trusted_profiles',
    service='iam',
    python_call='ibm_platform_services.iam_identity.IamIdentityV1().list_profiles(**params).get_result()',
    produced_fields='profiles[].id|profiles[].name|profiles[].crn|profiles[].description|profiles[].account_id|profiles[].created_at',
    resource_id_field='id',
    items_for='{{ response.profiles }}')

# ── IKS (IBM Kubernetes Service) ──────────────────────────────────────────────
add('ibm.iks.list_clusters',
    service='iks',
    python_call='ibm_cloud_sdk_core.BaseService().get_http_client().get("/v1/clusters").get_result()',
    produced_fields='id|name|region|resourceGroup|state|masterStatus|masterHealth|masterKubeVersion|workerCount|ingress|disableAutoUpdate',
    resource_id_field='id',
    items_for='{{ response.items }}')

add('ibm.iks.list_namespaces',
    service='iks',
    python_call='kubernetes.client.CoreV1Api().list_namespace(**params)',
    produced_fields='metadata.name|metadata.labels|metadata.annotations|status.phase',
    resource_id_field='metadata.name',
    items_for='{{ response }}')

add('ibm.iks.list_pods',
    service='iks',
    python_call='kubernetes.client.CoreV1Api().list_pod_for_all_namespaces(**params)',
    produced_fields='metadata.name|metadata.namespace|metadata.labels|spec.containers|spec.securityContext|spec.serviceAccountName|spec.automountServiceAccountToken|status.phase',
    resource_id_field='metadata.name',
    items_for='{{ response }}')

add('ibm.iks.list_rolebindings',
    service='iks',
    python_call='kubernetes.client.RbacAuthorizationV1Api().list_role_binding_for_all_namespaces(**params)',
    produced_fields='metadata.name|metadata.namespace|roleRef.kind|roleRef.name|subjects',
    resource_id_field='metadata.name',
    items_for='{{ response }}')

add('ibm.iks.list_secrets',
    service='iks',
    python_call='kubernetes.client.CoreV1Api().list_secret_for_all_namespaces(**params)',
    produced_fields='metadata.name|metadata.namespace|type|data',
    resource_id_field='metadata.name',
    items_for='{{ response }}')

# ── KMS (Key Protect / HPCS) ─────────────────────────────────────────────────
add('ibm.kms.list_keys',
    service='kms',
    python_call='ibm_platform_services.key_protect.KeyProtectV2().list_keys(**params).get_result()',
    produced_fields='resources[].id|resources[].name|resources[].crn|resources[].state|resources[].algorithmType|resources[].createdBy|resources[].creationDate|resources[].lastUpdateDate|resources[].dualAuthDelete|resources[].keyRingID|resources[].deletionDate',
    resource_id_field='id',
    items_for='{{ response.resources }}')

# ── Logging / Activity Tracker ────────────────────────────────────────────────
add('ibm.logging.activity_tracker.list_activity_trackers',
    service='logging',
    python_call='ibm_platform_services.resource_controller.ResourceControllerV1().list_resource_instances(resource_id="logdnaat",**params).get_result()',
    produced_fields='resources[].id|resources[].name|resources[].crn|resources[].region_id|resources[].state|resources[].resource_group_id|resources[].created_at',
    resource_id_field='id',
    items_for='{{ response.resources }}')

# ── SCC (Security and Compliance Center) ──────────────────────────────────────
add('ibm.scc.list_account_settings',
    service='scc',
    python_call='ibm_platform_services.security_and_compliance_center_api.SecurityAndComplianceCenterApiV3().get_settings(**params).get_result()',
    op_kind='read_get',
    produced_fields='event_notifications|object_storage|id|account_id',
    resource_id_field='id',
    items_for='{{ response }}')

add('ibm.scc.list_audit_compliance_checks',
    service='scc',
    python_call='ibm_platform_services.security_and_compliance_center_api.SecurityAndComplianceCenterApiV3().list_scans(**params).get_result()',
    produced_fields='scans[].id|scans[].name|scans[].status|scans[].scan_type|scans[].created_by|scans[].created_on|scans[].next_scan_time',
    resource_id_field='id',
    items_for='{{ response.scans }}')

add('ibm.scc.list_audit_configs',
    service='scc',
    python_call='ibm_platform_services.security_and_compliance_center_api.SecurityAndComplianceCenterApiV3().list_profiles(**params).get_result()',
    produced_fields='profiles[].id|profiles[].profile_name|profiles[].profile_description|profiles[].profile_type|profiles[].profile_version|profiles[].created_by|profiles[].created_on',
    resource_id_field='id',
    items_for='{{ response.profiles }}')

add('ibm.scc.list_audit_findings',
    service='scc',
    python_call='ibm_platform_services.security_and_compliance_center_api.SecurityAndComplianceCenterApiV3().list_reports(**params).get_result()',
    produced_fields='reports[].id|reports[].type|reports[].group_id|reports[].created_on|reports[].scan_time|reports[].controls_summary|reports[].evaluations_summary',
    resource_id_field='id',
    items_for='{{ response.reports }}')

add('ibm.scc.list_audit_policies',
    service='scc',
    python_call='ibm_platform_services.security_and_compliance_center_api.SecurityAndComplianceCenterApiV3().list_control_libraries(**params).get_result()',
    produced_fields='control_libraries[].id|control_libraries[].account_id|control_libraries[].control_library_name|control_libraries[].control_library_description|control_libraries[].control_library_type|control_libraries[].created_on|control_libraries[].created_by',
    resource_id_field='id',
    items_for='{{ response.control_libraries }}')

add('ibm.scc.list_findings',
    service='scc',
    python_call='ibm_platform_services.security_and_compliance_center_api.SecurityAndComplianceCenterApiV3().list_report_evaluations(**params).get_result()',
    produced_fields='evaluations[].home_account_id|evaluations[].report_id|evaluations[].control_id|evaluations[].component_id|evaluations[].assessment|evaluations[].evaluate_time|evaluations[].result',
    resource_id_field='report_id',
    items_for='{{ response.evaluations }}')

# ── Secrets Manager ───────────────────────────────────────────────────────────
add('ibm.secrets.list_secrets',
    service='secrets',
    python_call='ibm_platform_services.secrets_manager.SecretsManagerV2().list_secrets(**params).get_result()',
    produced_fields='secrets[].id|secrets[].name|secrets[].description|secrets[].secret_type|secrets[].crn|secrets[].created_by|secrets[].created_at|secrets[].updated_at|secrets[].state|secrets[].rotation|secrets[].expiration_date',
    resource_id_field='id',
    items_for='{{ response.secrets }}')

# ── VPC extras ────────────────────────────────────────────────────────────────
add('ibm.vsi.list_instances',
    service='vsi',
    python_call='ibm_platform_services.vpc.VpcV1().list_instances(**params).get_result()',
    produced_fields='instances[].id|instances[].name|instances[].crn|instances[].status|instances[].zone|instances[].profile|instances[].image|instances[].vpc|instances[].primary_network_interface|instances[].memory|instances[].vcpu|instances[].created_at',
    resource_id_field='id',
    items_for='{{ response.instances }}')

# ── Databases ─────────────────────────────────────────────────────────────────
add('ibm.db.list_instances',
    service='db',
    python_call='ibm_platform_services.resource_controller.ResourceControllerV1().list_resource_instances(resource_group_id=params.get("resource_group_id"),**params).get_result()',
    produced_fields='resources[].id|resources[].name|resources[].crn|resources[].resource_id|resources[].resource_plan_id|resources[].state|resources[].region_id|resources[].created_at|resources[].updated_at',
    resource_id_field='id',
    items_for='{{ response.resources }}')

add('ibm.database.list_users',
    service='db',
    python_call='ibm_platform_services.cloud_databases.CloudDatabasesV5().list_deployables(**params).get_result()',
    produced_fields='deployables[].type|deployables[].versions',
    resource_id_field='type',
    items_for='{{ response.deployables }}')

add('ibm.cloud-databases.list_deployments',
    service='db',
    python_call='ibm_platform_services.cloud_databases.CloudDatabasesV5().list_deployables(**params).get_result()',
    produced_fields='deployables[].type|deployables[].versions',
    resource_id_field='type',
    items_for='{{ response.deployables }}')

add('ibm.cloudant.list_databases',
    service='db',
    python_call='ibm_cloud_sdk_core.BaseService().get_http_client().get("/_all_dbs").get_result()',
    produced_fields='name',
    resource_id_field='name',
    items_for='{{ response.items }}')

# ── CIEM ──────────────────────────────────────────────────────────────────────
add('ibm.ciem.chain.defense_evasion_log_destroy',
    service='ciem',
    python_call='ibm_platform_services.activity_tracker.ActivityTrackerV1().list_events(**params).get_result()',
    produced_fields='events[].id|events[].action|events[].outcome|events[].initiator|events[].target|events[].requestData|events[].severity|events[].logSourceCRN|events[].saveServiceCopy',
    resource_id_field='id',
    items_for='{{ response.events }}')

# ── K8s op used in IKS checks ─────────────────────────────────────────────────
add('k8s.audit.list_pods',
    service='iks',
    python_call='kubernetes.client.CoreV1Api().list_pod_for_all_namespaces(**params)',
    produced_fields='metadata.name|metadata.namespace|metadata.labels|spec.containers|spec.securityContext|status.phase',
    resource_id_field='metadata.name',
    items_for='{{ response }}')

# ─────────────────────────────────────────────────────────────────────────────
print(f"New ops to add: {len(new_ops)}")

with MASTER.open('w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=fieldnames)
    w.writeheader()
    w.writerows(rows)
    w.writerows(new_ops)

print(f"Total ops in CSV: {len(rows) + len(new_ops)}")
