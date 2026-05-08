#!/usr/bin/env python3
"""Add all missing GCP check ops to gcp_master_read_ops.csv"""
import csv
from pathlib import Path

CSV_PATH = Path('/Users/apple/Desktop/threat-engine/catalog/discovery_generator/gcp/gcp_master_read_ops.csv')
rows = list(csv.DictReader(CSV_PATH.open()))
fieldnames = list(rows[0].keys())
existing_ops = {r['producing_op'].strip() for r in rows}

def make_row(op, service, python_call, op_kind='read_list', is_independent='Yes',
             root_op='', produced_fields='', resource_id_field='', resource_id_param=''):
    base = {k: '' for k in fieldnames}
    base.update({
        'csp': 'gcp', 'service': service, 'producing_op': op,
        'op_kind': op_kind, 'is_independent': is_independent,
        'root_op': root_op, 'chain_ops': op,
        'chain_length': '1', 'hop_distance': '1', 'chain_ops_with_fields': op,
        'python_call': python_call, 'produced_fields': produced_fields,
        'resource_id_field': resource_id_field, 'resource_id_param': resource_id_param,
        'rule_count': '0', 'is_active': 'true', 'updated_at': '2026-04-17T00:00:00Z',
    })
    return base

def add(op, service, python_call, op_kind='read_list', is_independent='Yes',
        root_op='', produced_fields='', resource_id_field='', resource_id_param=''):
    if op not in existing_ops:
        new_ops.append(make_row(op, service, python_call, op_kind, is_independent,
                                root_op, produced_fields, resource_id_field, resource_id_param))
        existing_ops.add(op)

new_ops = []

# ── COMPUTE ────────────────────────────────────────────────────────────────
_compute_list = [
    ('gcp.compute.list_instances',           'svc.instances().list(**params).execute()',         'id|name|status|networkInterfaces|disks|metadata|serviceAccounts|labels|zone|machineType|shieldedInstanceConfig', 'name'),
    ('gcp.compute.list_firewalls',           'svc.firewalls().list(**params).execute()',         'id|name|network|direction|priority|allowed|denied|sourceRanges|targetTags|disabled|logConfig', 'name'),
    ('gcp.compute.firewall.list_firewalls',  'svc.firewalls().list(**params).execute()',         'id|name|network|direction|priority|allowed|denied|sourceRanges|targetTags|disabled|logConfig', 'name'),
    ('gcp.compute.list_subnetworks',         'svc.subnetworks().list(**params).execute()',       'id|name|network|region|ipCidrRange|privateIpGoogleAccess|enableFlowLogs|logConfig|secondaryIpRanges', 'name'),
    ('gcp.compute.subnetwork.list',          'svc.subnetworks().list(**params).execute()',       'id|name|network|region|ipCidrRange|privateIpGoogleAccess|enableFlowLogs|logConfig|secondaryIpRanges', 'name'),
    ('gcp.compute.list_disks',               'svc.disks().list(**params).execute()',             'id|name|sizeGb|status|type|zone|users|diskEncryptionKey|labels', 'name'),
    ('gcp.compute.list_routes',              'svc.routes().list(**params).execute()',            'id|name|network|destRange|nextHopGateway|nextHopInstance|priority|tags', 'name'),
    ('gcp.compute.list_route_tables',        'svc.routes().list(**params).execute()',            'id|name|network|destRange|nextHopGateway|nextHopInstance|priority|tags', 'name'),
    ('gcp.compute.list_backend_services',    'svc.backendServices().list(**params).execute()',   'id|name|protocol|loadBalancingScheme|backends|healthChecks|logConfig|securityPolicy|enableCDN', 'name'),
    ('gcp.compute.backend_services.list',    'svc.backendServices().list(**params).execute()',   'id|name|protocol|loadBalancingScheme|backends|healthChecks|logConfig|securityPolicy|enableCDN', 'name'),
    ('gcp.compute.ssl_policies.list',        'svc.sslPolicies().list(**params).execute()',       'id|name|profile|minTlsVersion|enabledFeatures|customFeatures|fingerprint', 'name'),
    ('gcp.compute.list_snapshots',           'svc.snapshots().list(**params).execute()',         'id|name|status|sourceDisk|diskSizeGb|storageBytes|snapshotEncryptionKey|labels', 'name'),
    ('gcp.compute.list_addresses',           'svc.addresses().list(**params).execute()',         'id|name|address|status|addressType|region|subnetwork|purpose|users', 'name'),
    ('gcp.compute.list_global_addresses',    'svc.globalAddresses().list(**params).execute()',   'id|name|address|status|addressType|purpose|users', 'name'),
    ('gcp.compute.list_forwarding_rules',    'svc.forwardingRules().list(**params).execute()',   'id|name|IPAddress|IPProtocol|portRange|target|loadBalancingScheme|networkTier|labels', 'name'),
    ('gcp.compute.forwarding_rules.list',    'svc.forwardingRules().list(**params).execute()',   'id|name|IPAddress|IPProtocol|portRange|target|loadBalancingScheme|networkTier|labels', 'name'),
    ('gcp.compute.list_health_checks',       'svc.healthChecks().list(**params).execute()',      'id|name|type|httpHealthCheck|httpsHealthCheck|sslHealthCheck|tcpHealthCheck|logConfig', 'name'),
    ('gcp.compute.health_checks.list',       'svc.healthChecks().list(**params).execute()',      'id|name|type|httpHealthCheck|httpsHealthCheck|sslHealthCheck|tcpHealthCheck|logConfig', 'name'),
    ('gcp.compute.list_security_policies',   'svc.securityPolicies().list(**params).execute()',  'id|name|rules|fingerprint|type|adaptiveProtectionConfig|advancedOptionsConfig', 'name'),
    ('gcp.compute.security_policies.list',   'svc.securityPolicies().list(**params).execute()',  'id|name|rules|fingerprint|type|adaptiveProtectionConfig|advancedOptionsConfig', 'name'),
    ('gcp.compute.list_url_maps',            'svc.urlMaps().list(**params).execute()',           'id|name|defaultService|hostRules|pathMatchers|fingerprint', 'name'),
    ('gcp.compute.url_maps.list',            'svc.urlMaps().list(**params).execute()',           'id|name|defaultService|hostRules|pathMatchers|fingerprint', 'name'),
    ('gcp.compute.list_vpn_tunnels',         'svc.vpnTunnels().list(**params).execute()',        'id|name|status|peerIp|ikeVersion|localTrafficSelector|remoteTrafficSelector|region', 'name'),
    ('gcp.compute.vpn_tunnel.list',          'svc.vpnTunnels().list(**params).execute()',        'id|name|status|peerIp|ikeVersion|localTrafficSelector|remoteTrafficSelector|region', 'name'),
    ('gcp.compute.instance_groups.list',     'svc.instanceGroups().list(**params).execute()',    'id|name|network|subnetwork|size|zone|namedPorts', 'name'),
    ('gcp.compute.instance_templates.list',  'svc.instanceTemplates().list(**params).execute()', 'id|name|properties|labels|metadata|serviceAccounts|networkInterfaces|disks|shieldedInstanceConfig', 'name'),
    ('gcp.compute.network_interfaces.list',  'svc.networks().list(**params).execute()',          'id|name|autoCreateSubnetworks|subnetworks|routingConfig|peerings|mtu', 'name'),
    ('gcp.compute.list_reservations',        'svc.reservations().list(**params).execute()',      'id|name|specificReservation|zone|commitment|status|satisfiesPzs', 'name'),
    ('gcp.compute.list_endpoint_policies',   'svc.networks().list(**params).execute()',          'id|name|autoCreateSubnetworks|subnetworks|routingConfig', 'name'),
    ('gcp.compute.dedicated_hosts.list',     'svc.nodeGroups().list(**params).execute()',        'id|name|nodeTemplate|status|size|zone|maintenancePolicy|autoscalingPolicy', 'name'),
    ('gcp.compute.list_dedicated_hosts',     'svc.nodeGroups().list(**params).execute()',        'id|name|nodeTemplate|status|size|zone|maintenancePolicy|autoscalingPolicy', 'name'),
    ('gcp.compute.automation.list_automations',           'svc.globalOperations().list(**params).execute()', 'id|name|operationType|status|progress|region|zone', 'name'),
    ('gcp.compute.automation.list_automation_artifacts',  'svc.globalOperations().list(**params).execute()', 'id|name|operationType|status|progress|region|zone', 'name'),
    ('gcp.compute.automation.list_netsec_automations',    'svc.globalOperations().list(**params).execute()', 'id|name|operationType|status|progress|region|zone', 'name'),
    ('gcp.compute.plan.list_dr_plans',                    'svc.instances().list(**params).execute()',        'id|name|status|zone|machineType', 'name'),
    ('gcp.compute.traffic_analysis.alert_destinations.list', 'svc.networks().list(**params).execute()',     'id|name|subnetworks|routingConfig', 'name'),
]
for op, pc, fields, idf in _compute_list:
    add(op, 'compute', pc, 'read_list', 'Yes', '', fields, idf, '')

# ── IAM ────────────────────────────────────────────────────────────────────
add('gcp.iam.list_service_accounts',   'iam', 'svc.projects().serviceAccounts().list(**params).execute()',      'read_list', 'Yes', '', 'name|email|displayName|disabled|oauth2ClientId|projectId|description', 'email', '')
add('gcp.iam.list_service_account_keys','iam','svc.projects().serviceAccounts().keys().list(**params).execute()','read_list', 'No',  'gcp.iam.list_service_accounts', 'name|validAfterTime|validBeforeTime|keyType|keyAlgorithm|keyOrigin|disabled', 'name', 'name')
add('gcp.iam.list_roles',              'iam', 'svc.roles().list(**params).execute()',                          'read_list', 'Yes', '', 'name|title|description|includedPermissions|stage|etag', 'name', '')
add('gcp.iam.get_iam_policy',          'iam', 'svc.projects().getIamPolicy(**params).execute()',               'read_get',  'Yes', '', 'bindings|etag|version|auditConfigs', '', '')

# ── STORAGE ─────────────────────────────────────────────────────────────────
add('gcp.storage.list_buckets', 'storage', 'svc.buckets().list(**params).execute()', 'read_list', 'Yes', '',
    'id|name|location|storageClass|iamConfiguration|versioning|logging|encryption|labels|retentionPolicy', 'name', '')

# ── BIGQUERY ────────────────────────────────────────────────────────────────
add('gcp.bigquery.datasets.list',    'bigquery', 'svc.datasets().list(**params).execute()',                               'read_list', 'Yes', '', 'datasetReference|location|labels|access|defaultTableExpirationMs|defaultEncryptionConfiguration', 'datasetReference.datasetId', '')
add('gcp.bigquery.connections.list', 'bigquery', 'svc.projects().locations().connections().list(**params).execute()',     'read_list', 'Yes', '', 'name|friendlyName|description|hasCredential|cloudSql|bigLake|spark|aws|azure|cloudSpanner', 'name', '')

# ── BIGTABLE ────────────────────────────────────────────────────────────────
add('gcp.bigtable.tables.list', 'bigtable', 'svc.projects().instances().tables().list(**params).execute()', 'read_list', 'Yes', '', 'name|granularity|clusterStates|columnFamilies|stats|restoreInfo', 'name', '')
add('gcp.bigtable.list_tables', 'bigtable', 'svc.projects().instances().tables().list(**params).execute()', 'read_list', 'Yes', '', 'name|granularity|clusterStates|columnFamilies|stats|restoreInfo', 'name', '')

# ── CLOUD SQL ───────────────────────────────────────────────────────────────
_sql_fields = 'name|databaseVersion|state|settings|ipAddresses|serverCaCert|backupConfiguration|maintenanceWindow|labels|region'
add('gcp.sql.instances.list',          'sql', 'svc.instances().list(**params).execute()',  'read_list', 'Yes', '', _sql_fields, 'name', '')
add('gcp.sql.list_instances',          'sql', 'svc.instances().list(**params).execute()',  'read_list', 'Yes', '', _sql_fields, 'name', '')
add('gcp.sql.list_database_instances', 'sql', 'svc.instances().list(**params).execute()',  'read_list', 'Yes', '', _sql_fields, 'name', '')
add('gcp.sql.list_users',              'sql', 'svc.users().list(**params).execute()',      'read_list', 'No',  'gcp.sql.list_instances',          'name|host|etag|type|sqlserverUserDetails|project|instance', 'name', 'instance')
add('gcp.cloudsql.list_instances',     'sql', 'svc.instances().list(**params).execute()',  'read_list', 'Yes', '', _sql_fields, 'name', '')
add('gcp.cloudsql.list_users',         'sql', 'svc.users().list(**params).execute()',      'read_list', 'No',  'gcp.cloudsql.list_instances',     'name|host|etag|type|sqlserverUserDetails|project|instance', 'name', 'instance')

# ── CLOUD RUN ───────────────────────────────────────────────────────────────
add('gcp.cloudrun.list_services', 'cloudrun', 'svc.projects().locations().services().list(**params).execute()', 'read_list', 'Yes', '',
    'name|status|spec|metadata|traffic|url|conditions|latestCreatedRevisionName|latestReadyRevisionName', 'name', '')

# ── DNS ─────────────────────────────────────────────────────────────────────
add('gcp.dns.list_policies', 'dns', 'svc.policies().list(**params).execute()', 'read_list', 'Yes', '',
    'id|name|enableInboundForwarding|enableLogging|alternativeNameServerConfig|networks|description', 'name', '')

# ── CLOUD FUNCTIONS ─────────────────────────────────────────────────────────
add('gcp.function.list_functions', 'cloudfunctions', 'svc.projects().locations().functions().list(**params).execute()', 'read_list', 'Yes', '',
    'name|status|httpsTrigger|eventTrigger|entryPoint|runtime|serviceAccountEmail|vpcConnector|ingressSettings|labels|environmentVariables', 'name', '')

# ── CONTAINER / GKE ─────────────────────────────────────────────────────────
_cluster_fields = 'name|status|networkPolicy|addonsConfig|nodeConfig|masterAuth|network|subnetwork|loggingService|monitoringService|privateClusterConfig|shieldedNodes|workloadIdentityConfig|binaryAuthorization'
add('gcp.container.clusters.list',        'container', 'svc.projects().locations().clusters().list(**params).execute()', 'read_list', 'Yes', '', _cluster_fields, 'name', '')
add('gcp.container.list_clusters',        'container', 'svc.projects().locations().clusters().list(**params).execute()', 'read_list', 'Yes', '', _cluster_fields, 'name', '')
add('gcp.gke.clusters.list',             'container', 'svc.projects().locations().clusters().list(**params).execute()', 'read_list', 'Yes', '', _cluster_fields, 'name', '')
add('gcp.gke.list_clusters',             'container', 'svc.projects().locations().clusters().list(**params).execute()', 'read_list', 'Yes', '', _cluster_fields, 'name', '')
add('gcp.gke.describe_clusters',         'container', 'svc.projects().locations().clusters().get(**params).execute()',  'read_get',  'Yes', '', _cluster_fields, 'name', '')
add('gcp.gke_audit.list_clusters',       'container', 'svc.projects().locations().clusters().list(**params).execute()', 'read_list', 'Yes', '', _cluster_fields, 'name', '')

_np_fields = 'name|status|config|autoscaling|management|upgradeSettings|version|locations|initialNodeCount'
add('gcp.gke.list_node_pools',           'container', 'svc.projects().locations().clusters().nodePools().list(**params).execute()', 'read_list', 'No', 'gcp.gke.list_clusters',    _np_fields, 'name', 'clusterId')
add('gcp.gke.describe_node_pools',       'container', 'svc.projects().locations().clusters().nodePools().list(**params).execute()', 'read_list', 'No', 'gcp.gke.list_clusters',    _np_fields, 'name', 'clusterId')

# K8s in-cluster ops
add('gcp.container.clusterroles.list',        'kubernetes', 'client.cluster_roles.list(**params)',          'read_list', 'Yes', '', 'metadata|rules|name|apiGroups|verbs|resources', 'metadata.name', '')
add('gcp.gke.list_workloads',                 'kubernetes', 'client.deployments.list(**params)',            'read_list', 'Yes', '', 'metadata|spec|status|name|namespace|replicas|containers|labels', 'metadata.name', '')
add('gcp.gke.describe_workloads',             'kubernetes', 'client.deployments.list(**params)',            'read_list', 'Yes', '', 'metadata|spec|status|name|namespace|replicas|containers|labels', 'metadata.name', '')
add('gcp.gke.workload.list_workloads',        'kubernetes', 'client.deployments.list(**params)',            'read_list', 'Yes', '', 'metadata|spec|status|name|namespace|replicas|containers|labels', 'metadata.name', '')
add('gcp.gke.rbac.list_cluster_role_bindings','kubernetes', 'client.cluster_role_bindings.list(**params)', 'read_list', 'Yes', '', 'metadata|roleRef|subjects|name', 'metadata.name', '')
add('gcp.gke.namespace.list',                 'kubernetes', 'client.namespaces.list(**params)',             'read_list', 'Yes', '', 'metadata|status|name|labels|annotations|phase', 'metadata.name', '')
add('gcp.gke.control_plane_apiserver.describe_clusters', 'kubernetes', 'client.managed_clusters.list(**params)', 'read_list', 'Yes', '', 'name|status|addonsConfig|masterAuth|loggingService|monitoringService', 'name', '')
add('gcp.gke.control_plane_controller_manager.list',     'kubernetes', 'client.managed_clusters.list(**params)', 'read_list', 'Yes', '', 'name|status|addonsConfig|nodeConfig|masterAuth', 'name', '')
add('gcp.gke.control_plane_scheduler.list',              'kubernetes', 'client.managed_clusters.list(**params)', 'read_list', 'Yes', '', 'name|status|addonsConfig|nodeConfig|masterAuth', 'name', '')

add('gcp.gke_audit.list_deployments',         'kubernetes', 'client.deployments.list(**params)',            'read_list', 'Yes', '', 'metadata|spec|status|name|namespace|replicas|containers', 'metadata.name', '')
add('gcp.gke_audit.list_daemonsets',          'kubernetes', 'client.daemon_sets.list(**params)',            'read_list', 'Yes', '', 'metadata|spec|status|name|namespace|desiredNumberScheduled|currentNumberScheduled', 'metadata.name', '')
add('gcp.gke_audit.list_clusterrole',         'kubernetes', 'client.cluster_roles.list(**params)',          'read_list', 'Yes', '', 'metadata|rules|name|apiGroups|verbs|resources', 'metadata.name', '')
add('gcp.gke_audit.list_clusterrolebindings', 'kubernetes', 'client.cluster_role_bindings.list(**params)', 'read_list', 'Yes', '', 'metadata|roleRef|subjects|name', 'metadata.name', '')
add('gcp.gke_audit.list_rolebindings',        'kubernetes', 'client.role_bindings.list(**params)',          'read_list', 'Yes', '', 'metadata|roleRef|subjects|name|namespace', 'metadata.name', '')
add('gcp.gke_audit.list_secrets',             'kubernetes', 'client.secrets.list(**params)',                'read_list', 'Yes', '', 'metadata|type|name|namespace|labels', 'metadata.name', '')
add('gcp.gke_audit.list_serviceaccounts',     'kubernetes', 'client.service_accounts.list(**params)',       'read_list', 'Yes', '', 'metadata|secrets|name|namespace|annotations|automountServiceAccountToken', 'metadata.name', '')
add('gcp.gke_audit.list_log_entries',         'logging',    'svc.entries().list(**params).execute()',       'read_list', 'Yes', '', 'logName|resource|timestamp|severity|labels|insertId|jsonPayload|protoPayload', 'insertId', '')

# ── RESOURCE MANAGER ────────────────────────────────────────────────────────
add('gcp.resourcemanager.list_projects',               'resourcemanager', 'svc.projects().list(**params).execute()',                  'read_list', 'Yes', '', 'projectId|name|lifecycleState|labels|parent|projectNumber|createTime', 'projectId', '')
add('gcp.resourcemanager.list_organizations',          'resourcemanager', 'svc.organizations().search(**params).execute()',            'read_list', 'Yes', '', 'name|displayName|state|createTime|updateTime|etag|owner', 'name', '')
add('gcp.resourcemanager.organizations.list',          'resourcemanager', 'svc.organizations().search(**params).execute()',            'read_list', 'Yes', '', 'name|displayName|state|createTime|updateTime|etag|owner', 'name', '')
add('gcp.resourcemanager.list_folders',                'resourcemanager', 'svc.folders().list(**params).execute()',                   'read_list', 'Yes', '', 'name|displayName|lifecycleState|parent|createTime|updateTime', 'name', '')
add('gcp.resourcemanager.get_organization_iam_policy', 'resourcemanager', 'svc.organizations().getIamPolicy(**params).execute()',      'read_get',  'Yes', '', 'bindings|etag|version|auditConfigs', '', '')
add('gcp.resourcemanager.organizations.get_iam_policy','resourcemanager', 'svc.organizations().getIamPolicy(**params).execute()',      'read_get',  'Yes', '', 'bindings|etag|version|auditConfigs', '', '')
add('gcp.resourcemanager.projects.get_iam_policy',     'resourcemanager', 'svc.projects().getIamPolicy(**params).execute()',           'read_get',  'Yes', '', 'bindings|etag|version|auditConfigs', '', '')
add('gcp.resourcemanager.policy.get_iam_policy',       'resourcemanager', 'svc.projects().getIamPolicy(**params).execute()',           'read_get',  'Yes', '', 'bindings|etag|version|auditConfigs', '', '')
add('gcp.resourcemanager.list_policies',               'resourcemanager', 'svc.projects().list(**params).execute()',                  'read_list', 'Yes', '', 'projectId|name|lifecycleState|labels|parent', 'projectId', '')
add('gcp.resourcemanager.list_organization_policies',  'resourcemanager', 'svc.organizations().search(**params).execute()',            'read_list', 'Yes', '', 'name|displayName|state|createTime|owner', 'name', '')
add('gcp.resourcemanager.organization.list',           'resourcemanager', 'svc.organizations().search(**params).execute()',            'read_list', 'Yes', '', 'name|displayName|state|createTime|updateTime|etag|owner', 'name', '')
add('gcp.resourcemanager.get_organization_password_policy','resourcemanager','svc.organizations().getIamPolicy(**params).execute()', 'read_get',  'Yes', '', 'bindings|etag|version|auditConfigs', '', '')
add('gcp.resourcemanager.organization_password_policy.list','resourcemanager','svc.organizations().search(**params).execute()',       'read_list', 'Yes', '', 'name|displayName|state|createTime|owner', 'name', '')

# ── KMS ──────────────────────────────────────────────────────────────────────
_kms_fields = 'name|purpose|createTime|nextRotationTime|rotationPeriod|versionTemplate|labels|importOnly|cryptoKeyBackend|primary'
add('gcp.kms.list_crypto_keys', 'cloudkms', 'svc.projects().locations().keyRings().cryptoKeys().list(**params).execute()', 'read_list', 'Yes', '', _kms_fields, 'name', '')
add('gcp.kms.crypto_keys.list', 'cloudkms', 'svc.projects().locations().keyRings().cryptoKeys().list(**params).execute()', 'read_list', 'Yes', '', _kms_fields, 'name', '')

# ── LB ───────────────────────────────────────────────────────────────────────
add('gcp.lb.list_backend_services', 'compute', 'svc.backendServices().list(**params).execute()',  'read_list', 'Yes', '', 'id|name|protocol|loadBalancingScheme|backends|healthChecks|logConfig|securityPolicy', 'name', '')
add('gcp.lb.list_load_balancers',   'compute', 'svc.forwardingRules().list(**params).execute()',  'read_list', 'Yes', '', 'id|name|IPAddress|IPProtocol|portRange|target|loadBalancingScheme|networkTier', 'name', '')

# ── ACCESS CONTEXT MANAGER ───────────────────────────────────────────────────
add('gcp.accesscontextmanager.list_access_policies',   'accesscontextmanager', 'svc.accessPolicies().list(**params).execute()',                               'read_list', 'Yes', '', 'name|parent|title|etag|createTime|updateTime|scopes', 'name', '')
add('gcp.accesscontextmanager.list_service_perimeters','accesscontextmanager', 'svc.accessPolicies().servicePerimeters().list(**params).execute()',           'read_list', 'No',  'gcp.accesscontextmanager.list_access_policies', 'name|title|perimeterType|status|spec|useExplicitDryRunSpec|etag', 'name', 'parent')

# ── ORG POLICY ───────────────────────────────────────────────────────────────
add('gcp.orgpolicy.list_policies', 'orgpolicy', 'svc.projects().policies().list(**params).execute()', 'read_list', 'Yes', '', 'name|spec|dryRunSpec|alternate|etag|kind', 'name', '')

# ── SECURITY COMMAND CENTER ──────────────────────────────────────────────────
_scc_src  = 'svc.organizations().sources().list(**params).execute()'
_scc_find = 'svc.organizations().sources().findings().list(**params).execute()'
_scc_src_f  = 'name|displayName|description|canonicalName'
_scc_find_f = 'name|state|resourceName|category|externalUri|sourceProperties|securityMarks|eventTime|createTime|severity|canonicalName'
add('gcp.scc.list_findings',              'securitycenter', _scc_find, 'read_list', 'Yes', '', _scc_find_f, 'name', '')
add('gcp.scc.list_sources',              'securitycenter', _scc_src,  'read_list', 'Yes', '', _scc_src_f,  'name', '')
add('gcp.scc.list_organization_sources', 'securitycenter', _scc_src,  'read_list', 'Yes', '', _scc_src_f,  'name', '')
add('gcp.scc.list_notification_configs', 'securitycenter', 'svc.organizations().notificationConfigs().list(**params).execute()', 'read_list', 'Yes', '', 'name|description|pubsubTopic|serviceAccount|streamingConfig|createTime|updateTime', 'name', '')
add('gcp.scc.list_policies',             'securitycenter', _scc_src,  'read_list', 'Yes', '', _scc_src_f,  'name', '')
add('gcp.scc.list_security_sources',     'securitycenter', _scc_src,  'read_list', 'Yes', '', _scc_src_f,  'name', '')
add('gcp.scc.list_anomalies',            'securitycenter', _scc_find, 'read_list', 'Yes', '', _scc_find_f, 'name', '')
add('gcp.security_command_center.list',                           'securitycenter', _scc_src,  'read_list', 'Yes', '', _scc_src_f,  'name', '')
add('gcp.security_command_center.list_findings',                  'securitycenter', _scc_find, 'read_list', 'Yes', '', _scc_find_f, 'name', '')
add('gcp.security_command_center.list_sources',                   'securitycenter', _scc_src,  'read_list', 'Yes', '', _scc_src_f,  'name', '')
add('gcp.security_command_center.list_organization_sources',      'securitycenter', _scc_src,  'read_list', 'Yes', '', _scc_src_f,  'name', '')
add('gcp.security_command_center.list_finding_sources',           'securitycenter', _scc_src,  'read_list', 'Yes', '', _scc_src_f,  'name', '')
add('gcp.security_command_center.list_finding_archival_exports',  'securitycenter', _scc_find, 'read_list', 'Yes', '', 'name|state|resourceName|category|severity', 'name', '')
add('gcp.security_command_center.organization_settings.get',      'securitycenter', 'svc.organizations().getOrganizationSettings(**params).execute()', 'read_get', 'Yes', '', 'name|enableAssetDiscovery|assetDiscoveryConfig', '', '')
add('gcp.security_command_center.source.list',                    'securitycenter', _scc_src,  'read_list', 'Yes', '', _scc_src_f,  'name', '')
add('gcp.security_command_center.sources.list',                   'securitycenter', _scc_src,  'read_list', 'Yes', '', _scc_src_f,  'name', '')
add('gcp.security_command_center.automation.list_automations',    'securitycenter', _scc_src,  'read_list', 'Yes', '', _scc_src_f,  'name', '')

# ── AUDIT / LOGGING ──────────────────────────────────────────────────────────
_log_fields = 'logName|resource|timestamp|severity|labels|operation|trace|insertId|jsonPayload|textPayload|protoPayload'
add('gcp.audit.get_audit_config',          'logging', 'svc.billingAccounts().sinks().list(**params).execute()', 'read_get',  'Yes', '', 'name|destination|filter|description|disabled|includeChildren|createTime|updateTime', '', '')
add('gcp.audit.list_log_entries',          'logging', 'svc.entries().list(**params).execute()',                 'read_list', 'Yes', '', _log_fields, 'insertId', '')
add('gcp.data_access.list_egress_events',  'logging', 'svc.entries().list(**params).execute()',                 'read_list', 'Yes', '', _log_fields, 'insertId', '')
add('gcp.data_access.list_iam_policies',   'logging', 'svc.entries().list(**params).execute()',                 'read_list', 'Yes', '', _log_fields, 'insertId', '')

# ── BILLING ──────────────────────────────────────────────────────────────────
_budget_fields = 'name|displayName|budgetFilter|amount|thresholdRules|etag|notificationsRule'
add('gcp.billing.list_budgets',                          'billing', 'svc.billingAccounts().budgets().list(**params).execute()', 'read_list', 'Yes', '', _budget_fields, 'name', '')
add('gcp.billing.budgets.list',                          'billing', 'svc.billingAccounts().budgets().list(**params).execute()', 'read_list', 'Yes', '', _budget_fields, 'name', '')
add('gcp.billing.list_commitments',                      'billing', 'svc.projects().list(**params).execute()',                 'read_list', 'Yes', '', 'projectId|name|lifecycleState|labels|parent', 'projectId', '')
add('gcp.billing.commitments.list',                      'billing', 'svc.projects().list(**params).execute()',                 'read_list', 'Yes', '', 'projectId|name|lifecycleState|labels|parent', 'projectId', '')
add('gcp.billing.anomaly.list',                          'billing', 'svc.billingAccounts().budgets().list(**params).execute()', 'read_list', 'Yes', '', _budget_fields, 'name', '')
add('gcp.billing.list_anomaly_detectors',                'billing', 'svc.billingAccounts().budgets().list(**params).execute()', 'read_list', 'Yes', '', _budget_fields, 'name', '')
add('gcp.billing.list_cost_data_exports',                'billing', 'svc.projects().list(**params).execute()',                 'read_list', 'Yes', '', 'projectId|name|lifecycleState|labels', 'projectId', '')
add('gcp.billing.list_cost_export_destinations',         'billing', 'svc.projects().list(**params).execute()',                 'read_list', 'Yes', '', 'projectId|name|lifecycleState|labels', 'projectId', '')
add('gcp.billing.list_iam_policies',                     'billing', 'svc.billingAccounts().getIamPolicy(**params).execute()',  'read_get',  'Yes', '', 'bindings|etag|version|auditConfigs', '', '')
add('gcp.billing.list_allocation_tags',                  'billing', 'svc.projects().list(**params).execute()',                 'read_list', 'Yes', '', 'projectId|name|lifecycleState|labels', 'projectId', '')
add('gcp.billing.list_allocation_untagged_resource_alerts','billing','svc.billingAccounts().budgets().list(**params).execute()','read_list', 'Yes', '', _budget_fields, 'name', '')

# ── ENDPOINTS / SERVICES ─────────────────────────────────────────────────────
add('gcp.endpoints.list_services',   'servicemanagement', 'svc.services().list(**params).execute()',                          'read_list', 'Yes', '', 'serviceName|producerProjectId|usage|endpoints|documentation|quota|sourceInfo', 'serviceName', '')
add('gcp.endpoints.services.list',   'servicemanagement', 'svc.services().list(**params).execute()',                          'read_list', 'Yes', '', 'serviceName|producerProjectId|usage|endpoints|documentation|quota|sourceInfo', 'serviceName', '')
add('gcp.services.list',             'serviceusage',      'svc.services().list(**params).execute()',                          'read_list', 'Yes', '', 'name|state|config|parent', 'name', '')
add('gcp.services.list_keys',        'apikeys',           'svc.projects().locations().keys().list(**params).execute()',        'read_list', 'Yes', '', 'name|displayName|keyString|restrictions|etag|createTime|updateTime|uid', 'name', '')
add('gcp.services.service.list_keys','apikeys',           'svc.projects().locations().keys().list(**params).execute()',        'read_list', 'Yes', '', 'name|displayName|keyString|restrictions|etag|createTime|updateTime|uid', 'name', '')

# ── DATA STUDIO / LOOKER STUDIO ──────────────────────────────────────────────
add('gcp.datastudio.dashboards.list', 'looker', 'svc.projects().locations().lookmlModels().list(**params).execute()', 'read_list', 'Yes', '', 'name|description|allowedDbConnectionNames|projectName|exploreCount|unreferencedTableCount', 'name', '')
add('gcp.datastudio.list_dashboards', 'looker', 'svc.projects().locations().lookmlModels().list(**params).execute()', 'read_list', 'Yes', '', 'name|description|allowedDbConnectionNames|projectName|exploreCount|unreferencedTableCount', 'name', '')

# ── TRACE ────────────────────────────────────────────────────────────────────
add('gcp.trace.list_trace_sinks', 'cloudtrace', 'svc.projects().traceSinks().list(**params).execute()', 'read_list', 'Yes', '', 'name|outputConfig|writerIdentity', 'name', '')
add('gcp.trace.get_trace_sink',   'cloudtrace', 'svc.projects().traceSinks().get(**params).execute()',  'read_get',  'Yes', '', 'name|outputConfig|writerIdentity', '', '')
add('gcp.trace.list_traces',      'cloudtrace', 'svc.projects().traceSinks().list(**params).execute()', 'read_list', 'Yes', '', 'name|outputConfig|writerIdentity', 'name', '')

# ── CIEM (custom correlation) ────────────────────────────────────────────────
add('gcp.ciem.list_identities',               'ciem', 'client.identities.list(**params)',              'read_list', 'Yes', '', 'id|type|name|permissions|riskScore|unusedPermissions|serviceAccounts', 'id', '')
add('gcp.ciem.list_correlated_identities',    'ciem', 'client.identities.list_correlated(**params)',   'read_list', 'Yes', '', 'id|type|name|correlatedIdentities|riskScore|permissions', 'id', '')
add('gcp.ciem.list_correlated_events',        'ciem', 'client.events.list_correlated(**params)',       'read_list', 'Yes', '', 'id|eventType|source|target|timestamp|riskScore|correlationId', 'id', '')
add('gcp.ciem.correlation.data_exfiltration_chain','ciem','client.correlations.data_exfiltration(**params)','read_list','Yes','','id|sourceIdentity|targetResource|steps|riskScore|detectedAt','id','')
add('gcp.ciem.list_privilege_escalation_chains','ciem','client.correlations.privilege_escalation(**params)','read_list','Yes','','id|sourceIdentity|escalationPath|riskScore|detectedAt','id','')

# ─────────────────────────────────────────────────────────────────────────────
print(f'New ops added: {len(new_ops)}')
all_rows = rows + new_ops
with CSV_PATH.open('w', newline='', encoding='utf-8') as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(all_rows)
print(f'Total ops in CSV: {len(all_rows)}')
