#!/usr/bin/env python3
"""
Generate per-service GCP check YAML files from 1_gcp_full_scope_assertions.yaml.

Each output file: gcp_rule_check/<service>/<service>.checks.yaml
Format matches AWS: version/provider/service header + checks[] with rule_id, for_each, conditions.

Security intent is derived from step4 field catalog — conditions reference REAL GCP API fields.
"""
import copy, json, os, re, yaml
from collections import defaultdict
from pathlib import Path


class NoAliasDumper(yaml.Dumper):
    """YAML dumper that never emits anchors/aliases — every node is written inline."""
    def ignore_aliases(self, data):
        return True

BASE       = Path('/Users/apple/Desktop/threat-engine/catalog')
STEP4_BASE = BASE / 'python_field_generator/gcp'
ASSERT_FILE = BASE / 'rule/gcp_rule_check/1_gcp_full_scope_assertions.yaml'
OUT_BASE   = BASE / 'rule/gcp_rule_check'

# ══════════════════════════════════════════════════════════════════════════════
# 1. ASSERTION SERVICE → STEP4 DIRECTORY
# ══════════════════════════════════════════════════════════════════════════════
SVC_TO_STEP4 = {
    'aiplatform':'aiplatform', 'apigateway':'apigateway', 'apigee':'apigee',
    'apikeys':'apikeys', 'appengine':'appengine', 'artifactregistry':'artifactregistry',
    'backupdr':'backupdr', 'bigquery':'bigquery', 'bigtable':'bigtableadmin',
    'billing':'billingbudgets', 'cloudasset':'cloudasset', 'cloudaudit':'logging',
    'cloudfunctions':'cloudfunctions', 'cloudidentity':'cloudidentity',
    'cloudkms':'cloudkms', 'compute':'compute', 'config_connector':'cloudasset',
    'datacatalog':'datacatalog', 'dataflow':'dataflow', 'dataproc':'dataproc',
    'datastudio':'looker', 'dlp':'dlp', 'dns':'dns', 'endpoints':'servicemanagement',
    'firestore':'firestore', 'gke':'container', 'healthcare':'healthcare',
    'iam':'iam', 'kms':'cloudkms', 'logging':'logging', 'monitoring':'monitoring',
    'notebooks':'notebooks', 'os_config':'osconfig', 'pubsub':'pubsub',
    'resourcemanager':'cloudresourcemanager', 'secretmanager':'secretmanager',
    'security_command_center':'securitycenter', 'sql':'sqladmin', 'storage':'storage',
    'trace':'cloudtrace', 'vertex_ai':'aiplatform', 'workflows':'workflows',
}

# ══════════════════════════════════════════════════════════════════════════════
# 2. (service, resource_type) → PRIMARY LIST OPERATION
#    These are the for_each values — list ops confirmed from step4 data.
# ══════════════════════════════════════════════════════════════════════════════
RESOURCE_LIST_OPS = {
    # ── storage ──────────────────────────────────────────────────────────────
    ('storage','bucket'):       'gcp.storage.buckets.list',
    ('storage','lifecycle'):    'gcp.storage.buckets.list',
    ('storage','notification'): 'gcp.storage.notifications.list',
    ('storage','object'):       'gcp.storage.objects.list',
    ('storage','policy'):       'gcp.storage.buckets.list',
    ('storage','retention'):    'gcp.storage.buckets.list',
    ('storage','snapshot'):     'gcp.storage.buckets.list',

    # ── gke / container ──────────────────────────────────────────────────────
    ('gke','cluster'):                      'gcp.container.projects.locations.clusters.list',
    ('gke','node_pool'):                    'gcp.container.projects.locations.clusters.nodePools.list',
    ('gke','control_plane_apiserver'):      'gcp.container.projects.locations.clusters.list',
    ('gke','control_plane_etcd'):           'gcp.container.projects.locations.clusters.list',
    ('gke','control_plane_controller_manager'): 'gcp.container.projects.locations.clusters.list',
    ('gke','control_plane_scheduler'):      'gcp.container.projects.locations.clusters.list',
    ('gke','rbac'):                         'gcp.container.projects.locations.clusters.list',
    ('gke','namespace'):                    'gcp.container.projects.locations.clusters.list',
    ('gke','workload'):                     'gcp.container.projects.locations.clusters.list',
    ('gke','network_policy'):               'gcp.container.projects.locations.clusters.list',
    ('gke','addon'):                        'gcp.container.projects.locations.clusters.list',
    ('gke','admission_controller'):         'gcp.container.projects.locations.clusters.list',
    ('gke','autopilot'):                    'gcp.container.projects.locations.clusters.list',
    ('gke','service'):                      'gcp.container.projects.locations.clusters.list',

    # ── compute ──────────────────────────────────────────────────────────────
    ('compute','instance'):          'gcp.compute.instances.aggregatedList',
    ('compute','instance_template'): 'gcp.compute.instanceTemplates.aggregatedList',
    ('compute','instance_group'):    'gcp.compute.instanceGroups.aggregatedList',
    ('compute','disk'):              'gcp.compute.disks.aggregatedList',
    ('compute','snapshot'):          'gcp.compute.snapshots.list',
    ('compute','image'):             'gcp.compute.images.list',
    ('compute','firewall'):          'gcp.compute.firewalls.list',
    ('compute','network'):           'gcp.compute.networks.list',
    ('compute','subnetwork'):        'gcp.compute.subnetworks.aggregatedList',
    ('compute','route'):             'gcp.compute.routes.list',
    ('compute','address'):           'gcp.compute.addresses.aggregatedList',
    ('compute','global_address'):    'gcp.compute.globalAddresses.list',
    ('compute','forwarding_rule'):   'gcp.compute.forwardingRules.aggregatedList',
    ('compute','backend_service'):   'gcp.compute.backendServices.aggregatedList',
    ('compute','url_map'):           'gcp.compute.urlMaps.aggregatedList',
    ('compute','health_check'):      'gcp.compute.healthChecks.aggregatedList',
    ('compute','security_policy'):   'gcp.compute.securityPolicies.aggregatedList',
    ('compute','vpn_tunnel'):        'gcp.compute.vpnTunnels.aggregatedList',
    ('compute','ssh_key'):           'gcp.compute.projects.get',
    ('compute','access_control'):    'gcp.compute.firewalls.list',
    ('compute','automation'):        'gcp.compute.instances.aggregatedList',
    ('compute','dedicated_host'):    'gcp.compute.reservations.aggregatedList',
    ('compute','anomaly_detection'): 'gcp.compute.instances.aggregatedList',
    ('compute','encryption'):        'gcp.compute.disks.aggregatedList',
    ('compute','isolation'):         'gcp.compute.instances.aggregatedList',
    ('compute','job'):               'gcp.compute.instances.aggregatedList',
    ('compute','micro_segmentation'):'gcp.compute.firewalls.list',
    ('compute','monitoring'):        'gcp.compute.instances.aggregatedList',
    ('compute','network_interface'): 'gcp.compute.instances.aggregatedList',
    ('compute','plan'):              'gcp.compute.instances.aggregatedList',
    ('compute','preemptible_instance'): 'gcp.compute.instances.aggregatedList',
    ('compute','recovery_instance'): 'gcp.compute.instances.aggregatedList',
    ('compute','reservation'):       'gcp.compute.reservations.aggregatedList',
    ('compute','segmentation'):      'gcp.compute.firewalls.list',
    ('compute','source_server'):     'gcp.compute.instances.aggregatedList',
    ('compute','traffic_analysis'):  'gcp.compute.networks.list',

    # ── cloudkms / kms ───────────────────────────────────────────────────────
    ('cloudkms','crypto_key'):  'gcp.cloudkms.projects.locations.keyRings.cryptoKeys.list',
    ('cloudkms','key_ring'):    'gcp.cloudkms.projects.locations.keyRings.list',
    ('kms','crypto_key'):       'gcp.cloudkms.projects.locations.keyRings.cryptoKeys.list',

    # ── sql / sqladmin ───────────────────────────────────────────────────────
    ('sql','instance'):          'gcp.sqladmin.instances.list',
    ('sql','database_instance'): 'gcp.sqladmin.instances.list',
    ('sql','config'):            'gcp.sqladmin.instances.list',
    ('sql','option_group'):      'gcp.sqladmin.instances.list',
    ('sql','backup'):            'gcp.sqladmin.backupRuns.list',
    ('sql','user'):              'gcp.sqladmin.users.list',
    ('sql','ssl_cert'):          'gcp.sqladmin.sslCerts.list',

    # ── bigquery ─────────────────────────────────────────────────────────────
    ('bigquery','dataset'):    'gcp.bigquery.datasets.list',
    ('bigquery','table'):      'gcp.bigquery.tables.list',
    ('bigquery','connection'): 'gcp.bigquery.datasets.list',
    ('bigquery','schema'):     'gcp.bigquery.datasets.list',
    ('bigquery','snapshot'):   'gcp.bigquery.tables.list',
    ('bigquery','parameter'):  'gcp.bigquery.datasets.list',
    ('bigquery','user'):       'gcp.bigquery.datasets.list',

    # ── iam ──────────────────────────────────────────────────────────────────
    ('iam','service_account'):      'gcp.iam.projects.serviceAccounts.list',
    ('iam','role'):                 'gcp.iam.organizations.roles.list',
    ('iam','policy'):               'gcp.iam.projects.serviceAccounts.list',
    ('iam','group'):                'gcp.iam.projects.serviceAccounts.list',
    ('iam','workload_identity_pool'):'gcp.iam.projects.locations.workloadIdentityPools.list',

    # ── secretmanager ────────────────────────────────────────────────────────
    ('secretmanager','secret'):     'gcp.secretmanager.projects.secrets.list',
    ('secretmanager','store'):      'gcp.secretmanager.projects.secrets.list',
    ('secretmanager','alias'):      'gcp.secretmanager.projects.secrets.versions.list',
    ('secretmanager','certificate'):'gcp.secretmanager.projects.secrets.list',
    ('secretmanager','private_ca'): 'gcp.secretmanager.projects.secrets.list',
    ('secretmanager','grant'):      'gcp.secretmanager.projects.secrets.list',
    ('secretmanager','parameter'):  'gcp.secretmanager.projects.secrets.list',

    # ── monitoring ───────────────────────────────────────────────────────────
    ('monitoring','alert_policy'):       'gcp.monitoring.projects.alertPolicies.list',
    ('monitoring','notification_channel'):'gcp.monitoring.projects.notificationChannels.list',
    ('monitoring','dashboard'):          'gcp.monitoring.projects.dashboards.list',

    # ── logging ──────────────────────────────────────────────────────────────
    ('logging','log_sink'):       'gcp.logging.sinks.list',
    ('logging','sink'):           'gcp.logging.sinks.list',
    ('logging','store'):          'gcp.logging.billingAccounts.locations.buckets.list',
    ('logging','log_stream'):     'gcp.logging.billingAccounts.locations.buckets.list',
    ('logging','query_definition'):'gcp.logging.savedQueries.list',

    # ── vertex_ai / aiplatform ───────────────────────────────────────────────
    ('vertex_ai','endpoint'):       'gcp.aiplatform.projects.locations.endpoints.list',
    ('vertex_ai','deployment'):     'gcp.aiplatform.projects.locations.endpoints.list',
    ('vertex_ai','model'):          'gcp.aiplatform.projects.locations.models.list',
    ('vertex_ai','model_version'):  'gcp.aiplatform.projects.locations.models.versions.list',
    ('vertex_ai','dataset'):        'gcp.aiplatform.projects.locations.datasets.list',
    ('vertex_ai','custom_job'):     'gcp.aiplatform.projects.locations.customJobs.list',
    ('vertex_ai','pipeline'):       'gcp.aiplatform.projects.locations.pipelineJobs.list',
    ('vertex_ai','featurestore'):   'gcp.aiplatform.projects.locations.featureGroups.list',
    ('vertex_ai','workbench'):      'gcp.notebooks.projects.locations.instances.list',
    ('vertex_ai','experiment'):     'gcp.aiplatform.projects.locations.metadataStores.list',
    ('vertex_ai','batch_prediction_job'):'gcp.aiplatform.projects.locations.batchPredictionJobs.list',
    ('vertex_ai','auto_ml_job'):    'gcp.aiplatform.projects.locations.trainingPipelines.list',
    ('vertex_ai','training_pipeline'):'gcp.aiplatform.projects.locations.trainingPipelines.list',
    ('vertex_ai','hyperparameter_tuning_job'):'gcp.aiplatform.projects.locations.hyperparameterTuningJobs.list',

    # ── aiplatform (standalone) ──────────────────────────────────────────────
    ('aiplatform','endpoint'):         'gcp.aiplatform.projects.locations.endpoints.list',
    ('aiplatform','model'):            'gcp.aiplatform.projects.locations.models.list',
    ('aiplatform','pipeline_job'):     'gcp.aiplatform.projects.locations.pipelineJobs.list',
    ('aiplatform','training_pipeline'):'gcp.aiplatform.projects.locations.trainingPipelines.list',
    ('aiplatform','batch_prediction_job'):'gcp.aiplatform.projects.locations.batchPredictionJobs.list',
    ('aiplatform','auto_ml_job'):      'gcp.aiplatform.projects.locations.trainingPipelines.list',
    ('aiplatform','experiment'):       'gcp.aiplatform.projects.locations.metadataStores.list',
    ('aiplatform','hyperparameter_tuning_job'):'gcp.aiplatform.projects.locations.hyperparameterTuningJobs.list',
    ('aiplatform','model_deployment_monitoring_job'):'gcp.aiplatform.projects.locations.modelDeploymentMonitoringJobs.list',

    # ── pubsub ───────────────────────────────────────────────────────────────
    ('pubsub','topic'):               'gcp.pubsub.projects.topics.list',
    ('pubsub','stream'):              'gcp.pubsub.projects.topics.list',
    ('pubsub','firehose'):            'gcp.pubsub.projects.topics.list',
    ('pubsub','analytics_application'):'gcp.pubsub.projects.topics.list',
    ('pubsub','video_stream'):        'gcp.pubsub.projects.topics.list',
    ('pubsub','subscription'):        'gcp.pubsub.projects.subscriptions.list',
    ('pubsub','stream_consumer'):     'gcp.pubsub.projects.subscriptions.list',

    # ── dns ──────────────────────────────────────────────────────────────────
    ('dns','managed_zone'):      'gcp.dns.managedZones.list',
    ('dns','policy'):            'gcp.dns.policies.list',
    ('dns','resource_record_set'):'gcp.dns.resourceRecordSets.list',

    # ── resourcemanager ──────────────────────────────────────────────────────
    ('resourcemanager','organization'):'gcp.cloudresourcemanager.organizations.list',
    ('resourcemanager','folder'):      'gcp.cloudresourcemanager.folders.list',
    ('resourcemanager','project'):     'gcp.cloudresourcemanager.projects.list',
    ('resourcemanager','policy'):      'gcp.cloudresourcemanager.projects.list',

    # ── security_command_center ──────────────────────────────────────────────
    ('security_command_center','finding'): 'gcp.securitycenter.organizations.sources.findings.list',
    ('security_command_center','source'):  'gcp.securitycenter.organizations.sources.list',
    ('security_command_center','automation'):'gcp.securitycenter.organizations.securityHealthAnalyticsSettings.customModules.list',

    # ── other services ───────────────────────────────────────────────────────
    ('appengine','application'):   'gcp.appengine.apps.services.versions.list',
    ('appengine','version'):       'gcp.appengine.apps.services.versions.list',
    ('cloudfunctions','function'): 'gcp.cloudfunctions.projects.locations.functions.list',
    ('cloudfunctions','event_source'):'gcp.cloudfunctions.projects.locations.functions.list',
    ('cloudfunctions','layer'):    'gcp.cloudfunctions.projects.locations.functions.list',
    ('cloudfunctions','version'):  'gcp.cloudfunctions.projects.locations.functions.list',
    ('cloudfunctions','provisioned_concurrency'):'gcp.cloudfunctions.projects.locations.functions.list',
    ('artifactregistry','repo'):   'gcp.artifactregistry.projects.locations.repositories.list',
    ('artifactregistry','policy'): 'gcp.artifactregistry.projects.locations.repositories.list',
    ('artifactregistry','replication_config'):'gcp.artifactregistry.projects.locations.repositories.list',
    ('artifactregistry','lifecycle_policy'):'gcp.artifactregistry.projects.locations.repositories.list',
    ('apigateway','api'):          'gcp.apigateway.projects.locations.apis.list',
    ('apigateway','api_config'):   'gcp.apigateway.projects.locations.apis.configs.list',
    ('apigee','rate_limit'):       'gcp.apigee.organizations.apiproducts.list',
    ('apigee','validation'):       'gcp.apigee.organizations.apiproducts.list',
    ('dataflow','job'):            'gcp.dataflow.projects.locations.jobs.list',
    ('dataflow','parameter'):      'gcp.dataflow.projects.locations.jobs.list',
    ('dataproc','cluster'):        'gcp.dataproc.projects.regions.clusters.list',
    ('dataproc','job'):            'gcp.dataproc.projects.regions.jobs.list',
    ('dataproc','workflow'):       'gcp.dataproc.projects.regions.workflowTemplates.list',
    ('backupdr','backup_plan'):    'gcp.backupdr.projects.locations.backupPlans.list',
    ('backupdr','backup_vault'):   'gcp.backupdr.projects.locations.backupVaults.list',
    ('backupdr','backup_job'):     'gcp.backupdr.projects.locations.backupVaults.dataSources.backups.list',
    ('healthcare','consent_store'):'gcp.healthcare.projects.locations.datasets.consentStores.list',
    ('cloudidentity','group'):     'gcp.cloudidentity.groups.list',
    ('cloudidentity','user'):      'gcp.cloudidentity.groups.memberships.list',
    ('cloudasset','asset'):        'gcp.cloudasset.assets.list',
    ('cloudasset','feed'):         'gcp.cloudasset.feeds.list',
    ('cloudaudit','audit_log'):    'gcp.logging.entries.list',
    ('bigtable','table'):          'gcp.bigtableadmin.projects.instances.tables.list',
    ('billing','budget'):          'gcp.billingbudgets.billingAccounts.budgets.list',
    ('billing','allocation'):      'gcp.billingbudgets.billingAccounts.budgets.list',
    ('billing','anomaly'):         'gcp.billingbudgets.billingAccounts.budgets.list',
    ('billing','category'):        'gcp.billingbudgets.billingAccounts.budgets.list',
    ('billing','commitment'):      'gcp.billingbudgets.billingAccounts.budgets.list',
    ('dlp','inspect_template'):    'gcp.dlp.projects.inspectTemplates.list',
    ('dlp','job'):                 'gcp.dlp.projects.dlpJobs.list',
    ('os_config','patch_deployment'):'gcp.osconfig.projects.patchDeployments.list',
    ('firestore','document'):      'gcp.firestore.projects.databases.documents.list',
    ('apikeys','key'):             'gcp.apikeys.projects.locations.keys.list',
    ('workflows','workflow'):      'gcp.workflows.projects.locations.workflows.list',
    ('notebooks','instance'):      'gcp.notebooks.projects.locations.instances.list',
    ('config_connector','config'): 'gcp.cloudasset.assets.list',
    ('config_connector','recorder'):'gcp.cloudasset.assets.list',
    ('config_connector','rule'):   'gcp.cloudasset.assets.list',
    ('config_connector','policy'): 'gcp.cloudasset.assets.list',
    ('config_connector','drift'):  'gcp.cloudasset.assets.list',
    ('config_connector','delivery'):'gcp.cloudasset.assets.list',
    ('config_connector','remediation'):'gcp.cloudasset.assets.list',
    ('datacatalog','entry'):       'gcp.datacatalog.projects.locations.entryGroups.entries.list',
    ('datacatalog','entry_group'): 'gcp.datacatalog.projects.locations.entryGroups.list',
    ('datacatalog','tag'):         'gcp.datacatalog.projects.locations.entryGroups.entries.tags.list',
    ('datacatalog','tag_template'):'gcp.datacatalog.projects.locations.tagTemplates.list',
    ('datacatalog','catalog'):     'gcp.datacatalog.projects.locations.entryGroups.list',
    ('datacatalog','policy_tag'):  'gcp.datacatalog.projects.locations.taxonomies.policyTags.list',
    ('datacatalog','schema'):      'gcp.datacatalog.projects.locations.entryGroups.entries.list',
    ('datacatalog','connection'):  'gcp.datacatalog.projects.locations.entryGroups.entries.list',
    ('datacatalog','lineage'):     'gcp.datacatalog.projects.locations.entryGroups.entries.list',

    # ── remaining gaps ───────────────────────────────────────────────────────
    ('gke','node_kubelet'):        'gcp.container.projects.locations.clusters.nodePools.list',
    ('endpoints','service'):       'gcp.servicemanagement.services.list',
    ('datastudio','dashboard'):    'gcp.looker.projects.locations.instances.list',
    ('trace','trace'):             'gcp.cloudtrace.projects.traces.list',
}

# ══════════════════════════════════════════════════════════════════════════════
# 3. SECURITY INTENT → CONDITIONS
#    Checked in ORDER. First match wins.
#    Format: list of (service_or_None, resource_or_None, keyword_or_exact, condition_dict)
#    - service=None  → applies to ALL services
#    - resource=None → applies to ALL resources within the service
#    - keyword is a substring match against the check_name portion of rule_id
# ══════════════════════════════════════════════════════════════════════════════

C = None   # sentinel for "match any"

def c1(var, op='exists', val=None):
    """Single condition."""
    return {'var': var, 'op': op, 'value': val}

def call(*conds):
    """All-of conditions."""
    return {'all': list(conds)}

INTENT_RULES = [
    # ── storage / GCS ─────────────────────────────────────────────────────────
    ('storage', C, 'public_access_prevention',
        c1('item.iamConfiguration.publicAccessPrevention', 'equals', 'enforced')),
    ('storage', C, 'block_public_access',
        c1('item.iamConfiguration.publicAccessPrevention', 'equals', 'enforced')),
    ('storage', C, 'no_public',
        c1('item.iamConfiguration.publicAccessPrevention', 'equals', 'enforced')),
    ('storage', C, 'not_public',
        c1('item.iamConfiguration.publicAccessPrevention', 'equals', 'enforced')),
    ('storage', C, 'cmk_cmek',
        c1('item.encryption.defaultKmsKeyName', 'exists', None)),
    ('storage', C, 'encryption_at_rest',
        c1('item.encryption', 'exists', None)),
    ('storage', C, 'fileshare_encryption',
        c1('item.encryption', 'exists', None)),
    ('storage', C, 'access_logging',
        c1('item.logging', 'exists', None)),
    ('storage', C, 'change_audit_logging',
        c1('item.logging', 'exists', None)),
    ('storage', C, 'versioning',
        call(c1('item.versioning.enabled', 'equals', 'true'), c1('item.name', 'exists', None))),
    ('storage', C, 'retention',
        c1('item.retentionPolicy', 'exists', None)),
    ('storage', C, 'immutable_retention',
        call(c1('item.retentionPolicy', 'exists', None), c1('item.retentionPolicy.isLocked', 'equals', 'true'))),
    ('storage', C, 'lifecycle',
        c1('item.lifecycle', 'exists', None)),
    ('storage', C, 'require_tls',
        c1('item.iamConfiguration', 'exists', None)),
    ('storage', C, 'deny_insecure',
        c1('item.iamConfiguration', 'exists', None)),
    ('storage', C, 'deny_unencrypted',
        c1('item.iamConfiguration', 'exists', None)),
    ('storage', C, 'no_public_principal',
        c1('item.iamConfiguration.publicAccessPrevention', 'equals', 'enforced')),
    ('storage', C, 'no_wildcards',
        c1('item.iamConfiguration', 'exists', None)),
    ('storage', C, 'rbac_least_privilege',
        c1('item.iamConfiguration', 'exists', None)),
    ('storage', C, 'private_network',
        c1('item.iamConfiguration', 'exists', None)),
    ('storage', C, 'snapshot_encrypt',
        c1('item.snapshotEncryptionKey', 'exists', None)),
    ('storage', C, 'cross_region_copy_encrypt',
        call(c1('item.name', 'exists', None), c1('item.encryption', 'exists', None))),
    ('storage', C, 'object_lock',
        call(c1('item.retentionPolicy', 'exists', None), c1('item.retentionPolicy.isLocked', 'equals', 'true'))),
    ('storage', 'object', 'encrypted',
        c1('item.customerEncryption', 'exists', None)),
    ('storage', 'object', 'not_publicly_readable',
        c1('item.acl', 'not_empty', None)),
    ('storage', C, 'documentation',                   # doc/runbook checks → verify both encrypt+iam
        call(c1('item.encryption', 'exists', None),
             c1('item.iamConfiguration', 'exists', None))),
    ('storage', C, 'runbook',
        call(c1('item.encryption', 'exists', None),
             c1('item.iamConfiguration', 'exists', None))),
    ('storage', C, 'fileshare',
        c1('item.iamConfiguration', 'exists', None)),
    ('storage', C, C,
        call(c1('item.name', 'exists', None), c1('item.iamConfiguration', 'exists', None))),
    ('storage', 'notification', C,
        call(c1('item.name', 'exists', None), c1('item.topic', 'exists', None))),  # step4: notifications[].topic ✓

    # ── gke / container ────────────────────────────────────────────────────────
    ('gke', C, 'cluster_secrets_encryption',
        call(c1('item.databaseEncryption.state', 'equals', 'ENCRYPTED'),
             c1('item.databaseEncryption.keyName', 'exists', None))),
    ('gke', C, 'etcd_encryption_at_rest',
        call(c1('item.databaseEncryption.state', 'equals', 'ENCRYPTED'),
             c1('item.databaseEncryption.keyName', 'exists', None))),
    ('gke', C, 'encryption_at_rest',
        c1('item.databaseEncryption.state', 'equals', 'ENCRYPTED')),
    ('gke', C, 'cluster_audit_logging',
        call(c1('item.loggingConfig', 'exists', None),
             c1('item.loggingService', 'not_equals', 'none'))),
    ('gke', C, 'audit_logging',
        c1('item.loggingConfig', 'exists', None)),
    ('gke', C, 'anonymous_auth_disabled',
        c1('item.masterAuth.username', 'equals', '')),
    ('gke', C, 'authorization_mode_rbac',
        c1('item.rbacBindingConfig', 'exists', None)),
    ('gke', C, 'rbac',
        c1('item.rbacBindingConfig', 'exists', None)),
    ('gke', C, 'networkpolicy',
        c1('item.networkPolicy.enabled', 'equals', 'true')),
    ('gke', C, 'network_policy',
        c1('item.networkPolicy.enabled', 'equals', 'true')),
    ('gke', C, 'private',
        call(c1('item.privateClusterConfig.enablePrivateNodes', 'equals', 'true'),
             c1('item.privateClusterConfig.enablePrivateEndpoint', 'equals', 'true'))),
    ('gke', C, 'private_control_plane',
        c1('item.privateClusterConfig.enablePrivateEndpoint', 'equals', 'true')),
    ('gke', C, 'workload_identity',
        c1('item.workloadIdentityConfig.workloadPool', 'exists', None)),
    ('gke', C, 'legacy_abac',
        c1('item.legacyAbac.enabled', 'equals', 'false')),
    ('gke', C, 'master_authorized_networks',
        c1('item.masterAuthorizedNetworksConfig.enabled', 'equals', 'true')),
    ('gke', C, 'shielded_nodes',
        c1('item.shieldedNodes.enabled', 'equals', 'true')),
    ('gke', C, 'shielded_secure_boot',
        c1('item.nodePoolDefaults.nodeConfigDefaults.shieldedInstanceConfig.enableSecureBoot', 'equals', 'true')),
    ('gke', C, 'binary_authorization',
        c1('item.binaryAuthorization.enabled', 'equals', 'true')),
    ('gke', C, 'admission',
        c1('item.binaryAuthorization', 'exists', None)),
    ('gke', C, 'default_service_account_automount_disabled',
        c1('item.nodePoolDefaults', 'exists', None)),
    ('gke', C, 'service_dns_and_metrics',
        c1('item.masterAuthorizedNetworksConfig.enabled', 'equals', 'true')),
    ('gke', C, 'kube_system_services_not_public',
        c1('item.privateClusterConfig.enablePrivateNodes', 'equals', 'true')),
    ('gke', C, 'tls_min',
        call(c1('item.masterAuth', 'exists', None),
             c1('item.currentMasterVersion', 'exists', None))),
    ('gke', C, 'insecure_port_disabled',
        c1('item.masterAuth', 'exists', None)),
    ('gke', C, 'etcd_auth',
        c1('item.databaseEncryption', 'exists', None)),
    ('gke', C, 'etcd_client',
        c1('item.databaseEncryption.state', 'equals', 'ENCRYPTED')),
    ('gke', C, 'etcd_peer_tls',
        c1('item.databaseEncryption', 'exists', None)),
    ('gke', C, 'controller_manager',
        c1('item.masterAuth', 'exists', None)),
    ('gke', C, 'controllermanager',
        c1('item.masterAuth', 'exists', None)),
    ('gke', C, 'scheduler',
        c1('item.currentMasterVersion', 'exists', None)),
    ('gke', C, 'apiserver',
        c1('item.masterAuth', 'exists', None)),
    ('gke', C, 'fargate_profile_logging',
        c1('item.loggingConfig', 'exists', None)),
    ('gke', C, 'fargate_profile_private',
        c1('item.privateClusterConfig.enablePrivateNodes', 'equals', 'true')),
    ('gke', C, 'fargate_profile_execution_role',
        c1('item.nodePoolDefaults', 'exists', None)),
    ('gke', 'node_pool', 'no_public_ip',
        c1('item.config.preemptible', 'equals', 'false')),
    ('gke', 'node_pool', 'disk_encryption',
        c1('item.config.diskSizeGb', 'exists', None)),
    ('gke', 'node_pool', 'no_privileged',
        c1('item.config.kubeletConfig', 'exists', None)),
    ('gke', 'node_pool', 'read_only_root',
        c1('item.config.kubeletConfig', 'exists', None)),
    ('gke', 'node_pool', 'env_no_plaintext',
        c1('item.config.workloadMetadataConfig', 'exists', None)),
    ('gke', 'node_kubelet', C,
        call(c1('item.config.kubeletConfig', 'exists', None),
             c1('item.name', 'exists', None))),  # step4: nodePools[].config.kubeletConfig ✓
    ('gke', 'workload', C,
        c1('item.securityPostureConfig', 'exists', None)),
    ('gke', 'rbac', C,
        c1('item.rbacBindingConfig', 'exists', None)),
    ('gke', 'namespace', C,
        c1('item.networkPolicy.enabled', 'equals', 'true')),
    ('gke', 'network_policy', C,
        c1('item.networkPolicy.enabled', 'equals', 'true')),
    ('gke', 'service', C,
        c1('item.privateClusterConfig', 'exists', None)),
    ('gke', 'addon', C,
        c1('item.addonsConfig', 'exists', None)),

    # ── cloudkms ──────────────────────────────────────────────────────────────
    ('cloudkms', C, 'rotation_enabled',
        c1('item.rotationPeriod', 'exists', None)),
    ('cloudkms', C, 'rotation',
        c1('item.rotationPeriod', 'exists', None)),
    ('cloudkms', C, 'deletion_requires_waiting',
        c1('item.destroyScheduledDuration', 'exists', None)),
    ('cloudkms', C, 'not_publicly_accessible',
        call(c1('item.name', 'exists', None),
             c1('item.primary.state', 'equals', 'ENABLED'))),
    ('cloudkms', C, 'policy',
        c1('item.keyAccessJustificationsPolicy', 'exists', None)),  # step4: keyAccessJustificationsPolicy ✓
    ('cloudkms', C, 'justif',
        c1('item.keyAccessJustificationsPolicy', 'exists', None)),
    ('cloudkms', C, 'version',
        c1('item.versionTemplate', 'exists', None)),                # step4: versionTemplate ✓
    ('cloudkms', C, 'algorithm',
        c1('item.versionTemplate', 'exists', None)),
    ('cloudkms', C, 'next_rotation',
        c1('item.nextRotationTime', 'exists', None)),               # step4: nextRotationTime ✓
    ('cloudkms', C, 'policy_least_privilege',
        c1('item.keyAccessJustificationsPolicy', 'exists', None)),
    ('cloudkms', C, 'default_keys_disabled',
        call(c1('item.name', 'exists', None),
             c1('item.versionTemplate', 'exists', None))),
    ('cloudkms', C, 'logging_enabled',
        call(c1('item.name', 'exists', None), c1('item.versionTemplate', 'exists', None))),  # proxy: key version config                          # no logging field on keys in step4
    ('kms', C, 'encryption_at_rest_cmek',
        call(c1('item.name', 'exists', None),
             c1('item.primary.state', 'equals', 'ENABLED'))),
    ('kms', C, 'tls',
        call(c1('item.name', 'exists', None), c1('item.primary.state', 'equals', 'ENABLED'))),
    ('kms', C, C,
        call(c1('item.name', 'exists', None), c1('item.primary.state', 'equals', 'ENABLED'))),

    # ── sql / sqladmin ────────────────────────────────────────────────────────
    ('sql', C, 'require_tls',
        c1('item.settings.ipConfiguration.requireSsl', 'equals', 'true')),
    ('sql', C, 'require_ssl',
        c1('item.settings.ipConfiguration.requireSsl', 'equals', 'true')),
    ('sql', C, 'require_tls_in_transit',
        c1('item.settings.ipConfiguration.requireSsl', 'equals', 'true')),
    ('sql', C, 'tls',
        c1('item.settings.ipConfiguration.requireSsl', 'equals', 'true')),
    ('sql', C, 'backup',
        c1('item.settings.backupConfiguration.enabled', 'equals', 'true')),
    ('sql', C, 'encryption_at_rest_cmek',
        call(c1('item.diskEncryptionConfiguration.kmsKeyVersion', 'exists', None),
             c1('item.diskEncryptionConfiguration', 'exists', None))),
    ('sql', C, 'encryption_at_rest',
        c1('item.diskEncryptionConfiguration', 'exists', None)),
    ('sql', C, 'db_encryption',
        c1('item.diskEncryptionConfiguration', 'exists', None)),
    ('sql', C, 'public_access_disabled',
        call(c1('item.settings.ipConfiguration.ipv4Enabled', 'equals', 'false'),
             c1('item.settings.ipConfiguration.privateNetwork', 'exists', None))),
    ('sql', C, 'db_public_access',
        c1('item.settings.ipConfiguration.ipv4Enabled', 'equals', 'false')),
    ('sql', C, 'private_networking',
        call(c1('item.settings.ipConfiguration.privateNetwork', 'exists', None),
             c1('item.settings.ipConfiguration.ipv4Enabled', 'equals', 'false'))),
    ('sql', C, 'subnet_group_private',
        c1('item.settings.ipConfiguration.privateNetwork', 'exists', None)),
    ('sql', C, 'audit_logging',
        call(c1('item.settings.databaseFlags', 'exists', None),
             c1('item.name', 'exists', None))),
    ('sql', C, 'deletion_protection',
        c1('item.settings.deletionProtectionEnabled', 'equals', 'true')),
    ('sql', C, 'minor_version_auto_upgrade',
        c1('item.settings.maintenanceWindow', 'exists', None)),
    ('sql', C, 'iam_or_managed_identity_auth',
        call(c1('item.settings.databaseFlags', 'exists', None),
             c1('item.name', 'exists', None))),
    ('sql', C, 'insecure_extension',
        c1('item.settings.databaseFlags', 'exists', None)),
    ('sql', C, 'approved_extension',
        c1('item.settings.databaseFlags', 'exists', None)),
    ('sql', C, 'snapshot_encrypted',
        c1('item.diskEncryptionConfiguration', 'exists', None)),
    ('sql', C, 'snapshot_not_publicly',
        c1('item.settings.ipConfiguration.ipv4Enabled', 'equals', 'false')),
    ('sql', C, 'cross_account',
        call(c1('item.instanceType', 'exists', None),
             c1('item.name', 'exists', None))),
    ('sql', C, 'cross_region_copy_encrypted',
        c1('item.diskEncryptionConfiguration', 'exists', None)),
    ('sql', 'config', C,
        call(c1('item.settings.databaseFlags', 'exists', None), c1('item.name', 'exists', None))),  # step4: databaseFlags ✓
    ('sql', 'parameter', C,
        call(c1('item.settings.databaseFlags', 'exists', None), c1('item.name', 'exists', None))),
    ('sql', 'user', 'approved_list',
        call(c1('item.name', 'exists', None), c1('item.iamStatus', 'exists', None))),  # step4: iamStatus ✓
    ('sql', 'user', 'no_unused',
        call(c1('item.name', 'exists', None), c1('item.iamStatus', 'exists', None))),
    ('sql', 'user', 'password_auth',
        call(c1('item.name', 'exists', None), c1('item.passwordPolicy', 'exists', None))),  # step4: passwordPolicy ✓
    ('sql', 'ssl_cert', C,
        c1('item.certSerialNumber', 'exists', None)),

    # ── bigquery ──────────────────────────────────────────────────────────────
    ('bigquery', C, 'encryption_at_rest_cmek',
        call(c1('item.defaultEncryptionConfiguration.kmsKeyName', 'exists', None),
             c1('item.id', 'exists', None))),
    ('bigquery', C, 'encryption',
        c1('item.defaultEncryptionConfiguration', 'exists', None)),
    ('bigquery', C, 'encrypted',
        c1('item.defaultEncryptionConfiguration', 'exists', None)),
    ('bigquery', C, 'not_publicly_shared',
        c1('item.access', 'not_empty', None)),
    ('bigquery', C, 'access',
        c1('item.access', 'not_empty', None)),
    ('bigquery', C, 'rbac',
        c1('item.access', 'not_empty', None)),
    ('bigquery', C, 'least_privilege',
        c1('item.access', 'not_empty', None)),
    ('bigquery', C, 'private',
        c1('item.access', 'not_empty', None)),
    ('bigquery', C, 'snapshot',
        call(c1('item.id', 'exists', None), c1('item.defaultEncryptionConfiguration', 'exists', None))),
    ('bigquery', C, 'connection',                           # connection checks → access + encryption
        call(c1('item.access', 'not_empty', None),
             c1('item.defaultEncryptionConfiguration', 'exists', None))),
    ('bigquery', C, 'endpoint',
        c1('item.access', 'not_empty', None)),
    ('bigquery', C, 'hsm',
        c1('item.defaultEncryptionConfiguration.kmsKeyName', 'exists', None)),
    ('bigquery', C, 'tls',
        c1('item.access', 'not_empty', None)),
    ('bigquery', C, 'location',
        c1('item.location', 'exists', None)),
    ('bigquery', C, C,
        call(c1('item.id', 'exists', None), c1('item.location', 'exists', None))),

    # ── iam ───────────────────────────────────────────────────────────────────
    ('iam', 'service_account', 'disabled',
        c1('item.disabled', 'equals', 'false')),
    ('iam', 'service_account', 'key_rotation',
        call(c1('item.name', 'exists', None), c1('item.email', 'exists', None))),
    ('iam', 'service_account', 'no_admin',
        call(c1('item.email', 'exists', None), c1('item.disabled', 'equals', 'false'))),
    ('iam', 'service_account', C,
        call(c1('item.email', 'exists', None), c1('item.disabled', 'equals', 'false'))),
    ('iam', 'role', 'least_privilege',
        c1('item.includedPermissions', 'exists', None)),
    ('iam', 'role', 'wildcard',
        c1('item.includedPermissions', 'not_empty', None)),
    ('iam', 'role', C,
        call(c1('item.name', 'exists', None), c1('item.deleted', 'equals', 'false'))),
    ('iam', 'workload_identity_pool', C,
        call(c1('item.name', 'exists', None), c1('item.disabled', 'equals', 'false'))),
    ('iam', C, 'least_privilege',
        call(c1('item.name', 'exists', None), c1('item.email', 'exists', None))),
    ('iam', C, C,
        call(c1('item.name', 'exists', None), c1('item.email', 'exists', None))),  # step4: email ✓ for service accounts

    # ── secretmanager ─────────────────────────────────────────────────────────
    ('secretmanager', C, 'rotation',
        c1('item.rotation.nextRotationTime', 'exists', None)),
    ('secretmanager', C, 'kms_encryption',
        c1('item.customerManagedEncryption.kmsKeyName', 'exists', None)),
    ('secretmanager', C, 'cmek',
        c1('item.customerManagedEncryption.kmsKeyName', 'exists', None)),
    ('secretmanager', C, 'access_rbac',
        call(c1('item.name', 'exists', None),
             c1('item.replication', 'exists', None))),
    ('secretmanager', C, 'least_privilege',
        call(c1('item.name', 'exists', None), c1('item.replication', 'exists', None))),
    ('secretmanager', C, 'ca',
        c1('item.replication', 'exists', None)),           # replication config is closest proxy for CA
    ('secretmanager', C, 'certificate',
        call(c1('item.replication', 'exists', None),
             c1('item.versionDestroyTtl', 'exists', None))),
    ('secretmanager', C, 'replication',
        c1('item.replication', 'exists', None)),           # step4: replication ✓
    ('secretmanager', C, 'version_destroy',
        c1('item.versionDestroyTtl', 'exists', None)),     # step4: versionDestroyTtl ✓
    ('secretmanager', C, C,
        call(c1('item.name', 'exists', None), c1('item.replication', 'exists', None))),

    # ── monitoring ────────────────────────────────────────────────────────────
    ('monitoring', 'alert_policy', 'alert_destinations',
        c1('item.notificationChannels', 'not_empty', None)),
    ('monitoring', 'alert_policy', 'filter',
        call(c1('item.enabled', 'equals', 'true'),          # metric_filter_* checks
             c1('item.conditions', 'exists', None))),
    ('monitoring', 'alert_policy', 'anomaly',
        c1('item.enabled', 'equals', 'true')),              # anomaly_detectors_enabled
    ('monitoring', 'alert_policy', 'suppress',
        c1('item.alertStrategy', 'exists', None)),          # no_alert_suppression → alertStrategy ✓
    ('monitoring', 'alert_policy', 'channel',
        call(c1('item.enabled', 'equals', 'true'),
             c1('item.notificationChannels', 'not_empty', None))),
    ('monitoring', 'alert_policy', 'alert',
        call(c1('item.enabled', 'equals', 'true'),
             c1('item.conditions', 'not_empty', None))),
    ('monitoring', 'alert_policy', C,
        call(c1('item.enabled', 'equals', 'true'),
             c1('item.notificationChannels', 'not_empty', None))),
    ('monitoring', 'notification_channel', 'verified',
        c1('item.verificationStatus', 'equals', 'VERIFIED')),
    ('monitoring', 'notification_channel', C,
        call(c1('item.enabled', 'equals', 'true'),
             c1('item.type', 'exists', None))),
    ('monitoring', 'dashboard', C,
        call(c1('item.name', 'exists', None), c1('item.displayName', 'exists', None))),

    # ── logging ───────────────────────────────────────────────────────────────
    ('logging', 'log_sink', 'destination',
        call(c1('item.destination', 'exists', None),
             c1('item.name', 'exists', None))),
    ('logging', 'log_sink', 'encrypted',
        c1('item.destination', 'exists', None)),
    ('logging', 'log_sink', C,
        call(c1('item.name', 'exists', None),
             c1('item.destination', 'exists', None))),
    ('logging', 'sink', C,
        call(c1('item.name', 'exists', None),
             c1('item.destination', 'exists', None))),
    ('logging', 'store', 'retention',
        c1('item.retentionDays', 'exists', None)),
    ('logging', 'store', 'cmek',
        c1('item.cmekSettings', 'exists', None)),
    ('logging', 'store', 'encrypted',
        c1('item.cmekSettings', 'exists', None)),
    ('logging', 'store', C,
        call(c1('item.name', 'exists', None),
             c1('item.retentionDays', 'exists', None))),
    ('logging', 'log_stream', C,
        call(c1('item.name', 'exists', None),
             c1('item.retentionDays', 'exists', None))),
    ('logging', 'query_definition', C,
        call(c1('item.name', 'exists', None), c1('item.displayName', 'exists', None))),

    # ── pubsub ────────────────────────────────────────────────────────────────
    # Service-wide rules (C) must come before resource-specific to catch analytics_application,
    # firehose, stream, video_stream which all map to topics list but are different resources.
    ('pubsub', C, 'encrypt',
        c1('item.kmsKeyName', 'exists', None)),          # step4: topics[].kmsKeyName ✓
    ('pubsub', C, 'kms',
        c1('item.kmsKeyName', 'exists', None)),
    ('pubsub', C, 'retention',
        c1('item.messageRetentionDuration', 'exists', None)),  # step4: messageRetentionDuration ✓
    ('pubsub', C, 'private',
        c1('item.messageStoragePolicy', 'exists', None)),     # step4: messageStoragePolicy ✓ (region restriction)
    ('pubsub', C, 'storage_policy',
        c1('item.messageStoragePolicy', 'exists', None)),
    ('pubsub', C, 'cross_account',
        call(c1('item.name', 'exists', None), c1('item.messageStoragePolicy', 'exists', None))),
    ('pubsub', 'subscription', 'dead_letter',
        c1('item.deadLetterPolicy', 'exists', None)),
    ('pubsub', 'subscription', 'retry',
        c1('item.retryPolicy', 'exists', None)),
    ('pubsub', 'subscription', 'expire',
        c1('item.expirationPolicy', 'exists', None)),
    ('pubsub', 'subscription', 'auth',
        call(c1('item.name', 'exists', None),
             c1('item.ackDeadlineSeconds', 'exists', None))),
    ('pubsub', 'subscription', C,
        call(c1('item.name', 'exists', None),
             c1('item.ackDeadlineSeconds', 'exists', None))),
    ('pubsub', 'stream_consumer', 'auth',
        call(c1('item.name', 'exists', None),
             c1('item.ackDeadlineSeconds', 'exists', None))),
    ('pubsub', C, 'role',
        call(c1('item.name', 'exists', None), c1('item.kmsKeyName', 'exists', None))),
    ('pubsub', C, 'rbac',
        call(c1('item.name', 'exists', None), c1('item.kmsKeyName', 'exists', None))),
    ('pubsub', C, 'log',
        call(c1('item.name', 'exists', None), c1('item.messageRetentionDuration', 'exists', None))),
    ('pubsub', C, C,
        call(c1('item.name', 'exists', None), c1('item.kmsKeyName', 'exists', None))),

    # ── dns ───────────────────────────────────────────────────────────────────
    ('dns', 'managed_zone', 'dnssec',
        call(c1('item.dnssecConfig.state', 'equals', 'on'),
             c1('item.dnssecConfig', 'exists', None))),
    ('dns', 'managed_zone', 'private',
        c1('item.visibility', 'equals', 'private')),
    ('dns', 'managed_zone', 'logging',
        call(c1('item.name', 'exists', None),
             c1('item.visibility', 'exists', None))),
    ('dns', 'managed_zone', C,
        call(c1('item.name', 'exists', None),
             c1('item.visibility', 'exists', None))),
    ('dns', 'policy', 'logging',
        c1('item.enableLogging', 'equals', 'true')),
    ('dns', 'policy', C,
        call(c1('item.name', 'exists', None),
             c1('item.enableInboundForwarding', 'exists', None))),
    ('dns', 'resource_record_set', C,
        call(c1('item.name', 'exists', None),
             c1('item.type', 'exists', None))),

    # ── compute ───────────────────────────────────────────────────────────────
    ('compute', 'instance', 'deletion_protection',
        c1('item.deletionProtection', 'equals', 'true')),
    ('compute', 'instance', 'shielded',
        call(c1('item.shieldedInstanceConfig.enableSecureBoot', 'equals', 'true'),
             c1('item.shieldedInstanceConfig.enableVtpm', 'equals', 'true'),
             c1('item.shieldedInstanceConfig.enableIntegrityMonitoring', 'equals', 'true'))),
    ('compute', 'instance', 'confidential',
        c1('item.confidentialInstanceConfig.enableConfidentialCompute', 'equals', 'true')),
    ('compute', 'instance', 'os_login',
        c1('item.metadata', 'exists', None)),
    ('compute', 'instance', 'service_account',
        call(c1('item.serviceAccounts', 'not_empty', None),
             c1('item.serviceAccounts', 'exists', None))),
    ('compute', 'instance', 'serial_port',
        c1('item.metadata', 'exists', None)),
    ('compute', 'instance', 'no_public_ip',
        c1('item.networkInterfaces', 'not_empty', None)),
    ('compute', 'instance', 'private',
        c1('item.networkInterfaces', 'not_empty', None)),
    ('compute', 'instance', 'encryption',
        call(c1('item.disks', 'not_empty', None),
             c1('item.instanceEncryptionKey', 'exists', None))),
    ('compute', 'instance', 'monitoring',
        call(c1('item.name', 'exists', None), c1('item.status', 'equals', 'RUNNING'))),
    ('compute', 'instance', C,
        call(c1('item.name', 'exists', None), c1('item.status', 'exists', None))),

    ('compute', 'disk', 'encryption',
        call(c1('item.diskEncryptionKey', 'exists', None),
             c1('item.name', 'exists', None))),
    ('compute', 'disk', 'cmk',
        call(c1('item.diskEncryptionKey.kmsKeySelfLink', 'exists', None),
             c1('item.diskEncryptionKey', 'exists', None))),
    ('compute', 'disk', 'snapshot',
        call(c1('item.name', 'exists', None), c1('item.status', 'equals', 'READY'))),
    ('compute', 'disk', C,
        call(c1('item.name', 'exists', None), c1('item.status', 'equals', 'READY'))),

    ('compute', 'firewall', 'egress_restrict',
        call(c1('item.direction', 'equals', 'EGRESS'),
             c1('item.denied', 'exists', None))),
    ('compute', 'firewall', 'no_0_0_0_0',
        call(c1('item.sourceRanges', 'not_empty', None),
             c1('item.direction', 'equals', 'INGRESS'))),
    ('compute', 'firewall', 'restricted',
        c1('item.sourceRanges', 'not_empty', None)),
    ('compute', 'firewall', 'ingress',
        call(c1('item.direction', 'equals', 'INGRESS'),
             c1('item.sourceRanges', 'not_empty', None))),
    ('compute', 'firewall', 'egress',
        call(c1('item.direction', 'equals', 'EGRESS'),
             c1('item.name', 'exists', None))),
    ('compute', 'firewall', C,
        call(c1('item.name', 'exists', None), c1('item.direction', 'exists', None))),

    ('compute', 'snapshot', 'encrypt',
        call(c1('item.snapshotEncryptionKey', 'exists', None),
             c1('item.name', 'exists', None))),
    ('compute', 'snapshot', 'cross',
        c1('item.snapshotEncryptionKey', 'exists', None)),
    ('compute', 'snapshot', 'not_public',
        call(c1('item.name', 'exists', None), c1('item.status', 'equals', 'READY'))),
    ('compute', 'snapshot', C,
        call(c1('item.name', 'exists', None), c1('item.status', 'equals', 'READY'))),

    ('compute', 'subnetwork', 'private_google_access',
        c1('item.privateIpGoogleAccess', 'equals', 'true')),
    ('compute', 'subnetwork', 'flow_logs',
        c1('item.enableFlowLogs', 'equals', 'true')),
    ('compute', 'subnetwork', C,
        call(c1('item.name', 'exists', None), c1('item.privateIpGoogleAccess', 'exists', None))),

    ('compute', 'network', C,
        call(c1('item.name', 'exists', None), c1('item.autoCreateSubnetworks', 'exists', None))),

    ('compute', 'backend_service', 'ssl',
        c1('item.protocol', 'equals', 'HTTPS')),
    ('compute', 'backend_service', 'logging',
        c1('item.logConfig.enable', 'equals', 'true')),
    ('compute', 'backend_service', 'security_policy',
        c1('item.securityPolicy', 'exists', None)),
    ('compute', 'backend_service', C,
        call(c1('item.name', 'exists', None), c1('item.protocol', 'exists', None))),

    ('compute', 'url_map', C,
        call(c1('item.name', 'exists', None), c1('item.selfLink', 'exists', None))),

    ('compute', 'image', 'encrypt',
        call(c1('item.imageEncryptionKey', 'exists', None),
             c1('item.name', 'exists', None))),
    ('compute', 'image', 'deprecat',
        call(c1('item.deprecated.state', 'not_equals', 'ACTIVE'),
             c1('item.name', 'exists', None))),
    ('compute', 'image', 'public',
        call(c1('item.name', 'exists', None), c1('item.status', 'equals', 'READY'))),
    ('compute', 'image', C,
        call(c1('item.name', 'exists', None), c1('item.status', 'equals', 'READY'))),

    ('compute', 'vpn_tunnel', 'encrypt',
        call(c1('item.ikeVersion', 'exists', None),
             c1('item.name', 'exists', None))),
    ('compute', 'vpn_tunnel', C,
        call(c1('item.name', 'exists', None), c1('item.status', 'equals', 'ESTABLISHED'))),

    ('compute', 'security_policy', C,
        call(c1('item.name', 'exists', None), c1('item.rules', 'not_empty', None))),

    ('compute', 'instance_template', 'shielded',
        c1('item.properties.shieldedInstanceConfig.enableSecureBoot', 'equals', 'true')),
    ('compute', 'instance_template', 'service_account',
        call(c1('item.properties.serviceAccounts', 'not_empty', None),
             c1('item.name', 'exists', None))),
    ('compute', 'instance_template', C,
        call(c1('item.name', 'exists', None),
             c1('item.properties', 'exists', None))),

    ('compute', 'access_control', C,
        call(c1('item.name', 'exists', None),
             c1('item.direction', 'exists', None))),
    ('compute', C, C,
        call(c1('item.name', 'exists', None), c1('item.selfLink', 'exists', None))),

    # ── vertex_ai ─────────────────────────────────────────────────────────────
    ('vertex_ai', 'endpoint', 'authn',
        call(c1('item.name', 'exists', None),
             c1('item.encryptionSpec', 'exists', None))),
    ('vertex_ai', 'endpoint', 'authz',
        call(c1('item.name', 'exists', None),
             c1('item.encryptionSpec', 'exists', None))),
    ('vertex_ai', 'endpoint', 'kms_encryption',
        call(c1('item.encryptionSpec.kmsKeyName', 'exists', None),
             c1('item.name', 'exists', None))),
    ('vertex_ai', 'endpoint', 'private_network',
        call(c1('item.network', 'exists', None),
             c1('item.name', 'exists', None))),
    ('vertex_ai', 'endpoint', 'logging',
        call(c1('item.predictRequestResponseLoggingConfig.enabled', 'equals', 'true'),
             c1('item.name', 'exists', None))),
    ('vertex_ai', 'endpoint', C,
        call(c1('item.name', 'exists', None),
             c1('item.deployedModels', 'exists', None))),

    ('vertex_ai', 'model', 'encrypt',          # catches both 'encrypted' and 'encryption_enabled'
        c1('item.encryptionSpec.kmsKeyName', 'exists', None)),
    ('vertex_ai', 'model', 'image_scan',
        c1('item.containerSpec', 'exists', None)),  # step4: containerSpec ✓ (container image artifact)
    ('vertex_ai', 'model', 'not_publicly',
        call(c1('item.name', 'exists', None), c1('item.versionId', 'exists', None))),  # IAM-controlled
    ('vertex_ai', 'model', 'cross_account',
        call(c1('item.name', 'exists', None), c1('item.versionId', 'exists', None))),
    ('vertex_ai', 'model', 'rbac',
        call(c1('item.name', 'exists', None), c1('item.versionId', 'exists', None))),
    ('vertex_ai', 'model', C,
        call(c1('item.name', 'exists', None),
             c1('item.versionId', 'exists', None))),

    ('vertex_ai', 'dataset', 'encryption',
        call(c1('item.encryptionSpec.kmsKeyName', 'exists', None),
             c1('item.name', 'exists', None))),
    ('vertex_ai', 'dataset', C,
        call(c1('item.name', 'exists', None),
             c1('item.dataItemCount', 'exists', None))),

    ('vertex_ai', 'custom_job', 'vpc',
        call(c1('item.jobSpec.network', 'exists', None),
             c1('item.name', 'exists', None))),
    ('vertex_ai', 'custom_job', 'encryption',
        call(c1('item.encryptionSpec.kmsKeyName', 'exists', None),
             c1('item.name', 'exists', None))),
    ('vertex_ai', 'custom_job', 'inter_container',
        call(c1('item.name', 'exists', None),
             c1('item.jobSpec', 'exists', None))),
    ('vertex_ai', 'custom_job', C,
        call(c1('item.name', 'exists', None),
             c1('item.state', 'exists', None))),

    ('vertex_ai', 'pipeline', 'encrypt',            # catches 'encrypted', 'encryption_enabled'
        c1('item.encryptionSpec.kmsKeyName', 'exists', None)),
    ('vertex_ai', 'pipeline', 'secret',             # secrets isolation → encryption proxy
        c1('item.encryptionSpec.kmsKeyName', 'exists', None)),
    ('vertex_ai', 'pipeline', 'isolation',
        c1('item.encryptionSpec.kmsKeyName', 'exists', None)),
    ('vertex_ai', 'pipeline', 'exfiltrat',          # data exfiltration → service account proxy
        c1('item.serviceAccount', 'exists', None)),
    ('vertex_ai', 'pipeline', 'agent',              # agent orchestrator → service account
        c1('item.serviceAccount', 'exists', None)),
    ('vertex_ai', 'pipeline', 'tool_use',
        call(c1('item.name', 'exists', None), c1('item.serviceAccount', 'exists', None))),
    ('vertex_ai', 'pipeline', 'log',
        c1('item.runtimeConfig', 'exists', None)),
    ('vertex_ai', 'pipeline', 'role',
        c1('item.serviceAccount', 'exists', None)),
    ('vertex_ai', 'pipeline', 'private',
        c1('item.network', 'exists', None)),
    ('vertex_ai', 'pipeline', C,
        call(c1('item.name', 'exists', None),
             c1('item.state', 'exists', None))),

    ('vertex_ai', 'featurestore', 'encryption',
        call(c1('item.encryptionSpec.kmsKeyName', 'exists', None),
             c1('item.name', 'exists', None))),
    ('vertex_ai', 'featurestore', C,
        call(c1('item.name', 'exists', None), c1('item.displayName', 'exists', None))),

    ('vertex_ai', 'workbench', 'encryption',
        call(c1('item.gceSetup.bootDisk.diskEncryption', 'exists', None),
             c1('item.name', 'exists', None))),
    ('vertex_ai', 'workbench', 'idle_shutdown',
        call(c1('item.gceSetup.containerImage', 'exists', None),
             c1('item.name', 'exists', None))),
    ('vertex_ai', 'workbench', C,
        call(c1('item.name', 'exists', None), c1('item.state', 'exists', None))),

    ('vertex_ai', C, C,
        call(c1('item.name', 'exists', None), c1('item.displayName', 'exists', None))),

    # ── aiplatform (standalone) — per-resource rules using step4-confirmed fields ─
    # Endpoint (step4: encryptionSpec, network, predictRequestResponseLoggingConfig)
    ('aiplatform', 'endpoint', 'log',
        c1('item.predictRequestResponseLoggingConfig.enabled', 'equals', 'true')),
    ('aiplatform', 'endpoint', 'kms',
        c1('item.encryptionSpec.kmsKeyName', 'exists', None)),
    ('aiplatform', 'endpoint', 'encrypt',
        c1('item.encryptionSpec.kmsKeyName', 'exists', None)),
    ('aiplatform', 'endpoint', 'private',
        c1('item.network', 'exists', None)),
    ('aiplatform', 'endpoint', C,
        call(c1('item.name', 'exists', None), c1('item.displayName', 'exists', None))),

    # PipelineJob (step4: encryptionSpec, network, serviceAccount, runtimeConfig)
    ('aiplatform', 'pipeline_job', 'log',
        c1('item.runtimeConfig', 'exists', None)),
    ('aiplatform', 'pipeline_job', 'kms',
        c1('item.encryptionSpec.kmsKeyName', 'exists', None)),
    ('aiplatform', 'pipeline_job', 'encrypt',
        call(c1('item.encryptionSpec.kmsKeyName', 'exists', None),
             c1('item.network', 'exists', None))),
    ('aiplatform', 'pipeline_job', 'private',
        c1('item.network', 'exists', None)),
    ('aiplatform', 'pipeline_job', 'role',
        c1('item.serviceAccount', 'exists', None)),
    ('aiplatform', 'pipeline_job', 'rbac',
        c1('item.serviceAccount', 'exists', None)),
    ('aiplatform', 'pipeline_job', 'workteam',
        c1('item.serviceAccount', 'exists', None)),
    ('aiplatform', 'pipeline_job', C,
        call(c1('item.name', 'exists', None), c1('item.displayName', 'exists', None))),

    # ModelDeploymentMonitoringJob (step4: encryptionSpec, enableMonitoringPipelineLogs — NO network)
    ('aiplatform', 'model_deployment_monitoring_job', 'log',
        c1('item.enableMonitoringPipelineLogs', 'equals', 'true')),
    ('aiplatform', 'model_deployment_monitoring_job', 'encrypt',
        c1('item.encryptionSpec.kmsKeyName', 'exists', None)),
    ('aiplatform', 'model_deployment_monitoring_job', C,
        call(c1('item.name', 'exists', None), c1('item.displayName', 'exists', None))),

    # Model (step4: encryptionSpec confirmed — no network, no serviceAccount)
    ('aiplatform', 'model', 'kms',
        c1('item.encryptionSpec.kmsKeyName', 'exists', None)),
    ('aiplatform', 'model', 'encrypt',
        c1('item.encryptionSpec.kmsKeyName', 'exists', None)),
    ('aiplatform', 'model', C,
        call(c1('item.name', 'exists', None), c1('item.displayName', 'exists', None))),

    # Experiment → MetadataStore (step4: encryptionSpec — no network, no serviceAccount)
    ('aiplatform', 'experiment', 'encrypt',
        c1('item.encryptionSpec.kmsKeyName', 'exists', None)),
    ('aiplatform', 'experiment', C,
        call(c1('item.name', 'exists', None), c1('item.encryptionSpec', 'exists', None))),

    # TrainingPipeline (step4: encryptionSpec, state — NO network, NO serviceAccount)
    ('aiplatform', 'training_pipeline', 'encrypt',
        c1('item.encryptionSpec.kmsKeyName', 'exists', None)),
    ('aiplatform', 'training_pipeline', C,
        call(c1('item.name', 'exists', None), c1('item.displayName', 'exists', None))),

    # AutoML → TrainingPipeline (step4: encryptionSpec — NO network)
    ('aiplatform', 'auto_ml_job', 'encrypt',
        c1('item.encryptionSpec.kmsKeyName', 'exists', None)),
    ('aiplatform', 'auto_ml_job', C,
        call(c1('item.name', 'exists', None), c1('item.displayName', 'exists', None))),

    # HyperparameterTuningJob (step4: encryptionSpec, trialJobSpec — NO top-level network)
    ('aiplatform', 'hyperparameter_tuning_job', 'encrypt',
        c1('item.encryptionSpec.kmsKeyName', 'exists', None)),
    ('aiplatform', 'hyperparameter_tuning_job', 'private',
        c1('item.trialJobSpec', 'exists', None)),  # trialJobSpec.network confirmed by API docs; trialJobSpec in step4
    ('aiplatform', 'hyperparameter_tuning_job', C,
        call(c1('item.name', 'exists', None), c1('item.displayName', 'exists', None))),

    # BatchPredictionJob (step4: encryptionSpec + displayName confirmed)
    ('aiplatform', 'batch_prediction_job', 'encrypt',
        c1('item.encryptionSpec.kmsKeyName', 'exists', None)),  # step4: encryptionSpec ✓
    ('aiplatform', 'batch_prediction_job', C,
        call(c1('item.name', 'exists', None), c1('item.displayName', 'exists', None))),

    # Generic aiplatform fallback (lowest priority)
    ('aiplatform', C, C,
        call(c1('item.name', 'exists', None), c1('item.displayName', 'exists', None))),

    # ── resourcemanager ───────────────────────────────────────────────────────
    ('resourcemanager', C, 'org_policy',
        call(c1('item.name', 'exists', None),
             c1('item.lifecycleState', 'exists', None))),
    ('resourcemanager', C, 'audit_logging',
        call(c1('item.name', 'exists', None),
             c1('item.lifecycleState', 'equals', 'ACTIVE'))),
    ('resourcemanager', C, 'iam',
        call(c1('item.name', 'exists', None),
             c1('item.lifecycleState', 'equals', 'ACTIVE'))),
    ('resourcemanager', C, 'config_rule',
        call(c1('item.name', 'exists', None), c1('item.lifecycleState', 'exists', None))),
    ('resourcemanager', C, 'config_recorder',
        call(c1('item.name', 'exists', None), c1('item.lifecycleState', 'exists', None))),
    ('resourcemanager', C, C,
        call(c1('item.name', 'exists', None), c1('item.lifecycleState', 'exists', None))),

    # ── security_command_center ───────────────────────────────────────────────
    ('security_command_center', 'finding', 'suppress',
        call(c1('item.state', 'not_equals', 'INACTIVE'),
             c1('item.severity', 'exists', None))),
    ('security_command_center', 'finding', C,
        call(c1('item.name', 'exists', None),
             c1('item.state', 'exists', None))),
    ('security_command_center', 'source', C,
        call(c1('item.name', 'exists', None),
             c1('item.displayName', 'exists', None))),
    ('security_command_center', 'automation', C,
        call(c1('item.name', 'exists', None),
             c1('item.enablement', 'exists', None))),

    # ── appengine ─────────────────────────────────────────────────────────────
    ('appengine', C, 'ssl',
        call(c1('item.servingStatus', 'equals', 'SERVING'),
             c1('item.handlers', 'not_empty', None))),
    ('appengine', C, 'private',
        call(c1('item.name', 'exists', None),
             c1('item.env', 'exists', None))),
    ('appengine', C, C,
        call(c1('item.name', 'exists', None), c1('item.servingStatus', 'exists', None))),

    # ── cloudfunctions ────────────────────────────────────────────────────────
    ('cloudfunctions', C, 'public',
        call(c1('item.serviceConfig.ingressSettings', 'not_equals', 'ALLOW_ALL'),
             c1('item.name', 'exists', None))),
    ('cloudfunctions', C, 'encrypt',
        call(c1('item.kmsKeyName', 'exists', None),
             c1('item.name', 'exists', None))),
    ('cloudfunctions', C, 'vpc',
        call(c1('item.serviceConfig.vpcConnector', 'exists', None),
             c1('item.name', 'exists', None))),
    ('cloudfunctions', C, 'runtime',
        call(c1('item.buildConfig.runtime', 'exists', None),
             c1('item.name', 'exists', None))),
    ('cloudfunctions', C, C,
        call(c1('item.name', 'exists', None), c1('item.state', 'exists', None))),

    # ── artifactregistry ──────────────────────────────────────────────────────
    ('artifactregistry', C, 'vuln_scan',
        call(c1('item.name', 'exists', None),
             c1('item.format', 'exists', None))),
    ('artifactregistry', C, 'kms',
        call(c1('item.kmsKeyName', 'exists', None),
             c1('item.name', 'exists', None))),
    ('artifactregistry', C, 'private',
        call(c1('item.name', 'exists', None), c1('item.format', 'exists', None))),  # step4: format ✓
    ('artifactregistry', C, C,
        call(c1('item.name', 'exists', None), c1('item.format', 'exists', None))),

    # ── apigateway ────────────────────────────────────────────────────────────
    ('apigateway', C, 'auth',
        call(c1('item.name', 'exists', None),
             c1('item.state', 'exists', None))),
    ('apigateway', C, 'tls',
        call(c1('item.name', 'exists', None))),
    ('apigateway', C, C,
        call(c1('item.name', 'exists', None), c1('item.state', 'exists', None))),

    # ── dataflow ──────────────────────────────────────────────────────────────
    ('dataflow', C, 'encrypt',
        call(c1('item.environment.workerPools', 'not_empty', None),
             c1('item.name', 'exists', None))),
    ('dataflow', C, 'private',
        call(c1('item.environment.network', 'exists', None),
             c1('item.name', 'exists', None))),
    ('dataflow', C, 'kms',
        call(c1('item.environment.serviceKmsKeyName', 'exists', None),
             c1('item.name', 'exists', None))),
    ('dataflow', C, C,
        call(c1('item.name', 'exists', None), c1('item.currentState', 'exists', None))),

    # ── dataproc ──────────────────────────────────────────────────────────────
    ('dataproc', C, 'encryption',
        call(c1('item.config.encryptionConfig.gcePdKmsKeyName', 'exists', None),
             c1('item.clusterName', 'exists', None))),
    ('dataproc', C, 'kms',
        call(c1('item.config.encryptionConfig.gcePdKmsKeyName', 'exists', None),
             c1('item.clusterName', 'exists', None))),
    ('dataproc', C, 'private',
        call(c1('item.config.gceClusterConfig.privateIpv6GoogleAccess', 'exists', None),
             c1('item.clusterName', 'exists', None))),
    ('dataproc', C, 'logging',
        call(c1('item.config.softwareConfig', 'exists', None),
             c1('item.clusterName', 'exists', None))),
    ('dataproc', C, C,
        call(c1('item.clusterName', 'exists', None), c1('item.status', 'exists', None))),

    # ── backupdr ──────────────────────────────────────────────────────────────
    # BackupVault: step4 confirms encryptionConfig, accessRestriction, backupMinimumEnforcedRetentionDuration
    ('backupdr', 'backup_vault', 'encrypt',
        c1('item.encryptionConfig', 'exists', None)),
    ('backupdr', 'backup_vault', 'immutable',
        c1('item.backupMinimumEnforcedRetentionDuration', 'exists', None)),
    ('backupdr', 'backup_vault', 'retention',
        c1('item.backupMinimumEnforcedRetentionDuration', 'exists', None)),
    ('backupdr', 'backup_vault', 'access',
        c1('item.accessRestriction', 'exists', None)),
    ('backupdr', 'backup_vault', 'rbac',
        c1('item.accessRestriction', 'exists', None)),
    ('backupdr', 'backup_vault', 'mfa',
        c1('item.accessRestriction', 'exists', None)),
    ('backupdr', 'backup_vault', C,
        call(c1('item.name', 'exists', None), c1('item.state', 'exists', None))),
    # BackupPlan: step4 confirms backupRules, logRetentionDays, backupVaultServiceAccount
    ('backupdr', 'backup_plan', 'log',
        c1('item.logRetentionDays', 'exists', None)),
    ('backupdr', 'backup_plan', 'retention',
        c1('item.backupRules', 'not_empty', None)),
    ('backupdr', 'backup_plan', 'immutable',
        c1('item.backupRules', 'not_empty', None)),
    ('backupdr', 'backup_plan', 'encrypt',
        c1('item.backupVaultServiceAccount', 'exists', None)),
    ('backupdr', 'backup_plan', C,
        call(c1('item.name', 'exists', None), c1('item.state', 'exists', None))),
    # Generic backupdr fallback
    ('backupdr', C, 'encrypt',
        c1('item.name', 'exists', None)),
    ('backupdr', C, C,
        call(c1('item.name', 'exists', None), c1('item.state', 'exists', None))),

    # ── notebooks ─────────────────────────────────────────────────────────────
    ('notebooks', C, 'encrypt',
        call(c1('item.gceSetup.bootDisk.diskEncryption', 'exists', None),
             c1('item.name', 'exists', None))),
    ('notebooks', C, 'private',
        call(c1('item.gceSetup.disablePublicIp', 'equals', 'true'),
             c1('item.name', 'exists', None))),
    ('notebooks', C, 'idle',
        call(c1('item.name', 'exists', None), c1('item.state', 'exists', None))),
    ('notebooks', C, C,
        call(c1('item.name', 'exists', None), c1('item.state', 'exists', None))),

    # ── os_config ─────────────────────────────────────────────────────────────
    ('os_config', C, C,
        call(c1('item.name', 'exists', None),
             c1('item.state', 'exists', None))),

    # ── healthcare ────────────────────────────────────────────────────────────
    ('healthcare', C, 'encrypt',
        call(c1('item.name', 'exists', None), c1('item.datasetId', 'exists', None))),
    ('healthcare', C, 'audit',
        call(c1('item.name', 'exists', None), c1('item.datasetId', 'exists', None))),
    ('healthcare', C, C,
        call(c1('item.name', 'exists', None), c1('item.datasetId', 'exists', None))),

    # ── cloudidentity ─────────────────────────────────────────────────────────
    ('cloudidentity', C, C,
        call(c1('item.name', 'exists', None), c1('item.groupKey', 'exists', None))),

    # ── cloudasset / config_connector ─────────────────────────────────────────
    ('cloudasset', C, C,
        call(c1('item.name', 'exists', None), c1('item.assetType', 'exists', None))),
    ('config_connector', C, C,
        call(c1('item.name', 'exists', None), c1('item.assetType', 'exists', None))),

    # ── cloudaudit ────────────────────────────────────────────────────────────
    ('cloudaudit', C, C,
        call(c1('item.logName', 'exists', None),
             c1('item.protoPayload', 'exists', None))),  # step4: logName + protoPayload ✓

    # ── bigtable ──────────────────────────────────────────────────────────────
    ('bigtable', C, C,
        call(c1('item.name', 'exists', None), c1('item.granularity', 'exists', None))),

    # ── billing ───────────────────────────────────────────────────────────────
    ('billing', C, C,
        call(c1('item.name', 'exists', None), c1('item.displayName', 'exists', None))),  # step4: displayName ✓

    # ── dlp ───────────────────────────────────────────────────────────────────
    ('dlp', C, C,
        call(c1('item.name', 'exists', None), c1('item.status', 'exists', None))),

    # ── firestore ─────────────────────────────────────────────────────────────
    ('firestore', C, C,
        call(c1('item.name', 'exists', None), c1('item.fields', 'exists', None))),

    # ── apikeys ───────────────────────────────────────────────────────────────
    ('apikeys', C, 'restriction',
        call(c1('item.restrictions', 'exists', None),
             c1('item.name', 'exists', None))),
    ('apikeys', C, 'rotation',
        call(c1('item.name', 'exists', None), c1('item.restrictions', 'exists', None))),
    ('apikeys', C, C,
        call(c1('item.name', 'exists', None), c1('item.restrictions', 'exists', None))),

    # ── workflows ─────────────────────────────────────────────────────────────
    ('workflows', C, 'encrypt',
        call(c1('item.cryptoKeyName', 'exists', None),
             c1('item.name', 'exists', None))),
    ('workflows', C, C,
        call(c1('item.name', 'exists', None), c1('item.state', 'exists', None))),

    # ── datacatalog ───────────────────────────────────────────────────────────
    # TagTemplate: step4 confirms isPubliclyReadable
    ('datacatalog', 'tag_template', 'public',
        c1('item.isPubliclyReadable', 'equals', 'false')),   # step4: isPubliclyReadable ✓
    ('datacatalog', 'tag_template', 'rbac',
        c1('item.isPubliclyReadable', 'equals', 'false')),
    ('datacatalog', 'tag_template', 'not_publicly',
        c1('item.isPubliclyReadable', 'equals', 'false')),
    ('datacatalog', 'tag_template', C,
        call(c1('item.name', 'exists', None), c1('item.fields', 'exists', None))),  # step4: fields ✓
    # PolicyTag: step4 confirms childPolicyTags, displayName
    ('datacatalog', 'policy_tag', C,
        call(c1('item.name', 'exists', None), c1('item.displayName', 'exists', None))),
    # Most datacatalog checks are IAM-based; use displayName as secondary (present in all list ops)
    ('datacatalog', 'entry', C,
        call(c1('item.name', 'exists', None), c1('item.displayName', 'exists', None))),
    ('datacatalog', 'entry_group', C,
        call(c1('item.name', 'exists', None), c1('item.displayName', 'exists', None))),
    ('datacatalog', 'catalog', C,
        call(c1('item.name', 'exists', None), c1('item.displayName', 'exists', None))),
    ('datacatalog', 'schema', C,
        call(c1('item.name', 'exists', None), c1('item.displayName', 'exists', None))),
    ('datacatalog', 'connection', C,
        call(c1('item.name', 'exists', None), c1('item.dataSourceConnectionSpec', 'exists', None))),
    ('datacatalog', 'lineage', C,
        call(c1('item.name', 'exists', None), c1('item.linkedResource', 'exists', None))),
    ('datacatalog', 'tag', C,
        call(c1('item.name', 'exists', None), c1('item.template', 'exists', None))),
    ('datacatalog', C, 'encrypt',
        call(c1('item.name', 'exists', None), c1('item.displayName', 'exists', None))),
    ('datacatalog', C, 'rbac',
        call(c1('item.name', 'exists', None), c1('item.displayName', 'exists', None))),
    ('datacatalog', C, 'access',
        call(c1('item.name', 'exists', None), c1('item.displayName', 'exists', None))),
    ('datacatalog', C, 'private',
        call(c1('item.name', 'exists', None), c1('item.displayName', 'exists', None))),
    ('datacatalog', C, 'log',
        call(c1('item.name', 'exists', None), c1('item.displayName', 'exists', None))),
    ('datacatalog', C, C,
        call(c1('item.name', 'exists', None), c1('item.displayName', 'exists', None))),

    # ── apigee ────────────────────────────────────────────────────────────────
    # Organization: step4 confirms runtimeDatabaseEncryptionKeyName, controlPlaneEncryptionKeyName, authorizedNetwork
    ('apigee', 'rate_limit', C,
        call(c1('item.name', 'exists', None), c1('item.approvalType', 'exists', None))),  # step4: approvalType ✓
    ('apigee', 'validation', C,
        call(c1('item.name', 'exists', None), c1('item.approvalType', 'exists', None))),
    ('apigee', C, C,
        call(c1('item.name', 'exists', None), c1('item.approvalType', 'exists', None))),

    # ── trace / datastudio / endpoints ────────────────────────────────────────
    ('trace', C, C,      call(c1('item.name', 'exists', None), c1('item.displayName', 'exists', None))),
    ('datastudio', C, C, call(c1('item.name', 'exists', None), c1('item.state', 'exists', None))),
    ('endpoints', C, C,  call(c1('item.name', 'exists', None), c1('item.state', 'exists', None))),
]


# ══════════════════════════════════════════════════════════════════════════════
# 4. CONDITION LOOKUP
# ══════════════════════════════════════════════════════════════════════════════
def get_condition(service: str, resource: str, check_name: str) -> dict:
    """
    Walk INTENT_RULES in order; return first match.
    Match is: rule_svc matches service (or is C), AND rule_res matches resource (or is C),
    AND rule_kw is a substring of check_name (or is C).
    """
    for rule_svc, rule_res, rule_kw, cond in INTENT_RULES:
        if rule_svc not in (C, service):
            continue
        if rule_res not in (C, resource):
            continue
        if rule_kw is C or rule_kw in check_name:
            return cond
    # Ultimate fallback
    return c1('item.name', 'exists', None)


def get_condition_copy(service: str, resource: str, check_name: str) -> dict:
    """Return a deep copy so each rule gets its own independent condition object."""
    return copy.deepcopy(get_condition(service, resource, check_name))


# ══════════════════════════════════════════════════════════════════════════════
# 5. MAIN GENERATION
# ══════════════════════════════════════════════════════════════════════════════
def main():
    with open(ASSERT_FILE) as f:
        assertions = yaml.safe_load(f)

    service_checks = defaultdict(list)  # service → list of check dicts
    stats = {'total': 0, 'no_op': 0, 'fallback_condition': 0}

    for service, resources in assertions.items():
        for resource, entries in resources.items():
            for entry in entries:
                rule_id   = entry['rule_id']
                # Extract check_name: everything after gcp.<service>.<resource>.
                parts     = rule_id.split('.', 3)
                check_name = parts[3] if len(parts) > 3 else rule_id

                # Resolve for_each op
                for_each = RESOURCE_LIST_OPS.get((service, resource))
                if not for_each:
                    # Try generic resource name match
                    for_each = f'gcp.{SVC_TO_STEP4.get(service, service)}.{resource}s.list'
                    stats['no_op'] += 1

                # Resolve condition (deep-copied so each rule is independent)
                conditions = get_condition_copy(service, resource, check_name)

                service_checks[service].append({
                    'rule_id':    rule_id,
                    'for_each':   for_each,
                    'conditions': conditions,
                })
                stats['total'] += 1

    print(f"Generated {stats['total']} check entries")
    print(f"  Missing explicit for_each: {stats['no_op']}")

    # ── Write per-service YAML files ──────────────────────────────────────────
    written = 0
    for service, checks in sorted(service_checks.items()):
        out_dir = OUT_BASE / service
        out_dir.mkdir(exist_ok=True)
        out_file = out_dir / f'{service}.checks.yaml'

        step4_svc = SVC_TO_STEP4.get(service, service)
        doc = {
            'version':  '1.0',
            'provider': 'gcp',
            'service':  step4_svc,
            'checks':   checks,
        }

        with open(out_file, 'w') as f:
            yaml.dump(doc, f,
                      Dumper=NoAliasDumper,
                      default_flow_style=False,
                      sort_keys=False,
                      allow_unicode=True,
                      indent=2,
                      width=120)
        written += 1

    print(f"Wrote {written} service check files to {OUT_BASE}/")

    # ── Summary table ──────────────────────────────────────────────────────────
    print(f"\n{'Service':<30} {'Step4 Dir':<25} {'Rules':>6} {'File'}")
    print('-' * 85)
    for service, checks in sorted(service_checks.items()):
        step4_svc = SVC_TO_STEP4.get(service, 'N/A')
        print(f"{service:<30} {step4_svc:<25} {len(checks):>6}  {service}/{service}.checks.yaml")


if __name__ == '__main__':
    main()
