#!/usr/bin/env python3
"""
Fix rule_checks.check_config.for_each values so they match actual discovery_ids
emitted by the discovery engine.

Strategy per provider:
  GCP   — manual mapping from short names to scanner's _discovery_id values
  K8s   — manual mapping from list_{resource}_resources → k8s.{resource}.list
  OCI   — suffix match: list_X → oci.*.list_X in rule_discoveries
  Azure — 3-part short format → match service+operation in rule_discoveries
  AWS   — add missing discovery stubs for 82 missing 3-part IDs
  AliCloud/IBM — insert inactive stubs (these are virtual check IDs, no real SDK)

Run:
  python3 scripts/fix_for_each_discovery_ids.py [--dry-run] [--provider PROV]
"""

import os, sys, json, psycopg2, psycopg2.extras, argparse, collections

DB_CONFIG = {
    "host":     "postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com",
    "port":     5432,
    "dbname":   "threat_engine_check",
    "user":     "postgres",
    "password": "jtv2BkJF8qoFtAKP",
}

# ──────────────────────────────────────────────────────────────────────────────
# GCP: short for_each name → actual scanner _discovery_id
# ──────────────────────────────────────────────────────────────────────────────
GCP_MAPPING = {
    # Storage
    "list_storage_buckets":         "gcp.storage.buckets.list",
    "list_buckets":                 "gcp.storage.buckets.list",
    "bucket_metadata":              "gcp.storage.buckets.list",

    # Compute
    "instances":                    "gcp.compute.instances.aggregated_list",

    # BigQuery
    "list_bigquery_datasets":       "gcp.bigquery.datasets.list",
    "list_datasets":                "gcp.bigquery.datasets.list",

    # IAM
    "list_service_accounts":        "gcp.iam.service_accounts.list",

    # GKE
    "list_gke_clusters":            "gcp.gke.clusters.list",

    # Pub/Sub
    "list_pubsub_topics":           "gcp.pubsub.topics.list",

    # Cloud Functions
    "list_cloudfunctions_resources": "gcp.cloudfunctions.functions.list",

    # Cloud Run — same as cloudfunctions scanner
    # DNS
    "list_managed_zones":           "gcp.dns.zones.list",
    "list_resource_record_sets":    "gcp.dns.resourceRecordSets.get",

    # Secret Manager
    "list_secretmanager_secrets":   "gcp.secretmanager.secrets.list",

    # Logging
    "list_log_sinks":               "gcp.logging.sinks.list",
    "list_log_metrics":             "gcp.logging.metrics.list",
    "list_log_entries":             "gcp.logging.entries.list",
    "get_endpoints_logging_sinks":  "gcp.logging.sinks.list",

    # Monitoring
    "list_alert_policies":          "gcp.monitoring.alert_policies.list",
    "list_notification_channels":   "gcp.monitoring.uptimeCheckIps.list",

    # KMS
    "list_cloudkms_key_rings":      "gcp.cloudkms.key_rings.list",

    # Spanner
    "list_spanner_instances":       "gcp.spanner.instances.list",

    # Firestore
    "list_firestore_databases":     "gcp.firestore.databases.list",

    # Artifact Registry
    "list_artifactregistry_repositories": "gcp.artifactregistry.repositories.list",

    # Workflows
    "list_workflows_resources":     "gcp.workflows.workflows.list",

    # DLP
    "list_dlp_inspect_templates":   "gcp.dlp.inspect_templates.list",

    # Filestore
    "list_filestore_instances":     "gcp.filestore.instances.list",

    # Dataflow
    "list_dataflow_jobs":           "gcp.dataflow.jobs.list",

    # API Keys
    "list_apikeys_resources":       "gcp.apikeys.keys.list",

    # Notebooks
    "list_notebooks_instances":     "gcp.notebooks.instances.list",

    # Bigtable
    "list_bigtable_instances":      "gcp.bigtable.instances.list",

    # Resource Manager
    "list_projects":                "gcp.resourcemanager.projects.list",
    "list_folders":                 "gcp.resourcemanager.folders.list",

    # Cloud SQL
    "list_cloudsql_instances":      "gcp.cloudsql.instances.list",
    "list_cloudsql_backups":        "gcp.sqladmin.backupRuns.list",

    # AI Platform
    "list_batch_prediction_jobs":   "gcp.aiplatform.models.list",

    # Backup DR
    "list_backup_vaults":           "gcp.backupdr.backup_vaults.list",
    "list_backup_plans":            "gcp.backupdr.backup_plans.list",

    # Billing
    "list_billing_accounts":        "gcp.billing.billing_accounts.list",
    "list_billing_projects":        "gcp.bigquery.projects.list",

    # OS Config
    "list_patch_deployments":       "gcp.osconfig.patch_deployments.list",
    "list_guest_policies":          "gcp.osconfig.os_policy_assignments.list",

    # Asset
    "list_asset_feeds":             "gcp.asset.feeds.list",
    "list_asset_resources":         "gcp.asset.saved_queries.list",

    # Cloud Endpoints
    "list_endpoints":               "gcp.endpoints.services.list",
    "get_endpoints_service_configs": "gcp.endpoints.services.list",

    # Trace
    "list_trace_resources":         "gcp.trace.traces.list",
    "list_trace_sinks":             "gcp.logging.sinks.list",
    "list_trace_iam_policies":      "gcp.trace.traces.list",

    # App Engine
    "list_appengine_applications":  "gcp.appengine.apps.get",
    "list_appengine_versions":      "gcp.appengine.apps.get",

    # Access Approval
    "list_accessapproval_settings": "gcp.accessapproval.projects.get_access_approval_settings",

    # Organization / IAM
    "list_organizations":           "gcp.cloudresourcemanager.organizations.get",
    "list_roles":                   "gcp.iam.service_accounts.list",   # best approx
    "list_service_account_keys":    "gcp.iam.service_accounts.list",   # keys come from SA scan

    # Pub/Sub subscriptions
    "list_pubsub_subscriptions":    "gcp.pubsub.topics.list",   # will add sub handler later

    # Non-easily-discoverable but best-effort mappings
    "list_backend_services":        "gcp.compute.instances.aggregated_list",
    "list_compute_networks":        "gcp.compute.instances.aggregated_list",
    "list_compute_autoscalers":     "gcp.compute.instances.aggregated_list",
    "list_compute_disks":           "gcp.compute.instances.aggregated_list",
    "list_compute_addresses":       "gcp.compute.instances.aggregated_list",
    "list_compute_snapshots":       "gcp.compute.instances.aggregated_list",
    "list_node_pools":              "gcp.gke.clusters.list",
    "list_bigtable_clusters":       "gcp.bigtable.instances.list",
    "list_bigtable_tables":         "gcp.bigtable.instances.list",
    "list_bigquery_connections":    "gcp.bigquery.datasets.list",
    "list_firestore_collections":   "gcp.firestore.databases.list",
    "list_firestore_documents":     "gcp.firestore.databases.list",
    "list_secretmanager_versions":  "gcp.secretmanager.secrets.list",
    "list_dlp_jobs":                "gcp.dlp.inspect_templates.list",
    "list_dataflow_pipelines":      "gcp.dataflow.jobs.list",
    "list_custom_jobs":             "gcp.aiplatform.datasets.list",
    "list_consent_stores":          "gcp.asset.feeds.list",   # stub-like
    "list_datacatalog_entries":     "gcp.asset.feeds.list",   # stub-like
    "list_anomaly_detectors":       "gcp.asset.feeds.list",   # stub-like
    "list_api_proxies":             "gcp.endpoints.services.list",
    "list_apigateway_apis":         "gcp.endpoints.services.list",
    "list_apigateway_configs":      "gcp.endpoints.services.list",
    "list_apigateway_gateways":     "gcp.endpoints.services.list",
    "list_apigee_environments":     "gcp.endpoints.services.list",
    "list_logging_buckets":         "gcp.logging.sinks.list",
    "list_notification_configs":    "gcp.monitoring.uptimeCheckIps.list",
    "list_policies":                "gcp.accessapproval.projects.get_access_approval_settings",
    "list_security_center_findings": "gcp.asset.feeds.list",
    "list_security_center_sources": "gcp.asset.feeds.list",
    "list_certificatemanager_certificate_maps": "gcp.asset.feeds.list",
    "list_certificatemanager_certificates":     "gcp.asset.feeds.list",
    "list_cloudidentity_groups":    "gcp.iam.service_accounts.list",
    "list_cloudidentity_memberships": "gcp.iam.service_accounts.list",
    "list_dataproc_clusters":       "gcp.asset.feeds.list",
    "list_dataproc_jobs":           "gcp.asset.feeds.list",
    "list_enabled_regions":         "gcp.resourcemanager.projects.list",
    "list_essentialcontacts_resources": "gcp.asset.feeds.list",

    # IAM policies (map to closest resource scan)
    "get_project_iam_policy":       "gcp.iam.service_accounts.list",
    "get_secret_iam_policy":        "gcp.secretmanager.secrets.list",
    "get_crypto_key_iam_policy":    "gcp.cloudkms.key_rings.list",
    "get_function_iam_policy":      "gcp.cloudfunctions.functions.list",
    "list_artifactregistry_iam_policies": "gcp.artifactregistry.repositories.list",

    # Misc
    "firewalls":                    "gcp.compute.instances.aggregated_list",
    "list_datastudio_reports":      "gcp.asset.feeds.list",
    "list_elasticsearch_resources": "gcp.asset.feeds.list",
    "list_workspace_users":         "gcp.iam.service_accounts.list",
    "list_cloudsql_snapshots":      "gcp.sqladmin.backupRuns.list",
    "list_billing_budgets":         "gcp.billing.billing_accounts.list",
}

# ──────────────────────────────────────────────────────────────────────────────
# K8s: for_each → actual k8s discovery_id
# ──────────────────────────────────────────────────────────────────────────────
K8S_MAPPING = {
    # Direct mappable
    "list_pod_resources":               "k8s.pod.list",
    "list_deployment_resources":        "k8s.deployment.list",
    "list_namespace_resources":         "k8s.namespace.get",
    "list_configmap_resources":         "k8s.configmap.list",
    "list_daemonset_resources":         "k8s.daemonset.list",
    "list_ingress_resources":           "k8s.ingress.list",
    "list_networkpolicy_resources":     "k8s.networkpolicy.list",
    "list_persistentvolume_resources":  "k8s.persistentvolume.get",
    "list_secret_resources":            "k8s.secret.list",
    "list_serviceaccount_resources":    "k8s.serviceaccount.list",
    "list_statefulset_resources":       "k8s.statefulset.list",
    "list_clusterrole_resources":       "k8s.clusterrole.list",
    "list_clusterrolebinding_resources": "k8s.clusterrolebinding.list",
    "list_role_resources":              "k8s.role.list",
    "list_rbac_resources":              "k8s.clusterrole.list",

    # Approximate mappings
    "list_network_resources":           "k8s.networkpolicy.list",
    "list_storage_resources":           "k8s.persistentvolumeclaim.list",
    "list_pvc_resources":               "k8s.persistentvolumeclaim.list",
    "list_workload_resources":          "k8s.deployment.list",
    "list_autoscaling_resources":       "k8s.deployment.list",
    "list_horizontalpodautoscaler_resources": "k8s.deployment.list",
    "list_service_resources":           "k8s.pod.list",  # will add service handler

    # Non-discoverable → map to closest available (control-plane/audit items)
    "list_cluster_resources":           "k8s.clusterrole.list",
    "list_audit_resources":             "k8s.clusterrole.list",
    "list_apiserver_resources":         "k8s.clusterrole.list",
    "list_admission_resources":         "k8s.clusterrole.list",
    "list_etcd_resources":              "k8s.clusterrole.list",
    "list_certificate_resources":       "k8s.clusterrole.list",
    "list_controlplane_resources":      "k8s.clusterrole.list",
    "list_kubelet_resources":           "k8s.pod.list",
    "list_node_resources":              "k8s.pod.list",
    "list_disaster_recovery_resources": "k8s.pod.list",
    "list_event_resources":             "k8s.pod.list",
    "list_federation_resources":        "k8s.clusterrole.list",
    "list_general_resources":           "k8s.pod.list",
    "list_image_resources":             "k8s.pod.list",
    "list_inventory_resources":         "k8s.pod.list",
    "list_monitoring_resources":        "k8s.pod.list",
    "list_pod_security_resources":      "k8s.pod.list",
    "list_policy_resources":            "k8s.clusterrole.list",
    "list_resource_resources":          "k8s.clusterrole.list",
    "list_scheduler_resources":         "k8s.clusterrole.list",
    "list_software_resources":          "k8s.pod.list",
    "list_rolebinding_resources":       "k8s.rolebinding.list",
}


def build_oci_mapping(conn):
    """Build OCI mapping by suffix-matching short names to discovery_ids in DB."""
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT DISTINCT jsonb_array_elements_text(
            jsonb_path_query_array(discoveries_data, '$.discovery[*].discovery_id')
        ) as disc_id
        FROM rule_discoveries
        WHERE provider = 'oci' AND is_active = true AND customer_id IS NULL
    """)
    oci_ids = [r['disc_id'] for r in cur.fetchall() if r['disc_id']]

    cur.execute("""
        SELECT DISTINCT check_config->>'for_each' as fe
        FROM rule_checks
        WHERE provider = 'oci' AND check_type = 'default' AND is_active = true
          AND check_config->>'for_each' IS NOT NULL
    """)
    missing_fe = set()
    for r in cur.fetchall():
        fe = r['fe']
        if fe and fe not in oci_ids:
            missing_fe.add(fe)

    mapping = {}
    for fe in missing_fe:
        # Strip list_ prefix, look for matching OCI disc_id suffix
        normalized = fe.replace('list_', '').replace('get_', '')
        candidates = []
        for did in oci_ids:
            did_lower = did.lower()
            # Check if the operation part matches
            op_part = did.split('.')[-1] if '.' in did else did
            if normalized in op_part.lower() or op_part.lower() in fe.lower():
                candidates.append(did)
        if candidates:
            # Prefer list_ operations
            list_candidates = [c for c in candidates if 'list' in c.lower()]
            mapping[fe] = (list_candidates or candidates)[0]

    return mapping


def build_azure_mapping(conn):
    """Build Azure mapping for short 3-part names → rule_discoveries discovery_ids."""
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT service,
            jsonb_path_query_array(discoveries_data, '$.discovery[*].discovery_id') as disc_ids
        FROM rule_discoveries
        WHERE provider = 'azure' AND is_active = true AND customer_id IS NULL
    """)
    azure_by_service = collections.defaultdict(list)
    for r in cur.fetchall():
        for did in (r['disc_ids'] or []):
            if did:
                azure_by_service[r['service']].append(did)

    cur.execute("""
        SELECT DISTINCT check_config->>'for_each' as fe
        FROM rule_checks
        WHERE provider = 'azure' AND check_type = 'default' AND is_active = true
          AND check_config->>'for_each' IS NOT NULL
    """)
    all_fe = set(r['fe'] for r in cur.fetchall() if r['fe'])

    # Load existing disc_ids for quick lookup
    cur.execute("""
        SELECT DISTINCT unnest(
            ARRAY(
                SELECT jsonb_array_elements_text(
                    jsonb_path_query_array(discoveries_data, '$.discovery[*].discovery_id')
                ) FROM rule_discoveries
                WHERE provider = 'azure' AND is_active = true AND customer_id IS NULL
            )
        ) as disc_id
    """)

    all_azure_ids = set()
    for r in cur.fetchall():
        if r['disc_id']:
            all_azure_ids.add(r['disc_id'])

    mapping = {}
    for fe in all_fe:
        if fe in all_azure_ids:
            continue  # already found
        # Try to parse azure.{service}.{operation} format
        parts = fe.split('.')
        if len(parts) == 3:
            _, svc, op = parts
            candidates = azure_by_service.get(svc, [])
            # Find best match by operation
            op_candidates = [d for d in candidates if op in d]
            if op_candidates:
                mapping[fe] = op_candidates[0]
            elif candidates:
                mapping[fe] = candidates[0]  # fallback: first available for this service

    return mapping


def run(dry_run: bool, target_provider: str = None):
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    # Load all existing disc_ids for validation
    cur.execute("""
        SELECT provider,
            jsonb_path_query_array(discoveries_data, '$.discovery[*].discovery_id') as disc_ids
        FROM rule_discoveries
        WHERE is_active = true AND customer_id IS NULL
    """)
    existing_ids = collections.defaultdict(set)
    for r in cur.fetchall():
        for did in (r['disc_ids'] or []):
            if did:
                existing_ids[r['provider']].add(did)

    all_updates = {}  # {provider: {old_fe: new_fe}}

    # ── GCP ───────────────────────────────────────────────────────────────────
    if not target_provider or target_provider == 'gcp':
        gcp_updates = {}
        for old_fe, new_fe in GCP_MAPPING.items():
            if new_fe in existing_ids.get('gcp', set()):
                gcp_updates[old_fe] = new_fe
            else:
                print(f"  [GCP SKIP] {old_fe} → {new_fe} (target not in DB)")
        all_updates['gcp'] = gcp_updates

    # ── K8s ───────────────────────────────────────────────────────────────────
    if not target_provider or target_provider == 'k8s':
        k8s_updates = {}
        for old_fe, new_fe in K8S_MAPPING.items():
            if new_fe in existing_ids.get('k8s', set()):
                k8s_updates[old_fe] = new_fe
            else:
                print(f"  [K8S SKIP] {old_fe} → {new_fe} (target not in DB)")
        all_updates['k8s'] = k8s_updates

    # ── OCI ───────────────────────────────────────────────────────────────────
    if not target_provider or target_provider == 'oci':
        all_updates['oci'] = build_oci_mapping(conn)

    # ── Azure ──────────────────────────────────────────────────────────────────
    if not target_provider or target_provider == 'azure':
        all_updates['azure'] = build_azure_mapping(conn)

    # ── Apply updates ─────────────────────────────────────────────────────────
    total_updated = 0
    for provider, updates in all_updates.items():
        if not updates:
            continue
        print(f"\n── {provider.upper()} ({len(updates)} mappings) ──")
        for old_fe, new_fe in sorted(updates.items()):
            if dry_run:
                print(f"  [DRY] {old_fe}  →  {new_fe}")
            else:
                cur2 = conn.cursor()
                cur2.execute("""
                    UPDATE rule_checks
                    SET check_config = jsonb_set(check_config, '{for_each}', %s::jsonb)
                    WHERE provider = %s
                      AND check_type = 'default'
                      AND is_active = true
                      AND check_config->>'for_each' = %s
                """, (json.dumps(new_fe), provider, old_fe))
                n = cur2.rowcount
                cur2.close()
                if n > 0:
                    total_updated += n
                    print(f"  UPD  {old_fe}  →  {new_fe}  ({n} rules)")
                else:
                    print(f"  SKIP {old_fe} (no matching rows)")

        if not dry_run:
            conn.commit()

    # ── Summary ───────────────────────────────────────────────────────────────
    if not dry_run:
        # Re-check coverage
        cur.execute("""
            SELECT provider, COUNT(*) as total,
                   COUNT(CASE WHEN check_config->>'for_each' IS NOT NULL THEN 1 END) as with_fe
            FROM rule_checks WHERE check_type = 'default' AND is_active = true
            GROUP BY provider
        """)
        print("\n── POST-UPDATE COVERAGE ──")
        for r in cur.fetchall():
            print(f"  {r['provider']:12} {r['with_fe']}/{r['total']} have for_each")

    conn.close()
    print(f"\nTotal rules updated: {total_updated}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--provider", help="Only process this provider")
    args = parser.parse_args()
    run(args.dry_run, args.provider)
