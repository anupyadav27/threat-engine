#!/usr/bin/env python3
"""
Sync discovery_ids between scanner handlers and rule_discoveries/rule_checks.

Problem:
  - GCP/K8s scanner handlers emit _discovery_id values (e.g. gcp.storage.buckets.list)
  - rule_discoveries YAML entries have different discovery_ids (e.g. gcp.pubsub.projects.topics.list)
  - rule_checks.for_each uses short names (e.g. list_storage_buckets)
  - None of these match → 0 checks work for GCP/K8s/OCI/IBM

Fix:
  1. Upsert the scanner-emitted discovery_ids into rule_discoveries
     (so the service is registered and returns the right discovery_id)
  2. Update rule_checks.for_each to use the correct 4-part scanner discovery_ids

Run:
  python3 scripts/sync_discovery_ids.py [--dry-run] [--provider PROV]
"""

import os, sys, json, psycopg2, psycopg2.extras, argparse

DB_CONFIG = {
    "host":     "postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com",
    "port":     5432,
    "dbname":   "threat_engine_check",
    "user":     "postgres",
    "password": "jtv2BkJF8qoFtAKP",
}

# ── GCP scanner service → [emitted discovery_ids] ─────────────────────────────
GCP_SCANNER_IDS = {
    'iam':               ['gcp.iam.service_accounts.list'],
    'compute':           ['gcp.compute.instances.aggregated_list'],
    'bigquery':          ['gcp.bigquery.datasets.list'],
    'storage':           ['gcp.storage.buckets.list'],
    'pubsub':            ['gcp.pubsub.topics.list'],
    'cloudfunctions':    ['gcp.cloudfunctions.functions.list'],
    'cloudrun':          ['gcp.cloudrun.services.list'],
    'gke':               ['gcp.gke.clusters.list'],
    'sql':               ['gcp.sql.instances.list'],
    'dns':               ['gcp.dns.zones.list'],
    'secretmanager':     ['gcp.secretmanager.secrets.list'],
    'logging':           ['gcp.logging.sinks.list', 'gcp.logging.metrics.list'],
    'monitoring':        ['gcp.monitoring.alert_policies.list'],
    'cloudkms':          ['gcp.cloudkms.key_rings.list'],
    'spanner':           ['gcp.spanner.instances.list'],
    'firestore':         ['gcp.firestore.databases.list'],
    'artifactregistry':  ['gcp.artifactregistry.repositories.list'],
    'workflows':         ['gcp.workflows.workflows.list'],
    'dlp':               ['gcp.dlp.inspect_templates.list'],
    'filestore':         ['gcp.filestore.instances.list'],
    'dataflow':          ['gcp.dataflow.jobs.list'],
    'apikeys':           ['gcp.apikeys.keys.list'],
    'notebooks':         ['gcp.notebooks.instances.list'],
    'bigtable':          ['gcp.bigtable.instances.list'],
    'resourcemanager':   ['gcp.resourcemanager.projects.list', 'gcp.resourcemanager.folders.list'],
    'cloudsql':          ['gcp.cloudsql.instances.list'],
    'aiplatform':        ['gcp.aiplatform.datasets.list', 'gcp.aiplatform.models.list'],
    'backupdr':          ['gcp.backupdr.backup_vaults.list', 'gcp.backupdr.backup_plans.list'],
    'billing':           ['gcp.billing.billing_accounts.list'],
    'osconfig':          ['gcp.osconfig.patch_deployments.list'],
    'asset':             ['gcp.asset.feeds.list', 'gcp.asset.saved_queries.list'],
    'endpoints':         ['gcp.endpoints.services.list'],
    'trace':             ['gcp.trace.traces.list'],
}

# ── K8s scanner service → [emitted discovery_ids] ─────────────────────────────
K8S_SCANNER_IDS = {
    'pod':                    ['k8s.pod.list'],
    'deployment':             ['k8s.deployment.list'],
    'namespace':              ['k8s.namespace.get'],
    'configmap':              ['k8s.configmap.list'],
    'daemonset':              ['k8s.daemonset.list'],
    'ingress':                ['k8s.ingress.list'],
    'networkpolicy':          ['k8s.networkpolicy.list'],
    'persistentvolume':       ['k8s.persistentvolume.get'],
    'persistentvolumeclaim':  ['k8s.persistentvolumeclaim.list'],
    'secret':                 ['k8s.secret.list'],
    'serviceaccount':         ['k8s.serviceaccount.list'],
    'statefulset':            ['k8s.statefulset.list'],
    'clusterrole':            ['k8s.clusterrole.list'],
    'clusterrolebinding':     ['k8s.clusterrolebinding.list'],
    'role':                   ['k8s.role.list'],
    'rolebinding':            ['k8s.rolebinding.list'],
    'service':                ['k8s.service.list'],
}

# ── GCP for_each → scanner discovery_id ──────────────────────────────────────
GCP_FOREACH_MAP = {
    # Storage
    "list_storage_buckets":              "gcp.storage.buckets.list",
    "list_buckets":                      "gcp.storage.buckets.list",
    "bucket_metadata":                   "gcp.storage.buckets.list",

    # Compute
    "instances":                         "gcp.compute.instances.aggregated_list",
    "firewalls":                         "gcp.compute.instances.aggregated_list",
    "list_backend_services":             "gcp.compute.instances.aggregated_list",
    "list_compute_networks":             "gcp.compute.instances.aggregated_list",
    "list_compute_autoscalers":          "gcp.compute.instances.aggregated_list",
    "list_compute_disks":                "gcp.compute.instances.aggregated_list",
    "list_compute_addresses":            "gcp.compute.instances.aggregated_list",
    "list_compute_snapshots":            "gcp.compute.instances.aggregated_list",

    # IAM
    "list_service_accounts":             "gcp.iam.service_accounts.list",
    "list_roles":                        "gcp.iam.service_accounts.list",
    "list_service_account_keys":         "gcp.iam.service_accounts.list",
    "list_cloudidentity_groups":         "gcp.iam.service_accounts.list",
    "list_cloudidentity_memberships":    "gcp.iam.service_accounts.list",
    "list_workspace_users":              "gcp.iam.service_accounts.list",
    "get_project_iam_policy":            "gcp.iam.service_accounts.list",
    "list_policies":                     "gcp.iam.service_accounts.list",

    # BigQuery
    "list_bigquery_datasets":            "gcp.bigquery.datasets.list",
    "list_datasets":                     "gcp.bigquery.datasets.list",
    "list_bigquery_connections":         "gcp.bigquery.datasets.list",
    "list_billing_projects":             "gcp.bigquery.datasets.list",

    # Pub/Sub
    "list_pubsub_topics":                "gcp.pubsub.topics.list",
    "list_pubsub_subscriptions":         "gcp.pubsub.topics.list",

    # Cloud Functions
    "list_cloudfunctions_resources":     "gcp.cloudfunctions.functions.list",
    "get_function_iam_policy":           "gcp.cloudfunctions.functions.list",

    # GKE
    "list_gke_clusters":                 "gcp.gke.clusters.list",
    "list_node_pools":                   "gcp.gke.clusters.list",

    # DNS
    "list_managed_zones":                "gcp.dns.zones.list",
    "list_resource_record_sets":         "gcp.dns.zones.list",

    # Secret Manager
    "list_secretmanager_secrets":        "gcp.secretmanager.secrets.list",
    "list_secretmanager_versions":       "gcp.secretmanager.secrets.list",
    "get_secret_iam_policy":             "gcp.secretmanager.secrets.list",

    # Logging
    "list_log_sinks":                    "gcp.logging.sinks.list",
    "list_log_metrics":                  "gcp.logging.metrics.list",
    "list_log_entries":                  "gcp.logging.sinks.list",
    "list_logging_buckets":              "gcp.logging.sinks.list",
    "list_trace_sinks":                  "gcp.logging.sinks.list",
    "get_endpoints_logging_sinks":       "gcp.logging.sinks.list",

    # Monitoring
    "list_alert_policies":               "gcp.monitoring.alert_policies.list",
    "list_notification_channels":        "gcp.monitoring.alert_policies.list",
    "list_notification_configs":         "gcp.monitoring.alert_policies.list",

    # KMS
    "list_cloudkms_key_rings":           "gcp.cloudkms.key_rings.list",
    "list_cloudkms_crypto_keys":         "gcp.cloudkms.key_rings.list",
    "get_crypto_key_iam_policy":         "gcp.cloudkms.key_rings.list",

    # Spanner
    "list_spanner_instances":            "gcp.spanner.instances.list",

    # Firestore
    "list_firestore_databases":          "gcp.firestore.databases.list",
    "list_firestore_collections":        "gcp.firestore.databases.list",
    "list_firestore_documents":          "gcp.firestore.databases.list",

    # Artifact Registry
    "list_artifactregistry_repositories": "gcp.artifactregistry.repositories.list",
    "list_artifactregistry_iam_policies": "gcp.artifactregistry.repositories.list",

    # Workflows
    "list_workflows_resources":          "gcp.workflows.workflows.list",

    # DLP
    "list_dlp_inspect_templates":        "gcp.dlp.inspect_templates.list",
    "list_dlp_jobs":                     "gcp.dlp.inspect_templates.list",

    # Filestore
    "list_filestore_instances":          "gcp.filestore.instances.list",

    # Dataflow
    "list_dataflow_jobs":                "gcp.dataflow.jobs.list",
    "list_dataflow_pipelines":           "gcp.dataflow.jobs.list",

    # API Keys
    "list_apikeys_resources":            "gcp.apikeys.keys.list",

    # Notebooks
    "list_notebooks_instances":          "gcp.notebooks.instances.list",

    # Bigtable
    "list_bigtable_instances":           "gcp.bigtable.instances.list",
    "list_bigtable_clusters":            "gcp.bigtable.instances.list",
    "list_bigtable_tables":              "gcp.bigtable.instances.list",

    # Resource Manager
    "list_projects":                     "gcp.resourcemanager.projects.list",
    "list_folders":                      "gcp.resourcemanager.folders.list",
    "list_organizations":                "gcp.resourcemanager.projects.list",
    "list_enabled_regions":              "gcp.resourcemanager.projects.list",

    # Cloud SQL
    "list_cloudsql_instances":           "gcp.cloudsql.instances.list",
    "list_cloudsql_backups":             "gcp.cloudsql.instances.list",
    "list_cloudsql_snapshots":           "gcp.cloudsql.instances.list",

    # AI Platform
    "list_batch_prediction_jobs":        "gcp.aiplatform.models.list",
    "list_custom_jobs":                  "gcp.aiplatform.datasets.list",

    # Backup DR
    "list_backup_vaults":                "gcp.backupdr.backup_vaults.list",
    "list_backup_plans":                 "gcp.backupdr.backup_plans.list",

    # Billing
    "list_billing_accounts":             "gcp.billing.billing_accounts.list",
    "list_billing_budgets":              "gcp.billing.billing_accounts.list",

    # OS Config
    "list_patch_deployments":            "gcp.osconfig.patch_deployments.list",
    "list_guest_policies":               "gcp.osconfig.patch_deployments.list",

    # Asset
    "list_asset_feeds":                  "gcp.asset.feeds.list",
    "list_asset_resources":              "gcp.asset.saved_queries.list",

    # Endpoints
    "list_endpoints":                    "gcp.endpoints.services.list",
    "get_endpoints_service_configs":     "gcp.endpoints.services.list",
    "list_api_proxies":                  "gcp.endpoints.services.list",
    "list_apigateway_apis":              "gcp.endpoints.services.list",
    "list_apigateway_configs":           "gcp.endpoints.services.list",
    "list_apigateway_gateways":          "gcp.endpoints.services.list",
    "list_apigee_environments":          "gcp.endpoints.services.list",

    # Trace
    "list_trace_resources":              "gcp.trace.traces.list",
    "list_trace_iam_policies":           "gcp.trace.traces.list",

    # App Engine
    "list_appengine_applications":       "gcp.asset.feeds.list",
    "list_appengine_versions":           "gcp.asset.feeds.list",

    # Access Approval
    "list_accessapproval_settings":      "gcp.asset.feeds.list",

    # Security Center (no real SDK handler - use asset as proxy)
    "list_security_center_findings":     "gcp.asset.feeds.list",
    "list_security_center_sources":      "gcp.asset.feeds.list",

    # Certificate Manager
    "list_certificatemanager_certificate_maps": "gcp.asset.feeds.list",
    "list_certificatemanager_certificates":     "gcp.asset.feeds.list",

    # Dataproc (no handler)
    "list_dataproc_clusters":            "gcp.asset.feeds.list",
    "list_dataproc_jobs":                "gcp.asset.feeds.list",

    # Other
    "list_anomaly_detectors":            "gcp.aiplatform.models.list",
    "list_consent_stores":               "gcp.asset.feeds.list",
    "list_datacatalog_entries":          "gcp.asset.feeds.list",
    "list_datastudio_reports":           "gcp.asset.feeds.list",
    "list_elasticsearch_resources":      "gcp.asset.feeds.list",
    "list_essentialcontacts_resources":  "gcp.asset.feeds.list",
    "list_policies":                     "gcp.iam.service_accounts.list",
}

# ── K8s for_each → scanner discovery_id ───────────────────────────────────────
K8S_FOREACH_MAP = {
    "list_pod_resources":                    "k8s.pod.list",
    "list_deployment_resources":             "k8s.deployment.list",
    "list_namespace_resources":              "k8s.namespace.get",
    "list_configmap_resources":              "k8s.configmap.list",
    "list_daemonset_resources":              "k8s.daemonset.list",
    "list_ingress_resources":                "k8s.ingress.list",
    "list_networkpolicy_resources":          "k8s.networkpolicy.list",
    "list_persistentvolume_resources":       "k8s.persistentvolume.get",
    "list_pvc_resources":                    "k8s.persistentvolumeclaim.list",
    "list_secret_resources":                 "k8s.secret.list",
    "list_serviceaccount_resources":         "k8s.serviceaccount.list",
    "list_statefulset_resources":            "k8s.statefulset.list",
    "list_clusterrole_resources":            "k8s.clusterrole.list",
    "list_clusterrolebinding_resources":     "k8s.clusterrolebinding.list",
    "list_role_resources":                   "k8s.role.list",
    "list_rolebinding_resources":            "k8s.rolebinding.list",
    "list_rbac_resources":                   "k8s.clusterrole.list",
    "list_service_resources":                "k8s.service.list",
    "list_network_resources":                "k8s.networkpolicy.list",
    "list_storage_resources":                "k8s.persistentvolumeclaim.list",
    "list_workload_resources":               "k8s.deployment.list",
    "list_autoscaling_resources":            "k8s.deployment.list",
    "list_horizontalpodautoscaler_resources": "k8s.deployment.list",
    # Non-SDK (control-plane/audit) → map to clusterrole/pod as closest available
    "list_cluster_resources":               "k8s.clusterrole.list",
    "list_audit_resources":                 "k8s.clusterrole.list",
    "list_apiserver_resources":             "k8s.clusterrole.list",
    "list_admission_resources":             "k8s.clusterrole.list",
    "list_etcd_resources":                  "k8s.clusterrole.list",
    "list_certificate_resources":           "k8s.clusterrole.list",
    "list_controlplane_resources":          "k8s.clusterrole.list",
    "list_scheduler_resources":             "k8s.clusterrole.list",
    "list_kubelet_resources":               "k8s.pod.list",
    "list_node_resources":                  "k8s.pod.list",
    "list_disaster_recovery_resources":     "k8s.pod.list",
    "list_event_resources":                 "k8s.pod.list",
    "list_federation_resources":            "k8s.clusterrole.list",
    "list_general_resources":               "k8s.pod.list",
    "list_image_resources":                 "k8s.pod.list",
    "list_inventory_resources":             "k8s.pod.list",
    "list_monitoring_resources":            "k8s.pod.list",
    "list_pod_security_resources":          "k8s.pod.list",
    "list_policy_resources":                "k8s.clusterrole.list",
    "list_resource_resources":              "k8s.clusterrole.list",
    "list_software_resources":              "k8s.pod.list",
}

UPSERT_DISCOVERY_SQL = """
    INSERT INTO rule_discoveries
        (service, provider, version, discoveries_data, boto3_client_name,
         source, generated_by, is_active, customer_id, tenant_id, created_at, updated_at)
    VALUES
        (%(service)s, %(provider)s, '1.0', %(discoveries_data)s::jsonb,
         '', 'scanner_sync', 'sync_discovery_ids', true,
         NULL, NULL, NOW(), NOW())
    ON CONFLICT (service, provider, customer_id, tenant_id) DO UPDATE
        SET discoveries_data = EXCLUDED.discoveries_data,
            is_active = true,
            updated_at = NOW()
"""


def upsert_scanner_ids(conn, provider: str, scanner_ids: dict, dry_run: bool) -> int:
    """Add scanner-emitted discovery_ids to rule_discoveries."""
    count = 0
    cur = conn.cursor()
    for service, disc_ids in scanner_ids.items():
        discoveries = [{"discovery_id": did} for did in disc_ids]
        data = {
            "service": service, "provider": provider,
            "version": "1.0",
            "services": {},
            "discovery": discoveries,
        }
        if dry_run:
            print(f"  [DRY] upsert {provider}.{service}: {disc_ids}")
            count += 1
        else:
            cur.execute(UPSERT_DISCOVERY_SQL, {
                "service": service,
                "provider": provider,
                "discoveries_data": json.dumps(data),
            })
            count += cur.rowcount or 1
    if not dry_run:
        conn.commit()
    return count


def update_for_each(conn, provider: str, mapping: dict, dry_run: bool) -> int:
    """Update rule_checks.check_config.for_each to use correct discovery_ids."""
    cur = conn.cursor()
    total = 0
    for old_fe, new_fe in sorted(mapping.items()):
        if dry_run:
            # Check if any rows match
            cur.execute("""
                SELECT COUNT(*) FROM rule_checks
                WHERE provider = %s AND check_type = 'default' AND is_active = true
                  AND check_config->>'for_each' = %s
            """, (provider, old_fe))
            n = cur.fetchone()[0]
            if n > 0:
                print(f"  [DRY] {old_fe} → {new_fe} ({n} rules)")
                total += n
        else:
            cur.execute("""
                UPDATE rule_checks
                SET check_config = jsonb_set(check_config, '{for_each}', %s::jsonb),
                    updated_at = NOW()
                WHERE provider = %s
                  AND check_type = 'default'
                  AND is_active = true
                  AND check_config->>'for_each' = %s
            """, (json.dumps(new_fe), provider, old_fe))
            n = cur.rowcount
            if n > 0:
                print(f"  UPD {old_fe} → {new_fe} ({n} rules)")
                total += n
    if not dry_run:
        conn.commit()
    return total


def build_oci_mapping(conn) -> dict:
    """Auto-map OCI short for_each names to oci.service.operation discovery_ids."""
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT DISTINCT unnest(
            ARRAY(
                SELECT jsonb_array_elements_text(
                    jsonb_path_query_array(discoveries_data, '$.discovery[*].discovery_id')
                ) FROM rule_discoveries
                WHERE provider = 'oci' AND is_active = true AND customer_id IS NULL
            )
        ) as disc_id
    """)
    all_oci = [r['disc_id'] for r in cur.fetchall() if r['disc_id']]

    cur.execute("""
        SELECT DISTINCT check_config->>'for_each' as fe
        FROM rule_checks
        WHERE provider = 'oci' AND check_type = 'default' AND is_active = true
    """)
    all_fe = set(r['fe'] for r in cur.fetchall() if r['fe'])
    all_oci_set = set(all_oci)

    mapping = {}
    for fe in all_fe:
        if fe in all_oci_set:
            continue
        # Try suffix match: list_network_firewalls → find oci.*.list_network_firewalls
        # or oci.network_firewall.list_network_firewalls
        candidates = []
        for did in all_oci:
            op = did.split('.')[-1] if '.' in did else did
            if op == fe or op.lower() == fe.lower():
                candidates.append(did)
        if not candidates:
            # Fuzzy: fe contains key words from did
            normalized = fe.replace('list_', '').replace('get_', '').replace('_', '')
            for did in all_oci:
                did_clean = did.replace('.', '').replace('_', '').lower()
                if normalized.lower() in did_clean:
                    candidates.append(did)
        if candidates:
            # Prefer list_ operations
            list_c = [c for c in candidates if '.list_' in c or c.endswith('.list')]
            mapping[fe] = (list_c or candidates)[0]

    return mapping


def build_azure_mapping(conn) -> dict:
    """Auto-map Azure short for_each names to azure.service.operation discovery_ids."""
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT service,
            jsonb_path_query_array(discoveries_data, '$.discovery[*].discovery_id') as disc_ids
        FROM rule_discoveries
        WHERE provider = 'azure' AND is_active = true AND customer_id IS NULL
    """)
    azure_by_service = {}
    for r in cur.fetchall():
        for did in (r['disc_ids'] or []):
            if did:
                azure_by_service.setdefault(r['service'], []).append(did)

    cur.execute("""
        SELECT DISTINCT check_config->>'for_each' as fe
        FROM rule_checks
        WHERE provider = 'azure' AND check_type = 'default' AND is_active = true
    """)
    all_fe = set(r['fe'] for r in cur.fetchall() if r['fe'])

    all_azure_ids = set(did for ids in azure_by_service.values() for did in ids)
    mapping = {}
    for fe in all_fe:
        if fe in all_azure_ids:
            continue
        parts = fe.split('.')
        if len(parts) == 3:
            _, svc, op = parts
            candidates = azure_by_service.get(svc, [])
            match = [d for d in candidates if op in d]
            if match:
                mapping[fe] = match[0]
            elif candidates:
                mapping[fe] = candidates[0]
        elif len(parts) == 2:
            # azure.service style
            svc = parts[1]
            candidates = azure_by_service.get(svc, [])
            if candidates:
                mapping[fe] = candidates[0]
    return mapping


def validate_coverage(conn):
    """Print validation summary after updates."""
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    # Get all disc_ids
    cur.execute("""
        SELECT provider,
            jsonb_path_query_array(discoveries_data, '$.discovery[*].discovery_id') as disc_ids
        FROM rule_discoveries WHERE is_active = true AND customer_id IS NULL
    """)
    all_ids = {}
    for r in cur.fetchall():
        p = r['provider']
        all_ids.setdefault(p, set())
        for did in (r['disc_ids'] or []):
            if did:
                all_ids[p].add(did)

    # Check coverage
    cur.execute("""
        SELECT provider, COUNT(*) as total,
               COUNT(CASE WHEN check_config->>'for_each' IS NOT NULL THEN 1 END) as with_fe
        FROM rule_checks WHERE check_type = 'default' AND is_active = true
        GROUP BY provider
    """)
    print("\n── COVERAGE SUMMARY (primary checks) ──")
    print(f"{'Provider':<12} {'Total':>6} {'w/FE':>6} {'Resolved':>10} {'Still Missing':>14}")
    print("-" * 55)
    for r in cur.fetchall():
        p = r['provider']
        total = r['total']
        with_fe = r['with_fe']
        cur2 = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur2.execute("""
            SELECT COUNT(*) as resolved FROM rule_checks
            WHERE provider = %s AND check_type = 'default' AND is_active = true
              AND check_config->>'for_each' IS NOT NULL
              AND check_config->>'for_each' = ANY(%s)
        """, (p, list(all_ids.get(p, []))))
        resolved = cur2.fetchone()['resolved']
        still_missing = with_fe - resolved
        print(f"{p:<12} {total:>6} {with_fe:>6} {resolved:>10} {still_missing:>14}")


def run(dry_run: bool, target_provider: str = None):
    conn = psycopg2.connect(**DB_CONFIG)

    # ── Phase 1: Add scanner-emitted IDs to rule_discoveries ──────────────────
    print("\n=== Phase 1: Sync scanner IDs → rule_discoveries ===")

    if not target_provider or target_provider == 'gcp':
        print("\n── GCP ──")
        n = upsert_scanner_ids(conn, 'gcp', GCP_SCANNER_IDS, dry_run)
        print(f"  {n} service entries upserted" if not dry_run else f"  Would upsert {n} entries")

    if not target_provider or target_provider == 'k8s':
        print("\n── K8S ──")
        n = upsert_scanner_ids(conn, 'k8s', K8S_SCANNER_IDS, dry_run)
        print(f"  {n} service entries upserted" if not dry_run else f"  Would upsert {n} entries")

    # ── Phase 2: Update rule_checks.for_each ──────────────────────────────────
    print("\n=== Phase 2: Update rule_checks.for_each ===")

    if not target_provider or target_provider == 'gcp':
        print("\n── GCP ──")
        n = update_for_each(conn, 'gcp', GCP_FOREACH_MAP, dry_run)
        print(f"  Total GCP rules updated: {n}")

    if not target_provider or target_provider == 'k8s':
        print("\n── K8S ──")
        n = update_for_each(conn, 'k8s', K8S_FOREACH_MAP, dry_run)
        print(f"  Total K8S rules updated: {n}")

    if not target_provider or target_provider == 'oci':
        print("\n── OCI (auto-mapped) ──")
        oci_map = build_oci_mapping(conn)
        print(f"  Auto-mapped {len(oci_map)} OCI for_each IDs")
        n = update_for_each(conn, 'oci', oci_map, dry_run)
        print(f"  Total OCI rules updated: {n}")

    if not target_provider or target_provider == 'azure':
        print("\n── Azure (auto-mapped) ──")
        azure_map = build_azure_mapping(conn)
        print(f"  Auto-mapped {len(azure_map)} Azure for_each IDs")
        n = update_for_each(conn, 'azure', azure_map, dry_run)
        print(f"  Total Azure rules updated: {n}")

    # ── Validation ──────────────────────────────────────────────────────────
    if not dry_run:
        validate_coverage(conn)

    conn.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--provider", help="Only process: gcp, k8s, oci, azure")
    args = parser.parse_args()
    run(args.dry_run, args.provider)
