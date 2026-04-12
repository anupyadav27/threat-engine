-- GCP audit_activity expansion rules

-- threat.gcp.audit.storage_list_buckets
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.gcp.audit.storage_list_buckets', 'storage', 'gcp', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "gcp_audit"}, {"op": "equals", "field": "service", "value": "storage.googleapis.com"}, {"op": "contains", "field": "operation", "value": "storage.buckets.list"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.gcp.audit.storage_list_buckets', 'storage', 'gcp', 'medium',
    $t$GCP Storage: Buckets Listed$t$, $t$GCS buckets were enumerated. Attackers list buckets to find misconfigured public or world-readable storage.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.gcp.audit.storage_set_iam
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.gcp.audit.storage_set_iam', 'storage', 'gcp', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "gcp_audit"}, {"op": "equals", "field": "service", "value": "storage.googleapis.com"}, {"op": "contains", "field": "operation", "value": "storage.buckets.setIamPolicy"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.gcp.audit.storage_set_iam', 'storage', 'gcp', 'medium',
    $t$GCP Storage: Bucket IAM Policy Set$t$, $t$A GCS bucket IAM policy was set. This controls who can read, write, or manage the bucket.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.gcp.audit.storage_object_get
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.gcp.audit.storage_object_get', 'storage', 'gcp', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "gcp_audit"}, {"op": "equals", "field": "service", "value": "storage.googleapis.com"}, {"op": "contains", "field": "operation", "value": "storage.objects.get"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.gcp.audit.storage_object_get', 'storage', 'gcp', 'medium',
    $t$GCP Storage: Object Retrieved from Bucket$t$, $t$An object was retrieved from a GCS bucket. Monitor for access to sensitive data stores.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.gcp.audit.sa_delete
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.gcp.audit.sa_delete', 'iam', 'gcp', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "gcp_audit"}, {"op": "equals", "field": "service", "value": "iam.googleapis.com"}, {"op": "contains", "field": "operation", "value": "DeleteServiceAccount"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.gcp.audit.sa_delete', 'iam', 'gcp', 'medium',
    $t$GCP IAM: Service Account Deleted$t$, $t$A GCP service account was deleted. This can break workloads or be used to remove audit trails for a compromised account.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.gcp.audit.sa_disable
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.gcp.audit.sa_disable', 'iam', 'gcp', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "gcp_audit"}, {"op": "equals", "field": "service", "value": "iam.googleapis.com"}, {"op": "contains", "field": "operation", "value": "DisableServiceAccount"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.gcp.audit.sa_disable', 'iam', 'gcp', 'medium',
    $t$GCP IAM: Service Account Disabled$t$, $t$A GCP service account was disabled. This may be used to disrupt workloads or cover tracks.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.gcp.audit.project_iam_binding_add
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.gcp.audit.project_iam_binding_add', 'iam', 'gcp', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "gcp_audit"}, {"op": "equals", "field": "service", "value": "cloudresourcemanager.googleapis.com"}, {"op": "contains", "field": "operation", "value": "SetIamPolicy"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.gcp.audit.project_iam_binding_add', 'iam', 'gcp', 'medium',
    $t$GCP Resource Manager: Project IAM Policy Updated$t$, $t$Project-level IAM policy was updated. Changes may grant new permissions to users, groups, or service accounts.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.gcp.audit.org_iam_policy
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.gcp.audit.org_iam_policy', 'iam', 'gcp', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "gcp_audit"}, {"op": "equals", "field": "service", "value": "cloudresourcemanager.googleapis.com"}, {"op": "contains", "field": "operation", "value": "organizations.setIamPolicy"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.gcp.audit.org_iam_policy', 'iam', 'gcp', 'medium',
    $t$GCP Resource Manager: Organization IAM Policy Updated$t$, $t$Organization-level IAM policy was modified. This affects all projects and folders in the organization.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.gcp.audit.compute_delete_instance
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.gcp.audit.compute_delete_instance', 'compute', 'gcp', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "gcp_audit"}, {"op": "equals", "field": "service", "value": "compute.googleapis.com"}, {"op": "contains", "field": "operation", "value": "compute.instances.delete"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.gcp.audit.compute_delete_instance', 'compute', 'gcp', 'medium',
    $t$GCP Compute: VM Instance Deleted$t$, $t$A GCP VM instance was deleted. This may be destructive data destruction or covering tracks by eliminating evidence.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.gcp.audit.compute_start_instance
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.gcp.audit.compute_start_instance', 'compute', 'gcp', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "gcp_audit"}, {"op": "equals", "field": "service", "value": "compute.googleapis.com"}, {"op": "contains", "field": "operation", "value": "compute.instances.start"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.gcp.audit.compute_start_instance', 'compute', 'gcp', 'medium',
    $t$GCP Compute: VM Instance Started$t$, $t$A stopped GCP VM was started. Dormant instances may be activated for persistence or lateral movement.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.gcp.audit.compute_network_create
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.gcp.audit.compute_network_create', 'compute', 'gcp', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "gcp_audit"}, {"op": "equals", "field": "service", "value": "compute.googleapis.com"}, {"op": "contains", "field": "operation", "value": "compute.networks.insert"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.gcp.audit.compute_network_create', 'compute', 'gcp', 'medium',
    $t$GCP Compute: New VPC Network Created$t$, $t$A new VPC network was created. Shadow networks can be used to exfiltrate traffic outside of monitored channels.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.gcp.audit.compute_route_insert
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.gcp.audit.compute_route_insert', 'compute', 'gcp', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "gcp_audit"}, {"op": "equals", "field": "service", "value": "compute.googleapis.com"}, {"op": "contains", "field": "operation", "value": "compute.routes.insert"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.gcp.audit.compute_route_insert', 'compute', 'gcp', 'medium',
    $t$GCP Compute: Custom Route Inserted$t$, $t$A new custom route was inserted into a VPC. Custom routes can redirect traffic to attacker-controlled endpoints.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.gcp.audit.run_service_deploy
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.gcp.audit.run_service_deploy', 'run', 'gcp', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "gcp_audit"}, {"op": "equals", "field": "service", "value": "run.googleapis.com"}, {"op": "contains", "field": "operation", "value": "google.cloud.run.v1.Services.CreateService"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.gcp.audit.run_service_deploy', 'run', 'gcp', 'medium',
    $t$GCP Cloud Run: Service Deployed$t$, $t$A new Cloud Run service was deployed. Monitor for unauthorized serverless workloads in your environment.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.gcp.audit.run_service_iam
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.gcp.audit.run_service_iam', 'run', 'gcp', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "gcp_audit"}, {"op": "equals", "field": "service", "value": "run.googleapis.com"}, {"op": "contains", "field": "operation", "value": "google.cloud.run.v1.Services.SetIamPolicy"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.gcp.audit.run_service_iam', 'run', 'gcp', 'medium',
    $t$GCP Cloud Run: Service IAM Policy Set (Possible Public Access)$t$, $t$Cloud Run service IAM policy was set. Setting allUsers/allAuthenticatedUsers makes the service publicly accessible.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.gcp.audit.functions_deploy
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.gcp.audit.functions_deploy', 'functions', 'gcp', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "gcp_audit"}, {"op": "equals", "field": "service", "value": "cloudfunctions.googleapis.com"}, {"op": "contains", "field": "operation", "value": "google.cloud.functions.v1.CloudFunctionsService.CreateFunction"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.gcp.audit.functions_deploy', 'functions', 'gcp', 'medium',
    $t$GCP Cloud Functions: Function Deployed$t$, $t$A Cloud Function was deployed. Unauthorized function deployments may provide persistent execution capability.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.gcp.audit.functions_iam
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.gcp.audit.functions_iam', 'functions', 'gcp', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "gcp_audit"}, {"op": "equals", "field": "service", "value": "cloudfunctions.googleapis.com"}, {"op": "contains", "field": "operation", "value": "google.cloud.functions.v1.CloudFunctionsService.SetIamPolicy"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.gcp.audit.functions_iam', 'functions', 'gcp', 'medium',
    $t$GCP Cloud Functions: Function IAM Policy Set$t$, $t$Cloud Function IAM policy was set. Public functions can be invoked by anyone on the internet.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.gcp.audit.bq_dataset_list
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.gcp.audit.bq_dataset_list', 'bigquery', 'gcp', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "gcp_audit"}, {"op": "equals", "field": "service", "value": "bigquery.googleapis.com"}, {"op": "contains", "field": "operation", "value": "datasetservice.list"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.gcp.audit.bq_dataset_list', 'bigquery', 'gcp', 'medium',
    $t$GCP BigQuery: Datasets Listed$t$, $t$BigQuery datasets were enumerated. Listing datasets reveals the data catalog and enables targeted exfiltration.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.gcp.audit.bq_dataset_iam
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.gcp.audit.bq_dataset_iam', 'bigquery', 'gcp', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "gcp_audit"}, {"op": "equals", "field": "service", "value": "bigquery.googleapis.com"}, {"op": "contains", "field": "operation", "value": "datasetservice.setIamPolicy"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.gcp.audit.bq_dataset_iam', 'bigquery', 'gcp', 'medium',
    $t$GCP BigQuery: Dataset IAM Policy Modified$t$, $t$BigQuery dataset access controls were modified. Changes may expose sensitive analytics data to unauthorized users.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.gcp.audit.bq_table_copy
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.gcp.audit.bq_table_copy', 'bigquery', 'gcp', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "gcp_audit"}, {"op": "equals", "field": "service", "value": "bigquery.googleapis.com"}, {"op": "contains", "field": "operation", "value": "jobservice.insert"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.gcp.audit.bq_table_copy', 'bigquery', 'gcp', 'medium',
    $t$GCP BigQuery: Job Inserted (Query/Copy/Export)$t$, $t$A BigQuery job was inserted. This covers queries, data copies, and exports that may involve sensitive data access.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.gcp.audit.dns_change_create
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.gcp.audit.dns_change_create', 'dns', 'gcp', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "gcp_audit"}, {"op": "equals", "field": "service", "value": "dns.googleapis.com"}, {"op": "contains", "field": "operation", "value": "dns.changes.create"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.gcp.audit.dns_change_create', 'dns', 'gcp', 'medium',
    $t$GCP DNS: DNS Record Change Created$t$, $t$A DNS record was changed. DNS modifications can be used for domain hijacking or redirecting traffic.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.gcp.audit.dns_zone_delete
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.gcp.audit.dns_zone_delete', 'dns', 'gcp', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "gcp_audit"}, {"op": "equals", "field": "service", "value": "dns.googleapis.com"}, {"op": "contains", "field": "operation", "value": "dns.managedZones.delete"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.gcp.audit.dns_zone_delete', 'dns', 'gcp', 'medium',
    $t$GCP DNS: Managed DNS Zone Deleted$t$, $t$A managed DNS zone was deleted. This removes all DNS records and can cause service outages.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.gcp.audit.appengine_deploy
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.gcp.audit.appengine_deploy', 'appengine', 'gcp', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "gcp_audit"}, {"op": "equals", "field": "service", "value": "appengine.googleapis.com"}, {"op": "contains", "field": "operation", "value": "google.appengine.v1.Versions.CreateVersion"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.gcp.audit.appengine_deploy', 'appengine', 'gcp', 'medium',
    $t$GCP App Engine: New Application Version Deployed$t$, $t$A new App Engine version was deployed. Unauthorized deployments may introduce malicious code to the application.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.gcp.audit.cloudbuild_trigger_create
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.gcp.audit.cloudbuild_trigger_create', 'cloudbuild', 'gcp', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "gcp_audit"}, {"op": "equals", "field": "service", "value": "cloudbuild.googleapis.com"}, {"op": "contains", "field": "operation", "value": "google.devtools.cloudbuild.v1.CloudBuild.CreateBuildTrigger"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.gcp.audit.cloudbuild_trigger_create', 'cloudbuild', 'gcp', 'medium',
    $t$GCP Cloud Build: Build Trigger Created$t$, $t$A Cloud Build trigger was created. Build triggers can execute arbitrary code when source code changes are pushed.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.gcp.audit.cloudbuild_run
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.gcp.audit.cloudbuild_run', 'cloudbuild', 'gcp', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "gcp_audit"}, {"op": "equals", "field": "service", "value": "cloudbuild.googleapis.com"}, {"op": "contains", "field": "operation", "value": "google.devtools.cloudbuild.v1.CloudBuild.CreateBuild"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.gcp.audit.cloudbuild_run', 'cloudbuild', 'gcp', 'medium',
    $t$GCP Cloud Build: Build Manually Triggered$t$, $t$A Cloud Build job was manually triggered. Monitor for unexpected builds that may execute malicious pipelines.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.gcp.audit.armor_policy_delete
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.gcp.audit.armor_policy_delete', 'compute', 'gcp', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "gcp_audit"}, {"op": "equals", "field": "service", "value": "compute.googleapis.com"}, {"op": "contains", "field": "operation", "value": "compute.securityPolicies.delete"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.gcp.audit.armor_policy_delete', 'compute', 'gcp', 'medium',
    $t$GCP Cloud Armor: Security Policy Deleted$t$, $t$A Cloud Armor security policy was deleted, removing DDoS and WAF protection from protected backends.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.gcp.audit.dataflow_job_create
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.gcp.audit.dataflow_job_create', 'dataflow', 'gcp', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "gcp_audit"}, {"op": "equals", "field": "service", "value": "dataflow.googleapis.com"}, {"op": "contains", "field": "operation", "value": "google.dataflow.v1beta3.Jobs.CreateJob"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.gcp.audit.dataflow_job_create', 'dataflow', 'gcp', 'medium',
    $t$GCP Dataflow: Job Created (Data Pipeline)$t$, $t$A Dataflow pipeline job was created. Monitor for unauthorized data movement pipelines targeting sensitive datasets.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.gcp.audit.project_create
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.gcp.audit.project_create', 'cloudresourcemanager', 'gcp', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "gcp_audit"}, {"op": "equals", "field": "service", "value": "cloudresourcemanager.googleapis.com"}, {"op": "contains", "field": "operation", "value": "google.cloud.resourcemanager.v3.Projects.CreateProject"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.gcp.audit.project_create', 'cloudresourcemanager', 'gcp', 'medium',
    $t$GCP Resource Manager: New Project Created$t$, $t$A new GCP project was created. Unauthorized projects can be used to host covert infrastructure outside normal oversight.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.gcp.audit.project_delete
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.gcp.audit.project_delete', 'cloudresourcemanager', 'gcp', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "gcp_audit"}, {"op": "equals", "field": "service", "value": "cloudresourcemanager.googleapis.com"}, {"op": "contains", "field": "operation", "value": "google.cloud.resourcemanager.v3.Projects.DeleteProject"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.gcp.audit.project_delete', 'cloudresourcemanager', 'gcp', 'medium',
    $t$GCP Resource Manager: Project Deleted$t$, $t$A GCP project was deleted. Project deletion destroys all resources and is irreversible after the recovery window.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.gcp.audit.org_policy_set
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.gcp.audit.org_policy_set', 'orgpolicy', 'gcp', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "gcp_audit"}, {"op": "equals", "field": "service", "value": "orgpolicy.googleapis.com"}, {"op": "contains", "field": "operation", "value": "google.cloud.orgpolicy.v2.OrgPolicy.UpdatePolicy"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.gcp.audit.org_policy_set', 'orgpolicy', 'gcp', 'medium',
    $t$GCP Org Policy: Organization Policy Updated$t$, $t$An organization policy constraint was updated. Relaxing org policies can enable prohibited actions across all projects.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.gcp.audit.pubsub_sub_iam
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.gcp.audit.pubsub_sub_iam', 'pubsub', 'gcp', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "gcp_audit"}, {"op": "equals", "field": "service", "value": "pubsub.googleapis.com"}, {"op": "contains", "field": "operation", "value": "google.pubsub.v1.Subscriber.SetIamPolicy"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.gcp.audit.pubsub_sub_iam', 'pubsub', 'gcp', 'medium',
    $t$GCP Pub/Sub: Subscription IAM Policy Modified$t$, $t$Pub/Sub subscription access controls were modified. Subscribers receive all messages on the topic.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.gcp.audit.kms_encrypt
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.gcp.audit.kms_encrypt', 'cloudkms', 'gcp', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "gcp_audit"}, {"op": "equals", "field": "service", "value": "cloudkms.googleapis.com"}, {"op": "contains", "field": "operation", "value": "Encrypt"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.gcp.audit.kms_encrypt', 'cloudkms', 'gcp', 'medium',
    $t$GCP KMS: Data Encrypted Using KMS Key$t$, $t$Data was encrypted using a KMS key. While normal, high-frequency encrypt/decrypt may indicate key abuse.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.gcp.audit.kms_import_job
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.gcp.audit.kms_import_job', 'cloudkms', 'gcp', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "gcp_audit"}, {"op": "equals", "field": "service", "value": "cloudkms.googleapis.com"}, {"op": "contains", "field": "operation", "value": "CreateImportJob"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.gcp.audit.kms_import_job', 'cloudkms', 'gcp', 'medium',
    $t$GCP KMS: Key Import Job Created$t$, $t$A KMS key import job was created. Importing external key material overrides Google-generated key entropy.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.gcp.audit.spanner_set_iam
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.gcp.audit.spanner_set_iam', 'spanner', 'gcp', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "gcp_audit"}, {"op": "equals", "field": "service", "value": "spanner.googleapis.com"}, {"op": "contains", "field": "operation", "value": "SetIamPolicy"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.gcp.audit.spanner_set_iam', 'spanner', 'gcp', 'medium',
    $t$GCP Spanner: Database IAM Policy Modified$t$, $t$Spanner database access controls were modified. Changes may expose production data to unauthorized principals.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;
