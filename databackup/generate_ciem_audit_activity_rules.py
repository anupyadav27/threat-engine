#!/usr/bin/env python3
"""
Generate audit_activity rules for Azure, GCP, OCI, IBM to match AWS's 59 rules.

Current:  Azure=51, GCP=41, OCI=25, IBM=27
Target:   each ≥ 59
"""
import json
import os

OUT_DIR = os.path.dirname(os.path.abspath(__file__))

# ── helpers ──────────────────────────────────────────────────────────────────

SEV = ('medium', 50)
MITRE = '["TA0007","TA0009"]'
MITRE_TECHS = '["T1087","T1530","T1526","T1082"]'
DOMAIN = 'threat_detection'


def conds(cond_list):
    return json.dumps({"conditions": {"all": cond_list}})


def az_act_eq(arm_op):
    return conds([
        {"op": "equals", "field": "source_type", "value": "azure_activity"},
        {"op": "equals", "field": "operation",   "value": arm_op},
    ])


def az_act_contains(fragment):
    return conds([
        {"op": "equals",   "field": "source_type", "value": "azure_activity"},
        {"op": "contains", "field": "operation",   "value": fragment},
    ])


def gcp_audit(svc, op_contains):
    return conds([
        {"op": "equals",   "field": "source_type", "value": "gcp_audit"},
        {"op": "equals",   "field": "service",     "value": svc},
        {"op": "contains", "field": "operation",   "value": op_contains},
    ])


def oci_audit(cadf_domain, op_contains):
    return conds([
        {"op": "equals",   "field": "source_type", "value": "oci_audit"},
        {"op": "equals",   "field": "service",     "value": cadf_domain},
        {"op": "contains", "field": "operation",   "value": op_contains},
    ])


def ibm_act(svc, op_contains):
    return conds([
        {"op": "equals",   "field": "source_type", "value": "ibm_activity"},
        {"op": "equals",   "field": "service",     "value": svc},
        {"op": "contains", "field": "operation",   "value": op_contains},
    ])


def emit(f, rule_id, svc, provider, title, desc, check_config):
    sev, risk = SEV
    f.write(f"""
-- {rule_id}
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('{rule_id}', '{svc}', '{provider}', 'log', '{check_config}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('{rule_id}', '{svc}', '{provider}', '{sev}',
    $t${title}$t$, $t${desc}$t$,
    '{DOMAIN}', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '{MITRE_TECHS}'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;
""")


# ── Azure ─────────────────────────────────────────────────────────────────────

def generate_azure(out_dir):
    path = os.path.join(out_dir, "ciem_azure_audit_activity_rules.sql")
    n = 0
    with open(path, "w") as f:
        f.write("-- Azure audit_activity expansion rules\n")

        rules = [
            # rule_id, service, arm_op_or_fragment, is_contains, title, desc
            # Container Registry
            ("threat.azure.audit.acr_credentials_list",
             "containerregistry",
             "Microsoft.ContainerRegistry/registries/listCredentials/action", False,
             "Azure ACR: Registry Admin Credentials Listed",
             "Admin credentials for an Azure Container Registry were listed. These allow full push/pull access to all images."),
            ("threat.azure.audit.acr_token_list",
             "containerregistry",
             "Microsoft.ContainerRegistry/registries/tokens/listPasswords/action", False,
             "Azure ACR: Registry Token Passwords Listed",
             "Scoped access token passwords for an Azure Container Registry were listed."),

            # Conditional Access
            ("threat.azure.audit.ca_policy_create",
             "aad",
             "microsoft.directory/conditionalAccessPolicies/create", False,
             "Azure AD: Conditional Access Policy Created",
             "A new Azure AD Conditional Access policy was created. Changes may weaken authentication requirements."),
            ("threat.azure.audit.ca_policy_delete",
             "aad",
             "microsoft.directory/conditionalAccessPolicies/delete", False,
             "Azure AD: Conditional Access Policy Deleted",
             "An Azure AD Conditional Access policy was deleted, potentially removing MFA or location-based access controls."),
            ("threat.azure.audit.ca_named_location_create",
             "aad",
             "microsoft.directory/namedLocations/create", False,
             "Azure AD: Named Location (Trusted Network) Created",
             "A named location (trusted IP range) was added. Attackers may add their own IPs to bypass Conditional Access rules."),

            # NSG / Network monitoring
            ("threat.azure.audit.nsg_flow_log_disable",
             "network",
             "Microsoft.Network/networkWatchers/flowLogs/delete", False,
             "Azure Network Watcher: NSG Flow Log Deleted",
             "An NSG flow log resource was deleted, removing network traffic visibility for the associated NSG."),
            ("threat.azure.audit.public_ip_assign",
             "network",
             "Microsoft.Network/networkInterfaces/write", True,
             "Azure Network: NIC Configuration Updated (Possible Public IP Assignment)",
             "A network interface configuration was updated, which may include associating a new public IP address."),
            ("threat.azure.audit.vnet_dns_update",
             "network",
             "Microsoft.Network/virtualNetworks/write", True,
             "Azure VNet: Virtual Network Configuration Updated",
             "Virtual network configuration was updated, potentially changing DNS servers or address space."),

            # SQL
            ("threat.azure.audit.sql_server_firewall",
             "sql",
             "Microsoft.Sql/servers/firewallRules/write", False,
             "Azure SQL: Server Firewall Rule Modified",
             "A SQL Server firewall rule was created or updated. Overly broad rules may expose the database to the internet."),
            ("threat.azure.audit.sql_transparent_encryption",
             "sql",
             "Microsoft.Sql/servers/databases/transparentDataEncryption/write", False,
             "Azure SQL: Transparent Data Encryption Setting Changed",
             "TDE settings for an Azure SQL database were modified. Disabling TDE removes encryption at rest."),
            ("threat.azure.audit.sql_vulnerability_scan",
             "sql",
             "Microsoft.Sql/servers/vulnerabilityAssessments/write", False,
             "Azure SQL: Vulnerability Assessment Setting Modified",
             "SQL Server vulnerability assessment settings were changed. Disabling this removes periodic security scanning."),

            # Storage
            ("threat.azure.audit.storage_lifecycle_delete",
             "storage",
             "Microsoft.Storage/storageAccounts/managementPolicies/delete", False,
             "Azure Storage: Lifecycle Management Policy Deleted",
             "Storage account lifecycle policy was deleted, potentially preserving sensitive data beyond intended retention."),
            ("threat.azure.audit.storage_private_endpoint",
             "storage",
             "Microsoft.Storage/storageAccounts/privateEndpointConnections/write", True,
             "Azure Storage: Private Endpoint Connection Modified",
             "A private endpoint connection for a storage account was modified, potentially changing network access controls."),

            # Service Bus / Event Hub / Cache
            ("threat.azure.audit.event_hub_key_list",
             "eventhub",
             "Microsoft.EventHub/namespaces/authorizationRules/listkeys/action", False,
             "Azure Event Hub: Namespace Authorization Keys Listed",
             "Event Hub namespace SAS keys were listed. These keys grant send/listen access to the namespace."),
            ("threat.azure.audit.service_bus_key_list",
             "servicebus",
             "Microsoft.ServiceBus/namespaces/authorizationRules/listkeys/action", False,
             "Azure Service Bus: Namespace Authorization Keys Listed",
             "Service Bus namespace SAS keys were listed. These keys grant access to all queues and topics."),
            ("threat.azure.audit.redis_key_list",
             "cache",
             "Microsoft.Cache/redis/listKeys/action", False,
             "Azure Redis Cache: Access Keys Listed",
             "Redis Cache primary and secondary keys were listed. These provide full access to the cache instance."),

            # Backup
            ("threat.azure.audit.backup_vault_policy",
             "recoveryservices",
             "Microsoft.RecoveryServices/vaults/backupPolicies/delete", False,
             "Azure Backup: Backup Policy Deleted",
             "A Recovery Services vault backup policy was deleted. This may remove scheduled backups for protected resources."),
            ("threat.azure.audit.backup_protection_disable",
             "recoveryservices",
             "Microsoft.RecoveryServices/vaults/backupFabrics/protectionContainers/protectedItems/delete", True,
             "Azure Backup: Backup Protection Disabled for Item",
             "Backup protection was disabled for a resource, stopping future backups and exposing it to unrecoverable deletion."),

            # AKS additional
            ("threat.azure.audit.aks_stop",
             "containerservice",
             "Microsoft.ContainerService/managedClusters/stop/action", False,
             "Azure AKS: Cluster Stopped",
             "An AKS cluster was stopped. This terminates all running workloads on the cluster."),
            ("threat.azure.audit.aks_rbac_binding",
             "containerservice",
             "Microsoft.ContainerService/managedClusters/accessProfiles/listCredential/action", False,
             "Azure AKS: Cluster Access Profile Credentials Listed",
             "AKS cluster access profile credentials were retrieved, providing kubectl access to the cluster."),

            # Functions
            ("threat.azure.audit.function_key_list",
             "web",
             "Microsoft.Web/sites/host/listkeys/action", False,
             "Azure Functions: Function App Host Keys Listed",
             "Function App host (master + function) keys were listed. These keys allow invoking any function in the app."),

            # Management Groups / Policy
            ("threat.azure.audit.management_group_move",
             "managementgroups",
             "Microsoft.Management/managementGroups/subscriptions/write", True,
             "Azure: Subscription Moved to Different Management Group",
             "A subscription was moved to a different management group, potentially changing policy inheritance and access controls."),
            ("threat.azure.audit.policy_exemption_create",
             "resources",
             "Microsoft.Authorization/policyExemptions/write", False,
             "Azure Policy: Policy Exemption Created",
             "A policy exemption was created. This waives a policy requirement for a scope, reducing compliance coverage."),

            # App Service / Deployment
            ("threat.azure.audit.app_publishing_credentials",
             "web",
             "Microsoft.Web/sites/publishxml/action", False,
             "Azure App Service: Publishing Credentials Retrieved",
             "App Service publishing credentials (FTP/WebDeploy) were retrieved, enabling code deployment to the web app."),
            ("threat.azure.audit.app_config_list",
             "web",
             "Microsoft.Web/sites/config/list/action", False,
             "Azure App Service: App Configuration and Secrets Listed",
             "App Service configuration (including connection strings and app settings with secrets) was listed."),

            # Managed Identity
            ("threat.azure.audit.user_assigned_mi_credentials",
             "managedidentity",
             "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write", True,
             "Azure Managed Identity: Federated Identity Credential Created",
             "A federated identity credential was added to a user-assigned managed identity, allowing external workloads to impersonate it."),
        ]

        for entry in rules:
            rid, svc, op_val, is_contains, title, desc = entry
            cfg = az_act_contains(op_val) if is_contains else az_act_eq(op_val)
            emit(f, rid, svc, "azure", title, desc, cfg)
            n += 1

    print(f"Azure audit_activity: {n} → {path}")
    return n


# ── GCP ───────────────────────────────────────────────────────────────────────

def generate_gcp(out_dir):
    path = os.path.join(out_dir, "ciem_gcp_audit_activity_rules.sql")
    n = 0
    with open(path, "w") as f:
        f.write("-- GCP audit_activity expansion rules\n")

        rules = [
            # rule_id, service, gcp_svc_uri, op_contains, title, desc
            # Storage
            ("threat.gcp.audit.storage_list_buckets",
             "storage",
             "storage.googleapis.com", "storage.buckets.list",
             "GCP Storage: Buckets Listed",
             "GCS buckets were enumerated. Attackers list buckets to find misconfigured public or world-readable storage."),
            ("threat.gcp.audit.storage_set_iam",
             "storage",
             "storage.googleapis.com", "storage.buckets.setIamPolicy",
             "GCP Storage: Bucket IAM Policy Set",
             "A GCS bucket IAM policy was set. This controls who can read, write, or manage the bucket."),
            ("threat.gcp.audit.storage_object_get",
             "storage",
             "storage.googleapis.com", "storage.objects.get",
             "GCP Storage: Object Retrieved from Bucket",
             "An object was retrieved from a GCS bucket. Monitor for access to sensitive data stores."),

            # IAM / Service Accounts
            ("threat.gcp.audit.sa_delete",
             "iam",
             "iam.googleapis.com", "DeleteServiceAccount",
             "GCP IAM: Service Account Deleted",
             "A GCP service account was deleted. This can break workloads or be used to remove audit trails for a compromised account."),
            ("threat.gcp.audit.sa_disable",
             "iam",
             "iam.googleapis.com", "DisableServiceAccount",
             "GCP IAM: Service Account Disabled",
             "A GCP service account was disabled. This may be used to disrupt workloads or cover tracks."),
            ("threat.gcp.audit.project_iam_binding_add",
             "iam",
             "cloudresourcemanager.googleapis.com", "SetIamPolicy",
             "GCP Resource Manager: Project IAM Policy Updated",
             "Project-level IAM policy was updated. Changes may grant new permissions to users, groups, or service accounts."),
            ("threat.gcp.audit.org_iam_policy",
             "iam",
             "cloudresourcemanager.googleapis.com", "organizations.setIamPolicy",
             "GCP Resource Manager: Organization IAM Policy Updated",
             "Organization-level IAM policy was modified. This affects all projects and folders in the organization."),

            # Compute
            ("threat.gcp.audit.compute_delete_instance",
             "compute",
             "compute.googleapis.com", "compute.instances.delete",
             "GCP Compute: VM Instance Deleted",
             "A GCP VM instance was deleted. This may be destructive data destruction or covering tracks by eliminating evidence."),
            ("threat.gcp.audit.compute_start_instance",
             "compute",
             "compute.googleapis.com", "compute.instances.start",
             "GCP Compute: VM Instance Started",
             "A stopped GCP VM was started. Dormant instances may be activated for persistence or lateral movement."),
            ("threat.gcp.audit.compute_network_create",
             "compute",
             "compute.googleapis.com", "compute.networks.insert",
             "GCP Compute: New VPC Network Created",
             "A new VPC network was created. Shadow networks can be used to exfiltrate traffic outside of monitored channels."),
            ("threat.gcp.audit.compute_route_insert",
             "compute",
             "compute.googleapis.com", "compute.routes.insert",
             "GCP Compute: Custom Route Inserted",
             "A new custom route was inserted into a VPC. Custom routes can redirect traffic to attacker-controlled endpoints."),

            # Cloud Run / Functions
            ("threat.gcp.audit.run_service_deploy",
             "run",
             "run.googleapis.com", "google.cloud.run.v1.Services.CreateService",
             "GCP Cloud Run: Service Deployed",
             "A new Cloud Run service was deployed. Monitor for unauthorized serverless workloads in your environment."),
            ("threat.gcp.audit.run_service_iam",
             "run",
             "run.googleapis.com", "google.cloud.run.v1.Services.SetIamPolicy",
             "GCP Cloud Run: Service IAM Policy Set (Possible Public Access)",
             "Cloud Run service IAM policy was set. Setting allUsers/allAuthenticatedUsers makes the service publicly accessible."),
            ("threat.gcp.audit.functions_deploy",
             "functions",
             "cloudfunctions.googleapis.com", "google.cloud.functions.v1.CloudFunctionsService.CreateFunction",
             "GCP Cloud Functions: Function Deployed",
             "A Cloud Function was deployed. Unauthorized function deployments may provide persistent execution capability."),
            ("threat.gcp.audit.functions_iam",
             "functions",
             "cloudfunctions.googleapis.com", "google.cloud.functions.v1.CloudFunctionsService.SetIamPolicy",
             "GCP Cloud Functions: Function IAM Policy Set",
             "Cloud Function IAM policy was set. Public functions can be invoked by anyone on the internet."),

            # BigQuery
            ("threat.gcp.audit.bq_dataset_list",
             "bigquery",
             "bigquery.googleapis.com", "datasetservice.list",
             "GCP BigQuery: Datasets Listed",
             "BigQuery datasets were enumerated. Listing datasets reveals the data catalog and enables targeted exfiltration."),
            ("threat.gcp.audit.bq_dataset_iam",
             "bigquery",
             "bigquery.googleapis.com", "datasetservice.setIamPolicy",
             "GCP BigQuery: Dataset IAM Policy Modified",
             "BigQuery dataset access controls were modified. Changes may expose sensitive analytics data to unauthorized users."),
            ("threat.gcp.audit.bq_table_copy",
             "bigquery",
             "bigquery.googleapis.com", "jobservice.insert",
             "GCP BigQuery: Job Inserted (Query/Copy/Export)",
             "A BigQuery job was inserted. This covers queries, data copies, and exports that may involve sensitive data access."),

            # DNS
            ("threat.gcp.audit.dns_change_create",
             "dns",
             "dns.googleapis.com", "dns.changes.create",
             "GCP DNS: DNS Record Change Created",
             "A DNS record was changed. DNS modifications can be used for domain hijacking or redirecting traffic."),
            ("threat.gcp.audit.dns_zone_delete",
             "dns",
             "dns.googleapis.com", "dns.managedZones.delete",
             "GCP DNS: Managed DNS Zone Deleted",
             "A managed DNS zone was deleted. This removes all DNS records and can cause service outages."),

            # App Engine
            ("threat.gcp.audit.appengine_deploy",
             "appengine",
             "appengine.googleapis.com", "google.appengine.v1.Versions.CreateVersion",
             "GCP App Engine: New Application Version Deployed",
             "A new App Engine version was deployed. Unauthorized deployments may introduce malicious code to the application."),

            # Cloud Build
            ("threat.gcp.audit.cloudbuild_trigger_create",
             "cloudbuild",
             "cloudbuild.googleapis.com", "google.devtools.cloudbuild.v1.CloudBuild.CreateBuildTrigger",
             "GCP Cloud Build: Build Trigger Created",
             "A Cloud Build trigger was created. Build triggers can execute arbitrary code when source code changes are pushed."),
            ("threat.gcp.audit.cloudbuild_run",
             "cloudbuild",
             "cloudbuild.googleapis.com", "google.devtools.cloudbuild.v1.CloudBuild.CreateBuild",
             "GCP Cloud Build: Build Manually Triggered",
             "A Cloud Build job was manually triggered. Monitor for unexpected builds that may execute malicious pipelines."),

            # Cloud Armor
            ("threat.gcp.audit.armor_policy_delete",
             "compute",
             "compute.googleapis.com", "compute.securityPolicies.delete",
             "GCP Cloud Armor: Security Policy Deleted",
             "A Cloud Armor security policy was deleted, removing DDoS and WAF protection from protected backends."),

            # Dataflow
            ("threat.gcp.audit.dataflow_job_create",
             "dataflow",
             "dataflow.googleapis.com", "google.dataflow.v1beta3.Jobs.CreateJob",
             "GCP Dataflow: Job Created (Data Pipeline)",
             "A Dataflow pipeline job was created. Monitor for unauthorized data movement pipelines targeting sensitive datasets."),

            # Project lifecycle
            ("threat.gcp.audit.project_create",
             "cloudresourcemanager",
             "cloudresourcemanager.googleapis.com", "google.cloud.resourcemanager.v3.Projects.CreateProject",
             "GCP Resource Manager: New Project Created",
             "A new GCP project was created. Unauthorized projects can be used to host covert infrastructure outside normal oversight."),
            ("threat.gcp.audit.project_delete",
             "cloudresourcemanager",
             "cloudresourcemanager.googleapis.com", "google.cloud.resourcemanager.v3.Projects.DeleteProject",
             "GCP Resource Manager: Project Deleted",
             "A GCP project was deleted. Project deletion destroys all resources and is irreversible after the recovery window."),

            # Org Policy
            ("threat.gcp.audit.org_policy_set",
             "orgpolicy",
             "orgpolicy.googleapis.com", "google.cloud.orgpolicy.v2.OrgPolicy.UpdatePolicy",
             "GCP Org Policy: Organization Policy Updated",
             "An organization policy constraint was updated. Relaxing org policies can enable prohibited actions across all projects."),

            # Pub/Sub
            ("threat.gcp.audit.pubsub_sub_iam",
             "pubsub",
             "pubsub.googleapis.com", "google.pubsub.v1.Subscriber.SetIamPolicy",
             "GCP Pub/Sub: Subscription IAM Policy Modified",
             "Pub/Sub subscription access controls were modified. Subscribers receive all messages on the topic."),

            # KMS
            ("threat.gcp.audit.kms_encrypt",
             "cloudkms",
             "cloudkms.googleapis.com", "Encrypt",
             "GCP KMS: Data Encrypted Using KMS Key",
             "Data was encrypted using a KMS key. While normal, high-frequency encrypt/decrypt may indicate key abuse."),
            ("threat.gcp.audit.kms_import_job",
             "cloudkms",
             "cloudkms.googleapis.com", "CreateImportJob",
             "GCP KMS: Key Import Job Created",
             "A KMS key import job was created. Importing external key material overrides Google-generated key entropy."),

            # Spanner
            ("threat.gcp.audit.spanner_set_iam",
             "spanner",
             "spanner.googleapis.com", "SetIamPolicy",
             "GCP Spanner: Database IAM Policy Modified",
             "Spanner database access controls were modified. Changes may expose production data to unauthorized principals."),
        ]

        for entry in rules:
            rid, svc, gcp_svc, op_c, title, desc = entry
            cfg = gcp_audit(gcp_svc, op_c)
            emit(f, rid, svc, "gcp", title, desc, cfg)
            n += 1

    print(f"GCP audit_activity: {n} → {path}")
    return n


# ── OCI ───────────────────────────────────────────────────────────────────────

def generate_oci(out_dir):
    path = os.path.join(out_dir, "ciem_oci_audit_activity_rules.sql")
    n = 0
    with open(path, "w") as f:
        f.write("-- OCI audit_activity expansion rules\n")

        rules = [
            # rule_id, service, cadf_domain, op_contains, title, desc
            # IAM
            ("threat.oci.audit.dynamic_group_create",
             "identity",
             "com.oraclecloud.identity", "CreateDynamicGroup",
             "OCI IAM: Dynamic Group Created",
             "An OCI dynamic group was created. Dynamic groups grant instance principals access to OCI resources."),
            ("threat.oci.audit.dynamic_group_update",
             "identity",
             "com.oraclecloud.identity", "UpdateDynamicGroup",
             "OCI IAM: Dynamic Group Updated",
             "An OCI dynamic group was updated. Changes to matching rules may extend resource access to unintended instances."),
            ("threat.oci.audit.compartment_create",
             "identity",
             "com.oraclecloud.identity", "CreateCompartment",
             "OCI IAM: Compartment Created",
             "A new OCI compartment was created. Compartments isolate resources and their policies."),
            ("threat.oci.audit.compartment_delete",
             "identity",
             "com.oraclecloud.identity", "DeleteCompartment",
             "OCI IAM: Compartment Deleted",
             "An OCI compartment was deleted. Deleting a compartment removes all resources within it."),
            ("threat.oci.audit.federation_create",
             "identity",
             "com.oraclecloud.identity", "CreateIdentityProvider",
             "OCI IAM: Identity Federation Provider Created",
             "An identity federation provider (SAML/OIDC) was created, enabling external users to authenticate to OCI."),
            ("threat.oci.audit.saml_assertion_map",
             "identity",
             "com.oraclecloud.identity", "CreateIdpGroupMapping",
             "OCI IAM: IdP Group Mapping Created",
             "An IdP group was mapped to an OCI group, granting external identity users access to OCI resources."),
            ("threat.oci.audit.auth_token_list",
             "identity",
             "com.oraclecloud.identity", "ListAuthTokens",
             "OCI IAM: Auth Tokens Listed",
             "Auth tokens (used for third-party API access) were listed. These tokens provide programmatic access."),
            ("threat.oci.audit.smtp_credentials_list",
             "identity",
             "com.oraclecloud.identity", "ListSmtpCredentials",
             "OCI IAM: SMTP Credentials Listed",
             "SMTP credentials were listed. These allow sending email via OCI Email Delivery service."),
            ("threat.oci.audit.user_group_list",
             "identity",
             "com.oraclecloud.identity", "ListUserGroupMemberships",
             "OCI IAM: User Group Memberships Listed",
             "User group memberships were enumerated. This reveals privilege mapping across OCI groups."),
            ("threat.oci.audit.mfa_device_delete",
             "identity",
             "com.oraclecloud.identity", "DeleteMfaTotpDevice",
             "OCI IAM: MFA Device Deleted from User",
             "An MFA TOTP device was deleted from an OCI user account, weakening authentication."),
            ("threat.oci.audit.iam_user_create",
             "identity",
             "com.oraclecloud.identity", "CreateUser",
             "OCI IAM: User Account Created",
             "A new OCI IAM user was created. Monitor for unauthorized user creation that may establish persistence."),
            ("threat.oci.audit.policy_get",
             "identity",
             "com.oraclecloud.identity", "GetPolicy",
             "OCI IAM: Policy Retrieved",
             "An OCI IAM policy was retrieved. Attackers enumerate policies to understand granted permissions."),

            # Vault / KMS
            ("threat.oci.audit.kms_key_create",
             "kms",
             "com.oraclecloud.keymanagement", "CreateKey",
             "OCI KMS: Encryption Key Created",
             "A new OCI KMS encryption key was created. Monitor for unexpected key creation that may be used to encrypt exfiltrated data."),
            ("threat.oci.audit.kms_key_import",
             "kms",
             "com.oraclecloud.keymanagement", "ImportKeyVersion",
             "OCI KMS: Key Material Imported",
             "External key material was imported into OCI KMS, replacing Oracle-managed entropy with a user-controlled key."),
            ("threat.oci.audit.vault_secret_version",
             "vault",
             "com.oraclecloud.vault", "CreateSecretVersion",
             "OCI Vault: New Secret Version Created",
             "A new version was added to an OCI Vault secret. This may rotate credentials or inject malicious values."),
            ("threat.oci.audit.vault_delete",
             "vault",
             "com.oraclecloud.vault", "ScheduleVaultDeletion",
             "OCI Vault: Vault Scheduled for Deletion",
             "An OCI Vault was scheduled for deletion. This will destroy all keys and secrets after the waiting period."),

            # Object Storage
            ("threat.oci.audit.object_storage_policy",
             "objectstorage",
             "com.oraclecloud.objectstorage", "UpdateBucket",
             "OCI Object Storage: Bucket Configuration Updated",
             "OCI Object Storage bucket configuration was updated, potentially changing access policies or versioning settings."),
            ("threat.oci.audit.object_storage_list",
             "objectstorage",
             "com.oraclecloud.objectstorage", "ListBuckets",
             "OCI Object Storage: Buckets Listed",
             "OCI Object Storage buckets were enumerated. Listing buckets reveals available data stores for targeted exfiltration."),
            ("threat.oci.audit.object_get",
             "objectstorage",
             "com.oraclecloud.objectstorage", "GetObject",
             "OCI Object Storage: Object Retrieved",
             "An object was retrieved from OCI Object Storage. Monitor for access to sensitive configuration or data files."),

            # Streaming (Kafka)
            ("threat.oci.audit.streaming_creds_list",
             "streaming",
             "com.oraclecloud.streaming", "ListStreams",
             "OCI Streaming: Streams Listed",
             "OCI Streaming (managed Kafka) streams were listed. Streams can carry sensitive event data."),
            ("threat.oci.audit.streaming_message_get",
             "streaming",
             "com.oraclecloud.streaming", "GetMessages",
             "OCI Streaming: Messages Retrieved from Stream",
             "Messages were read from an OCI streaming topic. Sensitive operational data may be exposed."),

            # Functions
            ("threat.oci.audit.functions_invoke_audit",
             "functions",
             "com.oraclecloud.functions", "InvokeFunction",
             "OCI Functions: Function Invoked",
             "An OCI function was invoked. Unauthorized function invocations may execute malicious code or access sensitive resources."),

            # Resource Manager
            ("threat.oci.audit.resource_manager_job",
             "resourcemanager",
             "com.oraclecloud.resourcemanager", "CreateJob",
             "OCI Resource Manager: Terraform Job Created",
             "An OCI Resource Manager (Terraform) job was created. Infrastructure-as-code jobs can create, modify, or destroy resources."),

            # Database
            ("threat.oci.audit.adb_rotate_wallet",
             "database",
             "com.oraclecloud.database", "RotateAutonomousDatabaseEncryptionKey",
             "OCI Autonomous DB: Encryption Key Rotated",
             "The encryption key for an Autonomous Database was rotated. Unexpected key rotation may indicate compromise."),
            ("threat.oci.audit.db_home_delete",
             "database",
             "com.oraclecloud.database", "DeleteDbHome",
             "OCI Database: DB Home Deleted",
             "An OCI Database Home was deleted, removing all databases within it. This is a destructive operation."),
            ("threat.oci.audit.db_system_stop",
             "database",
             "com.oraclecloud.database", "DbNodeAction",
             "OCI Database: DB Node Action Triggered",
             "An action (stop/start/reset) was triggered on an OCI DB node. Stopping nodes causes database downtime."),

            # Certificates
            ("threat.oci.audit.certificate_issued",
             "certificates",
             "com.oraclecloud.certificatesmanagement", "CreateCertificate",
             "OCI Certificates: Certificate Created",
             "A TLS certificate was created via OCI Certificates service. Monitor for unauthorized certificate issuance."),

            # Service Connector (Log Routing)
            ("threat.oci.audit.service_connector_create",
             "sch",
             "com.oraclecloud.sch", "CreateServiceConnector",
             "OCI Service Connector Hub: Connector Created (Log Routing)",
             "A Service Connector hub was created to route data between OCI services. May be used to exfiltrate logs or stream data."),

            # Logging
            ("threat.oci.audit.log_unified_search",
             "loggingsearch",
             "com.oraclecloud.loggingsearch", "SearchLogs",
             "OCI Logging: Log Search Executed",
             "OCI unified logging was searched. Attackers may query logs to understand what monitoring is in place."),

            # Events
            ("threat.oci.audit.event_rule_create",
             "events",
             "com.oraclecloud.events", "CreateRule",
             "OCI Events: Event Rule Created",
             "An OCI Events service rule was created. Event rules trigger actions (notifications, functions) on resource changes."),

            # Identity Domain
            ("threat.oci.audit.identity_domain_deactivate",
             "identitydomain",
             "com.oraclecloud.identitydomains", "deactivate",
             "OCI Identity Domain: Domain Deactivated",
             "An OCI Identity Domain was deactivated, preventing all users in the domain from authenticating."),

            # Network
            ("threat.oci.audit.drg_route_create",
             "network",
             "com.oraclecloud.virtualnetwork", "CreateDrgRouteTable",
             "OCI DRG: Dynamic Routing Gateway Route Table Created",
             "A DRG route table was created, potentially redirecting inter-VCN traffic through an attacker-controlled path."),
        ]

        for entry in rules:
            rid, svc, cadf_dom, op_c, title, desc = entry
            cfg = oci_audit(cadf_dom, op_c)
            emit(f, rid, svc, "oci", title, desc, cfg)
            n += 1

    print(f"OCI audit_activity: {n} → {path}")
    return n


# ── IBM ───────────────────────────────────────────────────────────────────────

def generate_ibm(out_dir):
    path = os.path.join(out_dir, "ciem_ibm_audit_activity_rules.sql")
    n = 0
    with open(path, "w") as f:
        f.write("-- IBM audit_activity expansion rules\n")

        rules = [
            # rule_id, service, ibm_svc (underscore), op_contains, title, desc
            # IAM
            ("threat.ibm.audit.account_settings_get",
             "iam_identity",
             "iam_identity", "iam-identity.account.get",
             "IBM IAM: Account Settings Retrieved",
             "IBM Cloud account identity settings (MFA config, session limits) were retrieved. Used for reconnaissance of auth controls."),
            ("threat.ibm.audit.iam_account_settings_update",
             "iam_identity",
             "iam_identity", "iam-identity.account.update",
             "IBM IAM: Account Identity Settings Updated",
             "IBM Cloud account identity settings (MFA, session length, IP restrictions) were updated, potentially weakening auth controls."),
            ("threat.ibm.audit.user_invite",
             "user_management",
             "user_management", "user-management.user.invite",
             "IBM Cloud: User Invited to Account",
             "A user was invited to the IBM Cloud account. Unexpected invitations may establish unauthorized access."),
            ("threat.ibm.audit.user_remove",
             "user_management",
             "user_management", "user-management.user.remove",
             "IBM Cloud: User Removed from Account",
             "A user was removed from the IBM Cloud account. This may be used to eliminate audit trails or lock out administrators."),
            ("threat.ibm.audit.iam_service_policy_delete",
             "iam",
             "iam", "iam.policy.delete",
             "IBM IAM: Service Access Policy Deleted",
             "An IAM service access policy was deleted, potentially removing restrictions on service-to-service calls."),
            ("threat.ibm.audit.iam_trusted_profile_update",
             "iam_identity",
             "iam_identity", "iam-identity.profile.update",
             "IBM IAM: Trusted Profile Updated",
             "An IAM trusted profile (compute resource identity) was updated. Changes may expand what resources can assume the profile."),
            ("threat.ibm.audit.cbr_delete",
             "context_based_restrictions",
             "context_based_restrictions", "context-based-restrictions.rule.delete",
             "IBM CBR: Context-Based Restriction Rule Deleted",
             "A context-based restriction rule was deleted, removing network or resource-based access controls."),
            ("threat.ibm.audit.cbr_zone_delete",
             "context_based_restrictions",
             "context_based_restrictions", "context-based-restrictions.zone.delete",
             "IBM CBR: Context-Based Restriction Zone Deleted",
             "A CBR network zone was deleted, potentially expanding the allowed source networks for service access."),

            # Resource Management
            ("threat.ibm.audit.resource_instance_creds_list",
             "resource_controller",
             "resource_controller", "resource-controller.key.list",
             "IBM Resource: Service Instance Credentials Listed",
             "Service credentials (API keys) for a resource instance were listed. These credentials provide direct service access."),
            ("threat.ibm.audit.resource_instance_creds_create",
             "resource_controller",
             "resource_controller", "resource-controller.key.create",
             "IBM Resource: Service Instance Credentials Created",
             "New credentials were created for a resource instance. New credentials provide additional access paths to the service."),
            ("threat.ibm.audit.resource_instance_delete",
             "resource_controller",
             "resource_controller", "resource-controller.instance.delete",
             "IBM Resource: Service Instance Deleted",
             "A resource service instance was deleted. This is a destructive action that removes the service and its data."),

            # COS (Object Storage)
            ("threat.ibm.audit.cos_object_read",
             "cloud_object_storage",
             "cloud_object_storage", "cloud-object-storage.object.read",
             "IBM COS: Object Read from Bucket",
             "An object was read from an IBM Cloud Object Storage bucket. Monitor for access to sensitive data stores."),
            ("threat.ibm.audit.cos_replication_create",
             "cloud_object_storage",
             "cloud_object_storage", "cloud-object-storage.bucket-replication.create",
             "IBM COS: Bucket Replication Configuration Created",
             "Bucket replication was configured, routing all object copies to another destination that may be attacker-controlled."),
            ("threat.ibm.audit.cos_lifecycle_delete",
             "cloud_object_storage",
             "cloud_object_storage", "cloud-object-storage.bucket-lifecycle.delete",
             "IBM COS: Bucket Lifecycle Policy Deleted",
             "Bucket lifecycle policy was deleted, potentially preserving sensitive data beyond intended retention period."),

            # VPC / Network
            ("threat.ibm.audit.vpc_floating_ip_add",
             "is",
             "is", "is.floating-ip.create",
             "IBM VPC: Floating IP Created (Public Exposure)",
             "A floating IP was created in IBM VPC, potentially assigning a public IP address to a private instance."),
            ("threat.ibm.audit.vpc_acl_create",
             "is",
             "is", "is.network-acl.create",
             "IBM VPC: Network ACL Created",
             "A new network ACL was created in IBM VPC, modifying traffic filtering for associated subnets."),
            ("threat.ibm.audit.vpc_image_export",
             "is",
             "is", "is.image.export",
             "IBM VPC: Custom Image Exported",
             "A VPC custom image was exported to COS. Exported images may contain sensitive data or OS configurations."),
            ("threat.ibm.audit.vpc_ssh_key_create",
             "is",
             "is", "is.key.create",
             "IBM VPC: SSH Key Created",
             "An SSH key was created in IBM VPC. New SSH keys can be injected into instances at creation for unauthorized access."),

            # Kubernetes / Code Engine
            ("threat.ibm.audit.iks_worker_reboot",
             "containers_kubernetes",
             "containers_kubernetes", "containers.worker.reboot",
             "IBM IKS: Worker Node Rebooted",
             "An IKS Kubernetes worker node was rebooted. May be used to disrupt workloads or force pod restarts."),
            ("threat.ibm.audit.code_engine_app_create",
             "codeengine",
             "codeengine", "codeengine.application.create",
             "IBM Code Engine: Application Deployed",
             "A Code Engine application was deployed. Monitor for unauthorized serverless workload deployments."),
            ("threat.ibm.audit.code_engine_job_run",
             "codeengine",
             "codeengine", "codeengine.jobrun.create",
             "IBM Code Engine: Job Run Created",
             "A Code Engine batch job run was created. Unexpected job executions may perform unauthorized data processing."),

            # Transit Gateway / Direct Link
            ("threat.ibm.audit.transit_gw_connect",
             "transit",
             "transit", "transit.connection.create",
             "IBM Transit Gateway: Connection Created",
             "A Transit Gateway connection was created, linking two networks. Unexpected connections may enable lateral movement."),
            ("threat.ibm.audit.directlink_gw_list",
             "directlink",
             "directlink", "directlink.gateway.list",
             "IBM Direct Link: Gateways Listed",
             "Direct Link gateways were listed. This reveals on-premises network connectivity and potential pivot targets."),

            # Schematics (Terraform)
            ("threat.ibm.audit.schematics_workspace_run",
             "schematics",
             "schematics", "schematics.workspace-run.create",
             "IBM Schematics: Workspace Job Run Created",
             "An IBM Schematics (Terraform) workspace job was triggered. Jobs can create, modify, or destroy cloud resources."),

            # App ID
            ("threat.ibm.audit.appid_client_secret",
             "appid",
             "appid", "appid.application.read",
             "IBM App ID: Application Client Secret Retrieved",
             "App ID application secrets were retrieved. These secrets authenticate OAuth2 client applications."),

            # Security Compliance
            ("threat.ibm.audit.scc_scope_create",
             "compliance",
             "compliance", "compliance.posture.create",
             "IBM Security and Compliance Center: Scope Created",
             "A new SCC scope was created, defining which IBM Cloud resources to evaluate for compliance."),

            # Monitoring
            ("threat.ibm.audit.monitoring_alert_delete",
             "sysdig_monitor",
             "sysdig_monitor", "sysdig-monitor.alert.delete",
             "IBM Monitoring: Alert Rule Deleted",
             "A monitoring alert rule was deleted, removing visibility into performance anomalies or security events."),
            ("threat.ibm.audit.monitoring_dashboard_update",
             "sysdig_monitor",
             "sysdig_monitor", "sysdig-monitor.dashboard.update",
             "IBM Monitoring: Dashboard Updated",
             "A monitoring dashboard was updated. Dashboards reveal what operational metrics are being tracked."),

            # Key Protect
            ("threat.ibm.audit.kms_key_import",
             "kms",
             "kms", "kms.secrets.create",
             "IBM Key Protect: Key Created or Imported",
             "A root key was created or imported into IBM Key Protect. Imported keys use external key material."),

            # Secrets Manager
            ("threat.ibm.audit.secrets_rotation_update",
             "secrets_manager",
             "secrets_manager", "secrets-manager.secret-rotation.set",
             "IBM Secrets Manager: Secret Auto-Rotation Configuration Updated",
             "Secret auto-rotation settings were updated. Disabling rotation keeps credentials active indefinitely."),

            # Toolchain / DevOps
            ("threat.ibm.audit.toolchain_pipeline_run",
             "toolchain",
             "toolchain", "toolchain.pipeline-run.create",
             "IBM Toolchain: CI/CD Pipeline Run Triggered",
             "A Continuous Delivery pipeline run was triggered. Unexpected pipeline runs may deploy unauthorized code."),
            ("threat.ibm.audit.satellite_location_create",
             "satellite",
             "satellite", "satellite.location.create",
             "IBM Satellite: Satellite Location Created",
             "An IBM Satellite location was created, extending IBM Cloud to an on-premises or edge environment."),
        ]

        for entry in rules:
            rid, svc, ibm_svc, op_c, title, desc = entry
            cfg = ibm_act(ibm_svc, op_c)
            emit(f, rid, svc, "ibm", title, desc, cfg)
            n += 1

    print(f"IBM audit_activity: {n} → {path}")
    return n


# ── main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    az = generate_azure(OUT_DIR)
    gcp = generate_gcp(OUT_DIR)
    oci = generate_oci(OUT_DIR)
    ibm = generate_ibm(OUT_DIR)
    print(f"\nTotal new audit_activity rules: {az + gcp + oci + ibm}")
    print("\nExpected totals after insert:")
    print(f"  Azure: 51 + {az} = {51 + az}")
    print(f"  GCP:   41 + {gcp} = {41 + gcp}")
    print(f"  OCI:   25 + {oci} = {25 + oci}")
    print(f"  IBM:   27 + {ibm} = {27 + ibm}")
