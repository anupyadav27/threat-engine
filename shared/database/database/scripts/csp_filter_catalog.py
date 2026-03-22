"""
csp_filter_catalog.py — Enterprise-level managed-resource filter rules for all CSPs.

Each CSP has managed/system resources that should be excluded from CSPM scanning:
  - Cloud-provider-owned resources (AWS-managed KMS aliases, Google-managed SAs, etc.)
  - System/internal resources (default event buses, primary workgroups, etc.)
  - Non-customer resources (public AMIs, shared snapshots, etc.)

Structure:
  FILTER_CATALOG[csp][service] = {
      "api_filters":      [...],   # pre-call: modify API params before the SDK call
      "response_filters": [...],   # post-call: exclude items from the API response
  }

api_filter fields:
  discovery_id   — exact match against the YAML discovery_id (e.g. "aws.ec2.describe_snapshots")
  filter_type    — "api_param"
  api_parameter  — SDK param name (e.g. "OwnerIds")
  api_value      — value to set (list, bool, string, int)
  priority       — execution order (lower = first, default 10)
  description    — human-readable reason

response_filter fields:
  discovery_id   — exact match against the YAML discovery_id
  filter_type    — "exclude_pattern"
  field_path     — dot-notation field on each item (e.g. "AliasName")
  pattern        — regex / prefix / contains / exact / suffix string
  pattern_type   — "regex" | "prefix" | "suffix" | "contains" | "exact"
  priority       — execution order (lower = first, default 100)
  description    — human-readable reason

Discovery ID naming conventions by CSP:
  aws:      aws.{service}.{boto3_method}         e.g. aws.ec2.describe_snapshots
            Note: boto3 "DB" → "d_b" split in some RDS/DocDB/Neptune IDs
  azure:    azure.{service}.{Method_Name}         e.g. azure.resources.ResourceGroups_List
  gcp:      gcp.{service}.{resource}.{verb}       e.g. gcp.compute.disks.aggregatedList
            REST path style: gcp.iam.projects.serviceAccounts.list
  oci:      oci.{service}.{sdk_method}            e.g. oci.identity.list_policies (snake_case)
  alicloud: alicloud.{service}.{ApiOperation}     e.g. alicloud.ram.ListPolicies (PascalCase)
  ibm:      ibm.{service}.{operation}             e.g. ibm.iam.list-policies (kebab-case)

Consumed by: consolidated_services/database/scripts/sync_discoveries_to_db.py
Stored in:   rule_discoveries.filter_rules (JSONB) in threat_engine_check DB
Read by:     engine_discoveries/utils/config_loader.py → get_filter_rules()
             engine_discoveries/utils/filter_engine.py
"""

from typing import Any

# ── helpers ───────────────────────────────────────────────────────────────────

def _api(discovery_id: str, param: str, value: Any,
         priority: int = 10, desc: str = "") -> dict:
    return {
        "discovery_id":  discovery_id,
        "filter_type":   "api_param",
        "api_parameter": param,
        "api_value":     value,
        "priority":      priority,
        "description":   desc,
    }


def _excl(discovery_id: str, field: str, pattern: str,
          ptype: str = "regex", priority: int = 100, desc: str = "") -> dict:
    return {
        "discovery_id": discovery_id,
        "filter_type":  "exclude_pattern",
        "field_path":   field,
        "pattern":      pattern,
        "pattern_type": ptype,
        "priority":     priority,
        "description":  desc,
    }


def _excl_exact(discovery_id: str, field: str, value: str,
                priority: int = 100, desc: str = "") -> dict:
    return {
        "discovery_id": discovery_id,
        "filter_type":  "exclude_pattern",
        "field_path":   field,
        "pattern":      value,
        "pattern_type": "exact",
        "priority":     priority,
        "description":  desc,
    }


# ══════════════════════════════════════════════════════════════════════════════
# AWS
# Source: engine_check/engine_check_aws/engine/service_scanner.py
# Validated against curated engine_check service YAML discovery IDs.
#
# Intentionally excluded (no AWS-managed versions in customer accounts):
#   - lambda: no AWS-managed Lambda functions in customer accounts
#   - ecr:    no AWS-managed private ECR repositories in customer accounts
#   - s3, sqs, sns, dynamodb, redshift, elasticache: all customer-owned
# ══════════════════════════════════════════════════════════════════════════════

_AWS: dict[str, dict] = {

    # ── EC2 ──────────────────────────────────────────────────────────────────
    # Without OwnerIds/Owners filter, describe_snapshots returns ALL public
    # snapshots (millions of AWS/community), describe_images returns 100K+ AMIs.
    "ec2": {
        "api_filters": [
            _api("aws.ec2.describe_snapshots",   "OwnerIds", ["self"],
                 desc="Only return EBS snapshots owned by this account"),
            _api("aws.ec2.describe_images",      "Owners",   ["self"],
                 desc="Only return AMIs owned by this account"),
            _api("aws.ec2.describe_fpga_images", "Owners",   ["self"],
                 desc="Only return FPGA images owned by this account"),
        ],
        "response_filters": [],
    },

    # ── RDS ──────────────────────────────────────────────────────────────────
    # Discovery ID note: YAML convention splits some "DB" literals as "d_b":
    #   describe_db_cluster_snapshots → aws.rds.describe_db_cluster_snapshots (no split)
    #   describe_db_snapshots         → aws.rds.describe_d_b_snapshots (split)
    "rds": {
        "api_filters": [
            _api("aws.rds.describe_db_cluster_snapshots", "IncludeShared", False,
                 priority=10, desc="Exclude shared RDS cluster snapshots"),
            _api("aws.rds.describe_db_cluster_snapshots", "IncludePublic", False,
                 priority=11, desc="Exclude public RDS cluster snapshots"),
            _api("aws.rds.describe_d_b_snapshots", "IncludeShared", False,
                 priority=10, desc="Exclude shared RDS DB snapshots"),
            _api("aws.rds.describe_d_b_snapshots", "IncludePublic", False,
                 priority=11, desc="Exclude public RDS DB snapshots"),
        ],
        "response_filters": [],
    },

    # ── DocumentDB ───────────────────────────────────────────────────────────
    # Discovery ID uses 'd_b' split: aws.docdb.describe_d_b_cluster_snapshots
    "docdb": {
        "api_filters": [
            _api("aws.docdb.describe_d_b_cluster_snapshots", "IncludeShared", False,
                 priority=10, desc="Exclude shared DocumentDB cluster snapshots"),
            _api("aws.docdb.describe_d_b_cluster_snapshots", "IncludePublic", False,
                 priority=11, desc="Exclude public DocumentDB cluster snapshots"),
        ],
        "response_filters": [],
    },

    # ── Neptune ──────────────────────────────────────────────────────────────
    # Discovery ID uses 'd_b' split: aws.neptune.describe_d_b_cluster_snapshots
    "neptune": {
        "api_filters": [
            _api("aws.neptune.describe_d_b_cluster_snapshots", "IncludeShared", False,
                 priority=10, desc="Exclude shared Neptune cluster snapshots"),
            _api("aws.neptune.describe_d_b_cluster_snapshots", "IncludePublic", False,
                 priority=11, desc="Exclude public Neptune cluster snapshots"),
        ],
        "response_filters": [],
    },

    # ── IAM ──────────────────────────────────────────────────────────────────
    # API filter: Scope=Local limits list_policies to customer-managed only (not AWS).
    # Response filters provide a safety net for any edge-case slip-through.
    "iam": {
        "api_filters": [
            _api("aws.iam.list_policies", "Scope", "Local",
                 desc="Only return customer-managed IAM policies (exclude AWS-managed)"),
        ],
        "response_filters": [
            _excl("aws.iam.list_roles", "Path",
                  r"^(/aws-service-role/|/aws-reserved/)", "regex",
                  desc="Exclude AWS service-linked roles (/aws-service-role/) "
                       "and AWS-reserved internal roles (/aws-reserved/)"),
            _excl("aws.iam.list_policies", "Arn",
                  "^arn:aws:iam::aws:policy/", "prefix",
                  desc="Safety net: exclude AWS-managed policy ARNs "
                       "(Scope=Local API filter already handles this)"),
        ],
    },

    # ── KMS ──────────────────────────────────────────────────────────────────
    # AWS-managed KMS keys all have aliases in the alias/aws/ namespace.
    # Customer CMKs use alias/my-key-name format.
    "kms": {
        "api_filters": [],
        "response_filters": [
            _excl("aws.kms.list_aliases", "AliasName", "^alias/aws/", "prefix",
                  desc="Exclude AWS-managed KMS key aliases (alias/aws/* namespace)"),
        ],
    },

    # ── Secrets Manager ───────────────────────────────────────────────────────
    # AWS-managed: aws/* (e.g. aws/rds/cluster, aws/ssm/parameter)
    # RDS-managed: rds!* (auto-created when enabling RDS password management)
    "secretsmanager": {
        "api_filters": [],
        "response_filters": [
            _excl("aws.secretsmanager.list_secrets", "Name", r"^(aws/|rds!)", "regex",
                  desc="Exclude AWS-managed (aws/) and RDS auto-managed (rds!) secrets"),
        ],
    },

    # ── CloudFormation ────────────────────────────────────────────────────────
    # list_stacks without a filter returns ALL stacks including DELETE_COMPLETE
    # history (thousands of entries in active accounts). Only fetch live stacks.
    "cloudformation": {
        "api_filters": [
            _api("aws.cloudformation.list_stacks", "StackStatusFilter",
                 [
                     "CREATE_COMPLETE",
                     "CREATE_FAILED",
                     "UPDATE_COMPLETE",
                     "UPDATE_ROLLBACK_COMPLETE",
                     "UPDATE_ROLLBACK_FAILED",
                     "ROLLBACK_COMPLETE",
                     "IMPORT_COMPLETE",
                     "IMPORT_ROLLBACK_COMPLETE",
                     "DELETE_FAILED",
                 ],
                 desc="Return only live stacks; exclude DELETE_COMPLETE/IN_PROGRESS history"),
        ],
        "response_filters": [],
    },

    # ── SSM ──────────────────────────────────────────────────────────────────
    # Without Owner=Self filters: list_documents returns thousands of AWS/Amazon/
    # third-party runbooks; describe_patch_baselines returns all AWS predefined baselines.
    "ssm": {
        "api_filters": [
            _api("aws.ssm.list_documents", "Owner", "Self",
                 desc="Only return customer-managed SSM documents"),
            _api("aws.ssm.describe_patch_baselines", "Owner", "Self",
                 desc="Only return customer-managed SSM patch baselines"),
        ],
        "response_filters": [
            _excl("aws.ssm.describe_parameters", "Name", "^/aws/", "prefix",
                  desc="Exclude AWS-managed SSM parameters (/aws/* namespace)"),
            _excl("aws.ssm.list_commands", "DocumentName", "^AWS-", "prefix",
                  desc="Exclude commands invoked from AWS-managed runbooks (AWS-*)"),
            _excl("aws.ssm.describe_automation_executions", "DocumentName", "^AWS-",
                  "prefix",
                  desc="Exclude automations run from AWS-managed documents (AWS-*)"),
        ],
    },

    # ── EventBridge ───────────────────────────────────────────────────────────
    # Every AWS account has exactly one default event bus that cannot be deleted.
    "events": {
        "api_filters": [],
        "response_filters": [
            _excl_exact("aws.events.list_event_buses", "Name", "default",
                        desc="Exclude the non-deletable AWS default event bus"),
        ],
    },

    # ── Athena ────────────────────────────────────────────────────────────────
    # Every AWS account has a 'primary' workgroup that cannot be deleted.
    "athena": {
        "api_filters": [],
        "response_filters": [
            _excl_exact("aws.athena.list_work_groups", "Name", "primary",
                        desc="Exclude the non-deletable AWS primary Athena workgroup"),
        ],
    },

    # ── Keyspaces (Amazon Cassandra) ──────────────────────────────────────────
    # Cassandra system keyspaces are AWS-managed: system, system_schema,
    # system_auth, system_traces, system_distributed, system_views, system_virtual_schema.
    "keyspaces": {
        "api_filters": [],
        "response_filters": [
            _excl("aws.keyspaces.list_keyspaces", "keyspaceName", "^system", "prefix",
                  desc="Exclude AWS-managed Cassandra system keyspaces (system*)"),
        ],
    },

    # ── CloudWatch Logs ───────────────────────────────────────────────────────
    # AWS services write to log groups under /aws/ prefix (e.g. /aws/lambda/,
    # /aws/rds/, /aws/apigateway/). These are service-generated, not customer-managed.
    "logs": {
        "api_filters": [],
        "response_filters": [
            _excl("aws.logs.describe_log_groups", "logGroupName", "^/aws/", "prefix",
                  desc="Exclude AWS service-generated log groups (/aws/* namespace)"),
        ],
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# AZURE
# Service keys match data_pythonsdk/azure/{service}/ directory names.
# Discovery IDs match azure/{service}/step6_*.discovery.yaml entries.
#
# Intentionally excluded from filters:
#   keyvault: no Azure-managed Key Vault instances in customer subscriptions;
#             the list_by_subscription operation lacks a 'name' field at vault
#             list level, so name-based filtering is not feasible.
# ══════════════════════════════════════════════════════════════════════════════

_AZURE: dict[str, dict] = {

    # ── Resource Groups + Policy Definitions ──────────────────────────────────
    # Service dir: data_pythonsdk/azure/resources/
    # ResourceGroups_List fields: id, name, location, tags, type, provisioning_state
    # PolicyDefinitions_List fields include policy_type (BuiltIn | Custom | Static)
    "resources": {
        "api_filters": [],
        "response_filters": [
            # Azure automatically creates these system resource groups:
            _excl("azure.resources.ResourceGroups_List", "name",
                  r"^(NetworkWatcherRG|AzureBackupRG|MC_|cloud-shell-storage"
                  r"|ManagedPlatformRG|DefaultResourceGroup-)",
                  "regex",
                  desc="Exclude Azure-managed system resource groups: "
                       "NetworkWatcher, Backup, AKS managed cluster (MC_), "
                       "Cloud Shell storage, platform managed, VM diagnostics default"),
            _excl("azure.resources.ResourceGroups_List", "name",
                  "^databricks-rg-", "prefix",
                  desc="Exclude Databricks-managed resource groups (databricks-rg-*)"),
            # Built-in and Static policy definitions are Azure-managed (cannot be modified)
            _excl("azure.resources.PolicyDefinitions_List", "policy_type", "BuiltIn",
                  "exact",
                  desc="Exclude Azure built-in policy definitions (Azure-managed)"),
            _excl("azure.resources.PolicyDefinitions_List", "policy_type", "Static",
                  "exact",
                  desc="Exclude Azure static/platform policy definitions"),
        ],
    },

    # ── Role Definitions ──────────────────────────────────────────────────────
    # Service dir: data_pythonsdk/azure/authorization/
    # azure.authorization.list fields: id, name, type, assignable_scopes, description
    # type=BuiltInRole → Azure built-in (managed); type=CustomRole → customer-created
    "authorization": {
        "api_filters": [],
        "response_filters": [
            _excl("azure.authorization.list", "type", "BuiltInRole", "exact",
                  desc="Exclude Azure built-in role definitions (type=BuiltInRole); "
                       "only scan customer-created custom roles"),
        ],
    },

    # ── Storage Accounts ─────────────────────────────────────────────────────
    # Service dir: data_pythonsdk/azure/storage/
    # azure.storage.list_by_resource_group fields: name, id, location, ...
    # Azure auto-creates diagnostic storage accounts with identifiable prefixes.
    "storage": {
        "api_filters": [],
        "response_filters": [
            _excl("azure.storage.list_by_resource_group", "name",
                  r"^(azurediag|azurestorlog|csediag)", "regex",
                  desc="Exclude Azure-managed diagnostic storage accounts "
                       "(azurediag*, azurestorlog*, csediag*)"),
        ],
    },

    # ── Compute (VMs) ────────────────────────────────────────────────────────
    # Service dir: data_pythonsdk/azure/compute/
    # azure.compute.list_all fields: id, name, location, tags, type, ...
    # AKS node VMs are named aks-{nodepool}-{number}-vmss{hex}
    "compute": {
        "api_filters": [],
        "response_filters": [
            _excl("azure.compute.list_all", "name", r"^aks(win)?-", "regex",
                  desc="Exclude AKS-managed virtual machines "
                       "(Linux: aks-*, Windows: akswin-*)"),
        ],
    },

    # ── Network Resources ─────────────────────────────────────────────────────
    # Service dir: data_pythonsdk/azure/network/
    # azure.network.list_all fields: id, name, location, tags, type, ...
    # AKS creates NSGs, route tables, public IPs, load balancers with aks- prefix.
    # 'kubernetes' is the default internal LB name AKS creates.
    "network": {
        "api_filters": [],
        "response_filters": [
            _excl("azure.network.list_all", "name",
                  r"^(aks-|aks_|kubernetes$)", "regex",
                  desc="Exclude AKS-managed network resources: "
                       "NSGs/VNets/LBs/PIPs (aks-* prefix) and internal LB (kubernetes)"),
        ],
    },

    # ── Managed Identities ────────────────────────────────────────────────────
    # Service dir: data_pythonsdk/azure/msi/
    # azure.msi.list fields: name, display
    # Azure monitoring (OMS/MMA agent) and AKS create system-managed identities.
    "msi": {
        "api_filters": [],
        "response_filters": [
            _excl("azure.msi.list", "name",
                  r"^(omsagent|mma-agent|aks-)", "regex",
                  desc="Exclude AKS-managed identities (aks-*) and "
                       "Azure Monitor agent identities (omsagent, mma-agent)"),
        ],
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# GCP
# Discovery IDs use GCP REST API path style:
#   gcp.{service}.{resource.path}.{verb}
# All IDs validated against data_pythonsdk/gcp/{service}/step6_*.discovery.yaml.
#
# Intentionally excluded from filters:
#   container: GKE Autopilot clusters are customer-created resources (not Google-managed)
#   cloudkms:  All KMS keys/key rings in a GCP project are customer-created;
#              Google does NOT place managed keys into customer KMS projects
# ══════════════════════════════════════════════════════════════════════════════

_GCP: dict[str, dict] = {

    # ── IAM (Service Accounts + Predefined Roles) ─────────────────────────────
    # Service dir: data_pythonsdk/gcp/iam/
    # gcp.iam.projects.serviceAccounts.list: email, name, displayName, ...
    # gcp.iam.roles.list: returns ONLY predefined (Google-managed) roles (name starts roles/)
    # gcp.iam.organizations.roles.list / gcp.iam.projects.roles.list → customer custom roles
    "iam": {
        "api_filters": [],
        "response_filters": [
            # Default Google-managed service accounts created in every project:
            _excl("gcp.iam.projects.serviceAccounts.list", "email",
                  r"@(cloudservices|developer|appspot|cloudbuild|"
                  r"cloudcomposer-accounts)\.gserviceaccount\.com$",
                  "regex",
                  desc="Exclude Google default service accounts: App Engine, "
                       "Compute Engine developer SA, Cloud Build, Cloud Composer"),
            # GCP internal service agents (gcp-sa-* accounts used by GCP services):
            _excl("gcp.iam.projects.serviceAccounts.list", "email",
                  r"@gcp-sa-[^@]+\.iam\.gserviceaccount\.com$",
                  "regex",
                  desc="Exclude GCP internal service agent accounts (gcp-sa-*)"),
            # gcp.iam.roles.list returns ONLY predefined Google roles (roles/*).
            # Exclude the entire result set — predefined roles are Google-managed.
            _excl("gcp.iam.roles.list", "name", "^roles/", "prefix",
                  desc="Exclude all GCP predefined roles (roles/* namespace); "
                       "custom org/project roles are in organizations.roles.list "
                       "and projects.roles.list"),
        ],
    },

    # ── Compute (VMs, Disks, Firewalls, Snapshots, LB infrastructure) ─────────
    # Service dir: data_pythonsdk/gcp/compute/
    # IDs follow pattern: gcp.compute.{resource}.{verb}
    # GKE node instances/disks/snapshots: named gke-{cluster}-{nodepool}-{hash}
    # GKE firewall rules: gke-{cluster}-* and default-allow-* (default VPC rules)
    # Kubernetes ingress LB infrastructure (created by GKE ingress controller):
    #   k8s-be-{hash}   healthChecks       k8s-fw-{hash}   forwardingRules
    #   k8s1-{hash}     backendServices    k8s-tp-{hash}   targetHttpProxies
    #   k8s-um-{hash}   urlMaps            k8s-tps-{hash}  targetHttpsProxies
    #   k8s-ssl-{hash}  sslCertificates
    "compute": {
        "api_filters": [],
        "response_filters": [
            # GKE node resources
            _excl("gcp.compute.instances.aggregatedList", "name", "^gke-", "prefix",
                  desc="Exclude GKE-managed compute instances (gke-* naming)"),
            _excl("gcp.compute.disks.aggregatedList", "name", "^gke-", "prefix",
                  desc="Exclude GKE-managed persistent disks (gke-* naming)"),
            _excl("gcp.compute.snapshots.list", "name", "^gke-", "prefix",
                  desc="Exclude GKE-managed disk snapshots (gke-* naming)"),
            # Firewall rules: GKE node rules, default VPC allow rules, k8s ingress rules
            _excl("gcp.compute.firewalls.list", "name",
                  r"^(gke-|default-allow-|k8s-fw-)", "regex",
                  desc="Exclude GKE-managed firewall rules (gke-*), "
                       "GCP default VPC allow rules (default-allow-*), "
                       "and Kubernetes ingress firewall rules (k8s-fw-*)"),
            # Kubernetes ingress controller LB infrastructure
            _excl("gcp.compute.healthChecks.aggregatedList", "name", "^k8s-", "prefix",
                  desc="Exclude GKE ingress health checks (k8s-be-* naming)"),
            _excl("gcp.compute.backendServices.aggregatedList", "name", "^k8s", "prefix",
                  desc="Exclude GKE ingress backend services (k8s1-*, k8s-be-* naming)"),
            _excl("gcp.compute.forwardingRules.aggregatedList", "name", "^k8s-fw", "prefix",
                  desc="Exclude GKE ingress forwarding rules (k8s-fw-*, k8s-fws-* naming)"),
            _excl("gcp.compute.targetHttpProxies.aggregatedList", "name", "^k8s-tp", "prefix",
                  desc="Exclude GKE ingress target HTTP proxies (k8s-tp-* naming)"),
            _excl("gcp.compute.targetHttpsProxies.aggregatedList", "name", "^k8s-tps", "prefix",
                  desc="Exclude GKE ingress target HTTPS proxies (k8s-tps-* naming)"),
            _excl("gcp.compute.urlMaps.aggregatedList", "name", "^k8s", "prefix",
                  desc="Exclude GKE ingress URL maps (k8s-um-*, k8s1-* naming)"),
            _excl("gcp.compute.sslCertificates.aggregatedList", "name", "^k8s-ssl-", "prefix",
                  desc="Exclude GKE ingress managed SSL certificates (k8s-ssl-* naming)"),
        ],
    },

    # ── Cloud Logging ─────────────────────────────────────────────────────────
    # Service dir: data_pythonsdk/gcp/logging/
    # _Default and _Required are Google-reserved log buckets in every project.
    # _Required: holds Admin Activity and System Event audit logs (immutable).
    # _Default:  receives all other log entries by default.
    "logging": {
        "api_filters": [],
        "response_filters": [
            _excl("gcp.logging.projects.locations.buckets.list", "name",
                  r"^(_Default|_Required)$", "regex",
                  desc="Exclude Google-managed reserved log buckets: "
                       "_Default (default sink) and _Required (immutable audit logs)"),
        ],
    },

    # ── Resource Manager (Projects) ───────────────────────────────────────────
    # Service dir: data_pythonsdk/gcp/cloudresourcemanager/
    # sys-* projects: GCP system/infrastructure projects visible in org listings.
    # google-* projects: Google-owned projects that appear in org-level scans.
    "cloudresourcemanager": {
        "api_filters": [],
        "response_filters": [
            _excl("gcp.cloudresourcemanager.projects.list", "projectId",
                  r"^(sys-|google-)", "regex",
                  desc="Exclude GCP system projects (sys-*) and "
                       "Google-owned projects (google-*) from org-level scans"),
        ],
    },

    # ── Cloud Storage ─────────────────────────────────────────────────────────
    # Service dir: data_pythonsdk/gcp/storage/
    # GCP auto-creates these buckets for internal service use:
    #   artifacts.{project}.appspot.com      — legacy Container Registry storage
    #   gcf-sources-{project}-{region}       — Cloud Functions gen1 source archives
    #   gcf-artifacts-{project}-{region}     — Cloud Functions gen2 build artifacts
    #   staging.{project}.appspot.com        — App Engine staging
    #   goog-*                               — Google-internal buckets visible in org
    #   dataflow-staging-{project}-{region}  — Dataflow staging (auto-created on job run)
    #   dataproc-staging-{project}-{region}  — Dataproc staging (auto-created on cluster)
    #   dataproc-temp-{project}-{region}     — Dataproc temp (auto-created on cluster)
    "storage": {
        "api_filters": [],
        "response_filters": [
            _excl("gcp.storage.buckets.list", "name",
                  r"^(artifacts\.|gcf-sources-|gcf-artifacts-|staging\.|goog-"
                  r"|dataflow-staging-|dataproc-staging-|dataproc-temp-)",
                  "regex",
                  desc="Exclude GCP service-managed buckets: "
                       "Container Registry (artifacts.*), "
                       "Cloud Functions (gcf-sources-*, gcf-artifacts-*), "
                       "App Engine staging (staging.*), "
                       "Google-internal (goog-*), "
                       "Dataflow staging (dataflow-staging-*), "
                       "Dataproc staging/temp (dataproc-staging-*, dataproc-temp-*)"),
        ],
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# OCI (Oracle Cloud Infrastructure)
# Service keys match data_pythonsdk/oci/{service}/ directory names.
# Discovery IDs validated against step6_*.discovery.yaml (snake_case SDK style).
#
# Intentionally excluded from filters:
#   key_management: Oracle does NOT place managed keys into customer KMS vaults;
#                   all keys in oci.key_management are customer-created
#   virtual_network: Default security lists and route tables are customer-modifiable
#                    and should be scanned for misconfigurations (0.0.0.0/0 rules)
# ══════════════════════════════════════════════════════════════════════════════

_OCI: dict[str, dict] = {

    # ── Identity (IAM: Policies, Groups, Users, Compartments) ─────────────────
    # Service dir: data_pythonsdk/oci/identity/
    # OCI IAM lives entirely in the 'identity' service (SDK: oci.identity.list_*)
    # All IDs confirmed in step6_identity.discovery.yaml.
    "identity": {
        "api_filters": [],
        "response_filters": [
            # Oracle pre-creates these policies in the root compartment:
            _excl("oci.identity.list_policies", "name",
                  r"^(Tenant Admin Policy|PSM-root-policy|PSM-mgd-slb-service-policy)",
                  "regex",
                  desc="Exclude Oracle-managed root compartment policies: "
                       "Tenant Admin Policy, PSM root/SLB policies"),
            # Oracle creates default groups in every tenancy:
            _excl("oci.identity.list_groups", "name",
                  r"^(Administrators|All Domain Users)$", "regex",
                  desc="Exclude Oracle default IAM groups: "
                       "Administrators and All Domain Users"),
            # IDCS-federated users appear with oracleidentitycloudservice/ prefix:
            _excl("oci.identity.list_users", "name",
                  "^oracleidentitycloudservice/", "prefix",
                  desc="Exclude Oracle Identity Cloud Service federated users "
                       "(oracleidentitycloudservice/* prefix)"),
            # Oracle creates managed compartments for some PaaS services:
            _excl("oci.identity.list_compartments", "name",
                  "^ManagedCompartmentFor", "prefix",
                  desc="Exclude Oracle-managed compartments (ManagedCompartmentFor*)"),
        ],
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# ALICLOUD (Alibaba Cloud)
# Service keys match data_pythonsdk/alicloud/{service}/ directory names.
# Discovery IDs use PascalCase (AliCloud SDK style): alicloud.{service}.{Method}
#
# Note on ECS DescribeSnapshots: SnapshotType filter removed — both 'user'
# (manually created) and 'auto' (policy-created) snapshots are customer-owned
# data and should be scanned for encryption/retention compliance.
# ══════════════════════════════════════════════════════════════════════════════

_ALICLOUD: dict[str, dict] = {

    # ── RAM (Resource Access Management) ──────────────────────────────────────
    # Service dir: data_pythonsdk/alicloud/ram/
    # Alibaba-managed system policies: AliyunECSFullAccess, AliyunOSSReadOnlyAccess, etc.
    # Service-linked roles: AliyunServiceRoleForECS, AliyunServiceRoleForRDS, etc.
    "ram": {
        "api_filters": [],
        "response_filters": [
            _excl("alicloud.ram.ListPolicies", "PolicyName", "^Aliyun", "prefix",
                  desc="Exclude Alibaba Cloud system RAM policies (Aliyun* prefix); "
                       "e.g. AliyunECSFullAccess, AliyunOSSReadOnlyAccess"),
            _excl("alicloud.ram.ListRoles", "RoleName",
                  "^AliyunServiceRole", "prefix",
                  desc="Exclude Alibaba Cloud service-linked roles (AliyunServiceRole*); "
                       "e.g. AliyunServiceRoleForECS, AliyunServiceRoleForRDS"),
        ],
    },

    # ── KMS ───────────────────────────────────────────────────────────────────
    # Service dir: data_pythonsdk/alicloud/kms/
    # Alibaba-managed service encryption keys have IDs starting with 'acs:kms:'.
    # Customer-created keys have plain UUID-format KeyIds.
    "kms": {
        "api_filters": [],
        "response_filters": [
            _excl("alicloud.kms.ListKeys", "KeyId", "^acs:kms:", "prefix",
                  desc="Exclude Alibaba Cloud managed service keys (acs:kms:* KeyId format); "
                       "customer keys use plain UUID format"),
        ],
    },

    # ── ECS (Elastic Compute Service) ─────────────────────────────────────────
    # Service dir: data_pythonsdk/alicloud/ecs/
    # DescribeImages: ImageOwnerAlias controls which images are returned.
    #   system=Alibaba public images, marketplace=3rd-party, self=customer-created.
    # DescribeSnapshots: No SnapshotType filter — both manual and auto-policy
    #   snapshots are customer data and should be scanned.
    "ecs": {
        "api_filters": [
            _api("alicloud.ecs.DescribeImages", "ImageOwnerAlias", "self",
                 desc="Only return customer-created ECS images (exclude Alibaba "
                      "system images and marketplace images)"),
        ],
        "response_filters": [],
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# IBM Cloud
# Service keys match data_pythonsdk/ibm/{service}/ directory names.
# Discovery IDs use kebab-case (IBM Cloud SDK style): ibm.{service}.{operation}
# All IDs validated against step6_*.discovery.yaml.
#
# Intentionally excluded from filters:
#   resource_controller: IBM does not inject managed instances into customer accounts;
#                        name-prefix filtering risks excluding legitimately named instances
#   key_protect: All keys in a Key Protect instance are customer-created;
#                the 'extractable=false' pattern incorrectly excludes customer root keys
# ══════════════════════════════════════════════════════════════════════════════

_IBM: dict[str, dict] = {

    # ── IAM ───────────────────────────────────────────────────────────────────
    # Service dir: data_pythonsdk/ibm/iam/
    # IBM Cloud predefined platform roles have CRNs in the format:
    #   crn:v1:bluemix:public:iam::::role:{RoleName}
    # Custom roles use account-scoped CRNs and should be scanned.
    # ibm.iam.list-roles confirmed in step6_iam.discovery.yaml (4 total IDs).
    "iam": {
        "api_filters": [],
        "response_filters": [
            _excl("ibm.iam.list-roles", "crn",
                  "^crn:v1:bluemix:public:iam::::role:", "prefix",
                  desc="Exclude IBM Cloud predefined platform roles "
                       "(crn:v1:bluemix:public:iam::::role:* CRN format); "
                       "e.g. Viewer, Editor, Administrator, Operator, Manager"),
        ],
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# Master catalog — keyed by CSP name (matches rule_discoveries.provider)
# ══════════════════════════════════════════════════════════════════════════════

FILTER_CATALOG: dict[str, dict[str, dict]] = {
    "aws":      _AWS,
    "azure":    _AZURE,
    "gcp":      _GCP,
    "oci":      _OCI,
    "alicloud": _ALICLOUD,
    "ibm":      _IBM,
}


def get_filter_rules(csp: str, service: str) -> dict:
    """
    Return filter_rules JSONB for a specific CSP + service.
    Returns {"api_filters": [], "response_filters": []} if not configured.
    """
    return FILTER_CATALOG.get(csp, {}).get(
        service, {"api_filters": [], "response_filters": []}
    )


def has_filters(csp: str, service: str) -> bool:
    """Return True if this CSP/service has any filter rules."""
    rules = get_filter_rules(csp, service)
    return bool(rules["api_filters"] or rules["response_filters"])


def all_filtered_services(csp: str) -> list[str]:
    """Return list of services that have filter rules for a given CSP."""
    return [svc for svc, rules in FILTER_CATALOG.get(csp, {}).items()
            if rules.get("api_filters") or rules.get("response_filters")]


def catalog_summary() -> dict:
    """Return a count summary: {csp: {service: {api: n, response: n}}}."""
    out = {}
    for csp, services in FILTER_CATALOG.items():
        out[csp] = {}
        for svc, rules in services.items():
            na = len(rules.get("api_filters", []))
            nr = len(rules.get("response_filters", []))
            if na or nr:
                out[csp][svc] = {"api": na, "response": nr}
    return out


if __name__ == "__main__":
    summary = catalog_summary()
    total_api = total_resp = 0
    for csp, services in summary.items():
        print(f"\n{csp.upper()}")
        for svc, counts in services.items():
            print(f"  {svc:<42} api={counts['api']}  response={counts['response']}")
            total_api  += counts["api"]
            total_resp += counts["response"]
    print(f"\nTotal: {sum(len(v) for v in summary.values())} services, "
          f"{total_api} api_filters, {total_resp} response_filters")
