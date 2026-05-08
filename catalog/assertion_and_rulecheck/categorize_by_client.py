"""
Phase 0b — Python Client Categorization + Duplicate Suppression

For every rule_id:
  1. Assigns `python_client` — the primary SDK client that owns the resource
  2. Assigns `check_client`  — the SDK client actually used for the CHECK logic
     (often differs from python_client for cross-service checks: IAM, KMS, etc.)
  3. Marks `is_duplicate: true` + `canonical_rule_id` when the same (check_client,
     normalized_check_leaf) appears for 2+ different primary services — meaning
     one shared check function can cover all of them.

Output:
  - In-place YAML update: adds python_client, check_client, is_duplicate, canonical_rule_id
  - client_dedup_report.md   — per-CSP summary + duplicate list
  - client_groups.csv        — full rule-level detail
"""

from __future__ import annotations
import csv
from collections import defaultdict
from pathlib import Path
from typing import Optional

import yaml

ROOT = Path(__file__).parent
FILES = sorted(ROOT.glob("[0-9]_*_full_scope_assertions.yaml"))

# ═══════════════════════════════════════════════════════════
#  Primary client maps  (service-name → Python client string)
# ═══════════════════════════════════════════════════════════

AWS_CLIENT = {
    "accessanalyzer": "boto3.accessanalyzer",
    "account": "boto3.account",
    "acm": "boto3.acm",
    "acm-pca": "boto3.acm-pca",
    "apigateway": "boto3.apigateway",
    "apigatewayv2": "boto3.apigatewayv2",
    "appstream": "boto3.appstream",
    "appsync": "boto3.appsync",
    "athena": "boto3.athena",
    "autoscaling": "boto3.autoscaling",
    "backup": "boto3.backup",
    "batch": "boto3.batch",
    "bedrock": "boto3.bedrock",
    "budgets": "boto3.budgets",
    "cloudformation": "boto3.cloudformation",
    "cloudfront": "boto3.cloudfront",
    "cloudtrail": "boto3.cloudtrail",
    "cloudwatch": "boto3.cloudwatch",
    "codeartifact": "boto3.codeartifact",
    "codebuild": "boto3.codebuild",
    "cognito": "boto3.cognito-idp",
    "config": "boto3.config",
    "controltower": "boto3.controltower",
    "costexplorer": "boto3.ce",
    "datasync": "boto3.datasync",
    "detective": "boto3.detective",
    "directconnect": "boto3.directconnect",
    "directoryservice": "boto3.ds",
    "dms": "boto3.dms",
    "docdb": "boto3.docdb",
    "drs": "boto3.drs",
    "dynamodb": "boto3.dynamodb",
    "ebs": "boto3.ec2",
    "ec2": "boto3.ec2",
    "ecr": "boto3.ecr",
    "ecs": "boto3.ecs",
    "edr": "boto3.ec2",
    "efs": "boto3.efs",
    "eip": "boto3.ec2",
    "eks": "boto3.eks",
    "elastic": "boto3.es",
    "elasticache": "boto3.elasticache",
    "elasticbeanstalk": "boto3.elasticbeanstalk",
    "elb": "boto3.elb",
    "elbv2": "boto3.elbv2",
    "emr": "boto3.emr",
    "eventbridge": "boto3.events",
    "fargate": "boto3.ecs",
    "firehose": "boto3.firehose",
    "fsx": "boto3.fsx",
    "glacier": "boto3.glacier",
    "globalaccelerator": "boto3.globalaccelerator",
    "glue": "boto3.glue",
    "guardduty": "boto3.guardduty",
    "iam": "boto3.iam",
    "identitycenter": "boto3.sso-admin",
    "identitystore": "boto3.identitystore",
    "inspector": "boto3.inspector2",
    "inspector2": "boto3.inspector2",
    "kafka": "boto3.kafka",
    "keyspaces": "boto3.keyspaces",
    "kinesis": "boto3.kinesis",
    "kinesisanalytics": "boto3.kinesisanalyticsv2",
    "kinesisfirehose": "boto3.firehose",
    "kinesisvideostreams": "boto3.kinesisvideo",
    "kms": "boto3.kms",
    "lakeformation": "boto3.lakeformation",
    "lambda": "boto3.lambda",
    "lightsail": "boto3.lightsail",
    "macie": "boto3.macie2",
    "mq": "boto3.mq",
    "neptune": "boto3.neptune",
    "networkfirewall": "boto3.network-firewall",
    "opensearch": "boto3.opensearch",
    "organizations": "boto3.organizations",
    "parameterstore": "boto3.ssm",
    "quicksight": "boto3.quicksight",
    "rds": "boto3.rds",
    "redshift": "boto3.redshift",
    "route53": "boto3.route53",
    "s3": "boto3.s3",
    "sagemaker": "boto3.sagemaker",
    "savingsplans": "boto3.savingsplans",
    "secretsmanager": "boto3.secretsmanager",
    "securityhub": "boto3.securityhub",
    "servicecatalog": "boto3.servicecatalog",
    "ses": "boto3.ses",
    "shield": "boto3.shield",
    "sns": "boto3.sns",
    "sqs": "boto3.sqs",
    "ssm": "boto3.ssm",
    "sso": "boto3.sso-admin",
    "stepfunctions": "boto3.stepfunctions",
    "storagegateway": "boto3.storagegateway",
    "timestream": "boto3.timestream-query",
    "transfer": "boto3.transfer",
    "vpc": "boto3.ec2",
    "vpcflowlogs": "boto3.ec2",
    "waf": "boto3.waf",
    "wafv2": "boto3.wafv2",
    "wellarchitected": "boto3.wellarchitected",
    "workflows": "boto3.glue",
    "workspaces": "boto3.workspaces",
    "xray": "boto3.xray",
}

AZURE_CLIENT = {
    "aad": "msgraph-sdk-python",
    "ad": "msgraph-sdk-python",
    "aisearch": "azure.mgmt.search",
    "aks": "azure.mgmt.containerservice",
    "api": "azure.mgmt.apimanagement",
    "app": "azure.mgmt.web",
    "application": "azure.mgmt.applicationinsights",
    "appservice": "azure.mgmt.web",
    "automation": "azure.mgmt.automation",
    "backup": "azure.mgmt.recoveryservices",
    "batch": "azure.mgmt.batch",
    "billing": "azure.mgmt.billing",
    "cache": "azure.mgmt.redis",
    "cdn": "azure.mgmt.cdn",
    "compute": "azure.mgmt.compute",
    "config": "azure.mgmt.policyinsights",
    "container": "azure.mgmt.containerinstance",
    "containerregistry": "azure.mgmt.containerregistry",
    "cosmos": "azure.mgmt.cosmosdb",
    "cosmosdb": "azure.mgmt.cosmosdb",
    "cost": "azure.mgmt.costmanagement",
    "data": "azure.mgmt.datafactory",
    "databricks": "azure.mgmt.databricks",
    "dataprotection": "azure.mgmt.dataprotection",
    "defender": "azure.mgmt.security",
    "disk": "azure.mgmt.compute",
    "dns": "azure.mgmt.dns",
    "entra": "msgraph-sdk-python",
    "entrad": "msgraph-sdk-python",
    "event": "azure.mgmt.eventhub",
    "front": "azure.mgmt.frontdoor",
    "function": "azure.mgmt.web",
    "functionapp": "azure.mgmt.web",
    "functions": "azure.mgmt.web",
    "graph": "msgraph-sdk-python",
    "hdinsight": "azure.mgmt.hdinsight",
    "iam": "azure.mgmt.authorization",
    "intune": "msgraph-sdk-python",
    "iot": "azure.mgmt.iothub",
    "key": "azure.mgmt.keyvault",
    "keyvault": "azure.mgmt.keyvault",
    "kubernetes": "azure.mgmt.containerservice",
    "kusto": "azure.mgmt.kusto",
    "load": "azure.mgmt.network",
    "loadbalancer": "azure.mgmt.network",
    "loganalytics": "azure.mgmt.loganalytics",
    "logic": "azure.mgmt.logic",
    "machine": "azure.mgmt.machinelearningservices",
    "managedidentity": "azure.mgmt.msi",
    "management": "azure.mgmt.managementgroups",
    "managementgroup": "azure.mgmt.managementgroups",
    "mariadb": "azure.mgmt.rdbms",
    "monitor": "azure.mgmt.monitor",
    "mysql": "azure.mgmt.rdbms.mysql_flexibleservers",
    "network": "azure.mgmt.network",
    "networksecuritygroup": "azure.mgmt.network",
    "notification": "azure.mgmt.notificationhubs",
    "policy": "azure.mgmt.resource.policy",
    "postgresql": "azure.mgmt.rdbms.postgresql_flexibleservers",
    "power": "azure.mgmt.powerbidedicated",
    "purview": "azure.mgmt.purview",
    "rbac": "azure.mgmt.authorization",
    "recoveryservices": "azure.mgmt.recoveryservices",
    "redis": "azure.mgmt.redis",
    "resource": "azure.mgmt.resource",
    "search": "azure.mgmt.search",
    "security": "azure.mgmt.security",
    "servicebus": "azure.mgmt.servicebus",
    "signalr": "azure.mgmt.signalr",
    "site": "azure.mgmt.recoveryservices",
    "sql": "azure.mgmt.sql",
    "storage": "azure.mgmt.storage",
    "streamanalytics": "azure.mgmt.streamanalytics",
    "subscription": "azure.mgmt.subscription",
    "synapse": "azure.mgmt.synapse",
    "traffic": "azure.mgmt.trafficmanager",
    "virtualmachines": "azure.mgmt.compute",
    "vm": "azure.mgmt.compute",
    "vpn": "azure.mgmt.network",
    "webapp": "azure.mgmt.web",
}

GCP_CLIENT = {
    "accessapproval": "google.cloud.accessapproval_v1",
    "accesscontextmanager": "google.cloud.accesscontextmanager_v1",
    "aiplatform": "google.cloud.aiplatform_v1",
    "apigateway": "google.cloud.apigateway_v1",
    "apigee": "google.cloud.apigee_v1",
    "apikeys": "google.cloud.apikeys_v2",
    "appengine": "google.cloud.appengine_admin_v1",
    "artifactregistry": "google.cloud.artifactregistry_v1",
    "audit": "google.cloud.logging_v2",
    "backupdr": "google.cloud.backupdr_v1",
    "bigquery": "google.cloud.bigquery",
    "bigtable": "google.cloud.bigtable_admin_v2",
    "billing": "google.cloud.billing_v1",
    "certificatemanager": "google.cloud.certificate_manager_v1",
    "ciem": "google.cloud.iam_v1",
    "cloudasset": "google.cloud.asset_v1",
    "cloudfunctions": "google.cloud.functions_v2",
    "cloudidentity": "google.cloud.identity_v1",
    "cloudkms": "google.cloud.kms_v1",
    "cloudrun": "google.cloud.run_v2",
    "cloudsql": "google.cloud.sql_v1",
    "compute": "google.cloud.compute_v1",
    "container": "google.cloud.container_v1",
    "data_access": "google.cloud.logging_v2",
    "datacatalog": "google.cloud.datacatalog_v1",
    "dataflow": "google.cloud.dataflow_v1beta3",
    "dataproc": "google.cloud.dataproc_v1",
    "datastudio": "google.cloud.looker_v1",
    "dlp": "google.cloud.dlp_v2",
    "dns": "google.cloud.dns_v1",
    "endpoints": "google.cloud.servicemanagement_v1",
    "essentialcontacts": "google.cloud.essential_contacts_v1",
    "filestore": "google.cloud.filestore_v1",
    "firestore": "google.cloud.firestore_v1",
    "flow": "google.cloud.compute_v1",
    "function": "google.cloud.functions_v2",
    "gcp": "google.cloud.logging_v2",        # log.gcp.* — log-based rules
    "gke": "google.cloud.container_v1",
    "gke_audit": "google.cloud.logging_v2",
    "healthcare": "google.cloud.healthcare_v1",
    "iam": "google.cloud.iam_v1",
    "kms": "google.cloud.kms_v1",
    "lb": "google.cloud.compute_v1",
    "logging": "google.cloud.logging_v2",
    "monitoring": "google.cloud.monitoring_v3",
    "notebooks": "google.cloud.notebooks_v1",
    "orgpolicy": "google.cloud.orgpolicy_v2",
    "osconfig": "google.cloud.osconfig_v1",
    "pubsub": "google.cloud.pubsub_v1",
    "resourcemanager": "google.cloud.resourcemanager_v3",
    "scc": "google.cloud.securitycenter_v1",
    "secretmanager": "google.cloud.secretmanager_v1",
    "security_command_center": "google.cloud.securitycenter_v1",
    "services": "google.cloud.serviceusage_v1",
    "spanner": "google.cloud.spanner_v1",
    "sql": "google.cloud.sql_v1",
    "storage": "google.cloud.storage",
    "trace": "google.cloud.trace_v1",
    "workflows": "google.cloud.workflows_v1",
}

OCI_CLIENT = {
    "ai_anomaly_detection": "oci.ai_anomaly_detection",
    "ai_language": "oci.ai_language",
    "analytics": "oci.analytics",
    "apigateway": "oci.apigateway",
    "artifacts": "oci.artifacts",
    "audit": "oci.audit",
    "bds": "oci.bds",
    "block_storage": "oci.core",
    "certificates": "oci.certificates",
    "cloud_guard": "oci.cloud_guard",
    "compute": "oci.core",
    "container_engine": "oci.container_engine",
    "container_instances": "oci.container_instances",
    "data_catalog": "oci.data_catalog",
    "data_flow": "oci.data_flow",
    "data_integration": "oci.data_integration",
    "data_safe": "oci.data_safe",
    "data_science": "oci.data_science",
    "database": "oci.database",
    "devops": "oci.devops",
    "dns": "oci.dns",
    "edge_services": "oci.waa",
    "events": "oci.events",
    "file_storage": "oci.file_storage",
    "functions": "oci.functions",
    "identity": "oci.identity",
    "key_management": "oci.key_management",
    "load_balancer": "oci.load_balancer",
    "logging": "oci.logging",
    "monitoring": "oci.monitoring",
    "mysql": "oci.mysql",
    "network_firewall": "oci.network_firewall",
    "nosql": "oci.nosql",
    "object_storage": "oci.object_storage",
    "ons": "oci.ons",
    "queue": "oci.queue",
    "redis": "oci.redis",
    "resource_manager": "oci.resource_manager",
    "streaming": "oci.streaming",
    "vault": "oci.vault",
    "virtual_network": "oci.core",
    "waf": "oci.waf",
}

K8S_CLIENT = {
    "admission": "kubernetes.AdmissionregistrationV1Api",
    "apiserver": "kubernetes.CoreV1Api",
    "audit": "kubernetes.CoreV1Api",
    "autoscaling": "kubernetes.AutoscalingV1Api",
    "certificate": "kubernetes.CertificatesV1Api",
    "cluster": "kubernetes.CoreV1Api",
    "clusterrole": "kubernetes.RbacAuthorizationV1Api",
    "clusterrolebinding": "kubernetes.RbacAuthorizationV1Api",
    "configmap": "kubernetes.CoreV1Api",
    "controlplane": "kubernetes.CoreV1Api",
    "cronjob": "kubernetes.BatchV1Api",
    "daemonset": "kubernetes.AppsV1Api",
    "deployment": "kubernetes.AppsV1Api",
    "disaster_recovery": "kubernetes.CoreV1Api",
    "etcd": "kubernetes.CoreV1Api",
    "event": "kubernetes.CoreV1Api",
    "federation": "kubernetes.CoreV1Api",
    "general": "kubernetes.CoreV1Api",
    "horizontalpodautoscaler": "kubernetes.AutoscalingV1Api",
    "image": "kubernetes.CoreV1Api",
    "ingress": "kubernetes.NetworkingV1Api",
    "inventory": "kubernetes.CoreV1Api",
    "job": "kubernetes.BatchV1Api",
    "kubelet": "kubernetes.CoreV1Api",
    "limitrange": "kubernetes.CoreV1Api",
    "monitoring": "kubernetes.CoreV1Api",
    "namespace": "kubernetes.CoreV1Api",
    "network": "kubernetes.NetworkingV1Api",
    "networkpolicy": "kubernetes.NetworkingV1Api",
    "node": "kubernetes.CoreV1Api",
    "persistentvolume": "kubernetes.CoreV1Api",
    "persistentvolumeclaim": "kubernetes.CoreV1Api",
    "pod": "kubernetes.CoreV1Api",
    "pod_security": "kubernetes.CoreV1Api",
    "podtemplate": "kubernetes.CoreV1Api",
    "policy": "kubernetes.PolicyV1Api",
    "rbac": "kubernetes.RbacAuthorizationV1Api",
    "replicaset": "kubernetes.AppsV1Api",
    "resource": "kubernetes.CoreV1Api",
    "resourcequota": "kubernetes.CoreV1Api",
    "role": "kubernetes.RbacAuthorizationV1Api",
    "rolebinding": "kubernetes.RbacAuthorizationV1Api",
    "scheduler": "kubernetes.CoreV1Api",
    "secret": "kubernetes.CoreV1Api",
    "service": "kubernetes.CoreV1Api",
    "serviceaccount": "kubernetes.CoreV1Api",
    "software": "kubernetes.CoreV1Api",
    "statefulset": "kubernetes.AppsV1Api",
    "storage": "kubernetes.StorageV1Api",
    "storageclass": "kubernetes.StorageV1Api",
    "workload": "kubernetes.CoreV1Api",
}

ALICLOUD_CLIENT = {
    "accessanalyzer": "alibabacloud_ram20150501",
    "ack": "alibabacloud_cs20151215",
    "actiontrail": "alibabacloud_actiontrail20200706",
    "alb": "alibabacloud_alb20200616",
    "analyticdb": "alibabacloud_adb20190315",
    "api": "alibabacloud_cloudapi20160714",
    "apigateway": "alibabacloud_cloudapi20160714",
    "apikeys": "alibabacloud_cloudapi20160714",
    "apsaradb": "alibabacloud_rds20140815",
    "apsaramq": "alibabacloud_alikafka20190916",
    "apsaravideo": "alibabacloud_vod20170321",
    "arms": "alibabacloud_arms20190808",
    "artifacts": "alibabacloud_cr20181201",
    "bss": "alibabacloud_bssopenapi20171214",
    "cas": "alibabacloud_cas20180713",
    "cdn": "alibabacloud_cdn20180510",
    "cen": "alibabacloud_cbn20170912",
    "cfw": "alibabacloud_cloudfw20171207",
    "cloudfw": "alibabacloud_cloudfw20171207",
    "cloudmonitor": "alibabacloud_cms20190101",
    "cms": "alibabacloud_cms20190101",
    "config": "alibabacloud_config20200907",
    "cr": "alibabacloud_cr20181201",
    "data": "alibabacloud_dataworks20200518",
    "datahub": "alibabacloud_datahub20190101",
    "dataworks": "alibabacloud_dataworks20200518",
    "ddos": "alibabacloud_ddospro20170201",
    "dedicated": "alibabacloud_ecs20140526",
    "devops": "alibabacloud_devops20210625",
    "dlf": "alibabacloud_datalake_formation20210901",
    "dms": "alibabacloud_dms_enterprise20181101",
    "dns": "alibabacloud_alidns20150109",
    "dts": "alibabacloud_dts20200101",
    "ecs": "alibabacloud_ecs20140526",
    "efs": "alibabacloud_dbfs20200418",
    "eip": "alibabacloud_vpc20160428",
    "elasticsearch": "alibabacloud_elasticsearch20170613",
    "emr": "alibabacloud_emr20160408",
    "ess": "alibabacloud_ess20140828",
    "eventbridge": "alibabacloud_eventbridge20200401",
    "expressconnect": "alibabacloud_vpc20160428",
    "fc": "alibabacloud_fc_open20210406",
    "general": "alibabacloud_ecs20140526",
    "gtm": "alibabacloud_alidns20150109",
    "hbr": "alibabacloud_hbr20170908",
    "hologres": "alibabacloud_hologres20200601",
    "ims": "alibabacloud_ims20190815",
    "kms": "alibabacloud_kms20160120",
    "nas": "alibabacloud_nas20170626",
    "oss": "alibabacloud_oss20190517",
    "polardb": "alibabacloud_polardb20170801",
    "ram": "alibabacloud_ram20150501",
    "rds": "alibabacloud_rds20140815",
    "redis": "alibabacloud_r_kvstore20150101",
    "sas": "alibabacloud_sas20181203",
    "slb": "alibabacloud_slb20140515",
    "sls": "alibabacloud_log20201230",
    "vpc": "alibabacloud_vpc20160428",
    "waf": "alibabacloud_waf_openapi20211001",
}

CSP_MAPS = {
    "aws": AWS_CLIENT,
    "azure": AZURE_CLIENT,
    "gcp": GCP_CLIENT,
    "oci": OCI_CLIENT,
    "k8s": K8S_CLIENT,
    "alicloud": ALICLOUD_CLIENT,
}

# ═══════════════════════════════════════════════════════════
#  Cross-service check patterns
#  (check_leaf_prefix → override check_client)
#  Only applied for AWS where cross-service calls are well-defined.
#  The pattern must NOT match when the primary service already IS that client.
# ═══════════════════════════════════════════════════════════

# Order matters — first match wins
AWS_CROSS_SERVICE: list[tuple[str, str]] = [
    # KMS key-specific checks (call kms.describe_key / kms.get_key_rotation_status)
    ("kms_key_rotation", "boto3.kms"),
    ("kms_key_policy", "boto3.kms"),
    ("kms_key_expiration", "boto3.kms"),
    ("kms_key_deletion", "boto3.kms"),
    ("kms_cmk_encryption_in_secrets", "boto3.kms"),
    # IAM role/policy checks (call iam.list_attached_role_policies etc.)
    ("execution_roles_least_privilege", "boto3.iam"),
    ("execution_role_least_privilege", "boto3.iam"),
    ("execution_role_no_admin", "boto3.iam"),
    ("instance_profile_least_privilege", "boto3.iam"),
    ("iam_role_least_privilege", "boto3.iam"),
    ("iam_role_compliance", "boto3.iam"),
    # CloudTrail account-level checks
    ("cloudtrail_management_and_data_logging", "boto3.cloudtrail"),
    # GuardDuty account-level
    ("guardduty_enabled", "boto3.guardduty"),
    ("guardduty_centrally_managed", "boto3.guardduty"),
    # SecurityHub account-level
    ("securityhub_enabled", "boto3.securityhub"),
    # Macie
    ("macie_enabled", "boto3.macie2"),
    ("macie_policy", "boto3.macie2"),
    # Inspector
    ("inspector_agents_or_scanners", "boto3.inspector2"),
    # Config
    ("config_enabled", "boto3.config"),
]

# GCP cross-service patterns
GCP_CROSS_SERVICE: list[tuple[str, str]] = [
    ("iam_binding", "google.cloud.iam_v1"),
    ("iam_policy", "google.cloud.iam_v1"),
    ("kms_key_rotation", "google.cloud.kms_v1"),
    ("kms_cmek", "google.cloud.kms_v1"),
    ("cloudkms", "google.cloud.kms_v1"),
    ("audit_logging", "google.cloud.logging_v2"),
    ("audit_config", "google.cloud.logging_v2"),
    ("scc_finding", "google.cloud.securitycenter_v1"),
]

# OCI cross-service patterns
OCI_CROSS_SERVICE: list[tuple[str, str]] = [
    ("iam_policy", "oci.identity"),
    ("kms_key", "oci.key_management"),
    ("audit_log", "oci.audit"),
    ("cloud_guard", "oci.cloud_guard"),
]

# AliCloud cross-service patterns
ALICLOUD_CROSS_SERVICE: list[tuple[str, str]] = [
    ("ram_policy", "alibabacloud_ram20150501"),
    ("ram_role", "alibabacloud_ram20150501"),
    ("kms_key", "alibabacloud_kms20160120"),
    ("actiontrail", "alibabacloud_actiontrail20200706"),
    ("cloudmonitor", "alibabacloud_cms20190101"),
    ("sas_", "alibabacloud_sas20181203"),
]

CSP_CROSS_SERVICE = {
    "aws": AWS_CROSS_SERVICE,
    "gcp": GCP_CROSS_SERVICE,
    "oci": OCI_CROSS_SERVICE,
    "alicloud": ALICLOUD_CROSS_SERVICE,
}

# ═══════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════

def get_csp(rule_id: str) -> str:
    """Extract CSP prefix from rule_id (handles log.gcp.* too)."""
    prefix = rule_id.split(".")[0]
    if prefix == "log":
        return rule_id.split(".")[1]  # log.gcp.* → gcp
    return prefix


def get_service(rule_id: str) -> str:
    """Extract service segment. log.gcp.SERVICE.* → SERVICE, else csp.SERVICE.*"""
    parts = rule_id.split(".")
    if parts[0] == "log":
        return parts[2] if len(parts) > 2 else "unknown"
    return parts[1] if len(parts) > 1 else "unknown"


def get_check_leaf(rule_id: str) -> str:
    """Last segment of rule_id — the specific check name."""
    return rule_id.split(".")[-1]


def resolve_primary_client(csp: str, service: str) -> str:
    cmap = CSP_MAPS.get(csp, {})
    return cmap.get(service, f"{csp}.UNKNOWN.{service}")


def resolve_check_client(csp: str, primary_client: str, check_leaf: str) -> str:
    """
    Returns the check_client — the SDK client whose API is called to evaluate
    the condition. Defaults to primary_client when no cross-service pattern matches.
    """
    patterns = CSP_CROSS_SERVICE.get(csp, [])
    lower = check_leaf.lower()
    for pattern, override_client in patterns:
        if pattern in lower and override_client != primary_client:
            return override_client
    return primary_client


# ═══════════════════════════════════════════════════════════
#  YAML walker
# ═══════════════════════════════════════════════════════════

def collect_all(node) -> list[dict]:
    result = []
    if isinstance(node, dict):
        if "rule_id" in node:
            result.append(node)
        else:
            for v in node.values():
                result.extend(collect_all(v))
    elif isinstance(node, list):
        for item in node:
            result.extend(collect_all(item))
    return result


# ═══════════════════════════════════════════════════════════
#  Deduplication
# ═══════════════════════════════════════════════════════════

def find_duplicates(rules: list[dict]) -> dict[str, str]:
    """
    Within one CSP, group by (check_client, check_leaf).
    For cross-service groups (check_client != primary_client for all members),
    pick a canonical and mark the rest as duplicates.

    Returns: { rule_id → canonical_rule_id } for duplicate rules only.
             The canonical rule_id maps to itself (not included in output).
    """
    # group key → list of rule entries
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for r in rules:
        cc = r.get("check_client", "")
        pc = r.get("python_client", "")
        if cc and cc != pc:  # only cross-service
            key = (cc, r.get("check_leaf", ""))
            groups[key].append(r)

    duplicates: dict[str, str] = {}
    for (cc, leaf), members in groups.items():
        if len(members) < 2:
            continue
        # Pick canonical: prefer the rule whose primary service IS the check_client
        # (e.g., for check_client=boto3.iam, prefer a rule from service=iam)
        cc_service = cc.split(".")[-1]  # boto3.iam → iam, google.cloud.iam_v1 → iam_v1
        canonical = None
        for m in members:
            m_svc = get_service(m["rule_id"])
            if cc_service in m_svc or m_svc in cc_service:
                canonical = m["rule_id"]
                break
        if canonical is None:
            # fallback: alphabetically first
            canonical = min(m["rule_id"] for m in members)
        for m in members:
            if m["rule_id"] != canonical:
                duplicates[m["rule_id"]] = canonical

    return duplicates


# ═══════════════════════════════════════════════════════════
#  Main processing
# ═══════════════════════════════════════════════════════════

def process_file(path: Path) -> tuple[int, dict, list[dict]]:
    data = yaml.safe_load(path.read_text())
    csp_tag = path.stem.split("_")[1].lower()   # e.g. "aws", "azure"

    rules = collect_all(data)

    # Pass 1: assign python_client, check_client, check_leaf
    for r in rules:
        rid = r["rule_id"]
        csp = get_csp(rid)
        svc = get_service(rid)
        leaf = get_check_leaf(rid)
        pc = resolve_primary_client(csp, svc)
        cc = resolve_check_client(csp, pc, leaf)
        r["python_client"] = pc
        r["check_client"] = cc
        r["check_leaf"] = leaf   # temp field for dedup; removed before write

    # Pass 2: find duplicates
    dups = find_duplicates(rules)
    for r in rules:
        rid = r["rule_id"]
        if rid in dups:
            r["is_duplicate"] = True
            r["canonical_rule_id"] = dups[rid]
        else:
            r.pop("is_duplicate", None)
            r.pop("canonical_rule_id", None)

    # Remove temp field before write
    for r in rules:
        r.pop("check_leaf", None)

    # Rewrite YAML
    text = path.read_text()
    lines = text.splitlines()
    header_end = 0
    for i, line in enumerate(lines):
        if line.startswith("#") or line.strip() == "":
            header_end = i + 1
        else:
            break
    header = "\n".join(lines[:header_end])
    body = yaml.safe_dump(data, sort_keys=False, default_flow_style=False,
                          allow_unicode=True, width=200)
    path.write_text(header.rstrip() + "\n\n" + body)

    from collections import Counter
    counts = Counter(r.get("python_client") for r in rules)
    return len(rules), dict(counts), [
        {**r, "csp": csp_tag}
        for r in rules
        if r.get("is_duplicate")
    ]


# ═══════════════════════════════════════════════════════════
#  Reports
# ═══════════════════════════════════════════════════════════

def write_report(all_dups: list[dict], all_client_counts: dict) -> None:
    md = ROOT / "client_dedup_report.md"
    csv_path = ROOT / "client_groups.csv"

    lines = [
        "# Client Categorization + Deduplication Report",
        "",
        "Generated by `categorize_by_client.py`.",
        "",
        "## Summary",
        "",
        "| CSP | Total rules | Unique clients | Cross-service duplicates |",
        "|-----|----------:|---------------:|--------------------------:|",
    ]
    grand_total = grand_dups = 0
    for csp, counts in all_client_counts.items():
        total = sum(counts.values())
        n_clients = len(counts)
        n_dups = sum(1 for d in all_dups if d.get("csp") == csp)
        lines.append(f"| {csp} | {total} | {n_clients} | {n_dups} |")
        grand_total += total
        grand_dups += n_dups
    lines.append(f"| **Total** | **{grand_total}** | — | **{grand_dups}** |")

    lines += [
        "",
        "## Cross-Service Duplicates",
        "",
        "Rules whose `check_client` differs from `python_client` and share",
        "the same check leaf with another service. One canonical is kept;",
        "duplicates share the same generated check function.",
        "",
        "| Duplicate rule_id | Canonical rule_id | check_client |",
        "|---|---|---|",
    ]
    for d in sorted(all_dups, key=lambda x: x["rule_id"]):
        lines.append(
            f"| `{d['rule_id']}` "
            f"| `{d.get('canonical_rule_id', '')}` "
            f"| `{d.get('check_client', '')}` |"
        )

    md.write_text("\n".join(lines) + "\n")

    # CSV: full rule × client detail
    # Collect all rules for CSV (re-read since YAML already written)
    all_rows = []
    for path in FILES:
        data = yaml.safe_load(path.read_text())
        rules = collect_all(data)
        csp = path.stem.split("_")[1].lower()
        for r in rules:
            all_rows.append({
                "csp": csp,
                "rule_id": r.get("rule_id", ""),
                "python_client": r.get("python_client", ""),
                "check_client": r.get("check_client", ""),
                "implementable": r.get("implementable", ""),
                "severity": r.get("severity", ""),
                "is_duplicate": r.get("is_duplicate", False),
                "canonical_rule_id": r.get("canonical_rule_id", ""),
            })
    with open(csv_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(all_rows[0].keys()))
        w.writeheader()
        w.writerows(all_rows)

    print(f"Reports written:\n  {md}\n  {csv_path}")


# ═══════════════════════════════════════════════════════════
#  Entry point
# ═══════════════════════════════════════════════════════════

def main() -> None:
    all_dups: list[dict] = []
    all_client_counts: dict[str, dict] = {}

    for path in FILES:
        csp = path.stem.split("_")[1].upper()
        print(f"[{csp}] processing {path.name} …")
        total, counts, dups = process_file(path)
        all_dups.extend(dups)
        csp_lower = csp.lower()
        all_client_counts[csp_lower] = counts
        n_unique = len(counts)
        print(f"  → {total} rules, {n_unique} clients, {len(dups)} cross-service duplicates")

    write_report(all_dups, all_client_counts)
    print(f"\nTotal cross-service duplicates: {len(all_dups)}")


if __name__ == "__main__":
    main()
