"""
Security Graph Builder — Populates Neo4j from PostgreSQL inventory + threat data.

Creates a Wiz-style security graph with:
  - Resource nodes  (S3Bucket, IAMRole, IAMPolicy, SecurityGroup, Lambda, etc.)
  - Threat nodes    (ThreatDetection overlaid on resources)
  - Finding nodes   (MisconfigFinding per rule violation)
  - Relationship edges (REFERENCES, RELATES_TO, HAS_THREAT, HAS_FINDING, etc.)
  - Virtual nodes   (Internet, Account, Region) for reachability analysis

Node labels map resource types → graph-friendly labels across all CSPs:

  AWS:
    s3.resource / s3.bucket  → S3Bucket
    iam.role                 → IAMRole
    iam.policy               → IAMPolicy
    iam.user                 → IAMUser
    iam.group                → IAMGroup
    iam.instance-profile     → InstanceProfile
    ec2.security-group       → SecurityGroup
    ec2.instance             → EC2Instance
    ec2.volume               → EBSVolume
    ec2.network-interface    → NetworkInterface
    lambda.resource          → LambdaFunction
    vpc.subnet               → Subnet
    vpc.vpc                  → VPC
    rds.instance             → RDSInstance
    eks.cluster              → EKSCluster
    kms.key                  → KMSKey

  Azure:
    azure.storage_account        → StorageAccount
    azure.blob_container         → BlobContainer
    azure.virtual_machine        → VirtualMachine
    azure.network_security_group → NetworkSecurityGroup
    azure.sql_server             → SQLServer
    azure.sql_database           → SQLDatabase
    azure.key_vault              → KeyVault
    azure.app_service            → AppService
    azure.function_app           → FunctionApp
    azure.aks_cluster            → AKSCluster
    azure.managed_identity       → ManagedIdentity
    azure.resource_group         → ResourceGroup
    azure.subscription           → AzureSubscription

  GCP:
    gcp.gcs_bucket           → GCSBucket
    gcp.compute_instance     → ComputeInstance
    gcp.vpc_network          → VPCNetwork
    gcp.vpc_firewall_rule    → VPCFirewallRule
    gcp.iam_service_account  → ServiceAccount
    gcp.cloud_function       → CloudFunction
    gcp.gke_cluster          → GKECluster
    gcp.cloud_sql_instance   → CloudSQLInstance
    gcp.kms_key_ring         → KMSKeyRing
    gcp.bigquery_dataset     → BigQueryDataset
    gcp.pubsub_topic         → PubSubTopic

  OCI:
    oci.compute_instance          → OCIComputeInstance
    oci.object_storage_bucket     → ObjectStorageBucket
    oci.vcn                       → VCN
    oci.security_list             → SecurityList
    oci.network_security_group    → OCINetworkSecurityGroup
    oci.autonomous_database       → AutonomousDatabase

  K8s:
    k8s.pod            → K8sPod
    k8s.deployment     → K8sDeployment
    k8s.service        → K8sService
    k8s.namespace      → K8sNamespace
    k8s.serviceaccount → K8sServiceAccount
    k8s.ingress        → K8sIngress
"""

from __future__ import annotations

import logging
import os
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ── Resource type → Neo4j label mapping ──────────────────────────────────────
# Covers AWS, Azure, GCP, OCI, K8s. Falls back to "CloudResource" for unknowns.
RESOURCE_TYPE_LABELS: Dict[str, str] = {
    # ── AWS ──────────────────────────────────────────────────────────────────
    "s3.resource": "S3Bucket",
    "s3.bucket": "S3Bucket",
    "s3": "S3Bucket",
    "iam.role": "IAMRole",
    "iam.policy": "IAMPolicy",
    "iam.user": "IAMUser",
    "iam.group": "IAMGroup",
    "iam.instance-profile": "InstanceProfile",
    "iam.iam-instance-profile-association": "InstanceProfileAssociation",
    "ec2.security-group": "SecurityGroup",
    "ec2.iam-instance-profile-association": "InstanceProfileAssociation",
    "ec2.instance": "EC2Instance",
    "ec2.volume": "EBSVolume",
    "ec2.network-interface": "NetworkInterface",
    "ec2.subnet": "Subnet",
    "ec2.vpc": "VPC",
    "lambda.resource": "LambdaFunction",
    "lambda.function": "LambdaFunction",
    "vpc.subnet": "Subnet",
    "vpc.vpc": "VPC",
    "vpc.internet-gateway": "InternetGateway",
    "vpc.nat-gateway": "NATGateway",
    "rds.instance": "RDSInstance",
    "rds.db-instance": "RDSInstance",
    "rds.cluster": "RDSCluster",
    "eks.cluster": "EKSCluster",
    "kms.key": "KMSKey",
    "kms.alias": "KMSAlias",
    "cloudtrail.trail": "CloudTrailTrail",
    # ── AWS AI/ML ─────────────────────────────────────────────────────────────
    "bedrock.foundation-model": "BedrockModel",
    "bedrock.inference-profile": "BedrockModel",
    "bedrock.default-prompt-router": "BedrockModel",
    "bedrock.agent": "BedrockAgent",
    "sagemaker.notebook-instance": "SageMakerNotebook",
    "sagemaker.training-job": "SageMakerTrainingJob",
    "sagemaker.model": "SageMakerModel",
    "sagemaker.endpoint": "SageMakerEndpoint",
    "sagemaker.hub": "SageMakerHub",
    # ── AWS Security / Secrets ─────────────────────────────────────────────────
    "secretsmanager.secret": "SecretsManagerSecret",
    "ssm.parameter": "SSMParameter",
    # ── AWS Analytics ─────────────────────────────────────────────────────────
    "athena.workgroup": "AthenaWorkgroup",
    "glue.database": "GlueDatabase",
    "glue.table": "GlueTable",
    "redshift.cluster": "RedshiftCluster",
    "redshift.resource": "RedshiftCluster",
    "emr.cluster": "EMRCluster",
    # ── AWS Queues/Streams (lateral movement data) ──────────────────────────
    "sqs.queue": "SQSQueue",
    "sns.topic": "SNSTopic",
    "secretsmanager.secret": "SecretsManagerSecret",
    "elasticloadbalancing.loadbalancer": "LoadBalancer",
    "elasticloadbalancingv2.loadbalancer": "LoadBalancer",
    "elbv2.loadbalancer": "LoadBalancer",
    "elb.loadbalancer": "LoadBalancer",
    "dynamodb.table": "DynamoDBTable",
    "dynamodb.resource": "DynamoDBTable",
    "rds.cluster": "RDSCluster",
    "rds.db-cluster": "RDSCluster",
    "elasticache.cluster": "ElastiCacheCluster",
    "elasticache.replication-group": "ElastiCacheCluster",
    "redshift.cluster": "RedshiftCluster",
    "redshift.resource": "RedshiftCluster",
    "efs.file-system": "EFSFileSystem",
    "elasticfilesystem.file-system": "EFSFileSystem",
    "docdb.cluster": "DocumentDBCluster",
    "docdb.resource": "DocumentDBCluster",
    "neptune.cluster": "NeptuneCluster",
    "neptune.resource": "NeptuneCluster",
    "secretsmanager.secret": "SecretsManagerSecret",
    "glacier.vault": "GlacierVault",
    "glacier.vaults": "GlacierVault",
    "ssm.parameter": "SSMParameter",
    "apigateway.restapi": "APIGateway",
    "apigateway.resource": "APIGateway",
    "cloudfront.distribution": "CloudFrontDistribution",
    "wafv2.web-acl": "WAFWebACL",
    "guardduty.detector": "GuardDutyDetector",
    "securityhub.hub": "SecurityHub",
    # ── Azure ─────────���──────────────────────────────────────────────────────
    "azure.storage_account": "StorageAccount",
    "azure.blob_container": "BlobContainer",
    "azure.virtual_machine": "VirtualMachine",
    "azure.network_security_group": "NetworkSecurityGroup",
    "azure.sql_server": "SQLServer",
    "azure.sql_database": "SQLDatabase",
    "azure.key_vault": "KeyVault",
    "azure.app_service": "AppService",
    "azure.function_app": "FunctionApp",
    "azure.aks_cluster": "AKSCluster",
    "azure.managed_identity": "ManagedIdentity",
    "azure.service_principal": "ServicePrincipal",
    "azure.resource_group": "ResourceGroup",
    "azure.subscription": "AzureSubscription",
    "azure.virtual_network": "VirtualNetwork",
    "azure.subnet": "AzureSubnet",
    "azure.public_ip_address": "PublicIPAddress",
    "azure.load_balancer": "AzureLoadBalancer",
    "azure.application_gateway": "ApplicationGateway",
    "azure.cosmos_db": "CosmosDB",
    "azure.service_bus": "ServiceBus",
    "azure.event_hub": "EventHub",
    "azure.container_registry": "ContainerRegistry",
    "azure.monitor_log_analytics": "LogAnalytics",
    # ── GCP ──────────────────────────────────────────────────────────────────
    "gcp.gcs_bucket": "GCSBucket",
    "gcp.compute_instance": "ComputeInstance",
    "gcp.vpc_network": "VPCNetwork",
    "gcp.vpc_firewall_rule": "VPCFirewallRule",
    "gcp.firewall": "VPCFirewallRule",
    "gcp.iam_service_account": "ServiceAccount",
    "gcp.service_account": "ServiceAccount",
    "gcp.cloud_function": "CloudFunction",
    "gcp.gke_cluster": "GKECluster",
    "gcp.cloud_sql_instance": "CloudSQLInstance",
    "gcp.kms_key_ring": "KMSKeyRing",
    "gcp.kms_crypto_key": "KMSCryptoKey",
    "gcp.bigquery_dataset": "BigQueryDataset",
    "gcp.bigquery_table": "BigQueryTable",
    "gcp.pubsub_topic": "PubSubTopic",
    "gcp.pubsub_subscription": "PubSubSubscription",
    "gcp.cloud_run_service": "CloudRunService",
    "gcp.artifact_registry": "ArtifactRegistry",
    "gcp.logging_sink": "LoggingSink",
    # ── OCI ──────────────────────────────────────────────────────────────────
    "oci.compute_instance": "OCIComputeInstance",
    "oci.object_storage_bucket": "ObjectStorageBucket",
    "oci.vcn": "VCN",
    "oci.security_list": "SecurityList",
    "oci.network_security_group": "OCINetworkSecurityGroup",
    "oci.autonomous_database": "AutonomousDatabase",
    "oci.vault": "OCIVault",
    "oci.compartment": "Compartment",
    # ── K8s ──────────────────────────────────────────────────────────────────
    "k8s.pod": "K8sPod",
    "k8s.deployment": "K8sDeployment",
    "k8s.service": "K8sService",
    "k8s.namespace": "K8sNamespace",
    "k8s.serviceaccount": "K8sServiceAccount",
    "k8s.ingress": "K8sIngress",
    "k8s.configmap": "K8sConfigMap",
    "k8s.secret": "K8sSecret",
    "k8s.role": "K8sRole",
    "k8s.clusterrole": "K8sClusterRole",
    "k8s.rolebinding": "K8sRoleBinding",
    "k8s.clusterrolebinding": "K8sClusterRoleBinding",
    "k8s.networkpolicy": "K8sNetworkPolicy",
    "k8s.daemonset": "K8sDaemonSet",
    "k8s.statefulset": "K8sStatefulSet",
    "k8s.job": "K8sJob",
    "k8s.cronjob": "K8sCronJob",
    "k8s.persistentvolumeclaim": "K8sPVC",
    "k8s.persistentvolume": "K8sPV",
    # ── Azure (additional) ────────────────────────────────────────────────────
    "azure.log_analytics_workspace": "LogAnalyticsWorkspace",
    "azure.disk": "AzureDisk",
    "azure.snapshot": "AzureSnapshot",
    "azure.availability_set": "AvailabilitySet",
    "azure.vmss": "VMSS",
    "azure.public_ip": "PublicIP",
    "azure.load_balancer": "LoadBalancer",
    "azure.application_gateway": "ApplicationGateway",
    "azure.dns_zone": "DNSZone",
    "azure.app_service_plan": "AppServicePlan",
    "azure.container_registry": "ContainerRegistry",
    "azure.role_assignment": "RoleAssignment",
    "azure.role_definition": "RoleDefinition",
    "azure.cosmosdb": "CosmosDB",
    "azure.servicebus": "ServiceBus",
    "azure.eventhub": "EventHub",
    "azure.logic_app": "LogicApp",
    "azure.activity_log_alert": "ActivityLogAlert",
    "azure.defender_pricing": "DefenderPricing",
    "azure.security_contact": "SecurityContact",
    "azure.diagnostic_setting": "DiagnosticSetting",
    # ── GCP (additional) ─────────────────────────────────────────────────────
    "gcp.kms_key_ring": "KMSKeyRing",
    "gcp.kms_crypto_key": "KMSCryptoKey",
    "gcp.vpc_subnetwork": "VPCSubnetwork",
    "gcp.compute_disk": "ComputeDisk",
    "gcp.backend_service": "BackendService",
    "gcp.forwarding_rule": "ForwardingRule",
    "gcp.cloud_run_service": "CloudRunService",
    "gcp.dns_zone": "DNSZone",
    "gcp.log_sink": "LogSink",
    "gcp.alert_policy": "AlertPolicy",
    "gcp.secret": "GCPSecret",
    "gcp.redis_instance": "RedisInstance",
    "gcp.spanner_instance": "SpannerInstance",
    "gcp.bigtable_instance": "BigtableInstance",
    "gcp.pubsub_subscription": "PubSubSubscription",
}


def _neo4j_label(resource_type: str) -> str:
    """Map resource type to Neo4j node label.

    AWS dot-notation:  'ec2.instance'   → 'EC2Instance'  (derives PascalCase)
    Azure/GCP/K8s:     'VirtualMachine' → 'VirtualMachine' (already PascalCase — use as-is)
    Empty:             ''               → 'Resource'

    Falls back to a derived label for unmapped dot-notation types:
      azure.X → CamelCase(X)           e.g. "azure.sql_server" → "SQLServer"
      gcp.X   → GcpCamelCase(X)        e.g. "gcp.gcs_bucket" → "GcpGcsBucket"
      k8s.X   → K8sCamelCase(X)        e.g. "k8s.daemon_set" → "K8sDaemonSet"
      oci.X   → OciCamelCase(X)        e.g. "oci.block_volume" → "OciBlockVolume"
      ibm.X   → IbmCamelCase(X)
    """
    if not resource_type:
        return "Resource"

    if resource_type in RESOURCE_TYPE_LABELS:
        return RESOURCE_TYPE_LABELS[resource_type]

    # Derive label for unmapped dot-notation types (AWS/legacy CSP prefix format)
    if "." in resource_type:
        csp, _, rest = resource_type.partition(".")
        # snake_case → PascalCase
        pascal = "".join(w.capitalize() for w in rest.split("_"))
        _CSP_PREFIX = {"azure": "", "gcp": "Gcp", "k8s": "K8s",
                       "oci": "Oci", "ibm": "Ibm", "alicloud": "Ali"}
        prefix = _CSP_PREFIX.get(csp.lower(), csp.upper())
        return f"{prefix}{pascal}" if prefix else pascal

    # Azure/GCP/K8s types are already PascalCase — return as-is
    # e.g. "VirtualMachine", "GCEInstance", "Pod", "StorageAccount"
    return resource_type


# ── Relation type mapping ─────────────────────────────────────────────────────
# Maps inventory relation_type → Neo4j relationship type.
# Two edge kinds:
#   "path"        — attacker traversal edges (attack_path_category != None)
#   "association" — context edges (misconfigs, encryption, ownership, etc.)
_RELATION_TYPE_MAP: Dict[str, str] = {
    # Network / topology (context-inferred by _infer_rel_type)
    "contained_by": "_CONTEXT",        # overridden by _infer_rel_type()
    "attached_to":  "_CONTEXT",        # overridden by _infer_rel_type()
    # IAM / access — PATH edges
    "uses":               "ASSUMES",   # instance-profile → role, lambda → role
    "assumes":            "ASSUMES",
    "can_assume":         "ASSUMES",   # alias
    "can_access":         "CAN_ACCESS",
    "grants_access_to":   "CAN_ACCESS",
    # Data access — PATH edges
    "stores_data_in":     "STORES",
    "stores":             "STORES",
    "backs_up_to":        "STORES",
    "replicates_to":      "STORES",
    # Logging / audit — ASSOCIATION edges
    "logging_enabled_to": "LOGS_TO",
    "logged_to":          "LOGS_TO",
    # Encryption — ASSOCIATION edges
    "encrypted_by":       "ENCRYPTED_BY",
    # DNS / resolution — PATH edge (data_flow)
    "resolves_to":        "RESOLVES_TO",
    # Network membership — ASSOCIATION edge
    "member_of":          "MEMBER_OF",
    # Execution platform — PATH edge
    "runs_on":            "RUNS_ON",
    # Association-only edges (never followed for attack paths)
    "depends_on":         "DEPENDS_ON",
    "protects":           "PROTECTS",
    "owns":               "OWNS",
    "protected_by":       "PROTECTED_BY",
    "monitored_by":       "MONITORED_BY",
}

# Edges that define the attacker's traversal route
_PATH_REL_TYPES: frozenset = frozenset({
    "ASSUMES", "CAN_ACCESS", "ACCESSES", "STORES", "CONNECTS_TO",
    "HOSTED_IN", "IN_VPC", "RUNS_ON", "ROUTES_TO", "EXPOSES",
    "ATTACHED_TO", "RESOLVES_TO",
})

# Edges that provide context about a node (misconfigs, encryption, ownership)
_ASSOCIATION_REL_TYPES: frozenset = frozenset({
    "ENCRYPTED_BY", "LOGS_TO", "PROTECTED_BY", "DEPENDS_ON",
    "PROTECTS", "OWNS", "MEMBER_OF", "MONITORED_BY",
})


def _infer_rel_type(
    raw_type: str, from_type: str, to_type: str
) -> str:
    """Context-aware mapping for contained_by / attached_to based on resource types.

    The same inventory relation_type (e.g. 'contained_by') means different things
    depending on which resource types are involved:
      SG → VPC        = IN_VPC  (the SG belongs to the VPC)
      Subnet → VPC    = IN_VPC
      NACL → VPC      = IN_VPC
      EC2 → Subnet    = HOSTED_IN  (the instance sits in the subnet)
      EC2 → VPC       = IN_VPC
      Lambda → VPC    = IN_VPC
      Lambda → SG     = PROTECTED_BY
      Lambda → Subnet = HOSTED_IN
      EC2 → SG        = PROTECTED_BY
      EC2 → ENI       = CONNECTS_TO
      EC2 → Volume    = ATTACHED_TO  (data access path)
    """
    tt = (to_type or "").lower()

    # VPC containment
    if tt.endswith(".vpc") or tt == "ec2.vpc":
        return "IN_VPC"

    # Subnet hosting
    if tt.endswith(".subnet") or tt == "ec2.subnet":
        return "HOSTED_IN"

    # Security group protection
    if tt.endswith(".security-group") or tt == "ec2.security-group":
        return "PROTECTED_BY"

    # Network interface
    if "network-interface" in tt:
        return "CONNECTS_TO"

    # Volume attachment — PATH edge (data access)
    if "volume" in tt:
        return "ATTACHED_TO"

    # Default: look up the static map, fall back to uppercased raw
    mapped = _RELATION_TYPE_MAP.get(raw_type.lower())
    if mapped and not mapped.startswith("_"):
        return mapped
    return raw_type.upper().replace(" ", "_").replace("-", "_")


def _safe_props(d: Dict[str, Any], max_depth: int = 1) -> Dict[str, Any]:
    """Flatten a dict for Neo4j properties (Neo4j doesn't support nested maps)."""
    flat: Dict[str, Any] = {}
    for k, v in d.items():
        if v is None:
            continue
        if isinstance(v, (str, int, float, bool)):
            flat[k] = v
        elif isinstance(v, (list, tuple)):
            # Convert list to string if contains non-primitives
            if v and isinstance(v[0], dict):
                flat[k] = json.dumps(v)
            else:
                flat[k] = [str(x) for x in v]
        elif isinstance(v, dict) and max_depth > 0:
            for k2, v2 in v.items():
                if isinstance(v2, (str, int, float, bool)):
                    flat[f"{k}_{k2}"] = v2
        elif isinstance(v, datetime):
            flat[k] = v.isoformat()
        else:
            flat[k] = str(v)[:500]
    return flat


class SecurityGraphBuilder:
    """
    Builds and maintains the security graph in Neo4j.

    Usage:
        builder = SecurityGraphBuilder()
        stats = builder.build_graph(tenant_id="588989875114")
        print(stats)  # {"nodes_created": 350, "relationships_created": 850, ...}
    """

    def __init__(
        self,
        neo4j_uri: Optional[str] = None,
        neo4j_user: Optional[str] = None,
        neo4j_password: Optional[str] = None,
    ):
        self._uri = neo4j_uri or os.getenv("NEO4J_URI", "neo4j+s://17ec5cbb.databases.neo4j.io")
        self._user = neo4j_user or os.getenv("NEO4J_USER", "neo4j")
        self._password = neo4j_password or os.getenv("NEO4J_PASSWORD", "")
        self._driver = None

    def _get_driver(self):
        if self._driver is None:
            from neo4j import GraphDatabase
            self._driver = GraphDatabase.driver(
                self._uri, auth=(self._user, self._password)
            )
        return self._driver

    def close(self):
        if self._driver:
            self._driver.close()
            self._driver = None

    # ── PostgreSQL data loaders ──────────────────────────────────────────

    def _pg_conn(self, db_name: str):
        import psycopg2
        host = os.getenv("THREAT_DB_HOST", "localhost")
        port = os.getenv("THREAT_DB_PORT", "5432")
        user = os.getenv("THREAT_DB_USER", "postgres")
        pwd = os.getenv("THREAT_DB_PASSWORD", "")
        return psycopg2.connect(
            f"postgresql://{user}:{pwd}@{host}:{port}/{db_name}"
        )

    def _load_attack_path_categories_for_graph(self, tenant_id: str) -> Optional[Dict[str, Optional[str]]]:
        """Load attack_path_category from resource_security_relationship_rules for Neo4j edge tagging."""
        from psycopg2.extras import RealDictCursor
        try:
            conn = self._pg_conn("threat_engine_inventory")
            try:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("""
                        SELECT DISTINCT relation_type, attack_path_category
                        FROM resource_security_relationship_rules
                        WHERE is_active = TRUE
                    """)
                    cats = {}
                    for row in cur.fetchall():
                        cats[row["relation_type"]] = row.get("attack_path_category")
                    if cats:
                        logger.info(f"Loaded attack_path_category for {len(cats)} relation types")
                        return cats
            finally:
                conn.close()
        except Exception as e:
            logger.warning(f"Could not load attack_path_categories: {e}")
        return None

    def _load_inventory_findings(self, tenant_id: str) -> List[Dict[str, Any]]:
        from psycopg2.extras import RealDictCursor
        conn = self._pg_conn("threat_engine_inventory")
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Match by tenant_id OR account_id (inventory may use different tenant naming)
                cur.execute("""
                    SELECT asset_id, resource_uid, provider, account_id, region,
                           resource_type, resource_id, name,
                           configuration::text AS configuration,
                           compliance_status, risk_score, criticality
                    FROM inventory_findings
                    WHERE tenant_id = %s OR account_id = %s
                """, (tenant_id, tenant_id))
                return [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()

    def _load_inventory_relationships(self, tenant_id: str) -> List[Dict[str, Any]]:
        from psycopg2.extras import RealDictCursor
        conn = self._pg_conn("threat_engine_inventory")
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT from_uid, to_uid, relation_type,
                           source_resource_uid, target_resource_uid,
                           relationship_type, relationship_strength,
                           bidirectional, properties,
                           from_resource_type, to_resource_type
                    FROM inventory_relationships
                    WHERE tenant_id = %s OR account_id = %s
                """, (tenant_id, tenant_id))
                return [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()

    def _load_threat_detections(self, tenant_id: str) -> List[Dict[str, Any]]:
        from psycopg2.extras import RealDictCursor
        conn = self._pg_conn("threat_engine_threat")
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT detection_id, scan_id, detection_type,
                           rule_id, rule_name, resource_uid, resource_id,
                           resource_type, account_id, region, provider,
                           severity, confidence, status, threat_category,
                           mitre_tactics, mitre_techniques
                    FROM threat_detections
                    WHERE tenant_id = %s
                """, (tenant_id,))
                return [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()

    def _load_check_findings(self, tenant_id: str) -> List[Dict[str, Any]]:
        from psycopg2.extras import RealDictCursor
        conn = self._pg_conn("threat_engine_check")
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT cf.id AS finding_id, cf.scan_run_id, cf.rule_id,
                           cf.resource_uid, cf.resource_type,
                           cf.status,
                           rm.severity, rm.title, rm.service, rm.domain,
                           rm.mitre_techniques, rm.mitre_tactics
                    FROM check_findings cf
                    LEFT JOIN rule_metadata rm ON cf.rule_id = rm.rule_id
                    WHERE cf.tenant_id = %s AND cf.status = 'FAIL'
                    LIMIT 5000
                """, (tenant_id,))
                return [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()

    def _load_threat_analyses(self, tenant_id: str) -> List[Dict[str, Any]]:
        from psycopg2.extras import RealDictCursor
        conn = self._pg_conn("threat_engine_threat")
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT a.analysis_id, a.detection_id, a.risk_score,
                           a.verdict, a.analysis_results, a.recommendations,
                           a.attack_chain
                    FROM threat_analysis a
                    WHERE a.tenant_id = %s
                """, (tenant_id,))
                return [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()

    # ── Neo4j graph writers ──────────────────────────────────────────────

    def _clear_graph(self, tenant_id: str):
        """Remove all nodes/rels for this tenant."""
        driver = self._get_driver()
        with driver.session() as session:
            session.run(
                "MATCH (n {tenant_id: $tid}) DETACH DELETE n",
                tid=tenant_id,
            )
            logger.info(f"Cleared existing graph for tenant {tenant_id}")

    def _create_constraints(self):
        """Create uniqueness constraints and indexes."""
        driver = self._get_driver()
        constraints = [
            "CREATE CONSTRAINT IF NOT EXISTS FOR (r:Resource) REQUIRE r.uid IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (t:ThreatDetection) REQUIRE t.detection_id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (f:Finding) REQUIRE f.finding_id IS UNIQUE",
            "CREATE INDEX IF NOT EXISTS FOR (r:Resource) ON (r.tenant_id)",
            "CREATE INDEX IF NOT EXISTS FOR (r:Resource) ON (r.account_id)",
            "CREATE INDEX IF NOT EXISTS FOR (r:Resource) ON (r.resource_type)",
            "CREATE INDEX IF NOT EXISTS FOR (r:Resource) ON (r.provider)",
            "CREATE INDEX IF NOT EXISTS FOR (t:ThreatDetection) ON (t.severity)",
            "CREATE INDEX IF NOT EXISTS FOR (t:ThreatDetection) ON (t.resource_arn)",
            "CREATE INDEX IF NOT EXISTS FOR (t:ThreatDetection) ON (t.provider)",
        ]
        with driver.session() as session:
            for c in constraints:
                try:
                    session.run(c)
                except Exception as e:
                    logger.debug(f"Constraint/index note: {e}")

    def _create_resource_nodes(
        self, session, findings: List[Dict[str, Any]], tenant_id: str
    ) -> int:
        """Create Resource nodes from inventory_findings."""
        count = 0
        # Batch in groups of 100
        batch_size = 100
        for i in range(0, len(findings), batch_size):
            batch = findings[i:i + batch_size]
            params = []
            for f in batch:
                label = _neo4j_label(f.get("resource_type", ""))
                cfg = f.get("configuration")
                props = {
                    "uid": f["resource_uid"],
                    "asset_id": str(f["asset_id"]),
                    "tenant_id": tenant_id,
                    "provider": f.get("provider") or "unknown",
                    "account_id": f.get("account_id", ""),
                    "region": f.get("region", ""),
                    "resource_type": f.get("resource_type", ""),
                    "resource_id": f.get("resource_id", ""),
                    "name": f.get("name", ""),
                    "compliance_status": f.get("compliance_status", ""),
                    "risk_score": f.get("risk_score", 0),
                    "criticality": f.get("criticality", ""),
                    "label": label,
                    # Store config as string for internet exposure inference queries
                    "configuration": cfg if isinstance(cfg, str) else (json.dumps(cfg) if cfg else ""),
                }
                params.append(props)

            session.run("""
                UNWIND $batch AS p
                MERGE (r:Resource {uid: p.uid})
                SET r += p,
                    r:Resource
            """, batch=params)

            count += len(batch)

        # Batch label-setting: group UIDs by label → one query per label type
        # (avoids N individual session.run() calls which OOM at scale)
        # Skip generic "Resource" label (already set in MERGE) — only set specific labels
        label_groups: Dict[str, List[str]] = {}
        for f in findings:
            label = _neo4j_label(f.get("resource_type", ""))
            if label not in ("Resource", "CloudResource"):
                label_groups.setdefault(label, []).append(f["resource_uid"])

        for label, uids in label_groups.items():
            for j in range(0, len(uids), 500):
                chunk = uids[j:j + 500]
                try:
                    session.run(
                        f"UNWIND $uids AS uid MATCH (r:Resource {{uid: uid}}) SET r:`{label}`",
                        uids=chunk,
                    )
                except Exception:
                    pass

        return count

    def _create_virtual_nodes(
        self,
        session,
        tenant_id: str,
        accounts: Dict[str, str],  # account_id → provider
        regions: Set[str],
    ) -> int:
        """Create Internet, Account, and Region virtual nodes."""
        _CSP_DISPLAY = {
            "aws": "AWS", "azure": "Azure", "gcp": "GCP",
            "oci": "OCI", "ibm": "IBM", "alicloud": "AliCloud", "k8s": "K8s",
        }
        count = 0

        # Internet node
        session.run("""
            MERGE (i:Internet:VirtualNode {uid: 'INTERNET'})
            SET i.name = 'Internet', i.tenant_id = $tid, i.risk_score = 100
        """, tid=tenant_id)
        count += 1

        # Account nodes — named by CSP (e.g. "AWS Account 588989875114")
        for acct, provider in accounts.items():
            csp_label = _CSP_DISPLAY.get(provider.lower(), provider.upper())
            session.run("""
                MERGE (a:Account:VirtualNode {uid: $uid})
                SET a.name = $name, a.tenant_id = $tid, a.account_id = $acct,
                    a.provider = $provider
            """, uid=f"account:{acct}", name=f"{csp_label} Account {acct}",
                tid=tenant_id, acct=acct, provider=provider)
            count += 1

        # Region nodes
        for region in regions:
            session.run("""
                MERGE (rg:Region:VirtualNode {uid: $uid})
                SET rg.name = $name, rg.tenant_id = $tid, rg.region = $region
            """, uid=f"region:{region}", name=region, tid=tenant_id, region=region)
            count += 1

        return count

    def _create_resource_relationships(
        self, session, relationships: List[Dict[str, Any]],
        attack_path_categories: Optional[Dict[str, Optional[str]]] = None,
    ) -> int:
        """Create edges between resource nodes from inventory_relationships.

        Both inventory_findings and inventory_relationships now use raw ARN
        format, so no UID conversion is needed.  We use _infer_rel_type() to
        map the inventory relation_type to attack-path-relevant Neo4j types.

        Sets attack_path_category on each edge so Cypher queries can filter
        attack-relevant relationships.
        """
        # Import inline fallback if not provided
        if attack_path_categories is None:
            from ..analyzer.threat_analyzer import _ATTACK_PATH_CATEGORIES
            attack_path_categories = _ATTACK_PATH_CATEGORIES

        all_params: Dict[str, List[Dict]] = {}  # rel_type → [params]
        for rel in relationships:
            src = rel.get("source_resource_uid") or rel.get("from_uid") or ""
            dst = rel.get("target_resource_uid") or rel.get("to_uid") or ""

            if not src or not dst or src == dst:
                continue

            raw_type = (
                rel.get("relationship_type") or rel.get("relation_type") or "RELATED"
            )
            from_type = rel.get("from_resource_type", "")
            to_type = rel.get("to_resource_type", "")
            rel_type = _infer_rel_type(raw_type, from_type, to_type)

            # Look up attack_path_category for the raw relation_type
            category = attack_path_categories.get(raw_type)

            # Determine edge_kind: "path" if it participates in attack traversal,
            # "association" if it provides context only (findings, encryption, etc.)
            if category is not None and category != "":
                edge_kind = "path"
            elif rel_type in _PATH_REL_TYPES:
                edge_kind = "path"
            else:
                edge_kind = "association"

            all_params.setdefault(rel_type, []).append({
                "src": src, "dst": dst,
                "strength": rel.get("relationship_strength", "strong"),
                "attack_path_category": category or "",
                "relation_type_raw": raw_type,
                "edge_kind": edge_kind,
            })

        count = 0
        batch_size = 500

        for rel_type, params in all_params.items():
            for i in range(0, len(params), batch_size):
                chunk = params[i:i + batch_size]
                try:
                    result = session.run(f"""
                        UNWIND $batch AS p
                        MATCH (a:Resource {{uid: p.src}})
                        MATCH (b:Resource {{uid: p.dst}})
                        MERGE (a)-[r:`{rel_type}`]->(b)
                        SET r.strength = p.strength,
                            r.attack_path_category = p.attack_path_category,
                            r.relation_type_raw = p.relation_type_raw,
                            r.edge_kind = p.edge_kind
                        RETURN COUNT(*) AS c
                    """, batch=chunk)
                    record = result.single()
                    count += record["c"] if record else 0
                except Exception as exc:
                    logger.debug(f"Relationship batch failed ({rel_type}): {exc}")

        return count

    def _create_hierarchy_edges(self, session, findings: List[Dict[str, Any]]) -> int:
        """Connect resources to Account and Region virtual nodes (batched)."""
        batch_size = 500
        count = 0

        # Collect CONTAINS params
        contains_params = []
        for f in findings:
            acct = f.get("account_id")
            if acct:
                contains_params.append({"uid": f["resource_uid"], "acct_uid": f"account:{acct}"})

        for i in range(0, len(contains_params), batch_size):
            chunk = contains_params[i:i + batch_size]
            session.run("""
                UNWIND $batch AS p
                MATCH (r:Resource {uid: p.uid})
                MATCH (a:Account {uid: p.acct_uid})
                MERGE (a)-[:CONTAINS]->(r)
            """, batch=chunk)
            count += len(chunk)

        # Collect HOSTS params
        hosts_params = []
        for f in findings:
            region = f.get("region")
            if region:
                hosts_params.append({"uid": f["resource_uid"], "region_uid": f"region:{region}"})

        for i in range(0, len(hosts_params), batch_size):
            chunk = hosts_params[i:i + batch_size]
            session.run("""
                UNWIND $batch AS p
                MATCH (r:Resource {uid: p.uid})
                MATCH (rg:Region {uid: p.region_uid})
                MERGE (rg)-[:HOSTS]->(r)
            """, batch=chunk)
            count += len(chunk)

        return count

    def _create_threat_nodes(
        self, session, detections: List[Dict[str, Any]], tenant_id: str
    ) -> int:
        """Create ThreatDetection nodes and link to Resource nodes (batched)."""
        batch_size = 500
        count = 0

        # Prepare all props
        all_props = []
        for det in detections:
            det_id = str(det["detection_id"])
            resource_uid = det.get("resource_uid") or det.get("resource_arn") or ""
            mitre_techniques = det.get("mitre_techniques") or []
            mitre_tactics = det.get("mitre_tactics") or []

            all_props.append({
                "detection_id": det_id,
                "tenant_id": tenant_id,
                "scan_id": det.get("scan_id", ""),
                "detection_type": det.get("detection_type", ""),
                "rule_id": det.get("rule_id", ""),
                "rule_name": det.get("rule_name", ""),
                "resource_uid": resource_uid,
                "resource_type": det.get("resource_type", ""),
                "severity": det.get("severity", ""),
                "confidence": det.get("confidence", ""),
                "status": det.get("status", ""),
                "threat_category": det.get("threat_category", ""),
                "mitre_techniques": mitre_techniques if isinstance(mitre_techniques, list) else [],
                "mitre_tactics": mitre_tactics if isinstance(mitre_tactics, list) else [],
            })

        # Batch MERGE ThreatDetection nodes
        for i in range(0, len(all_props), batch_size):
            chunk = all_props[i:i + batch_size]
            session.run("""
                UNWIND $batch AS p
                MERGE (t:ThreatDetection {detection_id: p.detection_id})
                SET t += p
            """, batch=chunk)
            count += len(chunk)

        # Batch MERGE HAS_THREAT edges
        link_params = [
            {"det_id": p["detection_id"], "uid": p["resource_uid"]}
            for p in all_props if p["resource_uid"]
        ]
        for i in range(0, len(link_params), batch_size):
            chunk = link_params[i:i + batch_size]
            session.run("""
                UNWIND $batch AS p
                MATCH (t:ThreatDetection {detection_id: p.det_id})
                MATCH (r:Resource {uid: p.uid})
                MERGE (r)-[h:HAS_THREAT]->(t)
                SET h.edge_kind = 'association'
            """, batch=chunk)

        return count

    def _create_finding_nodes(
        self, session, findings: List[Dict[str, Any]], tenant_id: str
    ) -> int:
        """Create Finding nodes from check_findings and link to Resources."""
        count = 0
        batch_size = 200

        for i in range(0, len(findings), batch_size):
            batch = findings[i:i + batch_size]
            params = []
            for f in batch:
                mitre_techs = f.get("mitre_techniques") or []
                if mitre_techs and isinstance(mitre_techs, list):
                    if mitre_techs and isinstance(mitre_techs[0], dict):
                        mitre_techs = [t.get("technique_id", str(t)) for t in mitre_techs]

                props = {
                    "finding_id": str(f["finding_id"]),
                    "tenant_id": tenant_id,
                    "rule_id": f.get("rule_id", ""),
                    "resource_uid": f.get("resource_uid", ""),
                    "severity": f.get("severity", ""),
                    "status": f.get("status", ""),
                    "title": f.get("title", ""),
                    "service": f.get("service", ""),
                    "domain": f.get("domain", ""),
                    "mitre_techniques": mitre_techs,
                }
                params.append(props)

            session.run("""
                UNWIND $batch AS p
                MERGE (f:Finding {finding_id: p.finding_id})
                SET f += p
            """, batch=params)

            # Link findings to resources — batched UNWIND (avoids N individual queries)
            link_params = [
                {"fid": str(f["finding_id"]), "ruid": f.get("resource_uid", "")}
                for f in batch if f.get("resource_uid")
            ]
            if link_params:
                try:
                    # HAS_FINDING — internal graph edge (resource owns finding)
                    # AFFECTED_BY — semantic association edge (resource is affected by finding)
                    # Both carry edge_kind="association" — not traversed for attack paths
                    session.run("""
                        UNWIND $links AS lnk
                        MATCH (f:Finding {finding_id: lnk.fid})
                        MATCH (r:Resource {uid: lnk.ruid})
                        MERGE (r)-[h:HAS_FINDING]->(f)
                        SET h.edge_kind = 'association'
                        MERGE (r)-[a:AFFECTED_BY]->(f)
                        SET a.edge_kind = 'association'
                    """, links=link_params)
                except Exception:
                    pass

            count += len(batch)

        return count

    def _create_analysis_edges(
        self, session, analyses: List[Dict[str, Any]]
    ) -> int:
        """Link ThreatDetection nodes with analysis risk data (batched)."""
        batch_size = 500
        count = 0

        # Batch 1: SET risk_score/verdict/blast_radius on ThreatDetection nodes
        risk_params = []
        for a in analyses:
            blast = a.get("analysis_results", {}).get("blast_radius", {})
            risk_params.append({
                "det_id": str(a["detection_id"]),
                "risk": a.get("risk_score", 0),
                "verdict": a.get("verdict", ""),
                "blast": blast.get("reachable_count", 0),
            })

        for i in range(0, len(risk_params), batch_size):
            chunk = risk_params[i:i + batch_size]
            session.run("""
                UNWIND $batch AS p
                MATCH (t:ThreatDetection {detection_id: p.det_id})
                SET t.risk_score = p.risk,
                    t.verdict = p.verdict,
                    t.blast_radius = p.blast,
                    t.analyzed = true
            """, batch=chunk)
            count += len(chunk)

        # Batch 2: ATTACK_PATH edges from attack chains
        path_params = []
        for a in analyses:
            det_id = str(a["detection_id"])
            chain = a.get("attack_chain") or []
            for step in chain[1:]:
                hop_from = step.get("hop_from", "")
                hop_to = step.get("resource", "")
                if hop_from and hop_to:
                    path_params.append({
                        "from_uid": hop_from,
                        "to_uid": hop_to,
                        "det_id": det_id,
                        "step": step.get("step", 0),
                        "action": step.get("action", ""),
                    })

        for i in range(0, len(path_params), batch_size):
            chunk = path_params[i:i + batch_size]
            try:
                session.run("""
                    UNWIND $batch AS p
                    MATCH (a:Resource) WHERE a.uid STARTS WITH p.from_uid
                    MATCH (b:Resource) WHERE b.uid STARTS WITH p.to_uid
                    MERGE (a)-[r:ATTACK_PATH]->(b)
                    SET r.detection_id = p.det_id,
                        r.step = p.step,
                        r.action = p.action
                """, batch=chunk)
                count += len(chunk)
            except Exception:
                pass

        return count

    def _load_compute_and_store_labels(self) -> Tuple[List[str], List[str]]:
        """Query architecture_resource_placement for compute and data-store
        resource types, then map to Neo4j labels.

        Returns:
            (compute_labels, data_store_labels) — de-duped lists of Neo4j labels.
        """
        from psycopg2.extras import RealDictCursor
        try:
            conn = self._pg_conn("threat_engine_inventory")
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Compute: VM, function (Lambda), container workloads
                cur.execute("""
                    SELECT DISTINCT resource_type
                    FROM architecture_resource_placement
                    WHERE visual_group IN ('compute', 'compute-serverless', 'compute-container')
                      AND visual_subgroup IN ('ec2', 'lambda', 'ecs', 'eks', 'vm', 'function')
                """)
                compute_types = [r["resource_type"] for r in cur.fetchall()]

                # Data stores: storage + database + AI models + security (secrets)
                cur.execute("""
                    SELECT DISTINCT resource_type
                    FROM architecture_resource_placement
                    WHERE visual_group IN (
                        'storage-object', 'storage-block', 'storage-file',
                        'compute-database', 'encryption',
                        'ai',            -- Bedrock, SageMaker models (AI data access path)
                        'compute-analytics'  -- Redshift, EMR, Glue
                    )
                """)
                store_types = [r["resource_type"] for r in cur.fetchall()]
            conn.close()
        except Exception as exc:
            logger.warning(f"Could not load architecture_resource_placement: {exc}")
            return [], []

        # Map resource_type → Neo4j label; skip unknowns (would be CloudResource)
        def _to_labels(types: List[str]) -> List[str]:
            seen: set = set()
            labels = []
            for rt in types:
                lbl = _neo4j_label(rt)
                if lbl != "CloudResource" and lbl not in seen:
                    seen.add(lbl)
                    labels.append(lbl)
            return labels

        return _to_labels(compute_types), _to_labels(store_types)

    def _create_internet_edges(self, session, tenant_id: str) -> int:
        """Wire data-store reachability edges (compute → data stores).

        Internet exposure is handled entirely by _infer_internet_exposure() via
        check_findings (the check engine is the authoritative source for what is
        actually exposed).  This method adds compute → data-store ACCESSES edges
        so attack paths continue from internet-exposed compute to sensitive data.

        Compute and data-store resource types are loaded dynamically from
        architecture_resource_placement (single source of truth).  Edge scope is:
          - block storage (EBS): exact from discovery_findings Attachments
          - all others: same account + region proximity (inferred)
        """
        count = 0

        # ── 1. EC2 → EBS: exact edges from discovery_findings Attachments ──
        try:
            from psycopg2.extras import RealDictCursor
            import json as _json
            disc_conn = self._pg_conn("threat_engine_discoveries")
            with disc_conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT DISTINCT
                        emitted_fields->>'VolumeId' AS vol_id,
                        emitted_fields->'Attachments'  AS attachments,
                        region, account_id
                    FROM discovery_findings
                    WHERE discovery_id = 'aws.ec2.describe_volumes'
                      AND account_id = %s
                      AND emitted_fields->'Attachments' IS NOT NULL
                      AND emitted_fields->>'Attachments' != '[]'
                """, (tenant_id,))
                vol_rows = cur.fetchall()
            disc_conn.close()

            ebs_batch = []
            for row in vol_rows:
                vol_id = row.get("vol_id")
                attachments = row.get("attachments")
                if not vol_id or not attachments:
                    continue
                if isinstance(attachments, str):
                    attachments = _json.loads(attachments)
                for att in (attachments or []):
                    if att.get("State") != "attached":
                        continue
                    instance_id = att.get("InstanceId")
                    if not instance_id:
                        continue
                    region = row.get("region", "")
                    acct = row.get("account_id", tenant_id)
                    ebs_batch.append({
                        "instance_arn": f"arn:aws:ec2:{region}:{acct}:instance/{instance_id}",
                        "volume_arn":   f"arn:aws:ec2:{region}:{acct}:volume/{vol_id}",
                    })

            for i in range(0, len(ebs_batch), 500):
                chunk = ebs_batch[i:i + 500]
                r = session.run("""
                    UNWIND $batch AS p
                    MATCH (ec2:Resource {uid: p.instance_arn})
                    MATCH (vol:Resource {uid: p.volume_arn})
                    MERGE (ec2)-[e:ATTACHED_TO]->(vol)
                    SET e.attack_path_category = 'data_access',
                        e.edge_kind = 'path'
                    RETURN COUNT(e) AS c
                """, batch=chunk)
                rec = r.single()
                count += rec["c"] if rec else 0
        except Exception as exc:
            logger.debug(f"EC2→EBS exact edges failed: {exc}")

        # ── 2. EC2 → IAM InstanceProfile: privilege escalation edges from discovery ──
        # inventory_relationships often misses EC2→InstanceProfile for some tenants.
        # Pull directly from discovery_findings (authoritative source).
        try:
            from psycopg2.extras import RealDictCursor as _RDC2
            disc2 = self._pg_conn("threat_engine_discoveries")
            try:
                with disc2.cursor(cursor_factory=_RDC2) as cur:
                    cur.execute("""
                        SELECT DISTINCT
                            emitted_fields->>'InstanceId'               AS instance_id,
                            emitted_fields->'IamInstanceProfile'->>'Arn' AS profile_arn,
                            account_id, region
                        FROM discovery_findings
                        WHERE discovery_id = 'aws.ec2.describe_instances'
                          AND emitted_fields->'IamInstanceProfile'->>'Arn' IS NOT NULL
                    """)
                    ec2_iam_rows = cur.fetchall()
            finally:
                disc2.close()

            iam_batch = []
            for row in ec2_iam_rows:
                instance_id = row.get("instance_id")
                profile_arn = row.get("profile_arn")
                if not instance_id or not profile_arn:
                    continue
                region = row.get("region", "")
                acct = row.get("account_id", "")
                ec2_uid = f"arn:aws:ec2:{region}:{acct}:instance/{instance_id}"
                iam_batch.append({"ec2_uid": ec2_uid, "profile_arn": profile_arn})

            for i in range(0, len(iam_batch), 500):
                chunk = iam_batch[i:i + 500]
                try:
                    r = session.run("""
                        UNWIND $batch AS p
                        MATCH (ec2:Resource {uid: p.ec2_uid})
                        MATCH (ip:Resource {uid: p.profile_arn})
                        MERGE (ec2)-[e:ASSUMES]->(ip)
                        SET e.attack_path_category = 'privilege_escalation',
                            e.edge_kind = 'path',
                            e.reason = 'iam_instance_profile'
                        RETURN COUNT(e) AS c
                    """, batch=chunk)
                    rec = r.single()
                    count += rec["c"] if rec else 0
                except Exception as exc:
                    logger.debug(f"EC2→InstanceProfile batch failed: {exc}")
            logger.info(f"Added EC2→InstanceProfile ASSUMES edges from {len(iam_batch)} discovery records")
        except Exception as exc:
            logger.warning(f"EC2→IAM privilege escalation edges failed: {exc}")

        # ── 3. Lambda → IAM Role: exact edges from discovery_findings ──
        try:
            from psycopg2.extras import RealDictCursor as _RDC3
            disc3 = self._pg_conn("threat_engine_discoveries")
            try:
                with disc3.cursor(cursor_factory=_RDC3) as cur:
                    cur.execute("""
                        SELECT DISTINCT
                            emitted_fields->>'FunctionArn'    AS fn_arn,
                            emitted_fields->>'Role'           AS role_arn,
                            account_id, region
                        FROM discovery_findings
                        WHERE discovery_id = 'aws.lambda.list_functions'
                          AND emitted_fields->>'Role' IS NOT NULL
                    """)
                    lambda_rows = cur.fetchall()
            finally:
                disc3.close()

            lambda_batch = []
            for row in lambda_rows:
                fn_arn = row.get("fn_arn")
                role_arn = row.get("role_arn")
                if fn_arn and role_arn:
                    lambda_batch.append({"fn_arn": fn_arn, "role_arn": role_arn})

            for i in range(0, len(lambda_batch), 500):
                chunk = lambda_batch[i:i + 500]
                try:
                    r = session.run("""
                        UNWIND $batch AS p
                        MATCH (fn:Resource {uid: p.fn_arn})
                        MATCH (role:Resource {uid: p.role_arn})
                        MERGE (fn)-[e:ASSUMES]->(role)
                        SET e.attack_path_category = 'privilege_escalation',
                            e.edge_kind = 'path',
                            e.reason = 'lambda_execution_role'
                        RETURN COUNT(e) AS c
                    """, batch=chunk)
                    rec = r.single()
                    count += rec["c"] if rec else 0
                except Exception as exc:
                    logger.debug(f"Lambda→IAMRole batch failed: {exc}")
        except Exception as exc:
            logger.warning(f"Lambda→IAM edges failed: {exc}")

        # ── 3b. Compute → SecretsManager/SSM: credential theft path ─────────────
        # SecretsManager and SSM Parameter Store are critical credential theft targets.
        try:
            r = session.run("""
                MATCH (c:Resource {tenant_id: $tid})
                WHERE c.resource_type IN [
                    'ec2.instance', 'lambda.function', 'lambda.resource',
                    'eks.cluster', 'ecs.task-definition', 'ecs.service'
                ]
                MATCH (s:Resource {tenant_id: $tid, account_id: c.account_id})
                WHERE s.resource_type IN [
                    'secretsmanager.secret', 'ssm.parameter',
                    'secretsmanager.resource'
                ]
                MERGE (c)-[e:ACCESSES]->(s)
                SET e.attack_path_category = 'credential_theft',
                    e.edge_kind = 'path',
                    e.inferred = true,
                    e.mitre_technique = 'T1552.006'
                RETURN COUNT(e) AS c
            """, tid=tenant_id)
            rec = r.single()
            count += rec["c"] if rec else 0
        except Exception as exc:
            logger.debug(f"Compute→SecretsManager edges failed: {exc}")

        # ── 3c. Compute → KMS: encryption key access (data_access + lateral movement) ──
        # KMS key compromise unlocks ALL data encrypted with it — S3, RDS, EBS, etc.
        # T1552: unsecured credentials / T1485: data destruction via re-encryption
        try:
            r = session.run("""
                MATCH (c:Resource {tenant_id: $tid})
                WHERE c.resource_type IN [
                    'ec2.instance', 'lambda.function', 'lambda.resource',
                    'eks.cluster', 'ecs.task-definition'
                ]
                MATCH (k:Resource {tenant_id: $tid, account_id: c.account_id})
                WHERE k.resource_type IN ['kms.key', 'kms.alias']
                  AND (k.region = c.region OR k.region IS NULL OR k.region = '')
                MERGE (c)-[e:ACCESSES]->(k)
                SET e.attack_path_category = 'data_access',
                    e.edge_kind = 'path',
                    e.inferred = true,
                    e.reason = 'kms_decrypt_chain',
                    e.mitre_technique = 'T1485'
                RETURN COUNT(e) AS c
            """, tid=tenant_id)
            rec = r.single()
            count += rec["c"] if rec else 0
        except Exception as exc:
            logger.debug(f"Compute→KMS edges failed: {exc}")

        # ── 3d. Compute → Bedrock / SageMaker: AI model access path ───────────────
        # Internet-exposed compute calling AI models can exfiltrate training data,
        # perform prompt injection, or poison model outputs. T1565: data manipulation.
        try:
            r = session.run("""
                MATCH (c:Resource {tenant_id: $tid})
                WHERE c.resource_type IN [
                    'ec2.instance', 'lambda.function', 'lambda.resource',
                    'eks.cluster'
                ]
                MATCH (ai:Resource {tenant_id: $tid, account_id: c.account_id})
                WHERE ai.resource_type IN [
                    'bedrock.foundation-model', 'bedrock.inference-profile',
                    'bedrock.agent', 'bedrock.default-prompt-router',
                    'sagemaker.endpoint', 'sagemaker.model',
                    'sagemaker.notebook-instance'
                ]
                MERGE (c)-[e:ACCESSES]->(ai)
                SET e.attack_path_category = 'ai_model_access',
                    e.edge_kind = 'path',
                    e.inferred = true,
                    e.reason = 'ai_service_invocation',
                    e.mitre_technique = 'T1565'
                RETURN COUNT(e) AS c
            """, tid=tenant_id)
            rec = r.single()
            count += rec["c"] if rec else 0
        except Exception as exc:
            logger.debug(f"Compute→AI/Bedrock edges failed: {exc}")

        # ── 3e. ECS tasks → data stores: container workload data access ────────────
        # ECS tasks often have IAM task roles granting broad data store access.
        try:
            r = session.run("""
                MATCH (c:Resource {tenant_id: $tid})
                WHERE c.resource_type IN ['ecs.task-definition', 'ecs.service', 'ecs.cluster']
                MATCH (d:Resource {tenant_id: $tid, account_id: c.account_id})
                WHERE d.resource_type IN [
                    's3.resource', 's3.bucket',
                    'dynamodb.table', 'dynamodb.resource',
                    'rds.instance', 'rds.db-instance', 'rds.cluster',
                    'elasticache.cluster', 'elasticache.replication-group',
                    'sqs.queue', 'sns.topic'
                ]
                  AND (d.region = c.region OR d.region IS NULL OR d.region = '')
                MERGE (c)-[e:ACCESSES]->(d)
                SET e.attack_path_category = 'data_access',
                    e.edge_kind = 'path',
                    e.inferred = true,
                    e.reason = 'ecs_task_data_access'
                RETURN COUNT(e) AS c
            """, tid=tenant_id)
            rec = r.single()
            count += rec["c"] if rec else 0
        except Exception as exc:
            logger.debug(f"ECS→DataStore edges failed: {exc}")

        # ── 3f. IAM Role → privilege escalation chain ──────────────────────────────
        # InstanceProfile → IAMRole → (if admin) → all resources.
        # Creates ASSUMES chain so attack paths traverse: compute → profile → role.
        try:
            r = session.run("""
                MATCH (ip:InstanceProfile {tenant_id: $tid})
                MATCH (role:IAMRole {tenant_id: $tid, account_id: ip.account_id})
                MERGE (ip)-[e:ASSUMES]->(role)
                SET e.attack_path_category = 'privilege_escalation',
                    e.edge_kind = 'path',
                    e.reason = 'instance_profile_role_link'
                RETURN COUNT(e) AS c
            """, tid=tenant_id)
            rec = r.single()
            count += rec["c"] if rec else 0
        except Exception as exc:
            logger.debug(f"InstanceProfile→IAMRole edges failed: {exc}")

        # ── 3g. API Gateway → S3 direct (API GW can serve S3 via integration) ──────
        try:
            r = session.run("""
                MATCH (apigw:Resource {tenant_id: $tid})
                WHERE apigw.resource_type IN [
                    'apigateway.item_rest_api', 'apigateway.resource',
                    'apigatewayv2.api', 'apigatewayv2.item_api'
                ]
                MATCH (s:S3Bucket {tenant_id: $tid, account_id: apigw.account_id})
                MERGE (apigw)-[e:ACCESSES]->(s)
                SET e.attack_path_category = 'data_access',
                    e.edge_kind = 'path',
                    e.inferred = true,
                    e.reason = 'api_gw_s3_integration'
                RETURN COUNT(e) AS c
            """, tid=tenant_id)
            rec = r.single()
            count += rec["c"] if rec else 0
        except Exception as exc:
            logger.debug(f"APIGateway→S3 edges failed: {exc}")

        # ── 3h. ECR → Lambda/ECS: supply chain attack path ────────────────────────
        # Compromised container image in ECR → deployed to Lambda/ECS → code execution
        # T1195.002: compromise software supply chain
        try:
            r = session.run("""
                MATCH (reg:Resource {tenant_id: $tid})
                WHERE reg.resource_type IN ['ecr.repository', 'ecr.resource']
                MATCH (consumer:Resource {tenant_id: $tid, account_id: reg.account_id})
                WHERE consumer.resource_type IN [
                    'ecs.task-definition', 'ecs.service',
                    'lambda.function', 'lambda.resource',
                    'eks.cluster'
                ]
                MERGE (reg)-[e:PROVIDES_IMAGE_TO]->(consumer)
                SET e.attack_path_category = 'lateral_movement',
                    e.edge_kind = 'path',
                    e.inferred = true,
                    e.reason = 'container_supply_chain',
                    e.mitre_technique = 'T1195.002'
                RETURN COUNT(e) AS c
            """, tid=tenant_id)
            rec = r.single()
            count += rec["c"] if rec else 0
        except Exception as exc:
            logger.debug(f"ECR→Lambda/ECS supply chain edges failed: {exc}")

        # ── 4. Inferred compute → data-store edges (architecture_resource_placement driven) ──
        compute_labels, store_labels = self._load_compute_and_store_labels()
        if not compute_labels or not store_labels:
            logger.warning("No compute/store labels from architecture_resource_placement; skipping inferred edges")
            return count

        logger.info(
            f"Building data-store edges: {len(compute_labels)} compute types "
            f"× {len(store_labels)} data-store types"
        )

        # Single batched query: pass label lists as parameters and use IN-filter
        # on the __labels__ property stored on each node (avoids 110K Cypher round-trips).
        # We use a MATCH on Resource (base label shared by all) and filter by resource_type.
        # resource_type values correspond to Neo4j labels so we can match directly.
        try:
            r = session.run("""
                MATCH (c:Resource {tenant_id: $tid})
                WHERE any(lbl IN labels(c) WHERE lbl IN $compute_lbls)
                MATCH (d:Resource {tenant_id: $tid, account_id: c.account_id})
                WHERE any(lbl IN labels(d) WHERE lbl IN $store_lbls)
                  AND c <> d
                  AND (d.region = c.region
                       OR d.region IS NULL OR d.region = ''
                       OR c.region IS NULL OR c.region = '')
                MERGE (c)-[e:ACCESSES]->(d)
                SET e.attack_path_category = 'data_access',
                    e.edge_kind = 'path',
                    e.inferred = true
                RETURN COUNT(e) AS c
            """, tid=tenant_id, compute_lbls=compute_labels, store_lbls=store_labels)
            rec = r.single()
            if rec:
                count += rec["c"]
        except Exception as exc:
            logger.warning(f"Batched data-store edges failed, falling back to per-pair: {exc}")
            # Fallback: original per-pair loop (slow but correct)
            for compute_lbl in compute_labels:
                for store_lbl in store_labels:
                    try:
                        r = session.run(f"""
                            MATCH (c:`{compute_lbl}` {{tenant_id: $tid}})
                            MATCH (d:`{store_lbl}` {{tenant_id: $tid, account_id: c.account_id}})
                            WHERE c <> d
                              AND (d.region = c.region
                                   OR d.region IS NULL OR d.region = ''
                                   OR c.region IS NULL OR c.region = '')
                            MERGE (c)-[e:ACCESSES]->(d)
                            SET e.attack_path_category = 'data_access',
                                e.edge_kind = 'path',
                                e.inferred = true
                            RETURN COUNT(e) AS c
                        """, tid=tenant_id)
                        rec = r.single()
                        if rec:
                            count += rec["c"]
                    except Exception as exc2:
                        logger.debug(f"{compute_lbl}→{store_lbl} edges failed: {exc2}")

        return count

    def _infer_internet_exposure(self, session, tenant_id: str) -> int:
        """
        Infer internet exposure for all CSPs using the exposure detector package.

        Detection is split by CSP into dedicated modules under graph/exposure/:
          _common.py  — CSP-agnostic: check_findings rule patterns + config JSON
          _aws.py     — AWS: EC2, RDS, ELB, EKS, API-GW, Lambda, Cognito, OpenSearch
          _azure.py   — Azure: VMs, SQL, Storage, AKS, App Service, Databases
          _gcp.py     — GCP: GCE, CloudSQL, GKE, Cloud Run, GCS, Cloud Functions
          _oci.py     — OCI: Compute, Autonomous DB, Object Storage, Load Balancers

        Each detector runs independently. If a CSP module fails (e.g. no discovery
        data for that cloud), it logs a warning and the others continue.
        """
        from .exposure import detect_all
        return detect_all(session, tenant_id, self._pg_conn)

    # ── Main orchestrator ────────────────────────────────────────────────

    def _load_iam_policy_statements(self, tenant_id: str) -> List[Dict[str, Any]]:
        """
        Load IAM policy statements from iam_policy_statements table.

        Returns Allow statements that have specific (non-wildcard) resource ARNs.
        These become CAN_ACCESS and ASSUMES edges in the graph.
        """
        from psycopg2.extras import RealDictCursor
        try:
            conn = self._pg_conn("threat_engine_iam")
            try:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("""
                        SELECT attached_to_arn, attached_to_type,
                               effect, actions, resources,
                               is_admin, is_wildcard_principal,
                               is_cross_account, has_external_id,
                               principals
                        FROM iam_policy_statements
                        WHERE tenant_id = %s
                          AND effect = 'Allow'
                          AND is_aws_managed = FALSE
                        LIMIT 10000
                    """, (tenant_id,))
                    return [dict(r) for r in cur.fetchall()]
            finally:
                conn.close()
        except Exception as exc:
            logger.warning(f"Could not load iam_policy_statements: {exc}")
            return []

    def _create_iam_permission_edges(
        self, session, statements: List[Dict[str, Any]], tenant_id: str
    ) -> int:
        """
        Create IAM permission edges in Neo4j from iam_policy_statements.

        Edge types created:
          CAN_ACCESS — principal → specific resource ARN (non-wildcard resources)
                       attack_path_category = data_access / execution / privilege_escalation
          ASSUMES    — cross-account trust (principal_type=role, is_cross_account=True)
                       attack_path_category = lateral_movement / privilege_escalation

        Admin policies (is_admin=True) create CAN_ACCESS with privilege_escalation
        to highlight the most dangerous "god-mode" permissions.
        """
        _DATA_PREFIXES = ("s3:", "rds:", "dynamodb:", "secretsmanager:", "kms:", "glacier:")
        _EXEC_PREFIXES = ("lambda:", "ecs:", "ec2:run", "ssm:send", "eks:")
        _IAM_PREFIXES  = ("iam:", "sts:")

        def _classify(actions: List[str], is_admin: bool) -> str:
            if is_admin or "*" in actions:
                return "privilege_escalation"
            actions_lc = [a.lower() for a in actions]
            if any(a.startswith(p) for a in actions_lc for p in _IAM_PREFIXES):
                return "privilege_escalation"
            if any(a.startswith(p) for a in actions_lc for p in _EXEC_PREFIXES):
                return "execution"
            if any(a.startswith(p) for a in actions_lc for p in _DATA_PREFIXES):
                return "data_access"
            return ""

        can_access_batch: List[Dict] = []
        assumes_batch: List[Dict] = []

        for stmt in statements:
            principal = stmt.get("attached_to_arn") or ""
            if not principal:
                continue

            resources: List[str] = stmt.get("resources") or []
            actions: List[str] = stmt.get("actions") or []
            is_admin: bool = bool(stmt.get("is_admin"))
            is_cross_acct: bool = bool(stmt.get("is_cross_account"))

            attack_cat = _classify(actions, is_admin)

            # CAN_ACCESS: for statements with specific (non-wildcard) resource ARNs
            for resource_arn in resources:
                if not resource_arn or resource_arn == "*" or not resource_arn.startswith("arn:"):
                    continue
                can_access_batch.append({
                    "src": principal,
                    "dst": resource_arn,
                    "attack_path_category": attack_cat,
                    "actions": ",".join(actions[:10]),
                    "is_admin": is_admin,
                })

            # ASSUMES: for cross-account / same-account trust (principals list)
            principals_list: List[str] = stmt.get("principals") or []
            for prl in principals_list:
                if not prl or prl == "*":
                    continue
                cat = "lateral_movement" if is_cross_acct else "privilege_escalation"
                assumes_batch.append({
                    "src": prl,
                    "dst": principal,
                    "attack_path_category": cat,
                    "is_cross_account": is_cross_acct,
                })

        count = 0
        batch_size = 500

        # CAN_ACCESS edges
        for i in range(0, len(can_access_batch), batch_size):
            chunk = can_access_batch[i:i + batch_size]
            try:
                r = session.run("""
                    UNWIND $batch AS p
                    MATCH (a:Resource {uid: p.src})
                    MATCH (b:Resource {uid: p.dst})
                    MERGE (a)-[e:CAN_ACCESS]->(b)
                    SET e.attack_path_category = p.attack_path_category,
                        e.edge_kind = 'path',
                        e.actions = p.actions,
                        e.is_admin = p.is_admin
                    RETURN COUNT(e) AS c
                """, batch=chunk)
                rec = r.single()
                count += rec["c"] if rec else 0
            except Exception as exc:
                logger.debug(f"IAM CAN_ACCESS batch failed: {exc}")

        # ASSUMES edges (trust relationships)
        # Role→Role chaining is tagged edge_kind='association' to keep it out of path traversal
        # (too noisy — creates hundreds of similar paths). Compute→Role stays 'path'.
        for i in range(0, len(assumes_batch), batch_size):
            chunk = assumes_batch[i:i + batch_size]
            try:
                r = session.run("""
                    UNWIND $batch AS p
                    MATCH (a:Resource {uid: p.src})
                    MATCH (b:Resource {uid: p.dst})
                    MERGE (a)-[e:ASSUMES]->(b)
                    SET e.attack_path_category = p.attack_path_category,
                        e.edge_kind = CASE
                            WHEN (a:IAMRole OR a:ServiceAccount) AND (b:IAMRole OR b:ServiceAccount)
                            THEN 'association'
                            ELSE 'path'
                        END,
                        e.is_cross_account = p.is_cross_account
                    RETURN COUNT(e) AS c
                """, batch=chunk)
                rec = r.single()
                count += rec["c"] if rec else 0
            except Exception as exc:
                logger.debug(f"IAM ASSUMES trust batch failed: {exc}")

        logger.info(
            f"IAM permission edges: {len(can_access_batch)} CAN_ACCESS + "
            f"{len(assumes_batch)} ASSUMES candidates → {count} created"
        )
        return count

    def build_graph(self, tenant_id: str) -> Dict[str, Any]:
        """
        Build complete security graph for a tenant.

        Loads data from all 3 PostgreSQL databases and creates the Neo4j graph.
        """
        logger.info(f"Building security graph for tenant {tenant_id}")
        stats: Dict[str, int] = {}

        # 1. Create constraints/indexes
        self._create_constraints()

        # 2. Clear existing graph for this tenant
        self._clear_graph(tenant_id)

        # 3. Load all PostgreSQL data
        logger.info("Loading inventory findings...")
        inv_findings = self._load_inventory_findings(tenant_id)
        logger.info(f"  → {len(inv_findings)} inventory resources")

        logger.info("Loading inventory relationships...")
        inv_rels = self._load_inventory_relationships(tenant_id)
        logger.info(f"  → {len(inv_rels)} relationships")

        logger.info("Loading threat detections...")
        detections = self._load_threat_detections(tenant_id)
        logger.info(f"  → {len(detections)} threat detections")

        logger.info("Loading check findings (FAIL only)...")
        check_findings = self._load_check_findings(tenant_id)
        logger.info(f"  → {len(check_findings)} failed check findings")

        logger.info("Loading threat analyses...")
        analyses = self._load_threat_analyses(tenant_id)
        logger.info(f"  → {len(analyses)} analyses")

        # 4. Build graph
        driver = self._get_driver()
        with driver.session() as session:
            # 4a. Virtual nodes (Internet, Accounts, Regions)
            # accounts: Dict[account_id → provider] — preserves CSP per account
            accounts: Dict[str, str] = {}
            for f in inv_findings:
                acct = f.get("account_id")
                if acct:
                    accounts.setdefault(acct, f.get("provider") or "unknown")
            regions = set(f.get("region", "") for f in inv_findings if f.get("region"))
            stats["virtual_nodes"] = self._create_virtual_nodes(session, tenant_id, accounts, regions)
            logger.info(f"  → {stats['virtual_nodes']} virtual nodes")

            # 4b. Resource nodes from inventory
            stats["resource_nodes"] = self._create_resource_nodes(session, inv_findings, tenant_id)
            logger.info(f"  → {stats['resource_nodes']} resource nodes")

            # 4c. Also create Resource nodes for any uid referenced in threats
            # but not in inventory (so we don't lose threat→resource links)
            existing_uids = set(f["resource_uid"] for f in inv_findings)
            missing_resources = []
            for det in detections:
                uid = det.get("resource_uid") or det.get("resource_arn") or ""
                if uid and uid not in existing_uids:
                    existing_uids.add(uid)
                    missing_resources.append({
                        "asset_id": str(det["detection_id"]),
                        "resource_uid": uid,
                        "provider": det.get("provider") or "unknown",
                        "account_id": det.get("account_id", ""),
                        "region": det.get("region", ""),
                        "resource_type": det.get("resource_type", ""),
                        "resource_id": det.get("resource_id", ""),
                        "name": uid.split(":::")[-1] if ":::" in uid else uid.split("/")[-1],
                        "compliance_status": "non_compliant",
                        "risk_score": 60,
                        "criticality": "high",
                    })
            if missing_resources:
                extra = self._create_resource_nodes(session, missing_resources, tenant_id)
                stats["resource_nodes"] += extra
                logger.info(f"  → +{extra} resource nodes from threat ARNs")

            # 4d. Resource relationships (with attack_path_category on edges)
            # Load categories from DB for Neo4j edge classification
            attack_path_cats = self._load_attack_path_categories_for_graph(tenant_id)
            stats["resource_rels"] = self._create_resource_relationships(
                session, inv_rels, attack_path_cats
            )
            logger.info(f"  → {stats['resource_rels']} resource relationships")

            # 4e. Hierarchy (Account/Region → Resource)
            all_findings = inv_findings + missing_resources
            stats["hierarchy_rels"] = self._create_hierarchy_edges(session, all_findings)
            logger.info(f"  → {stats['hierarchy_rels']} hierarchy relationships")

            # 4f. ThreatDetection nodes
            stats["threat_nodes"] = self._create_threat_nodes(session, detections, tenant_id)
            logger.info(f"  → {stats['threat_nodes']} threat detection nodes")

            # 4g. Finding nodes
            stats["finding_nodes"] = self._create_finding_nodes(session, check_findings, tenant_id)
            logger.info(f"  → {stats['finding_nodes']} finding nodes")

            # 4h. Analysis enrichment + attack paths
            stats["analysis_edges"] = self._create_analysis_edges(session, analyses)
            logger.info(f"  → {stats['analysis_edges']} analysis/attack-path edges")

            # 4i. Data store reachability edges (EC2/Lambda → EBS/S3/RDS/DynamoDB/EFS/etc.)
            stats["internet_edges"] = self._create_internet_edges(session, tenant_id)
            logger.info(f"  → {stats['internet_edges']} data store reachability edges")

            # 4j. Infer additional internet exposure from network boundary config
            stats["exposure_edges"] = self._infer_internet_exposure(session, tenant_id)
            logger.info(f"  → {stats['exposure_edges']} internet exposure edges")

            # 4k. IAM permission edges from iam_policy_statements (CAN_ACCESS, ASSUMES)
            iam_stmts = self._load_iam_policy_statements(tenant_id)
            logger.info(f"Loading IAM policy statements... → {len(iam_stmts)} statements")
            stats["iam_permission_edges"] = self._create_iam_permission_edges(session, iam_stmts, tenant_id)
            logger.info(f"  → {stats['iam_permission_edges']} IAM permission edges")

        # Summary
        total_nodes = stats.get("virtual_nodes", 0) + stats.get("resource_nodes", 0) + \
                      stats.get("threat_nodes", 0) + stats.get("finding_nodes", 0)
        total_rels = stats.get("resource_rels", 0) + stats.get("hierarchy_rels", 0) + \
                     stats.get("analysis_edges", 0) + stats.get("exposure_edges", 0) + \
                     stats.get("internet_edges", 0) + stats.get("iam_permission_edges", 0)

        stats["total_nodes"] = total_nodes
        stats["total_relationships"] = total_rels

        logger.info(f"Security graph built: {total_nodes} nodes, {total_rels} relationships")
        return stats
