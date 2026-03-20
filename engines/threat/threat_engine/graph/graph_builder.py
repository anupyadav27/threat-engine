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
    "sqs.queue": "SQSQueue",
    "sns.topic": "SNSTopic",
    "secretsmanager.secret": "SecretsManagerSecret",
    "elasticloadbalancing.loadbalancer": "LoadBalancer",
    "elasticloadbalancingv2.loadbalancer": "LoadBalancer",
    "cloudfront.distribution": "CloudFrontDistribution",
    "wafv2.web-acl": "WAFWebACL",
    "guardduty.detector": "GuardDutyDetector",
    "securityhub.hub": "SecurityHub",
    # ── Azure ────────────────────────────────────────────────────────────────
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
    "k8s.networkpolicy": "K8sNetworkPolicy",
}

# ── Internet-facing resource types per CSP ────────────────────────────────────
# These node labels indicate a resource that controls network ingress/egress.
# Used by _infer_internet_exposure() to detect public-facing paths.
_NETWORK_BOUNDARY_LABELS: Dict[str, List[str]] = {
    "aws":   ["SecurityGroup"],
    "azure": ["NetworkSecurityGroup"],
    "gcp":   ["VPCFirewallRule"],
    "oci":   ["SecurityList", "OCINetworkSecurityGroup"],
    "k8s":   ["K8sNetworkPolicy", "K8sIngress"],
}

# ── Storage resource types per CSP ────────────────────────────────────────────
# Used for public storage exposure inference.
_STORAGE_LABELS: Dict[str, str] = {
    "aws":   "S3Bucket",
    "azure": "StorageAccount",
    "gcp":   "GCSBucket",
    "oci":   "ObjectStorageBucket",
}


def _neo4j_label(resource_type: str) -> str:
    """Map resource type to Neo4j node label."""
    return RESOURCE_TYPE_LABELS.get(resource_type, "CloudResource")


# ── Relation type mapping ─────────────────────────────────────────────────────
# Maps inventory relation_type → Neo4j relationship type for attack-path traversal.
# The Cypher attack-path query traverses: CONNECTS_TO, ACCESSES, USES, ASSUMES,
# PROTECTED_BY, ROUTES_TO — so we map inventory types to these.
_RELATION_TYPE_MAP: Dict[str, str] = {
    # Network / topology
    "contained_by": "_CONTEXT",        # placeholder — overridden by _infer_rel_type()
    "attached_to":  "_CONTEXT",        # placeholder — overridden by _infer_rel_type()
    # IAM / access
    "uses":               "ASSUMES",   # instance-profile → role, lambda → role
    "assumes":            "ASSUMES",
    # Logging / audit
    "logging_enabled_to": "LOGS_TO",
    "logged_to":          "LOGS_TO",
    # Encryption
    "encrypted_by":       "ENCRYPTED_BY",
    "resolves_to":        "RESOLVES_TO",
    # Network membership
    "member_of":          "MEMBER_OF",
    "runs_on":            "RUNS_ON",
}


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
      EC2 → Volume    = USES
    """
    ft = from_type.lower()
    tt = to_type.lower()

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

    # Volume attachment
    if "volume" in tt:
        return "USES"

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
        """Load attack_path_category from resource_relationship_rules for Neo4j edge tagging."""
        from psycopg2.extras import RealDictCursor
        try:
            conn = self._pg_conn("threat_engine_inventory")
            try:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("""
                        SELECT DISTINCT relation_type, attack_path_category
                        FROM resource_relationship_rules
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
                    SELECT cf.id AS finding_id, cf.check_scan_id, cf.rule_id,
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
            "CREATE INDEX IF NOT EXISTS FOR (t:ThreatDetection) ON (t.severity)",
            "CREATE INDEX IF NOT EXISTS FOR (t:ThreatDetection) ON (t.resource_arn)",
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
        label_groups: Dict[str, List[str]] = {}
        for f in findings:
            label = _neo4j_label(f.get("resource_type", ""))
            if label != "CloudResource":
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

            all_params.setdefault(rel_type, []).append({
                "src": src, "dst": dst,
                "strength": rel.get("relationship_strength", "strong"),
                "attack_path_category": category or "",
                "relation_type_raw": raw_type,
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
                            r.relation_type_raw = p.relation_type_raw
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
                MERGE (r)-[:HAS_THREAT]->(t)
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
                    session.run("""
                        UNWIND $links AS lnk
                        MATCH (f:Finding {finding_id: lnk.fid})
                        MATCH (r:Resource {uid: lnk.ruid})
                        MERGE (r)-[:HAS_FINDING]->(f)
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

    def _create_internet_edges(self, session, tenant_id: str) -> int:
        """Wire the Internet virtual node to internet-facing resources.

        Creates the IGW → VPC → Subnet/EC2 flow path:
          Internet -[EXPOSES]-> InternetGateway
          InternetGateway -[CONNECTS_TO]-> VPC  (same region/account)
          VPC -[CONNECTS_TO]-> EC2Instance       (EC2 in same account/region via CONTAINED_BY)
        Also directly exposes S3 buckets that have public-access findings.
        """
        count = 0

        # 1. Internet → every InternetGateway node
        try:
            r = session.run("""
                MATCH (inet:Internet), (igw:Resource {tenant_id: $tid})
                WHERE igw.resource_type STARTS WITH 'ec2.internet-gateway'
                MERGE (inet)-[e:EXPOSES]->(igw)
                RETURN COUNT(e) AS c
            """, tid=tenant_id)
            rec = r.single()
            if rec:
                count += rec["c"]
        except Exception as exc:
            logger.debug(f"Internet→IGW edges failed: {exc}")

        # 2. InternetGateway → VPC in same region+account (IGW attaches to one VPC)
        try:
            r = session.run("""
                MATCH (igw:Resource {tenant_id: $tid})
                WHERE igw.resource_type STARTS WITH 'ec2.internet-gateway'
                MATCH (vpc:VPC {tenant_id: $tid, account_id: igw.account_id, region: igw.region})
                MERGE (igw)-[e:CONNECTS_TO]->(vpc)
                RETURN COUNT(e) AS c
            """, tid=tenant_id)
            rec = r.single()
            if rec:
                count += rec["c"]
        except Exception as exc:
            logger.debug(f"IGW→VPC edges failed: {exc}")

        # 3. VPC → EC2Instance in same region+account (instances live inside VPCs)
        try:
            r = session.run("""
                MATCH (vpc:VPC {tenant_id: $tid})
                MATCH (ec2:EC2Instance {tenant_id: $tid, account_id: vpc.account_id, region: vpc.region})
                MERGE (vpc)-[e:CONTAINS]->(ec2)
                RETURN COUNT(e) AS c
            """, tid=tenant_id)
            rec = r.single()
            if rec:
                count += rec["c"]
        except Exception as exc:
            logger.debug(f"VPC→EC2 edges failed: {exc}")

        # 4. EC2Instance → S3Bucket (via Lambda or direct: all S3 in same account reachable from EC2)
        #    Use ACCESSES edge type — only if both exist in the graph
        try:
            r = session.run("""
                MATCH (ec2:EC2Instance {tenant_id: $tid})
                MATCH (s3:S3Bucket {tenant_id: $tid, account_id: ec2.account_id})
                MERGE (ec2)-[e:ACCESSES]->(s3)
                RETURN COUNT(e) AS c
            """, tid=tenant_id)
            rec = r.single()
            if rec:
                count += rec["c"]
        except Exception as exc:
            logger.debug(f"EC2→S3 edges failed: {exc}")

        # 5. Lambda → S3Bucket in same account
        try:
            r = session.run("""
                MATCH (fn:LambdaFunction {tenant_id: $tid})
                MATCH (s3:S3Bucket {tenant_id: $tid, account_id: fn.account_id})
                MERGE (fn)-[e:ACCESSES]->(s3)
                RETURN COUNT(e) AS c
            """, tid=tenant_id)
            rec = r.single()
            if rec:
                count += rec["c"]
        except Exception as exc:
            logger.debug(f"Lambda→S3 edges failed: {exc}")

        return count

    def _infer_internet_exposure(self, session, tenant_id: str) -> int:
        """
        Infer internet exposure using check_findings (FAIL results from check engine).

        The check engine already evaluated rules like:
          - SG allows 0.0.0.0/0 inbound (port_*_exposed_to_internet rules)
          - S3 bucket is publicly accessible
          - EC2 instance has public IP
          - Lambda has public URL

        We use the Finding nodes (HAS_FINDING edges) to identify exposed resources
        instead of parsing raw configuration JSON.  This is more reliable because
        the check engine has already done the deep inspection.

        Strategy:
          1. Find resources with internet-exposure findings (rule_id patterns)
          2. Create Internet -[EXPOSES]-> Resource edges
          3. Also check configuration for public IPs as backup
        """
        count = 0

        # ── 1. Check findings that indicate internet exposure ──────────────────
        # These rule_id patterns cover SG open ports, public access, public IP, etc.
        exposure_patterns = [
            "exposed_to_internet",      # SG port_*_exposed_to_internet rules
            "public_access",            # S3/storage public access
            "publicly_accessible",      # RDS/Redshift publicly accessible
            "public_ip",                # EC2 public IP
            "unrestricted",             # unrestricted inbound/outbound
            "open_to_world",            # open to world
            "0_0_0_0",                  # literal 0.0.0.0 in rule ID
            "internet_facing",          # internet-facing resources
            "ingress_from_all",         # ingress from all IPs
        ]
        # Build OR condition for rule_id matching
        where_clauses = " OR ".join(
            f"f.rule_id CONTAINS '{p}'" for p in exposure_patterns
        )
        result = session.run(f"""
            MATCH (r:Resource {{tenant_id: $tid}})-[:HAS_FINDING]->(f:Finding)
            WHERE {where_clauses}
            RETURN DISTINCT r.uid AS uid, r.resource_type AS rtype,
                   collect(DISTINCT f.rule_id)[0..3] AS sample_rules
        """, tid=tenant_id)

        exposed_uids = set()
        for record in result:
            uid = record["uid"]
            if uid in exposed_uids:
                continue
            exposed_uids.add(uid)
            session.run("""
                MATCH (i:Internet {uid: 'INTERNET'})
                MATCH (r:Resource {uid: $uid})
                MERGE (i)-[e:EXPOSES]->(r)
                SET e.reason = 'check_finding_exposure',
                    e.resource_type = $rtype
            """, uid=uid, rtype=record["rtype"] or "")
            count += 1

        # ── 2. Public storage via findings ─────────────────────────────────────
        result = session.run("""
            MATCH (r:Resource {tenant_id: $tid})-[:HAS_FINDING]->(f:Finding)
            WHERE f.rule_id CONTAINS 'public'
               OR f.rule_id CONTAINS 'anonymous'
               OR f.title CONTAINS 'public'
            WITH DISTINCT r
            WHERE r.resource_type CONTAINS 's3'
               OR r.resource_type CONTAINS 'storage'
               OR r.resource_type CONTAINS 'bucket'
               OR r.resource_type CONTAINS 'blob'
            RETURN r.uid AS uid
        """, tid=tenant_id)
        for record in result:
            uid = record["uid"]
            if uid in exposed_uids:
                continue
            exposed_uids.add(uid)
            session.run("""
                MATCH (i:Internet {uid: 'INTERNET'})
                MATCH (r:Resource {uid: $uid})
                MERGE (i)-[e:EXPOSES]->(r)
                SET e.reason = 'public_storage_finding'
            """, uid=uid)
            count += 1

        # ── 3. Public IP from configuration (backup) ───────────────────────────
        result = session.run("""
            MATCH (r:Resource {tenant_id: $tid})
            WHERE r.configuration IS NOT NULL
              AND (
                r.configuration CONTAINS '"PublicIpAddress"'
                OR r.configuration CONTAINS '"public_ip"'
                OR r.configuration CONTAINS '"natIP"'
                OR r.configuration CONTAINS '"primaryPublicIPAddress"'
              )
              AND NOT (r.configuration CONTAINS '"PublicIpAddress": null')
              AND NOT (r.configuration CONTAINS '"PublicIpAddress": ""')
            RETURN r.uid AS uid
        """, tid=tenant_id)
        for record in result:
            uid = record["uid"]
            if uid in exposed_uids:
                continue
            exposed_uids.add(uid)
            session.run("""
                MATCH (i:Internet {uid: 'INTERNET'})
                MATCH (r:Resource {uid: $uid})
                MERGE (i)-[e:EXPOSES]->(r)
                SET e.reason = 'public_ip_assigned'
            """, uid=uid)
            count += 1

        logger.info(f"Inferred {count} internet exposure edges across all CSPs")
        return count

    # ── Main orchestrator ────────────────────────────────────────────────

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

            # 4i. Internet flow edges (Internet→IGW→VPC→EC2→S3)
            stats["internet_edges"] = self._create_internet_edges(session, tenant_id)
            logger.info(f"  → {stats['internet_edges']} internet flow edges")

            # 4j. Infer additional internet exposure from network boundary config
            stats["exposure_edges"] = self._infer_internet_exposure(session, tenant_id)
            logger.info(f"  → {stats['exposure_edges']} internet exposure edges")

        # Summary
        total_nodes = stats.get("virtual_nodes", 0) + stats.get("resource_nodes", 0) + \
                      stats.get("threat_nodes", 0) + stats.get("finding_nodes", 0)
        total_rels = stats.get("resource_rels", 0) + stats.get("hierarchy_rels", 0) + \
                     stats.get("analysis_edges", 0) + stats.get("exposure_edges", 0) + \
                     stats.get("internet_edges", 0)

        stats["total_nodes"] = total_nodes
        stats["total_relationships"] = total_rels

        logger.info(f"Security graph built: {total_nodes} nodes, {total_rels} relationships")
        return stats
