"""
Crown Jewel Classifier — AP-P1-01.

Classifies Neo4j Resource nodes as crown jewels based on resource type and
posture signals from resource_security_posture.

Classification criteria (architecture doc section 4.3):
  - Storage (s3.bucket, blob.container, gcs.bucket, oci.object_storage):
      ONLY when data_classification IN ('pii', 'financial', 'credentials')
  - Database (rds.instance, aurora.cluster, cloud_sql.instance, oci.autonomous_db):
      Always
  - Secrets (secretsmanager.secret, ssm.parameter with SecureString):
      Always
  - IAM (iam.role, iam.user):
      When is_admin_role=True OR has_wildcard_policy=True
  - K8s clusters (eks.cluster, aks.cluster, gke.cluster, k8s.cluster):
      Always
  - Container registries (ecr.repository, acr.registry, gcr.repository):
      Always
  - AI/ML (sagemaker.endpoint, bedrock.model, vertex_ai.endpoint):
      Always
  - Data warehouse / search (redshift.cluster, elasticsearch.domain,
      opensearch.domain, bigquery.dataset):
      Always
  - KMS / key vault (kms.key, key_vault.key):
      Always

Manual overrides from crown_jewel_overrides table always take precedence.
If the overrides table is missing (AP-P2-01 not yet migrated), logs a warning
and continues with auto-classification.

crown_jewel_type values:
  data, secrets, identity, infra_control, ai_model, code, data_warehouse, encryption_control

Security notes:
  - All Neo4j queries include tenant_id: $tid property filter.
  - posture_writer called with correct tenant_id from scan context.
  - Classification does NOT call json.loads() on JSONB posture fields.
  - Override lookup queries WHERE tenant_id = $tid AND resource_uid = $uid.
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Any, Dict, List, Optional, Set

import psycopg2.extras

logger = logging.getLogger("crown_jewel_classifier")

# ---------------------------------------------------------------------------
# Resource types that are ALWAYS crown jewels
# ---------------------------------------------------------------------------
_ALWAYS_CROWN_JEWEL: Dict[str, str] = {
    # Databases
    "rds.instance":              "data",
    "aurora.cluster":            "data",
    "cloud_sql.instance":        "data",
    "oci.autonomous_db":         "data",
    "oci.mysql":                 "data",
    "azure.sql_database":        "data",
    "azure.mysql_flexible":      "data",
    "azure.postgresql_flexible": "data",
    # Secrets / parameters
    "secretsmanager.secret":     "secrets",
    "ssm.parameter":             "secrets",
    "azure.key_vault_secret":    "secrets",
    "gcp.secret_manager":        "secrets",
    # K8s clusters
    "eks.cluster":               "infra_control",
    "aks.cluster":               "infra_control",
    "gke.cluster":               "infra_control",
    "k8s.cluster":               "infra_control",
    "oci.oke_cluster":           "infra_control",
    # Container registries
    "ecr.repository":            "code",
    "acr.registry":              "code",
    "gcr.repository":            "code",
    "artifact_registry.repo":    "code",
    # AI/ML
    "sagemaker.endpoint":        "ai_model",
    "sagemaker.model":           "ai_model",
    "bedrock.model":             "ai_model",
    "vertex_ai.endpoint":        "ai_model",
    "azure.ml_workspace":        "ai_model",
    # Data warehouse / search
    "redshift.cluster":          "data_warehouse",
    "elasticsearch.domain":      "data_warehouse",
    "opensearch.domain":         "data_warehouse",
    "bigquery.dataset":          "data_warehouse",
    "azure.synapse":             "data_warehouse",
    # KMS / key vault
    "kms.key":                   "encryption_control",
    "key_vault.key":             "encryption_control",
    "gcp.kms_key":               "encryption_control",
    "oci.vault_key":             "encryption_control",
    # K8s control plane (AC-11)
    "k8s.etcd":                  "infra_control",
    # K8s secrets — always classified (conservative; any secret could be sensitive) (AC-11)
    "k8s.secret":                "secrets",
}

# Storage types that are crown jewels ONLY with sensitive data classification
_STORAGE_TYPES: Set[str] = {
    "s3.bucket",
    "blob.container",
    "gcs.bucket",
    "oci.object_storage",
    "adls.filesystem",
    "azure.storage_blob",
}

# IAM types that depend on posture signals
_IAM_TYPES: Set[str] = {
    "iam.role",
    "iam.user",
    "azure.service_principal",
    "gcp.service_account",
    "oci.iam_user",
}

# K8s workload types classified when privileged (AC-11)
_K8S_PRIVILEGED_TYPES: Set[str] = {
    "k8s.daemonset",
    "k8s.deployment",
    "k8s.statefulset",
}

# K8s ServiceAccount classified when RBAC over-permissive (AC-11)
_K8S_SA_TYPES: Set[str] = {
    "k8s.serviceaccount",
}

# K8s ConfigMap classified when it contains sensitive key names (AC-11)
_K8S_CONFIGMAP_TYPES: Set[str] = {
    "k8s.configmap",
}

_SENSITIVE_CM_PATTERNS = ("password", "secret", "token", "key", "credential", "cert")

# AI endpoint types that are crown jewels when publicly accessible OR training data has PII
_AI_ENDPOINT_TYPES: Set[str] = {
    "sagemaker_endpoint",
    "sagemaker.endpoint",
    "bedrock_model",
    "bedrock.model",
    "sagemaker_notebook",
    "sagemaker.notebook",
    "vertex_ai.endpoint",
    "azure.ml_workspace",
}

# Sensitive data classifications for storage crown jewels
_SENSITIVE_DATA_CLASSES: Set[str] = {"pii", "financial", "credentials"}

# Aliases from full-namespace resource types (as stored in Neo4j by graph-build)
# to the canonical short names used by the classifier sets above.
# Format: actual Neo4j resource_type → canonical type
_TYPE_ALIASES: Dict[str, str] = {
    # K8s — graph-build stores bare names or full k8s.apps/Kind paths
    "secret":                               "k8s.secret",
    "secrets":                              "k8s.secret",
    "k8s.apps/replicaset":                  "k8s.deployment",
    "replicaset":                           "k8s.daemonset",
    "replicaset.k8s.apps/replicaset":       "k8s.deployment",
    "deployments":                          "k8s.deployment",
    "daemonset":                            "k8s.daemonset",
    "daemonsets":                           "k8s.daemonset",
    "statefulsets":                         "k8s.statefulset",
    "serviceaccount":                       "k8s.serviceaccount",
    "serviceaccounts":                      "k8s.serviceaccount",
    "configmap":                            "k8s.configmap",
    # GCP — graph-build may add gcp. prefix or use different surface name
    "gcp.gcs_bucket":                       "gcs.bucket",
    "gcp.iam_service_account":              "gcp.service_account",
    "gcp.secret_manager_secret":            "gcp.secret_manager",
    "gcp.kms_cryptokey":                    "gcp.kms_key",
    "gcp.bigquery":                         "bigquery.dataset",
    "gcp.bigquery_table":                   "bigquery.dataset",
    "gcp.cloud_sql":                        "cloud_sql.instance",
    "gcp.gke_cluster":                      "gke.cluster",
    "gcp.artifact_registry":                "artifact_registry.repo",
    # OCI — graph-build stores full objectstorage path
    "object_storage.oci.objectstorage/bucket": "oci.object_storage",
    "oci.objectstorage_bucket":             "oci.object_storage",
    "oci.object_storage_bucket":            "oci.object_storage",
    "database.oci.database/autonomousdatabase": "oci.autonomous_db",
    "oci.autonomous_database":              "oci.autonomous_db",
    "containerengine.oci.containerengine/cluster": "oci.oke_cluster",
    "oci.oke":                              "oci.oke_cluster",
    "vault.oci.keymanagement/key":          "oci.vault_key",
    "oci.vault":                            "oci.vault_key",
    # AliCloud RAM — graph-build stores full ram.alicloud.ram/Kind paths
    "ram.alicloud.ram/role":                "iam.role",
    "ram.alicloud.ram/user":                "iam.user",
    "oss.alicloud.oss/bucket":              "s3.bucket",
    "rds.alicloud.rds/dbinstance":          "rds.instance",
    # Azure — alternate surface names
    "azure.storage_account":               "blob.container",
    "azure.keyvault_secret":               "azure.key_vault_secret",
    "azure.kubernetes_cluster":            "aks.cluster",
    # AWS — alternate surface names that graph-build may emit
    "aws.secretsmanager_secret":            "secretsmanager.secret",
    "aws.rds_instance":                     "rds.instance",
    "aws.s3_bucket":                        "s3.bucket",
    "aws.kms_key":                          "kms.key",
    "aws.eks_cluster":                      "eks.cluster",
    "aws.ecr_repository":                   "ecr.repository",
    "aws.redshift_cluster":                 "redshift.cluster",
    "aws.opensearch_domain":                "opensearch.domain",
    "aws.elasticsearch_domain":             "elasticsearch.domain",
}


class CrownJewelClassifier:
    """Classifies Neo4j resource nodes as crown jewels.

    Called from run_scan.py at the start of each attack-path scan.
    Writes is_crown_jewel and crown_jewel_type to Neo4j nodes via MERGE/SET.
    Writes same signals to resource_security_posture via posture_writer.
    """

    def __init__(
        self,
        neo4j_driver: Any,
        inventory_conn: Any,
        scan_run_id: str,
        tenant_id: str,
        account_id: str = "",
        provider: str = "aws",
    ) -> None:
        """Initialise the classifier.

        Args:
            neo4j_driver:    neo4j.GraphDatabase driver instance.
            inventory_conn:  psycopg2 connection to threat_engine_inventory DB.
            scan_run_id:     Current pipeline run UUID.
            tenant_id:       Tenant identifier (from scan context — NOT from resource props).
            account_id:      Cloud account ID.
            provider:        CSP identifier.
        """
        self.neo4j_driver = neo4j_driver
        self.inventory_conn = inventory_conn
        self.scan_run_id = scan_run_id
        self.tenant_id = tenant_id
        self.account_id = account_id
        self.provider = provider

    # ---------------------------------------------------------------------------
    # Public interface
    # ---------------------------------------------------------------------------

    def classify(self) -> int:
        """Run the full classification pipeline.

        Returns:
            Number of resources classified as crown jewels.
        """
        overrides = self._load_overrides()
        posture_rows = self._load_posture_signals()
        resources = self._load_neo4j_resources()

        classified_count = 0
        for res in resources:
            uid = res.get("uid") or res.get("resource_uid", "")
            if not uid:
                continue

            # Manual override takes precedence (AC-14)
            if uid in overrides:
                override = overrides[uid]
                if not override.get("is_crown_jewel", True):
                    # Analyst explicitly marked this as non-crown-jewel
                    continue
                # Analyst tagged as crown jewel — use their type
                cj_type = override.get("crown_jewel_type", "data") or "data"
                self._mark_neo4j(uid, cj_type)
                self._mark_posture(uid, cj_type, res)
                classified_count += 1
                continue

            # Posture override (AP-ENHANCE-02): threat-v1 wrote is_crown_jewel=true
            # for T2/T3 incident targets — trust that signal and skip heuristics.
            posture = posture_rows.get(uid, {})
            if posture.get("is_crown_jewel"):
                cj_type = posture.get("crown_jewel_type") or "data"
                self._mark_neo4j(uid, cj_type)
                self._mark_posture(uid, cj_type, res)
                classified_count += 1
                continue

            # Auto-classification
            cj_type = self._auto_classify(uid, res, posture)
            if cj_type:
                self._mark_neo4j(uid, cj_type)
                self._mark_posture(uid, cj_type, res)
                classified_count += 1

        logger.info(
            '{"engine":"attack-path","stage":"crown_jewel_classify",'
            '"tenant_id":"%s","classified":%d,"total_resources":%d}',
            self.tenant_id,
            classified_count,
            len(resources),
        )
        return classified_count

    # ---------------------------------------------------------------------------
    # Private helpers
    # ---------------------------------------------------------------------------

    def _auto_classify(
        self,
        uid: str,
        resource: Dict[str, Any],
        posture: Dict[str, Any],
    ) -> Optional[str]:
        """Return crown_jewel_type string or None.

        Args:
            uid:       Resource UID.
            resource:  Neo4j resource node dict.
            posture:   Matching posture row dict (may be empty if not yet stored).
        """
        rtype = (resource.get("resource_type") or "").lower()
        # Normalize to canonical short name (handles full-path types from graph-build)
        rtype = _TYPE_ALIASES.get(rtype, rtype)

        # Storage: only sensitive data (AC-2)
        if rtype in _STORAGE_TYPES:
            dc = (posture.get("data_classification") or resource.get("data_classification") or "").lower()
            if dc in _SENSITIVE_DATA_CLASSES:
                return "data"
            return None

        # IAM: only admin role or wildcard policy (AC-5)
        if rtype in _IAM_TYPES:
            is_admin = posture.get("is_admin_role") or resource.get("is_admin_role") or False
            has_wildcard = posture.get("has_wildcard_policy") or resource.get("has_wildcard_policy") or False
            if is_admin or has_wildcard:
                return "identity"
            return None

        # AI endpoints: crown jewel when publicly accessible OR training data has PII (PC-P2-04)
        if rtype in _AI_ENDPOINT_TYPES:
            publicly_accessible = posture.get("ai_model_publicly_accessible") or False
            training_pii = posture.get("ai_training_data_has_pii") or False
            if publicly_accessible or training_pii:
                return "ai_endpoint"
            # Fall through to _ALWAYS_CROWN_JEWEL check below for always-crown-jewel AI types

        # K8s privileged workloads (AC-11)
        if rtype in _K8S_PRIVILEGED_TYPES:
            if posture.get("has_privileged_container") or resource.get("has_privileged_container"):
                return "k8s_privileged_workload"
            return None

        # K8s ServiceAccount over-permissive RBAC (AC-11)
        if rtype in _K8S_SA_TYPES:
            if posture.get("k8s_rbac_overpermissive") or resource.get("k8s_rbac_overpermissive"):
                return "k8s_cluster_admin"
            return None

        # K8s ConfigMap with sensitive key names (AC-11)
        if rtype in _K8S_CONFIGMAP_TYPES:
            name = (resource.get("name") or resource.get("resource_uid") or "").lower()
            if any(p in name for p in _SENSITIVE_CM_PATTERNS):
                return "k8s_secrets"
            return None

        # Always-crown-jewel resource types (AC-3, AC-4, AC-6, AC-7, AC-8, AC-9, AC-10, AC-11)
        cj_type = _ALWAYS_CROWN_JEWEL.get(rtype)
        return cj_type

    def _mark_neo4j(self, uid: str, crown_jewel_type: str) -> None:
        """Set is_crown_jewel=true and crown_jewel_type on the Neo4j node.

        All MATCH clauses include tenant_id: $tid (AC-15).
        """
        if not self.neo4j_driver:
            return
        try:
            with self.neo4j_driver.session(database="neo4j") as session:
                session.run(
                    """
                    MATCH (r:Resource {tenant_id: $tid, uid: $uid})
                    SET r.is_crown_jewel = true,
                        r.crown_jewel_type = $type
                    """,
                    tid=self.tenant_id,
                    uid=uid,
                    type=crown_jewel_type,
                )
        except Exception as exc:
            logger.warning("Neo4j crown jewel set failed uid=%s: %s", uid, exc)

    def _mark_posture(
        self,
        uid: str,
        crown_jewel_type: str,
        resource: Dict[str, Any],
    ) -> None:
        """Write crown jewel signals to resource_security_posture (AC-12, AC-16)."""
        try:
            from engine_common.posture_writer import upsert_posture_signals
        except ImportError:
            logger.warning("posture_writer not available — skipping posture update for uid=%s", uid)
            return

        try:
            upsert_posture_signals(
                self.inventory_conn,
                resource_uid=uid,
                scan_run_id=self.scan_run_id,
                tenant_id=self.tenant_id,    # from scan context, NOT from resource props (AC-16)
                account_id=self.account_id,
                provider=self.provider,
                resource_type=resource.get("resource_type") or "",
                region=resource.get("region"),
                resource_name=resource.get("name") or resource.get("resource_name"),
                is_crown_jewel=True,
                crown_jewel_type=crown_jewel_type,
            )
        except Exception as exc:
            logger.warning("posture write failed uid=%s: %s", uid, exc)

    def _load_overrides(self) -> Dict[str, Dict[str, Any]]:
        """Load manual crown jewel overrides for this tenant.

        Returns dict: resource_uid → {is_crown_jewel, crown_jewel_type}.
        Gracefully handles missing table (AP-P2-01 not yet migrated).
        """
        overrides: Dict[str, Dict[str, Any]] = {}
        try:
            # NOTE: We query via the attack_path DB connection, not inventory.
            # The overrides table lives in threat_engine_attack_path.
            from engine_common.db_connections import get_attack_path_conn
            ap_conn = get_attack_path_conn()
            try:
                with ap_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute(
                        """
                        SELECT resource_uid, is_crown_jewel, crown_jewel_type
                        FROM crown_jewel_overrides
                        WHERE tenant_id = %s
                        """,
                        (self.tenant_id,),
                    )
                    for row in cur.fetchall():
                        overrides[row["resource_uid"]] = dict(row)
            finally:
                ap_conn.close()
        except Exception as exc:
            logger.warning(
                "crown_jewel_overrides table not accessible — "
                "continuing with auto-classification only. Error: %s",
                exc,
            )
        return overrides

    def _load_posture_signals(self) -> Dict[str, Dict[str, Any]]:
        """Load posture signals for this (scan_run_id, tenant_id).

        Returns dict: resource_uid → posture row dict.
        JSONB fields auto-deserialized by psycopg2 — no json.loads() (AC-17).
        """
        posture: Dict[str, Dict[str, Any]] = {}
        try:
            with self.inventory_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT resource_uid, data_classification, is_admin_role,
                           has_wildcard_policy, crown_jewel_type, is_crown_jewel
                    FROM resource_security_posture
                    WHERE tenant_id = %s AND scan_run_id = %s
                    """,
                    (self.tenant_id, self.scan_run_id),
                )
                for row in cur.fetchall():
                    posture[row["resource_uid"]] = dict(row)
        except Exception as exc:
            logger.warning("Failed to load posture signals: %s", exc)
        return posture

    def _load_neo4j_resources(self) -> List[Dict[str, Any]]:
        """Load all Resource nodes for this tenant from Neo4j.

        Returns list of dicts with uid, resource_type, and available properties.
        All MATCH clauses include tenant_id: $tid (AC-15).
        """
        if not self.neo4j_driver:
            return []
        resources: List[Dict[str, Any]] = []
        try:
            with self.neo4j_driver.session(database="neo4j") as session:
                result = session.run(
                    """
                    MATCH (r:Resource {tenant_id: $tid})
                    RETURN
                        r.uid AS uid,
                        r.resource_type AS resource_type,
                        r.region AS region,
                        r.name AS name,
                        r.data_classification AS data_classification,
                        r.is_admin_role AS is_admin_role,
                        r.has_wildcard_policy AS has_wildcard_policy
                    """,
                    tid=self.tenant_id,
                )
                for record in result:
                    resources.append(dict(record))
        except Exception as exc:
            logger.error("Failed to load Neo4j resources: %s", exc)
        return resources
