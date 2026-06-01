"""
Crown Jewel Classifier — AP-P1-01.

Classifies Neo4j Resource nodes as crown jewels based on resource type and
posture signals from resource_security_posture.

Classification criteria (architecture doc section 4.3):
  - Storage (s3.bucket, blob.container, gcs.bucket, oci.object_storage):
      ONLY when data_classification IN ('pii', 'financial', 'credentials')
  - Database (rds.instance, aurora.cluster, cloud_sql.instance, dynamodb.table,
      documentdb.cluster, elasticache.cluster, emr.cluster, neptune.cluster, etc.):
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
from typing import Any, Dict, List, Optional

import psycopg2.extras

logger = logging.getLogger("crown_jewel_classifier")

# ---------------------------------------------------------------------------
# Category-based crown jewel rules (single source of truth = di_resource_catalog)
#
# These dicts define WHICH categories are crown jewels and what type they map to.
# The actual resource_type → crown_jewel_type mapping is loaded at runtime by
# _load_from_di_catalog() which queries di_resource_catalog in threat_engine_di.
# No individual resource types are hardcoded here — new services added to the
# catalog are automatically classified without any code changes.
# ---------------------------------------------------------------------------
_CROWN_JEWEL_CATEGORIES: Dict[str, str] = {
    "database":   "data",               # RDS, DynamoDB, Aurora, CosmosDB, Firestore, OCI MySQL...
    "storage":    "data",               # S3, EBS, EFS, GCS, Azure Blob, AliCloud OSS, OCI Object...
    "analytics":  "data_warehouse",     # Redshift, BigQuery, Athena, Synapse, EMR, Glue...
    "encryption": "encryption_control", # KMS, Key Vault, GCP KMS, OCI Vault, Secrets Manager...
    "ai_ml":      "ai_model",           # SageMaker, Bedrock, Vertex AI, Azure ML...
    "messaging":  "data_warehouse",     # Kinesis, MSK, EventHub, SQS, Kafka...
}

# Container subcategories — split because registry ≠ orchestration
_CROWN_JEWEL_CONTAINER_SUBCATEGORY: Dict[str, str] = {
    "orchestration_k8s":     "infra_control",   # EKS, AKS, GKE, OKE
    "orchestration_managed": "infra_control",   # ECS, GKE Autopilot, AKS managed
    "registry":              "code",             # ECR, ACR, GCR, AliCloud Container Registry
}

# Word patterns that indicate a K8s ConfigMap holds sensitive data.
# These are semantic content rules — they cannot be expressed as resource type metadata.
_SENSITIVE_CM_PATTERNS = ("password", "secret", "token", "key", "credential", "cert")

# Generic type names that appear across dozens of services in di_resource_catalog.
# Adding these as bare keys to _catalog_types would classify every record of that
# type (e.g. all 3 k+ "resource"-type rows in asset_inventory) as a crown jewel,
# regardless of which service they belong to. Only service-qualified forms like
# "rds.resource" or "sagemaker.action" should match for these names.
_BARE_KEY_BLOCKLIST: frozenset = frozenset({
    "resource", "action", "config", "image", "lambda", "recipe",
    "indexe", "kms",
    # Generic names used by many services — only service-qualified forms should match.
    # e.g. "opensearch.domain" = valid CJ; bare "domain" from apigateway/route53 = not a CJ.
    "domain", "key", "policy", "certificate",
})

# Compound resource types that are sub-resources / metadata — not data stores or secrets.
# Both underscore and dot forms are listed because asset_inventory stores either convention.
# The denylist is checked against both rtype and rtype_dot in _auto_classify().
_COMPOUND_TYPE_DENYLIST: frozenset = frozenset({
    # TLS certs / CA bundles
    "rds_certificate", "rds.certificate",
    "acm_certificate", "acm.certificate",
    "kms_certificate", "kms.certificate",
    # Sub-resource metadata
    "key_rotation_status", "key.rotation.status",
    "key_policy", "key.policy",
    # RDS operational sub-resources (not data stores)
    "rds_db_recommendation", "rds.db.recommendation",
    "rds_db_snapshot", "rds.db.snapshot",
    "rds_db_cluster_snapshot", "rds.db.cluster.snapshot",
})

# ---------------------------------------------------------------------------
# Conditional classification rules — driven by di_resource_catalog subcategory.
#
# Maps di_resource_catalog.subcategory → condition key used by _auto_classify().
# The condition key tells the classifier WHICH posture signal to check.
# Resource types themselves are NOT listed here — they come from the catalog query.
# ---------------------------------------------------------------------------
_CONDITIONAL_SUBCATEGORIES: Dict[str, str] = {
    # identity subcategories → check is_admin_role or has_wildcard_policy
    "iam_role":        "iam",
    "iam_user":        "iam",
    "service_account": "iam",
    "federation":      "iam",
    # container workload subcategories → check has_privileged_container
    "workload":        "k8s_privileged",
    # container serviceaccount subcategory → check k8s_rbac_overpermissive
    "serviceaccount":  "k8s_sa",
    # container config subcategory → check name for sensitive patterns
    "config":          "k8s_configmap",
}

# Resource types that are always crown jewels regardless of di_resource_catalog classification.
# These are strategic account-level control plane targets (ACCOUNT_TAKEOVER).
# organizations_account = root of the AWS account hierarchy; always a high-value target.
# iam_root_user = AWS account root; if accessible, full account takeover is possible.
# Keyed by both underscore (asset_inventory) and dot (DI engine) forms.
_ALWAYS_CJ_RESOURCE_TYPES: Dict[str, str] = {
    "organizations_account":  "infra_control",
    "organizations.account":  "infra_control",
    "iam_root_user":          "infra_control",
    "iam.root_user":          "infra_control",
    # K8s / container cluster types — always infra_control regardless of di_resource_catalog state
    "eks.cluster":            "infra_control",
    "eks_cluster":            "infra_control",
    "ecs_cluster":            "infra_control",
    "ecs.cluster":            "infra_control",
    "aks.cluster":            "infra_control",
    "aks_cluster":            "infra_control",
    "gke.cluster":            "infra_control",
    "gke_cluster":            "infra_control",
    "k8s.cluster":            "infra_control",
    "k8s_cluster":            "infra_control",
}


class CrownJewelClassifier:
    """Classifies resources as crown jewels using PostgreSQL only.

    Called from run_scan.py at the start of each attack-path scan.
    Reads resources from asset_inventory (threat_engine_di).
    Writes is_crown_jewel and crown_jewel_type to resource_security_posture.
    """

    def __init__(
        self,
        inventory_conn: Any,
        scan_run_id: str,
        tenant_id: str,
        account_id: str = "",
        provider: str = "aws",
    ) -> None:
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
        self._load_from_di_catalog()
        overrides = self._load_overrides()
        posture_rows = self._load_posture_signals()
        resources = self._load_resources_from_inventory()

        classified_count = 0
        classified_uids: set = set()
        for res in resources:
            uid = res.get("resource_uid", "")
            if not uid:
                continue

            # Priority 1: Manual override — analyst decision always wins.
            if uid in overrides:
                override = overrides[uid]
                if not override.get("is_crown_jewel", True):
                    continue
                cj_type = override.get("crown_jewel_type", "data") or "data"
                self._mark_posture(uid, cj_type, res)
                classified_count += 1
                classified_uids.add(uid)
                continue

            # Priority 2: catalog category-based + conditional posture rules.
            posture = posture_rows.get(uid, {})
            cj_type = self._auto_classify(res, posture)
            if cj_type:
                self._mark_posture(uid, cj_type, res)
                classified_count += 1
                classified_uids.add(uid)

        # Pass 2: admin IAM roles that have is_admin_role=TRUE in RSP but are not
        # present in asset_inventory (e.g. SSO reserved roles, cross-account roles).
        # These are always crown jewels for ACCOUNT_TAKEOVER / PRIVILEGE_ESCALATION.
        _iam_role_rtypes = {"iam_role", "iam.role", "iam_user", "iam.user"}
        for uid, posture in posture_rows.items():
            if uid in classified_uids:
                continue
            rtype = (posture.get("resource_type") or "").lower()
            if rtype not in _iam_role_rtypes:
                continue
            if not posture.get("is_admin_role"):
                continue
            self._mark_posture(uid, "identity", {"resource_type": rtype, "provider": "aws"})
            classified_count += 1
            classified_uids.add(uid)

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
        resource: Dict[str, Any],
        posture: Dict[str, Any],
    ) -> Optional[str]:
        """Return crown_jewel_type string or None."""
        rtype = (resource.get("resource_type") or "").lower()
        # Normalize using aliases loaded from di_resource_catalog.canonical_type
        rtype = self._type_aliases.get(rtype, rtype)
        # Dot-normalized form: asset_inventory uses both s3_bucket (underscore) and
        # dynamodb.table (dot); catalog keys include both forms after _load_from_di_catalog.
        rtype_dot = rtype.replace("_", ".")

        # Reject known false-positive compound types (TLS certs, rotation metadata, etc.)
        # Check both underscore and dot forms — asset_inventory uses either convention.
        if rtype in _COMPOUND_TYPE_DENYLIST or rtype_dot in _COMPOUND_TYPE_DENYLIST:
            return None

        # Always-CJ strategic control plane resources (ACCOUNT_TAKEOVER, CLUSTER_TAKEOVER).
        cj_type = _ALWAYS_CJ_RESOURCE_TYPES.get(rtype) or _ALWAYS_CJ_RESOURCE_TYPES.get(rtype_dot)
        if cj_type:
            return cj_type

        # Conditional rules — which resource types undergo these checks is driven
        # by di_resource_catalog.subcategory via _CONDITIONAL_SUBCATEGORIES.
        condition = self._conditional_types.get(rtype) or self._conditional_types.get(rtype_dot)
        if condition == "iam":
            is_admin = posture.get("is_admin_role") or resource.get("is_admin_role") or False
            has_wildcard = posture.get("has_wildcard_policy") or resource.get("has_wildcard_policy") or False
            return "identity" if (is_admin or has_wildcard) else None

        if condition == "k8s_privileged":
            privileged = posture.get("has_privileged_container") or resource.get("has_privileged_container")
            return "k8s_privileged_workload" if privileged else None

        if condition == "k8s_sa":
            overpermissive = posture.get("k8s_rbac_overpermissive") or resource.get("k8s_rbac_overpermissive")
            return "k8s_cluster_admin" if overpermissive else None

        if condition == "k8s_configmap":
            name = (resource.get("name") or resource.get("resource_uid") or "").lower()
            return "k8s_secrets" if any(p in name for p in _SENSITIVE_CM_PATTERNS) else None

        # Always-CJ lookup — fully driven by di_resource_catalog.category.
        # Covers all CSPs for: database, storage, analytics, encryption, ai_ml,
        # messaging, container registries + orchestration.
        # Try plain type first, then dot-normalized (handles s3_bucket → s3.bucket).
        return self._catalog_types.get(rtype) or self._catalog_types.get(rtype_dot)

    def _load_resources_from_inventory(self) -> List[Dict[str, Any]]:
        """Load all resources for this tenant from asset_inventory (threat_engine_di).

        Returns list of dicts with resource_uid, resource_type, region, resource_name,
        account_id, provider, and emitted_fields (for data_classification signals).
        """
        resources: List[Dict[str, Any]] = []
        try:
            with self.inventory_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT DISTINCT ON (resource_uid)
                        resource_uid,
                        resource_type,
                        resource_name,
                        region,
                        account_id,
                        provider,
                        emitted_fields
                    FROM asset_inventory
                    WHERE tenant_id = %s
                      AND resource_uid IS NOT NULL
                      AND resource_uid != ''
                    ORDER BY resource_uid, last_seen_at DESC
                    """,
                    (self.tenant_id,),
                )
                for row in cur.fetchall():
                    resources.append(dict(row))
        except Exception as exc:
            logger.error("Failed to load resources from asset_inventory: %s", exc)
            try:
                self.inventory_conn.rollback()
            except Exception:
                pass
        return resources

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

        # Derive provider from the resource's own asset_inventory.provider field so that
        # a GCP/K8s scan does not overwrite AWS ARNs with the wrong provider in RSP.
        # ARN prefix is the authoritative fallback — it cannot be wrong.
        resource_provider = self._derive_provider(uid, resource.get("provider") or "")

        try:
            upsert_posture_signals(
                self.inventory_conn,
                resource_uid=uid,
                scan_run_id=self.scan_run_id,
                tenant_id=self.tenant_id,    # from scan context, NOT from resource props (AC-16)
                account_id=self.account_id,
                provider=resource_provider,
                resource_type=resource.get("resource_type") or "",
                region=resource.get("region"),
                resource_name=resource.get("name") or resource.get("resource_name"),
                is_crown_jewel=True,
                crown_jewel_type=crown_jewel_type,
            )
        except Exception as exc:
            logger.warning("posture write failed uid=%s: %s", uid, exc)
            # Rollback aborted transaction so subsequent writes on the same connection succeed
            try:
                self.inventory_conn.rollback()
            except Exception:
                pass

    @staticmethod
    def _derive_provider(uid: str, resource_provider: str) -> str:
        """Return the correct CSP provider for a resource_uid.

        ARN prefix is authoritative — it cannot be forged by scan context.
        Falls back to the asset_inventory.provider field, then empty string.
        """
        if uid.startswith("arn:aws:"):
            return "aws"
        if uid.startswith("/subscriptions/"):
            return "azure"
        if uid.startswith("projects/") or uid.startswith("//"):
            return "gcp"
        if uid.startswith("ocid1."):
            return "oci"
        return resource_provider or ""

    def _load_from_di_catalog(self) -> None:
        """Populate three runtime lookups from di_resource_catalog in threat_engine_di.

        Sets on self:
          _catalog_types:     resource_type → crown_jewel_type  (always crown jewels)
          _conditional_types: resource_type → condition_key     (needs posture check)
          _type_aliases:      raw_type      → canonical_type    (normalization)

        All three default to empty dicts — classification degrades gracefully if the
        DI DB is unreachable or di_resource_catalog has no rows yet.
        """
        self._catalog_types: Dict[str, str] = {}
        self._conditional_types: Dict[str, str] = {}
        self._type_aliases: Dict[str, str] = {}

        try:
            from engine_common.db_connections import get_di_conn
            di_conn = get_di_conn()
            try:
                all_categories = (
                    list(_CROWN_JEWEL_CATEGORIES.keys())
                    + ["container", "identity"]
                )
                with di_conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT service, resource_type, category, subcategory, canonical_type
                        FROM di_resource_catalog
                        WHERE category = ANY(%s)
                          AND resource_type IS NOT NULL
                        """,
                        (all_categories,),
                    )
                    for service, resource_type, category, subcategory, canonical_type in cur.fetchall():
                        sub = subcategory or ""
                        svc = (service or "").lower()
                        rtype = (resource_type or "").lower()

                        # Hard-skip sub-resource types in the compound denylist even when
                        # di_resource_catalog lists them under an encryption/storage category.
                        # Without this guard, key_rotation_status and key_policy get loaded
                        # into _catalog_types and bypass the denylist check in _auto_classify().
                        rtype_dot = rtype.replace("_", ".")
                        if rtype in _COMPOUND_TYPE_DENYLIST or rtype_dot in _COMPOUND_TYPE_DENYLIST:
                            continue

                        # Build all key variants to match both naming conventions:
                        #   - "service.resource-type" (dot notation, DI engine format)
                        #   - "service_resource_type" (underscore, CloudQuery/boto3 format)
                        # Generic types (resource, action, config, image, etc.) must NOT
                        # be added as bare keys — they match too broadly across services.
                        keys = [] if rtype in _BARE_KEY_BLOCKLIST else [rtype]
                        if svc:
                            dot_key = f"{svc}.{rtype}"
                            keys.append(dot_key)
                            keys.append(dot_key.replace(".", "_"))    # s3.bucket → s3_bucket
                            keys.append(f"{svc}.{rtype.replace('_', '-')}")

                        # --- Type alias (raw Neo4j form → catalog canonical form) ---
                        if canonical_type and canonical_type != resource_type:
                            for k in keys:
                                self._type_aliases[k] = canonical_type

                        # --- Always-CJ categories ---
                        if category in _CROWN_JEWEL_CATEGORIES:
                            for k in keys:
                                self._catalog_types[k] = _CROWN_JEWEL_CATEGORIES[category]

                        # --- Container: registry/orchestration = always CJ;
                        #     workload/serviceaccount/config = conditional ---
                        elif category == "container":
                            cj_type = _CROWN_JEWEL_CONTAINER_SUBCATEGORY.get(sub)
                            if cj_type:
                                for k in keys:
                                    self._catalog_types[k] = cj_type
                            elif sub in _CONDITIONAL_SUBCATEGORIES:
                                for k in keys:
                                    self._conditional_types[k] = (
                                        _CONDITIONAL_SUBCATEGORIES[sub]
                                    )

                        # --- Identity: always conditional (needs posture check) ---
                        elif category == "identity":
                            condition = _CONDITIONAL_SUBCATEGORIES.get(sub)
                            if condition:
                                for k in keys:
                                    self._conditional_types[k] = condition

                logger.info(
                    '{"engine":"attack-path","stage":"di_catalog_load","tenant_id":"%s",'
                    '"always_cj":%d,"conditional":%d,"aliases":%d}',
                    self.tenant_id,
                    len(self._catalog_types),
                    len(self._conditional_types),
                    len(self._type_aliases),
                )
            finally:
                di_conn.close()
        except Exception as exc:
            logger.warning(
                "di_resource_catalog lookup failed — classification uses empty catalog "
                "(only conditional posture rules will run): %s",
                exc,
            )

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
        """Load posture signals needed for conditional classification rules.

        Returns dict: resource_uid → posture row dict.
        JSONB fields auto-deserialized by psycopg2 — no json.loads() (AC-17).

        Columns loaded:
          - has_privileged_container  → K8s privileged workload check
          - k8s_rbac_overpermissive   → K8s ServiceAccount check
          - is_admin_role             → IAM admin role check (fallback; primary from Neo4j props)
          - has_wildcard_policy       → IAM wildcard policy check (fallback; primary from Neo4j props)

        is_crown_jewel is intentionally NOT loaded — threat-v1 engine is being removed
        and is no longer a trusted signal source. Crown jewel state is owned entirely
        by this classifier going forward.
        """
        posture: Dict[str, Dict[str, Any]] = {}
        try:
            with self.inventory_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT resource_uid,
                           resource_type,
                           has_privileged_container,
                           k8s_rbac_overpermissive,
                           is_admin_role
                    FROM resource_security_posture
                    WHERE tenant_id = %s
                    """,
                    (self.tenant_id,),
                )
                for row in cur.fetchall():
                    posture[row["resource_uid"]] = dict(row)
        except Exception as exc:
            logger.warning("Failed to load posture signals: %s", exc)
            try:
                self.inventory_conn.rollback()
            except Exception:
                pass
        return posture

