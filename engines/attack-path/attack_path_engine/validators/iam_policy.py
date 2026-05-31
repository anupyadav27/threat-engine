"""
Validator: IAM Policy (IAM-001..003)

Reads iam_policy_statements for this tenant/scan, maps Allow actions to crown jewel
resource types, and writes identity → CAN_READ / CAN_DECRYPT / CAN_INVOKE edges
directly to asset_relationships with is_attack_edge=TRUE.

Supports all CSPs: AWS, GCP, Azure, AliCloud, OCI, IBM, K8s.

Edge type mapping:
  kms:Decrypt / kms:* / cloudkms:*   → CAN_DECRYPT  (IAM-003)
  secretsmanager:* / ssm:* / secretmanager:*  → CAN_READ  (IAM-002)
  lambda:* / cloudfunctions:* / fc:* → CAN_INVOKE   (IAM-001)
  s3:*, storage:*, rds:*, bigquery:* → CAN_READ     (IAM-001)
"""
from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any, Dict, List

import psycopg2.extras

from .base import _upsert_attack_edges

logger = logging.getLogger("attack-path.validators.iam_policy")

# IAM service prefix → resource_type substrings that classify as that service.
# Keys are IAM action prefixes (e.g. "neptune-db" for neptune-db:ReadDataViaQuery).
# Values are resource_type substrings matched against asset_inventory (both underscore
# and dot-notation since Resource Explorer and catalog use different formats).
_SERVICE_TO_TYPE_HINTS: Dict[str, List[str]] = {
    # ══ AWS ═══════════════════════════════════════════════════════════════════
    # ── Core storage / data ────────────────────────────────────────────────────
    "s3":             ["s3_bucket", "s3.bucket", "s3.", "s3"],
    "dynamodb":       ["dynamodb_table", "dynamodb.table", "dynamodb.", "dynamodb"],
    "rds":            ["rds_db_instance", "rds_cluster", "rds.db-instance", "rds.cluster", "rds."],
    "redshift":       ["redshift_cluster", "redshift.cluster", "redshift.", "redshift"],
    "es":             ["opensearch_domain", "opensearch.", "elasticsearch."],
    "opensearch":     ["opensearch_domain", "opensearch."],
    "elasticache":    ["elasticache_cluster", "elasticache.cluster", "elasticache."],
    "efs":            ["efs_file_system", "elasticfilesystem.", "efs."],
    "fsx":            ["fsx_file_system", "fsx.", "fsx_"],
    "backup":         ["backup_vault", "backup.backup-vault", "backup."],
    # ── Secrets / encryption ───────────────────────────────────────────────────
    "kms":            ["kms_key", "kms.key", "kms.", "kms",
                       "cloudkms_crypto_key", "cloudkms.crypto_key", "cloudkms.",  # GCP KMS
                       "oci_key_management", "keyvault_vault", "keyvault.vault"],   # OCI/Azure
    "secretsmanager": ["secretsmanager_secret", "secretsmanager.secret", "secretsmanager.",
                       "secretmanager_secret", "secretmanager.secret", "secretmanager."],  # GCP
    # ── Compute / containers ───────────────────────────────────────────────────
    "lambda":         ["lambda_function", "lambda.function", "lambda."],
    "ecs":            ["ecs_cluster", "ecs.cluster", "ecs."],
    "eks":            ["eks_cluster", "eks.cluster", "eks.", "eks"],
    "ecr":            ["ecr_repository", "ecr.repository", "ecr.", "ecr"],
    "apprunner":      ["apprunner.", "apprunner_"],
    # ── Analytics / ML ────────────────────────────────────────────────────────
    "glue":           ["glue_database", "glue_table", "glue.database", "glue.table", "glue."],
    "athena":         ["athena_workgroup", "athena.workgroup", "athena."],
    "emr":            ["emr_cluster", "emr.cluster", "emr."],
    "sagemaker":      ["sagemaker_", "sagemaker."],
    "bedrock":        ["bedrock.foundation-model", "bedrock.inference-profile",
                       "bedrock.default-prompt-router", "bedrock-agent.", "bedrock.", "bedrock_"],
    "kinesis":        ["kinesis_stream", "kinesis.stream", "kinesis.", "kinesis"],
    "timestream":     ["timestream.", "timestream_"],
    # ── Databases (specialty) ──────────────────────────────────────────────────
    "neptune-db":     ["neptune.db-instance", "neptune.db-cluster", "neptune_db_cluster",
                       "neptune_db_instance", "neptune.", "neptune_"],
    "docdb":          ["docdb.db-instance", "docdb.db-cluster", "documentdb_",
                       "documentdb.", "docdb_", "docdb."],
    # ── Messaging / streaming ──────────────────────────────────────────────────
    "kafka":          ["kafka-cluster.", "kafka_cluster", "msk_cluster", "msk.", "msk_"],
    "kafka-cluster":  ["kafka-cluster.", "kafka_cluster", "msk_cluster", "msk.", "msk_"],
    "mq":             ["mq_broker", "mq_configuration", "mq.", "mq_"],
    "states":         ["stepfunctions_state_machine", "stepfunctions.state-machine",
                       "stepfunctions.", "stepfunctions_"],
    "events":         ["events.event-bus", "events.rule", "events_", "eventbridge."],
    # ── Identity / access ─────────────────────────────────────────────────────
    "cognito-idp":    ["cognito_user_pool", "cognito.user_pool", "cognito.user-pool",
                       "cognito-idp.", "cognito_"],
    "cognito-identity": ["cognito-identity.identitypool", "cognito-identity.", "cognito_identity_pool"],
    # ── Security / compliance ──────────────────────────────────────────────────
    "wafv2":          ["wafv2.", "waf_web_acl", "wafv2_", "waf."],
    # ── Code / dev ────────────────────────────────────────────────────────────
    "codecommit":     ["codecommit.", "codecommit_"],
    # ── Data transfer / migration ──────────────────────────────────────────────
    "transfer":       ["transfer_server", "transfer.", "transfer_"],
    "dms":            ["dms_replication_instance", "dms.", "dms_"],
    "datasync":       ["datasync.", "datasync_"],
    # ── IoT ───────────────────────────────────────────────────────────────────
    "iot":            ["iot.resource", "iot.domainconfiguration", "iot_thing", "iot.", "iot_"],

    # ══ GCP ═══════════════════════════════════════════════════════════════════
    "storage":        ["storage_bucket", "storage.bucket", "gcs.", "gcs_",
                       "storage_storage_account", "storage.storage_account",  # Azure Storage
                       "oss_bucket", "oss.bucket", "oss_"],                    # AliCloud OSS
    "bigquery":       ["bigquery_dataset", "bigquery.dataset", "bigquery_table", "bigquery.table",
                       "bigquery.", "bigquery_"],
    "cloudsql":       ["sqladmin_instance", "sqladmin.instance", "cloudsql.", "cloudsql_"],
    "secretmanager":  ["secretmanager_secret", "secretmanager.secret", "secretmanager."],
    "cloudkms":       ["cloudkms_crypto_key", "cloudkms.crypto_key", "cloudkms."],
    "container":      ["container_cluster", "container.cluster", "container.node_pool",
                       "containerservice_managed_cluster", "containerservice.",  # Azure AKS
                       "containerengine_cluster", "containerengine.cluster"],   # OCI OKE
    "run":            ["run_service", "run.service", "cloudrun.", "run_"],
    "cloudfunctions": ["cloudfunctions_function", "cloudfunctions.function",
                       "cloudfunctions.", "cloudfunctions_",
                       "functions_function", "functions.function"],             # OCI Functions
    "pubsub":         ["pubsub_topic", "pubsub.topic", "pubsub_subscription", "pubsub.subscription",
                       "pubsub.", "pubsub_"],
    "spanner":        ["spanner_instance", "spanner.instance", "spanner.", "spanner_"],
    "datastore":      ["datastore.", "firestore.", "datastore_", "firestore_"],
    "compute":        ["compute_instance", "compute.instance", "compute.disk",
                       "compute_virtual_machine", "compute.virtual_machine",    # Azure VM
                       "ecs_instance", "ecs.instance"],                         # AliCloud ECS

    # ══ Azure ════════════════════════════════════════════════════════════════
    "keyvault":       ["keyvault_vault", "keyvault.vault", "keyvault.", "keyvault_"],
    "sql":            ["sql_server", "sql.server", "sql_database", "sql.database", "sql.", "sql_",
                       "rds_db_instance", "rds."],                              # shared with AWS RDS
    "cosmosdb":       ["cosmosdb.", "cosmosdb_", "documentdb_", "cosmos_"],
    "containerregistry": ["containerregistry_registry", "containerregistry.registry",
                           "ecr_repository", "ecr."],                           # shared with AWS ECR

    # ══ AliCloud ════════════════════════════════════════════════════════════
    "oss":            ["oss_bucket", "oss.bucket", "oss.", "oss_"],             # AliCloud Object Storage
    "fc":             ["fc_function", "fc.function", "fc.", "fc_",              # AliCloud Function Compute
                       "lambda_function", "lambda."],                           # shared
    "polardb":        ["polardb.", "polardb_"],
    "ack":            ["ack_cluster", "ack.", "ack_"],                          # AliCloud Container Service

    # ══ OCI ═══════════════════════════════════════════════════════════════════
    "objectstorage":  ["oci_objectstorage", "objectstorage.", "objectstorage_",
                       "storage.bucket"],                                       # shared with GCP
    "database":       ["database_autonomous_database", "database.autonomous_database",
                       "database.", "database_", "rds_", "rds.",               # shared
                       "sqladmin.", "sqladmin_"],
    "blockstorage":   ["blockstorage_volume", "blockstorage.", "blockstorage_"],

    # ══ IBM ════════════════════════════════════════════════════════════════════
    "cloud-object-storage": ["oss.", "oss_", "cos_", "cos.", "s3_bucket"],

    # ══ K8s ═══════════════════════════════════════════════════════════════════
    "k8s.secrets":    ["k8s_secret", "kubernetes.secret", "k8s.secret", "secret_"],
    "k8s.pods":       ["k8s_pod", "kubernetes.pod", "k8s.pod", "pod_"],
    "k8s.configmaps": ["k8s_configmap", "kubernetes.configmap", "configmap_"],
    "k8s.serviceaccounts": ["k8s_serviceaccount", "kubernetes.serviceaccount", "serviceaccount_"],
    "k8s":            ["k8s_", "kubernetes.", "k8s."],
    "streaming":      ["streaming.", "streaming_", "kafka-cluster.", "kinesis."],  # OCI Streaming / Kinesis
}

# attached_to_type (from iam_policy_statements) → source_type for attack graph
_ATTACHED_TYPE_TO_SOURCE_TYPE: Dict[str, str] = {
    "role":               "iam.role",
    "user":               "iam.user",
    "group":              "iam.group",
    "service_account":    "iam.service_account",      # GCP + K8s
    "service_principal":  "msi.service_principal",    # Azure
    "managed_identity":   "msi.user_assigned_identity",
    "assume_role":        "iam.role",
    "role_binding":       "iam.role",                 # K8s ClusterRoleBinding
    "access_policy":      "iam.group",                # IBM Access Group
    "attached":           "iam.role",
    "inline":             "iam.user",
}
_DEFAULT_SOURCE_TYPE = "iam.role"

# Invoke actions across all CSPs → CAN_INVOKE
_INVOKE_SERVICES = frozenset({
    "lambda", "cloudfunctions", "fc",           # AWS / GCP / AliCloud function compute
    "bedrock",                                   # AWS Bedrock
    "states",                                    # AWS StepFunctions
    "run",                                       # GCP Cloud Run
    "apprunner",                                 # AWS App Runner
})
_INVOKE_ACTION_SUFFIXES = frozenset({
    "invokefunction", "invokemodel", "invokeagent", "invokeflow",
    "startexecution", "startsynccexecution", "call",
})

# Secrets/SSM → CAN_READ secret-specific rule
_SECRET_SERVICES = frozenset({"secretsmanager", "secretmanager", "ssm"})

# KMS-family across all CSPs → CAN_DECRYPT
_DECRYPT_SERVICES = frozenset({"kms", "cloudkms", "keyvault"})


def _edge_type_for(svc: str, action_lower: str) -> tuple:
    """Return (attack_edge_type, validation_rule_id) for a service + action."""
    if svc in _DECRYPT_SERVICES:
        return "CAN_DECRYPT", "IAM-003"
    if svc in _SECRET_SERVICES:
        return "CAN_READ", "IAM-002"
    if svc in _INVOKE_SERVICES:
        action_part = action_lower.split(":")[-1] if ":" in action_lower else action_lower
        if action_lower in ("*:*", "*") or action_part in _INVOKE_ACTION_SUFFIXES or action_part == "*":
            return "CAN_INVOKE", "IAM-001"
    return "CAN_READ", "IAM-001"


def validate_iam_policy(
    di_conn: Any,
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
) -> int:
    """Write CAN_READ / CAN_DECRYPT / CAN_INVOKE edges for IAM policy → crown jewel access.

    Supports all CSPs: AWS, GCP, Azure, AliCloud, OCI, IBM, K8s.
    Non-fatal — any DB error returns 0.
    """

    # ── Step 1: Load crown jewels (uid + resource_type) from di DB ──────────
    cj_by_service: Dict[str, List[tuple]] = defaultdict(list)
    try:
        with di_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT DISTINCT ON (rsp.resource_uid)
                    rsp.resource_uid,
                    COALESCE(ai.resource_type, '') AS resource_type
                FROM resource_security_posture rsp
                LEFT JOIN asset_inventory ai
                    ON ai.resource_uid = rsp.resource_uid
                    AND ai.tenant_id   = rsp.tenant_id
                WHERE rsp.tenant_id    = %s
                  AND rsp.is_crown_jewel = TRUE
                ORDER BY rsp.resource_uid, ai.last_seen_at DESC NULLS LAST
                """,
                (tenant_id,),
            )
            for row in cur.fetchall():
                uid = row["resource_uid"]
                rtype = (row["resource_type"] or "").lower()
                for svc, hints in _SERVICE_TO_TYPE_HINTS.items():
                    if any(rtype.startswith(h) or h in rtype for h in hints):
                        cj_by_service[svc].append((uid, rtype))
    except Exception as exc:
        logger.warning("iam_policy: crown jewel load failed: %s", exc)
        try:
            di_conn.rollback()
        except Exception:
            pass
        return 0

    if not cj_by_service:
        logger.info("iam_policy: no crown jewels for tenant=%s — skipping", tenant_id)
        return 0

    # ── Step 2: Load IAM policy statements from IAM DB ──────────────────────
    try:
        from engine_common.db_connections import get_iam_conn
        iam_conn = get_iam_conn()
    except Exception as exc:
        logger.warning("iam_policy: IAM DB unavailable — skipping: %s", exc)
        return 0

    rows = []
    try:
        with iam_conn.cursor() as cur:
            # Do NOT filter by scan_run_id — IAM engine runs independently under
            # different scan_run_ids; filtering always returns 0 rows.
            cur.execute(
                """
                SELECT DISTINCT attached_to_arn, actions, attached_to_type
                FROM iam_policy_statements
                WHERE tenant_id = %s
                  AND effect = 'Allow'
                  AND attached_to_arn IS NOT NULL
                  AND actions IS NOT NULL
                  AND NOT COALESCE(not_action_mode, FALSE)
                """,
                (tenant_id,),
            )
            rows = cur.fetchall()
    except Exception as exc:
        logger.warning("iam_policy: statement query failed: %s", exc)
        try:
            iam_conn.rollback()
        except Exception:
            pass
        return 0
    finally:
        try:
            iam_conn.close()
        except Exception:
            pass

    if not rows:
        logger.info("iam_policy: 0 Allow statements found for tenant=%s", tenant_id)
        return 0

    # ── Step 3: Map identity → services it can access ────────────────────────
    # identity_arn → {svc: (attached_to_type, [actions])}
    role_svc_actions: Dict[str, Dict[str, Any]] = defaultdict(lambda: defaultdict(list))
    # identity_arn → attached_to_type (kept for source_type derivation in step 4)
    identity_types: Dict[str, str] = {}

    for role_arn, actions, attached_to_type in rows:
        if not role_arn or not isinstance(actions, list):
            continue
        identity_types.setdefault(role_arn, attached_to_type or "role")
        for action in actions:
            if not isinstance(action, str):
                continue
            action_lower = action.lower().strip()
            if action_lower in ("*", "*:*"):
                for svc in _SERVICE_TO_TYPE_HINTS:
                    role_svc_actions[role_arn][svc].append(action_lower)
            elif ":" in action_lower:
                svc = action_lower.split(":")[0]
                if svc in _SERVICE_TO_TYPE_HINTS:
                    role_svc_actions[role_arn][svc].append(action_lower)

    # ── Step 4: Build attack edges ───────────────────────────────────────────
    edges: List[Dict[str, Any]] = []
    seen: set = set()

    for role_arn, svc_actions in role_svc_actions.items():
        source_type = _ATTACHED_TYPE_TO_SOURCE_TYPE.get(
            identity_types.get(role_arn, "role"), _DEFAULT_SOURCE_TYPE
        )
        for svc, action_list in svc_actions.items():
            # Pick the most permissive action for edge type derivation
            representative_action = action_list[0] if action_list else f"{svc}:*"
            edge_type, rule_id = _edge_type_for(svc, representative_action)

            for (cj_uid, cj_rtype) in cj_by_service.get(svc, []):
                key = (role_arn, edge_type, cj_uid)
                if key in seen:
                    continue
                seen.add(key)
                edges.append({
                    "source_uid":            role_arn,
                    "source_type":           source_type,
                    "target_uid":            cj_uid,
                    "target_type":           cj_rtype,
                    "relation_type":         edge_type,
                    "attack_edge_type":      edge_type,
                    "validation_rule_id":    rule_id,
                    "relationship_category": "identity",
                    "attack_path_category":  "privilege_escalation",
                    "confidence":            "high",
                    "attack_evidence": {
                        "iam_service":      svc,
                        "sample_action":    representative_action,
                        "derived_from":     "iam_policy_validator",
                        "target_type":      cj_rtype,
                        "attached_to_type": identity_types.get(role_arn, "role"),
                    },
                })

    if not edges:
        logger.info("iam_policy: 0 edges after mapping (tenant=%s)", tenant_id)
        return 0

    written = _upsert_attack_edges(di_conn, edges, scan_run_id, tenant_id, account_id, provider)
    logger.info(
        "iam_policy: %d CAN_READ/CAN_DECRYPT/CAN_INVOKE edges → tenant=%s scan=%s",
        written, tenant_id, scan_run_id,
    )
    return written
