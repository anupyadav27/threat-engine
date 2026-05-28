"""
Encryption relationship writer — derives data-plane edges from KMS/encryption
analysis and writes them to asset_relationships in the DI DB.

Edges written:
  resource → ENCRYPTED_BY     → kms_key   (resource uses this key for at-rest encryption)
  kms_key  → GRANTS_DECRYPT_TO → principal (key policy grants decrypt to external account/role)

Sources:
  dep_graph      — DependencyGraph object from dependency_graph.py (preferred)
  kms_relationships — inventory relationship list (fallback if dep_graph unavailable)
  cross_account_findings — list of cross-account key sharing findings

attack_path_category:
  ENCRYPTED_BY normal → data_access
  GRANTS_DECRYPT_TO cross-account → data_exfil
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from engine_common.db_connections import get_di_conn
from engine_common.relationship_writer import upsert_asset_relationships

logger = logging.getLogger(__name__)


def write_encryption_relationships(
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
    dep_graph: Optional[Any] = None,
    kms_relationships: Optional[List[Dict[str, Any]]] = None,
    cross_account_findings: Optional[List[Dict[str, Any]]] = None,
) -> int:
    """Derive encryption data-plane edges and upsert to asset_relationships.

    Non-fatal — any exception is caught so a failure never aborts the pipeline.

    Args:
        dep_graph:             DependencyGraph with resource_to_keys mapping (preferred).
        kms_relationships:     Inventory relationship list [{source_uid, target_uid, ...}].
                               Used as fallback when dep_graph is None.
        cross_account_findings: Cross-account key sharing findings from
                               cross_account_keys.analyze_cross_account_keys().

    Returns:
        Number of edges written (0 on error).
    """
    try:
        edges: List[Dict[str, Any]] = []

        edges.extend(_encrypted_by_edges(dep_graph, kms_relationships or []))
        edges.extend(_grants_decrypt_to_edges(cross_account_findings or []))

        if not edges:
            logger.info(
                "Encryption relationship writer: no edges derived for scan %s", scan_run_id
            )
            return 0

        conn = get_di_conn()
        try:
            written = upsert_asset_relationships(
                conn, edges,
                scan_run_id=scan_run_id,
                tenant_id=tenant_id,
                account_id=account_id,
                provider=provider,
            )
            logger.info(
                "Encryption relationship writer: wrote %d edges for scan %s", written, scan_run_id
            )
            return written
        finally:
            conn.close()

    except Exception as exc:
        logger.warning(
            "Encryption relationship write failed (non-fatal): %s", exc, exc_info=True
        )
        return 0


def _encrypted_by_edges(
    dep_graph: Optional[Any],
    kms_relationships: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Build resource → ENCRYPTED_BY → kms_key edges."""
    edges: List[Dict[str, Any]] = []

    if dep_graph is not None:
        # Preferred: DependencyGraph.resource_to_keys (built from inventory + datasec + discovery)
        for resource_uid, key_arns in dep_graph.resource_to_keys.items():
            if not resource_uid:
                continue
            for key_arn in key_arns:
                if not key_arn or key_arn == resource_uid:
                    continue
                key_meta = dep_graph.key_metadata.get(key_arn) or {}
                edges.append({
                    "source_uid": resource_uid,
                    "source_type": _infer_resource_type(resource_uid),
                    "target_uid": key_arn,
                    "target_type": "kms_key",
                    "relation_type": "ENCRYPTED_BY",
                    "relation_metadata": {
                        "key_manager": key_meta.get("key_manager"),
                        "key_state": key_meta.get("key_state"),
                        "rotation_enabled": key_meta.get("rotation_enabled"),
                        "attack_path_category": "data_access",
                    },
                })
        return edges

    # Fallback: inventory kms_relationships list
    for rel in kms_relationships:
        source = rel.get("source_uid") or rel.get("resource_uid") or ""
        target = rel.get("target_uid") or rel.get("kms_key_arn") or rel.get("key_arn") or ""
        if not source or not target:
            continue
        edges.append({
            "source_uid": source,
            "source_type": rel.get("source_type") or _infer_resource_type(source),
            "target_uid": target,
            "target_type": "kms_key",
            "relation_type": "ENCRYPTED_BY",
            "relation_metadata": {
                "relation_subtype": rel.get("relation_type", ""),
                "attack_path_category": "data_access",
            },
        })

    return edges


def _grants_decrypt_to_edges(
    cross_account_findings: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Build kms_key → GRANTS_DECRYPT_TO → external_account edges from cross-account findings."""
    edges: List[Dict[str, Any]] = []

    for finding in cross_account_findings:
        key_arn = finding.get("key_arn") or finding.get("resource_uid") or ""
        if not key_arn:
            continue

        external_accounts = finding.get("external_accounts") or []
        for ext_account in external_accounts:
            if not ext_account:
                continue
            # Normalise: account IDs become account:aws:{id}, ARNs kept as-is
            if ext_account.startswith("arn:"):
                target_uid = ext_account
                target_type = "iam_principal"
            else:
                target_uid = f"account:aws:{ext_account}"
                target_type = "aws_account"

            edges.append({
                "source_uid": key_arn,
                "source_type": "kms_key",
                "target_uid": target_uid,
                "target_type": target_type,
                "relation_type": "GRANTS_DECRYPT_TO",
                "relation_metadata": {
                    "sharing_type": finding.get("sharing_type", ""),
                    "grant_count": finding.get("grant_count"),
                    "severity": finding.get("severity", "high"),
                    "attack_path_category": "data_exfil",
                },
            })

    return edges


def _infer_resource_type(uid: str) -> str:
    """Best-effort resource type from UID patterns."""
    if not uid:
        return "resource"
    uid_lower = uid.lower()
    if ":s3:::" in uid_lower or uid_lower.startswith("arn:aws:s3"):
        return "s3_bucket"
    if ":rds:" in uid_lower:
        return "rds_instance"
    if ":dynamodb:" in uid_lower:
        return "dynamodb_table"
    if ":ec2:" in uid_lower and "volume" in uid_lower:
        return "ebs_volume"
    if ":secretsmanager:" in uid_lower:
        return "secretsmanager_secret"
    if ":lambda:" in uid_lower:
        return "lambda_function"
    if ":sqs:" in uid_lower:
        return "sqs_queue"
    if ":sns:" in uid_lower:
        return "sns_topic"
    if ":glacier:" in uid_lower:
        return "s3_glacier_vault"
    return "resource"
