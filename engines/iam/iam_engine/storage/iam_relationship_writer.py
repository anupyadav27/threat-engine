"""
IAM relationship writer — derives identity edges from parsed IAM data and writes
them to asset_relationships in the DI DB.

Edges written:
  principal → ASSUMES    → iam_role     (trust policy allows principal to assume role)
  role/user → HAS_POLICY → iam_policy   (managed policy attached to identity)
  user      → MEMBER_OF  → iam_group    (user belongs to an IAM group)
  instance_profile → LINKED_TO → iam_role  (EC2 instance profile → role it wraps)

attack_path_category mapping:
  ASSUMES cross-account → privilege_escalation
  ASSUMES same-account  → lateral_movement
  HAS_POLICY admin/wildcard → privilege_escalation
  HAS_POLICY normal         → lateral_movement
  MEMBER_OF / LINKED_TO   → lateral_movement
"""

from __future__ import annotations

import logging
from typing import Any, List, Optional

from engine_common.db_connections import get_di_conn
from engine_common.relationship_writer import upsert_asset_relationships

logger = logging.getLogger(__name__)


def write_iam_relationships(
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
    trust_relationships: Optional[List[Any]] = None,
    managed_policies: Optional[List[Any]] = None,
    groups: Optional[List[Any]] = None,
    instance_profiles: Optional[List[Any]] = None,
) -> int:
    """Derive IAM identity edges and upsert to asset_relationships.

    Non-fatal — any exception is caught and logged so a failure never aborts
    the main scan pipeline.

    Args:
        trust_relationships: List of TrustRelationship objects from trust_analyzer.
        managed_policies:    List of ParsedPolicy objects (those with attached_to_arn set).
        groups:              Raw group dicts from IAM reader (may contain Users list).
        instance_profiles:   Raw instance profile dicts (contain Roles list).

    Returns:
        Number of edges written (0 on error).
    """
    try:
        edges: List[dict] = []

        edges.extend(_assumes_edges(trust_relationships or [], account_id))
        edges.extend(_has_policy_edges(managed_policies or []))
        edges.extend(_member_of_edges(groups or []))
        edges.extend(_linked_to_edges(instance_profiles or []))

        if not edges:
            logger.info("IAM relationship writer: no edges derived for scan %s", scan_run_id)
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
            logger.info("IAM relationship writer: wrote %d edges for scan %s", written, scan_run_id)
            return written
        finally:
            conn.close()

    except Exception as exc:
        logger.warning("IAM relationship write failed (non-fatal): %s", exc, exc_info=True)
        return 0


def _assumes_edges(trust_relationships: List[Any], own_account_id: str) -> List[dict]:
    """principal → ASSUMES → role from TrustRelationship objects."""
    edges = []
    for tr in trust_relationships:
        principal = getattr(tr, "trusted_principal", None) or ""
        role_arn = getattr(tr, "source_role_arn", None) or ""
        if not principal or not role_arn:
            continue

        effect = getattr(tr, "effect", "Allow")
        if effect != "Allow":
            continue

        principal_type = getattr(tr, "principal_type", "unknown")
        is_cross_account = getattr(tr, "is_cross_account", False)

        # Infer cross-account if not set but account differs from own_account_id
        if not is_cross_account and own_account_id:
            is_cross_account = own_account_id not in principal

        category = "privilege_escalation" if is_cross_account else "lateral_movement"

        edges.append({
            "source_uid": principal,
            "source_type": principal_type,
            "target_uid": role_arn,
            "target_type": "iam_role",
            "relation_type": "ASSUMES",
            "relation_metadata": {
                "principal_type": principal_type,
                "effect": effect,
                "is_cross_account": is_cross_account,
                "attack_path_category": category,
            },
        })

    return edges


def _has_policy_edges(managed_policies: List[Any]) -> List[dict]:
    """role/user/group → HAS_POLICY → iam_policy from ParsedPolicy objects."""
    edges = []
    seen: set = set()

    for policy in managed_policies:
        attached_to = getattr(policy, "attached_to_arn", None) or ""
        policy_arn = getattr(policy, "policy_arn", None) or ""
        if not attached_to or not policy_arn:
            continue

        key = (attached_to, policy_arn)
        if key in seen:
            continue
        seen.add(key)

        attached_type = getattr(policy, "attached_to_type", "role") or "role"

        # Detect admin/wildcard for category
        stmts = getattr(policy, "statements", []) or []
        is_admin = any(getattr(s, "is_admin", False) for s in stmts)
        has_wildcard = any(getattr(s, "is_wildcard_action", False) for s in stmts)
        category = "privilege_escalation" if (is_admin or has_wildcard) else "lateral_movement"

        edges.append({
            "source_uid": attached_to,
            "source_type": f"iam_{attached_type}",
            "target_uid": policy_arn,
            "target_type": "iam_policy",
            "relation_type": "HAS_POLICY",
            "relation_metadata": {
                "attached_to_type": attached_type,
                "is_admin": is_admin,
                "has_wildcard": has_wildcard,
                "attack_path_category": category,
            },
        })

    return edges


def _member_of_edges(groups: List[Any]) -> List[dict]:
    """user → MEMBER_OF → group from group dicts that carry a Users list."""
    edges = []
    for group in groups:
        group_arn = group.get("Arn") or group.get("_resource_uid") or ""
        if not group_arn:
            continue

        # Groups from get_account_authorization_details carry a Users list
        users_in_group = group.get("Users") or group.get("GroupMembersList") or []
        for user_entry in users_in_group:
            user_arn = ""
            if isinstance(user_entry, dict):
                user_arn = user_entry.get("Arn") or user_entry.get("UserArn") or ""
            elif isinstance(user_entry, str):
                user_arn = user_entry
            if not user_arn:
                continue

            edges.append({
                "source_uid": user_arn,
                "source_type": "iam_user",
                "target_uid": group_arn,
                "target_type": "iam_group",
                "relation_type": "MEMBER_OF",
                "relation_metadata": {
                    "group_name": group.get("GroupName", ""),
                    "attack_path_category": "lateral_movement",
                },
            })

    return edges


def _linked_to_edges(instance_profiles: List[Any]) -> List[dict]:
    """instance_profile → LINKED_TO → iam_role from instance profile dicts."""
    edges = []
    for profile in instance_profiles:
        profile_arn = profile.get("Arn") or profile.get("_resource_uid") or ""
        if not profile_arn:
            continue

        roles = profile.get("Roles") or []
        for role_entry in roles:
            role_arn = ""
            if isinstance(role_entry, dict):
                role_arn = role_entry.get("Arn") or role_entry.get("RoleArn") or ""
            elif isinstance(role_entry, str):
                role_arn = role_entry
            if not role_arn:
                continue

            edges.append({
                "source_uid": profile_arn,
                "source_type": "iam_instance_profile",
                "target_uid": role_arn,
                "target_type": "iam_role",
                "relation_type": "LINKED_TO",
                "relation_metadata": {
                    "profile_name": profile.get("InstanceProfileName", ""),
                    "attack_path_category": "privilege_escalation",
                },
            })

    return edges
