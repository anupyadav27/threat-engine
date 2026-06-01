"""
IAM relationship writer — derives identity edges from parsed IAM data and writes
them to asset_relationships in the DI DB.

Edges written:
  principal → ASSUMES         → iam_role     (trust policy allows principal to assume role)
  role/user → HAS_POLICY      → iam_policy   (managed policy attached to identity)
  user      → MEMBER_OF       → iam_group    (user belongs to an IAM group)
  instance_profile → LINKED_TO → iam_role   (EC2 instance profile → role it wraps)
  resource  → GRANTS_ACCESS_TO → principal  (resource-based policy grants access)
  identity  → CAN_ACCESS       → resource   (wildcard Resource:* policy expansion)

attack_path_category mapping:
  ASSUMES cross-account       → privilege_escalation
  ASSUMES same-account        → lateral_movement
  HAS_POLICY admin/wildcard   → privilege_escalation
  HAS_POLICY normal           → lateral_movement
  MEMBER_OF / LINKED_TO       → lateral_movement
  GRANTS_ACCESS_TO            → data_access (or data_exfil for KMS)
  CAN_ACCESS wildcard         → lateral_movement (or privilege_escalation for IAM actions)
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

import psycopg2.extras

from engine_common.db_connections import get_di_conn, get_iam_conn
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
    resource_policy_edges: bool = True,
    wildcard_expansion_edges: bool = True,
) -> int:
    """Derive IAM identity edges and upsert to asset_relationships.

    Non-fatal — any exception is caught and logged so a failure never aborts
    the main scan pipeline.

    Args:
        trust_relationships:      TrustRelationship objects from trust_analyzer.
        managed_policies:         ParsedPolicy objects (attached_to_arn set).
        groups:                   Group dicts from IAM reader (may contain Users list).
        instance_profiles:        Instance profile dicts (contain Roles list).
        resource_policy_edges:    If True, derive GRANTS_ACCESS_TO from resource policies.
        wildcard_expansion_edges: If True, derive CAN_ACCESS from wildcard Resource:* policies.

    Returns:
        Number of edges written (0 on error).
    """
    try:
        edges: List[dict] = []

        edges.extend(_assumes_edges(trust_relationships or [], account_id))
        edges.extend(_has_policy_edges(managed_policies or []))
        edges.extend(_member_of_edges(groups or []))
        edges.extend(_linked_to_edges(instance_profiles or []))

        di_conn = get_di_conn()
        try:
            if resource_policy_edges:
                edges.extend(
                    _grants_access_to_edges(di_conn, scan_run_id, tenant_id, provider)
                )

            if wildcard_expansion_edges and managed_policies:
                edges.extend(
                    _can_access_edges(
                        di_conn, scan_run_id, tenant_id, provider,
                        managed_policies or [],
                    )
                )

            # Permission access edges: CAN_READ/CAN_INVOKE edges derived from
            # specific service actions in policy statements (ECR, SageMaker, Bedrock).
            edges.extend(
                _permission_access_edges(di_conn, scan_run_id, tenant_id, provider)
            )

            # Fallback: derive edges directly from asset_inventory for scans where
            # iam_policy_statements lacks managed policy data (DI scan timed out).
            if provider == "aws":
                edges.extend(
                    _direct_permission_edges_from_inventory(di_conn, tenant_id, provider)
                )

            if not edges:
                logger.info("IAM relationship writer: no edges derived for scan %s", scan_run_id)
                return 0

            written = upsert_asset_relationships(
                di_conn, edges,
                scan_run_id=scan_run_id,
                tenant_id=tenant_id,
                account_id=account_id,
                provider=provider,
            )
            logger.info("IAM relationship writer: wrote %d edges for scan %s", written, scan_run_id)
            return written

        finally:
            di_conn.close()

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

        # Cross-account assume: emit an explicit CAN_ASSUME attack edge so the BFS
        # can traverse it as a lateral movement / privilege escalation hop.
        if is_cross_account:
            edges.append({
                "source_uid": principal,
                "source_type": principal_type,
                "target_uid": role_arn,
                "target_type": "iam_role",
                "relation_type": "CAN_ASSUME",
                "is_attack_edge": True,
                "attack_path_category": "privilege_escalation",
                "relation_metadata": {
                    "principal_type": principal_type,
                    "effect": effect,
                    "is_cross_account": True,
                    "cross_account": True,
                    "attack_path_category": "privilege_escalation",
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


# ── Resource policy edges (GRANTS_ACCESS_TO / GRANTS_DECRYPT_TO) ─────────────────

def _grants_access_to_edges(
    di_conn: "psycopg2.connection",
    scan_run_id: str,
    tenant_id: str,
    provider: str,
) -> List[dict]:
    """
    Derive resource → GRANTS_ACCESS_TO → principal edges from resource-based policies.

    Reads iam_resource_policy_rules from the IAM DB to know which resource types
    carry embedded policies.  Then queries asset_inventory in DI DB to get those
    resources and parses the policy JSON from emitted_fields.
    """
    edges: List[dict] = []

    # Load rules from IAM DB
    rules = _load_resource_policy_rules(provider)
    if not rules:
        return edges

    # Group rules by resource_type to minimise DB round-trips
    rules_by_type: Dict[str, List[Dict]] = {}
    for rule in rules:
        rules_by_type.setdefault(rule["resource_type"], []).append(rule)

    for resource_type, type_rules in rules_by_type.items():
        # Fetch resources of this type for this scan
        sql = """
            SELECT resource_uid, emitted_fields
            FROM asset_inventory
            WHERE tenant_id = %s AND scan_run_id = %s
              AND provider = %s AND resource_type = %s
        """
        with di_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, (tenant_id, scan_run_id, provider, resource_type))
            resources = cur.fetchall()

        for res in resources:
            emitted = res["emitted_fields"]
            if isinstance(emitted, str):
                try:
                    emitted = json.loads(emitted)
                except (ValueError, TypeError):
                    emitted = {}
            emitted = emitted or {}
            resource_uid = res["resource_uid"]

            for rule in type_rules:
                policy_field = rule["policy_field"]
                principal_key = rule.get("principal_key")
                rel_type = rule.get("relation_type", "GRANTS_ACCESS_TO")
                category = rule.get("attack_path_category", "data_access")

                policy_raw = emitted.get(policy_field)
                if not policy_raw:
                    continue

                # policy may be a JSON string or already a dict
                if isinstance(policy_raw, str):
                    try:
                        policy_raw = json.loads(policy_raw)
                    except (ValueError, TypeError):
                        continue

                for principal in _extract_policy_principals(policy_raw, principal_key):
                    if not principal:
                        continue
                    edges.append({
                        "source_uid":    resource_uid,
                        "source_type":   resource_type,
                        "target_uid":    principal,
                        "target_type":   "iam_principal",
                        "relation_type": rel_type,
                        "relation_metadata": {
                            "policy_field":         policy_field,
                            "principal_key":        principal_key,
                            "attack_path_category": category,
                        },
                    })

    return edges


def _extract_policy_principals(policy: Any, principal_key: Optional[str]) -> List[str]:
    """
    Walk an IAM policy document (AWS-style Statement list) and return all Allow
    principals matching principal_key (AWS, Service, Federated) or all if None.
    Also handles GCP-style iamPolicy (bindings list) and plain lists.
    """
    principals: List[str] = []

    if isinstance(policy, list):
        # GCP-style: list of {role, members: [...]} bindings
        for binding in policy:
            if isinstance(binding, dict):
                members = binding.get("members") or []
                for m in members:
                    principals.append(str(m))
        return principals

    if not isinstance(policy, dict):
        return principals

    # AWS-style: {Statement: [{Effect, Principal, Action, Resource}, ...]}
    statements = policy.get("Statement") or policy.get("statements") or []
    if not isinstance(statements, list):
        statements = [statements]

    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        effect = stmt.get("Effect", "Allow")
        if effect == "Deny":
            continue

        principal_block = stmt.get("Principal") or stmt.get("principal")
        if not principal_block:
            continue

        if principal_block == "*":
            principals.append("*")
            continue

        if isinstance(principal_block, str):
            principals.append(principal_block)
            continue

        if isinstance(principal_block, dict):
            if principal_key:
                values = principal_block.get(principal_key, [])
                if isinstance(values, str):
                    values = [values]
                principals.extend(values)
            else:
                for _k, vals in principal_block.items():
                    if isinstance(vals, str):
                        principals.append(vals)
                    elif isinstance(vals, list):
                        principals.extend(str(v) for v in vals)

    return principals


def _load_resource_policy_rules(provider: str) -> List[Dict]:
    """Load iam_resource_policy_rules for the given CSP from IAM DB. Returns [] on error."""
    try:
        iam_conn = get_iam_conn()
        sql = """
            SELECT resource_type, policy_field, principal_key, relation_type, attack_path_category
            FROM iam_resource_policy_rules
            WHERE csp = %s AND is_active = TRUE
        """
        with iam_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, (provider,))
            rows = [dict(r) for r in cur.fetchall()]
        iam_conn.close()
        return rows
    except Exception as exc:
        logger.debug("Could not load resource_policy_rules (non-fatal): %s", exc)
        return []


# ── Wildcard CAN_ACCESS edges ────────────────────────────────────────────────────

def _can_access_edges(
    di_conn: "psycopg2.connection",
    scan_run_id: str,
    tenant_id: str,
    provider: str,
    managed_policies: List[Any],
) -> List[dict]:
    """
    Derive identity → CAN_ACCESS → resource edges for policies with Resource:*.

    For each managed policy with a wildcard Resource statement, reads
    iam_action_resource_map to know which resource types the action prefix
    applies to, then queries asset_inventory for matching resources.

    Caps at 50 CAN_ACCESS edges per identity to avoid graph explosion.
    """
    edges: List[dict] = []
    action_map = _load_action_resource_map(provider)
    if not action_map:
        return edges

    for policy in managed_policies:
        attached_to = getattr(policy, "attached_to_arn", None) or ""
        if not attached_to:
            continue
        attached_type = getattr(policy, "attached_to_type", "role") or "role"

        stmts = getattr(policy, "statements", []) or []
        for stmt in stmts:
            # Only wildcard resource statements
            resources = getattr(stmt, "resources", []) or []
            has_wildcard = "*" in resources or any(r == "*" for r in resources)
            if not has_wildcard:
                continue

            effect = getattr(stmt, "effect", "Allow")
            if effect != "Allow":
                continue

            actions = getattr(stmt, "actions", []) or []
            if "*" in actions:
                # Allow * with Resource:* — map to all action prefixes (cap to avoid flood)
                matched_types = _all_resource_types(action_map)
            else:
                matched_types = _actions_to_resource_types(actions, action_map)

            for resource_type, category in matched_types.items():
                # Fetch matching resources (limit 50 per type per identity)
                sql = """
                    SELECT resource_uid FROM asset_inventory
                    WHERE tenant_id = %s AND scan_run_id = %s
                      AND provider = %s AND resource_type = %s
                    LIMIT 50
                """
                with di_conn.cursor() as cur:
                    cur.execute(sql, (tenant_id, scan_run_id, provider, resource_type))
                    target_uids = [row[0] for row in cur.fetchall()]

                for tgt_uid in target_uids:
                    edges.append({
                        "source_uid":    attached_to,
                        "source_type":   f"iam_{attached_type}",
                        "target_uid":    tgt_uid,
                        "target_type":   resource_type,
                        "relation_type": "CAN_ACCESS",
                        "relation_metadata": {
                            "attack_path_category": category,
                            "via_wildcard_resource": True,
                        },
                    })
                    if len(edges) >= 10000:
                        # Safety cap — log and return early
                        logger.warning(
                            "CAN_ACCESS edge cap hit (10000) for scan %s — truncating", scan_run_id
                        )
                        return edges

    return edges


# ── Permission-based access edges (CAN_READ / CAN_INVOKE / CAN_DECRYPT) ──────────
#
# Maps lowercase IAM action → (relation_type, target_resource_type, attack_category).
# All edges tagged is_attack_edge=True so BFS traverses them without any engine change.
_PERMISSION_ACTION_MAP: Dict[str, tuple] = {
    # ── ECR → CODE_ACCESS ────────────────────────────────────────────────────────
    "ecr:batchgetimage":             ("CAN_READ",    "ecr_repository",           "data_access"),
    "ecr:getdownloadurlforlayer":    ("CAN_READ",    "ecr_repository",           "data_access"),
    "ecr:describeimages":            ("CAN_READ",    "ecr_repository",           "data_access"),
    "ecr:getauthorizationtoken":     ("CAN_READ",    "ecr_repository",           "data_access"),
    # ── SageMaker → AI_MODEL_ACCESS ──────────────────────────────────────────────
    "sagemaker:invokeendpoint":                  ("CAN_INVOKE", "sagemaker_endpoint",       "data_access"),
    "sagemaker:invokeendpointasync":             ("CAN_INVOKE", "sagemaker_endpoint",       "data_access"),
    "sagemaker:invokeendpointwithresponsestream":("CAN_INVOKE", "sagemaker_endpoint",       "data_access"),
    # ── Bedrock → AI_MODEL_ACCESS ─────────────────────────────────────────────────
    "bedrock:invokemodel":                        ("CAN_INVOKE", "bedrock_model", "data_access"),
    "bedrock:invokemodelwithresponsestream":       ("CAN_INVOKE", "bedrock_model", "data_access"),
    "bedrock:invoke":                             ("CAN_INVOKE", "bedrock_model", "data_access"),
    # ── S3 → DATA_THEFT ───────────────────────────────────────────────────────────
    "s3:getobject":                  ("CAN_READ",    "s3_bucket",                "data_access"),
    "s3:listbucket":                 ("CAN_READ",    "s3_bucket",                "data_access"),
    "s3:listallmybuckets":           ("CAN_READ",    "s3_bucket",                "data_access"),
    "s3:getbucketacl":               ("CAN_READ",    "s3_bucket",                "data_access"),
    "s3:headobject":                 ("CAN_READ",    "s3_bucket",                "data_access"),
    # ── Secrets Manager → SECRET_THEFT ───────────────────────────────────────────
    "secretsmanager:getsecretvalue": ("CAN_READ",    "secretsmanager_secret",    "data_access"),
    "secretsmanager:describesecret": ("CAN_READ",    "secretsmanager_secret",    "data_access"),
    "secretsmanager:listsecrets":    ("CAN_READ",    "secretsmanager_secret",    "data_access"),
    # ── KMS → DECRYPTION ──────────────────────────────────────────────────────────
    "kms:decrypt":                   ("CAN_DECRYPT", "kms_key",                  "data_access"),
    "kms:generatedatakey":           ("CAN_DECRYPT", "kms_key",                  "data_access"),
    "kms:generatedatakeywithoutplaintext": ("CAN_DECRYPT", "kms_key",           "data_access"),
    "kms:reencryptfrom":             ("CAN_DECRYPT", "kms_key",                  "data_access"),
    # ── Lambda → CODE_ACCESS (lateral movement to Lambda functions) ───────────────
    "lambda:invokefunction":         ("CAN_INVOKE",  "lambda_function",          "lateral_movement"),
    "lambda:invokewithqualifier":    ("CAN_INVOKE",  "lambda_function",          "lateral_movement"),
    # ── AWS Organizations → ACCOUNT_TAKEOVER ─────────────────────────────────────
    # Admin roles with organizations:* can control the entire AWS org account structure.
    "organizations:deleteorganization":          ("CAN_ASSUME", "organizations_account", "privilege_escalation"),
    "organizations:inviteaccounttoorganization": ("CAN_ASSUME", "organizations_account", "privilege_escalation"),
    "organizations:removeaccountfromorganization": ("CAN_ASSUME", "organizations_account", "privilege_escalation"),
    "organizations:createorganization":          ("CAN_ASSUME", "organizations_account", "privilege_escalation"),
    "organizations:leaveorganization":           ("CAN_ASSUME", "organizations_account", "privilege_escalation"),
}

# Wildcard service prefix → same edge as the explicit actions above.
_PERMISSION_WILDCARD_PREFIXES: Dict[str, tuple] = {
    "ecr:":              ("CAN_READ",    "ecr_repository",           "data_access"),
    "sagemaker:":        ("CAN_INVOKE",  "sagemaker_endpoint",       "data_access"),
    "bedrock:":          ("CAN_INVOKE",  "bedrock_model", "data_access"),
    "s3:":               ("CAN_READ",    "s3_bucket",                "data_access"),
    "secretsmanager:":   ("CAN_READ",    "secretsmanager_secret",    "data_access"),
    "kms:":              ("CAN_DECRYPT", "kms_key",                  "data_access"),
    "lambda:":           ("CAN_INVOKE",  "lambda_function",          "lateral_movement"),
    "organizations:":    ("CAN_ASSUME",  "organizations_account",    "privilege_escalation"),
}


def _permission_access_edges(
    di_conn: "psycopg2.connection",
    scan_run_id: str,
    tenant_id: str,
    provider: str,
) -> List[dict]:
    """Derive CAN_READ / CAN_INVOKE edges from IAM policy statement actions.

    Reads iam_policy_statements for the scan, matches actions against
    ``_PERMISSION_ACTION_MAP`` and ``_PERMISSION_WILDCARD_PREFIXES``, then looks up
    matching target resources in asset_inventory.  Emits ``is_attack_edge=True`` so
    the attack-path BFS engine traverses these edges without any code change.

    Limits target lookups to 100 resources per (identity, relation, resource_type)
    triple to prevent graph explosion.
    """
    edges: List[dict] = []

    try:
        iam_conn = get_iam_conn()
        try:
            with iam_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT attached_to_arn, attached_to_type, unnest(actions) AS action
                    FROM iam_policy_statements
                    WHERE scan_run_id = %s AND tenant_id = %s AND effect = 'Allow'
                      AND attached_to_type IN ('role', 'user')
                      AND actions IS NOT NULL
                    """,
                    (scan_run_id, tenant_id),
                )
                stmt_rows = cur.fetchall()
        finally:
            iam_conn.close()
    except Exception as exc:
        logger.debug("Permission action query skipped (non-fatal): %s", exc)
        return edges

    # Collect unique (attached_to_arn, rel_type, target_rtype, category, attached_type) tuples.
    # Using a set prevents duplicate lookups when the same role has multiple statements.
    identity_targets: Dict[tuple, str] = {}  # (arn, rel, rtype) → attached_type

    for row in stmt_rows:
        attached_to = row.get("attached_to_arn") or ""
        attached_type = row.get("attached_to_type") or "role"
        action = (row.get("action") or "").lower().strip()
        if not attached_to or not action:
            continue

        edge_spec = _PERMISSION_ACTION_MAP.get(action)
        if not edge_spec:
            # Wildcard action (*) → all service prefixes
            if action == "*":
                for _spec in _PERMISSION_WILDCARD_PREFIXES.values():
                    key = (attached_to, _spec[0], _spec[1], _spec[2])
                    identity_targets[key] = attached_type
                continue
            # Service wildcard (ecr:*, sagemaker:*, etc.)
            for prefix, spec in _PERMISSION_WILDCARD_PREFIXES.items():
                if action.startswith(prefix):
                    edge_spec = spec
                    break
        if not edge_spec:
            continue

        rel_type, target_rtype, category = edge_spec
        key = (attached_to, rel_type, target_rtype, category)
        identity_targets[key] = attached_type

    for (attached_to, rel_type, target_rtype, category), attached_type in identity_targets.items():
        try:
            with di_conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT DISTINCT resource_uid FROM asset_inventory
                    WHERE tenant_id = %s AND provider = %s AND resource_type = %s
                    LIMIT 100
                    """,
                    (tenant_id, provider, target_rtype),
                )
                target_uids = [r[0] for r in cur.fetchall()]
        except Exception as exc:
            logger.debug("Target lookup failed for %s: %s", target_rtype, exc)
            continue

        source_type = f"iam_{attached_type}"
        for tgt_uid in target_uids:
            edges.append({
                "source_uid":             attached_to,
                "source_type":            source_type,
                "target_uid":             tgt_uid,
                "target_type":            target_rtype,
                "relation_type":          rel_type,
                "is_attack_edge":         True,
                "attack_path_category":   category,
                "relation_metadata": {
                    "attack_path_category": category,
                    "derived_from":         "iam_policy_statement",
                },
            })

    logger.info(
        "Permission access edges: %d edges for scan %s (provider=%s)",
        len(edges), scan_run_id, provider,
    )
    return edges


# ── Direct permission edges from asset_inventory (fallback for DI-timeout scans) ──

# Admin policy ARNs/names that grant all permissions.
_KNOWN_ADMIN_POLICY_ARNS: frozenset = frozenset([
    "AdministratorAccess",
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "AdministratorAccess-Amplify",
    "PowerUserAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
    "AWSOrganizationsFullAccess",
    "arn:aws:iam::aws:policy/AWSOrganizationsFullAccess",
    "IAMFullAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
])

# Role name substrings that always indicate full admin access (SSO, org access roles).
_ADMIN_ROLE_NAME_PATTERNS: tuple = (
    "AdministratorAccess",
    "OrganizationsAccountAccessRole",
    "AWSControlTowerExecution",
)


def _direct_permission_edges_from_inventory(
    di_conn: "psycopg2.connection",
    tenant_id: str,
    provider: str,
) -> List[dict]:
    """Derive CAN_READ/CAN_INVOKE/CAN_DECRYPT edges from asset_inventory when
    iam_policy_statements is sparse (DI scan timed out on expensive API calls).

    Reads the latest tenant-level ``get_account_authorization_details_roles`` data to
    find inline policies and attached managed policies, matches actions against
    ``_PERMISSION_ACTION_MAP``, then looks up target resources in asset_inventory.
    Non-fatal — any exception returns [].
    """
    edges: List[dict] = []

    try:
        # Load latest role records containing AttachedManagedPolicies + RolePolicyList
        with di_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT DISTINCT ON (resource_uid) resource_uid, emitted_fields
                FROM asset_inventory
                WHERE tenant_id = %s
                  AND discovery_id = 'aws.iam.get_account_authorization_details_roles'
                ORDER BY resource_uid, last_seen_at DESC
                """,
                (tenant_id,),
            )
            role_rows = cur.fetchall()

        if not role_rows:
            return edges

        # Load managed policy documents so we can resolve attached policy actions.
        policy_actions_map: Dict[str, List[str]] = {}  # policy_arn → [actions]
        try:
            with di_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT DISTINCT ON (resource_uid) resource_uid, emitted_fields
                    FROM asset_inventory
                    WHERE tenant_id = %s
                      AND discovery_id IN (
                          'aws.iam.get_account_authorization_details_policies',
                          'aws.iam.get_policy_version'
                      )
                    ORDER BY resource_uid, last_seen_at DESC
                    """,
                    (tenant_id,),
                )
                for prow in cur.fetchall():
                    ef = prow["emitted_fields"] or {}
                    arn = ef.get("Arn") or ef.get("PolicyArn") or prow["resource_uid"] or ""
                    if not arn:
                        continue
                    acts = _extract_actions_from_policy_versions(ef)
                    if acts:
                        policy_actions_map[arn] = acts
        except Exception as pdoc_exc:
            logger.debug("Policy doc loading skipped (non-fatal): %s", pdoc_exc)

        # Derive (role_arn, rel_type, target_rtype, category) → source_type
        identity_targets: Dict[tuple, str] = {}

        for rrow in role_rows:
            role_arn = rrow["resource_uid"] or ""
            if not role_arn:
                continue
            ef = rrow["emitted_fields"] or {}

            # 0. SSO / org admin roles: emit all service edges by role name pattern
            role_name = ef.get("RoleName") or role_arn.split("/")[-1]
            if any(p in role_name for p in _ADMIN_ROLE_NAME_PATTERNS):
                for spec in _PERMISSION_WILDCARD_PREFIXES.values():
                    identity_targets[(role_arn, spec[0], spec[1], spec[2])] = "iam_role"

            # 1. Inline policies — document already embedded in role record
            for ipol in (ef.get("RolePolicyList") or []):
                if not isinstance(ipol, dict):
                    continue
                doc = ipol.get("PolicyDocument")
                if isinstance(doc, dict):
                    for act in _extract_actions_from_doc(doc):
                        spec = _resolve_permission_action(act)
                        if spec:
                            identity_targets[(role_arn, spec[0], spec[1], spec[2])] = "iam_role"

            # 2. Attached managed policies
            for apol in (ef.get("AttachedManagedPolicies") or []):
                if not isinstance(apol, dict):
                    continue
                pname = apol.get("PolicyName") or ""
                parn = apol.get("PolicyArn") or ""
                # Known admin policy → emit edges for all tracked service prefixes
                if pname in _KNOWN_ADMIN_POLICY_ARNS or parn in _KNOWN_ADMIN_POLICY_ARNS:
                    for spec in _PERMISSION_WILDCARD_PREFIXES.values():
                        identity_targets[(role_arn, spec[0], spec[1], spec[2])] = "iam_role"
                    continue
                # "AdministratorAccess" in the policy ARN suffix also counts
                if "AdministratorAccess" in parn or "AdministratorAccess" in pname:
                    for spec in _PERMISSION_WILDCARD_PREFIXES.values():
                        identity_targets[(role_arn, spec[0], spec[1], spec[2])] = "iam_role"
                    continue
                # Resolved policy document actions
                for act in (policy_actions_map.get(parn) or []):
                    spec = _resolve_permission_action(act)
                    if spec:
                        identity_targets[(role_arn, spec[0], spec[1], spec[2])] = "iam_role"

        # Resolve target UIDs and build edges
        for (role_arn, rel_type, target_rtype, category), source_type in identity_targets.items():
            try:
                with di_conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT DISTINCT resource_uid FROM asset_inventory
                        WHERE tenant_id = %s AND provider = %s AND resource_type = %s
                        LIMIT 100
                        """,
                        (tenant_id, provider, target_rtype),
                    )
                    target_uids = [r[0] for r in cur.fetchall()]
            except Exception as tgt_exc:
                logger.debug("Direct perm target lookup failed for %s: %s", target_rtype, tgt_exc)
                continue

            for tgt_uid in target_uids:
                edges.append({
                    "source_uid":           role_arn,
                    "source_type":          source_type,
                    "target_uid":           tgt_uid,
                    "target_type":          target_rtype,
                    "relation_type":        rel_type,
                    "is_attack_edge":       True,
                    "attack_path_category": category,
                    "relation_metadata": {
                        "attack_path_category": category,
                        "derived_from":         "asset_inventory_direct",
                    },
                })

        logger.info(
            "Direct inventory permission edges: %d for tenant %s (provider=%s)",
            len(edges), tenant_id, provider,
        )

    except Exception as exc:
        logger.debug("Direct inventory permission edges failed (non-fatal): %s", exc)

    return edges


def _extract_actions_from_policy_versions(ef: dict) -> List[str]:
    """Extract Allow actions from a policy record's PolicyVersionList or Document field."""
    actions: List[str] = []
    for version in (ef.get("PolicyVersionList") or []):
        if not isinstance(version, dict) or not version.get("IsDefaultVersion"):
            continue
        doc = version.get("Document") or version.get("PolicyDocument")
        if isinstance(doc, dict):
            actions.extend(_extract_actions_from_doc(doc))
    if not actions:
        doc = ef.get("Document") or ef.get("PolicyDocument")
        if isinstance(doc, dict):
            actions.extend(_extract_actions_from_doc(doc))
    return actions


def _extract_actions_from_doc(doc: dict) -> List[str]:
    """Pull all Allow-effect actions from an IAM policy document Statement list."""
    actions: List[str] = []
    for stmt in (doc.get("Statement") or []):
        if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
            continue
        stmt_actions = stmt.get("Action") or []
        if isinstance(stmt_actions, str):
            stmt_actions = [stmt_actions]
        actions.extend(str(a) for a in stmt_actions)
    return actions


def _resolve_permission_action(action: str) -> Optional[tuple]:
    """Return (rel_type, target_rtype, category) for an IAM action via exact match
    or service-wildcard prefix.  Returns None for unrecognised actions.
    """
    action_lower = action.lower().strip()
    if not action_lower or action_lower == "*":
        return None
    spec = _PERMISSION_ACTION_MAP.get(action_lower)
    if spec:
        return spec
    for prefix, pspec in _PERMISSION_WILDCARD_PREFIXES.items():
        if action_lower.startswith(prefix):
            return pspec
    return None


def _load_action_resource_map(provider: str) -> Dict[str, Any]:
    """Load iam_action_resource_map for the given CSP. Returns {} on error."""
    try:
        iam_conn = get_iam_conn()
        sql = """
            SELECT action_prefix, resource_types, attack_path_category
            FROM iam_action_resource_map
            WHERE csp = %s AND is_active = TRUE
        """
        with iam_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, (provider,))
            result = {row["action_prefix"]: row for row in cur.fetchall()}
        iam_conn.close()
        return result
    except Exception as exc:
        logger.debug("Could not load action_resource_map (non-fatal): %s", exc)
        return {}


def _actions_to_resource_types(actions: List[str], action_map: Dict) -> Dict[str, str]:
    """Map action list to {resource_type: attack_path_category} using prefix matching."""
    result: Dict[str, str] = {}
    for action in actions:
        action_lower = (action or "").lower()
        for prefix, mapping in action_map.items():
            if action_lower.startswith(prefix.lower()):
                category = mapping.get("attack_path_category", "lateral_movement")
                for rt in (mapping.get("resource_types") or []):
                    result[rt] = category
    return result


def _all_resource_types(action_map: Dict) -> Dict[str, str]:
    """Flatten entire action_map to {resource_type: attack_path_category}."""
    result: Dict[str, str] = {}
    for mapping in action_map.values():
        category = mapping.get("attack_path_category", "lateral_movement")
        for rt in (mapping.get("resource_types") or []):
            result[rt] = category
    return result
