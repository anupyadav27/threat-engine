"""
IAM Privilege Escalation Path Detector

Detects multi-hop privilege escalation paths from parsed IAM data:
  - PassRole escalation → identity can pass a role with admin access
  - CreatePolicy+SetDefault combo → self-escalation via policy version management
  - AttachPolicy escalation → identity can attach an admin policy to any resource
  - AssumeRole chain (2-hop max) → identity A assumes B, B has admin

CDR enrichment: if cdr_findings shows recent use of escalation actions by the
source identity's actor_principal, the finding is upgraded to a CDR-confirmed
CRITICAL severity finding.

Rule IDs produced:
  aws.iam.role.privilege_escalation_via_pass_role        (CRITICAL)
  aws.iam.role.privilege_escalation_via_create_policy    (CRITICAL)
  aws.iam.role.privilege_escalation_via_attach_policy    (HIGH)
  aws.iam.role.privilege_escalation_via_assume_role_chain (HIGH)
  aws.iam.role.privilege_escalation_cdr_confirmed        (CRITICAL — CDR upgrade)
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ADMIN_POLICY_ARNS = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
}

# Actions that indicate a policy grants admin-level access when on Resource:*
_ADMIN_ACTIONS = {"*", "iam:*"}

# CDR operations that confirm in-the-wild use of escalation vectors
_CDR_ESCALATION_OPERATIONS = {
    "AssumeRole",
    "PassRole",
    "CreatePolicyVersion",
    "AttachRolePolicy",
    "AttachUserPolicy",
}

# Severity constants
_SEV_CRITICAL = "critical"
_SEV_HIGH = "high"

# CDR lookback window in days
_CDR_LOOKBACK_DAYS = 30


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding_id(rule_id: str, source_arn: str, account_id: str) -> str:
    """Compute a deterministic 16-char finding ID (SHA-256 prefix)."""
    raw = f"{rule_id}|{source_arn}|{account_id}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _is_admin_effect(effective_permissions: Dict[str, Any]) -> bool:
    """Return True if the effective_permissions dict signals full admin access.

    The effective_permissions dict is expected to have the structure:
        {action_or_service: [resource, ...], ...}
    or a simpler boolean/list structure stored by some parsers.
    This function uses a best-effort check.
    """
    if not effective_permissions:
        return False
    # Dict keyed by action string
    for action in effective_permissions:
        if action in _ADMIN_ACTIONS:
            resources = effective_permissions[action]
            if isinstance(resources, (list, tuple)):
                if "*" in resources:
                    return True
            elif resources == "*":
                return True
    return False


def _has_action_on_wildcard(
    effective_permissions: Dict[str, Any],
    target_action: str,
) -> bool:
    """Return True if the identity has target_action on Resource:* .

    Args:
        effective_permissions: Dict of action → resource list from parsed role/user.
        target_action: e.g. 'iam:PassRole', 'iam:AttachRolePolicy'
    """
    if not effective_permissions:
        return False
    # Exact match
    resources = effective_permissions.get(target_action)
    if resources is not None:
        if isinstance(resources, (list, tuple)):
            return "*" in resources
        return resources == "*"
    # Wildcard service prefix e.g. 'iam:*' covers iam:PassRole
    service = target_action.split(":")[0] + ":*"
    resources = effective_permissions.get(service) or effective_permissions.get("*")
    if resources is not None:
        if isinstance(resources, (list, tuple)):
            return "*" in resources
        return resources == "*"
    return False


def _has_both_actions(
    effective_permissions: Dict[str, Any],
    action_a: str,
    action_b: str,
) -> bool:
    """Return True if effective_permissions includes BOTH action_a and action_b."""
    return (
        _has_action_on_wildcard(effective_permissions, action_a)
        and _has_action_on_wildcard(effective_permissions, action_b)
    )


def _identity_arn(entity: Dict[str, Any]) -> str:
    """Extract the canonical ARN for a role or user dict."""
    return (
        entity.get("_resource_uid")
        or entity.get("Arn")
        or entity.get("arn")
        or ""
    )


def _identity_name(entity: Dict[str, Any]) -> str:
    """Extract the human-readable name for a role or user dict."""
    return (
        entity.get("RoleName")
        or entity.get("UserName")
        or entity.get("name")
        or _identity_arn(entity).split("/")[-1]
        or "unknown"
    )


def _entity_resource_type(entity: Dict[str, Any]) -> str:
    """Return 'iam_role' or 'iam_user' based on entity content."""
    if entity.get("RoleName") or entity.get("AssumeRolePolicyDocument"):
        return "iam_role"
    if entity.get("UserName") or entity.get("PasswordLastUsed") is not None:
        return "iam_user"
    return "iam_role"


def _get_effective_permissions(entity: Dict[str, Any]) -> Dict[str, Any]:
    """Extract the effective_permissions dict from a role/user entity.

    Parsers may store this under 'effective_permissions', 'EffectivePermissions',
    or within emitted_fields. Returns an empty dict if not found.
    """
    perms = (
        entity.get("effective_permissions")
        or entity.get("EffectivePermissions")
        or {}
    )
    if not isinstance(perms, dict):
        return {}
    return perms


def _has_attached_admin_policy(entity: Dict[str, Any]) -> bool:
    """Return True if the entity has AdministratorAccess or Action:* attached."""
    attached = entity.get("AttachedManagedPolicies") or []
    for p in attached:
        arn = p.get("PolicyArn", "") if isinstance(p, dict) else str(p)
        if arn in _ADMIN_POLICY_ARNS:
            return True
    return _is_admin_effect(_get_effective_permissions(entity))


def _can_assume(source: Dict[str, Any], target: Dict[str, Any]) -> bool:
    """Return True if source has sts:AssumeRole on the target role's ARN or *.

    Checks the trust policy of the target role to see if source is a principal.
    """
    target_arn = _identity_arn(target)
    source_arn = _identity_arn(source)
    if not target_arn or not source_arn:
        return False

    # Check target's trust policy (AssumeRolePolicyDocument)
    trust_doc = target.get("AssumeRolePolicyDocument") or {}
    if isinstance(trust_doc, str):
        import json as _json
        try:
            trust_doc = _json.loads(trust_doc)
        except Exception:
            trust_doc = {}

    statements = trust_doc.get("Statement") or []
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        if stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal") or {}
        if principal == "*":
            return True
        if isinstance(principal, str) and principal == source_arn:
            return True
        if isinstance(principal, dict):
            aws_principals = principal.get("AWS") or []
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]
            for p in aws_principals:
                if p == "*" or p == source_arn:
                    return True
    return False


# ---------------------------------------------------------------------------
# CDR enrichment
# ---------------------------------------------------------------------------


def _query_cdr_for_identity(
    cdr_conn: Any,
    actor_principal: str,
    tenant_id: str,
) -> Dict[str, Any]:
    """Query cdr_findings for escalation operations by this principal.

    Args:
        cdr_conn: psycopg2 connection to threat_engine_cdr.
        actor_principal: IAM identity ARN to look up in cdr_findings.actor_principal.
        tenant_id: Tenant ID — MUST be included in all CDR queries.

    Returns:
        Dict with keys 'cdr_active' (bool) and 'cdr_use_count' (int).
    """
    result = {"cdr_active": False, "cdr_use_count": 0}
    if not cdr_conn or not actor_principal:
        return result
    try:
        with cdr_conn.cursor() as cur:
            cur.execute(
                """
                SELECT COUNT(*) AS use_count
                FROM cdr_findings
                WHERE tenant_id = %s
                  AND actor_principal = %s
                  AND operation = ANY(%s)
                  AND event_time >= NOW() - INTERVAL %s
                """,
                (
                    tenant_id,
                    actor_principal,
                    list(_CDR_ESCALATION_OPERATIONS),
                    f"{_CDR_LOOKBACK_DAYS} days",
                ),
            )
            row = cur.fetchone()
            if row and row[0] > 0:
                result["cdr_active"] = True
                result["cdr_use_count"] = int(row[0])
    except Exception as exc:
        logger.debug("CDR enrichment query failed (non-fatal): %s", exc)
    return result


def _enrich_with_cdr(
    findings: List[Dict[str, Any]],
    cdr_conn: Optional[Any],
    tenant_id: str,
) -> List[Dict[str, Any]]:
    """Enrich escalation findings with CDR confirmation signals.

    For each finding, queries cdr_findings using the source identity ARN as
    actor_principal. If matching CDR events are found within the last 30 days,
    upgrades severity to CRITICAL and sets rule_id to the CDR-confirmed variant.

    Args:
        findings: List of escalation finding dicts to enrich (mutated in place).
        cdr_conn: Optional psycopg2 connection to the CDR DB. If None, skips enrichment.
        tenant_id: Tenant scoping — included in all CDR queries.

    Returns:
        The same list with CDR signals applied.
    """
    if not cdr_conn or not findings:
        return findings

    # Batch unique source ARNs to avoid repeated queries
    unique_arns = {f["resource_uid"] for f in findings if f.get("resource_uid")}
    cdr_by_arn: Dict[str, Dict[str, Any]] = {}
    for arn in unique_arns:
        cdr_by_arn[arn] = _query_cdr_for_identity(cdr_conn, arn, tenant_id)

    for finding in findings:
        source_arn = finding.get("resource_uid", "")
        cdr_data = cdr_by_arn.get(source_arn, {"cdr_active": False, "cdr_use_count": 0})
        finding_data = finding.get("finding_data", {})
        finding_data["cdr_active"] = cdr_data["cdr_active"]
        finding_data["cdr_use_count"] = cdr_data["cdr_use_count"]
        finding["finding_data"] = finding_data

        if cdr_data["cdr_active"]:
            finding["severity"] = _SEV_CRITICAL
            finding["rule_id"] = "aws.iam.role.privilege_escalation_cdr_confirmed"
            finding["title"] = (
                "[CDR Confirmed] " + finding.get("title", "Privilege escalation path")
            )
            logger.info(
                "CDR-confirmed escalation for %s (%d CDR events)",
                source_arn,
                cdr_data["cdr_use_count"],
            )

    return findings


# ---------------------------------------------------------------------------
# Detection functions
# ---------------------------------------------------------------------------


def _detect_pass_role(
    roles: List[Dict[str, Any]],
    users: List[Dict[str, Any]],
    account_id: str,
    tenant_id: str,
    scan_run_id: str,
) -> List[Dict[str, Any]]:
    """Detect identities that can iam:PassRole to an admin role.

    Pattern: identity has iam:PassRole on * (or specific resource that resolves
    to an admin role), and the target role has AdministratorAccess or Action:*.

    Args:
        roles: Parsed role dicts from the IAM discovery reader.
        users: Parsed user dicts.
        account_id: AWS account ID.
        tenant_id: Tenant identifier.
        scan_run_id: Scan run ID.

    Returns:
        List of finding dicts.
    """
    findings: List[Dict[str, Any]] = []

    # Build set of admin role ARNs in the account for target matching
    admin_role_arns = {
        _identity_arn(r)
        for r in roles
        if _has_attached_admin_policy(r) and _identity_arn(r)
    }
    if not admin_role_arns:
        logger.debug("No admin roles found — skipping PassRole escalation check")
        return findings

    all_identities = list(roles) + list(users)
    now = _now_utc()

    for identity in all_identities:
        source_arn = _identity_arn(identity)
        if not source_arn:
            continue
        perms = _get_effective_permissions(identity)
        if not _has_action_on_wildcard(perms, "iam:PassRole"):
            continue

        for target_arn in admin_role_arns:
            if target_arn == source_arn:
                continue  # skip self
            rule_id = "aws.iam.role.privilege_escalation_via_pass_role"
            findings.append({
                "finding_id": _finding_id(rule_id, source_arn, account_id),
                "resource_uid": source_arn,
                "resource_type": _entity_resource_type(identity),
                "rule_id": rule_id,
                "severity": _SEV_CRITICAL,
                "status": "FAIL",
                "account_id": account_id,
                "tenant_id": tenant_id,
                "scan_run_id": scan_run_id,
                "region": "global",
                "provider": "aws",
                "title": (
                    f"Privilege escalation path: iam:PassRole → {target_arn}"
                ),
                "description": (
                    f"Identity '{_identity_name(identity)}' has iam:PassRole "
                    f"on Resource:* and can pass the admin role {target_arn} "
                    f"to a service or EC2 instance, gaining full admin access."
                ),
                "remediation": (
                    "Restrict iam:PassRole to specific non-admin role ARNs. "
                    "Never grant iam:PassRole on Resource:* without a condition."
                ),
                "iam_security_modules": ["privilege_escalation", "least_privilege"],
                "is_iam_relevant": True,
                "finding_data": {
                    "escalation_action": "iam:PassRole",
                    "source_identity": source_arn,
                    "target_identity": target_arn,
                    "target_has_admin": True,
                    "hop_count": 1,
                    "cdr_active": False,
                    "cdr_use_count": 0,
                },
                "first_seen_at": now,
                "last_seen_at": now,
            })
            # One finding per source → target pair; break to avoid duplicate IDs
            # (finding_id is deterministic per source, so we record only first target)
            break

    return findings


def _detect_create_policy_escalation(
    roles: List[Dict[str, Any]],
    users: List[Dict[str, Any]],
    account_id: str,
    tenant_id: str,
    scan_run_id: str,
) -> List[Dict[str, Any]]:
    """Detect identities with CreatePolicyVersion + SetDefaultPolicyVersion combo.

    Having both actions allows creating a new version of any managed policy
    with Action:* / Resource:* and then activating it — a self-escalation path.

    Args:
        roles: Parsed role dicts.
        users: Parsed user dicts.
        account_id: AWS account ID.
        tenant_id: Tenant identifier.
        scan_run_id: Scan run ID.

    Returns:
        List of finding dicts.
    """
    findings: List[Dict[str, Any]] = []
    all_identities = list(roles) + list(users)
    now = _now_utc()

    for identity in all_identities:
        source_arn = _identity_arn(identity)
        if not source_arn:
            continue
        perms = _get_effective_permissions(identity)
        if not _has_both_actions(
            perms, "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"
        ):
            continue

        rule_id = "aws.iam.role.privilege_escalation_via_create_policy"
        findings.append({
            "finding_id": _finding_id(rule_id, source_arn, account_id),
            "resource_uid": source_arn,
            "resource_type": _entity_resource_type(identity),
            "rule_id": rule_id,
            "severity": _SEV_CRITICAL,
            "status": "FAIL",
            "account_id": account_id,
            "tenant_id": tenant_id,
            "scan_run_id": scan_run_id,
            "region": "global",
            "provider": "aws",
            "title": (
                f"Privilege escalation path: "
                f"iam:CreatePolicyVersion + iam:SetDefaultPolicyVersion on "
                f"'{_identity_name(identity)}'"
            ),
            "description": (
                f"Identity '{_identity_name(identity)}' has both "
                f"iam:CreatePolicyVersion and iam:SetDefaultPolicyVersion on "
                f"Resource:*. This allows creating a new admin policy version "
                f"(Action:* / Resource:*) and activating it — granting themselves "
                f"full AWS access without needing an existing admin role."
            ),
            "remediation": (
                "Remove iam:CreatePolicyVersion or iam:SetDefaultPolicyVersion "
                "from non-admin identities. Scope to specific policy ARNs and "
                "require approval workflows for policy version changes."
            ),
            "iam_security_modules": ["privilege_escalation", "policy_analysis"],
            "is_iam_relevant": True,
            "finding_data": {
                "escalation_action": "iam:CreatePolicyVersion+iam:SetDefaultPolicyVersion",
                "source_identity": source_arn,
                "target_identity": "",
                "target_has_admin": True,
                "hop_count": 1,
                "cdr_active": False,
                "cdr_use_count": 0,
            },
            "first_seen_at": now,
            "last_seen_at": now,
        })

    return findings


def _detect_attach_policy_escalation(
    roles: List[Dict[str, Any]],
    users: List[Dict[str, Any]],
    account_id: str,
    tenant_id: str,
    scan_run_id: str,
) -> List[Dict[str, Any]]:
    """Detect identities that can attach an admin policy to any resource.

    Having iam:AttachRolePolicy or iam:AttachUserPolicy on Resource:* allows
    the identity to attach AdministratorAccess to any role/user — including
    themselves.

    Args:
        roles: Parsed role dicts.
        users: Parsed user dicts.
        account_id: AWS account ID.
        tenant_id: Tenant identifier.
        scan_run_id: Scan run ID.

    Returns:
        List of finding dicts.
    """
    findings: List[Dict[str, Any]] = []
    all_identities = list(roles) + list(users)
    now = _now_utc()

    for identity in all_identities:
        source_arn = _identity_arn(identity)
        if not source_arn:
            continue
        perms = _get_effective_permissions(identity)
        has_attach_role = _has_action_on_wildcard(perms, "iam:AttachRolePolicy")
        has_attach_user = _has_action_on_wildcard(perms, "iam:AttachUserPolicy")
        if not (has_attach_role or has_attach_user):
            continue

        escalation_action = (
            "iam:AttachRolePolicy"
            if has_attach_role
            else "iam:AttachUserPolicy"
        )
        rule_id = "aws.iam.role.privilege_escalation_via_attach_policy"
        findings.append({
            "finding_id": _finding_id(rule_id, source_arn, account_id),
            "resource_uid": source_arn,
            "resource_type": _entity_resource_type(identity),
            "rule_id": rule_id,
            "severity": _SEV_HIGH,
            "status": "FAIL",
            "account_id": account_id,
            "tenant_id": tenant_id,
            "scan_run_id": scan_run_id,
            "region": "global",
            "provider": "aws",
            "title": (
                f"Privilege escalation path: {escalation_action} on "
                f"'{_identity_name(identity)}'"
            ),
            "description": (
                f"Identity '{_identity_name(identity)}' has {escalation_action} "
                f"on Resource:*. This allows attaching AdministratorAccess to "
                f"any role or user — including themselves — achieving full "
                f"AWS admin access."
            ),
            "remediation": (
                f"Remove {escalation_action} from non-admin identities or "
                f"restrict Resource to specific role/user ARNs. Add SCPs "
                f"to prevent attaching admin policies without MFA."
            ),
            "iam_security_modules": ["privilege_escalation", "least_privilege"],
            "is_iam_relevant": True,
            "finding_data": {
                "escalation_action": escalation_action,
                "source_identity": source_arn,
                "target_identity": "*",
                "target_has_admin": True,
                "hop_count": 1,
                "cdr_active": False,
                "cdr_use_count": 0,
            },
            "first_seen_at": now,
            "last_seen_at": now,
        })

    return findings


def _detect_assume_role_chain(
    roles: List[Dict[str, Any]],
    users: List[Dict[str, Any]],
    account_id: str,
    tenant_id: str,
    scan_run_id: str,
) -> List[Dict[str, Any]]:
    """Detect 2-hop AssumeRole chains where the terminal role has admin access.

    Pattern: Identity A can assume Role B (via trust policy); Role B has admin.
    This means A is one API call away from full admin via sts:AssumeRole.

    Only checks direct (1-hop) chains here; hop_count is set to 2 to reflect
    the call depth (assume → use admin role).

    Args:
        roles: Parsed role dicts — must include AssumeRolePolicyDocument.
        users: Parsed user dicts.
        account_id: AWS account ID.
        tenant_id: Tenant identifier.
        scan_run_id: Scan run ID.

    Returns:
        List of finding dicts.
    """
    findings: List[Dict[str, Any]] = []

    # Build index of admin roles (final hop)
    admin_roles = [r for r in roles if _has_attached_admin_policy(r) and _identity_arn(r)]
    if not admin_roles:
        return findings

    all_identities = list(roles) + list(users)
    now = _now_utc()

    for source in all_identities:
        source_arn = _identity_arn(source)
        if not source_arn:
            continue
        for admin_role in admin_roles:
            target_arn = _identity_arn(admin_role)
            if target_arn == source_arn:
                continue  # skip self-loop
            if not _can_assume(source, admin_role):
                continue

            rule_id = "aws.iam.role.privilege_escalation_via_assume_role_chain"
            findings.append({
                "finding_id": _finding_id(rule_id, source_arn, account_id),
                "resource_uid": source_arn,
                "resource_type": _entity_resource_type(source),
                "rule_id": rule_id,
                "severity": _SEV_HIGH,
                "status": "FAIL",
                "account_id": account_id,
                "tenant_id": tenant_id,
                "scan_run_id": scan_run_id,
                "region": "global",
                "provider": "aws",
                "title": (
                    f"Privilege escalation path: AssumeRole chain "
                    f"'{_identity_name(source)}' → '{_identity_name(admin_role)}' (admin)"
                ),
                "description": (
                    f"Identity '{_identity_name(source)}' ({source_arn}) is trusted "
                    f"by admin role '{_identity_name(admin_role)}' ({target_arn}). "
                    f"A single sts:AssumeRole call grants full admin access. "
                    f"This is a 2-hop escalation path "
                    f"(assume → operate with admin privileges)."
                ),
                "remediation": (
                    "Restrict the trust policy of admin roles to only necessary "
                    "identities. Add MFA/ExternalId conditions. Consider removing "
                    "AdministratorAccess and using permission boundaries instead."
                ),
                "iam_security_modules": ["privilege_escalation", "role_management"],
                "is_iam_relevant": True,
                "finding_data": {
                    "escalation_action": "sts:AssumeRole",
                    "source_identity": source_arn,
                    "target_identity": target_arn,
                    "target_has_admin": True,
                    "hop_count": 2,
                    "cdr_active": False,
                    "cdr_use_count": 0,
                },
                "first_seen_at": now,
                "last_seen_at": now,
            })
            break  # One finding per source (deterministic finding_id requires it)

    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def detect_privilege_escalation_paths(
    roles: List[Dict[str, Any]],
    users: List[Dict[str, Any]],
    account_id: str,
    tenant_id: str,
    scan_run_id: str,
    cdr_conn: Optional[Any] = None,
) -> List[Dict[str, Any]]:
    """Detect multi-hop IAM privilege escalation paths.

    Runs four detection passes:
      1. PassRole → admin role
      2. CreatePolicyVersion + SetDefaultPolicyVersion combo
      3. AttachRolePolicy / AttachUserPolicy on Resource:*
      4. AssumeRole chain into an admin role (2-hop)

    Optionally enriches findings with CDR confirmation if cdr_conn is provided.
    CDR enrichment is best-effort — detection proceeds even if CDR is unavailable.

    Args:
        roles: Parsed role dicts with _resource_uid, Arn, AttachedManagedPolicies,
               AssumeRolePolicyDocument, and optionally effective_permissions.
        users: Parsed user dicts with _resource_uid, Arn, AttachedManagedPolicies,
               and optionally effective_permissions.
        account_id: AWS account ID.
        tenant_id: Tenant identifier — used to scope all DB queries.
        scan_run_id: Pipeline scan run ID.
        cdr_conn: Optional psycopg2 connection to threat_engine_cdr. If None,
                  CDR enrichment is skipped silently.

    Returns:
        List of finding dicts ready for iam_findings INSERT.
    """
    all_findings: List[Dict[str, Any]] = []

    # --- 1. PassRole escalation ---
    try:
        pass_role = _detect_pass_role(roles, users, account_id, tenant_id, scan_run_id)
        logger.debug("PassRole escalation: %d findings", len(pass_role))
        all_findings.extend(pass_role)
    except Exception as exc:
        logger.warning("PassRole escalation detection failed (non-fatal): %s", exc)

    # --- 2. CreatePolicy + SetDefault self-escalation ---
    try:
        create_policy = _detect_create_policy_escalation(
            roles, users, account_id, tenant_id, scan_run_id
        )
        logger.debug("CreatePolicy escalation: %d findings", len(create_policy))
        all_findings.extend(create_policy)
    except Exception as exc:
        logger.warning("CreatePolicy escalation detection failed (non-fatal): %s", exc)

    # --- 3. AttachPolicy escalation ---
    try:
        attach_policy = _detect_attach_policy_escalation(
            roles, users, account_id, tenant_id, scan_run_id
        )
        logger.debug("AttachPolicy escalation: %d findings", len(attach_policy))
        all_findings.extend(attach_policy)
    except Exception as exc:
        logger.warning("AttachPolicy escalation detection failed (non-fatal): %s", exc)

    # --- 4. AssumeRole chain ---
    try:
        assume_chain = _detect_assume_role_chain(
            roles, users, account_id, tenant_id, scan_run_id
        )
        logger.debug("AssumeRole chain escalation: %d findings", len(assume_chain))
        all_findings.extend(assume_chain)
    except Exception as exc:
        logger.warning("AssumeRole chain detection failed (non-fatal): %s", exc)

    # Deduplicate by finding_id (keep first occurrence)
    seen: set = set()
    deduped: List[Dict[str, Any]] = []
    for f in all_findings:
        fid = f["finding_id"]
        if fid not in seen:
            seen.add(fid)
            deduped.append(f)

    logger.info(
        "Escalation detector: %d findings before CDR enrichment (scan=%s)",
        len(deduped),
        scan_run_id,
    )

    # --- CDR enrichment (best-effort) ---
    try:
        deduped = _enrich_with_cdr(deduped, cdr_conn, tenant_id)
    except Exception as exc:
        logger.warning("CDR enrichment failed (non-fatal): %s", exc)

    cdr_confirmed = sum(1 for f in deduped if f.get("finding_data", {}).get("cdr_active"))
    logger.info(
        "Escalation detector: %d total findings, %d CDR-confirmed (scan=%s)",
        len(deduped),
        cdr_confirmed,
        scan_run_id,
    )

    return deduped
