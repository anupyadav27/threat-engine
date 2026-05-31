"""
AliCloud IAM Provider (RAM — Resource Access Management)

Analyzes AliCloud RAM posture from discovery_findings:
  - RAM user with direct AdministratorAccess or wildcard policy → CRITICAL
  - AccessKey rotation > 90 / 180 days → HIGH / CRITICAL
  - MFA not required for console login → CRITICAL
  - RAM role with wildcard cross-account trust → HIGH
  - Custom policy with Action:* Resource:* → CRITICAL
"""

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from .base import BaseIAMProvider, empty_result

logger = logging.getLogger(__name__)

_ADMIN_POLICIES = {"AdministratorAccess", "AliyunRootAccessControl"}


def _fid(rule_id: str, resource_uid: str, scan_run_id: str) -> str:
    raw = f"{rule_id}|{resource_uid}|{scan_run_id}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _days_since(date_str: str) -> int:
    if not date_str:
        return 0
    try:
        dt = datetime.fromisoformat(date_str.rstrip("Z").split(".")[0]).replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).days
    except Exception:
        return 0


def _has_wildcard_statement(policy_doc: Dict) -> bool:
    """Return True if policy document contains Action:* + Resource:* Allow."""
    if not policy_doc:
        return False
    stmts = policy_doc.get("Statement") or []
    for stmt in stmts:
        if not isinstance(stmt, dict):
            continue
        if stmt.get("Effect") != "Allow":
            continue
        action = stmt.get("Action", [])
        resource = stmt.get("Resource", [])
        if isinstance(action, str):
            action = [action]
        if isinstance(resource, str):
            resource = [resource]
        if "*" in action and "*" in resource:
            return True
    return False


class AliCloudIAMProvider(BaseIAMProvider):
    """AliCloud RAM analysis provider."""

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
    ) -> Dict[str, Any]:
        result = empty_result()

        try:
            from psycopg2.extras import RealDictCursor
            from engine_common.db_connections import get_discovery_conn
        except ImportError as exc:
            logger.warning("AliCloud IAM provider: missing dependency (%s) — returning empty", exc)
            return result

        policy_findings: List[Dict[str, Any]] = []

        try:
            disc_conn = get_discovery_conn()
            with disc_conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT resource_uid, resource_type, emitted_fields, account_id, region
                    FROM discovery_findings
                    WHERE scan_run_id = %s
                      AND tenant_id = %s
                      AND provider = 'alicloud'
                      AND service = 'ram'
                    ORDER BY resource_uid
                    """,
                    (scan_run_id, tenant_id),
                )
                rows = cur.fetchall()
            disc_conn.close()
        except Exception as exc:
            logger.error("AliCloud IAM: discovery_findings query failed: %s", exc)
            return result

        for row in rows:
            fields = row.get("emitted_fields") or {}
            resource_uid = row.get("resource_uid", "")
            resource_type = row.get("resource_type", "")
            region = row.get("region") or "global"
            acct = row.get("account_id") or account_id or ""

            # ── Module 1: RAM user direct AdministratorAccess ──
            if "user" in resource_type.lower():
                attached = fields.get("AttachedPolicies") or []
                for pol in attached:
                    pname = pol.get("PolicyName", "")
                    if pname in _ADMIN_POLICIES:
                        policy_findings.append({
                            "finding_id": _fid("alicloud.ram.user.direct_admin", resource_uid, scan_run_id),
                            "rule_id": "alicloud.ram.user.direct_admin",
                            "severity": "critical",
                            "status": "FAIL",
                            "title": f"AliCloud RAM user has {pname} attached directly (not via group)",
                            "resource_uid": resource_uid,
                            "resource_type": resource_type,
                            "account_id": acct,
                            "region": region,
                            "provider": "alicloud",
                            "iam_security_modules": ["least_privilege"],
                            "finding_data": {
                                "policy_name": pname,
                                "remediation": "Assign AdministratorAccess via group, not directly to user.",
                            },
                        })
                        break

            # ── Module 2: AccessKey rotation ──
            if "access_key" in resource_type.lower() or "accesskey" in resource_type.lower():
                create_date = fields.get("CreateDate", "")
                age_days = _days_since(create_date)
                if age_days > 180:
                    policy_findings.append({
                        "finding_id": _fid("alicloud.ram.access_key.rotation_critical", resource_uid, scan_run_id),
                        "rule_id": "alicloud.ram.access_key.rotation_critical",
                        "severity": "critical",
                        "status": "FAIL",
                        "title": f"AliCloud AccessKey not rotated in {age_days} days (>180)",
                        "resource_uid": resource_uid,
                        "resource_type": resource_type,
                        "account_id": acct,
                        "region": region,
                        "provider": "alicloud",
                        "iam_security_modules": ["access_control"],
                        "finding_data": {
                            "age_days": age_days, "create_date": create_date,
                            "remediation": "Rotate AliCloud AccessKeys older than 90 days.",
                        },
                    })
                elif age_days > 90:
                    policy_findings.append({
                        "finding_id": _fid("alicloud.ram.access_key.rotation_high", resource_uid, scan_run_id),
                        "rule_id": "alicloud.ram.access_key.rotation_high",
                        "severity": "high",
                        "status": "FAIL",
                        "title": f"AliCloud AccessKey not rotated in {age_days} days (>90)",
                        "resource_uid": resource_uid,
                        "resource_type": resource_type,
                        "account_id": acct,
                        "region": region,
                        "provider": "alicloud",
                        "iam_security_modules": ["access_control"],
                        "finding_data": {
                            "age_days": age_days, "create_date": create_date,
                            "remediation": "Rotate AliCloud AccessKeys older than 90 days.",
                        },
                    })

            # ── Module 3: MFA enforcement ──
            if "security_preference" in resource_type.lower() or "account" in resource_type.lower():
                mfa_required = fields.get("LoginProfile", {}).get("MFABindRequired", True)
                if not mfa_required:
                    policy_findings.append({
                        "finding_id": _fid("alicloud.ram.account.mfa_not_required", resource_uid, scan_run_id),
                        "rule_id": "alicloud.ram.account.mfa_not_required",
                        "severity": "critical",
                        "status": "FAIL",
                        "title": "AliCloud RAM account does not require MFA for console login",
                        "resource_uid": resource_uid,
                        "resource_type": resource_type,
                        "account_id": acct,
                        "region": region,
                        "provider": "alicloud",
                        "iam_security_modules": ["access_control"],
                        "finding_data": {
                            "mfa_bind_required": mfa_required,
                            "remediation": "Enable MFABindRequired in RAM account security preferences.",
                        },
                    })

            # ── Module 4: RAM role wildcard cross-account trust ──
            if "role" in resource_type.lower():
                trust_policy = fields.get("AssumeRolePolicyDocument") or {}
                stmts = trust_policy.get("Statement") or []
                for stmt in stmts:
                    if not isinstance(stmt, dict):
                        continue
                    principal = stmt.get("Principal", {})
                    if isinstance(principal, dict):
                        ram_principal = principal.get("RAM", "")
                    else:
                        ram_principal = str(principal)
                    if "acs:ram::*:root" in ram_principal or ram_principal == "*":
                        policy_findings.append({
                            "finding_id": _fid("alicloud.ram.role.wildcard_trust", resource_uid, scan_run_id),
                            "rule_id": "alicloud.ram.role.wildcard_trust",
                            "severity": "high",
                            "status": "FAIL",
                            "title": "AliCloud RAM role has wildcard cross-account trust principal",
                            "resource_uid": resource_uid,
                            "resource_type": resource_type,
                            "account_id": acct,
                            "region": region,
                            "provider": "alicloud",
                            "iam_security_modules": ["role_management"],
                            "finding_data": {
                                "principal": ram_principal,
                                "remediation": "Restrict RAM role trust to specific account IDs, not wildcard.",
                            },
                        })
                        break

            # ── Module 5: Custom policy wildcard ──
            if "policy" in resource_type.lower() and "system" not in resource_type.lower():
                policy_doc = fields.get("PolicyDocument") or {}
                if _has_wildcard_statement(policy_doc):
                    policy_findings.append({
                        "finding_id": _fid(
                            "alicloud.ram.policy.wildcard_action_resource", resource_uid, scan_run_id
                        ),
                        "rule_id": "alicloud.ram.policy.wildcard_action_resource",
                        "severity": "critical",
                        "status": "FAIL",
                        "title": "AliCloud RAM policy allows Action:* Resource:* (full admin equivalent)",
                        "resource_uid": resource_uid,
                        "resource_type": resource_type,
                        "account_id": acct,
                        "region": region,
                        "provider": "alicloud",
                        "iam_security_modules": ["least_privilege"],
                        "finding_data": {
                            "remediation": "Remove wildcard Action and Resource from RAM custom policies.",
                        },
                    })

        result["policy_findings"] = policy_findings
        logger.info(
            "AliCloud IAM provider: %d findings for scan=%s account=%s",
            len(policy_findings), scan_run_id, account_id,
        )
        _write_alicloud_policy_statements(scan_run_id, tenant_id, account_id, rows)
        return result


def _extract_alicloud_statements(
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    rows: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Extract iam_policy_statements rows from AliCloud RAM discovery rows.

    AliCloud RAM actions already use service:action format (e.g. oss:GetObject)
    so they feed directly into the attack-path SERVICE_TO_TYPE_HINTS parser.
    """
    import hashlib
    statements = []

    for row in rows:
        fields = row.get("emitted_fields") or {}
        resource_uid = row.get("resource_uid", "") or ""
        resource_type = (row.get("resource_type") or "").lower()

        # Role or user rows that have AttachedPolicies with wildcard → write *:* statement
        if "user" in resource_type or "role" in resource_type:
            attached = fields.get("AttachedPolicies") or []
            policy_doc = fields.get("PolicyDocument") or {}
            stmts = policy_doc.get("Statement") or []

            # Direct wildcard admin policies
            for pol in attached:
                pname = pol.get("PolicyName", "")
                if pname in _ADMIN_POLICIES:
                    sid = "ali_" + hashlib.sha1(
                        f"alicloud|{tenant_id}|{resource_uid}|admin".encode()
                    ).hexdigest()[:40]
                    statements.append({
                        "statement_id":   sid,
                        "scan_run_id":    scan_run_id,
                        "tenant_id":      tenant_id,
                        "provider":       "alicloud",
                        "account_id":     account_id,
                        "policy_arn":     pname,
                        "policy_name":    pname,
                        "policy_type":    "attached",
                        "is_aws_managed": False,
                        "attached_to_arn":  resource_uid,
                        "attached_to_type": "role" if "role" in resource_type else "user",
                        "resource_uid":   resource_uid,
                        "sid":            None,
                        "effect":         "Allow",
                        "actions":        ["*:*"],
                        "not_action_mode": False,
                        "resources":      ["*"],
                        "conditions":     None,
                        "principals":     [resource_uid],
                        "is_admin":       True,
                        "is_wildcard_principal": False,
                        "has_external_id": None,
                        "is_cross_account": None,
                    })

            # Inline policy document statements on this entity
            for s in stmts:
                if not isinstance(s, dict) or s.get("Effect") != "Allow":
                    continue
                actions = s.get("Action") or []
                if isinstance(actions, str):
                    actions = [actions]
                resources = s.get("Resource") or ["*"]
                if isinstance(resources, str):
                    resources = [resources]
                sid_key = f"alicloud|{tenant_id}|{resource_uid}|{','.join(actions[:3])}"
                stmt_id = "ali_" + hashlib.sha1(sid_key.encode()).hexdigest()[:40]
                statements.append({
                    "statement_id":   stmt_id,
                    "scan_run_id":    scan_run_id,
                    "tenant_id":      tenant_id,
                    "provider":       "alicloud",
                    "account_id":     account_id,
                    "policy_arn":     resource_uid,
                    "policy_name":    resource_uid,
                    "policy_type":    "inline",
                    "is_aws_managed": False,
                    "attached_to_arn":  resource_uid,
                    "attached_to_type": "role" if "role" in resource_type else "user",
                    "resource_uid":   resource_uid,
                    "sid":            s.get("Sid"),
                    "effect":         "Allow",
                    "actions":        actions,
                    "not_action_mode": False,
                    "resources":      resources,
                    "conditions":     None,
                    "principals":     [resource_uid],
                    "is_admin":       "*" in actions,
                    "is_wildcard_principal": False,
                    "has_external_id": None,
                    "is_cross_account": None,
                })

    return statements


def _write_alicloud_policy_statements(
    scan_run_id: str, tenant_id: str, account_id: str, rows: List[Dict[str, Any]],
) -> None:
    statements = _extract_alicloud_statements(scan_run_id, tenant_id, account_id, rows)
    if not statements:
        return
    try:
        from iam_engine.storage.iam_db_writer import save_policy_statements
        count = save_policy_statements(scan_run_id, tenant_id, statements, provider="alicloud")
        logger.info("AliCloud IAM: wrote %d policy statements", count)
    except Exception as e:
        logger.warning("AliCloud IAM: failed to write policy statements (non-fatal): %s", e)
