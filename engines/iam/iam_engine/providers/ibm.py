"""
IBM Cloud IAM Provider

Analyzes IBM Cloud IAM posture from discovery_findings:
  - API key rotation (> 90 / 180 days → HIGH / CRITICAL)
  - Service ID over-permission (Administrator on * resource)
  - Account-level MFA enforcement (mfa=NONE → CRITICAL)
  - Trusted Profile wildcard admin → CRITICAL
  - Access Group wildcard platform-services admin → HIGH
"""

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from .base import BaseIAMProvider, empty_result

logger = logging.getLogger(__name__)

_ADMIN_ROLE_FRAGMENT = "role:Administrator"
_WILDCARD_RESOURCE_VALUES = {"*", ""}


def _fid(rule_id: str, resource_uid: str, scan_run_id: str) -> str:
    raw = f"{rule_id}|{resource_uid}|{scan_run_id}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _days_since(date_str: str) -> int:
    """Return days since ISO-8601 date string, or 0 on parse error."""
    if not date_str:
        return 0
    try:
        dt = datetime.fromisoformat(date_str.rstrip("Z").split(".")[0]).replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).days
    except Exception:
        return 0


def _is_admin_role(roles: List[Dict]) -> bool:
    return any(_ADMIN_ROLE_FRAGMENT in r.get("role_id", "") for r in roles)


def _is_wildcard_resource(resources: List[Dict]) -> bool:
    for res in resources:
        for attr in res.get("attributes", []):
            if attr.get("name") == "resourceType" and attr.get("value", "") in _WILDCARD_RESOURCE_VALUES:
                return True
    return False


class IBMIAMProvider(BaseIAMProvider):
    """IBM Cloud IAM analysis provider."""

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
            logger.warning("IBM IAM provider: missing dependency (%s) — returning empty", exc)
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
                      AND provider = 'ibm'
                      AND service IN ('iam', 'accounts')
                    ORDER BY resource_uid
                    """,
                    (scan_run_id, tenant_id),
                )
                rows = cur.fetchall()
            disc_conn.close()
        except Exception as exc:
            logger.error("IBM IAM: discovery_findings query failed: %s", exc)
            return result

        now = datetime.now(timezone.utc)

        for row in rows:
            fields = row.get("emitted_fields") or {}
            resource_uid = row.get("resource_uid", "")
            resource_type = row.get("resource_type", "")
            region = row.get("region") or "global"
            acct = row.get("account_id") or account_id or ""

            # ── Module 1: API Key rotation ──
            if "api_key" in resource_type.lower() or "apikey" in resource_type.lower():
                created_at = fields.get("created_at", "")
                age_days = _days_since(created_at)
                locked = fields.get("locked", False)
                if age_days > 180:
                    policy_findings.append({
                        "finding_id": _fid("ibm.iam.api_key.rotation_critical", resource_uid, scan_run_id),
                        "rule_id": "ibm.iam.api_key.rotation_critical",
                        "severity": "critical",
                        "status": "FAIL",
                        "title": f"IBM API key not rotated in {age_days} days (>180)",
                        "resource_uid": resource_uid,
                        "resource_type": resource_type,
                        "account_id": acct,
                        "region": region,
                        "provider": "ibm",
                        "iam_security_modules": ["access_control"],
                        "finding_data": {
                            "age_days": age_days, "locked": locked, "created_at": created_at,
                            "remediation": "Rotate or delete API keys older than 90 days.",
                        },
                    })
                elif age_days > 90:
                    policy_findings.append({
                        "finding_id": _fid("ibm.iam.api_key.rotation_high", resource_uid, scan_run_id),
                        "rule_id": "ibm.iam.api_key.rotation_high",
                        "severity": "high",
                        "status": "FAIL",
                        "title": f"IBM API key not rotated in {age_days} days (>90)",
                        "resource_uid": resource_uid,
                        "resource_type": resource_type,
                        "account_id": acct,
                        "region": region,
                        "provider": "ibm",
                        "iam_security_modules": ["access_control"],
                        "finding_data": {
                            "age_days": age_days, "locked": locked, "created_at": created_at,
                            "remediation": "Rotate API keys older than 90 days.",
                        },
                    })

            # ── Module 2: Service ID over-permission ──
            if "service_id" in resource_type.lower() or "serviceid" in resource_type.lower():
                policies = fields.get("policies") or []
                for pol in policies:
                    if not isinstance(pol, dict):
                        continue
                    roles_list = pol.get("roles") or []
                    resources_list = pol.get("resources") or [{}]
                    if _is_admin_role(roles_list) and _is_wildcard_resource(resources_list):
                        policy_findings.append({
                            "finding_id": _fid("ibm.iam.service_id.wildcard_admin", resource_uid, scan_run_id),
                            "rule_id": "ibm.iam.service_id.wildcard_admin",
                            "severity": "critical",
                            "status": "FAIL",
                            "title": "IBM Service ID has Administrator role on all resources",
                            "resource_uid": resource_uid,
                            "resource_type": resource_type,
                            "account_id": acct,
                            "region": region,
                            "provider": "ibm",
                            "iam_security_modules": ["least_privilege"],
                            "finding_data": {
                                "policy_id": pol.get("id", ""),
                                "remediation": "Scope Service ID policies to specific resources and actions.",
                            },
                        })
                        break

            # ── Module 3: Account MFA enforcement ──
            if "account_settings" in resource_type.lower() or "account.settings" in resource_type.lower():
                mfa = fields.get("mfa", "NONE")
                if mfa in ("NONE", ""):
                    policy_findings.append({
                        "finding_id": _fid("ibm.iam.account.mfa_not_enforced", resource_uid, scan_run_id),
                        "rule_id": "ibm.iam.account.mfa_not_enforced",
                        "severity": "critical",
                        "status": "FAIL",
                        "title": "IBM account-level MFA is not enforced (mfa=NONE)",
                        "resource_uid": resource_uid,
                        "resource_type": resource_type,
                        "account_id": acct,
                        "region": region,
                        "provider": "ibm",
                        "iam_security_modules": ["access_control"],
                        "finding_data": {
                            "current_mfa_setting": mfa,
                            "remediation": "Set account MFA to TOTP4ALL in IBM IAM settings.",
                        },
                    })

            # ── Module 4: Trusted Profile wildcard admin ──
            if "trusted_profile" in resource_type.lower():
                policies = fields.get("policies") or []
                for pol in policies:
                    if not isinstance(pol, dict):
                        continue
                    roles_list = pol.get("roles") or []
                    resources_list = pol.get("resources") or [{}]
                    if _is_admin_role(roles_list) and _is_wildcard_resource(resources_list):
                        policy_findings.append({
                            "finding_id": _fid("ibm.iam.trusted_profile.wildcard_admin", resource_uid, scan_run_id),
                            "rule_id": "ibm.iam.trusted_profile.wildcard_admin",
                            "severity": "critical",
                            "status": "FAIL",
                            "title": "IBM Trusted Profile grants Administrator on all resources",
                            "resource_uid": resource_uid,
                            "resource_type": resource_type,
                            "account_id": acct,
                            "region": region,
                            "provider": "ibm",
                            "iam_security_modules": ["role_management"],
                            "finding_data": {
                                "remediation": "Restrict Trusted Profile policies to specific services and resources.",
                            },
                        })
                        break

            # ── Module 5: Access Group wildcard platform-services admin ──
            if "access_group" in resource_type.lower():
                policies = fields.get("policies") or []
                for pol in policies:
                    if not isinstance(pol, dict):
                        continue
                    roles_list = pol.get("roles") or []
                    resources_list = pol.get("resources") or [{}]
                    is_platform_wide = False
                    for res in resources_list:
                        for attr in res.get("attributes", []):
                            if attr.get("name") == "serviceType" and attr.get("value") == "platform-services":
                                is_platform_wide = True
                    if _is_admin_role(roles_list) and is_platform_wide:
                        policy_findings.append({
                            "finding_id": _fid("ibm.iam.access_group.platform_admin", resource_uid, scan_run_id),
                            "rule_id": "ibm.iam.access_group.platform_admin",
                            "severity": "high",
                            "status": "FAIL",
                            "title": "IBM Access Group grants Administrator on all platform services",
                            "resource_uid": resource_uid,
                            "resource_type": resource_type,
                            "account_id": acct,
                            "region": region,
                            "provider": "ibm",
                            "iam_security_modules": ["role_management"],
                            "finding_data": {
                                "policy_id": pol.get("id", ""),
                                "remediation": "Scope Access Group policies to specific services.",
                            },
                        })
                        break

        result["policy_findings"] = policy_findings
        logger.info(
            "IBM IAM provider: %d findings for scan=%s account=%s",
            len(policy_findings), scan_run_id, account_id,
        )
        _write_ibm_policy_statements(scan_run_id, tenant_id, account_id, rows)
        return result


# IBM IAM role → pseudo-action
_IBM_ROLE_ACTION_MAP = {
    "Administrator": "*:*",
    "Manager":       "*:*",
    "Operator":      "*:*",
    "Editor":        "*:write",
    "Writer":        "*:write",
    "Viewer":        "*:read",
    "Reader":        "*:read",
}


def _ibm_roles_to_actions(roles: List[Dict]) -> List[str]:
    """Convert IBM IAM role list to pseudo-actions."""
    actions = set()
    for r in roles:
        rid = r.get("role_id", "")
        # role_id looks like "crn:v1:bluemix:public:iam::::role:Administrator"
        for role_name, action in _IBM_ROLE_ACTION_MAP.items():
            if role_name in rid:
                actions.add(action)
                break
        else:
            actions.add("*:read")  # conservative fallback
    return list(actions) if actions else ["*:read"]


def _write_ibm_policy_statements(
    scan_run_id: str, tenant_id: str, account_id: str, rows: List[Dict[str, Any]],
) -> None:
    """Convert IBM IAM service ID and access group policies to iam_policy_statements."""
    import hashlib
    if not rows:
        return

    statements = []
    for row in rows:
        fields = row.get("emitted_fields") or {}
        resource_uid = row.get("resource_uid", "") or ""
        resource_type = (row.get("resource_type") or "").lower()

        if "service_id" not in resource_type and "access_group" not in resource_type and "trusted_profile" not in resource_type:
            continue

        policies = fields.get("policies") or []
        for pol in policies:
            if not isinstance(pol, dict):
                continue
            roles_list = pol.get("roles") or []
            actions = _ibm_roles_to_actions(roles_list)
            is_admin = "*:*" in actions

            stmt_key = f"ibm|{tenant_id}|{resource_uid}|{pol.get('id','')}"
            stmt_id = "ibm_" + hashlib.sha1(stmt_key.encode()).hexdigest()[:40]

            attached_type = "service_principal" if "service_id" in resource_type else "group"

            statements.append({
                "statement_id":   stmt_id,
                "scan_run_id":    scan_run_id,
                "tenant_id":      tenant_id,
                "provider":       "ibm",
                "account_id":     account_id,
                "policy_arn":     pol.get("id", resource_uid),
                "policy_name":    pol.get("id", resource_uid),
                "policy_type":    "access_policy",
                "is_aws_managed": False,
                "attached_to_arn":  resource_uid,
                "attached_to_type": attached_type,
                "resource_uid":   resource_uid,
                "sid":            None,
                "effect":         "Allow",
                "actions":        actions,
                "not_action_mode": False,
                "resources":      ["*"],
                "conditions":     None,
                "principals":     [resource_uid],
                "is_admin":       is_admin,
                "is_wildcard_principal": False,
                "has_external_id": None,
                "is_cross_account": None,
            })

    if not statements:
        return
    try:
        from iam_engine.storage.iam_db_writer import save_policy_statements
        count = save_policy_statements(scan_run_id, tenant_id, statements, provider="ibm")
        logger.info("IBM IAM: wrote %d policy statements", count)
    except Exception as e:
        logger.warning("IBM IAM: failed to write policy statements (non-fatal): %s", e)
