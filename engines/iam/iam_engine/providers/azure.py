"""
Azure IAM Provider

Reads Azure RBAC data from check_findings / discovery_findings to surface:
  - Overly-permissive role assignments (Owner/Contributor at subscription scope)
  - Guest user accounts with elevated privileges
  - Service principals with Owner rights
  - Writes RBAC role assignments to iam_policy_statements for attack-path IAM edges

Queries discovery_findings for Azure RBAC-related resources and check_findings
for Azure RBAC/identity-related rule failures.
"""

import hashlib
import logging
from typing import Any, Dict, List

from .base import BaseIAMProvider, empty_result

logger = logging.getLogger(__name__)

# Azure built-in role → pseudo service:action format.
# Covers the roles most commonly assigned in enterprise Azure tenants.
_AZURE_ROLE_TO_ACTIONS: Dict[str, List[str]] = {
    "owner":                            ["*:*"],
    "contributor":                      ["*:*"],
    "reader":                           ["*:read"],
    # Storage
    "storage blob data owner":          ["storage:*"],
    "storage blob data contributor":    ["storage:write"],
    "storage blob data reader":         ["storage:read"],
    "storage queue data contributor":   ["storage:write"],
    "storage queue data reader":        ["storage:read"],
    "storage account contributor":      ["storage:*"],
    "storage account key operator service role": ["storage:*"],
    # Key Vault
    "key vault administrator":          ["keyvault:*"],
    "key vault secrets officer":        ["keyvault:*"],
    "key vault secrets user":           ["keyvault:get"],
    "key vault crypto officer":         ["keyvault:*"],
    "key vault crypto user":            ["keyvault:get"],
    "key vault reader":                 ["keyvault:read"],
    "key vault contributor":            ["keyvault:*"],
    # SQL / Database
    "sql db contributor":               ["sql:*"],
    "sql server contributor":           ["sql:*"],
    "sql managed instance contributor": ["sql:*"],
    "azure sql db contributor":         ["sql:*"],
    # Cosmos DB
    "cosmosdb account reader role":     ["cosmosdb:read"],
    "cosmos db operator":               ["cosmosdb:*"],
    # Container / AKS
    "azure kubernetes service cluster admin role": ["container:*"],
    "azure kubernetes service cluster user role":  ["container:read"],
    "azure kubernetes service rbac cluster admin":  ["container:*"],
    "acr pull":                         ["containerregistry:pull"],
    "acr push":                         ["containerregistry:push"],
    "acrpull":                          ["containerregistry:pull"],
    "acrpush":                          ["containerregistry:push"],
    # Compute
    "virtual machine contributor":      ["compute:*"],
    "virtual machine administrator login": ["compute:*"],
    "virtual machine user login":       ["compute:read"],
}


def _azure_role_to_actions(role_name: str) -> List[str]:
    """Map Azure RBAC role name to pseudo service:action list.

    Falls back to a heuristic for unlisted roles:
    Owner/Contributor-like → *:* ; otherwise parse service from role name.
    """
    if not role_name:
        return ["*:read"]
    key = role_name.lower().strip()
    if key in _AZURE_ROLE_TO_ACTIONS:
        return _AZURE_ROLE_TO_ACTIONS[key]
    # Heuristic: roles containing "owner", "admin", "contributor" → wildcard
    if any(w in key for w in ("owner", "admin", "contributor", "operator")):
        return ["*:*"]
    # Heuristic: extract first word as service guess
    first_word = key.split()[0] if key else "unknown"
    return [f"{first_word}:read"]


def _azure_principal_type(principal_type: str) -> str:
    """Normalize Azure principalType to attached_to_type."""
    pt = (principal_type or "").lower()
    if pt in ("serviceprincipal", "service_principal", "application"):
        return "service_principal"
    if pt == "group":
        return "group"
    return "user"


class AzureIAMProvider(BaseIAMProvider):
    """Azure RBAC analysis provider."""

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
    ) -> Dict[str, Any]:
        """Analyze Azure IAM posture from discovery and check findings.

        Queries:
          - discovery_findings WHERE provider='azure' AND
            (service LIKE 'authorization%' OR resource_type LIKE '%role%')
          - check_findings WHERE provider='azure' AND status='FAIL' AND
            (rule_id LIKE '%iam%' OR rule_id LIKE '%rbac%' OR
             rule_id LIKE '%identity%' OR rule_id LIKE '%role%')

        Args:
            scan_run_id: Pipeline scan run ID
            tenant_id: Tenant identifier
            account_id: Azure subscription ID

        Returns:
            Standardized result dict with Azure IAM policy findings.
        """
        result = empty_result()

        try:
            from psycopg2.extras import RealDictCursor
            from engine_common.db_connections import get_check_conn, get_discovery_conn
        except ImportError as e:
            logger.warning(f"Azure IAM provider: missing dependency ({e}) — returning empty results")
            return result

        policy_findings: List[Dict[str, Any]] = []

        # ── Query discovery_findings for Azure RBAC resources ──
        try:
            disc_conn = get_discovery_conn()
            with disc_conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT resource_uid, resource_type, emitted_fields, account_id, region
                    FROM discovery_findings
                    WHERE scan_run_id = %s
                      AND tenant_id = %s
                      AND provider = 'azure'
                      AND (service LIKE 'authorization%%' OR resource_type LIKE '%%role%%')
                    ORDER BY resource_uid
                    """,
                    (scan_run_id, tenant_id),
                )
                rbac_rows = cur.fetchall()
            disc_conn.close()

            for row in rbac_rows:
                fields = row.get("emitted_fields") or {}
                role_def_name = (
                    fields.get("roleName")
                    or fields.get("RoleDefinitionName")
                    or fields.get("role_definition_name", "")
                )
                scope = fields.get("scope") or fields.get("Scope", "")
                principal_type = fields.get("principalType") or fields.get("PrincipalType", "")

                # Flag Owner/Contributor assigned at subscription scope
                risky_roles = {"Owner", "Contributor"}
                if role_def_name in risky_roles and "/subscriptions/" in scope and "/resourceGroups/" not in scope:
                    resource_uid = row.get("resource_uid", "")
                    policy_findings.append({
                        "finding_id": f"azure_rbac_broad_{resource_uid[-16:] if resource_uid else 'unknown'}",
                        "rule_id": "azure.iam.rbac.broad_subscription_role",
                        "severity": "high",
                        "status": "FAIL",
                        "title": f"Azure {role_def_name} role assigned at subscription scope",
                        "resource_uid": resource_uid,
                        "resource_type": row.get("resource_type", "azure.authorization.roleassignment"),
                        "account_id": row.get("account_id", account_id),
                        "region": row.get("region", "global"),
                        "provider": "azure",
                        "finding_data": {
                            "module": "azure_rbac_analysis",
                            "role_name": role_def_name,
                            "scope": scope,
                            "principal_type": principal_type,
                            "remediation": (
                                f"Restrict the {role_def_name} assignment to a specific "
                                "resource group or resource instead of the full subscription."
                            ),
                        },
                    })

                # Flag Guest users with elevated privileges
                if principal_type in ("Guest", "guest") and role_def_name in risky_roles:
                    resource_uid = row.get("resource_uid", "")
                    policy_findings.append({
                        "finding_id": f"azure_rbac_guest_{resource_uid[-16:] if resource_uid else 'unknown'}",
                        "rule_id": "azure.iam.rbac.guest_with_privileged_role",
                        "severity": "critical",
                        "status": "FAIL",
                        "title": f"Azure Guest user assigned {role_def_name} role",
                        "resource_uid": resource_uid,
                        "resource_type": row.get("resource_type", "azure.authorization.roleassignment"),
                        "account_id": row.get("account_id", account_id),
                        "region": row.get("region", "global"),
                        "provider": "azure",
                        "finding_data": {
                            "module": "azure_rbac_analysis",
                            "role_name": role_def_name,
                            "principal_type": principal_type,
                            "remediation": (
                                "Remove privileged role assignments from Guest accounts. "
                                "Use regular member accounts with least-privilege roles."
                            ),
                        },
                    })

            logger.info(
                f"Azure IAM provider: {len(rbac_rows)} RBAC resources, "
                f"{len(policy_findings)} findings from discovery"
            )

        except Exception as e:
            logger.warning(f"Azure IAM discovery query failed (non-fatal): {e}")

        # ── Query check_findings for Azure identity/RBAC failures ──
        try:
            check_conn = get_check_conn()
            with check_conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT finding_id, rule_id, severity, status,
                           resource_uid, resource_type, account_id, region,
                           finding_data
                    FROM check_findings
                    WHERE scan_run_id = %s
                      AND tenant_id = %s
                      AND provider = 'azure'
                      AND status = 'FAIL'
                      AND (
                          rule_id ILIKE '%%iam%%'
                          OR rule_id ILIKE '%%rbac%%'
                          OR rule_id ILIKE '%%identity%%'
                          OR rule_id ILIKE '%%role%%'
                          OR rule_id ILIKE '%%aad%%'
                          OR rule_id ILIKE '%%entra%%'
                      )
                    """,
                    (scan_run_id, tenant_id),
                )
                check_rows = cur.fetchall()
            check_conn.close()

            existing_ids = {f["finding_id"] for f in policy_findings}
            for row in check_rows:
                fid = row.get("finding_id", "")
                if fid in existing_ids:
                    continue
                finding_data = row.get("finding_data") or {}
                policy_findings.append({
                    "finding_id": fid,
                    "rule_id": row.get("rule_id", ""),
                    "severity": row.get("severity", "medium"),
                    "status": "FAIL",
                    "title": finding_data.get("title", row.get("rule_id", "")),
                    "resource_uid": row.get("resource_uid", ""),
                    "resource_type": row.get("resource_type", ""),
                    "account_id": row.get("account_id", account_id),
                    "region": row.get("region", "global"),
                    "provider": "azure",
                    "finding_data": {
                        "source": "check_engine",
                        **finding_data,
                    },
                })

            logger.info(
                f"Azure IAM provider: {len(check_rows)} check failures merged, "
                f"{len(policy_findings)} total findings"
            )

        except Exception as e:
            logger.warning(f"Azure IAM check_findings query failed (non-fatal): {e}")

        result["policy_findings"] = policy_findings

        # ── Write Azure RBAC assignments to iam_policy_statements ──
        _write_azure_policy_statements(scan_run_id, tenant_id, account_id, rbac_rows)

        return result


def _write_azure_policy_statements(
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    rbac_rows: List[Dict[str, Any]],
) -> None:
    """Convert Azure RBAC role assignments to iam_policy_statements rows."""
    if not rbac_rows:
        return

    statements: List[Dict[str, Any]] = []
    for row in rbac_rows:
        fields = row.get("emitted_fields") or {}
        resource_uid = row.get("resource_uid", "") or ""

        role_name = (
            fields.get("roleName")
            or fields.get("RoleDefinitionName")
            or fields.get("role_definition_name", "")
        )
        principal_id = (
            fields.get("principalId")
            or fields.get("PrincipalId")
            or fields.get("principal_id", "")
        )
        principal_type = (
            fields.get("principalType")
            or fields.get("PrincipalType", "")
        )
        scope = fields.get("scope") or fields.get("Scope") or resource_uid

        if not principal_id or not role_name:
            continue

        actions = _azure_role_to_actions(role_name)
        is_admin = "*:*" in actions

        stmt_key = f"azure|{tenant_id}|{principal_id}|{role_name}|{scope}"
        stmt_id = "az_" + hashlib.sha1(stmt_key.encode()).hexdigest()[:40]

        statements.append({
            "statement_id":   stmt_id,
            "scan_run_id":    scan_run_id,
            "tenant_id":      tenant_id,
            "provider":       "azure",
            "account_id":     account_id,
            "policy_arn":     resource_uid,
            "policy_name":    role_name,
            "policy_type":    "role_assignment",
            "is_aws_managed": False,
            "attached_to_arn":  principal_id,
            "attached_to_type": _azure_principal_type(principal_type),
            "resource_uid":   scope,
            "sid":            None,
            "effect":         "Allow",
            "actions":        actions,
            "not_action_mode": False,
            "resources":      [scope] if scope else ["*"],
            "conditions":     None,
            "principals":     [principal_id],
            "is_admin":       is_admin,
            "is_wildcard_principal": False,
            "has_external_id": None,
            "is_cross_account": None,
        })

    if not statements:
        return

    try:
        from iam_engine.storage.iam_db_writer import save_policy_statements
        count = save_policy_statements(scan_run_id, tenant_id, statements, provider="azure")
        logger.info(f"Azure IAM: wrote {count} policy statements to iam_policy_statements")
    except Exception as e:
        logger.warning(f"Azure IAM: failed to write policy statements (non-fatal): {e}")
