"""
GCP IAM Provider

Reads GCP IAM data from discovery_findings / check_findings to surface:
  - Primitive roles (roles/owner, roles/editor) assigned to identities
  - Public service accounts (allUsers / allAuthenticatedUsers bindings)
  - Service accounts with project-level admin rights
  - Writes GCP IAM bindings to iam_policy_statements for attack-path IAM edges

Queries discovery_findings for GCP IAM resources (service='iam' or
service='cloudresourcemanager') and check_findings for GCP IAM failures.
"""

import hashlib
import logging
from typing import Any, Dict, List, Optional

from .base import BaseIAMProvider, empty_result

logger = logging.getLogger(__name__)

# GCP primitive roles are overly broad
_PRIMITIVE_ROLES = {"roles/owner", "roles/editor"}

# Public principals that should never have roles
_PUBLIC_PRINCIPALS = {"allUsers", "allAuthenticatedUsers"}


def _gcp_role_to_pseudo_action(role: str) -> str:
    """Convert a GCP IAM role to a pseudo service:action format.

    Enables the attack-path iam_policy validator to map GCP bindings to
    resource types using the same SERVICE_TO_TYPE_HINTS logic as AWS.

    Examples:
        roles/storage.objectAdmin      → storage:objectAdmin
        roles/bigquery.dataViewer      → bigquery:dataViewer
        roles/cloudkms.cryptoKeyDecrypter → cloudkms:cryptoKeyDecrypter
        roles/owner                    → *:*
        roles/editor                   → *:*
        roles/viewer                   → *:read
        projects/p/roles/custom        → *:*
    """
    if not role:
        return "*:*"
    role_lower = role.lower()
    if role_lower in ("roles/owner", "roles/editor"):
        return "*:*"
    if role_lower == "roles/viewer":
        return "*:read"
    if role.startswith("roles/"):
        suffix = role[6:]
        if "." in suffix:
            svc, action = suffix.split(".", 1)
            return f"{svc.lower()}:{action}"
        return f"{suffix.lower()}:*"
    # Custom project-scoped roles — treat conservatively
    return "*:*"


def _gcp_member_type(member: str) -> str:
    """Derive attached_to_type from GCP IAM member string."""
    if member.startswith("serviceAccount:"):
        return "service_account"
    if member.startswith("user:"):
        return "user"
    if member.startswith("group:"):
        return "group"
    return "user"


class GCPIAMProvider(BaseIAMProvider):
    """GCP IAM analysis provider."""

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
    ) -> Dict[str, Any]:
        """Analyze GCP IAM posture from discovery and check findings.

        Queries:
          - discovery_findings WHERE provider='gcp' AND
            service IN ('iam', 'cloudresourcemanager')
          - check_findings WHERE provider='gcp' AND status='FAIL' AND
            (rule_id LIKE '%iam%' OR rule_id LIKE '%serviceaccount%')

        Args:
            scan_run_id: Pipeline scan run ID
            tenant_id: Tenant identifier
            account_id: GCP project ID

        Returns:
            Standardized result dict with GCP IAM policy findings.
        """
        result = empty_result()

        try:
            from psycopg2.extras import RealDictCursor
            from engine_common.db_connections import get_check_conn, get_discovery_conn
        except ImportError as e:
            logger.warning(f"GCP IAM provider: missing dependency ({e}) — returning empty results")
            return result

        policy_findings: List[Dict[str, Any]] = []

        # ── Query discovery_findings for GCP IAM resources ──
        try:
            disc_conn = get_discovery_conn()
            with disc_conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT resource_uid, resource_type, emitted_fields, account_id, region
                    FROM discovery_findings
                    WHERE scan_run_id = %s
                      AND tenant_id = %s
                      AND provider = 'gcp'
                      AND service IN ('iam', 'cloudresourcemanager')
                    ORDER BY resource_uid
                    """,
                    (scan_run_id, tenant_id),
                )
                iam_rows = cur.fetchall()
            disc_conn.close()

            for row in iam_rows:
                fields = row.get("emitted_fields") or {}
                resource_uid = row.get("resource_uid", "")
                resource_type = row.get("resource_type", "")

                # Check IAM policy bindings for primitive roles and public members
                bindings = fields.get("bindings") or fields.get("iamBindings") or []
                if isinstance(bindings, list):
                    for binding in bindings:
                        if not isinstance(binding, dict):
                            continue
                        role = binding.get("role", "")
                        members = binding.get("members") or []

                        # Primitive role assignment
                        if role in _PRIMITIVE_ROLES:
                            policy_findings.append({
                                "finding_id": f"gcp_primitive_{resource_uid[-12:] if resource_uid else 'unknown'}_{role.split('/')[-1]}",
                                "rule_id": "gcp.iam.primitive_role_in_use",
                                "severity": "high",
                                "status": "FAIL",
                                "title": f"GCP primitive role '{role}' assigned at project level",
                                "resource_uid": resource_uid,
                                "resource_type": resource_type,
                                "account_id": row.get("account_id", account_id),
                                "region": row.get("region", "global"),
                                "provider": "gcp",
                                "finding_data": {
                                    "module": "gcp_iam_analysis",
                                    "role": role,
                                    "member_count": len(members),
                                    "remediation": (
                                        f"Replace {role} with predefined or custom roles "
                                        "following the principle of least privilege."
                                    ),
                                },
                            })

                        # Public principal binding
                        public_members = [m for m in members if m in _PUBLIC_PRINCIPALS]
                        if public_members:
                            policy_findings.append({
                                "finding_id": f"gcp_public_{resource_uid[-12:] if resource_uid else 'unknown'}_{role.split('/')[-1]}",
                                "rule_id": "gcp.iam.public_principal_binding",
                                "severity": "critical",
                                "status": "FAIL",
                                "title": f"GCP resource '{resource_uid}' has public IAM binding",
                                "resource_uid": resource_uid,
                                "resource_type": resource_type,
                                "account_id": row.get("account_id", account_id),
                                "region": row.get("region", "global"),
                                "provider": "gcp",
                                "finding_data": {
                                    "module": "gcp_iam_analysis",
                                    "role": role,
                                    "public_members": public_members,
                                    "remediation": (
                                        "Remove allUsers and allAuthenticatedUsers from IAM "
                                        "bindings unless intentional public access is required."
                                    ),
                                },
                            })

            logger.info(
                f"GCP IAM provider: {len(iam_rows)} IAM resources, "
                f"{len(policy_findings)} findings from discovery"
            )

        except Exception as e:
            logger.warning(f"GCP IAM discovery query failed (non-fatal): {e}")

        # ── Query check_findings for GCP IAM failures ──
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
                      AND provider = 'gcp'
                      AND status = 'FAIL'
                      AND (
                          rule_id ILIKE '%%iam%%'
                          OR rule_id ILIKE '%%serviceaccount%%'
                          OR rule_id ILIKE '%%role%%'
                          OR rule_id ILIKE '%%identity%%'
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
                    "provider": "gcp",
                    "finding_data": {
                        "source": "check_engine",
                        **finding_data,
                    },
                })

            logger.info(
                f"GCP IAM provider: {len(check_rows)} check failures merged, "
                f"{len(policy_findings)} total findings"
            )

        except Exception as e:
            logger.warning(f"GCP IAM check_findings query failed (non-fatal): {e}")

        result["policy_findings"] = policy_findings

        # ── Write GCP IAM bindings to iam_policy_statements ──
        # Enables attack-path iam_policy validator to build GCP identity→resource edges.
        # Each (member, role, resource) tuple becomes one statement row.
        _write_gcp_policy_statements(
            scan_run_id, tenant_id, account_id, iam_rows,
        )

        return result


def _write_gcp_policy_statements(
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    iam_rows: List[Dict[str, Any]],
) -> None:
    """Convert GCP IAM bindings to iam_policy_statements rows for attack-path edges."""
    if not iam_rows:
        return

    statements: List[Dict[str, Any]] = []
    for row in iam_rows:
        fields = row.get("emitted_fields") or {}
        resource_uid = row.get("resource_uid", "") or ""
        bindings = fields.get("bindings") or fields.get("iamBindings") or []
        if not isinstance(bindings, list):
            continue

        for binding in bindings:
            if not isinstance(binding, dict):
                continue
            role = binding.get("role", "")
            members = binding.get("members") or []
            if not role or not isinstance(members, list):
                continue

            pseudo_action = _gcp_role_to_pseudo_action(role)
            is_admin = pseudo_action == "*:*"

            for member in members:
                if not isinstance(member, str):
                    continue
                # Skip public bindings — they don't represent identity-specific access
                if member in _PUBLIC_PRINCIPALS:
                    continue

                # Use a stable hash so repeated scans update rather than duplicate
                stmt_key = f"gcp|{tenant_id}|{member}|{role}|{resource_uid}"
                stmt_id = "gcp_" + hashlib.sha1(stmt_key.encode()).hexdigest()[:40]

                statements.append({
                    "statement_id":   stmt_id,
                    "scan_run_id":    scan_run_id,
                    "tenant_id":      tenant_id,
                    "provider":       "gcp",
                    "account_id":     account_id,
                    "policy_arn":     role,
                    "policy_name":    role,
                    "policy_type":    "binding",
                    "is_aws_managed": False,
                    "attached_to_arn":  member,
                    "attached_to_type": _gcp_member_type(member),
                    "resource_uid":   resource_uid,
                    "sid":            None,
                    "effect":         "Allow",
                    "actions":        [pseudo_action],
                    "not_action_mode": False,
                    "resources":      [resource_uid] if resource_uid else ["*"],
                    "conditions":     None,
                    "principals":     [member],
                    "is_admin":       is_admin,
                    "is_wildcard_principal": False,
                    "has_external_id": None,
                    "is_cross_account": None,
                })

    if not statements:
        return

    try:
        from iam_engine.storage.iam_db_writer import save_policy_statements
        count = save_policy_statements(scan_run_id, tenant_id, statements, provider="gcp")
        logger.info(f"GCP IAM: wrote {count} policy statements to iam_policy_statements")
    except Exception as e:
        logger.warning(f"GCP IAM: failed to write policy statements (non-fatal): {e}")
