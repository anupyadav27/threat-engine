"""
GCP IAM Provider

Reads GCP IAM data from discovery_findings / check_findings to surface:
  - Primitive roles (roles/owner, roles/editor) assigned to identities
  - Public service accounts (allUsers / allAuthenticatedUsers bindings)
  - Service accounts with project-level admin rights

Queries discovery_findings for GCP IAM resources (service='iam' or
service='cloudresourcemanager') and check_findings for GCP IAM failures.
"""

import logging
from typing import Any, Dict, List

from .base import BaseIAMProvider, empty_result

logger = logging.getLogger(__name__)

# GCP primitive roles are overly broad
_PRIMITIVE_ROLES = {"roles/owner", "roles/editor"}

# Public principals that should never have roles
_PUBLIC_PRINCIPALS = {"allUsers", "allAuthenticatedUsers"}


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
        return result
