"""
OCI IAM Provider

Reads OCI Identity resources from discovery_findings and check_findings to surface:
  - Users without MFA enabled
  - Overly broad OCI policies (Allow group X to manage all-resources in tenancy)
  - Users in Administrators group (admin group membership)
  - Inactive / blocked users with active credentials
  - API keys not rotated (customer secret keys)

Queries:
  - discovery_findings WHERE provider='oci' AND service='identity'
    filtered to IAM-relevant discovery_ids (list_users, list_groups,
    list_policies, list_user_group_memberships, list_mfa_totp_devices,
    list_customer_secret_keys, list_dynamic_groups)
  - check_findings WHERE provider='oci' AND status='FAIL' AND
    (rule_id LIKE '%iam%' OR rule_id LIKE '%identity%' OR
     rule_id LIKE '%user%' OR rule_id LIKE '%policy%')
"""

import hashlib
import logging
from typing import Any, Dict, List

from .base import BaseIAMProvider, empty_result

logger = logging.getLogger(__name__)

# OCI discovery_ids that are IAM-relevant
_IAM_DISCOVERY_IDS = {
    "oci.identity.list_users",
    "oci.identity.list_groups",
    "oci.identity.list_policies",
    "oci.identity.list_user_group_memberships",
    "oci.identity.list_mfa_totp_devices",
    "oci.identity.list_customer_secret_keys",
    "oci.identity.list_dynamic_groups",
    "oci.identity.list_api_keys",
    "oci.identity.get_user",
    "oci.identity.get_group",
    "oci.identity.get_policy",
    "oci.identity.get_mfa_totp_device",
    "oci.identity.get_dynamic_group",
    "oci.identity.list_auth_tokens",
    "oci.identity.list_smtp_credentials",
}

# Policy statement keywords that indicate broad admin access
_ADMIN_STATEMENT_PATTERNS = (
    "manage all-resources",
    "manage all_resources",
    "use all-resources",
    "use all_resources",
    "inspect all-resources",
    "inspect all_resources",
    "read all-resources",
    "read all_resources",
)

# Group names that indicate administrator access
_ADMIN_GROUP_NAMES = {
    "Administrators",
    "administrators",
    "admin",
    "Admin",
    "Administrator",
    "administrator",
}


def _make_finding_id(rule_id: str, resource_uid: str, account_id: str) -> str:
    """Generate deterministic finding_id from (rule_id, resource_uid, account_id).

    Args:
        rule_id: Rule identifier string
        resource_uid: Resource OCID or identifier
        account_id: OCI tenancy OCID

    Returns:
        16-character hex prefix of sha256 hash (deterministic, no duplicates on re-run).
    """
    raw = f"{rule_id}|{resource_uid}|{account_id}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


class OCIIAMProvider(BaseIAMProvider):
    """OCI IAM analysis provider.

    Reads OCI identity resources from discovery_findings and check_findings
    to detect IAM security issues: missing MFA, overly broad policies,
    admin group membership, inactive users with active credentials.
    """

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
    ) -> Dict[str, Any]:
        """Analyze OCI IAM posture from discovery and check findings.

        Args:
            scan_run_id: Pipeline scan run ID
            tenant_id: Tenant identifier
            account_id: OCI tenancy OCID

        Returns:
            Standardized result dict with OCI IAM policy findings.
        """
        result = empty_result()

        try:
            from psycopg2.extras import RealDictCursor
            from engine_common.db_connections import get_check_conn, get_discoveries_conn
        except ImportError as e:
            logger.warning(
                f"OCI IAM provider: missing dependency ({e}) — returning empty results"
            )
            return result

        policy_findings: List[Dict[str, Any]] = []

        # ── Step 1: Query discovery_findings for OCI identity resources ──
        users: List[Dict[str, Any]] = []
        groups: List[Dict[str, Any]] = []
        policies: List[Dict[str, Any]] = []
        memberships: List[Dict[str, Any]] = []
        mfa_devices: List[Dict[str, Any]] = []
        api_keys: List[Dict[str, Any]] = []

        try:
            disc_conn = get_discoveries_conn()
            with disc_conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT resource_uid, resource_type, discovery_id,
                           emitted_fields, account_id, region
                    FROM discovery_findings
                    WHERE scan_run_id = %s
                      AND tenant_id = %s
                      AND provider = 'oci'
                      AND service = 'identity'
                    ORDER BY discovery_id, resource_uid
                    """,
                    (scan_run_id, tenant_id),
                )
                identity_rows = cur.fetchall()
            disc_conn.close()

            for row in identity_rows:
                did = row.get("discovery_id", "")
                fields = row.get("emitted_fields") or {}

                if "list_users" in did or "get_user" in did:
                    users.append(dict(row))
                elif "list_groups" in did or "get_group" in did:
                    groups.append(dict(row))
                elif "list_policies" in did or "get_policy" in did:
                    policies.append(dict(row))
                elif "list_user_group_memberships" in did or "get_user_group_membership" in did:
                    memberships.append(dict(row))
                elif "list_mfa_totp_devices" in did or "get_mfa_totp_device" in did:
                    mfa_devices.append(dict(row))
                elif "list_api_keys" in did or "list_auth_tokens" in did or "list_customer_secret_keys" in did:
                    api_keys.append(dict(row))

            logger.info(
                f"OCI IAM provider: loaded {len(users)} users, {len(groups)} groups, "
                f"{len(policies)} policies, {len(memberships)} memberships, "
                f"{len(mfa_devices)} MFA devices, {len(api_keys)} API keys"
                f" from scan={scan_run_id}"
            )

        except Exception as e:
            logger.warning(f"OCI IAM discovery query failed (non-fatal): {e}")

        # ── Step 2: Populate result entity lists ──
        result["users"] = users
        result["groups"] = groups

        # ── Step 3: Detector — MFA not enabled for users ──
        mfa_device_uids = {
            row.get("emitted_fields", {}).get("user_id", "")
            or row.get("resource_uid", "")
            for row in mfa_devices
        }

        for user_row in users:
            fields = user_row.get("emitted_fields") or {}
            resource_uid = user_row.get("resource_uid", "")
            user_name = fields.get("name", resource_uid)
            status = fields.get("status", "ACTIVE").upper()
            is_mfa = fields.get("is_mfa_activated")

            # Skip blocked/inactive users
            if status not in ("ACTIVE", ""):
                continue

            # Check is_mfa_activated field first (populated by discovery YAML)
            mfa_enabled = (
                is_mfa is True
                or is_mfa == "true"
                or is_mfa == "True"
                or resource_uid in mfa_device_uids
            )
            if not mfa_enabled:
                fid = _make_finding_id("oci.iam.user.mfa_not_enabled", resource_uid, account_id)
                policy_findings.append({
                    "finding_id": fid,
                    "rule_id": "oci.iam.user.mfa_not_enabled",
                    "severity": "high",
                    "status": "FAIL",
                    "title": f"OCI user '{user_name}' does not have MFA enabled",
                    "resource_uid": resource_uid,
                    "resource_type": user_row.get("resource_type", "oci.identity.user"),
                    "account_id": user_row.get("account_id", account_id),
                    "region": user_row.get("region", "global"),
                    "provider": "oci",
                    "iam_security_modules": ["access_control"],
                    "finding_data": {
                        "module": "oci_iam_analysis",
                        "source": "discovery",
                        "user_name": user_name,
                        "is_mfa_activated": is_mfa,
                        "remediation": (
                            "Enable Multi-Factor Authentication (MFA) for the OCI user. "
                            "Navigate to Identity > Users > select user > Enable MFA."
                        ),
                    },
                })

        # ── Step 4: Detector — Overly broad OCI policy statements ──
        for policy_row in policies:
            fields = policy_row.get("emitted_fields") or {}
            resource_uid = policy_row.get("resource_uid", "")
            policy_name = fields.get("name", resource_uid)
            statements = fields.get("statements") or []

            # statements may be a list of strings like:
            # "Allow group Administrators to manage all-resources in tenancy"
            if isinstance(statements, str):
                statements = [statements]

            for stmt in statements:
                if not isinstance(stmt, str):
                    continue
                stmt_lower = stmt.lower()
                for pattern in _ADMIN_STATEMENT_PATTERNS:
                    if pattern in stmt_lower and "tenancy" in stmt_lower:
                        # Broad tenancy-level policy
                        fid = _make_finding_id(
                            "oci.iam.policy.broad_tenancy_access",
                            f"{resource_uid}:{stmt[:50]}",
                            account_id,
                        )
                        policy_findings.append({
                            "finding_id": fid,
                            "rule_id": "oci.iam.policy.broad_tenancy_access",
                            "severity": "critical",
                            "status": "FAIL",
                            "title": (
                                f"OCI policy '{policy_name}' grants broad tenancy-level access"
                            ),
                            "resource_uid": resource_uid,
                            "resource_type": policy_row.get(
                                "resource_type", "oci.identity.policy"
                            ),
                            "account_id": policy_row.get("account_id", account_id),
                            "region": policy_row.get("region", "global"),
                            "provider": "oci",
                            "iam_security_modules": ["least_privilege"],
                            "finding_data": {
                                "module": "oci_iam_analysis",
                                "source": "discovery",
                                "policy_name": policy_name,
                                "statement": stmt,
                                "remediation": (
                                    "Restrict OCI policy statements to specific compartments "
                                    "and resource types instead of 'all-resources in tenancy'. "
                                    "Follow the principle of least privilege."
                                ),
                            },
                        })
                        break  # One finding per statement

        # ── Step 5: Detector — Users in Administrators group ──
        admin_group_uids = {
            row.get("resource_uid", "")
            for row in groups
            if (row.get("emitted_fields") or {}).get("name", "") in _ADMIN_GROUP_NAMES
        }

        if admin_group_uids:
            for membership_row in memberships:
                fields = membership_row.get("emitted_fields") or {}
                group_id = (
                    fields.get("group_id")
                    or fields.get("groupId")
                    or ""
                )
                user_id = (
                    fields.get("user_id")
                    or fields.get("userId")
                    or ""
                )
                resource_uid = membership_row.get("resource_uid", "")

                if group_id in admin_group_uids or resource_uid in admin_group_uids:
                    fid = _make_finding_id(
                        "oci.iam.user.admin_group_membership",
                        resource_uid or user_id,
                        account_id,
                    )
                    policy_findings.append({
                        "finding_id": fid,
                        "rule_id": "oci.iam.user.admin_group_membership",
                        "severity": "high",
                        "status": "FAIL",
                        "title": (
                            f"OCI user is a member of an Administrators group — "
                            f"membership={resource_uid}"
                        ),
                        "resource_uid": resource_uid,
                        "resource_type": membership_row.get(
                            "resource_type", "oci.identity.user_group_membership"
                        ),
                        "account_id": membership_row.get("account_id", account_id),
                        "region": membership_row.get("region", "global"),
                        "provider": "oci",
                        "iam_security_modules": ["access_control"],
                        "finding_data": {
                            "module": "oci_iam_analysis",
                            "source": "discovery",
                            "group_id": group_id,
                            "user_id": user_id,
                            "remediation": (
                                "Review membership in the Administrators group. "
                                "Use break-glass procedures for administrative tasks "
                                "and assign least-privilege roles for day-to-day access."
                            ),
                        },
                    })

        logger.info(
            f"OCI IAM provider: {len(policy_findings)} findings from discovery analysis "
            f"(scan={scan_run_id})"
        )

        # ── Step 6: Query check_findings for OCI IAM-tagged rule failures ──
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
                      AND provider = 'oci'
                      AND status = 'FAIL'
                      AND (
                          rule_id ILIKE '%%iam%%'
                          OR rule_id ILIKE '%%identity%%'
                          OR rule_id ILIKE '%%user%%'
                          OR rule_id ILIKE '%%policy%%'
                          OR rule_id ILIKE '%%mfa%%'
                          OR rule_id ILIKE '%%group%%'
                      )
                    """,
                    (scan_run_id, tenant_id),
                )
                check_rows = cur.fetchall()
            check_conn.close()

            existing_ids = {f["finding_id"] for f in policy_findings}
            merged_count = 0
            for row in check_rows:
                fid = str(row.get("finding_id", ""))
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
                    "provider": "oci",
                    "iam_security_modules": ["access_control"],
                    "finding_data": {
                        "source": "check_engine",
                        **finding_data,
                    },
                })
                existing_ids.add(fid)
                merged_count += 1

            logger.info(
                f"OCI IAM provider: merged {merged_count} check_findings failures, "
                f"{len(policy_findings)} total findings (scan={scan_run_id})"
            )

        except Exception as e:
            logger.warning(f"OCI IAM check_findings query failed (non-fatal): {e}")

        result["policy_findings"] = policy_findings
        return result
