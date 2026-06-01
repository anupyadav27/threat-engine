"""
Write IAM engine posture signals to resource_security_posture after scan.

Called at the end of run_scan.py after iam_findings are persisted.
Queries iam_policy_statements and iam_findings, aggregates per resource_uid,
then batch-upserts IAM-owned columns to resource_security_posture.

Column ownership (IAM engine writes ONLY these columns):
    has_attached_role, role_has_wildcard_policy, role_allows_cross_account,
    mfa_enforced, has_permission_boundary, is_admin_role, can_access_pii, iam_detail,
    has_priv_escalation_path, priv_escalation_hop_count, priv_escalation_cdr_confirmed
"""

from __future__ import annotations

import logging
from typing import Any

import psycopg2.extras

from engine_common.db_connections import get_iam_conn, get_di_conn
from engine_common.posture_writer import upsert_posture_signals

logger = logging.getLogger(__name__)

_BATCH_SIZE = 500


def write_iam_posture_signals(
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
) -> int:
    """Aggregate IAM signals from iam_findings/iam_policy_statements and upsert.

    Returns number of posture rows written.
    """
    try:
        signals_by_uid = _aggregate_iam_signals(scan_run_id, tenant_id)
        if not signals_by_uid:
            logger.info("IAM posture signals: no IAM findings for scan %s", scan_run_id)
            return 0

        inv_conn = get_di_conn()
        try:
            written = _batch_upsert(
                inv_conn, signals_by_uid,
                scan_run_id, tenant_id, account_id, provider,
            )
            logger.info("IAM posture signals: wrote %d rows for scan %s", written, scan_run_id)
            return written
        finally:
            inv_conn.close()

    except Exception as exc:
        logger.warning("IAM posture signal write failed (non-fatal): %s", exc, exc_info=True)
        return 0


def _aggregate_iam_signals(scan_run_id: str, tenant_id: str) -> dict[str, dict[str, Any]]:
    """Query iam_findings + iam_policy_statements for the scan and aggregate per resource."""
    iam_conn = get_iam_conn()
    signals: dict[str, dict[str, Any]] = {}

    try:
        with iam_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            # Pull per-resource summary from iam_findings
            cur.execute("""
                SELECT
                    resource_uid,
                    resource_type,
                    MAX(CASE WHEN (rule_id ILIKE '%%admin%%' OR rule_id ILIKE '%%privilege%%')
                             AND resource_type ILIKE '%%role%%' THEN 1 ELSE 0 END) = 1
                        AS is_admin_role,
                    MAX(CASE WHEN rule_id ILIKE '%%wildcard%%' AND status = 'FAIL' THEN 1 ELSE 0 END) = 1
                        AS role_has_wildcard_policy,
                    MAX(CASE WHEN rule_id ILIKE '%%cross_account%%' OR rule_id ILIKE '%%trust%%' THEN 1 ELSE 0 END) = 1
                        AS role_allows_cross_account,
                    MAX(CASE WHEN rule_id ILIKE '%%mfa%%' AND status = 'PASS' THEN 1 ELSE 0 END) = 1
                        AS mfa_enforced,
                    MAX(CASE WHEN rule_id ILIKE '%%permission_boundary%%' AND status = 'PASS' THEN 1 ELSE 0 END) = 1
                        AS has_permission_boundary,
                    MAX(CASE WHEN (rule_id ILIKE '%%s3%%' OR rule_id ILIKE '%%data%%' OR rule_id ILIKE '%%pii%%')
                             AND status = 'FAIL' THEN 1 ELSE 0 END) = 1
                        AS can_access_pii,
                    bool_or(TRUE) AS has_attached_role
                FROM iam_findings
                WHERE scan_run_id = %s AND tenant_id = %s AND resource_uid IS NOT NULL
                GROUP BY resource_uid, resource_type
            """, (scan_run_id, tenant_id))

            for row in cur.fetchall():
                uid = row["resource_uid"]
                signals[uid] = {
                    "resource_type": row.get("resource_type", "iam_resource"),
                    "has_attached_role": True,
                    "is_admin_role": bool(row["is_admin_role"]),
                    "role_has_wildcard_policy": bool(row["role_has_wildcard_policy"]),
                    "role_allows_cross_account": bool(row["role_allows_cross_account"]),
                    "mfa_enforced": bool(row["mfa_enforced"]),
                    "has_permission_boundary": bool(row["has_permission_boundary"]),
                    "can_access_pii": bool(row["can_access_pii"]),
                    "has_priv_escalation_path": False,
                    "priv_escalation_hop_count": 0,
                    "priv_escalation_cdr_confirmed": False,
                }

        # Detect privilege escalation paths from escalation_detector rule IDs.
        # Reads finding_data JSONB directly for precise hop_count and CDR confirmation.
        # Falls back to ILIKE pattern if the new rule IDs are not present.
        _ESCALATION_RULE_PREFIX = "aws.iam.role.privilege_escalation"
        try:
            with iam_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as _esc_cur:
                _esc_cur.execute("""
                    SELECT
                        resource_uid,
                        COUNT(*) AS escalation_count,
                        MIN((finding_data->>'hop_count')::int) AS min_hop_count,
                        bool_or(
                            (finding_data->>'cdr_active')::boolean IS TRUE
                            OR rule_id = 'aws.iam.role.privilege_escalation_cdr_confirmed'
                        ) AS cdr_confirmed
                    FROM iam_findings
                    WHERE scan_run_id = %s
                      AND tenant_id = %s
                      AND resource_uid IS NOT NULL
                      AND status = 'FAIL'
                      AND rule_id LIKE %s
                    GROUP BY resource_uid
                """, (scan_run_id, tenant_id, _ESCALATION_RULE_PREFIX + "%"))
                _esc_rows = _esc_cur.fetchall()

            if _esc_rows:
                for _row in _esc_rows:
                    _uid = _row["resource_uid"]
                    if _uid in signals:
                        signals[_uid]["has_priv_escalation_path"] = True
                        _hop = int(_row["min_hop_count"] or 1)
                        signals[_uid]["priv_escalation_hop_count"] = max(_hop, 1)
                        signals[_uid]["priv_escalation_cdr_confirmed"] = bool(
                            _row["cdr_confirmed"]
                )
            else:
                # Fallback: ILIKE scan for older/non-standard escalation rule IDs
                with iam_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as _fb_cur:
                    _fb_cur.execute("""
                        SELECT
                            resource_uid,
                            COUNT(*) FILTER (WHERE rule_id ILIKE '%%escalat%%' AND status = 'FAIL')
                                AS escalation_count,
                            COUNT(*) FILTER (WHERE (rule_id ILIKE '%%passrole%%'
                                OR rule_id ILIKE '%%pass_role%%'
                                OR rule_id ILIKE '%%assume%%')
                                AND status = 'FAIL')
                                AS hop_count
                        FROM iam_findings
                        WHERE scan_run_id = %s AND tenant_id = %s AND resource_uid IS NOT NULL
                        GROUP BY resource_uid
                        HAVING COUNT(*) FILTER (WHERE rule_id ILIKE '%%escalat%%'
                            OR rule_id ILIKE '%%passrole%%'
                            OR rule_id ILIKE '%%pass_role%%') > 0
                    """, (scan_run_id, tenant_id))
                    for _row in _fb_cur.fetchall():
                        _uid = _row["resource_uid"]
                        if _uid in signals:
                            _esc = int(_row["escalation_count"] or 0)
                            _hops = int(_row["hop_count"] or 0)
                            if _esc > 0:
                                signals[_uid]["has_priv_escalation_path"] = True
                                signals[_uid]["priv_escalation_hop_count"] = max(_hops, 1)
        except Exception as _esc_exc:
            logger.debug("Privilege escalation detection skipped: %s", _esc_exc)

        # Enrich from iam_policy_statements (more precise admin/wildcard signals + iam_detail)
        try:
            with iam_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT
                        resource_uid,
                        bool_or(is_admin) AS is_admin,
                        bool_or(is_wildcard_principal) AS is_wildcard_principal,
                        bool_or(is_cross_account) AS is_cross_account,
                        COUNT(*) AS policy_statement_count,
                        array_agg(DISTINCT policy_arn) FILTER (WHERE policy_arn IS NOT NULL)
                            AS policy_arns,
                        array_agg(DISTINCT attached_to_arn) FILTER (WHERE attached_to_arn IS NOT NULL)
                            AS role_arns
                    FROM iam_policy_statements
                    WHERE scan_run_id = %s AND tenant_id = %s AND resource_uid IS NOT NULL
                    GROUP BY resource_uid
                """, (scan_run_id, tenant_id))
                for row in cur.fetchall():
                    uid = row["resource_uid"]
                    if uid in signals:
                        signals[uid]["is_admin_role"] = signals[uid]["is_admin_role"] or bool(row["is_admin"])
                        signals[uid]["role_has_wildcard_policy"] = (
                            signals[uid]["role_has_wildcard_policy"] or bool(row["is_wildcard_principal"])
                        )
                        signals[uid]["role_allows_cross_account"] = (
                            signals[uid]["role_allows_cross_account"] or bool(row["is_cross_account"])
                        )
                        _role_arns = row["role_arns"] or []
                        _policy_arns = row["policy_arns"] or []
                        signals[uid]["iam_detail"] = {
                            "role_arns": _role_arns[:5],
                            "policy_arns": _policy_arns[:10],
                            "policy_statement_count": int(row["policy_statement_count"] or 0),
                            "is_admin": bool(row["is_admin"]),
                            "is_wildcard_principal": bool(row["is_wildcard_principal"]),
                            "is_cross_account": bool(row["is_cross_account"]),
                        }
        except Exception as stmt_exc:
            logger.debug("iam_policy_statements enrichment skipped: %s", stmt_exc)

        # Supplement: capture admin IAM roles that have no findings (bypass iam_findings gate).
        # A role may be fully compliant (zero violations) yet have is_admin=TRUE in its
        # policy statements — it would be invisible to the first iam_findings query above.
        # This block ensures those roles reach RSP with is_admin_role=TRUE and the correct
        # resource_type ('iam_role' / 'iam_user') so crown_jewel_classifier can find them.
        try:
            with iam_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT DISTINCT
                        attached_to_arn AS resource_uid,
                        attached_to_type,
                        bool_or(is_admin)             AS is_admin,
                        bool_or(is_wildcard_principal) AS is_wildcard,
                        bool_or(is_cross_account)      AS is_cross
                    FROM iam_policy_statements
                    WHERE scan_run_id = %s AND tenant_id = %s
                      AND attached_to_type IN ('role', 'user')
                      AND (is_admin = TRUE OR is_wildcard_principal = TRUE)
                      AND attached_to_arn IS NOT NULL
                    GROUP BY attached_to_arn, attached_to_type
                """, (scan_run_id, tenant_id))
                for row in cur.fetchall():
                    uid = row["resource_uid"]
                    if not uid:
                        continue
                    attached_type = row.get("attached_to_type") or "role"
                    rtype = "iam_role" if attached_type == "role" else "iam_user"
                    if uid in signals:
                        signals[uid]["is_admin_role"] = (
                            signals[uid].get("is_admin_role") or bool(row["is_admin"])
                        )
                        signals[uid]["role_has_wildcard_policy"] = (
                            signals[uid].get("role_has_wildcard_policy") or bool(row["is_wildcard"])
                        )
                        signals[uid]["resource_type"] = rtype
                    else:
                        signals[uid] = {
                            "resource_type": rtype,
                            "has_attached_role": True,
                            "is_admin_role": bool(row["is_admin"]),
                            "role_has_wildcard_policy": bool(row["is_wildcard"]),
                            "role_allows_cross_account": bool(row["is_cross"]),
                            "mfa_enforced": False,
                            "has_permission_boundary": False,
                            "can_access_pii": False,
                            "has_priv_escalation_path": False,
                            "priv_escalation_hop_count": 0,
                            "priv_escalation_cdr_confirmed": False,
                            "iam_detail": {
                                "is_admin": bool(row["is_admin"]),
                                "is_wildcard_principal": bool(row["is_wildcard"]),
                                "is_cross_account": bool(row["is_cross"]),
                                "policy_statement_count": 0,
                                "role_arns": [],
                                "policy_arns": [],
                            },
                        }
        except Exception as admin_exc:
            logger.debug("Admin role supplementary query skipped: %s", admin_exc)

    finally:
        iam_conn.close()

    # Direct admin role detection from asset_inventory.
    # When iam_policy_statements lacks managed policy data (DI scan timed out on
    # get_account_authorization_details), detect admin roles directly by checking
    # AttachedManagedPolicies and inline RolePolicyList from the latest available
    # tenant-level asset_inventory data.
    _detect_admin_roles_from_inventory(signals, tenant_id)

    # Ensure every uid has at least a minimal iam_detail from collected boolean signals.
    # This runs when iam_policy_statements is empty or has no overlapping UIDs.
    for uid, sig in signals.items():
        if "iam_detail" not in sig:
            sig["iam_detail"] = {
                "is_admin": sig.get("is_admin_role", False),
                "is_wildcard_principal": sig.get("role_has_wildcard_policy", False),
                "is_cross_account": sig.get("role_allows_cross_account", False),
                "policy_statement_count": 0,
                "role_arns": [],
                "policy_arns": [],
            }

    return signals


# Known AWS-managed admin policy names / ARN suffixes.
_ADMIN_POLICY_NAMES = frozenset([
    "AdministratorAccess",
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "AdministratorAccess-Amplify",
    "AdministratorAccess-Amplify",
    "PowerUserAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
    "AWSOrganizationsFullAccess",
    "arn:aws:iam::aws:policy/AWSOrganizationsFullAccess",
    "IAMFullAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
])


def _detect_admin_roles_from_inventory(
    signals: dict[str, dict[str, Any]],
    tenant_id: str,
) -> None:
    """Detect admin IAM roles from asset_inventory when iam_policy_statements is incomplete.

    Uses the latest available get_account_authorization_details_roles data for the
    tenant (not scan_run_id scoped) to find roles with AdministratorAccess or inline
    Action:* + Resource:* policies.  Writes is_admin_role=TRUE into signals.
    """
    try:
        inv_conn = get_di_conn()
        try:
            with inv_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT DISTINCT ON (resource_uid)
                        resource_uid, emitted_fields
                    FROM asset_inventory
                    WHERE tenant_id = %s
                      AND discovery_id = 'aws.iam.get_account_authorization_details_roles'
                    ORDER BY resource_uid, last_seen_at DESC
                """, (tenant_id,))
                rows = cur.fetchall()

            admin_count = 0
            for row in rows:
                uid = row["resource_uid"]
                if not uid:
                    continue
                ef = row["emitted_fields"] or {}
                attached = ef.get("AttachedManagedPolicies") or []
                inline = ef.get("RolePolicyList") or []

                is_admin = False
                # SSO reserved roles: AWSReservedSSO_AdministratorAccess_* are always admin.
                role_name = ef.get("RoleName") or uid.split("/")[-1]
                if "AdministratorAccess" in role_name or "OrganizationsAccountAccessRole" in role_name:
                    is_admin = True

                # Check attached managed policies by name / ARN
                if not is_admin:
                    for pol in attached:
                        if not isinstance(pol, dict):
                            continue
                        pname = pol.get("PolicyName") or ""
                        parn = pol.get("PolicyArn") or ""
                        if pname in _ADMIN_POLICY_NAMES or parn in _ADMIN_POLICY_NAMES:
                            is_admin = True
                            break

                # Check inline policies for Action:* + Resource:*
                if not is_admin:
                    for ipol in inline:
                        if not isinstance(ipol, dict):
                            continue
                        doc = ipol.get("PolicyDocument")
                        if not isinstance(doc, dict):
                            continue
                        for stmt in (doc.get("Statement") or []):
                            if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
                                continue
                            actions = stmt.get("Action", [])
                            resources = stmt.get("Resource", [])
                            if isinstance(actions, str):
                                actions = [actions]
                            if isinstance(resources, str):
                                resources = [resources]
                            if "*" in actions and "*" in resources:
                                is_admin = True
                                break
                        if is_admin:
                            break

                if not is_admin:
                    continue

                admin_count += 1
                if uid in signals:
                    signals[uid]["is_admin_role"] = True
                    signals[uid]["role_has_wildcard_policy"] = True
                    signals[uid]["resource_type"] = "iam_role"
                else:
                    signals[uid] = {
                        "resource_type": "iam_role",
                        "has_attached_role": True,
                        "is_admin_role": True,
                        "role_has_wildcard_policy": True,
                        "role_allows_cross_account": False,
                        "mfa_enforced": False,
                        "has_permission_boundary": False,
                        "can_access_pii": True,
                        "has_priv_escalation_path": False,
                        "priv_escalation_hop_count": 0,
                        "priv_escalation_cdr_confirmed": False,
                        "iam_detail": {
                            "is_admin": True,
                            "is_wildcard_principal": False,
                            "is_cross_account": False,
                            "policy_statement_count": 0,
                            "role_arns": [uid],
                            "policy_arns": [],
                        },
                    }
            if admin_count:
                logger.info(
                    "IAM posture signals: detected %d admin roles from asset_inventory", admin_count
                )
        finally:
            inv_conn.close()

    except Exception as exc:
        logger.debug("Admin role detection from inventory skipped: %s", exc)


def _batch_upsert(
    inv_conn: Any,
    signals_by_uid: dict[str, dict[str, Any]],
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
) -> int:
    """Upsert signals in batches of _BATCH_SIZE. Returns total rows written."""
    uids = list(signals_by_uid.keys())
    written = 0

    for i in range(0, len(uids), _BATCH_SIZE):
        batch = uids[i : i + _BATCH_SIZE]
        for uid in batch:
            sig = signals_by_uid[uid]
            resource_type = sig.pop("resource_type", "iam_resource")
            upsert_posture_signals(
                inv_conn,
                resource_uid=uid,
                scan_run_id=scan_run_id,
                tenant_id=tenant_id,
                account_id=account_id,
                provider=provider,
                resource_type=resource_type,
                **sig,
            )
            written += 1

    return written
