"""
FlagMapper — derives boolean threat-signal flags on Neo4j Resource nodes
from check_findings, driven by rule_metadata.threat_flags.

Runs as Step 3b, after MisconfigLoader and before PatternExecutor.

Design: FlagMapper is the CSP-agnostic translation layer.

Primary path (DB-driven):
    JOIN check_findings → rule_metadata ON rule_id.
    For each FAIL finding, read rule_metadata.threat_flags (JSONB array).
    Aggregate resource_uids per flag, then batch-SET on Neo4j.

Fallback path (keyword matching):
    For rules where threat_flags IS NULL or empty (not yet bootstrapped),
    fall back to the hardcoded keyword sets to derive flags.
    Run scripts/bootstrap_threat_flags.py --apply to eliminate the fallback.

Flags set here (from check_findings FAIL status):
  internet_exposed       — resource reachable from internet
  is_admin_role          — IAM principal with admin/privilege-escalation capability
  has_imdsv1             — EC2/VM with legacy metadata service (SSRF vector)
  has_no_mfa             — IAM user/principal without MFA
  has_stale_credentials  — access keys not rotated within policy window
  has_no_audit_trail     — CloudTrail/audit logging disabled or misconfigured
  has_no_rotation            — KMS key or secret with rotation disabled
  has_privileged_container   — K8s pod/container running with privileged mode or host namespace

Flags NOT set here (handled by other steps):
  has_critical_cve  — VulnLoader (Step 4)
  is_crown_jewel    — CrownJewelClassifier (Step 7)
  cdr_actor_seen    — CDRLoader (Step 5)

CP1-01: all Cypher via $parameter bindings.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Set

from neo4j import Driver

logger = logging.getLogger(__name__)

# ── Keyword fallback sets (used only when threat_flags is NULL/empty) ────────
# Primary source of truth is now rule_metadata.threat_flags.
# Run scripts/bootstrap_threat_flags.py --apply to populate it.

_INTERNET_EXPOSED_KEYWORDS = (
    "internet_ingress",
    "not_publicly_accessible",
    "url_public",
    "unrestricted_access",
    "publicly_accessible",
    "public_access_configured",
    "no_public_ip",
    "cifs_unrestricted",
    "master_nodes_no_public_ip",
    "internet_ingress_all_ports",
    "internet_ingress_high_risk",
    "public_network_access",
    "network_access_default_deny",
    "external_ip",
    "publicly_accessible_gcp",
    "internet_access_restricted",
)

_ADMIN_ROLE_KEYWORDS = (
    "admin_star",
    "privilege_escalation",
    "no_cluster_admin",
    "no_instance_profile_with_admin",
    "root_access",
    "full_admin",
    "no_admin_to_authenticated",
    "no_owner_subscription",
    "no_co_administrator",
    "no_primitive_role",
    "cluster_admin_binding",
)

_HAS_IMDSV1_KEYWORDS = (
    "imdsv2_enabled",
    "imds_v2_required",
    "metadata_service_v1",
)

_HAS_NO_MFA_KEYWORDS = (
    "mfa_enabled",
    "without_mfa",
    "mfa_not_enabled",
    "mfa_required",
    "mfa_configured",
    "two_factor",
    "two_step_verification",
    "multi_factor",
)

_HAS_STALE_CREDENTIALS_KEYWORDS = (
    "access_keys_rotated",
    "access_key_age",
    "key_rotation_90",
    "access_key_rotation",
    "credential_rotation",
    "key_expiry",
    "service_account_key_age",
)

_HAS_NO_AUDIT_TRAIL_KEYWORDS = (
    "cloudtrail",
    "audit_log_enabled",
    "audit_logging",
    "activity_log_enabled",
    "diagnostic_setting_enabled",
    "audit_log",
    "gcp_audit",
    "audit_enabled",
    "action_trail",
)

_HAS_NO_ROTATION_KEYWORDS = (
    "rotation_enabled",
    "key_rotation",
    "auto_rotation",
    "rotation_policy",
    "automatic_rotation",
)

_HAS_PRIVILEGED_CONTAINER_KEYWORDS = (
    "privileged_container",
    "privileged_pod",
    "hostpid",
    "host_pid",
    "privileged_contexts_denied",
    "no_privileged",
    "privileged_mode",
    "host_namespace",
)

_KEYWORD_MAP = {
    "internet_exposed":           _INTERNET_EXPOSED_KEYWORDS,
    "is_admin_role":              _ADMIN_ROLE_KEYWORDS,
    "has_imdsv1":                 _HAS_IMDSV1_KEYWORDS,
    "has_no_mfa":                 _HAS_NO_MFA_KEYWORDS,
    "has_stale_credentials":      _HAS_STALE_CREDENTIALS_KEYWORDS,
    "has_no_audit_trail":         _HAS_NO_AUDIT_TRAIL_KEYWORDS,
    "has_no_rotation":            _HAS_NO_ROTATION_KEYWORDS,
    "has_privileged_container":   _HAS_PRIVILEGED_CONTAINER_KEYWORDS,
}

ALL_FLAGS = list(_KEYWORD_MAP.keys())

# Resets all flags to false for the tenant+account before re-deriving them.
# Required so stale flags from prior runs don't persist when a rule is
# un-bootstrapped or a resource no longer has a FAIL finding.
_CLEAR_FLAGS_CYPHER = (
    "MATCH (r:Resource) "
    "WHERE r.tenant_id = $tid AND r.account_id = $account_id "
    "SET " + ", ".join(f"r.{f} = false" for f in _KEYWORD_MAP)
)


def _flags_from_keywords(rule_id: str) -> List[str]:
    """Keyword fallback: derive flags from rule_id substring matching."""
    rid = rule_id.lower()
    return [flag for flag, kws in _KEYWORD_MAP.items() if any(kw in rid for kw in kws)]


class FlagMapper:
    """Sets boolean threat-signal flags on Resource nodes from check_findings.

    Primary path: reads rule_metadata.threat_flags (DB-driven, CSP-agnostic).
    Fallback: keyword matching on rule_id (used while bootstrap is in progress).

    Resolution: some check rules report Security Group or IAM Role ARNs as
    resource_uid (e.g. internet_exposed SG rules, is_admin_role IAM rules).
    Those UIDs have no corresponding Neo4j Resource node since SGs and IAM
    policy ARNs are not inventoried as standalone nodes.  FlagMapper resolves
    them via inventory_relationships: set the flag on the parent resource that
    USES / ASSUMES the proxy resource.
    """

    # resource_uid fragments that indicate a "proxy" resource — not directly
    # a graph node.  For these we resolve via inventory_relationships.
    _SG_FRAGMENT  = ":security-group/"
    _IAM_FRAGMENT = ":iam::"

    def __init__(self, check_conn: Any, neo4j_driver: Driver, inv_conn: Any = None) -> None:
        self._check_conn = check_conn
        self._driver = neo4j_driver
        # Optional: inventory DB connection for proxy resolution.
        # Passed in by run_scan; None falls back to direct-UID only.
        self._inv_conn = inv_conn

    def map(
        self,
        tenant_id: str,
        account_id: str,
        scan_run_id: str,
    ) -> Dict[str, int]:
        """Derive and write boolean flags to Neo4j Resource nodes.

        Args:
            tenant_id:    Tenant scope — all writes are scoped by tenant.
            account_id:   Cloud account being scanned.
            scan_run_id:  The check scan whose findings drive flag derivation.

        Returns:
            Dict with per-flag counts of resources flagged.
        """
        db_flagged, fallback_count = self._fetch_db_driven(
            tenant_id, account_id, scan_run_id
        )

        if fallback_count > 0:
            logger.info(
                "FlagMapper: %d rules used keyword fallback (run "
                "bootstrap_threat_flags.py --apply to eliminate this)",
                fallback_count,
            )

        flag_sets: Dict[str, Set[str]] = {f: set() for f in ALL_FLAGS}
        for uid, flags in db_flagged:
            for flag in flags:
                if flag in flag_sets:
                    flag_sets[flag].add(uid)

        # Resolve proxy UIDs (Security Groups, IAM role ARNs) that have no
        # direct Neo4j node.  Replace them with the parent resource_uids that
        # USE / ASSUME them via inventory_relationships.
        if self._inv_conn is not None:
            self._resolve_proxy_uids(flag_sets, tenant_id, account_id)

        db = os.environ.get("NEO4J_DATABASE", "neo4j")
        with self._driver.session(database=db) as session:
            session.run(_CLEAR_FLAGS_CYPHER, tid=tenant_id, account_id=account_id)
            for flag, uids in flag_sets.items():
                _set_flag(session, uids, tenant_id, flag)

        result = {flag: len(uids) for flag, uids in flag_sets.items()}
        logger.info("FlagMapper complete: %s", result,
                    extra={"tenant_id": tenant_id, "scan_run_id": scan_run_id})
        return result

    def _resolve_proxy_uids(
        self,
        flag_sets: Dict[str, Set[str]],
        tenant_id: str,
        account_id: str,
    ) -> None:
        """Replace proxy resource UIDs with their parent resource UIDs.

        Security Group ARNs and IAM Role ARNs are not Neo4j Resource nodes.
        Walk inventory_relationships to find the EC2/Lambda/etc. resources
        that USE those SGs (relation_type='uses'/'attached_to') or ASSUME
        those IAM roles (relation_type='assumes'), and swap the proxy UID for
        the parent UID so the flag lands on a real graph node.
        """
        # Collect all proxy UIDs across all flags that need resolution
        sg_uids: Set[str] = set()
        iam_uids: Set[str] = set()
        for uids in flag_sets.values():
            for uid in list(uids):
                if self._SG_FRAGMENT in uid:
                    sg_uids.add(uid)
                elif self._IAM_FRAGMENT in uid and (":role/" in uid or ":policy/" in uid):
                    iam_uids.add(uid)

        if not sg_uids and not iam_uids:
            return

        cur = self._inv_conn.cursor()

        # SG → parent resources (uses, attached_to)
        sg_to_parents: Dict[str, List[str]] = {}
        if sg_uids:
            cur.execute(
                """
                SELECT to_uid AS proxy_uid, from_uid AS parent_uid
                FROM   inventory_relationships
                WHERE  tenant_id    = %s
                  AND  account_id   = %s
                  AND  relation_type IN ('uses', 'attached_to', 'secured_by')
                  AND  to_uid = ANY(%s)
                """,
                (tenant_id, account_id, list(sg_uids)),
            )
            for row in cur.fetchall():
                sg_to_parents.setdefault(row["proxy_uid"], []).append(row["parent_uid"])

        # IAM role → resources that assume it (assumes)
        iam_to_parents: Dict[str, List[str]] = {}
        if iam_uids:
            cur.execute(
                """
                SELECT to_uid AS proxy_uid, from_uid AS parent_uid
                FROM   inventory_relationships
                WHERE  tenant_id    = %s
                  AND  account_id   = %s
                  AND  relation_type = 'assumes'
                  AND  to_uid = ANY(%s)
                """,
                (tenant_id, account_id, list(iam_uids)),
            )
            for row in cur.fetchall():
                iam_to_parents.setdefault(row["proxy_uid"], []).append(row["parent_uid"])

        cur.close()
        proxy_map = {**sg_to_parents, **iam_to_parents}

        if not proxy_map:
            logger.debug("FlagMapper: no proxy→parent mappings found in inventory_relationships")
            return

        resolved = 0
        for flag, uids in flag_sets.items():
            proxy_hits = uids & set(proxy_map.keys())
            for proxy_uid in proxy_hits:
                uids.discard(proxy_uid)
                for parent_uid in proxy_map[proxy_uid]:
                    uids.add(parent_uid)
                    resolved += 1

        logger.info(
            "FlagMapper proxy resolution: %d proxy UIDs → %d parent resource UIDs",
            len(proxy_map), resolved,
            extra={"tenant_id": tenant_id},
        )

    def _fetch_db_driven(
        self,
        tenant_id: str,
        account_id: str,
        scan_run_id: str,
    ) -> tuple[List[tuple[str, List[str]]], int]:
        """Fetch FAIL findings joined with rule_metadata.threat_flags.

        Returns:
            (list of (resource_uid, flags), fallback_count)
            fallback_count — number of rules that fell back to keyword matching
        """
        cur = self._check_conn.cursor()
        cur.execute(
            """
            SELECT cf.resource_uid,
                   cf.rule_id,
                   rm.threat_flags
            FROM   check_findings cf
            LEFT JOIN rule_metadata rm USING (rule_id)
            WHERE  cf.tenant_id   = %s
              AND  cf.account_id  = %s
              AND  cf.scan_run_id = %s
              AND  cf.status      = 'FAIL'
            """,
            (tenant_id, account_id, scan_run_id),
        )
        rows = cur.fetchall()
        cur.close()

        result: List[tuple[str, List[str]]] = []
        fallback_count = 0

        for row in rows:
            resource_uid = row.get("resource_uid") or ""
            threat_flags = row.get("threat_flags")

            if not resource_uid:
                continue

            # DB-driven path only: JSONB auto-deserialized to Python list by psycopg2.
            # threat_flags = []  means "bootstrapped, no flags for this rule" → skip.
            # threat_flags = None should not occur (bootstrap sets [] as default) → skip.
            # Keyword fallback removed: it caused false positives (EKS/Cognito/CloudTrail
            # resources incorrectly getting is_admin_role) and masked bootstrap gaps.
            if threat_flags and isinstance(threat_flags, list):
                result.append((resource_uid, threat_flags))

        return result, fallback_count


def _set_flag(session: Any, uids: Set[str], tenant_id: str, flag: str) -> None:
    """Batch-set a boolean property on Resource nodes matching the uid set."""
    if not uids:
        return
    session.run(
        f"MATCH (r:Resource) "
        f"WHERE r.tenant_id = $tid AND r.resource_uid IN $uids "
        f"SET r.{flag} = true",
        tid=tenant_id,
        uids=list(uids),
    )
