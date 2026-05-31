"""
Attack Path Engine — Scan Orchestrator.

Pipeline stage 6.5 — runs AFTER graph-build, BEFORE risk.

Orchestration order:
  1.   CrownJewelClassifier.classify()
  2a-pre. _mark_internet_exposed_from_discoveries() — write is_internet_exposed to posture
  2a.  Fetch internet-exposed UIDs from resource_security_posture
  2b.  PostgreSQL BFS (pg_graph) — primary path computation, no Neo4j required
  2c.  Neo4j BFS (fallback) — runs if pg_graph returns 0 paths and Neo4j available
  3.   Fetch posture_lookup from resource_security_posture
  3b.  Fetch security_findings_lookup
  4.   scorer.score_paths() (probability_score + impact_score per path)
  4b.  attack_vector.classify_attack_vector() — MITRE ATT&CK T1/T2/T3 + confidence per path
  4c.  path_explainer.explain_path() — Orca-style narrative for top-50 paths
  5.   deduplicator.deduplicate()
  6.   choke_point_detector.detect_choke_points()
  7.   writer.write_paths() + write_path_nodes() + write_history()
  8.   posture_updater.update_attack_path_signals()
  8b.  Cross-engine composite flags
  9.   Threat pattern enrichment (optional — skipped if threat_scenario_incidents missing)

Neo4j role: visualization/UI graph rendering only — no longer needed for path computation.

Security notes:
  - No DEV_BYPASS_AUTH anywhere in this file.
  - scan_run_id and tenant_id validated before processing.
  - All DB writes scoped by tenant_id from scan_runs table.
"""

from __future__ import annotations

import logging
import os
import sys
import time
from typing import Any, Dict

import psycopg2.extras

logger = logging.getLogger("attack-path.run_scan")

# Structured JSON log helper
def _jlog(event: str, **kwargs: Any) -> None:
    parts = [f'"engine":"attack-path"', f'"event":"{event}"']
    for k, v in kwargs.items():
        if isinstance(v, str):
            parts.append(f'"{k}":"{v}"')
        else:
            parts.append(f'"{k}":{v}')
    logger.info("{%s}", ", ".join(parts))


def _mark_internet_exposed_from_discoveries(
    inventory_conn: Any,
    tenant_id: str,
    scan_run_id: str,
) -> int:
    """Mark is_internet_exposed=true in resource_security_posture.

    Primary path: reads resource_uids from network_exposure_findings (written by IEDS
    Phase L0 in the network engine — covers all CSPs, all exposure tiers via YAML rules).

    Fallback path: if IEDS wrote 0 rows (network engine not yet run or failed), falls
    back to raw emitted_fields pattern-matching on asset_inventory / discovery_findings.

    Only asserts true — never sets false. Returns count of resources marked.
    """
    import os as _os

    try:
        inventory_conn.rollback()
    except Exception:
        pass

    total_marked = 0

    # --- Primary path: read from IEDS network_exposure_findings ---
    ieds_uids: list = []
    try:
        from engine_common.db_connections import get_network_conn
        net_conn = get_network_conn()
        try:
            with net_conn.cursor() as cur:
                cur.execute("""
                    SELECT DISTINCT resource_uid
                    FROM   network_exposure_findings
                    WHERE  tenant_id   = %s
                      AND  scan_run_id = %s
                      AND  status      = 'OPEN'
                      AND  origin_type = 'internet'
                      AND  resource_uid IS NOT NULL
                """, (tenant_id, scan_run_id))
                ieds_uids = [row[0] for row in cur.fetchall()]
        finally:
            net_conn.close()
        logger.info(
            "IEDS primary: %d internet-exposed UIDs from network_exposure_findings (scan=%s)",
            len(ieds_uids), scan_run_id,
        )
    except Exception as _ieds_err:
        logger.debug("IEDS primary path unavailable: %s", _ieds_err)

    exposed_uids = list(ieds_uids)

    # --- Fallback: emitted_fields pattern scan (kept when IEDS wrote 0 rows) ---
    if not exposed_uids:
        logger.info("IEDS fallback: reading emitted_fields patterns (scan=%s)", scan_run_id)
        _di_enabled = _os.getenv("DI_ENGINE_ENABLED", "false").lower() == "true"
        try:
            if _di_enabled:
                from engine_common.db_connections import get_di_conn
                src_conn = get_di_conn()
                table = "asset_inventory"
            else:
                from engine_common.db_connections import get_discoveries_conn
                src_conn = get_discoveries_conn()
                table = "discovery_findings"

            try:
                with src_conn.cursor() as cur:
                    cur.execute(
                        f"""
                        SELECT DISTINCT resource_uid
                        FROM {table}
                        WHERE tenant_id    = %s
                          AND resource_uid IS NOT NULL
                          AND resource_uid != ''
                          AND (
                            -- EC2 public IP: instances only, not image/status sub-resources
                            ((emitted_fields->>'PublicIpAddress') IS NOT NULL
                             AND resource_type = 'ec2_instance')
                            -- RDS/cache publicly accessible: DB instances only
                            OR ((emitted_fields->>'PubliclyAccessible') = 'true'
                                AND resource_type IN (
                                  'rds_db_instance', 'elasticache_cluster',
                                  'elasticache_replication_group', 'redshift_cluster',
                                  'opensearch_domain', 'opensearch_domain_config'
                                ))
                            -- ELB internet-facing scheme: load balancers only
                            OR ((emitted_fields->>'Scheme') = 'internet-facing'
                                AND resource_type = 'elbv2_load_balancer')
                            -- Lambda function URL: function level only, not config/concurrency sub-resources
                            OR ((emitted_fields->>'FunctionUrl') IS NOT NULL
                                AND resource_type = 'lambda_function')
                            -- API Gateway / CloudFront: always internet entry points
                            OR resource_type IN (
                              'apigateway.restapi',
                              'apigateway.httpapi',
                              'apigateway.v2api',
                              'apigatewayv2.api',
                              'apigatewayv2_api',
                              'cloudfront_distribution'
                            )
                          )
                        """,
                        (tenant_id,),
                    )
                    exposed_uids = [row[0] for row in cur.fetchall()]
            finally:
                src_conn.close()
        except Exception as _fb_err:
            logger.warning("Fallback emitted_fields scan failed: %s", _fb_err)

    if not exposed_uids:
        logger.info("No internet-exposed resources for tenant=%s scan=%s", tenant_id, scan_run_id)
        return 0

    try:
        with inventory_conn.cursor() as cur:
            cur.execute(
                """
                UPDATE resource_security_posture
                SET is_internet_exposed = true,
                    updated_at          = NOW()
                WHERE tenant_id  = %s
                  AND resource_uid = ANY(%s)
                """,
                (tenant_id, exposed_uids),
            )
            total_marked = cur.rowcount
        # Commit immediately — this UPDATE must persist even when BFS finds 0 paths.
        inventory_conn.commit()
        logger.info(
            "Marked %d resources is_internet_exposed=true (from %d candidates) tenant=%s",
            total_marked, len(exposed_uids), tenant_id,
        )
        return total_marked

    except Exception as exc:
        logger.warning("Could not mark internet_exposed (non-fatal): %s", exc)
        try:
            inventory_conn.rollback()
        except Exception:
            pass
        return 0



def _fetch_attack_entry_uids(
    di_conn: Any,
    tenant_id: str,
) -> Dict[str, str]:
    """Return {resource_uid: attack_entry_point_category} for ALL attack entry points.

    Merges three sources in priority order:
      1. resource_security_posture WHERE is_attack_entry_point=TRUE (explicit category set by engine)
      2. resource_security_posture WHERE is_internet_exposed=TRUE (legacy signal → INTERNET_ENTRY)
      3. asset_relationships internet edges (covers resources without posture rows yet)

    Returns:
        Dict[uid → category] where category is one of:
        INTERNET_ENTRY | IDENTITY_ENTRY | CICD_ENTRY | THIRD_PARTY_ENTRY |
        INTERNAL_WORKLOAD_ENTRY | ENDPOINT_AGENT_ENTRY
    """
    entry_map: Dict[str, str] = {}
    try:
        with di_conn.cursor() as cur:
            # Source 1: explicit attack entry points with category
            cur.execute(
                """
                SELECT resource_uid,
                       COALESCE(attack_entry_point_category, 'INTERNET_ENTRY') AS category
                FROM resource_security_posture
                WHERE tenant_id = %s
                  AND is_attack_entry_point = TRUE
                  AND resource_uid IS NOT NULL
                """,
                (tenant_id,),
            )
            for uid, cat in cur.fetchall():
                entry_map[uid] = cat

            # Source 2: is_internet_exposed=TRUE (legacy signal; setdefault so explicit wins)
            cur.execute(
                """
                SELECT DISTINCT resource_uid
                FROM resource_security_posture
                WHERE tenant_id = %s
                  AND is_internet_exposed = TRUE
                  AND resource_uid IS NOT NULL
                """,
                (tenant_id,),
            )
            for (uid,) in cur.fetchall():
                entry_map.setdefault(uid, "INTERNET_ENTRY")

            # Source 3: internet relationship edges (covers missing posture rows)
            cur.execute(
                """
                SELECT DISTINCT source_uid
                FROM asset_relationships
                WHERE tenant_id = %s
                  AND LOWER(relation_type) IN ('internet_connected', 'internet_accessible')
                  AND source_uid IS NOT NULL
                  AND source_uid NOT LIKE 'internet:%%'
                  AND source_uid NOT LIKE 'pseudo:%%'
                """,
                (tenant_id,),
            )
            for (uid,) in cur.fetchall():
                entry_map.setdefault(uid, "INTERNET_ENTRY")

    except Exception as exc:
        logger.warning("Could not fetch attack entry UIDs (falling back to empty set): %s", exc)
        try:
            di_conn.rollback()
        except Exception:
            pass

    return entry_map


# CICD OIDC providers whose presence in a trust policy marks the role as a CI/CD entry point
_CICD_OIDC_PROVIDERS = (
    "token.actions.githubusercontent.com",  # GitHub Actions
    "gitlab.com",
    "circleci.com",
    "app.terraform.io",
    "jenkins.io",
    "bitbucket.org",
)


def _mark_non_internet_entry_points(
    di_conn: Any,
    tenant_id: str,
) -> Dict[str, int]:
    """Detect and mark non-internet attack entry points in resource_security_posture.

    Categories marked:
      IDENTITY_ENTRY     — IAM users without MFA (credential compromise attack surface)
      CICD_ENTRY         — Roles with OIDC trust to external CI/CD providers
      THIRD_PARTY_ENTRY  — Cross-account roles assumable by external AWS accounts
      ENDPOINT_AGENT_ENTRY — EC2 instances with SSM agent (remote shell via StartSession)
      INTERNAL_WORKLOAD_ENTRY — Pods/workloads with privileged container security violations

    Only marks; never unmarks. Non-fatal per category — one failure doesn't block others.

    Returns:
        Dict[category → count_marked]
    """
    counts: Dict[str, int] = {}

    # ── IDENTITY_ENTRY: identity principals without MFA (multi-CSP) ───────────
    # Covers AWS IAM users, Azure AD/Entra users, GCP service accounts, OCI IAM users.
    # IAM engine sets mfa_enforced only on identity-type resources; resource_type
    # patterns guard against non-identity rows that may inadvertently carry the field.
    try:
        with di_conn.cursor() as cur:
            cur.execute(
                """
                SELECT resource_uid
                FROM resource_security_posture
                WHERE tenant_id    = %s
                  AND mfa_enforced  = FALSE
                  AND resource_uid IS NOT NULL
                  AND NOT COALESCE(is_attack_entry_point, FALSE)
                  AND (
                        resource_type ILIKE '%%iam%%user%%'          -- AWS / GCP IAM user
                     OR resource_type ILIKE 'identity.user%%'        -- OCI identity.user
                     OR resource_type ILIKE '%%directory%%user%%'    -- Azure AD user
                     OR resource_type ILIKE '%%graph%%user%%'        -- Azure MS Graph user
                     OR resource_type ILIKE '%%entra%%user%%'        -- Azure Entra ID user
                     OR resource_type ILIKE '%%service_account%%'    -- GCP service account
                  )
                """,
                (tenant_id,),
            )
            iam_user_uids = [row[0] for row in cur.fetchall()]

        if iam_user_uids:
            with di_conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE resource_security_posture
                    SET is_attack_entry_point       = TRUE,
                        attack_entry_point_category = 'IDENTITY_ENTRY',
                        updated_at                  = NOW()
                    WHERE tenant_id    = %s
                      AND resource_uid = ANY(%s)
                    """,
                    (tenant_id, iam_user_uids),
                )
                counts["IDENTITY_ENTRY"] = cur.rowcount
            di_conn.commit()
    except Exception as exc:
        logger.debug("IDENTITY_ENTRY marking failed (non-fatal): %s", exc)
        try:
            di_conn.rollback()
        except Exception:
            pass

    # ── CICD_ENTRY / THIRD_PARTY_ENTRY: IAM role trust policies ───────────
    # Currently AWS-only: reads iam_policy_statements (written by the IAM engine
    # for AWS IAM roles). Azure Managed Identity federation and GCP Workload Identity
    # Federation are not yet captured in a shared table — extend the IAM engine to
    # write their trust configurations when those CSPs are fully supported.
    try:
        from engine_common.db_connections import get_iam_conn
        iam_conn = get_iam_conn()
        cicd_uids: list = []
        third_party_uids: list = []
        try:
            with iam_conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT DISTINCT attached_to_arn, principal_arn
                    FROM iam_policy_statements
                    WHERE tenant_id      = %s
                      AND effect         = 'Allow'
                      AND attached_to_arn IS NOT NULL
                      AND principal_arn   IS NOT NULL
                    """,
                    (tenant_id,),
                )
                for role_arn, principal_arn in cur.fetchall():
                    p_lower = (principal_arn or "").lower()
                    # CICD: trust to external OIDC providers
                    if any(provider in p_lower for provider in _CICD_OIDC_PROVIDERS):
                        cicd_uids.append(role_arn)
                    # THIRD_PARTY: cross-account AssumeRole (different AWS account)
                    elif principal_arn.startswith("arn:aws:iam:"):
                        role_parts = (role_arn or "").split(":")
                        princ_parts = principal_arn.split(":")
                        if (len(role_parts) >= 5 and len(princ_parts) >= 5
                                and role_parts[4] != princ_parts[4]):
                            third_party_uids.append(role_arn)
        finally:
            iam_conn.close()

        for uids, cat in ((list(set(cicd_uids)), "CICD_ENTRY"),
                          (list(set(third_party_uids)), "THIRD_PARTY_ENTRY")):
            if not uids:
                continue
            try:
                with di_conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE resource_security_posture
                        SET is_attack_entry_point       = TRUE,
                            attack_entry_point_category = %s,
                            updated_at                  = NOW()
                        WHERE tenant_id    = %s
                          AND resource_uid = ANY(%s)
                          AND NOT COALESCE(is_attack_entry_point, FALSE)
                        """,
                        (cat, tenant_id, uids),
                    )
                    counts[cat] = cur.rowcount
                di_conn.commit()
            except Exception as exc:
                logger.debug("%s marking failed (non-fatal): %s", cat, exc)
                try:
                    di_conn.rollback()
                except Exception:
                    pass

    except Exception as exc:
        logger.debug("IAM trust policy scan unavailable (non-fatal): %s", exc)

    # ── ENDPOINT_AGENT_ENTRY: agent-managed compute (multi-CSP) ──────────
    # Primary: MANAGED_BY_AGENT edges written by catalog_relationship_writer.
    #   Active CSP rules (catalog/relationships/{csp}/infrastructure_attachment.yaml):
    #     AWS:   ssm_describe_instance_information.InstanceId → ec2_instance
    #     Azure: hybridcompute_machine (when Arc discovery YAML is added)
    #     GCP:   osconfig_inventory → compute.instance (when OS Config YAML added)
    #     OCI:   managementagent_management_agent → compute.instance (when agent YAML added)
    # Secondary: direct asset_inventory query for CSP-specific agent resource types
    #   where the agent resource IS the compute endpoint (Azure Arc, GCP OS Config).
    try:
        agent_managed_uids: list = []
        with di_conn.cursor() as cur:
            # Primary: catalog-driven MANAGED_BY_AGENT edges (all CSPs)
            cur.execute(
                """
                SELECT DISTINCT target_uid
                FROM asset_relationships
                WHERE tenant_id   = %s
                  AND relation_type = 'MANAGED_BY_AGENT'
                  AND target_uid IS NOT NULL
                """,
                (tenant_id,),
            )
            agent_managed_uids = [row[0] for row in cur.fetchall()]

            if not agent_managed_uids:
                # Secondary: CSPs where the agent resource IS the compute endpoint.
                # Azure Arc machines are the managed servers themselves.
                # GCP/OCI agent inventory rows ARE the managed instances.
                cur.execute(
                    """
                    SELECT DISTINCT resource_uid
                    FROM asset_inventory
                    WHERE tenant_id = %s
                      AND resource_uid IS NOT NULL
                      AND resource_type = ANY(%s)
                    """,
                    (tenant_id, [
                        "hybridcompute.machine",            # Azure Arc connected machine
                        "hybridcompute_machine",            # (underscore-normalized variant)
                        "managementagent.management_agent", # OCI management agent host
                        "managementagent_management_agent", # (underscore-normalized)
                        "osconfig.inventory",               # GCP OS Config inventory
                        "osconfig_inventory",               # (underscore-normalized)
                    ]),
                )
                agent_managed_uids = [row[0] for row in cur.fetchall()]

        if agent_managed_uids:
            with di_conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE resource_security_posture
                    SET is_attack_entry_point       = TRUE,
                        attack_entry_point_category = 'ENDPOINT_AGENT_ENTRY',
                        updated_at                  = NOW()
                    WHERE tenant_id    = %s
                      AND resource_uid = ANY(%s)
                      AND NOT COALESCE(is_attack_entry_point, FALSE)
                    """,
                    (tenant_id, agent_managed_uids),
                )
                counts["ENDPOINT_AGENT_ENTRY"] = cur.rowcount
            di_conn.commit()
    except Exception as exc:
        logger.debug("ENDPOINT_AGENT_ENTRY marking failed (non-fatal): %s", exc)
        try:
            di_conn.rollback()
        except Exception:
            pass

    # ── INTERNAL_WORKLOAD_ENTRY: privileged pods ───────────────────────────
    try:
        from engine_common.db_connections import get_container_conn
        container_conn = get_container_conn()
        workload_uids: list = []
        try:
            with container_conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT DISTINCT resource_uid
                    FROM container_security_findings
                    WHERE tenant_id  = %s
                      AND LOWER(rule_id) LIKE '%%privileged%%'
                      AND LOWER(status) = 'open'
                      AND resource_uid IS NOT NULL
                    """,
                    (tenant_id,),
                )
                workload_uids = [row[0] for row in cur.fetchall()]
        finally:
            container_conn.close()

        if workload_uids:
            with di_conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE resource_security_posture
                    SET is_attack_entry_point       = TRUE,
                        attack_entry_point_category = 'INTERNAL_WORKLOAD_ENTRY',
                        updated_at                  = NOW()
                    WHERE tenant_id    = %s
                      AND resource_uid = ANY(%s)
                      AND NOT COALESCE(is_attack_entry_point, FALSE)
                    """,
                    (tenant_id, workload_uids),
                )
                counts["INTERNAL_WORKLOAD_ENTRY"] = cur.rowcount
            di_conn.commit()
    except Exception as exc:
        logger.debug("INTERNAL_WORKLOAD_ENTRY marking failed (non-fatal): %s", exc)
        try:
            di_conn.rollback()
        except Exception:
            pass

    return counts




def run_attack_path_scan(
    scan_run_id: str,
    tenant_id: str,
    account_id: str = "",
) -> Dict[str, Any]:
    """Execute the full attack-path scan pipeline.

    Args:
        scan_run_id:  UUID of the current pipeline run.
        tenant_id:    Tenant identifier (validated against scan_runs table).
        account_id:   Cloud account ID.

    Returns:
        Metrics dict: crown_jewel_count, raw_paths_before_dedup, final_path_count,
        critical_path_count, choke_point_count, scan_duration_seconds.
    """
    start_time = time.time()
    _jlog("scan_start", scan_run_id=scan_run_id, tenant_id=tenant_id)

    metrics: Dict[str, Any] = {
        "crown_jewel_count": 0,
        "raw_paths_before_dedup": 0,
        "final_path_count": 0,
        "critical_path_count": 0,
        "choke_point_count": 0,
        "scan_duration_seconds": 0,
    }

    # ── DB connections ────────────────────────────────────────────────────────
    from engine_common.db_connections import get_attack_path_conn, get_di_conn

    attack_path_conn = get_attack_path_conn()
    # DI conn: all graph data (asset_relationships, asset_inventory, resource_security_posture)
    # lives in threat_engine_di since inventory engine was retired 2026-05-27.
    di_conn = get_di_conn()

    # Threat DB connection — for reading threat_scenario_incidents.
    # Falls back to None if env vars not set (enrichment skipped gracefully).
    threat_conn = None
    try:
        from engine_common.db_connections import get_threat_conn
        threat_conn = get_threat_conn()
    except Exception as _tc_err:
        logger.warning("Could not connect to threat DB — enrichment will be skipped: %s", _tc_err)

    # ── Determine provider from scan_runs ─────────────────────────────────────
    provider = "aws"
    try:
        from engine_common.db_connections import get_onboarding_conn
        onb_conn = get_onboarding_conn()
        try:
            with onb_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT provider, account_id FROM scan_runs WHERE scan_run_id = %s",
                    (scan_run_id,),
                )
                row = cur.fetchone()
                if row:
                    provider = row.get("provider") or "aws"
                    if not account_id:
                        account_id = row.get("account_id") or ""
        finally:
            onb_conn.close()
    except Exception as exc:
        logger.warning("Could not read scan_runs metadata: %s", exc)

    try:
        # ── Stage 1: Crown Jewel Classification ───────────────────────────────
        # Reset stale crown jewel marks from previous scans so the classifier
        # starts with a clean slate. Without this, old is_crown_jewel=true rows
        # accumulate across scans and inflate the BFS crown jewel set.
        _jlog("stage", name="crown_jewel_classify", scan_run_id=scan_run_id)
        try:
            with di_conn.cursor() as _cj_cur:
                _cj_cur.execute(
                    "UPDATE resource_security_posture"
                    " SET is_crown_jewel = false, crown_jewel_type = NULL"
                    " WHERE tenant_id = %s",
                    (tenant_id,),
                )
            di_conn.commit()
            _jlog("crown_jewel_reset", tenant_id=tenant_id, scan_run_id=scan_run_id)
        except Exception as _cj_rst_err:
            logger.warning("crown_jewel reset failed (non-fatal): %s", _cj_rst_err)
            try:
                di_conn.rollback()
            except Exception:
                pass

        from .core.crown_jewel_classifier import CrownJewelClassifier
        classifier = CrownJewelClassifier(
            inventory_conn=di_conn,
            scan_run_id=scan_run_id,
            tenant_id=tenant_id,
            account_id=account_id,
            provider=provider,
        )
        cj_count = classifier.classify()
        metrics["crown_jewel_count"] = cj_count
        _jlog("crown_jewels_classified", count=cj_count, scan_run_id=scan_run_id)

        # ── Stage 2a-pre: Write is_internet_exposed from discovery data ─────────
        # Reads emitted_fields for public indicators and upserts is_internet_exposed=true.
        _jlog("stage", name="internet_exposed_mark", scan_run_id=scan_run_id)
        marked_count = _mark_internet_exposed_from_discoveries(di_conn, tenant_id, scan_run_id)
        _jlog("internet_exposed_marked", count=marked_count, scan_run_id=scan_run_id)

        # ── Stage 2a-pre2b: Mark non-internet attack entry points ─────────────
        # Detects and marks IDENTITY_ENTRY (IAM users without MFA), CICD_ENTRY
        # (OIDC trust roles), THIRD_PARTY_ENTRY (cross-account roles),
        # ENDPOINT_AGENT_ENTRY (SSM-managed EC2), INTERNAL_WORKLOAD_ENTRY
        # (privileged pods). All non-fatal per category.
        _jlog("stage", name="non_internet_entry_mark", scan_run_id=scan_run_id)
        try:
            entry_counts = _mark_non_internet_entry_points(di_conn, tenant_id)
            _jlog(
                "non_internet_entry_marked",
                scan_run_id=scan_run_id,
                identity=entry_counts.get("IDENTITY_ENTRY", 0),
                cicd=entry_counts.get("CICD_ENTRY", 0),
                third_party=entry_counts.get("THIRD_PARTY_ENTRY", 0),
                endpoint_agent=entry_counts.get("ENDPOINT_AGENT_ENTRY", 0),
                internal_workload=entry_counts.get("INTERNAL_WORKLOAD_ENTRY", 0),
            )
        except Exception as _ep_err:
            logger.warning("Non-internet entry point marking failed (non-fatal): %s", _ep_err)

        # ── Stage 2a: Fetch ALL attack entry point UIDs with categories ─────────
        # Returns Dict[uid → category] merging all entry types.
        # internet_exposed_uids is kept as the variable name for call-site compat.
        _jlog("stage", name="entry_point_lookup", scan_run_id=scan_run_id)
        entry_categories_map = _fetch_attack_entry_uids(di_conn, tenant_id)
        internet_exposed_uids = list(entry_categories_map.keys())
        _jlog(
            "entry_point_uids",
            scan_run_id=scan_run_id,
            total=len(internet_exposed_uids),
            internet=sum(1 for c in entry_categories_map.values() if c == "INTERNET_ENTRY"),
            identity=sum(1 for c in entry_categories_map.values() if c == "IDENTITY_ENTRY"),
            cicd=sum(1 for c in entry_categories_map.values() if c == "CICD_ENTRY"),
            third_party=sum(1 for c in entry_categories_map.values() if c == "THIRD_PARTY_ENTRY"),
            endpoint_agent=sum(1 for c in entry_categories_map.values() if c == "ENDPOINT_AGENT_ENTRY"),
            internal_workload=sum(1 for c in entry_categories_map.values() if c == "INTERNAL_WORKLOAD_ENTRY"),
        )

        # ── Stage 2a-pre2: Attack edge validators ──────────────────────────────
        # Reads asset_relationships + posture and writes is_attack_edge=TRUE rows
        # for CAN_REACH, CAN_INVOKE, CAN_USE_IDENTITY, CAN_ASSUME, CAN_READ, etc.
        # Non-fatal — validators do not block BFS if they fail.
        _jlog("stage", name="attack_edge_validators", scan_run_id=scan_run_id)
        try:
            from .validators import run_all_validators
            val_results = run_all_validators(
                di_conn=di_conn,
                scan_run_id=scan_run_id,
                tenant_id=tenant_id,
                account_id=account_id,
                provider=provider,
            )
            _jlog(
                "attack_edge_validators_complete",
                scan_run_id=scan_run_id,
                internet_reachability=val_results.get("internet_reachability", 0),
                service_chain=val_results.get("service_chain", 0),
                identity_usage=val_results.get("identity_usage", 0),
                assume_role=val_results.get("assume_role", 0),
                data_access=val_results.get("data_access", 0),
                total=sum(val_results.values()),
            )
        except Exception as _val_err:
            logger.warning("Attack edge validators failed (non-fatal): %s", _val_err)

        # ── Stage 3: Fetch posture_lookup ────────────────────────────────────
        # Loaded BEFORE BFS so pg_graph can use is_crown_jewel from posture.
        _jlog("stage", name="posture_lookup", scan_run_id=scan_run_id)
        posture_lookup = _build_posture_lookup(di_conn, scan_run_id, tenant_id)
        _jlog("posture_lookup_built", entries=len(posture_lookup), scan_run_id=scan_run_id)

        # ── Stage 2b: PostgreSQL BFS (primary) ───────────────────────────────
        # asset_relationships is in threat_engine_di (di_conn) since inventory DB retired.
        # IAM policy edges and EKS worker_node_of edges are now written to asset_relationships
        # as validated edges (is_attack_edge=TRUE) by iam_policy + eks_worker validators above,
        # so no synthetic extra_edges are needed here.
        _jlog("stage", name="pg_bfs", scan_run_id=scan_run_id)
        from .graph.pg_graph import run_pg_bfs
        raw_paths = run_pg_bfs(
            inventory_conn=di_conn,
            tenant_id=tenant_id,
            scan_run_id=scan_run_id,
            internet_exposed_uids=internet_exposed_uids,
            posture_lookup=posture_lookup,
            entry_categories=entry_categories_map,
        )
        _jlog("pg_bfs_complete", raw_paths=len(raw_paths), scan_run_id=scan_run_id)

        # Neo4j BFS fallback intentionally removed — pg_graph is the sole path
        # computation engine. If pg_graph returns 0 paths (no internet-exposed
        # resources reachable to crown jewels via inventory_relationships),
        # we report 0 paths. A fake fallback from VirtualNodes is worse than no paths.
        if not raw_paths:
            _jlog("pg_bfs_no_paths", scan_run_id=scan_run_id,
                  exposed=len(internet_exposed_uids),
                  crown_jewels=sum(1 for r in posture_lookup.values() if getattr(r, "is_crown_jewel", False)))

        metrics["raw_paths_before_dedup"] = len(raw_paths)

        if not raw_paths:
            _jlog("scan_complete_no_paths", scan_run_id=scan_run_id)
            return metrics

        # ── Stage 3b: Fetch security_findings_lookup ─────────────────────────
        # Loads cross-engine security_findings rows keyed by resource_uid.
        # Used by write_path_nodes to populate per-hop misconfigs/cves/detections.
        _jlog("stage", name="findings_lookup", scan_run_id=scan_run_id)
        all_uids = {uid for p in raw_paths for uid in p.node_uids}
        findings_lookup = _build_findings_lookup(di_conn, tenant_id, all_uids)
        _jlog("findings_lookup_built", entries=len(findings_lookup), scan_run_id=scan_run_id)

        # ── Stage 3c: Load attack objective catalog ───────────────────────────
        # Loads (provider, resource_type) → {objective_type, required_capability}
        # from attack_objective_catalog for objective tagging + OBJ-05 validation.
        # Non-fatal: falls back to empty dicts (uses hardcoded fallback table).
        _jlog("stage", name="objective_catalog_load", scan_run_id=scan_run_id)
        objective_catalog, fallback_table = _load_objective_catalog(di_conn)
        _jlog(
            "objective_catalog_loaded",
            scan_run_id=scan_run_id,
            catalog_entries=len(objective_catalog),
            fallback_entries=len(fallback_table),
        )

        # ── Stage 4: Score paths ──────────────────────────────────────────────
        # findings_lookup is passed so CDR threat_detections + MITRE technique
        # chains on each hop directly influence P (probability score).
        # objective_catalog passed for formal attack objective tagging (OBJ-02 to OBJ-05).
        _jlog("stage", name="score", scan_run_id=scan_run_id)
        from .core.scorer import score_paths
        scored_paths = score_paths(
            raw_paths, posture_lookup, findings_lookup,
            objective_catalog=objective_catalog,
            fallback_table=fallback_table,
        )
        _jlog("paths_scored", count=len(scored_paths), scan_run_id=scan_run_id)

        # ── Stage 4b: MITRE ATT&CK attack vector classification ──────────────
        # Labels each path with T1/T2/T3 pattern, confidence level, and
        # per-hop MITRE technique IDs. The AttackVector result is cached in
        # av_cache (keyed by object id) so Stage 4c can reuse it without
        # calling classify_attack_vector a second time for the top-50 paths.
        _jlog("stage", name="attack_vector_classify", scan_run_id=scan_run_id)
        av_cache: Dict[int, Any] = {}  # id(sp) → AttackVector
        try:
            from .core.attack_vector import classify_attack_vector
            confirmed_count = 0
            likely_count = 0
            for sp in scored_paths:
                av = classify_attack_vector(
                    path_node_uids=sp.node_uids,
                    edge_types=sp.edge_types,
                    depth=sp.depth,
                    posture_lookup=posture_lookup,
                    findings_lookup=findings_lookup,
                )
                av_cache[id(sp)] = av
                sp.attack_vector_type = av.vector_type
                sp.confidence_level = av.confidence
                sp.mitre_techniques = av.technique_ids()
                sp.tactic_sequence = av.tactic_sequence
                if av.confidence == "confirmed":
                    confirmed_count += 1
                elif av.confidence == "likely":
                    likely_count += 1
            _jlog(
                "attack_vector_complete",
                scan_run_id=scan_run_id,
                confirmed=confirmed_count,
                likely=likely_count,
                speculative=len(scored_paths) - confirmed_count - likely_count,
            )
        except Exception as _av_err:
            logger.warning("Attack vector classification failed (non-fatal): %s", _av_err)

        # ── Stage 4c: Orca-style path explanation (top 50 paths) ─────────────
        # Generates step-by-step narrative for the highest-scoring paths.
        # Uses av_cache to avoid recomputing classify_attack_vector for top-50.
        _jlog("stage", name="path_explain", scan_run_id=scan_run_id)
        try:
            from .core.attack_vector import classify_attack_vector
            from .core.path_explainer import explain_path
            top_paths = sorted(scored_paths, key=lambda p: p.path_score, reverse=True)[:50]
            for sp in top_paths:
                try:
                    av = av_cache.get(id(sp)) or classify_attack_vector(
                        path_node_uids=sp.node_uids,
                        edge_types=sp.edge_types,
                        depth=sp.depth,
                        posture_lookup=posture_lookup,
                        findings_lookup=findings_lookup,
                    )
                    sp.explanation = explain_path(
                        node_uids=sp.node_uids,
                        node_types=sp.node_types,
                        edge_types=sp.edge_types,
                        hop_categories=sp.hop_categories,
                        severity=sp.severity,
                        path_score=sp.path_score,
                        attack_vector=av,
                        posture_lookup=posture_lookup,
                        findings_lookup=findings_lookup,
                    )
                except Exception as _exp_err:
                    logger.debug("Path explain failed for one path (non-fatal): %s", _exp_err)
            _jlog("path_explain_complete", count=len(top_paths), scan_run_id=scan_run_id)
        except Exception as _pe_err:
            logger.warning("Path explanation stage failed (non-fatal): %s", _pe_err)

        # ── Stage 5: Deduplicate ──────────────────────────────────────────────
        _jlog("stage", name="dedup", scan_run_id=scan_run_id)
        from .core.deduplicator import deduplicate
        final_paths = deduplicate(scored_paths, posture_lookup)
        metrics["final_path_count"] = len(final_paths)
        critical_count = sum(1 for p in final_paths if (p.severity or "").upper() == "CRITICAL")
        metrics["critical_path_count"] = critical_count
        _jlog(
            "dedup_complete",
            final_paths=len(final_paths),
            critical=critical_count,
            scan_run_id=scan_run_id,
        )

        # ── Stage 5b: Quality cap — keep top-N by criticality score ──────────
        # BFS may generate thousands of paths in large environments. After 3-phase
        # dedup collapses equivalent exposures, we rank survivors by path_score and
        # keep the highest-scoring MAX_WRITE_PATHS. This ensures the DB always
        # contains the most critical paths, not just the first N found by BFS order.
        MAX_WRITE_PATHS = 500
        if len(final_paths) > MAX_WRITE_PATHS:
            pre_cap = len(final_paths)
            final_paths = sorted(final_paths, key=lambda p: p.path_score, reverse=True)[:MAX_WRITE_PATHS]
            metrics["final_path_count"] = len(final_paths)
            metrics["critical_path_count"] = sum(1 for p in final_paths if (p.severity or "").upper() == "CRITICAL")
            _jlog(
                "quality_cap_applied",
                scan_run_id=scan_run_id,
                before=pre_cap,
                kept=len(final_paths),
                pruned=pre_cap - len(final_paths),
            )

        # ── Stage 6: Choke point detection ───────────────────────────────────
        _jlog("stage", name="choke_detect", scan_run_id=scan_run_id)
        from .core.choke_point_detector import detect_choke_points
        choke_points = detect_choke_points(final_paths)
        metrics["choke_point_count"] = len(choke_points)
        _jlog("choke_detect_complete", choke_points=len(choke_points), scan_run_id=scan_run_id)

        # ── Stage 7: DB writes ────────────────────────────────────────────────
        _jlog("stage", name="db_write", scan_run_id=scan_run_id)
        from .db.writer import write_paths, write_path_nodes, write_history
        write_paths(attack_path_conn, final_paths, tenant_id, scan_run_id, account_id, provider)
        write_path_nodes(attack_path_conn, final_paths, tenant_id, findings_lookup=findings_lookup)
        write_history(attack_path_conn, final_paths, tenant_id, scan_run_id)
        _jlog("db_write_complete", scan_run_id=scan_run_id)

        # ── Stage 8: Posture update ───────────────────────────────────────────
        _jlog("stage", name="posture_update", scan_run_id=scan_run_id)
        from .db.posture_updater import update_attack_path_signals
        update_attack_path_signals(
            di_conn,
            final_paths,
            choke_points,
            tenant_id,
            scan_run_id,
            account_id,
            provider,
        )
        _jlog("posture_update_complete", scan_run_id=scan_run_id)

        # ── Stage 8b: Cross-engine composite flags ────────────────────────────
        _jlog("stage", name="composite_flags", scan_run_id=scan_run_id)
        try:
            from .db.posture_updater import update_composite_flags
            update_composite_flags(di_conn, tenant_id, scan_run_id)
        except Exception as _cf_err:
            logger.warning("Composite flag update failed (non-fatal): %s", _cf_err)
        _jlog("composite_flags_complete", scan_run_id=scan_run_id)

        # ── Stage 9: Threat pattern enrichment ───────────────────────────────
        if threat_conn and final_paths:
            _jlog("stage", name="threat_enrichment", scan_run_id=scan_run_id)
            try:
                from .db.threat_incidents_loader import load_threat_incidents
                from .db.path_enricher import enrich_paths
                threat_incidents = load_threat_incidents(
                    threat_conn, tenant_id, scan_run_id
                )
                enrich_counts = enrich_paths(
                    attack_path_conn, final_paths, threat_incidents, tenant_id
                )
                _jlog(
                    "enrichment_complete",
                    scan_run_id=scan_run_id,
                    confirmed=enrich_counts.get("confirmed", 0),
                    likely=enrich_counts.get("likely", 0),
                    speculative=enrich_counts.get("speculative", 0),
                )
                metrics["enrichment_confirmed"] = enrich_counts.get("confirmed", 0)
            except Exception as enrich_err:
                logger.warning("Threat enrichment failed (non-fatal): %s", enrich_err)
        else:
            _jlog(
                "enrichment_skipped",
                scan_run_id=scan_run_id,
                reason="no_threat_conn_or_no_paths",
            )

    except Exception as exc:
        logger.exception(
            '{"engine":"attack-path","event":"scan_error","scan_run_id":"%s","error":"%s"}',
            scan_run_id,
            exc,
        )
        raise
    finally:
        try:
            attack_path_conn.close()
        except Exception:
            pass
        try:
            di_conn.close()
        except Exception:
            pass
        if threat_conn:
            try:
                threat_conn.close()
            except Exception:
                pass

    elapsed = round(time.time() - start_time, 1)
    metrics["scan_duration_seconds"] = elapsed

    _jlog(
        "scan_complete",
        scan_run_id=scan_run_id,
        crown_jewel_count=metrics["crown_jewel_count"],
        raw_paths_before_dedup=metrics["raw_paths_before_dedup"],
        final_path_count=metrics["final_path_count"],
        critical_path_count=metrics["critical_path_count"],
        choke_point_count=metrics["choke_point_count"],
        scan_duration_seconds=elapsed,
    )
    return metrics


def _load_objective_catalog(
    di_conn: Any,
) -> tuple:
    """Load attack_objective_catalog and attack_objective_fallback from DI DB.

    Returns:
        (objective_catalog, fallback_table) where:
          objective_catalog: Dict[(provider, resource_type) → {objective_type, required_capability}]
          fallback_table:    Dict[(crown_jewel_type, access_capability) → {objective_type, required_capability}]

    Non-fatal: returns empty dicts if the table doesn't exist yet (migration not applied).
    """
    objective_catalog: Dict[str, Any] = {}
    fallback_table: Dict[str, Any] = {}

    try:
        with di_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT provider, resource_type, objective_type, required_capability
                FROM attack_objective_catalog
                WHERE is_active = TRUE
                """
            )
            for row in cur.fetchall():
                key = (row["provider"], row["resource_type"])
                objective_catalog[key] = {
                    "objective_type":      row["objective_type"],
                    "required_capability": row["required_capability"],
                }
    except Exception as exc:
        logger.debug("attack_objective_catalog not available (non-fatal): %s", exc)
        try:
            di_conn.rollback()
        except Exception:
            pass

    try:
        with di_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT crown_jewel_type, access_capability, objective_type, required_capability
                FROM attack_objective_fallback
                """
            )
            for row in cur.fetchall():
                key = (row["crown_jewel_type"], row["access_capability"])
                fallback_table[key] = {
                    "objective_type":      row["objective_type"],
                    "required_capability": row["required_capability"],
                }
    except Exception as exc:
        logger.debug("attack_objective_fallback not available (non-fatal): %s", exc)
        try:
            di_conn.rollback()
        except Exception:
            pass

    return objective_catalog, fallback_table


def _build_findings_lookup(
    inventory_conn: Any,
    tenant_id: str,
    resource_uids: set,
) -> Dict[str, Any]:
    """Load security_findings rows and group by resource_uid.

    Returns:
        Dict[resource_uid, {"misconfigs": [...], "cves": [...], "threat_detections": [...]}]

    Finding types map:
        check / network / datasec → misconfigs
        vuln                      → cves
        cdr / threat_detection    → threat_detections
    """
    if not resource_uids:
        return {}

    lookup: Dict[str, Any] = {}
    try:
        uids_list = list(resource_uids)
        with inventory_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT resource_uid, finding_type, severity, rule_id,
                       title, epss_score, cvss_score, mitre_technique_id,
                       mitre_tactic, detail, status
                FROM security_findings
                WHERE tenant_id = %s
                  AND resource_uid = ANY(%s::varchar[])
                  AND LOWER(status) = 'open'
                ORDER BY resource_uid, severity DESC
                LIMIT 5000
                """,
                (tenant_id, uids_list),
            )
            for row in cur.fetchall():
                uid = row["resource_uid"]
                entry = lookup.setdefault(uid, {"misconfigs": [], "cves": [], "threat_detections": []})
                ftype = row.get("finding_type") or ""
                item = {
                    "rule_id": row.get("rule_id"),
                    "title": row.get("title"),
                    "severity": row.get("severity"),
                }
                if ftype == "vuln":
                    item["epss_score"] = float(row["epss_score"]) if row.get("epss_score") else None
                    item["cvss_score"] = float(row["cvss_score"]) if row.get("cvss_score") else None
                    entry["cves"].append(item)
                elif ftype in ("threat_detection", "cdr"):
                    item["mitre_technique_id"] = row.get("mitre_technique_id")
                    item["mitre_tactic"] = row.get("mitre_tactic")
                    entry["threat_detections"].append(item)
                else:
                    entry["misconfigs"].append(item)
    except Exception as exc:
        logger.warning("Failed to build findings_lookup: %s", exc)

    return lookup


def _build_posture_lookup(
    inventory_conn: Any,
    scan_run_id: str,
    tenant_id: str,
) -> Dict[str, Any]:
    """Pre-fetch posture signals from resource_security_posture.

    Returns dict: resource_uid → PostureRow.
    JSONB fields auto-deserialized by psycopg2 — no json.loads().

    Not filtered by scan_run_id — resource_security_posture has UNIQUE on
    (resource_uid, tenant_id) so each resource has one row. Crown jewel signals
    are persistent across scans (written by classifier + threat_v1). Filtering
    by scan_run_id would miss crown jewels written in earlier pipeline stages.
    """
    from .models.attack_path import PostureRow

    posture_lookup: Dict[str, Any] = {}
    try:
        with inventory_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT
                    resource_uid,
                    COALESCE(resource_type, '')              AS resource_type,
                    COALESCE(is_internet_exposed, false)     AS is_internet_exposed,
                    epss_max                                 AS max_epss,
                    COALESCE(has_waf, false)                 AS waf_protected,
                    COALESCE(mfa_enforced, false)            AS mfa_required,
                    COALESCE(has_permission_boundary, false) AS has_permission_boundary,
                    COALESCE(has_active_cdr_actor, false)    AS has_active_cdr_actor,
                    COALESCE(crown_jewel_type, '')           AS crown_jewel_type,
                    data_classification,
                    COALESCE(blast_radius_count, 0)          AS blast_radius_count,
                    COALESCE(is_encrypted_at_rest, true)     AS is_encrypted_at_rest,
                    COALESCE(is_crown_jewel, false)          AS is_crown_jewel,
                    COALESCE(is_on_attack_path, false)       AS is_on_attack_path,
                    COALESCE(attack_path_count, 0)           AS attack_path_count,
                    COALESCE(is_choke_point, false)          AS is_choke_point,
                    COALESCE(check_critical, 0)              AS critical_misconfig_count,
                    COALESCE(check_high, 0)                  AS high_misconfig_count
                FROM resource_security_posture
                WHERE tenant_id = %s
                """,
                (tenant_id,),
            )
            for row in cur.fetchall():
                row_dict = dict(row)
                uid = row_dict.pop("resource_uid")
                # Create PostureRow — psycopg2 already deserialized JSONB, no json.loads()
                posture_lookup[uid] = PostureRow(resource_uid=uid, **row_dict)
    except Exception as exc:
        logger.warning("Failed to build posture_lookup: %s", exc)

    return posture_lookup
