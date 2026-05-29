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
from typing import Any, Dict, Optional

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
                            (emitted_fields->>'PublicIpAddress') IS NOT NULL
                            OR (emitted_fields->>'PubliclyAccessible') = 'true'
                            OR (emitted_fields->>'Scheme') = 'internet-facing'
                            OR (emitted_fields->>'FunctionUrl') IS NOT NULL
                            OR resource_type IN (
                              'apigateway.restapi',
                              'apigateway.httpapi',
                              'apigateway.v2api',
                              'apigatewayv2.api'
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


def _fetch_internet_exposed_uids(
    inventory_conn: Any,
    tenant_id: str,
) -> list:
    """Return resource_uids that are internet-exposed.

    Merges two sources:
      1. resource_security_posture WHERE is_internet_exposed=true  (network/check engine signal)
      2. asset_relationships WHERE relation_type='internet_connected' (FROM side = exposed resource)

    Source 2 is critical when posture rows don't yet exist for newly discovered resources.
    The FROM side of an internet_connected edge is always the cloud resource (e.g. EC2 instance);
    the TO side is always the synthetic 'internet:0.0.0.0/0' sentinel node.
    """
    uids: set = set()
    try:
        with inventory_conn.cursor() as cur:
            # Source 1: posture table
            cur.execute(
                """
                SELECT DISTINCT resource_uid
                FROM resource_security_posture
                WHERE tenant_id = %s
                  AND is_internet_exposed = true
                """,
                (tenant_id,),
            )
            for row in cur.fetchall():
                uids.add(row[0])

            # Source 2: asset_relationships internet exposure edges
            # Covers INTERNET_CONNECTED and INTERNET_ACCESSIBLE edge types.
            cur.execute(
                """
                SELECT DISTINCT source_uid AS uid
                FROM asset_relationships
                WHERE tenant_id = %s
                  AND LOWER(relation_type) IN ('internet_connected', 'internet_accessible')
                  AND source_uid IS NOT NULL
                  AND source_uid NOT LIKE 'internet:%%'
                  AND source_uid NOT LIKE 'pseudo:%%'
                """,
                (tenant_id,),
            )
            rel_uids = [row[0] for row in cur.fetchall()]
            uids.update(rel_uids)
            if rel_uids:
                logger.info(
                    "Added %d internet-exposed UIDs from asset_relationships tenant=%s",
                    len(rel_uids), tenant_id,
                )
    except Exception as exc:
        logger.warning("Could not fetch internet-exposed UIDs: %s", exc)
        try:
            inventory_conn.rollback()
        except Exception:
            pass
    return list(uids)


def _build_iam_permission_edges(
    tenant_id: str,
    posture_lookup: Dict[str, Any],
    scan_run_id: str = "",
) -> Dict[str, list]:
    """Build synthetic IAM role → crown jewel edges from iam_policy_statements.

    These edges supplement inventory_relationships for cases where the IAM engine
    has written policy statement data but the inventory engine has not yet linked
    role ARNs to the resources they can access.

    For non-AWS tenants the iam_policy_statements table is empty (IAM engine only
    processes AWS IAM), so the function returns {} naturally with no code changes
    needed.

    Attack chain enabled:
      Internet → EC2 → (assumes) → IAM role → (grants_access_to) → Crown Jewel

    Returns:
        Dict[role_arn → List[(crown_jewel_uid, 'grants_access_to', 'iam.role', crown_jewel_type)]]
    """
    # Map IAM service prefix → resource_type substrings that classify as that service.
    # Each hint list includes the plain service name to catch resource_type='ecr'/'kms'
    # (exact-name types) as well as compound types like 'ecr.repository'/'kms.key'.
    SERVICE_TO_TYPE_HINTS: Dict[str, list] = {
        "s3":              ["s3.bucket", "s3.", "s3"],
        "dynamodb":        ["dynamodb.table", "dynamodb.", "dynamodb"],
        "secretsmanager":  ["secretsmanager.secret", "secretsmanager."],
        "kms":             ["kms.key", "kms.", "kms"],
        "rds":             ["rds.db-instance", "rds.cluster", "rds."],
        "elasticache":     ["elasticache.cluster", "elasticache."],
        "kinesis":         ["kinesis.stream", "kinesis.", "kinesis"],
        "eks":             ["eks.cluster", "eks.", "eks"],
        "ecr":             ["ecr.repository", "ecr.", "ecr"],
        "glue":            ["glue.database", "glue.table", "glue.", "glue"],
        "athena":          ["athena.workgroup", "athena.", "athena"],
        "emr":             ["emr.cluster", "emr.", "emr"],
        "sagemaker":       ["sagemaker.", "sagemaker.model", "sagemaker"],
        "ecs":             ["ecs.cluster", "ecs.", "ecs"],
        "lambda":          ["lambda.function", "lambda.", "lambda"],
        "redshift":        ["redshift.cluster", "redshift.", "redshift"],
        "es":              ["opensearch.", "elasticsearch."],
        "opensearch":      ["opensearch.", "opensearch.domain", "opensearch"],
        "backup":          ["backup.backup-vault", "backup.", "backup"],
        "efs":             ["elasticfilesystem.", "efs.", "efs"],
    }

    # Pre-build crown jewels grouped by service prefix
    cj_by_service: Dict[str, list] = {}
    for uid, row in posture_lookup.items():
        if not getattr(row, "is_crown_jewel", False):
            continue
        rtype = getattr(row, "resource_type", "") or ""
        for svc, hints in SERVICE_TO_TYPE_HINTS.items():
            if any(rtype.startswith(h) or h in rtype for h in hints):
                cj_by_service.setdefault(svc, []).append((uid, rtype))

    if not cj_by_service:
        logger.info("No crown jewels found in posture — skipping IAM edge build")
        return {}

    extra_edges: Dict[str, list] = {}

    try:
        from engine_common.db_connections import get_iam_conn
        iam_conn = get_iam_conn()
    except Exception as exc:
        logger.warning("IAM DB unavailable — skipping IAM permission edges: %s", exc)
        return {}

    try:
        with iam_conn.cursor() as cur:
            # Do NOT filter by scan_run_id — IAM engine runs independently and its
            # policy statements accumulate under different scan_run_ids than the
            # main pipeline. Filtering would always return 0 rows.
            cur.execute(
                """
                SELECT DISTINCT attached_to_arn, actions, effect, attached_to_type
                FROM iam_policy_statements
                WHERE tenant_id = %s
                  AND effect = 'Allow'
                  AND attached_to_arn IS NOT NULL
                  AND actions IS NOT NULL
                  AND NOT COALESCE(not_action_mode, FALSE)
                """,
                (tenant_id,),
            )
            rows = cur.fetchall()

        # Build role → services_it_can_access
        from collections import defaultdict
        role_services: Dict[str, set] = defaultdict(set)
        for role_arn, actions, _effect, attached_type in rows:
            if not role_arn or not isinstance(actions, list):
                continue
            for action in actions:
                if not isinstance(action, str):
                    continue
                action_lower = action.lower().strip()
                if action_lower in ("*", "*:*"):
                    # Wildcard — can access everything
                    role_services[role_arn].update(SERVICE_TO_TYPE_HINTS.keys())
                elif ":" in action_lower:
                    svc = action_lower.split(":")[0]
                    if svc in SERVICE_TO_TYPE_HINTS:
                        role_services[role_arn].add(svc)

        # Build extra_edges: role → [(crown_uid, 'grants_access_to', 'iam.role', rtype)]
        for role_arn, services in role_services.items():
            edges = []
            for svc in services:
                for (cj_uid, cj_rtype) in cj_by_service.get(svc, []):
                    edges.append((cj_uid, "grants_access_to", "iam.role", cj_rtype))
            if edges:
                extra_edges[role_arn] = edges

        logger.info(
            "IAM permission edges: %d roles → %d synthetic edges (tenant=%s)",
            len(extra_edges),
            sum(len(v) for v in extra_edges.values()),
            tenant_id,
        )
    except Exception as exc:
        logger.warning("IAM permission edge build failed (non-fatal): %s", exc)
        try:
            iam_conn.rollback()
        except Exception:
            pass
    finally:
        try:
            iam_conn.close()
        except Exception:
            pass

    return extra_edges


def _build_eks_worker_node_edges(
    di_conn: Any,
    tenant_id: str,
    internet_exposed_uids: list,
    posture_lookup: Optional[Dict[str, Any]] = None,
) -> Dict[str, list]:
    """Build synthetic EC2 → EKS cluster edges for EKS worker nodes.

    EKS cluster ARNs are NOT in asset_inventory (only workloads like daemonsets/deployments
    are stored there). We find the cluster via posture_lookup (resource_security_posture),
    which stores the cluster with resource_type='eks.cluster'.

    Strategy:
      1. Scan posture_lookup for UIDs matching the EKS cluster ARN pattern:
         arn:aws:eks:REGION:ACCOUNT:cluster/NAME  (6 colon-parts, last = 'cluster/X')
      2. Build account+region → [cluster_arn] lookup.
      3. Query asset_inventory for EC2 instances with EKS nodegroup instance profiles.
      4. Match EC2 to cluster by account+region → emit worker_node_of edges.

    Returns:
        Dict[ec2_uid → [(eks_cluster_uid, 'worker_node_of', 'ec2.instance', 'eks.cluster')]]
    """
    edges: Dict[str, list] = {}
    try:
        from collections import defaultdict

        # Step 1: Find EKS cluster UIDs from posture_lookup
        # EKS cluster is NOT in asset_inventory — use posture_lookup (resource_security_posture)
        eks_by_account_region: Dict[str, list] = defaultdict(list)
        if posture_lookup:
            for uid in posture_lookup:
                if not uid.startswith("arn:aws:eks:"):
                    continue
                parts = uid.split(":")
                # Cluster ARN has exactly 6 colon-parts; last part = 'cluster/NAME' with no extra '/'
                if len(parts) == 6 and parts[5].startswith("cluster/") and "/" not in parts[5][8:]:
                    region = parts[3]
                    account = parts[4]
                    eks_by_account_region[f"{account}:{region}"].append(uid)

        if not eks_by_account_region:
            logger.info("EKS worker node edges: no cluster UIDs found in posture_lookup (tenant=%s)", tenant_id)
            return {}

        # Step 2: Find EC2 instances with EKS nodegroup instance profiles
        with di_conn.cursor() as cur:
            cur.execute(
                """
                SELECT DISTINCT resource_uid, region, account_id
                FROM asset_inventory
                WHERE tenant_id = %s
                  AND resource_type LIKE 'ec2%%'
                  AND resource_uid LIKE 'arn:aws:ec2:%%:instance/%%'
                  AND (emitted_fields->'IamInstanceProfile'->>'Arn') LIKE '%%instance-profile/eks-%%'
                """,
                (tenant_id,),
            )
            ec2_rows = cur.fetchall()

        for (ec2_uid, region, account_id) in ec2_rows:
            key = f"{account_id}:{region}"
            target_clusters = eks_by_account_region.get(key, [])
            if target_clusters:
                edges[ec2_uid] = [
                    (cls_arn, "worker_node_of", "ec2.instance", "eks.cluster")
                    for cls_arn in target_clusters
                ]

        if edges:
            logger.info(
                "EKS worker node edges: %d EC2 → %d cluster edges (tenant=%s)",
                len(edges),
                sum(len(v) for v in edges.values()),
                tenant_id,
            )
    except Exception as exc:
        logger.warning("EKS worker node edge build failed (non-fatal): %s", exc)
    return edges


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
    from engine_common.db_connections import get_attack_path_conn, get_di_conn, get_inventory_conn

    attack_path_conn = get_attack_path_conn()
    # DI conn: reads/writes resource_security_posture and security_findings (now in DI DB)
    di_conn = get_di_conn()
    # inventory_conn: only for inventory_relationships graph topology (pg_graph)
    inventory_conn = get_inventory_conn()

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
        _jlog("stage", name="crown_jewel_classify", scan_run_id=scan_run_id)
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
        # Reads discovery_findings.emitted_fields for public indicators
        # (PublicIpAddress, PubliclyAccessible, Scheme=internet-facing, FunctionUrl)
        # and upserts is_internet_exposed=true into resource_security_posture (DI DB).
        # This runs BEFORE the BFS lookup so the BFS immediately sees real entry points
        # without requiring the network engine to have written to posture first.
        _jlog("stage", name="internet_exposed_mark", scan_run_id=scan_run_id)
        marked_count = _mark_internet_exposed_from_discoveries(di_conn, tenant_id, scan_run_id)
        _jlog("internet_exposed_marked", count=marked_count, scan_run_id=scan_run_id)

        # ── Stage 2a: Fetch internet-exposed UIDs from resource_security_posture ─
        _jlog("stage", name="internet_exposed_lookup", scan_run_id=scan_run_id)
        internet_exposed_uids = _fetch_internet_exposed_uids(di_conn, tenant_id)
        _jlog("internet_exposed_uids", count=len(internet_exposed_uids), scan_run_id=scan_run_id)

        # ── Stage 3: Fetch posture_lookup ────────────────────────────────────
        # Loaded BEFORE BFS so pg_graph can use is_crown_jewel from posture.
        _jlog("stage", name="posture_lookup", scan_run_id=scan_run_id)
        posture_lookup = _build_posture_lookup(di_conn, scan_run_id, tenant_id)
        _jlog("posture_lookup_built", entries=len(posture_lookup), scan_run_id=scan_run_id)

        # ── Stage 2b-pre: IAM permission edges (synthetic graph enrichment) ────
        # Reads iam_policy_statements to build IAM role → crown jewel edges.
        # Attack path enabled: Internet → EC2 → (has_role) → IAM role → (grants_access_to) → Crown Jewel
        _jlog("stage", name="iam_permission_edges", scan_run_id=scan_run_id)
        iam_extra_edges = _build_iam_permission_edges(tenant_id, posture_lookup, scan_run_id)
        _jlog("iam_permission_edges_built", synthetic_edges=sum(len(v) for v in iam_extra_edges.values()),
              roles_with_access=len(iam_extra_edges), scan_run_id=scan_run_id)

        # ── Stage 2b-pre3: EKS worker node edges (topology bridge) ──────────────
        # Reconstructs EC2 → EKS cluster worker_node_of edges that the inventory
        # engine does not write. Without these, internet-exposed EKS worker nodes
        # have no path to the EKS crown jewel in the pg BFS graph.
        _jlog("stage", name="eks_worker_edges", scan_run_id=scan_run_id)
        eks_worker_edges = _build_eks_worker_node_edges(di_conn, tenant_id, internet_exposed_uids, posture_lookup=posture_lookup)
        for ec2_uid, worker_edges in eks_worker_edges.items():
            iam_extra_edges.setdefault(ec2_uid, []).extend(worker_edges)
        _jlog("eks_worker_edges_merged", ec2_worker_nodes=len(eks_worker_edges), scan_run_id=scan_run_id)

        # ── Stage 2b: PostgreSQL BFS (primary) ───────────────────────────────
        # Reads inventory_relationships directly — no Neo4j dependency.
        _jlog("stage", name="pg_bfs", scan_run_id=scan_run_id)
        from .graph.pg_graph import run_pg_bfs
        raw_paths = run_pg_bfs(
            inventory_conn=inventory_conn,
            tenant_id=tenant_id,
            scan_run_id=scan_run_id,
            internet_exposed_uids=internet_exposed_uids,
            posture_lookup=posture_lookup,
            extra_edges=iam_extra_edges if iam_extra_edges else None,
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

        # ── Stage 4: Score paths ──────────────────────────────────────────────
        # findings_lookup is passed so CDR threat_detections + MITRE technique
        # chains on each hop directly influence P (probability score).
        _jlog("stage", name="score", scan_run_id=scan_run_id)
        from .core.scorer import score_paths
        scored_paths = score_paths(raw_paths, posture_lookup, findings_lookup)
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
        critical_count = sum(1 for p in final_paths if p.severity == "critical")
        metrics["critical_path_count"] = critical_count
        _jlog(
            "dedup_complete",
            final_paths=len(final_paths),
            critical=critical_count,
            scan_run_id=scan_run_id,
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
        try:
            inventory_conn.close()
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
