"""
Attack Path Engine — Scan Orchestrator.

Pipeline stage 6.5 — runs AFTER graph-build, BEFORE risk.

Orchestration order (architecture doc section 2):
  1. CrownJewelClassifier.classify()
  2. Neo4jClient.reverse_bfs()
  3. Fetch posture_lookup from resource_security_posture
  4. scorer.score_paths() (probability_score + impact_score per path)
  5. deduplicator.deduplicate()
  6. choke_point_detector.detect_choke_points()
  7. writer.write_paths() + write_path_nodes() + write_history()
  8. posture_updater.update_attack_path_signals()

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


def _fetch_internet_exposed_uids(
    inventory_conn: Any,
    tenant_id: str,
) -> list:
    """Return resource_uids where is_internet_exposed=true in resource_security_posture.

    Not filtered by scan_run_id — posture is accumulated across scans so even
    resources scanned in a previous run are valid entry point candidates.
    Replaces the :Internet Neo4j node dependency — posture is the authoritative signal.
    """
    try:
        with inventory_conn.cursor() as cur:
            cur.execute(
                """
                SELECT DISTINCT resource_uid
                FROM resource_security_posture
                WHERE tenant_id = %s
                  AND is_internet_exposed = true
                """,
                (tenant_id,),
            )
            return [row[0] for row in cur.fetchall()]
    except Exception as exc:
        logger.warning("Could not fetch internet-exposed UIDs: %s", exc)
        return []


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
    from engine_common.db_connections import get_attack_path_conn, get_inventory_conn

    attack_path_conn = get_attack_path_conn()
    inventory_conn = get_inventory_conn()

    # Threat DB connection — for reading threat_scenario_incidents.
    # Falls back to None if env vars not set (enrichment skipped gracefully).
    threat_conn = None
    try:
        from engine_common.db_connections import get_threat_conn
        threat_conn = get_threat_conn()
    except Exception as _tc_err:
        logger.warning("Could not connect to threat DB — enrichment will be skipped: %s", _tc_err)

    # ── Neo4j driver ──────────────────────────────────────────────────────────
    neo4j_driver = None
    try:
        from neo4j import GraphDatabase
        neo4j_driver = GraphDatabase.driver(
            os.getenv("NEO4J_URI", "bolt://localhost:7687"),
            auth=(
                os.getenv("NEO4J_USER", "neo4j"),
                os.getenv("NEO4J_PASSWORD", ""),
            ),
        )
    except Exception as exc:
        logger.warning("Neo4j driver unavailable — crown jewel classification and BFS will be skipped: %s", exc)

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
        from .crown_jewel_classifier import CrownJewelClassifier
        classifier = CrownJewelClassifier(
            neo4j_driver=neo4j_driver,
            inventory_conn=inventory_conn,
            scan_run_id=scan_run_id,
            tenant_id=tenant_id,
            account_id=account_id,
            provider=provider,
        )
        cj_count = classifier.classify()
        metrics["crown_jewel_count"] = cj_count
        _jlog("crown_jewels_classified", count=cj_count, scan_run_id=scan_run_id)

        # ── Stage 2a: Fetch internet-exposed UIDs from resource_security_posture ─
        # Reads is_internet_exposed=true from posture BEFORE BFS so the BFS can
        # treat those resources as internet entry points. This removes the
        # dependency on graph-build creating an :Internet node — the posture table
        # (populated by network/check engines) is the authoritative signal.
        _jlog("stage", name="internet_exposed_lookup", scan_run_id=scan_run_id)
        internet_exposed_uids = _fetch_internet_exposed_uids(inventory_conn, tenant_id)
        _jlog("internet_exposed_uids", count=len(internet_exposed_uids), scan_run_id=scan_run_id)

        # ── Stage 2b: Reverse BFS ─────────────────────────────────────────────
        _jlog("stage", name="bfs", scan_run_id=scan_run_id)
        from .graph.neo4j_client import Neo4jClient
        neo4j_client = Neo4jClient()
        raw_paths = neo4j_client.reverse_bfs(
            tenant_id=tenant_id,
            scan_run_id=scan_run_id,
            internet_exposed_uids=internet_exposed_uids,
        )
        metrics["raw_paths_before_dedup"] = len(raw_paths)
        _jlog("bfs_complete", raw_paths=len(raw_paths), scan_run_id=scan_run_id)

        if not raw_paths:
            _jlog("scan_complete_no_paths", scan_run_id=scan_run_id)
            return metrics

        # ── Stage 3: Fetch posture_lookup ────────────────────────────────────
        _jlog("stage", name="posture_lookup", scan_run_id=scan_run_id)
        posture_lookup = _build_posture_lookup(inventory_conn, scan_run_id, tenant_id)
        _jlog("posture_lookup_built", entries=len(posture_lookup), scan_run_id=scan_run_id)

        # ── Stage 3b: Fetch security_findings_lookup ─────────────────────────
        # Loads cross-engine security_findings rows keyed by resource_uid.
        # Used by write_path_nodes to populate per-hop misconfigs/cves/detections.
        _jlog("stage", name="findings_lookup", scan_run_id=scan_run_id)
        all_uids = {uid for p in raw_paths for uid in p.node_uids}
        findings_lookup = _build_findings_lookup(inventory_conn, tenant_id, all_uids)
        _jlog("findings_lookup_built", entries=len(findings_lookup), scan_run_id=scan_run_id)

        # ── Stage 4: Score paths ──────────────────────────────────────────────
        # findings_lookup is passed so CDR threat_detections + MITRE technique
        # chains on each hop directly influence P (probability score).
        _jlog("stage", name="score", scan_run_id=scan_run_id)
        from .core.scorer import score_paths
        scored_paths = score_paths(raw_paths, posture_lookup, findings_lookup)
        _jlog("paths_scored", count=len(scored_paths), scan_run_id=scan_run_id)

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
            inventory_conn,
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
            update_composite_flags(inventory_conn, tenant_id, scan_run_id)
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
            inventory_conn.close()
        except Exception:
            pass
        if threat_conn:
            try:
                threat_conn.close()
            except Exception:
                pass
        if neo4j_driver:
            try:
                neo4j_driver.close()
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
                  AND status = 'open'
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
    """
    from .models.attack_path import PostureRow

    posture_lookup: Dict[str, Any] = {}
    try:
        with inventory_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT
                    resource_uid,
                    is_internet_exposed,
                    epss_max        AS max_epss,
                    has_waf         AS waf_protected,
                    mfa_enforced    AS mfa_required,
                    has_permission_boundary,
                    has_active_cdr_actor,
                    crown_jewel_type,
                    data_classification,
                    blast_radius_count,
                    is_crown_jewel,
                    is_on_attack_path,
                    attack_path_count,
                    is_choke_point
                FROM resource_security_posture
                WHERE scan_run_id = %s AND tenant_id = %s
                """,
                (scan_run_id, tenant_id),
            )
            for row in cur.fetchall():
                row_dict = dict(row)
                uid = row_dict.pop("resource_uid")
                # Create PostureRow — psycopg2 already deserialized JSONB, no json.loads()
                posture_lookup[uid] = PostureRow(resource_uid=uid, **row_dict)
    except Exception as exc:
        logger.warning("Failed to build posture_lookup: %s", exc)

    return posture_lookup
