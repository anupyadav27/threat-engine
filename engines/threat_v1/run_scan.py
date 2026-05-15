"""
run_scan.py — GraphBuilder entry point invoked by the Argo pipeline.

Execution order (REQUIREMENTS §3, Sprint Plan S1-07):

  Step 0: scan_run_id ownership validation (CP1-07 — security gate, must run first)
  Step 1: Advisory lock acquisition (W-01: keyed on tenant+account, not tenant alone)
  Step 2: Resolve best scan_run_id per source engine
  Step 3: Load check findings → Resource + MisconfigFinding nodes
  Step 3b: Flag mapper → set internet_exposed, is_admin_role on Resource nodes
  Step 4: Load vuln findings → VulnFinding nodes + update has_critical_cve flags
  Step 5: Load CDR events → CDREvent + CDRActor nodes (actor_principal hashed — CP1-02)
  Step 6: Load inventory relationships → attack-path edges
  Step 7: Crown jewel classification → set is_crown_jewel flags
  Step 8: Record threat_scan_runs_v1 completion row
  Step 9: Release advisory lock

Any exception in steps 3–7 rolls back the threat DB advisory lock and exits with
non-zero code. The graph state in Neo4j is left as-is (partial writes are safe —
PatternExecutor always sees a current graph, a partial graph just fires fewer patterns).

Argo does NOT retry on non-zero exit for ownership failures (step 0). It does retry
for transient errors (steps 2–7) according to the workflow template retryStrategy.
"""
from __future__ import annotations

import hashlib
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Dict, Optional

from threat_v1.database import (
    get_cdr_conn,
    get_check_conn,
    get_inventory_conn,
    get_neo4j_driver,
    get_threat_conn,
    get_vuln_conn,
)
from threat_v1.graph.crown_jewel_classifier import CrownJewelClassifier
from threat_v1.graph.cdr_loader import CDRLoader
from threat_v1.graph.edge_builder import EdgeBuilder
from threat_v1.graph.flag_mapper import FlagMapper
from threat_v1.graph.misconfig_loader import MisconfigLoader
from threat_v1.graph.resource_resolver import ResourceResolver
from threat_v1.graph.semantic_edge_synthesizer import SemanticEdgeSynthesizer
from threat_v1.graph.vuln_loader import VulnLoader
from threat_v1.detector.pattern_executor import PatternExecutor

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("run_scan")

_ADVISORY_LOCK_NAMESPACE = "threat_v1_graph_build"


def _advisory_lock_key(tenant_id: str, account_id: str) -> int:
    """Deterministic 32-bit key from tenant+account — W-01 requires BOTH."""
    raw = f"{_ADVISORY_LOCK_NAMESPACE}|{tenant_id}|{account_id}"
    return int(hashlib.md5(raw.encode()).hexdigest()[:8], 16) & 0x7FFFFFFF


def _validate_ownership(
    threat_conn,
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
) -> bool:
    """CP1-07: verify scan_run_id belongs to this tenant/account before any reads.

    Returns True if ownership confirmed, False if no matching row found.
    This is a security gate — failure must abort immediately.
    """
    cur = threat_conn.cursor()
    cur.execute(
        """
        SELECT 1
        FROM scan_orchestration
        WHERE scan_run_id = %s
          AND tenant_id   = %s
          AND account_id  = %s
        LIMIT 1
        """,
        (scan_run_id, tenant_id, account_id),
    )
    row = cur.fetchone()
    cur.close()
    return row is not None


def _acquire_advisory_lock(threat_conn, lock_key: int) -> None:
    """Acquire a session-level advisory lock. Blocks until lock is available."""
    cur = threat_conn.cursor()
    cur.execute("SELECT pg_advisory_lock(%s)", (lock_key,))
    cur.close()


def _release_advisory_lock(threat_conn, lock_key: int) -> None:
    """Release the session-level advisory lock."""
    try:
        cur = threat_conn.cursor()
        cur.execute("SELECT pg_advisory_unlock(%s)", (lock_key,))
        cur.close()
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to release advisory lock %s: %s", lock_key, exc)


def _record_scan_run(
    threat_conn,
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    status: str,
    stats: Dict,
    error_message: Optional[str] = None,
) -> None:
    cur = threat_conn.cursor()
    cur.execute(
        """
        INSERT INTO threat_scan_runs_v1 (
            scan_run_id, tenant_id, account_id, status, mode,
            graph_node_count, graph_edge_count,
            incident_count, patterns_evaluated, patterns_fired,
            patterns_timed_out, patterns_suppressed,
            completed_at, error_detail
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (scan_run_id, tenant_id) DO UPDATE
        SET status             = EXCLUDED.status,
            graph_node_count   = EXCLUDED.graph_node_count,
            graph_edge_count   = EXCLUDED.graph_edge_count,
            incident_count     = EXCLUDED.incident_count,
            patterns_evaluated = EXCLUDED.patterns_evaluated,
            patterns_fired     = EXCLUDED.patterns_fired,
            completed_at       = EXCLUDED.completed_at,
            error_detail       = EXCLUDED.error_detail
        """,
        (
            scan_run_id,
            tenant_id,
            account_id,
            status,
            "full",
            stats.get("resource_count", 0),
            stats.get("edge_count", 0),
            stats.get("incidents_written", 0),
            stats.get("patterns_run", 0),
            stats.get("total_matches", 0),
            0,
            0,
            datetime.now(timezone.utc),
            error_message,
        ),
    )
    threat_conn.commit()
    cur.close()


def build_graph(
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
) -> None:
    """Execute the 9-step graph build pipeline."""

    threat_conn = get_threat_conn()
    lock_key = _advisory_lock_key(tenant_id, account_id)
    stats: Dict = {}
    lock_acquired = False

    try:
        # ── Step 0: Ownership validation (CP1-07) ────────────────────────────
        logger.info("Step 0: ownership validation for scan_run_id=%s", scan_run_id)
        if not _validate_ownership(threat_conn, scan_run_id, tenant_id, account_id):
            logger.error(
                "Ownership validation FAILED — no scan_orchestration row for "
                "scan_run_id=%s tenant=%s account=%s. Aborting.",
                scan_run_id, tenant_id, account_id,
            )
            sys.exit(1)
        logger.info("Step 0: ownership validated")

        # ── Step 1: Advisory lock ─────────────────────────────────────────────
        logger.info("Step 1: acquiring advisory lock key=%s", lock_key)
        _acquire_advisory_lock(threat_conn, lock_key)
        lock_acquired = True
        logger.info("Step 1: lock acquired")

        # Open all cross-engine connections after lock
        check_conn = get_check_conn()
        vuln_conn = get_vuln_conn()
        cdr_conn = get_cdr_conn()
        inventory_conn = get_inventory_conn()
        neo4j_driver = get_neo4j_driver()

        # ── Step 2: Resolve best scan_run_id per engine ───────────────────────
        logger.info("Step 2: resolving source scan_run_ids")
        resolver = ResourceResolver(check_conn, vuln_conn, cdr_conn, inventory_conn)
        resolved = resolver.resolve(tenant_id, account_id)
        logger.info("Step 2: resolved=%s", resolved)

        # ── Step 3: Misconfig loader ──────────────────────────────────────────
        check_scan = resolved.get("check") or scan_run_id
        logger.info("Step 3: loading check findings (scan=%s)", check_scan)
        misconfig_result = MisconfigLoader(check_conn, neo4j_driver).load(
            tenant_id, account_id, check_scan,
        )
        stats["resource_count"] = misconfig_result["resource_count"]
        stats["misconfig_count"] = misconfig_result["finding_count"]
        logger.info("Step 3: %s", misconfig_result)

        # ── Step 3b: Flag mapper ──────────────────────────────────────────────
        logger.info("Step 3b: mapping check rule flags to Neo4j Resource nodes")
        flag_result = FlagMapper(check_conn, neo4j_driver, inv_conn=inventory_conn).map(
            tenant_id, account_id, check_scan,
        )
        stats["flag_result"] = flag_result
        logger.info("Step 3b: %s", flag_result)

        # ── Step 4: Vuln loader ───────────────────────────────────────────────
        vuln_scan = resolved.get("vuln")
        if vuln_scan:
            logger.info("Step 4: loading vuln findings (scan=%s)", vuln_scan)
            vuln_result = VulnLoader(vuln_conn, neo4j_driver).load(
                tenant_id, account_id, vuln_scan,
            )
            stats["vuln_count"] = vuln_result["vuln_count"]
            logger.info("Step 4: %s", vuln_result)
        else:
            logger.info("Step 4: no vuln scan found, skipping")
            stats["vuln_count"] = 0

        # ── Step 5: CDR loader ────────────────────────────────────────────────
        cdr_scan = resolved.get("cdr")
        if cdr_scan:
            logger.info("Step 5: loading CDR events (scan=%s)", cdr_scan)
            cdr_result = CDRLoader(cdr_conn, neo4j_driver).load(tenant_id, cdr_scan)
            stats["cdr_event_count"] = cdr_result["event_count"]
            logger.info("Step 5: %s", cdr_result)
        else:
            logger.info("Step 5: no CDR scan found, skipping")
            stats["cdr_event_count"] = 0

        # ── Step 6: Edge builder ──────────────────────────────────────────────
        logger.info("Step 6: building security edges from inventory_relationships")
        edge_result = EdgeBuilder(inventory_conn, neo4j_driver).build(
            tenant_id, account_id,
        )
        stats["edge_count"] = edge_result["edge_count"]
        logger.info("Step 6: %s", edge_result)

        # ── Step 6b: Semantic edge synthesis ─────────────────────────────────
        logger.info("Step 6b: synthesizing semantic edges (CAN_ESCALATE_TO, CAN_ACCESS, EXECUTES_IN, FLOWS_TO)")
        synth_result = SemanticEdgeSynthesizer(neo4j_driver).synthesize(tenant_id, account_id)
        stats["semantic_edge_count"] = synth_result["edge_count"]
        logger.info("Step 6b: %s", synth_result)

        # ── Step 7: Crown jewel classification ────────────────────────────────
        logger.info("Step 7: classifying crown jewels")
        cj_result = CrownJewelClassifier(
            inventory_conn, threat_conn, neo4j_driver,
        ).classify(tenant_id, account_id)
        stats["crown_jewel_count"] = cj_result["crown_jewel_count"]
        logger.info("Step 7: %s", cj_result)

        # ── Step 7b: Pattern execution (runs after full graph is built) ──────────
        csp = os.environ.get("ACCOUNT_CSP", "aws")
        logger.info("Step 7b: executing patterns (csp=%s)", csp)
        executor_result = PatternExecutor(threat_conn, neo4j_driver).execute(
            tenant_id=tenant_id,
            account_id=account_id,
            scan_run_id=scan_run_id,
            csp=csp,
        )
        stats["patterns_run"] = executor_result["patterns_run"]
        stats["incidents_written"] = executor_result["incidents_written"]
        logger.info("Step 7b: %s", executor_result)

        # ── Step 8: Record completion ─────────────────────────────────────────
        logger.info("Step 8: recording threat_scan_runs_v1 completion row")
        _record_scan_run(
            threat_conn, scan_run_id, tenant_id, account_id, "completed", stats,
        )

        neo4j_driver.close()
        logger.info(
            "Graph build COMPLETE — scan_run_id=%s stats=%s",
            scan_run_id, stats,
        )

    except Exception as exc:
        logger.error(
            "Graph build FAILED — scan_run_id=%s error=%s",
            scan_run_id, exc,
            exc_info=True,
        )
        try:
            _record_scan_run(
                threat_conn, scan_run_id, tenant_id, account_id,
                "failed", stats, error_message=str(exc),
            )
        except Exception:  # noqa: BLE001
            pass
        raise

    finally:
        # ── Step 9: Release advisory lock ─────────────────────────────────────
        if lock_acquired:
            logger.info("Step 9: releasing advisory lock")
            _release_advisory_lock(threat_conn, lock_key)
        threat_conn.close()


if __name__ == "__main__":
    scan_run_id = os.environ.get("SCAN_RUN_ID") or (sys.argv[1] if len(sys.argv) > 1 else "")
    tenant_id = os.environ.get("TENANT_ID") or (sys.argv[2] if len(sys.argv) > 2 else "")
    account_id = os.environ.get("ACCOUNT_ID") or (sys.argv[3] if len(sys.argv) > 3 else "")

    if not all([scan_run_id, tenant_id, account_id]):
        logger.error(
            "Missing required args. Usage: run_scan.py <scan_run_id> <tenant_id> <account_id> "
            "or set SCAN_RUN_ID / TENANT_ID / ACCOUNT_ID env vars."
        )
        sys.exit(1)

    build_graph(scan_run_id, tenant_id, account_id)
