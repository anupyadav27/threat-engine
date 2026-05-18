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
  Step 7a: Enrich Neo4j nodes from resource_security_posture (AP-ENHANCE-03)
  Step 7b: Pattern execution (PatternExecutor)
  Step 7c: Write T2/T3 incident targets as crown jewels to posture (AP-ENHANCE-02)
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


_T2T3_TYPE_TO_CJ: Dict[str, str] = {
    # Storage / data
    "s3.bucket": "data", "gcs.bucket": "data", "oci.object_storage": "data",
    "blob.container": "data", "adls.filesystem": "data", "azure.storage_blob": "data",
    # Databases
    "rds.instance": "database", "rds.cluster": "database",
    "dynamodb.table": "database", "redshift.cluster": "database",
    "cloud_sql.instance": "database", "bigquery.dataset": "database",
    "oci.autonomous_db": "database", "azure.sql_database": "database",
    # Secrets / KMS
    "secretsmanager.secret": "secrets", "gcp.secret_manager": "secrets",
    "azure.key_vault_secret": "secrets",
    "kms.key": "encryption_control", "gcp.kms_key": "encryption_control",
    "oci.vault_key": "encryption_control",
    # Identity
    "iam.role": "identity", "iam.user": "identity",
    "gcp.service_account": "identity", "azure.service_principal": "identity",
    # Infra control
    "eks.cluster": "infra_control", "gke.cluster": "infra_control",
    "oci.oke_cluster": "infra_control", "aks.cluster": "infra_control",
    # AI endpoints
    "sagemaker.endpoint": "ai_endpoint", "sagemaker_endpoint": "ai_endpoint",
    "bedrock.model": "ai_endpoint", "bedrock_model": "ai_endpoint",
    # Code
    "ecr.repository": "code", "artifact_registry.repo": "code",
}


def _derive_cj_type(resource_type: str) -> str:
    """Map a resource_security_posture.resource_type to a crown_jewel_type string."""
    rtype = (resource_type or "").lower()
    if rtype in _T2T3_TYPE_TO_CJ:
        return _T2T3_TYPE_TO_CJ[rtype]
    # Prefix heuristics for types not in the explicit map
    if any(rtype.startswith(p) for p in ("rds.", "dynamodb.", "redshift.", "cloud_sql.", "bigquery.", "oci.autonomous")):
        return "database"
    if any(rtype.startswith(p) for p in ("s3", "gcs", "blob", "oci.object")):
        return "data"
    if any(rtype.startswith(p) for p in ("iam.", "gcp.service_account", "azure.service_principal")):
        return "identity"
    if any(rtype.startswith(p) for p in ("kms.", "secretsmanager.", "gcp.kms", "oci.vault")):
        return "secrets"
    return "data"


def _enrich_neo4j_from_posture(inventory_conn, neo4j_driver, tenant_id: str) -> Dict:
    """Step 7a: Push posture signals (is_crown_jewel, is_internet_exposed) into Neo4j node props."""
    cur = inventory_conn.cursor()
    cur.execute(
        """
        SELECT resource_uid, is_crown_jewel, is_internet_exposed, crown_jewel_type, resource_type
        FROM resource_security_posture
        WHERE tenant_id = %s
          AND (is_crown_jewel = TRUE OR is_internet_exposed = TRUE)
        """,
        (tenant_id,),
    )
    rows = cur.fetchall()
    cur.close()

    if not rows:
        return {"enriched_count": 0}

    enriched = 0
    with neo4j_driver.session() as session:
        for resource_uid, is_crown_jewel, is_internet_exposed, crown_jewel_type, resource_type in rows:
            props: Dict = {}
            if is_crown_jewel:
                props["is_crown_jewel"] = True
                if crown_jewel_type:
                    props["crown_jewel_type"] = crown_jewel_type
            if is_internet_exposed:
                props["entry_point_type"] = "internet"
            if resource_type:
                # Short canonical name: strip 'service.' prefix if present
                canonical = resource_type.split(".")[-1] if "." in resource_type else resource_type
                props["resource_type_canonical"] = canonical
            if props:
                session.run(
                    "MATCH (r:Resource {uid: $uid, tenant_id: $tid}) SET r += $props",
                    uid=resource_uid, tid=tenant_id, props=props,
                )
                enriched += 1

    return {"enriched_count": enriched}


def _write_t23_crown_jewels_to_posture(
    threat_conn,
    inventory_conn,
    tenant_id: str,
    scan_run_id: str,
) -> Dict:
    """Step 7c: Mark T2/T3 incident target resources as crown jewels in resource_security_posture."""
    cur = threat_conn.cursor()
    cur.execute(
        """
        SELECT DISTINCT target_resource_uid
        FROM threat_incidents
        WHERE tenant_id = %s
          AND scan_run_id = %s
          AND tier IN (2, 3)
          AND target_resource_uid IS NOT NULL
        """,
        (tenant_id, scan_run_id),
    )
    target_uids = [row[0] for row in cur.fetchall()]
    cur.close()

    if not target_uids:
        return {"crown_jewels_written": 0}

    # Fetch resource_type for each uid so we can derive crown_jewel_type
    inv_cur = inventory_conn.cursor()
    inv_cur.execute(
        """
        SELECT resource_uid, resource_type
        FROM resource_security_posture
        WHERE tenant_id = %s
          AND resource_uid = ANY(%s)
        """,
        (tenant_id, target_uids),
    )
    uid_to_type: Dict[str, str] = {row[0]: row[1] for row in inv_cur.fetchall()}

    updated = 0
    for uid in target_uids:
        rtype = uid_to_type.get(uid, "")
        cj_type = _derive_cj_type(rtype)
        inv_cur.execute(
            """
            UPDATE resource_security_posture
            SET is_crown_jewel = TRUE,
                crown_jewel_type = COALESCE(crown_jewel_type, %s)
            WHERE resource_uid = %s
              AND tenant_id = %s
            """,
            (cj_type, uid, tenant_id),
        )
        updated += inv_cur.rowcount

    inventory_conn.commit()
    inv_cur.close()

    return {"crown_jewels_written": updated}


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

        # ── Step 7a: Enrich Neo4j node props from resource_security_posture ───
        # AP-ENHANCE-03: pushes is_crown_jewel + entry_point_type='internet'
        # onto graph nodes so PatternExecutor sees posture-backed signals.
        logger.info("Step 7a: enriching Neo4j nodes from posture")
        try:
            enrich_result = _enrich_neo4j_from_posture(inventory_conn, neo4j_driver, tenant_id)
            stats["posture_enriched"] = enrich_result["enriched_count"]
            logger.info("Step 7a: %s", enrich_result)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Step 7a: posture enrichment failed (non-fatal): %s", exc)
            stats["posture_enriched"] = 0

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

        # ── Step 7c: Write T2/T3 crown jewels back to posture ─────────────────
        # AP-ENHANCE-02: T2/T3 incident targets are definitionally crown jewels.
        logger.info("Step 7c: writing T2/T3 crown jewels to resource_security_posture")
        try:
            cj_posture_result = _write_t23_crown_jewels_to_posture(
                threat_conn, inventory_conn, tenant_id, scan_run_id,
            )
            stats["t23_crown_jewels_written"] = cj_posture_result["crown_jewels_written"]
            logger.info("Step 7c: %s", cj_posture_result)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Step 7c: T2/T3 posture write failed (non-fatal): %s", exc)

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
