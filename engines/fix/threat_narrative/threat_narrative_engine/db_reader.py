"""
Database reader for the Attack Path Narrative Engine.

Reads all context data needed for LLM narrative generation from:
  - attack_paths + attack_path_nodes (attack_path DB) — primary source
  - check_findings + rule_control_mapping + compliance_frameworks (check DB)
  - discovery_findings (discoveries DB) — resource name/tags

All queries are parameterized — no f-string SQL.
JSONB columns are auto-deserialized by psycopg2; never call json.loads() on them.
All missing fields default to safe fallback values — callers receive a fully-populated dict.
"""

import logging
import os
from typing import Any

import psycopg2
import psycopg2.extras

from threat_narrative_engine.prompt_templates import (
    build_tactic_sequence_display,
    build_mitre_display,
)

logger = logging.getLogger("threat_narrative")


# ── Connection factories ───────────────────────────────────────────────────────

def _resolve_password(prefix: str) -> str:
    p = prefix.upper()
    return (
        os.getenv(f"{p}_DB_PASSWORD")
        or os.getenv("DB_PASSWORD")
        or os.getenv("DISCOVERIES_DB_PASSWORD", "")
    )


def _make_conn(prefix: str, default_db: str) -> psycopg2.extensions.connection:
    p = prefix.upper()
    return psycopg2.connect(
        host=os.getenv(f"{p}_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv(f"{p}_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv(f"{p}_DB_NAME", default_db),
        user=os.getenv(f"{p}_DB_USER", os.getenv("DB_USER", "postgres")),
        password=_resolve_password(p),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
        connect_timeout=10,
    )


# ── Path ID listing ────────────────────────────────────────────────────────────

def list_path_ids(scan_run_id: str) -> list[str]:
    """Return top attack path IDs for a scan — critical and high severity, by score.

    Args:
        scan_run_id: The pipeline scan run UUID.

    Returns:
        List of path_id strings (max 20). Empty list if none found.

    Raises:
        psycopg2.OperationalError: If attack_path DB is unreachable.
    """
    conn = _make_conn("ATTACK_PATH", "threat_engine_attack_path")
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT path_id
                FROM attack_paths
                WHERE scan_run_id = %s
                  AND severity IN ('critical', 'high')
                ORDER BY path_score DESC
                LIMIT 20
                """,
                (scan_run_id,),
            )
            rows = cur.fetchall()
        return [r[0] for r in rows]
    finally:
        conn.close()


# ── Main context reader ────────────────────────────────────────────────────────

def read_path_context(scan_run_id: str, path_id: str) -> dict[str, Any]:
    """Read all data needed for narrative generation for one attack path.

    Queries (in order):
      1. attack_paths: chain_type, entry_point_uid, crown_jewel_uid,
         entry_point_type, crown_jewel_type, severity, path_score,
         data_classification, mitre_techniques, tactic_sequence,
         misconfig_count, threat_count, blast_radius_count,
         attack_vector_type, confidence_level
      2. attack_path_nodes: hop evidence summary (misconfigs, cves)
      3. check_findings + compliance: framework names
      4. discovery_findings: entry/crown jewel resource names

    Args:
        scan_run_id: The pipeline scan run UUID.
        path_id: The specific attack path ID.

    Returns:
        Dict with all fields needed by prompt_templates. Any missing field
        defaults to a safe fallback. Never returns None for a prompt field.
    """
    ctx: dict[str, Any] = {
        "path_id": path_id,
        "scan_run_id": scan_run_id,
        # attack_paths fields
        "chain_type": "",
        "entry_point_uid": "",
        "crown_jewel_uid": "",
        "entry_point_type": "unknown",
        "crown_jewel_type": "unknown",
        "severity": "medium",
        "path_score": 0,
        "data_classification": "unknown classification",
        "mitre_techniques": [],
        "tactic_sequence": [],
        "tactic_sequence_display": "multi-stage attack",
        "misconfig_count": 0,
        "threat_count": 0,
        "blast_radius_count": 0,
        "attack_vector_type": "T1",
        "confidence_level": "speculative",
        "attack_name": "",
        # compliance fields
        "framework_list": "none identified",
        # discovery fields
        "entry_resource_name": "",
        "crown_jewel_name": "",
    }

    # ── 1. attack_paths ───────────────────────────────────────────────────────
    try:
        conn = _make_conn("ATTACK_PATH", "threat_engine_attack_path")
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT
                        path_id, chain_type,
                        entry_point_uid, crown_jewel_uid,
                        entry_point_type, crown_jewel_type,
                        severity, path_score,
                        data_classification,
                        attack_technique_chain, node_uids,
                        misconfig_count, threat_count,
                        confidence_level, attack_name
                    FROM attack_paths
                    WHERE path_id = %s
                    """,
                    (path_id,),
                )
                row = cur.fetchone()
        finally:
            conn.close()

        if row:
            ctx["chain_type"] = row.get("chain_type") or ""
            ctx["entry_point_uid"] = row.get("entry_point_uid") or ""
            ctx["crown_jewel_uid"] = row.get("crown_jewel_uid") or ""
            ctx["entry_point_type"] = row.get("entry_point_type") or "unknown"
            ctx["crown_jewel_type"] = row.get("crown_jewel_type") or "unknown"
            ctx["severity"] = row.get("severity") or "medium"
            ctx["path_score"] = row.get("path_score") or 0
            ctx["data_classification"] = row.get("data_classification") or "unknown classification"
            ctx["misconfig_count"] = row.get("misconfig_count") or 0
            ctx["threat_count"] = row.get("threat_count") or 0
            ctx["confidence_level"] = row.get("confidence_level") or "speculative"
            ctx["attack_name"] = row.get("attack_name") or ""
            # Derive tactic_sequence from attack_technique_chain JSONB
            # attack_technique_chain is [{name, id, tactic}, ...] or list of tactic strings
            tech_chain = row.get("attack_technique_chain") or []
            if isinstance(tech_chain, list):
                tactics = []
                for t in tech_chain:
                    if isinstance(t, dict):
                        tactic = t.get("tactic") or t.get("name") or ""
                        if tactic:
                            tactics.append(tactic)
                    elif isinstance(t, str) and t:
                        tactics.append(t)
                ctx["tactic_sequence"] = tactics
            ctx["tactic_sequence_display"] = build_tactic_sequence_display(ctx["tactic_sequence"])
            # blast_radius approximated from node_uids length
            node_uids = row.get("node_uids") or []
            ctx["blast_radius_count"] = len(node_uids) if isinstance(node_uids, list) else 0
            ctx["attack_vector_type"] = "T1"  # not stored in DB — default
        else:
            logger.warning(
                "attack_paths row not found",
                extra={"path_id": path_id},
            )
    except psycopg2.OperationalError as exc:
        logger.error(
            "Failed to connect to attack_path DB",
            extra={"path_id": path_id, "error": str(exc)},
        )
        raise

    # ── 2. attack_path_nodes — hop evidence summary ───────────────────────────
    try:
        conn = _make_conn("ATTACK_PATH", "threat_engine_attack_path")
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT COUNT(*) AS hop_count
                    FROM attack_path_nodes
                    WHERE path_id = %s
                    """,
                    (path_id,),
                )
                row = cur.fetchone()
        finally:
            conn.close()
        if row:
            ctx["hop_count"] = row[0] or 0
    except Exception as exc:
        logger.warning(
            "Could not read attack_path_nodes — using defaults",
            extra={"path_id": path_id, "error": str(exc)},
        )

    # ── 3. check_findings + compliance (join on crown jewel resource) ─────────
    crown_jewel_uid = ctx["crown_jewel_uid"]
    if crown_jewel_uid:
        try:
            conn = _make_conn("CHECK", "threat_engine_check")
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT DISTINCT cf.name AS framework_name
                        FROM check_findings chf
                        JOIN rule_control_mapping rcm ON chf.rule_id = rcm.rule_id
                        JOIN compliance_frameworks cf ON rcm.framework_id = cf.framework_id
                        WHERE chf.scan_run_id = %s
                          AND chf.resource_uid = %s
                          AND chf.status = 'FAIL'
                        LIMIT 10
                        """,
                        (scan_run_id, crown_jewel_uid),
                    )
                    rows = cur.fetchall()
            finally:
                conn.close()
            if rows:
                names = [r[0] for r in rows if r[0]]
                if names:
                    ctx["framework_list"] = ", ".join(sorted(set(names)))
        except psycopg2.OperationalError as exc:
            logger.warning(
                "Could not read compliance frameworks — using defaults",
                extra={"path_id": path_id, "error": str(exc)},
            )
        except Exception as exc:
            logger.warning(
                "Unexpected error reading compliance frameworks",
                extra={"path_id": path_id, "error": str(exc)},
            )

    # ── 4. discovery_findings — resource names ────────────────────────────────
    for uid_key, name_key in [
        ("entry_point_uid", "entry_resource_name"),
        ("crown_jewel_uid", "crown_jewel_name"),
    ]:
        uid = ctx.get(uid_key, "")
        if not uid:
            continue
        try:
            conn = _make_conn("DISCOVERIES", "threat_engine_discoveries")
            try:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute(
                        """
                        SELECT resource_name
                        FROM discovery_findings
                        WHERE scan_run_id = %s AND resource_uid = %s
                        LIMIT 1
                        """,
                        (scan_run_id, uid),
                    )
                    row = cur.fetchone()
            finally:
                conn.close()
            if row and row.get("resource_name"):
                ctx[name_key] = row["resource_name"]
        except Exception as exc:
            logger.warning(
                "Could not read discovery resource name",
                extra={"uid": uid, "error": str(exc)},
            )

    return ctx


# ── Legacy alias for backward compatibility ────────────────────────────────────

def list_detection_ids(scan_run_id: str) -> list[str]:
    """Alias for list_path_ids — kept for backward compatibility."""
    return list_path_ids(scan_run_id)


def read_detection_context(scan_run_id: str, detection_id: str) -> dict[str, Any]:
    """Alias for read_path_context — kept for backward compatibility."""
    return read_path_context(scan_run_id, detection_id)
