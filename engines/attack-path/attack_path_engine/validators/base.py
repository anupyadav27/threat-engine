"""Base class for all attack edge validators."""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import psycopg2.extras

logger = logging.getLogger("attack-path.validators")

_BATCH_SIZE = 500

# Synthetic node for internet origin (all CSPs)
INTERNET_NODE = "pseudo:internet:global"


def _upsert_attack_edges(
    conn: Any,
    edges: List[Dict[str, Any]],
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
) -> int:
    """Upsert validated attack edges into asset_relationships.

    ON CONFLICT (scan_run_id, tenant_id, source_uid, relation_type, target_uid)
    updates attack-edge columns — a later run always wins.
    """
    if not edges:
        return 0

    # Deduplicate by (source_uid, relation_type, target_uid) — last write wins.
    # Prevents ON CONFLICT cardinality violations when validators emit duplicate pairs.
    seen: dict = {}
    for e in edges:
        key = (e["source_uid"], e["relation_type"], e["target_uid"])
        seen[key] = e
    edges = list(seen.values())

    sql = """
        INSERT INTO asset_relationships (
            scan_run_id, tenant_id, account_id, provider,
            source_uid, source_type, target_uid, target_type,
            relation_type, relation_metadata,
            relationship_category, attack_path_category,
            evidence_field_path, evidence_value,
            resolution_status, confidence,
            is_attack_edge, attack_edge_type,
            validation_status, validation_rule_id, attack_evidence
        )
        VALUES %s
        ON CONFLICT (scan_run_id, tenant_id, source_uid, relation_type, target_uid)
        DO UPDATE SET
            is_attack_edge     = TRUE,
            attack_edge_type   = EXCLUDED.attack_edge_type,
            validation_status  = EXCLUDED.validation_status,
            validation_rule_id = EXCLUDED.validation_rule_id,
            attack_evidence    = EXCLUDED.attack_evidence,
            last_seen_at       = NOW()
    """

    rows = []
    for e in edges:
        meta = e.get("relation_metadata") or {}
        if isinstance(meta, dict):
            meta = psycopg2.extras.Json(meta)
        evidence = e.get("attack_evidence") or {}
        if isinstance(evidence, dict):
            evidence = psycopg2.extras.Json(evidence)
        rows.append((
            scan_run_id, tenant_id, account_id, provider,
            e["source_uid"], e.get("source_type") or "",
            e["target_uid"], e.get("target_type") or "",
            e["relation_type"], meta,
            e.get("relationship_category") or "attack",
            e.get("attack_path_category") or "lateral_movement",
            e.get("evidence_field_path"),
            e.get("evidence_value"),
            "validated", e.get("confidence") or "high",
            True, e["attack_edge_type"],
            "validated", e["validation_rule_id"], evidence,
        ))

    total = 0
    for i in range(0, len(rows), _BATCH_SIZE):
        batch = rows[i:i + _BATCH_SIZE]
        with conn.cursor() as cur:
            psycopg2.extras.execute_values(cur, sql, batch, page_size=_BATCH_SIZE)
        conn.commit()
        total += len(batch)

    return total
