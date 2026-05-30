"""
Write CDR-observed actor→resource access as OBSERVED_ACCESS edges to asset_relationships.

Called at the end of run_scan.py after CDR posture signals are written.

Edge semantics:
  source_uid = actor_principal ARN (IAM identity that performed the action)
  target_uid = resource_uid      (cloud resource that was accessed)
  relation_type = OBSERVED_ACCESS

Uses the pipeline scan_run_id (not CDR scan_run_id) so attack-path engine can
traverse these edges alongside structural edges from the same pipeline run.

Severity high/critical → is_attack_edge=True (traversed by attack-path graph).
Severity medium/low   → is_attack_edge=False (informational edge only).
"""

from __future__ import annotations

import logging
from typing import Any

import psycopg2.extras

from engine_common.db_connections import get_cdr_conn, get_di_conn
from engine_common.relationship_writer import upsert_asset_relationships

from cdr_engine.posture_signals import _resolve_pipeline_scan_run_id

logger = logging.getLogger(__name__)

_ATTACK_SEVERITIES = {"critical", "high"}


def write_behavioral_edges(
    cdr_scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
) -> int:
    """Write OBSERVED_ACCESS edges from CDR findings to asset_relationships.

    Returns number of edges written (0 on error or nothing to write).
    """
    pipeline_scan_run_id = _resolve_pipeline_scan_run_id(tenant_id, account_id)
    if not pipeline_scan_run_id:
        logger.info(
            "CDR behavioral edges: no pipeline scan_run_id for tenant=%s account=%s — skipping",
            tenant_id, account_id,
        )
        return 0

    edges = _build_edges(cdr_scan_run_id, tenant_id, account_id, provider)
    if not edges:
        logger.info("CDR behavioral edges: no actor→resource pairs in scan %s", cdr_scan_run_id)
        return 0

    try:
        di_conn = get_di_conn()
        try:
            written = upsert_asset_relationships(
                conn=di_conn,
                edges=edges,
                scan_run_id=pipeline_scan_run_id,
                tenant_id=tenant_id,
                account_id=account_id,
                provider=provider,
            )
            logger.info(
                "CDR behavioral edges: wrote %d OBSERVED_ACCESS edges "
                "(pipeline_scan=%s, cdr_scan=%s, tenant=%s)",
                written, pipeline_scan_run_id, cdr_scan_run_id, tenant_id,
            )
            return written
        finally:
            di_conn.close()
    except Exception as exc:
        logger.warning("CDR behavioral edges write failed (non-fatal): %s", exc, exc_info=True)
        return 0


def _build_edges(
    cdr_scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
) -> list[dict[str, Any]]:
    """Aggregate (actor_principal, resource_uid) pairs from cdr_findings into edge dicts."""
    try:
        cdr_conn = get_cdr_conn()
    except Exception:
        logger.debug("get_cdr_conn not available, using di conn fallback")
        cdr_conn = get_di_conn()

    edges: list[dict[str, Any]] = []

    try:
        with cdr_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT
                    actor_principal,
                    actor_principal_type,
                    resource_uid,
                    resource_type,
                    MIN(severity) FILTER (WHERE LOWER(severity) IN ('critical','high'))
                        AS has_high_severity,
                    array_agg(DISTINCT mitre_technique_id)
                        FILTER (WHERE mitre_technique_id IS NOT NULL) AS techs,
                    array_agg(DISTINCT action_category)
                        FILTER (WHERE action_category IS NOT NULL) AS action_categories,
                    MAX(event_time) AS last_seen_at,
                    COUNT(*) AS event_count
                FROM cdr_findings
                WHERE scan_run_id = %s
                  AND tenant_id = %s
                  AND actor_principal IS NOT NULL
                  AND actor_principal != ''
                  AND resource_uid IS NOT NULL
                  AND resource_uid != ''
                  AND actor_principal != resource_uid
                GROUP BY actor_principal, actor_principal_type, resource_uid, resource_type
                """,
                (cdr_scan_run_id, tenant_id),
            )
            rows = cur.fetchall()
    finally:
        cdr_conn.close()

    for row in rows:
        actor = row["actor_principal"]
        resource = row["resource_uid"]
        is_attack = row["has_high_severity"] is not None
        techs = row.get("techs") or []
        if isinstance(techs, str):
            techs = [techs]
        categories = row.get("action_categories") or []

        edges.append({
            "source_uid": actor,
            "source_type": row.get("actor_principal_type") or "iam_identity",
            "target_uid": resource,
            "target_type": row.get("resource_type") or "",
            "relation_type": "OBSERVED_ACCESS",
            "relationship_category": "behavioral",
            "attack_path_category": "lateral_movement" if is_attack else None,
            "evidence_field_path": "cdr_findings.actor_principal",
            "evidence_value": actor[:512],
            "is_attack_edge": is_attack,
            "resolution_status": "validated",
            "confidence": "high" if is_attack else "medium",
            "relation_metadata": {
                "mitre_techniques": techs[:5],
                "action_categories": categories[:5],
                "event_count": int(row.get("event_count") or 1),
                "last_seen_at": str(row.get("last_seen_at") or ""),
                "provider": provider,
            },
        })

    return edges
