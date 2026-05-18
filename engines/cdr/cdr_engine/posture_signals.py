"""
Write CDR engine posture signals to resource_security_posture after cron run.

Called at the end of run_scan.py after CDR findings are persisted.
Only writes posture rows for resources WHERE a CDR actor was observed (AC-11:
resources with no CDR observation are NOT written — absence = false by default).

CDR-owned columns:
    has_active_cdr_actor, cdr_actor_count, cdr_last_seen_at, cdr_ttps

Column ownership: CDR engine writes ONLY these columns.

CDR note: CDR runs on an independent cron schedule, not tied to a main scan_run_id.
We look up the most recent scan_run_id from scan_orchestration for this tenant/account,
and use that for posture writes so attack-path engine can join on it.
If no scan_run_id is found, we skip the posture write.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import psycopg2.extras

from engine_common.db_connections import get_inventory_conn, get_onboarding_conn
from engine_common.posture_writer import upsert_posture_signals

logger = logging.getLogger(__name__)

_BATCH_SIZE = 500


def write_cdr_posture_signals(
    cdr_scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
) -> int:
    """Write CDR actor observations to resource_security_posture.

    Uses cdr_scan_run_id to query CDR findings; resolves the matching
    pipeline scan_run_id from scan_orchestration for cross-engine joins.

    Returns number of posture rows written.
    """
    try:
        pipeline_scan_run_id = _resolve_pipeline_scan_run_id(tenant_id, account_id)
        if not pipeline_scan_run_id:
            logger.info(
                "CDR posture signals: no pipeline scan_run_id found for tenant=%s account=%s — skipping",
                tenant_id, account_id,
            )
            return 0

        signals_by_uid = _aggregate_cdr_signals(cdr_scan_run_id, tenant_id)
        if not signals_by_uid:
            logger.info("CDR posture signals: no actor observations for scan %s", cdr_scan_run_id)
            return 0

        inv_conn = get_inventory_conn()
        try:
            written = _batch_upsert(
                inv_conn, signals_by_uid,
                pipeline_scan_run_id, tenant_id, account_id, provider,
            )
            logger.info(
                "CDR posture signals: wrote %d rows (pipeline_scan=%s, cdr_scan=%s)",
                written, pipeline_scan_run_id, cdr_scan_run_id,
            )
            return written
        finally:
            inv_conn.close()

    except Exception as exc:
        logger.warning("CDR posture signal write failed (non-fatal): %s", exc, exc_info=True)
        return 0


def _resolve_pipeline_scan_run_id(tenant_id: str, account_id: str) -> Optional[str]:
    """Look up the most recent completed pipeline scan_run_id for this tenant/account."""
    try:
        conn = get_onboarding_conn()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT scan_run_id
                    FROM scan_runs
                    WHERE tenant_id = %s AND account_id = %s
                      AND status IN ('completed', 'running')
                    ORDER BY created_at DESC
                    LIMIT 1
                """, (tenant_id, account_id))
                row = cur.fetchone()
                return str(row[0]) if row else None
        finally:
            conn.close()
    except Exception as exc:
        logger.debug("Could not resolve pipeline scan_run_id: %s", exc)
        return None


def _aggregate_cdr_signals(cdr_scan_run_id: str, tenant_id: str) -> dict[str, dict[str, Any]]:
    """Query cdr_findings for actor observations, aggregate per resource_uid.

    Only includes resources where an actor was actually observed (has_active_cdr_actor=True).
    Resources with no CDR observations are intentionally omitted (AC-11).
    """
    try:
        # CDR DB is reached via inventory conn — CDR uses the same shared DB pool
        # The cdr_findings table lives in threat_engine_cdr DB
        from engine_common.db_connections import get_cdr_conn
        cdr_conn = get_cdr_conn()
    except Exception:
        # Fallback: use inventory conn which may have cross-schema access
        logger.debug("get_cdr_conn not available, using inventory conn fallback")
        cdr_conn = get_inventory_conn()

    signals: dict[str, dict[str, Any]] = {}

    try:
        with cdr_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT
                    resource_uid,
                    resource_type,
                    COUNT(DISTINCT actor_principal) AS actor_count,
                    MAX(event_time) AS last_seen_at,
                    array_agg(DISTINCT mitre_technique_id)
                        FILTER (WHERE mitre_technique_id IS NOT NULL)
                        AS ttps
                FROM cdr_findings
                WHERE scan_run_id = %s
                  AND tenant_id = %s
                  AND resource_uid IS NOT NULL
                GROUP BY resource_uid, resource_type
            """, (cdr_scan_run_id, tenant_id))

            for row in cur.fetchall():
                uid = row["resource_uid"]
                ttps = row.get("ttps") or []
                if isinstance(ttps, str):
                    ttps = [ttps]

                signals[uid] = {
                    "resource_type": row.get("resource_type", "cdr_resource"),
                    "has_active_cdr_actor": True,
                    "cdr_actor_count": int(row.get("actor_count") or 1),
                    "cdr_last_seen_at": row.get("last_seen_at"),
                    "cdr_ttps": ttps if ttps else None,
                }

    finally:
        cdr_conn.close()

    return signals


def write_cdr_iam_cross_signal(
    cdr_scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
) -> int:
    """Link CDR actor_principal ARNs to IAM role posture rows.

    Queries cdr_findings for all distinct actor_principal values for this tenant,
    then matches them against iam_findings.resource_uid in the IAM DB.
    When matched: sets has_active_cdr_actor=TRUE + cdr_ttps on the IAM role's
    resource_security_posture row.

    Called AFTER write_cdr_posture_signals() so the CDR cron fully enriches
    both the accessed resource AND the identity used to access it.

    Returns number of IAM posture rows updated.
    """
    try:
        pipeline_scan_run_id = _resolve_pipeline_scan_run_id(tenant_id, account_id)
        if not pipeline_scan_run_id:
            logger.info(
                "CDR-IAM cross-signal: no pipeline scan_run_id for tenant=%s account=%s — skipping",
                tenant_id, account_id,
            )
            return 0

        actor_ttps = _collect_actor_ttps(cdr_scan_run_id, tenant_id)
        if not actor_ttps:
            logger.info("CDR-IAM cross-signal: no actor_principal values in scan %s", cdr_scan_run_id)
            return 0

        # Check whether IAM posture rows exist for this scan — skip if main scan hasn't run
        inv_conn = get_inventory_conn()
        try:
            with inv_conn.cursor() as cur:
                cur.execute(
                    """SELECT COUNT(*) FROM resource_security_posture
                       WHERE scan_run_id = %s AND tenant_id = %s AND is_admin_role = TRUE""",
                    (pipeline_scan_run_id, tenant_id),
                )
                admin_row_count = cur.fetchone()[0]

            if admin_row_count == 0:
                logger.info(
                    "CDR-IAM cross-signal: no IAM posture rows for scan=%s — main pipeline not yet run",
                    pipeline_scan_run_id,
                )
                return 0

            # Match actor ARNs against resource_security_posture.resource_uid scoped to tenant
            updated = 0
            for actor_principal, ttps in actor_ttps.items():
                import json as _json
                with inv_conn.cursor() as cur:
                    cur.execute(
                        """UPDATE resource_security_posture
                           SET has_active_cdr_actor = TRUE,
                               cdr_ttps = %s,
                               updated_at = NOW()
                           WHERE resource_uid = %s
                             AND tenant_id = %s
                             AND scan_run_id = %s""",
                        (
                            _json.dumps(list(ttps)) if ttps else None,
                            actor_principal,
                            tenant_id,
                            pipeline_scan_run_id,
                        ),
                    )
                    updated += cur.rowcount

            inv_conn.commit()
            logger.info(
                "CDR-IAM cross-signal: matched %d actor principals → %d IAM posture rows updated "
                "(tenant=%s scan=%s)",
                len(actor_ttps), updated, tenant_id, pipeline_scan_run_id,
            )
            return updated

        finally:
            inv_conn.close()

    except Exception as exc:
        logger.warning("CDR-IAM cross-signal write failed (non-fatal): %s", exc, exc_info=True)
        return 0


def _collect_actor_ttps(cdr_scan_run_id: str, tenant_id: str) -> dict[str, set[str]]:
    """Return {actor_principal: {mitre_technique_ids}} from cdr_findings for this scan."""
    try:
        from engine_common.db_connections import get_cdr_conn
        cdr_conn = get_cdr_conn()
    except Exception:
        cdr_conn = get_inventory_conn()

    actor_ttps: dict[str, set[str]] = {}

    try:
        with cdr_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """SELECT actor_principal,
                          array_agg(DISTINCT mitre_technique_id)
                              FILTER (WHERE mitre_technique_id IS NOT NULL) AS ttps
                   FROM cdr_findings
                   WHERE scan_run_id = %s
                     AND tenant_id = %s
                     AND actor_principal IS NOT NULL
                   GROUP BY actor_principal""",
                (cdr_scan_run_id, tenant_id),
            )
            for row in cur.fetchall():
                principal = row["actor_principal"]
                ttps = row.get("ttps") or []
                if isinstance(ttps, str):
                    ttps = [ttps]
                actor_ttps[principal] = set(ttps)
    finally:
        cdr_conn.close()

    return actor_ttps


def _batch_upsert(
    inv_conn: Any,
    signals_by_uid: dict[str, dict[str, Any]],
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
) -> int:
    """Upsert signals in batches. Returns total rows written."""
    uids = list(signals_by_uid.keys())
    written = 0

    for i in range(0, len(uids), _BATCH_SIZE):
        batch = uids[i : i + _BATCH_SIZE]
        for uid in batch:
            sig = signals_by_uid[uid]
            resource_type = sig.pop("resource_type", "cdr_resource")
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
