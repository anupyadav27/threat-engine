"""
OCI-specific internet exposure detection.

Tier 1 (check findings patterns) is already handled by _common.py.
This module adds discovery-based precision for OCI services.

Services covered:
  Compute instances with public IP assignment
  Autonomous Database with public endpoint
  Object Storage buckets with public access
  Load Balancers (internet-facing by default)

NOTE: When OCI discovery is not implemented, all detections fall back
gracefully to the check findings already handled by _common.py.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, List, Set

logger = logging.getLogger(__name__)


def _merge_exposes(session: Any, uids: List[str], reason: str) -> int:
    count = 0
    for i in range(0, len(uids), 200):
        chunk = uids[i:i + 200]
        r = session.run("""
            UNWIND $uids AS uid
            MATCH (i:Internet {uid: 'INTERNET'})
            MATCH (r:Resource {uid: uid})
            MERGE (i)-[e:EXPOSES]->(r)
            SET e.reason = $reason
            RETURN COUNT(e) AS c
        """, uids=chunk, reason=reason)
        rec = r.single()
        count += rec["c"] if rec else 0
    return count


def detect(
    session: Any,
    tenant_id: str,
    pg_conn_fn: Callable,
    exposed_uids: Set[str],
) -> int:
    """OCI-specific exposure detection. Returns count of new EXPOSES edges."""
    count = 0
    count += _compute_public_ip(session, pg_conn_fn, exposed_uids)
    count += _autonomous_db_public(session, tenant_id, exposed_uids)
    count += _object_storage_public(session, tenant_id, exposed_uids)
    count += _load_balancer_public(session, tenant_id, exposed_uids)
    return count


def _compute_public_ip(
    session: Any,
    pg_conn_fn: Callable,
    exposed_uids: Set[str],
) -> int:
    """OCI Compute instances with a public IP address."""
    try:
        from psycopg2.extras import RealDictCursor
        conn = pg_conn_fn("threat_engine_discoveries")
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT DISTINCT
                        emitted_fields->>'id' AS instance_id
                    FROM discovery_findings
                    WHERE discovery_id IN (
                        'oci.compute.instances.list',
                        'oci.core.instances'
                    )
                      AND emitted_fields->>'publicIp' IS NOT NULL
                      AND emitted_fields->>'publicIp' NOT IN ('', 'null')
                """)
                rows = cur.fetchall()
        finally:
            conn.close()

        new_uids = [row["instance_id"] for row in rows
                    if row.get("instance_id") and row["instance_id"] not in exposed_uids]
        for uid in new_uids:
            exposed_uids.add(uid)
        n = _merge_exposes(session, new_uids, "oci_compute_public_ip")
        if new_uids:
            logger.info(f"oci: Compute public IP: {len(new_uids)} instances → {n} edges")
        return n
    except Exception as exc:
        logger.debug(f"oci: Compute public IP detection skipped: {exc}")
        return 0


def _autonomous_db_public(
    session: Any,
    tenant_id: str,
    exposed_uids: Set[str],
) -> int:
    """OCI Autonomous Database with public endpoint — check findings."""
    try:
        result = session.run("""
            MATCH (r:AutonomousDatabase {tenant_id: $tid})-[:HAS_FINDING]->(f:Finding)
            WHERE f.rule_id CONTAINS 'public' OR f.rule_id CONTAINS 'network_access'
               OR f.rule_id CONTAINS 'private_endpoint'
            RETURN DISTINCT r.uid AS uid
        """, tid=tenant_id)
        new_uids = [rec["uid"] for rec in result
                    if rec.get("uid") and rec["uid"] not in exposed_uids]
        for uid in new_uids:
            exposed_uids.add(uid)
        return _merge_exposes(session, new_uids, "oci_autonomous_db_public")
    except Exception as exc:
        logger.debug(f"oci: Autonomous DB detection skipped: {exc}")
        return 0


def _object_storage_public(
    session: Any,
    tenant_id: str,
    exposed_uids: Set[str],
) -> int:
    """OCI Object Storage buckets with public access — check findings."""
    try:
        result = session.run("""
            MATCH (r:ObjectStorageBucket {tenant_id: $tid})-[:HAS_FINDING]->(f:Finding)
            WHERE f.rule_id CONTAINS 'public' OR f.rule_id CONTAINS 'access_type'
               OR f.rule_id CONTAINS 'objectread' OR f.rule_id CONTAINS 'anonymous'
            RETURN DISTINCT r.uid AS uid
        """, tid=tenant_id)
        new_uids = [rec["uid"] for rec in result
                    if rec.get("uid") and rec["uid"] not in exposed_uids]
        for uid in new_uids:
            exposed_uids.add(uid)
        return _merge_exposes(session, new_uids, "oci_object_storage_public")
    except Exception as exc:
        logger.debug(f"oci: Object Storage detection skipped: {exc}")
        return 0


def _load_balancer_public(
    session: Any,
    tenant_id: str,
    exposed_uids: Set[str],
) -> int:
    """OCI Load Balancers are internet-facing by default unless internal."""
    try:
        result = session.run("""
            MATCH (r:Resource {tenant_id: $tid})
            WHERE r.resource_type IN ['oci.load_balancer', 'oci.loadbalancer']
              AND NOT EXISTS { MATCH (:Internet)-[:EXPOSES]->(r) }
            RETURN r.uid AS uid
        """, tid=tenant_id)
        new_uids = [rec["uid"] for rec in result
                    if rec.get("uid") and rec["uid"] not in exposed_uids]
        for uid in new_uids:
            exposed_uids.add(uid)
        return _merge_exposes(session, new_uids, "oci_load_balancer_public")
    except Exception as exc:
        logger.debug(f"oci: Load Balancer detection skipped: {exc}")
        return 0
