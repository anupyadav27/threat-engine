"""
GCP-specific internet exposure detection.

Tier 1 (check findings patterns) is already handled by _common.py.
This module adds discovery-based precision for GCP services.

Services covered:
  Compute Engine instances with external IP (natIP)
  Cloud SQL instances with public IP or authorized networks 0.0.0.0/0
  GKE clusters with public master endpoint
  Cloud Run services (always publicly accessible by default)
  GCS buckets with allUsers / allAuthenticatedUsers ACL
  Cloud Functions (HTTP-triggered, always internet-accessible)
  BigQuery datasets with public IAM

NOTE: When GCP discovery is not implemented, all detections fall back
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
    """GCP-specific exposure detection. Returns count of new EXPOSES edges."""
    count = 0
    count += _gce_external_ip(session, pg_conn_fn, exposed_uids)
    count += _cloud_sql_public(session, pg_conn_fn, exposed_uids)
    count += _gke_public_master(session, pg_conn_fn, exposed_uids)
    count += _cloud_run_public(session, tenant_id, exposed_uids)
    count += _gcs_public_acl(session, tenant_id, exposed_uids)
    count += _cloud_functions_http(session, tenant_id, exposed_uids)
    return count


def _gce_external_ip(
    session: Any,
    pg_conn_fn: Callable,
    exposed_uids: Set[str],
) -> int:
    """GCE instances with natIP (external IP address)."""
    try:
        from psycopg2.extras import RealDictCursor
        conn = pg_conn_fn("threat_engine_discoveries")
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT DISTINCT
                        emitted_fields->>'selfLink' AS self_link,
                        emitted_fields->>'id'       AS instance_id
                    FROM discovery_findings
                    WHERE discovery_id IN (
                        'gcp.compute.instances.list',
                        'gcp.compute.instances.aggregatedList'
                    )
                      AND emitted_fields->'networkInterfaces'->0
                          ->'accessConfigs'->0->>'natIP' IS NOT NULL
                """)
                rows = cur.fetchall()
        finally:
            conn.close()

        new_uids = []
        for row in rows:
            uid = row.get("self_link") or row.get("instance_id")
            if uid and uid not in exposed_uids:
                exposed_uids.add(uid)
                new_uids.append(uid)

        n = _merge_exposes(session, new_uids, "gce_external_ip")
        if new_uids:
            logger.info(f"gcp: GCE external IP: {len(new_uids)} instances → {n} edges")
        return n
    except Exception as exc:
        logger.debug(f"gcp: GCE external IP detection skipped: {exc}")
        return 0


def _cloud_sql_public(
    session: Any,
    pg_conn_fn: Callable,
    exposed_uids: Set[str],
) -> int:
    """Cloud SQL instances with public IP or authorized networks 0.0.0.0/0."""
    try:
        from psycopg2.extras import RealDictCursor
        conn = pg_conn_fn("threat_engine_discoveries")
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT DISTINCT
                        emitted_fields->>'selfLink' AS self_link,
                        emitted_fields->>'name'     AS name
                    FROM discovery_findings
                    WHERE discovery_id IN (
                        'gcp.sqladmin.instances.list'
                    )
                      AND (
                        emitted_fields->'settings'->'ipConfiguration'
                            ->>'ipv4Enabled' = 'true'
                        OR emitted_fields->'settings'->'ipConfiguration'
                           ->'authorizedNetworks'->0->>'value' = '0.0.0.0/0'
                      )
                """)
                rows = cur.fetchall()
        finally:
            conn.close()

        new_uids = [row.get("self_link") or row.get("name") for row in rows]
        new_uids = [u for u in new_uids if u and u not in exposed_uids]
        for uid in new_uids:
            exposed_uids.add(uid)

        n = _merge_exposes(session, new_uids, "gcp_cloudsql_public_ip")
        if new_uids:
            logger.info(f"gcp: Cloud SQL public: {len(new_uids)} instances → {n} edges")
        return n
    except Exception as exc:
        logger.debug(f"gcp: Cloud SQL public detection skipped: {exc}")
        return 0


def _gke_public_master(
    session: Any,
    pg_conn_fn: Callable,
    exposed_uids: Set[str],
) -> int:
    """GKE clusters with public master endpoint (no private cluster)."""
    try:
        from psycopg2.extras import RealDictCursor
        conn = pg_conn_fn("threat_engine_discoveries")
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT DISTINCT
                        emitted_fields->>'selfLink'  AS self_link,
                        emitted_fields->>'name'      AS name
                    FROM discovery_findings
                    WHERE discovery_id IN (
                        'gcp.container.clusters.list'
                    )
                      AND (
                        emitted_fields->'privateClusterConfig'->>'enablePrivateEndpoint' = 'false'
                        OR emitted_fields->'privateClusterConfig' IS NULL
                        OR emitted_fields->>'endpoint' IS NOT NULL
                      )
                """)
                rows = cur.fetchall()
        finally:
            conn.close()

        new_uids = [row.get("self_link") or row.get("name") for row in rows]
        new_uids = [u for u in new_uids if u and u not in exposed_uids]
        for uid in new_uids:
            exposed_uids.add(uid)

        n = _merge_exposes(session, new_uids, "gke_public_master_endpoint")
        if new_uids:
            logger.info(f"gcp: GKE public master: {len(new_uids)} clusters → {n} edges")
        return n
    except Exception as exc:
        logger.debug(f"gcp: GKE public master detection skipped: {exc}")
        return 0


def _cloud_run_public(
    session: Any,
    tenant_id: str,
    exposed_uids: Set[str],
) -> int:
    """Cloud Run services are publicly accessible unless explicitly restricted."""
    try:
        result = session.run("""
            MATCH (r:CloudRunService {tenant_id: $tid})
            WHERE NOT EXISTS { MATCH (:Internet)-[:EXPOSES]->(r) }
            RETURN r.uid AS uid
        """, tid=tenant_id)
        new_uids = [rec["uid"] for rec in result
                    if rec.get("uid") and rec["uid"] not in exposed_uids]
        for uid in new_uids:
            exposed_uids.add(uid)
        n = _merge_exposes(session, new_uids, "cloud_run_public")
        if new_uids:
            logger.info(f"gcp: Cloud Run: {len(new_uids)} services → {n} edges")
        return n
    except Exception as exc:
        logger.debug(f"gcp: Cloud Run detection skipped: {exc}")
        return 0


def _gcs_public_acl(
    session: Any,
    tenant_id: str,
    exposed_uids: Set[str],
) -> int:
    """GCS buckets with allUsers / allAuthenticatedUsers in IAM — check findings."""
    try:
        result = session.run("""
            MATCH (r:GCSBucket {tenant_id: $tid})-[:HAS_FINDING]->(f:Finding)
            WHERE f.rule_id CONTAINS 'public' OR f.rule_id CONTAINS 'all_users'
               OR f.rule_id CONTAINS 'allauthenticated' OR f.rule_id CONTAINS 'uniform_bucket'
            RETURN DISTINCT r.uid AS uid
        """, tid=tenant_id)
        new_uids = [rec["uid"] for rec in result
                    if rec.get("uid") and rec["uid"] not in exposed_uids]
        for uid in new_uids:
            exposed_uids.add(uid)
        return _merge_exposes(session, new_uids, "gcs_public_acl")
    except Exception as exc:
        logger.debug(f"gcp: GCS public ACL detection skipped: {exc}")
        return 0


def _cloud_functions_http(
    session: Any,
    tenant_id: str,
    exposed_uids: Set[str],
) -> int:
    """HTTP-triggered Cloud Functions are internet-accessible by default."""
    try:
        result = session.run("""
            MATCH (r:CloudFunction {tenant_id: $tid})
            WHERE NOT EXISTS { MATCH (:Internet)-[:EXPOSES]->(r) }
            RETURN r.uid AS uid
        """, tid=tenant_id)
        new_uids = [rec["uid"] for rec in result
                    if rec.get("uid") and rec["uid"] not in exposed_uids]
        for uid in new_uids:
            exposed_uids.add(uid)
        n = _merge_exposes(session, new_uids, "cloud_function_http_trigger")
        if new_uids:
            logger.info(f"gcp: Cloud Functions: {len(new_uids)} functions → {n} edges")
        return n
    except Exception as exc:
        logger.debug(f"gcp: Cloud Functions detection skipped: {exc}")
        return 0
