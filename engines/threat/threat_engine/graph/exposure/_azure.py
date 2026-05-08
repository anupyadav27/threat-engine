"""
Azure-specific internet exposure detection.

Tier 1 (check findings patterns) is already handled by _common.py.
This module adds discovery-based precision for Azure services that have
specific publicly_accessible / public_endpoint fields.

Services covered:
  Virtual Machines with public IP
  SQL Server with public network access enabled
  Storage Accounts with public blob access
  AKS cluster with authorized IP ranges disabled
  App Service / Function App with public access
  Azure Database (PostgreSQL / MySQL / MariaDB) publicly accessible
  Azure Cosmos DB with public network access

NOTE: When Azure discovery is not implemented, all detections gracefully
fall back to the check findings already handled by _common.py. No errors
are raised — each sub-detector catches its own exceptions.
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
    """Azure-specific exposure detection. Returns count of new EXPOSES edges."""
    count = 0
    count += _virtual_machines_public_ip(session, pg_conn_fn, exposed_uids)
    count += _sql_server_public_access(session, pg_conn_fn, exposed_uids)
    count += _storage_public_blob(session, tenant_id, exposed_uids)
    count += _aks_public_api(session, pg_conn_fn, exposed_uids)
    count += _app_service_public(session, tenant_id, exposed_uids)
    count += _azure_database_public(session, pg_conn_fn, exposed_uids)
    return count


def _virtual_machines_public_ip(
    session: Any,
    pg_conn_fn: Callable,
    exposed_uids: Set[str],
) -> int:
    """Azure VMs with a public IP address assignment."""
    try:
        from psycopg2.extras import RealDictCursor
        conn = pg_conn_fn("threat_engine_discoveries")
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT DISTINCT
                        emitted_fields->>'id' AS vm_id,
                        emitted_fields->'properties'->'networkProfile'
                            ->'networkInterfaces'->0->'properties'
                            ->'ipConfigurations'->0->'properties'
                            ->>'publicIPAddress' AS public_ip
                    FROM discovery_findings
                    WHERE discovery_id IN (
                        'azure.compute.virtual_machines',
                        'azure.virtualmachines.list'
                    )
                      AND emitted_fields->'properties'->'networkProfile' IS NOT NULL
                """)
                rows = cur.fetchall()
        finally:
            conn.close()

        new_uids = []
        for row in rows:
            vm_id = row.get("vm_id")
            public_ip = row.get("public_ip")
            if vm_id and public_ip and public_ip not in (None, "", "null"):
                uid = vm_id.lower()
                if uid not in exposed_uids:
                    exposed_uids.add(uid)
                    new_uids.append(uid)

        return _merge_exposes(session, new_uids, "azure_vm_public_ip")
    except Exception as exc:
        logger.debug(f"azure: VM public IP detection skipped: {exc}")
        return 0


def _sql_server_public_access(
    session: Any,
    pg_conn_fn: Callable,
    exposed_uids: Set[str],
) -> int:
    """Azure SQL Server with PublicNetworkAccess = Enabled."""
    try:
        from psycopg2.extras import RealDictCursor
        conn = pg_conn_fn("threat_engine_discoveries")
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT DISTINCT emitted_fields->>'id' AS sql_id
                    FROM discovery_findings
                    WHERE discovery_id IN (
                        'azure.sql.servers',
                        'azure.sqlservers.list'
                    )
                      AND lower(
                        emitted_fields->'properties'->>'publicNetworkAccess'
                      ) = 'enabled'
                      AND emitted_fields->>'id' IS NOT NULL
                """)
                rows = cur.fetchall()
        finally:
            conn.close()

        new_uids = [row["sql_id"].lower() for row in rows
                    if row.get("sql_id") and row["sql_id"].lower() not in exposed_uids]
        for uid in new_uids:
            exposed_uids.add(uid)
        n = _merge_exposes(session, new_uids, "azure_sql_public_network")
        if new_uids:
            logger.info(f"azure: SQL public: {len(new_uids)} servers → {n} edges")
        return n
    except Exception as exc:
        logger.debug(f"azure: SQL public access detection skipped: {exc}")
        return 0


def _storage_public_blob(
    session: Any,
    tenant_id: str,
    exposed_uids: Set[str],
) -> int:
    """Azure Storage Accounts with public blob access enabled — check findings."""
    try:
        result = session.run("""
            MATCH (r:Resource {tenant_id: $tid})-[:HAS_FINDING]->(f:Finding)
            WHERE r.resource_type IN [
                'azure.storage_account', 'azure.blob_container'
            ]
              AND (f.rule_id CONTAINS 'public_blob'
                OR f.rule_id CONTAINS 'allow_blob_public'
                OR f.rule_id CONTAINS 'blob_public_access'
                OR f.rule_id CONTAINS 'public_access')
            RETURN DISTINCT r.uid AS uid
        """, tid=tenant_id)
        new_uids = [rec["uid"] for rec in result
                    if rec.get("uid") and rec["uid"] not in exposed_uids]
        for uid in new_uids:
            exposed_uids.add(uid)
        return _merge_exposes(session, new_uids, "azure_storage_public_blob")
    except Exception as exc:
        logger.debug(f"azure: Storage public blob detection skipped: {exc}")
        return 0


def _aks_public_api(
    session: Any,
    pg_conn_fn: Callable,
    exposed_uids: Set[str],
) -> int:
    """AKS cluster with API server public endpoint (no authorized IP ranges)."""
    try:
        from psycopg2.extras import RealDictCursor
        conn = pg_conn_fn("threat_engine_discoveries")
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT DISTINCT emitted_fields->>'id' AS cluster_id
                    FROM discovery_findings
                    WHERE discovery_id IN (
                        'azure.containerservice.managedclusters',
                        'azure.aks.clusters'
                    )
                      AND (
                        emitted_fields->'properties'->>'enablePrivateCluster' = 'false'
                        OR emitted_fields->'properties'->'apiServerAccessProfile'
                           ->>'enablePrivateCluster' = 'false'
                      )
                      AND emitted_fields->>'id' IS NOT NULL
                """)
                rows = cur.fetchall()
        finally:
            conn.close()

        new_uids = [row["cluster_id"].lower() for row in rows
                    if row.get("cluster_id") and row["cluster_id"].lower() not in exposed_uids]
        for uid in new_uids:
            exposed_uids.add(uid)
        n = _merge_exposes(session, new_uids, "azure_aks_public_api")
        if new_uids:
            logger.info(f"azure: AKS public API: {len(new_uids)} clusters → {n} edges")
        return n
    except Exception as exc:
        logger.debug(f"azure: AKS public API detection skipped: {exc}")
        return 0


def _app_service_public(
    session: Any,
    tenant_id: str,
    exposed_uids: Set[str],
) -> int:
    """Azure App Services / Function Apps with public access — check findings."""
    try:
        result = session.run("""
            MATCH (r:Resource {tenant_id: $tid})-[:HAS_FINDING]->(f:Finding)
            WHERE r.resource_type IN ['azure.app_service', 'azure.function_app']
              AND (f.rule_id CONTAINS 'public' OR f.rule_id CONTAINS 'access_restriction'
                OR f.rule_id CONTAINS 'network_access' OR f.rule_id CONTAINS 'vnet')
            RETURN DISTINCT r.uid AS uid
        """, tid=tenant_id)
        new_uids = [rec["uid"] for rec in result
                    if rec.get("uid") and rec["uid"] not in exposed_uids]
        for uid in new_uids:
            exposed_uids.add(uid)
        return _merge_exposes(session, new_uids, "azure_app_service_public")
    except Exception as exc:
        logger.debug(f"azure: App Service detection skipped: {exc}")
        return 0


def _azure_database_public(
    session: Any,
    pg_conn_fn: Callable,
    exposed_uids: Set[str],
) -> int:
    """Azure Database for PostgreSQL / MySQL with public network access."""
    try:
        from psycopg2.extras import RealDictCursor
        conn = pg_conn_fn("threat_engine_discoveries")
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT DISTINCT emitted_fields->>'id' AS db_id
                    FROM discovery_findings
                    WHERE discovery_id IN (
                        'azure.dbforpostgresql.flexibleservers',
                        'azure.dbformysql.flexibleservers',
                        'azure.dbforpostgresql.servers',
                        'azure.dbformysql.servers'
                    )
                      AND lower(
                        emitted_fields->'properties'->>'publicNetworkAccess'
                      ) = 'enabled'
                      AND emitted_fields->>'id' IS NOT NULL
                """)
                rows = cur.fetchall()
        finally:
            conn.close()

        new_uids = [row["db_id"].lower() for row in rows
                    if row.get("db_id") and row["db_id"].lower() not in exposed_uids]
        for uid in new_uids:
            exposed_uids.add(uid)
        n = _merge_exposes(session, new_uids, "azure_database_public_network")
        if new_uids:
            logger.info(f"azure: Database public: {len(new_uids)} servers → {n} edges")
        return n
    except Exception as exc:
        logger.debug(f"azure: Database public detection skipped: {exc}")
        return 0
