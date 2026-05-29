"""
relationship_writer — shared utility for writing security relationship edges to
asset_relationships (threat_engine_di DB).

Multiple engines write edges to this table:
  - DI phase-2 writer: structural edges (PLACED_IN, BELONGS_TO, PROTECTED_BY basic)
  - Network engine: topology edges (INTERNET_ACCESSIBLE, GOVERNED_BY, ROUTES_VIA, PEERED_WITH, etc.)
  - IAM engine: identity edges (ASSUMES, HAS_POLICY, MEMBER_OF)
  - Encryption engine: data-plane edges (ENCRYPTED_BY, GRANTS_DECRYPT_TO)

The INSERT...ON CONFLICT pattern relies on the unique constraint added by
di_008_asset_relationships_unique.sql:
    UNIQUE (scan_run_id, tenant_id, source_uid, relation_type, target_uid)

ON CONFLICT DO UPDATE SET relation_metadata = EXCLUDED.relation_metadata, last_seen_at = NOW()
ensures the richer engine-computed metadata (from later pipeline stages) wins over
the DI writer's simpler version.

Usage:
    from engine_common.relationship_writer import upsert_asset_relationships

    edges = [
        {
            "source_uid": "arn:aws:ec2:us-east-1:123:subnet/subnet-abc",
            "source_type": "subnet",
            "target_uid": "arn:aws:ec2:us-east-1:123:network-acl/acl-xyz",
            "target_type": "network_acl",
            "relation_type": "GOVERNED_BY",
            "relation_metadata": {"acl_rule_count": 12, "effective_exposure": "VPC_INTERNAL"},
        },
        ...
    ]
    written = upsert_asset_relationships(
        conn, edges,
        scan_run_id="550e8400-...",
        tenant_id="my-tenant",
        account_id="123456789012",
        provider="aws",
    )
"""

from __future__ import annotations

import logging
from typing import Any

import psycopg2.extras

logger = logging.getLogger(__name__)

_BATCH_SIZE = 500

# Mandatory top-level keys in every edge dict
_REQUIRED_EDGE_KEYS = frozenset({"source_uid", "target_uid", "relation_type"})


def upsert_asset_relationships(
    conn: Any,
    edges: list[dict[str, Any]],
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
) -> int:
    """Upsert a list of relationship edges into asset_relationships.

    Each edge in ``edges`` must contain:
        - source_uid (str): Canonical UID of the source resource.
        - target_uid (str): Canonical UID of the target resource.
        - relation_type (str): Relationship type (e.g. INTERNET_ACCESSIBLE, GOVERNED_BY).

    Optional edge keys:
        - source_type (str): Resource type of the source node.
        - target_type (str): Resource type of the target node.
        - relation_metadata (dict): JSON metadata enriching the edge. Caller
              passes a plain dict; this function wraps it in psycopg2.extras.Json.

    ON CONFLICT (scan_run_id, tenant_id, source_uid, relation_type, target_uid)
    updates relation_metadata and last_seen_at so later-running engines with
    richer computed metadata always win over earlier structural edges.

    Args:
        conn: psycopg2 connection; caller owns the transaction/commit lifecycle.
        edges: List of edge dicts to upsert (see above).
        scan_run_id: Current pipeline run UUID.
        tenant_id: Tenant identifier — never NULL.
        account_id: Cloud account / subscription ID.
        provider: CSP identifier (aws/azure/gcp/oci/alicloud/k8s).

    Returns:
        Number of rows upserted.

    Raises:
        ValueError: If tenant_id is None or an edge is missing required keys.
        psycopg2.Error: Propagated for caller transaction handling.
    """
    if not tenant_id:
        raise ValueError("upsert_asset_relationships: tenant_id must not be None/empty")
    if not edges:
        return 0

    _validate_edges(edges)

    total = 0
    for batch_start in range(0, len(edges), _BATCH_SIZE):
        batch = edges[batch_start : batch_start + _BATCH_SIZE]
        rows = _build_rows(batch, scan_run_id, tenant_id, account_id, provider)
        total += _execute_upsert(conn, rows)

    logger.debug(
        "upsert_asset_relationships: upserted %d edges",
        total,
        extra={
            "scan_run_id": str(scan_run_id),
            "tenant_id": tenant_id,
            "edge_count": total,
        },
    )
    return total


def _validate_edges(edges: list[dict[str, Any]]) -> None:
    for i, edge in enumerate(edges):
        missing = _REQUIRED_EDGE_KEYS - edge.keys()
        if missing:
            raise ValueError(
                f"upsert_asset_relationships: edge[{i}] missing required keys: {sorted(missing)}"
            )
        if not edge["source_uid"] or not edge["target_uid"]:
            raise ValueError(
                f"upsert_asset_relationships: edge[{i}] has empty source_uid or target_uid"
            )


def _build_rows(
    edges: list[dict[str, Any]],
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
) -> list[tuple]:
    rows = []
    for edge in edges:
        meta = edge.get("relation_metadata") or {}
        if isinstance(meta, dict):
            meta = psycopg2.extras.Json(meta)
        rows.append((
            scan_run_id,
            tenant_id,
            account_id,
            provider,
            edge["source_uid"],
            edge.get("source_type") or "",
            edge["target_uid"],
            edge.get("target_type") or "",
            edge["relation_type"],
            meta,
        ))
    return rows


def _execute_upsert(conn: Any, rows: list[tuple]) -> int:
    sql = """
        INSERT INTO asset_relationships (
            scan_run_id,
            tenant_id,
            account_id,
            provider,
            source_uid,
            source_type,
            target_uid,
            target_type,
            relation_type,
            relation_metadata
        )
        VALUES %s
        ON CONFLICT (scan_run_id, tenant_id, source_uid, relation_type, target_uid)
        DO UPDATE SET
            relation_metadata = EXCLUDED.relation_metadata,
            source_type       = EXCLUDED.source_type,
            target_type       = EXCLUDED.target_type,
            last_seen_at      = NOW()
    """
    with conn.cursor() as cur:
        psycopg2.extras.execute_values(cur, sql, rows, page_size=_BATCH_SIZE)
    conn.commit()
    return len(rows)
