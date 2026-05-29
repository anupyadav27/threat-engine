"""
Catalog-driven infrastructure relationship writer (DI engine).

Reads rules from resource_relationship_catalog (threat_engine_di, category='infrastructure'),
then for each rule:
  1. Queries asset_inventory for source resources of the given type/CSP/tenant/scan_run_id.
  2. Extracts target identifiers from emitted_fields using field_path traversal:
       field_ref:       emitted_fields["SubnetId"]
       array_field_ref: emitted_fields["BlockDeviceMappings"] → each[*].Ebs.VolumeId
  3. Looks up the target identifier in asset_inventory to get canonical resource_uid.
  4. Writes edges to asset_relationships via upsert_asset_relationships.

Non-fatal: any exception is caught and logged — a catalog writer failure
should never abort the DI scan pipeline.

Called from: engines/di/run_scan.py (Phase 2 tail, after write_assets)
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, Iterator, List, Optional, Tuple

import psycopg2
import psycopg2.extras

from engine_common.db_connections import get_di_conn
from engine_common.relationship_writer import upsert_asset_relationships

logger = logging.getLogger(__name__)

_BATCH_SIZE = 500


# ── Field path traversal ────────────────────────────────────────────────────────

def _resolve_field_ref(emitted: Dict[str, Any], field_path: str) -> List[str]:
    """Extract a single scalar value from emitted_fields using dot-notation path."""
    parts = field_path.split(".")
    node: Any = emitted
    for part in parts:
        if not isinstance(node, dict):
            return []
        node = node.get(part)
        if node is None:
            return []
    return [str(node)] if node else []


def _resolve_array_field_ref(emitted: Dict[str, Any], field_path: str) -> List[str]:
    """
    Traverse an array field path like "BlockDeviceMappings[*].Ebs.VolumeId".
    Supports:
      - "List[*].Field" — list of objects, extract leaf field from each
      - "List[*]" — list of scalars
      - "A.B[*].C.D" — nested object → list → leaf
      - "A[*].B[*].C" — nested arrays (outer then inner)
    """
    # Split on [*] to get path segments
    # e.g. "BlockDeviceMappings[*].Ebs.VolumeId" → ["BlockDeviceMappings", ".Ebs.VolumeId"]
    # e.g. "VpcConfig.SecurityGroupIds[*]" → ["VpcConfig.SecurityGroupIds", ""]
    parts = re.split(r'\[\*\]', field_path)

    def _extract_leaf(node: Any, dot_path: str) -> Optional[str]:
        """Extract a scalar from node using a .Field.Sub path string."""
        if not dot_path or dot_path == ".":
            return str(node) if node is not None else None
        sub_parts = dot_path.lstrip(".").split(".")
        cur = node
        for sp in sub_parts:
            if not sp:
                continue
            if not isinstance(cur, dict):
                return None
            cur = cur.get(sp)
            if cur is None:
                return None
        return str(cur) if cur is not None else None

    def _traverse(node: Any, segments: List[str]) -> List[str]:
        if not segments:
            return [str(node)] if node is not None else []

        seg = segments[0]
        rest = segments[1:]

        # Navigate into object using dot-path before the first [*]
        parts_seg = seg.lstrip(".").split(".")
        cur = node
        for p in parts_seg:
            if not p:
                continue
            if not isinstance(cur, dict):
                return []
            cur = cur.get(p)
            if cur is None:
                return []

        if not isinstance(cur, list):
            # Treat as list with single element if not a list
            cur = [cur]

        results = []
        for item in cur:
            if not rest:
                v = str(item) if item is not None else None
                if v:
                    results.append(v)
            else:
                results.extend(_traverse(item, rest))
        return results

    return _traverse(emitted, parts)


def _extract_identifiers(emitted: Dict[str, Any], field_path: str, path_type: str) -> List[str]:
    """Route to correct extractor based on field_path_type."""
    if not emitted or not field_path:
        return []
    if path_type == "array_field_ref":
        return _resolve_array_field_ref(emitted, field_path)
    # Default: field_ref
    return _resolve_field_ref(emitted, field_path)


# ── Catalog loader ───────────────────────────────────────────────────────────────

def _load_catalog_rules(conn: "psycopg2.connection", csp: str) -> List[Dict[str, Any]]:
    """Load active infrastructure rules for the given CSP from resource_relationship_catalog."""
    sql = """
        SELECT id, source_resource_type, target_resource_type, relation_type,
               field_path, field_path_type, target_identifier_field,
               attack_path_category, description
        FROM resource_relationship_catalog
        WHERE csp = %s AND is_active = TRUE AND relationship_category = 'infrastructure'
        ORDER BY source_resource_type, relation_type
    """
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(sql, (csp,))
        return [dict(r) for r in cur.fetchall()]


# ── Asset inventory lookup ───────────────────────────────────────────────────────

def _fetch_source_resources(
    conn: "psycopg2.connection",
    tenant_id: str,
    scan_run_id: str,
    csp: str,
    resource_type: str,
) -> Iterator[Tuple[str, Dict[str, Any]]]:
    """
    Yield (resource_uid, emitted_fields) pairs for source resources.
    Uses keyset pagination to avoid huge memory usage for large accounts.
    """
    sql = """
        SELECT resource_uid, emitted_fields
        FROM asset_inventory
        WHERE tenant_id = %s
          AND scan_run_id = %s
          AND provider = %s
          AND resource_type = %s
          AND resource_uid > %s
        ORDER BY resource_uid
        LIMIT 1000
    """
    last_uid = ""
    while True:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, (tenant_id, scan_run_id, csp, resource_type, last_uid))
            rows = cur.fetchall()
        if not rows:
            break
        for row in rows:
            emitted = row["emitted_fields"]
            if isinstance(emitted, str):
                try:
                    emitted = json.loads(emitted)
                except (ValueError, TypeError):
                    emitted = {}
            yield row["resource_uid"], (emitted or {})
        last_uid = rows[-1]["resource_uid"]
        if len(rows) < 1000:
            break


def _resolve_target_uid(
    conn: "psycopg2.connection",
    tenant_id: str,
    scan_run_id: str,
    csp: str,
    target_resource_type: str,
    identifier: str,
) -> Optional[str]:
    """
    Resolve a raw identifier (e.g. volume ID, ARN, IP) to a canonical resource_uid
    in asset_inventory. Tries exact match on resource_uid first, then looks for
    the identifier inside emitted_fields values.
    """
    if not identifier:
        return None

    # 1. Exact resource_uid match
    sql_exact = """
        SELECT resource_uid FROM asset_inventory
        WHERE tenant_id = %s AND scan_run_id = %s AND provider = %s
          AND resource_type = %s AND resource_uid = %s
        LIMIT 1
    """
    with conn.cursor() as cur:
        cur.execute(sql_exact, (tenant_id, scan_run_id, csp, target_resource_type, identifier))
        row = cur.fetchone()
        if row:
            return row[0]

    # 2. Partial UID match (identifier appears at end of ARN/OCID/resourceId)
    sql_suffix = """
        SELECT resource_uid FROM asset_inventory
        WHERE tenant_id = %s AND scan_run_id = %s AND provider = %s
          AND resource_type = %s
          AND (resource_uid LIKE %s OR resource_uid LIKE %s)
        LIMIT 1
    """
    with conn.cursor() as cur:
        cur.execute(sql_suffix, (
            tenant_id, scan_run_id, csp, target_resource_type,
            f"%{identifier}",   # ARN suffix
            f"%/{identifier}",  # path suffix
        ))
        row = cur.fetchone()
        if row:
            return row[0]

    # 3. Not found — use identifier as synthetic UID so edge is still written
    return identifier


# ── Main writer ─────────────────────────────────────────────────────────────────

def write_catalog_relationships(
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
) -> int:
    """
    Derive infrastructure attachment edges from resource_relationship_catalog
    and write them to asset_relationships.

    Args:
        scan_run_id: pipeline scan ID
        tenant_id:   tenant scoping
        account_id:  cloud account ID
        provider:    csp string (aws|azure|gcp|oci|alicloud|ibm|k8s)

    Returns:
        Total number of edges written (0 on error).
    """
    try:
        conn = get_di_conn()
        try:
            return _run(conn, scan_run_id, tenant_id, account_id, provider)
        finally:
            conn.close()
    except Exception as exc:
        logger.warning(
            "catalog_relationship_writer failed (non-fatal): %s", exc, exc_info=True
        )
        return 0


def _run(
    conn: "psycopg2.connection",
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    csp: str,
) -> int:
    rules = _load_catalog_rules(conn, csp)
    if not rules:
        logger.info("catalog_relationship_writer: no rules for csp=%s", csp)
        return 0

    logger.info(
        "catalog_relationship_writer: processing %d rules for csp=%s scan=%s",
        len(rules), csp, scan_run_id,
    )

    edges: List[Dict[str, Any]] = []
    total_written = 0

    for rule in rules:
        src_type = rule["source_resource_type"]
        tgt_type = rule["target_resource_type"]
        rel_type = rule["relation_type"]
        field_path = rule["field_path"]
        path_type = rule.get("field_path_type") or "field_ref"
        category = rule.get("attack_path_category") or "lateral_movement"

        rule_edges = 0
        for src_uid, emitted in _fetch_source_resources(
            conn, tenant_id, scan_run_id, csp, src_type
        ):
            identifiers = _extract_identifiers(emitted, field_path, path_type)
            for ident in identifiers:
                tgt_uid = _resolve_target_uid(
                    conn, tenant_id, scan_run_id, csp, tgt_type, ident
                )
                if not tgt_uid:
                    continue
                edges.append({
                    "source_uid":       src_uid,
                    "source_type":      src_type,
                    "target_uid":       tgt_uid,
                    "target_type":      tgt_type,
                    "relation_type":    rel_type,
                    "relation_metadata": {
                        "attack_path_category": category,
                        "catalog_rule_id": rule.get("id"),
                        "raw_identifier": ident,
                    },
                })
                rule_edges += 1

                # Flush when batch is full
                if len(edges) >= _BATCH_SIZE:
                    total_written += upsert_asset_relationships(
                        conn, edges,
                        scan_run_id=scan_run_id,
                        tenant_id=tenant_id,
                        account_id=account_id,
                        provider=csp,
                    )
                    edges = []

        if rule_edges:
            logger.debug(
                "rule %s→%s via %s: %d edges derived",
                src_type, tgt_type, rel_type, rule_edges,
            )

    # Flush remainder
    if edges:
        total_written += upsert_asset_relationships(
            conn, edges,
            scan_run_id=scan_run_id,
            tenant_id=tenant_id,
            account_id=account_id,
            provider=csp,
        )

    logger.info(
        "catalog_relationship_writer: wrote %d edges for csp=%s scan=%s",
        total_written, csp, scan_run_id,
    )
    return total_written
