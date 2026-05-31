"""
Attack Path Engine — PostgreSQL Graph BFS.

Replaces Neo4j as the primary path-computation engine.
Neo4j is retained for visualization/UI rendering only.

Architecture:
  1. Load asset_relationships WHERE is_attack_edge=TRUE for the tenant.
  2. Build in-memory adjacency list: from_uid → [(to_uid, rel_type, from_type, to_type)].
  3. Load crown jewels and internet-exposed nodes from resource_security_posture.
  4. Run BFS forward from each internet-exposed node, stopping at crown jewels.
  5. Return List[RawPath] using the same model contract as Neo4jClient.

Design decisions:
  - Pure Python BFS — no graph DB dependency.
  - Only edges with is_attack_edge=TRUE are loaded — these are edges that the
    VAL-01 validator layer has explicitly promoted as traversable attack edges.
    Structural/context-only edges (PROTECTED_BY, GOVERNED_BY, ROUTES_VIA, etc.)
    are excluded. This eliminates noisy false-positive paths.
  - Reads ALL validated edges for the tenant (not filtered by scan_run_id) so
    the graph reflects accumulated topology from multiple scans.
  - Max 500 paths, max 7 hops, consistent with Neo4j BFS limits.
  - relation_type is preserved verbatim; attack_vector.py maps it to MITRE techniques.
  - Synthetic in-memory edges (IAM permission edges, EKS worker-node edges) are
    merged via extra_edges in run_pg_bfs() — they bypass the DB filter and are
    already pre-validated by their source builders.

Security notes:
  - All queries scoped by tenant_id — no cross-tenant leakage.
  - No string interpolation in SQL — parameterised queries only.
"""

from __future__ import annotations

import logging
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional, Set, Tuple

import psycopg2.extras

from ..models.attack_path import RawPath

logger = logging.getLogger("attack-path.pg_graph")

# BFS limits
# MAX_HOPS=7: keeps paths actionable (>7 hops is rarely exploitable end-to-end).
# MAX_PATHS=10_000: safety valve against pathological graphs only.
# Quality filtering (top-N by score) is applied POST-dedup in run_scan.py, so this
# cap should never be the binding constraint in practice — dedup collapses paths first.
MAX_PATHS = 10_000
MAX_HOPS = 7

# Maps attack_entry_point_category values → hop_category string used in hop_categories[0]
_ENTRY_CAT_TO_HOP: Dict[str, str] = {
    "INTERNET_ENTRY":          "internet",
    "IDENTITY_ENTRY":          "identity",
    "CICD_ENTRY":              "cicd",
    "THIRD_PARTY_ENTRY":       "third_party",
    "INTERNAL_WORKLOAD_ENTRY": "compute",
    "ENDPOINT_AGENT_ENTRY":    "compute",
}


def build_pg_graph(
    inventory_conn: Any,
    tenant_id: str,
    scan_run_id: Optional[str] = None,
) -> Dict[str, List[Tuple[str, str, str, str]]]:
    """Load validated attack edges from asset_relationships and return an adjacency list.

    Only loads rows where is_attack_edge=TRUE — edges explicitly promoted by the
    VAL-01 validator layer (internet_reachability, service_chain, identity_usage,
    assume_role, data_access). Structural/context-only edges are excluded.

    Reads ALL validated edges for the tenant (no scan_run_id filter) so the graph
    reflects accumulated topology across scans. Synthetic in-memory edges (IAM
    permission edges, EKS worker-node edges) are merged by the caller via extra_edges.

    Args:
        inventory_conn: psycopg2 connection to threat_engine_di.
        tenant_id:      Tenant filter.
        scan_run_id:    Unused — kept for call-site compatibility.

    Returns:
        Dict[from_uid → List[(to_uid, relation_type, from_type, to_type)]].
    """
    adj: Dict[str, List[Tuple[str, str, str, str]]] = defaultdict(list)

    total = 0
    try:
        with inventory_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT DISTINCT
                    source_uid                    AS from_uid,
                    target_uid                    AS to_uid,
                    LOWER(relation_type)          AS rel_type,
                    COALESCE(source_type, '')     AS from_type,
                    COALESCE(target_type, '')     AS to_type
                FROM asset_relationships
                WHERE tenant_id = %s
                  AND is_attack_edge = TRUE
                  AND source_uid IS NOT NULL
                  AND target_uid IS NOT NULL
                  AND UPPER(relation_type) != 'INTERNET_ACCESSIBLE'
                """,
                (tenant_id,),
            )
            for row in cur.fetchall():
                adj[row["from_uid"]].append((
                    row["to_uid"],
                    row["rel_type"] or "",
                    row["from_type"] or "",
                    row["to_type"] or "",
                ))
                total += 1

        logger.info(
            "pg_graph asset_relationships: tenant=%s edges=%d unique_sources=%d",
            tenant_id, total, len(adj),
        )
    except Exception as exc:
        logger.warning("pg_graph: asset_relationships read failed (non-fatal): %s", exc)
        try:
            inventory_conn.rollback()
        except Exception:
            pass

    return dict(adj)


def _categorise_hop(resource_type: str, is_exposed: bool) -> str:
    """Map resource_type to a hop category for chain_type labelling."""
    rt = (resource_type or "").lower()
    if is_exposed:
        return "internet"
    if any(x in rt for x in ("ec2", "vm", "compute", "instance", "lambda", "function", "ecs",
                              "cloud_run", "cloudrun")):
        return "compute"
    if any(x in rt for x in ("s3", "blob", "gcs", "storage", "bucket", "adls", "oss")):
        return "data"
    if any(x in rt for x in ("rds", "db", "database", "redshift", "dynamo", "cassandra",
                              "cosmos", "firestore", "bigtable", "nosql")):
        return "database"
    if any(x in rt for x in ("kms", "key", "vault", "secret")):
        return "secrets"
    if any(x in rt for x in ("iam", "role", "policy", "user", "group", "identity",
                              "service_account", "serviceaccount", "principal", "ram")):
        return "identity"
    if any(x in rt for x in ("vpc", "subnet", "sg", "security_group", "alb", "nlb", "elb",
                              "loadbalancer", "vcn", "vnet", "nsg", "network_security_group",
                              "slb", "firewall", "route_table")):
        return "network"
    if any(x in rt for x in ("eks", "k8s", "kubernetes", "pod", "container",
                              "oke", "aks", "gke")):
        return "container"
    return "compute"


def reverse_bfs(
    adj: Dict[str, List[Tuple[str, str, str, str]]],
    exposed_uids: Set[str],
    crown_jewel_uids: Set[str],
    posture_lookup: Dict[str, Any],
    max_hops: int = MAX_HOPS,
    max_paths: int = MAX_PATHS,
    entry_categories: Optional[Dict[str, str]] = None,
) -> List[RawPath]:
    """Run BFS forward from all attack entry points toward crown jewels.

    Args:
        adj:              Adjacency list from build_pg_graph().
        exposed_uids:     Set of all attack entry point UIDs (internet + identity + cicd + ...).
        crown_jewel_uids: Set of crown jewel UIDs (path destinations).
        posture_lookup:   Pre-fetched posture signals for categorisation.
        max_hops:         Maximum BFS depth.
        max_paths:        Stop after collecting this many paths.
        entry_categories: Dict[uid → attack_entry_point_category] for all entry UIDs.
                          Drives hop_categories[0] and entry_point_category on RawPath.

    Returns:
        List of RawPath objects, one per complete path found.
    """
    paths: List[RawPath] = []
    _ec = entry_categories or {}

    if not exposed_uids or not crown_jewel_uids:
        logger.info(
            "pg BFS skipped: entry_uids=%d crown_jewel_uids=%d",
            len(exposed_uids),
            len(crown_jewel_uids),
        )
        return paths

    logger.info(
        "pg BFS starting: entry_points=%d crown_jewels=%d max_hops=%d",
        len(exposed_uids),
        len(crown_jewel_uids),
        max_hops,
    )

    # Pre-BFS: entry nodes that ARE crown jewels → depth-0 direct-exposure paths.
    for uid in sorted(exposed_uids):
        if len(paths) >= max_paths:
            break
        if uid in crown_jewel_uids:
            pr = posture_lookup.get(uid)
            rtype = getattr(pr, "resource_type", "") or ""
            entry_cat = _ec.get(uid, "INTERNET_ENTRY")
            hop_cat = _ENTRY_CAT_TO_HOP.get(entry_cat, "internet")
            paths.append(RawPath(
                crown_jewel_uid=uid,
                entry_point_uid=uid,
                node_uids=[uid],
                node_types=[rtype],
                edge_types=[],
                hop_categories=[hop_cat],
                depth=0,
                max_epss=None,
                misconfig_count=0,
                threat_count=0,
                top_cves=[],
                entry_point_category=entry_cat,
            ))

    logger.info("pg BFS depth-0 (direct exposure): %d paths", sum(1 for p in paths if p.depth == 0))

    for entry_uid in sorted(exposed_uids):
        if len(paths) >= max_paths:
            break

        entry_cat = _ec.get(entry_uid, "INTERNET_ENTRY")
        entry_hop_cat = _ENTRY_CAT_TO_HOP.get(entry_cat, "internet")

        # BFS state: (current_uid, path_node_uids, path_rel_types, path_from_types, path_to_types)
        queue: deque = deque()
        queue.append((
            entry_uid,
            [entry_uid],          # node_uids so far
            [],                   # edge/rel types so far
            [],                   # from resource types
            [],                   # to resource types
        ))
        # Visited per BFS run to prevent cycles
        visited: Set[str] = {entry_uid}

        while queue and len(paths) < max_paths:
            current_uid, node_uids, edge_types, from_types, to_types = queue.popleft()

            depth = len(node_uids) - 1  # hops from entry

            if current_uid in crown_jewel_uids and current_uid != entry_uid:
                # Found a complete path — build RawPath and stop BFS from this node.
                hop_categories = []
                for i, uid in enumerate(node_uids):
                    if i == 0:
                        # Entry hop: use the actual entry category, not resource type
                        hop_categories.append(entry_hop_cat)
                    else:
                        rtype = from_types[i] if i < len(from_types) else (
                            to_types[i - 1] if i > 0 and i - 1 < len(to_types) else ""
                        )
                        hop_categories.append(_categorise_hop(rtype, False))

                paths.append(RawPath(
                    crown_jewel_uid=current_uid,
                    entry_point_uid=entry_uid,
                    node_uids=list(node_uids),
                    node_types=list(from_types) + [to_types[-1] if to_types else ""],
                    edge_types=list(edge_types),
                    hop_categories=hop_categories,
                    depth=depth,
                    max_epss=None,
                    misconfig_count=0,
                    threat_count=0,
                    top_cves=[],
                    entry_point_category=entry_cat,
                ))
                continue  # do NOT explore further from the crown jewel

            if depth >= max_hops:
                continue

            for (next_uid, rel_type, from_type, to_type) in adj.get(current_uid, []):
                if next_uid in visited:
                    continue
                visited.add(next_uid)
                queue.append((
                    next_uid,
                    node_uids + [next_uid],
                    edge_types + [rel_type],
                    from_types + [from_type],
                    to_types + [to_type],
                ))

    logger.info(
        "pg BFS complete: paths_found=%d entry_points_scanned=%d",
        len(paths),
        len(exposed_uids),
    )
    return paths


def run_pg_bfs(
    inventory_conn: Any,
    tenant_id: str,
    scan_run_id: str,
    internet_exposed_uids: List[str],
    posture_lookup: Dict[str, Any],
    max_hops: int = MAX_HOPS,
    max_paths: int = MAX_PATHS,
    extra_edges: Optional[Dict[str, List[Tuple[str, str, str, str]]]] = None,
    entry_categories: Optional[Dict[str, str]] = None,
) -> List[RawPath]:
    """Top-level entry point called from run_scan.py.

    Builds the graph from asset_relationships (is_attack_edge=TRUE) and merges
    caller-supplied synthetic edges. Supports all attack entry point types:
    internet-exposed, identity (IAM), CI/CD, third-party, internal workload, endpoint agent.

    Args:
        inventory_conn:        psycopg2 connection to the DI DB.
        tenant_id:             Tenant identifier.
        scan_run_id:           Current pipeline run UUID.
        internet_exposed_uids: ALL attack entry point UIDs (internet + non-internet).
        posture_lookup:        Pre-fetched posture dict (uid → PostureRow).
        max_hops:              BFS depth limit (default 7).
        max_paths:             Path count limit (default 500).
        extra_edges:           Optional dict of synthetic edges to merge.
        entry_categories:      Dict[uid → attack_entry_point_category] for all entry UIDs.
                               Drives hop_categories[0] and entry_point_category on RawPath.

    Returns:
        List[RawPath] — same contract as Neo4jClient.reverse_bfs().
    """
    adj = build_pg_graph(inventory_conn, tenant_id, scan_run_id)

    # Merge synthetic edges (e.g. IAM permission graph, EKS node membership).
    # Also register alias keys: role ARNs may appear as the last path segment
    # (e.g. "my-role") in CAN_USE_IDENTITY edges, while the synthetic edge source
    # is the full ARN ("arn:aws:iam::123:role/my-role"). Build a suffix→full_uid
    # alias map so both formats connect through the adjacency list.
    if extra_edges:
        extra_count = 0
        # Build alias: last path segment of each extra_uid → extra_uid (full ARN)
        uid_aliases: Dict[str, str] = {}
        for extra_uid in extra_edges:
            suffix = extra_uid.rstrip("/").rsplit("/", 1)[-1]
            if suffix and suffix != extra_uid:
                uid_aliases[suffix] = extra_uid

        for from_uid, edges in extra_edges.items():
            adj.setdefault(from_uid, [])
            adj[from_uid].extend(edges)
            # Also register under short-name alias so suffix-only UIDs resolve
            suffix = from_uid.rstrip("/").rsplit("/", 1)[-1]
            if suffix and suffix != from_uid:
                adj.setdefault(suffix, [])
                adj[suffix].extend(edges)
            extra_count += len(edges)
        logger.info("pg_graph: merged %d synthetic extra edges from %d sources (%d aliases)",
                    extra_count, len(extra_edges), len(uid_aliases))

    if not adj:
        logger.warning("pg_graph returned empty adjacency list — no paths possible")
        return []

    crown_jewel_uids: Set[str] = {
        uid for uid, row in posture_lookup.items() if getattr(row, "is_crown_jewel", False)
    }
    exposed_set: Set[str] = set(internet_exposed_uids)

    return reverse_bfs(
        adj=adj,
        exposed_uids=exposed_set,
        crown_jewel_uids=crown_jewel_uids,
        posture_lookup=posture_lookup,
        max_hops=max_hops,
        max_paths=max_paths,
        entry_categories=entry_categories,
    )
