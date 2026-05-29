"""
Attack Path Engine — PostgreSQL Graph BFS.

Replaces Neo4j as the primary path-computation engine.
Neo4j is retained for visualization/UI rendering only.

Architecture:
  1. Load inventory_relationships for tenant from inventory DB.
  2. Build in-memory adjacency list: from_uid → [(to_uid, rel_type, from_type, to_type)].
  3. Load crown jewels and internet-exposed nodes from resource_security_posture.
  4. Run BFS forward from each internet-exposed node, stopping at crown jewels.
  5. Return List[RawPath] using the same model contract as Neo4jClient.

Design decisions:
  - Pure Python BFS — no graph DB dependency.
  - Reads ALL relationships for the tenant (not filtered by scan_run_id) so the
    graph reflects the accumulated topology from multiple scans.
  - Max 500 paths, max 7 hops, consistent with Neo4j BFS limits.
  - relation_type is preserved verbatim; attack_vector.py maps it to MITRE techniques.

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

# BFS limits (match Neo4j client constants)
MAX_PATHS = 500
MAX_HOPS = 7

# Posture-only relations written to asset_relationships but NOT traversal edges.
# ExposureLoader handles INTERNET_ACCESSIBLE separately; DataSec/DBSec consume
# ENCRYPTED_BY/PROTECTED_BY/GOVERNED_BY/ROUTES_VIA directly from the DB.
_POSTURE_ONLY_RELS: frozenset = frozenset({
    "INTERNET_ACCESSIBLE", "ENCRYPTED_BY", "PROTECTED_BY", "GOVERNED_BY", "ROUTES_VIA",
})

# Relation types that represent attack-path-relevant edges.
# Covers AWS, Azure, GCP, OCI, AliCloud, IBM Cloud, and K8s edge types.
_ATTACK_RELEVANT_TYPES: Set[str] = {
    # Generic / all-CSP
    "accesses",
    "attached_to",
    "contains",
    "depends_on",
    "encrypted_by",
    "exposed_via",
    "executes_on",
    "has_role",
    "member_of",
    "mounts",
    "reads",
    "routes_to",
    "uses",
    "writes",
    "can_assume",
    "can_access",
    "reachable_from",
    "lateral_movement",
    "privilege_escalation",
    "data_access",
    "exposure",
    "execution",
    "data_flow",
    "internet_connected",   # inventory engine marks exposure edges for all CSPs
    "exposed_through",      # synonym used by some inventory providers
    "grants_access_to",     # IAM permission edges
    "stores_data_in",       # compute → data store
    "assumes",              # role assumption
    # Non-AWS CSPs (Azure, GCP, OCI, AliCloud, IBM, K8s)
    "connected_to",         # Azure VNet peering, GCP VPC peering, OCI VCN peering
    "allows_traffic_from",  # Azure NSG, OCI Security List, GCP Firewall allow rule
    "serves_traffic_for",   # Load Balancer → backend pool (all CSPs)
    "has_policy",           # Azure/GCP/OCI IAM policy attachments
    "manages",              # Management plane: cluster → node, control plane → workload
    "triggers",             # Cloud Functions, Lambda, Azure Functions event triggers
    "invokes",              # API Gateway → Lambda / Cloud Function
    "controlled_by",        # Resource controlled by management plane (K8s, OCI)
    "runs_on",              # Container → node, Lambda → compute fleet
    # Per-engine security edges (written to asset_relationships, new in catalog sprint)
    "linked_to",            # IAM identity chain (LINKED_TO edges from iam_relationship_writer)
    "grants_decrypt_to",    # KMS key grants decrypt to external principal (data_exfil)
    "has_endpoint",         # NLB/ALB exposes a service endpoint (network engine)
    "peered_with",          # VPC peering (same account)
    "peered_with_external", # VPC peering (cross-account — lateral movement)
    "mounted_by",           # EFS/block volume mounted by workload
    "connected_via",        # Transit gateway / direct connect
    "worker_node_of",       # EC2 is a worker node of an EKS cluster
    "can_access",           # Explicit IAM allow (already in set, kept for clarity)
    # Topology edges that enable multi-hop lateral movement chains.
    # An attacker who compromises resource A can traverse to resource B if:
    #   - A HAS_PROFILE B → A can use B's IAM permissions (privilege escalation)
    #   - A IN_VPC/IN_SUBNET B → A has L3 network access to other resources in same zone
    #   - A CONTAINED_BY/PLACED_IN B → inverse containment; bridges resource → zone → resource chains
    #   - A ASSOCIATED_WITH B → explicit association between resources (e.g. Lambda → VPC config)
    "has_profile",          # EC2 instance has IAM instance profile → role assumption chain
    "in_vpc",               # Resource in VPC → lateral movement within VPC boundary
    "in_subnet",            # Resource in subnet → L3-level lateral movement path
    "contained_by",         # Inverse of CONTAINS; enables bidirectional topology traversal
    "placed_in",            # Resource placed in network zone (region/AZ/subnet)
    "associated_with",      # Generic resource association (Lambda↔VPC, SG↔resource, etc.)
}


def build_pg_graph(
    inventory_conn: Any,
    tenant_id: str,
    scan_run_id: Optional[str] = None,
) -> Dict[str, List[Tuple[str, str, str, str]]]:
    """Load asset_relationships and return an adjacency list.

    Reads ALL rows for the tenant (no scan_run_id filter) so the graph
    reflects accumulated topology across scans. Only edge types in
    _ATTACK_RELEVANT_TYPES are included to keep the graph focused.

    Args:
        inventory_conn: psycopg2 connection to threat_engine_di.
        tenant_id:      Tenant filter.
        scan_run_id:    Unused — kept for call-site compatibility.

    Returns:
        Dict[from_uid → List[(to_uid, relation_type, from_type, to_type)]].
    """
    adj: Dict[str, List[Tuple[str, str, str, str]]] = defaultdict(list)

    attack_rel_list = [r.upper() for r in _ATTACK_RELEVANT_TYPES]
    placeholders = ",".join(["%s"] * len(attack_rel_list))
    total = 0
    try:
        with inventory_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                f"""
                SELECT DISTINCT
                    source_uid                    AS from_uid,
                    target_uid                    AS to_uid,
                    LOWER(relation_type)          AS rel_type,
                    COALESCE(source_type, '')     AS from_type,
                    COALESCE(target_type, '')     AS to_type
                FROM asset_relationships
                WHERE tenant_id = %s
                  AND UPPER(relation_type) IN ({placeholders})
                  AND source_uid IS NOT NULL
                  AND target_uid IS NOT NULL
                """,
                (tenant_id, *attack_rel_list),
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
) -> List[RawPath]:
    """Run BFS forward from internet-exposed nodes toward crown jewels.

    Args:
        adj:              Adjacency list from build_pg_graph().
        exposed_uids:     Set of internet-exposed resource UIDs (entry points).
        crown_jewel_uids: Set of crown jewel UIDs (path destinations).
        posture_lookup:   Pre-fetched posture signals for categorisation.
        max_hops:         Maximum BFS depth.
        max_paths:        Stop after collecting this many paths.

    Returns:
        List of RawPath objects, one per complete path found.
    """
    paths: List[RawPath] = []

    if not exposed_uids or not crown_jewel_uids:
        logger.info(
            "pg BFS skipped: exposed_uids=%d crown_jewel_uids=%d",
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

    for entry_uid in sorted(exposed_uids):
        if len(paths) >= max_paths:
            break

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
                # Crown jewels are destinations, not transit nodes. Continuing BFS
                # from a crown jewel generates invalid paths (CJ as intermediate hop)
                # and wastes work the deduplicator would have to undo downstream.
                hop_categories = []
                for i, uid in enumerate(node_uids):
                    is_exposed_hop = (i == 0)
                    rtype = from_types[i] if i < len(from_types) else (
                        to_types[i - 1] if i > 0 and i - 1 < len(to_types) else ""
                    )
                    hop_categories.append(_categorise_hop(rtype, is_exposed_hop))

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
) -> List[RawPath]:
    """Top-level entry point called from run_scan.py.

    Builds the graph from inventory_relationships and merges any caller-supplied
    synthetic edges (e.g. IAM permission edges from iam_policy_statements).

    Args:
        inventory_conn:        psycopg2 connection to the inventory DB.
        tenant_id:             Tenant identifier.
        scan_run_id:           Current pipeline run UUID.
        internet_exposed_uids: UIDs with is_internet_exposed=true.
        posture_lookup:        Pre-fetched posture dict (uid → PostureRow).
        max_hops:              BFS depth limit (default 7).
        max_paths:             Path count limit (default 500).
        extra_edges:           Optional dict of synthetic edges to merge into the
                               adjacency list before BFS.  Format matches adj:
                               {from_uid: [(to_uid, rel_type, from_type, to_type), ...]}

    Returns:
        List[RawPath] — same contract as Neo4jClient.reverse_bfs().
    """
    adj = build_pg_graph(inventory_conn, tenant_id, scan_run_id)

    # Merge synthetic edges (e.g. IAM permission graph, EKS node membership)
    if extra_edges:
        extra_count = 0
        for from_uid, edges in extra_edges.items():
            adj.setdefault(from_uid, [])
            adj[from_uid].extend(edges)
            extra_count += len(edges)
        logger.info("pg_graph: merged %d synthetic extra edges from %d sources",
                    extra_count, len(extra_edges))

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
    )
