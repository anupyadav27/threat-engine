"""
Attack Path Engine — Choke Point Detector.

Identifies the top-10 nodes that appear as choke points (penultimate node in
convergence groups) across the most distinct path groups.

"Fix this one node, break the most paths."
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Dict, List, Set

from ..models.attack_path import ChokePoint, Path

logger = logging.getLogger("attack-path.choke_point_detector")


def detect_choke_points(
    deduplicated_paths: List[Path],
    top_n: int = 10,
) -> List[ChokePoint]:
    """Identify the top-N choke point nodes.

    A choke point is a node (choke_node_uid) that appears in the most distinct
    group_ids. Fixing this one node breaks paths across all those groups.

    Args:
        deduplicated_paths:  Output of deduplicator.deduplicate().
        top_n:               Return top N nodes by paths_blocked_if_fixed (default 10).

    Returns:
        List of ChokePoint objects, sorted by paths_blocked_if_fixed descending.
    """
    # Collect (choke_node_uid → set of distinct group_ids)
    node_groups: Dict[str, Set[str]] = defaultdict(set)
    # Collect (choke_node_uid → list of representative path scores)
    node_scores: Dict[str, List[int]] = defaultdict(list)

    for p in deduplicated_paths:
        if not p.choke_node_uid:
            continue
        if not p.group_id:
            continue
        node_groups[p.choke_node_uid].add(p.group_id)
        if p.is_representative:
            node_scores[p.choke_node_uid].append(p.path_score)

    if not node_groups:
        logger.info("No choke points detected — all paths are singletons or have no group.")
        return []

    # Sort by number of distinct groups descending
    sorted_nodes = sorted(
        node_groups.keys(),
        key=lambda uid: len(node_groups[uid]),
        reverse=True,
    )[:top_n]

    choke_points: List[ChokePoint] = []
    for uid in sorted_nodes:
        paths_blocked = len(node_groups[uid])
        scores = node_scores.get(uid, [])
        avg_score = float(sum(scores) / len(scores)) if scores else 0.0
        choke_points.append(ChokePoint(
            node_uid=uid,
            paths_blocked_if_fixed=paths_blocked,
            avg_path_score=avg_score,
        ))

    logger.info(
        '{"engine":"attack-path","stage":"choke_detect","choke_point_count":%d}',
        len(choke_points),
    )
    return choke_points
