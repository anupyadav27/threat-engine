"""
Attack Path Engine — Three-Phase Deduplicator.

Phase 1: Exact dedup by sha256("|".join(node_uids)).
         On collision, highest-scoring path wins.

Phase 2: Subpath absorption.
         Short path absorbed into long path ONLY IF:
           - short.node_uids is a suffix of long.node_uids, AND
           - the short path's entry node is NOT independently internet-exposed
             (posture_lookup[entry_uid].is_internet_exposed == False).

Phase 3: Exposure-Key grouping.
         Groups paths by (crown_jewel_uid, effective_access_principal, access_capability).
         effective_access_principal = node_uids[-2] — the last principal before the target.
         access_capability          = edge_types[-1] — the final access edge (can_read, etc.).

         This correctly groups: "ALB→EC2→AppRole→S3" and "APIGW→Lambda→AppRole→S3"
         (same exposure: AppRole reads S3) while keeping "Lambda→AdminRole→S3" separate
         (different principal → different blast radius).

         is_representative=True for highest-scoring path in each group.
         choke_node_uid = effective_access_principal (the privilege node blocking all routes).

Security notes:
  - Phase 2 independence check uses posture_lookup (DB-sourced) — NEVER trusts
    node metadata from Neo4j path alone.
  - deduplicator does not accept raw DB connections.
  - sha256 from Python standard library hashlib only.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Dict, List, Optional

from ..models.attack_path import Path, PostureRow, ScoredPath

logger = logging.getLogger("attack-path.deduplicator")


def _path_id(node_uids: List[str]) -> str:
    """Compute path_id as sha256 of pipe-joined node UIDs."""
    raw = "|".join(node_uids).encode()
    return hashlib.sha256(raw).hexdigest()


def _exposure_key(crown_jewel_uid: str, effective_principal: Optional[str], access_cap: Optional[str]) -> str:
    """Compute group_id as first 16 chars of sha256(target|principal|capability).

    Groups paths by WHO can reach WHAT via WHICH capability, not by route.
    Two paths reaching the same crown jewel via the same role + same edge type
    share an exposure key regardless of how many different entry-point routes exist.
    """
    principal = effective_principal or ""
    cap = (access_cap or "unknown").lower()
    key_str = f"{crown_jewel_uid}|{principal}|{cap}"
    return hashlib.sha256(key_str.encode()).hexdigest()[:16]


def is_suffix(short: List[str], long: List[str]) -> bool:
    """Return True if short is a proper suffix of long (len(short) < len(long)).

    AC-5: is_suffix(short, long) returns True if long[-len(short):] == short
    AND len(short) < len(long).
    """
    if len(short) >= len(long):
        return False
    return long[-len(short):] == short


def deduplicate(
    scored_paths: List[ScoredPath],
    posture_lookup: Dict[str, PostureRow],
) -> List[Path]:
    """Run all three deduplication phases and return annotated Path objects.

    Args:
        scored_paths:    Scored paths from scorer.py.
        posture_lookup:  Pre-fetched posture signals keyed by resource_uid.

    Returns:
        List of Path objects with group_id, is_representative, choke_node_uid,
        absorbed_count, and path_id populated.
    """
    if not scored_paths:
        return []

    # ── Convert ScoredPath → Path (add dedup fields) ──────────────────────────
    paths: List[Path] = []
    for sp in scored_paths:
        pid = _path_id(sp.node_uids)
        # Effective access principal = last node before crown jewel (node_uids[-2])
        # Access capability = final edge type (edge_types[-1])
        effective_principal = sp.node_uids[-2] if len(sp.node_uids) >= 2 else None
        access_cap = sp.edge_types[-1].lower() if sp.edge_types else None
        paths.append(Path(
            **sp.model_dump(),
            path_id=pid,
            group_id=None,
            group_size=1,
            is_representative=True,
            choke_node_uid=None,
            absorbed_count=0,
            effective_access_principal=effective_principal,
            access_capability=access_cap,
        ))

    # ── Phase 1: Exact dedup ───────────────────────────────────────────────────
    seen: Dict[str, Path] = {}
    for p in paths:
        existing = seen.get(p.path_id)
        if existing is None:
            seen[p.path_id] = p
        else:
            # Higher-scoring path wins
            if p.path_score > existing.path_score:
                seen[p.path_id] = p

    paths = list(seen.values())
    logger.debug("Dedup Phase 1 (exact): %d paths remaining", len(paths))

    # ── Phase 2: Subpath absorption ────────────────────────────────────────────
    # Sort by length descending so outer loop iterates potential absorbers.
    paths.sort(key=lambda p: len(p.node_uids), reverse=True)

    # Track which indexes are absorbed
    absorbed_flags = [False] * len(paths)

    for i, long_path in enumerate(paths):
        if absorbed_flags[i]:
            continue
        for j in range(i + 1, len(paths)):
            if absorbed_flags[j]:
                continue
            short_path = paths[j]
            if not is_suffix(short_path.node_uids, long_path.node_uids):
                continue

            # Independence check: if short path's entry is independently internet-exposed,
            # do NOT absorb (it is a genuine separate entry point).
            entry_uid = short_path.node_uids[0] if short_path.node_uids else ""
            entry_posture = posture_lookup.get(entry_uid)
            if entry_posture and entry_posture.is_internet_exposed:
                # Preserve the independently-exposed path (AC-4)
                continue

            # Absorb
            absorbed_flags[j] = True
            paths[i] = Path(
                **paths[i].model_dump(exclude={"absorbed_count"}),
                absorbed_count=paths[i].absorbed_count + 1,
            )

    paths = [p for idx, p in enumerate(paths) if not absorbed_flags[idx]]
    logger.debug("Dedup Phase 2 (subpath absorption): %d paths remaining", len(paths))

    # ── Phase 3: Exposure-Key grouping ────────────────────────────────────────
    # Group key = hash(crown_jewel_uid | effective_access_principal | access_capability)
    # Paths that reach the same crown jewel via the same privilege principal and
    # the same capability are the same exposure — regardless of their entry route.
    groups: Dict[str, List[int]] = {}
    for idx, p in enumerate(paths):
        key_hash = _exposure_key(p.crown_jewel_uid, p.effective_access_principal, p.access_capability)
        groups.setdefault(key_hash, []).append(idx)

    for group_id, idxs in groups.items():
        best_idx = max(idxs, key=lambda i: paths[i].path_score)
        group_size = len(idxs)

        # choke_node_uid = effective_access_principal of the representative path.
        # This is the privilege node that, if remediated, blocks ALL routes in the group.
        best_path = paths[best_idx]
        choke = best_path.effective_access_principal if group_size > 1 else None

        for idx in idxs:
            p = paths[idx]
            paths[idx] = Path(
                **p.model_dump(exclude={"group_id", "group_size", "is_representative", "choke_node_uid"}),
                group_id=group_id,
                group_size=group_size,
                is_representative=(idx == best_idx),
                choke_node_uid=choke,
            )

    logger.info(
        '{"engine":"attack-path","stage":"dedup","final_path_count":%d}',
        len(paths),
    )
    return paths
