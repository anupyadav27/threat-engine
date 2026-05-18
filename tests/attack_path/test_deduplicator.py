"""
Unit tests for attack_path_engine.core.deduplicator — AP-P2-05.

Tests verify all 3 phases:
  Phase 1: exact dedup by sha256 of node_uids
  Phase 2: subpath absorption (with independence check)
  Phase 3: convergence grouping (group_id, is_representative, choke_node_uid)
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "engines", "attack-path"))

import pytest

from attack_path_engine.core.deduplicator import deduplicate, is_suffix
from attack_path_engine.models.attack_path import PostureRow, ScoredPath


def _scored_path(
    node_uids: list,
    node_types: list | None = None,
    crown_uid: str = "crown-1",
    entry_uid: str = "entry-1",
    path_score: int = 50,
    severity: str = "medium",
) -> ScoredPath:
    """Helper to construct a minimal ScoredPath."""
    if node_types is None:
        node_types = ["internet"] + ["compute"] * (len(node_uids) - 2) + ["rds.instance"]
        node_types = node_types[:len(node_uids)]
    return ScoredPath(
        crown_jewel_uid=crown_uid,
        entry_point_uid=entry_uid,
        node_uids=node_uids,
        node_types=node_types,
        edge_types=["CONNECTED_TO"] * max(0, len(node_uids) - 1),
        hop_categories=node_types,
        depth=len(node_uids) - 1,
        path_score=path_score,
        severity=severity,
        probability_score=0.50,
        impact_score=1.00,
        chain_type="Internet → Data",
    )


def _posture(uid: str, **kwargs) -> PostureRow:
    return PostureRow(resource_uid=uid, **kwargs)


# ---------------------------------------------------------------------------
# is_suffix helper
# ---------------------------------------------------------------------------

def test_is_suffix_true():
    assert is_suffix(["B", "C"], ["A", "B", "C"]) is True


def test_is_suffix_false_not_suffix():
    assert is_suffix(["A", "C"], ["A", "B", "C"]) is False


def test_is_suffix_same_length():
    # Same length means NOT proper suffix
    assert is_suffix(["A", "B", "C"], ["A", "B", "C"]) is False


def test_is_suffix_empty():
    assert is_suffix([], ["A", "B"]) is False


# ---------------------------------------------------------------------------
# Phase 1: Exact dedup
# ---------------------------------------------------------------------------

def test_phase1_exact_dedup_lower_score_removed():
    """Two paths with identical node_uids — lower-scored one removed."""
    uids = ["entry-1", "mid-1", "crown-1"]
    p1 = _scored_path(uids, path_score=70)
    p2 = _scored_path(uids, path_score=40)
    posture_lookup = {}
    result = deduplicate([p1, p2], posture_lookup)
    assert len(result) == 1
    assert result[0].path_score == 70


def test_phase1_different_paths_both_survive():
    """Paths with different node_uids both survive Phase 1."""
    p1 = _scored_path(["entry-1", "mid-1", "crown-1"], path_score=70)
    p2 = _scored_path(["entry-2", "mid-2", "crown-1"], path_score=40)
    result = deduplicate([p1, p2], {})
    assert len(result) == 2


# ---------------------------------------------------------------------------
# Phase 2: Subpath absorption
# ---------------------------------------------------------------------------

def test_phase2_subpath_absorbed_when_entry_not_internet_exposed():
    """Short path with non-internet-exposed entry absorbed into longer path."""
    long_uids = ["entry-1", "mid-1", "crown-1"]
    short_uids = ["mid-1", "crown-1"]   # suffix of long_uids

    long_path = _scored_path(long_uids, path_score=70)
    short_path = _scored_path(short_uids, path_score=40)

    # mid-1 is the short path's entry — NOT internet-exposed
    posture_lookup = {
        "mid-1": _posture("mid-1", is_internet_exposed=False),
    }
    result = deduplicate([long_path, short_path], posture_lookup)

    # short path should be absorbed
    surviving_ids = [p.path_id for p in result]
    assert len(result) == 1
    assert result[0].absorbed_count == 1


def test_phase2_subpath_not_absorbed_when_entry_internet_exposed():
    """Short path with internet-exposed entry NOT absorbed — remains as separate path."""
    long_uids = ["entry-1", "mid-1", "crown-1"]
    short_uids = ["mid-1", "crown-1"]  # suffix of long

    long_path = _scored_path(long_uids, path_score=70)
    short_path = _scored_path(short_uids, path_score=40)

    # mid-1 is internet-exposed → must NOT be absorbed
    posture_lookup = {
        "mid-1": _posture("mid-1", is_internet_exposed=True),
    }
    result = deduplicate([long_path, short_path], posture_lookup)
    assert len(result) == 2


# ---------------------------------------------------------------------------
# Phase 3: Convergence grouping
# ---------------------------------------------------------------------------

def test_phase3_same_crown_and_tail_types_share_group_id():
    """Two paths with same (crown_jewel_uid, last-2-node-types) share a group_id."""
    # Both end in ["iam.role", "rds.instance"] and same crown jewel
    p1 = _scored_path(
        ["entry-A", "iam.role-1", "crown-1"],
        node_types=["internet", "iam.role", "rds.instance"],
        crown_uid="crown-1",
        path_score=70,
    )
    p2 = _scored_path(
        ["entry-B", "iam.role-2", "crown-1"],
        node_types=["vpn", "iam.role", "rds.instance"],
        crown_uid="crown-1",
        path_score=50,
    )
    result = deduplicate([p1, p2], {})
    assert len(result) == 2
    # They should share a group_id (same tail types + same crown)
    assert result[0].group_id == result[1].group_id


def test_phase3_representative_is_highest_score():
    """Highest-scoring path in group is marked is_representative=True."""
    p1 = _scored_path(
        ["entry-A", "iam.role-1", "crown-1"],
        node_types=["internet", "iam.role", "rds.instance"],
        crown_uid="crown-1",
        path_score=70,
    )
    p2 = _scored_path(
        ["entry-B", "iam.role-2", "crown-1"],
        node_types=["vpn", "iam.role", "rds.instance"],
        crown_uid="crown-1",
        path_score=50,
    )
    result = deduplicate([p1, p2], {})
    representatives = [p for p in result if p.is_representative]
    assert len(representatives) == 1
    assert representatives[0].path_score == 70


def test_phase3_choke_node_uid_is_penultimate():
    """choke_node_uid = node_uids[-2] of the representative path for groups > 1."""
    p1 = _scored_path(
        ["entry-A", "iam-node", "crown-1"],
        node_types=["internet", "iam.role", "rds.instance"],
        crown_uid="crown-1",
        path_score=70,
    )
    p2 = _scored_path(
        ["entry-B", "iam-node-2", "crown-1"],
        node_types=["vpn", "iam.role", "rds.instance"],
        crown_uid="crown-1",
        path_score=50,
    )
    result = deduplicate([p1, p2], {})
    # Both should have choke_node_uid set (it's the penultimate uid of the representative)
    rep = next(p for p in result if p.is_representative)
    assert rep.choke_node_uid == rep.node_uids[-2]


# ---------------------------------------------------------------------------
# End-to-end: 10 input paths → fewer than 10 output after all phases
# ---------------------------------------------------------------------------

def test_end_to_end_reduces_paths():
    """10 input paths with known structure → fewer than 10 output paths."""
    paths = []

    # 5 paths with identical node_uids — only 1 should survive Phase 1
    for i in range(5):
        paths.append(_scored_path(["entry-1", "mid-1", "crown-1"], path_score=50 + i))

    # 2 paths with subpath relationship (non-internet-exposed entry)
    paths.append(_scored_path(["entry-2", "mid-2", "crown-2"], path_score=60))  # long
    paths.append(_scored_path(["mid-2", "crown-2"], path_score=40))             # short (to be absorbed)

    # 3 distinct paths that survive all phases
    for i in range(3):
        paths.append(_scored_path([f"e-unique-{i}", f"m-unique-{i}", "crown-3"], path_score=30 + i))

    posture_lookup = {
        "mid-2": _posture("mid-2", is_internet_exposed=False),
    }

    result = deduplicate(paths, posture_lookup)
    assert len(result) < 10, f"Expected < 10 output paths, got {len(result)}"
