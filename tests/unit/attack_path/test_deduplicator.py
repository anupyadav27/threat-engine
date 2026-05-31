"""Unit tests for the attack path three-phase deduplicator (AP-P2-05).

Architecture reference: Section 6 — Deduplication Algorithm.

Phase 1: Exact hash dedup — identical node_uid lists → keep highest score.
Phase 2: Subpath absorption — short path is suffix of long path AND entry NOT
         independently internet-exposed → absorb into long path.
Phase 3: Convergence grouping — paths sharing (crown_jewel_uid, last-2-node-types)
         → same group_id, choke_node_uid = node_uids[-2] of group.

No external dependencies. Pure logic only.
"""

from __future__ import annotations

import hashlib
import pytest
from dataclasses import dataclass, field
from typing import List, Optional, Dict


# ── Minimal stubs ─────────────────────────────────────────────────────────────

@dataclass
class NodePosture:
    resource_uid: str
    is_internet_exposed: bool = False


@dataclass
class RawPath:
    """Represents a raw path before deduplication."""
    node_uids: List[str]
    node_types: List[str]
    crown_jewel_uid: str
    score: int = 50
    # Set by deduplicator
    group_id: Optional[str] = None
    group_size: int = 1
    choke_node_uid: Optional[str] = None
    is_representative: bool = True
    absorbed_count: int = 0


# ── Deduplicator implementation (from architecture doc Section 6) ─────────────

def _path_hash(node_uids: List[str]) -> str:
    return hashlib.sha256("|".join(node_uids).encode()).hexdigest()


def is_suffix(short: List[str], long: List[str]) -> bool:
    if len(short) >= len(long):
        return False
    return long[-len(short):] == short


def deduplicate(raw_paths: List[RawPath], posture_lookup: Dict[str, NodePosture]) -> List[RawPath]:
    # Phase 1: Exact dedup by node_uid hash — keep highest score
    seen: Dict[str, RawPath] = {}
    for p in raw_paths:
        h = _path_hash(p.node_uids)
        if h not in seen or p.score > seen[h].score:
            seen[h] = p
    paths = list(seen.values())

    # Phase 2: Subpath absorption
    # Sort longest first
    paths.sort(key=lambda p: len(p.node_uids), reverse=True)
    absorbed = set()
    for i, long_path in enumerate(paths):
        for j, short_path in enumerate(paths):
            if i == j or j in absorbed:
                continue
            if is_suffix(short_path.node_uids, long_path.node_uids):
                entry_uid = short_path.node_uids[0]
                entry_posture = posture_lookup.get(entry_uid)
                if entry_posture is None or not entry_posture.is_internet_exposed:
                    absorbed.add(j)
                    long_path.absorbed_count += 1

    paths = [p for i, p in enumerate(paths) if i not in absorbed]

    # Phase 3: Convergence grouping
    # Key = (crown_jewel_uid, last-2-node-types)
    groups: Dict[tuple, List[RawPath]] = {}
    for path in paths:
        tail = tuple(path.node_types[-2:])
        key = (path.crown_jewel_uid, tail)
        groups.setdefault(key, []).append(path)

    for group_key, group_paths in groups.items():
        gid = hashlib.sha256(str(group_key).encode()).hexdigest()[:12]
        choke = group_paths[0].node_uids[-2] if len(group_paths) > 1 else None
        best = max(group_paths, key=lambda x: x.score)
        for p in group_paths:
            p.group_id = gid
            p.group_size = len(group_paths)
            p.choke_node_uid = choke
            p.is_representative = (p is best)

    return paths


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _make_path(
    node_uids: List[str],
    node_types: List[str],
    crown_jewel_uid: str,
    score: int = 50,
) -> RawPath:
    return RawPath(
        node_uids=node_uids,
        node_types=node_types,
        crown_jewel_uid=crown_jewel_uid,
        score=score,
    )


def _make_posture(uid: str, is_internet_exposed: bool = False) -> NodePosture:
    return NodePosture(resource_uid=uid, is_internet_exposed=is_internet_exposed)


def _make_posture_map(*nodes: NodePosture) -> Dict[str, NodePosture]:
    return {n.resource_uid: n for n in nodes}


# ── Phase 1: Exact dedup tests ────────────────────────────────────────────────

class TestPhase1ExactDedup:
    def test_two_identical_paths_keep_highest_score(self):
        p1 = _make_path(["a", "b", "c"], ["ec2", "role", "s3"], "c", score=60)
        p2 = _make_path(["a", "b", "c"], ["ec2", "role", "s3"], "c", score=75)
        posture = _make_posture_map(_make_posture("a"), _make_posture("b"), _make_posture("c"))
        result = deduplicate([p1, p2], posture)
        assert len(result) == 1
        assert result[0].score == 75

    def test_identical_paths_same_score_keeps_one(self):
        p1 = _make_path(["x", "y"], ["ec2", "s3"], "y", score=50)
        p2 = _make_path(["x", "y"], ["ec2", "s3"], "y", score=50)
        posture = _make_posture_map(_make_posture("x"), _make_posture("y"))
        result = deduplicate([p1, p2], posture)
        assert len(result) == 1

    def test_different_paths_both_kept(self):
        p1 = _make_path(["a", "b", "c"], ["ec2", "role", "s3"], "c", score=60)
        p2 = _make_path(["d", "b", "c"], ["lambda", "role", "s3"], "c", score=70)
        posture = _make_posture_map(
            _make_posture("a"), _make_posture("b"),
            _make_posture("c"), _make_posture("d"),
        )
        result = deduplicate([p1, p2], posture)
        assert len(result) == 2

    def test_three_duplicates_keep_highest_score(self):
        paths = [
            _make_path(["a", "b"], ["ec2", "s3"], "b", score=40),
            _make_path(["a", "b"], ["ec2", "s3"], "b", score=90),
            _make_path(["a", "b"], ["ec2", "s3"], "b", score=55),
        ]
        posture = _make_posture_map(_make_posture("a"), _make_posture("b"))
        result = deduplicate(paths, posture)
        assert len(result) == 1
        assert result[0].score == 90

    def test_empty_input_returns_empty(self):
        result = deduplicate([], {})
        assert result == []


# ── is_suffix helper tests ────────────────────────────────────────────────────

class TestIsSuffix:
    def test_short_is_suffix_of_long(self):
        assert is_suffix(["b", "c"], ["a", "b", "c"]) is True

    def test_single_element_suffix(self):
        assert is_suffix(["c"], ["a", "b", "c"]) is True

    def test_not_suffix_different_tail(self):
        assert is_suffix(["b", "d"], ["a", "b", "c"]) is False

    def test_equal_length_returns_false(self):
        assert is_suffix(["a", "b", "c"], ["a", "b", "c"]) is False

    def test_short_longer_than_long_returns_false(self):
        assert is_suffix(["a", "b", "c", "d"], ["b", "c"]) is False

    def test_empty_short_returns_false(self):
        # Zero-length short path has no meaningful suffix relationship
        assert is_suffix([], ["a", "b"]) is False

    def test_partial_overlap_not_suffix(self):
        assert is_suffix(["a", "b"], ["x", "a", "c"]) is False


# ── Phase 2: Subpath absorption tests ────────────────────────────────────────

class TestPhase2SubpathAbsorption:
    def test_suffix_with_non_exposed_entry_is_absorbed(self):
        """Short path absorbed when its entry is NOT independently internet-exposed."""
        long_path = _make_path(
            ["internet", "ec2-1", "role-1", "s3-crown"],
            ["virtual", "ec2.instance", "iam.role", "s3.bucket"],
            "s3-crown", score=80,
        )
        short_path = _make_path(
            ["role-1", "s3-crown"],
            ["iam.role", "s3.bucket"],
            "s3-crown", score=60,
        )
        # role-1 is NOT independently internet-exposed
        posture = _make_posture_map(
            _make_posture("internet", is_internet_exposed=True),
            _make_posture("ec2-1", is_internet_exposed=False),
            _make_posture("role-1", is_internet_exposed=False),
            _make_posture("s3-crown", is_internet_exposed=False),
        )
        result = deduplicate([long_path, short_path], posture)
        assert len(result) == 1
        assert result[0].node_uids == long_path.node_uids

    def test_suffix_with_exposed_entry_is_not_absorbed(self):
        """Short path kept when its entry IS independently internet-exposed."""
        long_path = _make_path(
            ["internet", "ec2-1", "role-1", "s3-crown"],
            ["virtual", "ec2.instance", "iam.role", "s3.bucket"],
            "s3-crown", score=80,
        )
        short_path = _make_path(
            ["role-1", "s3-crown"],
            ["iam.role", "s3.bucket"],
            "s3-crown", score=60,
        )
        # role-1 IS independently internet-exposed
        posture = _make_posture_map(
            _make_posture("internet", is_internet_exposed=True),
            _make_posture("ec2-1", is_internet_exposed=False),
            _make_posture("role-1", is_internet_exposed=True),
            _make_posture("s3-crown", is_internet_exposed=False),
        )
        result = deduplicate([long_path, short_path], posture)
        assert len(result) == 2

    def test_non_suffix_path_not_absorbed(self):
        """Path with different node sequence is never absorbed regardless of exposure."""
        path_a = _make_path(
            ["a", "b", "c", "crown"],
            ["t1", "t2", "t3", "t4"],
            "crown", score=70,
        )
        path_b = _make_path(
            ["x", "y", "crown"],
            ["t5", "t6", "t4"],
            "crown", score=50,
        )
        posture = _make_posture_map(
            _make_posture("a"), _make_posture("b"), _make_posture("c"),
            _make_posture("crown"), _make_posture("x"), _make_posture("y"),
        )
        result = deduplicate([path_a, path_b], posture)
        assert len(result) == 2

    def test_absorbed_count_incremented_on_long_path(self):
        long_path = _make_path(
            ["internet", "ec2", "role", "s3"],
            ["v", "ec2.instance", "iam.role", "s3.bucket"],
            "s3", score=80,
        )
        short_path = _make_path(
            ["role", "s3"],
            ["iam.role", "s3.bucket"],
            "s3", score=40,
        )
        posture = _make_posture_map(
            _make_posture("internet", is_internet_exposed=True),
            _make_posture("ec2", is_internet_exposed=False),
            _make_posture("role", is_internet_exposed=False),
            _make_posture("s3", is_internet_exposed=False),
        )
        result = deduplicate([long_path, short_path], posture)
        assert len(result) == 1
        assert result[0].absorbed_count == 1

    def test_short_path_with_same_length_not_suffix(self):
        """Equal-length paths are never in suffix relation."""
        path_a = _make_path(["a", "b", "crown"], ["t1", "t2", "t3"], "crown", score=70)
        path_b = _make_path(["x", "b", "crown"], ["t1", "t2", "t3"], "crown", score=50)
        posture = _make_posture_map(
            _make_posture("a"), _make_posture("b"),
            _make_posture("crown"), _make_posture("x"),
        )
        result = deduplicate([path_a, path_b], posture)
        assert len(result) == 2


# ── Phase 3: Convergence grouping tests ──────────────────────────────────────

class TestPhase3ConvergenceGrouping:
    def test_three_paths_sharing_last_two_types_get_same_group_id(self):
        crown = "s3-crown"
        # All converge at (iam.role, s3.bucket)
        p1 = _make_path(["a1", "role-1", crown], ["ec2.instance", "iam.role", "s3.bucket"],
                        crown, score=80)
        p2 = _make_path(["a2", "role-1", crown], ["lambda.function", "iam.role", "s3.bucket"],
                        crown, score=70)
        p3 = _make_path(["a3", "role-1", crown], ["eks.cluster", "iam.role", "s3.bucket"],
                        crown, score=60)
        posture = _make_posture_map(
            _make_posture("a1"), _make_posture("a2"), _make_posture("a3"),
            _make_posture("role-1"), _make_posture(crown),
        )
        result = deduplicate([p1, p2, p3], posture)
        assert len(result) == 3
        group_ids = {p.group_id for p in result}
        assert len(group_ids) == 1  # all in same group

    def test_choke_node_is_second_to_last_uid(self):
        crown = "s3-crown"
        p1 = _make_path(["a1", "role-X", crown], ["ec2.instance", "iam.role", "s3.bucket"],
                        crown, score=80)
        p2 = _make_path(["a2", "role-X", crown], ["lambda.function", "iam.role", "s3.bucket"],
                        crown, score=70)
        posture = _make_posture_map(
            _make_posture("a1"), _make_posture("a2"),
            _make_posture("role-X"), _make_posture(crown),
        )
        result = deduplicate([p1, p2], posture)
        for p in result:
            assert p.choke_node_uid == "role-X"

    def test_is_representative_highest_score_path(self):
        crown = "crown"
        p1 = _make_path(["a1", "mid", crown], ["t1", "iam.role", "s3.bucket"], crown, score=90)
        p2 = _make_path(["a2", "mid", crown], ["t2", "iam.role", "s3.bucket"], crown, score=60)
        p3 = _make_path(["a3", "mid", crown], ["t3", "iam.role", "s3.bucket"], crown, score=75)
        posture = _make_posture_map(
            _make_posture("a1"), _make_posture("a2"), _make_posture("a3"),
            _make_posture("mid"), _make_posture(crown),
        )
        result = deduplicate([p1, p2, p3], posture)
        representatives = [p for p in result if p.is_representative]
        assert len(representatives) == 1
        assert representatives[0].score == 90

    def test_different_crown_jewels_get_different_groups(self):
        """Paths to different crown jewels never share a group even with same tail types."""
        p1 = _make_path(["entry", "role", "s3-a"], ["ec2.instance", "iam.role", "s3.bucket"],
                        "s3-a", score=70)
        p2 = _make_path(["entry", "role", "s3-b"], ["ec2.instance", "iam.role", "s3.bucket"],
                        "s3-b", score=70)
        posture = _make_posture_map(
            _make_posture("entry"), _make_posture("role"),
            _make_posture("s3-a"), _make_posture("s3-b"),
        )
        result = deduplicate([p1, p2], posture)
        assert len(result) == 2
        group_ids = {p.group_id for p in result}
        # Different crown jewels → different groups
        assert len(group_ids) == 2

    def test_single_path_in_group_no_choke_node(self):
        """A group of one path has choke_node_uid=None (no convergence point)."""
        p1 = _make_path(["a", "b", "crown"], ["t1", "t2", "t3"], "crown", score=60)
        posture = _make_posture_map(
            _make_posture("a"), _make_posture("b"), _make_posture("crown"),
        )
        result = deduplicate([p1], posture)
        assert len(result) == 1
        assert result[0].choke_node_uid is None

    def test_group_size_reflects_path_count_per_group(self):
        crown = "crown"
        paths = [
            _make_path([f"entry-{i}", "role", crown],
                       ["ec2.instance", "iam.role", "s3.bucket"], crown, score=50 + i * 5)
            for i in range(4)
        ]
        posture_nodes = [_make_posture(f"entry-{i}") for i in range(4)]
        posture_nodes += [_make_posture("role"), _make_posture(crown)]
        posture = _make_posture_map(*posture_nodes)
        result = deduplicate(paths, posture)
        assert all(p.group_size == 4 for p in result)


# ── Full pipeline test ────────────────────────────────────────────────────────

class TestFullDeduplicationPipeline:
    def test_exact_dup_plus_subpath_plus_convergence(self):
        """All three phases applied together."""
        crown = "s3-crown"

        # Phase 1 duplicates: same node list, different scores
        dup_a = _make_path(["inet", "ec2", "role", crown],
                           ["virtual", "ec2.instance", "iam.role", "s3.bucket"],
                           crown, score=85)
        dup_b = _make_path(["inet", "ec2", "role", crown],
                           ["virtual", "ec2.instance", "iam.role", "s3.bucket"],
                           crown, score=70)  # lower score → dropped

        # Phase 2 subpath of dup_a (role → crown, entry=role not exposed)
        subpath = _make_path(["role", crown],
                             ["iam.role", "s3.bucket"],
                             crown, score=50)

        # Second distinct path that converges with dup_a on last 2 types
        path_b = _make_path(["inet2", "lambda", "role", crown],
                            ["virtual", "lambda.function", "iam.role", "s3.bucket"],
                            crown, score=75)

        posture = _make_posture_map(
            _make_posture("inet", is_internet_exposed=True),
            _make_posture("inet2", is_internet_exposed=True),
            _make_posture("ec2", is_internet_exposed=False),
            _make_posture("lambda", is_internet_exposed=False),
            _make_posture("role", is_internet_exposed=False),
            _make_posture(crown, is_internet_exposed=False),
        )

        result = deduplicate([dup_a, dup_b, subpath, path_b], posture)

        # After phase 1: dup_b dropped (lower score), 3 remain
        # After phase 2: subpath absorbed (role not exposed), 2 remain
        # After phase 3: 2 paths grouped (same crown + same last-2-types)
        assert len(result) == 2

        scores = sorted(p.score for p in result)
        assert scores == [75, 85]

        # Both in same group
        group_ids = {p.group_id for p in result}
        assert len(group_ids) == 1

        # Choke node = second-to-last of group paths = "role"
        for p in result:
            assert p.choke_node_uid == "role"

        # Representative is highest score path
        reps = [p for p in result if p.is_representative]
        assert len(reps) == 1
        assert reps[0].score == 85

    def test_absorbed_count_on_representative_after_phase2(self):
        crown = "crown"
        long_path = _make_path(["a", "b", "c", crown],
                               ["t1", "t2", "t3", "t4"], crown, score=80)
        sub1 = _make_path(["b", "c", crown], ["t2", "t3", "t4"], crown, score=30)
        sub2 = _make_path(["c", crown], ["t3", "t4"], crown, score=20)
        posture = _make_posture_map(
            _make_posture("a"), _make_posture("b", is_internet_exposed=False),
            _make_posture("c", is_internet_exposed=False), _make_posture(crown),
        )
        result = deduplicate([long_path, sub1, sub2], posture)
        assert len(result) == 1
        assert result[0].absorbed_count == 2
