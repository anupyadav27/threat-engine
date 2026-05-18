"""
Unit tests for attack_path_engine.core.scorer — AP-P2-04.

Tests verify:
  - Entry point base probabilities
  - CDR actor elevation (×1.40, post-loop)
  - WAF/MFA/permission boundary discounts
  - EPSS multipliers
  - Impact crown jewel type weights
  - Combined discount formula: 0.90 × 0.80 × 0.50 × 0.70 ≈ 0.252
  - path_score = round(min(100, P × I × 100))
  - Severity bucket assignment
  - probability never reaches 0.0
"""

import sys
import os

# Allow import from engines directory during tests
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "engines", "attack-path"))

import pytest

from attack_path_engine.core.scorer import (
    compute_path_score,
    impact_score,
    probability_score,
    score_paths,
    severity_bucket,
)
from attack_path_engine.models.attack_path import PostureRow, RawPath


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _raw_path(
    entry_uid: str = "entry-1",
    crown_uid: str = "crown-1",
    node_uids: list | None = None,
    node_types: list | None = None,
) -> RawPath:
    return RawPath(
        crown_jewel_uid=crown_uid,
        entry_point_uid=entry_uid,
        node_uids=node_uids or [entry_uid, crown_uid],
        node_types=node_types or ["internet", "rds.instance"],
        edge_types=["CONNECTED_TO"],
        hop_categories=["internet", "data"],
        depth=1,
    )


def _posture(uid: str, **kwargs) -> PostureRow:
    return PostureRow(resource_uid=uid, **kwargs)


# ---------------------------------------------------------------------------
# probability_score — base probability from entry point type
# ---------------------------------------------------------------------------

def test_internet_entry_base_probability():
    path = _raw_path(entry_uid="e1", node_types=["Internet", "rds.instance"])
    posture_lookup = {
        "e1": _posture("e1", entry_point_type="internet"),
        "crown-1": _posture("crown-1"),
    }
    p = probability_score(path, posture_lookup)
    assert abs(p - 0.90) < 0.01, f"Expected ~0.90, got {p}"


def test_vpn_entry_base_probability():
    path = _raw_path(entry_uid="e1", node_types=["vpn", "rds.instance"])
    posture_lookup = {"e1": _posture("e1", entry_point_type="vpn")}
    p = probability_score(path, posture_lookup)
    assert abs(p - 0.60) < 0.01, f"Expected ~0.60, got {p}"


def test_peer_account_entry_base_probability():
    path = _raw_path(entry_uid="e1", node_types=["PeerAccount", "rds.instance"])
    posture_lookup = {"e1": _posture("e1", entry_point_type="peer_account")}
    p = probability_score(path, posture_lookup)
    assert abs(p - 0.40) < 0.01, f"Expected ~0.40, got {p}"


# ---------------------------------------------------------------------------
# probability_score — CDR actor elevation
# ---------------------------------------------------------------------------

def test_cdr_actor_elevates_probability():
    path = _raw_path(entry_uid="e1", node_types=["internet", "rds.instance"])
    # Without CDR
    posture_no_cdr = {
        "e1": _posture("e1", entry_point_type="internet"),
        "crown-1": _posture("crown-1"),
    }
    p_no_cdr = probability_score(path, posture_no_cdr)

    # With CDR on one node
    posture_with_cdr = {
        "e1": _posture("e1", entry_point_type="internet", has_active_cdr_actor=True),
        "crown-1": _posture("crown-1"),
    }
    p_with_cdr = probability_score(path, posture_with_cdr)

    assert p_with_cdr > p_no_cdr, "CDR actor must elevate probability"
    # CDR elevation is ×1.40 applied after loop
    assert abs(p_with_cdr - min(1.0, 0.90 * 1.40)) < 0.01


# ---------------------------------------------------------------------------
# probability_score — WAF/MFA/permission boundary discounts
# ---------------------------------------------------------------------------

def test_waf_discount():
    path = _raw_path(entry_uid="e1", node_types=["internet", "rds.instance"])
    posture_lookup = {
        "e1": _posture("e1", entry_point_type="internet", waf_protected=True),
        "crown-1": _posture("crown-1"),
    }
    p = probability_score(path, posture_lookup)
    # internet (0.90) × waf (0.80) = 0.72
    assert abs(p - 0.90 * 0.80) < 0.01, f"Expected ~{0.90 * 0.80:.4f}, got {p}"


def test_mfa_discount():
    path = _raw_path(entry_uid="e1", node_types=["internet", "rds.instance"])
    posture_lookup = {
        "e1": _posture("e1", entry_point_type="internet", mfa_required=True),
        "crown-1": _posture("crown-1"),
    }
    p = probability_score(path, posture_lookup)
    # internet (0.90) × mfa (0.50) = 0.45
    assert abs(p - 0.90 * 0.50) < 0.01


def test_waf_mfa_boundary_combined_discount():
    """WAF + MFA + permission boundary combined: 0.90 × 0.80 × 0.50 × 0.70 ≈ 0.252."""
    path = _raw_path(entry_uid="e1", node_types=["internet", "rds.instance"])
    posture_lookup = {
        "e1": _posture(
            "e1",
            entry_point_type="internet",
            waf_protected=True,
            mfa_required=True,
            has_permission_boundary=True,
        ),
        "crown-1": _posture("crown-1"),
    }
    p = probability_score(path, posture_lookup)
    expected = 0.90 * 0.80 * 0.50 * 0.70
    assert abs(p - expected) < 0.01, f"Expected ~{expected:.4f}, got {p}"


# ---------------------------------------------------------------------------
# probability_score — probability never reaches 0.0
# ---------------------------------------------------------------------------

def test_probability_never_zero():
    """With every discount stacked, probability must remain > 0.0."""
    path = _raw_path(
        entry_uid="e1",
        node_uids=["e1", "mid", "crown-1"],
        node_types=["peer_account", "iam.role", "rds.instance"],
    )
    posture_lookup = {
        "e1": _posture("e1", entry_point_type="peer_account"),
        "mid": _posture(
            "mid",
            waf_protected=True,
            mfa_required=True,
            has_permission_boundary=True,
            max_epss=0.80,
            critical_misconfig_count=3,
        ),
        "crown-1": _posture("crown-1"),
    }
    p = probability_score(path, posture_lookup)
    assert p > 0.0, "probability must never be 0.0"


# ---------------------------------------------------------------------------
# impact_score — PII crown jewel
# ---------------------------------------------------------------------------

def test_pii_crown_jewel_impact():
    """data type with pii classification: base 1.00 × data_class 1.20."""
    path = _raw_path(crown_uid="c1")
    posture_lookup = {
        "entry-1": _posture("entry-1"),
        "c1": _posture("c1", crown_jewel_type="data", data_classification="pii"),
    }
    i = impact_score(path, posture_lookup)
    expected = 1.00 * 1.20
    assert abs(i - expected) < 0.01, f"Expected ~{expected:.4f}, got {i}"


def test_blast_radius_multiplier():
    """blast_radius_count > 50 → I × 1.30."""
    path = _raw_path(crown_uid="c1")
    posture_lookup = {
        "entry-1": _posture("entry-1"),
        "c1": _posture("c1", crown_jewel_type="data", blast_radius_count=60),
    }
    i = impact_score(path, posture_lookup)
    expected = 1.00 * 1.30  # data base × blast_radius
    assert abs(i - expected) < 0.01


def test_no_encryption_multiplier():
    """encryption_type='none' → I × 1.10."""
    path = _raw_path(crown_uid="c1")
    posture_lookup = {
        "entry-1": _posture("entry-1"),
        "c1": _posture("c1", crown_jewel_type="data", encryption_type="none"),
    }
    i = impact_score(path, posture_lookup)
    expected = 1.00 * 1.10  # data base × no_encryption
    assert abs(i - expected) < 0.01


# ---------------------------------------------------------------------------
# path_score formula and severity buckets
# ---------------------------------------------------------------------------

def test_path_score_formula():
    """path_score = round(min(100, P × I × 100))."""
    p_val = 0.80
    i_val = 1.20
    score = compute_path_score(p_val, i_val)
    expected = round(min(100, p_val * i_val * 100))
    assert score == expected


def test_severity_critical():
    assert severity_bucket(87) == "critical"
    assert severity_bucket(80) == "critical"


def test_severity_high():
    assert severity_bucket(65) == "high"
    assert severity_bucket(60) == "high"
    assert severity_bucket(79) == "high"


def test_severity_medium():
    assert severity_bucket(55) == "medium"
    assert severity_bucket(40) == "medium"
    assert severity_bucket(59) == "medium"


def test_severity_low():
    assert severity_bucket(39) == "low"
    assert severity_bucket(0) == "low"


# ---------------------------------------------------------------------------
# score_paths integration
# ---------------------------------------------------------------------------

def test_score_paths_returns_scored_paths():
    raw_paths = [
        _raw_path(entry_uid="e1", crown_uid="c1"),
        _raw_path(entry_uid="e2", crown_uid="c2"),
    ]
    posture_lookup = {
        "e1": _posture("e1", entry_point_type="internet"),
        "c1": _posture("c1", crown_jewel_type="data"),
        "e2": _posture("e2", entry_point_type="vpn"),
        "c2": _posture("c2", crown_jewel_type="secrets"),
    }
    scored = score_paths(raw_paths, posture_lookup)
    assert len(scored) == 2
    for sp in scored:
        assert sp.path_score >= 0
        assert sp.severity in ("critical", "high", "medium", "low")
        assert sp.probability_score > 0.0
        assert sp.impact_score > 0.0
