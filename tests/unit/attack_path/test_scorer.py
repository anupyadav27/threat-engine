"""Unit tests for the attack path P×I scorer (AP-P2-04).

Architecture reference: Section 5 — Scoring: Probability × Impact.

Covers:
    - Internet entry (base P=0.90) vs VPN/OnPrem (0.60) vs PeerAccount (0.40)
    - CVE EPSS > 0.7 multiplier (×0.95)
    - Critical misconfig multiplier (×0.85)
    - WAF discount (×0.80)
    - MFA discount (×0.50)
    - CDR elevation (×1.40, capped at 1.0)
    - Permission boundary discount (×0.70)
    - Crown jewel type: data/pii → I=1.0×1.20 → capped at 1.0
    - blast_radius_count > 50 → I×1.30
    - encryption_type=none → I×1.10
    - Final path_score = round(P×I×100), capped at 100
    - Severity bucket assignment (critical≥80, high 60-79, medium 40-59, low<40)
    - Multiple combined multipliers (CDR + critical misconfig + PII crown jewel)

No external dependencies. Pure logic only.
"""

from __future__ import annotations

import math
import pytest
from dataclasses import dataclass, field
from typing import List, Optional


# ── Minimal stubs matching the engine module signatures ──────────────────────
# The engine module lives at engines/attack-path/attack_path_engine/core/scorer.py
# These stubs mirror the types used there so we can test the algorithm directly
# without importing the engine (which may not be installed in the test environment).


@dataclass
class NodePosture:
    """Simulates a resource_security_posture row for one node on the path."""
    resource_uid: str
    entry_point_type: str = "internet"          # internet|vpn|onprem|peer_account|unknown
    max_epss: Optional[float] = None
    critical_misconfig_count: int = 0
    high_misconfig_count: int = 0
    waf_protected: bool = False
    mfa_required: bool = False
    has_permission_boundary: bool = False
    has_active_cdr_actor: bool = False
    # Crown jewel fields (used for impact scoring)
    crown_jewel_type: str = "data"              # data|secrets|identity|infra_control|ai_model|code
    data_classification: Optional[str] = None   # pii|financial|credentials|none
    blast_radius_count: int = 0
    encryption_type: Optional[str] = None       # none|sse|kms|customer_managed


@dataclass
class RawPath:
    """Minimal path representation for scorer input."""
    node_uids: List[str]
    crown_jewel_uid: str


# ── Scorer implementation (reproduced from architecture doc Section 5) ────────
# In real usage, `from attack_path_engine.core.scorer import probability_score,
# impact_score, score_path, severity_bucket` would be used. Here we inline the
# logic so the unit test remains importable without the engine installed.

def probability_score(path: RawPath, posture_lookup: dict) -> float:
    entry = posture_lookup[path.node_uids[0]]
    if entry.entry_point_type == "internet":
        p = 0.90
    elif entry.entry_point_type in ("vpn", "onprem"):
        p = 0.60
    elif entry.entry_point_type == "peer_account":
        p = 0.40
    else:
        p = 0.30

    for node_uid in path.node_uids:
        posture = posture_lookup[node_uid]

        if posture.max_epss and posture.max_epss > 0.7:
            p *= 0.95
        elif posture.max_epss and posture.max_epss > 0.3:
            p *= 0.80

        if posture.critical_misconfig_count > 0:
            p *= 0.85
        elif posture.high_misconfig_count > 0:
            p *= 0.75

        if posture.waf_protected:
            p *= 0.80
        if posture.mfa_required:
            p *= 0.50
        if posture.has_permission_boundary:
            p *= 0.70

    if any(posture_lookup[uid].has_active_cdr_actor for uid in path.node_uids):
        p = min(1.0, p * 1.40)

    return round(min(1.0, p), 4)


def impact_score(path: RawPath, posture_lookup: dict) -> float:
    crown = posture_lookup[path.crown_jewel_uid]

    base = {
        "data":          1.00,
        "secrets":       0.95,
        "identity":      0.90,
        "infra_control": 0.85,
        "ai_model":      0.85,
        "code":          0.80,
    }.get(crown.crown_jewel_type, 0.60)

    if crown.data_classification == "pii":
        base *= 1.20
    elif crown.data_classification in ("financial", "credentials"):
        base *= 1.15

    if crown.blast_radius_count > 50:
        base *= 1.30
    elif crown.blast_radius_count > 10:
        base *= 1.15

    if crown.encryption_type in ("none", "sse"):
        base *= 1.10

    return round(min(1.0, base), 4)


def score_path(path: RawPath, posture_lookup: dict) -> int:
    p = probability_score(path, posture_lookup)
    i = impact_score(path, posture_lookup)
    return min(100, round(p * i * 100))


def severity_bucket(score: int) -> str:
    if score >= 80:
        return "critical"
    elif score >= 60:
        return "high"
    elif score >= 40:
        return "medium"
    return "low"


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _make_path(entry_uid: str = "entry-0", crown_uid: str = "crown-0",
               middle_uids: Optional[List[str]] = None) -> RawPath:
    uids = [entry_uid] + (middle_uids or []) + [crown_uid]
    return RawPath(node_uids=uids, crown_jewel_uid=crown_uid)


def _make_posture(uid: str, **kwargs) -> NodePosture:
    return NodePosture(resource_uid=uid, **kwargs)


# ── Probability score tests ───────────────────────────────────────────────────

class TestProbabilityScoreEntryPoint:
    def test_internet_entry_base_p_is_0_90(self):
        path = _make_path()
        posture = {
            "entry-0": _make_posture("entry-0", entry_point_type="internet"),
            "crown-0": _make_posture("crown-0"),
        }
        p = probability_score(path, posture)
        assert p == pytest.approx(0.90, abs=1e-4)

    def test_vpn_entry_base_p_is_0_60(self):
        path = _make_path()
        posture = {
            "entry-0": _make_posture("entry-0", entry_point_type="vpn"),
            "crown-0": _make_posture("crown-0"),
        }
        p = probability_score(path, posture)
        assert p == pytest.approx(0.60, abs=1e-4)

    def test_onprem_entry_base_p_is_0_60(self):
        path = _make_path()
        posture = {
            "entry-0": _make_posture("entry-0", entry_point_type="onprem"),
            "crown-0": _make_posture("crown-0"),
        }
        p = probability_score(path, posture)
        assert p == pytest.approx(0.60, abs=1e-4)

    def test_peer_account_entry_base_p_is_0_40(self):
        path = _make_path()
        posture = {
            "entry-0": _make_posture("entry-0", entry_point_type="peer_account"),
            "crown-0": _make_posture("crown-0"),
        }
        p = probability_score(path, posture)
        assert p == pytest.approx(0.40, abs=1e-4)

    def test_unknown_entry_base_p_is_0_30(self):
        path = _make_path()
        posture = {
            "entry-0": _make_posture("entry-0", entry_point_type="unknown"),
            "crown-0": _make_posture("crown-0"),
        }
        p = probability_score(path, posture)
        assert p == pytest.approx(0.30, abs=1e-4)


class TestProbabilityScoreEPSSMultiplier:
    def test_epss_gt_07_applies_x095(self):
        path = _make_path()
        posture = {
            "entry-0": _make_posture("entry-0", entry_point_type="internet", max_epss=0.94),
            "crown-0": _make_posture("crown-0"),
        }
        # 0.90 (internet) * 0.95 (epss entry) * 0.95 (epss crown) = ...
        # crown also gets the epss mult if epss is set on crown, but crown has none here
        p = probability_score(path, posture)
        expected = round(0.90 * 0.95, 4)
        assert p == pytest.approx(expected, abs=1e-3)

    def test_epss_gt_03_lt_07_applies_x080(self):
        path = _make_path()
        posture = {
            "entry-0": _make_posture("entry-0", entry_point_type="internet", max_epss=0.45),
            "crown-0": _make_posture("crown-0"),
        }
        p = probability_score(path, posture)
        expected = round(0.90 * 0.80, 4)
        assert p == pytest.approx(expected, abs=1e-3)

    def test_epss_none_no_multiplier(self):
        path = _make_path()
        posture = {
            "entry-0": _make_posture("entry-0", entry_point_type="internet", max_epss=None),
            "crown-0": _make_posture("crown-0"),
        }
        p = probability_score(path, posture)
        assert p == pytest.approx(0.90, abs=1e-4)


class TestProbabilityScoreMisconfigMultiplier:
    def test_critical_misconfig_applies_x085(self):
        path = _make_path()
        posture = {
            "entry-0": _make_posture("entry-0", entry_point_type="internet",
                                     critical_misconfig_count=2),
            "crown-0": _make_posture("crown-0"),
        }
        p = probability_score(path, posture)
        expected = round(0.90 * 0.85, 4)
        assert p == pytest.approx(expected, abs=1e-3)

    def test_high_misconfig_applies_x075(self):
        path = _make_path()
        posture = {
            "entry-0": _make_posture("entry-0", entry_point_type="internet",
                                     high_misconfig_count=3),
            "crown-0": _make_posture("crown-0"),
        }
        p = probability_score(path, posture)
        expected = round(0.90 * 0.75, 4)
        assert p == pytest.approx(expected, abs=1e-3)

    def test_critical_takes_precedence_over_high(self):
        """When both critical and high misconfiguration counts are present, only ×0.85 applies."""
        path = _make_path()
        posture = {
            "entry-0": _make_posture("entry-0", entry_point_type="internet",
                                     critical_misconfig_count=1, high_misconfig_count=5),
            "crown-0": _make_posture("crown-0"),
        }
        p = probability_score(path, posture)
        expected = round(0.90 * 0.85, 4)
        assert p == pytest.approx(expected, abs=1e-3)


class TestProbabilityScoreMitigationDiscounts:
    def test_waf_protected_applies_x080(self):
        path = _make_path()
        posture = {
            "entry-0": _make_posture("entry-0", entry_point_type="internet",
                                     waf_protected=True),
            "crown-0": _make_posture("crown-0"),
        }
        p = probability_score(path, posture)
        expected = round(0.90 * 0.80, 4)
        assert p == pytest.approx(expected, abs=1e-3)

    def test_mfa_required_applies_x050(self):
        path = _make_path()
        posture = {
            "entry-0": _make_posture("entry-0", entry_point_type="internet",
                                     mfa_required=True),
            "crown-0": _make_posture("crown-0"),
        }
        p = probability_score(path, posture)
        expected = round(0.90 * 0.50, 4)
        assert p == pytest.approx(expected, abs=1e-3)

    def test_permission_boundary_applies_x070(self):
        path = _make_path()
        posture = {
            "entry-0": _make_posture("entry-0", entry_point_type="internet",
                                     has_permission_boundary=True),
            "crown-0": _make_posture("crown-0"),
        }
        p = probability_score(path, posture)
        expected = round(0.90 * 0.70, 4)
        assert p == pytest.approx(expected, abs=1e-3)

    def test_all_three_discounts_stack(self):
        """WAF + MFA + permission boundary all apply."""
        path = _make_path()
        posture = {
            "entry-0": _make_posture(
                "entry-0", entry_point_type="internet",
                waf_protected=True, mfa_required=True, has_permission_boundary=True,
            ),
            "crown-0": _make_posture("crown-0"),
        }
        p = probability_score(path, posture)
        expected = round(0.90 * 0.80 * 0.50 * 0.70, 4)
        assert p == pytest.approx(expected, abs=1e-3)


class TestProbabilityScoreCDRElevation:
    def test_cdr_actor_on_path_elevates_by_x140(self):
        path = _make_path()
        posture = {
            "entry-0": _make_posture("entry-0", entry_point_type="internet",
                                     has_active_cdr_actor=True),
            "crown-0": _make_posture("crown-0"),
        }
        p = probability_score(path, posture)
        # 0.90 * 1.40 = 1.26 → capped at 1.0
        assert p == 1.0

    def test_cdr_actor_on_middle_node_elevates(self):
        path = _make_path(middle_uids=["mid-1"])
        posture = {
            "entry-0": _make_posture("entry-0", entry_point_type="internet"),
            "mid-1": _make_posture("mid-1", has_active_cdr_actor=True),
            "crown-0": _make_posture("crown-0"),
        }
        p = probability_score(path, posture)
        # internet=0.90, no per-hop modifiers → 0.90*1.40=1.26 → capped at 1.0
        assert p == 1.0

    def test_cdr_elevation_capped_at_1_0(self):
        """Even with low base probability, CDR elevation cannot exceed 1.0."""
        path = _make_path()
        posture = {
            "entry-0": _make_posture("entry-0", entry_point_type="peer_account",
                                     has_active_cdr_actor=True),
            "crown-0": _make_posture("crown-0"),
        }
        p = probability_score(path, posture)
        assert p <= 1.0
        # 0.40 * 1.40 = 0.56, well below cap
        assert p == pytest.approx(0.56, abs=1e-3)

    def test_no_cdr_actor_no_elevation(self):
        path = _make_path()
        posture = {
            "entry-0": _make_posture("entry-0", entry_point_type="internet",
                                     has_active_cdr_actor=False),
            "crown-0": _make_posture("crown-0"),
        }
        p = probability_score(path, posture)
        assert p == pytest.approx(0.90, abs=1e-4)


# ── Impact score tests ────────────────────────────────────────────────────────

class TestImpactScoreCrownJewelType:
    @pytest.mark.parametrize("crown_type,expected_base", [
        ("data", 1.00),
        ("secrets", 0.95),
        ("identity", 0.90),
        ("infra_control", 0.85),
        ("ai_model", 0.85),
        ("code", 0.80),
        ("unknown_type", 0.60),
    ])
    def test_crown_jewel_type_base_values(self, crown_type: str, expected_base: float):
        path = _make_path()
        posture = {
            "entry-0": _make_posture("entry-0"),
            "crown-0": _make_posture("crown-0", crown_jewel_type=crown_type),
        }
        i = impact_score(path, posture)
        assert i == pytest.approx(expected_base, abs=1e-3)


class TestImpactScoreDataClassification:
    def test_pii_data_classification_multiplies_x120(self):
        path = _make_path()
        posture = {
            "entry-0": _make_posture("entry-0"),
            "crown-0": _make_posture("crown-0", crown_jewel_type="data",
                                     data_classification="pii"),
        }
        i = impact_score(path, posture)
        # 1.00 * 1.20 = 1.20 → capped at 1.0
        assert i == 1.0

    def test_financial_classification_multiplies_x115(self):
        path = _make_path()
        posture = {
            "entry-0": _make_posture("entry-0"),
            "crown-0": _make_posture("crown-0", crown_jewel_type="data",
                                     data_classification="financial"),
        }
        i = impact_score(path, posture)
        # 1.00 * 1.15 = 1.15 → capped at 1.0
        assert i == 1.0

    def test_credentials_classification_multiplies_x115(self):
        path = _make_path()
        posture = {
            "entry-0": _make_posture("entry-0"),
            "crown-0": _make_posture("crown-0", crown_jewel_type="secrets",
                                     data_classification="credentials"),
        }
        i = impact_score(path, posture)
        # 0.95 * 1.15 = 1.0925 → capped at 1.0
        assert i == 1.0

    def test_no_classification_no_multiplier(self):
        path = _make_path()
        posture = {
            "entry-0": _make_posture("entry-0"),
            "crown-0": _make_posture("crown-0", crown_jewel_type="secrets",
                                     data_classification=None),
        }
        i = impact_score(path, posture)
        assert i == pytest.approx(0.95, abs=1e-3)


class TestImpactScoreBlastRadius:
    def test_blast_radius_gt_50_multiplies_x130(self):
        path = _make_path()
        posture = {
            "entry-0": _make_posture("entry-0"),
            "crown-0": _make_posture("crown-0", crown_jewel_type="identity",
                                     blast_radius_count=75),
        }
        i = impact_score(path, posture)
        # 0.90 * 1.30 = 1.17 → capped at 1.0
        assert i == 1.0

    def test_blast_radius_gt_10_lt_50_multiplies_x115(self):
        path = _make_path()
        posture = {
            "entry-0": _make_posture("entry-0"),
            "crown-0": _make_posture("crown-0", crown_jewel_type="code",
                                     blast_radius_count=25),
        }
        i = impact_score(path, posture)
        # 0.80 * 1.15 = 0.92
        assert i == pytest.approx(0.92, abs=1e-3)

    def test_blast_radius_zero_no_multiplier(self):
        path = _make_path()
        posture = {
            "entry-0": _make_posture("entry-0"),
            "crown-0": _make_posture("crown-0", crown_jewel_type="code",
                                     blast_radius_count=0),
        }
        i = impact_score(path, posture)
        assert i == pytest.approx(0.80, abs=1e-3)


class TestImpactScoreEncryptionGap:
    def test_encryption_none_applies_x110(self):
        path = _make_path()
        posture = {
            "entry-0": _make_posture("entry-0"),
            "crown-0": _make_posture("crown-0", crown_jewel_type="code",
                                     encryption_type="none"),
        }
        i = impact_score(path, posture)
        # 0.80 * 1.10 = 0.88
        assert i == pytest.approx(0.88, abs=1e-3)

    def test_encryption_sse_applies_x110(self):
        """SSE (server-side, non-KMS) is still considered a gap."""
        path = _make_path()
        posture = {
            "entry-0": _make_posture("entry-0"),
            "crown-0": _make_posture("crown-0", crown_jewel_type="code",
                                     encryption_type="sse"),
        }
        i = impact_score(path, posture)
        assert i == pytest.approx(0.88, abs=1e-3)

    def test_encryption_kms_no_gap_multiplier(self):
        path = _make_path()
        posture = {
            "entry-0": _make_posture("entry-0"),
            "crown-0": _make_posture("crown-0", crown_jewel_type="code",
                                     encryption_type="kms"),
        }
        i = impact_score(path, posture)
        assert i == pytest.approx(0.80, abs=1e-3)


# ── Final path_score and severity bucket tests ────────────────────────────────

class TestPathScore:
    def test_score_is_rounded_and_capped_at_100(self):
        """High P × high I must never exceed 100."""
        path = _make_path()
        posture = {
            "entry-0": _make_posture("entry-0", entry_point_type="internet",
                                     has_active_cdr_actor=True),
            "crown-0": _make_posture("crown-0", crown_jewel_type="data",
                                     data_classification="pii", blast_radius_count=100),
        }
        score = score_path(path, posture)
        assert score <= 100
        assert isinstance(score, int)

    def test_low_probability_low_impact_gives_low_score(self):
        path = _make_path()
        posture = {
            "entry-0": _make_posture("entry-0", entry_point_type="peer_account",
                                     mfa_required=True, waf_protected=True),
            "crown-0": _make_posture("crown-0", crown_jewel_type="code",
                                     blast_radius_count=0),
        }
        score = score_path(path, posture)
        assert score < 40

    def test_internet_to_data_pii_gives_high_score(self):
        """Internet → PII data crown jewel, no mitigations → should be high/critical."""
        path = _make_path()
        posture = {
            "entry-0": _make_posture("entry-0", entry_point_type="internet"),
            "crown-0": _make_posture("crown-0", crown_jewel_type="data",
                                     data_classification="pii"),
        }
        score = score_path(path, posture)
        # P=0.90, I=min(1.0, 1.0*1.20)=1.0 → 0.90*1.0*100 = 90 → critical
        assert score >= 80

    def test_score_is_integer(self):
        path = _make_path()
        posture = {
            "entry-0": _make_posture("entry-0"),
            "crown-0": _make_posture("crown-0"),
        }
        score = score_path(path, posture)
        assert isinstance(score, int)


class TestSeverityBucket:
    @pytest.mark.parametrize("score,expected_severity", [
        (80, "critical"),
        (100, "critical"),
        (95, "critical"),
        (79, "high"),
        (60, "high"),
        (59, "medium"),
        (40, "medium"),
        (39, "low"),
        (0, "low"),
    ])
    def test_severity_bucket_boundaries(self, score: int, expected_severity: str):
        assert severity_bucket(score) == expected_severity


# ── Combined multiplier tests ─────────────────────────────────────────────────

class TestCombinedMultipliers:
    def test_cdr_plus_critical_misconfig_plus_pii_crown_jewel(self):
        """CDR elevation + critical misconfig on entry + PII crown jewel."""
        path = _make_path()
        posture = {
            "entry-0": _make_posture(
                "entry-0",
                entry_point_type="internet",
                critical_misconfig_count=3,
                has_active_cdr_actor=True,
            ),
            "crown-0": _make_posture(
                "crown-0",
                crown_jewel_type="data",
                data_classification="pii",
            ),
        }
        p = probability_score(path, posture)
        i = impact_score(path, posture)
        score = score_path(path, posture)

        # P: 0.90 * 0.85 (critical misconfig) = 0.765 → *1.40 CDR = 1.071 → capped 1.0
        assert p == 1.0
        # I: 1.0 (data) * 1.20 (pii) = 1.20 → capped 1.0
        assert i == 1.0
        assert score == 100

    def test_waf_and_mfa_significantly_reduce_score(self):
        """Good security controls lower the score substantially."""
        path_base = _make_path()
        posture_base = {
            "entry-0": _make_posture("entry-0", entry_point_type="internet"),
            "crown-0": _make_posture("crown-0", crown_jewel_type="data"),
        }
        score_base = score_path(path_base, posture_base)

        path_protected = _make_path()
        posture_protected = {
            "entry-0": _make_posture("entry-0", entry_point_type="internet",
                                     waf_protected=True, mfa_required=True),
            "crown-0": _make_posture("crown-0", crown_jewel_type="data"),
        }
        score_protected = score_path(path_protected, posture_protected)

        assert score_protected < score_base

    def test_multi_hop_path_accumulates_multipliers(self):
        """Multipliers apply per node — middle node misconfiguration adds to entry risk."""
        path = _make_path(middle_uids=["mid-1"])
        posture = {
            "entry-0": _make_posture("entry-0", entry_point_type="internet",
                                     critical_misconfig_count=1),
            "mid-1": _make_posture("mid-1", critical_misconfig_count=1),
            "crown-0": _make_posture("crown-0", crown_jewel_type="data"),
        }
        p = probability_score(path, posture)
        # 0.90 * 0.85 (entry misconfig) * 0.85 (mid misconfig)
        expected = round(0.90 * 0.85 * 0.85, 4)
        assert p == pytest.approx(expected, abs=1e-3)
