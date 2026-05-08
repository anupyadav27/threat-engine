"""Unit tests for the threat_posture_delta BFF handler (THREAT-UI-03).

Covers:
    - _compute_delta: new / resolved / escalated / de-escalated classification
    - _composite_score: weighted scoring
    - _attack_coverage_pct: tactic coverage
    - _build_available_scans: scan list construction
    - view_threat_posture_delta HTTP endpoint: 2-scan comparison, single-scan mode, empty list
    - view_threat_trend HTTP endpoint: 90-day window, 7-day window, provider filter
"""

import json
import pytest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient
from fastapi import FastAPI

_AUTH_CTX = json.dumps({
    "user_id": "test-user",
    "email": "test@cspm.local",
    "role": "analyst",
    "level": 4,
    "scope_level": "tenant",
    "permissions": ["threats:read", "scans:read"],
    "tenant_ids": ["t1"],
    "account_ids": None,
    "engine_tenant_id": "t1",
    "org_ids": None,
})
_AUTH_HEADERS = {"X-Auth-Context": _AUTH_CTX}

from shared.api_gateway.bff.threat_posture_delta import (
    router,
    _compute_delta,
    _composite_score,
    _attack_coverage_pct,
    _build_available_scans,
    _scenario_key,
    _date_label,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────

def _make_scenario(uid: str, category: str, severity: str, risk_score: int) -> dict:
    return {
        "scenario_id": f"id-{uid}-{category}",
        "title": f"{category} on {uid}",
        "severity": severity,
        "risk_score": risk_score,
        "resource_uid": uid,
        "resource_name": uid,
        "resource_type": "aws_s3_bucket",
        "csp": "aws",
        "region": "us-east-1",
        "account_id": "123456789012",
        "threat_category": category,
        "mitre_techniques": [],
        "first_seen_at": "2026-04-28T12:00:00Z",
        "last_seen_at": "2026-04-28T12:00:00Z",
    }


# ── Pure helper tests ─────────────────────────────────────────────────────────

class TestCompositeScore:
    def test_empty_list(self):
        assert _composite_score([]) == 0

    def test_single_critical(self):
        s = [_make_scenario("r1", "Exposure", "critical", 90)]
        score = _composite_score(s)
        assert 0 <= score <= 100

    def test_lower_score_for_lower_risk(self):
        high = [_make_scenario("r1", "E", "critical", 80)]
        low_ = [_make_scenario("r1", "E", "low", 20)]
        assert _composite_score(high) > _composite_score(low_)


class TestAttackCoveragePct:
    def test_empty(self):
        assert _attack_coverage_pct([]) == 0.0

    def test_no_mitre_techniques(self):
        s = [_make_scenario("r1", "E", "high", 70)]
        assert _attack_coverage_pct(s) == 0.0

    def test_with_known_tactic(self):
        s = [{
            **_make_scenario("r1", "E", "high", 70),
            "mitre_techniques": [{"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access"}],
        }]
        pct = _attack_coverage_pct(s)
        assert pct > 0.0
        assert pct <= 100.0


class TestBuildAvailableScans:
    def test_empty_list(self):
        assert _build_available_scans([]) == []

    def test_deduplicates_and_sorts_newest_first(self):
        runs = [
            {"scan_run_id": "aaa", "completed_at": "2026-04-28T12:00:00Z"},
            {"scan_run_id": "bbb", "completed_at": "2026-05-01T10:00:00Z"},
            {"scan_run_id": "aaa", "completed_at": "2026-04-28T12:00:00Z"},  # duplicate
        ]
        result = _build_available_scans(runs)
        assert len(result) == 2
        assert result[0]["scan_run_id"] == "bbb"  # newest first
        assert result[1]["scan_run_id"] == "aaa"

    def test_label_generation(self):
        runs = [{"scan_run_id": "xxx", "completed_at": "2026-05-01T10:00:00Z"}]
        result = _build_available_scans(runs)
        assert result[0]["label"] == "May 01"

    def test_skips_missing_scan_run_id(self):
        runs = [
            {"completed_at": "2026-05-01T10:00:00Z"},  # no scan_run_id
            {"scan_run_id": "yyy", "completed_at": "2026-05-01T10:00:00Z"},
        ]
        result = _build_available_scans(runs)
        assert len(result) == 1
        assert result[0]["scan_run_id"] == "yyy"


class TestComputeDelta:
    def test_no_overlap_all_new(self):
        sa = []
        sb = [_make_scenario("r1", "Exposure", "high", 70)]
        new_, resolved, esc, de_esc = _compute_delta(sa, sb)
        assert len(new_) == 1
        assert len(resolved) == 0
        assert len(esc) == 0
        assert len(de_esc) == 0

    def test_no_overlap_all_resolved(self):
        sa = [_make_scenario("r1", "Exposure", "high", 70)]
        sb = []
        new_, resolved, esc, de_esc = _compute_delta(sa, sb)
        assert len(new_) == 0
        assert len(resolved) == 1

    def test_escalated(self):
        base = _make_scenario("r1", "Exposure", "high", 60)
        newer = {**base, "risk_score": 85}
        new_, resolved, esc, de_esc = _compute_delta([base], [newer])
        assert len(esc) == 1
        assert esc[0]["risk_score_a"] == 60
        assert esc[0]["risk_score_b"] == 85
        assert esc[0]["risk_score_delta"] == 25

    def test_deescalated(self):
        base = _make_scenario("r1", "Exposure", "high", 85)
        newer = {**base, "risk_score": 60}
        new_, resolved, esc, de_esc = _compute_delta([base], [newer])
        assert len(de_esc) == 1
        assert de_esc[0]["risk_score_delta"] == -25

    def test_unchanged_not_in_any_list(self):
        s = _make_scenario("r1", "Exposure", "high", 70)
        new_, resolved, esc, de_esc = _compute_delta([s], [s])
        assert len(new_) == 0
        assert len(resolved) == 0
        assert len(esc) == 0
        assert len(de_esc) == 0

    def test_mixed_scenario(self):
        sa = [
            _make_scenario("r1", "CatA", "critical", 90),  # will be resolved
            _make_scenario("r2", "CatB", "high", 60),       # will escalate to 80
        ]
        sb = [
            _make_scenario("r2", "CatB", "high", 80),       # escalated
            _make_scenario("r3", "CatC", "medium", 50),     # new
        ]
        new_, resolved, esc, de_esc = _compute_delta(sa, sb)
        assert len(new_) == 1
        assert new_[0]["resource_uid"] == "r3"
        assert len(resolved) == 1
        assert resolved[0]["resource_uid"] == "r1"
        assert len(esc) == 1
        assert esc[0]["resource_uid"] == "r2"
        assert esc[0]["risk_score_delta"] == 20


# ── HTTP endpoint tests ───────────────────────────────────────────────────────

@pytest.fixture
def app():
    a = FastAPI()
    a.include_router(router)
    return a


@pytest.fixture
def client(app):
    return TestClient(app, raise_server_exceptions=False)


# Sample threat data returned by the threat engine /api/v1/threat/ui-data
_THREAT_DATA_A = {
    "threats": [
        {
            "id": "det-001",
            "resource_uid": "arn:aws:s3:::bucket-a",
            "threat_category": "PublicAccess",
            "severity": "critical",
            "risk_score": 90,
            "resource_name": "bucket-a",
            "region": "us-east-1",
            "provider": "aws",
            "account_id": "123456789012",
        }
    ],
    "scan_meta": {"completed_at": "2026-04-28T12:00:00Z"},
}

_THREAT_DATA_B = {
    "threats": [
        {
            "id": "det-001",
            "resource_uid": "arn:aws:s3:::bucket-a",
            "threat_category": "PublicAccess",
            "severity": "critical",
            "risk_score": 95,  # escalated
            "resource_name": "bucket-a",
            "region": "us-east-1",
            "provider": "aws",
            "account_id": "123456789012",
        },
        {
            "id": "det-002",
            "resource_uid": "arn:aws:iam:::role/over-perm",
            "threat_category": "ExcessivePermissions",
            "severity": "high",
            "risk_score": 75,  # new
            "resource_name": "over-perm",
            "region": "us-east-1",
            "provider": "aws",
            "account_id": "123456789012",
        },
    ],
    "scan_meta": {"completed_at": "2026-05-01T10:00:00Z"},
}

_SCAN_RUNS_DATA = {
    "scan_runs": [
        {"scan_run_id": "scan-bbb", "completed_at": "2026-05-01T10:00:00Z", "status": "completed"},
        {"scan_run_id": "scan-aaa", "completed_at": "2026-04-28T12:00:00Z", "status": "completed"},
    ],
    "count": 2,
}


class TestPostureDeltaEndpoint:
    def test_two_scan_comparison(self, client):
        """AC1: Returns summary, new_scenarios, resolved, escalated, deescalated, available_scans."""
        with patch(
            "shared.api_gateway.bff.threat_posture_delta.fetch_many",
            new=AsyncMock(side_effect=[
                [_SCAN_RUNS_DATA],                        # first call: scan list
                [_THREAT_DATA_A, _THREAT_DATA_B],         # second call: both scans
            ]),
        ):
            resp = client.get(
                "/api/v1/views/threat-posture-delta",
                params={"scan_a": "scan-aaa", "scan_b": "scan-bbb"},
                headers=_AUTH_HEADERS,
            )
        assert resp.status_code == 200
        data = resp.json()
        assert "summary" in data
        assert "new_scenarios" in data
        assert "resolved_scenarios" in data
        assert "escalated_scenarios" in data
        assert "deescalated_scenarios" in data
        assert "available_scans" in data
        assert data["single_scan_mode"] is False

    def test_escalated_scenario_has_delta_fields(self, client):
        """AC10: Escalated scenarios include risk_score_a, risk_score_b, risk_score_delta."""
        with patch(
            "shared.api_gateway.bff.threat_posture_delta.fetch_many",
            new=AsyncMock(side_effect=[
                [_SCAN_RUNS_DATA],
                [_THREAT_DATA_A, _THREAT_DATA_B],
            ]),
        ):
            resp = client.get(
                "/api/v1/views/threat-posture-delta",
                params={"scan_a": "scan-aaa", "scan_b": "scan-bbb"},
                headers=_AUTH_HEADERS,
            )
        data = resp.json()
        # bucket-a is in both scans but escalated from 90 → 95
        esc = data["escalated_scenarios"]
        assert len(esc) >= 1
        assert "risk_score_a" in esc[0]
        assert "risk_score_b" in esc[0]
        assert "risk_score_delta" in esc[0]
        assert esc[0]["risk_score_delta"] > 0

    def test_single_scan_mode_one_scan(self, client):
        """AC13: single_scan_mode=true when only one scan is available."""
        single_run = {
            "scan_runs": [
                {"scan_run_id": "scan-only", "completed_at": "2026-05-01T10:00:00Z"},
            ],
            "count": 1,
        }
        with patch(
            "shared.api_gateway.bff.threat_posture_delta.fetch_many",
            new=AsyncMock(side_effect=[
                [single_run],
                [_THREAT_DATA_B],  # single-scan fetch
            ]),
        ):
            resp = client.get(
                "/api/v1/views/threat-posture-delta",
                headers=_AUTH_HEADERS,
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["single_scan_mode"] is True
        assert data["new_scenarios"] == []
        assert data["escalated_scenarios"] == []
        assert data["available_scans"][0]["scan_run_id"] == "scan-only"

    def test_single_scan_mode_empty_scan_list(self, client):
        """AC13: single_scan_mode=true when no scans exist."""
        with patch(
            "shared.api_gateway.bff.threat_posture_delta.fetch_many",
            new=AsyncMock(side_effect=[
                [{"scan_runs": [], "count": 0}],
                # single-scan fetch not called when scan_b is absent
            ]),
        ):
            resp = client.get(
                "/api/v1/views/threat-posture-delta",
                headers=_AUTH_HEADERS,
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["single_scan_mode"] is True
        assert data["available_scans"] == []

    def test_no_credential_ref_in_response(self, client):
        """Security: credential_ref must never appear in the response."""
        with patch(
            "shared.api_gateway.bff.threat_posture_delta.fetch_many",
            new=AsyncMock(side_effect=[
                [_SCAN_RUNS_DATA],
                [_THREAT_DATA_A, _THREAT_DATA_B],
            ]),
        ):
            resp = client.get(
                "/api/v1/views/threat-posture-delta",
                params={"scan_a": "scan-aaa", "scan_b": "scan-bbb"},
                headers=_AUTH_HEADERS,
            )
        import json
        assert "credential_ref" not in json.dumps(resp.json())


class TestThreatTrendEndpoint:
    _TREND_ENGINE_RESP = {
        "tenant_id": "t1",
        "days": 90,
        "trend_data": [
            {
                "date": "2026-02-10",
                "total_threats": 28,
                "by_severity": {"critical": 2, "high": 7, "medium": 14, "low": 5},
                "by_category": {"Initial Access": 3, "Credential Access": 4, "Exfiltration": 2},
            },
            {
                "date": "2026-03-15",
                "total_threats": 33,
                "by_severity": {"critical": 4, "high": 9, "medium": 12, "low": 8},
                "by_category": {"Initial Access": 5, "Credential Access": 6},
            },
        ],
        "summary": {"trend_direction": "increasing", "percent_change": 17.9},
    }

    _SCAN_RUNS = {
        "scan_runs": [
            {"scan_run_id": "scan-feb", "completed_at": "2026-02-10T08:00:00Z"},
            {"scan_run_id": "scan-mar", "completed_at": "2026-03-15T09:00:00Z"},
        ],
        "count": 2,
    }

    def test_90_day_window(self, client):
        """AC2: Returns trend_data with date, risk_score, severity counts."""
        with patch(
            "shared.api_gateway.bff.threat_posture_delta.fetch_many",
            new=AsyncMock(return_value=[self._TREND_ENGINE_RESP, self._SCAN_RUNS]),
        ):
            resp = client.get(
                "/api/v1/views/threat-trend",
                params={"days": "90"},
                headers=_AUTH_HEADERS,
            )
        assert resp.status_code == 200
        data = resp.json()
        assert "trend_data" in data
        assert data["days"] == 90
        # Each point must have required fields
        for pt in data["trend_data"]:
            assert "date" in pt
            assert "risk_score" in pt
            assert "critical" in pt
            assert "high" in pt
            assert "medium" in pt
            assert "low" in pt
            assert "total" in pt

    def test_7_day_window(self, client):
        """AC2: 7-day window accepted."""
        with patch(
            "shared.api_gateway.bff.threat_posture_delta.fetch_many",
            new=AsyncMock(return_value=[self._TREND_ENGINE_RESP, self._SCAN_RUNS]),
        ):
            resp = client.get(
                "/api/v1/views/threat-trend",
                params={"days": "7"},
                headers=_AUTH_HEADERS,
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["days"] == 7

    def test_tactics_in_response_when_available(self, client):
        """Tactics map present when engine provides by_category."""
        with patch(
            "shared.api_gateway.bff.threat_posture_delta.fetch_many",
            new=AsyncMock(return_value=[self._TREND_ENGINE_RESP, self._SCAN_RUNS]),
        ):
            resp = client.get(
                "/api/v1/views/threat-trend",
                params={"days": "90"},
                headers=_AUTH_HEADERS,
            )
        data = resp.json()
        pts_with_tactics = [p for p in data["trend_data"] if "tactics" in p]
        assert len(pts_with_tactics) > 0

    def test_empty_trend_data(self, client):
        """Graceful response when engine returns no trend data."""
        import shared.api_gateway.bff._cache as _cache_mod
        _cache_mod._store.clear()  # flush in-process cache so no prior test bleeds in

        with patch(
            "shared.api_gateway.bff.threat_posture_delta.fetch_many",
            new=AsyncMock(return_value=[
                {"trend_data": [], "days": 90},
                {"scan_runs": [], "count": 0},
            ]),
        ):
            import json as _j
            _empty_headers = {"X-Auth-Context": _j.dumps({
                "user_id": "test-user", "email": "test@cspm.local", "role": "analyst",
                "level": 4, "scope_level": "tenant", "permissions": [],
                "tenant_ids": ["t2-empty"], "account_ids": None,
                "engine_tenant_id": "t2-empty", "org_ids": None,
            })}
            resp = client.get(
                "/api/v1/views/threat-trend",
                headers=_empty_headers,
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["trend_data"] == []
        assert data["total_scans"] == 0

    def test_scan_run_id_linked_to_date(self, client):
        """Trend data points include scan_run_id for tooltip link."""
        with patch(
            "shared.api_gateway.bff.threat_posture_delta.fetch_many",
            new=AsyncMock(return_value=[self._TREND_ENGINE_RESP, self._SCAN_RUNS]),
        ):
            resp = client.get(
                "/api/v1/views/threat-trend",
                params={"days": "90"},
                headers=_AUTH_HEADERS,
            )
        data = resp.json()
        # At least some points should have scan_run_id
        ids = [p["scan_run_id"] for p in data["trend_data"] if p.get("scan_run_id")]
        assert len(ids) > 0
