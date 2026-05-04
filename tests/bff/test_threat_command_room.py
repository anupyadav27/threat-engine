"""Unit tests for the threat_command_room BFF handler.

Mocks fetch_many so no real engine calls are made.  Verifies response shape,
signal_type derivation, title construction, and empty-state handling.
"""

import pytest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient
from fastapi import FastAPI

from shared.api_gateway.bff.threat_command_room import router, _build_title, _derive_signal_types, _composite_score


# ── Unit tests for pure helpers ───────────────────────────────────────────────

class TestBuildTitle:
    def test_uses_description_when_sentence(self):
        det = {"description": "Exposed S3 bucket allows public read access"}
        assert _build_title(det) == "Exposed S3 bucket allows public read access"

    def test_ignores_rule_id_like_description(self):
        det = {"description": "aws.s3.public_access", "threat_category": "PublicAccess", "resource_uid": "arn:aws:s3:::my-bucket"}
        title = _build_title(det)
        assert "aws.s3" not in title
        assert "my-bucket" in title

    def test_builds_from_threat_category(self):
        det = {"threat_category": "DataExposure", "resource_uid": "arn:aws:s3:::pii-bucket"}
        title = _build_title(det)
        assert "pii-bucket" in title
        assert "Data" in title

    def test_fallback_with_rule_id(self):
        det = {"rule_id": "aws.iam.excessive_permissions", "resource_uid": "arn:aws:iam::123:role/admin"}
        title = _build_title(det)
        assert "aws" in title.lower() or "iam" in title.lower()

    def test_all_empty(self):
        title = _build_title({})
        assert "Threat scenario" in title


class TestDeriveSignalTypes:
    @pytest.mark.parametrize("category,expected", [
        ("IAMCredentialExposure", "identity"),
        ("ExcessivePermissions",  "identity"),
        ("DataExposure",          "misconfig"),
        ("PublicAccess",          "misconfig"),
        ("NetworkExposure",       "network"),
        ("VulnerabilityExploit",  "vulnerability"),
        ("AIModelRisk",           "ai_security"),
        ("UnknownCategory",       "misconfig"),
        ("",                      "misconfig"),
    ])
    def test_mapping(self, category, expected):
        result = _derive_signal_types(category)
        assert result == [expected]


class TestCompositeScore:
    def test_empty_list_returns_zero(self):
        assert _composite_score([]) == 0

    def test_single_critical_high_score(self):
        scenarios = [{"severity": "critical", "risk_score": 90}]
        score = _composite_score(scenarios)
        assert 0 <= score <= 100
        assert score == 90  # single item, weighted avg = score itself

    def test_mixed_severities(self):
        scenarios = [
            {"severity": "critical", "risk_score": 90},
            {"severity": "low",      "risk_score": 10},
        ]
        score = _composite_score(scenarios)
        # critical weight=4, low weight=1 → (90*4 + 10*1) / 5 = 370/5 = 74
        assert score == 74

    def test_capped_at_100(self):
        scenarios = [{"severity": "critical", "risk_score": 200}]
        assert _composite_score(scenarios) == 100

    def test_zero_risk_scores(self):
        scenarios = [{"severity": "high", "risk_score": 0}]
        assert _composite_score(scenarios) == 0


# ── Integration-style tests (FastAPI TestClient, fetch_many mocked) ───────────

import json

# Minimal auth context for integration tests — matches the X-Auth-Context header format
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

_MOCK_THREAT_DATA = {
    "threats": [
        {
            "id": "det-001",
            "description": "Overly permissive IAM role allows cross-account access",
            "threat_category": "ExcessivePermissions",
            "severity": "critical",
            "risk_score": 88,
            "resource_uid": "arn:aws:iam::123456:role/admin-role",
            "resource_name": "admin-role",
            "resource_type": "IAMRole",
            "csp": "aws",
            "region": "us-east-1",
            "account_id": "123456789012",
            "mitre_techniques": [{"id": "T1078", "name": "Valid Accounts"}],
            "first_seen_at": "2026-05-01T08:00:00Z",
        },
        {
            "id": "det-002",
            "description": "Public S3 bucket with PII data exposed",
            "threat_category": "DataExposure",
            "severity": "high",
            "risk_score": 72,
            "resource_uid": "arn:aws:s3:::pii-bucket",
            "resource_name": "pii-bucket",
            "resource_type": "S3Bucket",
            "csp": "aws",
            "region": "us-east-1",
            "account_id": "123456789012",
            "mitre_techniques": ["T1530"],
            "first_seen_at": "2026-05-01T09:00:00Z",
        },
    ],
    "summary": {
        "total_detections": 2,
        "critical": 1,
        "high": 1,
        "medium": 0,
        "low": 0,
    },
    "scan_meta": {
        "scan_run_id": "scan-run-abc",
        "status": "completed",
    },
}


@pytest.fixture
def test_app():
    app = FastAPI()
    app.include_router(router)
    return app


@pytest.fixture
def client(test_app):
    return TestClient(test_app)


@pytest.fixture(autouse=True)
def mock_cache(monkeypatch):
    """Disable the BFF cache so every test hits the handler logic."""
    monkeypatch.setattr(
        "shared.api_gateway.bff.threat_command_room.cached_view",
        lambda key, value=None, ttl=60: None,
    )


@pytest.fixture
def mock_fetch(monkeypatch):
    async def _fake_fetch_many(calls, auth_headers=None):
        return [_MOCK_THREAT_DATA]

    monkeypatch.setattr(
        "shared.api_gateway.bff.threat_command_room.fetch_many",
        _fake_fetch_many,
    )


class TestViewThreatCommandRoom:
    def test_returns_200_with_required_shape(self, client, mock_fetch):
        resp = client.get("/api/v1/views/threat-command-room", headers=_AUTH_HEADERS)
        assert resp.status_code == 200
        body = resp.json()
        assert "pulse_stats" in body
        assert "scenarios" in body
        assert "total" in body
        assert "scan_run_id" in body

    def test_pulse_stats_counts(self, client, mock_fetch):
        resp = client.get("/api/v1/views/threat-command-room", headers=_AUTH_HEADERS)
        ps = resp.json()["pulse_stats"]
        assert ps["critical_count"] == 1
        assert ps["high_count"] == 1
        assert ps["medium_count"] == 0
        assert ps["low_count"] == 0

    def test_pulse_stats_composite_score_nonzero(self, client, mock_fetch):
        resp = client.get("/api/v1/views/threat-command-room", headers=_AUTH_HEADERS)
        ps = resp.json()["pulse_stats"]
        assert 0 < ps["composite_score"] <= 100

    def test_scenarios_sorted_by_risk_score_desc(self, client, mock_fetch):
        resp = client.get("/api/v1/views/threat-command-room", headers=_AUTH_HEADERS)
        scenarios = resp.json()["scenarios"]
        assert len(scenarios) == 2
        assert scenarios[0]["risk_score"] >= scenarios[1]["risk_score"]

    def test_scenario_has_required_fields(self, client, mock_fetch):
        resp = client.get("/api/v1/views/threat-command-room", headers=_AUTH_HEADERS)
        s = resp.json()["scenarios"][0]
        required_fields = [
            "scenario_id", "title", "severity", "risk_score",
            "resource_uid", "resource_name", "resource_type",
            "csp", "region", "account_id", "signal_types",
            "mitre_techniques", "setup_summary", "first_seen_at",
        ]
        for field in required_fields:
            assert field in s, f"Missing field: {field}"

    def test_signal_types_derived_from_category(self, client, mock_fetch):
        resp = client.get("/api/v1/views/threat-command-room", headers=_AUTH_HEADERS)
        scenarios = resp.json()["scenarios"]
        # det-001: ExcessivePermissions → identity
        iam_scenario = next(s for s in scenarios if s["scenario_id"] == "det-001")
        assert "identity" in iam_scenario["signal_types"]
        # det-002: DataExposure → misconfig
        s3_scenario = next(s for s in scenarios if s["scenario_id"] == "det-002")
        assert "misconfig" in s3_scenario["signal_types"]

    def test_mitre_techniques_normalised(self, client, mock_fetch):
        resp = client.get("/api/v1/views/threat-command-room", headers=_AUTH_HEADERS)
        scenarios = resp.json()["scenarios"]
        # det-001: list-of-dicts
        iam = next(s for s in scenarios if s["scenario_id"] == "det-001")
        assert iam["mitre_techniques"][0]["id"] == "T1078"
        # det-002: list-of-strings
        s3 = next(s for s in scenarios if s["scenario_id"] == "det-002")
        assert s3["mitre_techniques"][0]["id"] == "T1530"

    def test_no_credential_ref_in_response(self, client, mock_fetch):
        resp = client.get("/api/v1/views/threat-command-room", headers=_AUTH_HEADERS)
        body = resp.json()
        body_str = str(body)
        assert "credential_ref" not in body_str

    def test_auth_required(self, client, mock_fetch):
        resp = client.get("/api/v1/views/threat-command-room")
        assert resp.status_code == 401

    def test_provider_filter_applied(self, client, monkeypatch):
        """When provider=azure is passed, aws threats are excluded."""
        async def _fake_fetch(calls, auth_headers=None):
            return [_MOCK_THREAT_DATA]

        monkeypatch.setattr(
            "shared.api_gateway.bff.threat_command_room.fetch_many",
            _fake_fetch,
        )
        resp = client.get("/api/v1/views/threat-command-room?provider=azure", headers=_AUTH_HEADERS)
        assert resp.status_code == 200
        body = resp.json()
        # All mock detections have csp=aws, so filter for azure should yield 0
        assert body["total"] == 0
        assert body["scenarios"] == []

    def test_empty_response_when_engine_down(self, client, monkeypatch):
        """Engine returning None → empty pulse_stats with 0 counts."""
        async def _fail_fetch(calls, auth_headers=None):
            return [None]

        monkeypatch.setattr(
            "shared.api_gateway.bff.threat_command_room.fetch_many",
            _fail_fetch,
        )
        resp = client.get("/api/v1/views/threat-command-room", headers=_AUTH_HEADERS)
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 0
        assert body["pulse_stats"]["critical_count"] == 0
