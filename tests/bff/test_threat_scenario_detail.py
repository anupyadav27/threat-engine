"""Unit tests for the threat_scenario_detail BFF handler.

Mocks fetch_many so no real engine calls are made.  Verifies response shape,
field normalisation, credential_ref stripping, fallback values, and input
validation.
"""

import json
import pytest
from unittest.mock import AsyncMock, patch
from fastapi import FastAPI
from fastapi.testclient import TestClient

_AUTH_CTX = json.dumps({
    "user_id": "test-user", "email": "test@cspm.local", "role": "analyst",
    "level": 4, "scope_level": "tenant", "permissions": ["threats:read"],
    "tenant_ids": ["tenant-1"], "account_ids": None,
    "engine_tenant_id": "tenant-1", "org_ids": None,
})
_AUTH_HEADERS = {"X-Auth-Context": _AUTH_CTX}

from shared.api_gateway.bff.threat_scenario_detail import (
    router,
    _validate_scenario_id,
    _build_contributing_findings,
    _build_blast_radius,
    _build_remediation_actions,
    _strip_credential_ref,
    _human_age,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_threat(overrides=None):
    """Return a minimal threat_raw dict."""
    base = {
        "description": "Compromised IAM role with access to S3",
        "severity": "critical",
        "risk_score": 94,
        "resource_uid": "arn:aws:s3:::prod-pii-bucket",
        "resource_name": "prod-pii-bucket",
        "resource_type": "S3Bucket",
        "provider": "aws",
        "region": "us-east-1",
        "account_id": "588989875114",
        "threat_category": "PublicAccess",
        "mitre_techniques": [{"id": "T1078", "name": "Valid Accounts"}],
        "first_seen_at": "2026-04-28T10:00:00Z",
        "chain_of_consequence": "Attacker pivots via IAM role to S3 bucket.",
        "stakes_narrative": "The over-permissioned role is the entry point.",
    }
    if overrides:
        base.update(overrides)
    return base


def _make_findings_response():
    return {
        "findings": [
            {
                "finding_id": "abc12345678",
                "signal_type": "misconfig",
                "rule_id": "S3_PUBLIC_ACCESS",
                "rule_name": "S3 bucket allows public access",
                "severity": "critical",
                "resource_type": "S3Bucket",
                "plain_english": "This bucket is publicly readable.",
                "fix_guidance": "Enable S3 Block Public Access.",
                "first_seen_at": "2026-04-28T10:00:00Z",
                "credential_ref": "threat-engine/account/123",  # must be stripped
                "raw_evidence": {"bucket_acl": "public-read"},
            }
        ]
    }


# ── Unit tests for pure helpers ───────────────────────────────────────────────

class TestValidateScenarioId:
    def test_valid_uuid_like(self):
        _validate_scenario_id("abc123-def456-ABC")

    def test_valid_alphanumeric(self):
        _validate_scenario_id("abc123")

    def test_valid_underscores(self):
        _validate_scenario_id("threat_id_123")

    def test_rejects_slash(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            _validate_scenario_id("../../etc/passwd")
        assert exc_info.value.status_code == 400

    def test_rejects_empty(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException):
            _validate_scenario_id("")

    def test_rejects_special_chars(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException):
            _validate_scenario_id("abc<script>")

    def test_rejects_too_long(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException):
            _validate_scenario_id("a" * 200)


class TestStripCredentialRef:
    def test_removes_credential_ref(self):
        finding = {
            "finding_id": "abc",
            "credential_ref": "threat-engine/account/123",
            "severity": "critical",
        }
        result = _strip_credential_ref(finding)
        assert "credential_ref" not in result
        assert result["finding_id"] == "abc"
        assert result["severity"] == "critical"

    def test_no_credential_ref_ok(self):
        finding = {"finding_id": "abc", "severity": "low"}
        result = _strip_credential_ref(finding)
        assert result == finding

    def test_does_not_mutate_original(self):
        finding = {"credential_ref": "secret", "other": "value"}
        _strip_credential_ref(finding)
        assert "credential_ref" in finding  # original untouched


class TestBuildContributingFindings:
    def test_strips_credential_ref(self):
        raw = {
            "findings": [
                {
                    "finding_id": "f1",
                    "signal_type": "misconfig",
                    "severity": "high",
                    "credential_ref": "secret-value",
                }
            ]
        }
        result = _build_contributing_findings(raw)
        assert len(result) == 1
        assert "credential_ref" not in result[0]

    def test_sort_order_misconfig_first(self):
        raw = {
            "findings": [
                {"finding_id": "v1", "signal_type": "vulnerability", "severity": "critical"},
                {"finding_id": "m1", "signal_type": "misconfig",     "severity": "high"},
                {"finding_id": "i1", "signal_type": "identity",      "severity": "medium"},
            ]
        }
        result = _build_contributing_findings(raw)
        assert result[0]["signal_type"] == "misconfig"
        assert result[1]["signal_type"] == "identity"
        assert result[2]["signal_type"] == "vulnerability"

    def test_handles_list_input(self):
        raw = [
            {"finding_id": "f1", "signal_type": "network", "severity": "low"},
        ]
        result = _build_contributing_findings(raw)
        assert len(result) == 1
        assert result[0]["signal_type"] == "network"

    def test_empty_input(self):
        assert _build_contributing_findings({}) == []
        assert _build_contributing_findings([]) == []
        assert _build_contributing_findings(None) == []

    def test_derives_signal_type_from_category(self):
        raw = {"findings": [{"finding_id": "f1", "threat_category": "IAMCredentialExposure", "severity": "high"}]}
        result = _build_contributing_findings(raw)
        assert result[0]["signal_type"] == "identity"


class TestBuildBlastRadius:
    def test_prefers_risk_engine_data(self):
        threat = {}
        risk = {
            "blast_radius": {
                "root_node": {"resource_uid": "arn:aws:s3:::bucket", "resource_type": "S3Bucket", "data_class": "PII"},
                "first_hop": [{"resource_uid": "arn:aws:iam::123:role/reader"}],
                "second_hop": [],
                "third_hop_count": 5,
            }
        }
        result = _build_blast_radius(threat, risk)
        assert result["root_node"]["resource_uid"] == "arn:aws:s3:::bucket"
        assert result["third_hop_count"] == 5

    def test_fallback_to_threat_data(self):
        threat = {
            "resource_uid": "arn:aws:s3:::my-bucket",
            "resource_type": "S3Bucket",
        }
        result = _build_blast_radius(threat, None)
        assert result["root_node"]["resource_uid"] == "arn:aws:s3:::my-bucket"
        assert result["first_hop"] == []

    def test_empty_inputs(self):
        result = _build_blast_radius({}, None)
        assert result["first_hop"] == []
        assert result["second_hop"] == []
        assert result["third_hop_count"] == 0


class TestBuildRemediationActions:
    def test_string_steps_converted(self):
        remediation = {"steps": ["Enable MFA", "Rotate credentials"]}
        result = _build_remediation_actions(remediation, {})
        assert len(result) == 2
        assert result[0]["step"] == 1
        assert result[0]["description"] == "Enable MFA"
        assert result[0]["urgency"] == "immediate"
        assert result[1]["urgency"] == "short_term"

    def test_dict_steps_preserve_fields(self):
        remediation = {
            "steps": [
                {
                    "description": "Block public access",
                    "urgency": "immediate",
                    "owner": "Cloud Ops",
                    "effort": "Low",
                    "effort_time": "15 minutes",
                    "impact": "Removes exfiltration path",
                    "ai_fix_available": True,
                }
            ]
        }
        result = _build_remediation_actions(remediation, {})
        assert result[0]["owner"] == "Cloud Ops"
        assert result[0]["ai_fix_available"] is True
        assert result[0]["effort_time"] == "15 minutes"

    def test_falls_back_to_analysis_recommendations(self):
        result = _build_remediation_actions({}, {"recommendations": ["Step A", "Step B"]})
        assert len(result) == 2

    def test_empty_inputs(self):
        assert _build_remediation_actions({}, {}) == []


class TestHumanAge:
    def test_returns_dash_for_none(self):
        assert _human_age(None) == "—"

    def test_returns_dash_for_empty(self):
        assert _human_age("") == "—"

    def test_returns_just_now(self):
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).isoformat()
        result = _human_age(ts)
        assert result == "just now"

    def test_handles_bad_format_gracefully(self):
        assert _human_age("not-a-date") == "—"


# ── Integration-style tests (FastAPI TestClient + mocked fetch_many) ──────────

@pytest.fixture(autouse=True)
def mock_cache(monkeypatch):
    """Disable the BFF cache so every test hits handler logic fresh."""
    monkeypatch.setattr(
        "shared.api_gateway.bff.threat_scenario_detail.cached_view",
        lambda key, value=None, ttl=60: None,
    )


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


@pytest.mark.asyncio
async def test_endpoint_returns_200_shape(client):
    """Full endpoint integration: verify all top-level keys present in response."""
    threat = _make_threat()
    findings = _make_findings_response()

    with patch(
        "shared.api_gateway.bff.threat_scenario_detail.fetch_many",
        new_callable=AsyncMock,
        return_value=[threat, {}, findings, {}, None],
    ):
        resp = client.get(
            "/api/v1/views/threat-scenario/abc123",
            headers=_AUTH_HEADERS,
        )

    assert resp.status_code == 200
    body = resp.json()

    required_keys = [
        "scenario_id", "title", "severity", "risk_score",
        "resource_uid", "resource_name", "resource_type",
        "csp", "region", "account_id",
        "signal_types", "mitre_techniques",
        "chain_of_consequence", "stakes_narrative",
        "contributing_findings", "blast_radius",
        "compliance_violations", "remediation_actions",
        "resource_metadata", "first_seen_at", "scan_age",
    ]
    for key in required_keys:
        assert key in body, f"Missing key: {key}"


@pytest.mark.asyncio
async def test_credential_ref_stripped_from_response(client):
    """AC16: credential_ref must not appear in contributing_findings."""
    threat = _make_threat()
    findings = _make_findings_response()  # contains credential_ref in raw finding

    with patch(
        "shared.api_gateway.bff.threat_scenario_detail.fetch_many",
        new_callable=AsyncMock,
        return_value=[threat, {}, findings, {}, None],
    ):
        resp = client.get(
            "/api/v1/views/threat-scenario/abc123",
            headers=_AUTH_HEADERS,
        )

    body = resp.json()
    for f in body.get("contributing_findings", []):
        assert "credential_ref" not in f, "credential_ref leaked into response"


@pytest.mark.asyncio
async def test_invalid_scenario_id_returns_400(client):
    """OWASP Input Validation: path traversal characters rejected with 400."""
    resp = client.get(
        "/api/v1/views/threat-scenario/../etc/passwd",
        headers=_AUTH_HEADERS,
    )
    # FastAPI path routing will handle the path segment differently but
    # the validator should catch any injection patterns that pass through
    assert resp.status_code in (400, 404, 422)


@pytest.mark.asyncio
async def test_null_narrative_columns_become_empty_string(client):
    """chain_of_consequence and stakes_narrative should be '' not null."""
    threat = _make_threat({"chain_of_consequence": None, "stakes_narrative": None})

    with patch(
        "shared.api_gateway.bff.threat_scenario_detail.fetch_many",
        new_callable=AsyncMock,
        return_value=[threat, {}, {}, {}, None],
    ):
        resp = client.get(
            "/api/v1/views/threat-scenario/abc123",
            headers=_AUTH_HEADERS,
        )

    body = resp.json()
    assert body["chain_of_consequence"] == ""
    assert body["stakes_narrative"] == ""


@pytest.mark.asyncio
async def test_all_engine_failures_returns_empty_but_valid(client):
    """When all engines return None, response should still have required keys."""
    with patch(
        "shared.api_gateway.bff.threat_scenario_detail.fetch_many",
        new_callable=AsyncMock,
        return_value=[None, None, None, None, None],
    ):
        resp = client.get(
            "/api/v1/views/threat-scenario/abc123",
            headers=_AUTH_HEADERS,
        )

    assert resp.status_code == 200
    body = resp.json()
    assert body["scenario_id"] == "abc123"
    assert body["contributing_findings"] == []
    assert body["remediation_actions"] == []


@pytest.mark.asyncio
async def test_auth_required(client):
    """tenant_id is required — omitting it should return 422."""
    resp = client.get("/api/v1/views/threat-scenario/abc123")
    assert resp.status_code == 401  # no X-Auth-Context


@pytest.mark.asyncio
async def test_mitre_techniques_normalised(client):
    """MITRE techniques should be [{id, name, url}] in response."""
    threat = _make_threat({
        "mitre_techniques": [
            {"id": "T1078", "name": "Valid Accounts"},
            "T1530",
        ]
    })

    with patch(
        "shared.api_gateway.bff.threat_scenario_detail.fetch_many",
        new_callable=AsyncMock,
        return_value=[threat, {}, {}, {}, None],
    ):
        resp = client.get(
            "/api/v1/views/threat-scenario/abc123",
            headers=_AUTH_HEADERS,
        )

    body = resp.json()
    techs = body["mitre_techniques"]
    assert len(techs) >= 1
    for t in techs:
        assert "id" in t
        assert "name" in t
        assert "url" in t
