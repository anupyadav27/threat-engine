"""Contract tests for the universal finding-detail BFF (JNY-06).

CP-2 amendment coverage:
  - B1: only LONG canonical engine slugs accepted (Literal validation).
  - B2: PATCH endpoint emits an audit log line.
  - B3: StandardColumns has all 14 mandatory columns; sensitive keys cannot
        smuggle through findingData / engineExtensions.
  - B4: secops returns 501.
"""

from __future__ import annotations

import logging
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError


# ── B3: 14 mandatory columns on StandardColumns ─────────────────────────────

MANDATORY_14 = {
    "tenantId",
    "scanRunId",
    "credentialRef",
    "credentialType",
    "findingId",
    "accountId",
    "provider",
    "region",
    "resourceUid",
    "resourceType",
    "severity",
    "status",
    "firstSeenAt",
    "lastSeenAt",
}


def test_standard_columns_contains_mandatory_14() -> None:
    from shared.api_gateway.bff.views._schemas import StandardColumns

    assert set(StandardColumns.model_fields) >= MANDATORY_14


def test_credential_fields_excluded_from_serialization() -> None:
    from shared.api_gateway.bff.views._schemas import StandardColumns

    sc = StandardColumns(
        tenantId="t-1",
        findingId="f-1",
        credentialRef="threat-engine/cred/abc",
        credentialType="access_key",
    )
    dumped = sc.model_dump()
    assert "credentialRef" not in dumped
    assert "credentialType" not in dumped


# ── B3: model_validator scrubs sensitive keys from the full payload ────────

def _make_response(finding_data: dict | None = None, extensions: dict | None = None):
    from shared.api_gateway.bff.views._schemas import (
        ComplianceBlock,
        EngineExtensions,
        FindingDetailResponse,
        FindingHeader,
        RelatedFindingsBlock,
        RemediationBlock,
        StandardColumns,
    )

    std = StandardColumns(tenantId="t-1", findingId="f-1")
    header = FindingHeader(
        findingId="f-1",
        engine="check",
        standardColumns=std,
        findingData=finding_data or {},
    )
    return FindingDetailResponse(
        finding=header,
        resourceContext=None,
        relatedFindings=RelatedFindingsBlock(available=True),
        compliance=ComplianceBlock(available=True),
        remediation=RemediationBlock(available=True),
        engineExtensions=EngineExtensions(**(extensions or {})),
    )


def test_finding_data_credential_key_rejected() -> None:
    """A `credential_ref` smuggled into findingData must be rejected."""
    with pytest.raises(ValidationError):
        _make_response(finding_data={"credential_ref": "leak-me"})


def test_finding_data_secret_key_rejected() -> None:
    with pytest.raises(ValidationError):
        _make_response(finding_data={"my_secret": "x"})


def test_finding_data_raw_event_key_rejected() -> None:
    with pytest.raises(ValidationError):
        _make_response(finding_data={"raw_event": {"foo": "bar"}})


def test_clean_payload_serializes() -> None:
    resp = _make_response(finding_data={"title": "ok"})
    dumped = resp.model_dump()
    assert dumped["finding"]["findingData"]["title"] == "ok"


# ── B1: engine slug Literal validation ─────────────────────────────────────

def test_engine_slug_short_alias_rejected() -> None:
    """Short-form aliases like `network` / `container` / `ai` are NOT canonical."""
    from shared.api_gateway.bff.views._schemas import FindingHeader, StandardColumns

    std = StandardColumns(tenantId="t", findingId="f")
    with pytest.raises(ValidationError):
        FindingHeader(findingId="f", engine="network", standardColumns=std)


def test_engine_slug_canonical_long_accepted() -> None:
    from shared.api_gateway.bff.views._schemas import FindingHeader, StandardColumns

    std = StandardColumns(tenantId="t", findingId="f")
    h = FindingHeader(findingId="f", engine="network-security", standardColumns=std)
    assert h.engine == "network-security"


# ── B4: 501 for secops ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_secops_returns_501() -> None:
    from fastapi import HTTPException
    from shared.api_gateway.bff.views.finding_detail import get_finding_detail

    req = MagicMock()
    req.headers = {}
    req.state = MagicMock()
    req.state.auth_context = None

    with pytest.raises(HTTPException) as exc:
        await get_finding_detail(req, "secops", "abc")
    assert exc.value.status_code == 501


@pytest.mark.asyncio
async def test_unknown_engine_returns_400() -> None:
    from fastapi import HTTPException
    from shared.api_gateway.bff.views.finding_detail import get_finding_detail

    req = MagicMock()
    req.headers = {}
    req.state = MagicMock()
    with pytest.raises(HTTPException) as exc:
        await get_finding_detail(req, "not-a-real-engine", "abc")
    assert exc.value.status_code == 400


# ── 404 on not-found / cross-tenant ────────────────────────────────────────

class _FakeAuth:
    def __init__(self) -> None:
        self.user_id = "user-1"
        self.engine_tenant_id = "tenant-abc"
        self.tenant_ids = ["tenant-abc"]

    def has_permission(self, key: str) -> bool:
        return True

    def is_platform_level(self) -> bool:
        return False

    def can_access_tenant(self, t: str) -> bool:
        return True


@pytest.mark.asyncio
async def test_404_when_no_row() -> None:
    from fastapi import HTTPException
    from shared.api_gateway.bff.views import finding_detail as fd

    req = MagicMock()
    req.headers = {}
    req.state = MagicMock()
    req.state.auth_context = _FakeAuth()

    async def _allow(_request):
        return _FakeAuth()

    with patch.object(fd, "require_permission", lambda _p: _allow), \
         patch.object(fd, "resolve_tenant_id", return_value="tenant-abc"), \
         patch.object(fd, "_read_finding_row", return_value=None):
        with pytest.raises(HTTPException) as exc:
            await fd.get_finding_detail(req, "check", "missing-id")
    assert exc.value.status_code == 404


# ── B2: PATCH emits audit log ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_patch_emits_audit_log(caplog: pytest.LogCaptureFixture) -> None:
    from shared.api_gateway.bff.views import finding_detail as fd
    from shared.api_gateway.bff.views._schemas import StatusUpdateRequest

    req = MagicMock()
    req.headers = {"x-request-id": "req-1"}
    req.state = MagicMock()
    req.state.auth_context = _FakeAuth()

    fake_row = {
        "finding_id": "f-1",
        "scan_run_id": None,
        "tenant_id": "tenant-abc",
        "account_id": "acct",
        "credential_ref": None,
        "credential_type": None,
        "provider": "aws",
        "region": "us-east-1",
        "resource_uid": "arn:aws:s3:::bucket",
        "resource_type": "s3_bucket",
        "severity": "high",
        "status": "RESOLVED",
        "first_seen_at": datetime.utcnow(),
        "last_seen_at": datetime.utcnow(),
        "rule_id": "RULE-1",
        "finding_data": {"title": "Public bucket"},
    }

    async def _allow(_request):
        return _FakeAuth()

    body = StatusUpdateRequest(status="RESOLVED", note="ack")

    with patch.object(fd, "require_permission", lambda _p: _allow), \
         patch.object(fd, "resolve_tenant_id", return_value="tenant-abc"), \
         patch.object(fd, "_write_status", return_value=fake_row):
        with caplog.at_level(logging.INFO, logger="api-gateway.audit"):
            result = await fd.patch_finding_status(req, body, "check", "f-1")

    assert result.findingId == "f-1"
    audit_records = [
        r for r in caplog.records if r.name == "api-gateway.audit"
    ]
    assert audit_records, "expected an audit log entry"
    rec = audit_records[0]
    assert rec.message == "finding_status_change"
    # Verify load-bearing fields landed on the LogRecord via `extra=`
    assert getattr(rec, "engine", None) == "check"
    assert getattr(rec, "finding_id", None) == "f-1"
    assert getattr(rec, "new_status", None) == "RESOLVED"
    assert getattr(rec, "tenant_id", None) == "tenant-abc"
