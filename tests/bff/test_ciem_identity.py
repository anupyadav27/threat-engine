"""BFF contract tests for GET /api/v1/views/ciem_identity.

Covers JNY-03 MF-3:
  - ciem:sensitive permission gate (viewer → 403)
  - audit log on 200 + 403 with required SOC2 fields
"""
import json
import logging
from unittest.mock import AsyncMock, MagicMock, patch
import pytest


class FakeAuth:
    def __init__(self, permissions=None, tenant_id="tenant-abc"):
        self.permissions = permissions if permissions is not None else ["ciem:sensitive"]
        self.engine_tenant_id = tenant_id
        self.tenant_ids = [tenant_id]
        self.user_id = "user-123"

    def is_platform_level(self):
        return False

    def can_access_tenant(self, tid):
        return True


def _make_request():
    req = MagicMock()
    req.headers = {}
    req.state = MagicMock()
    return req


@pytest.mark.asyncio
async def test_view_ciem_identity_viewer_403(caplog):
    """Viewer (no ciem:sensitive) → 403 + audit log emitted with result=403."""
    from fastapi import HTTPException
    from shared.api_gateway.bff.ciem_identity import view_ciem_identity
    auth = FakeAuth(permissions=["threats:read"])
    req = _make_request()
    with patch("shared.api_gateway.bff.ciem_identity._parse_auth_context", return_value=auth), \
         patch("shared.api_gateway.bff.ciem_identity.resolve_tenant_id", return_value="tenant-abc"):
        with caplog.at_level(logging.INFO, logger="api-gateway.audit"):
            with pytest.raises(HTTPException) as exc:
                await view_ciem_identity(req, principal="arn:aws:iam::123:role/X", scan_run_id=None)
    assert exc.value.status_code == 403
    recs = [r for r in caplog.records if r.name == "api-gateway.audit"]
    assert len(recs) == 1
    payload = json.loads(recs[0].getMessage())
    assert payload["result"] == 403
    assert payload["endpoint"] == "GET /api/v1/views/ciem_identity"
    assert payload["principal"] == "arn:aws:iam::123:role/X"
    assert payload["user_id"] == "user-123"
    assert payload["tenant_id"] == "tenant-abc"


@pytest.mark.asyncio
async def test_view_ciem_identity_audit_log_200(caplog):
    """Analyst → 200 + audit log with top_5_identity_arns + all SOC2 fields."""
    from shared.api_gateway.bff.ciem_identity import view_ciem_identity
    auth = FakeAuth()
    req = _make_request()
    identity = {"identity_arn": "arn:aws:iam::123:role/X"}
    findings = {"findings": [
        {"actor_principal": "arn:aws:iam::123:role/X", "severity": "high"},
    ]}
    activity = {"hourly_data": [], "dow_data": []}

    async def fake_fetch_engine(client, engine, path, params=None, auth_headers=None):
        if path.endswith("/profile"):
            return identity
        if path.endswith("/findings"):
            return findings
        if path.endswith("/activity"):
            return activity
        return None

    with patch("shared.api_gateway.bff.ciem_identity._parse_auth_context", return_value=auth), \
         patch("shared.api_gateway.bff.ciem_identity.resolve_tenant_id", return_value="tenant-abc"), \
         patch("shared.api_gateway.bff.ciem_identity._fetch_engine", new=fake_fetch_engine), \
         patch("shared.api_gateway.bff.ciem_identity.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        with caplog.at_level(logging.INFO, logger="api-gateway.audit"):
            result = await view_ciem_identity(req, principal="arn:aws:iam::123:role/X", scan_run_id=None)
    assert "identity" in result
    recs = [r for r in caplog.records if r.name == "api-gateway.audit"]
    assert len(recs) == 1
    payload = json.loads(recs[0].getMessage())
    assert payload["result"] == 200
    for required in ("timestamp", "user_id", "tenant_id", "endpoint", "principal", "request_id", "top_5_identity_arns"):
        assert required in payload, f"audit payload missing {required}"
