"""BFF contract tests for GET /api/v1/views/inventory/{asset_id}/ciem."""
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
    return req


_INV_DATA = {"tenant_id": "tenant-abc", "resource_uid": "arn:aws:s3:::my-bucket"}
_CIEM_FINDINGS = [
    {"actor_principal": "arn:aws:iam::123:role/MyRole", "principal_type": "role",
     "severity": "high", "action_category": "admin", "event_time": "2026-01-01T00:00:00Z"},
    {"actor_principal": "arn:aws:iam::123:role/MyRole", "principal_type": "role",
     "severity": "medium", "action_category": "read", "event_time": "2026-01-02T00:00:00Z"},
]


@pytest.mark.asyncio
async def test_200_correct_shape():
    from shared.api_gateway.bff.inventory import view_inventory_ciem
    auth = FakeAuth()
    req = _make_request()

    inv_response = MagicMock(status_code=200)
    inv_response.json.return_value = _INV_DATA
    ciem_response = MagicMock(status_code=200)
    ciem_response.json.return_value = _CIEM_FINDINGS

    with patch("shared.api_gateway.bff.inventory._parse_auth_context", return_value=auth), \
         patch("shared.api_gateway.bff.inventory.resolve_tenant_id", return_value="tenant-abc"), \
         patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        mock_client.get.side_effect = [inv_response, ciem_response]
        result = await view_inventory_ciem(req, "asset-123")

    assert "identities" in result
    assert "totalIdentities" in result
    assert "overPrivilegedCount" in result
    assert "truncated" in result


@pytest.mark.asyncio
async def test_401_unauthenticated():
    from fastapi import HTTPException
    from shared.api_gateway.bff.inventory import view_inventory_ciem
    req = _make_request()
    with patch("shared.api_gateway.bff.inventory._parse_auth_context", return_value=None):
        with pytest.raises(HTTPException) as exc:
            await view_inventory_ciem(req, "asset-123")
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_403_viewer_no_permission():
    from fastapi import HTTPException
    from shared.api_gateway.bff.inventory import view_inventory_ciem
    auth = FakeAuth(permissions=["threats:read"])  # no ciem:sensitive
    req = _make_request()
    with patch("shared.api_gateway.bff.inventory._parse_auth_context", return_value=auth):
        with pytest.raises(HTTPException) as exc:
            await view_inventory_ciem(req, "asset-123")
    assert exc.value.status_code == 403
    assert "Analyst" in exc.value.detail


@pytest.mark.asyncio
async def test_403_wrong_tenant():
    from fastapi import HTTPException
    from shared.api_gateway.bff.inventory import view_inventory_ciem
    auth = FakeAuth()
    req = _make_request()

    inv_response = MagicMock(status_code=200)
    inv_response.json.return_value = {"tenant_id": "other-tenant", "resource_uid": "x"}

    with patch("shared.api_gateway.bff.inventory._parse_auth_context", return_value=auth), \
         patch("shared.api_gateway.bff.inventory.resolve_tenant_id", return_value="tenant-abc"), \
         patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        mock_client.get.return_value = inv_response
        with pytest.raises(HTTPException) as exc:
            await view_inventory_ciem(req, "asset-123")
    assert exc.value.status_code == 403


# ─────────────────────────────────────────────────────────────────────────────
# JNY-03 MF-4: view_asset_ciem audit log + permission gate tests
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_view_asset_ciem_viewer_403(caplog):
    """Viewer (no ciem:sensitive) → 403 + audit log emitted."""
    import logging
    from fastapi import HTTPException
    from shared.api_gateway.bff.inventory import view_asset_ciem
    auth = FakeAuth(permissions=["threats:read"])
    req = _make_request()
    with patch("shared.api_gateway.bff.inventory._parse_auth_context", return_value=auth), \
         patch("shared.api_gateway.bff.inventory.resolve_tenant_id", return_value="tenant-abc"):
        with caplog.at_level(logging.INFO, logger="api-gateway.audit"):
            with pytest.raises(HTTPException) as exc:
                await view_asset_ciem(req, "arn:aws:s3:::my-bucket")
    assert exc.value.status_code == 403
    audit_recs = [r for r in caplog.records if r.name == "api-gateway.audit"]
    assert len(audit_recs) == 1
    import json
    payload = json.loads(audit_recs[0].getMessage())
    assert payload["result"] == 403
    assert payload["endpoint"].endswith("/ciem")
    assert payload["asset_id"] == "arn:aws:s3:::my-bucket"


@pytest.mark.asyncio
async def test_view_asset_ciem_cross_tenant_403(caplog):
    """Analyst whose tenant doesn't match the asset's tenant → 403 + audit."""
    import logging
    from fastapi import HTTPException
    from shared.api_gateway.bff.inventory import view_asset_ciem
    auth = FakeAuth()
    req = _make_request()
    with patch("shared.api_gateway.bff.inventory._parse_auth_context", return_value=auth), \
         patch("shared.api_gateway.bff.inventory.resolve_tenant_id", return_value="tenant-abc"), \
         patch("shared.api_gateway.bff.inventory.fetch_many",
               new=AsyncMock(return_value=[{"resource_uid": "x", "tenant_id": "other-tenant"}])):
        with caplog.at_level(logging.INFO, logger="api-gateway.audit"):
            with pytest.raises(HTTPException) as exc:
                await view_asset_ciem(req, "arn:aws:s3:::my-bucket")
    assert exc.value.status_code == 403
    audit_recs = [r for r in caplog.records if r.name == "api-gateway.audit"]
    assert any(json_loads_safe(r.getMessage()).get("result") == 403 for r in audit_recs)


@pytest.mark.asyncio
async def test_view_asset_ciem_audit_log_200(caplog):
    """Analyst happy path → 200 + audit log with top_5_identity_arns."""
    import logging
    from shared.api_gateway.bff.inventory import view_asset_ciem
    auth = FakeAuth()
    req = _make_request()
    inv = {"resource_uid": "arn:aws:s3:::my-bucket", "tenant_id": "tenant-abc"}
    ciem = {"findings": _CIEM_FINDINGS}
    with patch("shared.api_gateway.bff.inventory._parse_auth_context", return_value=auth), \
         patch("shared.api_gateway.bff.inventory.resolve_tenant_id", return_value="tenant-abc"), \
         patch("shared.api_gateway.bff.inventory.fetch_many",
               new=AsyncMock(side_effect=[[inv], [ciem]])):
        with caplog.at_level(logging.INFO, logger="api-gateway.audit"):
            result = await view_asset_ciem(req, "arn:aws:s3:::my-bucket")
    assert "identities" in result
    audit_recs = [r for r in caplog.records if r.name == "api-gateway.audit"]
    assert len(audit_recs) == 1
    import json
    payload = json.loads(audit_recs[0].getMessage())
    assert payload["result"] == 200
    assert payload["user_id"] == "user-123"
    assert payload["tenant_id"] == "tenant-abc"
    assert "top_5_identity_arns" in payload


def json_loads_safe(s):
    import json
    try:
        return json.loads(s)
    except Exception:
        return {}


@pytest.mark.asyncio
async def test_empty_findings():
    from shared.api_gateway.bff.inventory import view_inventory_ciem
    auth = FakeAuth()
    req = _make_request()

    inv_response = MagicMock(status_code=200)
    inv_response.json.return_value = _INV_DATA
    ciem_response = MagicMock(status_code=200)
    ciem_response.json.return_value = []

    with patch("shared.api_gateway.bff.inventory._parse_auth_context", return_value=auth), \
         patch("shared.api_gateway.bff.inventory.resolve_tenant_id", return_value="tenant-abc"), \
         patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        mock_client.get.side_effect = [inv_response, ciem_response]
        result = await view_inventory_ciem(req, "asset-123")

    assert result == {"identities": [], "totalIdentities": 0, "overPrivilegedCount": 0, "truncated": False}
