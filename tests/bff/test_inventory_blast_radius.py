"""BFF tests for JNY-02: greedy :path sub-route dispatch to view_blast_radius.

Reproduces the original 500 (stray tenant_id kwarg → TypeError) and verifies
constitution-correct empty-state behaviour when the threat engine returns no data.
"""
from unittest.mock import AsyncMock, MagicMock, patch
import pytest


def _make_request():
    req = MagicMock()
    req.headers = {}
    req.state = MagicMock()
    return req


@pytest.mark.asyncio
async def test_blast_radius_returns_200_with_valid_uid():
    """Was 500 due to stray tenant_id kwarg in sub-route dispatch — must now be 200."""
    from shared.api_gateway.bff.inventory import view_asset_detail

    uid = "arn:aws:ec2:us-east-1:123456789012:instance/i-abc/blast-radius"

    fake_resp = MagicMock(status_code=200)
    fake_resp.json.return_value = {
        "reachable_resources": [],
        "reachable_count": 0,
        "depth_distribution": {},
        "resources_with_threats": 0,
    }

    with patch("shared.api_gateway.bff.inventory.resolve_tenant_id", return_value="tenant-abc"), \
         patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        mock_client.get = AsyncMock(return_value=fake_resp)
        result = await view_asset_detail(_make_request(), uid, scan_run_id="latest")

    # Must return canonical empty envelope (constitution: no fallback synthetic data)
    assert isinstance(result, dict)
    assert result.get("nodes") == []
    assert result.get("edges") == []
    assert result.get("total_impacted") == 0


@pytest.mark.asyncio
async def test_blast_radius_empty_state_for_uid_with_no_data():
    """Engine 5xx → empty envelope (no fallback). Constitution-aligned."""
    from shared.api_gateway.bff.inventory import view_asset_detail

    uid = "arn:aws:s3:::my-bucket/blast-radius"

    fake_resp = MagicMock(status_code=503)
    fake_resp.json.return_value = {}

    with patch("shared.api_gateway.bff.inventory.resolve_tenant_id", return_value="tenant-abc"), \
         patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        mock_client.get = AsyncMock(return_value=fake_resp)
        result = await view_asset_detail(_make_request(), uid, scan_run_id="latest")

    assert result.get("nodes") == []
    assert result.get("edges") == []
    assert result.get("total_impacted") == 0
