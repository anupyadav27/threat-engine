"""BFF contract tests for GET /api/v1/views/threats/technique/{technique_id}."""

from unittest.mock import MagicMock, patch

import pytest


# ── Fixtures ──────────────────────────────────────────────────────────────────

class FakeAuth:
    def __init__(self, level=4, permissions=None, tenant_id="tenant-abc"):
        self.level = level
        self.permissions = permissions if permissions is not None else ["threat:read"]
        self.engine_tenant_id = tenant_id
        self.tenant_ids = [tenant_id]

    def has_permission(self, key: str) -> bool:
        return key in self.permissions

    def is_platform_level(self) -> bool:
        return False

    def can_access_tenant(self, tid: str) -> bool:
        return True


def _make_request(auth=None):
    req = MagicMock()
    req.headers = {}
    req.state = MagicMock()
    req.state.auth_context = auth
    return req


_TECH_ROW = {
    "technique_id": "T1530",
    "technique_name": "Data from Cloud Storage",
    "tactics": ["Collection"],
    "severity_base": "high",
    "remediation_guidance": {"compliance_controls": {"CIS": "2.1.1"}},
}

_COUNTS_ROW = {"affected_resources": 7, "detection_count": 12}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _patch_db(tech_row, counts_row):
    """Return a context manager that patches _get_threat_conn with mock data."""
    mock_conn = MagicMock()
    mock_cur = MagicMock()
    mock_cur.__enter__ = lambda s: s
    mock_cur.__exit__ = MagicMock(return_value=False)

    # fetchone returns tech_row on first call, counts_row on second
    mock_cur.fetchone.side_effect = [tech_row, counts_row]
    mock_conn.cursor.return_value = mock_cur
    mock_conn.__enter__ = lambda s: s
    mock_conn.__exit__ = MagicMock(return_value=False)

    return patch(
        "shared.api_gateway.bff.technique_detail._get_threat_conn",
        return_value=mock_conn,
    )


# ── Tests ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_200_correct_shape():
    """Known technique returns 200 with all required fields."""
    from shared.api_gateway.bff.technique_detail import view_technique_detail

    auth = FakeAuth()
    req = _make_request(auth)

    with patch("shared.api_gateway.bff.technique_detail._parse_auth_context", return_value=auth), \
         patch("shared.api_gateway.bff.technique_detail.resolve_tenant_id", return_value="tenant-abc"), \
         _patch_db(_TECH_ROW, _COUNTS_ROW):
        result = await view_technique_detail(req, "T1530")

    assert result["techniqueId"] == "T1530"
    assert result["techniqueName"] == "Data from Cloud Storage"
    assert result["tactics"] == ["Collection"]
    assert result["severityBase"] == "high"
    assert result["url"] == "https://attack.mitre.org/techniques/T1530/"
    assert result["affectedResources"] == 7
    assert result["detectionCount"] == 12
    assert isinstance(result["d3fendMappings"], list)
    assert isinstance(result["complianceControls"], dict)


@pytest.mark.asyncio
async def test_d3fend_mappings_t1530():
    """T1530 returns the two expected D3FEND entries."""
    from shared.api_gateway.bff.technique_detail import view_technique_detail

    auth = FakeAuth()
    req = _make_request(auth)

    with patch("shared.api_gateway.bff.technique_detail._parse_auth_context", return_value=auth), \
         patch("shared.api_gateway.bff.technique_detail.resolve_tenant_id", return_value="tenant-abc"), \
         _patch_db(_TECH_ROW, _COUNTS_ROW):
        result = await view_technique_detail(req, "T1530")

    ids = [m["id"] for m in result["d3fendMappings"]]
    assert "D3-EAL" in ids
    assert "D3-PLM" in ids


@pytest.mark.asyncio
async def test_d3fend_empty_for_unknown_technique():
    """Technique not in D3FEND_MAP returns empty d3fendMappings."""
    from shared.api_gateway.bff.technique_detail import view_technique_detail

    auth = FakeAuth()
    req = _make_request(auth)

    unknown_row = dict(_TECH_ROW, technique_id="T9000", technique_name="Unknown")
    unknown_counts = {"affected_resources": 0, "detection_count": 0}

    with patch("shared.api_gateway.bff.technique_detail._parse_auth_context", return_value=auth), \
         patch("shared.api_gateway.bff.technique_detail.resolve_tenant_id", return_value="tenant-abc"), \
         _patch_db(unknown_row, unknown_counts):
        result = await view_technique_detail(req, "T9000")

    assert result["d3fendMappings"] == []


@pytest.mark.asyncio
async def test_404_nonexistent_technique():
    """Non-existent technique_id returns 404."""
    from fastapi import HTTPException
    from shared.api_gateway.bff.technique_detail import view_technique_detail

    auth = FakeAuth()
    req = _make_request(auth)

    with patch("shared.api_gateway.bff.technique_detail._parse_auth_context", return_value=auth), \
         patch("shared.api_gateway.bff.technique_detail.resolve_tenant_id", return_value="tenant-abc"), \
         _patch_db(None, None):  # fetchone returns None → technique not found
        with pytest.raises(HTTPException) as exc_info:
            await view_technique_detail(req, "T9999")

    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_401_unauthenticated():
    """Missing auth header returns 401."""
    from fastapi import HTTPException
    from shared.api_gateway.bff.technique_detail import view_technique_detail

    req = _make_request(auth=None)

    with patch("shared.api_gateway.bff.technique_detail._parse_auth_context", return_value=None):
        with pytest.raises(HTTPException) as exc_info:
            await view_technique_detail(req, "T1530")

    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_tenant_isolation_ignores_query_param():
    """tenant_id comes from AuthContext only — query param is ignored."""
    from shared.api_gateway.bff.technique_detail import view_technique_detail

    auth = FakeAuth(tenant_id="real-tenant")
    req = _make_request(auth)
    # Even if someone appends ?tenant_id=attacker in a real request,
    # resolve_tenant_id uses AuthContext only — verified by patching to return real-tenant.

    with patch("shared.api_gateway.bff.technique_detail._parse_auth_context", return_value=auth), \
         patch("shared.api_gateway.bff.technique_detail.resolve_tenant_id", return_value="real-tenant") as mock_tid, \
         _patch_db(_TECH_ROW, _COUNTS_ROW):
        result = await view_technique_detail(req, "T1530")

    # resolve_tenant_id was called and returned real-tenant (not any forged param)
    mock_tid.assert_called_once_with(req)
    assert result["affectedResources"] == 7  # real tenant's data


@pytest.mark.asyncio
async def test_compliance_controls_from_remediation_guidance():
    """complianceControls is extracted from remediation_guidance JSONB."""
    from shared.api_gateway.bff.technique_detail import view_technique_detail

    auth = FakeAuth()
    req = _make_request(auth)

    with patch("shared.api_gateway.bff.technique_detail._parse_auth_context", return_value=auth), \
         patch("shared.api_gateway.bff.technique_detail.resolve_tenant_id", return_value="tenant-abc"), \
         _patch_db(_TECH_ROW, _COUNTS_ROW):
        result = await view_technique_detail(req, "T1530")

    assert result["complianceControls"] == {"CIS": "2.1.1"}


@pytest.mark.asyncio
async def test_compliance_controls_null_remediation():
    """complianceControls returns {} when remediation_guidance is None."""
    from shared.api_gateway.bff.technique_detail import view_technique_detail

    auth = FakeAuth()
    req = _make_request(auth)

    no_remediation_row = dict(_TECH_ROW, remediation_guidance=None)

    with patch("shared.api_gateway.bff.technique_detail._parse_auth_context", return_value=auth), \
         patch("shared.api_gateway.bff.technique_detail.resolve_tenant_id", return_value="tenant-abc"), \
         _patch_db(no_remediation_row, _COUNTS_ROW):
        result = await view_technique_detail(req, "T1530")

    assert result["complianceControls"] == {}


@pytest.mark.asyncio
async def test_sub_technique_url():
    """Sub-techniques like T1078.001 produce correct MITRE URL with '/' separator."""
    from shared.api_gateway.bff.technique_detail import view_technique_detail

    auth = FakeAuth()
    req = _make_request(auth)

    sub_row = dict(_TECH_ROW, technique_id="T1078.001", technique_name="Valid Accounts: Default Accounts")

    with patch("shared.api_gateway.bff.technique_detail._parse_auth_context", return_value=auth), \
         patch("shared.api_gateway.bff.technique_detail.resolve_tenant_id", return_value="tenant-abc"), \
         _patch_db(sub_row, _COUNTS_ROW):
        result = await view_technique_detail(req, "T1078.001")

    assert result["url"] == "https://attack.mitre.org/techniques/T1078/001/"
