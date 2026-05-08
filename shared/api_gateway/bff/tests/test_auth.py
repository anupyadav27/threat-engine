import json
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException


def make_request(auth_ctx_dict=None):
    req = MagicMock()
    if auth_ctx_dict:
        req.headers = {"X-Auth-Context": json.dumps(auth_ctx_dict)}
    else:
        req.headers = {}
    req.state = MagicMock(auth_header=None)
    return req


def _base_ctx(**overrides):
    base = {
        "user_id": "u1",
        "email": "a@b.com",
        "role": "tenant_admin",
        "level": 4,
        "scope_level": "tenant",
        "permissions": [],
        "engine_tenant_id": None,
        "tenant_ids": None,
    }
    base.update(overrides)
    return base


def test_resolve_tenant_id_from_engine_tenant_id():
    from bff._auth import resolve_tenant_id
    req = make_request(_base_ctx(engine_tenant_id="my-tenant", tenant_ids=["uuid-123"]))
    assert resolve_tenant_id(req) == "my-tenant"


def test_resolve_tenant_id_fallback_to_tenant_ids():
    from bff._auth import resolve_tenant_id
    req = make_request(_base_ctx(engine_tenant_id=None, tenant_ids=["slug-001"]))
    assert resolve_tenant_id(req) == "slug-001"


def test_resolve_tenant_id_raises_401_no_context():
    from bff._auth import resolve_tenant_id
    req = make_request(None)
    with pytest.raises(HTTPException) as exc_info:
        resolve_tenant_id(req)
    assert exc_info.value.status_code == 401


def test_resolve_tenant_id_raises_400_no_tenants():
    from bff._auth import resolve_tenant_id
    req = make_request(_base_ctx(engine_tenant_id=None, tenant_ids=[]))
    with pytest.raises(HTTPException) as exc_info:
        resolve_tenant_id(req)
    assert exc_info.value.status_code == 400


def test_account_filter_returns_none_for_unrestricted():
    from bff._auth import account_filter
    req = make_request(_base_ctx(account_ids=None))
    assert account_filter(req) is None


def test_account_filter_returns_list_for_restricted():
    from bff._auth import account_filter
    req = make_request(_base_ctx(account_ids=["588989875114"]))
    assert account_filter(req) == ["588989875114"]


def test_require_tenant_access_platform_admin_passes():
    from bff._auth import require_tenant_access
    req = make_request(_base_ctx(tenant_ids=None, scope_level="platform"))
    # Should not raise — None tenant_ids means unrestricted
    require_tenant_access(req, "any-tenant")


def test_require_tenant_access_raises_403_wrong_tenant():
    from bff._auth import require_tenant_access
    req = make_request(_base_ctx(tenant_ids=["allowed-tenant"], engine_tenant_id="allowed-tenant"))
    with pytest.raises(HTTPException) as exc_info:
        require_tenant_access(req, "other-tenant")
    assert exc_info.value.status_code == 403


def test_require_tenant_access_raises_401_no_context():
    from bff._auth import require_tenant_access
    req = make_request(None)
    with pytest.raises(HTTPException) as exc_info:
        require_tenant_access(req, "any-tenant")
    assert exc_info.value.status_code == 401
