"""Parametrized smoke tests for BFF views with Pydantic response models (JNY-13).

These tests hit a locally-running gateway (port-forwarded to 8000 by default)
and assert each modeled endpoint:

  1. Returns 200 OK for an authenticated platform-admin context.
  2. Has a body that re-validates against the corresponding Pydantic model
     declared in `bff._common_schemas` — proving the contract a deployed
     gateway is serving matches what callers expect.

Run only after deploying the gateway image with the response_model= changes:

    kubectl port-forward -n threat-engine-engines svc/api-gateway 8000:80 &
    pytest tests/bff/test_bff_smoke.py -v

Skips automatically when the gateway isn't reachable, so CI can call it
opportunistically without false failures.
"""

from __future__ import annotations

import json
import os
import sys

import pytest

# Make the gateway package importable so we can resolve response models.
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(_REPO_ROOT, "shared", "api_gateway"))

try:
    import httpx
except ImportError:  # pragma: no cover
    httpx = None  # type: ignore

from bff import _common_schemas as schemas  # noqa: E402

GATEWAY = os.environ.get("BFF_GATEWAY_URL", "http://127.0.0.1:8000")

# Platform-admin context — matches the dev login (admin@cspm.local).
# Kept inline so the smoke test is self-contained; override via env var
# `BFF_AUTH_CONTEXT` for non-default tenants.
_DEFAULT_AUTH_CTX = {
    "user_id": "admin@cspm.local",
    "tenant_id": "default",
    "roles": ["platform_admin"],
    "permissions": ["*:*"],
}
AUTH_HEADER = os.environ.get(
    "BFF_AUTH_CONTEXT", json.dumps(_DEFAULT_AUTH_CTX)
)


# (path, expected_status, response_model_class_name)
ENDPOINTS = [
    ("/api/v1/views/inventory",  200, "InventoryViewResponse"),
    ("/api/v1/views/threats",    200, "ThreatsViewResponse"),
    ("/api/v1/views/ciem",       200, "CiemViewResponse"),
    ("/api/v1/views/compliance", 200, "ComplianceViewResponse"),
    ("/api/v1/views/iam",        200, "IamViewResponse"),
    ("/api/v1/views/datasec",    200, "DatasecViewResponse"),
]


def _gateway_reachable() -> bool:
    if httpx is None:
        return False
    try:
        httpx.get(f"{GATEWAY}/api/v1/health/live", timeout=2.0)
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _gateway_reachable(),
    reason=f"gateway not reachable at {GATEWAY}",
)


@pytest.mark.parametrize("path,expected,model_name", ENDPOINTS)
def test_bff_smoke(path: str, expected: int, model_name: str) -> None:
    """Each modeled BFF endpoint returns the expected status and a body
    that re-validates against its Pydantic response model."""
    assert httpx is not None, "httpx not installed"

    resp = httpx.get(
        GATEWAY + path,
        headers={"X-Auth-Context": AUTH_HEADER},
        timeout=20.0,
    )

    assert resp.status_code == expected, (
        f"{path} -> {resp.status_code} body={resp.text[:200]}"
    )

    if resp.status_code != 200:
        return

    model_cls = getattr(schemas, model_name)
    # If FastAPI is serving with response_model=, the body already matches
    # the schema; re-validating here is a defense-in-depth contract check.
    model_cls.model_validate(resp.json())


def test_sensitive_key_scrubber_blocks_credential_leak() -> None:
    """Defense-in-depth: the base scrubber must reject any payload with
    `credential|secret|raw_event` keys, regardless of nesting depth."""
    with pytest.raises(ValueError, match="sensitive key"):
        schemas.InventoryViewResponse(
            pageContext={"title": "x"},
            assets=[{"nested": {"credentialRef": "leak"}}],
        )

    with pytest.raises(ValueError, match="sensitive key"):
        schemas.ThreatsViewResponse(
            pageContext={"title": "x"},
            threats=[{"raw_event": {"x": 1}}],
        )
