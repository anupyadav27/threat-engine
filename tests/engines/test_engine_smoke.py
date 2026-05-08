"""JNY-15 Phase H — Layer 0 black-box smoke tests for engine HTTP endpoints.

Hits each engine through the cluster ingress NLB and asserts:
- Expected HTTP status (typically 200)
- Response body is JSON-decodable
- Tests do NOT fail on data emptiness — only HTTP/JSON errors

These complement (not replace) per-engine Pydantic `response_model` adoption,
which is tracked under STORY-ENG-PYDANTIC-COVERAGE.md as 22 spin-off stories.

Run:
    pytest /Users/apple/Desktop/threat-engine/tests/engines/test_engine_smoke.py -v

Skip locally without cluster access by setting:
    SKIP_ENGINE_SMOKE=1
"""

from __future__ import annotations

import json
import os

import httpx
import pytest


NLB = os.environ.get(
    "ENGINE_SMOKE_NLB",
    "http://a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com",
)

# Platform-admin auth context with broad *:read perms for black-box smoke.
# The gateway's AuthMiddleware accepts X-Auth-Context as a JSON-encoded header
# for service-to-service / test calls.
AUTH_CONTEXT = json.dumps(
    {
        "user_id": "smoke-test",
        "email": "smoke@cspm.local",
        "tenant_id": "00000000-0000-0000-0000-000000000000",
        "is_platform_admin": True,
        "roles": ["platform_admin"],
        "permissions": [
            "threats:read",
            "inventory:read",
            "compliance:read",
            "iam:read",
            "datasec:read",
            "encryption:read",
            "network:read",
            "ciem:read",
            "ai_security:read",
            "container_security:read",
            "database_security:read",
            "risk:read",
            "secops:read",
            "vulnerability:read",
            "cnapp:read",
            "cwpp:read",
            "billing:read",
            "platform_admin:read",
            "rules:read",
            "onboarding:read",
            "discoveries:read",
            "check:read",
        ],
    }
)

HEADERS = {
    "X-Auth-Context": AUTH_CONTEXT,
    "Accept": "application/json",
}

# (engine, path, expected_status)
# 1-2 high-value listing endpoints per engine. Picked from
# .claude/documentation/UI-BFF-ENGINE-REFERENCE.md §4 Engine API Surface.
ENDPOINTS: list[tuple[str, str, int]] = [
    # Core findings engines
    ("inventory",          "/inventory/api/v1/inventory/ui-data",                   200),
    ("inventory-arch",     "/inventory/api/v1/inventory/architecture",              200),
    ("threat",             "/threat/api/v1/threat/ui-data",                         200),
    ("threat-list",        "/threat/api/v1/threat/list?limit=5",                    200),
    ("ciem",               "/ciem/api/v1/ciem/dashboard",                           200),
    ("ciem-identities",    "/ciem/api/v1/ciem/identities?limit=5",                  200),
    ("iam",                "/iam/api/v1/iam-security/ui-data",                      200),
    ("network",            "/network/api/v1/network-security/ui-data",              200),
    ("datasec",            "/datasec/api/v1/data-security/ui-data",                 200),
    ("encryption",         "/encryption/api/v1/encryption/ui-data",                 200),
    ("dbsec",              "/database-security/api/v1/database-security/ui-data",   200),
    ("ai-security",        "/ai-security/api/v1/ai-security/ui-data",               200),
    ("container",          "/container-security/api/v1/container-security/ui-data", 200),
    ("compliance",         "/compliance/api/v1/compliance/ui-data",                 200),
    ("compliance-fw",      "/compliance/api/v1/compliance/frameworks/summary",      200),
    ("check",              "/check/api/v1/health",                                  200),
    ("discoveries",        "/discoveries/api/v1/health",                            200),
    ("risk",               "/risk/api/v1/risk/ui-data",                             200),
    ("secops",             "/secops/api/v1/secops/sast/scans",                      200),
    ("vulnerability",      "/vulnerability/api/v1/agents",                          200),
    ("cnapp",              "/cnapp/api/v1/cnapp/dashboard",                         200),
    ("cwpp",               "/cwpp/api/v1/cwpp/ui-data",                             200),
    ("onboarding-accts",   "/onboarding/api/v1/cloud-accounts",                     200),
    ("onboarding-tenants", "/onboarding/api/v1/tenants",                            200),
    ("rule",               "/rule/api/v1/rules?limit=5",                            200),
    ("billing-plans",      "/billing/api/v1/billing/plans",                         200),
    ("platform-admin",     "/platform-admin/api/v1/platform-admin/health",          200),
]

# OpenAPI specs — every engine should expose a non-trivial spec.
OPENAPI_PATHS: list[tuple[str, str]] = [
    ("inventory",          "/inventory/openapi.json"),
    ("threat",             "/threat/openapi.json"),
    ("ciem",               "/ciem/openapi.json"),
    ("iam",                "/iam/openapi.json"),
    ("network",            "/network/openapi.json"),
    ("datasec",            "/datasec/openapi.json"),
    ("encryption",         "/encryption/openapi.json"),
    ("dbsec",              "/database-security/openapi.json"),
    ("ai-security",        "/ai-security/openapi.json"),
    ("container",          "/container-security/openapi.json"),
    ("compliance",         "/compliance/openapi.json"),
    ("check",              "/check/openapi.json"),
    ("discoveries",        "/discoveries/openapi.json"),
    ("risk",               "/risk/openapi.json"),
    ("secops",             "/secops/openapi.json"),
    ("vulnerability",      "/vulnerability/openapi.json"),
    ("cnapp",              "/cnapp/openapi.json"),
    ("cwpp",               "/cwpp/openapi.json"),
    ("onboarding",         "/onboarding/openapi.json"),
    ("rule",               "/rule/openapi.json"),
    ("billing",            "/billing/openapi.json"),
    ("platform-admin",     "/platform-admin/openapi.json"),
]


pytestmark = pytest.mark.skipif(
    os.environ.get("SKIP_ENGINE_SMOKE") == "1",
    reason="SKIP_ENGINE_SMOKE=1 set",
)


@pytest.fixture(scope="module")
def client() -> httpx.Client:
    with httpx.Client(base_url=NLB, headers=HEADERS, timeout=20.0, follow_redirects=True) as c:
        yield c


@pytest.mark.parametrize("engine,path,expected", ENDPOINTS, ids=[e[0] for e in ENDPOINTS])
def test_engine_endpoint_smoke(client: httpx.Client, engine: str, path: str, expected: int) -> None:
    """Engine listing/dashboard endpoints respond with expected status and valid JSON."""
    r = client.get(path)
    assert r.status_code == expected, (
        f"{engine} {path} → {r.status_code} (body: {r.text[:200]})"
    )
    # Must be JSON-decodable
    try:
        r.json()
    except json.JSONDecodeError as exc:  # pragma: no cover - assertion
        pytest.fail(f"{engine} {path} returned non-JSON body: {exc} body={r.text[:200]}")


@pytest.mark.parametrize("engine,path", OPENAPI_PATHS, ids=[e[0] for e in OPENAPI_PATHS])
def test_engine_openapi_spec(client: httpx.Client, engine: str, path: str) -> None:
    """Every engine publishes a non-trivial OpenAPI spec."""
    r = client.get(path)
    assert r.status_code == 200, f"{engine} openapi → {r.status_code}"
    spec = r.json()
    assert spec.get("openapi"), f"{engine} missing openapi version"
    paths = spec.get("paths") or {}
    assert len(paths) > 0, f"{engine} openapi has zero paths"


@pytest.mark.parametrize(
    "path",
    [
        "/inventory/api/v1/inventory/ui-data",
        "/threat/api/v1/threat/ui-data",
        "/ciem/api/v1/ciem/dashboard",
    ],
)
def test_no_5xx_on_oversized_id(client: httpx.Client, path: str) -> None:
    """Oversized query params must not 5xx (defense-in-depth check)."""
    r = client.get(path, params={"resource_uid": "x" * 4096})
    assert r.status_code < 500, f"{path} 5xx on oversized id: {r.status_code}"
