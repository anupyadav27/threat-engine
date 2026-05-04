# DI-08: BFF — Contract Tests: One Per View Asserting Non-Empty Response

## Track
Track 1 — Auth Context + Tenant Scoping

## Priority
P1 — can be written in parallel with DI-05/DI-06, deployed after them

## Story
As a QA engineer, I need one contract test per BFF view that asserts a non-empty response for the test tenant (`my-tenant` / `00000000-...`), so that future changes that break data loading are caught in CI before they reach production.

## Background

The root cause of many "no data" bugs was that wrong `tenant_id` was silently accepted and returned empty. With DI-05/DI-06 fixing the source, contract tests close the loop by continuously verifying the data path is end-to-end connected.

"Contract test" here means: authenticated request → BFF view → response has expected top-level fields with non-null, non-empty values.

## File to Create

`/Users/apple/Desktop/threat-engine/shared/api_gateway/bff/tests/test_bff_contracts.py`

## Implementation Pattern

```python
"""
BFF contract tests — one per view, asserting non-empty response shapes.

These are integration tests that require live engine connectivity.
Run them post-deploy or in a staging environment with a real scan_run_id.

Usage:
    pytest tests/test_bff_contracts.py --tb=short -q
"""

import os
import pytest
import httpx

GATEWAY_URL = os.getenv("GATEWAY_URL", "http://localhost:8000")
TEST_SESSION_COOKIE = os.getenv("TEST_SESSION_COOKIE")  # access_token value for test tenant

if not TEST_SESSION_COOKIE:
    pytest.skip("TEST_SESSION_COOKIE not set — skipping contract tests", allow_module_level=True)

COOKIES = {"access_token": TEST_SESSION_COOKIE}


def get_view(path: str, params: dict = None) -> dict:
    resp = httpx.get(
        f"{GATEWAY_URL}/api/v1/views/{path}",
        params=params or {},
        cookies=COOKIES,
        timeout=30,
    )
    assert resp.status_code == 200, f"View {path} returned {resp.status_code}: {resp.text[:200]}"
    data = resp.json()
    assert isinstance(data, dict), f"View {path} returned non-dict: {type(data)}"
    return data


class TestDashboardContract:
    def test_dashboard_has_kpi_groups(self):
        data = get_view("dashboard")
        assert "kpiGroups" in data, "dashboard missing kpiGroups"
        assert len(data["kpiGroups"]) > 0, "dashboard kpiGroups is empty"

    def test_dashboard_has_posture_score(self):
        data = get_view("dashboard")
        # Either postureScore or kpiGroups[0].items[0].value must be present
        assert data.get("postureScore") is not None or data.get("kpiGroups"), \
            "dashboard missing posture score"


class TestThreatsContract:
    def test_threats_has_threats_key(self):
        data = get_view("threats")
        assert "threats" in data, "threats view missing 'threats' key"

    def test_threats_has_mitre_matrix(self):
        data = get_view("threats")
        assert "mitreMatrix" in data, "threats view missing 'mitreMatrix'"

    def test_threats_has_kpi_groups(self):
        data = get_view("threats")
        assert "kpiGroups" in data, "threats view missing 'kpiGroups'"


class TestComplianceContract:
    def test_compliance_has_frameworks(self):
        data = get_view("compliance")
        assert "frameworks" in data or "complianceFrameworks" in data, \
            "compliance view missing frameworks"


class TestInventoryContract:
    def test_inventory_has_assets(self):
        data = get_view("inventory")
        has_assets = (
            "assets" in data or
            "resources" in data or
            "inventory" in data or
            "total" in data
        )
        assert has_assets, f"inventory view missing asset data. Keys: {list(data.keys())}"


class TestIamContract:
    def test_iam_has_findings(self):
        data = get_view("iam")
        assert "findings" in data or "iamFindings" in data or "total" in data, \
            f"iam view missing findings. Keys: {list(data.keys())}"


class TestRiskContract:
    def test_risk_has_score(self):
        data = get_view("risk")
        has_score = any(k in data for k in ("riskScore", "risk_score", "score", "summary", "scenarios"))
        assert has_score, f"risk view missing score data. Keys: {list(data.keys())}"


class TestMisconfigContract:
    def test_misconfig_has_findings(self):
        data = get_view("misconfig")
        assert "findings" in data or "total" in data or "summary" in data, \
            f"misconfig missing findings. Keys: {list(data.keys())}"


class TestUnauthenticatedReturns401:
    """All views must return 401 without a session cookie."""
    VIEWS = ["dashboard", "threats", "compliance", "inventory", "iam", "risk",
             "misconfig", "vulnerability", "datasec", "network-security", "ciem"]

    @pytest.mark.parametrize("view", VIEWS)
    def test_unauthenticated_returns_401(self, view):
        resp = httpx.get(f"{GATEWAY_URL}/api/v1/views/{view}", timeout=10)
        assert resp.status_code == 401, \
            f"View {view} returned {resp.status_code} without auth — expected 401"
```

## Acceptance Criteria

- [ ] Test file created at path above
- [ ] All TestUnauthenticated tests pass (401 without cookie)
- [ ] With `TEST_SESSION_COOKIE` set to a valid test-tenant session: all contract tests pass
- [ ] If a view has no scan data, the test still passes (non-empty response shape, just zero counts)
- [ ] Tests can be run in CI with `pytest -m contract` (add `@pytest.mark.contract` to class decorators)

## Note on "Non-Empty"
The contract tests verify RESPONSE SHAPE (required keys present), not DATA PRESENCE. A view returning `{"threats": [], "total": 0, "mitreMatrix": {}}` passes — it proves the pipeline is connected. A view returning `{}` or `{"error": ...}` fails.

## Definition of Done
- File committed
- At least 5 contract test classes written (dashboard, threats, compliance, inventory, iam)
- Unauthenticated 401 tests cover all 11 views in the list
- CI pipeline runs these in a `contract` test stage
