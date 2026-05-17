---
id: onboarding-D5
title: "Schedule CRUD API with region/service scope (BFF)"
sprint: D
points: 1
depends_on: [onboarding-C6, onboarding-C8]
blocks: [onboarding-D10]
security_blocks: []
nist_csf: PR.DS
owasp_samm: Implementation
csa_ccm: IAM-14
---

## Context

The schedule CRUD endpoints now have proper RBAC (C6) and the region/service scope columns exist (C8). However, the BFF layer in `shared/api_gateway/bff/onboarding_cloud_accounts.py` does not expose a schedule management view — the frontend has no way to display or manage schedules through the standard BFF pattern. This story adds a BFF view handler `view_schedules(auth_context)` that calls the onboarding engine's schedule endpoints and returns formatted data for the frontend. It also adds `view_schedule_detail(schedule_id, auth_context)` for per-schedule drilldown. The BFF follows the existing pattern: `fetchView(page)` → `/gateway/api/v1/views/{page}`. No fallback/mock data — if the onboarding engine is unreachable, return a 503.

## Acceptance Criteria

- [ ] AC1: BFF view `GET /gateway/api/v1/views/schedules` exists and calls the onboarding engine `GET /api/v1/schedules` with the caller's auth context forwarded.
- [ ] AC2: BFF response format:
  ```json
  {
    "schedules": [
      {
        "schedule_id": str,
        "account_id": str,
        "account_name": str,
        "cron_expression": str,
        "include_regions": [],
        "exclude_regions": [],
        "include_services": [],
        "exclude_services": [],
        "active": bool,
        "last_run_at": str | null,
        "next_run_at": str | null
      }
    ],
    "total": int
  }
  ```
- [ ] AC3: BFF view `GET /gateway/api/v1/views/schedule_detail?schedule_id={id}` returns full schedule detail including region/service scope arrays.
- [ ] AC4: BFF does NOT add fallback data or mock schedules if the engine returns empty — return `{"schedules": [], "total": 0}`.
- [ ] AC5: BFF forwards `X-Auth-Context` header to the onboarding engine — never adds or modifies `tenant_id` in the forwarded request.
- [ ] AC6: If the onboarding engine returns non-2xx, BFF returns 503 with `{"detail": "Schedule service unavailable"}`.
- [ ] AC7: BFF view is registered in `shared/api_gateway/bff/views/` or equivalent view registry.
- [ ] AC8: BFF contract test exists in `shared/api_gateway/bff/tests/` verifying the shape of the schedule response.
- [ ] AC9: `account_name` in the BFF response is enriched by joining the onboarding engine's account data — not a separate Django call.

## Key Files

- `shared/api_gateway/bff/onboarding_cloud_accounts.py` — Add `view_schedules()` and `view_schedule_detail()` handlers
- `shared/api_gateway/bff/views/` — Register new view names
- `shared/api_gateway/bff/tests/test_schedules.py` — BFF contract test

## Technical Notes

**Existing BFF pattern — mirror this:**
```bash
# Look at an existing BFF handler for the pattern:
cat /Users/apple/Desktop/threat-engine/shared/api_gateway/bff/onboarding_cloud_accounts.py | head -60
```

**View handler skeleton:**
```python
# onboarding_cloud_accounts.py
import os, requests

ONBOARDING_ENGINE_URL = os.environ.get(
    "ONBOARDING_ENGINE_URL",
    "http://engine-onboarding.threat-engine-engines.svc.cluster.local:8008"
)

def view_schedules(auth_context: dict) -> dict:
    """BFF view: list schedules for the authenticated tenant."""
    headers = {"X-Auth-Context": json.dumps(auth_context)}
    resp = requests.get(
        f"{ONBOARDING_ENGINE_URL}/api/v1/schedules",
        headers=headers,
        timeout=10,
    )
    if resp.status_code != 200:
        raise ServiceUnavailableError("Schedule service unavailable")
    data = resp.json()
    return {
        "schedules": _format_schedules(data),
        "total": len(data),
    }

def _format_schedules(raw: list) -> list:
    return [
        {
            "schedule_id": s["schedule_id"],
            "account_id": s["account_id"],
            "account_name": s.get("account_name", ""),
            "cron_expression": s.get("cron_expression", ""),
            "include_regions": s.get("include_regions") or [],
            "exclude_regions": s.get("exclude_regions") or [],
            "include_services": s.get("include_services") or [],
            "exclude_services": s.get("exclude_services") or [],
            "active": s.get("active", False),
            "last_run_at": s.get("last_run_at"),
            "next_run_at": s.get("next_run_at"),
        }
        for s in raw
    ]
```

**BFF contract test skeleton:**
```python
# tests/test_schedules.py
def test_view_schedules_shape(mock_onboarding_engine):
    mock_onboarding_engine.return_value = [
        {"schedule_id": "s1", "account_id": "a1", "active": True, ...}
    ]
    result = view_schedules(auth_context={"tenant_id": "t1"})
    assert "schedules" in result
    assert "total" in result
    assert isinstance(result["schedules"], list)
    for s in result["schedules"]:
        assert "exclude_regions" in s
        assert isinstance(s["exclude_regions"], list)
```

**CRITICAL: No fallback data** — if the engine returns 0 schedules, return `{"schedules": [], "total": 0}`. Do NOT add mock or hardcoded schedule data.

**View registration:** Check how other views are registered in the gateway:
```bash
grep -rn "view_" /Users/apple/Desktop/threat-engine/shared/api_gateway/bff/ --include="*.py" | \
  grep "register\|VIEWS\|views\[" | head -10
```

## Security Checklist

- [ ] BFF forwards `X-Auth-Context` without modification
- [ ] BFF does not inject or override `tenant_id` in forwarded requests
- [ ] No fallback/mock data (CSPM Constitution: never mask engine gaps with BFF data)
- [ ] No hardcoded secrets or credentials
- [ ] bmad-security-reviewer gate passed before merge

## Definition of Done

- [ ] All ACs pass
- [ ] BFF contract test covers `exclude_regions` as list (not null)
- [ ] No mock data in BFF handler
- [ ] `grep -r "mock\|fallback\|hardcoded" shared/api_gateway/bff/onboarding_cloud_accounts.py` — zero hits in view handler functions
- [ ] bmad-security-reviewer: no BLOCKERs
- [ ] `kubectl rollout status deployment/api-gateway -n threat-engine-engines` shows AVAILABLE
- [ ] `GET /gateway/api/v1/views/schedules` returns 200 for authenticated tenant_admin
