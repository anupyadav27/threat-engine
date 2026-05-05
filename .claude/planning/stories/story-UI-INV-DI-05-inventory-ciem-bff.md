# Story DI-05: New BFF Endpoint — `GET /api/v1/views/inventory/{asset_id}/ciem`

**Epic:** UI Investigation Journeys Sprint
**Status:** Ready for Dev
**Story Points:** 4
**Depends On:** DI-01 (ciem:sensitive permission in DB), DI-02 (scrub_config_fields utility)
**Blocks:** DI-10

## Context

The CIEM tab in the Asset Investigation Journey needs a BFF endpoint to aggregate CIEM findings by identity principal for a given asset. The CIEM engine has a `/api/v1/ciem/findings` endpoint that returns raw findings per resource. This BFF endpoint owns two responsibilities: (1) verify the requesting tenant actually owns the asset (ownership check prevents cross-tenant enumeration), and (2) aggregate findings into identity-level risk summaries for display.

## Scope

Add one new route handler to `shared/api_gateway/bff/inventory.py` and register it in the gateway router.

**Out of scope:** Any CIEM engine changes, frontend CIEM tab (DI-10), `scrub_config_fields` utility (DI-02).

## Files to Create/Modify

- `/Users/apple/Desktop/threat-engine/shared/api_gateway/bff/inventory.py` — add `view_inventory_ciem()` handler
- `/Users/apple/Desktop/threat-engine/shared/api_gateway/router.py` — verify the inventory BFF router is registered (it should already be; confirm the route is reachable)

## Implementation Notes

**Engine URLs (from `shared/api_gateway/bff/_shared.py`):**
- Inventory engine: accessed via `ENGINE_URLS["inventory"]` → `http://engine-inventory/`
- CIEM engine: accessed via `ENGINE_URLS["ciem"]` → `http://engine-ciem/`

**Permission gate:** The BFF uses `_parse_auth_context(request)` (from `shared/api_gateway/bff/_auth.py`). Check `ciem:sensitive` permission manually:
```python
ctx = _parse_auth_context(request)
if ctx is None:
    raise HTTPException(status_code=401, detail="Authentication required")
if "ciem:sensitive" not in (ctx.permissions or []):
    raise HTTPException(
        status_code=403,
        detail="You need Analyst access to view identity entitlements"
    )
tenant_id = resolve_tenant_id(request)  # raises 401/400 if not set
```

**CRITICAL — sequential calls (NOT parallel):**
```python
# Step 1: verify asset ownership (inventory engine)
import httpx
inventory_url = f"{ENGINE_URLS['inventory']}/api/v1/inventory/assets/{asset_id}"
async with httpx.AsyncClient(timeout=10.0) as client:
    inv_resp = await client.get(inventory_url, params={"tenant_id": tenant_id})

if inv_resp.status_code != 200:
    raise HTTPException(status_code=404, detail="Asset not found")

inv_data = inv_resp.json()
# Ownership check: confirm asset belongs to this tenant
if inv_data.get("tenant_id") != tenant_id:
    raise HTTPException(status_code=403, detail="Asset not found")

resource_uid = inv_data.get("resource_uid") or asset_id

# Step 2: fetch CIEM findings ONLY after ownership confirmed
ciem_url = f"{ENGINE_URLS['ciem']}/api/v1/ciem/findings"
async with httpx.AsyncClient(timeout=15.0) as client:
    ciem_resp = await client.get(
        ciem_url,
        params={"resource_uid": resource_uid, "tenant_id": tenant_id, "limit": 100}
    )

ciem_findings = ciem_resp.json() if ciem_resp.status_code == 200 else []
if isinstance(ciem_findings, dict):
    ciem_findings = ciem_findings.get("findings") or ciem_findings.get("items") or []
```

**Aggregation by `actor_principal`:**

CIEM finding fields (from `ciem_findings` table):
- `actor_principal` (str) — IAM ARN of the principal
- `principal_type` (str) — "role", "user", "service", etc.
- `severity` (str) — "critical", "high", "medium", "low"
- `action_category` (str) — "admin", "write", "read", "data_access"
- `event_time` (str ISO8601)

```python
from collections import defaultdict
from datetime import datetime, timezone

def _aggregate_by_principal(findings: list) -> list:
    """Group CIEM findings by actor_principal and derive risk metrics."""
    groups = defaultdict(list)
    for f in findings:
        principal = f.get("actor_principal") or "unknown"
        groups[principal].append(f)

    identities = []
    for principal, items in groups.items():
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for item in items:
            sev = (item.get("severity") or "low").lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        # Determine privilege level from action_category
        categories = {(item.get("action_category") or "").lower() for item in items}
        if "admin" in categories:
            privilege_level = "admin"
        elif "write" in categories or "data_access" in categories:
            privilege_level = "power"
        else:
            privilege_level = "readonly"

        # Risk score
        risk_score = min(
            100,
            sev_counts["critical"] * 25 + sev_counts["high"] * 10 + sev_counts["medium"] * 2
        )

        # Last used: max event_time across findings for this principal
        event_times = []
        for item in items:
            et = item.get("event_time")
            if et:
                try:
                    dt = datetime.fromisoformat(et.replace("Z", "+00:00"))
                    event_times.append(dt)
                except ValueError:
                    pass
        now = datetime.now(timezone.utc)
        last_used_days = None
        if event_times:
            most_recent = max(event_times)
            last_used_days = (now - most_recent).days

        # Principal type: use field from finding or infer from ARN
        principal_type = items[0].get("principal_type") or _infer_principal_type(principal)

        identities.append({
            "identity_arn": principal,
            "identity_type": principal_type,
            "privilege_level": privilege_level,
            "last_used_days": last_used_days,
            "risk_score": risk_score,
            "finding_count": len(items),
        })

    # Sort by risk_score descending
    identities.sort(key=lambda x: x["risk_score"], reverse=True)
    return identities


def _infer_principal_type(arn: str) -> str:
    """Infer principal type from ARN."""
    if not arn:
        return "unknown"
    a = arn.lower()
    if ":role/" in a:
        return "role"
    if ":user/" in a:
        return "user"
    if ":assumed-role/" in a:
        return "assumed-role"
    if ".amazonaws.com" in a:
        return "service"
    return "unknown"
```

**Truncation:** If total distinct principals > 100, set `truncated: true` and only return first 100.

**Over-privileged count:** Count of identities where `privilege_level == "admin"` OR `risk_score >= 75`.

**Audit log:** After successful response, write to audit log:
```python
# Use the existing audit log pattern in the codebase
# Location: shared/api_gateway/bff/ or shared/common/
# If no shared audit helper exists, log to structured logger at INFO level:
import logging
audit_logger = logging.getLogger("api-gateway.audit")
audit_logger.info(
    "CIEM sensitive data accessed",
    extra={
        "user_id": ctx.user_id if ctx else "unknown",
        "tenant_id": tenant_id,
        "asset_id": asset_id,
        "endpoint": f"/api/v1/views/inventory/{asset_id}/ciem",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
)
```

**Full handler:**
```python
@router.get("/inventory/{asset_id}/ciem")
async def view_inventory_ciem(
    request: Request,
    asset_id: str,
):
    """BFF: CIEM identity risk summary for a specific inventory asset.

    Requires ciem:sensitive permission. Verifies asset ownership before
    fetching CIEM data (sequential, not parallel).
    """
    # [permission check, ownership check, aggregation, audit log as described above]
    all_identities = _aggregate_by_principal(ciem_findings)
    truncated = len(all_identities) > 100
    identities = all_identities[:100]
    over_privileged = sum(
        1 for i in identities
        if i["privilege_level"] == "admin" or i["risk_score"] >= 75
    )
    return {
        "identities": identities,
        "totalIdentities": len(all_identities),
        "overPrivilegedCount": over_privileged,
        "truncated": truncated,
    }
```

**JSONB note:** CIEM findings returned by httpx `.json()` are already dicts — no `json.loads()` needed.

**`tenant_id` is ALWAYS from `AuthContext`** (via `resolve_tenant_id(request)`). Never accept `tenant_id` as a query parameter in this endpoint.

## Acceptance Criteria

- [ ] `GET /api/v1/views/inventory/{asset_id}/ciem` returns 200 with `{identities, totalIdentities, overPrivilegedCount, truncated}` for analyst session
- [ ] Viewer session (no `ciem:sensitive` permission) → 403 with `detail="You need Analyst access to view identity entitlements"`
- [ ] Unauthenticated request → 401
- [ ] Asset belonging to different tenant → 403 (ownership check fails)
- [ ] `tenant_id` in `params` to CIEM engine comes from `resolve_tenant_id(request)` — if caller passes `?tenant_id=other` in URL, it is ignored
- [ ] CIEM engine call executes ONLY after inventory ownership is confirmed (sequential, not parallel)
- [ ] Empty CIEM findings → `{identities: [], totalIdentities: 0, overPrivilegedCount: 0, truncated: false}`
- [ ] With 150 distinct principals → `truncated: true`, `identities` length is 100, `totalIdentities` is 150
- [ ] `admin` privilege_level assigned when any finding has `action_category="admin"`
- [ ] `risk_score = min(100, critical*25 + high*10 + medium*2)`
- [ ] Audit log entry written on every successful 200 response
- [ ] No mock/fallback data — if CIEM engine is down, return `{identities: [], ...}` (safe empty, not mock)

## Security Gates

- **B-1 (AuthContext-only tenant_id):** `tenant_id` resolved from `resolve_tenant_id(request)`, never from URL or query string
- **B-2 (ownership check):** Inventory engine confirms `tenant_id` match before CIEM call executes
- **B-4 (permission gate):** `ciem:sensitive` checked via `ctx.permissions` before any data fetch
- **B-6 (audit trail):** Every successful call logged with `user_id`, `tenant_id`, `asset_id`, `endpoint`, `timestamp`
- **No DEV_BYPASS_AUTH:** Standard auth context chain enforced

## Definition of Done

- [ ] Code written and passes linter
- [ ] BFF contract test added: `tests/bff/test_inventory_ciem.py` covering 200, 403 (viewer), 403 (wrong tenant), 401, empty findings
- [ ] bmad-security-reviewer approved (new endpoint with auth/DB/cross-engine calls)
- [ ] bmad-qa acceptance test run