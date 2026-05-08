# JNY-02 Handoff — cspm-bff-dev (DESIGN phase)

**Story:** `/Users/apple/Desktop/threat-engine/.claude/planning/stories/JNY-02_inventory-blast-radius-bff-fix.md`
**Status:** Root-cause confirmed. Fix locus = **BFF only** (no engine change required).
**Date:** 2026-05-04

---

## 1. Root cause

**File:** `/Users/apple/Desktop/threat-engine/shared/api_gateway/bff/inventory.py`
**Line:** 567–573

The greedy `:path` route at line 543 (`view_asset_detail`) swallows the
`/blast-radius` suffix and **manually dispatches** to `view_blast_radius` with
the kwarg `tenant_id=tenant_id`:

```python
# inventory.py:565-573
if resource_uid.endswith("/blast-radius"):
    actual_uid = resource_uid[: -len("/blast-radius")]
    return await view_blast_radius(
        request=request,
        resource_uid=actual_uid,
        tenant_id=tenant_id,        # <-- kwarg does NOT exist on the target
        scan_run_id=scan_run_id,
        max_depth=3,
    )
```

But `view_blast_radius` (defined at line 837) has **no `tenant_id` parameter**
in its signature — it derives `tenant_id` internally via
`resolve_tenant_id(request)`. Result: `TypeError: view_blast_radius() got an
unexpected keyword argument 'tenant_id'` is raised, caught by the gateway
global exception middleware, and returned as
`{"error":"Internal server error","correlation_id":"..."}` with HTTP 500.

**Why FastAPI doesn't route directly to the specific `/blast-radius` route at
line 837:** the `view_asset_detail` route uses `{resource_uid:path}` (greedy)
and is registered first. The greedy match wins for any URL containing slashes
in the uid (i.e. every ARN), so the manual dispatch path is the hot path.

This is a pure dispatch bug. Every code path inside `view_blast_radius` is
sound (returns `_EMPTY` on Neo4j 4xx/5xx, exceptions, or empty results —
honoring the no-fallback rule).

## 2. Engine dependencies (verified, no change needed)

`view_blast_radius` calls exactly one engine endpoint:

- **threat engine** — `GET /api/v1/graph/blast-radius/{resource_uid}`
  defined at `engines/threat/threat_engine/api_server.py:2525` (Neo4j-backed).

No other engines touched. **The engine is not the cause.**

## 3. Fix design (diff plan, ~1–7 lines)

**Minimal fix:** drop the bogus `tenant_id` kwarg from the manual dispatch at
line 570. `view_blast_radius` already resolves tenant from `X-Auth-Context` —
constitution-correct.

```diff
 if resource_uid.endswith("/blast-radius"):
     actual_uid = resource_uid[: -len("/blast-radius")]
     return await view_blast_radius(
         request=request,
         resource_uid=actual_uid,
-        tenant_id=tenant_id,
         scan_run_id=scan_run_id,
         max_depth=3,
     )
```

**Defense-in-depth (recommended, +5 lines):** wrap manual sub-route dispatches
in a try/except that surfaces a 503 for programming-level failures (signature
drift, etc.), distinct from data-empty cases:

```diff
     if resource_uid.endswith("/blast-radius"):
         actual_uid = resource_uid[: -len("/blast-radius")]
-        return await view_blast_radius(
-            request=request,
-            resource_uid=actual_uid,
-            scan_run_id=scan_run_id,
-            max_depth=3,
-        )
+        try:
+            return await view_blast_radius(
+                request=request,
+                resource_uid=actual_uid,
+                scan_run_id=scan_run_id,
+                max_depth=3,
+            )
+        except Exception:
+            logger.exception("blast-radius sub-dispatch failed uid=%s", actual_uid)
+            raise HTTPException(status_code=503, detail="blast-radius unavailable")
```

Per constitution: engine timeouts already become `_EMPTY` (200) inside
`view_blast_radius` — no change needed there. We escalate to 503 only for
**dispatch-layer** programming errors. Fail-loud where appropriate, no
synthetic data anywhere.

**Total diff:** 1 line (minimal) or ~7 lines (with defensive wrapper).
Recommend the minimal fix plus a contract test.

## 4. Pytest case skeleton

File: `/Users/apple/Desktop/threat-engine/shared/api_gateway/tests/test_bff_inventory_blast_radius.py`

```python
import pytest
from httpx import AsyncClient
from unittest.mock import patch, AsyncMock

@pytest.mark.asyncio
async def test_blast_radius_via_subroute_dispatch_does_not_500(app_client: AsyncClient):
    """Reproduces JNY-02: greedy :path dispatch passed kwarg tenant_id
    which view_blast_radius does not accept → 500."""
    uid = "arn:aws:ec2:us-east-1:123456789012:instance/i-abc"
    with patch("shared.api_gateway.bff.inventory._httpx.AsyncClient") as mock_client:
        mock_client.return_value.__aenter__.return_value.get = AsyncMock(
            return_value=AsyncMock(status_code=200, json=lambda: {
                "reachable_resources": [], "reachable_count": 0,
                "depth_distribution": {}, "resources_with_threats": 0,
            })
        )
        r = await app_client.get(
            f"/api/v1/views/inventory/asset/{uid}/blast-radius",
            headers={"X-Auth-Context": '{"tenant_id":"t-test"}'},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["nodes"] == [] and body["edges"] == []
        assert body["origin"] == uid
        assert body["total_impacted"] == 0

@pytest.mark.asyncio
async def test_blast_radius_engine_5xx_returns_empty_not_500(app_client):
    """Neo4j/threat engine outage → empty envelope (no fallback)."""
    uid = "arn:aws:s3:::my-bucket"
    with patch("shared.api_gateway.bff.inventory._httpx.AsyncClient") as mc:
        mc.return_value.__aenter__.return_value.get = AsyncMock(
            return_value=AsyncMock(status_code=503, json=lambda: {})
        )
        r = await app_client.get(
            f"/api/v1/views/inventory/asset/{uid}/blast-radius",
            headers={"X-Auth-Context": '{"tenant_id":"t-test"}'},
        )
        assert r.status_code == 200
        assert r.json()["nodes"] == []

@pytest.mark.asyncio
async def test_blast_radius_tenant_isolation(app_client):
    """Constitution: tenant_id read from X-Auth-Context only; query param ignored."""
    uid = "arn:aws:ec2:us-east-1:111:instance/i-x"
    # query-param tenant_id must NOT override the header
    r = await app_client.get(
        f"/api/v1/views/inventory/asset/{uid}/blast-radius?tenant_id=t-other",
        headers={"X-Auth-Context": '{"tenant_id":"t-real"}'},
    )
    assert r.status_code == 200
    # downstream call should have used t-real, not t-other (assert via mock spy)
```

## 5. Constitution check

- [x] No fallback masking — empty graph → canonical `_EMPTY` envelope (line 864, already there).
- [x] tenant_id from `X-Auth-Context` only — `resolve_tenant_id(request)` at line 851. Removing the bogus kwarg enforces this.
- [x] Engine timeout → BFF returns `_EMPTY` (200), not 5xx — already correct.
- [x] Standard finding columns — N/A (graph response, not findings).
- [ ] Fail-loud on **dispatch** error — recommended via defensive try/except (503).

## 6. Open questions for inventory engine specialist (Consulted)

1. Any production callers still pass legacy `?tenant_id=...` query param to
   `/inventory/asset/{uid}/blast-radius`? `view_blast_radius` ignores it
   (uses header only). Safe to keep ignoring, or log a deprecation warn?
2. Should `/inventory/asset/{uid}/blast-radius` be refactored out of greedy
   `:path` sub-dispatch entirely (explicit route at line 837 wins via stricter
   route ordering)? Current pattern is a maintenance hazard — every new
   sub-route requires editing two places. Out of scope for this fix but
   worth a follow-up story.

---

**JNY-02 cspm-bff-dev: root cause = stray `tenant_id` kwarg in greedy-path sub-dispatch. Fix locus = BFF. Diff size = 1 line (or ~7 with defensive wrapper). Open question: deprecate `?tenant_id` query param on this route?**
