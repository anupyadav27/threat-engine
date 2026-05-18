# Story AP-REDESIGN-01: Engine + BFF — Confidence Filter & KPIs

**Epic:** Attack Path UI Redesign  
**Phase:** REDESIGN  
**Priority:** P0  
**Story Points:** 3  
**Status:** ready  
**Depends on:** none  
**Blocked by:** nothing  

---

## Context

The attack-path engine stores `confidence_level` (confirmed/likely/speculative) on every path since migration `026_attack_path_threat_enrichment.sql`, but the engine's `GET /api/v1/attack-paths` endpoint does not accept it as a query filter, and the BFF does not forward it. The redesigned UI needs:

1. A `confidence_level` filter pill (Confirmed / Likely / Speculative)
2. `likely_paths` and `speculative_paths` KPI counts (currently only `confirmed_paths` is computed)

Additionally the `search` param is handled in AP-REDESIGN-02 (same PR target).

---

## Files to Change

| File | Change |
|------|--------|
| `engines/attack-path/attack_path_engine/api/routes.py` | Add `confidence_level` query param; add `likely_paths`/`speculative_paths` to KPI query |
| `shared/api_gateway/bff/attack_paths.py` | Forward `confidence_level` param; add `likely_paths`/`speculative_paths` to kpis dict |

---

## Acceptance Criteria

### Engine — `GET /api/v1/attack-paths`
- AC-1: Accepts optional query param `confidence_level: str | None = None` (values: confirmed / likely / speculative)
- AC-2: When `confidence_level` is provided, adds `AND confidence_level = :confidence_level` to the WHERE clause
- AC-3: KPI query adds two new counts:
  ```sql
  SUM(CASE WHEN confidence_level = 'likely' THEN 1 ELSE 0 END) AS likely_paths,
  SUM(CASE WHEN confidence_level = 'speculative' THEN 1 ELSE 0 END) AS speculative_paths
  ```
- AC-4: KPI response shape: `{ critical, high, choke_points, longest_open_days, paths_with_active_cdr, confirmed_paths, likely_paths, speculative_paths }`
- AC-5: `tenant_id` scoping unchanged — all queries still filter by `tenant_id` from `AuthContext`
- AC-6: Invalid `confidence_level` value → 422 Unprocessable Entity (FastAPI validation)

### BFF — `GET /api/v1/views/attack-paths`
- AC-7: Accepts `confidence_level` as optional query param and forwards it to engine
- AC-8: `kpis{}` in BFF response includes `likely_paths` and `speculative_paths` from engine response
- AC-9: Viewer role restriction unchanged — returns only `{total, kpis}`, no `paths[]`
- AC-10: If engine returns 503, BFF propagates 503 (no fallback)

---

## Technical Notes

**Engine routes.py change (additive):**
```python
@router.get("/attack-paths")
async def list_attack_paths(
    ...
    confidence_level: Optional[str] = Query(None, regex="^(confirmed|likely|speculative)$"),
    ...
):
```

**KPI query addition:**
```sql
SUM(CASE WHEN confidence_level = 'likely' THEN 1 ELSE 0 END) AS likely_paths,
SUM(CASE WHEN confidence_level = 'speculative' THEN 1 ELSE 0 END) AS speculative_paths
```
Add both to the existing KPI SELECT that already computes `confirmed_paths`.

**BFF attack_paths.py:**
- Add `confidence_level` to the param extraction block (same pattern as `severity`, `entry_point_type`)
- Add to engine call params dict: `if confidence_level: params["confidence_level"] = confidence_level`
- Add to kpis dict: `"likely_paths": engine_kpis.get("likely_paths", 0), "speculative_paths": engine_kpis.get("speculative_paths", 0)`

---

## Definition of Done
- [ ] Engine accepts `confidence_level` filter, returns 422 on invalid value
- [ ] KPI response includes `likely_paths` and `speculative_paths`
- [ ] BFF forwards param and includes new KPI fields
- [ ] `tenant_id` scoping verified (no cross-tenant data)
- [ ] All 5 roles tested: viewer gets KPI-only, others get full paths[]
- [ ] No `pytest` regressions on `tests/attack_path/`
- [ ] Docker build + local test pass before image push
- [ ] Image tag: `engine-attack-path:v-redesign-bff1`
- [ ] Gateway image tag: `api-gateway:v-redesign-bff1`
- [ ] `bmad-security-reviewer` gate passed (endpoint change)
