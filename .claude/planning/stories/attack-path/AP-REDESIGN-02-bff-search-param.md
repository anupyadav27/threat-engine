# Story AP-REDESIGN-02: Engine + BFF — Search Param

**Epic:** Attack Path UI Redesign  
**Phase:** REDESIGN  
**Priority:** P0  
**Story Points:** 2  
**Status:** ready  
**Depends on:** AP-REDESIGN-01 (same PR — engine + gateway image bump)  

---

## Context

The redesigned attack paths page includes a search box so analysts can find paths by crown jewel name, entry point resource, or attack pattern name. Currently the engine has no `search` param — all filtering is by structured fields (severity, entry_point_type, etc.).

This story adds full-text ILIKE search across `attack_name` and `crown_jewel_uid` columns.

---

## Files to Change

| File | Change |
|------|--------|
| `engines/attack-path/attack_path_engine/api/routes.py` | Add `search` query param with ILIKE filter |
| `shared/api_gateway/bff/attack_paths.py` | Forward `search` param to engine |

---

## Acceptance Criteria

### Engine — `GET /api/v1/attack-paths`
- AC-1: Accepts optional `search: str | None = None` query param (max 200 chars)
- AC-2: When `search` provided, adds to WHERE clause:
  ```sql
  AND (
    attack_name ILIKE :search_pattern
    OR crown_jewel_uid ILIKE :search_pattern
    OR chain_type ILIKE :search_pattern
  )
  ```
  where `search_pattern = f"%{search}%"`
- AC-3: `search` is applied AFTER `tenant_id` scoping — never cross-tenant
- AC-4: `search` is compatible with other filters (severity, confidence_level, entry_point_type) — all ANDed
- AC-5: Empty string `search=""` treated as no filter (same as `search=None`)
- AC-6: SQL injection prevented — use parameterized query (`:search_pattern` bind var), not f-string interpolation into SQL
- AC-7: KPI counts (critical, high, etc.) reflect search-filtered results when `search` is active

### BFF — `GET /api/v1/views/attack-paths`
- AC-8: Accepts `search` as optional query param (strip whitespace before forwarding)
- AC-9: Forwards non-empty `search` to engine call params
- AC-10: `choke_points_preview` is NOT filtered by search (always shows top global choke points)

---

## Technical Notes

**Engine safe parameterized pattern:**
```python
search: Optional[str] = Query(None, max_length=200)

# In query build:
if search and search.strip():
    conditions.append("(attack_name ILIKE :search_pat OR crown_jewel_uid ILIKE :search_pat OR chain_type ILIKE :search_pat)")
    params["search_pat"] = f"%{search.strip()}%"
```

**Never do this (SQL injection risk):**
```python
# BAD:
f"AND attack_name ILIKE '%{search}%'"
```

---

## Definition of Done
- [ ] Engine accepts `search` param with ILIKE on attack_name + crown_jewel_uid + chain_type
- [ ] Parameterized query only — no f-string SQL injection vector
- [ ] Combined with other filters correctly (AND logic)
- [ ] BFF forwards and strips whitespace
- [ ] Local test: search for known attack_name returns matching paths only
- [ ] Local test: search for non-existent term returns empty paths[] (not 500)
- [ ] Ships in same PR and image as AP-REDESIGN-01: `engine-attack-path:v-redesign-bff1` + `api-gateway:v-redesign-bff1`
- [ ] `bmad-security-reviewer` gate passed (injection check mandatory)