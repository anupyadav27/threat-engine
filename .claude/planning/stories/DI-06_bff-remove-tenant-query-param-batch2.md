# DI-06: BFF — Remove tenant_id Query Param from All Views (Batch 2: Remaining)

## Track
Track 1 — Auth Context + Tenant Scoping

## Priority
P1 — depends on DI-04, can run in parallel with DI-05

## Story
Convert remaining BFF view handlers to use `resolve_tenant_id(request)` instead of `tenant_id: str = Query(...)`.

## Scope (Batch 2)

Views NOT covered in DI-05:
1. `threat_attack_paths.py` — `/api/v1/views/threats/attack-paths`
2. `threat_blast_radius.py` — `/api/v1/views/threats/blast-radius`
3. `threat_command_room.py` — `/api/v1/views/threats/command-room`
4. `threat_detail.py` — `/api/v1/views/threats/{threat_id}`
5. `threat_graph.py` — `/api/v1/views/threats/graph` (2 endpoints)
6. `threat_posture_delta.py` — `/api/v1/views/threats/posture-delta` (2 endpoints)
7. `threat_scenario_detail.py` — `/api/v1/views/threats/scenario/{id}`
8. `threat_timeline.py` — `/api/v1/views/threats/timeline`
9. `threat_toxic_combos.py` — `/api/v1/views/threats/toxic-combinations`
10. `datasec.py` — `/api/v1/views/datasec`
11. `network_security.py` — `/api/v1/views/network-security`
12. `ciem.py` — `/api/v1/views/ciem`
13. `cnapp.py` — `/api/v1/views/cnapp`
14. `cwpp.py` — `/api/v1/views/cwpp`
15. `secops.py` — `/api/v1/views/secops`
16. `ai_security.py` — `/api/v1/views/ai-security`
17. `container_security.py` — `/api/v1/views/container-security`
18. `database_security.py` — `/api/v1/views/database-security`
19. `encryption.py` — `/api/v1/views/encryption`
20. `policies.py` — `/api/v1/views/policies`
21. `reports.py` — `/api/v1/views/reports`
22. `rules.py` — `/api/v1/views/rules`
23. `scan_status.py` — `/api/v1/views/scan-status`
24. `scan_timing.py` — `/api/v1/views/scan-timing`
25. `scope.py` — tenant_id is Optional here; use `resolve_tenant_id_optional(request)`

## Special Cases

### scope.py
Uses `tenant_id: Optional[str] = Query(None)`. Replace with:
```python
from ._auth import resolve_tenant_id_optional
# in function body:
tenant_id = resolve_tenant_id_optional(request)
```

### billing.py
Uses `tenant_id: Optional[str] = Query(None)`. Same pattern as scope.py.
The `platform_admin.py` view intentionally accepts tenant_id as a Query parameter for cross-tenant admin queries — DO NOT modify `platform_admin.py`.

### inventory.py additional endpoints (lines 545, 703, 1020, 1148)
`inventory.py` has 4+ endpoints. DI-05 covered the main one. Convert all remaining.

## Files to Modify

All files listed under Scope above, in `/Users/apple/Desktop/threat-engine/shared/api_gateway/bff/`

## Pattern (same as DI-05)

```python
# Remove from signature:
tenant_id: str = Query(...)

# Add as first line of body:
tenant_id = resolve_tenant_id(request)

# Add import at top of file:
from ._auth import resolve_tenant_id
```

## Files to NOT Modify
- `platform_admin.py` — intentionally accepts cross-tenant queries; needs tenant_id as param for admin lookups

## Acceptance Criteria

Same per-file criteria as DI-05, applied to all files in Batch 2:
- [ ] No `tenant_id: str = Query(...)` in any converted function signature
- [ ] Each converted function body starts with `tenant_id = resolve_tenant_id(request)` (or Optional variant)
- [ ] `platform_admin.py` is unchanged
- [ ] GET without session returns 401 for all converted endpoints
- [ ] Query string `tenant_id` parameter is silently ignored after conversion

## Definition of Done
- All files in Batch 2 converted
- Gateway image rebuilt and deployed
- grep confirms no remaining `tenant_id: str = Query(...)` except in `platform_admin.py`
