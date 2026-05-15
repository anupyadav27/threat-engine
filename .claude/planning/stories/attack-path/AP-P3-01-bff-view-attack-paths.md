# Story AP-P3-01: BFF View Handler — attack_paths.py

## Status: ready

## Metadata
- **Phase**: P3 — BFF + Risk Integration
- **Epic**: Attack Path Engine
- **Points**: 3
- **Priority**: P1
- **Depends on**: AP-P2-07 (engine routed via gateway, GET endpoints in engine), AP-P2-02 (engine scaffold with GET /attack-paths endpoints)
- **Blocks**: AP-P4-01 (frontend calls fetchView("attack-paths")), AP-P4-02 (choke points panel), AP-P4-03 (path detail panel)
- **RACI**: R=DEV A=DL C=SA,SR I=PO,QA
- **Security Gate**: bmad-security-reviewer mandatory (new BFF view handler, RBAC matrix, viewer restriction). bmad-security-architect must confirm viewer-only summary response shape.

## User Story

As the frontend, I want `fetchView("attack-paths")` to return the normalized attack paths list with KPIs and choke point preview, and `fetchView("attack-paths/{id}")` to return the full path story with per-hop detail, so that the UI can render the Attack Paths page without calling the engine directly.

## Context

Following the platform's BFF-for-charts-and-aggregates pattern (`api_patterns.xml`), the frontend never calls the engine directly for view data. All view data goes through `GET /api/v1/views/{page}` → BFF handler → engine.

The BFF handler for attack-paths normalizes the engine response and adds a `choke_points_preview` (top 3 choke nodes by paths_blocked) pulled from `GET /api/v1/choke-points`. It does NOT add any fallback/mock data — if the engine is unavailable, return 503.

The viewer role restriction is handled in the BFF: viewer calling the list endpoint receives only `{ total, kpis }` — the `paths[]` array is omitted entirely.

## Security Framework Tags

**OWASP SAMM Function**
- [ ] Governance  [ ] Design  [x] Implementation  [x] Verification  [ ] Operations

**NIST CSF 2.0 Function(s)**
- [ ] GV  [x] ID  [x] PR  [x] DE  [ ] RS  [ ] RC
PR.AC-4 (access permissions managed — viewer restriction), ID.RA-5 (risk data surfaced to authorized roles)

**CSA CCM v4 Domain(s)**
- IAM-09 (Access Control), IVS-01, DSP-07

## Threat Model

### STRIDE
| Threat | Component | Attack Scenario | Mitigation |
|--------|-----------|-----------------|------------|
| Info Disclosure | viewer response | viewer role receives paths[] array exposing per-node security detail | BFF explicitly checks AuthContext.role and omits paths[] for viewer; returns only total + kpis |
| Spoofing | BFF handler | BFF called without valid AuthContext → attacker sees all paths | require_permission("attack_path:read") enforced in BFF handler before forwarding to engine |
| DoS | BFF fallback | BFF returns cached/fallback data when engine is down — masks availability issues | NO fallback data — if engine unavailable, return 503 immediately (CSPM Constitution) |

## MITRE ATT&CK Techniques Addressed
N/A — BFF layer; no finding logic.

## Acceptance Criteria

### BFF Contract (mandatory)
- [ ] AC-1: File `shared/api_gateway/bff/attack_paths.py` created
- [ ] AC-2: Handler registered in gateway router for views: `GET /api/v1/views/attack-paths` and `GET /api/v1/views/attack-paths/{path_id}`
- [ ] AC-3: `GET /api/v1/views/attack-paths` calls engine `GET /api/v1/attack-paths` with query params forwarded (severity, entry_point_type, representative_only, page, page_size)
- [ ] AC-4: Response includes `choke_points_preview` array (top 3 choke nodes) fetched from engine `GET /api/v1/choke-points?limit=3`
- [ ] AC-5: `GET /api/v1/views/attack-paths/{path_id}` calls engine `GET /api/v1/attack-paths/{path_id}` and returns full response with `steps[]` array
- [ ] AC-6: Response adds `traversal_reason` enrichment per step (from `attack_path_nodes.traversal_reason` — passed through from engine)
- [ ] AC-7: NO fallback/mock data — engine unavailable → BFF returns HTTP 503 with `{"error": "attack-path engine unavailable"}`

### Viewer Role Restriction
- [ ] AC-8: When AuthContext role = viewer, `GET /api/v1/views/attack-paths` returns ONLY `{ "total": N, "kpis": {...} }` — `paths[]` array is NOT included
- [ ] AC-9: When AuthContext role = viewer, `GET /api/v1/views/attack-paths/{path_id}` returns 403

### RBAC Matrix (5 roles × 2 view endpoints)
- [ ] AC-10: platform_admin — list: full response with paths[]; detail: full steps[]
- [ ] AC-11: org_admin — list: full response with paths[]; detail: full steps[]
- [ ] AC-12: tenant_admin — list: full response with paths[]; detail: full steps[]
- [ ] AC-13: analyst — list: full response with paths[]; detail: full steps[]
- [ ] AC-14: viewer — list: summary only (total + kpis, no paths[]); detail: 403

### BFF Contract — Output Shape
- [ ] AC-15: List response includes: `paths[]` (each with path_id, severity, path_score, chain_type, entry_point_type, depth, title, crown_jewel_uid, crown_jewel_type, data_classification, group_id, group_size, is_representative, choke_node_uid, has_active_cdr_actor, max_epss, misconfig_count, first_seen_at, last_seen_at, open_days)
- [ ] AC-16: List response includes KPIs: `{ critical, high, choke_points, longest_open_days, paths_with_active_cdr }`
- [ ] AC-17: List response includes `choke_points_preview[]` with top-3 choke nodes (node_uid, node_name, node_type, paths_blocked_if_fixed)
- [ ] AC-18: Detail response includes `steps[]` array with all `attack_path_nodes` fields (hop_index, node_uid, node_name, node_type, edge_to_next, edge_category, traversal_reason, policy_statement, sg_rule, misconfigs, cves, threat_detections, cdr_actor_active, cdr_actor_uid)

### Contract Test
- [ ] AC-19: `tests/bff/test_attack_paths_bff.py` created with contract tests:
  - list endpoint returns correct shape (all required fields present, correct types)
  - viewer receives summary only (no paths[] key in response)
  - detail endpoint returns steps[] array
  - 503 returned when engine is mocked as unavailable (no fallback)

### Image Tag
- [ ] AC-20: Gateway image rebuilt and pushed with new tag (no `latest`) after adding attack_paths.py
- [ ] AC-21: `bff_contract.ndjson` updated with `attack-paths` view entry

### Health Check
- [ ] AC-22: `GET /api/v1/health/live` on gateway returns 200 after deploy
- [ ] AC-23: `kubectl logs` show no ERROR in first 50 lines

## Technical Notes

**File**: `shared/api_gateway/bff/attack_paths.py`

Pattern to follow: `shared/api_gateway/bff/threat_v1.py` (added in v-bff-threat1) for how to call engine + normalize response.

**No fallback data** (CSPM Constitution, CLAUDE.md anti-pattern #1): If `httpx.get(engine_url)` raises or returns non-200, raise 503 immediately. No `except: return mock_data`.

**Viewer restriction pattern**:
```python
auth = require_permission("attack_path:read")(...)
if auth.role == "viewer":
    return {"total": data["total"], "kpis": data["kpis"]}
return data
```

**choke_points_preview**: Two sequential engine calls are acceptable for this BFF. Use `asyncio.gather()` for parallel calls (attack-paths list + choke-points top-3) to keep latency under 500ms.

**bff_contract.ndjson entry** to add:
```json
{"view":"attack-paths","engine":"engine-attack-path","engine_url":"/api/v1/attack-paths","inputs":["tenant_id","scan_run_id","severity","entry_point_type","representative_only","page","page_size"],"required_output_fields":["paths","total","kpis","choke_points_preview"]}
```

## Key Files
- `/Users/apple/Desktop/threat-engine/shared/api_gateway/bff/attack_paths.py` (create new)
- `/Users/apple/Desktop/threat-engine/tests/bff/test_attack_paths_bff.py` (create new)
- `/Users/apple/Desktop/threat-engine/.claude/context/bff_contract.ndjson` (add attack-paths entry)

## Definition of Done
- [ ] `attack_paths.py` BFF handler committed and registered in gateway router
- [ ] `fetchView("attack-paths")` from frontend returns correct shape (tested locally)
- [ ] Viewer role receives summary-only response (tested with viewer JWT)
- [ ] `GET /api/v1/views/attack-paths/{id}` returns 403 for viewer
- [ ] Contract test file committed and passing
- [ ] 503 returned when engine is unavailable (mock test)
- [ ] Gateway image rebuilt with new tag; no `latest`
- [ ] bff_contract.ndjson updated
- [ ] MEMORY.md updated for gateway image tag change
- [ ] bmad-security-reviewer: no BLOCKERS