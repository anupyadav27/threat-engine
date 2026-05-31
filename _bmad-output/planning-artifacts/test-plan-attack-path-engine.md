---
title: "Test Plan — Attack Path Engine"
type: test-plan
status: active
version: "1.0"
date: "2026-05-15"
author: "cspm-qa-engineer"
engine: "engine-attack-path"
architecture_ref: "architecture-attack-path-engine.md"
quality_constitution_ref: ".claude/documentation/TESTING_QUALITY.md"
---

# Test Plan: Attack Path Engine

**Engine:** `engine-attack-path` | Port 8025 | DB: `threat_engine_attack_path`
**Pipeline position:** Step 6.5 (after graph-build, before risk)
**Stories covered:** AP-P0-01 through AP-P4-04 (18 stories across 5 phases)

---

## 1. Testing Scope Per Story

| Story | Description | L0 Static | L1 Unit | L2 Integration | L3 BFF Contract | L4 RBAC | L5 E2E Pipeline | L7 UI Smoke | L10 Post-Deploy |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| AP-P0-01 | DB migration: resource_security_posture table | grep checks | — | schema columns, UNIQUE constraint, indexes | — | — | posture rows written | — | — |
| AP-P0-02 | Shared posture_writer utility | import check | posture_writer upsert, None filtering, SQL injection safety | upsert idempotency on real DB | — | — | — | — | — |
| AP-P0-03 | Wire IAM/Network/DataSec/CDR engines to write posture signals | import check | — | each engine writes correct columns | — | — | posture populated after parallel step | — | — |
| AP-P1-01 | Expand crown jewel classifier | grep checks | auto-classify all resource types, PII/admin/EKS/S3/RDS logic | crown_jewel columns in posture table | — | — | crown_jewels endpoint non-empty | — | — |
| AP-P1-02 | Crown jewel override API | no hardcoded IDs | — | override row persists in crown_jewel_overrides | — | PATCH /crown-jewels: tenant_admin+ only | PATCH override survives scan re-run | — | — |
| AP-P2-01 | DB migration: attack_paths tables | grep checks | — | attack_paths, attack_path_nodes, history, overrides tables; all columns; JSONB list deserialization | — | — | — | — | DB connectivity check |
| AP-P2-02 | Engine scaffold (FastAPI app factory) | no latest tag | — | health/live + health/ready return correct shapes | — | 401 for all unauthenticated calls | — | — | health checks in post-deploy |
| AP-P2-03 | Reverse BFS Cypher query | — | — | Neo4j query returns non-empty result for seeded tenant | — | — | paths written to DB after scan | — | Neo4j connectivity check |
| AP-P2-04 | P×I scorer | — | All multipliers, entry types, CDR cap, severity buckets, combined multipliers | path_score written to attack_paths | — | — | — | — | — |
| AP-P2-05 | Deduplicator | — | Phase 1/2/3 logic, is_suffix, absorbed_count, group_id, choke_node_uid | deduplicated rows in attack_paths table | — | — | group_size and choke_node_uid populated | — | — |
| AP-P2-06 | Choke point detector + DB writer | — | — | is_choke_point rows in posture table; attack_path_nodes FK integrity | — | — | choke points > 0 when paths exist | — | — |
| AP-P2-07 | run_scan.py, Argo step, gateway route | no DEV_BYPASS, no latest | — | POST /internal/scan triggers full pipeline; scan_orchestration updated | — | POST /internal/scan: 404/405 from public router | engines_completed includes 'attack-path' | — | full validate_attack_path_deploy.sh |
| AP-P3-01 | BFF view: /views/attack-paths | — | — | — | paths/total/kpis shape; viewer strip; empty engine → 503; filters forwarded | BFF accessible to all roles; 401 without auth | BFF smoke in post-deploy | — | BFF smoke |
| AP-P3-02 | Risk engine reads attack-path posture signals | — | — | risk_scenarios updated_at > attack_paths first_seen_at | — | — | pipeline ordering verified in E2E | — | — |
| AP-P4-01 | Attack paths list page (/threats/attack-paths) | — | — | — | BFF contract | — | — | page loads, KPI cards, severity badge color, origin filters | — |
| AP-P4-02 | Choke point section | — | — | — | choke_points KPI field non-null | — | — | choke point section visible; click behavior | — |
| AP-P4-03 | Path detail side panel | — | — | — | steps[] in analyst response; steps[] absent in viewer response | viewer 403 on /attack-paths/{id} | — | click path → right panel opens | — |
| AP-P4-04 | Inventory asset detail tabs | — | — | — | — | — | — | compute → Network tab; S3 → Data tab | — |

**Coverage gaps (known):**
- L6 Rule Regression: attack-path engine does not add check rules; not applicable
- L8 Performance: BFF p95 < 500ms target — requires k6 script (deferred to perf sprint)
- L9 Security: SQL injection, SSRF, path_id enumeration tests — run via `/security-review` skill

---

## 2. E2E Test Flow

Full UI → BFF → Gateway → Engine → Neo4j + PostgreSQL path with verification points.

```
User (browser)
    │
    │  GET /threats/attack-paths (Next.js page)
    ▼
frontend/src/app/threats/attack-paths/page.tsx
    │  fetchView("attack-paths")
    ▼
frontend/src/lib/api.js → GET /gateway/api/v1/views/attack-paths
    │
    │  access_token cookie → AuthMiddleware → X-Auth-Context header
    ▼
shared/api_gateway/main.py (gateway)
    │  Routes /views/attack-paths to BFF handler
    ▼
shared/api_gateway/bff/attack_paths.py
    │  Calls engine-attack-path GET /api/v1/attack-paths?tenant_id=...
    ▼
engine-attack-path (port 8025)
    │  require_permission("attack_path:read")
    │  WHERE tenant_id = engine_tenant_id FROM AuthContext
    ▼
PostgreSQL (threat_engine_attack_path)
    │  SELECT * FROM attack_paths WHERE tenant_id = $tid AND scan_run_id = $latest
    ▼
BFF transforms response → strips steps[] for viewer role
    │
    ▼
Frontend renders KPI cards, path list, severity badges
```

**Verification points per layer:**

| Layer | What to verify | Test level |
|---|---|---|
| Auth cookie | 401 without access_token cookie | L4 RBAC |
| Gateway RBAC | X-Auth-Context has attack_path:read | L4 RBAC |
| BFF shape | paths, total, kpis all present and non-null | L3 BFF contract |
| BFF viewer strip | steps[] absent in viewer response | L3 BFF contract |
| Engine RBAC | require_permission() enforced | L4 RBAC |
| Engine tenant scope | WHERE tenant_id = $tid | L4 RBAC (cross-tenant test) |
| DB rows | attack_paths rows written for scan_run_id | L5 E2E |
| DB JSONB | node_uids is list not string | L2 Integration |
| Posture update | is_on_attack_path=true on path members | L5 E2E |
| Risk ordering | risk_scenarios.created_at > attack_paths.first_seen_at | L5 E2E |
| Neo4j query | Reverse BFS returns rows for seeded tenant | L2 Integration |
| UI render | KPI cards visible, severity badge #ef4444 | L7 UI smoke |

---

## 3. Test Execution Order

Test execution mirrors the build order. No phase begins until the prior phase's blocking tests pass.

```
Phase 0 (AP-P0-xx): Foundation
  ├── L0: grep checks (no json.loads, no latest, no DEV_BYPASS)
  ├── L1: test_posture_writer.py — upsert logic, None filtering
  └── L2: test_db_schema.py — resource_security_posture table exists

Phase 1 (AP-P1-xx): Crown Jewels
  ├── L1: test_crown_jewel_classifier.py — all 11 resource type rules
  ├── L1: test_posture_writer.py — crown jewel columns upserted
  └── L4: PATCH /crown-jewels RBAC (tenant_admin+ only)

Phase 2 (AP-P2-xx): Core Engine
  ├── L1: test_scorer.py — all P and I multipliers
  ├── L1: test_deduplicator.py — Phase 1/2/3 full pipeline
  ├── L2: test_db_schema.py — attack_paths/nodes/history/overrides tables
  ├── L2: JSONB columns deserialize to list
  └── L4: Full RBAC matrix (all 5 roles × 7 endpoints) — test_attack_path_rbac.py

Phase 3 (AP-P3-xx): BFF and Risk Integration
  ├── L3: test_attack_paths_bff.py — full contract shape
  ├── L3: viewer strip test (steps[] absent)
  ├── L3: engine unavailable → 503 (not 200 with empty)
  └── L5: pipeline ordering E2E — risk ran after attack-path

Phase 4 (AP-P4-xx): UI
  ├── L7: test_attack_paths.spec.ts — page loads, KPI cards, severity colors
  ├── L7: path card click → side panel
  └── L7: inventory tabs (compute=Network, S3=Data)

Deploy Gate
  └── L10: validate_attack_path_deploy.sh — image tag, health, logs, BFF smoke, DB, Neo4j
```

**Blocking gates:**
- L0 failures block L1
- L1 failures block L2
- L2 failures block L3 and L4
- L3 + L4 failures block deploy
- L10 failures trigger immediate rollback

---

## 4. QA Acceptance Criteria Per Phase

### Phase 0 — Foundation (AP-P0-01, AP-P0-02, AP-P0-03)

cspm-qa must verify:
- [ ] `resource_security_posture` table exists in `threat_engine_inventory` DB with all 40+ columns
- [ ] UNIQUE constraint on `(resource_uid, scan_run_id, tenant_id)` verified via `_get_unique_constraints()`
- [ ] 4 required indexes exist on `resource_security_posture`
- [ ] `posture_writer.upsert_posture_row()` tested: None values excluded, False/0/"" values included
- [ ] SQL parameterization verified: no f-string interpolation, values in params dict
- [ ] IAM, Network, DataSec, CDR engines each write their respective columns without touching other dimensions (partial update pattern confirmed)

**Phase 0 done when:** All L2 DB schema tests pass on the target RDS instance after migration job completes.

---

### Phase 1 — Crown Jewels (AP-P1-01, AP-P1-02)

cspm-qa must verify:
- [ ] All 11 resource type categories correctly classified (RDS always, S3 conditional on PII, IAM conditional on admin)
- [ ] Manual override `is_crown_jewel=false` suppresses auto-classification
- [ ] Manual override `is_crown_jewel=true` promotes non-crown-jewel
- [ ] Override UID mismatch → override ignored
- [ ] `PATCH /api/v1/crown-jewels/{uid}` returns 403 for analyst and viewer
- [ ] `PATCH /api/v1/crown-jewels/{uid}` returns 200 for tenant_admin, org_admin, platform_admin
- [ ] Override persists to `crown_jewel_overrides` table with correct `set_by` field
- [ ] Crown jewel classification survives scan re-run (override wins in next scan)

**Phase 1 done when:** Unit tests pass and RBAC matrix for PATCH verified.

---

### Phase 2 — Core Engine (AP-P2-01 through AP-P2-07)

cspm-qa must verify:
- [ ] `attack_paths` table schema verified: all columns, JSONB list deserialization, indexes
- [ ] `attack_path_nodes` FK references `attack_paths(path_id)` correctly
- [ ] `crown_jewel_overrides` UNIQUE on `(resource_uid, tenant_id)`
- [ ] P×I scorer: internet entry = 0.90, CDR elevation capped at 1.0, severity buckets correct
- [ ] Deduplicator Phase 1: exact hash keeps highest score
- [ ] Deduplicator Phase 2: subpath absorbed only when entry NOT independently exposed
- [ ] Deduplicator Phase 3: group_id consistent within convergence group; choke_node_uid = node_uids[-2]
- [ ] Full RBAC matrix (30 cells): all 5 roles × 7 endpoints match expected matrix
- [ ] Unauthenticated → 401 on all endpoints
- [ ] POST /internal/scan: 404/405 from public router (not exposed)
- [ ] Neo4j query: reverse BFS returns rows for test tenant after graph-build completes
- [ ] `scan_orchestration.engines_completed` includes 'attack-path' after Argo run

**Phase 2 done when:** All unit, integration, and RBAC tests pass; a test Argo scan completes with attack-path step.

---

### Phase 3 — BFF + Risk Integration (AP-P3-01, AP-P3-02)

cspm-qa must verify:
- [ ] GET /api/v1/views/attack-paths returns `{paths, total, kpis}` with all required fields
- [ ] `kpis` object has 5 required fields: critical, high, choke_points, longest_open_days, paths_with_active_cdr
- [ ] All KPI fields are non-null (integers, not null)
- [ ] Viewer role receives paths without `steps[]`, `policy_statement`, `sg_rule`
- [ ] Analyst role receives paths with full `steps[]`
- [ ] Engine unavailable → 503 (not 200 with empty kpis, not 500)
- [ ] `severity=critical` filter forwarded to engine in query params
- [ ] `entry_point_type=internet` filter forwarded to engine
- [ ] `credential_ref` absent from all BFF responses
- [ ] `_is_mock` and `_fallback` fields absent (no mock data)
- [ ] Risk engine ran AFTER attack-path step in pipeline (timestamps confirm ordering)
- [ ] `risk_scenarios` reads `is_on_attack_path`, `is_choke_point`, `blast_radius_count` from posture table

**Phase 3 done when:** BFF contract tests pass and a full pipeline scan confirms risk ordering.

---

### Phase 4 — UI (AP-P4-01 through AP-P4-04)

cspm-qa must verify:
- [ ] `/threats/attack-paths` loads without console errors (no unhandled JS exceptions)
- [ ] Skeleton screens appear during BFF load delay (data-testid="skeleton" or .animate-pulse)
- [ ] KPI cards render (`data-testid="kpi-card"` count ≥ 1)
- [ ] Critical severity badge background color = `rgb(239, 68, 68)` (#ef4444)
- [ ] Origin filter buttons present (All, Internet, VPN/OnPrem)
- [ ] Click path card → right panel with path canvas opens
- [ ] Choke point section/link navigates correctly
- [ ] `/inventory/[ec2-resource-id]` — Network tab present and active
- [ ] `/inventory/[s3-resource-id]` — Data tab present; Network tab NOT the active/selected tab
- [ ] No "undefined", "NaN", "null" values rendered in KPI card text

**Phase 4 done when:** All Playwright smoke tests pass on EKS environment.

---

## 5. Known Risk Areas

### 5.1 Neo4j Query Timeout

**Risk:** Reverse BFS query on large tenants (>10,000 nodes) may exceed 30-second timeout.

**Mitigation:**
- Architecture enforces `LIMIT 500` in Cypher
- Engine has 30s query timeout (`neo4j_client.py` connection config)
- Argo step has `retry: 0` — a timeout fails the step cleanly without retry loops
- Test coverage: L2 integration test verifies query completes in < 10s for seeded tenant
- Detection: post-deploy log check (L10) surfaces timeout ERROR lines within 60s

**QA gate:** Before Phase 2 deploy, verify Neo4j query completes for the largest available tenant's data set. If p95 > 20s, raise a P0 before deploying to production.

---

### 5.2 Deduplication Correctness

**Risk:** Phase 2 subpath absorption incorrectly absorbs a path whose entry is genuinely independently exposed. False negative — real attack path hidden from analyst.

**Mitigation:**
- Unit test explicitly covers `is_internet_exposed=true` entry → path NOT absorbed
- The `is_suffix()` function is tested for edge cases (equal length, partial overlap, empty)
- Absorbed paths are never deleted — `absorbed_count` stored on representative path for audit

**QA gate:** Unit test `test_suffix_with_exposed_entry_is_not_absorbed` must pass. Any change to deduplication logic requires re-running all Phase 2 unit tests.

---

### 5.3 Cross-Tenant Path Leakage

**Risk:** If `tenant_id` filtering fails in the Neo4j query or DB query, one tenant's attack paths could be visible to another.

**Mitigation:**
- Architecture mandates: all Neo4j node matches include `tenant_id: $tid` property filter
- All PostgreSQL queries: `WHERE tenant_id = $tid`
- L4 RBAC cross-tenant isolation test: `test_tenant_a_data_not_visible_to_tenant_b`
- L5 E2E: `TestCrossTenantIsolation` queries with OTHER_TENANT_ID and asserts zero rows

**QA gate:** Cross-tenant isolation tests (L4 + L5) are blocking gates. Any failure is a critical security defect — deploy is blocked until fixed. Do not merge with a cross-tenant test failure even under time pressure.

---

### 5.4 CDR Elevation False Positives

**Risk:** `has_active_cdr_actor=true` incorrectly set on posture rows due to CDR cron timing or stale data. This inflates probability scores and creates false critical paths.

**Mitigation:**
- CDR engine writes `cdr_actor_last_seen` alongside `has_active_cdr_actor`
- Attack path engine should reject CDR signals older than 48 hours (implementation: `posture_updater.py` age check)
- Unit test coverage: CDR elevation correctly capped at 1.0; CDR without active flag = no elevation
- FlagMapper in threat-v1 similarly clears stale flags at start of each run

**QA gate:** In L5 E2E, check that `paths_with_active_cdr` KPI count does not exceed the number of resources where `cdr_actor_last_seen` is within 48 hours.

---

### 5.5 JSONB Serialization (Constitution Rule)

**Risk:** Calling `json.loads()` on psycopg2 JSONB results (node_uids, hop_categories, etc.) would cause a TypeError — JSONB is auto-deserialized to Python dict/list.

**Mitigation:**
- L0 static check: `grep -r "json\.loads" engines/attack-path/` must return empty
- L2 integration test explicitly verifies: `isinstance(node_uids, list)` — not string
- CSPM Constitution section on JSONB is non-negotiable; any `json.loads()` on JSONB = blocking PR comment

**QA gate:** L0 grep check is the first check that runs. Any `json.loads()` pattern in engine code fails the static gate before any other test runs.

---

### 5.6 VSCode YAML Linter Tag Revert

**Risk:** After deploying `engine-attack-path:v-attack-path1`, the VSCode YAML linter silently reverts the image tag in `engine-attack-path.yaml` to the previous value. The next `kubectl apply` would roll back to the wrong image.

**Mitigation:**
- Post-deploy script (L10) CHECK 0 mandatory: pod image must match `$INTENDED_TAG`
- If mismatch: script prints rollback command and exits 1
- MEMORY.md production table updated after every deploy

**QA gate:** CHECK 0 in `validate_attack_path_deploy.sh` must pass. If it fails, fix with `kubectl set image`, not by editing YAML (YAML will be reverted again by linter).

---

## 6. Test File Inventory

| File | Level | Tests | Key assertions |
|---|---|---|---|
| `tests/unit/attack_path/test_scorer.py` | L1 | 27 | P multipliers, I multipliers, CDR cap, severity buckets, combined |
| `tests/unit/attack_path/test_deduplicator.py` | L1 | 22 | Phase 1/2/3, is_suffix edge cases, absorbed_count, group_id |
| `tests/unit/attack_path/test_crown_jewel_classifier.py` | L1 | 24 | All 11 resource types, manual overrides, case insensitivity |
| `tests/unit/attack_path/test_posture_writer.py` | L1 | 17 | None filtering, False/0/"" included, ON CONFLICT SET, SQL params |
| `tests/bff/test_attack_paths_bff.py` | L3 | 18 | paths/total/kpis shape, viewer strip, 503 on engine down, filters |
| `tests/rbac/test_attack_path_rbac.py` | L4 | 35 | Full 5×7 matrix, unauthenticated 401, cross-tenant |
| `tests/integration/test_attack_path_engine/test_db_schema.py` | L2 | 21 | All 4 tables, columns, constraints, indexes, JSONB deserialization |
| `tests/e2e/test_attack_path_pipeline_e2e.py` | L5 | 12 | Pipeline rows, scan_run_id threading, risk ordering, scan_orchestration |
| `tests/ui/smoke/test_attack_paths.spec.ts` | L7 | 9 | Page load, skeletons, KPI cards, severity color, filters, side panel, tabs |
| `tests/post_deploy/validate_attack_path_deploy.sh` | L10 | 6 | Image tag, health/live, health/ready, logs, BFF smoke, DB, Neo4j |

**Total test count: ~191** (27 + 22 + 24 + 17 + 18 + 35 + 21 + 12 + 9 + 6)

---

## 7. Running the Tests

### L1 — Unit tests (no external deps)
```bash
pytest tests/unit/attack_path/ -v --tb=short
```

### L2 — DB integration (requires port-forwarded RDS)
```bash
# Port-forward inventory DB
kubectl port-forward svc/engine-inventory 5432:5432 -n threat-engine-engines &

INVENTORY_DB_HOST=localhost \
INVENTORY_DB_NAME=threat_engine_inventory \
INVENTORY_DB_USER=postgres \
INVENTORY_DB_PASSWORD=<from-secret> \
pytest tests/integration/test_attack_path_engine/ -v --timeout=60
```

### L3 — BFF contract (no external deps — mocked engine calls)
```bash
pytest tests/bff/test_attack_paths_bff.py -v --tb=short
```

### L4 — RBAC matrix (no external deps — FastAPI TestClient)
```bash
pytest tests/rbac/test_attack_path_rbac.py -v --tb=short
```

### L5 — E2E pipeline (requires completed scan)
```bash
SCAN_RUN_ID=<uuid> \
ATTACK_PATH_DB_HOST=localhost \
INVENTORY_DB_HOST=localhost \
RISK_DB_HOST=localhost \
TENANT_ID=my-tenant \
pytest tests/e2e/test_attack_path_pipeline_e2e.py -v --timeout=120
```

### L7 — UI smoke (requires running frontend)
```bash
BASE_URL=http://<elb>/ui \
npx playwright test tests/ui/smoke/test_attack_paths.spec.ts \
  --config tests/e2e/playwright.config.ts
```

### L10 — Post-deploy (run immediately after kubectl rollout)
```bash
INTENDED_TAG=v-attack-path1 \
TENANT_ID=my-tenant \
bash tests/post_deploy/validate_attack_path_deploy.sh
```

### All blocking levels together (CI pre-merge)
```bash
# L0 static
grep -r "json\.loads" engines/attack-path/ | grep -v ".pyc"  # must be empty
grep -r "latest" deployment/aws/eks/engines/engine-attack-path.yaml  # must be empty
grep -r "DEV_BYPASS_AUTH" engines/attack-path/  # must be empty

# L1 unit
pytest tests/unit/attack_path/ -v --tb=short 2>&1 | tail -20

# L3 BFF
pytest tests/bff/test_attack_paths_bff.py -v --tb=short 2>&1 | tail -20

# L4 RBAC
pytest tests/rbac/test_attack_path_rbac.py -v --tb=short 2>&1 | tail -20
```
