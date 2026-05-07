# Sprint Plan — DCAT-02: Multi-CSP Catalog-Driven Discovery Migration

**Sprint ID:** DCAT-02
**Date:** 2026-05-07
**Duration:** 6-8 weeks (parallelizable across CSP specialists)
**Track:** Architecture / Cross-CSP / Foundational
**Depends on:** DCAT-01 (AWS catalog-as-truth, complete) ✅

---

## Problem Statement

DCAT-01 successfully landed catalog-as-truth for AWS:
- 372 service patches (49,731 fields auto-added) in catalog YAML + DB
- Jinja `NativeEnvironment` renderer in discovery scanner
- Verified flat `discovery_findings.emitted_fields` end-to-end

**But the renderer is AWS-only.** The other 6 CSP scanners are hand-coded discovery functions (one Python function per service per CSP) that don't read catalog YAML at all:

| CSP | Discovery model today | Total LoC | Catalog adoption |
|---|---|---|---|
| AWS | catalog-driven (Jinja templates → flat) | ~2k | ✅ DCAT-01 complete |
| GCP | hand-coded per-service Python | 1,661 | ❌ ignored |
| Azure | hand-coded per-service Python | 936 | ❌ ignored |
| OCI | hand-coded per-service Python | 1,820 | ❌ ignored |
| AliCloud | hand-coded per-service Python | 941 | ❌ ignored |
| K8s | hand-coded per-service Python | 979 | ❌ ignored |
| IBM | hand-coded per-service Python | 361 | ❌ ignored |

**Symptom:** every cloud-side data sparseness bug we hit on AWS (encryption Keys, IAM detail, certs) **will exist on every other CSP** with no remediation path until the same catalog-driven architecture lands per CSP.

---

## Architectural Goal

Bring all 6 non-AWS CSPs to the same catalog-as-truth contract that AWS now has:

1. Catalog YAML declares `discovery` blocks with `calls`, `for_each`, `emit.item` (Jinja templates).
2. DB `rule_discoveries.discoveries_data` mirrors the catalog (engines read from DB).
3. Generic scanner runtime executes catalog: SDK call → response → Jinja render → flat dict in `discovery_findings.emitted_fields`.
4. No hand-coded per-service Python in discovery — just per-CSP SDK adapters that turn `(service, action, params)` into a typed response.

---

## Per-CSP Adoption Pattern

Each CSP follows the same 5-phase rollout:

### Phase 1 — SDK Type-Stub Audit (`A0.5` analog)
- Build `load_<csp>_field_tree(service, operation)` in `scripts/catalog_gap_autogen.py`.
- For Azure: walk `azure-mgmt-*.models.*` Pydantic-like classes.
- For GCP: walk protobuf `descriptor` of each `*ServiceClient` method response.
- For OCI: walk `oci.<service>.models.<Response>.swagger_types`.
- For AliCloud: walk `aliyunsdkcore.acs_exception.exceptions` + per-service request/response models.
- For K8s: walk `kubernetes.client.models.*` openapi_types.
- For IBM: walk `ibm_*.models.*` request/response schemas.
- Run auto-suggester against the existing CSP catalog YAMLs in `catalog/discovery_generator_data/<csp>/`.
- Output: `catalog/_dcat_patches/<csp>/<svc>.patch.yaml` with auto-add/rename items.

### Phase 2 — Catalog Patches Applied (local + DB)
- Run `scripts/apply_catalog_patches.py --provider <csp> --all`.
- Run `scripts/dcat_db_sync.py` (already supports any provider).
- Validation: `rule_discoveries` table has updated `discoveries_data` for the CSP.

### Phase 3 — Generic Scanner Runtime
- Refactor each CSP's `service_scanner.py` from hand-coded discovery functions to a generic catalog-executor.
- Pattern: load catalog → for each discovery_id → call SDK action via thin adapter → render emit.item via shared `common.jinja_renderer.render_emit_item`.
- Reuse the same `_emit_failure_sink` + `discovery_emit_failures` table that DCAT-01 ships.

### Phase 4 — Per-CSP Adapter Layer
- Build a small SDK adapter per CSP: `(service, action, params, context) → response_dict`.
- Adapter handles SDK quirks (auth tokens, regional vs global endpoints, pagination).
- Keeps catalog YAML authoritative — no service-specific Python code.

### Phase 5 — Validation Pass
- Re-scan one tenant per CSP with `DISCOVERY_RENDER_EMIT=true`.
- Diff `discovery_findings.emitted_fields` shape against the catalog to verify flat output.
- Rerun all consumer engines (check, inventory, threat, etc.) → confirm `*_findings` populated.

---

## Per-CSP Effort Estimate

| CSP | SDK introspection | Catalog patches | Scanner refactor | Validation | Total |
|---|---|---|---|---|---|
| **GCP** | 3 days (protobuf walker) | 1 day (auto-gen + sync) | 7 days (refactor 1,661 LoC scanner) | 2 days | **~2.5 weeks** |
| **Azure** | 3 days (Pydantic-like models) | 1 day | 5 days (936 LoC) | 2 days | **~2 weeks** |
| **OCI** | 4 days (`swagger_types` walker) | 1 day | 7 days (1,820 LoC) | 2 days | **~3 weeks** |
| **AliCloud** | 3 days (per-service models) | 1 day | 5 days (941 LoC) | 2 days | **~2 weeks** |
| **K8s** | 2 days (openapi_types easy) | 1 day | 5 days (979 LoC) | 2 days | **~2 weeks** |
| **IBM** | 2 days | 1 day | 3 days (361 LoC, smallest) | 2 days | **~1.5 weeks** |

**Total sequential: ~13 weeks. With 3 specialists in parallel: ~5 weeks.**

---

## Sub-Sprint Breakdown

### DCAT-02-A — GCP (priority 1, largest non-AWS surface)
- Owner: GCP-discovery specialist
- Deliverables: gcp SDK type walker, 600 service patches applied, scanner refactored
- Dep: DCAT-01 renderer module (already in `engines/discoveries/common/`)

### DCAT-02-B — Azure (priority 2, similar size)
- Owner: Azure-discovery specialist
- Deliverables: azure-sdk type walker, 604 service patches, scanner refactored
- Notes: Azure has the most uniform SDK shape — should be simpler than GCP

### DCAT-02-C — OCI
- Owner: OCI-discovery specialist
- Deliverables: oci `swagger_types` walker, 345 service patches, scanner refactored
- Notes: largest scanner LoC, most refactor work

### DCAT-02-D — AliCloud
- Owner: AliCloud-discovery specialist
- Deliverables: aliyun model walker, 317 service patches, scanner refactored
- Notes: has region partitioning quirks — adapter handles

### DCAT-02-E — K8s
- Owner: K8s-discovery specialist
- Deliverables: kubernetes openapi walker, 122 service patches, scanner refactored
- Notes: simplest SDK introspection (openapi-generated)

### DCAT-02-F — IBM
- Owner: IBM-discovery specialist (or generalist)
- Deliverables: ibm SDK walker, 154 service patches, scanner refactored
- Notes: smallest surface, fastest sub-sprint

### DCAT-02-Z — Cross-cutting cleanup
- Owner: Platform team
- Deliverables:
  - Drop `_raw_response` fallback once all CSPs migrated
  - Add lint rule: any new code touching `emitted.get("X", {}).get("Y")` fails CI
  - Update CSPM_CONSTITUTION §X with catalog-as-truth standard for all providers
  - Single-source `discovery_emit_failures` dashboard query for ops

---

## Dependencies & Sequencing

```
DCAT-01 (AWS) ✅
   │
   ├── DCAT-02-A (GCP) — start immediately
   ├── DCAT-02-B (Azure) — start immediately
   ├── DCAT-02-C (OCI) — start immediately
   ├── DCAT-02-D (AliCloud) — wait for one of above to validate refactor pattern
   ├── DCAT-02-E (K8s) — wait for refactor pattern proven
   └── DCAT-02-F (IBM) — last (smallest, lowest risk)
        │
        └── DCAT-02-Z — fires after all CSPs done
```

Recommended: GCP, Azure, OCI in parallel (3 specialists) → AliCloud, K8s, IBM in second wave (3 more or rotation) → cleanup.

---

## Success Criteria

1. ✅ Every CSP has a `service_scanner.py` that consumes catalog YAML, not hand-coded.
2. ✅ Every CSP's `discovery_findings.emitted_fields` is flat (no nested envelopes) for new scans.
3. ✅ Every CSP runs through the same `common.jinja_renderer` module with `discovery_emit_failures` observability.
4. ✅ Every consumer engine (encryption, IAM, threat, datasec, etc.) reads flat fields from any CSP source without per-CSP unwrap code.
5. ✅ Catalog patches synced to `rule_discoveries` DB table for all CSPs.
6. ✅ Lint rule prevents any future regression to nested-JSON walking.

---

## Out of Scope (explicit)

- New service coverage (just migrate existing services to new architecture).
- Schema migration in `discovery_findings` table (the JSONB column accepts both shapes).
- Per-engine cutover for non-AWS data (handled by individual engine teams once their CSP catalog is migrated).
- Cross-CSP normalization of resource_uid format (separate sprint `STORY-RESOURCE-UID-UNIFY`).

---

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| GCP protobuf descriptors hard to walk programmatically | Medium | Medium | Fall back to `descriptor.json` files shipped with `grpcio-tools` |
| Azure SDK version drift between services | High | Low | Pin azure-mgmt-* per service, lock in requirements.txt |
| OCI scanner refactor breaks existing scans | Medium | High | Feature flag per CSP (`DISCOVERY_RENDER_EMIT_<CSP>=true`) |
| AliCloud regional partitioning surprises | Low | Medium | Adapter handles; existing scanner already deals with it |
| Catalog YAML drift during long migration | Medium | Medium | Lock `_dcat_patches/` review queue; weekly digest of unpatched gaps |

---

## Operational Plan

1. **Week 1**: spin up 3 per-CSP chips (GCP, Azure, OCI) with the deliverable list. Each agent loads catalog/_dcat_patches/<csp>/ + the existing scanner code.
2. **Week 2-3**: SDK introspection complete + patches generated for first 3 CSPs.
3. **Week 4**: scanner refactor for first 3 CSPs in feature-flagged form. Smoke test on a small tenant.
4. **Week 5**: AliCloud, K8s, IBM kick off in parallel.
5. **Week 6-7**: full validation pass per CSP, fix any catalog gaps surfaced.
6. **Week 8**: cleanup (remove `_raw_response` fallback, ship lint rule, update CONSTITUTION).

---

## Definition of Done

- [ ] All 6 non-AWS CSPs run on `common.jinja_renderer`.
- [ ] All `service_scanner.py` files use the generic catalog executor (no hand-coded discovery functions).
- [ ] `discovery_emit_failures` shows < 100 failures/week per CSP at steady state.
- [ ] CSPM_CONSTITUTION updated; lint rule active.
- [ ] This sprint plan archived in `stories/README.md` Completed Sprints.
