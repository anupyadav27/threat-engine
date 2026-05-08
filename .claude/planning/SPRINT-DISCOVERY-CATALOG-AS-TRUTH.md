# Sprint Plan — Discovery Catalog as Single Source of Truth

**Sprint ID:** DCAT-01
**Date:** 2026-05-06
**Duration:** 2-3 weeks (parallelizable across CSP specialists)
**Track:** Architecture / Cross-CSP / Foundational

---

## Problem Statement

The discovery engine writes raw boto3/SDK responses into `discovery_findings.emitted_fields` JSONB. Every consumer engine (encryption, compliance, IAM, threat, datasec, DBSec, container-security, AI security) then writes its own JSON-walking code to extract fields.

This causes two failure modes:

1. **Silent NULLs** — when an SDK response is nested (e.g. `DescribeKey` puts data under `KeyMetadata`), the consumer's flat `emitted.get("KeySpec")` returns None, columns end up NULL, no error logged. Confirmed in encryption engine: 13/13 keys have NULL `key_spec`, 12/13 have NULL `creation_date`.
2. **Edit fan-out** — a single AWS API change forces edits across N engines. KMS is consumed by 5 engines; updating one field requires 5 edits.

The catalog YAMLs (`catalog/discovery_generator_data/{csp}/{service}/step6_*.discovery.yaml`) **already declare** the per-field flatten via Jinja templates:

```yaml
discovery_id: aws.kms.describe_key
emit:
  item:
    KeySpec:      '{{ response.KeyMetadata.KeySpec }}'
    KeyState:     '{{ response.KeyMetadata.KeyState }}'
    CreationDate: '{{ response.KeyMetadata.CreationDate }}'
```

But the discovery scanner **never renders these templates** — for non-list APIs it dumps the raw response unchanged.

---

## Architectural Decision

**Catalog YAML is the single source of truth for discovery field extraction.** Engines never walk nested JSON.

- Discovery scanner renders `emit.item:` template (Jinja `NativeEnvironment`) at write time.
- `discovery_findings.emitted_fields` is **always flat**: `{KeySpec, KeyState, …}`, never `{KeyMetadata: {…}}`.
- Consumer engines read top-level fields only — no `emitted.get("KeyMetadata", {}).get("X")` walking.
- No `_raw_response` permanent fallback. Catalog gaps are fixed in catalog, not in engine code.
- A lint rule prevents future regressions.

---

## Existing Audit Infrastructure (verified 2026-05-06)

All 6 CSPs have `validate_*_vars_vs_discovery.py` scripts. Latest reports:

| CSP | Last claim | Action |
|---|---|---|
| AWS | 65.9% traceable (`DIRECT_VARS_TRACEABILITY_SUMMARY.md`) | **Fill 34% gap** |
| GCP | 100% (`GCP_100_PERCENT_COMPLETE.md`) | Re-run + verify |
| OCI | 100% (`OCI_100_PERCENT_COMPLETE.md`) | Re-run + verify |
| AliCloud | 100% (`100_PERCENT_COVERAGE_ACHIEVED.md`) | Re-run + verify |
| Azure | unclear | **Run + assess** |
| K8s | claims complete | Re-run + verify |
| IBM | 100% | Re-run + verify |

So **only AWS has a known coverage gap, but all CSP audits must be re-run** since check rules are added continuously.

---

## Sprint Deliverables

### Phase A — Audit (week 1, parallel)

Owner: per-CSP specialist agent + 1 backend coordinator.

| ID | Deliverable | Owner | Days |
|---|---|---|---|
| **A1** | Re-run all 6 CSP `validate_*_vars_vs_discovery.py` scripts; capture coverage % per service | coordinator | 1 |
| **A2** | Add inventory_identifier audit — for every resource_type, verify catalog declares the canonical resource_uid path (ARN format / OCID / GCP self-link / etc.) | coordinator | 1 |
| **A3** | Generate unified gap report `DCAT-AUDIT-2026-05-06.md`: (csp, service, discovery_id, missing_field, used_by_check_rule_id) | coordinator | 1 |
| **A4** | Per-CSP catalog patches — add missing fields to `step6_*.discovery.yaml` files | per-CSP specialist (5 in parallel) | 2-3 each |
| **A5** | Re-run audits — all CSPs must hit 100% before Phase B starts | coordinator | 1 |

**Phase A gate:** Every CSP audit reports ≥ 99% coverage. Hard gate — Phase B cannot start.

### Phase B — Renderer + Observability (week 2)

Owner: 1 backend engineer.

| ID | Deliverable | Days |
|---|---|---|
| **B1** | Implement `render_emit_item_template()` in `engines/discoveries/providers/aws/scanner/service_scanner.py` using `jinja2.nativetypes.NativeEnvironment` + `ChainableUndefined` | 2 |
| **B2** | Replicate renderer in non-AWS scanners (`providers/gcp/`, `providers/azure/`, `providers/oci/`, `providers/alicloud/`, `providers/k8s/`, `providers/ibm/`) — use shared helper from `engines/discoveries/common/jinja_renderer.py` | 2 |
| **B3** | YAML linter (`scripts/lint_catalog_emits.py`) — fails CI if any emit lacks `item:` block, has non-leaf field values, or references undefined Jinja variables | 1 |
| **B4** | Snapshot test fixture per CSP — canned API response + expected flat output, asserts the renderer produces correct flat dict | 1 |
| **B5** | Feature flag `DISCOVERY_RENDER_EMIT=true` (default off until Phase C passes) | 0.5 |
| **B6** | **Render-failure observability** — every Jinja render that produces None / Undefined / fails is logged as a structured event AND inserted into a `discovery_emit_failures` table (see schema below). Built into the renderer so it can never be skipped. | 1.5 |
| **B7** | **Failure analysis dashboard** — `scripts/analyze_emit_failures.py` aggregates the failure table by (csp, service, discovery_id, field) and produces a markdown report — top N missing-field hotspots for the next catalog patch round | 1 |

**Phase B gate:** Snapshot tests green. Lint passes. Failure-log table created and renderer writes to it on every miss.

#### B6 — Render-failure observability (design)

**Schema** — `discovery_emit_failures` table (in discoveries DB):
```sql
CREATE TABLE discovery_emit_failures (
    id              BIGSERIAL PRIMARY KEY,
    scan_run_id     UUID NOT NULL,
    tenant_id       VARCHAR(64) NOT NULL,
    provider        VARCHAR(20) NOT NULL,
    service         VARCHAR(64) NOT NULL,
    discovery_id    VARCHAR(128) NOT NULL,    -- e.g. "aws.kms.describe_key"
    resource_uid    VARCHAR(512),              -- which resource the render was for
    field_name      VARCHAR(128) NOT NULL,    -- e.g. "KeySpec"
    template        TEXT NOT NULL,             -- "{{ response.KeyMetadata.KeySpec }}"
    failure_reason  VARCHAR(32) NOT NULL,     -- 'undefined_path' | 'type_error' | 'jinja_syntax' | 'empty_string'
    failure_detail  TEXT,                      -- full exception message or path that was missing
    response_keys   JSONB,                     -- top-level keys actually present in response (debug aid)
    occurred_at     TIMESTAMPTZ DEFAULT now(),
    INDEX(provider, service, discovery_id, field_name),
    INDEX(scan_run_id),
    INDEX(occurred_at DESC)
);
```

**Renderer hook** — pseudocode for the catch:
```python
def render_field(field, template, ctx, meta):
    try:
        value = jinja_env.from_string(template).render(**ctx)
    except Exception as exc:
        log_emit_failure(meta, field, template, "jinja_syntax", str(exc))
        return None

    if isinstance(value, ChainableUndefined):
        log_emit_failure(meta, field, template, "undefined_path",
                         f"path missing in response; available top-level keys: {list(ctx['response'].keys())[:10]}")
        return None
    if value in ("", "None"):
        log_emit_failure(meta, field, template, "empty_string", None)
        return None
    return value
```

**Aggregation query** (drives next catalog patch sprint):
```sql
SELECT
    provider, service, discovery_id, field_name,
    COUNT(*) AS failure_count,
    COUNT(DISTINCT resource_uid) AS unique_resources_affected,
    array_agg(DISTINCT failure_reason) AS reasons,
    array_agg(DISTINCT response_keys::text) FILTER (WHERE response_keys IS NOT NULL) AS sample_response_shapes
FROM discovery_emit_failures
WHERE occurred_at > now() - interval '7 days'
GROUP BY provider, service, discovery_id, field_name
ORDER BY failure_count DESC
LIMIT 100;
```

**Why a table, not just logs:** logs get rotated, scrubbed, hard to aggregate cross-pod. A table gives durable, queryable history that survives engine restarts and lets ops produce weekly "field-coverage health" reports without scraping log shippers.

**Bonus:** the same script can run a daily Slack/email digest: "Top 10 fields that failed to render this week — fix in catalog YAML."

### Phase C — Validation (week 2 end)

Owner: 1 backend engineer + 1 QA.

| ID | Deliverable | Days |
|---|---|---|
| **C1** | Validation script `scripts/validate_render_no_regression.py`: re-render every existing `discovery_findings` row, diff old vs new shape, assert every column populated in `*_inventory` tables would still be populated | 2 |
| **C2** | Run validator against `test-tenant-002` — fix any catalog gaps surfaced (loop back to Phase A4 if needed) | 1 |
| **C3** | Run validator against `Multi-Cloud Platform` (largest tenant) | 1 |
| **C4** | Approval gate — sign-off from each CSP specialist on their own slice | 0.5 |

**Phase C gate:** Zero column-level regressions reported by validator.

### Phase D — Discovery cutover (week 3 start)

Owner: 1 backend engineer + ops.

| ID | Deliverable | Days |
|---|---|---|
| **D1** | Enable feature flag in staging — discovery scanner renders `emit.item:` for all new scans | 0.5 |
| **D2** | Trigger one scan per CSP against `test-tenant-002`, validate `discovery_findings.emitted_fields` is flat | 1 |
| **D3** | Production cutover — flag on for all engines, ship discovery image | 0.5 |
| **D4** | Re-scan all tenants once (background, batched per tenant) — repopulates `discovery_findings` with flat data | 2 (background) |

**Phase D gate:** All tenants re-scanned, validator confirms 100% flat shape.

### Phase E — Per-engine cutover (week 3 ongoing)

Owner: per-engine team. Sequential — one engine at a time.

For each consumer engine:

| Step | Action |
|---|---|
| E.x.1 | Audit engine's `*_inventory_builder.py` for nested-walking code paths |
| E.x.2 | Replace `emitted.get("Wrapper", {}).get("X")` with `emitted.get("X")` |
| E.x.3 | Drop any custom unwrap helpers (e.g. today's `KeyMetadata` merge in `key_inventory_builder.py`) |
| E.x.4 | Backfill `*_inventory` table from `discovery_findings.raw_data` via SQL — no re-scan needed |
| E.x.5 | Build + push engine image with `-flat1` tag |
| E.x.6 | Smoke test: BFF view returns populated columns |

Order (highest impact first):
1. **encryption** — already broken, fixes the immediate user-visible issue
2. **compliance** — high consumer of cross-service fields
3. **IAM** — heavy on nested `User`/`Role` envelopes
4. **threat** — many MITRE rules depend on flat fields
5. **datasec, dbsec, container-security, ai-security** — smaller surface
6. **risk, ciem, network-security** — already mostly flat

Estimate: 1 day per engine × 9 engines = 2 weeks (can run in parallel pairs).

### Phase F — Lock-in (week 5)

| ID | Deliverable | Days |
|---|---|---|
| **F1** | Pre-commit hook + CI lint: any new code referencing nested `emitted_fields` (e.g. `emitted.get("KeyMetadata"`)) fails review | 0.5 |
| **F2** | Update `.claude/documentation/CSPM_CONSTITUTION.md` §X — codify "catalog is sole truth, engines read flat fields only" | 0.5 |
| **F3** | Update `.claude/agents/cspm-discovery-engineer.md` and per-CSP agents with the new contract | 0.5 |
| **F4** | Retrospective + ADR — document the design decision and gotchas | 0.5 |

---

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| AWS catalog has more than 34% gap when re-run | Medium | High | Phase A is gated — block Phase B until 99%+ |
| Jinja `NativeEnvironment` doesn't preserve all types (datetime, Decimal) | Medium | Medium | B4 snapshot tests cover edge cases per CSP |
| Existing engines silently break when shape flips from nested to flat | High | High | Phase E is sequential and per-engine, with smoke test gate |
| Re-scan overload during Phase D4 | Low | Medium | Batch by tenant, off-peak, throttle scan jobs |
| Catalog-driven extraction misses fields engines added recently | Medium | High | Validator (C1) gates deploy; any column regression blocks |
| GCP/OCI/AliCloud "100%" claims are stale | Medium | Medium | Re-run script in A1; treat all CSPs as suspect until verified |
| Some emit blocks use templating Jinja can't natively render (custom filters, complex expressions) | Low | Medium | Add custom filter registry to renderer; lint catches usage |

---

## Resource & Skill Requirements

| Role | Count | Skills |
|---|---|---|
| Backend coordinator | 1 | Python, Jinja2, audit scripts, owns end-to-end |
| AWS specialist | 1 | boto3 deep, ARN patterns, KMS/IAM/EC2/RDS/S3 quirks |
| GCP specialist | 1 | google-cloud-* SDK, protobuf message types, project hierarchy |
| Azure specialist | 1 | azure-mgmt-* SDK, ARM templates, resource ID format |
| OCI specialist | 1 | OCI SDK, OCID format, compartment model |
| AliCloud specialist | 1 | aliyun-python-sdk, regional partitioning |
| K8s specialist | 0.5 | kubernetes Python client, CRD handling |
| IBM specialist | 0.5 | ibm-vpc, IAM patterns |
| QA | 1 | Snapshot testing, integration testing, contract diff |
| Per-engine team | varies | Engine-specific knowledge for cutover (Phase E) |

---

## Success Criteria

1. ✅ Every CSP audit reports ≥ 99% check_var ↔ emit traceability
2. ✅ Discovery scanner renders catalog `emit.item:` templates for both list and single modes
3. ✅ `discovery_findings.emitted_fields` is flat (no nested envelopes) for all post-cutover scans
4. ✅ Validator reports zero column-level regressions in any `*_inventory` table
5. ✅ All consumer engines drop nested-JSON walking; PRs adding such code fail CI
6. ✅ Catalog YAML is the documented single source of truth in CSPM_CONSTITUTION
7. ✅ The original encryption Keys/Certificates/Secrets columns populate end-to-end
8. ✅ **`discovery_emit_failures` table populated on every scan; weekly digest of top hotspots delivered to ops; no silent NULLs ever again**

---

## Out of Scope (explicit non-goals)

- Restructuring the YAML format itself (the two-mode `items_for` / `item:` design stays — see DCAT-RFC-01 for rationale)
- Catalog auto-generation from boto3 type stubs (separate sprint — `STORY-CATALOG-CODEGEN`)
- Migrating Layer 3 to a typed schema language (Pydantic / Avro / protobuf) — future quarter
- Cross-CSP normalization of resource_uid format — separate sprint (`STORY-RESOURCE-UID-UNIFY`)

---

## Hand-offs

- After Phase A: hand catalog gap report to per-CSP specialists for fill-in
- After Phase B: hand renderer to QA for snapshot validation
- After Phase D: hand flat `discovery_findings` to per-engine teams for cutover
- After Phase F: hand lint rules + docs to platform team for ongoing enforcement

---

## Dependencies

- `cspm-discovery-engineer` agent for code review
- `bmad-architect` agent for architectural sign-off on the catalog-as-truth contract
- `bmad-security-reviewer` agent for review of `_raw_response` removal (audit data path)
- Re-scan capacity: at least 6 hours of pipeline time per tenant (for Phase D4)

---

## Definition of Done

- All 6 phases complete
- Encryption engine Keys/Certificates/Secrets columns populated for `test-tenant-002` (the original bug)
- 9 consumer engines pass smoke tests against flat `discovery_findings`
- CSPM_CONSTITUTION updated
- This sprint plan archived to `stories/README.md` completed sprints
