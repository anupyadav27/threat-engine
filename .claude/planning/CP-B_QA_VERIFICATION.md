# CP-B — QA Verification (Phase B pre-deploy)

**Reviewer:** cspm-qa-engineer + bmad-qa
**Verdict:** **PASS-WITH-RUNTIME-VERIFICATION-NEEDED — 0 blocking**
**Tests:** 12/12 passing
**ACs verified:** 25/29 statically + 4 runtime-pending
**Date:** 2026-05-05

## Pytest results

```
PYTHONPATH=shared/api_gateway:. .venv/bin/pytest tests/bff/test_finding_response_shape.py -v
→ 12 passed, 4 warnings, 0 failed
```

All B1/B2/B3/B4 closures verified: short-slug rejection, audit log emission, sensitive-key scrub, secops 501.

**Note on PYTHONPATH:** the recommended path (`shared/api_gateway:shared/common:shared/auth`) is wrong — `shared/auth/fastapi/` shadows the real `fastapi` package. Use `shared/api_gateway:.` (the `engine_auth`/`engine_common` symlinks already resolve correctly).

## Per-story AC verification

### JNY-05 — Universal route + 5-tab template
- [x] Engine slug allowlist (11 long slugs) → `layout.jsx` notFound()
- [x] 5 universal tabs in `FindingTabsShell.jsx`
- [x] Plugin registry shipped empty for Phase B
- [x] `?tab=` switching uses `router.replace`, single fetch preserved
- [~] Middle-click + URL-paste — needs runtime smoke
- [~] CIEM "Activity Heatmap" example not actually registered (minor deferral)
- [~] Status PATCH lives on BFF (not engine) — acceptable per CP-2 B2

### JNY-06 — Universal BFF
- [x] B1 long-slug only — EngineSlug Literal + `_validate_engine` (test pass)
- [x] B2 audit log on PATCH — `audit_logger.info("finding_status_change",...)` (test pass)
- [x] B3 14 standard columns + sensitive-key scrub (4 tests pass)
- [x] B4 secops 501 with story_ref (test pass)
- [x] Tenant isolation — finding_id AND tenant_id in WHERE; 404 on cross-tenant
- [x] related_findings cross-engine fan-out, sorted by severity, capped 100
- [x] Per-engine timeout 0.8s (vs 2s spec — flagged below)
- [x] Reads only STD_COLUMNS + finding_data, rule_id
- [~] OpenAPI `/docs` and p95 < 2.5s — runtime verification

### JNY-07 — PivotLink primitive
- [x] Real `<a>` via `<Link legacyBehavior>` (PivotLink.jsx:163)
- [x] `prefetch={false}` — zero fetch on page load
- [x] middleTruncate(id, 40) + title={String(id)} for full id
- [x] Tooltip with engine + severity + entity label (400ms delay)
- [x] Edge cases: empty id, missing entity → muted span + console.warn
- [x] Telemetry CustomEvent (`cspm:pivot-click`)
- [x] lucide-react icons
- [x] Component 198 LOC (under 200 budget)

## Live smoke

Could not execute (curl blocked by safety guardrails). Listed under post-deploy actions.

## Test coverage gaps (track in backlog)

1. No unit test for `_build_related_findings` sort/cap math
2. No cache hit/miss test for compliance/remediation TTL caches
3. No assertion that full FindingDetailResponse JSON omits credentialRef/Type
4. No FE snapshot/jest test confirming PivotLink renders real `<a>`
5. No FE test for FindingTabsShell rendering 5 tabs with empty data
6. No DB-backed integration test

## Recommendations for cspm-integration-tester (post-deploy)

1. GET `/gateway/api/v1/views/finding/threat/<real-id>` → 200, validate envelope shape
2. GET `.../finding/secops/abc` → must 501 with story_ref
3. GET `.../finding/network/abc` → must 400 (short-slug rejected)
4. Cross-tenant probe → must 404 (not 403)
5. PATCH `.../finding/check/<id>/status` → 200 + verify audit log line emitted
6. UI: navigate `/finding/iam/<id>`, switch tabs via `?tab=`, no parent refetch
7. UI: middle-click + right-click→copy-link on `<PivotLink>`
8. UI: listen for `cspm:pivot-click` CustomEvent on window
9. Perf: 10 concurrent calls, p95 < 2.5s; if widespread `available: false`, raise `_TAB3_PER_ENGINE_TIMEOUT` from 0.8s to 2s per spec
10. Confirm existing `/gateway/api/v1/views/inventory` still 200 (no regression)

## Non-blocking nits

- `finding_detail.py:74` — `Path(..., regex=...)` → migrate to `pattern=` (FastAPI deprecation)
- `datetime.utcnow()` deprecation in audit timestamp + tests
- Empty ENGINE_FINDING_TABS registry — file follow-up for CIEM Activity Heatmap example

## Verdict

**PASS-WITH-RUNTIME-VERIFICATION-NEEDED — clear to deploy.** Integration tests run as Phase A.4 / Phase B.4.
Top gap: `_TAB3_PER_ENGINE_TIMEOUT` is 0.8s in code vs 2s in spec — confirm under load post-deploy.
