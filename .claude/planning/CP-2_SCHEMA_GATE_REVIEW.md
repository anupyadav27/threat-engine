# CP-2 Schema Gate Review — Phase B Designs

**Verdict:** PASS-WITH-CONDITIONS
**Reviewers:** bmad-security-architect (A) + cspm-rbac-guardian + cspm-standards-guardian
**Phase B dev unblocked:** CONDITIONAL — 4 blocking-pre-dev items must close (all are 1–2 line clarifications, not redesigns)

## 1. Per-handoff verdict

| Handoff | Pillar A (STRIDE) | Pillar B (RBAC) | Pillar C (Constitution) | Overall |
|---|---|---|---|---|
| JNY-05 | PASS-W-COND | PASS-W-COND | PASS-W-COND | PASS-W-COND |
| JNY-06 | PASS-W-COND | PASS-W-COND | PASS | PASS-W-COND |
| JNY-07 | PASS | PASS | PASS-W-COND | PASS-W-COND |

## 2. Blocking findings (must close before dev start)

**B1 — Engine slug taxonomy mismatch.** JNY-05 whitelist uses long slugs (`network-security`); JNY-06 `EngineSlug` literal uses short slugs (`network`). Will not interoperate at the URL→BFF boundary. **Required action:** pick ONE canonical set; recommend long slugs (K8s service names) and map short→long inside `_finding_engine_map.py`.

**B2 — Status PATCH bypasses BFF.** JNY-05 §2/§9 routes UI→engine directly for status mutation. Violates Constitution §UI-Backend / ADR §3.1.c. Gateway routes for `secops`, `ciem`, `dbsec`, `ai-security`, `encryption`, `container-security`, `iam`, `network-security`, `datasec` have inconsistent or missing PATCH RBAC + audit-log enforcement. **Required action:** route status PATCH through BFF with explicit per-engine writer functions.

**B3 — Standard column model gap.** JNY-06 `StandardColumns` Pydantic model needs (a) unit test asserting `set(StandardColumns.model_fields) ⊇ MANDATORY_14` and (b) `model_validator(mode='after')` rejecting any serialized output containing `/credential|secret|raw_event/i` keys.

**B4 — secops gap with no story link.** JNY-06 returns 501 for `secops` until "STORY-ENG-secops-finding-table" closes. That story does not exist. **Required action:** file the secops table-confirmation story OR explicitly accept secops findings can't open in Phase B (UI hide secops PivotLinks).

## 3. Conditional findings (must close before deploy)

C1: CIEM audit-log per-page-view (correct).
C2: Tab 3 cross-engine permission filter — disclose `restrictedEngines` (correct OWASP A01).
C3: Tab 4 Compliance — hide entire tab on 403 (Phase B); row-level redaction in Phase C.
C4: 5-min in-process LRU on rule_metadata cache (Phase B); Redis migration as Phase C tech debt.
C5: Telemetry sink — console.debug stub now; PostHog/DataDog as Phase C decision.
C6: `engineExtensions` denylist validator (`__proto__`, `constructor`, etc.).
C7: SectionErrorBoundary — confirm gateway injects `correlation_id` on all 11 engine responses.
C8: JNY-07 §9 router.push exclusions — add one-line reason comments.

## 4. Resolutions for OQs (consolidated)

**JNY-05:** OQ-1 defense-in-depth (c); OQ-2 per page-view; OQ-3 hide tab; OQ-4 long slugs.

**JNY-06:** OQ-1 YES (DB-direct OK); OQ-2 filter + restrictedEngines; OQ-3 YES validator; OQ-4 YES 404; OQ-5 YES safe; OQ-6 YES denylist. Engine OQs: secops blocking; threat_findings canonical; ciem null→{}; single rule_control_mapping; remediation_guidance standardized.

**JNY-07:** OQ-1 to='scan' with kind='project'; OQ-2 YES kind prop; OQ-3 console.debug stub; OQ-4 best-effort prefetch; OQ-5 target enforces; OQ-6 icons approved; OQ-7 severity color OK.

## 5. Sign-off

- [x] bmad-security-architect: **PASS-WITH-CONDITIONS** (B1, B2 pre-dev)
- [x] cspm-rbac-guardian: **PASS-WITH-CONDITIONS** (B2 pre-dev; C2 pre-deploy)
- [x] cspm-standards-guardian: **PASS-WITH-CONDITIONS** (B1, B3 pre-dev; C4, C6 pre-deploy)
- Next gate: CP-3 Auth termination gate (D14, before JNY-17)

**CP-2 verdict: CONDITIONAL. Blocking pre-dev: 4. Pre-deploy: 8. Top concern: status PATCH bypasses BFF/audit — gateway RBAC inconsistent across 7+ engines.**
