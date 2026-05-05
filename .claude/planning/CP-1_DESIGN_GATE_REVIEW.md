# CP-1 — Design Gate Review (Phase A complete)

**Date:** 2026-05-05
**Phase:** A (D1–D3) — Hard blockers
**Reviewers:** `bmad-security-architect` (per-story Accountable), `cspm-security-reviewer` (consolidated)
**Stories under review:** JNY-01, JNY-02, JNY-03

## Aggregate Verdict: **APPROVE WITH CHANGES — Phase B/C/D unblocked CONDITIONAL on 4 inline fixes**

All three stories may enter dev phase. Two MUST-FIXes are inline (1 hour each); two MUST-VERIFYs require code reads + tests, do not block dev start but must close before deploy (JNY-04).

---

## 1. Per-story design verdict summary

| Story | Lead handoff | Verdict | Pre-merge items | Risk |
|---|---|---|---|---|
| JNY-01 | [threat-engine](stories/JNY-01_handoff_threat-engine.md) (consult) | APPROVE WITH CHANGES | schema additions absorbed | Low |
| JNY-01 | [cspm-db-engineer](stories/JNY-01_handoff_cspm-db-engineer.md) (R) | Migration drafted, 262 lines | needs lock-window check | Low — split JNY-01a if threat_findings > 2 GB |
| JNY-01 | [bmad-security-architect](stories/JNY-01_handoff_bmad-security-architect.md) (C) | APPROVE WITH CHANGES | 4 controls (Tampering: Critical) | Medium — global ref table |
| JNY-02 | [cspm-bff-dev](stories/JNY-02_handoff_cspm-bff-dev.md) (R) | 1-line fix at `inventory.py:570` | none | None — micro-fix |
| JNY-03 | [django+rbac](stories/JNY-03_handoff_django-rbac.md) (R) | ACCEPT-with-minor-gaps | story-doc reconcile | Low |
| JNY-03 | [bmad-security-architect](stories/JNY-03_handoff_bmad-security-architect.md) (A — CP-1 gate) | **APPROVE WITH CHANGES** | 6 pre-merge controls | **Medium-High — `/ciem_identity` has NO permission gate today** |

## 2. Consolidated MUST-FIX list (blocks deploy, NOT dev start)

| # | Source | Fix | Story | Owner | Phase |
|---|---|---|---|---|---|
| **MF-1** | JNY-01 sec arch | Bundle `mitre_attack_enterprise_v15.1.json` STIX with **SHA-256 manifest** + 4-eyes PR review on every seed update; reject runtime fetch | JNY-01 | `cspm-db-engineer` + `cspm-deploy` | dev |
| **MF-2** | JNY-01 sec arch | Add format `CHECK (technique_id ~ '^T[0-9]{4}(\.[0-9]{3,4})?$')` constraint **before** any seed insert | JNY-01 | `cspm-db-engineer` | dev (already in draft) |
| **MF-3** | JNY-03 sec arch | **Add `ciem:sensitive` permission gate + audit log to `bff/ciem_identity.py:view_ciem_identity`** — currently the Stage 2 identity profile bypasses RBAC entirely | JNY-03 | `cspm-bff-dev` + `cspm-rbac-guardian` | dev |
| **MF-4** | JNY-03 sec arch | Add audit log to `bff/inventory.py:view_asset_ciem` (L705) covering top-5 `identity_arn`s + `result` field + `request_id` | JNY-03 | `cspm-bff-dev` | dev |
| **MF-5** | JNY-03 django+rbac | Reconcile story doc with migration 0013 — 4 roles (analyst/tenant_admin/org_admin/platform_admin), not "platform_admin only" | JNY-03 | `cspm-rbac-guardian` | docs (parallel) |

## 3. MUST-VERIFY list (do not block dev, must close before JNY-04 deploy)

| # | Source | Verify | Owner | Phase |
|---|---|---|---|---|
| **MV-1** | JNY-01 db-eng | Pre-apply `SELECT pg_total_relation_size('threat_findings')` — if > 2 GB, split STORED column ADD into JNY-01a separate migration | `cspm-db-engineer` | pre-deploy |
| **MV-2** | JNY-03 sec arch | `engines/ciem/ciem_engine/api_server.py` route `/api/v1/ciem/findings` enforces `tenant_id` from `X-Auth-Context`, NOT from query param | `ciem-engine` | pre-deploy |
| **MV-3** | JNY-03 sec arch | `tests/bff/test_inventory_ciem.py` covers: (a) viewer → 403, (b) cross-tenant asset → 403, (c) audit-log emission on 200+403 | `bmad-qa` | dev |
| **MV-4** | JNY-01 db-eng | Migration runs in BEGIN/COMMIT; rollback path exercised on staging DB before prod | `cspm-deploy` | pre-deploy |

## 4. SHIP-GATE items (deferred to post-Phase G — track, do not block sprint)

These were flagged but explicitly downgraded by reviewers as residual risk:

- **SG-1** — Add HMAC signature on `X-Auth-Context` header (Tampering Medium residual). Spin off as `STORY-SEC-HMAC-AUTH-CONTEXT`.
- **SG-2** — Audit logs to durable store (DB `audit_log` table or CloudWatch group with retention). `logging.getLogger` alone is not SOC2-durable. Spin off as `STORY-SEC-AUDIT-DURABLE`.
- **SG-3** — Per-user rate limit (60 req/min) on CIEM BFF routes. Spin off as `STORY-SEC-CIEM-RATELIMIT`.
- **SG-4** — NetworkPolicy verification (engine pods only reachable from gateway). Spin off as `STORY-SEC-NETPOL-VERIFY`.

Five spin-off stories total. Add to next sprint's backlog.

## 5. Decision log

| Decision | Rationale |
|---|---|
| `mitre_technique_reference` is a **global table** (no `tenant_id`) | Reference data, same for all tenants. Per-tenant filtering happens on `threat_findings` only. Documented in schema header comment. |
| Sub-technique handling: **BOTH** (parent rollup + exact match) via generated column | Avoids `LIKE` patterns in BFF, both queries are index-scans. |
| Seed source: **bundled STIX v15.1** at image build time, not runtime fetch | Cold-start, supply-chain hygiene, deterministic deploys. |
| `ciem:sensitive` granted to **4 roles** (analyst, tenant_admin, org_admin, platform_admin), not just platform_admin | Least-privilege analysis confirms analysts already see same-class data; denying breaks investigation journey. |
| Migration 0013 stays as-is | Already correct per RBAC matrix; story doc updates instead. |

## 6. Phase B/C/D entry — UNBLOCKED

The following can now begin in parallel (per Sprint §3 sequencing rules):

- **JNY-04** (deploy) — gated on JNY-01/02/03 dev complete + MV-1..4
- **JNY-05** (universal route) — Phase B start
- **JNY-06** (universal BFF) — Phase B start
- **JNY-13** (BFF L1+L2 contract tests) — Phase H, parallel
- **JNY-15** (Engine L0+L2) — Phase H, parallel

## 7. Open issues escalated to user

1. **Lock window** for JNY-01 migration: 60-120s estimated. Acceptable during off-peak; recommend coordinating with operators if `threat_findings` is being written to actively. Need user confirmation on deploy window.
2. **`/ciem_identity` permission gap** is a real security regression introduced by the new BFF (untracked file). Currently anyone with session reaches Stage 2 identity data without `ciem:sensitive`. **MF-3 closes it but the team should be aware this is hot.**
3. Story JNY-03 doc requires text-only update to match migration scope (4 roles).

## 8. Sign-off

**CP-1 Status:** ✅ PASSED — Phase B/C/D may begin
**Conditions:** MF-1..MF-5 land in dev phase before JNY-04 deploy. MV-1..MV-4 verified before deploy.
**Next gate:** CP-2 Schema gate (D7) — Pydantic response models for JNY-05/06/13/15.
