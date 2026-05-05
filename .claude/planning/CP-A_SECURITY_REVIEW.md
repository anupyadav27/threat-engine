# CP-A — Security Review (Phase A diff)

**Date:** 2026-05-04
**Reviewers:** cspm-security-reviewer + bmad-security-reviewer (combined gate)
**Scope:** JNY-01 (migrations + loader + technique_detail) + JNY-02 (blast-radius dispatch fix) + JNY-03 (CIEM gate + audit)
**Frameworks applied:** OWASP Top 10 2021, CSPM-specific, SLSA, STRIDE, CSA CCM, NIST CSF 2.0

---

## 1. Verdict — **PASS-WITH-CONDITIONS**

Phase A diff is safe to deploy to staging behind a feature flag. **One blocking finding (B-1)** must close before production deploy. All five CP-1 MUST-FIXes are now closed in code. Two medium-severity residuals are tracked as backlog. No critical findings.

**Deploy-blocking:** 1 (B-1: `_AUTH_AVAILABLE=False` bypass on CIEM engine `/findings`).
**Conditions to lift to PASS:** Confirm production K8s rollout has `_AUTH_AVAILABLE=True` import path (no fallback `lambda: None`); add deployment-time assertion test.

---

## 2. OWASP Top 10 2021

| # | Category | Status | Finding |
|---|---|---|---|
| A01 | Broken Access Control | PASS | `ciem:sensitive` gate fires on all 3 routes: `bff/inventory.py:771` (view_asset_ciem), `bff/inventory.py:1532` (view_inventory_ciem), `bff/ciem_identity.py:108` (view_ciem_identity). Tenant cross-check at `bff/inventory.py:800` and `bff/inventory.py:1548`. |
| A02 | Cryptographic Failures | PASS | SHA-256 used correctly for seed integrity (`load_mitre_reference.py:104-110`); raises `ValueError` on mismatch (`:125-129`) — not a warn. |
| A03 | Injection | PASS | All SQL parameterized: loader uses `execute_values` with `%s` template (`load_mitre_reference.py:233-240`); migration backfills use literal regex (`threat_mitre_technique_ref_001.sql:90-99`); endpoint uses `%(name)s` named params (`technique_detail.py:140-144`). LIKE patterns in `engines/ciem/ciem_engine/api_server.py:497-501` are parameterized. |
| A04 | Insecure Design | PASS | Sequential ownership-then-CIEM pattern preserved at `bff/inventory.py:788-810` and `:1539-1559`. Comment explicitly cites "sequential — NOT parallel" (`:756`). |
| A05 | Security Misconfiguration | PASS | Migration is BEGIN/COMMIT, format CHECK added `NOT VALID` then `VALIDATE` (good DDL hygiene, `threat_mitre_technique_ref_001.sql:130-140`). Generated STORED column documented (`threat_findings_mitre_parent_001a.sql:34-39`). |
| A06 | Vulnerable Components | N/A | No new dependencies. |
| A07 | Identification & Auth Failures | PARTIAL | Auth context sourced from `_parse_auth_context(request)` not query params on all 3 BFF routes. **However**, CIEM engine `/api/v1/ciem/findings` falls back to `"default-tenant"` when `_AUTH_AVAILABLE=False` (`engines/ciem/ciem_engine/api_server.py:469,473-477`). See B-1. |
| A08 | Software & Data Integrity | PASS | SHA-256 verification on bundled seed at startup (`api_server.py:128`) raises (does not silently fall through). Loader `main()` returns 1 on integrity failure (`load_mitre_reference.py:294-296`). |
| A09 | Logging & Monitoring | PASS | Audit logs emitted on 200 + 403 + 401 paths via dedicated `api-gateway.audit` logger; JSON-serialized; includes `timestamp`, `user_id`, `tenant_id`, `endpoint`, `target/principal`, `result`, `request_id`, `top_5_identity_arns`. Tests assert structure (`test_inventory_ciem.py:127-130`, `test_ciem_identity.py:50-54,91-92`). |
| A10 | SSRF | N/A | No outbound calls in scope. |

---

## 3. CSPM-specific

| # | Concern | Status | Finding |
|---|---|---|---|
| C-1 | Tenant isolation | PASS | Every query in scope filters on `tenant_id` from auth context, not query param. Reference table (`mitre_technique_reference`) is intentionally global, documented (`threat_mitre_technique_ref_001.sql:20`). Per-tenant filter applies to `threat_findings` joins (`technique_detail.py:78-86`). |
| C-2 | Credential leakage | PASS | No creds in audit payload. `view_ciem_identity` strips `event_raw` and `credential_ref` from forwarded findings (`ciem_identity.py:163-166`). DB connect uses env vars, never logs them (`load_mitre_reference.py:73-91`). |
| C-3 | No-bypass auth | FAIL (B-1) | `engines/ciem/ciem_engine/api_server.py:469`: `Depends(require_permission("ciem:read") if _AUTH_AVAILABLE else (lambda: None))`. If the auth import fails or is disabled, the `lambda: None` makes every CIEM API request unauthenticated and tenant becomes `"default-tenant"` (`:473-477`). |
| C-4 | Field stripping for lower roles | PASS | Sensitive fields stripped at `bff/ciem_identity.py:163-166`; permission gate handles role-based access. No data returned to viewers (403 before fetch). |

---

## 4. STRIDE on `engines/threat/threat_engine/api/technique_detail.py`

| Threat | Status | Finding |
|---|---|---|
| Spoofing | MEDIUM (R-1) | Endpoint accepts `tenant_id` as a free query param (`:107-110`) without verifying it against the caller's `X-Auth-Context`. A caller with auth to tenant A can pass tenant B and read aggregate counts for tenant B. Mitigation: counts are non-PII aggregates; reference data is global. Should resolve `tenant_id` from auth context, not Query. |
| Tampering | PASS | `affected_count` computed live via parameterized SQL on `threat_findings` with `tenant_id` filter; not user-influenced beyond tenant_id (see R-1). Format regex (`:42`) blocks SQLi attempts via `technique_id`. |
| Repudiation | LOW | New endpoint NOT audit-logged. Aggregate KPI is low-sensitivity, but request_id/user logging would aid forensics. Backlog. |
| Information Disclosure | PASS | 410 Gone payload (`:178-193`) returns only revoked/deprecated technique metadata + version + last_modified — all reference-catalog data already global. No tenant data leaked. |
| DoS | LOW | `WITH ref/exact_count/rollup_count` CTE — each touches `threat_findings` once with the new partial indexes (`threat_findings_mitre_parent_001a.sql:42-49`). At 9k OPEN findings the indexes make this ~ms-scale. No pagination needed. |
| Elevation of Privilege | MEDIUM (R-2) | Endpoint has NO permission gate and NO authentication check. Anyone reachable to the threat engine HTTP port can call `/api/v1/techniques/{id}`. Should be reachable only via gateway, but NetworkPolicy (CP-1 SHIP-GATE SG-4) is unverified. |

---

## 5. SLSA / Supply Chain (seed loader + bundled STIX)

| Check | Status | Finding |
|---|---|---|
| SHA-256 manifest verified | PASS | `load_mitre_reference.py:113-131` reads sibling `.sha256`, computes hex, **raises `ValueError` on mismatch** (line 126-129). `main()` returns exit 1 on `ValueError` (`:294-296`). Confirmed RAISE (not warn). |
| Build-time bundling, no runtime fetch | PASS | `DEFAULT_SEED_PATH = "/app/seeds/mitre_technique_reference.csv"` (`:65`) — file path inside container image. Loader is invoked at startup (`api_server.py:120`), reads from disk, no HTTP fetch in code path. |
| Image build reproducibility | PARTIAL | Loader and seed paths are pinned in `load_mitre_reference.py:65-67`. Recommend confirming Dockerfile `COPY` lines for `engines/threat/scripts/load_mitre_reference.py` and the seed CSV+`.sha256` are pinned (verified by cspm-deploy at JNY-04). |

---

## 6. CSA CCM + NIST CSF 2.0 mappings

**CSA CCM:**
- **IAM-09 (Privileged Access Risk)** — `ciem:sensitive` permission gate maps cleanly. Documented in migration 0013 (`platform/cspm-backend/user_auth/migrations/0013_ciem_sensitive_permission.py:9-12`).
- **LOG-08 (Audit Logs Protection)** — JSON-serialized audit log with required fields. Note: still emitted via `logging.getLogger("api-gateway.audit")` not durable store (CP-1 SHIP-GATE SG-2). Acceptable for Phase A; close pre-SOC2.

**NIST CSF 2.0:**
- **PR.AC (Identity Mgmt + Access Control)** — covered by `ciem:sensitive` gate + tenant cross-check.
- **DE.AE (Anomalies & Events)** — audit log captures access events with user/tenant/principal context.
- **RS (Respond)** — request_id propagation supports incident correlation.

---

## 7. Blocking findings (Critical/High)

### B-1 (HIGH) — CIEM engine auth-bypass fallback
**File:** `engines/ciem/ciem_engine/api_server.py:47-49, 469, 473-477`
**Issue:** `_AUTH_AVAILABLE = False` branch (when `engine_auth` import fails) replaces the FastAPI permission dependency with `lambda: None`, then `tenant_id` defaults to `"default-tenant"`. In that state, every CIEM `/findings` request is unauthenticated and reads cross-tenant data via the literal string `"default-tenant"`.
**Why blocking now:** Phase A introduces a journey that surfaces CIEM data through the BFF. The BFF gate at `bff/inventory.py:771` is sound, but if any internal caller (or sidecar test pod) hits the engine directly, the bypass fires.
**Fix:** Either (a) raise on `_AUTH_AVAILABLE=False` at engine startup (fail-closed), or (b) replace `lambda: None` with a stub returning 401/503. Add a deploy-time smoke test that asserts an unauthenticated request to `/api/v1/ciem/findings` returns 401, not 200.
**Owner:** ciem-engine.

---

## 8. Non-blocking findings (Medium/Low) — backlog

### R-1 (MEDIUM) — `technique_detail.py` accepts tenant_id from query param
**File:** `engines/threat/threat_engine/api/technique_detail.py:107-110, 140-144`
**Issue:** `tenant_id` is a Query parameter, not derived from `X-Auth-Context`. Caller can pass any tenant UUID and read aggregate finding counts for that tenant.
**Recommendation:** Resolve via `_parse_auth_context` and reject query-param overrides. Pair with R-2.
**Spin-off:** `STORY-SEC-TECHNIQUE-DETAIL-AUTH`.

### R-2 (MEDIUM) — `technique_detail.py` has no auth/permission check
**File:** `engines/threat/threat_engine/api/technique_detail.py:104-111`
**Issue:** No `Depends(require_permission(...))` on the new route. Reachable to anyone with network access to the threat engine pod.
**Recommendation:** Add `Depends(require_permission("threats:read"))`. Combine with R-1 spin-off.

### R-3 (LOW) — `technique_detail.py` not audit-logged
No audit log on the new endpoint. Add a single structured INFO line on every call.

### R-4 (LOW) — `view_inventory_ciem` audit log not JSON-serialized
**File:** `shared/api_gateway/bff/inventory.py:1574-1583`
**Issue:** Older audit code uses `logger.info(..., extra={...})` — relies on log handler to format `extra`. The newer `_jny03_emit_ciem_audit` JSON-serializes inline. Inconsistency makes log ingestion brittle.
**Recommendation:** Migrate `view_inventory_ciem` to use `_jny03_emit_ciem_audit`.

### R-5 (LOW) — `_emit_audit` logs result=200 on engine fetch failure
**File:** `shared/api_gateway/bff/ciem_identity.py:142-149`
**Recommendation:** Add `engine_status` field to distinguish degraded responses.

---

## 9. CP-1 → CP-A delta — MUST-FIX status

| ID | Description | Status | Evidence |
|---|---|---|---|
| MF-1 | Bundled STIX with SHA-256 manifest, no runtime fetch | CLOSED | `load_mitre_reference.py:65,113-131,294-296`; SHA-256 raises on mismatch, returns 1. |
| MF-2 | Format CHECK before any seed insert | CLOSED | `threat_mitre_technique_ref_001.sql:130-140`; `NOT VALID` then `VALIDATE`. Same regex enforced at `technique_detail.py:42`. |
| MF-3 | `ciem:sensitive` gate + audit on `view_ciem_identity` | CLOSED | `bff/ciem_identity.py:108-116` (gate); `:101-106, :109-112, :168-172` (audit on 401/403/200). |
| MF-4 | Audit log on `view_asset_ciem` w/ top-5 identity_arns + result + request_id | CLOSED | `bff/inventory.py:709-750` (helper); `:772-775, :795-798, :801-804, :893-897` (call sites). Tests assert payload (`test_inventory_ciem.py:127-130, 169-176`). |
| MF-5 | Story doc reconciled to 4 roles | CLOSED | Migration 0013 grants `ciem:sensitive` to analyst/tenant_admin/org_admin/platform_admin (`0013_ciem_sensitive_permission.py:29-34`). |

**All 5 MF closed.** No regressions introduced.

---

## 10. MUST-VERIFY status (informational)

| ID | Status |
|---|---|
| MV-1 (table size pre-flight) | Per CP-1: 102 rows verified — no JNY-01a split required. |
| MV-2 (CIEM `/findings` reads tenant from auth) | Verified PARTIAL. When `_AUTH_AVAILABLE=True`: tenant_id sourced from `auth.engine_tenant_id`. When False: defaults to `"default-tenant"` (B-1). |
| MV-3 (test_inventory_ciem covers viewer-403, cross-tenant-403, audit) | Verified. Tests at `test_inventory_ciem.py:71-103, 110-176`. |
| MV-4 (migration BEGIN/COMMIT + rollback path) | Verified. Both migrations wrap in BEGIN/COMMIT; rollback documented. |

---

## Final line

**CP-A security review: PASS-WITH-CONDITIONS. Blocking findings: 1. CP-1 MUST-FIX status: [MF-1..5 all closed]. Top residual: CIEM engine `_AUTH_AVAILABLE=False` fallback exposes `default-tenant` data unauthenticated.**
