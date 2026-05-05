# CP-B — Security Review (Phase B pre-deploy)

**Reviewer:** cspm-security-reviewer + bmad-security-reviewer
**Verdict:** **PASS-WITH-CONDITIONS — 0 Blocking, 4 Non-blocking**
**Date:** 2026-05-05

## OWASP Top 10 2021

| ID | Risk | Status | Evidence |
|----|------|--------|----------|
| A01 Access Control | PASS | `<engine>:read` per-engine via `require_permission(cfg["perm"])` (finding_detail.py:483, 610). Cross-tenant probe → 404 not 403. Tenant from auth context only. |
| A02 Crypto | PASS | No secrets in payload; `credential_ref/type` excluded via `Field(exclude=True)` + B3 denylist. |
| A03 Injection | PASS | All SQL parameterized; table names hard-coded in ENGINE_MAP. ID regex enforced server + client. |
| A04 Insecure Design | PASS | Sequence: validate engine → permission check → resolve tenant → DB. |
| A05 Misconfig | PASS | Pydantic Literal types throughout. |
| A07 AuthN | PASS-W-COND | ImportError fallback raises 401. NB-1: add startup assertion. |
| A09 Logging | PASS-W-COND | Audit log via `api-gateway.audit`. NB-2: `old_status=None` — capture prior state. |
| A10 SSRF | N/A | No outbound HTTP. |

## STRIDE on GET + PATCH endpoints

| Threat | Status | Evidence |
|--------|--------|----------|
| Spoofing | PASS | tenant from X-Auth-Context only. |
| Tampering (response) | PASS | model_validator walks full dict, rejects credential/secret/raw_event keys. EngineExtensions denylist blocks __proto__/constructor. |
| Tampering (request) | PASS-W-COND | StatusUpdateRequest.status Literal-restricted. NB-3: `note` lacks max_length. |
| Repudiation | PASS | Centralized audit via `api-gateway.audit` named logger. |
| Info Disclosure | PASS | 404≠403 prevents enumeration; restrictedEngines lists slugs only. |
| DoS | PASS-W-COND | Tab-3 fan-out 0.8s timeout; TTL caches 4096/300s. NB-4: rate limit. |
| EoP | PASS | PATCH passes <engine>:read; per-engine perm prevents cross-engine mutation. |

## CP-2 closure verification (security-critical)

| CP-2 | Closed? | Evidence |
|------|---------|----------|
| **B1** long-slug taxonomy | ✅ | EngineSlug Literal agrees in `_schemas.py:16-28` and `_finding_engine_map.py:32-44`; `layout.jsx:5-17` whitelist matches. |
| **B2** PATCH no longer bypasses BFF | ✅ | `FindingHeaderCard.jsx:73` calls `/api/v1/views/finding/${engine}/${id}/status`; centralized audit at `finding_detail.py:627`. |
| **B3** Pydantic credential denylist | ✅ | `_schemas.py:174-190` — `_walk_keys` + `_SENSITIVE_KEY_RE` regex. Active defense-in-depth. |
| **C2** Tab 3 perm filter w/ restrictedEngines | ✅ | `_partition_engines_by_permission` returns (permitted, restricted) by slug only. |
| **C6** engineExtensions denylist | ✅ | `_schemas.py:138-155` — rejects `__proto__`, `constructor`, `prototype`. |

## Frontend XSS / SLSA

- No `dangerouslySetInnerHTML` anywhere in `components/finding/*.jsx`
- RemediationTab `renderMarkdown` builds React text nodes only — auto-escaped
- All URL params via `encodeURIComponent` (pivot-routes.js, FindingHeaderCard.jsx)
- Tooltip text via `{}` interpolation only
- Telemetry: local CustomEvent, no network sink
- No new dependencies (pip or npm)

## Blocking findings

**None.**

## Non-blocking findings (Phase B follow-up tickets)

| # | Issue | Location | Recommendation |
|---|---|---|---|
| NB-1 | Engine_auth import fallback silent in prod | `finding_detail.py:42-47` | Add startup assertion |
| NB-2 | PATCH audit log missing `old_status` | `finding_detail.py:627-643` | SELECT FOR UPDATE in same txn |
| NB-3 | `StatusUpdateRequest.note` no `max_length` | `_schemas.py` | Add `Field(max_length=2000)` |
| NB-4 | Gateway middleware rate limit on PATCH unverified | n/a | Confirm config exists |

## Verdict

**PASS-WITH-CONDITIONS — 0 blocking. May proceed to deploy after code + QA gates.**
Top residual: PATCH audit log lacks old_status (NB-2 — track in next sprint).
