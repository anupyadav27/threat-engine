# Security Review — Auth & Onboarding Sprint

**Date:** 2026-05-03  
**Frameworks:** STRIDE, OWASP SAMM, MITRE ATT&CK for Cloud, D3FEND, NIST CSF 2.0

---

## 12 Blocking Controls (Must ship before launch)

| # | Story | Acceptance Criterion | ATT&CK |
|---|-------|---------------------|--------|
| **BLOCK-01** | SignupView | On duplicate email return HTTP 200 "If an account exists, a verification email will be sent." Never return 409 with email existence information. | T1589.002 |
| **BLOCK-02** | SignupView | Add `AnonRateThrottle` (10/hour per IP). Add CAPTCHA on frontend. Move `_sync_tenant_to_onboarding` out of `transaction.atomic()`. | T1136.003 |
| **BLOCK-03** | GoogleCallbackView | After code exchange, validate `profile["email"].split("@")[1] == requested_hd`. Validate `FRONTEND_URL` against `settings.ALLOWED_REDIRECT_HOSTS` at startup. | T1078.004 |
| **BLOCK-04** | Agent bootstrap | Add `require_permission("cloud_accounts:write")` (X-Auth-Context) to `POST /{account_id}/agent-token`. Change SHA-256 to `make_password()` for token hash. | T1528 |
| **BLOCK-05** | Onboarding engine auth | Apply platform auth middleware (X-Auth-Context) to all onboarding engine endpoints. Gate `POST /credentials`, `PATCH /{account_id}`, `POST /agent-token` behind permissions. | T1190 |
| **BLOCK-06** | PATCH cloud account | Replace `updates: dict` with explicit Pydantic `CloudAccountUpdate` model (allow-list of patchable fields). Add tenant ownership check before update. | T1190 |
| **BLOCK-07** | Tenant scoping | Remove `user_has_developer_role` bypass in `build_tenant_query`. Scope `org_admin` to their own `org_id`. Block until `Organization` model exists. | T1078 |
| **BLOCK-08** | TenantViewSet auth | Add `permission_classes = [CookieIsAuthenticated, HasPermission("tenants:read")]`. Implement `CookieTokenAuthentication` DRF backend. | T1190 |
| **BLOCK-09** | Export endpoint | Add explicit `id__in=user_tenant_ids` filter to export action, independent of `get_queryset()`. | T1078 |
| **BLOCK-10** | IDP domain lookup | Rate-limit `GET /tenants/idp-by-domain/` to 5 req/min per IP. Remove `tenant_id` from unauthenticated response — return only `idp_type` and `redirect_url`. | T1589 |
| **BLOCK-11** | org_admin org-boundary | All `org_admin` writes must include `WHERE tenant.org_id = request_user.org_id`. Do not ship write permissions until `Organization` model + boundary check is live. | T1078 |
| **BLOCK-12** | Async tenant sync | Celery task `sync_tenant_to_onboarding.apply_async(...)` outside `transaction.atomic()`. Dead-letter handler sets `tenant.status='sync_failed'` + alerts platform_admin. Add `POST /api/v1/tenants/{id}/resync` admin endpoint. | T1499 |

---

## 8 Warning Controls (Non-blocking, ship within sprint)

| # | Area | Action |
|---|------|--------|
| WARN-01 | Session token lookup | Use `token_hint` as DB pre-filter before PBKDF2. Add `db_index=True` to `UserSessions.token_hint`. |
| WARN-02 | Refresh rate limit | Add 60/hour per-IP rate limit to `RefreshTokenView`. |
| WARN-03 | Audit trail | `log_auth_event("signup.local")` in SignupView; `log_auth_event("agent_token.issued")` in issue_agent_token. |
| WARN-04 | `onboarding_pending` cookie | Change `httponly=True`. Use Redis short-lived flag instead. |
| WARN-05 | Internal engine auth | Add signed HMAC token or mTLS for engine-to-engine calls (billing, onboarding sync). |
| WARN-06 | Access token lifetime | Reduce `ACCESS_TOKEN_LIFETIME_MINUTES` from 60 to 15. |
| WARN-07 | Email verification | Add email verification step before auto-provisioning first tenant. |
| WARN-08 | Org slug squatting | Reserved slug list (admin, api, www, app, etc.). Rate-limit org creation to 3/day per IP. |

---

## Agent Bootstrap Token Design

**Current:** `secrets.token_urlsafe(32)` → SHA-256 hash, 15-min TTL, stored in `agent_registrations`.

**Minimum fix:** Replace SHA-256 with `make_password()` (PBKDF2 with salt). One-line change.

**Recommended (PKCE-like):**
1. UI generates `code_verifier = secrets.token_urlsafe(32)` locally
2. UI sends `code_challenge = SHA-256(code_verifier)` to `POST /agent-token` — server stores `code_challenge_hash`
3. Install command: `install.sh --registration-id {registration_id} --verifier {code_verifier}`
4. At bootstrap: agent sends `registration_id` + `code_verifier`. Server verifies `SHA-256(code_verifier) == code_challenge_hash`

No raw token ever appears in a URL, process listing, or shell history.

---

## org_admin Elevation Risks

| Path | Risk | Mitigation |
|------|------|-----------|
| Invite-based cross-org expansion | org_admin accepts invite to foreign org's tenant → gains `users:write` on foreign tenant | Org-boundary check on invite acceptance |
| `users:write` without boundary | Can add arbitrary users to any joined tenant | Enforce `tenant.org_id = user.org_id` on all writes |
| `rules:write` global scope | Rules are platform-wide; org_admin could disable rules affecting all tenants | Scope rule writes to org-owned rules; global rules = platform_admin only |
| No path to platform_admin | Cannot self-escalate — UserRoles assignment is invite-controlled | Low risk |

---

## MITRE ATT&CK → D3FEND Top 5

| ATT&CK | Technique | D3FEND Countermeasure | CSF 2.0 |
|--------|-----------|----------------------|---------|
| T1136.003 | Create Cloud Account (mass org creation) | D3-UAA User Account Auth + D3-ACH Account Creation Hardening | PR.AC |
| T1078.004 | Valid Accounts: Cloud | D3-MFA Multi-Factor Auth (missing); D3-UBA User Behavior Analytics | PR.AC / DE.CM |
| T1528 | Steal App Access Token (bootstrap in shell pipe) | D3-CNA Credential Hardening — PKCE token design | PR.DS |
| T1190 | Exploit Public-Facing App (onboarding unauthenticated) | D3-FAPA Filter Application Policy + D3-OAM Object Access Monitoring | PR.AC / DE.CM |
| T1071.001 | Web Protocol C2 (SSRF via ONBOARDING_ENGINE_URL) | D3-NTF Network Traffic Filtering (K8s NetworkPolicy) | PR.PT |

---

## NIST CSF 2.0 Gaps

| Function | Gap |
|---------|-----|
| PR.AC | DRF auth disabled; onboarding engine unauthenticated; no MFA; no org-boundary on org_admin |
| PR.DS | Bootstrap token in CLI argument; SHA-256 instead of PBKDF2 |
| DE.CM | No audit on signup; no audit on agent token issuance; no anomaly detection on scans:create rate |
| RC | No dead-letter for tenant sync failure; no agent re-registration flow; no broken-state recovery |

**RC Recovery Stories required:**
- RS-01: Dead-letter queue handler → `tenant.status='sync_failed'` + alert
- RS-02: `POST /api/v1/tenants/{id}/resync` admin endpoint
- RS-03: Agent re-registration — `POST /{account_id}/agent-token` invalidates previous `issued` token atomically
