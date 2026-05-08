# Story: Auth-B2 — Google OAuth hd Validation + FRONTEND_URL Allowlist + Session Hardening

## Status: ready

## Context

`GoogleCallbackView` performs an OAuth code exchange with Google but does NOT validate the
`hd` (hosted domain) parameter after receiving the profile. An attacker who can intercept
or forge the OAuth callback can supply a token for a different Google Workspace domain than
what was requested, bypassing domain-restricted SSO (BLOCK-03, ATT&CK T1078.004).

The `FRONTEND_URL` setting is used to build redirect URLs after OAuth callbacks. If it is
not validated against an allowlist at startup, an SSRF or open-redirect could redirect
users to attacker-controlled domains.

Additionally this story closes several WARN items that harden the session infrastructure:
- `UserSessions.token_hint` is declared `db_index=False` (line 81 of `models.py`) — adding
  an index enables fast pre-filter before the expensive PBKDF2 verify loop (WARN-01).
- `RefreshTokenView` has no rate limit (WARN-02).
- `onboarding_pending` cookie is currently not httponly (WARN-04).
- `ACCESS_TOKEN_LIFETIME_MINUTES` defaults to 60 (WARN-06); should be 15.

**Points:** Small–Medium (< 1 day to 1 day). Backend-only changes, no new DB tables.
One Django model field flag change (triggers migration for index), settings changes,
one view update.

**Dependencies:** None. Can run in parallel with Sprint A.

---

## Security Framework Tags

**OWASP SAMM Function**
- [ ] Governance  [ ] Design  [x] Implementation  [x] Verification  [ ] Operations

**NIST CSF 2.0 Function(s)**
- [ ] GV Govern  [ ] ID Identify  [x] PR Protect  [x] DE Detect  [ ] RS Respond  [ ] RC Recover

**CSA CCM v4 Domain(s)**
- CCM: IAM-01 (Identity and Access Management Policy), IAM-09 (User Access Reviews),
  IVS-06 (Network Security — redirect allowlist)

---

## Threat Model

### STRIDE

| Threat | Component | Attack Scenario | Mitigation |
|--------|-----------|-----------------|------------|
| Spoofing | `GoogleCallbackView` | Attacker obtains Google token for `evil.com` domain, presents it to callback for `acme.com`-restricted SSO config → gains access | Validate `profile["email"].split("@")[1] == requested_hd` after code exchange |
| Spoofing | `FRONTEND_URL` redirect | Open redirect: attacker crafts callback URL with `next=https://evil.com` → after OAuth, user is redirected to attacker site | Validate final redirect URL host against `settings.ALLOWED_REDIRECT_HOSTS` allowlist |
| Info Disclosure | `onboarding_pending` cookie | Cookie lacks `httponly` flag — JavaScript can read and exfiltrate it | Set `httponly=True` on cookie |
| DoS | `RefreshTokenView` no rate limit | Attacker hammers `/api/auth/refresh/` to exhaust server-side PBKDF2 compute | Add `RefreshRateThrottle` at 60/hour per IP |
| Info Disclosure | Session lookup O(n) scan | Large `user_sessions` table → verify_token called for every row → timing leak and slow response | `token_hint` index + pre-filter reduces verify_token calls to ~1 per request |

### PASTA

| Stage | Adversary Goal | Attack Path | Countermeasure |
|-------|---------------|-------------|----------------|
| Domain bypass | Authenticate as @acme.com user using @evil.com Google account | Complete OAuth flow with evil.com token, callback validates only that token is valid Google token (not that domain matches) | Post-exchange: `assert profile["email"].endswith("@" + requested_hd)` |
| SSRF via redirect | Redirect OAuth callback to internal metadata service | FRONTEND_URL misconfigured to point to `http://169.254.169.254/` | ALLOWED_REDIRECT_HOSTS allowlist checked at startup via AppConfig.ready() |

---

## MITRE ATT&CK Techniques Addressed

| Technique ID | Name | D3FEND Countermeasure | How this story addresses it |
|-------------|------|----------------------|----------------------------|
| T1078.004 | Valid Accounts: Cloud (OAuth domain bypass) | D3-MFA Multi-Factor Auth, D3-UBA User Behavior Analytics | `hd` parameter validated post-exchange |
| T1190 | Exploit Public-Facing Application (open redirect) | D3-FAPA Filter Application Policy | FRONTEND_URL allowlist at startup |
| T1110 | Brute Force (refresh token flooding) | D3-RPL Rate-Based Prevention Logic | 60/hour throttle on RefreshTokenView |

---

## Acceptance Criteria (Functional)

1. `GoogleCallbackView`: after the OAuth code exchange, if the original authorization
   request included an `hd` parameter (stored in the OAuth `state`), validate that
   `profile["email"].split("@")[1] == requested_hd`. If mismatch: redirect to
   `{FRONTEND_URL}/auth/login?error=domain_mismatch`. Do NOT create a session.
2. `GoogleCallbackView`: if no `hd` was requested (open Google OAuth), the domain check is
   skipped.
3. Django `AppConfig.ready()` in `user_auth/apps.py`: validate `settings.FRONTEND_URL`
   host against `settings.ALLOWED_REDIRECT_HOSTS` (a list of allowed hostnames, e.g.
   `["localhost", "app.cspm.local", "cspm.example.com"]`). Raise
   `django.core.exceptions.ImproperlyConfigured` if not in allowlist. This prevents
   misconfiguration from shipping to production.
4. `settings.py`: add `ALLOWED_REDIRECT_HOSTS = os.getenv("ALLOWED_REDIRECT_HOSTS", "localhost").split(",")`.
5. `onboarding_pending` cookie (wherever it is set in the OAuth callback views): add
   `httponly=True` parameter (WARN-04).
6. `RefreshTokenView`: add `throttle_classes = [RefreshRateThrottle]` where
   `RefreshRateThrottle` is `AnonRateThrottle` subclass with `rate = "60/hour"` (WARN-02).
7. `UserSessions.token_hint` field in `models.py`: change `db_index=False` to
   `db_index=True` (line 81). Create the corresponding migration.
8. `MeView._resolve_user_and_session()` (and any equivalent session lookup in
   `ChangePasswordView`, `UserListView`, `TenantIDPConfigDetailView._get_config`): use
   `token_hint` as a pre-filter before iterating and calling `verify_token()`. Specifically:
   ```python
   hint = access_token[:8]
   sessions = UserSessions.objects.filter(
       revoked=False, token_hint=hint
   ).select_related('user')
   ```
   The PBKDF2 `verify_token()` call then runs on at most ~1 row instead of all sessions.
9. `settings.py`: `ACCESS_TOKEN_LIFETIME_MINUTES` default value changed from `60` to `15`
   (WARN-06). The `REFRESH_TOKEN_LIFETIME_DAYS` default is NOT changed.
10. The `expiresIn` field returned by `LoginView` and `RefreshTokenView` must reflect the
    new 15-minute value when `ACCESS_TOKEN_LIFETIME_MINUTES` is 15.

---

## Acceptance Criteria (Security — must pass bmad-security-reviewer)

- [ ] `hd` parameter is read from the OAuth `state` object, not from the user-supplied `profile` Google response — the profile `hd` field can be spoofed in some configurations.
- [ ] `domain_mismatch` redirect does not include the attacker's email in the query string.
- [ ] `ALLOWED_REDIRECT_HOSTS` check is in `AppConfig.ready()`, not in the view — prevents the view from being called before the check runs.
- [ ] `token_hint` index migration does not contain `db_index=False` — confirmed by migration SQL output.
- [ ] `onboarding_pending` cookie `httponly=True` confirmed by grepping all `response.set_cookie` calls for this cookie name.
- [ ] `RefreshRateThrottle` uses `scope = "refresh"` distinct from `signup` and `login` scopes.
- [ ] `ACCESS_TOKEN_LIFETIME_MINUTES = 15` is documented in a comment: "# Changed from 60 to 15 per WARN-06".
- [ ] No plaintext credentials in logs.
- [ ] No `latest` image tag if Django image is rebuilt for the migration.
- [ ] BLOCK-03 and WARN-01, WARN-02, WARN-04, WARN-06 marked closed.

---

## Technical Notes

### Files to change

**`platform/cspm-backend/user_auth/models.py`** — line 81:
```python
# Before:
token_hint = models.CharField(max_length=8, null=True, blank=True, db_index=False)
# After:
token_hint = models.CharField(max_length=8, null=True, blank=True, db_index=True)
```
This requires a new migration: `python manage.py makemigrations user_auth --name add_token_hint_index`.

**`platform/cspm-backend/user_auth/views/local_auth.py`** — `MeView._resolve_user_and_session()`:

Current (line 362–368):
```python
sessions = UserSessions.objects.filter(revoked=False).select_related('user')
for session in sessions:
    if session.expires_at < timezone.now():
        continue
    if verify_token(access_token, session.token):
        return session.user, session
```

Replace with:
```python
hint = access_token[:8] if access_token else ""
sessions = UserSessions.objects.filter(
    revoked=False, token_hint=hint
).select_related('user')
for session in sessions:
    if session.expires_at < timezone.now():
        continue
    if verify_token(access_token, session.token):
        return session.user, session
```

Apply the same `token_hint` pre-filter pattern to `ChangePasswordView`, `UserListView`,
`RefreshTokenView`, and `_resolve_request_user()` in `tenant_management/views.py`.

**Google OAuth callback view** — locate via:
```bash
find /Users/apple/Desktop/threat-engine/platform/cspm-backend -name "google_auth.py" -o -name "google*.py" | head -5
```

Add after `profile` is fetched:
```python
# Validate hd (hosted domain) if it was included in the auth request
requested_hd = state_data.get("hd")  # or however hd is stored in state
if requested_hd:
    email_domain = profile.get("email", "").split("@")[-1]
    if email_domain != requested_hd:
        return redirect(f"{settings.FRONTEND_URL}/auth/login?error=domain_mismatch")
```

**`platform/cspm-backend/cspm_backend/settings.py`**:
```python
ALLOWED_REDIRECT_HOSTS = os.getenv("ALLOWED_REDIRECT_HOSTS", "localhost").split(",")
ACCESS_TOKEN_LIFETIME_MINUTES = int(os.getenv("ACCESS_TOKEN_LIFETIME_MINUTES", "15"))  # was 60
```

**`platform/cspm-backend/user_auth/apps.py`** — add `ready()` check:
```python
def ready(self):
    from django.conf import settings
    from django.core.exceptions import ImproperlyConfigured
    from urllib.parse import urlparse
    frontend_host = urlparse(settings.FRONTEND_URL).hostname
    allowed = [h.strip() for h in settings.ALLOWED_REDIRECT_HOSTS]
    if frontend_host not in allowed:
        raise ImproperlyConfigured(
            f"FRONTEND_URL host '{frontend_host}' not in ALLOWED_REDIRECT_HOSTS={allowed}"
        )
```

---

## Key Files

- `/Users/apple/Desktop/threat-engine/platform/cspm-backend/user_auth/models.py` (line 81)
- `/Users/apple/Desktop/threat-engine/platform/cspm-backend/user_auth/views/local_auth.py` (MeView._resolve_user_and_session, RefreshTokenView)
- `/Users/apple/Desktop/threat-engine/platform/cspm-backend/user_auth/apps.py` — add ready() check
- `/Users/apple/Desktop/threat-engine/platform/cspm-backend/cspm_backend/settings.py`
- Google OAuth callback view (grep for `GoogleCallbackView`)

---

## Definition of Done

- [ ] Test: `test_google_oauth_hd_mismatch_rejected` — profile domain != state hd → redirect with domain_mismatch
- [ ] Test: `test_google_oauth_no_hd_passes` — no hd in state → no domain check performed
- [ ] Test: `test_allowed_redirect_hosts_startup_check` — wrong FRONTEND_URL host → ImproperlyConfigured
- [ ] Test: `test_token_hint_prefilter` — session lookup queries only rows matching token_hint
- [ ] Test: `test_refresh_rate_limit_429` — 61st refresh in an hour returns 429
- [ ] Migration for `token_hint` index created and applied
- [ ] bmad-security-reviewer: no BLOCKERS
- [ ] BLOCK-03 and WARN-01, WARN-02, WARN-04, WARN-06 marked closed
