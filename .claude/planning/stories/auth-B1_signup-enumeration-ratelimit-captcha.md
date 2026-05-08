# Story: Auth-B1 — Signup Email Enumeration Fix + Rate Limiting + CAPTCHA

## Status: ready

## Context

`SignupView.post()` at line 243–244 in `local_auth.py` currently returns HTTP 409 with the
message `"An account with this email already exists."` This leaks email existence to an
unauthenticated attacker and enables user enumeration (BLOCK-01, ATT&CK T1589.002). The
fix is a one-line change: return HTTP 200 with a generic message.

`SignupView` and `PasswordResetRequestView` have no rate limiting — an attacker can
attempt unlimited signups per IP to perform account enumeration at scale or spam the
email system (BLOCK-02). `LoginView` similarly has no rate limit.

The frontend signup page has no CAPTCHA, making automated account creation trivial.

This story closes BLOCK-01 and BLOCK-02 from SECURITY-REVIEW-AUTH-SPRINT.md.

**Points:** Small (< 1 day). Two backend view changes, two DRF throttle class additions,
one frontend component addition.

**Dependencies:** None. Can run in parallel with Sprint A after A-1 merges.

---

## Security Framework Tags

**OWASP SAMM Function**
- [ ] Governance  [ ] Design  [x] Implementation  [x] Verification  [ ] Operations

**NIST CSF 2.0 Function(s)**
- [ ] GV Govern  [ ] ID Identify  [x] PR Protect  [x] DE Detect  [ ] RS Respond  [ ] RC Recover

**CSA CCM v4 Domain(s)**
- CCM: IAM-01 (Identity and Access Management Policy), IAM-03 (User Access Restriction),
  TVM-01 (Threat and Vulnerability Management — enumeration risk)

---

## Threat Model

### STRIDE

| Threat | Component | Attack Scenario | Mitigation |
|--------|-----------|-----------------|------------|
| Info Disclosure | `SignupView` duplicate email response | Attacker sends POST /api/auth/signup/ with known email, receives 409 confirming account exists | Return HTTP 200 generic message regardless of duplicate status |
| DoS | `SignupView` no rate limit | Script sends 10k signup attempts/hour per IP to exhaust email sending quota | `AnonRateThrottle(10/hour)` per IP on SignupView |
| DoS | `LoginView` no rate limit | Credential stuffing: attacker sends password spray across user list | `AnonRateThrottle(20/hour)` per IP on LoginView |
| Spoofing | CAPTCHA bypass | Automated bot completes signup flow without CAPTCHA | hCaptcha widget on frontend; server-side verify before creating user |
| Info Disclosure | `PasswordResetRequestView` email enumeration | POST with known email returns different response than unknown email | Generic response regardless of whether email exists |

### PASTA

| Stage | Adversary Goal | Attack Path | Countermeasure |
|-------|---------------|-------------|----------------|
| Reconnaissance | Build list of registered emails | POST /api/auth/signup/ with candidate emails; 409 = registered, 201 = new | All responses normalized to HTTP 200 generic message |
| Account creation flood | Create 1000s of trial accounts for abuse | Bot script hits /api/auth/signup/ — no rate limit, no CAPTCHA | 10/hour/IP throttle + hCaptcha |

---

## MITRE ATT&CK Techniques Addressed

| Technique ID | Name | D3FEND Countermeasure | How this story addresses it |
|-------------|------|----------------------|----------------------------|
| T1589.002 | Gather Victim Identity Info: Email Addresses | D3-OAM Object Access Monitoring | Remove 409 response that leaks email existence |
| T1136.003 | Create Cloud Account | D3-ACH Account Creation Hardening | Rate limit + CAPTCHA prevent automated org creation |
| T1110 | Brute Force | D3-RPL Rate-Based Prevention Logic | 20/hour rate limit on LoginView |

---

## Acceptance Criteria (Functional)

1. `SignupView.post()`: when `Users.objects.filter(email=email).exists()` is True, the view returns HTTP **200** with body `{"message": "If an account exists with this email, a verification email will be sent."}`. It must NOT return 409, must NOT create a new user, and must NOT call `provision_org_and_tenant()`.
2. `SignupView` has `throttle_classes = [SignupRateThrottle]` applied. `SignupRateThrottle` is an `AnonRateThrottle` subclass with `rate = "10/hour"`.
3. `LoginView` has `throttle_classes = [LoginRateThrottle]` applied. `LoginRateThrottle` is an `AnonRateThrottle` subclass with `rate = "20/hour"`.
4. If `PasswordResetRequestView` exists in the codebase, it also gets `throttle_classes = [SignupRateThrottle]` (same 10/hour rate).
5. When `NEXT_PUBLIC_HCAPTCHA_SITE_KEY` env var is set in the frontend, the signup page (`frontend/src/app/auth/signup/page.jsx` or equivalent) renders the hCaptcha widget from `@hcaptcha/react-hcaptcha`.
6. `SignupView.post()` verifies the hCaptcha token server-side before any user creation: POST to `https://hcaptcha.com/siteverify` with `secret=settings.HCAPTCHA_SECRET_KEY` and `response=data.get("hcaptcha_token")`. On failure return HTTP 400 `{"message": "CAPTCHA verification failed."}`.
7. When `HCAPTCHA_SECRET_KEY` is not set (local dev), CAPTCHA verification is skipped with a `logger.warning("CAPTCHA disabled — set HCAPTCHA_SECRET_KEY in production")`.
8. Rate-limited responses return HTTP 429 with `Retry-After` header set by DRF throttle.
9. `log_auth_event("signup.attempt.rate_limited")` is emitted when a request hits the throttle (override `throttle_failure_handler` or use DRF signal).

---

## Acceptance Criteria (Security — must pass bmad-security-reviewer)

- [ ] `SignupView` duplicate email path: response body identical for duplicate and new email (no timing oracle) — sleep is NOT added (constant-time check via ORM `exists()` is acceptable; the goal is identical HTTP response, not microsecond timing).
- [ ] HTTP status 200 (not 201 and not 409) on duplicate email path — confirmed by test.
- [ ] hCaptcha secret key sourced from `settings.HCAPTCHA_SECRET_KEY` (env var `HCAPTCHA_SECRET_KEY`) — never hardcoded or committed.
- [ ] hCaptcha verification uses `https://hcaptcha.com/siteverify` — not an internal proxy URL that could be tampered with.
- [ ] Rate throttle keys are IP-based (`REMOTE_ADDR`) — no user-identifier-based bypass possible before authentication.
- [ ] No plaintext credentials in logs.
- [ ] HCAPTCHA_SECRET_KEY is documented as a required production secret in `SECRETS-CREDENTIALS.md` (add inline note, not a new file).
- [ ] No `latest` image tag if a Django image rebuild is required.

---

## Technical Notes

### Backend — email enumeration fix

File: `/Users/apple/Desktop/threat-engine/platform/cspm-backend/user_auth/views/local_auth.py`

Current lines 243–244:
```python
if Users.objects.filter(email=email).exists():
    return JsonResponse({"message": "An account with this email already exists."}, status=409)
```

Replace with:
```python
if Users.objects.filter(email=email).exists():
    return JsonResponse(
        {"message": "If an account exists with this email, a verification email will be sent."},
        status=200,
    )
```

### Backend — DRF throttle classes

New file: `platform/cspm-backend/user_auth/throttles.py`
```python
from rest_framework.throttling import AnonRateThrottle

class SignupRateThrottle(AnonRateThrottle):
    scope = "signup"
    rate = "10/hour"

class LoginRateThrottle(AnonRateThrottle):
    scope = "login"
    rate = "20/hour"
```

Add to `settings.py` `REST_FRAMEWORK`:
```python
"DEFAULT_THROTTLE_CLASSES": [],  # per-view throttles only
"DEFAULT_THROTTLE_RATES": {
    "signup": "10/hour",
    "login": "20/hour",
},
```

Apply in views:
```python
# SignupView
throttle_classes = [SignupRateThrottle]

# LoginView
throttle_classes = [LoginRateThrottle]
```

Note: `LoginView` and `SignupView` inherit from `rest_framework.views.APIView` — DRF
throttles are natively supported.

### Backend — hCaptcha verification

```python
import httpx

def _verify_hcaptcha(token: str) -> bool:
    secret = getattr(settings, "HCAPTCHA_SECRET_KEY", None)
    if not secret:
        logger.warning("CAPTCHA disabled — set HCAPTCHA_SECRET_KEY in production")
        return True
    try:
        resp = httpx.post(
            "https://hcaptcha.com/siteverify",
            data={"secret": secret, "response": token},
            timeout=5.0,
        )
        return resp.json().get("success", False)
    except Exception:
        return False  # fail closed
```

Call in `SignupView.post()` before user creation:
```python
if not _verify_hcaptcha(data.get("hcaptcha_token", "")):
    return JsonResponse({"message": "CAPTCHA verification failed."}, status=400)
```

### Frontend — hCaptcha widget

Install: `npm install @hcaptcha/react-hcaptcha`

In `frontend/src/app/auth/signup/page.jsx` (or `.tsx`):
```jsx
import HCaptcha from "@hcaptcha/react-hcaptcha";
// Add to form state: const [captchaToken, setCaptchaToken] = useState(null);
// Render: <HCaptcha sitekey={process.env.NEXT_PUBLIC_HCAPTCHA_SITE_KEY} onVerify={setCaptchaToken} />
// Include captchaToken in POST body as hcaptcha_token
```

Render the widget only when `NEXT_PUBLIC_HCAPTCHA_SITE_KEY` is defined:
```jsx
{process.env.NEXT_PUBLIC_HCAPTCHA_SITE_KEY && (
  <HCaptcha sitekey={process.env.NEXT_PUBLIC_HCAPTCHA_SITE_KEY} onVerify={setCaptchaToken} />
)}
```

---

## Key Files

- `/Users/apple/Desktop/threat-engine/platform/cspm-backend/user_auth/views/local_auth.py` (lines 243–244)
- `/Users/apple/Desktop/threat-engine/platform/cspm-backend/user_auth/throttles.py` — new file
- `/Users/apple/Desktop/threat-engine/platform/cspm-backend/cspm_backend/settings.py` — `REST_FRAMEWORK` throttle rates
- Frontend signup page (locate: `find /Users/apple/Desktop/threat-engine/frontend/src -name "*.jsx" -path "*signup*"`)

---

## Definition of Done

- [ ] Test: `test_signup_duplicate_email_returns_200` — POST with existing email returns 200, not 409
- [ ] Test: `test_signup_rate_limit_429` — 11th request within an hour returns 429
- [ ] Test: `test_login_rate_limit_429` — 21st request within an hour returns 429
- [ ] Test: `test_hcaptcha_failure_returns_400` — mock hcaptcha verify returning false → 400
- [ ] Test: `test_hcaptcha_skip_when_no_secret` — no HCAPTCHA_SECRET_KEY → signup proceeds normally
- [ ] bmad-security-reviewer: no BLOCKERS
- [ ] BLOCK-01 and BLOCK-02 marked closed in SECURITY-REVIEW-AUTH-SPRINT.md