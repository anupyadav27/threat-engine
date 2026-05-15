---
id: auth-B1
title: "Email enumeration fix + rate limiting + CAPTCHA"
sprint: B
points: 1
depends_on: []
blocks: [auth-B3]
security_blocks: [BLOCK-01, BLOCK-02]
nist_csf: PR.AC
owasp_samm: Implementation
csa_ccm: IAM-09
---

## Context

BLOCK-01 and BLOCK-02 from the bmad-security-architect review identified two authentication vulnerabilities in the Django login and registration flows. BLOCK-01: the login endpoint returns different HTTP responses or messages for "email not found" vs "wrong password" — attackers can enumerate valid email addresses. BLOCK-02: no rate limiting exists on login, registration, or password reset endpoints — they are open to brute force. This story fixes both by (a) making all auth failure responses identical, (b) adding `django-ratelimit` throttle classes to login/register/password-reset, and (c) adding a CAPTCHA hook (the UI CAPTCHA integration is out of scope — just wire the server-side validation hook). The `throttles.py` file already exists in `platform/cspm-backend/user_auth/throttles.py` — extend it.

## Acceptance Criteria

- [ ] AC1 (BLOCK-01): Login endpoint returns HTTP 401 with identical body `{"detail": "Invalid credentials"}` whether the email does not exist OR the password is wrong — no distinguishable difference.
- [ ] AC2 (BLOCK-01): Password reset endpoint returns HTTP 200 with `{"detail": "If that email is registered, a reset link has been sent"}` regardless of whether the email exists.
- [ ] AC3 (BLOCK-02): Login endpoint enforces rate limit: maximum 10 requests per minute per IP; 11th request returns HTTP 429 with `Retry-After` header.
- [ ] AC4 (BLOCK-02): Registration endpoint enforces rate limit: maximum 5 requests per minute per IP; 6th request returns HTTP 429.
- [ ] AC5 (BLOCK-02): Password reset endpoint enforces rate limit: maximum 3 requests per minute per email; 4th request returns HTTP 429.
- [ ] AC6: Rate limit classes are defined in `platform/cspm-backend/user_auth/throttles.py` using `django-ratelimit` or DRF throttle classes — not inline in views.
- [ ] AC7: CAPTCHA server-side hook exists as `validate_captcha(token: str) -> bool` in `platform/cspm-backend/user_auth/utils/captcha.py` (even if it returns True for now — the hook must be present and called from registration view).
- [ ] AC8: All auth responses use consistent timing — avoid timing oracle attacks (use constant-time comparison for passwords via Django's built-in `check_password`).
- [ ] AC9: Unit tests cover: wrong-email and wrong-password both return 401 with identical body; rate-limit returns 429 after threshold; reset always returns 200.

## Key Files

- `platform/cspm-backend/user_auth/views/` — Fix login and password reset response bodies
- `platform/cspm-backend/user_auth/throttles.py` — Add throttle classes for login, register, reset
- `platform/cspm-backend/user_auth/utils/captcha.py` — Create CAPTCHA validation hook
- `platform/cspm-backend/user_auth/urls.py` — Ensure throttle classes are applied to URL patterns

## Technical Notes

**Email enumeration fix (login view):**
```python
# BEFORE (vulnerable):
if not user:
    return Response({"detail": "Email not found"}, status=401)
if not check_password(password, user.password):
    return Response({"detail": "Wrong password"}, status=401)

# AFTER (safe):
user = authenticate(request, username=email, password=password)
if not user:
    return Response({"detail": "Invalid credentials"}, status=401)
```

**Password reset enumeration fix:**
```python
# Always return 200 regardless of email existence:
try:
    user = User.objects.get(email=email)
    send_reset_email(user)
except User.DoesNotExist:
    pass  # intentionally silent
return Response({"detail": "If that email is registered, a reset link has been sent"}, status=200)
```

**DRF throttle classes:**
```python
# throttles.py
from rest_framework.throttling import AnonRateThrottle

class LoginRateThrottle(AnonRateThrottle):
    rate = '10/min'
    scope = 'login'

class RegisterRateThrottle(AnonRateThrottle):
    rate = '5/min'
    scope = 'register'

class PasswordResetRateThrottle(AnonRateThrottle):
    rate = '3/min'
    scope = 'password_reset'
```

**Apply throttle to view:**
```python
class LoginView(APIView):
    throttle_classes = [LoginRateThrottle]
```

**CAPTCHA hook (to be wired to a real service post-MVP):**
```python
# utils/captcha.py
import os, requests

def validate_captcha(token: str) -> bool:
    """Server-side CAPTCHA validation. Returns True if valid."""
    captcha_secret = os.environ.get("CAPTCHA_SECRET_KEY", "")
    if not captcha_secret:
        return True  # disabled if no key configured
    # Wire to hCaptcha / reCAPTCHA as needed
    return True  # MVP stub
```

**Verify no remaining enumeration:**
```bash
grep -r "Email not found\|email not found\|User not found" \
  /Users/apple/Desktop/threat-engine/platform/cspm-backend/ --include="*.py"
# Expected: zero hits
```

## Security Checklist

- [ ] `require_permission()` present on all new/modified endpoints (N/A — public auth endpoints, rate-limited instead)
- [ ] `tenant_id` sourced from `X-Auth-Context` only (N/A — pre-auth endpoints)
- [ ] No hardcoded secrets or credentials
- [ ] CAPTCHA secret loaded from environment variable, not hardcoded
- [ ] bmad-security-reviewer gate passed before merge

## Definition of Done

- [ ] All ACs pass
- [ ] `grep -r "organizations\|org_id" platform/` returns no new hits in changed files
- [ ] Unit tests: enumeration-identical-response test; rate-limit 429 test; reset-always-200 test
- [ ] bmad-security-reviewer: no BLOCKERs (BLOCK-01 and BLOCK-02 resolved)
- [ ] `kubectl rollout status deployment/cspm-backend -n threat-engine-engines` shows AVAILABLE
- [ ] `kubectl logs -l app=cspm-backend -n threat-engine-engines` shows no ERROR in first 60s
- [ ] Post-deploy: curl gateway health-check 200