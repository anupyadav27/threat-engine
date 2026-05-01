---
story_id: AUTH-03
title: Refactor Google OAuth to OIDC path + security fixes (state, PKCE)
status: ready
sprint: auth-redesign-1
depends_on: [AUTH-02]
blocks: [AUTH-08]
sme: Django/Python backend engineer
estimate: 1 day
---

# Story: Refactor Google OAuth to OIDC Path + Security Fixes

## Context

The current `google_auth.py` has two security gaps:
1. No OAuth `state` parameter — vulnerable to CSRF (RFC 6749 Section 10.12)
2. Calls `/oauth2/v3/userinfo` instead of validating ID token via JWKS — slower, and skips
   standard OIDC validation

Google is a valid OIDC 1.0 provider (issuer: `https://accounts.google.com`). After AUTH-02
implements a generic OIDC client, Google login can be routed through it rather than
maintaining a parallel implementation.

This story:
1. Fixes the security gaps in the existing Google flow as an immediate patch
2. Refactors `GoogleLoginView`/`GoogleCallbackView` to use the generic OIDC path from AUTH-02

## Files to Create/Modify

- `platform/cspm-backend/user_auth/views/google_auth.py` — fix state + refactor to OIDC path
- `platform/cspm-backend/user_auth/urls.py` — keep `/google/login/` and `/google/callback/` routes but redirect to OIDC flow internally

## Implementation Notes

### Phase 1 — Immediate Security Fix (can ship before AUTH-02)

In `GoogleLoginView.get()`:
1. Generate `state = secrets.token_urlsafe(32)`
2. Store in session: `request.session['google_oauth_state'] = state`
3. Add `state` to params dict

In `GoogleCallbackView.get()`:
1. At top of handler: `expected = request.session.pop('google_oauth_state', None)`
2. If `request.GET.get('state') != expected`: redirect to login with `error=csrf_detected`

### Phase 2 — Refactor to OIDC Path

After AUTH-02 is merged, `GoogleLoginView` becomes:

```python
class GoogleLoginView(APIView):
    """Redirect to generic OIDC flow using platform Google OAuth config."""

    def get(self, request: HttpRequest) -> HttpResponse:
        # Use platform-level Google OIDC config (no tenant_id required for global Google)
        # Construct the OIDC login URL manually or redirect to /api/auth/oidc/login/
        # with a special sentinel tenant_id='__platform__' for the global Google app
        tenant_id = request.GET.get('tenant', '__platform__')
        redirect_url = f"/api/auth/oidc/login/?tenant={tenant_id}&idp_type=google_oauth"
        return HttpResponseRedirect(redirect_url)
```

Platform-level Google OIDC config is stored as a `TenantIDPConfig` row with a sentinel
`tenant_id` pointing to a platform-owned tenant, OR loaded from env vars as a fallback.
Decision: use env vars as fallback so existing deployments continue to work without DB config.

### Google OIDC Discovery

Google's OIDC discovery URL: `https://accounts.google.com/.well-known/openid-configuration`
The generic OIDC client from AUTH-02 handles this automatically via issuer discovery.

### Retained routes

`/api/auth/google/login/` and `/api/auth/google/callback/` remain in `urls.py` for
backward compatibility. They internally delegate to the OIDC flow.

## Reference Files

- `platform/cspm-backend/user_auth/views/google_auth.py` — file to modify
- `platform/cspm-backend/user_auth/views/oidc_auth.py` — AUTH-02 output, used after merge

## Acceptance Criteria

- [ ] AC1: `GET /api/auth/google/login/` returns 302 to Google consent page containing `state` parameter
- [ ] AC2: Callback with missing or wrong `state` returns redirect to `/auth/login?error=csrf_detected`
- [ ] AC3: Callback with correct `state` completes login and sets httponly cookies
- [ ] AC4: `login_method` on created `UserSessions` is `'google'` (backward compat)
- [ ] AC5 (Phase 2): After AUTH-02 merge, `google_auth.py` contains no duplicate token exchange or userinfo logic — delegates entirely to OIDC client

## Definition of Done

- [ ] Phase 1 (state fix) can be shipped independently of AUTH-02
- [ ] Phase 2 refactor committed after AUTH-02 is merged and passing
- [ ] Existing Google login tested end-to-end against real Google OAuth app
- [ ] Story accepted by SM before merge
