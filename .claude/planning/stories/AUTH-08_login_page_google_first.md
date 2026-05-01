---
story_id: AUTH-08
title: Login page — Google-first UX, SSO button, hide local auth
status: ready
sprint: auth-redesign-1
depends_on: [AUTH-03, AUTH-05]
blocks: []
sme: Next.js / React frontend engineer
estimate: 1 day
---

# Story: Login Page — Google-First UX

## Context

The current login page (`frontend/`) presents local email/password form, Google, and SAML
as equal options. Per requirements, Google should be the primary/default CTA. SAML/OIDC
should appear as "Sign in with SSO." Local auth should be hidden behind an admin link.

This story redesigns the login page UX to reflect the new auth priority.

## Files to Create/Modify

- `frontend/src/app/auth/login/page.jsx` (or `.tsx`) — redesign layout
- `frontend/src/components/auth/` — new auth-specific components if needed
- `frontend/src/lib/api.js` — add `checkTenantIDP(domain)` call if email domain detection is needed

## Implementation Notes

### Login Page Layout (priority order)

```
┌─────────────────────────────────────────┐
│           Threat Engine CSPM            │
│                                         │
│  ┌───────────────────────────────────┐  │
│  │   Sign in with Google   [G icon]  │  │  ← Primary CTA (large, prominent)
│  └───────────────────────────────────┘  │
│                                         │
│  ─────────────── or ───────────────     │
│                                         │
│  ┌───────────────────────────────────┐  │
│  │   Sign in with SSO               │  │  ← Secondary CTA
│  └───────────────────────────────────┘  │
│                                         │
│  ─────────────────────────────────────  │
│                                         │
│              Admin login                │  ← Small link, bottom
└─────────────────────────────────────────┘
```

### Google Sign-In Button

Clicking "Sign in with Google" navigates to `GET /api/auth/google/login/`.
No email input required — Google handles account selection.

### SSO Button

Clicking "Sign in with SSO" shows an email input field:
1. User enters their work email
2. Frontend calls `GET /api/v1/tenants/idp-by-domain/?domain={email_domain}` to check if
   a `TenantIDPConfig` exists for that domain
3. If found: redirect to `/api/auth/oidc/login/?tenant={tenant_id}` (OIDC) or
   `/api/auth/saml/{tenant_id}/login/` (SAML) based on `idp_type`
4. If not found: show message "No SSO configured for this domain. Contact your admin."

### Admin Login Link

"Admin login" link navigates to `/auth/login?method=local`.
When `?method=local` is in the URL, show the email/password form (collapsed by default).
This matches the backend gate from AUTH-07.

### New API endpoint (backend — add to tenant_management views)

`GET /api/v1/tenants/idp-by-domain/?domain=acme.com`

Returns: `{"tenant_id": "...", "idp_type": "oidc", "idp_name": "Acme Okta"}` if found,
or `{"tenant_id": null}` if no IDP configured for that domain.

Lookup logic: query `TenantIDPConfig.allowed_domains` (JSONB array) for rows containing
the given domain where `is_active=True`.

This endpoint is public (no auth required) — only returns the existence of an IDP config,
not its contents.

Add to `tenant_management/views.py` and `tenant_management/urls.py`.

### Existing auth flow preservation

- Google callback at `/api/auth/google/callback/` unchanged
- Existing session cookie handling unchanged
- `fetchView` pattern in `frontend/src/lib/api.js` unchanged (this is auth pages only)

## Reference Files

- `frontend/src/app/auth/` — existing auth pages
- `frontend/src/lib/api.js` — API call pattern
- `platform/cspm-backend/tenant_management/views.py` — add `idp-by-domain` endpoint

## Acceptance Criteria

- [ ] AC1: Login page renders "Sign in with Google" as the first and largest button
- [ ] AC2: "Sign in with SSO" button expands to show email input
- [ ] AC3: Entering an email domain with a configured OIDC IDP redirects to OIDC login
- [ ] AC4: Entering an email domain with no configured IDP shows "No SSO configured" message
- [ ] AC5: Clicking "Admin login" shows the local email/password form
- [ ] AC6: `GET /api/v1/tenants/idp-by-domain/?domain=acme.com` returns correct IDP info
- [ ] AC7: `GET /api/v1/tenants/idp-by-domain/?domain=unknown.com` returns `{"tenant_id": null}`

## Definition of Done

- [ ] No existing auth flow broken (Google, local login both work)
- [ ] Login page renders correctly on mobile viewport (responsive)
- [ ] Story accepted by SM before merge