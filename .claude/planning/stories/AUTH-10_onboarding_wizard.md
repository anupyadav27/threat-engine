---
story_id: AUTH-10
title: Onboarding wizard — 6-step first-time user flow
status: ready
sprint: auth-redesign-2
depends_on: [AUTH-05, AUTH-06, AUTH-09]
blocks: []
sme: Full-stack engineer (Next.js + Django)
estimate: 3 days
---

# Story: Onboarding Wizard — 6-Step First-Time User Flow

## Context

Currently, new users are auto-provisioned into a tenant with a domain-derived name and
dropped directly into the dashboard. There is no guided onboarding. Users don't know:
- Their company name is "Gmail (auto)" because they used Google
- They need to connect a cloud account before they get any value
- They can invite teammates

This story implements a 6-step onboarding wizard shown to users whose tenant has zero
cloud accounts (first-time users).

## Steps

| Step | Title | What happens |
|------|-------|-------------|
| 1 | Welcome | Auto-provisioned (auth happens before wizard) |
| 2 | Company Setup | User provides company name, contact email; updates `Tenants` record |
| 3 | Configure SSO (optional) | User configures their IDP via `TenantIDPConfig` API (AUTH-05) |
| 4 | Invite Team (optional) | User invites colleagues via `POST /api/auth/invite/create/` |
| 5 | Connect Cloud Account | CSP selector → credential entry → schedule (uses onboarding engine) |
| 6 | First Scan | Trigger scan, show progress, redirect to dashboard |

## Files to Create/Modify

**Frontend**:
- `frontend/src/app/onboarding/page.jsx` — NEW: wizard container
- `frontend/src/app/onboarding/steps/` — NEW: individual step components
  - `CompanySetup.jsx`
  - `ConfigureSSO.jsx`
  - `InviteTeam.jsx`
  - `ConnectCloudAccount.jsx`
  - `FirstScan.jsx`
- `frontend/src/middleware.js` — redirect to `/onboarding` if tenant has 0 cloud accounts

**Backend**:
- `platform/cspm-backend/tenant_management/views.py` — add `PATCH /api/v1/tenants/{id}/` for company name update
- `platform/cspm-backend/tenant_management/urls.py` — add patch route

## Implementation Notes

### Wizard trigger (middleware)

After login, middleware checks: does the authenticated tenant have any cloud accounts?
Call `GET /api/v1/onboarding/accounts/?tenant_id={id}` (onboarding engine).
If count = 0: redirect to `/onboarding`.
If count > 0: proceed to dashboard.

Add `isOnboardingComplete` state to auth context or cookie.

### Step 2 — Company Setup

`PATCH /api/v1/tenants/{tenant_id}/`
Body: `{"name": "Acme Corp", "contact_email": "admin@acme.com"}`
Must validate user belongs to tenant.

### Step 3 — Configure SSO

Embed the IDP config form from AUTH-05 inline in the wizard.
SSO step is skippable ("Set up later" link advances to Step 4).

### Step 4 — Invite Team

Reuse `POST /api/auth/invite/create/` endpoint.
Show added invites in a list; "Skip" advances to Step 5.

### Step 5 — Connect Cloud Account

Multi-panel CSP selector showing: AWS, Azure, GCP, OCI, IBM, AliCloud, K8s.
Each CSP navigates to existing onboarding engine credential form.
Integrates with `POST /api/v1/onboarding/accounts/` (onboarding engine).

### Step 6 — First Scan

After account is connected, trigger scan via `POST /api/v1/onboarding/scan-runs/`.
Show progress using polling `GET /api/v1/onboarding/scan-runs/{scan_run_id}/status/`.
When scan completes (or times out at 5 min): redirect to dashboard.

### Skip all

"Skip setup" button at bottom of wizard advances directly to dashboard.
Wizard is shown again on next login if still 0 cloud accounts.

## Reference Files

- `frontend/src/lib/api.js` — API call patterns
- `frontend/src/middleware.js` — existing middleware
- `engines/onboarding/api/cloud_accounts.py` — cloud account API
- `platform/cspm-backend/tenant_management/views.py` — tenant CRUD

## Acceptance Criteria

- [ ] AC1: New user who has 0 cloud accounts is redirected to `/onboarding` after login
- [ ] AC2: Step 2 successfully updates `Tenants.name` via PATCH
- [ ] AC3: Step 3 SSO form creates a `TenantIDPConfig` record via AUTH-05 API
- [ ] AC4: Step 4 invite sends email (or shows success for mock in dev)
- [ ] AC5: Step 5 connects a cloud account via onboarding engine API
- [ ] AC6: Step 6 triggers a scan run and shows loading state
- [ ] AC7: "Skip setup" navigates to dashboard without error
- [ ] AC8: User who has >= 1 cloud account is NOT redirected to onboarding

## Definition of Done

- [ ] Wizard renders correctly on desktop (1280px) and laptop (1024px) viewports
- [ ] Each step can be reached independently via URL (deep-link for testing)
- [ ] Story accepted by SM before merge