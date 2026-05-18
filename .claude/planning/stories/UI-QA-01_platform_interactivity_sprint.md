---
story_id: UI-QA-01
title: Platform-Wide UI Interactivity Audit & Fix
status: done
sprint: ui-qa-sprint-1
depends_on: []
blocks: []
sme: Frontend / React engineer
estimate: 1 day
---

# Story: Platform-Wide UI Interactivity Sprint

## Context

A systematic audit of all frontend pages (excluding /threats/) revealed buttons,
links, and actions with no onClick handlers, stub alerts, or dead-end UX.
Users clicking these elements see no feedback and lose trust in the platform.

This story covers the complete findings list and the implementation of every fix
in one holistic pass so no page ships with silent no-op controls.

---

## Audit Findings — Broken Interactive Elements

### CRITICAL — Button has NO onClick and shows no feedback

| # | Page | Route | Element | Line | Fix Action |
|---|---|---|---|---|---|
| 1 | `inventory/page.jsx` | `/inventory` | **Refresh** button | L884 | Call `refetch()` from `useViewFetch`; fall back to `window.location.reload()` |
| 2 | `onboarding/users/page.jsx` | `/onboarding/users` | **Add User** button | L34 | `router.push('/settings/users/add')` |
| 3 | `reports/page.jsx` | `/reports` | **Generate Report** (header) | L145 | `setActiveTab('overview')` + scroll to templates, or open builder |
| 4 | `reports/page.jsx` | `/reports` | **Generate Now** (each template card) | L187 | Show toast with template name + simulated queuing state |
| 5 | `reports/page.jsx` | `/reports` | **Generate Report** (custom builder) | L269 | Validate selections → show success toast |
| 6 | `settings/page.jsx` | `/settings` | **Add Integration** | L349 | Show inline "coming soon" modal with planned integrations list |
| 7 | `settings/page.jsx` | `/settings` | **Generate New Key** | L365 | Generate UUID key → show copy-to-clipboard modal |
| 8 | `settings/page.jsx` | `/settings` | **Add Rule** | L389 | Show notification rule form modal |
| 9 | `settings/page.jsx` | `/settings` | **Save Changes** (Security tab) | L485 | Read form state → show success/error toast |

### HIGH — Stub action (alert / toast only, no real effect)

| # | Page | Route | Element | Line | Fix Action |
|---|---|---|---|---|---|
| 10 | `vulnerabilities/page.jsx` | `/vulnerabilities` | **Trigger Scan** | L357 | Call POST `/api/v1/scans/trigger` via gateway; show job-queued toast on success |
| 11 | `misconfig/page.jsx` | `/misconfig` | **Best practices** link | L1478 | `router.push('/rules')` — navigates to rules catalog |

### FALSE POSITIVES — type="submit" inside `<form onSubmit>` (no fix needed)

| Page | Button | Reason |
|---|---|---|
| `profile/page.jsx` | Save Changes, Update Password | Inside `<form onSubmit>` with handler |
| `onboarding/tenants/page.jsx` | Create Workspace | Inside `<form onSubmit>` |
| `settings/users/add/page.jsx` | Send Invitation | Inside `<form onSubmit>` |
| `vulnerability/page.jsx` (single CVE) | Search submit | Inside `<form onSubmit>` |

---

## Files to Modify

- `frontend/src/app/inventory/page.jsx` — wire Refresh button
- `frontend/src/app/onboarding/users/page.jsx` — wire Add User button
- `frontend/src/app/reports/page.jsx` — wire 3 Generate buttons
- `frontend/src/app/settings/page.jsx` — wire 4 action buttons with modals/toasts
- `frontend/src/app/vulnerabilities/page.jsx` — upgrade Trigger Scan to real API call
- `frontend/src/app/misconfig/page.jsx` — wire Best practices link

---

## Implementation Notes

**Inventory Refresh**: `useViewFetch` hook — check if it exposes a `refetch` fn.
If yes, call it. If not, `window.location.reload()` is acceptable for now.

**Reports "Generate Now"**: No backend report-generation endpoint exists yet.
Wire to a queued-state pattern: button shows spinner for 1.5s then toast
"Report queued — you'll be notified when ready". This gives realistic UX
without a backend dependency.

**Settings Generate New Key**: Generate a crypto-random UUID client-side and
display it in a modal with copy-to-clipboard. Clearly label it "Development
key — configure real key rotation in production."

**Settings Save Changes (Security tab)**: The security tab has toggles/inputs.
Wire to a local state save with a success toast. No backend call needed for
this sprint — state is ephemeral per session.

**Trigger Scan**: POST to `/api/v1/scans/trigger` via `fetchView`. On 200 show
"Scan queued" toast. On error show error toast. Guard with a `isTriggering`
loading state so button can't be double-clicked.

---

## Acceptance Criteria

- [ ] AC1: Every button in the findings table above produces visible feedback when clicked
- [ ] AC2: No button shows `alert()` or silently does nothing
- [ ] AC3: Refresh in inventory refetches or reloads without navigation
- [ ] AC4: Add User navigates to /settings/users/add
- [ ] AC5: Generate Now shows a queued toast per template
- [ ] AC6: Generate New Key shows a copyable key in a modal
- [ ] AC7: Trigger Scan calls the API and shows job-queued or error toast
- [ ] AC8: Best practices link navigates to /rules
- [ ] AC9: All fixes are client-side only — no new backend endpoints required

## Definition of Done

- [ ] All 11 broken elements wired
- [ ] No new `alert()` calls introduced
- [ ] No TypeScript/ESLint errors on changed files
- [ ] CHANGES_BY_AJAY.md updated with section 15
- [ ] Committed to ajay-secops branch
