# Story UIBFF-FIX-09: Accounts Page — Migrate from Raw Gateway Calls to BFF

## Status: ready-for-dev

## Metadata
- **Phase**: Sprint UIBFF-FIX — Direct Engine Call Elimination
- **Epic**: UI→BFF→Engine Verified Data Chain
- **Points**: 2
- **Priority**: P1 (raw fetch bypasses BFF — no credential sanitization)
- **Depends on**: None
- **Blocks**: None

## User Story

As a security engineer, I want the Cloud Accounts page to load data through the BFF so that sensitive credential fields are stripped before the UI receives them.

## Context

Audit finding: `accounts/page.jsx` line 22 uses raw `fetch()` directly to the gateway:
```javascript
fetch('/gateway/api/v1/cloud-accounts/', { headers: {...} })
```

The BFF handler `onboarding_cloud_accounts.py` already exists with `view_cloud_accounts()` (lines 115–157) which does credential sanitization (`strip_sensitive_fields()` at line 104). The raw fetch skips this and may expose `credential_ref` or other sensitive fields to the browser.

A BFF view `/api/v1/views/onboarding/cloud_accounts` is already registered.

## What to Build

### 1. Update `accounts/page.jsx` to use `fetchView`

```javascript
// BEFORE (line 22):
const response = await fetch('/gateway/api/v1/cloud-accounts/', {
  headers: { 'Content-Type': 'application/json', ...authHeaders },
});
const accounts = await response.json();

// AFTER:
import { fetchView } from '@/lib/api';
const data = await fetchView('onboarding/cloud_accounts');
const accounts = data.accounts || data || [];
```

Adjust downstream state updates — `accounts` from BFF uses camelCase (`accountId`, `accountName`) vs raw gateway's snake_case. Verify field names in `AccountCard` component and update as needed:
- `account.account_id` → `account.accountId`
- `account.account_name` → `account.accountName`
- `account.credential_ref` → stripped (not present in BFF response)
- `account.provider` → same
- `account.status` → same

### 2. Update scan trigger to keep as direct call (mutation)

Line 39: `fetch('/gateway/api/v1/schedules/run-all', {...})` is a mutation (trigger scan for all accounts). This can stay as a direct gateway call — mutations bypass BFF per constitution.

### 3. Verify `AccountCard` component field names

Read `accounts/page.jsx` render section — find where `AccountCard` is rendered and update prop names to match BFF camelCase output:
```javascript
// If AccountCard reads:
account.account_id    → account.accountId
account.account_name  → account.accountName
account.tenant_name   → account.tenantName
```

## Acceptance Criteria

### AC-01 — Accounts page loads via BFF
`GET /api/v1/views/onboarding/cloud_accounts` returns `accounts[]` array. Page renders account cards.

### AC-02 — `credential_ref` absent
`credential_ref` field is NOT present in any account object returned to the browser. BFF strips it via `strip_sensitive_fields()`.

### AC-03 — No raw `fetch('/gateway/api/v1/cloud-accounts/')` calls
`grep -n "fetch.*cloud-accounts" frontend/src/app/accounts/page.jsx` returns 0 hits.

### AC-04 — Scan-all trigger still works
Clicking "Scan All" still triggers scans via the raw gateway mutation call.

### AC-05 — camelCase fields in AccountCard
AccountCard displays `accountName` and `provider` correctly.

## Cleanup Steps (After Testing)

1. `grep -n "fetch.*cloud-accounts" frontend/src/app/accounts/page.jsx` — confirm 0 hits
2. Verify in browser DevTools that `credential_ref` is absent from network responses
3. Rebuild gateway if BFF changes needed, verify rollout
4. Post-deploy: load /accounts — account cards render correctly
5. Run "Scan All" — confirm scan is triggered

## Definition of Done

- [ ] `accounts/page.jsx` uses `fetchView('onboarding/cloud_accounts')`
- [ ] Field name updates in AccountCard render (snake_case → camelCase)
- [ ] Mutation (scan-all trigger) preserved as direct call
- [ ] AC-01 through AC-05 verified
- [ ] Cleanup completed — 0 raw fetch hits
- [ ] Frontend image: `yadavanup84/cspm-frontend:v-accounts-bff1`