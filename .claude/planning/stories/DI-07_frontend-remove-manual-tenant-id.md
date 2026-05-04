# DI-07: Frontend — Remove Manual tenant_id Passing from useViewFetch and Direct Calls

## Track
Track 1 — Auth Context + Tenant Scoping

## Priority
P2 — depends on DI-05 and DI-06 being fully deployed first

## Story
As a frontend engineer, I need to remove all manual `tenant_id` passing from `useViewFetch` and `fetchView` calls, now that the BFF reads tenant_id from the authenticated session. This eliminates the class of bug where the wrong ID was passed.

## Prerequisite
DI-05 and DI-06 must be deployed to the gateway first. After those stories, the BFF ignores `tenant_id` from the query string. Only then is it safe to remove it from the frontend without breaking data loading.

## Files to Modify

### 1. `/Users/apple/Desktop/threat-engine/frontend/src/lib/use-view-fetch.js`

Remove `tenant_id` from params:

```js
// Before:
const params = {
  tenant_id: tenantId,
  ...(provider  ? { provider }  : {}),
  ...(account   ? { account }   : {}),
  ...(region    ? { region }    : {}),
  ...extraRef.current,
};

// After:
const params = {
  ...(provider  ? { provider }  : {}),
  ...(account   ? { account }   : {}),
  ...(region    ? { region }    : {}),
  ...extraRef.current,
};
```

Also remove unused: `const tenantId = selectedTenant || TENANT_ID || 'default-tenant';`

The `selectedTenant` and `TENANT_ID` vars no longer need to be read here. Remove the `selectedTenant` dependency from the `useCallback` dep array:

```js
// Before:
}, [viewName, selectedTenant, provider, account, region]);

// After:
}, [viewName, provider, account, region]);
```

### 2. Direct `fetchView` calls that pass tenant_id

Search pattern: `fetchView(.*tenant_id`

Files that pass `tenant_id` to `fetchView()` directly (confirmed by grep):

- `/Users/apple/Desktop/threat-engine/frontend/src/app/policies/page.jsx` line 49:
  ```js
  // Before:
  const res = await fetchView('policies', { tenant_id: TENANT_ID });
  // After:
  const res = await fetchView('policies');
  ```

- `/Users/apple/Desktop/threat-engine/frontend/src/app/threats/toxic-combinations/page.jsx` line 178:
  ```js
  // Before: any tenant_id in params object → remove it
  ```

- `/Users/apple/Desktop/threat-engine/frontend/src/app/threats/attack-paths/page.jsx` line 613:
  ```js
  // Same pattern — remove tenant_id from params
  ```

Run a grep to find ALL remaining direct calls before implementing:
```bash
grep -rn "fetchView\|getFromEngine" /Users/apple/Desktop/threat-engine/frontend/src/app --include="*.jsx" | grep "tenant_id" | sort
```

Remove `tenant_id` from every call found.

### 3. `/Users/apple/Desktop/threat-engine/frontend/src/lib/api.js`

Remove the fallback `TENANT_ID` injection from `getFromEngine` and `fetchApi`:

```js
// Before (lines 79-82 in getFromEngine):
if (TENANT_ID && !url.searchParams.has('tenant_id')) {
  url.searchParams.append('tenant_id', TENANT_ID);
}

// After: remove these 3 lines entirely (from both fetchApi and getFromEngine)
```

Note: `postToEngine` also has this pattern — remove it there too.

### 4. `/Users/apple/Desktop/threat-engine/frontend/src/lib/constants.js`

Check if `TENANT_ID` is still used anywhere after this change:
```bash
grep -rn "TENANT_ID" /Users/apple/Desktop/threat-engine/frontend/src --include="*.js" --include="*.jsx"
```

If `TENANT_ID` is only referenced in `api.js` (which we just cleaned), remove the export from `constants.js`.

## Acceptance Criteria

- [ ] `use-view-fetch.js` no longer passes `tenant_id` in params object
- [ ] `use-view-fetch.js` no longer reads `selectedTenant` (or reads it only for display, not for API calls)
- [ ] Zero instances of `tenant_id` being appended to BFF view URLs from the frontend
- [ ] All pages that use `useViewFetch` still load data correctly (network tab shows no `tenant_id=` query param)
- [ ] Dashboard, Threats, Compliance pages all render data in E2E test
- [ ] No console errors about missing tenant_id

## Regression Check
After deployment, open browser network tab:
- Navigate to /threats
- Confirm request URL is `GET /api/v1/views/threats?provider=&...` with NO `tenant_id=` parameter
- Confirm response contains threat data (not empty)

## Definition of Done
- All manual `tenant_id` passing removed from frontend
- E2E test for dashboard, threats, compliance pages passes
- No `tenant_id` in BFF view request URLs in network tab
