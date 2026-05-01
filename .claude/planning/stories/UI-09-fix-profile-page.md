# UI-09: Fix profile page

## Status
Ready for dev

## Context
`frontend/src/app/profile/page.jsx` has four concrete bugs:
1. Fetches from the wrong path `/api/users/me/` (correct path is `/api/auth/me/`)
2. Reads non-existent fields `first_name`, `last_name`, `phone`, `is_superuser`, `date_joined` — the actual `MeView` response has `name` (single string), `email`, and `tenants[0].role`
3. The "Save Changes" button has no API call attached — changes are lost on reload
4. The "Change Password" button has no API call attached — nothing happens when clicked

This story fixes all four bugs and wires both actions to the real Django endpoints added in BE-01 and BE-02.

## Scope
**In scope:**
- Fix the fetch URL
- Fix field mapping from the API response
- Wire "Save Changes" to `PATCH /cspm/api/auth/me/`
- Wire "Change Password" to `POST /cspm/api/auth/change-password/`
- Add error toast on 4xx responses for both actions

**Out of scope:**
- Redesigning the profile page layout
- Adding avatar upload
- Adding two-factor authentication settings
- SSO profile editing (not supported by backend)

## Technical Notes

### Read these files first
```bash
# The profile page:
cat /Users/apple/Desktop/threat-engine/frontend/src/app/profile/page.jsx

# The API lib (fetchFromCspm function signature and base URL):
cat /Users/apple/Desktop/threat-engine/frontend/src/lib/api.js

# The auth context (to understand how to get current user data without an extra fetch):
cat /Users/apple/Desktop/threat-engine/frontend/src/lib/auth-context.js
```

### Fix 1: URL correction
```js
// BEFORE (line ~36):
const res = await fetchFromCspm('/api/users/me/');

// AFTER:
const res = await fetchFromCspm('/api/auth/me/');
```

### Fix 2: Field mapping
The `GET /api/auth/me/` response shape:
```json
{
  "id": "<uuid>",
  "email": "user@example.com",
  "name": "Jane Smith",
  "sso_provider": "local",
  "tenants": [{ "tenant_id": "...", "tenant_name": "...", "role": "admin", "status": "active" }]
}
```

How to populate the form:
- `name` field: split on first space → `firstName = name.split(' ')[0]`, `lastName = name.split(' ').slice(1).join(' ')`
- `email`: use directly
- `role`: use `tenants[0]?.role ?? 'member'`
- Remove `phone`, `is_superuser`, `date_joined` references entirely

If the page has a "First Name" and "Last Name" field in the form, populate them from the split. If it has a single "Name" field, populate it from `name` directly. Read the JSX to check what form fields exist.

### Fix 3: Wire "Save Changes"
```js
const handleSave = async () => {
  try {
    setSaving(true);
    const res = await fetchFromCspm('/api/auth/me/', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        first_name: firstName.trim(),
        last_name: lastName.trim(),
      }),
    });
    if (!res.ok) {
      const err = await res.json();
      showErrorToast(err.error || 'Failed to save changes');
      return;
    }
    showSuccessToast('Profile updated');
  } catch (e) {
    showErrorToast('Network error — please try again');
  } finally {
    setSaving(false);
  }
};
```

Note: `fetchFromCspm` signature may differ from `fetch`. Read `api.js` to see if it wraps the response or returns it raw. Adjust accordingly.

Find the existing toast pattern in the codebase:
```bash
grep -rn "toast\|Toast\|showError\|showSuccess" /Users/apple/Desktop/threat-engine/frontend/src --include="*.jsx" | head -10
```
Use whatever toast/notification component is already in use — do not add a new dependency.

### Fix 4: Wire "Change Password"
The change password form likely has `currentPassword` and `newPassword` fields. Wire the form submit:
```js
const handleChangePassword = async () => {
  try {
    setChangingPassword(true);
    const res = await fetchFromCspm('/api/auth/change-password/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        current_password: currentPassword,
        new_password: newPassword,
      }),
    });
    if (!res.ok) {
      const err = await res.json();
      showErrorToast(err.error || 'Failed to change password');
      return;
    }
    showSuccessToast('Password changed — please log in again');
    // Optionally redirect to login:
    // router.push('/auth/login');
  } catch (e) {
    showErrorToast('Network error — please try again');
  } finally {
    setChangingPassword(false);
  }
};
```

### `fetchFromCspm` path prefix
Check `api.js` — `fetchFromCspm` likely prepends `/cspm` to the path (the gateway routes Django requests under `/cspm/`). The calls in the Implementation Notes above already use `/api/auth/me/` — adjust with the prefix that `fetchFromCspm` requires. Read the function signature.

### Auth context optimization (optional)
If `AuthContext` already has the current user's `name` and `email` populated (from the login response), you can optionally populate the form from context instead of making an extra fetch. However, always making the fetch on mount is also correct — it ensures the form shows the latest data from the DB.

## Implementation Steps

1. Read `frontend/src/app/profile/page.jsx` in full — note all field references and button handlers
2. Read `frontend/src/lib/api.js` — confirm `fetchFromCspm` signature and any base URL prefix
3. Find the toast component used in other pages
4. Fix the fetch URL (line ~36)
5. Fix field mapping — remove `phone`, `is_superuser`, `date_joined`; add `name` split logic
6. Find the "Save Changes" button's `onClick` handler — add `handleSave` as shown above
7. Find the "Change Password" button/form submit handler — add `handleChangePassword`
8. Add loading/disabled state to both buttons during their respective API calls
9. Test manually: navigate to `/profile`, verify form populates, save a name change, verify it persists on reload

## Acceptance Criteria

**Given** a logged-in user navigates to `/profile`
**When** the page loads
**Then** the form shows the user's real name (from `/api/auth/me/`) and email, with no 404 error in Network tab

**Given** the user changes their first name in the form and clicks "Save Changes"
**When** the PATCH request completes successfully
**Then** a success notification appears; reloading the page shows the new name

**Given** the user enters the wrong current password and clicks "Change Password"
**When** the POST request returns 400
**Then** an inline error message appears with "Current password incorrect"

**Given** the user successfully changes their password
**When** they try to use the old token
**Then** they are redirected to login (session invalidated by BE-02)

**Given** a network error occurs during save
**When** the form submits
**Then** an error notification appears (not a silent failure)

## Test / Validation
```bash
# Playwright test (TC-PROFILE):
# 1. Navigate to /profile
# 2. Verify form fields populated (not empty, not "undefined")
# 3. Change first name field to "TestName"
# 4. Click Save Changes
# 5. Verify success toast appears
# 6. Reload page (F5)
# 7. Verify first name field still shows "TestName"

# API URL check:
grep -n "api/users/me\|api/auth/me" \
  /Users/apple/Desktop/threat-engine/frontend/src/app/profile/page.jsx
# Expected: only /api/auth/me/ references (no /api/users/me/)

# Field reference check:
grep -n "first_name\|last_name\|phone\|is_superuser\|date_joined" \
  /Users/apple/Desktop/threat-engine/frontend/src/app/profile/page.jsx
# Expected: first_name and last_name may appear in the PATCH body — OK
# NOT OK: reading them from the GET response (response has only 'name')
```

## Definition of Done
- [ ] Fetch URL changed from `/api/users/me/` to `/api/auth/me/`
- [ ] Form populated from `name` (split into first/last), `email`, `tenants[0].role`
- [ ] `phone`, `is_superuser`, `date_joined` removed from field bindings
- [ ] "Save Changes" calls `PATCH /api/auth/me/` with correct body
- [ ] "Change Password" calls `POST /api/auth/change-password/` with correct body
- [ ] Error toast shown on 4xx for both actions
- [ ] Loading/disabled state on buttons during API calls
- [ ] Profile data persists after save + page reload

## Points
3

## Dependencies
BE-01 (`PATCH /api/auth/me/`) must be merged first.
BE-02 (`POST /api/auth/change-password/`) must be merged first.
This is a Wave 3 story.
