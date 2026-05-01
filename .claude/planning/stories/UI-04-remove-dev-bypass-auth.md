# UI-04: Remove `DEV_BYPASS_AUTH` from production

## Status
Ready for dev

## Context
`frontend/src/lib/auth-context.js` contains a block (around lines 106–117) that checks `process.env.NEXT_PUBLIC_DEV_BYPASS_AUTH` and, if truthy, injects a synthetic authenticated session without any real login. This was added for local development convenience but is a critical security hole: if `NEXT_PUBLIC_DEV_BYPASS_AUTH=true` is ever set in a production Docker image (accidentally via `.env` copy or Dockerfile ENV instruction), the entire authentication layer is bypassed for all users. There is no CI guard preventing this.

## Scope
**In scope:**
- Gate the bypass block so it only runs when `NODE_ENV === 'development'` (in addition to the existing env var check)
- Add a CI check in the Dockerfile or a CI config file that greps for the flag being set to `true`

**Out of scope:**
- Removing the bypass feature entirely from development (it is useful for local work)
- Changing any other auth behaviour
- Modifying the Django backend

## Technical Notes

### File to modify: `frontend/src/lib/auth-context.js`

Read the file to find the exact bypass block. It will look approximately like:
```js
// Around line 106-117 (exact lines may differ slightly):
if (process.env.NEXT_PUBLIC_DEV_BYPASS_AUTH) {
  setSession({ ... synthetic session ... });
  setLoading(false);
  return;
}
```

Change the condition to:
```js
if (process.env.NODE_ENV === 'development' && process.env.NEXT_PUBLIC_DEV_BYPASS_AUTH === 'true') {
  // synthetic session
}
```

`NODE_ENV` is set to `'production'` automatically by Next.js when running `next build` and `next start`. It cannot be overridden by a `.env` file — it is hardcoded by the build toolchain. So this guard is effective.

### CI check to add

The goal is to prevent `NEXT_PUBLIC_DEV_BYPASS_AUTH=true` from appearing in the production Dockerfile or any `.env` file committed to the repo.

Option A — Add a shell check in `frontend/Dockerfile` as a build-time assertion (runs during `docker build`):
```dockerfile
# Add this as a RUN step before the final CMD, after copying .env* if any:
RUN ! grep -r "NEXT_PUBLIC_DEV_BYPASS_AUTH=true" /app/.env* 2>/dev/null || \
    (echo "ERROR: DEV_BYPASS_AUTH must not be true in production image" && exit 1)
```

Option B — Add a CI lint step. Check if `.github/workflows/` exists:
```bash
ls /Users/apple/Desktop/threat-engine/.github/workflows/
```
If a CI config exists, add a step:
```yaml
- name: Check no dev bypass in production
  run: |
    ! grep -r "NEXT_PUBLIC_DEV_BYPASS_AUTH=true" frontend/Dockerfile frontend/.env.production 2>/dev/null
```

Implement **both** A and B if both locations exist. If only Dockerfile exists, do Option A only.

### Finding the Dockerfile
```bash
find /Users/apple/Desktop/threat-engine/frontend -name "Dockerfile" | head -5
```

### Verifying the fix in production
```bash
# After deploying frontend image:
kubectl exec deployment/cspm-frontend -n threat-engine-engines -- printenv | grep DEV_BYPASS
# Expected: no output (variable not set)

# Also verify NODE_ENV:
kubectl exec deployment/cspm-frontend -n threat-engine-engines -- printenv NODE_ENV
# Expected: production
```

## Implementation Steps

1. Read `frontend/src/lib/auth-context.js` lines 100–120 to find the exact bypass block
2. Modify the condition to add `process.env.NODE_ENV === 'development' &&` guard
3. Find the frontend `Dockerfile`:
   ```bash
   find /Users/apple/Desktop/threat-engine/frontend -name "Dockerfile"
   ```
4. Add the Dockerfile `RUN` assertion step
5. Check if `.github/workflows/` exists and add CI step if applicable
6. Test locally: set `NEXT_PUBLIC_DEV_BYPASS_AUTH=true` in `.env.local` and confirm dev server still works (bypass still active in development)
7. Confirm that `NODE_ENV=production npm run build` does NOT trigger the bypass (test by logging what the condition evaluates to)

## Acceptance Criteria

**Given** `process.env.NODE_ENV === 'production'`
**When** auth-context.js loads, even if `NEXT_PUBLIC_DEV_BYPASS_AUTH=true` is set
**Then** the bypass block does not execute — real auth flow runs

**Given** `process.env.NODE_ENV === 'development'` and `NEXT_PUBLIC_DEV_BYPASS_AUTH=true`
**When** auth-context.js loads
**Then** the bypass still works (dev workflow not broken)

**Given** a Docker build where `NEXT_PUBLIC_DEV_BYPASS_AUTH=true` appears in `.env.production`
**When** `docker build` runs
**Then** the build fails with a clear error message

**Given** CI pipeline runs
**When** it checks `frontend/Dockerfile` for the flag
**Then** the check passes (flag not present) or fails the build (flag found)

## Test / Validation
```bash
# Check the auth-context guard:
grep -n "NODE_ENV\|DEV_BYPASS" /Users/apple/Desktop/threat-engine/frontend/src/lib/auth-context.js
# Expected: both conditions on the same line/block

# Check Dockerfile assertion exists:
grep -n "DEV_BYPASS" /Users/apple/Desktop/threat-engine/frontend/Dockerfile
# Expected: the grep assertion RUN step

# Check production env var is absent on running pod:
kubectl exec deployment/cspm-frontend -n threat-engine-engines -- printenv | grep DEV_BYPASS
# Expected: empty output
```

## Definition of Done
- [ ] `auth-context.js` bypass block gated by `NODE_ENV === 'development'` in addition to env var check
- [ ] Frontend `Dockerfile` contains a `RUN !grep` assertion for the flag
- [ ] CI config updated with the grep check (if CI config file exists)
- [ ] Dev workflow confirmed: bypass still works locally with `NODE_ENV=development`
- [ ] `npm run build` (production mode) does not trigger the bypass path
- [ ] No `.env.production` or `Dockerfile` in the repo sets `NEXT_PUBLIC_DEV_BYPASS_AUTH=true`

## Points
1

## Dependencies
None — this is a Wave 1 story, start immediately.