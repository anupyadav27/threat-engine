# UI-03: Next.js auth middleware

## Status
Ready for dev

## Context
`frontend/src/middleware.ts` does not exist. This means any unauthenticated user who knows a URL (e.g. `/dashboard`, `/threats`) can reach it directly in the browser without being logged in. The auth check only happens client-side inside `auth-context.js`, which loads after the page renders, causing a flash of unauthenticated content. A Next.js Edge middleware file intercepts requests server-side before the page renders and provides the correct redirect.

## Scope
**In scope:**
- Create `frontend/src/middleware.ts`
- Read the `access_token` cookie (set by Django auth on login)
- Redirect unauthenticated requests on protected routes to `/auth/login`
- Exclude public/static paths from the check

**Out of scope:**
- Validating or decoding the JWT (token validation happens in Django — middleware only checks presence)
- Changing how the cookie is set or named (do not touch Django auth)
- Changing any page files
- Rate limiting or CSRF (separate concerns)

## Technical Notes

### Cookie name
Read `frontend/src/lib/auth-context.js` to confirm the exact cookie name. Based on the Django auth setup it is likely `access_token`. Grep to confirm:
```bash
grep -n "access_token\|cookie" /Users/apple/Desktop/threat-engine/frontend/src/lib/auth-context.js | head -20
```

### Next.js middleware file location
Must be at `frontend/src/middleware.ts` (not inside `app/`). Next.js 15 picks it up automatically.

### Matcher config — routes that require auth
Protect everything except:
- `/auth/*` — login, register, password reset
- `/_next/*` — Next.js internal assets
- `/api/*` — Next.js API routes (BFF proxy, not the engine APIs)
- `/favicon.ico`
- `/public/*` — static assets

### Implementation pattern
```typescript
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  const token = request.cookies.get('access_token')?.value;

  if (!token) {
    const loginUrl = new URL('/auth/login', request.url);
    loginUrl.searchParams.set('next', request.nextUrl.pathname);
    return NextResponse.redirect(loginUrl);
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    '/((?!auth|_next/static|_next/image|favicon.ico|public).*)',
  ],
};
```

### `next` param
Set `?next=<original-path>` so the login page can redirect back after successful auth. Check if `frontend/src/app/auth/login/page.jsx` already reads `searchParams.next` and honors it — if not, note it as a follow-up but do not implement it in this story.

### Edge runtime compatibility
Next.js middleware runs on the Edge runtime. Do NOT import Node.js-only modules (`fs`, `crypto`, `jsonwebtoken`, etc.). The cookie check is pure string presence — no decoding needed.

### TypeScript
The file must be `.ts` not `.js`. If the project does not have a `tsconfig.json` covering `src/`, check `frontend/tsconfig.json`. If the project is JavaScript-only, create the file as `middleware.js` instead and adjust the types accordingly (remove type annotations).

## Implementation Steps

1. Read `frontend/src/lib/auth-context.js` to confirm the cookie name used for the access token
2. Check `frontend/tsconfig.json` to confirm TypeScript is configured for `src/`
3. Check if `frontend/src/app/auth/login/page.jsx` exists (middleware redirects there)
4. Create `frontend/src/middleware.ts` with the implementation shown above
5. Adjust the cookie name if it differs from `access_token`
6. Test locally:
   - Open incognito browser tab
   - Navigate to `http://localhost:3000/dashboard`
   - Confirm redirect to `/auth/login`
   - Log in
   - Confirm redirect back to `/dashboard` (if `?next` is supported by login page)
   - Navigate to `http://localhost:3000/auth/login` while logged in
   - Confirm no redirect loop (already authenticated users should still be able to view login page — do not add a redirect-away-from-login in this story)

## Acceptance Criteria

**Given** the user is not logged in (no `access_token` cookie)
**When** they navigate directly to `/dashboard`
**Then** the browser redirects to `/auth/login` before any page content renders

**Given** the user is logged in (valid `access_token` cookie present)
**When** they navigate to `/dashboard`
**Then** the page loads normally with no redirect

**Given** any request to `/auth/login`
**When** middleware runs
**Then** no redirect occurs (no redirect loop)

**Given** any request to `/_next/static/...`
**When** middleware runs
**Then** the request passes through without redirect (static assets remain accessible)

**Given** any request to `/favicon.ico`
**When** middleware runs
**Then** the request passes through without redirect

## Test / Validation
```bash
# After starting local dev server (npm run dev in frontend/):

# TC-AUTH-1: Unauthenticated access blocked
# Open incognito window, navigate to http://localhost:3000/dashboard
# Expected: browser URL changes to http://localhost:3000/auth/login

# TC-AUTH-2: Static assets pass through
curl -I http://localhost:3000/favicon.ico
# Expected: 200 OK (not 302)

# TC-AUTH-3: Auth routes pass through
curl -I http://localhost:3000/auth/login
# Expected: 200 OK (not 302)

# TC-AUTH-4: Middleware file is picked up
# In Next.js dev server output, confirm no "middleware not found" warning
```

## Definition of Done
- [ ] `frontend/src/middleware.ts` (or `.js`) exists
- [ ] Unauthenticated request to `/dashboard` redirects to `/auth/login`
- [ ] Authenticated request (cookie present) to `/dashboard` does not redirect
- [ ] Requests to `/auth/*`, `/_next/*`, `/favicon.ico` are not redirected
- [ ] No redirect loop on `/auth/login`
- [ ] `npm run build` succeeds (TypeScript compiles)
- [ ] No console errors in browser for authenticated users

## Points
2

## Dependencies
None — this is a Wave 1 story, start immediately.
