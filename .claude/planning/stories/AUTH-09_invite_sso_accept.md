---
story_id: AUTH-09
title: Invite flow — SSO accept path (no forced password)
status: ready
sprint: auth-redesign-2
depends_on: [AUTH-02, AUTH-04]
blocks: [AUTH-10]
sme: Django/Python backend engineer
estimate: 1.5 days
---

# Story: Invite Flow — SSO Accept Path

## Context

Current `AcceptInviteView` requires a password (min 8 chars) for new users. If a user's
organization uses SSO (OIDC or SAML), they should be able to accept an invite by signing
in via their IDP — no password required.

Flow after this story:
1. Admin sends invite to user@acme.com
2. User clicks invite link: `GET /api/auth/invite/{token}/` (unchanged)
3. Frontend shows options: "Accept with Google" | "Accept with SSO" | "Set a password"
4. User chooses SSO — frontend redirects to IDP login with invite token in state
5. On IDP callback: if invite token exists and email matches, consume invite and add to tenant

## Files to Create/Modify

- `platform/cspm-backend/user_auth/views/invite.py` — extend AcceptInviteView
- `platform/cspm-backend/user_auth/views/oidc_auth.py` — add invite_token to OIDC state
- `platform/cspm-backend/user_auth/views/saml_auth.py` — add invite_token to SAML RelayState
- `platform/cspm-backend/user_auth/urls.py` — add invite-SSO initiation routes

## Implementation Notes

### Approach: Pass invite_token through IDP flow

Add a new initiation endpoint:
`GET /api/auth/invite/{token}/sso/?tenant={tenant_id}`

1. Validate invite token (not used, not expired, email matches)
2. Store invite token in session: `request.session['pending_invite_token'] = token`
3. Redirect to OIDC or SAML login for the tenant

On OIDC/SAML callback:
1. Check `request.session.get('pending_invite_token')`
2. If present: after user upsert, also consume the invite (create TenantUsers if not exists, mark invite.used=True)
3. Clear session key

### AcceptInviteView changes

Make `password` optional:
```python
password = data.get("password") or ""
# Only require password if no SSO alternative
if not password and not _user_has_sso_provider(invite.email):
    return JsonResponse({"message": "Password required for non-SSO accounts"}, status=400)
```

`_user_has_sso_provider(email)`: check if `TenantIDPConfig` exists for the email domain
(reuse logic from `idp-by-domain` endpoint).

### ValidateInviteView changes

Return `idp_available` flag in response:
```json
{
  "email": "user@acme.com",
  "tenant_name": "Acme Corp",
  "tenant_id": "...",
  "role": "Member",
  "expires_at": "...",
  "idp_available": true,
  "idp_type": "oidc"
}
```

This allows the frontend to show appropriate accept options.

## Reference Files

- `platform/cspm-backend/user_auth/views/invite.py` — current invite flow
- `platform/cspm-backend/user_auth/views/oidc_auth.py` — OIDC flow from AUTH-02

## Acceptance Criteria

- [ ] AC1: Existing password-based invite acceptance still works
- [ ] AC2: `GET /api/auth/invite/{token}/` returns `idp_available: true` when email domain has active IDP config
- [ ] AC3: `GET /api/auth/invite/{token}/sso/?tenant={id}` redirects to IDP login
- [ ] AC4: After SSO login with matching email, invite is consumed and user added to tenant
- [ ] AC5: Invite token in session is cleared after consumption
- [ ] AC6: SSO accept with wrong email (different from invite email) fails with 403

## Definition of Done

- [ ] Code follows Python standards
- [ ] Both password and SSO paths tested
- [ ] Story accepted by SM before merge