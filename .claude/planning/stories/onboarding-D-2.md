---
story_id: onboarding-D-2
title: User invite flow API (Django) — invite, accept, cross-org cap
status: ready
sprint: onboarding-revamp-D
depends_on: [auth-A2, auth-B4]
blocks: [onboarding-D-3, onboarding-D-12]
sme: Django/DRF engineer
estimate: 2 days
---

# Story: User invite flow API (Django)

## User Story
As an `org_admin`, I want to invite users to my organization by email so that they get
access to my tenants with a specified role, and cross-org invites are automatically
capped to the `viewer` role.

## Context
Story auth-B4 adds `accept_invite_membership()` cross-org cap logic in `tenant_utils.py`.
This story builds the full invite API on top of that:
1. `POST /api/v1/invites/` — create invite token for email + tenant + role
2. `GET /api/v1/invites/{token}/` — validate invite token (for pre-accept validation in UI)
3. `POST /api/v1/invites/{token}/accept/` — accept invite, create TenantUsers, call `accept_invite_membership()`

**CORRECT DESIGN:**
- Invite stores: `inviter_customer_id = str(request.user.customer_id)` at creation time
- On accept: compare `invite.tenant.customer_id` vs `user.customer_id` → cross-org if different
- Cross-org invite: role capped at `viewer`, `log_auth_event("invite.cross_org_capped")` emitted
- `user_invitations` table already exists in cspm DB — this story builds on it

## Files to Create/Modify
- `platform/cspm-backend/tenant_management/views.py` — add `InviteCreateView`, `InviteAcceptView`
- `platform/cspm-backend/user_auth/utils/invite_utils.py` — `create_invite_token()`, `send_invite_email()`
- `platform/cspm-backend/tenant_management/urls.py` — add invite routes

## Implementation Notes

### `InviteCreateView`

```python
class InviteCreateView(APIView):
    authentication_classes = [CookieTokenAuthentication]
    permission_classes = [HasPermission("users:write")]

    def post(self, request):
        tenant_id = request.data.get("tenant_id")
        email = request.data.get("email")
        role_name = request.data.get("role", "viewer")

        # Verify tenant belongs to requester's org
        tenant = get_object_or_404(Tenants, id=tenant_id,
                                   customer_id=request.user.customer_id)

        # Cap role at tenant_admin (org_admin cannot grant higher than their own level)
        role = _get_role_capped(role_name, max_level=request.user_role_level)

        token = create_invite_token(
            email=email,
            tenant=tenant,
            role=role,
            inviter_customer_id=str(request.user.customer_id),
            created_by=request.user,
        )
        send_invite_email(email, token=token.token, inviter_name=request.user.email)
        return Response({"id": token.id, "email": email, "expires_at": token.expires_at},
                        status=201)
```

### `InviteAcceptView`

```python
class InviteAcceptView(APIView):
    authentication_classes = [CookieTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, token):
        invite = get_object_or_404(UserInvitations, token=token, status='pending')
        if invite.expires_at < timezone.now():
            return Response({"error": "Invite expired"}, status=410)

        result = accept_invite_membership(user=request.user, invite=invite)
        return Response({"joined": True, "cross_org": result.get("cross_org_invite", False)},
                        status=200)
```

### `create_invite_token()` helper

```python
def create_invite_token(email, tenant, role, inviter_customer_id, created_by):
    raw_token = secrets.token_urlsafe(32)
    return UserInvitations.objects.create(
        email=email,
        tenant=tenant,
        role=role,
        token=raw_token,
        inviter_customer_id=inviter_customer_id,  # stored for cross-org check on accept
        created_by=created_by,
        expires_at=timezone.now() + timedelta(days=7),
        status='pending',
    )
```

## Security Controls

- `tenant_id` validated against `request.user.customer_id` — cannot invite to foreign org's tenant
- Role capped at caller's own level — cannot grant higher privilege than self
- Invite token is `secrets.token_urlsafe(32)` — cryptographically random
- Token stored as-is (not hashed) — acceptable since token expires in 7 days and is single-use
- `accept_invite_membership()` handles cross-org role cap at viewer (story B4)

## Acceptance Criteria
- [ ] AC1: `POST /api/v1/invites/` by org_admin of org A with `tenant_id` from org B → 404
- [ ] AC2: `POST /api/v1/invites/` with `role=org_admin` by org_admin → role capped at `tenant_admin`
- [ ] AC3: `POST /api/v1/invites/{token}/accept/` where invite tenant is from foreign org → role capped at `viewer`, response includes `cross_org: true`
- [ ] AC4: Expired invite (> 7 days old) → 410
- [ ] AC5: Accepting valid same-org invite → `TenantUsers` row created with correct role
- [ ] AC6: Invite token must be single-use — second accept → 409 or 404

## Definition of Done
- [ ] `InviteCreateView` and `InviteAcceptView` implemented with RBAC
- [ ] `create_invite_token()` uses `secrets.token_urlsafe(32)`
- [ ] `accept_invite_membership()` called from AcceptView (B4 story provides the function)
- [ ] Tests: cross-org cap, expired token, single-use enforcement, foreign tenant 404
- [ ] `log_auth_event("invite.cross_org_capped")` emitted on cross-org accept
- [ ] bmad-security-reviewer: no BLOCKERs
