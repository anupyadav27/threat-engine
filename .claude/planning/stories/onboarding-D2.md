---
id: onboarding-D2
title: "User invite flow API (Django)"
sprint: D
points: 2
depends_on: [auth-A2]
blocks: [onboarding-D12]
security_blocks: []
nist_csf: PR.AC
owasp_samm: Implementation
csa_ccm: AIS-04
---

## Context

The platform has no user invite mechanism — every user currently registers via self-service. The PRD mandates that all users are invite-provisioned (self-service signup is disabled via `ALLOW_LOCAL_SIGNUP=false`). This story implements the invite flow: org_admin or platform_admin sends an invite to an email address specifying a role. The system creates a pending user record, sends an SES email with an accept link (containing a time-limited token), and the user activates their account by clicking the link. The accept endpoint validates the token, sets the password (or skips if using Google/SAML), and marks the user active. Depends on auth-A2 because the invite must set `customer_id` on the new user using the inviter's `customer_id`.

## Acceptance Criteria

- [ ] AC1: `POST /api/users/invite` endpoint exists in Django, requires `users:write` permission.
- [ ] AC2: Request body: `{"email": "user@example.com", "role": "tenant_admin", "group_id": "<optional>"}`. `customer_id` is NOT in request body — set server-side from `request.user.customer_id`.
- [ ] AC3: If email already exists in the org (same `customer_id`), return HTTP 409 with `{"detail": "User already exists in this org"}`.
- [ ] AC4: If email already exists in a DIFFERENT org (`customer_id` differs), return HTTP 422 with `{"detail": "Email is registered to a different org — cross-org invite not supported"}`.
- [ ] AC5: A pending user record is created in `user_auth_users` with `customer_id = request.user.customer_id`, `is_active=False`, `role=<requested_role>`.
- [ ] AC6: An invite token (UUID4, 72-hour TTL) is generated and stored (hashed) alongside the pending user record.
- [ ] AC7: SES email is sent from `FROM_EMAIL` env var to the invited email with a link: `https://<PLATFORM_URL>/auth/accept-invite?token=<raw_token>`.
- [ ] AC8: `POST /api/users/invite/accept` endpoint exists (no auth required — public endpoint using the invite token).
- [ ] AC9: Accept endpoint validates the token, marks user `is_active=True`, returns 200 with a session cookie set (or redirect to login for SSO users).
- [ ] AC10: Expired tokens (>72 hours) return HTTP 410 `{"detail": "Invite link expired"}`.
- [ ] AC11: Unit tests: invite new user; duplicate within org → 409; cross-org → 422; accept with valid token → 200; accept with expired token → 410.

## Key Files

- `platform/cspm-backend/user_auth/views/invite.py` — Create: invite send and accept endpoints
- `platform/cspm-backend/user_auth/models.py` — Add `InviteToken` model (or field on User)
- `platform/cspm-backend/user_auth/urls.py` — Wire invite and accept URLs
- `platform/cspm-backend/user_auth/tasks.py` — Celery task for async SES send

## Technical Notes

**InviteToken model (Django):**
```python
class InviteToken(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    token_hash = models.CharField(max_length=64, unique=True)  # SHA-256
    role = models.CharField(max_length=50)
    group_id = models.CharField(max_length=255, null=True, blank=True)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
```

**Invite send view:**
```python
class InviteView(APIView):
    authentication_classes = [CookieTokenAuthentication]
    # permission: users:write

    def post(self, request):
        email = request.data["email"]
        role = request.data["role"]
        customer_id = request.user.customer_id  # server-side, not from body

        # Check duplicate
        existing = User.objects.filter(email=email).first()
        if existing:
            if existing.customer_id == customer_id:
                return Response({"detail": "User already exists in this org"}, status=409)
            else:
                return Response({"detail": "Email is registered to a different org"}, status=422)

        # Create pending user
        user = User.objects.create(
            email=email, customer_id=customer_id, role=role, is_active=False
        )

        # Generate token
        raw_token = str(uuid4())
        token_hash = sha256(raw_token.encode()).hexdigest()
        InviteToken.objects.create(
            user=user,
            token_hash=token_hash,
            role=role,
            expires_at=now() + timedelta(hours=72),
        )

        # Send invite email (async Celery task)
        send_invite_email.delay(email, raw_token)
        return Response({"invited": email}, status=201)
```

**Accept view:**
```python
class InviteAcceptView(APIView):
    authentication_classes = []  # public endpoint
    permission_classes = []

    def post(self, request):
        raw_token = request.data.get("token")
        token_hash = sha256(raw_token.encode()).hexdigest()
        try:
            invite = InviteToken.objects.select_related('user').get(token_hash=token_hash)
        except InviteToken.DoesNotExist:
            return Response({"detail": "Invalid invite token"}, status=400)

        if invite.expires_at < now():
            return Response({"detail": "Invite link expired"}, status=410)

        invite.user.is_active = True
        invite.user.save(update_fields=['is_active'])
        invite.delete()

        # Create session / return cookie
        return Response({"status": "activated"}, status=200)
```

**SES Celery task:**
```python
@shared_task
def send_invite_email(email: str, raw_token: str):
    platform_url = os.environ["PLATFORM_URL"]
    accept_url = f"{platform_url}/auth/accept-invite?token={raw_token}"
    ses.send_email(
        Source=os.environ["FROM_EMAIL"],
        Destination={"ToAddresses": [email]},
        Message={
            "Subject": {"Data": "You've been invited to Onam Security"},
            "Body": {"Text": {"Data": f"Accept your invite: {accept_url}"}},
        }
    )
```

**FROM_EMAIL and PLATFORM_URL** must be set as K8s env vars in the cspm-backend Deployment. `FROM_EMAIL` must be SES-verified in `ap-south-1`.

**No `org_id` anywhere** — use `customer_id` throughout.

## Security Checklist

- [ ] `customer_id` set server-side from authenticated user — never from request body
- [ ] Raw invite token never stored in DB — only SHA-256 hash
- [ ] Accept endpoint is public — but validates time-limited token
- [ ] SES `FROM_EMAIL` from env var, not hardcoded
- [ ] Cross-org invite returns 422 (not 200 silently)
- [ ] bmad-security-reviewer gate passed before merge

## Definition of Done

- [ ] All ACs pass
- [ ] `grep -r "organizations\|org_id" platform/` returns no new hits
- [ ] Unit tests: 5 test cases (AC11)
- [ ] bmad-security-reviewer: no BLOCKERs
- [ ] `kubectl rollout status deployment/cspm-backend -n threat-engine-engines` shows AVAILABLE
- [ ] `kubectl logs -l app=cspm-backend -n threat-engine-engines` shows no ERROR in first 60s
- [ ] Post-deploy: invite email sent; accept link activates user