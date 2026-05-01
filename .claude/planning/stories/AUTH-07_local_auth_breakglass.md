---
story_id: AUTH-07
title: Restrict local auth to break-glass accounts
status: ready
sprint: auth-redesign-1
depends_on: []
blocks: []
sme: Django/Python backend engineer
estimate: 0.5 day
---

# Story: Restrict Local Auth to Break-Glass Accounts

## Context

The platform currently allows any user to sign up with email/password via `POST /api/auth/signup/`.
This creates an attack surface for credential stuffing and phishing. With Google-first + IDP auth,
local passwords are only needed as a break-glass mechanism for platform operators who need access
when all IDPs are unavailable.

This story:
1. Adds `is_break_glass` flag to `Users` model
2. Disables public signup by default (controlled by `ALLOW_LOCAL_SIGNUP` env var)
3. Hides local login form on the login page unless `?method=local` param is present
4. Retains password reset and change-password for break-glass accounts

## Files to Create/Modify

- `platform/cspm-backend/user_auth/models.py` — add `is_break_glass` field
- `platform/cspm-backend/user_auth/migrations/0007_users_is_break_glass.py` — NEW migration
- `platform/cspm-backend/user_auth/views/local_auth.py` — disable SignupView in prod
- `platform/cspm-backend/config/settings.py` — add `ALLOW_LOCAL_SIGNUP` env var

## Implementation Notes

### Model Change

Add to `Users` model:
```python
is_break_glass = models.BooleanField(default=False)
```

This field is `False` for all existing users. Platform operators set it to `True` manually
via Django admin for emergency accounts.

### Disable SignupView

In `user_auth/views/local_auth.py`, `SignupView.post()`:

```python
ALLOW_LOCAL_SIGNUP = os.getenv("ALLOW_LOCAL_SIGNUP", "false").lower() in ("true", "1", "yes")

class SignupView(APIView):
    def post(self, request):
        if not ALLOW_LOCAL_SIGNUP:
            return JsonResponse(
                {"message": "Local account creation is disabled. Use SSO to sign in."},
                status=403
            )
        # ... existing signup logic
```

Default in production K8s manifests: `ALLOW_LOCAL_SIGNUP=false`
Default in local development (`.env`): `ALLOW_LOCAL_SIGNUP=true`

### Migration

```python
# 0007_users_is_break_glass.py
from django.db import migrations, models

class Migration(migrations.Migration):
    dependencies = [
        ('user_auth', '0006_invite_and_password_reset_tokens'),
    ]
    operations = [
        migrations.AddField(
            model_name='users',
            name='is_break_glass',
            field=models.BooleanField(default=False),
        ),
    ]
```

### Login Page Behavior (frontend note for AUTH-08)

The frontend should:
- Default view: show only "Sign in with Google" + "Sign in with SSO" buttons
- Show local auth form only when URL contains `?method=local`
- Add a small "Admin login" link at the bottom that navigates to `?method=local`

This story does not implement the frontend change — that is AUTH-08. This story only
implements the backend gate.

### Password Reset and Change-Password

No changes needed. Both `PasswordResetRequestView` and `ChangePasswordView` are retained
as-is. They work for break-glass accounts and for users who set passwords before this change.

## Reference Files

- `platform/cspm-backend/user_auth/models.py` — Users model
- `platform/cspm-backend/user_auth/views/local_auth.py` — SignupView to modify
- `platform/cspm-backend/user_auth/migrations/0006_invite_and_password_reset_tokens.py` — latest migration

## Acceptance Criteria

- [ ] AC1: `POST /api/auth/signup/` returns 403 when `ALLOW_LOCAL_SIGNUP` env var is `false` or unset
- [ ] AC2: `POST /api/auth/signup/` succeeds when `ALLOW_LOCAL_SIGNUP=true`
- [ ] AC3: `Users` table has `is_break_glass` column (boolean, default false) after migration
- [ ] AC4: Existing users are not affected — all existing rows have `is_break_glass=false`
- [ ] AC5: `POST /api/auth/login/` (existing local login) still works for users with a local password

## Definition of Done

- [ ] Migration committed alongside model change
- [ ] `ALLOW_LOCAL_SIGNUP=false` set in production K8s ConfigMap or manifest
- [ ] `ALLOW_LOCAL_SIGNUP=true` remains default in local `.env` / dev setup
- [ ] Story accepted by SM before merge