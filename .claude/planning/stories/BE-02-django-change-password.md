# BE-02: Django — Add `POST /api/auth/change-password/`

## Status
Ready for dev

## Context
The frontend profile page has a "Change Password" form but there is no backend endpoint to handle it. The existing Django auth code only has a token-based password reset flow (`/api/auth/password-reset/`), which requires the user to be logged out and know their email. The missing endpoint is a simple authenticated change-password — user supplies their current password plus a new password, and the backend validates and updates it. All existing sessions must be invalidated after the change to prevent session hijacking with a stolen old token.

## Scope
**In scope:**
- New `ChangePasswordView` class in `platform/cspm-backend/user_auth/views/local_auth.py`
- New URL at `POST /api/auth/change-password/`
- Validate current password using `check_password()`
- Set new password using `set_password()`
- Invalidate all `UserSessions` for the user after password change
- Return HTTP 200 on success, HTTP 400 on wrong current password

**Out of scope:**
- Token-based reset flow (already exists, do not touch)
- Email notifications on password change (out of scope)
- Password strength policy enforcement beyond basic non-empty check

## Technical Notes

### Files to read before implementing
```bash
# The auth views file:
cat /Users/apple/Desktop/threat-engine/platform/cspm-backend/user_auth/views/local_auth.py

# The Users model and UserSessions model:
grep -rn "class UserSessions\|class Users\|class UserSession" \
  /Users/apple/Desktop/threat-engine/platform/cspm-backend/ --include="*.py" -l
# Read those model files

# URL routing:
cat /Users/apple/Desktop/threat-engine/platform/cspm-backend/user_auth/urls.py
```

### `UserSessions` model
Read the model to understand its fields. It will have at minimum: `user`, `session_token` (or `access_token`), and possibly `expires_at`. Invalidating sessions means either:
- `UserSessions.objects.filter(user=user).delete()` — hard delete all sessions
- OR set an `is_valid=False` / `invalidated_at=now()` field if the model has one

Check the model first and use whichever approach fits the existing schema.

### Implementation
```python
class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]  # use same class as MeView

    def post(self, request):
        current_password = request.data.get('current_password', '')
        new_password = request.data.get('new_password', '')

        # Validate inputs
        if not current_password or not new_password:
            return Response(
                {"error": "current_password and new_password are required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        if len(new_password) < 8:
            return Response(
                {"error": "new_password must be at least 8 characters"},
                status=status.HTTP_400_BAD_REQUEST
            )

        user = request.user

        # Validate current password
        if not user.check_password(current_password):
            return Response(
                {"error": "Current password incorrect"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Set new password
        user.set_password(new_password)
        user.save()

        # Invalidate all sessions for this user (force re-login on all devices)
        # Use .delete() or .update(is_valid=False) depending on the model
        UserSessions.objects.filter(user=user).delete()

        return Response(
            {"message": "Password changed successfully. Please log in again."},
            status=status.HTTP_200_OK
        )
```

### Import the `UserSessions` model
```python
from user_auth.models import UserSessions  # adjust path based on where models are defined
```
Confirm the import by reading the existing code in `local_auth.py` — other views likely already import from the models file.

### URL registration in `urls.py`
```python
from .views.local_auth import ChangePasswordView

urlpatterns = [
    # existing patterns...
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),
]
```

### Authentication
The user must be authenticated to call this endpoint — they use their current session token. The `IsAuthenticated` permission class handles this. Do not allow unauthenticated access.

### Security note
After `user.set_password(new_password)` and `user.save()`, the current request's session token is still valid (because the token is checked before password change). By deleting all `UserSessions`, the next request from the user with the old token will fail authentication — this is the intended behaviour (forces re-login).

## Implementation Steps

1. Read `local_auth.py` — understand the `IsAuthenticated` class used, how `request.user` is populated
2. Read the `Users` and `UserSessions` models — note the session invalidation approach
3. Read `user_auth/urls.py` to understand the url pattern format
4. Add `ChangePasswordView` class to `local_auth.py`
5. Import `ChangePasswordView` in `urls.py` and add `path('change-password/', ...)`
6. Restart Django server
7. Run the curl tests below

## Acceptance Criteria

**Given** an authenticated user sends `POST /api/auth/change-password/` with correct `current_password` and a valid `new_password`
**When** Django processes the request
**Then** HTTP 200 is returned and the user's password in the DB is updated

**Given** the same user's old token after a successful password change
**When** they call `GET /api/auth/me/` using the old token
**Then** HTTP 401 or 403 is returned (old session invalidated)

**Given** the user sends `POST /api/auth/change-password/` with an incorrect `current_password`
**When** Django processes the request
**Then** HTTP 400 is returned with `{"error": "Current password incorrect"}`

**Given** the user sends `POST /api/auth/change-password/` with `new_password` shorter than 8 chars
**When** Django processes the request
**Then** HTTP 400 is returned with an error about minimum length

**Given** an unauthenticated request (no token) to `POST /api/auth/change-password/`
**When** Django processes the request
**Then** HTTP 401 or 403 is returned

## Test / Validation
```bash
# Step 1: Login to get token
TOKEN=$(curl -s -X POST http://localhost:8008/api/auth/login/ \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@cspm.local","password":"Admin@12345"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Step 2: Change password
curl -s -X POST http://localhost:8008/api/auth/change-password/ \
  -b "access_token=$TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"current_password": "Admin@12345", "new_password": "NewPass@9876"}' \
  | python3 -m json.tool
# Expected: HTTP 200 {"message": "Password changed successfully..."}

# Step 3: Verify old token no longer works
curl -s -b "access_token=$TOKEN" http://localhost:8008/api/auth/me/
# Expected: HTTP 401 or 403

# Step 4: Login with new password
NEW_TOKEN=$(curl -s -X POST http://localhost:8008/api/auth/login/ \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@cspm.local","password":"NewPass@9876"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
echo "New token: $NEW_TOKEN"
# Expected: valid token returned

# Step 5: Reset password back for other tests
curl -s -X POST http://localhost:8008/api/auth/change-password/ \
  -b "access_token=$NEW_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"current_password": "NewPass@9876", "new_password": "Admin@12345"}'

# Step 6: Wrong current password test
curl -s -X POST http://localhost:8008/api/auth/change-password/ \
  -b "access_token=$NEW_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"current_password": "WRONGPASSWORD", "new_password": "NewPass@9876"}' \
  | python3 -m json.tool
# Expected: HTTP 400 {"error": "Current password incorrect"}
```

## Definition of Done
- [ ] `ChangePasswordView` class added to `local_auth.py`
- [ ] `POST /api/auth/change-password/` registered in `urls.py`
- [ ] Requires authentication (unauthenticated → 401/403)
- [ ] Wrong current password → HTTP 400 with `{"error": "Current password incorrect"}`
- [ ] Short new password → HTTP 400 with error message
- [ ] Correct flow → HTTP 200, password updated in DB
- [ ] All `UserSessions` for the user deleted after successful change
- [ ] Old token returns 401 after password change
- [ ] New password works for login

## Points
3

## Dependencies
None — this is a Wave 1 story, start immediately.