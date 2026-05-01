# BE-01: Django — Add `PATCH /api/auth/me/`

## Status
Ready for dev

## Context
`MeView` in the Django auth backend (`platform/cspm-backend/user_auth/views/local_auth.py`) only implements `GET`. The frontend profile page needs to update the user's name, but there is no PATCH endpoint. Sending a PATCH to `/api/auth/me/` currently returns 405 Method Not Allowed. This story adds the PATCH handler to the existing `MeView` class.

## Scope
**In scope:**
- Add `patch()` method to `MeView` in `local_auth.py`
- Accepts `{ first_name, last_name }` in request body
- Updates the `Users` model fields
- Returns the same response shape as `MeView.get()`

**Out of scope:**
- Adding email or password change to this endpoint (password change is BE-02)
- Adding phone number (not in the Users model)
- Adding any new URL routes (PATCH to the same URL as GET)
- Changing the `Users` model schema

## Technical Notes

### Files to read before implementing
```bash
# The main view file:
cat /Users/apple/Desktop/threat-engine/platform/cspm-backend/user_auth/views/local_auth.py

# The Users model:
cat /Users/apple/Desktop/threat-engine/platform/cspm-backend/user_auth/models.py
# or wherever the Users model is defined — grep:
grep -rn "class Users\|class User(" /Users/apple/Desktop/threat-engine/platform/cspm-backend/ --include="*.py"

# The URL routing:
cat /Users/apple/Desktop/threat-engine/platform/cspm-backend/user_auth/urls.py
```

### MeView current GET response shape (confirmed from source)
```json
{
  "id": "<uuid>",
  "email": "user@example.com",
  "name": "First Last",
  "sso_provider": "local",
  "tenants": [{ "tenant_id": "...", "tenant_name": "...", "role": "...", "status": "..." }]
}
```
The PATCH must return the same shape after updating.

### Implementation pattern
```python
class MeView(APIView):
    permission_classes = [IsAuthenticated]  # confirm exact class used in existing GET

    def get(self, request):
        # existing implementation — do not modify
        ...

    def patch(self, request):
        user = request.user  # or however the existing GET gets the user

        # Accepted fields only — reject any other fields silently or with validation error
        allowed_fields = {'first_name', 'last_name'}
        update_data = {k: v for k, v in request.data.items() if k in allowed_fields}

        if not update_data:
            return Response(
                {"error": "No valid fields provided. Accepted: first_name, last_name"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Validate: names must be non-empty strings if provided
        for field, value in update_data.items():
            if not isinstance(value, str) or not value.strip():
                return Response(
                    {"error": f"{field} must be a non-empty string"},
                    status=status.HTTP_400_BAD_REQUEST
                )

        # Apply updates
        for field, value in update_data.items():
            setattr(user, field, value.strip())
        user.save(update_fields=list(update_data.keys()))

        # Return same shape as GET
        return self.get(request)
```

Note: Confirm the exact attribute names on the `Users` model. If the model uses `name` as a single field (not `first_name`/`last_name` separately), adjust accordingly. Read the model first.

### `name` field in response
The GET response returns `"name": "First Last"` (single string). If the model stores `first_name` and `last_name` separately, the PATCH accepts them separately but the GET response builds the combined string. If the model stores `name` as a single field, accept `name` in PATCH instead.

The dev **must read the model** before deciding the field names.

### Authentication
The PATCH endpoint must require authentication — use the same `permission_classes` as the existing `get()` method. Do not add any new auth logic.

### URL routing
No URL change needed. Django class-based views on a single URL handle multiple HTTP methods via method names on the class. The `MeView` is already registered at `/api/auth/me/` — adding `patch()` to the class automatically enables `PATCH /api/auth/me/`.

Verify the URL registration:
```bash
grep -n "MeView\|me/" /Users/apple/Desktop/threat-engine/platform/cspm-backend/user_auth/urls.py
```

## Implementation Steps

1. Read `user_auth/views/local_auth.py` to understand the full `MeView` class and how `get()` builds its response
2. Read the `Users` model to confirm field names (`first_name`/`last_name` vs `name`)
3. Read `user_auth/urls.py` to confirm `MeView` is already registered at `me/`
4. Add `patch()` method to `MeView` as shown above (adjusted for actual model field names)
5. Restart the Django server locally
6. Test with curl (see Test section)
7. Confirm existing `GET /api/auth/me/` still works after the change

## Acceptance Criteria

**Given** an authenticated user sends `PATCH /api/auth/me/` with `{ "first_name": "Jane" }`
**When** Django processes the request
**Then** HTTP 200 is returned, the response body `name` field reflects the new name, and the `Users` DB row is updated

**Given** an authenticated user sends `PATCH /api/auth/me/` with `{ "first_name": "" }`
**When** Django processes the request
**Then** HTTP 400 is returned with a validation error message

**Given** an unauthenticated request (no token) sends `PATCH /api/auth/me/`
**When** Django processes the request
**Then** HTTP 401 or 403 is returned (same as unauthenticated GET)

**Given** the request body contains an unrecognised field `{ "phone": "123" }`
**When** Django processes the request
**Then** the unrecognised field is ignored (not saved), HTTP 400 returned with clear message about no valid fields

## Test / Validation
```bash
# Step 1: Get an access token by logging in
TOKEN=$(curl -s -X POST http://localhost:8008/api/auth/login/ \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@cspm.local","password":"Admin@12345"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Step 2: Verify current name
curl -s -b "access_token=$TOKEN" http://localhost:8008/api/auth/me/ | python3 -m json.tool

# Step 3: Update name
curl -s -X PATCH http://localhost:8008/api/auth/me/ \
  -b "access_token=$TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"first_name": "Jane"}' | python3 -m json.tool
# Expected: HTTP 200, name field updated in response

# Step 4: Verify persistence
curl -s -b "access_token=$TOKEN" http://localhost:8008/api/auth/me/ \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['name'])"
# Expected: "Jane <LastName>" (whatever last name was before)

# Step 5: Test validation
curl -s -X PATCH http://localhost:8008/api/auth/me/ \
  -b "access_token=$TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"first_name": ""}' | python3 -m json.tool
# Expected: HTTP 400 with error message
```

## Definition of Done
- [ ] `patch()` method added to `MeView` in `local_auth.py`
- [ ] Accepts `first_name` and/or `last_name` (based on actual model field names)
- [ ] Validates fields are non-empty strings
- [ ] Saves to `Users` model with `update_fields` (targeted save, not full save)
- [ ] Returns same response shape as `GET /api/auth/me/`
- [ ] Requires authentication (same as GET)
- [ ] Existing `GET /api/auth/me/` unchanged
- [ ] Curl test: PATCH with valid data → 200, DB row updated
- [ ] Curl test: PATCH with empty string → 400

## Points
2

## Dependencies
None — this is a Wave 1 story, start immediately.