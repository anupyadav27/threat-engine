"""
Unit tests for onboarding-D4 — Org profile + tenant-type API.

AC10 coverage (5 test cases):
  1. GET /api/org/profile/ returns org_name, contact_email, plan for authenticated user (AC1)
  2. PATCH /api/org/profile/ updates org_name; customer_id/plan are rejected (AC2, AC3)
  3. PATCH /api/tenants/{id}/type/ with invalid tenant_type returns 422 (AC5, AC6)
  4. GET /internal/tenants/{id}/type with valid X-Internal-Secret returns 200 (AC7)
  5. GET /internal/tenants/{id}/type without X-Internal-Secret returns 401 (AC7)

Run with:
    pytest platform/cspm-backend/tenant_management/tests/test_org_profile_and_tenant_type.py -v
"""

import os
import uuid
from datetime import timedelta
from unittest.mock import patch

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

import django

django.setup()

from django.test import TestCase, Client, override_settings
from django.utils import timezone


# ---------------------------------------------------------------------------
# Shared helpers (mirror test_group_management.py pattern)
# ---------------------------------------------------------------------------


def _make_user(email: str, customer_id: str = None):
    """Create an active Users row."""
    from user_auth.models import Users

    u = Users.objects.create_user(
        email=email,
        password="Test1234!",
        status="active",
    )
    cid = customer_id or str(u.id)
    u.customer_id = cid
    u.save(update_fields=["customer_id"])
    return u


def _assign_role(user, role_name: str, level: int = 2):
    """Assign a named role to a user. Requires seed migration 0009."""
    from user_auth.models import Roles, UserRoles

    try:
        role = Roles.objects.get(name=role_name)
    except Roles.DoesNotExist:
        role = Roles.objects.create(name=role_name, level=level)
    UserRoles.objects.get_or_create(user=user, role=role)
    return role


def _make_session(user) -> str:
    """Create a UserSessions row and return the raw access token."""
    from user_auth.models import UserSessions
    from user_auth.utils.auth_utils import (
        compute_auth_caches,
        generate_token,
        hash_token,
    )

    raw_token = generate_token()
    permissions_cache, scope_cache = compute_auth_caches(user)
    UserSessions.objects.create(
        id=uuid.uuid4(),
        user=user,
        token=hash_token(raw_token),
        refresh_token=hash_token(generate_token()),
        login_method="local",
        expires_at=timezone.now() + timedelta(days=1),
        ip_address="127.0.0.1",
        user_agent="test",
        token_hint=raw_token[:8],
        permissions_cache=permissions_cache,
        scope_cache=scope_cache,
    )
    return raw_token


def _make_tenant(customer_id: str, name: str = "Acme Corp") -> "Tenants":
    """Create a Tenants row owned by customer_id."""
    from tenant_management.models import Tenants

    tid = str(uuid.uuid4())
    return Tenants.objects.create(
        id=tid,
        engine_tenant_id=tid,
        name=name,
        status="active",
        tenant_type="cloud",
        customer_id=customer_id,
        plan="trial",
        contact_email="admin@acme.local",
    )


def _authed_client(user) -> tuple:
    """Return (Client, raw_token) with access_token cookie set."""
    token = _make_session(user)
    c = Client()
    c.cookies["access_token"] = token
    return c, token


# ---------------------------------------------------------------------------
# AC10-1: GET /api/org/profile/ returns org profile
# ---------------------------------------------------------------------------


class OrgProfileGetTest(TestCase):
    """AC1: GET /api/org/profile/ returns customer_id, org_name, contact_email, plan."""

    def setUp(self):
        self.cid = str(uuid.uuid4())
        self.user = _make_user("orgadmin@acme.local", customer_id=self.cid)
        _assign_role(self.user, "org_admin", level=2)
        self.tenant = _make_tenant(self.cid, name="Acme Corp")
        self.client_a, _ = _authed_client(self.user)

    def test_get_returns_org_profile_fields(self):
        """AC1: response includes customer_id, org_name, contact_email, plan."""
        resp = self.client_a.get("/api/org/profile/")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["customer_id"], self.cid)
        self.assertEqual(data["org_name"], "Acme Corp")
        self.assertEqual(data["contact_email"], "admin@acme.local")
        self.assertEqual(data["plan"], "trial")

    def test_unauthenticated_returns_401_or_403(self):
        """Unauthenticated access is rejected."""
        anon = Client()
        resp = anon.get("/api/org/profile/")
        self.assertIn(resp.status_code, (401, 403))


# ---------------------------------------------------------------------------
# AC10-2: PATCH /api/org/profile/ — update org_name; reject read-only fields
# ---------------------------------------------------------------------------


class OrgProfilePatchTest(TestCase):
    """AC2/AC3: PATCH /api/org/profile/ updates org_name; customer_id/plan are rejected."""

    def setUp(self):
        self.cid = str(uuid.uuid4())
        self.user = _make_user("orgadmin2@acme.local", customer_id=self.cid)
        _assign_role(self.user, "org_admin", level=2)
        self.tenant = _make_tenant(self.cid, name="Old Name Inc")
        self.client_a, _ = _authed_client(self.user)

    def test_patch_org_name_succeeds(self):
        """AC2: PATCH with org_name updates the tenant name."""
        import json

        resp = self.client_a.patch(
            "/api/org/profile/",
            data=json.dumps({"org_name": "New Name LLC"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data.get("updated"))

        # Verify DB was updated.
        from tenant_management.models import Tenants

        self.tenant.refresh_from_db()
        self.assertEqual(self.tenant.name, "New Name LLC")

    def test_patch_customer_id_is_rejected(self):
        """AC3: PATCH attempt to change customer_id returns 400."""
        import json

        resp = self.client_a.patch(
            "/api/org/profile/",
            data=json.dumps({"customer_id": "cust_evil"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 400)
        body = resp.json()
        self.assertIn("read-only", body.get("detail", "").lower())

    def test_patch_plan_is_rejected(self):
        """AC3: PATCH attempt to change plan returns 400."""
        import json

        resp = self.client_a.patch(
            "/api/org/profile/",
            data=json.dumps({"plan": "enterprise"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 400)


# ---------------------------------------------------------------------------
# AC10-3: PATCH /api/tenants/{id}/type/ with invalid tenant_type → 422
# ---------------------------------------------------------------------------


class TenantTypePatchInvalidTest(TestCase):
    """AC5/AC6: invalid tenant_type value returns 422."""

    def setUp(self):
        self.cid = str(uuid.uuid4())
        self.user = _make_user("orgadmin3@acme.local", customer_id=self.cid)
        _assign_role(self.user, "org_admin", level=2)
        self.tenant = _make_tenant(self.cid)
        self.client_a, _ = _authed_client(self.user)

    def test_invalid_tenant_type_returns_422(self):
        """AC6: non-enum value returns 422."""
        import json

        resp = self.client_a.patch(
            f"/api/tenants/{self.tenant.id}/type/",
            data=json.dumps({"tenant_type": "invalid_type"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 422)

    def test_valid_tenant_type_update_succeeds(self):
        """AC5: valid tenant_type value is accepted."""
        import json

        resp = self.client_a.patch(
            f"/api/tenants/{self.tenant.id}/type/",
            data=json.dumps({"tenant_type": "secops"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["tenant_type"], "secops")

    def test_cross_org_tenant_returns_404(self):
        """AC8: tenant from a different org returns 404."""
        import json

        other_cid = str(uuid.uuid4())
        other_tenant = _make_tenant(other_cid, name="Other Org")

        resp = self.client_a.patch(
            f"/api/tenants/{other_tenant.id}/type/",
            data=json.dumps({"tenant_type": "cloud"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 404)


# ---------------------------------------------------------------------------
# AC10-4 & AC10-5: GET /internal/tenants/{id}/type — X-Internal-Secret auth
# ---------------------------------------------------------------------------


_INTERNAL_SECRET = "test-internal-secret-d4-abc123"


class InternalTenantTypeViewTest(TestCase):
    """AC7: internal endpoint returns tenant_type with valid secret; 401 without."""

    def setUp(self):
        self.cid = str(uuid.uuid4())
        self.tenant = _make_tenant(self.cid, name="Internal Test Org")

    @override_settings()
    def test_valid_secret_returns_tenant_type(self):
        """AC7/AC10-4: valid X-Internal-Secret returns 200 with tenant_type."""
        with patch.dict(os.environ, {"X_INTERNAL_SECRET": _INTERNAL_SECRET}):
            c = Client()
            resp = c.get(
                f"/internal/tenants/{self.tenant.id}/type",
                HTTP_X_INTERNAL_SECRET=_INTERNAL_SECRET,
            )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["tenant_type"], "cloud")

    @override_settings()
    def test_missing_secret_returns_401(self):
        """AC7/AC10-5: missing X-Internal-Secret header returns 401."""
        with patch.dict(os.environ, {"X_INTERNAL_SECRET": _INTERNAL_SECRET}):
            c = Client()
            resp = c.get(f"/internal/tenants/{self.tenant.id}/type")
        self.assertEqual(resp.status_code, 401)

    @override_settings()
    def test_wrong_secret_returns_401(self):
        """AC7: wrong secret value returns 401."""
        with patch.dict(os.environ, {"X_INTERNAL_SECRET": _INTERNAL_SECRET}):
            c = Client()
            resp = c.get(
                f"/internal/tenants/{self.tenant.id}/type",
                HTTP_X_INTERNAL_SECRET="wrong-secret-xyz",
            )
        self.assertEqual(resp.status_code, 401)

    def test_nonexistent_tenant_returns_404(self):
        """AC7: valid secret but unknown tenant_id returns 404."""
        with patch.dict(os.environ, {"X_INTERNAL_SECRET": _INTERNAL_SECRET}):
            c = Client()
            resp = c.get(
                f"/internal/tenants/{uuid.uuid4()}/type",
                HTTP_X_INTERNAL_SECRET=_INTERNAL_SECRET,
            )
        self.assertEqual(resp.status_code, 404)
