"""
BILL-S07 — Invite endpoint consolidation regression tests.

Verifies that:
- The old /api/auth/invite/create/ URL returns 404 (removed)
- The surviving /api/v1/invites/ endpoint works with correct auth
- Unauthenticated POST returns 401/403
- Cross-org tenant_id returns 404
- Inviter role cap is enforced
- Token expiry is 48 hours (not 7 days)
- ValidateInviteView (GET /api/auth/invite/{token}/) still works
- AcceptInviteView (POST /api/auth/invite/{token}/accept/) still works

Run with:
    pytest platform/cspm-backend/user_auth/tests/test_invite_endpoint_consolidation.py -v
"""
import json
import os
import secrets
import uuid
from datetime import timedelta
from unittest.mock import patch

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

import django
django.setup()

from django.test import TestCase, Client
from django.utils import timezone


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_user(email: str, customer_id: str | None = None) -> "Users":
    """Create a Users row with an explicit customer_id."""
    from user_auth.models import Users
    u = Users.objects.create_user(email=email, password="TestPass123!", status="active")
    cid = customer_id or str(u.id)
    u.customer_id = cid
    u.save(update_fields=["customer_id"])
    return u


def _make_tenant(customer_id: str) -> "Tenants":
    """Create a Tenants row owned by customer_id."""
    from tenant_management.models import Tenants
    tid = str(uuid.uuid4())
    return Tenants.objects.create(
        id=tid,
        engine_tenant_id=tid,
        name=f"Test Tenant {tid[:8]}",
        status="active",
        tenant_type="cloud",
        customer_id=customer_id,
        plan="trial",
        contact_email="admin@test.local",
    )


def _make_session(user) -> str:
    """Create a UserSessions row and return the raw access token."""
    from user_auth.models import UserSessions
    from user_auth.utils.auth_utils import generate_token, hash_token, compute_auth_caches

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


def _assign_role(user, role_name: str):
    """Assign a named role to a user (requires seed migration 0009)."""
    from user_auth.models import Roles, UserRoles
    try:
        role = Roles.objects.get(name=role_name)
    except Roles.DoesNotExist:
        return None
    UserRoles.objects.get_or_create(user=user, role=role)
    return role


def _make_invite(invited_by, tenant, token: str | None = None, used: bool = False) -> "InviteTokens":
    """Create an InviteTokens row."""
    from user_auth.models import InviteTokens
    raw = token or secrets.token_urlsafe(32)
    return InviteTokens.objects.create(
        id=str(uuid.uuid4()),
        token=raw,
        email="invitee@test.local",
        tenant=tenant,
        invited_by=invited_by,
        expires_at=timezone.now() + timedelta(hours=48),
        used=used,
    )


# ── Test cases ────────────────────────────────────────────────────────────────

class TestOldCreateUrlReturns404(TestCase):
    """SEC-01 / AC-1: POST to removed URL returns 404."""

    def test_old_create_url_returns_404(self):
        client = Client()
        response = client.post(
            "/api/auth/invite/create/",
            data=json.dumps({"email": "x@test.local", "tenant_id": "any"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 404)


class TestNewCreateUrlUnauthenticatedReturns401(TestCase):
    """SEC-02 / AC-3: POST to surviving endpoint without credentials returns 401 or 403."""

    def test_new_create_url_unauthenticated_returns_401(self):
        client = Client()
        response = client.post(
            "/api/v1/invites/",
            data=json.dumps({"email": "x@test.local", "tenant_id": "any"}),
            content_type="application/json",
        )
        self.assertIn(response.status_code, (401, 403))


class TestNewCreateUrlWorksWithAuth(TestCase):
    """AC-2: POST to surviving endpoint with valid auth returns 201."""

    def test_new_create_url_works_with_auth(self):
        from user_auth.models import InviteTokens

        customer_id = str(uuid.uuid4())
        inviter = _make_user("inviter-new-url@test.local", customer_id=customer_id)
        _assign_role(inviter, "org_admin")
        tenant = _make_tenant(customer_id=customer_id)
        raw_token = _make_session(inviter)

        with patch("user_auth.utils.email_utils.send_invite_email"):
            client = Client()
            client.cookies["access_token"] = raw_token
            response = client.post(
                "/api/v1/invites/",
                data=json.dumps({
                    "email": "invitee-new-url@test.local",
                    "tenant_id": str(tenant.id),
                    "role": "viewer",
                }),
                content_type="application/json",
            )

        self.assertEqual(response.status_code, 201, response.content)
        data = response.json()
        self.assertIn("id", data)
        self.assertIn("email", data)
        self.assertIn("expires_at", data)


class TestCrossOrgTenantReturns404(TestCase):
    """SEC-03 / AC-4: tenant_id from a different org returns 404."""

    def test_cross_org_tenant_returns_404(self):
        org_a = str(uuid.uuid4())
        org_b = str(uuid.uuid4())

        inviter = _make_user("inviter-cross-org@test.local", customer_id=org_a)
        _assign_role(inviter, "org_admin")
        other_tenant = _make_tenant(customer_id=org_b)  # belongs to org_b
        raw_token = _make_session(inviter)

        client = Client()
        client.cookies["access_token"] = raw_token
        response = client.post(
            "/api/v1/invites/",
            data=json.dumps({
                "email": "victim@test.local",
                "tenant_id": str(other_tenant.id),
                "role": "viewer",
            }),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 404)


class TestRoleCapEnforced(TestCase):
    """SEC-04 / AC-5: analyst cannot grant org_admin — role silently capped to viewer."""

    def test_role_cap_enforced(self):
        from user_auth.models import InviteTokens, Roles

        try:
            Roles.objects.get(name="analyst")
            Roles.objects.get(name="org_admin")
            Roles.objects.get(name="viewer")
        except Roles.DoesNotExist:
            self.skipTest("Roles not seeded — run migration user_auth.0009")

        customer_id = str(uuid.uuid4())
        inviter = _make_user("inviter-cap@test.local", customer_id=customer_id)
        _assign_role(inviter, "analyst")
        tenant = _make_tenant(customer_id=customer_id)
        raw_token = _make_session(inviter)

        with patch("user_auth.utils.email_utils.send_invite_email"):
            client = Client()
            client.cookies["access_token"] = raw_token
            response = client.post(
                "/api/v1/invites/",
                data=json.dumps({
                    "email": "victim-cap@test.local",
                    "tenant_id": str(tenant.id),
                    "role": "org_admin",
                }),
                content_type="application/json",
            )

        self.assertEqual(response.status_code, 201, response.content)
        invite_id = response.json()["id"]
        invite = InviteTokens.objects.get(id=invite_id)
        self.assertIsNotNone(invite.role)
        self.assertEqual(invite.role.name, "viewer")


class TestTokenExpires48h(TestCase):
    """SEC-05 / AC-6: invite token expiry is 48 hours (not 7 days)."""

    def test_token_expires_48h(self):
        from user_auth.models import InviteTokens, Roles

        customer_id = str(uuid.uuid4())
        inviter = _make_user("inviter-expiry@test.local", customer_id=customer_id)
        _assign_role(inviter, "org_admin")
        tenant = _make_tenant(customer_id=customer_id)
        raw_token = _make_session(inviter)

        before = timezone.now()

        with patch("user_auth.utils.email_utils.send_invite_email"):
            client = Client()
            client.cookies["access_token"] = raw_token
            response = client.post(
                "/api/v1/invites/",
                data=json.dumps({
                    "email": "invitee-expiry@test.local",
                    "tenant_id": str(tenant.id),
                    "role": "viewer",
                }),
                content_type="application/json",
            )

        self.assertEqual(response.status_code, 201, response.content)
        invite = InviteTokens.objects.get(id=response.json()["id"])

        lower_bound = before + timedelta(hours=47)
        upper_bound = before + timedelta(hours=49)
        self.assertGreater(invite.expires_at, lower_bound,
            f"expires_at {invite.expires_at} should be > now+47h")
        self.assertLess(invite.expires_at, upper_bound,
            f"expires_at {invite.expires_at} should be < now+49h")


class TestValidateViewStillWorks(TestCase):
    """AC-7: GET /api/auth/invite/{token}/ (ValidateInviteView) still works."""

    def test_validate_view_still_works(self):
        inviter = _make_user("inviter-validate@test.local")
        tenant = _make_tenant(customer_id=inviter.customer_id)
        invite = _make_invite(inviter, tenant)

        client = Client()
        response = client.get(f"/api/auth/invite/{invite.token}/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["email"], "invitee@test.local")
        self.assertEqual(data["tenant_id"], str(tenant.id))


class TestAcceptViewStillWorks(TestCase):
    """AC-8: POST /api/auth/invite/{token}/accept/ (AcceptInviteView) still works."""

    def test_accept_view_still_works(self):
        inviter = _make_user("inviter-accept@test.local")
        tenant = _make_tenant(customer_id=inviter.customer_id)
        invite_email = f"accept-{uuid.uuid4().hex[:6]}@test.local"

        from user_auth.models import InviteTokens
        raw = secrets.token_urlsafe(32)
        InviteTokens.objects.create(
            id=str(uuid.uuid4()),
            token=raw,
            email=invite_email,
            tenant=tenant,
            invited_by=inviter,
            expires_at=timezone.now() + timedelta(hours=48),
            used=False,
        )

        client = Client()
        response = client.post(
            f"/api/auth/invite/{raw}/accept/",
            data=json.dumps({"password": "NewSecurePass123!"}),
            content_type="application/json",
        )
        # 201 = new account created and joined; 200 = existing account joined
        self.assertIn(response.status_code, (200, 201),
            f"Expected 200 or 201, got {response.status_code}: {response.content}")
