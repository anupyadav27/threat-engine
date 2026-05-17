"""
onboarding-D2 — InviteUserView / InviteUserAcceptView unit tests.

AC11 test cases:
  1. Invite new user → 201, user record created (status=pending), invite token stored (hashed).
  2. Duplicate invite within same org → 409 {"detail": "User already exists in this org"}.
  3. Cross-org email → 422 {"detail": "Email is registered to a different org…"}.
  4. Accept with valid token → 200, user status=active, auth cookies set.
  5. Accept with expired token → 410 {"detail": "Invite link expired"}.

Run with:
    pytest platform/cspm-backend/user_auth/tests/test_onboarding_d2_invite.py -v

Note: tests require the Django test DB to be available and migrations applied
      (including 0009 for role seeding and 0017 for nullable tenant FK).
"""
import hashlib
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


# ── Helpers ───────────────────────────────────────────────────────────────────

def _sha256(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _make_user(email: str, customer_id: str | None = None, status: str = "active") -> "Users":
    """Create a Users row with explicit customer_id."""
    from user_auth.models import Users

    u = Users.objects.create_user(email=email, password="TestPass123!", status=status)
    cid = customer_id or str(u.id)
    u.customer_id = cid
    u.save(update_fields=["customer_id"])
    return u


def _assign_role(user: "Users", role_name: str) -> None:
    """Assign a named role to a user (requires seed migration 0009)."""
    from user_auth.models import Roles, UserRoles

    try:
        role = Roles.objects.get(name=role_name)
    except Roles.DoesNotExist:
        return
    UserRoles.objects.get_or_create(user=user, role=role)


def _make_session(user: "Users") -> str:
    """Create a UserSessions row and return the raw access token."""
    from user_auth.models import UserSessions
    from user_auth.utils.auth_utils import compute_auth_caches, generate_token, hash_token

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
        user_agent="test-agent",
        token_hint=raw_token[:8],
        permissions_cache=permissions_cache,
        scope_cache=scope_cache,
    )
    return raw_token


def _make_hashed_invite(
    email: str,
    raw_token: str,
    inviter: "Users",
    customer_id: str,
    hours_offset: int = 72,
) -> "InviteTokens":
    """Create an InviteTokens row using the D2 hashed-token pattern.

    The `token` column stores the SHA-256 hex digest — matching what
    InviteUserView stores and InviteUserAcceptView looks up.
    """
    from user_auth.models import InviteTokens, Roles

    role = Roles.objects.filter(name="analyst").first()
    return InviteTokens.objects.create(
        id=str(uuid.uuid4()),
        token=_sha256(raw_token),
        email=email,
        tenant=None,  # D2 invites are customer_id-scoped, no tenant FK
        role=role,
        invited_by=inviter,
        expires_at=timezone.now() + timedelta(hours=hours_offset),
        used=False,
    )


# ── Test cases ────────────────────────────────────────────────────────────────


class TestInviteNewUser(TestCase):
    """AC11-1: Inviting a new email → 201, pending user created, hashed token stored."""

    def setUp(self):
        self.customer_id = str(uuid.uuid4())
        self.inviter = _make_user("inviter-d2-1@test.local", customer_id=self.customer_id)
        _assign_role(self.inviter, "org_admin")
        self.raw_token = _make_session(self.inviter)

    @patch("user_auth.utils.email_utils.send_invite_email")
    def test_invite_new_user_returns_201(self, mock_email):
        """POST /api/users/invite/ with a fresh email → 201, user row created as pending."""
        from user_auth.models import InviteTokens, Users

        target_email = f"newbie-{uuid.uuid4().hex[:6]}@test.local"
        client = Client()
        client.cookies["access_token"] = self.raw_token
        response = client.post(
            "/api/users/invite/",
            data={"email": target_email, "role": "analyst"},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 201, response.content)
        body = response.json()
        self.assertIn("invited", body)
        self.assertIn("user_id", body)
        self.assertIn("expires_at", body)
        self.assertEqual(body["invited"], target_email)

        # Pending user must exist with correct customer_id
        user = Users.objects.get(email=target_email)
        self.assertEqual(user.customer_id, self.customer_id)
        self.assertEqual(user.status, "pending")

        # Invite token stored as SHA-256 hash — raw token must NOT appear in DB
        invite = InviteTokens.objects.get(email=target_email)
        self.assertNotEqual(invite.token, "")
        self.assertNotIn(" ", invite.token)  # hex digest has no spaces
        # 64-char hex = SHA-256
        self.assertEqual(len(invite.token), 64)

        # Token TTL should be ~72 hours
        expected_lower = timezone.now() + timedelta(hours=71)
        expected_upper = timezone.now() + timedelta(hours=73)
        self.assertGreater(invite.expires_at, expected_lower)
        self.assertLess(invite.expires_at, expected_upper)

        mock_email.assert_called_once()


class TestInviteDuplicateWithinOrg(TestCase):
    """AC11-2 / AC3: Duplicate email in same org → HTTP 409."""

    def setUp(self):
        self.customer_id = str(uuid.uuid4())
        self.inviter = _make_user("inviter-d2-2@test.local", customer_id=self.customer_id)
        _assign_role(self.inviter, "org_admin")
        self.raw_token = _make_session(self.inviter)

        # Pre-existing user in the SAME org
        self.existing = _make_user(
            "existing-d2-2@test.local", customer_id=self.customer_id
        )

    def test_duplicate_within_org_returns_409(self):
        """Inviting an email that already belongs to the same org → 409."""
        client = Client()
        client.cookies["access_token"] = self.raw_token
        response = client.post(
            "/api/users/invite/",
            data={"email": self.existing.email, "role": "analyst"},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 409, response.content)
        body = response.json()
        self.assertIn("User already exists in this org", body.get("detail", ""))


class TestInviteCrossOrg(TestCase):
    """AC11-3 / AC4: Email in a DIFFERENT org → HTTP 422."""

    def setUp(self):
        org_a = str(uuid.uuid4())
        org_b = str(uuid.uuid4())

        self.inviter = _make_user("inviter-d2-3@test.local", customer_id=org_a)
        _assign_role(self.inviter, "org_admin")
        self.raw_token = _make_session(self.inviter)

        # Victim user belongs to a completely different org
        self.victim = _make_user("victim-d2-3@test.local", customer_id=org_b)

    def test_cross_org_invite_returns_422(self):
        """Inviting an email that belongs to a different org → 422."""
        client = Client()
        client.cookies["access_token"] = self.raw_token
        response = client.post(
            "/api/users/invite/",
            data={"email": self.victim.email, "role": "analyst"},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 422, response.content)
        body = response.json()
        self.assertIn("different org", body.get("detail", ""))


class TestAcceptValidToken(TestCase):
    """AC11-4 / AC8-AC9: Accept with valid token → 200, user activated, auth cookie set."""

    def setUp(self):
        self.customer_id = str(uuid.uuid4())
        self.inviter = _make_user("inviter-d2-4@test.local", customer_id=self.customer_id)
        self.pending_user = _make_user(
            f"pending-d2-4-{uuid.uuid4().hex[:6]}@test.local",
            customer_id=self.customer_id,
            status="pending",
        )
        self.raw_invite_token = secrets.token_urlsafe(32)
        _make_hashed_invite(
            email=self.pending_user.email,
            raw_token=self.raw_invite_token,
            inviter=self.inviter,
            customer_id=self.customer_id,
            hours_offset=72,
        )

    def test_accept_valid_token_returns_200(self):
        """POST /api/users/invite/accept/ with valid token → 200 + auth cookie."""
        from user_auth.models import Users

        client = Client()
        response = client.post(
            "/api/users/invite/accept/",
            data={"token": self.raw_invite_token, "password": "SecurePass123!"},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200, response.content)
        body = response.json()
        self.assertEqual(body.get("status"), "activated")
        self.assertIn("user", body)
        self.assertEqual(body["user"]["email"], self.pending_user.email)

        # User must be activated
        self.pending_user.refresh_from_db()
        self.assertEqual(self.pending_user.status, "active")

        # Auth cookie must be set
        self.assertIn("access_token", response.cookies)


class TestAcceptExpiredToken(TestCase):
    """AC11-5 / AC10: Accept with expired token (>72h) → HTTP 410."""

    def setUp(self):
        self.customer_id = str(uuid.uuid4())
        self.inviter = _make_user("inviter-d2-5@test.local", customer_id=self.customer_id)
        self.pending_user = _make_user(
            f"pending-d2-5-{uuid.uuid4().hex[:6]}@test.local",
            customer_id=self.customer_id,
            status="pending",
        )
        self.raw_invite_token = secrets.token_urlsafe(32)
        # hours_offset = -1 → already expired
        _make_hashed_invite(
            email=self.pending_user.email,
            raw_token=self.raw_invite_token,
            inviter=self.inviter,
            customer_id=self.customer_id,
            hours_offset=-1,
        )

    def test_accept_expired_token_returns_410(self):
        """POST /api/users/invite/accept/ with expired token → 410 with detail."""
        client = Client()
        response = client.post(
            "/api/users/invite/accept/",
            data={"token": self.raw_invite_token, "password": "SecurePass123!"},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 410, response.content)
        body = response.json()
        self.assertIn("Invite link expired", body.get("detail", ""))
