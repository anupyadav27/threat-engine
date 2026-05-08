"""
BILL-S06 — group_id FK on InviteTokens.

Tests:
  - Group invite created with valid group_id → group saved on token
    (uses surviving InviteCreateView at /api/v1/invites/ — BILL-S07)
  - Cross-org group_id rejected at invite creation (404)
  - ValidateInviteView returns group_name when group set
  - ValidateInviteView does NOT return group_id UUID
  - Acceptance creates GroupMembers + TenantGroupAccess rows
  - Acceptance with group pointing to deleted / stale group → skipped gracefully,
    membership still created (invite not blocked)
  - Acceptance without group_id → no GroupMembers row created

Run with:
    pytest platform/cspm-backend/user_auth/tests/test_invite_group.py -v
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

from django.test import TestCase, Client, RequestFactory
from django.utils import timezone


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


# ---------------------------------------------------------------------------
# Shared test helpers
# ---------------------------------------------------------------------------

def _make_user(email, customer_id=None):
    from user_auth.models import Users
    u = Users.objects.create_user(
        email=email,
        password="Test1234!",
        status="active",
    )
    if customer_id:
        u.customer_id = customer_id
        u.save(update_fields=["customer_id"])
    return u


def _make_tenant(customer_id, name="Test Tenant"):
    from tenant_management.models import Tenants
    return Tenants.objects.create(
        id=str(uuid.uuid4()),
        engine_tenant_id=str(uuid.uuid4()),
        name=name,
        status="active",
        tenant_type="cloud",
        customer_id=customer_id,
        plan="trial",
        contact_email="admin@example.com",
    )


def _make_group(customer_id, name="Engineering"):
    from tenant_management.models import CsmGroups
    return CsmGroups.objects.create(
        id=str(uuid.uuid4()),
        customer_id=customer_id,
        name=name,
    )


def _make_role(name="viewer"):
    from user_auth.models import Roles
    obj, _ = Roles.objects.get_or_create(name=name, defaults={"level": 4})
    return obj


def _make_tenant_user(user, tenant, role):
    from tenant_management.models import TenantUsers
    obj, _ = TenantUsers.objects.get_or_create(
        user=user,
        tenant=tenant,
        defaults={"id": str(uuid.uuid4()), "role": role, "is_active": True},
    )
    return obj


def _make_invite(email, tenant, role=None, group=None, used=False):
    from user_auth.models import InviteTokens
    return InviteTokens.objects.create(
        id=str(uuid.uuid4()),
        token=secrets.token_urlsafe(32),
        email=email,
        tenant=tenant,
        role=role,
        group=group,
        invited_by=None,
        expires_at=timezone.now() + timedelta(hours=48),
        used=used,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestCreateInviteWithGroup(TestCase):
    """POST /api/v1/invites/ group_id validation (surviving endpoint — BILL-S07)."""

    def setUp(self):
        self.customer_id = str(uuid.uuid4())
        self.inviter = _make_user("inviter@org.com", customer_id=self.customer_id)
        _assign_role(self.inviter, "org_admin")
        self.role = _make_role("viewer")
        self.tenant = _make_tenant(self.customer_id)
        _make_tenant_user(self.inviter, self.tenant, self.role)
        self.group = _make_group(self.customer_id)
        self.raw_token = _make_session(self.inviter)

    @patch("user_auth.utils.email_utils.send_invite_email")
    def test_create_invite_with_valid_group(self, mock_email):
        """group_id from same org → InviteTokens.group_id set correctly."""
        from user_auth.models import InviteTokens

        client = Client()
        client.cookies["access_token"] = self.raw_token
        response = client.post(
            "/api/v1/invites/",
            data=json.dumps({
                "email": "newuser@org.com",
                "tenant_id": str(self.tenant.id),
                "group_id": str(self.group.id),
                "role": "viewer",
            }),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 201, response.content)
        invite = InviteTokens.objects.get(email="newuser@org.com")
        self.assertIsNotNone(invite.group_id)
        self.assertEqual(str(invite.group_id), str(self.group.id))

    def test_create_invite_with_cross_org_group_returns_404(self):
        """group_id belonging to a different org → 404, no invite created."""
        from user_auth.models import InviteTokens

        other_customer_id = str(uuid.uuid4())
        other_group = _make_group(other_customer_id, name="OtherGroup")

        client = Client()
        client.cookies["access_token"] = self.raw_token
        response = client.post(
            "/api/v1/invites/",
            data=json.dumps({
                "email": "crossorg@other.com",
                "tenant_id": str(self.tenant.id),
                "group_id": str(other_group.id),
                "role": "viewer",
            }),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 404)
        body = response.json()
        self.assertIn("organisation", body["error"])
        # No invite row should have been created
        self.assertFalse(InviteTokens.objects.filter(email="crossorg@other.com").exists())


class TestValidateInviteGroupName(TestCase):
    """GET /api/auth/invite/{token}/ — group_name in response, no group_id."""

    def setUp(self):
        self.factory = RequestFactory()
        self.customer_id = str(uuid.uuid4())
        self.tenant = _make_tenant(self.customer_id)
        self.role = _make_role("viewer")
        self.group = _make_group(self.customer_id, name="Security Team")

    def test_validate_invite_returns_group_name_not_id(self):
        """ValidateInviteView response contains group_name but NOT group_id."""
        from user_auth.views.invite import ValidateInviteView

        invite = _make_invite("user@org.com", self.tenant, role=self.role, group=self.group)
        request = self.factory.get(f"/api/auth/invite/{invite.token}/")
        response = ValidateInviteView.as_view()(request, token=invite.token)

        self.assertEqual(response.status_code, 200)
        body = json.loads(response.content)
        self.assertEqual(body["group_name"], "Security Team")
        self.assertNotIn("group_id", body)

    def test_validate_invite_no_group_returns_null_group_name(self):
        """Invite without a group returns group_name=null in response."""
        from user_auth.views.invite import ValidateInviteView

        invite = _make_invite("user2@org.com", self.tenant, role=self.role, group=None)
        request = self.factory.get(f"/api/auth/invite/{invite.token}/")
        response = ValidateInviteView.as_view()(request, token=invite.token)

        self.assertEqual(response.status_code, 200)
        body = json.loads(response.content)
        self.assertIsNone(body["group_name"])
        self.assertNotIn("group_id", body)


class TestAcceptInviteGroupMembership(TestCase):
    """accept_invite_membership() group membership creation."""

    def setUp(self):
        self.customer_id = str(uuid.uuid4())
        self.tenant = _make_tenant(self.customer_id)
        self.role = _make_role("viewer")
        self.group = _make_group(self.customer_id, name="DevOps")
        self.user = _make_user("acceptor@org.com", customer_id=self.customer_id)

    def test_acceptance_creates_group_members(self):
        """Accepting an invite with group_id creates GroupMembers + TenantGroupAccess."""
        from user_auth.utils.tenant_utils import accept_invite_membership
        from tenant_management.models import GroupMembers, TenantGroupAccess

        invite = _make_invite(self.user.email, self.tenant, role=self.role, group=self.group)
        accept_invite_membership(self.user, invite)

        self.assertTrue(
            GroupMembers.objects.filter(group=self.group, user=self.user).exists(),
            "GroupMembers row should be created on invite acceptance",
        )
        self.assertTrue(
            TenantGroupAccess.objects.filter(group=self.group, tenant=self.tenant).exists(),
            "TenantGroupAccess row should be created on invite acceptance",
        )

    def test_acceptance_skips_stale_group(self):
        """Group customer_id changed since invite creation → acceptance succeeds, no GroupMembers."""
        from user_auth.utils.tenant_utils import accept_invite_membership
        from tenant_management.models import GroupMembers, TenantGroupAccess

        invite = _make_invite(self.user.email, self.tenant, role=self.role, group=self.group)

        # Simulate group being reassigned to a different org after the invite was issued
        self.group.customer_id = str(uuid.uuid4())
        self.group.save(update_fields=["customer_id"])

        # Acceptance should NOT raise — it logs a warning and skips group writes
        accept_invite_membership(self.user, invite)

        # Invite should still be consumed (used=True)
        invite.refresh_from_db()
        self.assertTrue(invite.used)

        # But no group membership rows created
        self.assertFalse(GroupMembers.objects.filter(user=self.user, group=self.group).exists())
        self.assertFalse(TenantGroupAccess.objects.filter(group=self.group, tenant=self.tenant).exists())

    def test_existing_invite_no_group_unaffected(self):
        """Invite without group_id → acceptance works normally, no GroupMembers row."""
        from user_auth.utils.tenant_utils import accept_invite_membership
        from tenant_management.models import GroupMembers, TenantUsers

        invite = _make_invite(self.user.email, self.tenant, role=self.role, group=None)
        accept_invite_membership(self.user, invite)

        invite.refresh_from_db()
        self.assertTrue(invite.used)
        self.assertTrue(TenantUsers.objects.filter(user=self.user, tenant=self.tenant).exists())
        # No GroupMembers created since invite had no group
        self.assertFalse(GroupMembers.objects.filter(user=self.user).exists())

    def test_group_members_and_tenant_group_access_are_atomic(self):
        """Atomic block: if used=True before accept_invite_membership, the whole block rolls back."""
        from user_auth.utils.tenant_utils import accept_invite_membership
        from user_auth.models import InviteTokens
        from tenant_management.models import GroupMembers, TenantUsers

        # Pre-mark the invite as used
        invite = _make_invite(self.user.email, self.tenant, role=self.role, group=self.group)
        invite.used = True
        invite.save(update_fields=["used"])

        # The SELECT FOR UPDATE / used=False filter should raise DoesNotExist
        with self.assertRaises(InviteTokens.DoesNotExist):
            accept_invite_membership(self.user, invite)

        # Nothing committed — neither TenantUsers nor GroupMembers exist
        self.assertFalse(TenantUsers.objects.filter(user=self.user, tenant=self.tenant).exists())
        self.assertFalse(GroupMembers.objects.filter(user=self.user).exists())
