"""
Unit tests for onboarding-D1 — Group management API.

AC10 coverage (6 test cases):
  1. List groups scoped to customer_id (AC1, AC9)
  2. Create group — customer_id set server-side, returns 201 (AC2)
  3. PATCH group — org_admin can update name/description (AC4)
  4. DELETE group — cascades GroupMembers rows (AC5)
  5. Add/remove member via nested endpoint (AC6, AC7)
  6. Cross-org group access returns 404, not group data (AC9)

Run with:
    pytest platform/cspm-backend/tenant_management/tests/test_group_management.py -v
"""

import json
import os
import uuid
from datetime import timedelta

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

import django

django.setup()

from django.test import TestCase, Client
from django.utils import timezone


# ---------------------------------------------------------------------------
# Shared test helpers
# ---------------------------------------------------------------------------


def _make_user(email: str, customer_id: str = None):
    """Create an active Users row, optionally with a customer_id."""
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


def _assign_role(user, role_name: str):
    """Assign a named role to a user. Requires seed migration 0009."""
    from user_auth.models import Roles, UserRoles

    try:
        role = Roles.objects.get(name=role_name)
    except Roles.DoesNotExist:
        role = Roles.objects.create(name=role_name, level=2)
    UserRoles.objects.get_or_create(user=user, role=role)
    return role


def _make_session(user) -> str:
    """Create a UserSessions row and return the raw access token string."""
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


def _make_group(customer_id: str, name: str = "Engineering"):
    """Create a CsmGroups row directly."""
    from tenant_management.models import CsmGroups

    return CsmGroups.objects.create(
        id=str(uuid.uuid4()),
        customer_id=customer_id,
        name=name,
    )


def _authed_client(user) -> tuple:
    """Return (Client, raw_token) with access_token cookie set."""
    token = _make_session(user)
    c = Client()
    c.cookies["access_token"] = token
    return c, token


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------


class GroupListScopedToCustomerTest(TestCase):
    """AC1 + AC9 — GET /api/groups/ returns only the caller's org groups."""

    def setUp(self):
        self.cid_a = str(uuid.uuid4())
        self.cid_b = str(uuid.uuid4())

        self.user_a = _make_user("admin-a@example.com", customer_id=self.cid_a)
        _assign_role(self.user_a, "org_admin")

        _make_group(self.cid_a, name="GroupA1")
        _make_group(self.cid_a, name="GroupA2")
        _make_group(self.cid_b, name="GroupB1")  # other org — must NOT appear

        self.client_a, _ = _authed_client(self.user_a)

    def test_list_returns_only_own_org_groups(self):
        resp = self.client_a.get("/api/groups/")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        names = [g["name"] for g in data.get("results", data)]
        self.assertIn("GroupA1", names)
        self.assertIn("GroupA2", names)
        self.assertNotIn("GroupB1", names)


class GroupCreateTest(TestCase):
    """AC2 — POST /api/groups/ creates group; customer_id is set server-side."""

    def setUp(self):
        self.cid = str(uuid.uuid4())
        self.user = _make_user("creator@example.com", customer_id=self.cid)
        _assign_role(self.user, "org_admin")
        self.client, _ = _authed_client(self.user)

    def test_create_group_returns_201_with_correct_customer_id(self):
        payload = {
            "name": "SecurityTeam",
            "description": "All security analysts",
            "customer_id": "SPOOFED_VALUE",  # must be ignored
        }
        resp = self.client.post(
            "/api/groups/",
            data=json.dumps(payload),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 201, resp.content)
        body = resp.json()
        # customer_id must come from the authenticated user, not the payload
        self.assertEqual(body["customer_id"], self.cid)
        self.assertEqual(body["name"], "SecurityTeam")


class GroupPatchTest(TestCase):
    """AC3 + AC4 — GET detail returns group; PATCH updates name/description."""

    def setUp(self):
        self.cid = str(uuid.uuid4())
        self.user = _make_user("patcher@example.com", customer_id=self.cid)
        _assign_role(self.user, "org_admin")
        self.group = _make_group(self.cid, name="OldName")
        self.client, _ = _authed_client(self.user)

    def test_get_detail_returns_200(self):
        resp = self.client.get(f"/api/groups/{self.group.id}/")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["name"], "OldName")

    def test_patch_updates_name_and_description(self):
        resp = self.client.patch(
            f"/api/groups/{self.group.id}/",
            data=json.dumps({"name": "NewName", "description": "Updated"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200, resp.content)
        body = resp.json()
        self.assertEqual(body["name"], "NewName")
        self.assertEqual(body["description"], "Updated")


class GroupDeleteCascadesMembersTest(TestCase):
    """AC5 — DELETE group cascades to GroupMembers rows."""

    def setUp(self):
        self.cid = str(uuid.uuid4())
        self.admin = _make_user("del-admin@example.com", customer_id=self.cid)
        _assign_role(self.admin, "org_admin")

        self.member_user = _make_user("member@example.com", customer_id=self.cid)
        _assign_role(self.member_user, "viewer")

        self.group = _make_group(self.cid, name="ToDelete")

        from tenant_management.models import GroupMembers

        GroupMembers.objects.create(
            id=str(uuid.uuid4()),
            group=self.group,
            user=self.member_user,
        )
        self.client, _ = _authed_client(self.admin)

    def test_delete_group_cascades_members(self):
        from tenant_management.models import GroupMembers

        group_id = self.group.id
        self.assertEqual(GroupMembers.objects.filter(group_id=group_id).count(), 1)

        resp = self.client.delete(f"/api/groups/{group_id}/")
        self.assertEqual(resp.status_code, 204, resp.content)

        # Both the group and member rows must be gone
        from tenant_management.models import CsmGroups

        self.assertFalse(CsmGroups.objects.filter(id=group_id).exists())
        self.assertEqual(GroupMembers.objects.filter(group_id=group_id).count(), 0)


class GroupMemberAddRemoveTest(TestCase):
    """AC6 + AC7 — POST /groups/{id}/members/ adds; DELETE /…/members/{uid}/ removes."""

    def setUp(self):
        self.cid = str(uuid.uuid4())
        self.admin = _make_user("member-admin@example.com", customer_id=self.cid)
        _assign_role(self.admin, "org_admin")

        self.new_member = _make_user("newmember@example.com", customer_id=self.cid)
        _assign_role(self.new_member, "viewer")

        self.group = _make_group(self.cid, name="TeamAlpha")
        self.client, _ = _authed_client(self.admin)

    def test_add_member_returns_201(self):
        resp = self.client.post(
            f"/api/groups/{self.group.id}/members/",
            data=json.dumps({"user_id": str(self.new_member.id)}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 201, resp.content)

        from tenant_management.models import GroupMembers

        self.assertTrue(
            GroupMembers.objects.filter(group=self.group, user=self.new_member).exists()
        )

    def test_remove_member_returns_204(self):
        from tenant_management.models import GroupMembers

        member_row = GroupMembers.objects.create(
            id=str(uuid.uuid4()),
            group=self.group,
            user=self.new_member,
        )

        resp = self.client.delete(
            f"/api/groups/{self.group.id}/members/{member_row.id}/"
        )
        self.assertEqual(resp.status_code, 204, resp.content)
        self.assertFalse(GroupMembers.objects.filter(id=member_row.id).exists())


class CrossOrgGroupAccess404Test(TestCase):
    """AC9 — accessing a group from a different org returns 404, not data."""

    def setUp(self):
        self.cid_a = str(uuid.uuid4())
        self.cid_b = str(uuid.uuid4())

        self.user_a = _make_user("orga@example.com", customer_id=self.cid_a)
        _assign_role(self.user_a, "org_admin")

        # Group belongs to org B
        self.group_b = _make_group(self.cid_b, name="OrgBSecret")

        self.client_a, _ = _authed_client(self.user_a)

    def test_get_cross_org_group_returns_404(self):
        resp = self.client_a.get(f"/api/groups/{self.group_b.id}/")
        self.assertEqual(resp.status_code, 404)

    def test_patch_cross_org_group_returns_404(self):
        resp = self.client_a.patch(
            f"/api/groups/{self.group_b.id}/",
            data=json.dumps({"name": "Hijacked"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 404)

    def test_delete_cross_org_group_returns_404(self):
        resp = self.client_a.delete(f"/api/groups/{self.group_b.id}/")
        self.assertEqual(resp.status_code, 404)
