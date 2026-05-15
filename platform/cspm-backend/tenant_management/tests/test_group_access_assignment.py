"""
Unit tests for onboarding-D3 — Group access assignment API (group-centric).

AC10 coverage (4 test cases):
  1. Valid tenant assignment → 201  (AC1, AC5, AC6)
  2. Cross-org group → 404          (AC5)
  3. Cross-org tenant → 404         (AC6)
  4. Delete group-tenant assignment → 204  (AC2)
  5. Valid account assignment → 201  (AC3, AC7)
  6. Delete group-account assignment → 204  (AC4)

Run with:
    pytest platform/cspm-backend/tenant_management/tests/test_group_access_assignment.py -v
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
# Shared helpers (mirrors test_group_management.py conventions)
# ---------------------------------------------------------------------------


def _make_user(email: str, customer_id: str = None):
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
    from user_auth.models import Roles, UserRoles

    try:
        role = Roles.objects.get(name=role_name)
    except Roles.DoesNotExist:
        role = Roles.objects.create(name=role_name, level=2)
    UserRoles.objects.get_or_create(user=user, role=role)
    return role


def _make_session(user) -> str:
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


def _make_group(customer_id: str, name: str = "TestGroup"):
    from tenant_management.models import CsmGroups

    return CsmGroups.objects.create(
        id=str(uuid.uuid4()),
        customer_id=customer_id,
        name=name,
    )


def _make_tenant(customer_id: str, name: str = "TestTenant"):
    from tenant_management.models import Tenants

    return Tenants.objects.create(
        id=str(uuid.uuid4()),
        customer_id=customer_id,
        name=name,
        status="active",
        plan="trial",
    )


def _authed_client(user) -> tuple:
    token = _make_session(user)
    c = Client()
    c.cookies["access_token"] = token
    return c, token


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------


class GroupTenantAssignValidTest(TestCase):
    """AC1 — POST /api/groups/{id}/tenants/ with valid same-org data → 201."""

    def setUp(self):
        self.cid = str(uuid.uuid4())
        self.user = _make_user("assign-admin@example.com", customer_id=self.cid)
        _assign_role(self.user, "org_admin")

        self.group = _make_group(self.cid, name="TeamAlpha")
        self.tenant = _make_tenant(self.cid, name="ProdTenant")
        self.client, _ = _authed_client(self.user)

    def test_assign_tenant_to_group_returns_201(self):
        resp = self.client.post(
            f"/api/groups/{self.group.id}/tenants/",
            data=json.dumps({"tenant_id": str(self.tenant.id), "role": "viewer"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 201, resp.content)
        body = resp.json()
        self.assertEqual(str(body["group"]), str(self.group.id))
        self.assertEqual(str(body["tenant"]), str(self.tenant.id))

    def test_assign_idempotent_returns_200(self):
        """Duplicate assignment updates role and returns 200 (not 409)."""
        payload = json.dumps({"tenant_id": str(self.tenant.id), "role": "viewer"})
        self.client.post(
            f"/api/groups/{self.group.id}/tenants/",
            data=payload,
            content_type="application/json",
        )
        resp = self.client.post(
            f"/api/groups/{self.group.id}/tenants/",
            data=payload,
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200, resp.content)


class CrossOrgGroupReturns404Test(TestCase):
    """AC5 — accessing a group from another org raises 404, not data."""

    def setUp(self):
        self.cid_a = str(uuid.uuid4())
        self.cid_b = str(uuid.uuid4())

        self.user_a = _make_user("user-a@example.com", customer_id=self.cid_a)
        _assign_role(self.user_a, "org_admin")

        # group belongs to org B
        self.group_b = _make_group(self.cid_b, name="OrgBGroup")
        # tenant in org A (irrelevant — group check fires first)
        self.tenant_a = _make_tenant(self.cid_a, name="TenantA")

        self.client_a, _ = _authed_client(self.user_a)

    def test_cross_org_group_returns_404(self):
        resp = self.client_a.post(
            f"/api/groups/{self.group_b.id}/tenants/",
            data=json.dumps({"tenant_id": str(self.tenant_a.id), "role": "viewer"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 404, resp.content)


class CrossOrgTenantReturns404Test(TestCase):
    """AC6 — assigning a group to a tenant from another org raises 404."""

    def setUp(self):
        self.cid_a = str(uuid.uuid4())
        self.cid_b = str(uuid.uuid4())

        self.user_a = _make_user("user-b@example.com", customer_id=self.cid_a)
        _assign_role(self.user_a, "org_admin")

        # group in own org
        self.group_a = _make_group(self.cid_a, name="GroupA")
        # tenant belongs to org B — must be rejected (AC6)
        self.tenant_b = _make_tenant(self.cid_b, name="CrossTenant")

        self.client_a, _ = _authed_client(self.user_a)

    def test_cross_org_tenant_returns_404(self):
        resp = self.client_a.post(
            f"/api/groups/{self.group_a.id}/tenants/",
            data=json.dumps({"tenant_id": str(self.tenant_b.id), "role": "viewer"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 404, resp.content)


class GroupTenantDeleteReturns204Test(TestCase):
    """AC2 — DELETE /api/groups/{id}/tenants/{tenant_id}/ returns 204."""

    def setUp(self):
        from tenant_management.models import TenantGroupAccess
        from user_auth.models import Roles

        self.cid = str(uuid.uuid4())
        self.user = _make_user("del-assign@example.com", customer_id=self.cid)
        _assign_role(self.user, "org_admin")

        self.group = _make_group(self.cid, name="DelGroup")
        self.tenant = _make_tenant(self.cid, name="DelTenant")

        # create the role row required for the FK
        try:
            role = Roles.objects.get(name="viewer")
        except Roles.DoesNotExist:
            role = Roles.objects.create(name="viewer", level=4)

        self.access = TenantGroupAccess.objects.create(
            id=str(uuid.uuid4()),
            group=self.group,
            tenant=self.tenant,
            role=role,
        )
        self.client, _ = _authed_client(self.user)

    def test_delete_assignment_returns_204(self):
        from tenant_management.models import TenantGroupAccess

        resp = self.client.delete(
            f"/api/groups/{self.group.id}/tenants/{self.tenant.id}/"
        )
        self.assertEqual(resp.status_code, 204, resp.content)
        self.assertFalse(TenantGroupAccess.objects.filter(id=self.access.id).exists())


class GroupAccountAssignValidTest(TestCase):
    """AC3 — POST /api/groups/{id}/accounts/ with valid same-org data → 201."""

    def setUp(self):
        self.cid = str(uuid.uuid4())
        self.user = _make_user("acct-admin@example.com", customer_id=self.cid)
        _assign_role(self.user, "org_admin")

        self.group = _make_group(self.cid, name="AccountGroup")
        self.tenant = _make_tenant(self.cid, name="AccountTenant")
        self.account_id = "123456789012"
        self.client, _ = _authed_client(self.user)

    def test_assign_account_to_group_returns_201(self):
        resp = self.client.post(
            f"/api/groups/{self.group.id}/accounts/",
            data=json.dumps({
                "account_id": self.account_id,
                "tenant_id": str(self.tenant.id),
                "role": "analyst",
            }),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 201, resp.content)
        body = resp.json()
        self.assertEqual(body["account_id"], self.account_id)


class GroupAccountDeleteReturns204Test(TestCase):
    """AC4 — DELETE /api/groups/{id}/accounts/{account_id}/?tenant_id=... returns 204."""

    def setUp(self):
        from tenant_management.models import AccountGroupAccess
        from user_auth.models import Roles

        self.cid = str(uuid.uuid4())
        self.user = _make_user("del-acct@example.com", customer_id=self.cid)
        _assign_role(self.user, "org_admin")

        self.group = _make_group(self.cid, name="DelAccountGroup")
        self.tenant = _make_tenant(self.cid, name="DelAccountTenant")
        self.account_id = "999999999999"

        try:
            role = Roles.objects.get(name="viewer")
        except Roles.DoesNotExist:
            role = Roles.objects.create(name="viewer", level=4)

        self.access = AccountGroupAccess.objects.create(
            id=str(uuid.uuid4()),
            group=self.group,
            tenant=self.tenant,
            account_id=self.account_id,
            role=role,
        )
        self.client, _ = _authed_client(self.user)

    def test_delete_account_assignment_returns_204(self):
        from tenant_management.models import AccountGroupAccess

        resp = self.client.delete(
            f"/api/groups/{self.group.id}/accounts/{self.account_id}/"
            f"?tenant_id={self.tenant.id}"
        )
        self.assertEqual(resp.status_code, 204, resp.content)
        self.assertFalse(AccountGroupAccess.objects.filter(id=self.access.id).exists())
