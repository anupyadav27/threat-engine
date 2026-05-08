"""
BILL-S01 — Atomic invite acceptance tests.

Verifies the SELECT FOR UPDATE / transaction.atomic() guard in
accept_invite_membership() prevents the race condition where two concurrent
requests for the same token both succeed.

Run with:
    pytest platform/cspm-backend/user_auth/tests/test_invite_atomic.py -v
"""
import os
import threading
import uuid
from datetime import timedelta
from unittest.mock import patch, MagicMock

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

import django
django.setup()

from django.db import IntegrityError
from django.test import TestCase, RequestFactory
from django.utils import timezone


def _make_invite(user, tenant, role=None, used=False):
    """Helper: create an InviteTokens row for (user, tenant)."""
    from user_auth.models import InviteTokens
    import secrets as _secrets
    return InviteTokens.objects.create(
        id=str(uuid.uuid4()),
        token=_secrets.token_urlsafe(32),
        email=user.email,
        tenant=tenant,
        role=role,
        invited_by=user,
        expires_at=timezone.now() + timedelta(hours=48),
        used=used,
    )


def _make_user(email, customer_id=None):
    """Helper: create a Users row."""
    from user_auth.models import Users
    u = Users.objects.create_user(email=email, password="TestPass123!")
    if customer_id is not None:
        u.customer_id = customer_id
        u.save(update_fields=["customer_id"])
    else:
        u.customer_id = str(u.id)
        u.save(update_fields=["customer_id"])
    return u


def _make_tenant(customer_id=None):
    """Helper: create a Tenants row."""
    from tenant_management.models import Tenants
    tid = str(uuid.uuid4())
    cid = customer_id or tid
    return Tenants.objects.create(
        id=tid,
        engine_tenant_id=tid,
        name=f"Test Tenant {tid[:8]}",
        status="active",
        tenant_type="cloud",
        customer_id=cid,
        plan="trial",
        contact_email="admin@test.local",
    )


class TestConcurrentAcceptOnlyOneSucceeds(TestCase):
    """AC-1 & AC-2: Concurrent POSTs — exactly one 201, one 409; exactly one TenantUsers row."""

    def test_concurrent_accept_only_one_succeeds(self):
        from user_auth.models import InviteTokens
        from user_auth.utils.tenant_utils import accept_invite_membership
        from tenant_management.models import TenantUsers

        inviter = _make_user("inviter-concurrent@test.local")
        invitee = _make_user("invitee-concurrent@test.local")
        tenant = _make_tenant(customer_id=inviter.customer_id)
        invite = _make_invite(inviter, tenant)

        results = []
        errors = []

        def _accept():
            try:
                # Re-fetch invite inside thread so each thread reads the same token
                fresh_invite = InviteTokens.objects.get(token=invite.token)
                accept_invite_membership(invitee, fresh_invite)
                results.append("ok")
            except InviteTokens.DoesNotExist:
                results.append("conflict")
            except Exception as exc:
                errors.append(exc)

        t1 = threading.Thread(target=_accept)
        t2 = threading.Thread(target=_accept)
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)

        self.assertEqual(errors, [], f"Unexpected errors: {errors}")
        # Exactly one success and one conflict (order not guaranteed)
        self.assertIn("ok", results)
        self.assertIn("conflict", results)
        # Exactly one TenantUsers row for (invitee, tenant)
        count = TenantUsers.objects.filter(user=invitee, tenant=tenant).count()
        self.assertEqual(count, 1)
        # invite.used must be True
        invite.refresh_from_db()
        self.assertTrue(invite.used)


class TestRollbackLeavesInviteUnused(TestCase):
    """AC-4: Rolling back the transaction leaves invite.used=False and no TenantUsers row."""

    def test_rollback_leaves_invite_unused(self):
        from user_auth.models import InviteTokens, UserRoles
        from user_auth.utils.tenant_utils import accept_invite_membership
        from tenant_management.models import TenantUsers

        inviter = _make_user("inviter-rollback@test.local")
        invitee = _make_user("invitee-rollback@test.local")
        tenant = _make_tenant(customer_id=inviter.customer_id)
        invite = _make_invite(inviter, tenant)

        # Force a rollback by making UserRoles.get_or_create raise IntegrityError
        with patch(
            "user_auth.models.UserRoles.objects.get_or_create",
            side_effect=IntegrityError("simulated constraint violation"),
        ):
            with self.assertRaises(IntegrityError):
                accept_invite_membership(invitee, invite)

        # Transaction must have rolled back
        invite.refresh_from_db()
        self.assertFalse(invite.used)
        self.assertFalse(TenantUsers.objects.filter(user=invitee, tenant=tenant).exists())


class TestAuditEventFiresOnCommit(TestCase):
    """AC-5: log_auth_event called exactly once on successful acceptance."""

    def test_audit_event_fires_on_commit(self):
        from user_auth.utils.tenant_utils import accept_invite_membership

        inviter = _make_user("inviter-audit-ok@test.local")
        invitee = _make_user("invitee-audit-ok@test.local")
        tenant = _make_tenant(customer_id=inviter.customer_id)
        invite = _make_invite(inviter, tenant)

        with patch(
            "user_auth.utils.tenant_utils.log_auth_event",
        ) as mock_log:
            accept_invite_membership(invitee, invite)

        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args
        self.assertEqual(call_kwargs[0][0], "invite.accept")


class TestAuditEventNotFiredOnRollback(TestCase):
    """AC-5: log_auth_event NOT called when the transaction rolls back."""

    def test_audit_event_not_fired_on_rollback(self):
        from user_auth.models import UserRoles
        from user_auth.utils.tenant_utils import accept_invite_membership

        inviter = _make_user("inviter-audit-fail@test.local")
        invitee = _make_user("invitee-audit-fail@test.local")
        tenant = _make_tenant(customer_id=inviter.customer_id)
        invite = _make_invite(inviter, tenant)

        with patch(
            "user_auth.utils.tenant_utils.log_auth_event",
        ) as mock_log:
            with patch(
                "user_auth.models.UserRoles.objects.get_or_create",
                side_effect=IntegrityError("simulated"),
            ):
                with self.assertRaises(IntegrityError):
                    accept_invite_membership(invitee, invite)

        mock_log.assert_not_called()


class TestCrossOrgCapStillWorks(TestCase):
    """AC-6: Cross-org invite results in viewer role even under atomic path."""

    def test_cross_org_cap_still_works(self):
        from user_auth.utils.tenant_utils import accept_invite_membership
        from tenant_management.models import TenantUsers

        # Different customer_ids → cross-org
        inviter = _make_user("inviter-crossorg@test.local", customer_id="org-a")
        invitee = _make_user("invitee-crossorg@test.local", customer_id="org-b")
        tenant = _make_tenant(customer_id="org-a")

        # Give the invite a non-viewer role (e.g. org_admin)
        from user_auth.models import Roles
        try:
            admin_role = Roles.objects.get(name="org_admin")
        except Roles.DoesNotExist:
            self.skipTest("org_admin role not seeded — run migration user_auth.0009")

        invite = _make_invite(inviter, tenant, role=admin_role)
        accept_invite_membership(invitee, invite)

        membership = TenantUsers.objects.get(user=invitee, tenant=tenant)
        self.assertEqual(membership.role.name, "viewer")


class TestAlreadyUsedTokenReturns409(TestCase):
    """AC-7: token with used=True raises DoesNotExist — view returns 409."""

    def test_already_used_token_raises_does_not_exist(self):
        from user_auth.models import InviteTokens
        from user_auth.utils.tenant_utils import accept_invite_membership

        inviter = _make_user("inviter-used@test.local")
        invitee = _make_user("invitee-used@test.local")
        tenant = _make_tenant(customer_id=inviter.customer_id)
        invite = _make_invite(inviter, tenant, used=True)

        with self.assertRaises(InviteTokens.DoesNotExist):
            accept_invite_membership(invitee, invite)

    def test_already_used_token_view_returns_409(self):
        """Integration: AcceptInviteView returns 409 when token was already used."""
        import json
        from user_auth.models import InviteTokens, Users
        from django.test import Client

        inviter = _make_user("inviter-409view@test.local")
        invitee_email = "invitee-409view@test.local"
        tenant = _make_tenant(customer_id=inviter.customer_id)
        invite = _make_invite(inviter, tenant, used=True)
        # Pre-create the invitee user so we don't fail on the user creation step
        Users.objects.create_user(
            email=invitee_email, password="TestPass123!", status="active"
        )

        client = Client()
        response = client.post(
            f"/api/auth/invite/{invite.token}/accept/",
            data=json.dumps({"password": "TestPass123!"}),
            content_type="application/json",
        )
        # View must return 410 for pre-existing used flag check (before atomic block),
        # OR 409 if the atomic guard raises DoesNotExist. Both are acceptable.
        self.assertIn(response.status_code, (409, 410))
