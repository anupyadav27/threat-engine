"""
auth-A2 — provision_tenant_for_new_user() unit tests.

Covers:
  AC2  — customer_id generated as cust_<12hex> when not already set
  AC2  — idempotent: existing customer_id is reused, no second tenant created
  AC3  — tenant.customer_id matches user.customer_id
  AC4  — tenant.tenant_type matches the parameter (default 'cloud')
  AC7  — transaction rollback: customer_id NOT persisted when tenant creation fails
  AC8  — return value is a dict with customer_id / tenant_id / tenant_type keys
  AC9  — Celery enqueue only fires on successful commit (on_commit not called on rollback)

Run with:
    pytest platform/cspm-backend/user_auth/tests/test_provision_tenant.py -v
"""
import os
import re
import uuid
from unittest.mock import patch, MagicMock

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

import django
django.setup()

from django.db import IntegrityError
from django.test import TestCase


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_user(email: str, customer_id: str = None):
    """Create a minimal Users row, optionally with a pre-set customer_id."""
    from user_auth.models import Users
    user = Users.objects.create_user(email=email, password="TestPass123!")
    if customer_id is not None:
        user.customer_id = customer_id
        user.save(update_fields=["customer_id"])
    return user


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestProvisionTenantNormal(TestCase):
    """AC2 / AC3 / AC4 / AC8 — happy path."""

    def test_generates_cust_prefixed_customer_id(self):
        """AC2: customer_id written to user is in cust_<12hex> format."""
        from services.provisioning import provision_tenant_for_new_user

        user = _make_user("new-user-cust@test.local")
        self.assertFalse(user.customer_id)  # no customer_id yet

        result = provision_tenant_for_new_user(user)

        user.refresh_from_db()
        self.assertRegex(
            user.customer_id,
            r"^cust_[0-9a-f]{12}$",
            msg="customer_id must be cust_ followed by exactly 12 hex chars",
        )
        # result dict must echo the same value
        self.assertEqual(result["customer_id"], user.customer_id)

    def test_tenant_customer_id_matches_user(self):
        """AC3: Tenants.customer_id == user.customer_id after provisioning."""
        from services.provisioning import provision_tenant_for_new_user
        from tenant_management.models import Tenants

        user = _make_user("match-custid@test.local")
        result = provision_tenant_for_new_user(user)

        tenant = Tenants.objects.get(id=result["tenant_id"])
        user.refresh_from_db()
        self.assertEqual(tenant.customer_id, user.customer_id)

    def test_default_tenant_type_is_cloud(self):
        """AC4: tenant_type defaults to 'cloud'."""
        from services.provisioning import provision_tenant_for_new_user
        from tenant_management.models import Tenants

        user = _make_user("cloud-type@test.local")
        result = provision_tenant_for_new_user(user)

        tenant = Tenants.objects.get(id=result["tenant_id"])
        self.assertEqual(tenant.tenant_type, "cloud")
        self.assertEqual(result["tenant_type"], "cloud")

    def test_explicit_tenant_type_stored(self):
        """AC4: explicit tenant_type is stored on both the tenant and the result dict."""
        from services.provisioning import provision_tenant_for_new_user
        from tenant_management.models import Tenants

        user = _make_user("secops-type@test.local")
        result = provision_tenant_for_new_user(user, tenant_type="secops")

        tenant = Tenants.objects.get(id=result["tenant_id"])
        self.assertEqual(tenant.tenant_type, "secops")
        self.assertEqual(result["tenant_type"], "secops")

    def test_return_value_is_dict_with_required_keys(self):
        """AC8: return value is a dict with customer_id, tenant_id, tenant_type."""
        from services.provisioning import provision_tenant_for_new_user

        user = _make_user("dict-return@test.local")
        result = provision_tenant_for_new_user(user)

        self.assertIsInstance(result, dict)
        self.assertIn("customer_id", result)
        self.assertIn("tenant_id", result)
        self.assertIn("tenant_type", result)
        # tenant_id must be a valid UUID string
        uuid.UUID(result["tenant_id"])  # raises ValueError if invalid


class TestProvisionTenantIdempotent(TestCase):
    """AC2 idempotency — user already has customer_id; no second tenant created."""

    def test_existing_customer_id_reused(self):
        """AC2: if user.customer_id is already set, it is not overwritten."""
        from services.provisioning import provision_tenant_for_new_user

        existing_cid = "cust_aabbccddeeff"
        user = _make_user("existing-cid@test.local", customer_id=existing_cid)
        result = provision_tenant_for_new_user(user)

        user.refresh_from_db()
        self.assertEqual(user.customer_id, existing_cid)
        self.assertEqual(result["customer_id"], existing_cid)

    def test_second_call_returns_existing_tenant(self):
        """Idempotent: second call with same user returns the existing tenant, not a new one."""
        from services.provisioning import provision_tenant_for_new_user
        from tenant_management.models import TenantUsers

        user = _make_user("idempotent-user@test.local")
        result1 = provision_tenant_for_new_user(user)
        result2 = provision_tenant_for_new_user(user)

        # Same tenant_id returned both times
        self.assertEqual(result1["tenant_id"], result2["tenant_id"])
        # Exactly one TenantUsers row
        membership_count = TenantUsers.objects.filter(user=user).count()
        self.assertEqual(membership_count, 1)


class TestProvisionTenantRollback(TestCase):
    """AC7: customer_id NOT persisted if tenant creation fails."""

    def test_customer_id_not_saved_on_tenant_create_failure(self):
        """AC7: transaction.atomic() rolls back customer_id write when Tenants.create fails."""
        from services.provisioning import provision_tenant_for_new_user
        from tenant_management.models import Tenants

        user = _make_user("rollback-user@test.local")
        original_customer_id = user.customer_id  # empty/None before provisioning

        with patch.object(
            Tenants.objects.__class__,
            "create",
            side_effect=IntegrityError("simulated DB failure"),
        ):
            with self.assertRaises(IntegrityError):
                provision_tenant_for_new_user(user)

        user.refresh_from_db()
        # customer_id must still be the original value (not the generated cust_ string)
        self.assertEqual(user.customer_id, original_customer_id)

    def test_celery_not_enqueued_on_rollback(self):
        """AC9: transaction.on_commit callbacks are not invoked when the transaction rolls back."""
        from services.provisioning import provision_tenant_for_new_user
        from tenant_management.models import Tenants

        user = _make_user("celery-rollback@test.local")

        with patch("services.provisioning.transaction.on_commit") as mock_on_commit:
            with patch.object(
                Tenants.objects.__class__,
                "create",
                side_effect=IntegrityError("simulated DB failure"),
            ):
                with self.assertRaises(IntegrityError):
                    provision_tenant_for_new_user(user)

        mock_on_commit.assert_not_called()
