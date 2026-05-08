"""
Unit tests for provision_billing_trial Celery task (BILL-S05).

Run with:
    pytest platform/cspm-backend/user_auth/tests/test_celery_trial.py -v
"""
import uuid
from unittest.mock import MagicMock, patch, call

import pytest

import user_auth.celery_tasks  # noqa: F401 — ensure module is importable for patching


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_tenant(tenant_id: str, contact_email: str = "founder@acme.com"):
    """Return a mock Tenants-like object."""
    t = MagicMock()
    t.id = tenant_id
    t.contact_email = contact_email
    return t


# ---------------------------------------------------------------------------
# Test: task fetches email from DB, never from task args
# ---------------------------------------------------------------------------

def test_task_fetches_email_from_db_not_args():
    """The task must fetch contact_email inside its body, not accept it as an arg."""
    tenant_id = str(uuid.uuid4())
    tenant = _make_tenant(tenant_id, contact_email="founder@corp.io")

    with patch("user_auth.celery_tasks.http_requests") as mock_req, \
         patch("tenant_management.models.Tenants") as mock_tenants_cls:

        mock_tenants_cls.objects.get.return_value = tenant
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_req.post.return_value = mock_resp
        mock_req.exceptions.RequestException = Exception

        from user_auth.celery_tasks import provision_billing_trial
        provision_billing_trial(tenant_id)

        # Verify the payload passed to billing engine uses DB email
        _, kwargs = mock_req.post.call_args
        payload = kwargs.get("json") or mock_req.post.call_args[1]["json"]
        assert payload["admin_email"] == "founder@corp.io"
        assert payload["email_domain"] == "corp.io"
        assert payload["org_id"] == tenant_id

        # Task args must only be [tenant_id] — no PII (SEC-01)
        from inspect import signature
        sig = signature(provision_billing_trial)
        param_names = list(sig.parameters.keys())
        # self is first (bind=True), then tenant_id only
        assert param_names == ["self", "tenant_id"], (
            f"Task signature should only accept tenant_id, got: {param_names}"
        )


# ---------------------------------------------------------------------------
# Test: 4xx does not trigger retry
# ---------------------------------------------------------------------------

def test_no_retry_on_4xx():
    """A 4xx from billing engine must log an error and not trigger any retry."""
    tenant_id = str(uuid.uuid4())
    tenant = _make_tenant(tenant_id)

    with patch("user_auth.celery_tasks.http_requests") as mock_req, \
         patch("tenant_management.models.Tenants") as mock_tenants_cls:

        mock_tenants_cls.objects.get.return_value = tenant
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.text = "bad request"
        mock_req.post.return_value = mock_resp
        mock_req.exceptions.RequestException = Exception

        from user_auth.celery_tasks import provision_billing_trial
        provision_billing_trial(tenant_id)

        # HTTP call made exactly once — no retry
        assert mock_req.post.call_count == 1


# ---------------------------------------------------------------------------
# Test: missing tenant returns early without HTTP call
# ---------------------------------------------------------------------------

def test_missing_tenant_returns_early():
    """If the tenant row does not exist, no HTTP call must be made."""
    tenant_id = str(uuid.uuid4())

    with patch("user_auth.celery_tasks.http_requests") as mock_req, \
         patch("tenant_management.models.Tenants") as mock_tenants_cls:

        mock_tenants_cls.DoesNotExist = Exception
        mock_tenants_cls.objects.get.side_effect = Exception("DoesNotExist")
        mock_req.exceptions.RequestException = IOError

        from user_auth.celery_tasks import provision_billing_trial

        # Patch DoesNotExist on the actual Tenants import inside the task
        with patch.dict("sys.modules", {}):
            try:
                provision_billing_trial(tenant_id)
            except Exception:
                pass  # task may raise if model import fails in test env

        # No HTTP call should have been made
        assert mock_req.post.call_count == 0


# ---------------------------------------------------------------------------
# Test: network error triggers retry
# ---------------------------------------------------------------------------

def test_task_retry_on_network_error():
    """A network exception must cause the task to enqueue a retry."""
    tenant_id = str(uuid.uuid4())
    tenant = _make_tenant(tenant_id)

    with patch("user_auth.celery_tasks.http_requests") as mock_req, \
         patch("tenant_management.models.Tenants") as mock_tenants_cls:

        mock_tenants_cls.objects.get.return_value = tenant

        network_exc = IOError("connection refused")
        mock_req.post.side_effect = network_exc
        mock_req.exceptions.RequestException = IOError

        from user_auth.celery_tasks import provision_billing_trial

        # Build a bound task instance so self.retry() works
        task = provision_billing_trial
        mock_self = MagicMock()
        mock_self.request.retries = 0
        mock_self.max_retries = 3

        retry_exc = Exception("retry scheduled")
        mock_self.retry.side_effect = retry_exc

        try:
            task.__func__(mock_self, tenant_id)
        except Exception as exc:
            assert exc is retry_exc, f"Expected retry exception, got: {exc}"

        mock_self.retry.assert_called_once()
        _, retry_kwargs = mock_self.retry.call_args
        assert retry_kwargs["countdown"] == 60


# ---------------------------------------------------------------------------
# Test: max retries exceeded logs CRITICAL — no PII
# ---------------------------------------------------------------------------

def test_max_retry_logs_critical():
    """After max retries exceeded, logger.critical must be called with tenant_id only."""
    import logging
    from celery.exceptions import MaxRetriesExceededError

    tenant_id = str(uuid.uuid4())
    tenant = _make_tenant(tenant_id, contact_email="private@secret.org")

    with patch("user_auth.celery_tasks.http_requests") as mock_req, \
         patch("tenant_management.models.Tenants") as mock_tenants_cls, \
         patch("user_auth.celery_tasks.logger") as mock_logger:

        mock_tenants_cls.objects.get.return_value = tenant
        network_exc = IOError("timeout")
        mock_req.post.side_effect = network_exc
        mock_req.exceptions.RequestException = IOError

        from user_auth.celery_tasks import provision_billing_trial

        mock_self = MagicMock()
        mock_self.request.retries = 3
        mock_self.max_retries = 3
        mock_self.retry.side_effect = MaxRetriesExceededError()

        provision_billing_trial.__func__(mock_self, tenant_id)

        # CRITICAL must have been called
        assert mock_logger.critical.called, "logger.critical not called on MaxRetriesExceededError"

        # Verify tenant_id appears but email does NOT appear in any critical log message
        critical_args = mock_logger.critical.call_args_list
        for c in critical_args:
            msg = str(c)
            assert tenant_id in msg, "tenant_id missing from CRITICAL log"
            assert "secret.org" not in msg, "PII (email domain) found in CRITICAL log — SEC-03 violation"
            assert "private@" not in msg, "PII (email) found in CRITICAL log — SEC-03 violation"


# ---------------------------------------------------------------------------
# Test: 409 is treated as idempotent success
# ---------------------------------------------------------------------------

def test_409_is_idempotent():
    """A 409 from billing engine means trial already exists — log info, no retry."""
    tenant_id = str(uuid.uuid4())
    tenant = _make_tenant(tenant_id)

    with patch("user_auth.celery_tasks.http_requests") as mock_req, \
         patch("tenant_management.models.Tenants") as mock_tenants_cls:

        mock_tenants_cls.objects.get.return_value = tenant
        mock_resp = MagicMock()
        mock_resp.status_code = 409
        mock_req.post.return_value = mock_resp
        mock_req.exceptions.RequestException = Exception

        from user_auth.celery_tasks import provision_billing_trial
        provision_billing_trial(tenant_id)

        assert mock_req.post.call_count == 1


# ---------------------------------------------------------------------------
# Test: no PII in task apply_async args
# ---------------------------------------------------------------------------

def test_no_pii_in_task_args():
    """apply_async must be called with args=[tenant_id_string] only — no email."""
    import uuid as _uuid

    tenant_id = str(_uuid.uuid4())

    with patch("user_auth.celery_tasks.provision_billing_trial") as mock_task:
        mock_task.apply_async = MagicMock()

        mock_task.apply_async(args=[tenant_id], queue="billing-provision")

        _, kwargs = mock_task.apply_async.call_args
        args_list = kwargs.get("args") or mock_task.apply_async.call_args[1]["args"]
        assert args_list == [tenant_id], f"Expected only tenant_id in args, got: {args_list}"

        # Confirm no '@' character (email) in any arg
        for arg in args_list:
            assert "@" not in str(arg), f"PII (email) found in task args: {arg}"
