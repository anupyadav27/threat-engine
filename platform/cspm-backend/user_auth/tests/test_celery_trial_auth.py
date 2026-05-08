"""
Unit tests verifying the provision_billing_trial Celery task sends
X-Internal-Secret header on every HTTP POST (BILL-S11).

Run with:
    pytest platform/cspm-backend/user_auth/tests/test_celery_trial_auth.py -v
"""

import os
import uuid
from unittest.mock import MagicMock, patch

import pytest

import user_auth.celery_tasks  # noqa: F401 — ensure module is importable for patching


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SECRET = "a4f8c2d1e3b5a7f9c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b6c8d0e2f4a6"


def _make_tenant(tenant_id: str, contact_email: str = "founder@acme.com") -> MagicMock:
    """Return a mock Tenants-like object with the given email.

    Args:
        tenant_id: UUID string for the tenant.
        contact_email: Email address to attach to the mock.

    Returns:
        MagicMock configured to look like a Tenants instance.
    """
    t = MagicMock()
    t.id = tenant_id
    t.contact_email = contact_email
    return t


# ---------------------------------------------------------------------------
# AC-7: Celery task sends X-Internal-Secret header
# ---------------------------------------------------------------------------

def test_celery_task_sends_secret_header() -> None:
    """provision_billing_trial must include X-Internal-Secret in every HTTP POST.

    The value must match the BILLING_INTERNAL_SECRET env var (which in production
    is loaded from the K8s secret and therefore matches the billing engine's copy).
    """
    tenant_id = str(uuid.uuid4())
    tenant = _make_tenant(tenant_id, contact_email="founder@corp.io")

    with patch.dict(os.environ, {"BILLING_INTERNAL_SECRET": _SECRET}, clear=False), \
         patch("user_auth.celery_tasks.http_requests") as mock_req, \
         patch("tenant_management.models.Tenants") as mock_tenants_cls:

        mock_tenants_cls.objects.get.return_value = tenant
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_req.post.return_value = mock_resp
        mock_req.exceptions.RequestException = Exception

        from user_auth.celery_tasks import provision_billing_trial

        # Call the underlying function directly (bypassing Celery machinery)
        provision_billing_trial(tenant_id)

        assert mock_req.post.call_count == 1, "Expected exactly one HTTP POST"

        call_kwargs = mock_req.post.call_args
        # headers may be positional or keyword — normalise
        headers = (
            call_kwargs.kwargs.get("headers")
            or (call_kwargs.args[2] if len(call_kwargs.args) > 2 else None)
        )
        assert headers is not None, "No headers argument found on http_requests.post call"
        assert "X-Internal-Secret" in headers, (
            "X-Internal-Secret header missing from provision_billing_trial HTTP POST"
        )
        assert headers["X-Internal-Secret"] == _SECRET, (
            "X-Internal-Secret header value does not match BILLING_INTERNAL_SECRET env var"
        )


def test_celery_task_sends_secret_even_when_empty() -> None:
    """Task must still send the X-Internal-Secret key even when env var is empty.

    The billing engine is responsible for rejecting empty secrets (503). The
    task's job is only to always include the header so behaviour is predictable.
    """
    tenant_id = str(uuid.uuid4())
    tenant = _make_tenant(tenant_id)

    with patch.dict(os.environ, {"BILLING_INTERNAL_SECRET": ""}, clear=False), \
         patch("user_auth.celery_tasks.http_requests") as mock_req, \
         patch("tenant_management.models.Tenants") as mock_tenants_cls:

        mock_tenants_cls.objects.get.return_value = tenant
        mock_resp = MagicMock()
        mock_resp.status_code = 503  # billing engine will reject
        mock_resp.text = "Service misconfigured"
        mock_req.post.return_value = mock_resp
        mock_req.exceptions.RequestException = Exception

        from user_auth.celery_tasks import provision_billing_trial

        provision_billing_trial(tenant_id)

        call_kwargs = mock_req.post.call_args
        headers = call_kwargs.kwargs.get("headers")
        assert headers is not None
        # Header key must still be present (value will be empty string)
        assert "X-Internal-Secret" in headers, (
            "X-Internal-Secret header must always be present in the HTTP POST"
        )


def test_secret_value_not_logged() -> None:
    """The secret value must not appear in any log record emitted by the task."""
    import logging

    tenant_id = str(uuid.uuid4())
    tenant = _make_tenant(tenant_id)

    with patch.dict(os.environ, {"BILLING_INTERNAL_SECRET": _SECRET}, clear=False), \
         patch("user_auth.celery_tasks.http_requests") as mock_req, \
         patch("tenant_management.models.Tenants") as mock_tenants_cls:

        mock_tenants_cls.objects.get.return_value = tenant
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_req.post.return_value = mock_resp
        mock_req.exceptions.RequestException = Exception

        from user_auth.celery_tasks import provision_billing_trial

        with patch("user_auth.celery_tasks.logger") as mock_logger:
            provision_billing_trial(tenant_id)

            all_log_calls = (
                mock_logger.info.call_args_list
                + mock_logger.warning.call_args_list
                + mock_logger.error.call_args_list
                + mock_logger.debug.call_args_list
                + mock_logger.critical.call_args_list
            )
            for log_call in all_log_calls:
                log_str = str(log_call)
                assert _SECRET not in log_str, (
                    f"Secret value found in log output — SEC-04 violation: {log_str[:100]}"
                )
