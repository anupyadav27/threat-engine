"""
Unit tests for the X-Internal-Secret auth gate on POST /trial/provision.

Story: BILL-S11 — Internal Service Auth Secret

Run with:
    pytest engines/billing/tests/test_trial_provision_auth.py -v
"""

import hmac
import importlib
import inspect
import logging
import os
import sys
from types import ModuleType
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_CORRECT_SECRET = "a4f8c2d1e3b5a7f9c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b6c8d0e2f4a6"
_WRONG_SECRET = "wrong-value-does-not-match"

_VALID_PAYLOAD: Dict[str, Any] = {
    "org_id": "00000000-0000-0000-0000-000000000001",
    "email_domain": "acme.com",
    "admin_email": "admin@acme.com",
}


def _build_client(secret_env: str = _CORRECT_SECRET) -> TestClient:
    """Return a TestClient with the trial router mounted and DB fully mocked.

    Args:
        secret_env: Value to set for BILLING_INTERNAL_SECRET env var.

    Returns:
        Configured TestClient ready for requests.
    """
    # Stub out the db module before importing the router so no real DB
    # connection is attempted during tests.
    db_stub = MagicMock()
    conn_stub = MagicMock()
    cursor_stub = MagicMock()
    cursor_stub.fetchone.side_effect = [
        (0,),           # domain_count query
        (0,),           # admin_domain_count query
        ("pro-plan-id",),  # pro plan lookup
    ]
    cursor_stub.rowcount = 1
    conn_stub.cursor.return_value = cursor_stub
    db_stub.get_conn.return_value = conn_stub

    # Load the real Pydantic models so FastAPI can build the request schema.
    # Using MagicMock subclasses here causes Pydantic to reject the type at
    # router mount time; the real BaseModel subclasses are required.
    import importlib.util as _ilu
    import os as _os

    _models_spec = _ilu.spec_from_file_location(
        "models",
        _os.path.join(_os.path.dirname(__file__), "..", "models.py"),
    )
    assert _models_spec is not None
    models_stub = _ilu.module_from_spec(_models_spec)
    _models_spec.loader.exec_module(models_stub)  # type: ignore[union-attr]

    with patch.dict(
        os.environ,
        {"BILLING_INTERNAL_SECRET": secret_env},
        clear=False,
    ):
        with patch.dict(
            sys.modules,
            {"db": db_stub, "models": models_stub},
        ):
            # Force re-import so the module-level _BILLING_INTERNAL_SECRET
            # is read with the patched env var.
            if "routers.trial" in sys.modules:
                del sys.modules["routers.trial"]
            if "trial" in sys.modules:
                del sys.modules["trial"]

            import importlib.util

            spec = importlib.util.spec_from_file_location(
                "routers.trial",
                os.path.join(
                    os.path.dirname(__file__),
                    "..",
                    "routers",
                    "trial.py",
                ),
            )
            assert spec is not None
            trial_mod: ModuleType = importlib.util.module_from_spec(spec)
            sys.modules["routers.trial"] = trial_mod
            spec.loader.exec_module(trial_mod)  # type: ignore[union-attr]

            app = FastAPI()
            app.include_router(trial_mod.router, prefix="/api/v1/billing")
            return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# AC-1: POST without header → 403
# ---------------------------------------------------------------------------

def test_missing_secret_returns_403() -> None:
    """POST to provision endpoint without X-Internal-Secret must return 403."""
    client = _build_client(secret_env=_CORRECT_SECRET)
    resp = client.post("/api/v1/billing/trial/provision", json=_VALID_PAYLOAD)
    assert resp.status_code == 403, f"Expected 403, got {resp.status_code}: {resp.text}"


# ---------------------------------------------------------------------------
# AC-2: POST with wrong secret → 403
# ---------------------------------------------------------------------------

def test_wrong_secret_returns_403() -> None:
    """POST with incorrect X-Internal-Secret must return 403."""
    client = _build_client(secret_env=_CORRECT_SECRET)
    resp = client.post(
        "/api/v1/billing/trial/provision",
        json=_VALID_PAYLOAD,
        headers={"X-Internal-Secret": _WRONG_SECRET},
    )
    assert resp.status_code == 403, f"Expected 403, got {resp.status_code}: {resp.text}"


# ---------------------------------------------------------------------------
# AC-3: POST with correct secret → 201
# ---------------------------------------------------------------------------

def test_correct_secret_returns_201() -> None:
    """POST with the correct X-Internal-Secret must reach business logic and return 201."""
    client = _build_client(secret_env=_CORRECT_SECRET)
    resp = client.post(
        "/api/v1/billing/trial/provision",
        json=_VALID_PAYLOAD,
        headers={"X-Internal-Secret": _CORRECT_SECRET},
    )
    assert resp.status_code == 201, f"Expected 201, got {resp.status_code}: {resp.text}"


# ---------------------------------------------------------------------------
# AC-4: BILLING_INTERNAL_SECRET not set → 503 (fail closed)
# ---------------------------------------------------------------------------

def test_unconfigured_secret_returns_503() -> None:
    """If BILLING_INTERNAL_SECRET env var is empty, all provision calls must return 503."""
    client = _build_client(secret_env="")
    resp = client.post(
        "/api/v1/billing/trial/provision",
        json=_VALID_PAYLOAD,
        headers={"X-Internal-Secret": "anything"},
    )
    assert resp.status_code == 503, f"Expected 503, got {resp.status_code}: {resp.text}"


# ---------------------------------------------------------------------------
# AC-6: Secret value never appears in log output
# ---------------------------------------------------------------------------

def test_secret_not_in_logs(caplog: pytest.LogCaptureFixture) -> None:
    """After a successful provision call, the secret value must not appear in any log record."""
    client = _build_client(secret_env=_CORRECT_SECRET)

    with caplog.at_level(logging.DEBUG):
        resp = client.post(
            "/api/v1/billing/trial/provision",
            json=_VALID_PAYLOAD,
            headers={"X-Internal-Secret": _CORRECT_SECRET},
        )

    assert resp.status_code == 201, f"Expected 201 for this sub-test, got {resp.status_code}"

    full_log = "\n".join(r.getMessage() for r in caplog.records)
    assert _CORRECT_SECRET not in full_log, (
        "SECRET VALUE found in log output — SEC-04 violation"
    )


# ---------------------------------------------------------------------------
# SEC-01: Code review — hmac.compare_digest used, not ==
# ---------------------------------------------------------------------------

def test_compare_digest_not_equality() -> None:
    """Source of trial.py must use hmac.compare_digest, not == for secret comparison."""
    trial_path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "routers",
        "trial.py",
    )
    source = open(trial_path).read()  # noqa: WPS515 — intentional source inspection

    assert "hmac.compare_digest" in source, (
        "hmac.compare_digest not found in trial.py — SEC-01 violation"
    )
    # Ensure naive equality comparison is not used for the secret
    assert "== _BILLING_INTERNAL_SECRET" not in source, (
        "Naive == comparison found for _BILLING_INTERNAL_SECRET — SEC-01 violation"
    )
    assert "_BILLING_INTERNAL_SECRET ==" not in source, (
        "Naive == comparison found for _BILLING_INTERNAL_SECRET — SEC-01 violation"
    )
