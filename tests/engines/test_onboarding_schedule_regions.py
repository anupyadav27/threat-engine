"""
Unit tests for onboarding-C8: include_regions / exclude_regions on Schedule ORM.

Tests cover:
  - AC1: ScheduleCreate / ScheduleUpdate models have the 4 new fields
  - AC2/AC3: create_schedule() and get_schedule() read/write the 4 fields
  - AC4/AC5: PATCH ScheduleUpdate allows the fields; extra fields silently dropped
  - AC6: ArgoClient.submit_pipeline() receives exclude_regions parameter
  - AC8: Schedules without new columns return null (not errors)
"""
import json
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# AC1 — ScheduleCreate / ScheduleUpdate model fields
# ---------------------------------------------------------------------------


def test_schedule_create_model_has_region_fields() -> None:
    """ScheduleCreate in models/schedule.py has all 4 new optional fields."""
    from engines.onboarding.models.schedule import ScheduleCreate
    import inspect

    fields = ScheduleCreate.model_fields if hasattr(ScheduleCreate, "model_fields") else ScheduleCreate.__fields__
    for field_name in ("include_regions", "exclude_regions", "include_services", "exclude_services"):
        assert field_name in fields, f"ScheduleCreate missing field: {field_name}"
        # Default must be None (Optional)
        default = fields[field_name].default if hasattr(fields[field_name], "default") else None
        assert default is None, f"{field_name} default should be None, got {default!r}"


def test_schedule_update_model_has_region_fields() -> None:
    """ScheduleUpdate in models/schedule.py has all 4 new optional fields."""
    from engines.onboarding.models.schedule import ScheduleUpdate

    fields = ScheduleUpdate.model_fields if hasattr(ScheduleUpdate, "model_fields") else ScheduleUpdate.__fields__
    for field_name in ("include_regions", "exclude_regions", "include_services", "exclude_services"):
        assert field_name in fields, f"ScheduleUpdate missing field: {field_name}"


def test_schedule_response_model_has_region_fields() -> None:
    """ScheduleResponse in models/schedule.py has all 4 new optional fields."""
    from engines.onboarding.models.schedule import ScheduleResponse

    fields = ScheduleResponse.model_fields if hasattr(ScheduleResponse, "model_fields") else ScheduleResponse.__fields__
    for field_name in ("include_regions", "exclude_regions", "include_services", "exclude_services"):
        assert field_name in fields, f"ScheduleResponse missing field: {field_name}"


# ---------------------------------------------------------------------------
# AC5 — ScheduleUpdate extra='ignore'
# ---------------------------------------------------------------------------


def test_schedule_update_extra_fields_ignored() -> None:
    """PATCH ScheduleUpdate silently drops unknown fields (no mass-assignment)."""
    from engines.onboarding.api.schedules import ScheduleUpdate

    # Attempt to set tenant_id and credential_ref — must be silently dropped
    body = ScheduleUpdate(
        **{
            "exclude_regions": ["ap-east-1"],
            "tenant_id": "evil-tenant",          # must be dropped
            "credential_ref": "stolen/secret",   # must be dropped
        }
    )
    dumped = body.model_dump() if hasattr(body, "model_dump") else body.dict()
    assert "tenant_id" not in dumped
    assert "credential_ref" not in dumped
    assert dumped.get("exclude_regions") == ["ap-east-1"]


def test_api_schedule_update_has_extra_ignore() -> None:
    """ScheduleUpdate in api/schedules.py has Config.extra == 'ignore'."""
    from engines.onboarding.api.schedules import ScheduleUpdate

    config = getattr(ScheduleUpdate, "model_config", None) or getattr(ScheduleUpdate, "Config", None)
    if config is None:
        pytest.skip("Cannot inspect Config")
    # Pydantic v2 stores in model_config dict; v1 in Config class
    if isinstance(config, dict):
        assert config.get("extra") == "ignore"
    else:
        assert getattr(config, "extra", None) == "ignore"


# ---------------------------------------------------------------------------
# AC2 / AC3 — create_schedule writes and get_schedule reads the 4 fields
# ---------------------------------------------------------------------------


def _make_fake_row(overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Return a realistic dict that mimics a DB row from the schedules table."""
    row: Dict[str, Any] = {
        "schedule_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "account_id":  "11111111-2222-3333-4444-555555555555",
        "tenant_id":   "tttttttt-tttt-tttt-tttt-tttttttttttt",
        "customer_id": "cccccccc-cccc-cccc-cccc-cccccccccccc",
        "schedule_name": "test-schedule",
        "cron_expression": "0 2 * * 0",
        "timezone": "UTC",
        "enabled": True,
        "include_regions": None,
        "exclude_regions": None,
        "include_services": None,
        "exclude_services": None,
        "engines_requested": ["discovery", "check"],
        "next_run_at": None,
        "last_run_at": None,
        "run_count": 0,
        "success_count": 0,
        "failure_count": 0,
        "notify_on_success": False,
        "notify_on_failure": True,
        "notification_emails": None,
        "created_at": "2026-01-01T00:00:00+00:00",
        "updated_at": "2026-01-01T00:00:00+00:00",
    }
    if overrides:
        row.update(overrides)
    return row


def test_create_schedule_passes_lists_not_json_strings() -> None:
    """
    create_schedule() must pass Python lists to psycopg2, not json.dumps() strings.
    Verify the cursor.execute call receives list objects for TEXT[] columns.
    """
    from engines.onboarding.database.schedule_operations import create_schedule

    fake_row = _make_fake_row({
        "include_regions": ["us-east-1", "eu-west-1"],
        "exclude_regions": ["ap-east-1"],
        "include_services": ["ec2", "s3"],
        "exclude_services": ["glacier"],
    })

    mock_cur = MagicMock()
    mock_cur.fetchone.return_value = fake_row
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cur

    with patch(
        "engines.onboarding.database.schedule_operations.get_db_connection",
        return_value=mock_conn,
    ):
        result = create_schedule({
            "account_id":     "11111111-2222-3333-4444-555555555555",
            "tenant_id":      "tttttttt-tttt-tttt-tttt-tttttttttttt",
            "customer_id":    "cccccccc-cccc-cccc-cccc-cccccccccccc",
            "include_regions": ["us-east-1", "eu-west-1"],
            "exclude_regions": ["ap-east-1"],
            "include_services": ["ec2", "s3"],
            "exclude_services": ["glacier"],
        })

    # Verify execute was called
    assert mock_cur.execute.called

    # Extract the VALUES tuple that was passed to execute()
    call_args = mock_cur.execute.call_args
    values_tuple = call_args[0][1]  # positional: (sql, values)

    # Locate the TEXT[] values (positions 8-11 in the INSERT: include_regions, exclude_regions,
    # include_services, exclude_services)
    # They must be Python lists — not strings produced by json.dumps()
    for v in values_tuple:
        if isinstance(v, str) and v.startswith("["):
            pytest.fail(
                f"json.dumps() string found in VALUES tuple: {v!r}. "
                "TEXT[] columns must receive Python lists, not JSON strings."
            )

    assert result["include_regions"] == ["us-east-1", "eu-west-1"]
    assert result["exclude_regions"] == ["ap-east-1"]


def test_get_schedule_returns_region_fields() -> None:
    """get_schedule() returns all 4 new fields from the DB row."""
    from engines.onboarding.database.schedule_operations import get_schedule

    fake_row = _make_fake_row({
        "include_regions": ["us-east-1"],
        "exclude_regions": ["ap-east-1"],
        "include_services": ["ec2"],
        "exclude_services": ["glacier"],
    })

    mock_cur = MagicMock()
    mock_cur.fetchone.return_value = fake_row
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cur

    with patch(
        "engines.onboarding.database.schedule_operations.get_db_connection",
        return_value=mock_conn,
    ):
        result = get_schedule("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")

    assert result is not None
    assert result["include_regions"] == ["us-east-1"]
    assert result["exclude_regions"] == ["ap-east-1"]
    assert result["include_services"] == ["ec2"]
    assert result["exclude_services"] == ["glacier"]


# ---------------------------------------------------------------------------
# AC8 — existing schedules without new columns return null, not errors
# ---------------------------------------------------------------------------


def test_get_schedule_null_region_fields_no_error() -> None:
    """Schedules without region columns return None for each field (not KeyError)."""
    from engines.onboarding.database.schedule_operations import get_schedule

    fake_row = _make_fake_row()  # include_regions etc. are None by default

    mock_cur = MagicMock()
    mock_cur.fetchone.return_value = fake_row
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cur

    with patch(
        "engines.onboarding.database.schedule_operations.get_db_connection",
        return_value=mock_conn,
    ):
        result = get_schedule("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")

    assert result is not None
    assert result.get("include_regions") is None
    assert result.get("exclude_regions") is None
    assert result.get("include_services") is None
    assert result.get("exclude_services") is None


# ---------------------------------------------------------------------------
# AC6 — ArgoClient.submit_pipeline receives exclude_regions
# ---------------------------------------------------------------------------


def test_argo_client_submit_pipeline_has_exclude_regions_param() -> None:
    """submit_pipeline() accepts exclude_regions and adds it to workflow parameters."""
    from engines.onboarding.scheduler.argo_client import ArgoClient

    client = ArgoClient()
    captured_body: Dict[str, Any] = {}

    def fake_post(url: str, body: Dict, context: str = "") -> Dict[str, Any]:
        captured_body.update(body)
        return {"metadata": {"name": "cspm-scan-abc123"}}

    client._post = fake_post  # type: ignore[method-assign]

    client.submit_pipeline(
        scan_run_id="scan-001",
        tenant_id="tenant-001",
        account_id="account-001",
        provider="aws",
        credential_type="access_key",
        credential_ref="threat-engine/account/123456789012",
        include_regions=["us-east-1"],
        exclude_regions=["ap-east-1", "me-south-1"],
        include_services=["ec2"],
        exclude_services=["glacier"],
    )

    # The parameters are submitted as "name=value" strings in submitOptions.parameters
    submit_params: List[str] = captured_body["submitOptions"]["parameters"]
    params_dict = dict(p.split("=", 1) for p in submit_params)

    assert params_dict.get("exclude-regions") == "ap-east-1,me-south-1", (
        f"exclude-regions not forwarded correctly. Got: {params_dict}"
    )
    assert params_dict.get("include-regions") == "us-east-1"
    assert params_dict.get("exclude-services") == "glacier"
    assert params_dict.get("include-services") == "ec2"


def test_argo_client_submit_pipeline_empty_exclude_regions() -> None:
    """submit_pipeline() with no exclude_regions sends an empty string parameter."""
    from engines.onboarding.scheduler.argo_client import ArgoClient

    client = ArgoClient()
    captured_body: Dict[str, Any] = {}

    def fake_post(url: str, body: Dict, context: str = "") -> Dict[str, Any]:
        captured_body.update(body)
        return {"metadata": {"name": "cspm-scan-xyz"}}

    client._post = fake_post  # type: ignore[method-assign]

    client.submit_pipeline(
        scan_run_id="scan-002",
        tenant_id="tenant-001",
        account_id="account-001",
    )

    submit_params: List[str] = captured_body["submitOptions"]["parameters"]
    params_dict = dict(p.split("=", 1) for p in submit_params)

    assert params_dict.get("exclude-regions") == ""
    assert params_dict.get("include-regions") == ""


# ---------------------------------------------------------------------------
# AC4 — update_schedule() persists region fields through the allowed-list
# ---------------------------------------------------------------------------


def test_update_schedule_persists_exclude_regions() -> None:
    """update_schedule() with exclude_regions passes the list to the DB UPDATE."""
    from engines.onboarding.database.schedule_operations import update_schedule

    fake_row = _make_fake_row({"exclude_regions": ["ap-east-1"]})

    mock_cur = MagicMock()
    mock_cur.fetchone.return_value = fake_row
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cur

    with patch(
        "engines.onboarding.database.schedule_operations.get_db_connection",
        return_value=mock_conn,
    ):
        result = update_schedule(
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            {"exclude_regions": ["ap-east-1"]},
        )

    assert result is not None
    assert mock_cur.execute.called

    # The VALUES passed to execute must NOT contain a json.dumps() string for TEXT[]
    call_args = mock_cur.execute.call_args
    values_list = call_args[0][1]
    for v in values_list:
        if isinstance(v, str) and v.startswith("["):
            pytest.fail(
                f"json.dumps() string found in UPDATE VALUES: {v!r}. "
                "TEXT[] columns must receive Python lists."
            )
