"""
Schedules API
Manages scan schedules for cloud accounts.
"""
import uuid
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from engine_onboarding.database.schedule_operations import (
    create_schedule,
    get_schedule,
    list_schedules,
    update_schedule,
    delete_schedule,
)
from engine_onboarding.database.cloud_accounts_operations import get_cloud_account

try:
    from engine_common.logger import setup_logger
    logger = setup_logger(__name__, engine_name="onboarding")
except Exception:
    import logging
    logger = logging.getLogger(__name__)


router = APIRouter(prefix="/api/v1/schedules", tags=["schedules"])


# ── Cron presets ──────────────────────────────────────────────────────────────

CRON_PRESETS = {
    "hourly":         "0 * * * *",
    "daily":          "0 2 * * *",
    "weekly":         "0 2 * * 0",
    "bi_weekly":      "0 2 * * 1/2",
    "monthly":        "0 2 1 * *",
}

ALL_ENGINES = ["discovery", "check", "inventory", "threat", "compliance", "iam", "datasec"]


def _next_run_from_cron(cron_expression: str, tz: str = "UTC") -> Optional[datetime]:
    """Return the next run timestamp for a cron expression. Falls back gracefully."""
    try:
        from croniter import croniter
        import pytz
        zone = pytz.timezone(tz)
        base = datetime.now(zone)
        it = croniter(cron_expression, base)
        dt = it.get_next(datetime)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


# ── Pydantic models ───────────────────────────────────────────────────────────

class ScheduleCreate(BaseModel):
    account_id:          str
    tenant_id:           str
    customer_id:         str
    schedule_name:       Optional[str]   = None
    cron_expression:     str             = Field("0 2 * * 0", description="Standard 5-field cron expression")
    preset:              Optional[str]   = Field(None, description="hourly|daily|weekly|bi_weekly|monthly — overrides cron_expression")
    timezone:            str             = "UTC"
    enabled:             bool            = True
    include_regions:     Optional[List[str]] = None
    include_services:    Optional[List[str]] = None
    exclude_services:    Optional[List[str]] = None
    engines_requested:   List[str]       = ALL_ENGINES
    notify_on_success:   bool            = False
    notify_on_failure:   bool            = True
    notification_emails: Optional[List[str]] = None


class ScheduleUpdate(BaseModel):
    schedule_name:       Optional[str]          = None
    cron_expression:     Optional[str]           = None
    preset:              Optional[str]           = None
    timezone:            Optional[str]           = None
    enabled:             Optional[bool]          = None
    include_regions:     Optional[List[str]]     = None
    include_services:    Optional[List[str]]     = None
    exclude_services:    Optional[List[str]]     = None
    engines_requested:   Optional[List[str]]     = None
    notify_on_success:   Optional[bool]          = None
    notify_on_failure:   Optional[bool]          = None
    notification_emails: Optional[List[str]]     = None


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/presets")
async def get_presets():
    """Return available cron presets with human labels."""
    return {
        "presets": [
            {"key": "hourly",    "label": "Every Hour",         "cron": CRON_PRESETS["hourly"]},
            {"key": "daily",     "label": "Every Day (2 AM)",   "cron": CRON_PRESETS["daily"]},
            {"key": "weekly",    "label": "Every Sunday (2 AM)","cron": CRON_PRESETS["weekly"]},
            {"key": "bi_weekly", "label": "Every 2 Weeks",      "cron": CRON_PRESETS["bi_weekly"]},
            {"key": "monthly",   "label": "Every Month (1st)",  "cron": CRON_PRESETS["monthly"]},
        ],
        "engines": ALL_ENGINES,
    }


@router.post("", status_code=201)
async def create_schedule_endpoint(body: ScheduleCreate):
    """Create a new schedule for a cloud account."""
    account = get_cloud_account(body.account_id)
    if not account:
        raise HTTPException(status_code=404, detail=f"Account {body.account_id} not found")

    # Preset overrides cron_expression
    cron = CRON_PRESETS.get(body.preset, body.cron_expression) if body.preset else body.cron_expression

    data = body.model_dump(exclude={"preset"})
    data["cron_expression"] = cron
    data["next_run_at"] = _next_run_from_cron(cron, body.timezone)

    try:
        schedule = create_schedule(data)
        logger.info(f"Schedule created: {schedule['schedule_id']} for account {body.account_id}")
        return schedule
    except Exception as e:
        logger.error(f"Error creating schedule: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("")
async def list_schedules_endpoint(
    account_id:   Optional[str] = Query(None),
    tenant_id:    Optional[str] = Query(None),
    customer_id:  Optional[str] = Query(None),
    enabled_only: bool          = Query(False),
    limit:        int           = Query(100, ge=1, le=500),
    offset:       int           = Query(0, ge=0),
):
    """List schedules with optional filters."""
    try:
        schedules = list_schedules(
            account_id=account_id,
            tenant_id=tenant_id,
            customer_id=customer_id,
            enabled_only=enabled_only,
            limit=limit,
            offset=offset,
        )
        return {"schedules": schedules, "count": len(schedules)}
    except Exception as e:
        logger.error(f"Error listing schedules: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{schedule_id}")
async def get_schedule_endpoint(schedule_id: str):
    """Get a schedule by ID."""
    schedule = get_schedule(schedule_id)
    if not schedule:
        raise HTTPException(status_code=404, detail=f"Schedule {schedule_id} not found")
    return schedule


@router.patch("/{schedule_id}")
async def update_schedule_endpoint(schedule_id: str, body: ScheduleUpdate):
    """Update a schedule."""
    updates = {k: v for k, v in body.model_dump().items() if v is not None}

    # Preset overrides cron
    if updates.get("preset"):
        updates["cron_expression"] = CRON_PRESETS.get(updates.pop("preset"), updates.get("cron_expression", "0 2 * * 0"))
    else:
        updates.pop("preset", None)

    # Recalculate next_run_at if cron changed
    if "cron_expression" in updates:
        tz = updates.get("timezone", "UTC")
        updates["next_run_at"] = _next_run_from_cron(updates["cron_expression"], tz)

    try:
        schedule = update_schedule(schedule_id, updates)
        if not schedule:
            raise HTTPException(status_code=404, detail=f"Schedule {schedule_id} not found")
        return schedule
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error updating schedule {schedule_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{schedule_id}", status_code=200)
async def delete_schedule_endpoint(schedule_id: str):
    """Delete a schedule."""
    deleted = delete_schedule(schedule_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Schedule {schedule_id} not found")
    return {"message": f"Schedule {schedule_id} deleted"}


@router.post("/{schedule_id}/enable")
async def enable_schedule(schedule_id: str):
    """Enable a schedule."""
    schedule = update_schedule(schedule_id, {"enabled": True})
    if not schedule:
        raise HTTPException(status_code=404, detail=f"Schedule {schedule_id} not found")
    return schedule


@router.post("/{schedule_id}/disable")
async def disable_schedule(schedule_id: str):
    """Disable a schedule without deleting it."""
    schedule = update_schedule(schedule_id, {"enabled": False})
    if not schedule:
        raise HTTPException(status_code=404, detail=f"Schedule {schedule_id} not found")
    return schedule


@router.post("/{schedule_id}/run-now", status_code=202)
async def run_now(schedule_id: str):
    """
    Trigger an immediate on-demand scan run for this schedule.
    Creates a scan_run record and fires the Argo workflow.
    Returns the scan_run_id so the UI can poll for status.
    """
    schedule = get_schedule(schedule_id)
    if not schedule:
        raise HTTPException(status_code=404, detail=f"Schedule {schedule_id} not found")

    account = get_cloud_account(schedule["account_id"])
    if not account:
        raise HTTPException(status_code=404, detail="Associated account not found")

    scan_run_id = str(uuid.uuid4())

    # Attempt to create scan_run record
    try:
        from engine_onboarding.database.scan_run_operations import create_scan_run
        scan_run = create_scan_run({
            "scan_run_id":       scan_run_id,
            "customer_id":       schedule["customer_id"],
            "tenant_id":         schedule["tenant_id"],
            "account_id":        schedule["account_id"],
            "schedule_uuid":     schedule_id,
            "provider":          account["provider"],
            "credential_type":   account["credential_type"],
            "credential_ref":    account["credential_ref"],
            "scan_type":         "full",
            "trigger_type":      "manual",
            "engines_requested": schedule.get("engines_requested", ALL_ENGINES),
            "include_regions":   schedule.get("include_regions"),
            "include_services":  schedule.get("include_services"),
            "exclude_services":  schedule.get("exclude_services"),
        })
    except ImportError:
        # scan_run_operations not yet implemented — return scan_run_id only
        scan_run = {"scan_run_id": scan_run_id}

    # Fire Argo workflow (best-effort, non-blocking)
    try:
        from engine_onboarding.scheduler.argo_client import trigger_scan
        await trigger_scan(
            scan_run_id=scan_run_id,
            tenant_id=schedule["tenant_id"],
            account_id=schedule["account_id"],
        )
    except Exception as e:
        logger.warning(f"Argo trigger failed for run-now {scan_run_id}: {e}")

    return {
        "message":     "Scan triggered",
        "scan_run_id": scan_run_id,
        "account_id":  schedule["account_id"],
        "provider":    account["provider"],
    }
