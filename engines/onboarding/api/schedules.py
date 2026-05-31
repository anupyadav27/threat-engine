"""
Schedules API
Manages scan schedules for cloud accounts.
"""
import os
import uuid
from datetime import datetime, timezone
from typing import Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

try:
    from engine_auth.fastapi.dependencies import require_permission, get_auth_context
    from engine_auth.core.models import AuthContext
    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False
    AuthContext = Any
    def require_permission(perm: str):  # type: ignore[misc]
        async def _noop():
            return None
        return _noop
    async def get_auth_context():  # type: ignore[misc]
        return None

from engine_onboarding.database.schedule_operations import (
    create_schedule,
    get_schedule,
    list_schedules,
    update_schedule,
    delete_schedule,
    get_active_schedules_for_tenant,
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
    exclude_regions:     Optional[List[str]] = None
    include_services:    Optional[List[str]] = None
    exclude_services:    Optional[List[str]] = None
    engines_requested:   List[str]       = ALL_ENGINES
    notify_on_success:   bool            = False
    notify_on_failure:   bool            = True
    notification_emails: Optional[List[str]] = None


class ScheduleUpdate(BaseModel):
    """PATCH body — allow-list only; unknown fields silently dropped (no mass-assignment)."""
    schedule_name:       Optional[str]          = None
    cron_expression:     Optional[str]           = None
    preset:              Optional[str]           = None
    timezone:            Optional[str]           = None
    enabled:             Optional[bool]          = None
    include_regions:     Optional[List[str]]     = None
    exclude_regions:     Optional[List[str]]     = None
    include_services:    Optional[List[str]]     = None
    exclude_services:    Optional[List[str]]     = None
    engines_requested:   Optional[List[str]]     = None
    notify_on_success:   Optional[bool]          = None
    notify_on_failure:   Optional[bool]          = None
    notification_emails: Optional[List[str]]     = None

    class Config:
        extra = 'ignore'


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/presets")
# RBAC: requires scans:read
async def get_presets(
    _: Any = Depends(require_permission("scans:read")),
):
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
# RBAC: requires scans:create
async def create_schedule_endpoint(
    body: ScheduleCreate,
    auth: Any = Depends(get_auth_context),
    _: Any = Depends(require_permission("scans:create")),
):
    """Create a new schedule for a cloud account."""
    account = get_cloud_account(body.account_id)
    if not account:
        raise HTTPException(status_code=404, detail=f"Account {body.account_id} not found")

    # Tenant isolation: verify the account belongs to the authenticated tenant
    if auth and getattr(auth, "engine_tenant_id", None):
        if account.get("tenant_id") != auth.engine_tenant_id:
            raise HTTPException(status_code=403, detail="Forbidden")

    # Preset overrides cron_expression
    cron = CRON_PRESETS.get(body.preset, body.cron_expression) if body.preset else body.cron_expression

    data = body.model_dump(exclude={"preset"})
    data["cron_expression"] = cron
    data["next_run_at"] = _next_run_from_cron(cron, body.timezone)

    # tenant_id must come from auth context — never trust request body
    if auth and getattr(auth, "engine_tenant_id", None):
        data["tenant_id"] = auth.engine_tenant_id

    try:
        schedule = create_schedule(data)
        logger.info(f"Schedule created: {schedule['schedule_id']} for account {body.account_id}")
        return schedule
    except Exception as e:
        logger.error(f"Error creating schedule: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("")
# RBAC: requires scans:read
async def list_schedules_endpoint(
    account_id:   Optional[str] = Query(None),
    tenant_id:    Optional[str] = Query(None),
    customer_id:  Optional[str] = Query(None),
    enabled_only: bool          = Query(False),
    limit:        int           = Query(100, ge=1, le=500),
    offset:       int           = Query(0, ge=0),
    auth: Any = Depends(get_auth_context),
    _: Any = Depends(require_permission("scans:read")),
):
    """List schedules with optional filters."""
    # Enforce tenant scope from auth context — prevent cross-tenant reads (AC4)
    if auth and getattr(auth, "engine_tenant_id", None):
        tenant_id = auth.engine_tenant_id
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
# RBAC: requires scans:read
async def get_schedule_endpoint(
    schedule_id: str,
    auth: Any = Depends(get_auth_context),
    _: Any = Depends(require_permission("scans:read")),
):
    """Get a schedule by ID."""
    schedule = get_schedule(schedule_id)
    if not schedule:
        raise HTTPException(status_code=404, detail=f"Schedule {schedule_id} not found")
    # Tenant isolation: cross-tenant reads return 403 (AC4, AC10)
    if auth and getattr(auth, "engine_tenant_id", None):
        if schedule.get("tenant_id") != auth.engine_tenant_id:
            raise HTTPException(status_code=403, detail="Forbidden")
    return schedule


@router.patch("/{schedule_id}")
# RBAC: requires scans:create
async def update_schedule_endpoint(
    schedule_id: str,
    body: ScheduleUpdate,
    auth: Any = Depends(get_auth_context),
    _: Any = Depends(require_permission("scans:create")),
):
    """Update a schedule."""
    # Tenant isolation: verify ownership before update (AC4, AC10)
    existing = get_schedule(schedule_id)
    if not existing:
        raise HTTPException(status_code=404, detail=f"Schedule {schedule_id} not found")
    if auth and getattr(auth, "engine_tenant_id", None):
        if existing.get("tenant_id") != auth.engine_tenant_id:
            raise HTTPException(status_code=403, detail="Forbidden")

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
# RBAC: requires scans:create
async def delete_schedule_endpoint(
    schedule_id: str,
    auth: Any = Depends(get_auth_context),
    _: Any = Depends(require_permission("scans:create")),
):
    """Delete a schedule."""
    # Tenant isolation: verify ownership before delete (AC4, AC10)
    schedule = get_schedule(schedule_id)
    if not schedule:
        raise HTTPException(status_code=404, detail=f"Schedule {schedule_id} not found")
    if auth and getattr(auth, "engine_tenant_id", None):
        if schedule.get("tenant_id") != auth.engine_tenant_id:
            raise HTTPException(status_code=403, detail="Forbidden")
    deleted = delete_schedule(schedule_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Schedule {schedule_id} not found")
    return {"message": f"Schedule {schedule_id} deleted"}


@router.post("/{schedule_id}/enable")
# RBAC: requires scans:create
async def enable_schedule(
    schedule_id: str,
    auth: Any = Depends(get_auth_context),
    _: Any = Depends(require_permission("scans:create")),
):
    """Enable a schedule."""
    # Tenant isolation: verify ownership before mutation (AC4, AC10)
    existing = get_schedule(schedule_id)
    if not existing:
        raise HTTPException(status_code=404, detail=f"Schedule {schedule_id} not found")
    if auth and getattr(auth, "engine_tenant_id", None):
        if existing.get("tenant_id") != auth.engine_tenant_id:
            raise HTTPException(status_code=403, detail="Forbidden")
    schedule = update_schedule(schedule_id, {"enabled": True})
    if not schedule:
        raise HTTPException(status_code=404, detail=f"Schedule {schedule_id} not found")
    return schedule


@router.post("/{schedule_id}/disable")
# RBAC: requires scans:create
async def disable_schedule(
    schedule_id: str,
    auth: Any = Depends(get_auth_context),
    _: Any = Depends(require_permission("scans:create")),
):
    """Disable a schedule without deleting it."""
    # Tenant isolation: verify ownership before mutation (AC4, AC10)
    existing = get_schedule(schedule_id)
    if not existing:
        raise HTTPException(status_code=404, detail=f"Schedule {schedule_id} not found")
    if auth and getattr(auth, "engine_tenant_id", None):
        if existing.get("tenant_id") != auth.engine_tenant_id:
            raise HTTPException(status_code=403, detail="Forbidden")
    schedule = update_schedule(schedule_id, {"enabled": False})
    if not schedule:
        raise HTTPException(status_code=404, detail=f"Schedule {schedule_id} not found")
    return schedule


@router.post("/{schedule_id}/run-now", status_code=202)
# RBAC: requires scans:create
async def run_now(
    schedule_id: str,
    auth: Any = Depends(get_auth_context),
    _: Any = Depends(require_permission("scans:create")),
):
    """
    Trigger an immediate on-demand scan run for this schedule.
    Creates a scan_run record and fires the Argo workflow.
    Returns the scan_run_id so the UI can poll for status.
    """
    schedule = get_schedule(schedule_id)
    if not schedule:
        raise HTTPException(status_code=404, detail=f"Schedule {schedule_id} not found")
    # Tenant isolation: verify ownership before triggering scan (AC4, AC10)
    if auth and getattr(auth, "engine_tenant_id", None):
        if schedule.get("tenant_id") != auth.engine_tenant_id:
            raise HTTPException(status_code=403, detail="Forbidden")

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
            provider=account.get("provider", "aws"),
            credential_type=account.get("credential_type", ""),
            credential_ref=account.get("credential_ref", ""),
            include_regions=schedule.get("include_regions") if isinstance(schedule.get("include_regions"), list) else None,
            exclude_regions=schedule.get("exclude_regions") if isinstance(schedule.get("exclude_regions"), list) else None,
            include_services=schedule.get("include_services") if isinstance(schedule.get("include_services"), list) else None,
            exclude_services=schedule.get("exclude_services") if isinstance(schedule.get("exclude_services"), list) else None,
        )
    except Exception as e:
        logger.warning(f"Argo trigger failed for run-now {scan_run_id}: {e}")

    return {
        "message":     "Scan triggered",
        "scan_run_id": scan_run_id,
        "account_id":  schedule["account_id"],
        "provider":    account["provider"],
    }


# ── Bulk run-all endpoint ─────────────────────────────────────────────────────

_MAX_BULK_SCANS = int(os.getenv("MAX_CONCURRENT_SCANS", "10"))
_HARD_MAX       = 20


@router.post("/run-all", status_code=202)
# RBAC: requires scans:create
async def run_all_schedules(
    tenant_id: str = Query(..., description="Trigger all active schedules for this tenant"),
    limit:     int = Query(10, ge=1, le=_HARD_MAX, description="Max concurrent scans to fire"),
    auth: Any = Depends(get_auth_context),
    _: Any = Depends(require_permission("scans:create")),
):
    """
    Trigger immediate scans for ALL active schedules in a tenant.

    Capped at MAX_CONCURRENT_SCANS (default 10, hard max 20).
    Argo failures are non-fatal — the scan_run record is still created
    and the caller can use the returned scan_run_ids to monitor progress.
    """
    if auth and getattr(auth, "engine_tenant_id", None):
        tenant_id = auth.engine_tenant_id  # always use the authenticated tenant

    cap = min(limit, _MAX_BULK_SCANS, _HARD_MAX)
    schedules = get_active_schedules_for_tenant(tenant_id, limit=cap)
    if not schedules:
        return {"triggered": 0, "scan_run_ids": [], "message": "No active schedules with valid credentials found"}

    from engine_onboarding.database.scan_run_operations import create_scan_run
    from engine_onboarding.scheduler.argo_client import ArgoClient

    argo = ArgoClient()
    triggered = []
    errors = []

    for sched in schedules:
        scan_run_id = str(uuid.uuid4())
        account_id  = sched["account_id"]
        try:
            create_scan_run({
                "scan_run_id":       scan_run_id,
                "customer_id":       sched["customer_id"],
                "tenant_id":         sched["tenant_id"],
                "account_id":        account_id,
                "schedule_uuid":     str(sched["schedule_id"]),
                "provider":          sched["provider"],
                "credential_type":   sched["credential_type"],
                "credential_ref":    sched["credential_ref"],
                "scan_type":         "full",
                "trigger_type":      "manual",
                "engines_requested": sched.get("engines_requested") or ALL_ENGINES,
                "include_regions":   sched.get("include_regions"),
                "exclude_regions":   sched.get("exclude_regions"),
                "include_services":  sched.get("include_services"),
                "exclude_services":  sched.get("exclude_services"),
            })
        except Exception as exc:
            logger.error("run-all: failed to create scan_run for account %s: %s", account_id, exc)
            errors.append({"account_id": account_id, "error": str(exc)})
            continue

        try:
            argo.submit_pipeline(
                scan_run_id=scan_run_id,
                tenant_id=sched["tenant_id"],
                account_id=account_id,
                provider=sched["provider"],
                credential_type=sched["credential_type"],
                credential_ref=sched["credential_ref"],
                include_regions=sched.get("include_regions") if isinstance(sched.get("include_regions"), list) else None,
                include_services=sched.get("include_services") if isinstance(sched.get("include_services"), list) else None,
            )
        except Exception as exc:
            logger.warning("run-all: Argo submit failed for %s (%s): %s", scan_run_id, account_id, exc)

        triggered.append({"scan_run_id": scan_run_id, "account_id": account_id})

    logger.info("run-all triggered %d scans for tenant %s", len(triggered), tenant_id)
    return {
        "triggered":    len(triggered),
        "scan_run_ids": triggered,
        "errors":       errors,
        "cap":          cap,
    }
