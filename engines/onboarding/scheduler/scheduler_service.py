"""
Scheduler Service — polls the schedules table and fires Argo workflows.

Design:
  - Single asyncio poll loop; interval controlled by SCHEDULER_INTERVAL_SECONDS env var.
  - Reads `get_due_schedules()` every tick (schedules with enabled=true AND next_run_at <= NOW()).
  - For each due schedule:
      1. Creates a scan_run record (status=pending).
      2. Submits the Argo workflow.
      3. Marks the scan_run running (or failed if Argo submission fails).
      4. Bumps schedule counters + recalculates next_run_at.
  - Never blocks the event loop: Argo call is sync but fast (HTTP, small payload).
  - On startup, any scan_runs stuck in 'running' for > STALE_SCAN_HOURS are
    moved to 'failed' so they don't block re-runs.
"""

import asyncio
import os
import uuid
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from engine_onboarding.database.schedule_operations import get_due_schedules, bump_schedule_after_run
from engine_onboarding.database.scan_run_operations import (
    create_scan_run,
    mark_scan_run_started,
    mark_scan_run_completed,
    list_scan_runs,
    update_scan_run,
)
from engine_onboarding.database.cloud_accounts_operations import update_cloud_account
from engine_onboarding.scheduler.argo_client import ArgoClient

logger = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────

SCHEDULER_INTERVAL_SECONDS = int(os.getenv("SCHEDULER_INTERVAL_SECONDS", "60"))
STALE_SCAN_HOURS            = int(os.getenv("STALE_SCAN_HOURS", "4"))
MAX_CONCURRENT_SCANS        = int(os.getenv("MAX_CONCURRENT_SCANS", "10"))


def _next_run_utc(cron_expression: str, tz: str = "UTC") -> Optional[datetime]:
    """Compute next run time from a cron expression. Returns None on error."""
    try:
        from croniter import croniter
        import pytz
        zone = pytz.timezone(tz)
        base = datetime.now(zone)
        it = croniter(cron_expression, base)
        dt = it.get_next(datetime)
        return dt.astimezone(timezone.utc)
    except Exception as e:
        logger.warning(f"cron parse error '{cron_expression}': {e}")
        return None


class SchedulerService:
    """
    Async poll-loop scheduler.

    Usage (called from FastAPI startup event):
        service = SchedulerService()
        asyncio.create_task(service.run())
    """

    def __init__(self):
        self.running    = False
        self._argo      = ArgoClient()
        self._lock      = asyncio.Lock()   # prevents overlapping ticks
        self._active    = 0                # concurrent scan counter

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def run(self):
        """Entry point. Runs until stop() is called."""
        self.running = True
        logger.info(
            f"Scheduler started — interval={SCHEDULER_INTERVAL_SECONDS}s "
            f"max_concurrent={MAX_CONCURRENT_SCANS}"
        )
        await self._cleanup_stale_runs()

        while self.running:
            try:
                async with self._lock:
                    await self._tick()
            except Exception as e:
                logger.error(f"Scheduler tick error: {e}", exc_info=True)

            await asyncio.sleep(SCHEDULER_INTERVAL_SECONDS)

    def stop(self):
        self.running = False
        logger.info("Scheduler stopping")

    # ── Main tick ─────────────────────────────────────────────────────────────

    async def _tick(self):
        if self._active >= MAX_CONCURRENT_SCANS:
            logger.debug(f"Skipping tick — {self._active} scans already running")
            return

        due = get_due_schedules(limit=MAX_CONCURRENT_SCANS - self._active)
        if not due:
            return

        logger.info(f"Found {len(due)} due schedules")
        for sched in due:
            asyncio.create_task(self._fire_schedule(sched))

    # ── Fire one schedule ─────────────────────────────────────────────────────

    async def _fire_schedule(self, sched: dict):
        schedule_id   = str(sched["schedule_id"])
        account_id    = sched["account_id"]
        tenant_id     = sched["tenant_id"]
        customer_id   = sched["customer_id"]
        provider      = sched.get("provider", "aws")
        cred_type     = sched.get("credential_type", "")
        cred_ref      = sched.get("credential_ref", "")
        cron          = sched.get("cron_expression", "0 2 * * 0")
        tz            = sched.get("timezone", "UTC")
        engines       = sched.get("engines_requested") or [
            "discovery", "check", "inventory", "threat", "compliance", "iam", "datasec"
        ]

        scan_run_id = str(uuid.uuid4())
        self._active += 1
        success = False

        try:
            # 1. Create scan_run record
            create_scan_run({
                "scan_run_id":       scan_run_id,
                "customer_id":       customer_id,
                "tenant_id":         tenant_id,
                "account_id":        account_id,
                "schedule_uuid":     schedule_id,
                "provider":          provider,
                "credential_type":   cred_type,
                "credential_ref":    cred_ref,
                "scan_type":         "full",
                "trigger_type":      "scheduled",
                "engines_requested": engines,
                "include_regions":   sched.get("include_regions"),
                "include_services":  sched.get("include_services"),
                "exclude_services":  sched.get("exclude_services"),
            })
            logger.info(f"scan_run created: {scan_run_id} (schedule={schedule_id})")

            # 2. Submit to Argo
            include_services = sched.get("include_services")
            include_regions  = sched.get("include_regions")
            workflow_name = self._argo.submit_pipeline(
                scan_run_id=scan_run_id,
                tenant_id=tenant_id,
                account_id=account_id,
                provider=provider,
                credential_type=cred_type,
                credential_ref=cred_ref,
                include_services=include_services if isinstance(include_services, list) else None,
                include_regions=include_regions   if isinstance(include_regions, list)  else None,
            ).get("metadata", {}).get("name")

            # 3. Mark running
            mark_scan_run_started(scan_run_id)
            logger.info(f"Argo workflow '{workflow_name}' started for scan_run_id={scan_run_id}")

            # 4. Stamp last_scan_at on account
            update_cloud_account(account_id, {"last_scan_at": datetime.now(timezone.utc)})
            success = True

        except Exception as e:
            logger.error(
                f"Failed to fire schedule {schedule_id} (scan_run_id={scan_run_id}): {e}",
                exc_info=True,
            )
            try:
                mark_scan_run_completed(
                    scan_run_id,
                    success=False,
                    error_details={"error": str(e), "stage": "argo_submit"},
                )
            except Exception:
                pass

        finally:
            # 5. Bump schedule counters + next_run_at regardless of outcome
            next_run = _next_run_utc(cron, tz)
            try:
                bump_schedule_after_run(schedule_id, success=success, next_run_at=next_run)
            except Exception as e:
                logger.error(f"Failed to bump schedule {schedule_id}: {e}")
            self._active -= 1

    # ── Cleanup stale runs on startup ─────────────────────────────────────────

    async def _cleanup_stale_runs(self):
        """Mark any scan_runs stuck in 'running' for > STALE_SCAN_HOURS as failed."""
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=STALE_SCAN_HOURS)
            conn_module = __import__(
                "engine_onboarding.database.connection",
                fromlist=["get_db_connection"],
            )
            conn = conn_module.get_db_connection()
            cur  = conn.cursor()
            try:
                cur.execute(
                    """
                    UPDATE scan_runs
                    SET overall_status = 'failed',
                        completed_at   = NOW(),
                        error_details  = '{"error":"marked stale by scheduler on startup"}'::jsonb
                    WHERE overall_status = 'running'
                      AND started_at < %s
                    """,
                    (cutoff,),
                )
                count = cur.rowcount
                conn.commit()
                if count:
                    logger.warning(f"Marked {count} stale scan_run(s) as failed on startup")
            finally:
                cur.close()
                conn.close()
        except Exception as e:
            logger.error(f"stale cleanup error: {e}")
