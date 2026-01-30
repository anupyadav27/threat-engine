"""
Schedule management API endpoints
"""
from fastapi import APIRouter, HTTPException
from typing import Optional, List
from datetime import datetime, timezone
import asyncio

from engine_onboarding.database import (
    get_account, create_schedule, get_schedule, update_schedule,
    list_schedules_by_tenant, list_schedules_by_account,
    list_executions_by_schedule, get_provider, create_execution
)
from engine_onboarding.models.schedule import (
    ScheduleCreate, ScheduleUpdate, ScheduleResponse, ScheduleExecutionResponse
)
from engine_onboarding.utils.helpers import calculate_next_run_time, is_valid_cron
from engine_onboarding.scheduler.task_executor import TaskExecutor

router = APIRouter(prefix="/api/v1/schedules", tags=["schedules"])


@router.post("", status_code=201)
async def create_schedule_endpoint(
    schedule: ScheduleCreate
):
    """Create a new schedule"""
    # Validate account exists
    # Convert UUID to string for database query
    account_id_str = str(schedule.account_id)
    tenant_id_str = str(schedule.tenant_id)
    account = get_account(account_id_str)
    if not account:
        raise HTTPException(404, f"Account {account_id_str} not found")
    
    # Get provider to determine provider_type
    provider = get_provider(account['provider_id'])
    if not provider:
        raise HTTPException(404, f"Provider not found for account {account_id_str}")
    
    # Validate cron expression if provided
    if schedule.schedule_type == 'cron' and schedule.cron_expression:
        if not is_valid_cron(schedule.cron_expression):
            raise HTTPException(400, "Invalid cron expression")
    
    # Calculate next run time
    next_run = calculate_next_run_time(
        schedule.schedule_type,
        schedule.cron_expression,
        schedule.interval_seconds,
        schedule.timezone
    )
    
    # Normalize regions and services - filter out invalid default values and empty strings
    def normalize_list(items: Optional[List[str]]) -> List[str]:
        """Filter out invalid default values like 'string' and empty strings"""
        if not items:
            return []
        return [item for item in items if item and item != "string" and item.strip()]
    
    normalized_regions = normalize_list(schedule.regions)
    normalized_services = normalize_list(schedule.services)
    normalized_exclude_services = normalize_list(schedule.exclude_services)
    
    # Create schedule
    schedule_obj = create_schedule(
        tenant_id=tenant_id_str,
        account_id=account_id_str,
        name=schedule.name,
        schedule_type=schedule.schedule_type,
        provider_type=provider['provider_type'],
        cron_expression=schedule.cron_expression,
        interval_seconds=schedule.interval_seconds,
        regions=normalized_regions,
        services=normalized_services,
        exclude_services=normalized_exclude_services,
        timezone=schedule.timezone
    )
    
    # Update with additional fields
    updates = {
        'description': schedule.description,
        'next_run_at': next_run.isoformat() if next_run else None,
        'notify_on_success': schedule.notify_on_success,
        'notify_on_failure': schedule.notify_on_failure,
        'notification_channels': schedule.notification_channels or {}
    }
    update_schedule(schedule_obj['schedule_id'], updates)
    
    return {
        "schedule_id": schedule_obj['schedule_id'],
        "name": schedule_obj['name'],
        "next_run_at": updates.get('next_run_at'),
        "status": "created"
    }


@router.get("")
async def list_schedules(
    tenant_id: Optional[str] = None,
    account_id: Optional[str] = None,
    status: Optional[str] = None
):
    """List schedules with filters"""
    if account_id:
        schedules = list_schedules_by_account(account_id)
    elif tenant_id:
        schedules = list_schedules_by_tenant(tenant_id)
    else:
        raise HTTPException(400, "Either tenant_id or account_id must be provided")
    
    # Filter by status if specified
    if status:
        schedules = [s for s in schedules if s.get('status') == status]
    
    return {
        "schedules": [
            {
                "schedule_id": s['schedule_id'],
                "name": s['name'],
                "account_id": s['account_id'],
                "schedule_type": s['schedule_type'],
                "cron_expression": s.get('cron_expression'),
                "status": s.get('status', 'active'),
                "enabled": s.get('enabled') == 'true',
                "last_run_at": s.get('last_run_at'),
                "next_run_at": s.get('next_run_at'),
                "run_count": s.get('run_count', 0)
            }
            for s in schedules
        ]
    }


@router.get("/{schedule_id}")
async def get_schedule_details(schedule_id: str):
    """Get schedule details"""
    schedule = get_schedule(schedule_id)
    if not schedule:
        raise HTTPException(404, "Schedule not found")
    
    return {
        "schedule_id": schedule['schedule_id'],
        "tenant_id": schedule['tenant_id'],
        "account_id": schedule['account_id'],
        "name": schedule['name'],
        "description": schedule.get('description'),
        "schedule_type": schedule['schedule_type'],
        "cron_expression": schedule.get('cron_expression'),
        "interval_seconds": schedule.get('interval_seconds', 0),
        "timezone": schedule.get('timezone', 'UTC'),
        "regions": schedule.get('regions', []),
        "services": schedule.get('services', []),
        "exclude_services": schedule.get('exclude_services', []),
        "status": schedule.get('status', 'active'),
        "enabled": schedule.get('enabled') == 'true',
        "last_run_at": schedule.get('last_run_at'),
        "next_run_at": schedule.get('next_run_at'),
        "run_count": schedule.get('run_count', 0),
        "success_count": schedule.get('success_count', 0),
        "failure_count": schedule.get('failure_count', 0),
        "created_at": schedule.get('created_at', ''),
        "updated_at": schedule.get('updated_at', '')
    }


@router.put("/{schedule_id}")
async def update_schedule_endpoint(
    schedule_id: str,
    update: ScheduleUpdate
):
    """Update a schedule"""
    schedule = get_schedule(schedule_id)
    if not schedule:
        raise HTTPException(404, "Schedule not found")
    
    updates = {}
    
    # Update fields
    if update.name:
        updates['name'] = update.name
    if update.description is not None:
        updates['description'] = update.description
    if update.schedule_type:
        updates['schedule_type'] = update.schedule_type
    if update.cron_expression:
        if not is_valid_cron(update.cron_expression):
            raise HTTPException(400, "Invalid cron expression")
        updates['cron_expression'] = update.cron_expression
        next_run = calculate_next_run_time(
            schedule.get('schedule_type', update.schedule_type or 'cron'),
            update.cron_expression,
            schedule.get('interval_seconds', 0),
            schedule.get('timezone', 'UTC')
        )
        updates['next_run_at'] = next_run.isoformat() if next_run else None
    if update.interval_seconds is not None:
        updates['interval_seconds'] = update.interval_seconds
        next_run = calculate_next_run_time(
            schedule.get('schedule_type', 'interval'),
            schedule.get('cron_expression'),
            update.interval_seconds,
            schedule.get('timezone', 'UTC')
        )
        updates['next_run_at'] = next_run.isoformat() if next_run else None
    if update.enabled is not None:
        updates['enabled'] = 'true' if update.enabled else 'false'
    if update.status:
        updates['status'] = update.status
    if update.regions is not None:
        updates['regions'] = update.regions
    if update.services is not None:
        updates['services'] = update.services
    
    if updates:
        update_schedule(schedule_id, updates)
    
    return {"status": "updated", "schedule_id": schedule_id}


@router.post("/{schedule_id}/trigger")
async def trigger_schedule_manually(
    schedule_id: str
):
    """Manually trigger a schedule"""
    schedule = get_schedule(schedule_id)
    if not schedule:
        raise HTTPException(404, "Schedule not found")
    
    # Normalize regions and services - filter out invalid default values
    def normalize_list(items):
        """Filter out invalid default values like 'string' and empty strings"""
        if not items:
            return []
        return [item for item in items if item and item != "string" and str(item).strip()]
    
    normalized_regions = normalize_list(schedule.get('regions', []))
    normalized_services = normalize_list(schedule.get('services', []))
    normalized_exclude_services = normalize_list(schedule.get('exclude_services', []))
    
    # Create execution and run in background.
    # IMPORTANT: don't block the request until scan completion (LB/clients will time out).
    execution = create_execution(
        schedule_id=schedule_id,
        account_id=schedule['account_id'],
        triggered_by='manual'
    )
    execution_id = execution["execution_id"]
    started_at = datetime.now(timezone.utc)

    executor = TaskExecutor()
    asyncio.create_task(
        executor.run_execution_in_background(
            execution_id=execution_id,
            started_at=started_at,
            schedule_id=schedule_id,
            account_id=schedule['account_id'],
            provider_type=schedule['provider_type'],
            regions=normalized_regions if normalized_regions else None,  # None means scan all
            services=normalized_services if normalized_services else None,  # None means scan all
            exclude_services=normalized_exclude_services if normalized_exclude_services else None,
        )
    )

    return {
        "status": "triggered",
        "execution_id": execution_id,
        "message": "Schedule execution started"
    }


@router.delete("/{schedule_id}")
async def delete_schedule_endpoint(schedule_id: str):
    """Delete a schedule"""
    schedule = get_schedule(schedule_id)
    if not schedule:
        raise HTTPException(404, "Schedule not found")
    
    from engine_onboarding.database.connection import get_db_session
    from engine_onboarding.database.models import Schedule
    
    with get_db_session() as db:
        schedule_obj = db.query(Schedule).filter(Schedule.schedule_id == schedule_id).first()
        if schedule_obj:
            db.delete(schedule_obj)
            db.commit()
    
    return {"status": "deleted", "schedule_id": schedule_id}


@router.get("/{schedule_id}/executions")
async def get_schedule_executions(
    schedule_id: str,
    limit: int = 50,
    offset: int = 0
):
    """Get execution history for a schedule"""
    schedule = get_schedule(schedule_id)
    if not schedule:
        raise HTTPException(404, "Schedule not found")
    
    executions = list_executions_by_schedule(schedule_id)
    
    # Apply pagination
    total = len(executions)
    executions = executions[offset:offset + limit]
    
    return {
        "executions": [
            {
                "execution_id": e['execution_id'],
                "started_at": e.get('started_at', ''),
                "completed_at": e.get('completed_at'),
                "status": e.get('status', 'unknown'),
                "total_checks": e.get('total_checks'),
                "passed_checks": e.get('passed_checks'),
                "failed_checks": e.get('failed_checks'),
                "execution_time_seconds": e.get('execution_time_seconds'),
                "triggered_by": e.get('triggered_by', 'unknown')
            }
            for e in executions
        ],
        "total": total
    }


@router.get("/{schedule_id}/executions/{execution_id}/status")
async def get_execution_status(schedule_id: str, execution_id: str):
    """Get real-time execution status"""
    from engine_onboarding.database import list_executions_by_schedule
    
    # Get execution from schedule's executions
    executions = list_executions_by_schedule(schedule_id)
    execution = next((e for e in executions if e.get('execution_id') == execution_id), None)
    
    if not execution:
        raise HTTPException(404, f"Execution {execution_id} not found")
    
    return {
        "execution_id": execution_id,
        "schedule_id": schedule_id,
        "status": execution.get('status', 'unknown'),
        "started_at": execution.get('started_at'),
        "completed_at": execution.get('completed_at'),
        "progress": execution.get('progress', {}),
        "error_message": execution.get('error_message')
    }


@router.get("/{schedule_id}/statistics")
async def get_schedule_statistics(schedule_id: str):
    """Get schedule performance statistics"""
    schedule = get_schedule(schedule_id)
    if not schedule:
        raise HTTPException(404, "Schedule not found")
    
    executions = list_executions_by_schedule(schedule_id)
    
    total_runs = len(executions)
    successful_runs = len([e for e in executions if e.get('status') == 'success'])
    failed_runs = len([e for e in executions if e.get('status') == 'failed'])
    success_rate = (successful_runs / total_runs * 100) if total_runs > 0 else 0.0
    
    durations = [e.get('execution_time_seconds', 0) for e in executions if e.get('execution_time_seconds')]
    avg_duration = sum(durations) / len(durations) if durations else 0
    
    return {
        "schedule_id": schedule_id,
        "total_runs": total_runs,
        "successful_runs": successful_runs,
        "failed_runs": failed_runs,
        "success_rate": round(success_rate, 2),
        "average_duration_seconds": round(avg_duration, 2),
        "last_run_at": schedule.get('last_run_at'),
        "next_run_at": schedule.get('next_run_at')
    }

