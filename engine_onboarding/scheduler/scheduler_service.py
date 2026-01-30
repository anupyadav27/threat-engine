"""
Main scheduler service
"""
import asyncio
from datetime import datetime
from typing import List, Dict, Any

from engine_onboarding.database import (
    get_due_schedules, get_schedule, update_schedule,
    create_execution, update_execution
)
from engine_onboarding.scheduler.task_executor import TaskExecutor
from engine_onboarding.utils.helpers import calculate_next_run_time
from engine_onboarding.config import settings


class SchedulerService:
    """Main scheduler service that manages and executes scheduled scans"""
    
    def __init__(self):
        self.executor = TaskExecutor()
        self.running = False
    
    async def start(self):
        """Start the scheduler service"""
        self.running = True
        print("Scheduler service started")
        
        while self.running:
            try:
                # Get all active schedules due to run
                active_schedules = self.get_active_schedules()
                
                # Execute each schedule
                for schedule_obj in active_schedules:
                    if self.should_run(schedule_obj):
                        await self.execute_schedule(schedule_obj)
                
                # Sleep before next check
                await asyncio.sleep(settings.scheduler_interval_seconds)
                
            except Exception as e:
                print(f"Scheduler error: {e}")
                await asyncio.sleep(settings.scheduler_interval_seconds)
    
    def get_active_schedules(self) -> List[Dict[str, Any]]:
        """Get all active schedules that should be checked"""
        return get_due_schedules()
    
    def should_run(self, schedule_obj: Dict[str, Any]) -> bool:
        """Check if a schedule should run now"""
        if schedule_obj.get('enabled') != 'true' or schedule_obj.get('status') != 'active':
            return False
        
        next_run_at = schedule_obj.get('next_run_at')
        if not next_run_at:
            return False
        
        now = datetime.utcnow().isoformat()
        return next_run_at <= now
    
    async def execute_schedule(self, schedule_obj: Dict[str, Any]):
        """Execute a scheduled scan"""
        from engine_onboarding.database import get_account
        
        schedule_id = schedule_obj['schedule_id']
        account_id = schedule_obj['account_id']
        tenant_id = schedule_obj.get('tenant_id')
        
        # Get account to retrieve tenant_id if not in schedule
        if not tenant_id:
            account = get_account(account_id)
            if account:
                tenant_id = account.get('tenant_id')
        
        # Create execution record
        execution = create_execution(
            schedule_id=schedule_id,
            account_id=account_id,
            triggered_by='scheduler'
        )
        execution_id = execution['execution_id']
        # Use execution_id as scan_run_id for consistency
        scan_run_id = execution_id
        started_at = datetime.fromisoformat(execution['started_at'].replace('Z', '+00:00'))
        
        try:
            # Normalize regions and services - filter out invalid default values
            def normalize_list(items):
                """Filter out invalid default values like 'string' and empty strings"""
                if not items:
                    return None
                normalized = [item for item in items if item and item != "string" and str(item).strip()]
                return normalized if normalized else None
            
            normalized_regions = normalize_list(schedule_obj.get('regions', []))
            normalized_services = normalize_list(schedule_obj.get('services', []))
            normalized_exclude_services = normalize_list(schedule_obj.get('exclude_services', []))
            
            # Execute the scan with tenant_id and scan_run_id
            result = await self.executor.execute_scan(
                account_id=account_id,
                provider_type=schedule_obj['provider_type'],
                tenant_id=tenant_id,
                scan_run_id=scan_run_id,
                regions=normalized_regions,  # None means scan all
                services=normalized_services,  # None means scan all
                exclude_services=normalized_exclude_services
            )
            
            # Calculate execution time
            completed_at = datetime.utcnow()
            execution_time = int((completed_at - started_at.replace(tzinfo=None)).total_seconds())
            
            # Update execution
            update_execution(
                execution_id=execution_id,
                status='completed',
                scan_id=result.get('scan_id'),
                total_checks=result.get('total_checks', 0),
                passed_checks=result.get('passed_checks', 0),
                failed_checks=result.get('failed_checks', 0)
            )
            
            # Update schedule stats
            next_run = calculate_next_run_time(
                schedule_obj['schedule_type'],
                schedule_obj.get('cron_expression'),
                schedule_obj.get('interval_seconds', 0),
                schedule_obj.get('timezone', 'UTC')
            )
            
            update_schedule(schedule_id, {
                'last_run_at': started_at.isoformat(),
                'run_count': schedule_obj.get('run_count', 0) + 1,
                'success_count': schedule_obj.get('success_count', 0) + 1,
                'next_run_at': next_run.isoformat() if next_run else None
            })
            
        except Exception as e:
            completed_at = datetime.utcnow()
            execution_time = int((completed_at - started_at.replace(tzinfo=None)).total_seconds())
            
            # Update execution with error
            update_execution(
                execution_id=execution_id,
                status='failed',
                error_message=str(e)
            )
            
            # Update schedule stats
            next_run = calculate_next_run_time(
                schedule_obj['schedule_type'],
                schedule_obj.get('cron_expression'),
                schedule_obj.get('interval_seconds', 0),
                schedule_obj.get('timezone', 'UTC')
            )
            
            update_schedule(schedule_id, {
                'failure_count': schedule_obj.get('failure_count', 0) + 1,
                'next_run_at': next_run.isoformat() if next_run else None
            })
    
    def stop(self):
        """Stop the scheduler service"""
        self.running = False
        print("Scheduler service stopped")

