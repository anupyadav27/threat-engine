"""
Database module for onboarding engine — normalized schema (migration 004).
All operations now live in dedicated modules; this file re-exports for backward compat.
"""
# New operations (migration 004 schema)
from engine_onboarding.database.tenant_operations import (
    create_tenant, get_tenant, list_tenants, update_tenant, delete_tenant,
)
from engine_onboarding.database.cloud_accounts_operations import (
    create_cloud_account, get_cloud_account, list_cloud_accounts,
    update_cloud_account, soft_delete_cloud_account,
)
from engine_onboarding.database.schedule_operations import (
    create_schedule, get_schedule, list_schedules, update_schedule,
    delete_schedule, get_due_schedules, bump_schedule_after_run,
)
from engine_onboarding.database.scan_run_operations import (
    create_scan_run, get_scan_run, list_scan_runs, update_scan_run,
    mark_scan_run_started, mark_scan_run_completed,
)
from engine_onboarding.database.connection import init_db

# Backward-compat aliases used by legacy code (task_executor, old scheduler)
get_account = get_cloud_account
update_account = update_cloud_account

# Stub functions for legacy callers that referenced the old execution/scan tables.
# These are no-ops; the new scheduler uses scan_runs instead.
def _noop(*args, **kwargs):
    return {}

create_execution              = _noop
update_execution              = _noop
create_scan_metadata          = _noop
update_scan_metadata          = _noop
create_orchestration_status   = _noop
update_orchestration_status   = _noop
mark_stale_running_executions_as_failed = _noop
list_executions_by_schedule   = lambda *a, **k: []
create_scan_result            = _noop
update_scan_result            = _noop
list_scan_results_by_account  = lambda *a, **k: []

__all__ = [
    'init_db',
    'create_tenant', 'get_tenant', 'list_tenants', 'update_tenant', 'delete_tenant',
    'create_cloud_account', 'get_cloud_account', 'list_cloud_accounts',
    'update_cloud_account', 'soft_delete_cloud_account',
    'get_account', 'update_account',
    'create_schedule', 'get_schedule', 'list_schedules', 'update_schedule',
    'delete_schedule', 'get_due_schedules', 'bump_schedule_after_run',
    'create_scan_run', 'get_scan_run', 'list_scan_runs', 'update_scan_run',
    'mark_scan_run_started', 'mark_scan_run_completed',
]
