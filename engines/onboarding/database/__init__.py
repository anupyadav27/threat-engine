"""
Database module for onboarding - PostgreSQL
"""
# PostgreSQL operations
from engine_onboarding.database.postgres_operations import (
    # Tenants
    create_tenant, get_tenant, get_tenant_by_name, list_tenants,
    # Providers
    create_provider, get_provider, get_provider_by_tenant_and_type,
    list_providers, list_providers_by_tenant,
    # Accounts
    create_account, get_account, update_account,
    list_accounts_by_tenant, list_accounts_by_provider,
    # Schedules
    create_schedule, get_schedule, update_schedule,
    list_schedules_by_tenant, list_schedules_by_account, get_due_schedules,
    # Executions
    create_execution, update_execution, list_executions_by_schedule, mark_stale_running_executions_as_failed,
    # Scan Results
    create_scan_result, update_scan_result, list_scan_results_by_account,
    # Scan Metadata (aliases for backward compatibility)
    create_scan_metadata, update_scan_metadata,
    # Orchestration Status
    create_orchestration_status, update_orchestration_status
)

# PostgreSQL database initialization
from engine_onboarding.database.connection import init_db

# Alias for backward compatibility
create_tables = init_db

__all__ = [
    # Table creation
    'init_db', 'create_tables',
    # Tenants
    'create_tenant', 'get_tenant', 'get_tenant_by_name', 'list_tenants',
    # Providers
    'create_provider', 'get_provider', 'get_provider_by_tenant_and_type',
    'list_providers', 'list_providers_by_tenant',
    # Accounts
    'create_account', 'get_account', 'update_account',
    'list_accounts_by_tenant', 'list_accounts_by_provider',
    # Schedules
    'create_schedule', 'get_schedule', 'update_schedule',
    'list_schedules_by_tenant', 'list_schedules_by_account', 'get_due_schedules',
    # Executions
    'create_execution', 'update_execution', 'list_executions_by_schedule', 'mark_stale_running_executions_as_failed',
    # Scan Results
    'create_scan_result', 'update_scan_result', 'list_scan_results_by_account',
    # Scan Metadata
    'create_scan_metadata', 'update_scan_metadata',
    # Orchestration Status
    'create_orchestration_status', 'update_orchestration_status'
]

