"""
PostgreSQL database operations - replacement for DynamoDB operations
"""
from typing import Dict, Any, List, Optional
from datetime import datetime
import uuid
import json
import logging
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc

from engine_onboarding.database.connection import SessionLocal, get_db_session
from engine_onboarding.database.models import (
    Tenant, Provider, Account, Schedule, Execution, ScanResult
)

logger = logging.getLogger(__name__)


def _to_dict(obj) -> Optional[Dict[str, Any]]:
    """Convert SQLAlchemy model instance to dict"""
    if obj is None:
        return None
    
    result = {}
    for column in obj.__table__.columns:
        value = getattr(obj, column.name)
        # Convert datetime to ISO format string
        if isinstance(value, datetime):
            value = value.isoformat()
        # Convert JSONB to list/dict
        elif isinstance(value, (list, dict)):
            value = value if value is not None else []
        result[column.name] = value
    return result


# ==================== TENANTS ====================

def create_tenant(tenant_name: str, description: Optional[str] = None) -> Dict[str, Any]:
    """Create a new tenant"""
    tenant_id = str(uuid.uuid4())
    
    with get_db_session() as db:
        tenant = Tenant(
            tenant_id=tenant_id,
            tenant_name=tenant_name,
            description=description or '',
            status='active'
        )
        db.add(tenant)
        db.commit()
        db.refresh(tenant)
        return _to_dict(tenant)


def get_tenant(tenant_id: str) -> Optional[Dict[str, Any]]:
    """Get tenant by ID"""
    with get_db_session() as db:
        tenant = db.query(Tenant).filter(Tenant.tenant_id == tenant_id).first()
        return _to_dict(tenant)


def get_tenant_by_name(tenant_name: str) -> Optional[Dict[str, Any]]:
    """Get tenant by name"""
    with get_db_session() as db:
        tenant = db.query(Tenant).filter(Tenant.tenant_name == tenant_name).first()
        return _to_dict(tenant)


def list_tenants() -> List[Dict[str, Any]]:
    """List all tenants"""
    with get_db_session() as db:
        tenants = db.query(Tenant).all()
        return [_to_dict(t) for t in tenants]


# ==================== PROVIDERS ====================

def create_provider(tenant_id: str, provider_type: str) -> Dict[str, Any]:
    """Create a new provider"""
    provider_id = str(uuid.uuid4())
    
    with get_db_session() as db:
        # Check if provider already exists for this tenant and type
        existing = db.query(Provider).filter(
            and_(
                Provider.tenant_id == tenant_id,
                Provider.provider_type == provider_type
            )
        ).first()
        
        if existing:
            return _to_dict(existing)
        
        provider = Provider(
            provider_id=provider_id,
            tenant_id=tenant_id,
            provider_type=provider_type,
            status='active'
        )
        db.add(provider)
        db.commit()
        db.refresh(provider)
        return _to_dict(provider)


def get_provider(provider_id: str) -> Optional[Dict[str, Any]]:
    """Get provider by ID"""
    if not provider_id:
        return None
    
    with get_db_session() as db:
        provider = db.query(Provider).filter(Provider.provider_id == provider_id).first()
        return _to_dict(provider)


def get_provider_by_tenant_and_type(tenant_id: str, provider_type: str) -> Optional[Dict[str, Any]]:
    """Get provider by tenant and type"""
    with get_db_session() as db:
        provider = db.query(Provider).filter(
            and_(
                Provider.tenant_id == tenant_id,
                Provider.provider_type == provider_type
            )
        ).first()
        return _to_dict(provider)


def list_providers() -> List[Dict[str, Any]]:
    """List all providers"""
    with get_db_session() as db:
        providers = db.query(Provider).all()
        return [_to_dict(p) for p in providers]


def list_providers_by_tenant(tenant_id: str) -> List[Dict[str, Any]]:
    """List providers by tenant"""
    with get_db_session() as db:
        providers = db.query(Provider).filter(Provider.tenant_id == tenant_id).all()
        return [_to_dict(p) for p in providers]


# ==================== ACCOUNTS ====================

def create_account(
    provider_id: str,
    tenant_id: str,
    account_name: str,
    account_number: Optional[str] = None
) -> Dict[str, Any]:
    """Create a new account"""
    account_id = str(uuid.uuid4())
    
    with get_db_session() as db:
        account = Account(
            account_id=account_id,
            provider_id=provider_id,
            tenant_id=tenant_id,
            account_name=account_name,
            account_number=account_number or '',
            status='pending',
            onboarding_status='pending'
        )
        db.add(account)
        db.commit()
        db.refresh(account)
        return _to_dict(account)


def get_account(account_id: str) -> Optional[Dict[str, Any]]:
    """Get account by ID"""
    with get_db_session() as db:
        account = db.query(Account).filter(Account.account_id == account_id).first()
        return _to_dict(account)


def update_account(account_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
    """Update account"""
    with get_db_session() as db:
        account = db.query(Account).filter(Account.account_id == account_id).first()
        if not account:
            raise ValueError(f"Account {account_id} not found")
        
        for key, value in updates.items():
            if key not in ['account_id', 'created_at'] and hasattr(account, key):
                setattr(account, key, value)
        
        db.commit()
        db.refresh(account)
        return _to_dict(account)


def list_accounts_by_tenant(tenant_id: str, status: Optional[str] = None) -> List[Dict[str, Any]]:
    """List accounts by tenant"""
    with get_db_session() as db:
        query = db.query(Account).filter(Account.tenant_id == tenant_id)
        if status:
            query = query.filter(Account.status == status)
        accounts = query.all()
        return [_to_dict(a) for a in accounts]


def list_accounts_by_provider(provider_id: str) -> List[Dict[str, Any]]:
    """List accounts by provider"""
    with get_db_session() as db:
        accounts = db.query(Account).filter(Account.provider_id == provider_id).all()
        return [_to_dict(a) for a in accounts]


# ==================== SCHEDULES ====================

def create_schedule(
    tenant_id: str,
    account_id: str,
    name: str,
    schedule_type: str,
    provider_type: str,
    cron_expression: Optional[str] = None,
    interval_seconds: Optional[int] = None,
    regions: Optional[List[str]] = None,
    services: Optional[List[str]] = None,
    exclude_services: Optional[List[str]] = None,
    timezone: str = 'UTC'
) -> Dict[str, Any]:
    """Create a new schedule"""
    schedule_id = str(uuid.uuid4())
    
    with get_db_session() as db:
        schedule = Schedule(
            schedule_id=schedule_id,
            tenant_id=tenant_id,
            account_id=account_id,
            name=name,
            schedule_type=schedule_type,
            provider_type=provider_type,
            cron_expression=cron_expression or '',
            interval_seconds=interval_seconds or 0,
            regions=regions or [],
            services=services or [],
            exclude_services=exclude_services or [],
            timezone=timezone,
            status='active',
            enabled=True
        )
        db.add(schedule)
        db.commit()
        db.refresh(schedule)
        return _to_dict(schedule)


def get_schedule(schedule_id: str) -> Optional[Dict[str, Any]]:
    """Get schedule by ID"""
    with get_db_session() as db:
        schedule = db.query(Schedule).filter(Schedule.schedule_id == schedule_id).first()
        return _to_dict(schedule)


def update_schedule(schedule_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
    """Update schedule"""
    with get_db_session() as db:
        schedule = db.query(Schedule).filter(Schedule.schedule_id == schedule_id).first()
        if not schedule:
            raise ValueError(f"Schedule {schedule_id} not found")
        
        for key, value in updates.items():
            if key not in ['schedule_id', 'created_at'] and hasattr(schedule, key):
                setattr(schedule, key, value)
        
        db.commit()
        db.refresh(schedule)
        return _to_dict(schedule)


def list_schedules_by_tenant(tenant_id: str) -> List[Dict[str, Any]]:
    """List schedules by tenant"""
    with get_db_session() as db:
        schedules = db.query(Schedule).filter(Schedule.tenant_id == tenant_id).all()
        return [_to_dict(s) for s in schedules]


def list_schedules_by_account(account_id: str) -> List[Dict[str, Any]]:
    """List schedules by account"""
    with get_db_session() as db:
        schedules = db.query(Schedule).filter(Schedule.account_id == account_id).all()
        return [_to_dict(s) for s in schedules]


def get_due_schedules() -> List[Dict[str, Any]]:
    """Get schedules that are due to run"""
    from datetime import datetime, timezone
    
    with get_db_session() as db:
        now = datetime.now(timezone.utc)
        schedules = db.query(Schedule).filter(
            and_(
                Schedule.enabled == True,
                Schedule.next_run_at <= now
            )
        ).all()
        return [_to_dict(s) for s in schedules]


# ==================== EXECUTIONS ====================

def create_execution(
    schedule_id: str,
    account_id: str,
    triggered_by: str = 'scheduler'
) -> Dict[str, Any]:
    """Create a new execution record"""
    execution_id = str(uuid.uuid4())
    
    with get_db_session() as db:
        execution = Execution(
            execution_id=execution_id,
            schedule_id=schedule_id,
            account_id=account_id,
            status='running',
            triggered_by=triggered_by
        )
        db.add(execution)
        db.commit()
        db.refresh(execution)
        return _to_dict(execution)


def update_execution(
    execution_id: str,
    status: str,
    scan_id: Optional[str] = None,
    total_checks: Optional[int] = None,
    passed_checks: Optional[int] = None,
    failed_checks: Optional[int] = None,
    error_message: Optional[str] = None
) -> Dict[str, Any]:
    """Update execution record"""
    from datetime import datetime, timezone
    
    with get_db_session() as db:
        execution = db.query(Execution).filter(Execution.execution_id == execution_id).first()
        if not execution:
            raise ValueError(f"Execution {execution_id} not found")
        
        execution.status = status
        execution.completed_at = datetime.now(timezone.utc)
        
        if scan_id:
            execution.scan_id = scan_id
        if total_checks is not None:
            execution.total_checks = total_checks
        if passed_checks is not None:
            execution.passed_checks = passed_checks
        if failed_checks is not None:
            execution.failed_checks = failed_checks
        if error_message:
            execution.error_message = error_message
        
        db.commit()
        db.refresh(execution)
        return _to_dict(execution)


def list_executions_by_schedule(schedule_id: str) -> List[Dict[str, Any]]:
    """List executions by schedule"""
    with get_db_session() as db:
        executions = db.query(Execution).filter(
            Execution.schedule_id == schedule_id
        ).order_by(desc(Execution.started_at)).all()
        return [_to_dict(e) for e in executions]


def mark_stale_running_executions_as_failed(max_age_minutes: int = 30) -> int:
    """
    Mark long-running executions as failed.

    This protects us against orphaned 'running' executions when a pod restarts
    mid-scan (or when the AWS engine restarts and loses scan state).
    """
    from datetime import datetime, timezone, timedelta

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=max_age_minutes)

    with get_db_session() as db:
        stale = db.query(Execution).filter(
            and_(
                Execution.status == 'running',
                Execution.started_at < cutoff
            )
        ).all()

        for e in stale:
            e.status = 'failed'
            e.completed_at = now
            if not e.error_message:
                e.error_message = (
                    "Marked failed as stale (service restart or engine lost scan state)."
                )

        db.commit()
        return len(stale)


# ==================== SCAN RESULTS ====================

def create_scan_result(
    scan_id: str,
    account_id: str,
    provider_type: str,
    scan_type: str = 'scheduled'
) -> Dict[str, Any]:
    """Create a new scan result record"""
    with get_db_session() as db:
        scan_result = ScanResult(
            scan_id=scan_id,
            account_id=account_id,
            provider_type=provider_type,
            scan_type=scan_type,
            status='running'
        )
        db.add(scan_result)
        db.commit()
        db.refresh(scan_result)
        return _to_dict(scan_result)


def update_scan_result(
    scan_id: str,
    status: str,
    total_checks: Optional[int] = None,
    passed_checks: Optional[int] = None,
    failed_checks: Optional[int] = None,
    error_checks: Optional[int] = None,
    result_storage_path: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Update scan result"""
    from datetime import datetime, timezone
    
    with get_db_session() as db:
        scan_result = db.query(ScanResult).filter(ScanResult.scan_id == scan_id).first()
        if not scan_result:
            raise ValueError(f"Scan result {scan_id} not found")
        
        scan_result.status = status
        scan_result.completed_at = datetime.now(timezone.utc)
        
        if total_checks is not None:
            scan_result.total_checks = total_checks
        if passed_checks is not None:
            scan_result.passed_checks = passed_checks
        if failed_checks is not None:
            scan_result.failed_checks = failed_checks
        if error_checks is not None:
            scan_result.error_checks = error_checks
        if result_storage_path:
            scan_result.result_storage_path = result_storage_path
        if metadata:
            scan_result.scan_metadata = metadata
        
        db.commit()
        db.refresh(scan_result)
        return _to_dict(scan_result)


def list_scan_results_by_account(account_id: str) -> List[Dict[str, Any]]:
    """List scan results by account"""
    with get_db_session() as db:
        scan_results = db.query(ScanResult).filter(
            ScanResult.account_id == account_id
        ).order_by(desc(ScanResult.started_at)).all()
        return [_to_dict(sr) for sr in scan_results]


# ==================== SCAN METADATA (for backward compatibility) ====================

def create_scan_metadata(
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
    scan_id: Optional[str] = None,
    status: str = 'running'
) -> Dict[str, Any]:
    """Create unified scan metadata record (alias for create_scan_result)"""
    # For PostgreSQL, we use scan_result table
    # scan_run_id maps to scan_id in ScanResult
    return create_scan_result(
        scan_id=scan_run_id,
        account_id=account_id,
        provider_type=provider,
        scan_type='scheduled'
    )


def update_scan_metadata(
    scan_run_id: str,
    status: Optional[str] = None,
    scan_id: Optional[str] = None,
    completed_at: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Update unified scan metadata record (alias for update_scan_result)"""
    update_data = {}
    if status:
        update_data['status'] = status
    if metadata:
        update_data['metadata'] = metadata
    
    return update_scan_result(
        scan_id=scan_run_id,
        status=status or 'running',
        **{k: v for k, v in update_data.items() if k != 'status'}
    )


# ==================== ORCHESTRATION STATUS ====================

def create_orchestration_status(
    scan_run_id: str,
    engine: str,
    status: str = 'running',
    tenant_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Create orchestration status record (uses shared.scan_orchestration table)"""
    from sqlalchemy import text
    from datetime import datetime, timezone
    
    with get_db_session() as db:
        # Insert into shared.scan_orchestration table
        # Note: This assumes the shared schema is accessible
        # For now, we'll use a simple approach - store in scan_results metadata
        # In production, this should use the shared.scan_orchestration table
        
        # For backward compatibility, we'll create a scan_result entry
        # with orchestration metadata
        result = create_scan_result(
            scan_id=f"{scan_run_id}_{engine}",
            account_id=tenant_id or "default",
            provider_type=engine,
            scan_type="orchestration"
        )
        
        # Update with orchestration metadata
        if metadata:
            update_scan_result(
                scan_id=f"{scan_run_id}_{engine}",
                status=status,
                metadata={"orchestration": metadata, "scan_run_id": scan_run_id}
            )
        
        return {
            "scan_run_id": scan_run_id,
            "engine": engine,
            "status": status,
            "created_at": datetime.now(timezone.utc).isoformat()
        }


def update_orchestration_status(
    scan_run_id: str,
    engine: str,
    status: str,
    response_data: Optional[Dict[str, Any]] = None,
    error: Optional[str] = None
) -> Dict[str, Any]:
    """Update orchestration status record"""
    from datetime import datetime, timezone
    
    scan_id = f"{scan_run_id}_{engine}"
    
    metadata = {
        "scan_run_id": scan_run_id,
        "engine": engine,
        "status": status,
        "updated_at": datetime.now(timezone.utc).isoformat()
    }
    
    if response_data:
        metadata["response_data"] = response_data
    
    if error:
        metadata["error"] = error
    
    return update_scan_result(
        scan_id=scan_id,
        status=status,
        metadata=metadata
    )

