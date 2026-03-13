"""
Task executor for scheduled scans
"""
import asyncio
import sys
import os
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from uuid import uuid4

# Add common to path for logger import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from engine_common.logger import setup_logger, LogContext, log_duration

from engine_onboarding.database import (
    get_account, create_execution, update_execution,
    create_scan_metadata, update_scan_metadata
)
from engine_onboarding.storage.secrets_manager_storage import secrets_manager_storage
from engine_onboarding.utils.engine_client import EngineClient
from engine_onboarding.orchestrator.engine_orchestrator import EngineOrchestrator
from engine_onboarding.notifications.webhook_sender import WebhookSender

logger = setup_logger(__name__, engine_name="task-executor")


class TaskExecutor:
    """Executes scheduled scans by calling appropriate engine"""
    
    def __init__(self):
        self.engine_client = EngineClient()
        self.orchestrator = EngineOrchestrator()
        self.webhook_sender = WebhookSender()
    
    async def execute_scan(
        self,
        account_id: str,
        provider_type: str,
        tenant_id: Optional[str] = None,
        scan_run_id: Optional[str] = None,
        regions: Optional[List[str]] = None,
        services: Optional[List[str]] = None,
        exclude_services: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Execute a compliance scan"""
        
        # Get account
        account = get_account(account_id)
        if not account:
            with LogContext(account_id=account_id):
                logger.error("Account not found")
            raise ValueError(f"Account {account_id} not found")
        
        if account.get('status') != "active":
            with LogContext(account_id=account_id, tenant_id=account.get('tenant_id')):
                logger.warning("Account is not active", extra={
                    "extra_fields": {"status": account.get('status')}
                })
            raise ValueError(f"Account {account_id} is not active")
        
        # Get tenant_id from account if not provided
        if not tenant_id:
            tenant_id = account.get('tenant_id')
        
        with LogContext(tenant_id=tenant_id, scan_run_id=scan_run_id, account_id=account_id):
            logger.info("Executing scan", extra={
                "extra_fields": {
                    "provider": provider_type,
                    "regions": regions,
                    "services": services,
                    "exclude_services": exclude_services
                }
            })
        
        # Normalize regions and services - filter out invalid values and empty lists
        def normalize_list(items: Optional[List[str]]) -> Optional[List[str]]:
            """Filter out invalid default values and return None if empty"""
            if not items:
                return None
            normalized = [item for item in items if item and item != "string" and str(item).strip()]
            return normalized if normalized else None
        
        normalized_regions = normalize_list(regions)
        normalized_services = normalize_list(services)
        normalized_exclude_services = normalize_list(exclude_services)
        
        # Get credentials from Secrets Manager
        credentials = secrets_manager_storage.retrieve(account_id)
        
        # Call appropriate engine
        # Pass None for empty lists to scan all regions/services
        if provider_type == "aws":
            result = await self.engine_client.scan_aws(
                credentials=credentials,
                account_number=account.get('account_number'),
                tenant_id=tenant_id,
                scan_run_id=scan_run_id,
                regions=normalized_regions,  # None means scan all regions
                services=normalized_services,  # None means scan all services
                exclude_services=normalized_exclude_services
            )
        elif provider_type == "azure":
            result = await self.engine_client.scan_azure(
                credentials=credentials,
                subscription_id=account.get('account_number'),
                tenant_id=tenant_id,
                scan_run_id=scan_run_id,
                regions=regions,
                services=services
            )
        elif provider_type == "gcp":
            result = await self.engine_client.scan_gcp(
                credentials=credentials,
                project_id=account.get('account_number'),
                tenant_id=tenant_id,
                scan_run_id=scan_run_id,
                regions=regions,
                services=services
            )
        elif provider_type == "alicloud":
            result = await self.engine_client.scan_alicloud(
                credentials=credentials,
                account_id=account.get('account_number'),
                tenant_id=tenant_id,
                scan_run_id=scan_run_id,
                regions=regions,
                services=services
            )
        else:
            raise ValueError(f"Unsupported provider: {provider_type}")
        
        return result
    
    async def execute_scheduled_scan(
        self,
        schedule_id: str,
        account_id: str,
        provider_type: str,
        regions: Optional[List[str]] = None,
        services: Optional[List[str]] = None,
        exclude_services: Optional[List[str]] = None,
        triggered_by: str = "scheduler"
    ) -> Dict[str, Any]:
        """Execute a scan and record execution history"""
        
        # Get account to retrieve tenant_id
        account = get_account(account_id)
        if not account:
            raise ValueError(f"Account {account_id} not found")
        tenant_id = account.get('tenant_id')
        
        # Create execution record
        execution = create_execution(
            schedule_id=schedule_id,
            account_id=account_id,
            triggered_by=triggered_by
        )
        execution_id = execution['execution_id']
        # Use execution_id as scan_run_id for consistency
        scan_run_id = execution_id
        started_at = datetime.fromisoformat(execution['started_at'].replace('Z', '+00:00'))
        
        # Create scan metadata
        create_scan_metadata(
            scan_run_id=scan_run_id,
            tenant_id=tenant_id,
            account_id=account_id,
            provider=provider_type,
            status='running'
        )
        
        try:
            # Execute scan with tenant_id and scan_run_id
            result = await self.execute_scan(
                account_id=account_id,
                provider_type=provider_type,
                tenant_id=tenant_id,
                scan_run_id=scan_run_id,
                regions=regions,
                services=services,
                exclude_services=exclude_services
            )
            
            # Calculate execution time
            completed_at = datetime.now(timezone.utc)
            execution_time = int((completed_at - started_at.replace(tzinfo=None)).total_seconds())
            
            # Update execution
            scan_id = result.get('scan_id', str(uuid4()))
            update_execution(
                execution_id=execution_id,
                status='completed',
                scan_id=scan_id,
                total_checks=result.get('total_checks', 0),
                passed_checks=result.get('passed_checks', 0),
                failed_checks=result.get('failed_checks', 0)
            )
            
            # Update scan metadata
            update_scan_metadata(
                scan_run_id=scan_run_id,
                status='completed',
                scan_id=scan_id,
                completed_at=completed_at.isoformat()
            )
            
            # Trigger downstream engines (non-blocking)
            try:
                orchestration_task = asyncio.create_task(
                    self.orchestrator.trigger_downstream_engines(
                        scan_run_id=scan_run_id,
                        tenant_id=tenant_id,
                        account_id=account_id,
                        provider_type=provider_type,
                        scan_id=scan_id
                    )
                )
                # Send webhook notification after orchestration completes
                asyncio.create_task(
                    self._send_notification_after_orchestration(
                        orchestration_task, scan_run_id, tenant_id, account_id, provider_type, "completed", scan_id
                    )
                )
            except Exception as e:
                import logging
                logger = logging.getLogger(__name__)
                logger.error(f"Failed to trigger downstream engines: {e}")
                # Don't fail the scan if orchestration fails
            
            # Send immediate webhook notification for scan completion
            asyncio.create_task(
                self._send_scan_completion_notification(
                    scan_run_id, tenant_id, account_id, provider_type, "completed", scan_id
                )
            )
            
            return {
                "execution_id": execution_id,
                "status": "completed",
                "result": result
            }
            
        except Exception as e:
            completed_at = datetime.now(timezone.utc)
            execution_time = int((completed_at - started_at.replace(tzinfo=None)).total_seconds())
            
            with LogContext(tenant_id=tenant_id, scan_run_id=scan_run_id, execution_id=execution_id):
                logger.error("Scan execution failed", exc_info=True, extra={
                    "extra_fields": {
                        "error": str(e),
                        "execution_time_seconds": execution_time
                    }
                })
            
            # Update execution with error
            update_execution(
                execution_id=execution_id,
                status='failed',
                error_message=str(e)
            )
            
            # Update scan metadata
            update_scan_metadata(
                scan_run_id=scan_run_id,
                status='failed',
                completed_at=completed_at.isoformat(),
                metadata={"error": str(e)}
            )
            
            raise

    async def run_execution_in_background(
        self,
        execution_id: str,
        started_at: datetime,
        schedule_id: str,
        account_id: str,
        provider_type: str,
        regions: Optional[List[str]] = None,
        services: Optional[List[str]] = None,
        exclude_services: Optional[List[str]] = None
    ) -> None:
        """
        Run a scan for an already-created execution record.

        Used by API endpoints to return immediately (non-blocking) while the scan runs.
        """
        # Get account to retrieve tenant_id
        account = get_account(account_id)
        tenant_id = account.get('tenant_id') if account else None
        # Use execution_id as scan_run_id
        scan_run_id = execution_id
        
        # Create scan metadata
        if tenant_id:
            create_scan_metadata(
                scan_run_id=scan_run_id,
                tenant_id=tenant_id,
                account_id=account_id,
                provider=provider_type,
                status='running'
            )
        
        try:
            result = await self.execute_scan(
                account_id=account_id,
                provider_type=provider_type,
                tenant_id=tenant_id,
                scan_run_id=scan_run_id,
                regions=regions,
                services=services,
                exclude_services=exclude_services
            )

            scan_id = result.get('scan_id', str(uuid4()))
            update_execution(
                execution_id=execution_id,
                status='completed',
                scan_id=scan_id,
                total_checks=result.get('total_checks', 0),
                passed_checks=result.get('passed_checks', 0),
                failed_checks=result.get('failed_checks', 0)
            )
            
            # Update scan metadata
            if tenant_id:
                update_scan_metadata(
                    scan_run_id=scan_run_id,
                    status='completed',
                    scan_id=scan_id,
                    completed_at=datetime.now(timezone.utc).isoformat()
                )
            
            # Trigger downstream engines (non-blocking)
            try:
                asyncio.create_task(
                    self.orchestrator.trigger_downstream_engines(
                        scan_run_id=execution_id,
                        tenant_id=tenant_id,
                        account_id=account_id,
                        provider_type=provider_type,
                        scan_id=scan_id
                    )
                )
            except Exception as e:
                import logging
                logger = logging.getLogger(__name__)
                logger.error(f"Failed to trigger downstream engines: {e}")
                # Don't fail the scan if orchestration fails
        except Exception as e:
            update_execution(
                execution_id=execution_id,
                status='failed',
                error_message=str(e)
            )
            
            # Update scan metadata
            if tenant_id:
                update_scan_metadata(
                    scan_run_id=scan_run_id,
                    status='failed',
                    completed_at=datetime.now(timezone.utc).isoformat(),
                    metadata={"error": str(e)}
                )
            
            # Send webhook notification for scan failure
            asyncio.create_task(
                self._send_scan_completion_notification(
                    scan_run_id, tenant_id, account_id, provider_type, "failed", None, {"error": str(e)}
                )
            )
    
    async def _send_scan_completion_notification(
        self,
        scan_run_id: str,
        tenant_id: Optional[str],
        account_id: str,
        provider_type: str,
        status: str,
        scan_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """Send webhook notification for scan completion"""
        if not tenant_id:
            return
        
        # Get tenant to retrieve webhook URL
        from engine_onboarding.database import get_tenant
        tenant = get_tenant(tenant_id)
        if not tenant:
            return
        
        webhook_url = tenant.get('webhook_url')
        if not webhook_url:
            return
        
        await self.webhook_sender.send_scan_completed(
            webhook_url=webhook_url,
            scan_run_id=scan_run_id,
            tenant_id=tenant_id,
            account_id=account_id,
            provider=provider_type,
            status=status,
            scan_id=scan_id,
            metadata=metadata
        )
    
    async def _send_notification_after_orchestration(
        self,
        orchestration_task: asyncio.Task,
        scan_run_id: str,
        tenant_id: Optional[str],
        account_id: str,
        provider_type: str,
        status: str,
        scan_id: Optional[str]
    ):
        """Wait for orchestration and send notification"""
        if not tenant_id:
            return
        
        try:
            orchestration_results = await orchestration_task
            
            # Get tenant to retrieve webhook URL
            from engine_onboarding.database import get_tenant
            tenant = get_tenant(tenant_id)
            if not tenant:
                return
            
            webhook_url = tenant.get('webhook_url')
            if not webhook_url:
                return
            
            await self.webhook_sender.send_orchestration_completed(
                webhook_url=webhook_url,
                scan_run_id=scan_run_id,
                orchestration_results=orchestration_results
            )
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to send orchestration notification: {e}")
            
            # Send webhook notification for scan failure
            asyncio.create_task(
                self._send_scan_completion_notification(
                    scan_run_id, tenant_id, account_id, provider_type, "failed", None, {"error": str(e)}
                )
            )

