"""
Full integration test for scan flow: Onboarding → ConfigScan → Downstream Engines
"""
import sys
import os
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.join(project_root, "onboarding_engine"))


@pytest.mark.asyncio
async def test_full_scan_flow_with_orchestration():
    """
    Test complete scan flow:
    1. Onboarding creates execution
    2. ConfigScan engine receives scan request with tenant_id and scan_run_id
    3. ConfigScan completes
    4. Orchestrator triggers downstream engines
    5. All engines receive correct scan_run_id
    """
    from unittest.mock import AsyncMock, MagicMock, patch
    
    # Mock account data
    mock_account = {
        'account_id': 'account-123',
        'tenant_id': 'tenant-456',
        'account_number': '123456789012',
        'status': 'active'
    }
    
    # Mock execution
    execution_id = 'execution-789'
    scan_run_id = execution_id  # Using execution_id as scan_run_id
    
    # Mock ConfigScan engine response
    mock_scan_response = {
        'scan_id': 'engine-scan-999',
        'status': 'completed',
        'total_checks': 100,
        'passed_checks': 80,
        'failed_checks': 20
    }
    
    # Track calls to verify integration
    engine_calls = []
    orchestration_calls = []
    
    # Mock engine client
    with patch('onboarding_engine.utils.engine_client.EngineClient') as mock_engine_client_class:
        mock_engine_client = MagicMock()
        mock_engine_client.scan_aws = AsyncMock(return_value=mock_scan_response)
        mock_engine_client_class.return_value = mock_engine_client
        
        # Mock database operations
        with patch('onboarding_engine.database.dynamodb_operations.get_account') as mock_get_account, \
             patch('onboarding_engine.database.dynamodb_operations.create_execution') as mock_create_execution, \
             patch('onboarding_engine.database.dynamodb_operations.update_execution') as mock_update_execution, \
             patch('onboarding_engine.database.dynamodb_operations.create_scan_metadata') as mock_create_metadata, \
             patch('onboarding_engine.database.dynamodb_operations.update_scan_metadata') as mock_update_metadata, \
             patch('onboarding_engine.storage.secrets_manager_storage.secrets_manager_storage.retrieve') as mock_retrieve:
            
            # Setup mocks
            mock_get_account.return_value = mock_account
            mock_create_execution.return_value = {
                'execution_id': execution_id,
                'started_at': datetime.utcnow().isoformat()
            }
            mock_retrieve.return_value = {
                'credential_type': 'aws_iam_role',
                'role_name': 'test-role'
            }
            
            # Mock orchestrator
            with patch('onboarding_engine.orchestrator.engine_orchestrator.EngineOrchestrator') as mock_orchestrator_class:
                mock_orchestrator = MagicMock()
                mock_orchestrator.trigger_downstream_engines = AsyncMock(return_value={
                    'scan_run_id': scan_run_id,
                    'engines': {
                        'threat': {'status': 'triggered'},
                        'compliance': {'status': 'triggered'},
                        'datasec': {'status': 'triggered'},
                        'inventory': {'status': 'triggered'}
                    }
                })
                mock_orchestrator_class.return_value = mock_orchestrator
                
                # Import and test task executor
                from onboarding_engine.scheduler.task_executor import TaskExecutor
                
                executor = TaskExecutor()
                
                # Execute scan
                result = await executor.execute_scheduled_scan(
                    schedule_id='schedule-123',
                    account_id='account-123',
                    provider_type='aws',
                    regions=['us-east-1'],
                    services=['s3'],
                    triggered_by='test'
                )
                
                # Verify results
                assert result['status'] == 'completed'
                assert result['execution_id'] == execution_id
                
                # Verify engine was called with tenant_id and scan_run_id
                mock_engine_client.scan_aws.assert_called_once()
                call_args = mock_engine_client.scan_aws.call_args
                assert call_args[1]['tenant_id'] == 'tenant-456'
                assert call_args[1]['scan_run_id'] == scan_run_id
                
                # Verify database operations
                mock_create_metadata.assert_called_once()
                metadata_call = mock_create_metadata.call_args
                assert metadata_call[1]['scan_run_id'] == scan_run_id
                assert metadata_call[1]['tenant_id'] == 'tenant-456'
                
                mock_update_metadata.assert_called_once()
                update_call = mock_update_metadata.call_args
                assert update_call[1]['scan_run_id'] == scan_run_id
                assert update_call[1]['status'] == 'completed'


@pytest.mark.asyncio
async def test_orchestration_triggers_all_engines():
    """Test that orchestrator triggers all downstream engines correctly"""
    from onboarding_engine.orchestrator.engine_orchestrator import EngineOrchestrator
    from unittest.mock import AsyncMock, patch
    
    orchestrator = EngineOrchestrator()
    
    # Mock HTTP responses for all engines
    mock_response = MagicMock()
    mock_response.json.return_value = {'status': 'success'}
    mock_response.raise_for_status = MagicMock()
    
    # Mock database operations
    with patch('onboarding_engine.orchestrator.engine_orchestrator.create_orchestration_status') as mock_create, \
         patch('onboarding_engine.orchestrator.engine_orchestrator.update_orchestration_status') as mock_update, \
         patch('onboarding_engine.orchestrator.engine_orchestrator.httpx.AsyncClient') as mock_client:
        
        mock_http_client = MagicMock()
        mock_http_client.post = AsyncMock(return_value=mock_response)
        mock_http_client.__aenter__ = AsyncMock(return_value=mock_http_client)
        mock_http_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.return_value = mock_http_client
        
        # Trigger orchestration
        result = await orchestrator.trigger_downstream_engines(
            scan_run_id='scan-123',
            tenant_id='tenant-456',
            account_id='account-789',
            provider_type='aws',
            scan_id='engine-scan-999'
        )
        
        # Verify all engines were triggered
        assert result['scan_run_id'] == 'scan-123'
        assert 'engines' in result
        assert 'threat' in result['engines']
        assert 'compliance' in result['engines']
        assert 'datasec' in result['engines']
        assert 'inventory' in result['engines']
        
        # Verify HTTP calls were made to all engines
        assert mock_http_client.post.call_count == 4  # One for each engine
        
        # Verify orchestration status was created for each engine
        assert mock_create.call_count == 4


@pytest.mark.asyncio
async def test_storage_paths_integration():
    """Test storage paths are used correctly in integration"""
    from common.storage_paths import StoragePathResolver
    
    resolver = StoragePathResolver(storage_type="local", local_base_path="/tmp/test")
    
    # Simulate scan flow
    scan_run_id = "scan-123"
    csp = "aws"
    
    # Get paths that would be used
    results_path = resolver.get_scan_results_path(csp, scan_run_id, "results.ndjson")
    summary_path = resolver.get_summary_path(csp, scan_run_id)
    inventory_path = resolver.get_inventory_path(csp, scan_run_id, "account-456", "us-east-1")
    
    # Verify paths are consistent
    assert scan_run_id in results_path
    assert scan_run_id in summary_path
    assert scan_run_id in inventory_path
    assert csp in results_path
    assert csp in summary_path
    assert csp in inventory_path


@pytest.mark.asyncio
async def test_webhook_notification_flow():
    """Test webhook notifications are sent correctly"""
    from onboarding_engine.notifications.webhook_sender import WebhookSender
    from unittest.mock import AsyncMock, patch, MagicMock
    
    sender = WebhookSender()
    
    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    
    with patch('onboarding_engine.notifications.webhook_sender.httpx.AsyncClient') as mock_client:
        mock_http_client = MagicMock()
        mock_http_client.post = AsyncMock(return_value=mock_response)
        mock_http_client.__aenter__ = AsyncMock(return_value=mock_http_client)
        mock_http_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.return_value = mock_http_client
        
        # Send notification
        result = await sender.send_scan_completed(
            webhook_url="http://test-webhook.com/notify",
            scan_run_id="scan-123",
            tenant_id="tenant-456",
            account_id="account-789",
            provider="aws",
            status="completed",
            scan_id="engine-scan-999"
        )
        
        assert result is True
        
        # Verify payload structure
        call_args = mock_http_client.post.call_args
        payload = call_args[1]["json"]
        assert payload["event_type"] == "scan_completed"
        assert payload["scan_run_id"] == "scan-123"
        assert payload["tenant_id"] == "tenant-456"
        assert payload["status"] == "completed"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
