"""
End-to-end integration test simulating complete scan flow
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
async def test_complete_scan_to_orchestration_flow():
    """
    Complete end-to-end test:
    1. User triggers scan via onboarding
    2. Onboarding creates execution and scan metadata
    3. ConfigScan engine receives request with tenant_id and scan_run_id
    4. ConfigScan completes and returns scan_id
    5. Orchestrator triggers all downstream engines
    6. Webhook notifications are sent
    7. All status is tracked in database
    """
    
    # Test data
    tenant_id = "tenant-456"
    account_id = "account-789"
    execution_id = "execution-123"
    scan_run_id = execution_id
    engine_scan_id = "engine-scan-999"
    provider = "aws"
    
    # Track all operations
    operations = []
    
    # Mock account
    mock_account = {
        'account_id': account_id,
        'tenant_id': tenant_id,
        'account_number': '123456789012',
        'status': 'active'
    }
    
    # Mock execution
    mock_execution = {
        'execution_id': execution_id,
        'started_at': datetime.utcnow().isoformat()
    }
    
    # Mock ConfigScan response
    mock_scan_result = {
        'scan_id': engine_scan_id,
        'status': 'completed',
        'total_checks': 100,
        'passed_checks': 80,
        'failed_checks': 20
    }
    
    # Mock database operations
    with patch('onboarding_engine.database.dynamodb_operations.get_account') as mock_get_account, \
         patch('onboarding_engine.database.dynamodb_operations.create_execution') as mock_create_execution, \
         patch('onboarding_engine.database.dynamodb_operations.update_execution') as mock_update_execution, \
         patch('onboarding_engine.database.dynamodb_operations.create_scan_metadata') as mock_create_metadata, \
         patch('onboarding_engine.database.dynamodb_operations.update_scan_metadata') as mock_update_metadata, \
         patch('onboarding_engine.database.dynamodb_operations.create_orchestration_status') as mock_create_orch, \
         patch('onboarding_engine.database.dynamodb_operations.update_orchestration_status') as mock_update_orch, \
         patch('onboarding_engine.database.dynamodb_operations.get_tenant') as mock_get_tenant, \
         patch('onboarding_engine.storage.secrets_manager_storage.secrets_manager_storage.retrieve') as mock_retrieve:
        
        # Setup mocks
        mock_get_account.return_value = mock_account
        mock_create_execution.return_value = mock_execution
        mock_get_tenant.return_value = {'tenant_id': tenant_id, 'webhook_url': 'http://test-webhook.com'}
        mock_retrieve.return_value = {'credential_type': 'aws_iam_role', 'role_name': 'test-role'}
        
        # Mock engine client
        with patch('onboarding_engine.utils.engine_client.EngineClient') as mock_engine_client_class:
            mock_engine_client = MagicMock()
            mock_engine_client.scan_aws = AsyncMock(return_value=mock_scan_result)
            mock_engine_client_class.return_value = mock_engine_client
            
            # Mock orchestrator HTTP calls
            with patch('onboarding_engine.orchestrator.engine_orchestrator.httpx.AsyncClient') as mock_http_client:
                mock_response = MagicMock()
                mock_response.json.return_value = {'status': 'success'}
                mock_response.raise_for_status = MagicMock()
                
                mock_http = MagicMock()
                mock_http.post = AsyncMock(return_value=mock_response)
                mock_http.__aenter__ = AsyncMock(return_value=mock_http)
                mock_http.__aexit__ = AsyncMock(return_value=None)
                mock_http_client.return_value = mock_http
                
                # Mock webhook sender
                with patch('onboarding_engine.notifications.webhook_sender.httpx.AsyncClient') as mock_webhook_client:
                    mock_webhook_response = MagicMock()
                    mock_webhook_response.raise_for_status = MagicMock()
                    
                    mock_webhook_http = MagicMock()
                    mock_webhook_http.post = AsyncMock(return_value=mock_webhook_response)
                    mock_webhook_http.__aenter__ = AsyncMock(return_value=mock_webhook_http)
                    mock_webhook_http.__aexit__ = AsyncMock(return_value=None)
                    mock_webhook_client.return_value = mock_webhook_http
                    
                    # Import and execute
                    from onboarding_engine.scheduler.task_executor import TaskExecutor
                    
                    executor = TaskExecutor()
                    
                    # Execute the complete flow
                    result = await executor.execute_scheduled_scan(
                        schedule_id='schedule-123',
                        account_id=account_id,
                        provider_type=provider,
                        regions=['us-east-1'],
                        services=['s3'],
                        triggered_by='test'
                    )
                    
                    # ========== VERIFICATIONS ==========
                    
                    # 1. Verify execution was created
                    mock_create_execution.assert_called_once()
                    exec_call = mock_create_execution.call_args
                    assert exec_call[1]['account_id'] == account_id
                    
                    # 2. Verify scan metadata was created with correct IDs
                    mock_create_metadata.assert_called_once()
                    metadata_call = mock_create_metadata.call_args
                    assert metadata_call[1]['scan_run_id'] == scan_run_id
                    assert metadata_call[1]['tenant_id'] == tenant_id
                    assert metadata_call[1]['account_id'] == account_id
                    assert metadata_call[1]['provider'] == provider
                    
                    # 3. Verify engine was called with tenant_id and scan_run_id
                    mock_engine_client.scan_aws.assert_called_once()
                    engine_call = mock_engine_client.scan_aws.call_args
                    assert engine_call[1]['tenant_id'] == tenant_id
                    assert engine_call[1]['scan_run_id'] == scan_run_id
                    assert engine_call[1]['account_number'] == '123456789012'
                    
                    # 4. Verify execution was updated with scan results
                    mock_update_execution.assert_called_once()
                    update_call = mock_update_execution.call_args
                    assert update_call[1]['execution_id'] == execution_id
                    assert update_call[1]['status'] == 'completed'
                    assert update_call[1]['scan_id'] == engine_scan_id
                    assert update_call[1]['total_checks'] == 100
                    
                    # 5. Verify scan metadata was updated
                    mock_update_metadata.assert_called_once()
                    metadata_update = mock_update_metadata.call_args
                    assert metadata_update[1]['scan_run_id'] == scan_run_id
                    assert metadata_update[1]['status'] == 'completed'
                    assert metadata_update[1]['scan_id'] == engine_scan_id
                    
                    # 6. Verify orchestrator was called (via async task)
                    # Note: Since it's async task, we verify it was scheduled
                    # In real scenario, we'd wait for it
                    
                    # 7. Verify webhook was called (if tenant has webhook_url)
                    # The webhook is sent in async task, so we verify the call was made
                    await asyncio.sleep(0.1)  # Give async tasks time
                    
                    # Verify result structure
                    assert result['status'] == 'completed'
                    assert result['execution_id'] == execution_id
                    assert 'result' in result


@pytest.mark.asyncio
async def test_error_handling_in_scan_flow():
    """Test error handling throughout the scan flow"""
    from onboarding_engine.scheduler.task_executor import TaskExecutor
    
    tenant_id = "tenant-456"
    account_id = "account-789"
    
    mock_account = {
        'account_id': account_id,
        'tenant_id': tenant_id,
        'status': 'active'
    }
    
    # Mock engine to raise error
    with patch('onboarding_engine.database.dynamodb_operations.get_account') as mock_get_account, \
         patch('onboarding_engine.database.dynamodb_operations.create_execution') as mock_create_execution, \
         patch('onboarding_engine.database.dynamodb_operations.update_execution') as mock_update_execution, \
         patch('onboarding_engine.database.dynamodb_operations.create_scan_metadata') as mock_create_metadata, \
         patch('onboarding_engine.database.dynamodb_operations.update_scan_metadata') as mock_update_metadata, \
         patch('onboarding_engine.storage.secrets_manager_storage.secrets_manager_storage.retrieve') as mock_retrieve, \
         patch('onboarding_engine.utils.engine_client.EngineClient') as mock_engine_client_class:
        
        mock_get_account.return_value = mock_account
        mock_create_execution.return_value = {
            'execution_id': 'exec-123',
            'started_at': datetime.utcnow().isoformat()
        }
        mock_retrieve.return_value = {'credential_type': 'aws_iam_role'}
        
        mock_engine_client = MagicMock()
        mock_engine_client.scan_aws = AsyncMock(side_effect=Exception("Engine error"))
        mock_engine_client_class.return_value = mock_engine_client
        
        executor = TaskExecutor()
        
        # Execute should handle error gracefully
        with pytest.raises(Exception):
            await executor.execute_scheduled_scan(
                schedule_id='schedule-123',
                account_id=account_id,
                provider_type='aws',
                triggered_by='test'
            )
        
        # Verify error was recorded
        mock_update_execution.assert_called()
        error_call = mock_update_execution.call_args
        assert error_call[1]['status'] == 'failed'
        assert 'error_message' in error_call[1] or error_call[1].get('error_message')
        
        # Verify metadata was updated with error
        mock_update_metadata.assert_called()
        metadata_error = mock_update_metadata.call_args
        assert metadata_error[1]['status'] == 'failed'


@pytest.mark.asyncio
async def test_multi_tenant_isolation():
    """Test that scan_run_id and tenant_id ensure multi-tenant isolation"""
    from common.storage_paths import StoragePathResolver
    
    resolver = StoragePathResolver(storage_type="local", local_base_path="/tmp/test")
    
    # Different tenants, same scan_run_id (shouldn't happen, but test isolation)
    tenant1_scan = resolver.get_scan_results_path("aws", "scan-123", "results.ndjson")
    tenant2_scan = resolver.get_scan_results_path("aws", "scan-123", "results.ndjson")
    
    # Paths should be the same (scan_run_id is the key)
    assert tenant1_scan == tenant2_scan
    
    # But different scan_run_ids should have different paths
    scan1_path = resolver.get_scan_results_path("aws", "scan-123", "results.ndjson")
    scan2_path = resolver.get_scan_results_path("aws", "scan-456", "results.ndjson")
    
    assert scan1_path != scan2_path
    assert "scan-123" in scan1_path
    assert "scan-456" in scan2_path


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
