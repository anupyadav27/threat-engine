"""
Integration tests for database operations
"""
import sys
import os
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.join(project_root, "onboarding_engine"))


def test_scan_metadata_creation_and_update():
    """Test scan metadata is created and updated correctly"""
    # Mock DynamoDB operations
    with patch('onboarding_engine.database.dynamodb_operations.dynamodb') as mock_dynamodb:
        mock_table = MagicMock()
        mock_dynamodb.Table.return_value = mock_table
        
        from onboarding_engine.database.dynamodb_operations import (
            create_scan_metadata,
            update_scan_metadata,
            get_scan_metadata
        )
        
        # Create scan metadata
        scan_run_id = "scan-123"
        tenant_id = "tenant-456"
        account_id = "account-789"
        provider = "aws"
        
        metadata = create_scan_metadata(
            scan_run_id=scan_run_id,
            tenant_id=tenant_id,
            account_id=account_id,
            provider=provider,
            status='running'
        )
        
        # Verify structure
        assert metadata['scan_run_id'] == scan_run_id
        assert metadata['tenant_id'] == tenant_id
        assert metadata['account_id'] == account_id
        assert metadata['provider'] == provider
        assert metadata['status'] == 'running'
        
        # Update metadata
        updated = update_scan_metadata(
            scan_run_id=scan_run_id,
            status='completed',
            scan_id='engine-scan-999',
            completed_at=datetime.utcnow().isoformat()
        )
        
        # Verify update was called
        assert mock_table.put_item.called
        assert mock_table.update_item.called


def test_orchestration_status_tracking():
    """Test orchestration status is tracked for each engine"""
    with patch('onboarding_engine.database.dynamodb_operations.dynamodb') as mock_dynamodb:
        mock_table = MagicMock()
        mock_dynamodb.Table.return_value = mock_table
        
        from onboarding_engine.database.dynamodb_operations import (
            create_orchestration_status,
            update_orchestration_status,
            list_orchestration_status
        )
        
        scan_run_id = "scan-123"
        
        # Create status for each engine
        engines = ["threat", "compliance", "datasec", "inventory"]
        for engine in engines:
            status = create_orchestration_status(
                scan_run_id=scan_run_id,
                engine=engine,
                status='pending'
            )
            assert status['scan_run_id'] == scan_run_id
            assert status['engine'] == engine
            assert status['status'] == 'pending'
        
        # Update status for one engine
        updated = update_orchestration_status(
            scan_run_id=scan_run_id,
            engine="threat",
            status='completed'
        )
        
        # Verify database operations
        assert mock_table.put_item.call_count == 4  # One for each engine
        assert mock_table.update_item.called


def test_execution_to_scan_metadata_link():
    """Test execution record links to scan metadata"""
    with patch('onboarding_engine.database.dynamodb_operations.dynamodb') as mock_dynamodb:
        mock_table = MagicMock()
        mock_dynamodb.Table.return_value = mock_table
        
        from onboarding_engine.database.dynamodb_operations import (
            create_execution,
            create_scan_metadata
        )
        
        # Create execution
        execution = create_execution(
            schedule_id='schedule-123',
            account_id='account-789',
            triggered_by='test'
        )
        execution_id = execution['execution_id']
        
        # Create scan metadata using execution_id as scan_run_id
        metadata = create_scan_metadata(
            scan_run_id=execution_id,  # Link via execution_id
            tenant_id='tenant-456',
            account_id='account-789',
            provider='aws',
            status='running'
        )
        
        # Verify link
        assert metadata['scan_run_id'] == execution_id
        assert metadata['account_id'] == 'account-789'


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
