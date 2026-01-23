"""
Tests for engine orchestrator
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from onboarding_engine.orchestrator.engine_orchestrator import EngineOrchestrator


@pytest.mark.asyncio
async def test_trigger_downstream_engines():
    """Test triggering all downstream engines"""
    orchestrator = EngineOrchestrator()
    
    # Mock HTTP client
    mock_response = MagicMock()
    mock_response.json.return_value = {"status": "success"}
    mock_response.raise_for_status = MagicMock()
    
    with patch('onboarding.orchestrator.engine_orchestrator.httpx.AsyncClient') as mock_client:
        mock_client.return_value.__aenter__.return_value.post = AsyncMock(return_value=mock_response)
        mock_client.return_value.__aenter__.return_value.__aexit__ = AsyncMock(return_value=None)
        
        # Mock database operations
        with patch('onboarding_engine.orchestrator.engine_orchestrator.create_orchestration_status') as mock_create, \
             patch('onboarding_engine.orchestrator.engine_orchestrator.update_orchestration_status') as mock_update:
            
            result = await orchestrator.trigger_downstream_engines(
                scan_run_id="scan-123",
                tenant_id="tenant-456",
                account_id="account-789",
                provider_type="aws",
                scan_id="engine-scan-999"
            )
            
            # Check that all engines were triggered
            assert result["scan_run_id"] == "scan-123"
            assert result["tenant_id"] == "tenant-456"
            assert "engines" in result
            assert "threat" in result["engines"]
            assert "compliance" in result["engines"]
            assert "datasec" in result["engines"]
            assert "inventory" in result["engines"]
            
            # Check orchestration status was created for each engine
            assert mock_create.call_count == 4  # One for each engine


@pytest.mark.asyncio
async def test_orchestrator_handles_failures():
    """Test orchestrator handles engine failures gracefully"""
    orchestrator = EngineOrchestrator()
    
    # Mock HTTP client to raise exception
    with patch('onboarding_engine.orchestrator.engine_orchestrator.httpx.AsyncClient') as mock_client:
        mock_client.return_value.__aenter__.return_value.post = AsyncMock(side_effect=Exception("Connection error"))
        mock_client.return_value.__aenter__.return_value.__aexit__ = AsyncMock(return_value=None)
        
        # Mock database operations
        with patch('onboarding_engine.orchestrator.engine_orchestrator.create_orchestration_status'), \
             patch('onboarding_engine.orchestrator.engine_orchestrator.update_orchestration_status'):
            
            result = await orchestrator.trigger_downstream_engines(
                scan_run_id="scan-123",
                tenant_id="tenant-456",
                account_id="account-789",
                provider_type="aws",
                scan_id="engine-scan-999"
            )
            
            # Should still return results with error status
            assert result["scan_run_id"] == "scan-123"
            assert "engines" in result
            # Engines should have failed status
            for engine_name in ["threat", "compliance", "datasec", "inventory"]:
                assert result["engines"][engine_name]["status"] == "failed"
                assert "error" in result["engines"][engine_name]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
