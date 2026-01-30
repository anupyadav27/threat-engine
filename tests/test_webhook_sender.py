"""
Tests for webhook sender
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from engine_onboarding.notifications.webhook_sender import WebhookSender


@pytest.mark.asyncio
async def test_send_scan_completed_success():
    """Test successful webhook notification"""
    sender = WebhookSender(timeout=5.0)
    
    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    
    with patch('engine_onboarding.notifications.webhook_sender.httpx.AsyncClient') as mock_client:
        mock_client.return_value.__aenter__.return_value.post = AsyncMock(return_value=mock_response)
        mock_client.return_value.__aenter__.return_value.__aexit__ = AsyncMock(return_value=None)
        
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
        mock_client.return_value.__aenter__.return_value.post.assert_called_once()
        
        # Check payload
        call_args = mock_client.return_value.__aenter__.return_value.post.call_args
        assert call_args[0][0] == "http://test-webhook.com/notify"
        payload = call_args[1]["json"]
        assert payload["event_type"] == "scan_completed"
        assert payload["scan_run_id"] == "scan-123"
        assert payload["status"] == "completed"


@pytest.mark.asyncio
async def test_send_scan_completed_failure():
    """Test webhook notification failure handling"""
    sender = WebhookSender(timeout=5.0)
    
    with patch('engine_onboarding.notifications.webhook_sender.httpx.AsyncClient') as mock_client:
        mock_client.return_value.__aenter__.return_value.post = AsyncMock(side_effect=Exception("Connection error"))
        mock_client.return_value.__aenter__.return_value.__aexit__ = AsyncMock(return_value=None)
        
        result = await sender.send_scan_completed(
            webhook_url="http://test-webhook.com/notify",
            scan_run_id="scan-123",
            tenant_id="tenant-456",
            account_id="account-789",
            provider="aws",
            status="failed"
        )
        
        assert result is False


@pytest.mark.asyncio
async def test_send_orchestration_completed():
    """Test orchestration completion webhook"""
    sender = WebhookSender(timeout=5.0)
    
    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    
    with patch('engine_onboarding.notifications.webhook_sender.httpx.AsyncClient') as mock_client:
        mock_client.return_value.__aenter__.return_value.post = AsyncMock(return_value=mock_response)
        mock_client.return_value.__aenter__.return_value.__aexit__ = AsyncMock(return_value=None)
        
        orchestration_results = {
            "engines": {
                "threat": {"status": "completed"},
                "compliance": {"status": "completed"}
            }
        }
        
        result = await sender.send_orchestration_completed(
            webhook_url="http://test-webhook.com/notify",
            scan_run_id="scan-123",
            orchestration_results=orchestration_results
        )
        
        assert result is True
        
        # Check payload
        call_args = mock_client.return_value.__aenter__.return_value.post.call_args
        payload = call_args[1]["json"]
        assert payload["event_type"] == "orchestration_completed"
        assert payload["scan_run_id"] == "scan-123"
        assert "orchestration" in payload


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
