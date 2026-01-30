"""
Integration tests for engine client with tenant_id and scan_run_id
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from engine_onboarding.utils.engine_client import EngineClient


@pytest.mark.asyncio
async def test_scan_aws_with_tenant_and_scan_run_id():
    """Test AWS scan with tenant_id and scan_run_id"""
    client = EngineClient()
    
    # Mock HTTP responses
    mock_scan_response = MagicMock()
    mock_scan_response.json.return_value = {"scan_id": "engine-scan-123"}
    mock_scan_response.raise_for_status = MagicMock()
    
    mock_status_response = MagicMock()
    mock_status_response.json.return_value = {"status": "completed"}
    mock_status_response.raise_for_status = MagicMock()
    
    mock_summary_response = MagicMock()
    mock_summary_response.json.return_value = {
        "summary": {
            "total_checks": 100,
            "passed_checks": 80,
            "failed_checks": 20
        },
        "duration_seconds": 120
    }
    mock_summary_response.raise_for_status = MagicMock()
    
    with patch('engine_onboarding.utils.engine_client.httpx.AsyncClient') as mock_client:
        mock_http_client = MagicMock()
        mock_http_client.post = AsyncMock(return_value=mock_scan_response)
        mock_http_client.get = AsyncMock(side_effect=[mock_status_response, mock_summary_response])
        mock_http_client.__aenter__ = AsyncMock(return_value=mock_http_client)
        mock_http_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.return_value = mock_http_client
        
        result = await client.scan_aws(
            credentials={"credential_type": "aws_iam_role", "role_name": "test-role"},
            account_number="123456789012",
            tenant_id="tenant-456",
            scan_run_id="scan-123",
            regions=["us-east-1"],
            services=["s3", "iam"]
        )
        
        assert result["scan_id"] == "engine-scan-123"
        assert result["status"] == "completed"
        assert result["total_checks"] == 100
        
        # Verify tenant_id and scan_run_id were sent in request
        post_call = mock_http_client.post.call_args
        request_payload = post_call[1]["json"]
        assert request_payload.get("tenant_id") == "tenant-456"
        assert request_payload.get("scan_run_id") == "scan-123"


@pytest.mark.asyncio
async def test_scan_azure_with_tenant_and_scan_run_id():
    """Test Azure scan with tenant_id and scan_run_id"""
    client = EngineClient()
    
    mock_response = MagicMock()
    mock_response.json.return_value = {"scan_id": "azure-scan-123", "status": "running"}
    mock_response.raise_for_status = MagicMock()
    
    with patch('engine_onboarding.utils.engine_client.httpx.AsyncClient') as mock_client:
        mock_http_client = MagicMock()
        mock_http_client.post = AsyncMock(return_value=mock_response)
        mock_http_client.__aenter__ = AsyncMock(return_value=mock_http_client)
        mock_http_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.return_value = mock_http_client
        
        result = await client.scan_azure(
            credentials={"credential_type": "service_principal"},
            subscription_id="sub-123",
            tenant_id="tenant-456",
            scan_run_id="scan-123"
        )
        
        # Verify tenant_id and scan_run_id were sent
        post_call = mock_http_client.post.call_args
        request_payload = post_call[1]["json"]
        assert request_payload.get("tenant_id") == "tenant-456"
        assert request_payload.get("scan_run_id") == "scan-123"


@pytest.mark.asyncio
async def test_scan_gcp_with_tenant_and_scan_run_id():
    """Test GCP scan with tenant_id and scan_run_id"""
    client = EngineClient()
    
    mock_response = MagicMock()
    mock_response.json.return_value = {"scan_id": "gcp-scan-123", "status": "running"}
    mock_response.raise_for_status = MagicMock()
    
    with patch('engine_onboarding.utils.engine_client.httpx.AsyncClient') as mock_client:
        mock_http_client = MagicMock()
        mock_http_client.post = AsyncMock(return_value=mock_response)
        mock_http_client.__aenter__ = AsyncMock(return_value=mock_http_client)
        mock_http_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.return_value = mock_http_client
        
        result = await client.scan_gcp(
            credentials={"credential_type": "service_account"},
            project_id="project-123",
            tenant_id="tenant-456",
            scan_run_id="scan-123"
        )
        
        # Verify tenant_id and scan_run_id were sent
        post_call = mock_http_client.post.call_args
        request_payload = post_call[1]["json"]
        assert request_payload.get("tenant_id") == "tenant-456"
        assert request_payload.get("scan_run_id") == "scan-123"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
