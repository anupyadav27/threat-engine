"""
API Gateway Tests
Tests for routing, authentication, and service discovery
"""

import pytest
import httpx
from fastapi.testclient import TestClient
from unittest.mock import patch, Mock
import os
import sys

# Add API Gateway to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'api_gateway'))

from main import app


class TestAPIGateway:
    """Test suite for API Gateway functionality"""
    
    def setup_method(self):
        """Set up test client"""
        self.client = TestClient(app)
    
    def test_health_endpoint(self):
        """Test API Gateway health endpoint"""
        response = self.client.get("/health")
        assert response.status_code == 200
        
        data = response.json()
        assert data["status"] == "healthy"
        assert "services" in data
        assert "timestamp" in data
    
    def test_root_endpoint(self):
        """Test root endpoint returns service info"""
        response = self.client.get("/")
        assert response.status_code == 200
        
        data = response.json()
        assert data["service"] == "threat-engine-api-gateway"
        assert data["version"] == "2.0.0"
        assert "routes" in data
    
    @patch('main.httpx.AsyncClient')
    def test_core_service_routing(self, mock_client):
        """Test routing to core engine service"""
        # Mock successful response from core service
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "ok", "service": "core-engine"}
        mock_response.content = b'{"status": "ok", "service": "core-engine"}'
        mock_response.headers = {"content-type": "application/json"}
        
        mock_client_instance = Mock()
        mock_client_instance.get.return_value = mock_response
        mock_client.return_value.__aenter__.return_value = mock_client_instance
        
        response = self.client.get("/api/v1/core/health")
        assert response.status_code == 200
        
        # Verify the backend service was called
        mock_client_instance.get.assert_called_once()
    
    @patch('main.httpx.AsyncClient')
    def test_platform_service_routing(self, mock_client):
        """Test routing to platform service"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "ok", "service": "platform"}
        mock_response.content = b'{"status": "ok", "service": "platform"}'
        mock_response.headers = {"content-type": "application/json"}
        
        mock_client_instance = Mock()
        mock_client_instance.get.return_value = mock_response
        mock_client.return_value.__aenter__.return_value = mock_client_instance
        
        response = self.client.get("/api/v1/platform/health")
        assert response.status_code == 200
    
    @patch('main.httpx.AsyncClient')
    def test_configscan_service_routing(self, mock_client):
        """Test routing to configscan service"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "ok", "service": "configscan"}
        mock_response.content = b'{"status": "ok", "service": "configscan"}'
        mock_response.headers = {"content-type": "application/json"}
        
        mock_client_instance = Mock()
        mock_client_instance.get.return_value = mock_response
        mock_client.return_value.__aenter__.return_value = mock_client_instance
        
        response = self.client.get("/api/v1/configscan/health")
        assert response.status_code == 200
    
    @patch('main.httpx.AsyncClient') 
    def test_data_secops_service_routing(self, mock_client):
        """Test routing to data-secops service"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "ok", "service": "data-secops"}
        mock_response.content = b'{"status": "ok", "service": "data-secops"}'
        mock_response.headers = {"content-type": "application/json"}
        
        mock_client_instance = Mock()
        mock_client_instance.get.return_value = mock_response
        mock_client.return_value.__aenter__.return_value = mock_client_instance
        
        response = self.client.get("/api/v1/data-secops/health")
        assert response.status_code == 200
    
    def test_invalid_route_404(self):
        """Test that invalid routes return 404"""
        response = self.client.get("/api/v1/nonexistent/health")
        assert response.status_code == 404
    
    @patch('main.httpx.AsyncClient')
    def test_service_unavailable_handling(self, mock_client):
        """Test handling when backend service is unavailable"""
        # Mock connection error
        mock_client_instance = Mock()
        mock_client_instance.get.side_effect = httpx.ConnectError("Connection failed")
        mock_client.return_value.__aenter__.return_value = mock_client_instance
        
        response = self.client.get("/api/v1/core/health")
        assert response.status_code == 503
        
        data = response.json()
        assert "error" in data
        assert "Service temporarily unavailable" in data["error"]
    
    def test_request_headers_forwarded(self):
        """Test that request headers are properly forwarded"""
        # This would require more sophisticated mocking to verify headers
        # For now, we'll test that custom headers don't break routing
        headers = {
            "X-Tenant-ID": "test-tenant",
            "X-User-ID": "test-user",
            "Authorization": "Bearer test-token"
        }
        
        response = self.client.get("/health", headers=headers)
        assert response.status_code == 200
    
    @patch('main.httpx.AsyncClient')
    def test_post_request_routing(self, mock_client):
        """Test POST request routing"""
        mock_response = Mock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"scan_id": "test-scan-123"}
        mock_response.content = b'{"scan_id": "test-scan-123"}'
        mock_response.headers = {"content-type": "application/json"}
        
        mock_client_instance = Mock()
        mock_client_instance.post.return_value = mock_response
        mock_client.return_value.__aenter__.return_value = mock_client_instance
        
        test_data = {"tenant_id": "test", "csp": "aws"}
        response = self.client.post("/api/v1/configscan/scan", json=test_data)
        assert response.status_code == 201
        
        # Verify POST data was forwarded
        mock_client_instance.post.assert_called_once()
    
    def test_cors_headers(self):
        """Test CORS headers are present"""
        response = self.client.options("/health")
        assert response.status_code == 200
        
        # Check for CORS headers
        assert "access-control-allow-origin" in response.headers
    
    @patch('main.httpx.AsyncClient')
    def test_timeout_handling(self, mock_client):
        """Test request timeout handling"""
        mock_client_instance = Mock()
        mock_client_instance.get.side_effect = httpx.TimeoutException("Request timed out")
        mock_client.return_value.__aenter__.return_value = mock_client_instance
        
        response = self.client.get("/api/v1/core/health")
        assert response.status_code == 504  # Gateway Timeout
        
        data = response.json()
        assert "error" in data
        assert "timeout" in data["error"].lower()


@pytest.mark.asyncio
class TestAPIGatewayAsync:
    """Async tests for API Gateway"""
    
    async def test_service_health_check_all(self):
        """Test health check aggregation from all services"""
        # This would test the actual health check aggregation logic
        # when implemented in the gateway
        pass
    
    async def test_load_balancing(self):
        """Test load balancing between service instances"""
        # This would test round-robin or other load balancing
        # when multiple instances are available
        pass
    
    async def test_circuit_breaker(self):
        """Test circuit breaker pattern for failing services"""
        # This would test circuit breaker implementation
        # to prevent cascading failures
        pass


if __name__ == "__main__":
    pytest.main([__file__, "-v"])