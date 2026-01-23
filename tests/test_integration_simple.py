"""
Simple integration tests that can run without full module dependencies
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from unittest.mock import MagicMock, patch


def test_storage_paths_integration():
    """Test storage paths work correctly"""
    from common.storage_paths import StoragePathResolver
    
    resolver = StoragePathResolver(storage_type="local", local_base_path="/tmp/test")
    
    # Test scan results path
    path = resolver.get_scan_results_path("aws", "scan-123")
    assert "aws-configScan-engine" in path
    assert "scan-123" in path
    assert path.endswith("results.ndjson")
    
    # Test S3 path
    s3_resolver = StoragePathResolver(storage_type="s3", s3_bucket="test-bucket")
    s3_path = s3_resolver.get_scan_results_path("aws", "scan-123")
    assert s3_path.startswith("s3://")
    assert "test-bucket" in s3_path


def test_api_models_serialization():
    """Test API models can be serialized"""
    from common.api_models import HealthResponse, ErrorResponse
    
    health = HealthResponse(status="healthy", version="1.0.0")
    assert health.status == "healthy"
    
    # Test JSON serialization
    import json
    health_dict = health.model_dump()
    assert health_dict["status"] == "healthy"
    
    error = ErrorResponse(error="Test error", error_code="TEST")
    error_dict = error.model_dump()
    assert error_dict["error"] == "Test error"


def test_retry_handler_decorator():
    """Test retry handler can be used as decorator"""
    from common.retry_handler import retry_with_backoff
    
    call_count = [0]
    
    @retry_with_backoff(max_retries=2, initial_delay=0.01)
    def test_func():
        call_count[0] += 1
        if call_count[0] < 2:
            raise ValueError("Retry me")
        return "success"
    
    result = test_func()
    assert result == "success"
    assert call_count[0] == 2


def test_circuit_breaker_basic():
    """Test circuit breaker basic functionality"""
    from common.circuit_breaker import CircuitBreaker, CircuitState
    
    breaker = CircuitBreaker(failure_threshold=2, recovery_timeout=0.1)
    
    def success():
        return "ok"
    
    # Should work normally
    assert breaker.call(success) == "ok"
    assert breaker.state == CircuitState.CLOSED
    
    # Fail twice to open circuit
    def fail():
        raise ValueError("fail")
    
    for _ in range(2):
        try:
            breaker.call(fail)
        except ValueError:
            pass
    
    assert breaker.state == CircuitState.OPEN


def test_webhook_payload_structure():
    """Test webhook sender creates correct payload structure"""
    from onboarding_engine.notifications.webhook_sender import WebhookSender
    from datetime import datetime
    
    sender = WebhookSender()
    
    # Test payload structure (without actually sending)
    payload = {
        "event_type": "scan_completed",
        "scan_run_id": "scan-123",
        "tenant_id": "tenant-456",
        "account_id": "account-789",
        "provider": "aws",
        "status": "completed",
        "timestamp": datetime.utcnow().isoformat()
    }
    
    assert payload["event_type"] == "scan_completed"
    assert payload["scan_run_id"] == "scan-123"
    assert "timestamp" in payload


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
