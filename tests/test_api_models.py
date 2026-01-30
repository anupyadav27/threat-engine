"""
Tests for shared API models
"""
import pytest
from datetime import datetime
from engine_common.api_models import HealthResponse, ErrorResponse, ScanMetadata, OrchestrationStatus


def test_health_response():
    """Test health response model"""
    response = HealthResponse(status="healthy", version="1.0.0")
    assert response.status == "healthy"
    assert response.version == "1.0.0"
    assert response.timestamp is not None
    
    # Test with details
    response = HealthResponse(
        status="healthy",
        details={"database": "connected", "redis": "connected"}
    )
    assert response.details["database"] == "connected"


def test_error_response():
    """Test error response model"""
    response = ErrorResponse(
        error="Test error",
        error_code="TEST_ERROR",
        details={"field": "value"}
    )
    assert response.error == "Test error"
    assert response.error_code == "TEST_ERROR"
    assert response.details["field"] == "value"
    assert response.timestamp is not None


def test_scan_metadata():
    """Test scan metadata model"""
    metadata = ScanMetadata(
        scan_run_id="scan-123",
        tenant_id="tenant-456",
        account_id="account-789",
        provider="aws",
        status="running",
        started_at=datetime.utcnow().isoformat()
    )
    assert metadata.scan_run_id == "scan-123"
    assert metadata.tenant_id == "tenant-456"
    assert metadata.provider == "aws"
    assert metadata.status == "running"
    
    # Test with completion
    metadata = ScanMetadata(
        scan_run_id="scan-123",
        tenant_id="tenant-456",
        account_id="account-789",
        provider="aws",
        status="completed",
        started_at=datetime.utcnow().isoformat(),
        completed_at=datetime.utcnow().isoformat(),
        scan_id="engine-scan-999"
    )
    assert metadata.status == "completed"
    assert metadata.completed_at is not None
    assert metadata.scan_id == "engine-scan-999"


def test_orchestration_status():
    """Test orchestration status model"""
    status = OrchestrationStatus(
        scan_run_id="scan-123",
        engine="threat",
        status="running",
        started_at=datetime.utcnow().isoformat()
    )
    assert status.scan_run_id == "scan-123"
    assert status.engine == "threat"
    assert status.status == "running"
    
    # Test with completion
    status = OrchestrationStatus(
        scan_run_id="scan-123",
        engine="threat",
        status="completed",
        started_at=datetime.utcnow().isoformat(),
        completed_at=datetime.utcnow().isoformat()
    )
    assert status.status == "completed"
    assert status.completed_at is not None
    
    # Test with error
    status = OrchestrationStatus(
        scan_run_id="scan-123",
        engine="threat",
        status="failed",
        started_at=datetime.utcnow().isoformat(),
        completed_at=datetime.utcnow().isoformat(),
        error="Test error"
    )
    assert status.status == "failed"
    assert status.error == "Test error"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
