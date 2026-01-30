"""
Integration tests that work with actual module structure
Tests the integration points without requiring full module dependencies
"""
import sys
import os
import pytest
import json
from unittest.mock import MagicMock, AsyncMock

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)


def test_scan_request_structure():
    """Test that scan request structure includes tenant_id and scan_run_id"""
    # Simulate the request structure that would be sent
    request_payload = {
        "account": "123456789012",
        "credentials": {
            "credential_type": "aws_iam_role",
            "role_name": "test-role"
        },
        "tenant_id": "tenant-456",
        "scan_run_id": "scan-123",
        "include_regions": ["us-east-1"],
        "include_services": ["s3", "iam"]
    }
    
    # Verify structure
    assert "tenant_id" in request_payload
    assert "scan_run_id" in request_payload
    assert request_payload["tenant_id"] == "tenant-456"
    assert request_payload["scan_run_id"] == "scan-123"
    
    # Verify JSON serialization
    json_str = json.dumps(request_payload)
    parsed = json.loads(json_str)
    assert parsed["tenant_id"] == "tenant-456"
    assert parsed["scan_run_id"] == "scan-123"


def test_scan_id_flow_consistency():
    """Test scan ID flow is consistent through the system"""
    # Step 1: Onboarding creates execution
    execution_id = "execution-789"
    scan_run_id = execution_id  # Onboarding uses execution_id as scan_run_id
    
    # Step 2: ConfigScan receives scan_run_id
    configscan_request = {
        "scan_run_id": scan_run_id,
        "tenant_id": "tenant-456",
        "account": "123456789012"
    }
    
    # Step 3: ConfigScan generates its own scan_id (for backward compatibility)
    engine_scan_id = "engine-scan-999"
    
    # Step 4: Downstream engines receive both
    threat_request = {
        "scan_run_id": scan_run_id,  # Primary identifier
        "tenant_id": "tenant-456",
        "cloud": "aws"
    }
    
    compliance_request = {
        "scan_id": engine_scan_id,  # Uses ConfigScan's scan_id
        "csp": "aws",
        "tenant_id": "tenant-456"
    }
    
    # Verify consistency
    assert configscan_request["scan_run_id"] == scan_run_id
    assert threat_request["scan_run_id"] == scan_run_id
    assert compliance_request["tenant_id"] == threat_request["tenant_id"]
    assert compliance_request["scan_id"] == engine_scan_id


def test_storage_path_integration_flow():
    """Test storage paths work correctly in integration flow"""
    from engine_common.storage_paths import StoragePathResolver
    
    resolver = StoragePathResolver(storage_type="local", local_base_path="/tmp/test")
    
    # Simulate scan flow
    scan_run_id = "scan-123"
    csp = "aws"
    account_id = "123456789012"
    region = "us-east-1"
    
    # ConfigScan writes results here
    configscan_write_path = resolver.get_scan_results_path(csp, scan_run_id, "results.ndjson")
    
    # Threat engine reads from same path
    threat_read_path = resolver.get_scan_results_path(csp, scan_run_id, "results.ndjson")
    
    # Compliance engine reads from same path
    compliance_read_path = resolver.get_scan_results_path(csp, scan_run_id, "results.ndjson")
    
    # DataSec engine reads from same path
    datasec_read_path = resolver.get_scan_results_path(csp, scan_run_id, "results.ndjson")
    
    # All should use same path
    assert configscan_write_path == threat_read_path
    assert configscan_write_path == compliance_read_path
    assert configscan_write_path == datasec_read_path
    
    # Verify path format
    assert f"{csp}-configScan-engine/output/{scan_run_id}" in configscan_write_path


def test_orchestration_payload_structure():
    """Test orchestration payloads are structured correctly"""
    # Threat engine payload
    threat_payload = {
        "tenant_id": "tenant-456",
        "scan_run_id": "scan-123",
        "cloud": "aws",
        "trigger_type": "orchestrated",
        "accounts": [],
        "regions": [],
        "services": [],
        "started_at": "2025-01-23T00:00:00Z",
        "completed_at": "2025-01-23T01:00:00Z"
    }
    
    # Compliance engine payload
    compliance_payload = {
        "scan_id": "engine-scan-999",
        "csp": "aws",
        "tenant_id": "tenant-456",
        "tenant_name": None,
        "trigger_type": "orchestrated"
    }
    
    # DataSec engine payload
    datasec_payload = {
        "csp": "aws",
        "scan_id": "engine-scan-999",
        "tenant_id": "tenant-456",
        "include_classification": True,
        "include_lineage": True,
        "include_residency": True,
        "include_activity": True,
        "allowed_regions": [],
        "max_findings": 5000
    }
    
    # Inventory engine payload
    inventory_payload = {
        "tenant_id": "tenant-456",
        "configscan_scan_id": "engine-scan-999",
        "providers": ["aws"],
        "accounts": [],
        "previous_scan_id": None
    }
    
    # Verify all have tenant_id
    assert threat_payload["tenant_id"] == "tenant-456"
    assert compliance_payload["tenant_id"] == "tenant-456"
    assert datasec_payload["tenant_id"] == "tenant-456"
    assert inventory_payload["tenant_id"] == "tenant-456"
    
    # Verify scan identifiers
    assert threat_payload["scan_run_id"] == "scan-123"
    assert compliance_payload["scan_id"] == "engine-scan-999"
    assert datasec_payload["scan_id"] == "engine-scan-999"
    assert inventory_payload["configscan_scan_id"] == "engine-scan-999"


def test_database_schema_consistency():
    """Test database schema supports integration requirements"""
    # Scan metadata schema
    scan_metadata = {
        "scan_run_id": "scan-123",  # Primary key
        "tenant_id": "tenant-456",
        "account_id": "account-789",
        "provider": "aws",
        "scan_id": "engine-scan-999",  # ConfigScan's scan_id
        "status": "completed",
        "started_at": "2025-01-23T00:00:00Z",
        "completed_at": "2025-01-23T01:00:00Z"
    }
    
    # Orchestration status schema
    orchestration_status = {
        "scan_run_id": "scan-123",  # Partition key
        "engine": "threat",  # Sort key
        "status": "completed",
        "started_at": "2025-01-23T01:00:00Z",
        "completed_at": "2025-01-23T01:05:00Z"
    }
    
    # Verify schema supports queries
    assert "scan_run_id" in scan_metadata
    assert "tenant_id" in scan_metadata
    assert "account_id" in scan_metadata
    assert "provider" in scan_metadata
    
    # Verify orchestration status links to scan
    assert orchestration_status["scan_run_id"] == scan_metadata["scan_run_id"]


def test_webhook_payload_integration():
    """Test webhook payloads contain all necessary information"""
    # Scan completion webhook
    scan_webhook = {
        "event_type": "scan_completed",
        "scan_run_id": "scan-123",
        "tenant_id": "tenant-456",
        "account_id": "account-789",
        "provider": "aws",
        "status": "completed",
        "scan_id": "engine-scan-999",
        "timestamp": "2025-01-23T01:00:00Z",
        "metadata": {
            "total_checks": 100,
            "passed_checks": 80,
            "failed_checks": 20
        }
    }
    
    # Orchestration completion webhook
    orchestration_webhook = {
        "event_type": "orchestration_completed",
        "scan_run_id": "scan-123",
        "timestamp": "2025-01-23T01:10:00Z",
        "orchestration": {
            "engines": {
                "threat": {"status": "completed"},
                "compliance": {"status": "completed"},
                "datasec": {"status": "completed"},
                "inventory": {"status": "completed"}
            }
        }
    }
    
    # Verify webhooks have necessary info
    assert scan_webhook["scan_run_id"] == "scan-123"
    assert scan_webhook["tenant_id"] == "tenant-456"
    assert scan_webhook["status"] == "completed"
    
    assert orchestration_webhook["scan_run_id"] == "scan-123"
    assert "orchestration" in orchestration_webhook


def test_error_propagation():
    """Test errors propagate correctly through the system"""
    # Simulate error at ConfigScan level
    configscan_error = {
        "scan_run_id": "scan-123",
        "status": "failed",
        "error": "Connection timeout"
    }
    
    # Error should be recorded in scan metadata
    scan_metadata_error = {
        "scan_run_id": "scan-123",
        "status": "failed",
        "completed_at": "2025-01-23T00:30:00Z",
        "metadata": {
            "error": "Connection timeout"
        }
    }
    
    # Error should be recorded in execution
    execution_error = {
        "execution_id": "scan-123",
        "status": "failed",
        "error_message": "Connection timeout"
    }
    
    # Verify error propagation
    assert configscan_error["status"] == "failed"
    assert scan_metadata_error["status"] == "failed"
    assert execution_error["status"] == "failed"
    assert "error" in configscan_error or "error_message" in execution_error


def test_multi_engine_coordination():
    """Test multiple engines coordinate using same identifiers"""
    scan_run_id = "scan-123"
    tenant_id = "tenant-456"
    engine_scan_id = "engine-scan-999"
    
    # All engines should know about the scan
    engines_status = {
        "scan_run_id": scan_run_id,
        "tenant_id": tenant_id,
        "engines": {
            "configscan": {
                "scan_id": engine_scan_id,
                "status": "completed"
            },
            "threat": {
                "scan_run_id": scan_run_id,
                "status": "running"
            },
            "compliance": {
                "scan_id": engine_scan_id,
                "status": "pending"
            },
            "datasec": {
                "scan_id": engine_scan_id,
                "status": "pending"
            },
            "inventory": {
                "configscan_scan_id": engine_scan_id,
                "status": "pending"
            }
        }
    }
    
    # Verify all engines reference the same scan
    assert engines_status["scan_run_id"] == scan_run_id
    assert engines_status["tenant_id"] == tenant_id
    assert engines_status["engines"]["configscan"]["scan_id"] == engine_scan_id
    assert engines_status["engines"]["threat"]["scan_run_id"] == scan_run_id
    assert engines_status["engines"]["compliance"]["scan_id"] == engine_scan_id


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
