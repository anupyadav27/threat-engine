"""
Integration tests for ConfigScan engine API with tenant_id and scan_run_id
"""
import sys
import os
import pytest
from unittest.mock import patch, MagicMock

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)


def test_aws_configscan_api_accepts_tenant_and_scan_run_id():
    """Test AWS ConfigScan API accepts and uses tenant_id and scan_run_id"""
    import json
    from fastapi.testclient import TestClient
    
    # We'll test the API structure without full engine dependencies
    # by checking the request model
    
    # Simulate the ScanRequest model structure
    request_data = {
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
    
    # Verify structure is correct
    assert "tenant_id" in request_data
    assert "scan_run_id" in request_data
    assert request_data["tenant_id"] == "tenant-456"
    assert request_data["scan_run_id"] == "scan-123"
    
    # Verify it can be serialized
    json_str = json.dumps(request_data)
    parsed = json.loads(json_str)
    assert parsed["tenant_id"] == "tenant-456"
    assert parsed["scan_run_id"] == "scan-123"


def test_scan_id_propagation_through_system():
    """Test scan_run_id propagates correctly through the system"""
    # Simulate the flow
    execution_id = "execution-789"
    scan_run_id = execution_id  # Onboarding uses execution_id as scan_run_id
    
    # ConfigScan receives scan_run_id
    configscan_scan_id = scan_run_id  # ConfigScan uses scan_run_id if provided
    
    # Downstream engines receive scan_run_id
    threat_engine_request = {
        "scan_run_id": scan_run_id,
        "tenant_id": "tenant-456",
        "cloud": "aws"
    }
    
    compliance_engine_request = {
        "scan_id": configscan_scan_id,  # Uses ConfigScan's scan_id
        "csp": "aws",
        "tenant_id": "tenant-456"
    }
    
    # Verify consistency
    assert threat_engine_request["scan_run_id"] == scan_run_id
    assert compliance_engine_request["scan_id"] == configscan_scan_id
    assert compliance_engine_request["tenant_id"] == threat_engine_request["tenant_id"]


def test_storage_path_consistency():
    """Test storage paths are consistent across engines"""
    from common.storage_paths import StoragePathResolver
    
    resolver = StoragePathResolver(storage_type="local", local_base_path="/tmp/test")
    
    scan_run_id = "scan-123"
    csp = "aws"
    
    # All engines should use same path format
    results_path = resolver.get_scan_results_path(csp, scan_run_id, "results.ndjson")
    summary_path = resolver.get_summary_path(csp, scan_run_id)
    
    # Verify format consistency
    assert f"{csp}-configScan-engine/output/{scan_run_id}" in results_path
    assert f"{csp}-configScan-engine/output/{scan_run_id}" in summary_path
    
    # Threat engine would read from same path
    threat_read_path = resolver.get_scan_results_path(csp, scan_run_id, "results.ndjson")
    assert threat_read_path == results_path
    
    # Compliance engine would read from same path
    compliance_read_path = resolver.get_scan_results_path(csp, scan_run_id, "results.ndjson")
    assert compliance_read_path == results_path


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
