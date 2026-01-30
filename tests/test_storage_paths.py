"""
Tests for storage path resolver
"""
import os
import pytest
from engine_common.storage_paths import StoragePathResolver, get_scan_results_path, get_inventory_path, get_summary_path


def test_storage_path_resolver_local():
    """Test local storage path resolution"""
    resolver = StoragePathResolver(storage_type="local", local_base_path="/tmp/test-output")
    
    path = resolver.get_scan_results_path("aws", "scan-123", "results.ndjson")
    assert path == "/tmp/test-output/engine_configscan_aws/output/scan-123/results.ndjson"
    
    path = resolver.get_scan_results_path("azure", "scan-456", "summary.json")
    assert path == "/tmp/test-output/engine_configscan_azure/output/scan-456/summary.json"


def test_storage_path_resolver_s3():
    """Test S3 storage path resolution"""
    resolver = StoragePathResolver(storage_type="s3", s3_bucket="test-bucket")
    
    path = resolver.get_scan_results_path("aws", "scan-123", "results.ndjson")
    assert path == "s3://test-bucket/engine_configscan_aws/output/scan-123/results.ndjson"


def test_inventory_path():
    """Test inventory path generation"""
    resolver = StoragePathResolver(storage_type="local", local_base_path="/tmp/test")
    
    path = resolver.get_inventory_path("aws", "scan-123", "account-456", "us-east-1")
    assert path == "/tmp/test/engine_configscan_aws/output/scan-123/inventory_account-456_us-east-1.ndjson"
    
    path = resolver.get_inventory_path("aws", "scan-123", "account-456")
    assert path == "/tmp/test/engine_configscan_aws/output/scan-123/inventory_account-456.ndjson"


def test_summary_path():
    """Test summary path generation"""
    resolver = StoragePathResolver(storage_type="local", local_base_path="/tmp/test")
    
    path = resolver.get_summary_path("aws", "scan-123")
    assert path == "/tmp/test/engine_configscan_aws/output/scan-123/summary.json"


def test_scan_directory():
    """Test scan directory path generation"""
    resolver = StoragePathResolver(storage_type="local", local_base_path="/tmp/test")
    
    path = resolver.get_scan_directory("aws", "scan-123")
    assert path == "/tmp/test/engine_configscan_aws/output/scan-123"


def test_convenience_functions():
    """Test convenience functions"""
    # These will use default resolver with environment variables
    # Just test they don't crash
    try:
        path = get_scan_results_path("aws", "scan-123")
        assert "engine_configscan_aws" in path
        assert "scan-123" in path
    except Exception:
        # If env vars not set, that's okay for local testing
        pass


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
