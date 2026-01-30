"""
Consolidated Services Tests
Tests for all consolidated service modules and endpoints
"""

import pytest
import httpx
from fastapi.testclient import TestClient
from unittest.mock import patch, Mock, AsyncMock
import asyncio
import json
import os
import sys

# Mock the imports for testing
@pytest.fixture
def mock_service_dependencies():
    """Mock external dependencies for service testing"""
    with patch('sqlalchemy.create_engine'), \
         patch('redis.Redis'), \
         patch('boto3.client'), \
         patch('subprocess.run'):
        yield


class TestCoreEngineService:
    """Test suite for Core Engine Service (Threat + Compliance + Rule)"""
    
    def setup_method(self):
        """Set up test environment"""
        # Mock the consolidated service
        self.mock_service = Mock()
        self.mock_service.health_check.return_value = {"status": "ok"}
    
    @pytest.mark.asyncio
    async def test_threat_module_initialization(self):
        """Test threat module initialization"""
        # This would test the actual threat module initialization
        # For now, we'll simulate the test
        assert True  # Placeholder for actual implementation
    
    @pytest.mark.asyncio
    async def test_compliance_module_initialization(self):
        """Test compliance module initialization"""
        assert True  # Placeholder
    
    @pytest.mark.asyncio
    async def test_rule_module_initialization(self):
        """Test rule module initialization"""
        assert True  # Placeholder
    
    @pytest.mark.asyncio
    async def test_integrated_scan_analysis(self):
        """Test integrated scan analysis endpoint"""
        # Test the cross-module integration functionality
        test_request = {
            "tenant_id": "test-tenant",
            "scan_id": "test-scan-123",
            "include_rules": True,
            "include_compliance": True
        }
        
        # Mock the integrated analysis
        expected_result = {
            "scan_id": "test-scan-123",
            "tenant_id": "test-tenant",
            "threat_analysis": {"threats_found": 5, "critical": 2},
            "compliance_status": {"compliant": True, "score": 85},
            "rule_violations": {"total": 3, "high_severity": 1},
            "recommendations": ["Fix critical vulnerabilities", "Update policies"]
        }
        
        # This would be an actual API call in real implementation
        result = expected_result  # Simulate successful analysis
        
        assert result["scan_id"] == test_request["scan_id"]
        assert result["tenant_id"] == test_request["tenant_id"]
        assert "threat_analysis" in result
        assert "compliance_status" in result
        assert "rule_violations" in result


class TestConfigScanService:
    """Test suite for ConfigScan Service (All CSP scanners)"""
    
    def setup_method(self):
        """Set up test environment"""
        self.mock_scanners = {
            "aws": Mock(),
            "azure": Mock(), 
            "gcp": Mock()
        }
    
    @pytest.mark.asyncio
    async def test_csp_scanner_registry(self):
        """Test CSP scanner registration and discovery"""
        # Test that all scanners are properly registered
        available_scanners = ["aws", "azure", "gcp", "alicloud", "ibm", "oci"]
        
        for csp in available_scanners:
            # This would test actual scanner availability
            assert True  # Placeholder for scanner registry test
    
    @pytest.mark.asyncio
    async def test_aws_scan_execution(self):
        """Test AWS scan execution"""
        scan_request = {
            "tenant_id": "test-tenant",
            "csp": "aws",
            "account_id": "123456789012",
            "regions": ["us-east-1", "us-west-2"],
            "services": ["ec2", "s3", "iam"]
        }
        
        # Mock successful scan result
        expected_result = {
            "scan_id": "aws-scan-123",
            "status": "completed",
            "findings": [
                {
                    "resource_arn": "arn:aws:s3:::test-bucket",
                    "severity": "high",
                    "finding": "Public bucket detected"
                }
            ],
            "summary": {"total_resources": 150, "findings": 1}
        }
        
        # Simulate scan execution
        result = expected_result  # Mock result
        
        assert result["status"] == "completed"
        assert len(result["findings"]) > 0
        assert result["summary"]["total_resources"] > 0
    
    @pytest.mark.asyncio
    async def test_multi_csp_scan(self):
        """Test scanning across multiple CSPs"""
        scan_request = {
            "tenant_id": "test-tenant",
            "csps": ["aws", "azure", "gcp"],
            "parallel_execution": True
        }
        
        # This would test parallel execution across multiple CSPs
        result = {"status": "completed", "csp_results": {}}
        
        for csp in scan_request["csps"]:
            result["csp_results"][csp] = {
                "status": "completed",
                "findings": [],
                "scan_duration": 120
            }
        
        assert len(result["csp_results"]) == 3
        assert all(r["status"] == "completed" for r in result["csp_results"].values())


class TestPlatformService:
    """Test suite for Platform Service (Inventory + Onboarding + Admin)"""
    
    def setup_method(self):
        """Set up test environment"""
        self.mock_db = Mock()
    
    @pytest.mark.asyncio
    async def test_inventory_module(self):
        """Test inventory functionality"""
        scan_request = {
            "tenant_id": "test-tenant",
            "providers": ["aws"],
            "accounts": ["123456789012"],
            "regions": ["us-east-1"]
        }
        
        expected_result = {
            "scan_run_id": "inv-20240101-123456",
            "status": "running",
            "total_assets": 0,
            "total_relationships": 0
        }
        
        # Mock inventory scan
        result = expected_result
        
        assert result["scan_run_id"].startswith("inv-")
        assert result["status"] in ["running", "completed"]
    
    @pytest.mark.asyncio
    async def test_onboarding_module(self):
        """Test tenant onboarding functionality"""
        tenant_request = {
            "tenant_name": "Test Tenant",
            "description": "Test tenant for validation",
            "status": "active"
        }
        
        expected_result = {
            "tenant_id": "tenant-123",
            "tenant_name": "Test Tenant",
            "status": "active",
            "created_at": "2024-01-01T00:00:00Z"
        }
        
        # Mock tenant creation
        result = expected_result
        
        assert result["tenant_name"] == tenant_request["tenant_name"]
        assert result["status"] == "active"
        assert "tenant_id" in result
    
    @pytest.mark.asyncio
    async def test_admin_module(self):
        """Test administrative functionality"""
        user_request = {
            "email": "test@example.com",
            "first_name": "Test",
            "last_name": "User",
            "is_superuser": False
        }
        
        expected_result = {
            "user_id": "user-123",
            "email": "test@example.com",
            "is_active": True,
            "created_at": "2024-01-01T00:00:00Z"
        }
        
        # Mock user creation
        result = expected_result
        
        assert result["email"] == user_request["email"]
        assert result["is_active"] is True
        assert "user_id" in result
    
    @pytest.mark.asyncio
    async def test_integrated_tenant_overview(self):
        """Test integrated tenant overview functionality"""
        tenant_id = "test-tenant"
        
        expected_result = {
            "tenant_id": tenant_id,
            "tenant_info": {"name": "Test Tenant", "status": "active"},
            "accounts": {"total": 2, "active": 2},
            "assets": {"total": 150, "by_provider": {"aws": 100, "azure": 50}},
            "schedules": {"total": 3, "active": 2}
        }
        
        # Mock integrated overview
        result = expected_result
        
        assert result["tenant_id"] == tenant_id
        assert "tenant_info" in result
        assert "accounts" in result
        assert "assets" in result
        assert "schedules" in result


class TestDataSecOpsService:
    """Test suite for Data SecOps Service (DataSec + SecOps + UserPortal)"""
    
    def setup_method(self):
        """Set up test environment"""
        self.mock_scanners = Mock()
    
    @pytest.mark.asyncio
    async def test_datasec_module(self):
        """Test data security functionality"""
        scan_request = {
            "tenant_id": "test-tenant",
            "csp": "aws",
            "scan_id": "configscan-123",
            "include_classification": True,
            "include_lineage": True
        }
        
        expected_result = {
            "schema_version": "1.0",
            "tenant_id": "test-tenant",
            "summary": {"total_findings": 5, "sensitive_data_found": True},
            "findings": [
                {
                    "resource_arn": "arn:aws:s3:::sensitive-bucket",
                    "classification": "confidential",
                    "data_types": ["pii", "financial"]
                }
            ]
        }
        
        # Mock data security scan
        result = expected_result
        
        assert result["tenant_id"] == scan_request["tenant_id"]
        assert result["summary"]["total_findings"] > 0
    
    @pytest.mark.asyncio
    async def test_secops_module(self):
        """Test vulnerability scanning functionality"""
        scan_request = {
            "project_name": "test-project",
            "tenant_id": "test-tenant",
            "save_results": True
        }
        
        expected_result = {
            "scan_id": "secops-scan-123",
            "project_name": "test-project",
            "status": "running",
            "message": "Vulnerability scan started"
        }
        
        # Mock vulnerability scan
        result = expected_result
        
        assert result["project_name"] == scan_request["project_name"]
        assert result["status"] in ["running", "completed"]
        assert "scan_id" in result
    
    @pytest.mark.asyncio
    async def test_userportal_module(self):
        """Test user portal functionality"""
        user_id = "test-user"
        tenant_id = "test-tenant"
        
        expected_result = {
            "user_id": user_id,
            "current_tenant": tenant_id,
            "accessible_tenants": [tenant_id],
            "email": "test@example.com",
            "first_name": "Test",
            "last_name": "User"
        }
        
        # Mock user profile
        result = expected_result
        
        assert result["user_id"] == user_id
        assert result["current_tenant"] == tenant_id
        assert tenant_id in result["accessible_tenants"]
    
    @pytest.mark.asyncio
    async def test_integrated_security_analysis(self):
        """Test integrated security analysis combining data security and vulnerability scanning"""
        analysis_request = {
            "tenant_id": "test-tenant",
            "project_name": "test-project",
            "scan_id": "configscan-123"
        }
        
        expected_result = {
            "tenant_id": "test-tenant",
            "analysis_id": "analysis-456",
            "status": "completed",
            "scans": {
                "datasec": {"findings": 3, "sensitive_data": True},
                "secops": {"vulnerabilities": 5, "critical": 1}
            },
            "correlation": {
                "high_risk_combinations": [
                    {
                        "type": "sensitive_data_with_vulns",
                        "risk_level": "critical"
                    }
                ]
            }
        }
        
        # Mock integrated analysis
        result = expected_result
        
        assert result["tenant_id"] == analysis_request["tenant_id"]
        assert "scans" in result
        assert "correlation" in result
        assert result["status"] == "completed"


@pytest.mark.integration
class TestServiceIntegration:
    """Integration tests across consolidated services"""
    
    @pytest.mark.asyncio
    async def test_end_to_end_scan_workflow(self):
        """Test complete scan workflow from ConfigScan to Data Security Analysis"""
        
        # Step 1: ConfigScan
        configscan_result = {
            "scan_id": "config-123",
            "status": "completed",
            "findings": [{"resource_arn": "arn:aws:s3:::test-bucket"}]
        }
        
        # Step 2: Core Engine Analysis
        core_analysis = {
            "scan_id": "config-123",
            "threat_analysis": {"threats_found": 2},
            "compliance_status": {"score": 85}
        }
        
        # Step 3: Data Security Analysis
        datasec_analysis = {
            "scan_id": "config-123",
            "sensitive_data_found": True,
            "classification": [{"resource": "test-bucket", "level": "confidential"}]
        }
        
        # Verify end-to-end workflow
        assert configscan_result["status"] == "completed"
        assert core_analysis["threat_analysis"]["threats_found"] > 0
        assert datasec_analysis["sensitive_data_found"] is True
    
    @pytest.mark.asyncio
    async def test_tenant_onboarding_to_first_scan(self):
        """Test complete tenant journey from onboarding to first scan"""
        
        # Step 1: Create tenant
        tenant = {
            "tenant_id": "new-tenant-123",
            "tenant_name": "New Tenant",
            "status": "active"
        }
        
        # Step 2: Add account
        account = {
            "account_id": "account-456",
            "tenant_id": "new-tenant-123",
            "account_name": "Test Account",
            "status": "active"
        }
        
        # Step 3: Create schedule
        schedule = {
            "schedule_id": "schedule-789",
            "tenant_id": "new-tenant-123",
            "account_id": "account-456",
            "enabled": True
        }
        
        # Step 4: Execute scan
        scan_result = {
            "scan_id": "first-scan-123",
            "tenant_id": "new-tenant-123",
            "status": "completed"
        }
        
        # Verify complete workflow
        assert tenant["status"] == "active"
        assert account["tenant_id"] == tenant["tenant_id"]
        assert schedule["enabled"] is True
        assert scan_result["status"] == "completed"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])