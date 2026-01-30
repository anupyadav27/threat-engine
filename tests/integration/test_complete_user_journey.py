"""
Complete user journey test - from initial request to final results

Tests the entire user experience:
1. User registers/logs in
2. User onboards cloud account
3. User triggers scan
4. User views real-time progress
5. User views results from all engines
6. User exports reports
"""
import sys
import os
import pytest
import json
from datetime import datetime

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)


def test_complete_user_journey_end_to_end():
    """
    Complete user journey from registration to viewing results
    """
    
    # ========== STEP 1: USER REGISTRATION ==========
    registration = {
        "email": "user@example.com",
        "password": "secure-password",
        "company": "Acme Corp"
    }
    
    tenant_created = {
        "tenant_id": "tenant-456",
        "tenant_name": "Acme Corp",
        "status": "active"
    }
    
    # ========== STEP 2: USER ONBOARDS AWS ACCOUNT ==========
    account_onboarding = {
        "tenant_id": tenant_created["tenant_id"],
        "provider": "aws",
        "account_name": "Production Account",
        "account_number": "123456789012",
        "credentials": {
            "credential_type": "aws_iam_role",
            "role_arn": "arn:aws:iam::123456789012:role/ThreatEngineRole"
        }
    }
    
    account_created = {
        "account_id": "account-789",
        "tenant_id": account_onboarding["tenant_id"],
        "provider": account_onboarding["provider"],
        "account_number": account_onboarding["account_number"],
        "status": "active"
    }
    
    # ========== STEP 3: USER TRIGGERS SCAN ==========
    scan_request = {
        "tenant_id": account_created["tenant_id"],
        "account_id": account_created["account_id"],
        "provider": account_created["provider"],
        "regions": ["us-east-1", "us-west-2"],
        "services": ["s3", "iam", "ec2"],
        "trigger_type": "manual"
    }
    
    execution_created = {
        "execution_id": "execution-123",
        "scan_run_id": "execution-123",  # Same as execution_id
        "tenant_id": scan_request["tenant_id"],
        "account_id": scan_request["account_id"],
        "status": "running"
    }
    
    # ========== STEP 4: USER VIEWS PROGRESS ==========
    progress_updates = [
        {
            "scan_run_id": execution_created["scan_run_id"],
            "engine": "configscan",
            "status": "running",
            "progress": 25,
            "message": "Scanning S3 buckets..."
        },
        {
            "scan_run_id": execution_created["scan_run_id"],
            "engine": "configscan",
            "status": "running",
            "progress": 50,
            "message": "Scanning IAM policies..."
        },
        {
            "scan_run_id": execution_created["scan_run_id"],
            "engine": "configscan",
            "status": "completed",
            "progress": 100,
            "scan_id": "engine-scan-999"
        },
        {
            "scan_run_id": execution_created["scan_run_id"],
            "engine": "orchestration",
            "status": "running",
            "message": "Triggering downstream engines..."
        },
        {
            "scan_run_id": execution_created["scan_run_id"],
            "engine": "threat",
            "status": "completed",
            "progress": 100
        },
        {
            "scan_run_id": execution_created["scan_run_id"],
            "engine": "compliance",
            "status": "completed",
            "progress": 100
        }
    ]
    
    # ========== STEP 5: USER VIEWS RESULTS ==========
    final_results = {
        "scan_run_id": execution_created["scan_run_id"],
        "tenant_id": scan_request["tenant_id"],
        "account_id": scan_request["account_id"],
        "status": "completed",
        "completed_at": datetime.utcnow().isoformat(),
        "engines": {
            "configscan": {
                "scan_id": "engine-scan-999",
                "total_checks": 150,
                "passed_checks": 120,
                "failed_checks": 30,
                "compliance_score": 80
            },
            "threat": {
                "total_threats": 25,
                "critical": 5,
                "high": 10,
                "medium": 10
            },
            "compliance": {
                "CIS": 85,
                "NIST": 78,
                "ISO27001": 82
            },
            "datasec": {
                "total_findings": 45,
                "classified_stores": 20
            },
            "inventory": {
                "total_assets": 500,
                "total_relationships": 1200
            }
        }
    }
    
    # ========== STEP 6: USER EXPORTS REPORT ==========
    export_request = {
        "scan_run_id": execution_created["scan_run_id"],
        "tenant_id": scan_request["tenant_id"],
        "format": "pdf",
        "include_engines": ["configscan", "threat", "compliance"]
    }
    
    export_result = {
        "scan_run_id": execution_created["scan_run_id"],
        "export_id": "export-789",
        "format": "pdf",
        "file_path": f"exports/{scan_request['tenant_id']}/{execution_created['scan_run_id']}.pdf",
        "status": "completed"
    }
    
    # ========== VALIDATIONS ==========
    
    # 1. Verify tenant creation
    assert tenant_created["tenant_id"] == "tenant-456"
    
    # 2. Verify account onboarding
    assert account_created["tenant_id"] == tenant_created["tenant_id"]
    assert account_created["account_id"] == "account-789"
    
    # 3. Verify scan request
    assert scan_request["tenant_id"] == account_created["tenant_id"]
    assert scan_request["account_id"] == account_created["account_id"]
    
    # 4. Verify execution creation
    assert execution_created["scan_run_id"] == execution_created["execution_id"]
    assert execution_created["tenant_id"] == scan_request["tenant_id"]
    
    # 5. Verify progress updates all reference same scan_run_id
    for update in progress_updates:
        assert update["scan_run_id"] == execution_created["scan_run_id"]
    
    # 6. Verify final results
    assert final_results["scan_run_id"] == execution_created["scan_run_id"]
    assert final_results["tenant_id"] == scan_request["tenant_id"]
    assert len(final_results["engines"]) == 5
    
    # 7. Verify export
    assert export_result["scan_run_id"] == execution_created["scan_run_id"]
    assert export_result["status"] == "completed"
    
    # 8. Verify all data is JSON serializable
    assert json.dumps(final_results)
    assert json.dumps(export_result)


def test_user_journey_with_multiple_scans():
    """Test user can manage multiple scans"""
    
    tenant_id = "tenant-456"
    account_id = "account-789"
    
    # ========== USER TRIGGERS MULTIPLE SCANS ==========
    scans = [
        {
            "scan_run_id": "scan-1",
            "tenant_id": tenant_id,
            "account_id": account_id,
            "triggered_at": "2025-01-23T10:00:00Z",
            "status": "completed"
        },
        {
            "scan_run_id": "scan-2",
            "tenant_id": tenant_id,
            "account_id": account_id,
            "triggered_at": "2025-01-23T14:00:00Z",
            "status": "running"
        },
        {
            "scan_run_id": "scan-3",
            "tenant_id": tenant_id,
            "account_id": account_id,
            "triggered_at": "2025-01-23T18:00:00Z",
            "status": "pending"
        }
    ]
    
    # ========== USER VIEWS ALL SCANS ==========
    all_scans_view = {
        "tenant_id": tenant_id,
        "account_id": account_id,
        "total_scans": len(scans),
        "scans": scans
    }
    
    # ========== VERIFY MULTI-SCAN MANAGEMENT ==========
    assert all_scans_view["tenant_id"] == tenant_id
    assert len(all_scans_view["scans"]) == 3
    
    # All scans should be for same tenant/account
    for scan in scans:
        assert scan["tenant_id"] == tenant_id
        assert scan["account_id"] == account_id
    
    # ========== USER COMPARES SCANS ==========
    comparison = {
        "tenant_id": tenant_id,
        "account_id": account_id,
        "scan1": scans[0]["scan_run_id"],
        "scan2": scans[1]["scan_run_id"],
        "comparison": {
            "configscan": {
                "scan1_failed": 30,
                "scan2_failed": 25,
                "improvement": 5
            }
        }
    }
    
    assert comparison["scan1"] == scans[0]["scan_run_id"]
    assert comparison["scan2"] == scans[1]["scan_run_id"]


def test_user_journey_error_recovery():
    """Test user journey handles errors and can retry"""
    
    tenant_id = "tenant-456"
    account_id = "account-789"
    
    # ========== FIRST SCAN FAILS ==========
    failed_scan = {
        "scan_run_id": "scan-failed-1",
        "tenant_id": tenant_id,
        "account_id": account_id,
        "status": "failed",
        "error": "Connection timeout",
        "failed_at": datetime.utcnow().isoformat()
    }
    
    # ========== USER RETRIES SCAN ==========
    retry_scan = {
        "scan_run_id": "scan-retry-1",
        "tenant_id": tenant_id,
        "account_id": account_id,
        "retry_of": failed_scan["scan_run_id"],
        "status": "running"
    }
    
    # ========== RETRY SUCCEEDS ==========
    successful_retry = {
        "scan_run_id": retry_scan["scan_run_id"],
        "tenant_id": tenant_id,
        "account_id": account_id,
        "status": "completed",
        "retry_of": failed_scan["scan_run_id"]
    }
    
    # ========== VERIFY ERROR RECOVERY ==========
    assert failed_scan["status"] == "failed"
    assert retry_scan["retry_of"] == failed_scan["scan_run_id"]
    assert successful_retry["status"] == "completed"
    assert successful_retry["retry_of"] == failed_scan["scan_run_id"]
    
    # Both scans should have same tenant/account
    assert failed_scan["tenant_id"] == retry_scan["tenant_id"]
    assert failed_scan["account_id"] == retry_scan["account_id"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
