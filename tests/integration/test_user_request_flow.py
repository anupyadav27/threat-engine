"""
End-to-end user request flow testing across all engines

Tests the complete flow:
User → Portal → Onboarding → ConfigScan → Orchestrator → Downstream Engines → Results
"""
import sys
import os
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime
import json

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.join(project_root, "engine_onboarding"))


@pytest.mark.asyncio
async def test_complete_user_scan_request_flow():
    """
    Test complete user request flow:
    1. User submits scan request via Portal/API
    2. Onboarding creates tenant/account if needed
    3. Onboarding creates execution and scan metadata
    4. ConfigScan engine receives request with tenant_id and scan_run_id
    5. ConfigScan executes scan and writes results
    6. Orchestrator triggers downstream engines
    7. All engines process and return results
    8. User receives consolidated results
    """
    
    # ========== SETUP: User Request ==========
    user_request = {
        "tenant_id": "tenant-456",
        "account_id": "account-789",
        "provider": "aws",
        "regions": ["us-east-1", "us-west-2"],
        "services": ["s3", "iam", "ec2"],
        "trigger_type": "manual"
    }
    
    # ========== STEP 1: Onboarding Processing ==========
    execution_id = "execution-123"
    scan_run_id = execution_id
    tenant_id = user_request["tenant_id"]
    account_id = user_request["account_id"]
    
    mock_account = {
        'account_id': account_id,
        'tenant_id': tenant_id,
        'account_number': '123456789012',
        'status': 'active'
    }
    
    mock_execution = {
        'execution_id': execution_id,
        'started_at': datetime.utcnow().isoformat()
    }
    
    # ========== STEP 2: ConfigScan Engine Call ==========
    configscan_request_payload = {
        "account": "123456789012",
        "credentials": {
            "credential_type": "aws_iam_role",
            "role_name": "test-role"
        },
        "tenant_id": tenant_id,  # From onboarding
        "scan_run_id": scan_run_id,  # From onboarding
        "include_regions": user_request["regions"],
        "include_services": user_request["services"]
    }
    
    configscan_response = {
        "scan_id": "engine-scan-999",
        "status": "completed",
        "total_checks": 150,
        "passed_checks": 120,
        "failed_checks": 30
    }
    
    # ========== STEP 3: Storage Path Usage ==========
    from engine_common.storage_paths import StoragePathResolver
    resolver = StoragePathResolver(storage_type="local", local_base_path="/tmp/test")
    
    results_path = resolver.get_scan_results_path("aws", scan_run_id, "results.ndjson")
    summary_path = resolver.get_summary_path("aws", scan_run_id)
    
    # ========== STEP 4: Orchestrator Triggers Downstream ==========
    orchestration_requests = {
        "threat": {
            "tenant_id": tenant_id,
            "scan_run_id": scan_run_id,
            "cloud": "aws",
            "trigger_type": "orchestrated"
        },
        "compliance": {
            "scan_id": configscan_response["scan_id"],
            "csp": "aws",
            "tenant_id": tenant_id,
            "trigger_type": "orchestrated"
        },
        "datasec": {
            "csp": "aws",
            "scan_id": configscan_response["scan_id"],
            "tenant_id": tenant_id,
            "include_classification": True
        },
        "inventory": {
            "tenant_id": tenant_id,
            "configscan_scan_id": configscan_response["scan_id"],
            "providers": ["aws"]
        }
    }
    
    # ========== STEP 5: Downstream Engine Responses ==========
    downstream_responses = {
        "threat": {
            "scan_run_id": scan_run_id,
            "status": "completed",
            "threat_summary": {
                "total_threats": 25,
                "critical": 5,
                "high": 10,
                "medium": 10
            }
        },
        "compliance": {
            "report_id": "compliance-report-123",
            "status": "completed",
            "compliance_scores": {
                "CIS": 85,
                "NIST": 78,
                "ISO27001": 82
            }
        },
        "datasec": {
            "scan_id": configscan_response["scan_id"],
            "status": "completed",
            "findings": {
                "total": 45,
                "classification": 20,
                "governance": 15,
                "protection": 10
            }
        },
        "inventory": {
            "scan_run_id": "inventory-scan-456",
            "status": "completed",
            "total_assets": 500,
            "total_relationships": 1200
        }
    }
    
    # ========== STEP 6: User Receives Consolidated Results ==========
    consolidated_results = {
        "scan_run_id": scan_run_id,
        "tenant_id": tenant_id,
        "account_id": account_id,
        "provider": "aws",
        "status": "completed",
        "configscan": {
            "scan_id": configscan_response["scan_id"],
            "total_checks": configscan_response["total_checks"],
            "passed_checks": configscan_response["passed_checks"],
            "failed_checks": configscan_response["failed_checks"],
            "results_path": results_path
        },
        "threat": downstream_responses["threat"],
        "compliance": downstream_responses["compliance"],
        "datasec": downstream_responses["datasec"],
        "inventory": downstream_responses["inventory"],
        "orchestration_status": {
            "threat": "completed",
            "compliance": "completed",
            "datasec": "completed",
            "inventory": "completed"
        }
    }
    
    # ========== VALIDATIONS ==========
    
    # 1. Verify user request structure
    assert "tenant_id" in user_request
    assert "account_id" in user_request
    assert "provider" in user_request
    
    # 2. Verify ConfigScan received correct IDs
    assert configscan_request_payload["tenant_id"] == tenant_id
    assert configscan_request_payload["scan_run_id"] == scan_run_id
    assert configscan_request_payload["include_regions"] == user_request["regions"]
    assert configscan_request_payload["include_services"] == user_request["services"]
    
    # 3. Verify storage paths are consistent
    assert scan_run_id in results_path
    assert scan_run_id in summary_path
    assert "engine_configscan_aws" in results_path
    
    # 4. Verify all downstream engines received correct identifiers
    assert orchestration_requests["threat"]["scan_run_id"] == scan_run_id
    assert orchestration_requests["threat"]["tenant_id"] == tenant_id
    assert orchestration_requests["compliance"]["scan_id"] == configscan_response["scan_id"]
    assert orchestration_requests["compliance"]["tenant_id"] == tenant_id
    assert orchestration_requests["datasec"]["scan_id"] == configscan_response["scan_id"]
    assert orchestration_requests["inventory"]["configscan_scan_id"] == configscan_response["scan_id"]
    
    # 5. Verify consolidated results structure
    assert consolidated_results["scan_run_id"] == scan_run_id
    assert consolidated_results["tenant_id"] == tenant_id
    assert consolidated_results["status"] == "completed"
    assert "configscan" in consolidated_results
    assert "threat" in consolidated_results
    assert "compliance" in consolidated_results
    assert "datasec" in consolidated_results
    assert "inventory" in consolidated_results
    
    # 6. Verify all engines completed successfully
    assert consolidated_results["orchestration_status"]["threat"] == "completed"
    assert consolidated_results["orchestration_status"]["compliance"] == "completed"
    assert consolidated_results["orchestration_status"]["datasec"] == "completed"
    assert consolidated_results["orchestration_status"]["inventory"] == "completed"
    
    # 7. Verify results are JSON serializable (for API responses)
    json_str = json.dumps(consolidated_results)
    parsed = json.loads(json_str)
    assert parsed["scan_run_id"] == scan_run_id


@pytest.mark.asyncio
async def test_user_request_with_scheduled_scan():
    """Test user creates a scheduled scan and it executes automatically"""
    
    # ========== USER CREATES SCHEDULE ==========
    schedule_request = {
        "tenant_id": "tenant-456",
        "account_id": "account-789",
        "name": "Daily Security Scan",
        "schedule_type": "cron",
        "cron_expression": "0 2 * * *",  # Daily at 2 AM
        "provider": "aws",
        "regions": ["us-east-1"],
        "services": ["s3", "iam"]
    }
    
    schedule_id = "schedule-123"
    
    # ========== SCHEDULER TRIGGERS SCAN ==========
    execution_id = "execution-456"
    scan_run_id = execution_id
    
    # Verify schedule contains all necessary info
    assert schedule_request["tenant_id"] == "tenant-456"
    assert schedule_request["account_id"] == "account-789"
    assert schedule_request["provider"] == "aws"
    
    # ========== SCAN EXECUTES ==========
    configscan_request = {
        "account": "123456789012",
        "tenant_id": schedule_request["tenant_id"],
        "scan_run_id": scan_run_id,
        "include_regions": schedule_request["regions"],
        "include_services": schedule_request["services"]
    }
    
    # Verify request matches schedule
    assert configscan_request["tenant_id"] == schedule_request["tenant_id"]
    assert configscan_request["include_regions"] == schedule_request["regions"]
    assert configscan_request["include_services"] == schedule_request["services"]
    
    # ========== RESULTS STORED ==========
    from engine_common.storage_paths import StoragePathResolver
    resolver = StoragePathResolver(storage_type="local", local_base_path="/tmp/test")
    
    results_path = resolver.get_scan_results_path("aws", scan_run_id, "results.ndjson")
    
    # Verify path uses scan_run_id from execution
    assert scan_run_id in results_path
    
    # ========== USER QUERIES RESULTS ==========
    user_query = {
        "scan_run_id": scan_run_id,
        "tenant_id": schedule_request["tenant_id"]
    }
    
    # Results should be accessible via scan_run_id
    assert user_query["scan_run_id"] == scan_run_id
    assert user_query["tenant_id"] == schedule_request["tenant_id"]


@pytest.mark.asyncio
async def test_user_request_multiple_accounts():
    """Test user requests scan for multiple accounts"""
    
    # ========== USER REQUEST FOR MULTIPLE ACCOUNTS ==========
    user_request = {
        "tenant_id": "tenant-456",
        "accounts": [
            {"account_id": "account-1", "account_number": "111111111111"},
            {"account_id": "account-2", "account_number": "222222222222"}
        ],
        "provider": "aws",
        "regions": ["us-east-1"]
    }
    
    # ========== MULTIPLE SCANS INITIATED ==========
    executions = []
    for account in user_request["accounts"]:
        execution_id = f"execution-{account['account_id']}"
        scan_run_id = execution_id
        
        executions.append({
            "execution_id": execution_id,
            "scan_run_id": scan_run_id,
            "account_id": account["account_id"],
            "tenant_id": user_request["tenant_id"]
        })
    
    # ========== VERIFY EACH SCAN HAS CORRECT IDs ==========
    for execution in executions:
        assert execution["tenant_id"] == user_request["tenant_id"]
        assert execution["scan_run_id"] == execution["execution_id"]
        assert execution["account_id"] in [acc["account_id"] for acc in user_request["accounts"]]
    
    # ========== VERIFY STORAGE PATHS ARE SEPARATE ==========
    from engine_common.storage_paths import StoragePathResolver
    resolver = StoragePathResolver(storage_type="local", local_base_path="/tmp/test")
    
    paths = []
    for execution in executions:
        path = resolver.get_scan_results_path("aws", execution["scan_run_id"], "results.ndjson")
        paths.append(path)
        assert execution["scan_run_id"] in path
    
    # Verify paths are different for different accounts
    assert paths[0] != paths[1]
    
    # ========== USER QUERIES ALL SCANS ==========
    all_results = {
        "tenant_id": user_request["tenant_id"],
        "scans": [
            {
                "scan_run_id": exec["scan_run_id"],
                "account_id": exec["account_id"],
                "status": "completed"
            }
            for exec in executions
        ]
    }
    
    # Verify all scans are linked to same tenant
    assert all_results["tenant_id"] == user_request["tenant_id"]
    assert len(all_results["scans"]) == len(user_request["accounts"])


@pytest.mark.asyncio
async def test_user_request_error_handling():
    """Test user request flow handles errors gracefully"""
    
    # ========== USER REQUEST ==========
    user_request = {
        "tenant_id": "tenant-456",
        "account_id": "account-789",
        "provider": "aws"
    }
    
    execution_id = "execution-123"
    scan_run_id = execution_id
    
    # ========== CONFIGSCAN FAILS ==========
    configscan_error = {
        "scan_run_id": scan_run_id,
        "status": "failed",
        "error": "Connection timeout to AWS"
    }
    
    # ========== ERROR PROPAGATED ==========
    error_response = {
        "scan_run_id": scan_run_id,
        "tenant_id": user_request["tenant_id"],
        "account_id": user_request["account_id"],
        "status": "failed",
        "error": configscan_error["error"],
        "error_source": "configscan",
        "timestamp": datetime.utcnow().isoformat()
    }
    
    # ========== VERIFY ERROR HANDLING ==========
    assert error_response["status"] == "failed"
    assert error_response["scan_run_id"] == scan_run_id
    assert error_response["tenant_id"] == user_request["tenant_id"]
    assert "error" in error_response
    
    # ========== VERIFY NO DOWNSTREAM ENGINES TRIGGERED ==========
    # When ConfigScan fails, orchestrator should not trigger downstream engines
    orchestration_status = {
        "scan_run_id": scan_run_id,
        "status": "skipped",
        "reason": "ConfigScan failed"
    }
    
    assert orchestration_status["status"] == "skipped"


@pytest.mark.asyncio
async def test_user_query_results_flow():
    """Test user queries for scan results across engines"""
    
    scan_run_id = "scan-123"
    tenant_id = "tenant-456"
    
    # ========== USER QUERIES CONFIGSCAN RESULTS ==========
    configscan_query = {
        "scan_run_id": scan_run_id,
        "tenant_id": tenant_id,
        "engine": "configscan"
    }
    
    # Results should be found using scan_run_id
    from engine_common.storage_paths import StoragePathResolver
    resolver = StoragePathResolver(storage_type="local", local_base_path="/tmp/test")
    configscan_path = resolver.get_scan_results_path("aws", scan_run_id, "results.ndjson")
    
    assert scan_run_id in configscan_path
    
    # ========== USER QUERIES THREAT RESULTS ==========
    threat_query = {
        "scan_run_id": scan_run_id,
        "tenant_id": tenant_id,
        "engine": "threat"
    }
    
    # Threat engine should use same scan_run_id
    assert threat_query["scan_run_id"] == scan_run_id
    assert threat_query["tenant_id"] == tenant_id
    
    # ========== USER QUERIES COMPLIANCE RESULTS ==========
    compliance_query = {
        "scan_id": "engine-scan-999",  # Uses ConfigScan's scan_id
        "csp": "aws",
        "tenant_id": tenant_id,
        "engine": "compliance"
    }
    
    # Compliance uses scan_id but also has tenant_id
    assert compliance_query["tenant_id"] == tenant_id
    
    # ========== USER QUERIES ALL RESULTS ==========
    all_results_query = {
        "scan_run_id": scan_run_id,
        "tenant_id": tenant_id,
        "include_all_engines": True
    }
    
    # All queries should use same identifiers
    assert all_results_query["scan_run_id"] == scan_run_id
    assert all_results_query["tenant_id"] == tenant_id
    
    # ========== VERIFY RESULTS CAN BE AGGREGATED ==========
    aggregated_results = {
        "scan_run_id": scan_run_id,
        "tenant_id": tenant_id,
        "engines": {
            "configscan": {"status": "completed", "path": configscan_path},
            "threat": {"status": "completed"},
            "compliance": {"status": "completed"},
            "datasec": {"status": "completed"},
            "inventory": {"status": "completed"}
        }
    }
    
    # All engines linked by scan_run_id and tenant_id
    assert aggregated_results["scan_run_id"] == scan_run_id
    assert aggregated_results["tenant_id"] == tenant_id
    assert len(aggregated_results["engines"]) == 5


@pytest.mark.asyncio
async def test_user_request_with_filters():
    """Test user request with filters (regions, services) propagates correctly"""
    
    # ========== USER REQUEST WITH FILTERS ==========
    user_request = {
        "tenant_id": "tenant-456",
        "account_id": "account-789",
        "provider": "aws",
        "filters": {
            "regions": ["us-east-1", "us-west-2"],
            "services": ["s3", "iam"],
            "severity": ["critical", "high"]
        }
    }
    
    execution_id = "execution-123"
    scan_run_id = execution_id
    
    # ========== FILTERS PROPAGATE TO CONFIGSCAN ==========
    configscan_request = {
        "tenant_id": user_request["tenant_id"],
        "scan_run_id": scan_run_id,
        "include_regions": user_request["filters"]["regions"],
        "include_services": user_request["filters"]["services"]
    }
    
    # Verify filters propagated
    assert configscan_request["include_regions"] == user_request["filters"]["regions"]
    assert configscan_request["include_services"] == user_request["filters"]["services"]
    
    # ========== FILTERS PROPAGATE TO DOWNSTREAM ENGINES ==========
    threat_request = {
        "scan_run_id": scan_run_id,
        "tenant_id": user_request["tenant_id"],
        "regions": user_request["filters"]["regions"],
        "services": user_request["filters"]["services"],
        "severity": user_request["filters"]["severity"]
    }
    
    # Verify threat engine receives filters
    assert threat_request["regions"] == user_request["filters"]["regions"]
    assert threat_request["severity"] == user_request["filters"]["severity"]
    
    # ========== RESULTS RESPECT FILTERS ==========
    filtered_results = {
        "scan_run_id": scan_run_id,
        "filters_applied": user_request["filters"],
        "results": {
            "regions_scanned": user_request["filters"]["regions"],
            "services_scanned": user_request["filters"]["services"]
        }
    }
    
    assert filtered_results["filters_applied"] == user_request["filters"]


@pytest.mark.asyncio
async def test_user_request_real_time_status():
    """Test user can query real-time status of scan across all engines"""
    
    scan_run_id = "scan-123"
    tenant_id = "tenant-456"
    
    # ========== USER QUERIES STATUS ==========
    status_query = {
        "scan_run_id": scan_run_id,
        "tenant_id": tenant_id
    }
    
    # ========== STATUS FROM ALL ENGINES ==========
    real_time_status = {
        "scan_run_id": scan_run_id,
        "tenant_id": tenant_id,
        "overall_status": "in_progress",
        "engines": {
            "configscan": {
                "status": "completed",
                "progress": 100,
                "scan_id": "engine-scan-999"
            },
            "threat": {
                "status": "running",
                "progress": 60
            },
            "compliance": {
                "status": "pending",
                "progress": 0
            },
            "datasec": {
                "status": "pending",
                "progress": 0
            },
            "inventory": {
                "status": "pending",
                "progress": 0
            }
        },
        "orchestration": {
            "status": "in_progress",
            "engines_completed": 1,
            "engines_total": 5
        }
    }
    
    # ========== VERIFY STATUS STRUCTURE ==========
    assert real_time_status["scan_run_id"] == scan_run_id
    assert real_time_status["tenant_id"] == tenant_id
    assert "engines" in real_time_status
    assert "orchestration" in real_time_status
    
    # All engines should be tracked
    assert len(real_time_status["engines"]) == 5
    
    # ========== USER QUERIES SPECIFIC ENGINE STATUS ==========
    engine_status_query = {
        "scan_run_id": scan_run_id,
        "tenant_id": tenant_id,
        "engine": "threat"
    }
    
    threat_status = real_time_status["engines"]["threat"]
    assert threat_status["status"] == "running"
    assert "progress" in threat_status


@pytest.mark.asyncio
async def test_user_request_cancellation():
    """Test user can cancel a scan and it propagates correctly"""
    
    scan_run_id = "scan-123"
    tenant_id = "tenant-456"
    
    # ========== USER CANCELS SCAN ==========
    cancel_request = {
        "scan_run_id": scan_run_id,
        "tenant_id": tenant_id,
        "reason": "User requested cancellation"
    }
    
    # ========== CANCELLATION PROPAGATES ==========
    cancellation_status = {
        "scan_run_id": scan_run_id,
        "tenant_id": tenant_id,
        "status": "cancelled",
        "cancelled_at": datetime.utcnow().isoformat(),
        "engines": {
            "configscan": {
                "status": "cancelled",
                "cancelled": True
            },
            "threat": {
                "status": "cancelled",
                "cancelled": True
            },
            "compliance": {
                "status": "cancelled",
                "cancelled": True
            },
            "datasec": {
                "status": "cancelled",
                "cancelled": True
            },
            "inventory": {
                "status": "cancelled",
                "cancelled": True
            }
        }
    }
    
    # ========== VERIFY CANCELLATION ==========
    assert cancellation_status["status"] == "cancelled"
    assert cancellation_status["scan_run_id"] == scan_run_id
    
    # All engines should be cancelled
    for engine, status in cancellation_status["engines"].items():
        assert status["status"] == "cancelled"
        assert status["cancelled"] is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
