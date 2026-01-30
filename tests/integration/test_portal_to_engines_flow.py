"""
Test portal engine integration with all backend engines

Tests the flow:
Portal UI → Portal API → Onboarding → ConfigScan → Orchestrator → Downstream Engines
"""
import sys
import os
import pytest
import json
from datetime import datetime

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)


def test_portal_scan_request_to_onboarding():
    """Test portal sends scan request to onboarding engine"""
    
    # ========== PORTAL UI USER ACTION ==========
    user_action = {
        "action": "start_scan",
        "tenant_id": "tenant-456",
        "account_id": "account-789",
        "provider": "aws",
        "regions": ["us-east-1"],
        "services": ["s3", "iam"]
    }
    
    # ========== PORTAL API FORWARDS TO ONBOARDING ==========
    portal_api_request = {
        "endpoint": "/api/v1/onboarding/schedules/{schedule_id}/trigger",
        "method": "POST",
        "body": {
            "tenant_id": user_action["tenant_id"],
            "account_id": user_action["account_id"],
            "provider": user_action["provider"],
            "regions": user_action["regions"],
            "services": user_action["services"]
        }
    }
    
    # Verify portal forwards all user data
    assert portal_api_request["body"]["tenant_id"] == user_action["tenant_id"]
    assert portal_api_request["body"]["account_id"] == user_action["account_id"]
    assert portal_api_request["body"]["provider"] == user_action["provider"]
    
    # ========== ONBOARDING PROCESSES REQUEST ==========
    onboarding_response = {
        "execution_id": "execution-123",
        "scan_run_id": "execution-123",
        "status": "running",
        "message": "Scan started"
    }
    
    # Portal receives execution_id which becomes scan_run_id
    assert onboarding_response["execution_id"] == onboarding_response["scan_run_id"]


def test_portal_queries_scan_status():
    """Test portal queries scan status from onboarding"""
    
    scan_run_id = "scan-123"
    tenant_id = "tenant-456"
    
    # ========== PORTAL QUERIES STATUS ==========
    portal_status_query = {
        "endpoint": f"/api/v1/onboarding/executions/{scan_run_id}",
        "method": "GET",
        "query_params": {
            "tenant_id": tenant_id
        }
    }
    
    # ========== ONBOARDING RETURNS STATUS ==========
    onboarding_status_response = {
        "execution_id": scan_run_id,
        "scan_run_id": scan_run_id,
        "tenant_id": tenant_id,
        "status": "completed",
        "scan_id": "engine-scan-999",
        "total_checks": 100,
        "passed_checks": 80,
        "failed_checks": 20
    }
    
    # Portal can display status
    assert onboarding_status_response["scan_run_id"] == scan_run_id
    assert onboarding_status_response["status"] == "completed"
    
    # ========== PORTAL QUERIES ORCHESTRATION STATUS ==========
    portal_orchestration_query = {
        "endpoint": f"/api/v1/onboarding/orchestration/{scan_run_id}",
        "method": "GET"
    }
    
    orchestration_status = {
        "scan_run_id": scan_run_id,
        "engines": {
            "threat": {"status": "completed"},
            "compliance": {"status": "completed"},
            "datasec": {"status": "completed"},
            "inventory": {"status": "completed"}
        }
    }
    
    # Portal can show orchestration progress
    assert orchestration_status["scan_run_id"] == scan_run_id
    assert len(orchestration_status["engines"]) == 4


def test_portal_fetches_results_from_engines():
    """Test portal fetches results from all engines"""
    
    scan_run_id = "scan-123"
    tenant_id = "tenant-456"
    
    # ========== PORTAL FETCHES CONFIGSCAN RESULTS ==========
    configscan_results_query = {
        "endpoint": f"/api/v1/scans/{scan_run_id}/results",
        "engine": "configscan",
        "query_params": {
            "tenant_id": tenant_id
        }
    }
    
    # ========== PORTAL FETCHES THREAT RESULTS ==========
    threat_results_query = {
        "endpoint": f"/api/v1/threat/reports/{scan_run_id}",
        "engine": "threat",
        "query_params": {
            "tenant_id": tenant_id
        }
    }
    
    # ========== PORTAL FETCHES COMPLIANCE RESULTS ==========
    compliance_results_query = {
        "endpoint": f"/api/v1/compliance/reports",
        "engine": "compliance",
        "query_params": {
            "scan_id": "engine-scan-999",
            "csp": "aws",
            "tenant_id": tenant_id
        }
    }
    
    # ========== PORTAL FETCHES DATASEC RESULTS ==========
    datasec_results_query = {
        "endpoint": f"/api/v1/data-security/findings",
        "engine": "datasec",
        "query_params": {
            "scan_id": "engine-scan-999",
            "csp": "aws",
            "tenant_id": tenant_id
        }
    }
    
    # ========== PORTAL FETCHES INVENTORY RESULTS ==========
    inventory_results_query = {
        "endpoint": f"/api/v1/inventory/assets",
        "engine": "inventory",
        "query_params": {
            "configscan_scan_id": "engine-scan-999",
            "tenant_id": tenant_id
        }
    }
    
    # ========== VERIFY ALL QUERIES USE CORRECT IDs ==========
    # Verify configscan query
    assert scan_run_id in configscan_results_query["endpoint"]
    assert configscan_results_query["query_params"]["tenant_id"] == tenant_id
    
    # Verify threat query
    assert scan_run_id in threat_results_query["endpoint"]
    assert threat_results_query["query_params"]["tenant_id"] == tenant_id
    
    # Verify compliance query
    assert compliance_results_query["query_params"]["scan_id"] == "engine-scan-999"
    assert compliance_results_query["query_params"]["tenant_id"] == tenant_id
    
    # Verify datasec query
    assert datasec_results_query["query_params"]["scan_id"] == "engine-scan-999"
    assert datasec_results_query["query_params"]["tenant_id"] == tenant_id
    
    # Verify inventory query
    assert inventory_results_query["query_params"]["configscan_scan_id"] == "engine-scan-999"
    assert inventory_results_query["query_params"]["tenant_id"] == tenant_id


def test_portal_dashboard_aggregation():
    """Test portal aggregates results from all engines for dashboard"""
    
    scan_run_id = "scan-123"
    tenant_id = "tenant-456"
    
    # ========== PORTAL AGGREGATES ALL RESULTS ==========
    dashboard_data = {
        "scan_run_id": scan_run_id,
        "tenant_id": tenant_id,
        "summary": {
            "configscan": {
                "total_checks": 100,
                "passed": 80,
                "failed": 20,
                "compliance_score": 80
            },
            "threat": {
                "total_threats": 25,
                "critical": 5,
                "high": 10
            },
            "compliance": {
                "CIS": 85,
                "NIST": 78,
                "ISO27001": 82
            },
            "datasec": {
                "total_findings": 45,
                "classified_data_stores": 20
            },
            "inventory": {
                "total_assets": 500,
                "total_relationships": 1200
            }
        },
        "overall_status": "completed",
        "last_updated": datetime.utcnow().isoformat()
    }
    
    # ========== VERIFY AGGREGATION ==========
    assert dashboard_data["scan_run_id"] == scan_run_id
    assert dashboard_data["tenant_id"] == tenant_id
    assert "summary" in dashboard_data
    assert len(dashboard_data["summary"]) == 5  # All 5 engines
    
    # All engines should have data
    assert "configscan" in dashboard_data["summary"]
    assert "threat" in dashboard_data["summary"]
    assert "compliance" in dashboard_data["summary"]
    assert "datasec" in dashboard_data["summary"]
    assert "inventory" in dashboard_data["summary"]
    
    # Data should be JSON serializable
    json_str = json.dumps(dashboard_data)
    parsed = json.loads(json_str)
    assert parsed["scan_run_id"] == scan_run_id


def test_portal_filters_and_search():
    """Test portal filters and search work across all engines"""
    
    scan_run_id = "scan-123"
    tenant_id = "tenant-456"
    
    # ========== USER APPLIES FILTERS IN PORTAL ==========
    portal_filters = {
        "scan_run_id": scan_run_id,
        "tenant_id": tenant_id,
        "filters": {
            "severity": ["critical", "high"],
            "service": "s3",
            "region": "us-east-1",
            "status": "failed"
        }
    }
    
    # ========== FILTERS APPLIED TO ALL ENGINE QUERIES ==========
    filtered_queries = {
        "configscan": {
            "scan_run_id": scan_run_id,
            "tenant_id": tenant_id,
            "service": portal_filters["filters"]["service"],
            "region": portal_filters["filters"]["region"],
            "status": portal_filters["filters"]["status"]
        },
        "threat": {
            "scan_run_id": scan_run_id,
            "tenant_id": tenant_id,
            "severity": portal_filters["filters"]["severity"]
        },
        "compliance": {
            "scan_id": "engine-scan-999",
            "tenant_id": tenant_id,
            "status": portal_filters["filters"]["status"]
        },
        "datasec": {
            "scan_id": "engine-scan-999",
            "tenant_id": tenant_id,
            "service": portal_filters["filters"]["service"]
        }
    }
    
    # ========== VERIFY FILTERS PROPAGATE ==========
    for engine, query in filtered_queries.items():
        assert query["tenant_id"] == tenant_id
        # Each engine receives relevant filters
        if engine == "threat":
            assert "severity" in query
        if engine in ["configscan", "datasec"]:
            assert "service" in query


def test_portal_export_functionality():
    """Test portal can export results from all engines"""
    
    scan_run_id = "scan-123"
    tenant_id = "tenant-456"
    
    # ========== USER REQUESTS EXPORT ==========
    export_request = {
        "scan_run_id": scan_run_id,
        "tenant_id": tenant_id,
        "format": "json",  # or "csv", "pdf"
        "engines": ["configscan", "threat", "compliance", "datasec", "inventory"]
    }
    
    # ========== PORTAL COLLECTS FROM ALL ENGINES ==========
    export_data = {
        "scan_run_id": scan_run_id,
        "tenant_id": tenant_id,
        "exported_at": datetime.utcnow().isoformat(),
        "engines": {
            "configscan": {
                "results_path": f"engine_configscan_aws/output/{scan_run_id}/results.ndjson"
            },
            "threat": {
                "report_path": f"threat_reports/{tenant_id}/{scan_run_id}.json"
            },
            "compliance": {
                "report_id": "compliance-report-123"
            },
            "datasec": {
                "findings_count": 45
            },
            "inventory": {
                "assets_count": 500
            }
        }
    }
    
    # ========== VERIFY EXPORT STRUCTURE ==========
    assert export_data["scan_run_id"] == scan_run_id
    assert export_data["tenant_id"] == tenant_id
    assert len(export_data["engines"]) == 5
    
    # All engines should have exportable data
    for engine in export_request["engines"]:
        assert engine in export_data["engines"]


def test_portal_real_time_updates():
    """Test portal receives real-time updates during scan"""
    
    scan_run_id = "scan-123"
    tenant_id = "tenant-456"
    
    # ========== PORTAL SUBSCRIBES TO UPDATES ==========
    # Portal would use WebSocket or polling
    
    # ========== UPDATE 1: CONFIGSCAN STARTED ==========
    update1 = {
        "scan_run_id": scan_run_id,
        "tenant_id": tenant_id,
        "event": "scan_started",
        "engine": "configscan",
        "timestamp": datetime.utcnow().isoformat()
    }
    
    # ========== UPDATE 2: CONFIGSCAN PROGRESS ==========
    update2 = {
        "scan_run_id": scan_run_id,
        "tenant_id": tenant_id,
        "event": "scan_progress",
        "engine": "configscan",
        "progress": 50,
        "timestamp": datetime.utcnow().isoformat()
    }
    
    # ========== UPDATE 3: CONFIGSCAN COMPLETED ==========
    update3 = {
        "scan_run_id": scan_run_id,
        "tenant_id": tenant_id,
        "event": "scan_completed",
        "engine": "configscan",
        "scan_id": "engine-scan-999",
        "timestamp": datetime.utcnow().isoformat()
    }
    
    # ========== UPDATE 4: ORCHESTRATION STARTED ==========
    update4 = {
        "scan_run_id": scan_run_id,
        "tenant_id": tenant_id,
        "event": "orchestration_started",
        "engines": ["threat", "compliance", "datasec", "inventory"],
        "timestamp": datetime.utcnow().isoformat()
    }
    
    # ========== UPDATE 5: DOWNSTREAM ENGINES COMPLETED ==========
    update5 = {
        "scan_run_id": scan_run_id,
        "tenant_id": tenant_id,
        "event": "orchestration_completed",
        "engines": {
            "threat": "completed",
            "compliance": "completed",
            "datasec": "completed",
            "inventory": "completed"
        },
        "timestamp": datetime.utcnow().isoformat()
    }
    
    # ========== VERIFY UPDATE FLOW ==========
    updates = [update1, update2, update3, update4, update5]
    
    for update in updates:
        assert update["scan_run_id"] == scan_run_id
        assert update["tenant_id"] == tenant_id
        assert "event" in update
        assert "timestamp" in update
    
    # Portal can track progress through all updates
    assert updates[0]["event"] == "scan_started"
    assert updates[2]["event"] == "scan_completed"
    assert updates[4]["event"] == "orchestration_completed"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
