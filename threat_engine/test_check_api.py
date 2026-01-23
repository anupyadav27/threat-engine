#!/usr/bin/env python3
"""
Test Check Results API endpoints

Tests the new check results API integrated into threat-engine.
"""

import requests
import json
from urllib.parse import quote

# API base URL
BASE_URL = "http://localhost:8000"
TENANT_ID = "test_tenant"
CUSTOMER_ID = "test_customer"

def test_endpoint(name: str, url: str, expected_keys: list = None):
    """Test a single endpoint"""
    print(f"\n{'='*80}")
    print(f"Testing: {name}")
    print(f"URL: {url}")
    print('='*80)
    
    try:
        response = requests.get(url, timeout=10)
        print(f"Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"Response Keys: {list(data.keys())}")
            
            if expected_keys:
                missing = [k for k in expected_keys if k not in data]
                if missing:
                    print(f"⚠️  Missing keys: {missing}")
                else:
                    print(f"✅ All expected keys present")
            
            # Show sample data (first 300 chars)
            print(f"Sample Data:")
            print(json.dumps(data, indent=2, default=str)[:300] + "...")
            
            return True
        else:
            print(f"❌ Failed: {response.text[:200]}")
            return False
    
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def main():
    """Run all API tests"""
    print("╔══════════════════════════════════════════════════════════════════════════════╗")
    print("║                     CHECK RESULTS API - Test Suite                           ║")
    print("╚══════════════════════════════════════════════════════════════════════════════╝")
    
    # Test 1: Dashboard
    test_endpoint(
        "Dashboard",
        f"{BASE_URL}/api/v1/checks/dashboard?tenant_id={TENANT_ID}",
        expected_keys=['total_checks', 'passed', 'failed', 'pass_rate', 'top_failing_services']
    )
    
    # Test 2: List Scans
    test_endpoint(
        "List Scans",
        f"{BASE_URL}/api/v1/checks/scans?tenant_id={TENANT_ID}&page=1&page_size=5",
        expected_keys=['scans', 'total', 'page', 'page_size', 'total_pages']
    )
    
    # Test 3: Scan Detail (using hardcoded scan ID from recent tests)
    scan_id = "check_20260122_210506"
    test_endpoint(
        "Scan Detail",
        f"{BASE_URL}/api/v1/checks/scans/{scan_id}?tenant_id={TENANT_ID}",
        expected_keys=['scan_id', 'total_checks', 'passed', 'failed', 'services_scanned']
    )
    
    # Test 4: Service Stats
    test_endpoint(
        "Service Stats",
        f"{BASE_URL}/api/v1/checks/scans/{scan_id}/services?tenant_id={TENANT_ID}",
        expected_keys=None  # Returns array
    )
    
    # Test 5: Service Detail
    test_endpoint(
        "Service Detail (S3)",
        f"{BASE_URL}/api/v1/checks/scans/{scan_id}/services/s3?tenant_id={TENANT_ID}",
        expected_keys=['service', 'total_checks', 'passed', 'failed', 'rules']
    )
    
    # Test 6: Scan Findings (paginated)
    test_endpoint(
        "Scan Findings (First Page)",
        f"{BASE_URL}/api/v1/checks/scans/{scan_id}/findings?tenant_id={TENANT_ID}&page=1&page_size=10",
        expected_keys=['findings', 'total', 'page', 'total_pages']
    )
    
    # Test 7: Search by Service
    test_endpoint(
        "Search by Service (s3)",
        f"{BASE_URL}/api/v1/checks/findings/search?query=s3&tenant_id={TENANT_ID}&page=1&page_size=5",
        expected_keys=['findings', 'total']
    )
    
    # Test 8: Search by Rule ID
    rule_id = "aws.s3.bucket.versioning_enabled"
    test_endpoint(
        "Search by Rule ID",
        f"{BASE_URL}/api/v1/checks/findings/search?query={rule_id}&tenant_id={TENANT_ID}",
        expected_keys=['findings', 'total']
    )
    
    # Test 9: Resource Findings
    resource_arn = "arn:aws:s3:::lgtech-website"
    test_endpoint(
        "Resource Findings",
        f"{BASE_URL}/api/v1/checks/resources/{quote(resource_arn, safe='')}?tenant_id={TENANT_ID}",
        expected_keys=['resource_arn', 'total_findings', 'findings']
    )
    
    # Test 10: Rule Findings
    test_endpoint(
        "Rule Findings",
        f"{BASE_URL}/api/v1/checks/rules/{quote(rule_id, safe='')}?tenant_id={TENANT_ID}",
        expected_keys=['rule_id', 'total_findings', 'findings', 'resources_affected']
    )
    
    # Test 11: Statistics
    test_endpoint(
        "Statistics (Group by Service)",
        f"{BASE_URL}/api/v1/checks/stats?tenant_id={TENANT_ID}&scan_id={scan_id}&group_by=service",
        expected_keys=['group_by', 'data']
    )
    
    # Test 12: Export (JSON)
    test_endpoint(
        "Export (JSON Format)",
        f"{BASE_URL}/api/v1/checks/scans/{scan_id}/export?tenant_id={TENANT_ID}&format=json&service=s3",
        expected_keys=['scan_id', 'total_findings', 'findings']
    )
    
    print(f"\n{'='*80}")
    print("✅ Test suite completed")
    print('='*80)


if __name__ == "__main__":
    main()
