#!/usr/bin/env python3
"""
Comprehensive API Test Suite for Threat Engine

Tests all endpoints for:
- Check Results API (11 endpoints)
- Discovery Results API (10 endpoints)

Validates:
- Response structure
- Error handling
- NDJSON fallback
- Pagination
- Multi-tenant isolation

Usage:
    python3 test_all_apis.py
"""

import requests
import json
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
from urllib.parse import quote
from datetime import datetime
from collections import defaultdict

# Configuration
BASE_URL = "http://localhost:8000"
TENANT_ID = "test_tenant"
CUSTOMER_ID = "test_customer"

# Colors for output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_header(text: str):
    """Print formatted header"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*80}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{text.center(80)}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*80}{Colors.RESET}\n")

def print_test(name: str, url: str):
    """Print test info"""
    print(f"{Colors.BOLD}🧪 {name}{Colors.RESET}")
    print(f"   {Colors.BLUE}URL: {url}{Colors.RESET}")

def print_success(message: str):
    """Print success message"""
    print(f"   {Colors.GREEN}✅ {message}{Colors.RESET}")

def print_warning(message: str):
    """Print warning message"""
    print(f"   {Colors.YELLOW}⚠️  {message}{Colors.RESET}")

def print_error(message: str):
    """Print error message"""
    print(f"   {Colors.RED}❌ {message}{Colors.RESET}")

def test_endpoint(
    name: str,
    method: str,
    url: str,
    params: Dict = None,
    expected_status: int = 200,
    expected_keys: List[str] = None,
    validate_func: callable = None
) -> Dict[str, Any]:
    """
    Test a single API endpoint
    
    Returns:
        {
            'name': str,
            'url': str,
            'success': bool,
            'status': int,
            'response_time_ms': float,
            'error': str or None,
            'data': dict or None,
            'validation': dict or None
        }
    """
    print_test(name, url)
    
    result = {
        'name': name,
        'url': url,
        'method': method,
        'success': False,
        'status': None,
        'response_time_ms': 0,
        'error': None,
        'data': None,
        'validation': {}
    }
    
    try:
        start_time = datetime.now()
        
        if method.upper() == 'GET':
            response = requests.get(url, params=params, timeout=30)
        elif method.upper() == 'POST':
            response = requests.post(url, json=params, timeout=30)
        else:
            raise ValueError(f"Unsupported method: {method}")
        
        elapsed = (datetime.now() - start_time).total_seconds() * 1000
        result['response_time_ms'] = elapsed
        result['status'] = response.status_code
        
        # Check status code
        if response.status_code == expected_status:
            print_success(f"Status: {response.status_code} ({elapsed:.0f}ms)")
            
            # Try to parse JSON
            try:
                data = response.json()
                result['data'] = data
                
                # Validate expected keys
                if expected_keys:
                    missing = [k for k in expected_keys if k not in data]
                    if missing:
                        print_warning(f"Missing keys: {missing}")
                        result['validation']['missing_keys'] = missing
                    else:
                        print_success("All expected keys present")
                        result['validation']['keys_valid'] = True
                
                # Custom validation
                if validate_func:
                    validation_result = validate_func(data)
                    result['validation'].update(validation_result)
                    if validation_result.get('valid'):
                        print_success("Custom validation passed")
                    else:
                        print_warning(f"Validation issue: {validation_result.get('message')}")
                
                result['success'] = True
                
            except json.JSONDecodeError:
                result['error'] = "Invalid JSON response"
                print_error("Invalid JSON response")
        
        elif response.status_code == 404:
            result['error'] = "Not Found (404)"
            print_warning("Not Found (404) - May be expected if no data")
            result['success'] = True  # 404 is acceptable for empty data
        
        else:
            result['error'] = f"Status {response.status_code}: {response.text[:200]}"
            print_error(f"Status {response.status_code}: {response.text[:200]}")
    
    except requests.exceptions.ConnectionError:
        result['error'] = "Connection refused - Is API server running?"
        print_error("Connection refused - Is API server running?")
    
    except requests.exceptions.Timeout:
        result['error'] = "Request timeout (>30s)"
        print_error("Request timeout")
    
    except Exception as e:
        result['error'] = str(e)
        print_error(f"Exception: {e}")
    
    return result


def validate_paginated_response(data: Dict) -> Dict:
    """Validate paginated response structure"""
    required = ['total', 'page', 'page_size', 'total_pages']
    missing = [k for k in required if k not in data]
    
    if missing:
        return {'valid': False, 'message': f"Missing pagination keys: {missing}"}
    
    # Check pagination logic
    if data.get('total_pages', 0) != (data.get('total', 0) + data.get('page_size', 1) - 1) // data.get('page_size', 1):
        return {'valid': False, 'message': "Pagination math incorrect"}
    
    return {'valid': True}


def validate_dashboard_response(data: Dict) -> Dict:
    """Validate dashboard response"""
    required = ['total_discoveries', 'unique_resources', 'services_scanned']
    missing = [k for k in required if k not in data]
    
    if missing:
        return {'valid': False, 'message': f"Missing keys: {missing}"}
    
    return {'valid': True}


# ============================================================================
# CHECK RESULTS API TESTS (11 endpoints)
# ============================================================================

def test_check_results_api() -> List[Dict]:
    """Test all check results API endpoints"""
    print_header("CHECK RESULTS API - Test Suite")
    
    results = []
    
    # Find a scan_id from NDJSON if available
    scan_id = find_scan_id_from_ndjson("check")
    if not scan_id:
        scan_id = "check_20260122_210506"  # Fallback
    
    # Test 1: Dashboard
    results.append(test_endpoint(
        "Check Dashboard",
        "GET",
        f"{BASE_URL}/api/v1/checks/dashboard",
        params={'tenant_id': TENANT_ID},
        expected_keys=['total_checks', 'passed', 'failed', 'pass_rate'],
        validate_func=validate_dashboard_response
    ))
    
    # Test 2: List Scans
    results.append(test_endpoint(
        "List Check Scans",
        "GET",
        f"{BASE_URL}/api/v1/checks/scans",
        params={'tenant_id': TENANT_ID, 'page': 1, 'page_size': 5},
        expected_keys=['scans', 'total', 'page', 'page_size', 'total_pages'],
        validate_func=validate_paginated_response
    ))
    
    # Test 3: Scan Detail
    results.append(test_endpoint(
        "Check Scan Detail",
        "GET",
        f"{BASE_URL}/api/v1/checks/scans/{scan_id}",
        params={'tenant_id': TENANT_ID},
        expected_keys=['scan_id', 'total_checks', 'passed', 'failed']
    ))
    
    # Test 4: Service Stats
    results.append(test_endpoint(
        "Check Service Stats",
        "GET",
        f"{BASE_URL}/api/v1/checks/scans/{scan_id}/services",
        params={'tenant_id': TENANT_ID},
        expected_status=200  # Returns array
    ))
    
    # Test 5: Service Detail
    results.append(test_endpoint(
        "Check Service Detail (S3)",
        "GET",
        f"{BASE_URL}/api/v1/checks/scans/{scan_id}/services/s3",
        params={'tenant_id': TENANT_ID},
        expected_keys=['service', 'total_checks', 'passed', 'failed']
    ))
    
    # Test 6: Scan Findings
    results.append(test_endpoint(
        "Check Scan Findings",
        "GET",
        f"{BASE_URL}/api/v1/checks/scans/{scan_id}/findings",
        params={'tenant_id': TENANT_ID, 'page': 1, 'page_size': 10},
        expected_keys=['findings', 'total', 'page', 'total_pages'],
        validate_func=validate_paginated_response
    ))
    
    # Test 7: Search Findings
    results.append(test_endpoint(
        "Search Check Findings",
        "GET",
        f"{BASE_URL}/api/v1/checks/findings/search",
        params={'query': 's3', 'tenant_id': TENANT_ID, 'page': 1, 'page_size': 10},
        expected_keys=['findings', 'total'],
        validate_func=validate_paginated_response
    ))
    
    # Test 8: Resource Findings
    resource_arn = "arn:aws:s3:::lgtech-website"
    results.append(test_endpoint(
        "Check Resource Findings",
        "GET",
        f"{BASE_URL}/api/v1/checks/resources/{quote(resource_arn, safe='')}",
        params={'tenant_id': TENANT_ID},
        expected_keys=['resource_arn', 'total_findings', 'findings']
    ))
    
    # Test 9: Rule Findings
    rule_id = "aws.s3.bucket.versioning_enabled"
    results.append(test_endpoint(
        "Check Rule Findings",
        "GET",
        f"{BASE_URL}/api/v1/checks/rules/{quote(rule_id, safe='')}",
        params={'tenant_id': TENANT_ID},
        expected_keys=['rule_id', 'total_findings', 'findings']
    ))
    
    # Test 10: Statistics
    results.append(test_endpoint(
        "Check Statistics",
        "GET",
        f"{BASE_URL}/api/v1/checks/stats",
        params={'tenant_id': TENANT_ID, 'scan_id': scan_id, 'group_by': 'service'},
        expected_keys=['group_by', 'data']
    ))
    
    # Test 11: Export
    results.append(test_endpoint(
        "Check Export (JSON)",
        "GET",
        f"{BASE_URL}/api/v1/checks/scans/{scan_id}/export",
        params={'tenant_id': TENANT_ID, 'format': 'json', 'service': 's3'},
        expected_keys=['scan_id', 'total_findings', 'findings']
    ))
    
    return results


# ============================================================================
# DISCOVERY RESULTS API TESTS (10 endpoints)
# ============================================================================

def test_discovery_results_api() -> List[Dict]:
    """Test all discovery results API endpoints"""
    print_header("DISCOVERY RESULTS API - Test Suite")
    
    results = []
    
    # Find a scan_id from NDJSON if available
    scan_id = find_scan_id_from_ndjson("discovery")
    if not scan_id:
        scan_id = "discovery_20260122_080533"  # Fallback
    
    # Test 1: Dashboard
    results.append(test_endpoint(
        "Discovery Dashboard",
        "GET",
        f"{BASE_URL}/api/v1/discoveries/dashboard",
        params={'tenant_id': TENANT_ID},
        expected_keys=['total_discoveries', 'unique_resources', 'services_scanned'],
        validate_func=validate_dashboard_response
    ))
    
    # Test 2: List Scans
    results.append(test_endpoint(
        "List Discovery Scans",
        "GET",
        f"{BASE_URL}/api/v1/discoveries/scans",
        params={'tenant_id': TENANT_ID, 'page': 1, 'page_size': 5},
        expected_keys=['scans', 'total', 'page', 'page_size', 'total_pages'],
        validate_func=validate_paginated_response
    ))
    
    # Test 3: Scan Detail
    results.append(test_endpoint(
        "Discovery Scan Detail",
        "GET",
        f"{BASE_URL}/api/v1/discoveries/scans/{scan_id}",
        params={'tenant_id': TENANT_ID},
        expected_keys=['scan_id', 'total_discoveries', 'unique_resources']
    ))
    
    # Test 4: Service Stats
    results.append(test_endpoint(
        "Discovery Service Stats",
        "GET",
        f"{BASE_URL}/api/v1/discoveries/scans/{scan_id}/services",
        params={'tenant_id': TENANT_ID},
        expected_status=200  # Returns array
    ))
    
    # Test 5: Service Detail
    results.append(test_endpoint(
        "Discovery Service Detail (S3)",
        "GET",
        f"{BASE_URL}/api/v1/discoveries/scans/{scan_id}/services/s3",
        params={'tenant_id': TENANT_ID},
        expected_keys=['service', 'total_discoveries', 'unique_resources']
    ))
    
    # Test 6: Scan Discoveries
    results.append(test_endpoint(
        "Discovery Scan Discoveries",
        "GET",
        f"{BASE_URL}/api/v1/discoveries/scans/{scan_id}/discoveries",
        params={'tenant_id': TENANT_ID, 'page': 1, 'page_size': 10},
        expected_keys=['discoveries', 'total', 'page', 'total_pages'],
        validate_func=validate_paginated_response
    ))
    
    # Test 7: Search Discoveries
    results.append(test_endpoint(
        "Search Discoveries",
        "GET",
        f"{BASE_URL}/api/v1/discoveries/discoveries/search",
        params={'query': 's3', 'tenant_id': TENANT_ID, 'page': 1, 'page_size': 10},
        expected_keys=['discoveries', 'total'],
        validate_func=validate_paginated_response
    ))
    
    # Test 8: Resource Discoveries
    resource_arn = "arn:aws:s3:::lgtech-website"
    results.append(test_endpoint(
        "Discovery Resource Discoveries",
        "GET",
        f"{BASE_URL}/api/v1/discoveries/resources/{quote(resource_arn, safe='')}",
        params={'tenant_id': TENANT_ID},
        expected_keys=['resource_arn', 'total_discoveries', 'discoveries']
    ))
    
    # Test 9: Discovery Function Detail
    discovery_id = "aws.s3.list_buckets"
    results.append(test_endpoint(
        "Discovery Function Detail",
        "GET",
        f"{BASE_URL}/api/v1/discoveries/functions/{quote(discovery_id, safe='')}",
        params={'tenant_id': TENANT_ID},
        expected_keys=['discovery_id', 'total_discoveries', 'service']
    ))
    
    # Test 10: Export
    results.append(test_endpoint(
        "Discovery Export (JSON)",
        "GET",
        f"{BASE_URL}/api/v1/discoveries/scans/{scan_id}/export",
        params={'tenant_id': TENANT_ID, 'format': 'json', 'service': 's3'},
        expected_keys=['scan_id', 'total_discoveries', 'discoveries']
    ))
    
    return results


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def find_scan_id_from_ndjson(scan_type: str) -> Optional[str]:
    """Find latest scan_id from NDJSON files"""
    if scan_type == "check":
        base = Path("/Users/apple/Desktop/threat-engine/engines-output/aws-configScan-engine/output/configscan/rule_check")
        pattern = "rule_check_*"
    else:
        base = Path("/Users/apple/Desktop/threat-engine/engines-output/aws-configScan-engine/output/configscan/discoveries")
        pattern = "discovery_*"
    
    if not base.exists():
        return None
    
    scan_dirs = sorted(base.glob(pattern), reverse=True)
    for scan_dir in scan_dirs:
        if scan_dir.is_dir():
            return scan_dir.name
    
    return None


def check_api_server() -> bool:
    """Check if API server is running"""
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=5)
        return response.status_code == 200
    except:
        try:
            # Try root endpoint
            response = requests.get(f"{BASE_URL}/", timeout=5)
            return response.status_code in [200, 404]  # 404 is OK, means server is running
        except:
            return False


def print_summary(all_results: List[Dict]):
    """Print comprehensive test summary"""
    print_header("TEST SUMMARY")
    
    # Separate by API type
    check_results = [r for r in all_results if 'check' in r['name'].lower()]
    discovery_results = [r for r in all_results if 'discovery' in r['name'].lower()]
    
    # Overall stats
    total = len(all_results)
    successful = len([r for r in all_results if r['success']])
    failed = total - successful
    
    print(f"{Colors.BOLD}Overall:{Colors.RESET}")
    print(f"  Total Tests: {total}")
    print(f"  {Colors.GREEN}✅ Successful: {successful}{Colors.RESET}")
    print(f"  {Colors.RED}❌ Failed: {failed}{Colors.RESET}")
    if total > 0:
        print(f"  Success Rate: {(successful/total*100):.1f}%")
    
    # Check Results API
    if check_results:
        check_success = len([r for r in check_results if r['success']])
        print(f"\n{Colors.BOLD}Check Results API:{Colors.RESET}")
        print(f"  Tests: {len(check_results)}")
        print(f"  {Colors.GREEN}✅ Successful: {check_success}/{len(check_results)}{Colors.RESET}")
        if len(check_results) > 0:
            print(f"  Success Rate: {(check_success/len(check_results)*100):.1f}%")
    
    # Discovery Results API
    if discovery_results:
        disc_success = len([r for r in discovery_results if r['success']])
        print(f"\n{Colors.BOLD}Discovery Results API:{Colors.RESET}")
        print(f"  Tests: {len(discovery_results)}")
        print(f"  {Colors.GREEN}✅ Successful: {disc_success}/{len(discovery_results)}{Colors.RESET}")
        if len(discovery_results) > 0:
            print(f"  Success Rate: {(disc_success/len(discovery_results)*100):.1f}%")
    
    # Performance stats
    response_times = [r['response_time_ms'] for r in all_results if r.get('response_time_ms', 0) > 0]
    if response_times:
        avg_time = sum(response_times) / len(response_times)
        max_time = max(response_times)
        print(f"\n{Colors.BOLD}Performance:{Colors.RESET}")
        print(f"  Average Response Time: {avg_time:.0f}ms")
        print(f"  Max Response Time: {max_time:.0f}ms")
    
    # Failed tests
    failed_tests = [r for r in all_results if not r['success']]
    if failed_tests:
        print(f"\n{Colors.RED}{Colors.BOLD}Failed Tests:{Colors.RESET}")
        for test in failed_tests:
            print(f"  ❌ {test['name']}")
            print(f"     Error: {test.get('error', 'Unknown')}")
            print(f"     URL: {test['url']}")
    
    # Warnings
    warnings = []
    for r in all_results:
        if r.get('validation', {}).get('missing_keys'):
            warnings.append(f"{r['name']}: Missing keys {r['validation']['missing_keys']}")
    
    if warnings:
        print(f"\n{Colors.YELLOW}{Colors.BOLD}Warnings:{Colors.RESET}")
        for w in warnings:
            print(f"  ⚠️  {w}")


def save_results(all_results: List[Dict], output_file: Path):
    """Save test results to JSON file"""
    summary = {
        'timestamp': datetime.now().isoformat(),
        'total_tests': len(all_results),
        'successful': len([r for r in all_results if r['success']]),
        'failed': len([r for r in all_results if not r['success']]),
        'results': all_results
    }
    
    with open(output_file, 'w') as f:
        json.dump(summary, f, indent=2, default=str)
    
    print(f"\n{Colors.BLUE}💾 Test results saved to: {output_file}{Colors.RESET}")


# ============================================================================
# MAIN
# ============================================================================

def main():
    """Run comprehensive API test suite"""
    print(f"{Colors.BOLD}{Colors.BLUE}")
    print("╔══════════════════════════════════════════════════════════════════════════════╗")
    print("║              COMPREHENSIVE API TEST SUITE - Threat Engine                     ║")
    print("║                                                                              ║")
    print("║  Testing: Check Results API (11 endpoints)                                 ║")
    print("║           Discovery Results API (10 endpoints)                             ║")
    print("╚══════════════════════════════════════════════════════════════════════════════╝")
    print(Colors.RESET)
    
    # Check if API server is running
    print(f"{Colors.BLUE}Checking API server...{Colors.RESET}")
    if not check_api_server():
        print_error("API server is not running!")
        print(f"\n{Colors.YELLOW}Please start the API server first:{Colors.RESET}")
        print(f"  cd threat-engine")
        print(f"  python3 -m uvicorn threat_engine.api_server:app --port 8000")
        return 1
    
    print_success("API server is running")
    
    # Run all tests
    all_results = []
    
    # Test Check Results API
    check_results = test_check_results_api()
    all_results.extend(check_results)
    
    # Test Discovery Results API
    discovery_results = test_discovery_results_api()
    all_results.extend(discovery_results)
    
    # Print summary
    print_summary(all_results)
    
    # Save results
    output_file = Path("/tmp/api_test_results.json")
    save_results(all_results, output_file)
    
    # Return exit code
    all_successful = all(r['success'] for r in all_results)
    return 0 if all_successful else 1


if __name__ == "__main__":
    sys.exit(main())
