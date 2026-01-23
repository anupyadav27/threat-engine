#!/usr/bin/env python3
"""
Test Check Results API with NDJSON Data

Loads NDJSON check results and tests API endpoints to verify:
- API can serve NDJSON data
- Response quality and structure
- Coverage matches expectations
"""

import json
import sys
import requests
from pathlib import Path
from typing import Dict, List, Any
from collections import Counter

# Configuration
BASE_URL = "http://localhost:8000"
TENANT_ID = "test_tenant"
NDJSON_BASE = Path("/Users/apple/Desktop/threat-engine/engines-output/aws-configScan-engine/output/configscan/rule_check")

def find_latest_ndjson() -> Path:
    """Find the most recent findings.ndjson file"""
    scan_dirs = sorted(NDJSON_BASE.glob("rule_check_*"), reverse=True)
    for scan_dir in scan_dirs:
        findings_file = scan_dir / "findings.ndjson"
        if findings_file.exists():
            return findings_file
    raise FileNotFoundError("No findings.ndjson files found")

def load_ndjson_sample(ndjson_file: Path, max_records: int = 1000) -> List[Dict]:
    """Load sample records from NDJSON"""
    records = []
    with open(ndjson_file, 'r') as f:
        for line in f:
            if not line.strip():
                continue
            try:
                record = json.loads(line)
                records.append(record)
                if len(records) >= max_records:
                    break
            except json.JSONDecodeError:
                continue
    return records

def test_api_endpoint(name: str, url: str, params: Dict = None) -> Dict[str, Any]:
    """Test an API endpoint"""
    print(f"\n{'='*80}")
    print(f"🧪 Testing: {name}")
    print(f"   URL: {url}")
    if params:
        print(f"   Params: {params}")
    print('='*80)
    
    try:
        response = requests.get(url, params=params, timeout=10)
        print(f"   Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ Success")
            return {'success': True, 'data': data, 'status': 200}
        else:
            error_text = response.text[:200]
            print(f"   ❌ Failed: {error_text}")
            return {'success': False, 'error': error_text, 'status': response.status_code}
    
    except requests.exceptions.ConnectionError:
        print(f"   ❌ Connection Error: Is API server running?")
        return {'success': False, 'error': 'Connection refused'}
    except Exception as e:
        print(f"   ❌ Exception: {e}")
        return {'success': False, 'error': str(e)}

def analyze_api_response(endpoint_name: str, response_data: Dict) -> Dict[str, Any]:
    """Analyze API response quality"""
    analysis = {
        'endpoint': endpoint_name,
        'has_data': bool(response_data),
        'keys': list(response_data.keys()) if isinstance(response_data, dict) else None
    }
    
    # Dashboard analysis
    if endpoint_name == 'dashboard':
        analysis.update({
            'total_checks': response_data.get('total_checks', 0),
            'pass_rate': response_data.get('pass_rate', 0),
            'services_scanned': response_data.get('services_scanned', 0),
            'top_services_count': len(response_data.get('top_failing_services', [])),
            'recent_scans_count': len(response_data.get('recent_scans', []))
        })
    
    # Scan list analysis
    elif endpoint_name == 'scans':
        analysis.update({
            'total_scans': response_data.get('total', 0),
            'scans_on_page': len(response_data.get('scans', [])),
            'page': response_data.get('page', 0),
            'page_size': response_data.get('page_size', 0)
        })
    
    # Findings analysis
    elif endpoint_name in ['findings', 'search']:
        findings = response_data.get('findings', [])
        analysis.update({
            'total_findings': response_data.get('total', 0),
            'findings_on_page': len(findings),
            'page': response_data.get('page', 0),
            'total_pages': response_data.get('total_pages', 0)
        })
        
        # Analyze sample findings
        if findings:
            sample = findings[0]
            analysis['sample_finding'] = {
                'has_arn': bool(sample.get('resource_arn')),
                'has_id': bool(sample.get('resource_id')),
                'has_status': bool(sample.get('status')),
                'has_rule_id': bool(sample.get('rule_id')),
                'has_checked_fields': bool(sample.get('checked_fields')),
                'has_finding_data': bool(sample.get('finding_data'))
            }
    
    return analysis

def print_analysis_summary(results: List[Dict]):
    """Print summary of all test results"""
    print("\n" + "="*80)
    print("📊 API TEST SUMMARY")
    print("="*80)
    
    successful = [r for r in results if r.get('success')]
    failed = [r for r in results if not r.get('success')]
    
    print(f"\n✅ Successful: {len(successful)}/{len(results)}")
    print(f"❌ Failed: {len(failed)}/{len(results)}")
    
    if successful:
        print(f"\n✅ SUCCESSFUL ENDPOINTS:")
        for result in successful:
            print(f"   • {result['name']}")
            if result.get('analysis'):
                analysis = result['analysis']
                if 'total_checks' in analysis:
                    print(f"     - Total Checks: {analysis['total_checks']:,}")
                if 'total_findings' in analysis:
                    print(f"     - Total Findings: {analysis['total_findings']:,}")
                if 'total_scans' in analysis:
                    print(f"     - Total Scans: {analysis['total_scans']}")
    
    if failed:
        print(f"\n❌ FAILED ENDPOINTS:")
        for result in failed:
            print(f"   • {result['name']}: {result.get('error', 'Unknown error')}")
    
    print()

def main():
    """Main test function"""
    print("╔══════════════════════════════════════════════════════════════════════════════╗")
    print("║              CHECK RESULTS API - NDJSON DATA TEST                            ║")
    print("╚══════════════════════════════════════════════════════════════════════════════╝")
    
    # Check if API server is running
    try:
        health = requests.get(f"{BASE_URL}/health", timeout=5)
        if health.status_code != 200:
            print("❌ API server not healthy. Please start it first:")
            print("   python3 -m uvicorn threat_engine.api_server:app --port 8000")
            return 1
    except:
        print("❌ Cannot connect to API server. Please start it first:")
        print("   python3 -m uvicorn threat_engine.api_server:app --port 8000")
        return 1
    
    print("✅ API server is running\n")
    
    # Find NDJSON file
    try:
        ndjson_file = find_latest_ndjson()
        print(f"📂 Using NDJSON: {ndjson_file.name}")
        
        # Load sample to get scan_id
        sample_records = load_ndjson_sample(ndjson_file, max_records=10)
        if not sample_records:
            print("❌ No records found in NDJSON file")
            return 1
        
        scan_id = sample_records[0].get('scan_id')
        print(f"📋 Scan ID: {scan_id}")
        print(f"📊 Sample records: {len(sample_records)}")
        print()
        
    except Exception as e:
        print(f"❌ Error finding NDJSON: {e}")
        return 1
    
    # Test results
    test_results = []
    
    # Test 1: Dashboard
    result = test_api_endpoint(
        "Dashboard",
        f"{BASE_URL}/api/v1/checks/dashboard",
        params={'tenant_id': TENANT_ID}
    )
    if result['success']:
        result['analysis'] = analyze_api_response('dashboard', result['data'])
    result['name'] = 'Dashboard'
    test_results.append(result)
    
    # Test 2: List Scans
    result = test_api_endpoint(
        "List Scans",
        f"{BASE_URL}/api/v1/checks/scans",
        params={'tenant_id': TENANT_ID, 'page': 1, 'page_size': 5}
    )
    if result['success']:
        result['analysis'] = analyze_api_response('scans', result['data'])
    result['name'] = 'List Scans'
    test_results.append(result)
    
    # Test 3: Scan Detail (if scan_id available)
    if scan_id:
        result = test_api_endpoint(
            "Scan Detail",
            f"{BASE_URL}/api/v1/checks/scans/{scan_id}",
            params={'tenant_id': TENANT_ID}
        )
        if result['success']:
            result['analysis'] = analyze_api_response('scan_detail', result['data'])
        result['name'] = 'Scan Detail'
        test_results.append(result)
    
    # Test 4: Service Stats
    if scan_id:
        result = test_api_endpoint(
            "Service Stats",
            f"{BASE_URL}/api/v1/checks/scans/{scan_id}/services",
            params={'tenant_id': TENANT_ID}
        )
        if result['success']:
            result['analysis'] = analyze_api_response('services', result['data'])
        result['name'] = 'Service Stats'
        test_results.append(result)
    
    # Test 5: Service Detail (S3)
    if scan_id:
        result = test_api_endpoint(
            "Service Detail (S3)",
            f"{BASE_URL}/api/v1/checks/scans/{scan_id}/services/s3",
            params={'tenant_id': TENANT_ID}
        )
        if result['success']:
            result['analysis'] = analyze_api_response('service_detail', result['data'])
        result['name'] = 'Service Detail (S3)'
        test_results.append(result)
    
    # Test 6: Search by Service
    result = test_api_endpoint(
        "Search (service=s3)",
        f"{BASE_URL}/api/v1/checks/findings/search",
        params={'query': 's3', 'tenant_id': TENANT_ID, 'page': 1, 'page_size': 10}
    )
    if result['success']:
        result['analysis'] = analyze_api_response('search', result['data'])
    result['name'] = 'Search'
    test_results.append(result)
    
    # Test 7: Search by Rule
    if sample_records:
        rule_id = sample_records[0].get('rule_id')
        if rule_id:
            result = test_api_endpoint(
                "Search (rule_id)",
                f"{BASE_URL}/api/v1/checks/findings/search",
                params={'query': rule_id, 'tenant_id': TENANT_ID, 'page': 1, 'page_size': 5}
            )
            if result['success']:
                result['analysis'] = analyze_api_response('search', result['data'])
            result['name'] = 'Search by Rule'
            test_results.append(result)
    
    # Test 8: Resource Findings (if ARN available)
    if sample_records:
        resource_arn = sample_records[0].get('resource_arn')
        if resource_arn:
            from urllib.parse import quote
            result = test_api_endpoint(
                "Resource Findings",
                f"{BASE_URL}/api/v1/checks/resources/{quote(resource_arn, safe='')}",
                params={'tenant_id': TENANT_ID}
            )
            if result['success']:
                result['analysis'] = analyze_api_response('resource', result['data'])
            result['name'] = 'Resource Findings'
            test_results.append(result)
    
    # Print summary
    print_analysis_summary(test_results)
    
    # Save results
    output_file = Path("/tmp/api_test_results.json")
    with open(output_file, 'w') as f:
        json.dump({
            'test_summary': {
                'total_tests': len(test_results),
                'successful': len([r for r in test_results if r.get('success')]),
                'failed': len([r for r in test_results if not r.get('success')])
            },
            'results': test_results
        }, f, indent=2, default=str)
    
    print(f"💾 Test results saved to: {output_file}")
    
    return 0 if all(r.get('success') for r in test_results) else 1

if __name__ == "__main__":
    sys.exit(main())
