#!/usr/bin/env python3
"""
Hybrid Architecture Test Script
Tests the new hybrid architecture: API Gateway → Battle-tested Engines → Centralized Database
"""

import requests
import json
import time
import sys
import os
from typing import Dict, Any

# Colors for output
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    PURPLE = '\033[0;35m'
    CYAN = '\033[0;36m'
    NC = '\033[0m'  # No Color

def print_header(text: str):
    """Print section header"""
    print(f"\n{Colors.CYAN}{text}{Colors.NC}")
    print(f"{Colors.CYAN}{'=' * len(text)}{Colors.NC}")

def print_success(text: str):
    """Print success message"""
    print(f"{Colors.GREEN}✅ {text}{Colors.NC}")

def print_error(text: str):
    """Print error message"""
    print(f"{Colors.RED}❌ {text}{Colors.NC}")

def print_warning(text: str):
    """Print warning message"""
    print(f"{Colors.YELLOW}⚠️  {text}{Colors.NC}")

def print_info(text: str):
    """Print info message"""
    print(f"{Colors.BLUE}ℹ️  {text}{Colors.NC}")

def make_request(method: str, url: str, **kwargs) -> Dict[str, Any]:
    """Make HTTP request with error handling"""
    try:
        response = requests.request(method, url, timeout=10, **kwargs)
        return {
            "success": response.status_code < 400,
            "status_code": response.status_code,
            "data": response.json() if response.content else {},
            "error": None
        }
    except requests.exceptions.RequestException as e:
        return {
            "success": False,
            "status_code": None,
            "data": {},
            "error": str(e)
        }

def test_api_gateway():
    """Test API Gateway functionality"""
    print_header("1. API Gateway Testing")
    
    # Test root endpoint
    result = make_request("GET", "http://localhost:8000/")
    if result["success"]:
        data = result["data"]
        print_success("API Gateway is running")
        print(f"   Version: {data.get('version')}")
        print(f"   Architecture: {data.get('architecture')}")
        print(f"   Supported CSPs: {data.get('supported_csps')}")
        print(f"   Available Services: {len(data.get('available_services', []))}")
        return True
    else:
        print_error(f"API Gateway failed: {result.get('error')}")
        return False

def test_gateway_health():
    """Test Gateway health and service discovery"""
    print_header("2. Gateway Health & Service Discovery")
    
    # Test gateway health
    result = make_request("GET", "http://localhost:8000/gateway/health")
    if result["success"]:
        data = result["data"]
        services = data.get("services", {})
        healthy_services = [name for name, healthy in services.items() if healthy]
        print_success(f"Gateway health check passed")
        print(f"   Healthy services: {len(healthy_services)}/{len(services)}")
        
        for service, healthy in services.items():
            status = "✅" if healthy else "❌"
            print(f"   {status} {service}")
        
        return len(healthy_services) > 0
    else:
        print_error(f"Gateway health check failed: {result.get('error')}")
        return False

def test_csp_discovery():
    """Test CSP discovery and routing"""
    print_header("3. ConfigScan CSP Discovery")
    
    # Test CSP listing
    result = make_request("GET", "http://localhost:8000/gateway/configscan/csps")
    if result["success"]:
        data = result["data"]
        csps = data.get("supported_csps", [])
        healthy_count = data.get("healthy_csp_count", 0)
        print_success(f"CSP discovery working")
        print(f"   Supported CSPs: {csps}")
        print(f"   Healthy CSP services: {healthy_count}/{len(csps)}")
        print(f"   Unified endpoint: {data.get('unified_endpoint')}")
        return len(csps) > 0
    else:
        print_error(f"CSP discovery failed: {result.get('error')}")
        return False

def test_configscan_routing():
    """Test ConfigScan routing for different CSPs"""
    print_header("4. ConfigScan Routing Test")
    
    # Test routing for each CSP
    csps_to_test = ["aws", "azure", "gcp"]
    success_count = 0
    
    for csp in csps_to_test:
        result = make_request("GET", f"http://localhost:8000/gateway/configscan/route-test?csp={csp}")
        if result["success"]:
            data = result["data"]
            print_success(f"{csp.upper()} routing configured")
            print(f"   Target service: {data.get('target_service')}")
            print(f"   Service URL: {data.get('service_url')}")
            print(f"   Unified endpoint: {data.get('unified_endpoint')}")
            print(f"   Direct endpoint: {data.get('direct_endpoint')}")
            success_count += 1
        else:
            print_error(f"{csp.upper()} routing failed: {result.get('error')}")
    
    return success_count > 0

def test_database_connectivity():
    """Test centralized database connectivity"""
    print_header("5. Database Connectivity Test")
    
    try:
        # Test PostgreSQL connection directly
        import psycopg2
        from psycopg2.extras import RealDictCursor
        
        conn_string = "postgresql://configscan_user:configscan_password@localhost:5432/threat_engine_configscan"
        conn = psycopg2.connect(conn_string)
        
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Test basic connectivity
            cur.execute("SELECT current_database(), current_user, version()")
            db_info = cur.fetchone()
            
            print_success("Centralized database connection successful")
            print(f"   Database: {db_info['current_database']}")
            print(f"   User: {db_info['current_user']}")
            print(f"   PostgreSQL Version: {db_info['version'].split()[1]}")
            
            # Test table structure
            cur.execute("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public' 
                ORDER BY table_name
            """)
            tables = [row['table_name'] for row in cur.fetchall()]
            
            print_success(f"Database schema verified: {len(tables)} tables")
            print(f"   Tables: {', '.join(tables)}")
            
            # Test sample data
            cur.execute("SELECT COUNT(*) as count FROM customers")
            customer_count = cur.fetchone()['count']
            
            cur.execute("SELECT COUNT(*) as count FROM tenants")
            tenant_count = cur.fetchone()['count']
            
            print_success("Sample data verified")
            print(f"   Customers: {customer_count}")
            print(f"   Tenants: {tenant_count}")
            
        conn.close()
        return True
        
    except Exception as e:
        print_error(f"Database connectivity test failed: {e}")
        return False

def test_engine_database_integration():
    """Test that engines can use centralized database configuration"""
    print_header("6. Engine Database Integration Test")
    
    try:
        # Test importing the centralized database config
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'consolidated_services'))
        
        from database.simple_config import (
            get_centralized_db_config,
            use_centralized_database,
            is_centralized_db_configured,
            get_configscan_database_url
        )
        
        # Test configuration retrieval
        config = get_centralized_db_config("configscan")
        print_success("Centralized database configuration imported")
        print(f"   Host: {config['host']}")
        print(f"   Database: {config['database']}")
        print(f"   User: {config['user']}")
        
        # Test configuration flags
        use_centralized = use_centralized_database()
        is_configured = is_centralized_db_configured("configscan")
        
        print_success("Configuration flags working")
        print(f"   Use centralized: {use_centralized}")
        print(f"   ConfigScan configured: {is_configured}")
        
        # Test connection URL generation
        db_url = get_configscan_database_url()
        print_success("Database URL generation working")
        print(f"   ConfigScan URL: {db_url}")
        
        return True
        
    except Exception as e:
        print_error(f"Engine database integration test failed: {e}")
        return False

def run_architecture_summary():
    """Display architecture summary"""
    print_header("🏗️  Hybrid Architecture Summary")
    
    print(f"{Colors.BLUE}Architecture Components:{Colors.NC}")
    print("┌─────────────────────────────────────────────────────────┐")
    print("│                    API Gateway                          │")
    print("│                   (Port 8000)                           │")  
    print("│          Single Entry Point & Orchestration            │")
    print("└─────────────────┬───────────────────────────────────────┘")
    print("                  │")
    print("         ┌────────┴────────┐")
    print("         │                 │")
    print("┌────────▼────────┐ ┌──────▼──────────────────────┐")
    print("│  Battle-Tested  │ │    Centralized Database     │")
    print("│     Engines     │ │       Management           │")
    print("│                 │ │                            │")
    print("│ • ConfigScan    │ │ • Unified Schemas          │")
    print("│   (13,000+      │ │ • Connection Pooling       │")
    print("│   files)        │ │ • Configuration Management │")
    print("│ • Onboarding    │ │ • Migration Tools          │")
    print("│ • Rule Engine   │ │ • Performance Optimization │")
    print("│ • Threat        │ │                            │")
    print("│ • Compliance    │ └────────────────────────────┘")
    print("│ • Inventory     │")
    print("└─────────────────┘")
    
    print(f"\n{Colors.GREEN}Benefits of This Hybrid Approach:{Colors.NC}")
    print("✅ Preserves 13,000+ files of battle-tested scanning logic")
    print("✅ Centralized database management and connection pooling")
    print("✅ Single API entry point via gateway")
    print("✅ Low migration risk - no rewriting of core logic")
    print("✅ Better resource utilization with shared database connections")
    print("✅ Incremental migration path - engine by engine")
    print("✅ Maintains CSP expertise in dedicated engines")

def main():
    """Run hybrid architecture test suite"""
    print(f"{Colors.CYAN}🧪 Hybrid Architecture Test Suite{Colors.NC}")
    print(f"{Colors.CYAN}================================={Colors.NC}")
    print("Testing: API Gateway → Battle-tested Engines → Centralized Database")
    
    test_results = []
    
    # Run tests
    test_results.append(("API Gateway", test_api_gateway()))
    test_results.append(("Gateway Health", test_gateway_health()))
    test_results.append(("CSP Discovery", test_csp_discovery()))
    test_results.append(("ConfigScan Routing", test_configscan_routing()))
    test_results.append(("Database Connectivity", test_database_connectivity()))
    test_results.append(("Engine DB Integration", test_engine_database_integration()))
    
    # Summary
    print_header("🎯 Test Results Summary")
    
    passed_tests = [name for name, result in test_results if result]
    failed_tests = [name for name, result in test_results if not result]
    
    print(f"Passed: {len(passed_tests)}/{len(test_results)}")
    print(f"Failed: {len(failed_tests)}/{len(test_results)}")
    
    if passed_tests:
        print(f"\n{Colors.GREEN}✅ Successful Tests:{Colors.NC}")
        for test_name in passed_tests:
            print(f"   ✅ {test_name}")
    
    if failed_tests:
        print(f"\n{Colors.RED}❌ Failed Tests:{Colors.NC}")
        for test_name in failed_tests:
            print(f"   ❌ {test_name}")
    
    # Architecture summary
    run_architecture_summary()
    
    if len(failed_tests) == 0:
        print(f"\n{Colors.GREEN}🎉 All tests passed! Hybrid architecture is working perfectly!{Colors.NC}")
        return 0
    else:
        print(f"\n{Colors.YELLOW}⚠️  Some tests failed. Check service status and try again.{Colors.NC}")
        return 1

if __name__ == "__main__":
    sys.exit(main())