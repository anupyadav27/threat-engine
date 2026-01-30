#!/usr/bin/env python3
"""
ConfigScan Service Local Test Script
Tests the ConfigScan service endpoints locally
"""

import asyncio
import httpx
import json
import sys
from datetime import datetime


class ConfigScanTester:
    """Test suite for ConfigScan service"""
    
    def __init__(self, base_url="http://localhost:8002"):
        self.base_url = base_url
        self.test_tenant = "test-tenant-aws"
        self.test_customer = "test-customer-1"
        
    async def test_health_endpoint(self):
        """Test service health endpoint"""
        print("🔍 Testing health endpoint...")
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(f"{self.base_url}/health")
                
                if response.status_code == 200:
                    data = response.json()
                    print(f"✅ Health check passed: {data.get('status')}")
                    if 'scanners' in data:
                        print(f"   Available scanners: {list(data['scanners'].keys())}")
                    return True
                else:
                    print(f"❌ Health check failed: {response.status_code}")
                    return False
                    
        except Exception as e:
            print(f"❌ Health check error: {e}")
            return False
    
    async def test_service_info(self):
        """Test service info endpoint"""
        print("\n🔍 Testing service info...")
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(f"{self.base_url}/")
                
                if response.status_code == 200:
                    data = response.json()
                    print(f"✅ Service info: {data.get('service')} v{data.get('version')}")
                    print(f"   Description: {data.get('description')}")
                    return True
                else:
                    print(f"❌ Service info failed: {response.status_code}")
                    return False
                    
        except Exception as e:
            print(f"❌ Service info error: {e}")
            return False
    
    async def test_scanner_availability(self):
        """Test scanner availability"""
        print("\n🔍 Testing scanner availability...")
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(f"{self.base_url}/scanners")
                
                if response.status_code == 200:
                    data = response.json()
                    print(f"✅ Scanner registry loaded")
                    
                    for csp, info in data.get('scanners', {}).items():
                        status = "✅" if info.get('available') else "❌"
                        print(f"   {status} {csp.upper()} Scanner")
                        if info.get('services'):
                            print(f"      Services: {', '.join(info['services'][:5])}")
                        if info.get('regions'):
                            print(f"      Regions: {', '.join(info['regions'][:3])}...")
                    
                    return True
                else:
                    print(f"❌ Scanner availability failed: {response.status_code}")
                    return False
                    
        except Exception as e:
            print(f"❌ Scanner availability error: {e}")
            return False
    
    async def test_database_connection(self):
        """Test database connectivity through the service"""
        print("\n🔍 Testing database connection...")
        
        try:
            async with httpx.AsyncClient() as client:
                # Try to get scans list (this will test DB connection)
                response = await client.get(
                    f"{self.base_url}/scans",
                    params={"tenant_id": self.test_tenant}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    print(f"✅ Database connection working")
                    print(f"   Found {len(data.get('scans', []))} scans for tenant {self.test_tenant}")
                    return True
                else:
                    print(f"❌ Database connection failed: {response.status_code}")
                    if response.status_code == 404:
                        print("   This might be normal if no scans exist yet")
                        return True
                    return False
                    
        except Exception as e:
            print(f"❌ Database connection error: {e}")
            return False
    
    async def test_scan_creation(self):
        """Test scan creation (mock scan)"""
        print("\n🔍 Testing scan creation...")
        
        try:
            scan_request = {
                "tenant_id": self.test_tenant,
                "customer_id": self.test_customer,
                "csp": "aws",
                "account_id": "123456789012",
                "regions": ["us-east-1"],
                "services": ["s3", "ec2"],
                "scan_type": "discovery",
                "mock_scan": True  # Enable mock mode for testing
            }
            
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{self.base_url}/scan",
                    json=scan_request
                )
                
                if response.status_code in [200, 201, 202]:
                    data = response.json()
                    scan_id = data.get('scan_id')
                    print(f"✅ Scan creation successful: {scan_id}")
                    print(f"   Status: {data.get('status')}")
                    
                    # Test getting scan status
                    if scan_id:
                        await self.test_scan_status(scan_id)
                    
                    return True
                else:
                    print(f"❌ Scan creation failed: {response.status_code}")
                    try:
                        error_data = response.json()
                        print(f"   Error: {error_data}")
                    except:
                        print(f"   Response: {response.text}")
                    return False
                    
        except Exception as e:
            print(f"❌ Scan creation error: {e}")
            return False
    
    async def test_scan_status(self, scan_id):
        """Test getting scan status"""
        print(f"\n🔍 Testing scan status for {scan_id}...")
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(f"{self.base_url}/scans/{scan_id}")
                
                if response.status_code == 200:
                    data = response.json()
                    print(f"✅ Scan status retrieved: {data.get('status')}")
                    if data.get('total_resources'):
                        print(f"   Resources: {data.get('resources_scanned')}/{data.get('total_resources')}")
                    return True
                else:
                    print(f"❌ Scan status failed: {response.status_code}")
                    return False
                    
        except Exception as e:
            print(f"❌ Scan status error: {e}")
            return False
    
    async def test_api_docs(self):
        """Test API documentation endpoint"""
        print("\n🔍 Testing API documentation...")
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(f"{self.base_url}/docs")
                
                if response.status_code == 200:
                    print("✅ API documentation available at /docs")
                    return True
                else:
                    print(f"❌ API documentation failed: {response.status_code}")
                    return False
                    
        except Exception as e:
            print(f"❌ API documentation error: {e}")
            return False
    
    async def run_all_tests(self):
        """Run all tests"""
        print("🧪 Starting ConfigScan Service Tests")
        print(f"Service URL: {self.base_url}")
        print("=" * 50)
        
        tests = [
            self.test_health_endpoint,
            self.test_service_info,
            self.test_scanner_availability,
            self.test_database_connection,
            self.test_scan_creation,
            self.test_api_docs
        ]
        
        passed = 0
        total = len(tests)
        
        for test in tests:
            try:
                if await test():
                    passed += 1
            except Exception as e:
                print(f"❌ Test {test.__name__} failed with exception: {e}")
        
        print("\n" + "=" * 50)
        print(f"🧪 Test Results: {passed}/{total} tests passed")
        
        if passed == total:
            print("🎉 All tests passed! ConfigScan service is working correctly.")
            return True
        else:
            print(f"⚠️  {total - passed} tests failed. Check the service configuration.")
            return False


async def main():
    """Main test function"""
    if len(sys.argv) > 1:
        base_url = sys.argv[1]
    else:
        base_url = "http://localhost:8002"
    
    tester = ConfigScanTester(base_url)
    success = await tester.run_all_tests()
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    asyncio.run(main())