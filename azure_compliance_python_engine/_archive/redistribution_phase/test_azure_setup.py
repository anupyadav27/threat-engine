#!/usr/bin/env python3
"""
Quick test script for Azure Client Factory
Run this to verify the factory can create clients
"""

import sys
import os
import logging

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def check_environment():
    """Check if required environment variables are set"""
    required = ['AZURE_SUBSCRIPTION_ID']
    optional = ['AZURE_TENANT_ID', 'AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET']
    
    print("=" * 70)
    print("ENVIRONMENT CHECK")
    print("=" * 70)
    
    missing = []
    for var in required:
        value = os.getenv(var)
        if value:
            print(f"✓ {var}: {value[:8]}...")
        else:
            print(f"✗ {var}: NOT SET")
            missing.append(var)
    
    print("\nOptional (for Service Principal):")
    for var in optional:
        value = os.getenv(var)
        if value:
            print(f"✓ {var}: {value[:8]}...")
        else:
            print(f"  {var}: not set (using DefaultAzureCredential)")
    
    if missing:
        print(f"\n❌ Missing required variables: {', '.join(missing)}")
        print("\nSet them with:")
        print("export AZURE_SUBSCRIPTION_ID='your-subscription-id'")
        return False
    
    print("\n✓ Environment OK")
    return True


def test_client_factory():
    """Test the Azure Client Factory"""
    print("\n" + "=" * 70)
    print("TESTING AZURE CLIENT FACTORY")
    print("=" * 70)
    
    try:
        from auth.azure_client_factory import AzureClientFactory
        
        print("\n1. Creating factory...")
        factory = AzureClientFactory()
        print(f"✓ Factory created for subscription: {factory.subscription_id[:8]}...")
        
        print(f"\n2. Available services: {len(factory.list_available_services())}")
        
        # Group by package
        from collections import defaultdict
        by_package = defaultdict(list)
        for service in factory.list_available_services():
            info = factory.get_service_info(service)
            by_package[info['package']].append(service)
        
        print(f"\n3. Grouped by {len(by_package)} packages:")
        for package, services in sorted(by_package.items())[:5]:  # Show first 5
            print(f"   {package}")
            print(f"      Services: {', '.join(services[:3])}" + 
                  (f" (+{len(services)-3} more)" if len(services) > 3 else ""))
        print(f"   ... and {len(by_package)-5} more packages")
        
        # Test client creation for critical services
        print("\n4. Testing client creation (no network calls):")
        test_services = ['compute', 'storage', 'network', 'security', 'keyvault']
        
        created = []
        failed = []
        
        for service in test_services:
            try:
                client = factory.get_client(service)
                client_type = type(client).__name__
                created.append((service, client_type))
                print(f"   ✓ {service:15s} → {client_type}")
            except ImportError as e:
                failed.append((service, "Package not installed"))
                print(f"   ✗ {service:15s} → Package not installed")
            except Exception as e:
                failed.append((service, str(e)))
                print(f"   ✗ {service:15s} → {e}")
        
        print("\n" + "=" * 70)
        print("SUMMARY")
        print("=" * 70)
        print(f"✓ Clients created: {len(created)}/{len(test_services)}")
        if failed:
            print(f"✗ Failed: {len(failed)}")
            print("\nTo fix failures, run:")
            print("pip install -r requirements.txt")
        else:
            print("✓ All test clients created successfully!")
        
        return len(failed) == 0
        
    except ImportError as e:
        print(f"\n✗ Failed to import AzureClientFactory: {e}")
        print("\nMake sure you're in the azure_compliance_python_engine directory")
        return False
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_service_mapping():
    """Test service mapping against actual service folders"""
    print("\n" + "=" * 70)
    print("SERVICE FOLDER VALIDATION")
    print("=" * 70)
    
    try:
        from pathlib import Path
        from auth.azure_client_factory import AzureClientFactory
        
        services_dir = Path(__file__).parent / 'services'
        if not services_dir.exists():
            print(f"✗ Services directory not found: {services_dir}")
            return False
        
        factory = AzureClientFactory()
        available = set(factory.list_available_services())
        
        service_folders = [d.name for d in services_dir.iterdir() if d.is_dir()]
        
        print(f"\n1. Service folders found: {len(service_folders)}")
        print(f"2. Mapped services in factory: {len(available)}")
        
        # Check unmapped services
        unmapped = []
        for folder in service_folders:
            if folder not in available:
                unmapped.append(folder)
        
        if unmapped:
            print(f"\n⚠️  Unmapped service folders ({len(unmapped)}):")
            for svc in sorted(unmapped)[:10]:
                print(f"   - {svc}")
            if len(unmapped) > 10:
                print(f"   ... and {len(unmapped)-10} more")
            print("\nThese folders need cleanup or mapping updates")
        else:
            print("\n✓ All service folders are mapped!")
        
        # Show some mapped services
        mapped = [f for f in service_folders if f in available]
        print(f"\n✓ Correctly mapped ({len(mapped)}):")
        for svc in sorted(mapped)[:10]:
            info = factory.get_service_info(svc)
            print(f"   {svc:20s} → {info['package']}")
        if len(mapped) > 10:
            print(f"   ... and {len(mapped)-10} more")
        
        return True
        
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests"""
    print("\n")
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 15 + "Azure Client Factory Test Suite" + " " * 22 + "║")
    print("╚" + "═" * 68 + "╝")
    
    # Change to script directory
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    results = {
        'environment': check_environment(),
        'factory': False,
        'mapping': False
    }
    
    if results['environment']:
        results['factory'] = test_client_factory()
        results['mapping'] = test_service_mapping()
    
    # Final summary
    print("\n" + "=" * 70)
    print("FINAL RESULTS")
    print("=" * 70)
    
    for test, passed in results.items():
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{status:8s} {test.upper()}")
    
    all_passed = all(results.values())
    
    if all_passed:
        print("\n" + "🎉 " * 15)
        print("ALL TESTS PASSED! Azure Client Factory is ready to use.")
        print("🎉 " * 15)
        return 0
    else:
        print("\n⚠️  Some tests failed. Review output above for details.")
        return 1


if __name__ == "__main__":
    sys.exit(main())

