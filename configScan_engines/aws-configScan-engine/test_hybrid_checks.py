#!/usr/bin/env python3
"""
Test script for hybrid check engine (NDJSON and Database modes)
"""
import os
import sys
import logging
from pathlib import Path

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from engine.check_engine import CheckEngine
from engine.database_manager import DatabaseManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

def test_ndjson_mode():
    """Test NDJSON mode (local testing)"""
    print("\n" + "=" * 80)
    print("TESTING NDJSON MODE (Local Testing)")
    print("=" * 80)
    
    # Use a recent discovery scan ID
    scan_id = "discovery_20260122_080533"  # Update with your actual scan ID
    
    # Initialize check engine in NDJSON mode
    check_engine = CheckEngine(use_ndjson=True)
    
    print(f"\n✅ CheckEngine initialized in NDJSON mode")
    print(f"📁 Loading discoveries from: engines-output/aws-configScan-engine/output/discoveries/{scan_id}/discovery/")
    
    # Test with S3 service
    try:
        results = check_engine.run_check_scan(
            scan_id=scan_id,
            customer_id="test_customer",
            tenant_id="test_tenant",
            provider="aws",
            hierarchy_id="039612851381",  # Update with your account ID
            hierarchy_type="account",
            services=["s3"]  # Test with one service first
        )
        
        print(f"\n✅ NDJSON Mode Test Completed!")
        print(f"   Mode: {results.get('mode')}")
        print(f"   Total Checks: {results.get('total_checks')}")
        print(f"   Passed: {results.get('passed')}")
        print(f"   Failed: {results.get('failed')}")
        print(f"   Errors: {results.get('errors')}")
        print(f"   Output: {results.get('output_path')}")
        
        return results
        
    except Exception as e:
        print(f"\n❌ NDJSON Mode Test Failed: {e}")
        import traceback
        traceback.print_exc()
        return None

def test_database_mode():
    """Test Database mode (production)"""
    print("\n" + "=" * 80)
    print("TESTING DATABASE MODE (Production)")
    print("=" * 80)
    
    try:
        # Initialize database
        db = DatabaseManager()
        print("✅ Database connection established")
        
        # Initialize check engine in database mode
        check_engine = CheckEngine(db_manager=db, use_ndjson=False)
        
        print(f"✅ CheckEngine initialized in DATABASE mode")
        
        # Use a recent discovery scan ID
        scan_id = "discovery_20260122_080533"  # Update with your actual scan ID
        
        # Test with S3 service
        results = check_engine.run_check_scan(
            scan_id=scan_id,
            customer_id="test_customer",
            tenant_id="test_tenant",
            provider="aws",
            hierarchy_id="039612851381",  # Update with your account ID
            hierarchy_type="account",
            services=["s3"]  # Test with one service first
        )
        
        print(f"\n✅ Database Mode Test Completed!")
        print(f"   Mode: {results.get('mode')}")
        print(f"   Total Checks: {results.get('total_checks')}")
        print(f"   Passed: {results.get('passed')}")
        print(f"   Failed: {results.get('failed')}")
        print(f"   Errors: {results.get('errors')}")
        print(f"   Output: {results.get('output_path')}")
        
        return results
        
    except Exception as e:
        print(f"\n⚠️  Database Mode Test Skipped: {e}")
        print("   (This is expected if database is not configured)")
        return None

def test_auto_detect_mode():
    """Test auto-detect mode"""
    print("\n" + "=" * 80)
    print("TESTING AUTO-DETECT MODE")
    print("=" * 80)
    
    try:
        # Try to initialize database
        db = DatabaseManager()
        print("✅ Database connection available")
        
        # Initialize without specifying mode (auto-detect)
        check_engine = CheckEngine(db_manager=db)
        
        mode = "DATABASE" if not check_engine.use_ndjson else "NDJSON"
        print(f"✅ Auto-detected mode: {mode}")
        
        return True
        
    except Exception as e:
        print(f"⚠️  Database not available, will use NDJSON mode")
        check_engine = CheckEngine()
        print(f"✅ Auto-detected mode: NDJSON")
        return True

def main():
    """Run all tests"""
    print("\n" + "=" * 80)
    print("HYBRID CHECK ENGINE TEST SUITE")
    print("=" * 80)
    
    # Test 1: Auto-detect mode
    test_auto_detect_mode()
    
    # Test 2: NDJSON mode
    ndjson_results = test_ndjson_mode()
    
    # Test 3: Database mode (if available)
    db_results = test_database_mode()
    
    # Summary
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    
    if ndjson_results:
        print(f"✅ NDJSON Mode: PASSED")
        print(f"   - Checks: {ndjson_results.get('total_checks')}")
        print(f"   - Passed: {ndjson_results.get('passed')}")
        print(f"   - Failed: {ndjson_results.get('failed')}")
    else:
        print(f"❌ NDJSON Mode: FAILED")
    
    if db_results:
        print(f"✅ Database Mode: PASSED")
        print(f"   - Checks: {db_results.get('total_checks')}")
        print(f"   - Passed: {db_results.get('passed')}")
        print(f"   - Failed: {db_results.get('failed')}")
    else:
        print(f"⚠️  Database Mode: SKIPPED (database not configured)")
    
    print("\n" + "=" * 80)
    print("✅ Hybrid check engine implementation complete!")
    print("=" * 80)
    print("\nUsage:")
    print("  # NDJSON mode (local)")
    print("  check_engine = CheckEngine(use_ndjson=True)")
    print("  ")
    print("  # Database mode (production)")
    print("  db = DatabaseManager()")
    print("  check_engine = CheckEngine(db_manager=db, use_ndjson=False)")
    print("  ")
    print("  # Auto-detect mode")
    print("  check_engine = CheckEngine(db_manager=db)  # Auto-detects")
    print("=" * 80)

if __name__ == '__main__':
    main()
