#!/usr/bin/env python3
"""
Test Enhanced Scan with New Features
Demonstrates progressive output, phase logging, and scan modes
"""
import os
import sys
import logging
from pathlib import Path

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from engine.database_manager import DatabaseManager
from engine.scan_controller import ScanController
from utils.progress_monitor import ProgressMonitor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def test_enhanced_discovery():
    """Test enhanced discovery scan with progressive output"""
    
    # Test configuration
    customer_id = "test_cust_001"
    tenant_id = "test_tenant_001"
    provider = "aws"
    hierarchy_id = "588989875114"
    hierarchy_type = "account"
    
    # Test with a few services
    test_services = ["s3", "iam"]
    test_regions = ["ap-south-1"]
    
    logger.info("=" * 80)
    logger.info("ENHANCED DISCOVERY SCAN TEST")
    logger.info("=" * 80)
    logger.info(f"Customer: {customer_id}")
    logger.info(f"Tenant: {tenant_id}")
    logger.info(f"Account: {hierarchy_id}")
    logger.info(f"Services: {test_services}")
    logger.info(f"Regions: {test_regions}")
    logger.info("=" * 80)
    
    try:
        # Initialize database
        logger.info("\n1. Initializing database...")
        db_manager = DatabaseManager()
        logger.info("✅ Database connection established")
        
        # Create customer and tenant
        logger.info("\n2. Creating customer and tenant...")
        db_manager.create_customer(customer_id, customer_name="Test Customer")
        db_manager.create_tenant(tenant_id, customer_id, provider, tenant_name="Test AWS Tenant")
        logger.info("✅ Customer and tenant created")
        
        # Register hierarchy
        logger.info("\n3. Registering hierarchy...")
        db_manager.register_hierarchy(
            tenant_id=tenant_id,
            provider=provider,
            hierarchy_type=hierarchy_type,
            hierarchy_id=hierarchy_id,
            hierarchy_name=f"AWS Account {hierarchy_id}"
        )
        logger.info("✅ Hierarchy registered")
        
        # Initialize scan controller
        logger.info("\n4. Initializing scan controller...")
        controller = ScanController(db_manager)
        logger.info("✅ Scan controller ready")
        
        # Run discovery scan
        logger.info("\n5. Running discovery scan...")
        logger.info("   This will use progressive output and phase logging...")
        
        result = controller.run_scan(
            customer_id=customer_id,
            tenant_id=tenant_id,
            provider=provider,
            hierarchy_id=hierarchy_id,
            hierarchy_type=hierarchy_type,
            scan_mode="discovery_only",
            services=test_services,
            regions=test_regions
        )
        
        discovery_scan_id = result.get('discovery_scan_id')
        logger.info(f"✅ Discovery scan completed: {discovery_scan_id}")
        
        # Monitor progress
        logger.info("\n6. Checking progress...")
        monitor = ProgressMonitor(discovery_scan_id)
        monitor.display_progress("discovery")
        
        # Display summary
        logger.info("\n7. Displaying summary...")
        monitor.display_summary("discovery")
        
        return {
            'discovery_scan_id': discovery_scan_id,
            'result': result
        }
        
    except Exception as e:
        logger.error(f"❌ Error during test: {e}", exc_info=True)
        raise

if __name__ == '__main__':
    try:
        result = test_enhanced_discovery()
        print("\n" + "=" * 80)
        print("TEST COMPLETED SUCCESSFULLY")
        print("=" * 80)
        print(f"Discovery Scan ID: {result['discovery_scan_id']}")
        print("=" * 80)
        print("\n💡 Tip: Use ProgressMonitor to monitor progress in real-time:")
        print(f"   monitor = ProgressMonitor('{result['discovery_scan_id']}')")
        print("   monitor.monitor_live('discovery', interval=5)")
        print("=" * 80)
    except Exception as e:
        logger.error(f"❌ Error during test: {e}", exc_info=True)
        raise

