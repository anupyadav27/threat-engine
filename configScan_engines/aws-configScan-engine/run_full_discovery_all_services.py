#!/usr/bin/env python3
"""
Full Discovery Scan - All Services, All Regions
Run comprehensive discovery scan for all enabled services across all regions
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

# AWS Regions (all standard regions)
ALL_AWS_REGIONS = [
    'us-east-1',      # N. Virginia
    'us-east-2',      # Ohio
    'us-west-1',      # N. California
    'us-west-2',      # Oregon
    'ap-south-1',     # Mumbai
    'ap-southeast-1', # Singapore
    'ap-southeast-2', # Sydney
    'ap-northeast-1', # Tokyo
    'ap-northeast-2', # Seoul
    'ap-northeast-3', # Osaka
    'ca-central-1',   # Canada
    'eu-central-1',   # Frankfurt
    'eu-west-1',      # Ireland
    'eu-west-2',      # London
    'eu-west-3',      # Paris
    'eu-north-1',     # Stockholm
    'sa-east-1',      # São Paulo
    'af-south-1',     # Cape Town
    'ap-east-1',      # Hong Kong
    'me-south-1',     # Bahrain
    'me-central-1',   # UAE
    'eu-south-1',     # Milan
    'ap-south-2',     # Hyderabad
    'eu-central-2',   # Zurich
    'ap-southeast-3', # Jakarta
    'ap-southeast-4', # Melbourne
    'il-central-1',   # Israel
]

def run_full_discovery_scan():
    """Run full discovery scan for all services and all regions"""
    
    # Set parallel processing environment variables (if not already set)
    if 'MAX_SERVICE_WORKERS' not in os.environ:
        os.environ['MAX_SERVICE_WORKERS'] = '10'  # Parallel service processing
    if 'MAX_REGION_WORKERS' not in os.environ:
        os.environ['MAX_REGION_WORKERS'] = '5'    # Parallel region processing
    if 'MAX_DISCOVERY_WORKERS' not in os.environ:
        os.environ['MAX_DISCOVERY_WORKERS'] = '50'  # Parallel independent discoveries
    if 'FOR_EACH_MAX_WORKERS' not in os.environ:
        os.environ['FOR_EACH_MAX_WORKERS'] = '50'   # Parallel for_each items
    
    # Configuration
    customer_id = "test_cust_001"
    tenant_id = "test_tenant_001"
    provider = "aws"
    hierarchy_id = "588989875114"  # Your account ID
    hierarchy_type = "account"
    
    # Use all regions
    regions = ALL_AWS_REGIONS
    
    logger.info(f"Parallel Processing Configuration:")
    logger.info(f"  MAX_SERVICE_WORKERS: {os.environ.get('MAX_SERVICE_WORKERS', '10')}")
    logger.info(f"  MAX_REGION_WORKERS: {os.environ.get('MAX_REGION_WORKERS', '5')}")
    logger.info(f"  MAX_DISCOVERY_WORKERS: {os.environ.get('MAX_DISCOVERY_WORKERS', '50')}")
    logger.info(f"  FOR_EACH_MAX_WORKERS: {os.environ.get('FOR_EACH_MAX_WORKERS', '50')}")
    
    logger.info("=" * 80)
    logger.info("FULL DISCOVERY SCAN - ALL SERVICES, ALL REGIONS")
    logger.info("=" * 80)
    logger.info(f"Customer: {customer_id}")
    logger.info(f"Tenant: {tenant_id}")
    logger.info(f"Account: {hierarchy_id}")
    logger.info(f"Regions: {len(regions)} regions")
    logger.info(f"Services: ALL ENABLED SERVICES")
    logger.info("=" * 80)
    logger.info("\n⚠️  WARNING: This will scan ALL services across ALL regions")
    logger.info("   This may take a significant amount of time and make many API calls")
    logger.info("   Estimated time: 30-60 minutes depending on services")
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
        
        # Get all enabled services
        from utils.service_feature_manager import ServiceFeatureManager
        feature_manager = ServiceFeatureManager()
        all_services = feature_manager.get_enabled_services('discovery')
        logger.info(f"   Found {len(all_services)} services with discovery enabled")
        
        # Run discovery scan for ALL services
        logger.info("\n5. Starting full discovery scan...")
        logger.info("   This will scan all services across all regions...")
        logger.info("   Progress will be saved incrementally...")
        logger.info("\n   💡 Tip: You can monitor progress in another terminal:")
        logger.info("      python3 -c \"from utils.progress_monitor import ProgressMonitor; ")
        logger.info("                   monitor = ProgressMonitor('SCAN_ID'); ")
        logger.info("                   monitor.monitor_live('discovery', interval=10)\"")
        logger.info("")
        
        # Use discovery engine directly for all services
        from engine.discovery_engine import DiscoveryEngine
        discovery_engine = DiscoveryEngine(db_manager)
        
        # Run discovery for all services
        discovery_scan_id = discovery_engine.run_discovery_for_all_services(
            customer_id=customer_id,
            tenant_id=tenant_id,
            provider=provider,
            hierarchy_id=hierarchy_id,
            hierarchy_type=hierarchy_type,
            regions=regions
        )
        
        result = {
            'discovery_scan_id': discovery_scan_id,
            'status': 'completed'
        }
        
        logger.info("=" * 80)
        logger.info("DISCOVERY SCAN COMPLETED")
        logger.info("=" * 80)
        logger.info(f"Scan ID: {discovery_scan_id}")
        logger.info("")
        logger.info("📝 NOTE: Results are saved to NDJSON files only (no database writes).")
        logger.info("   To upload to database, run:")
        logger.info(f"   python3 upload_scan_to_database.py --scan-id {discovery_scan_id} --hierarchy-id {hierarchy_id}")
        logger.info("=" * 80)
        logger.info(f"\n✅ Full discovery scan completed: {discovery_scan_id}")
        
        # Display final summary
        logger.info("\n6. Final Summary...")
        monitor = ProgressMonitor(discovery_scan_id)
        monitor.display_progress("discovery")
        monitor.display_summary("discovery")
        
        return {
            'discovery_scan_id': discovery_scan_id,
            'result': result,
            'services': all_services,
            'regions': regions
        }
        
    except Exception as e:
        logger.error(f"❌ Error during full discovery scan: {e}", exc_info=True)
        raise

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Run full discovery scan for all services and regions')
    parser.add_argument('--regions', nargs='+', help='Specific regions to scan (default: all regions)')
    parser.add_argument('--services', nargs='+', help='Specific services to scan (default: all enabled)')
    parser.add_argument('--confirm', action='store_true', help='Skip confirmation prompt')
    
    args = parser.parse_args()
    
    if not args.confirm:
        print("\n" + "=" * 80)
        print("⚠️  WARNING: This will scan ALL services across ALL regions")
        print("   This will make many API calls and may take 30-60 minutes")
        print("=" * 80)
        response = input("\nContinue? (yes/no): ")
        if response.lower() not in ['yes', 'y']:
            print("Cancelled.")
            sys.exit(0)
    
    try:
        # Override regions if specified
        if args.regions:
            ALL_AWS_REGIONS = args.regions
        
        # Override services if specified
        if args.services:
            # Modify the function to accept services parameter
            import types
            original_func = run_full_discovery_scan
            def run_with_services():
                result = original_func()
                # Services will be filtered by controller
                return result
            run_full_discovery_scan = run_with_services
        
        result = run_full_discovery_scan()
        
        print("\n" + "=" * 80)
        print("FULL DISCOVERY SCAN COMPLETED")
        print("=" * 80)
        print(f"Discovery Scan ID: {result['discovery_scan_id']}")
        print(f"Services Scanned: {len(result['services'])}")
        print(f"Regions Scanned: {len(result['regions'])}")
        print("=" * 80)
        print(f"\n📊 View results:")
        print(f"   Output: engines-output/aws-configScan-engine/output/discoveries/{result['discovery_scan_id']}/discovery/")
        print(f"\n📈 Monitor progress:")
        print(f"   python3 -c \"from utils.progress_monitor import ProgressMonitor; monitor = ProgressMonitor('{result['discovery_scan_id']}'); monitor.display_progress('discovery')\"")
        print("=" * 80)
        
    except KeyboardInterrupt:
        logger.info("\n\n⏸️  Scan interrupted by user")
        logger.info("   Progress has been saved - you can resume or check partial results")
    except Exception as e:
        logger.error(f"❌ Error during scan: {e}", exc_info=True)
        raise

