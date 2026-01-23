#!/usr/bin/env python3
"""
Standalone script to upload scan results from NDJSON files to database
"""
import os
import sys
import argparse
import logging
from pathlib import Path

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from engine.database_manager import DatabaseManager
from engine.database_upload_engine import DatabaseUploadEngine

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

def main():
    parser = argparse.ArgumentParser(
        description='Upload scan results from NDJSON files to database'
    )
    parser.add_argument(
        '--scan-id',
        required=True,
        help='Scan ID to upload'
    )
    parser.add_argument(
        '--output-dir',
        type=Path,
        default=Path('/Users/apple/Desktop/threat-engine/engines-output/aws-configScan-engine/output'),
        help='Base output directory (default: engines-output/aws-configScan-engine/output)'
    )
    parser.add_argument(
        '--customer-id',
        default='default-customer',
        help='Customer ID (default: default-customer)'
    )
    parser.add_argument(
        '--tenant-id',
        default='default-tenant',
        help='Tenant ID (default: default-tenant)'
    )
    parser.add_argument(
        '--provider',
        default='aws',
        help='Provider name (default: aws)'
    )
    parser.add_argument(
        '--hierarchy-id',
        required=True,
        help='Hierarchy ID (e.g., account_id)'
    )
    parser.add_argument(
        '--hierarchy-type',
        default='account',
        help='Hierarchy type (default: account)'
    )
    
    args = parser.parse_args()
    
    # Find scan directory
    discovery_dir = args.output_dir / "discovery"
    scan_dirs = [d for d in discovery_dir.iterdir() if d.is_dir() and args.scan_id in d.name]
    
    if not scan_dirs:
        logger.error(f"No scan directory found for scan_id: {args.scan_id}")
        logger.info(f"Available scans in {discovery_dir}:")
        for d in sorted(discovery_dir.iterdir()):
            if d.is_dir():
                logger.info(f"  - {d.name}")
        sys.exit(1)
    
    if len(scan_dirs) > 1:
        logger.warning(f"Multiple scan directories found, using: {scan_dirs[0]}")
    
    scan_dir = scan_dirs[0]
    logger.info(f"Using scan directory: {scan_dir}")
    
    try:
        # Initialize database
        logger.info("Initializing database connection...")
        db_manager = DatabaseManager()
        logger.info("✅ Database connection established")
        
        # Create customer and tenant if they don't exist
        try:
            db_manager.create_customer(args.customer_id, customer_name="Upload Customer")
            logger.info(f"✅ Customer created: {args.customer_id}")
        except Exception as e:
            logger.debug(f"Customer may already exist: {e}")
        
        try:
            db_manager.create_tenant(
                args.tenant_id,
                args.customer_id,
                args.provider,
                tenant_name="Upload Tenant"
            )
            logger.info(f"✅ Tenant created: {args.tenant_id}")
        except Exception as e:
            logger.debug(f"Tenant may already exist: {e}")
        
        # Register hierarchy if needed
        try:
            db_manager.register_hierarchy(
                tenant_id=args.tenant_id,
                provider=args.provider,
                hierarchy_type=args.hierarchy_type,
                hierarchy_id=args.hierarchy_id,
                hierarchy_name=f"{args.provider.upper()} {args.hierarchy_type.title()} {args.hierarchy_id}"
            )
            logger.info(f"✅ Hierarchy registered: {args.hierarchy_id}")
        except Exception as e:
            logger.debug(f"Hierarchy may already exist: {e}")
        
        # Initialize upload engine
        logger.info("Initializing upload engine...")
        upload_engine = DatabaseUploadEngine(db_manager)
        
        # Upload scan results
        logger.info("=" * 80)
        logger.info("UPLOADING SCAN RESULTS TO DATABASE")
        logger.info("=" * 80)
        logger.info(f"Scan ID: {args.scan_id}")
        logger.info(f"Customer: {args.customer_id}")
        logger.info(f"Tenant: {args.tenant_id}")
        logger.info(f"Provider: {args.provider}")
        logger.info(f"Hierarchy: {args.hierarchy_id} ({args.hierarchy_type})")
        logger.info(f"Output Directory: {scan_dir}")
        logger.info("=" * 80)
        
        stats = upload_engine.upload_scan_to_database(
            scan_id=args.scan_id,
            output_dir=scan_dir,
            customer_id=args.customer_id,
            tenant_id=args.tenant_id,
            provider=args.provider,
            hierarchy_id=args.hierarchy_id,
            hierarchy_type=args.hierarchy_type
        )
        
        # Print summary
        logger.info("=" * 80)
        logger.info("UPLOAD SUMMARY")
        logger.info("=" * 80)
        logger.info(f"Total Files: {stats['total_files']}")
        logger.info(f"Total Records: {stats['total_records']:,}")
        logger.info(f"Total Uploaded: {stats['total_uploaded']:,}")
        logger.info(f"Errors: {len(stats['errors'])}")
        
        if stats['by_service']:
            logger.info("\nBy Service:")
            for service, svc_stats in sorted(stats['by_service'].items()):
                logger.info(f"  {service}: {svc_stats['uploaded']:,}/{svc_stats['records']:,} records")
        
        if stats['errors']:
            logger.warning("\nErrors:")
            for error in stats['errors']:
                logger.warning(f"  {error['file']}: {error['error']}")
        
        logger.info("=" * 80)
        logger.info("✅ Upload completed successfully!")
        
    except Exception as e:
        logger.error(f"Upload failed: {e}", exc_info=True)
        sys.exit(1)

if __name__ == '__main__':
    main()

