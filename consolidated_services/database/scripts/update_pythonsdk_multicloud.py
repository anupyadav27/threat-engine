#!/usr/bin/env python3
"""
Multi-Cloud Python SDK Database Update Script
Updates threat_engine_pythonsdk database with CSV data for ALL CSPs
Connects to RDS Mumbai and updates metadata tables

Usage:
    # Test with dry-run
    python3 update_pythonsdk_multicloud.py --dry-run

    # Run live update
    python3 update_pythonsdk_multicloud.py
"""

import os
import sys
import csv
import json
import psycopg2
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))

try:
    from database.config.database_config import get_shared_config
    USE_SHARED_CONFIG = True
except ImportError:
    print("⚠️  Could not import database config, will use environment variables")
    USE_SHARED_CONFIG = False

# Configuration
THREAT_ENGINE_BASE = "/Users/apple/Desktop/threat-engine"
PYTHON_SDK_DIR = f"{THREAT_ENGINE_BASE}/data_pythonsdk"
CSV_BASE_DIR = "/Users/apple/Desktop/cspm"

# CSP Configuration
CSP_CONFIG = {
    'aws': {
        'csv_file': 'services_resources_arn.csv',
        'csv_dir': 'aws_services_data_fieldandinventories',
        'sdk_dir': 'aws',
        'id_field': 'arn_pattern',
        'id_type': 'arn'
    },
    'azure': {
        'csv_file': 'services_resources_ids.csv',
        'csv_dir': 'azure_services_data_fieldandinventories',
        'sdk_dir': 'azure',
        'id_field': 'resource_id_pattern',
        'id_type': 'resource_id'
    },
    'gcp': {
        'csv_file': 'services_resources_names.csv',
        'csv_dir': 'gcp_services_data_fieldandinventories',
        'sdk_dir': 'gcp',
        'id_field': 'resource_name_pattern',
        'id_type': 'resource_name'
    },
    'oci': {
        'csv_file': 'services_resources_ocids.csv',
        'csv_dir': 'oci_services_data_fieldandinventories',
        'sdk_dir': 'oci',
        'id_field': 'ocid_pattern',
        'id_type': 'ocid'
    },
    'ibm': {
        'csv_file': 'services_resources_crns.csv',
        'csv_dir': 'ibm_services_data_fieldandinventories',
        'sdk_dir': 'ibm',
        'id_field': 'crn_pattern',
        'id_type': 'crn'
    },
    'alibaba': {
        'csv_file': 'services_resources_arns.csv',
        'csv_dir': 'alibaba_services_data_fieldandinventories',
        'sdk_dir': 'alicloud',  # Note: SDK uses 'alicloud'
        'id_field': 'arn_pattern',
        'id_type': 'arn'
    }
}


class MultiCloudDatabaseUpdater:
    """Updates threat_engine_pythonsdk database for multi-cloud support"""

    def __init__(self, dry_run=False):
        self.dry_run = dry_run
        self.db = None
        self.cursor = None
        self.stats = {
            'services': {'inserted': 0, 'updated': 0, 'skipped': 0},
            'operations': {'inserted': 0, 'updated': 0, 'skipped': 0},
            'resource_inventory': {'inserted': 0, 'updated': 0, 'skipped': 0},
            'fields': {'inserted': 0, 'updated': 0, 'skipped': 0},
            'relationship_rules': {'inserted': 0, 'updated': 0, 'skipped': 0}
        }

        if not dry_run:
            self.connect_db()

    def connect_db(self):
        """Connect to RDS PostgreSQL database"""
        try:
            if USE_SHARED_CONFIG:
                # Use consolidated database config
                config = get_shared_config()
                self.db = psycopg2.connect(
                    host=config.host,
                    port=config.port,
                    database=config.database,
                    user=config.username,
                    password=config.password,
                    connect_timeout=30
                )
                print(f"✅ Connected to RDS: {config.host}:{config.port}/{config.database}")
            else:
                # Fallback to environment variables
                self.db = psycopg2.connect(
                    host=os.getenv('SHARED_DB_HOST', 'localhost'),
                    port=int(os.getenv('SHARED_DB_PORT', '5432')),
                    database=os.getenv('SHARED_DB_NAME', 'threat_engine_shared'),
                    user=os.getenv('SHARED_DB_USER', 'shared_user'),
                    password=os.getenv('SHARED_DB_PASSWORD', ''),
                    connect_timeout=30
                )
                print(f"✅ Connected to database using environment variables")

            self.cursor = self.db.cursor()

        except Exception as e:
            print(f"❌ Database connection failed: {e}")
            print("\n💡 Tip: Make sure your database credentials are set:")
            print("   - In .env file, or")
            print("   - In environment variables (SHARED_DB_HOST, SHARED_DB_PORT, etc.)")
            raise

    def close_db(self):
        """Close database connection"""
        if self.cursor:
            self.cursor.close()
        if self.db:
            self.db.close()

    # ========================================
    # STEP 1: Update CSP table
    # ========================================

    def update_csp_table(self):
        """Ensure all CSPs exist in csp table"""
        print("\n" + "="*80)
        print("STEP 1: Updating CSP Table")
        print("="*80)

        csp_data = [
            ('aws', 'Amazon Web Services', 'AWS Cloud Platform', 'boto3'),
            ('azure', 'Microsoft Azure', 'Azure Cloud Platform', 'azure-sdk'),
            ('gcp', 'Google Cloud Platform', 'GCP Cloud Platform', 'google-cloud-sdk'),
            ('oci', 'Oracle Cloud Infrastructure', 'OCI Cloud Platform', 'oci-sdk'),
            ('ibm', 'IBM Cloud', 'IBM Cloud Platform', 'ibm-cloud-sdk'),
            ('alibaba', 'Alibaba Cloud', 'Alibaba Cloud Platform', 'aliyun-python-sdk')
        ]

        for csp_id, csp_name, description, sdk_version in csp_data:
            if self.dry_run:
                print(f"  [DRY RUN] Would upsert CSP: {csp_id}")
                continue

            # Check if exists
            self.cursor.execute(
                "SELECT csp_id FROM csp WHERE csp_id = %s",
                (csp_id,)
            )

            if self.cursor.fetchone():
                # Update
                self.cursor.execute("""
                    UPDATE csp
                    SET csp_name = %s, description = %s, sdk_version = %s, last_updated = NOW()
                    WHERE csp_id = %s
                """, (csp_name, description, sdk_version, csp_id))
                print(f"  ✅ Updated CSP: {csp_id}")
            else:
                # Insert
                self.cursor.execute("""
                    INSERT INTO csp
                    (csp_id, csp_name, description, sdk_version, total_services, last_updated, metadata, created_at)
                    VALUES (%s, %s, %s, %s, 0, NOW(), '{}', NOW())
                """, (csp_id, csp_name, description, sdk_version))
                print(f"  ✅ Inserted CSP: {csp_id}")

        if not self.dry_run:
            self.db.commit()

    # ========================================
    # STEP 2: Add new columns to services table
    # ========================================

    def update_services_schema(self):
        """Add new columns to services table"""
        print("\n" + "="*80)
        print("STEP 2: Updating Services Table Schema")
        print("="*80)

        if self.dry_run:
            print("  [DRY RUN] Would add columns:")
            print("    - resource_types TEXT[]")
            print("    - independent_methods TEXT[]")
            print("    - dependent_methods TEXT[]")
            print("    - data_quality VARCHAR(20)")
            print("    - primary_arn_pattern TEXT")
            print("    - primary_resource_id_pattern TEXT")
            print("    - resource_identifier_type VARCHAR(50)")
            return

        # Add columns one by one to handle existing columns gracefully
        columns_to_add = [
            ("resource_types", "TEXT[]"),
            ("independent_methods", "TEXT[]"),
            ("dependent_methods", "TEXT[]"),
            ("data_quality", "VARCHAR(20)"),
            ("primary_arn_pattern", "TEXT"),
            ("primary_resource_id_pattern", "TEXT"),
            ("resource_identifier_type", "VARCHAR(50)")
        ]

        for col_name, col_type in columns_to_add:
            try:
                sql = f"ALTER TABLE services ADD COLUMN IF NOT EXISTS {col_name} {col_type};"
                self.cursor.execute(sql)
                self.db.commit()
                print(f"  ✅ Added column: {col_name}")
            except Exception as e:
                if "already exists" in str(e):
                    print(f"  ℹ️  Column already exists: {col_name}")
                else:
                    print(f"  ⚠️  Error adding {col_name}: {e}")
                self.db.rollback()

    # ========================================
    # STEP 3: Load CSV data for a CSP
    # ========================================

    def load_csv_services(self, csp: str) -> List[Dict]:
        """Load services from CSV for a CSP"""
        config = CSP_CONFIG.get(csp)
        if not config:
            print(f"  ⚠️  No config for CSP: {csp}")
            return []

        csv_path = os.path.join(CSV_BASE_DIR, config['csv_dir'], config['csv_file'])

        if not os.path.exists(csv_path):
            print(f"  ⚠️  CSV not found: {csv_path}")
            return []

        services = []
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                services.append(row)

        print(f"  📊 Loaded {len(services)} services from CSV")
        return services

    # ========================================
    # STEP 4: Update services table with CSV data
    # ========================================

    def update_services_from_csv(self, csp: str):
        """Update services table from CSV"""
        print(f"\n{'='*80}")
        print(f"STEP 3: Updating Services for {csp.upper()}")
        print("="*80)

        services = self.load_csv_services(csp)
        if not services:
            print(f"  ⚠️  No services to update for {csp}")
            return

        config = CSP_CONFIG[csp]
        inserted = 0
        updated = 0

        for service_row in services:
            service_name = service_row['service'].lower()
            service_id = f"{csp}.{service_name}"

            # Parse CSV data
            resource_types = [service_row.get('resource', service_name.upper())]
            independent_methods = [m.strip() for m in service_row.get('independent_methods', '').split(',') if m.strip()]
            dependent_methods = [m.strip() for m in service_row.get('dependent_methods', '').split(',') if m.strip()]
            data_quality = service_row.get('data_quality', 'basic')
            resource_id_pattern = service_row.get(config['id_field'], '')
            resource_identifier_type = service_row.get('resource_identifiers', config['id_type'])

            total_ops = len(independent_methods) + len(dependent_methods)
            discovery_ops = len(independent_methods)

            if self.dry_run:
                if inserted + updated < 3:  # Show first 3
                    print(f"  [DRY RUN] Would upsert: {service_id} ({discovery_ops} discovery, {len(dependent_methods)} enrichment)")
                continue

            # Check if exists
            self.cursor.execute(
                "SELECT service_id FROM services WHERE service_id = %s",
                (service_id,)
            )
            exists = self.cursor.fetchone()

            if exists:
                # Update
                if csp == 'aws':
                    sql = """
                    UPDATE services
                    SET
                        resource_types = %s,
                        independent_methods = %s,
                        dependent_methods = %s,
                        data_quality = %s,
                        primary_arn_pattern = %s,
                        resource_identifier_type = %s,
                        total_operations = %s,
                        discovery_operations = %s,
                        last_updated = NOW()
                    WHERE service_id = %s
                    """
                    self.cursor.execute(sql, (
                        resource_types,
                        independent_methods,
                        dependent_methods,
                        data_quality,
                        resource_id_pattern,
                        resource_identifier_type,
                        total_ops,
                        discovery_ops,
                        service_id
                    ))
                else:
                    sql = """
                    UPDATE services
                    SET
                        resource_types = %s,
                        independent_methods = %s,
                        dependent_methods = %s,
                        data_quality = %s,
                        primary_resource_id_pattern = %s,
                        resource_identifier_type = %s,
                        total_operations = %s,
                        discovery_operations = %s,
                        last_updated = NOW()
                    WHERE service_id = %s
                    """
                    self.cursor.execute(sql, (
                        resource_types,
                        independent_methods,
                        dependent_methods,
                        data_quality,
                        resource_id_pattern,
                        resource_identifier_type,
                        total_ops,
                        discovery_ops,
                        service_id
                    ))

                updated += 1

            else:
                # Insert
                if csp == 'aws':
                    sql = """
                    INSERT INTO services (
                        service_id, csp_id, service_name, resource_types,
                        independent_methods, dependent_methods, data_quality,
                        primary_arn_pattern, resource_identifier_type,
                        total_operations, discovery_operations, created_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                    """
                    self.cursor.execute(sql, (
                        service_id, csp, service_name, resource_types,
                        independent_methods, dependent_methods, data_quality,
                        resource_id_pattern, resource_identifier_type,
                        total_ops, discovery_ops
                    ))
                else:
                    sql = """
                    INSERT INTO services (
                        service_id, csp_id, service_name, resource_types,
                        independent_methods, dependent_methods, data_quality,
                        primary_resource_id_pattern, resource_identifier_type,
                        total_operations, discovery_operations, created_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                    """
                    self.cursor.execute(sql, (
                        service_id, csp, service_name, resource_types,
                        independent_methods, dependent_methods, data_quality,
                        resource_id_pattern, resource_identifier_type,
                        total_ops, discovery_ops
                    ))

                inserted += 1

        if not self.dry_run:
            self.db.commit()
            print(f"  ✅ Inserted: {inserted}, Updated: {updated}")
        else:
            print(f"  [DRY RUN] Would insert: ~{len(services) // 2}, update: ~{len(services) // 2}")

        self.stats['services']['inserted'] += inserted
        self.stats['services']['updated'] += updated

    # ========================================
    # STEP 5: Update operations table
    # ========================================

    def update_operations_from_csv(self, csp: str):
        """Update operations table from CSV"""
        print(f"\nSTEP 4: Updating Operations for {csp.upper()}")
        print("-" * 80)

        services = self.load_csv_services(csp)
        if not services:
            return

        inserted = 0
        skipped = 0

        for service_row in services:
            service_name = service_row['service'].lower()
            service_id = f"{csp}.{service_name}"

            # Independent operations
            independent_methods = [m.strip() for m in service_row.get('independent_methods', '').split(',') if m.strip()]
            for method in independent_methods:
                if self.dry_run:
                    inserted += 1
                    continue

                # Check if exists
                self.cursor.execute(
                    "SELECT id FROM operations WHERE service_id = %s AND python_method = %s",
                    (service_id, method)
                )

                if self.cursor.fetchone():
                    skipped += 1
                    continue

                # Insert
                operation_name = ''.join(word.capitalize() for word in method.split('_'))

                sql = """
                INSERT INTO operations (
                    service_id, operation_name, python_method, operation_type,
                    is_discovery, is_root_operation, created_at, updated_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, NOW(), NOW())
                """

                self.cursor.execute(sql, (
                    service_id,
                    operation_name,
                    method,
                    'independent',
                    True,
                    True
                ))
                inserted += 1

            # Dependent operations
            dependent_methods = [m.strip() for m in service_row.get('dependent_methods', '').split(',') if m.strip()]
            for method in dependent_methods:
                if self.dry_run:
                    inserted += 1
                    continue

                # Check if exists
                self.cursor.execute(
                    "SELECT id FROM operations WHERE service_id = %s AND python_method = %s",
                    (service_id, method)
                )

                if self.cursor.fetchone():
                    skipped += 1
                    continue

                # Insert
                operation_name = ''.join(word.capitalize() for word in method.split('_'))

                sql = """
                INSERT INTO operations (
                    service_id, operation_name, python_method, operation_type,
                    is_discovery, is_root_operation, created_at, updated_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, NOW(), NOW())
                """

                self.cursor.execute(sql, (
                    service_id,
                    operation_name,
                    method,
                    'dependent',
                    False,
                    False
                ))
                inserted += 1

        if not self.dry_run:
            self.db.commit()

        print(f"  ✅ Inserted: {inserted}, Skipped: {skipped} existing")

        self.stats['operations']['inserted'] += inserted
        self.stats['operations']['skipped'] += skipped

    # ========================================
    # STEP 6: Update resource_inventory from Python SDK
    # ========================================

    def update_resource_inventory(self, csp: str):
        """Update resource_inventory from Python SDK resource_inventory_report.json"""
        print(f"\nSTEP 5: Updating Resource Inventory for {csp.upper()}")
        print("-" * 80)

        sdk_dir = os.path.join(PYTHON_SDK_DIR, CSP_CONFIG[csp]['sdk_dir'])
        if not os.path.exists(sdk_dir):
            print(f"  ⚠️  Python SDK directory not found: {sdk_dir}")
            return

        inserted = 0
        updated = 0
        skipped = 0

        # Iterate through all service directories
        for service_dir in Path(sdk_dir).iterdir():
            if not service_dir.is_dir():
                continue

            service_name = service_dir.name
            service_id = f"{csp}.{service_name}"

            # Check for resource_inventory_report.json
            inventory_file = service_dir / 'resource_inventory_report.json'
            if not inventory_file.exists():
                skipped += 1
                continue

            try:
                with open(inventory_file, 'r', encoding='utf-8') as f:
                    inventory_data = json.load(f)

                if self.dry_run:
                    inserted += 1
                    continue

                # Extract data
                resources = inventory_data.get('resources', [])
                total_resource_types = len(resources)
                total_operations = len(inventory_data.get('all_operations', []))
                discovery_operations = len([r for r in resources if r.get('root_operations')])

                # Check if exists
                self.cursor.execute(
                    "SELECT id FROM resource_inventory WHERE service_id = %s",
                    (service_id,)
                )
                exists = self.cursor.fetchone()

                if exists:
                    # Update
                    sql = """
                    UPDATE resource_inventory
                    SET
                        inventory_data = %s,
                        total_resource_types = %s,
                        total_operations = %s,
                        discovery_operations = %s,
                        version = 1.0,
                        generated_at = NOW(),
                        updated_at = NOW()
                    WHERE service_id = %s
                    """
                    self.cursor.execute(sql, (
                        json.dumps(inventory_data),
                        total_resource_types,
                        total_operations,
                        discovery_operations,
                        service_id
                    ))
                    updated += 1
                else:
                    # Insert
                    sql = """
                    INSERT INTO resource_inventory (
                        service_id, inventory_data, total_resource_types,
                        total_operations, discovery_operations, version,
                        generated_at, created_at, updated_at
                    )
                    VALUES (%s, %s, %s, %s, %s, 1.0, NOW(), NOW(), NOW())
                    """
                    self.cursor.execute(sql, (
                        service_id,
                        json.dumps(inventory_data),
                        total_resource_types,
                        total_operations,
                        discovery_operations
                    ))
                    inserted += 1

            except Exception as e:
                print(f"  ⚠️  Error processing {service_id}: {e}")
                continue

        if not self.dry_run:
            self.db.commit()

        print(f"  ✅ Inserted: {inserted}, Updated: {updated}, Skipped: {skipped}")

        self.stats['resource_inventory']['inserted'] += inserted
        self.stats['resource_inventory']['updated'] += updated
        self.stats['resource_inventory']['skipped'] += skipped

    # ========================================
    # MAIN EXECUTION
    # ========================================

    def update_all_csps(self):
        """Update all CSPs in database"""
        print("\n" + "="*80)
        print("MULTI-CLOUD DATABASE UPDATE")
        print("="*80)
        print(f"Mode: {'🔍 DRY RUN (no changes)' if self.dry_run else '⚠️  LIVE UPDATE'}")
        print(f"Target CSPs: {', '.join(CSP_CONFIG.keys())}")
        print(f"RDS Location: Mumbai")
        print("="*80)

        # Step 1: Update CSP table
        self.update_csp_table()

        # Step 2: Update services schema
        self.update_services_schema()

        # Step 3-6: Update each CSP
        for csp in CSP_CONFIG.keys():
            self.update_services_from_csv(csp)
            self.update_operations_from_csv(csp)
            self.update_resource_inventory(csp)

        # Print summary
        self.print_summary()

    def print_summary(self):
        """Print update summary"""
        print("\n" + "="*80)
        print("📊 UPDATE SUMMARY")
        print("="*80)

        for table, stats in self.stats.items():
            total = stats['inserted'] + stats['updated']
            if total > 0:
                print(f"\n{table.upper().replace('_', ' ')}:")
                print(f"  Inserted: {stats['inserted']:,}")
                print(f"  Updated:  {stats['updated']:,}")
                if stats['skipped'] > 0:
                    print(f"  Skipped:  {stats['skipped']:,}")

        print("\n" + "="*80)
        if self.dry_run:
            print("✅ DRY RUN COMPLETE - No changes made to database")
            print("\n💡 To apply these changes, run without --dry-run flag")
        else:
            print("✅ DATABASE UPDATE COMPLETE")
            print("\n🎯 Next Steps:")
            print("   1. Verify updates with SQL queries")
            print("   2. Update inventory engine code")
            print("   3. Test with single service")
        print("="*80)


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Update Python SDK database for multi-cloud')
    parser.add_argument('--dry-run', '-n', action='store_true', help='Run in dry-run mode (no changes)')
    args = parser.parse_args()

    if args.dry_run:
        print("\n🔍 Running in DRY RUN mode - no changes will be made to database\n")
    else:
        print("\n⚠️  Running in LIVE mode - database will be updated!")
        print("   Press Ctrl+C within 5 seconds to cancel...")
        import time
        try:
            for i in range(5, 0, -1):
                print(f"   {i}...")
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n\n✋ Cancelled by user")
            sys.exit(0)
        print()

    # Run updater
    updater = MultiCloudDatabaseUpdater(dry_run=args.dry_run)

    try:
        updater.update_all_csps()
    except KeyboardInterrupt:
        print("\n\n⚠️  Update cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        if updater.db:
            updater.close_db()


if __name__ == "__main__":
    main()
