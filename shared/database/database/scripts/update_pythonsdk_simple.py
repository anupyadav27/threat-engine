#!/usr/bin/env python3
"""
Simplified Multi-Cloud Python SDK Database Update Script - Fixed for duplicates
"""

import os
import sys
import csv
import json
import psycopg2
from pathlib import Path
from typing import Dict, List

THREAT_ENGINE_BASE = "/Users/apple/Desktop/threat-engine"
PYTHON_SDK_DIR = f"{THREAT_ENGINE_BASE}/data_pythonsdk"
CSV_BASE_DIR = "/Users/apple/Desktop/cspm"

CSP_CONFIG = {
    'aws': {'csv_file': 'services_resources_arn.csv', 'csv_dir': 'aws_services_data_fieldandinventories', 'sdk_dir': 'aws', 'id_field': 'arn_pattern', 'id_type': 'arn'},
    'azure': {'csv_file': 'services_resources_ids.csv', 'csv_dir': 'azure_services_data_fieldandinventories', 'sdk_dir': 'azure', 'id_field': 'resource_id_pattern', 'id_type': 'resource_id'},
    'gcp': {'csv_file': 'services_resources_names.csv', 'csv_dir': 'gcp_services_data_fieldandinventories', 'sdk_dir': 'gcp', 'id_field': 'resource_name_pattern', 'id_type': 'resource_name'},
    'oci': {'csv_file': 'services_resources_ocids.csv', 'csv_dir': 'oci_services_data_fieldandinventories', 'sdk_dir': 'oci', 'id_field': 'ocid_pattern', 'id_type': 'ocid'},
    'ibm': {'csv_file': 'services_resources_crns.csv', 'csv_dir': 'ibm_services_data_fieldandinventories', 'sdk_dir': 'ibm', 'id_field': 'crn_pattern', 'id_type': 'crn'},
    'alibaba': {'csv_file': 'services_resources_arns.csv', 'csv_dir': 'alibaba_services_data_fieldandinventories', 'sdk_dir': 'alicloud', 'id_field': 'arn_pattern', 'id_type': 'arn'}
}


class DatabaseUpdater:
    def __init__(self, host, port, database, user, password, dry_run=False):
        self.dry_run = dry_run
        self.db = None
        self.cursor = None
        self.stats = {
            'services': {'inserted': 0, 'updated': 0},
            'operations': {'inserted': 0, 'skipped': 0},
            'resource_inventory': {'inserted': 0, 'updated': 0}
        }

        if not dry_run:
            try:
                self.db = psycopg2.connect(
                    host=host, port=port, database=database,
                    user=user, password=password, connect_timeout=30
                )
                self.cursor = self.db.cursor()
                print(f"✅ Connected to: {host}:{port}/{database}")
            except Exception as e:
                print(f"❌ Connection failed: {e}")
                raise

    def close(self):
        if self.cursor:
            self.cursor.close()
        if self.db:
            self.db.close()

    def update_csp_table(self):
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

            self.cursor.execute("SELECT csp_id FROM csp WHERE csp_id = %s", (csp_id,))
            if self.cursor.fetchone():
                self.cursor.execute("""
                    UPDATE csp SET csp_name = %s, description = %s, sdk_version = %s, last_updated = NOW()
                    WHERE csp_id = %s
                """, (csp_name, description, sdk_version, csp_id))
                print(f"  ✅ Updated CSP: {csp_id}")
            else:
                self.cursor.execute("""
                    INSERT INTO csp (csp_id, csp_name, description, sdk_version, total_services, last_updated, metadata, created_at)
                    VALUES (%s, %s, %s, %s, 0, NOW(), '{}', NOW())
                """, (csp_id, csp_name, description, sdk_version))
                print(f"  ✅ Inserted CSP: {csp_id}")

        if not self.dry_run:
            self.db.commit()

    def update_services_schema(self):
        print("\n" + "="*80)
        print("STEP 2: Updating Services Table Schema")
        print("="*80)

        columns = [
            ("resource_types", "TEXT[]"),
            ("independent_methods", "TEXT[]"),
            ("dependent_methods", "TEXT[]"),
            ("data_quality", "VARCHAR(20)"),
            ("primary_arn_pattern", "TEXT"),
            ("primary_resource_id_pattern", "TEXT"),
            ("resource_identifier_type", "VARCHAR(50)")
        ]

        if self.dry_run:
            for col_name, col_type in columns:
                print(f"  [DRY RUN] Would add column: {col_name} {col_type}")
            return

        for col_name, col_type in columns:
            try:
                self.cursor.execute(f"ALTER TABLE services ADD COLUMN IF NOT EXISTS {col_name} {col_type};")
                self.db.commit()
                print(f"  ✅ Added column: {col_name}")
            except Exception as e:
                if "already exists" in str(e):
                    print(f"  ℹ️  Column exists: {col_name}")
                else:
                    print(f"  ⚠️  Error: {col_name}: {e}")
                self.db.rollback()

    def load_csv_services(self, csp: str) -> List[Dict]:
        config = CSP_CONFIG.get(csp)
        if not config:
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
        return services

    def update_services_from_csv(self, csp: str):
        print(f"\n{'='*80}")
        print(f"STEP 3: Updating Services for {csp.upper()}")
        print("="*80)

        services = self.load_csv_services(csp)
        if not services:
            return

        print(f"  📊 Processing {len(services)} services...")
        config = CSP_CONFIG[csp]
        inserted, updated = 0, 0

        for service_row in services:
            service_name = service_row['service'].lower()
            service_id = f"{csp}.{service_name}"

            resource_types = [service_row.get('resource', service_name.upper())]
            independent_methods = [m.strip() for m in service_row.get('independent_methods', '').split(',') if m.strip()]
            dependent_methods = [m.strip() for m in service_row.get('dependent_methods', '').split(',') if m.strip()]
            data_quality = service_row.get('data_quality', 'basic')
            resource_id_pattern = service_row.get(config['id_field'], '')
            resource_identifier_type = service_row.get('resource_identifiers', config['id_type'])

            if self.dry_run:
                continue

            self.cursor.execute("SELECT service_id FROM services WHERE service_id = %s", (service_id,))
            exists = self.cursor.fetchone()

            if exists:
                if csp == 'aws':
                    self.cursor.execute("""
                        UPDATE services SET resource_types = %s, independent_methods = %s, dependent_methods = %s,
                        data_quality = %s, primary_arn_pattern = %s, resource_identifier_type = %s,
                        total_operations = %s, discovery_operations = %s, last_updated = NOW()
                        WHERE service_id = %s
                    """, (resource_types, independent_methods, dependent_methods, data_quality,
                          resource_id_pattern, resource_identifier_type,
                          len(independent_methods) + len(dependent_methods), len(independent_methods), service_id))
                else:
                    self.cursor.execute("""
                        UPDATE services SET resource_types = %s, independent_methods = %s, dependent_methods = %s,
                        data_quality = %s, primary_resource_id_pattern = %s, resource_identifier_type = %s,
                        total_operations = %s, discovery_operations = %s, last_updated = NOW()
                        WHERE service_id = %s
                    """, (resource_types, independent_methods, dependent_methods, data_quality,
                          resource_id_pattern, resource_identifier_type,
                          len(independent_methods) + len(dependent_methods), len(independent_methods), service_id))
                updated += 1
            else:
                if csp == 'aws':
                    self.cursor.execute("""
                        INSERT INTO services (service_id, csp_id, service_name, resource_types, independent_methods,
                        dependent_methods, data_quality, primary_arn_pattern, resource_identifier_type,
                        total_operations, discovery_operations, created_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                    """, (service_id, csp, service_name, resource_types, independent_methods, dependent_methods,
                          data_quality, resource_id_pattern, resource_identifier_type,
                          len(independent_methods) + len(dependent_methods), len(independent_methods)))
                else:
                    self.cursor.execute("""
                        INSERT INTO services (service_id, csp_id, service_name, resource_types, independent_methods,
                        dependent_methods, data_quality, primary_resource_id_pattern, resource_identifier_type,
                        total_operations, discovery_operations, created_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                    """, (service_id, csp, service_name, resource_types, independent_methods, dependent_methods,
                          data_quality, resource_id_pattern, resource_identifier_type,
                          len(independent_methods) + len(dependent_methods), len(independent_methods)))
                inserted += 1

        if not self.dry_run:
            self.db.commit()
            print(f"  ✅ Inserted: {inserted}, Updated: {updated}")
        self.stats['services']['inserted'] += inserted
        self.stats['services']['updated'] += updated

    def update_operations_from_csv(self, csp: str):
        print(f"\nSTEP 4: Updating Operations for {csp.upper()}")
        print("-" * 80)

        services = self.load_csv_services(csp)
        if not services:
            return

        inserted, skipped = 0, 0
        for service_row in services:
            service_name = service_row['service'].lower()
            service_id = f"{csp}.{service_name}"

            for method in [m.strip() for m in service_row.get('independent_methods', '').split(',') if m.strip()]:
                if self.dry_run:
                    inserted += 1
                    continue

                # Use INSERT ON CONFLICT to handle duplicates
                operation_name = ''.join(word.capitalize() for word in method.split('_'))
                try:
                    self.cursor.execute("""
                        INSERT INTO operations (service_id, operation_name, python_method, operation_type,
                        is_discovery, is_root_operation, created_at, updated_at)
                        VALUES (%s, %s, %s, %s, %s, %s, NOW(), NOW())
                        ON CONFLICT (service_id, operation_name) DO UPDATE
                        SET python_method = EXCLUDED.python_method,
                            operation_type = EXCLUDED.operation_type,
                            is_discovery = EXCLUDED.is_discovery,
                            updated_at = NOW()
                    """, (service_id, operation_name, method, 'independent', True, True))
                    inserted += 1
                except Exception as e:
                    if "duplicate" in str(e).lower():
                        skipped += 1
                    else:
                        print(f"  ⚠️  Error inserting {service_id}.{operation_name}: {e}")

            for method in [m.strip() for m in service_row.get('dependent_methods', '').split(',') if m.strip()]:
                if self.dry_run:
                    inserted += 1
                    continue

                operation_name = ''.join(word.capitalize() for word in method.split('_'))
                try:
                    self.cursor.execute("""
                        INSERT INTO operations (service_id, operation_name, python_method, operation_type,
                        is_discovery, is_root_operation, created_at, updated_at)
                        VALUES (%s, %s, %s, %s, %s, %s, NOW(), NOW())
                        ON CONFLICT (service_id, operation_name) DO UPDATE
                        SET python_method = EXCLUDED.python_method,
                            operation_type = EXCLUDED.operation_type,
                            is_discovery = EXCLUDED.is_discovery,
                            updated_at = NOW()
                    """, (service_id, operation_name, method, 'dependent', False, False))
                    inserted += 1
                except Exception as e:
                    if "duplicate" in str(e).lower():
                        skipped += 1
                    else:
                        print(f"  ⚠️  Error inserting {service_id}.{operation_name}: {e}")

        if not self.dry_run:
            self.db.commit()
        print(f"  ✅ Inserted/Updated: {inserted}, Skipped: {skipped}")
        self.stats['operations']['inserted'] += inserted
        self.stats['operations']['skipped'] += skipped

    def update_resource_inventory(self, csp: str):
        print(f"\nSTEP 5: Updating Resource Inventory for {csp.upper()}")
        print("-" * 80)

        sdk_dir = os.path.join(PYTHON_SDK_DIR, CSP_CONFIG[csp]['sdk_dir'])
        if not os.path.exists(sdk_dir):
            print(f"  ⚠️  SDK directory not found: {sdk_dir}")
            return

        inserted, updated = 0, 0
        for service_dir in Path(sdk_dir).iterdir():
            if not service_dir.is_dir():
                continue

            inventory_file = service_dir / 'resource_inventory_report.json'
            if not inventory_file.exists():
                continue

            try:
                with open(inventory_file, 'r', encoding='utf-8') as f:
                    inventory_data = json.load(f)

                service_id = f"{csp}.{service_dir.name}"
                if self.dry_run:
                    inserted += 1
                    continue

                self.cursor.execute("SELECT id FROM resource_inventory WHERE service_id = %s", (service_id,))
                exists = self.cursor.fetchone()

                if exists:
                    self.cursor.execute("""
                        UPDATE resource_inventory SET inventory_data = %s, total_resource_types = %s,
                        total_operations = %s, discovery_operations = %s, version = 1.0,
                        generated_at = NOW(), updated_at = NOW() WHERE service_id = %s
                    """, (json.dumps(inventory_data), len(inventory_data.get('resources', [])),
                          len(inventory_data.get('all_operations', [])),
                          len([r for r in inventory_data.get('resources', []) if r.get('root_operations')]),
                          service_id))
                    updated += 1
                else:
                    self.cursor.execute("""
                        INSERT INTO resource_inventory (service_id, inventory_data, total_resource_types,
                        total_operations, discovery_operations, version, generated_at, created_at, updated_at)
                        VALUES (%s, %s, %s, %s, %s, 1.0, NOW(), NOW(), NOW())
                    """, (service_id, json.dumps(inventory_data), len(inventory_data.get('resources', [])),
                          len(inventory_data.get('all_operations', [])),
                          len([r for r in inventory_data.get('resources', []) if r.get('root_operations')])))
                    inserted += 1
            except:
                continue

        if not self.dry_run:
            self.db.commit()
        print(f"  ✅ Inserted: {inserted}, Updated: {updated}")
        self.stats['resource_inventory']['inserted'] += inserted
        self.stats['resource_inventory']['updated'] += updated

    def run(self):
        print("\n" + "="*80)
        print("MULTI-CLOUD DATABASE UPDATE")
        print("="*80)
        print(f"Mode: {'🔍 DRY RUN' if self.dry_run else '⚠️  LIVE UPDATE'}")
        print("="*80)

        self.update_csp_table()
        self.update_services_schema()

        for csp in CSP_CONFIG.keys():
            self.update_services_from_csv(csp)
            self.update_operations_from_csv(csp)
            self.update_resource_inventory(csp)

        print("\n" + "="*80)
        print("📊 SUMMARY")
        print("="*80)
        print(f"Services: Inserted {self.stats['services']['inserted']}, Updated {self.stats['services']['updated']}")
        print(f"Operations: Inserted/Updated {self.stats['operations']['inserted']}, Skipped {self.stats['operations']['skipped']}")
        print(f"Resource Inventory: Inserted {self.stats['resource_inventory']['inserted']}, Updated {self.stats['resource_inventory']['updated']}")
        print("="*80)


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--dry-run', '-n', action='store_true')
    parser.add_argument('--host', default=os.getenv('SHARED_DB_HOST', 'localhost'))
    parser.add_argument('--port', type=int, default=int(os.getenv('SHARED_DB_PORT', '5432')))
    parser.add_argument('--database', default=os.getenv('SHARED_DB_NAME', 'threat_engine_shared'))
    parser.add_argument('--user', default=os.getenv('SHARED_DB_USER', 'shared_user'))
    parser.add_argument('--password', default=os.getenv('SHARED_DB_PASSWORD', ''))
    args = parser.parse_args()

    if not args.dry_run and not args.password:
        print("❌ Error: Password required for live update")
        print("   Use --password or set SHARED_DB_PASSWORD environment variable")
        sys.exit(1)

    updater = DatabaseUpdater(args.host, args.port, args.database, args.user, args.password, args.dry_run)
    try:
        updater.run()
    finally:
        updater.close()


if __name__ == "__main__":
    main()
