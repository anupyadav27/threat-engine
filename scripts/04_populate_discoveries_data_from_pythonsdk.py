#!/usr/bin/env python3
"""
Populate discoveries_data column from YAML files in data_pythonsdk directory
"""
import os
import yaml
import json
import psycopg2
from pathlib import Path
from typing import Dict, List

# Database connection config
CHECK_DB_CONFIG = {
    'host': os.getenv('CHECK_DB_HOST', 'localhost'),
    'port': int(os.getenv('CHECK_DB_PORT', '5432')),
    'database': os.getenv('CHECK_DB_NAME', 'threat_engine_check'),
    'user': os.getenv('CHECK_DB_USER', 'check_user'),
    'password': os.getenv('CHECK_DB_PASSWORD', '')
}

def find_discovery_yaml_files(base_path: str) -> Dict[str, List[Path]]:
    """Find all *_discovery.yaml files organized by CSP"""

    discovery_files = {
        'aws': [],
        'azure': [],
        'gcp': [],
        'oci': [],
        'alicloud': []
    }

    base = Path(base_path)

    # Find AWS files
    aws_dir = base / 'aws'
    if aws_dir.exists():
        discovery_files['aws'] = list(aws_dir.glob('*/*_discovery.yaml'))
        # Exclude .backup files
        discovery_files['aws'] = [f for f in discovery_files['aws'] if not str(f).endswith('.backup')]

    # Find Azure files
    azure_dir = base / 'azure'
    if azure_dir.exists():
        discovery_files['azure'] = list(azure_dir.glob('*/*_discovery.yaml'))
        discovery_files['azure'] = [f for f in discovery_files['azure'] if not str(f).endswith('.backup')]

    # Find GCP files
    gcp_dir = base / 'gcp'
    if gcp_dir.exists():
        discovery_files['gcp'] = list(gcp_dir.glob('*/*_discovery.yaml'))
        discovery_files['gcp'] = [f for f in discovery_files['gcp'] if not str(f).endswith('.backup')]

    # Find OCI files
    oci_dir = base / 'oci'
    if oci_dir.exists():
        discovery_files['oci'] = list(oci_dir.glob('*/*_discovery.yaml'))
        discovery_files['oci'] = [f for f in discovery_files['oci'] if not str(f).endswith('.backup')]

    # Find AliCloud files
    alicloud_dir = base / 'alicloud'
    if alicloud_dir.exists():
        discovery_files['alicloud'] = list(alicloud_dir.glob('*/*_discovery.yaml'))
        discovery_files['alicloud'] = [f for f in discovery_files['alicloud'] if not str(f).endswith('.backup')]

    return discovery_files

def populate_discoveries_data():
    """Parse YAML files and populate discoveries_data column"""

    # Base path to YAML files
    base_path = "/Users/apple/Desktop/data_pythonsdk"

    # Find all discovery YAML files
    discovery_files = find_discovery_yaml_files(base_path)

    print("=== Discovery YAML Files Found ===")
    for csp, files in discovery_files.items():
        print(f"{csp.upper()}: {len(files)} files")
    print()

    # Connect to database
    conn = psycopg2.connect(**CHECK_DB_CONFIG)
    cur = conn.cursor()

    total_updated = 0
    total_errors = 0
    total_skipped = 0

    # Process each CSP
    for provider, files in discovery_files.items():
        if not files:
            continue

        print(f"\n=== Processing {provider.upper()} ({len(files)} services) ===")

        for yaml_file in files:
            try:
                # Extract service name from filename
                # e.g., accessanalyzer_discovery.yaml → accessanalyzer
                service = yaml_file.stem.replace('_discovery', '')

                # Load YAML content
                with open(yaml_file, 'r') as f:
                    yaml_content = yaml.safe_load(f)

                # Skip if empty
                if not yaml_content:
                    print(f"⚠ {service}: Empty YAML, skipping")
                    total_skipped += 1
                    continue

                # Convert to JSON string for JSONB
                json_content = json.dumps(yaml_content)

                # Update discoveries_data column
                cur.execute("""
                    UPDATE rule_discoveries
                    SET discoveries_data = %s::jsonb,
                        updated_at = NOW()
                    WHERE service = %s AND provider = %s
                """, (json_content, service, provider))

                if cur.rowcount > 0:
                    total_updated += 1
                    print(f"✓ {service}: Updated ({len(json_content)} bytes)")
                else:
                    total_skipped += 1
                    print(f"⚠ {service}: No matching row in database")

            except yaml.YAMLError as e:
                total_errors += 1
                print(f"✗ {yaml_file.name}: YAML parse error - {e}")
            except Exception as e:
                total_errors += 1
                print(f"✗ {yaml_file.name}: Error - {e}")

        # Commit after each CSP
        conn.commit()
        print(f"✓ Committed {provider.upper()} updates")

    # Close connection
    cur.close()
    conn.close()

    # Summary
    print("\n" + "="*60)
    print("=== Final Summary ===")
    print(f"Total services updated: {total_updated}")
    print(f"Total services skipped: {total_skipped}")
    print(f"Total errors: {total_errors}")
    print(f"Total YAML files processed: {total_updated + total_skipped + total_errors}")
    print("="*60)

if __name__ == "__main__":
    populate_discoveries_data()
