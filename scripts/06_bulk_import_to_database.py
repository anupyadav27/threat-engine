#!/usr/bin/env python3
"""
Bulk import rule_discoveries data from CSV/NDJSON into PostgreSQL database.

This script:
1. Truncates existing rule_discoveries table (optional)
2. Bulk imports all 1,303 services from extracted data
3. Updates JSONB columns properly
4. Creates proper indexes
"""
import os
import json
import csv
import psycopg2
from psycopg2.extras import execute_values
from datetime import datetime

# Database connection config
CHECK_DB_CONFIG = {
    'host': os.getenv('CHECK_DB_HOST', 'localhost'),
    'port': int(os.getenv('CHECK_DB_PORT', '5432')),
    'database': os.getenv('CHECK_DB_NAME', 'threat_engine_check'),
    'user': os.getenv('CHECK_DB_USER', 'check_user'),
    'password': os.getenv('CHECK_DB_PASSWORD', '')
}

INPUT_NDJSON = "/Users/apple/Desktop/threat-engine/bulk_import/rule_discoveries_complete.ndjson"

# Increase CSV field size limit
csv.field_size_limit(10 * 1024 * 1024)  # 10 MB

def load_ndjson_data():
    """Load data from NDJSON file"""
    services = []
    seen_services = set()

    with open(INPUT_NDJSON, 'r') as f:
        for line in f:
            row = json.loads(line)

            # Check for duplicate service names (regardless of provider)
            # If duplicate, prefix with provider to make unique
            service_key = row['service']
            if service_key in seen_services:
                # Prefix with provider to make unique
                row['service'] = f"{row['provider']}_{row['service']}"
                print(f"  ⚠ Renamed duplicate service: {service_key} → {row['service']}")

            seen_services.add(service_key)
            # Parse JSON strings back to objects
            row['discoveries_data'] = json.loads(row['discoveries_data']) if row['discoveries_data'] else {}
            row['extraction_patterns'] = json.loads(row['extraction_patterns']) if row['extraction_patterns'] else None
            row['filter_rules'] = json.loads(row['filter_rules']) if row['filter_rules'] else {}
            row['pagination_config'] = json.loads(row['pagination_config']) if row['pagination_config'] else {}
            row['features'] = json.loads(row['features']) if row['features'] else {}
            row['arn_identifier_independent_methods'] = json.loads(row['arn_identifier_independent_methods']) if row['arn_identifier_independent_methods'] else None
            row['arn_identifier_dependent_methods'] = json.loads(row['arn_identifier_dependent_methods']) if row['arn_identifier_dependent_methods'] else None

            # Convert string booleans
            row['is_active'] = row['is_active'].lower() == 'true' if isinstance(row['is_active'], str) else row['is_active']

            services.append(row)

    return services

def bulk_import(truncate=False):
    """Bulk import services into database"""

    # Load data
    print("Loading NDJSON data...")
    services = load_ndjson_data()
    print(f"✓ Loaded {len(services)} services from NDJSON")

    # Connect to database
    conn = psycopg2.connect(**CHECK_DB_CONFIG)
    cur = conn.cursor()

    # Optional: Truncate existing data
    if truncate:
        print("\n⚠ Truncating existing rule_discoveries table...")
        cur.execute("TRUNCATE TABLE rule_discoveries RESTART IDENTITY CASCADE")
        conn.commit()
        print("✓ Table truncated")

    # Prepare data for bulk insert
    print("\nPreparing bulk insert...")

    columns = [
        'service', 'provider', 'version', 'is_active', 'boto3_client_name', 'scope',
        'arn_pattern', 'arn_identifier', 'arn_identifier_independent_methods',
        'arn_identifier_dependent_methods', 'extraction_patterns', 'filter_rules',
        'pagination_config', 'features', 'discoveries_data', 'created_at', 'updated_at'
    ]

    values = []
    for service in services:
        row = [
            service['service'],
            service['provider'],
            service.get('version', ''),
            service['is_active'],
            service['boto3_client_name'],
            service['scope'],
            service.get('arn_pattern'),
            service.get('arn_identifier'),
            json.dumps(service.get('arn_identifier_independent_methods')) if service.get('arn_identifier_independent_methods') else None,
            json.dumps(service.get('arn_identifier_dependent_methods')) if service.get('arn_identifier_dependent_methods') else None,
            json.dumps(service.get('extraction_patterns')) if service.get('extraction_patterns') else None,
            json.dumps(service['filter_rules']),
            json.dumps(service['pagination_config']),
            json.dumps(service['features']),
            json.dumps(service['discoveries_data']),
            datetime.now(),
            datetime.now()
        ]
        values.append(tuple(row))

    # Bulk insert
    print(f"Inserting {len(values)} services...")

    insert_query = f"""
        INSERT INTO rule_discoveries (
            service, provider, version, is_active, boto3_client_name, scope,
            arn_pattern, arn_identifier, arn_identifier_independent_methods,
            arn_identifier_dependent_methods, extraction_patterns, filter_rules,
            pagination_config, features, discoveries_data, created_at, updated_at
        ) VALUES %s
    """

    execute_values(cur, insert_query, values, page_size=100)
    conn.commit()

    print(f"✓ Successfully inserted/updated {len(values)} services")

    # Verify counts
    print("\n=== Verification ===")
    cur.execute("SELECT provider, COUNT(*) FROM rule_discoveries GROUP BY provider ORDER BY provider")
    results = cur.fetchall()
    for provider, count in results:
        print(f"  {provider.upper()}: {count} services")

    cur.execute("SELECT COUNT(*) FROM rule_discoveries WHERE discoveries_data != '{}'::jsonb")
    populated_count = cur.fetchone()[0]
    print(f"\n  Services with discovery YAML: {populated_count}")

    # Close connection
    cur.close()
    conn.close()

    print("\n✓ Bulk import completed successfully!")

if __name__ == "__main__":
    import sys

    # Check if user wants to truncate
    truncate = '--truncate' in sys.argv or '-t' in sys.argv

    if truncate:
        confirm = input("⚠ WARNING: This will DELETE all existing data in rule_discoveries table. Continue? (yes/no): ")
        if confirm.lower() != 'yes':
            print("Aborted.")
            sys.exit(0)

    bulk_import(truncate=truncate)
