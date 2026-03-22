#!/usr/bin/env python3
"""
Data Population Script - Populate New ARN Identifier Columns

This script:
1. Loads ARN identifier data from Python SDK resource_inventory
2. Populates rule_discoveries with boto3_client_name and ARN identifiers
3. Populates resource_inventory with service_name and arn_identifiers_summary
"""

import psycopg2
import json
import sys
from typing import Dict, List

# Database Configurations
CHECK_DB_CONFIG = {
    'host': 'postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com',
    'database': 'threat_engine_check',
    'user': 'postgres',
    'password': 'jtv2BkJF8qoFtAKP'
}

PYTHONSDK_DB_CONFIG = {
    'host': 'postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com',
    'database': 'threat_engine_pythonsdk',
    'user': 'postgres',
    'password': 'jtv2BkJF8qoFtAKP'
}


def load_python_sdk_arn_data() -> Dict:
    """
    Load ARN identifier data from Python SDK resource_inventory table

    Returns:
        Dict: {
            'aws.iam': {
                'user_detail_list': {
                    'arn_entity': 'iam.user_detail_list_arn',
                    'independent_methods': ['GetUser', 'ListUsers', ...],
                    'dependent_methods': ['GetGroup', ...],
                    'can_use_independent': True
                },
                ...
            },
            ...
        }
    """
    print("Loading ARN identifier data from Python SDK database...")

    conn = psycopg2.connect(**PYTHONSDK_DB_CONFIG)
    cur = conn.cursor()

    cur.execute("""
        SELECT service_id, inventory_data
        FROM resource_inventory
        WHERE service_id LIKE 'aws.%'
        ORDER BY service_id
    """)

    arn_data = {}
    service_count = 0

    for row in cur.fetchall():
        service_id = row[0]  # "aws.iam"
        inventory_data = row[1] if isinstance(row[1], dict) else json.loads(row[1])

        resources = inventory_data.get('resources', [])
        service_count += 1

        # Find resources with ARN identifiers
        for resource in resources:
            if resource.get('has_arn') and resource.get('arn_entity'):
                resource_type = resource['resource_type']

                if service_id not in arn_data:
                    arn_data[service_id] = {}

                arn_data[service_id][resource_type] = {
                    'arn_entity': resource['arn_entity'],
                    'independent_methods': resource.get('root_operations', []),
                    'dependent_methods': resource.get('dependent_operations', []),
                    'can_use_independent': resource.get('can_get_from_root_ops', False),
                    'classification': resource.get('classification', 'UNKNOWN')
                }

    cur.close()
    conn.close()

    print(f"✅ Loaded ARN data for {service_count} services")
    print(f"   Found {len(arn_data)} services with ARN identifiers")

    return arn_data


def populate_rule_discoveries(arn_data: Dict):
    """
    Populate rule_discoveries table with boto3_client_name and ARN identifiers

    Args:
        arn_data: ARN identifier data from Python SDK
    """
    print("\nPopulating rule_discoveries table...")
    print("=" * 70)

    conn = psycopg2.connect(**CHECK_DB_CONFIG)
    cur = conn.cursor()

    # Get all rule_discoveries records
    cur.execute("""
        SELECT id, service, provider, discoveries_data
        FROM rule_discoveries
        WHERE provider = 'aws' AND is_active = TRUE
        ORDER BY service
    """)

    rows = cur.fetchall()
    total_records = len(rows)
    update_count = 0
    with_arn_count = 0
    with_independent_count = 0

    print(f"Processing {total_records} rule_discoveries records...")

    for row in rows:
        rule_id = row[0]
        service = row[1]  # "iam"
        provider = row[2]  # "aws"
        discoveries_data = row[3] if isinstance(row[3], dict) else json.loads(row[3])

        # Extract boto3 client name from discoveries_data
        boto3_client = discoveries_data.get('services', {}).get('client', service)

        # Find matching ARN identifier from Python SDK
        service_id = f"{provider}.{service}"  # "aws.iam"

        arn_identifier = None
        independent_methods = []
        dependent_methods = []

        if service_id in arn_data:
            # Find primary resource (prefer PRIMARY_RESOURCE with can_use_independent=True)
            primary_resource = None

            # First pass: find PRIMARY_RESOURCE with independent methods
            for resource_type, resource_info in arn_data[service_id].items():
                if (resource_info.get('classification') == 'PRIMARY_RESOURCE' and
                    resource_info.get('can_use_independent')):
                    primary_resource = resource_info
                    break

            # Second pass: find any resource with independent methods
            if not primary_resource:
                for resource_type, resource_info in arn_data[service_id].items():
                    if resource_info.get('can_use_independent'):
                        primary_resource = resource_info
                        break

            # Third pass: use first resource with ARN
            if not primary_resource:
                primary_resource = list(arn_data[service_id].values())[0]

            if primary_resource:
                arn_identifier = primary_resource['arn_entity']
                independent_methods = primary_resource['independent_methods']
                dependent_methods = primary_resource['dependent_methods']

                with_arn_count += 1
                if independent_methods:
                    with_independent_count += 1

        # Update rule_discoveries record
        cur.execute("""
            UPDATE rule_discoveries
            SET
                boto3_client_name = %s,
                arn_identifier = %s,
                arn_identifier_independent_methods = %s,
                arn_identifier_dependent_methods = %s
            WHERE id = %s
        """, (
            boto3_client,
            arn_identifier,
            independent_methods if independent_methods else None,
            dependent_methods if dependent_methods else None,
            rule_id
        ))

        update_count += 1

        # Progress update every 100 records
        if update_count % 100 == 0:
            conn.commit()
            print(f"  Processed {update_count}/{total_records} records...")

    # Final commit
    conn.commit()

    print("\n" + "=" * 70)
    print("✅ rule_discoveries update complete")
    print(f"   Total records: {total_records}")
    print(f"   Updated: {update_count}")
    print(f"   With ARN identifier: {with_arn_count} ({with_arn_count/total_records*100:.1f}%)")
    print(f"   With independent methods: {with_independent_count} ({with_independent_count/total_records*100:.1f}%)")

    cur.close()
    conn.close()


def populate_resource_inventory():
    """
    Populate resource_inventory table with service_name, boto3_client_name, and arn_identifiers_summary
    """
    print("\nPopulating resource_inventory table...")
    print("=" * 70)

    conn = psycopg2.connect(**PYTHONSDK_DB_CONFIG)
    cur = conn.cursor()

    cur.execute("""
        SELECT id, service_id, inventory_data
        FROM resource_inventory
        ORDER BY service_id
    """)

    update_count = 0
    total_records = 0
    rows = cur.fetchall()

    print(f"Processing {len(rows)} resource_inventory records...")

    for row in rows:
        inv_id = row[0]
        service_id = row[1]  # "aws.iam"
        inventory_data = row[2] if isinstance(row[2], dict) else json.loads(row[2])

        # Extract service name
        service_name = inventory_data.get('service', service_id.split('.')[-1])

        # Extract boto3 client name (use service_name for now, can be overridden)
        boto3_client_name = service_name

        # Build ARN identifiers summary
        arn_identifiers_summary = {}
        resources = inventory_data.get('resources', [])

        for resource in resources:
            if resource.get('has_arn') and resource.get('arn_entity'):
                resource_type = resource['resource_type']
                arn_identifiers_summary[resource_type] = {
                    'arn_entity': resource['arn_entity'],
                    'independent_methods': resource.get('root_operations', []),
                    'dependent_methods': resource.get('dependent_operations', []),
                    'can_use_independent': resource.get('can_get_from_root_ops', False),
                    'classification': resource.get('classification', 'UNKNOWN')
                }

        # Update record
        cur.execute("""
            UPDATE resource_inventory
            SET
                service_name = %s,
                boto3_client_name = %s,
                arn_identifiers_summary = %s
            WHERE id = %s
        """, (
            service_name,
            boto3_client_name,
            json.dumps(arn_identifiers_summary) if arn_identifiers_summary else None,
            inv_id
        ))

        update_count += 1
        total_records += 1

        # Progress update every 200 records
        if update_count % 200 == 0:
            conn.commit()
            print(f"  Processed {update_count}/{len(rows)} records...")

    # Final commit
    conn.commit()

    print("\n" + "=" * 70)
    print("✅ resource_inventory update complete")
    print(f"   Total records updated: {total_records}")

    cur.close()
    conn.close()


def main():
    """
    Main execution function
    """
    print("=" * 70)
    print("DATA POPULATION SCRIPT - ARN IDENTIFIERS")
    print("=" * 70)

    try:
        # Step 1: Load ARN data from Python SDK
        arn_data = load_python_sdk_arn_data()

        # Step 2: Populate rule_discoveries
        populate_rule_discoveries(arn_data)

        # Step 3: Populate resource_inventory
        populate_resource_inventory()

        print("\n" + "=" * 70)
        print("✅ ALL DATA POPULATION COMPLETE")
        print("=" * 70)
        print("\nNext step: Run 03_export_updated_csv.sh to export fresh CSV files")

    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
