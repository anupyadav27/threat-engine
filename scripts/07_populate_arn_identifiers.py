#!/usr/bin/env python3
"""
Populate ARN patterns and identifiers from resource_inventory_report.json files

Extracts:
- arn_pattern: Primary ARN pattern for the service's main resource
- arn_identifier: Primary identifier field name
- arn_identifier_independent_methods: Operations that can get identifier without dependencies
- arn_identifier_dependent_methods: Operations that require other parameters

Data source: /Users/apple/Desktop/data_pythonsdk/{csp}/{service}/resource_inventory_report.json
"""

import os
import json
import psycopg2
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from collections import defaultdict

# Database connection config
CHECK_DB_CONFIG = {
    'host': os.getenv('CHECK_DB_HOST', 'localhost'),
    'port': int(os.getenv('CHECK_DB_PORT', '5432')),
    'database': os.getenv('CHECK_DB_NAME', 'threat_engine_check'),
    'user': os.getenv('CHECK_DB_USER', 'check_user'),
    'password': os.getenv('CHECK_DB_PASSWORD', 'check_password')
}

BASE_PATH = "/Users/apple/Desktop/data_pythonsdk"


def extract_arn_and_identifiers(inventory_file: Path, service: str, provider: str) -> Optional[Dict]:
    """
    Extract ARN patterns and identifier data from resource_inventory_report.json

    Returns:
        {
            'arn_pattern': 'arn:aws:ec2:{region}:{account_id}:instance/{instance_id}',
            'arn_identifier': 'instance_id',
            'arn_identifier_independent_methods': ['DescribeInstances'],
            'arn_identifier_dependent_methods': []
        }
    """
    try:
        with open(inventory_file, 'r') as f:
            data = json.load(f)

        resources = data.get('resources', [])
        if not resources or not isinstance(resources, list):
            return None

        # Strategy: Find the "main" resource for this service
        # Priority:
        # 1. Resource with most ARN-producing operations
        # 2. Resource that can get ARN from root operations (independent)
        # 3. First resource with both ARN and ID entities

        best_resource = None
        best_score = -1

        for resource in resources:
            if not isinstance(resource, dict):
                continue

            arn_entity = resource.get('arn_entity')
            id_entities = resource.get('id_entities', [])
            arn_ops = resource.get('arn_producing_operations', [])
            id_ops = resource.get('id_producing_operations', [])
            can_get_from_roots = resource.get('can_get_arn_from_roots', False)
            requires_dependent = resource.get('requires_dependent_ops', True)

            # Skip resources without identifiers
            if not id_entities and not arn_entity:
                continue

            # Calculate score
            score = 0
            score += len(arn_ops) * 3  # More ARN-producing ops = higher priority
            score += len(id_ops) * 2   # More ID-producing ops = higher priority
            score += 10 if can_get_from_roots else 0  # Can get from roots = high priority
            score += 5 if not requires_dependent else 0  # Independent = higher priority
            score += 10 if arn_entity else 0  # Has ARN entity = important
            score += 5 if id_entities else 0  # Has ID entities = important

            if score > best_score:
                best_score = score
                best_resource = resource

        if not best_resource:
            return None

        # Extract data from best resource
        result = {
            'arn_pattern': None,
            'arn_identifier': None,
            'arn_identifier_independent_methods': [],
            'arn_identifier_dependent_methods': []
        }

        # Extract ARN pattern from arn_entity
        arn_entity = best_resource.get('arn_entity')
        if arn_entity:
            # Convert arn_entity like "ec2.instance_arn" to ARN pattern
            # For AWS: arn:aws:{service}:{region}:{account_id}:{resource_type}/{identifier}
            if provider == 'aws':
                resource_type = best_resource.get('resource_type', 'resource')
                # Clean up resource type (remove duplicate parts)
                if '_' in resource_type:
                    parts = resource_type.split('_')
                    # Remove duplicate service name from resource type
                    cleaned_parts = [p for p in parts if p != service.replace('-', '')]
                    resource_type = '_'.join(cleaned_parts) if cleaned_parts else parts[-1]

                result['arn_pattern'] = f"arn:aws:{service}:{{region}}:{{account_id}}:{resource_type}/{{identifier}}"

        # Extract identifier from id_entities (use first one)
        id_entities = best_resource.get('id_entities', [])
        if id_entities:
            # Extract identifier name from entity like "ec2.instance_id"
            first_id = id_entities[0]
            if '.' in first_id:
                result['arn_identifier'] = first_id.split('.')[-1]
            else:
                result['arn_identifier'] = first_id

        # Categorize operations into independent vs dependent
        id_ops = best_resource.get('id_producing_operations', [])
        can_get_from_roots = best_resource.get('can_get_arn_from_roots', False)
        requires_dependent = best_resource.get('requires_dependent_ops', True)

        if id_ops:
            if can_get_from_roots or not requires_dependent:
                # These are independent operations
                result['arn_identifier_independent_methods'] = id_ops
            else:
                # These are dependent operations
                result['arn_identifier_dependent_methods'] = id_ops

        return result if (result['arn_pattern'] or result['arn_identifier']) else None

    except Exception as e:
        print(f"  ✗ Error parsing {inventory_file}: {e}")
        return None


def populate_arn_identifiers():
    """Extract ARN and identifier data from all resource inventory reports"""

    # Connect to database
    conn = psycopg2.connect(**CHECK_DB_CONFIG)
    cur = conn.cursor()

    # Statistics
    stats = {
        'total_services': 0,
        'inventory_files_found': 0,
        'successfully_extracted': 0,
        'updated_in_db': 0,
        'no_match_in_db': 0,
        'extraction_failed': 0,
        'by_provider': defaultdict(lambda: {'found': 0, 'extracted': 0, 'updated': 0})
    }

    print("="*80)
    print("ARN and Identifier Population from Resource Inventory Reports")
    print("="*80)

    # Process each CSP
    for provider in ['aws', 'azure', 'gcp', 'oci', 'alicloud']:
        provider_dir = Path(BASE_PATH) / provider

        if not provider_dir.exists():
            print(f"\n⚠️  {provider.upper()}: Directory not found, skipping")
            continue

        print(f"\n{'='*80}")
        print(f"Processing {provider.upper()}")
        print(f"{'='*80}")

        # Find all resource_inventory_report.json files
        inventory_files = list(provider_dir.glob('*/resource_inventory_report.json'))

        if not inventory_files:
            print(f"  ⚠️  No inventory reports found")
            continue

        print(f"  Found {len(inventory_files)} inventory report files")
        stats['inventory_files_found'] += len(inventory_files)
        stats['by_provider'][provider]['found'] = len(inventory_files)

        for inventory_file in sorted(inventory_files):
            stats['total_services'] += 1
            service = inventory_file.parent.name

            # Extract ARN and identifier data
            extracted = extract_arn_and_identifiers(inventory_file, service, provider)

            if not extracted:
                stats['extraction_failed'] += 1
                print(f"  ⚠️  {service}: No usable data extracted")
                continue

            stats['successfully_extracted'] += 1
            stats['by_provider'][provider]['extracted'] += 1

            # Update database
            try:
                # Convert lists to JSON
                independent_methods = json.dumps(extracted['arn_identifier_independent_methods'])
                dependent_methods = json.dumps(extracted['arn_identifier_dependent_methods'])

                cur.execute("""
                    UPDATE rule_discoveries
                    SET
                        arn_pattern = %s,
                        arn_identifier = %s,
                        arn_identifier_independent_methods = %s::jsonb,
                        arn_identifier_dependent_methods = %s::jsonb,
                        updated_at = NOW()
                    WHERE service = %s AND provider = %s
                """, (
                    extracted['arn_pattern'],
                    extracted['arn_identifier'],
                    independent_methods,
                    dependent_methods,
                    service,
                    provider
                ))

                if cur.rowcount > 0:
                    stats['updated_in_db'] += 1
                    stats['by_provider'][provider]['updated'] += 1
                    print(f"  ✓ {service}: Updated")
                    print(f"      ARN: {extracted['arn_pattern']}")
                    print(f"      ID: {extracted['arn_identifier']}")
                    print(f"      Independent ops: {len(extracted['arn_identifier_independent_methods'])}")
                    print(f"      Dependent ops: {len(extracted['arn_identifier_dependent_methods'])}")
                else:
                    stats['no_match_in_db'] += 1
                    print(f"  ⚠️  {service}: Not found in database")

            except Exception as e:
                stats['extraction_failed'] += 1
                print(f"  ✗ {service}: Database update failed - {e}")

        # Commit after each provider
        conn.commit()
        print(f"\n  ✓ Committed {stats['by_provider'][provider]['updated']} updates for {provider.upper()}")

    # Close connection
    cur.close()
    conn.close()

    # Print summary
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    print(f"Total services processed: {stats['total_services']}")
    print(f"Inventory files found: {stats['inventory_files_found']}")
    print(f"Successfully extracted: {stats['successfully_extracted']}")
    print(f"Updated in database: {stats['updated_in_db']}")
    print(f"No match in database: {stats['no_match_in_db']}")
    print(f"Extraction failed: {stats['extraction_failed']}")

    print(f"\nBy Provider:")
    for provider, data in sorted(stats['by_provider'].items()):
        print(f"  {provider.upper()}: {data['found']} found, {data['extracted']} extracted, {data['updated']} updated")

    print("\n" + "="*80)
    print(f"✅ Completed! Updated {stats['updated_in_db']} services with ARN and identifier data")
    print("="*80)


if __name__ == "__main__":
    populate_arn_identifiers()
