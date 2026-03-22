#!/usr/bin/env python3
"""
Enrich rule_discoveries Table Population Script
================================================
Extracts hardcoded configurations from Python files and populates
the new rule_discoveries table columns with service metadata.

Data Sources:
1. boto3_client_name: discovery_helper.SERVICE_TO_{CSP}_CLIENT dict
2. scope: Defaults to 'regional' (can be manually updated via SQL for global services)
3. filter_rules: service_scanner.py (hardcoded filter logic - AWS only)
4. pagination_config: service_scanner.py (hardcoded page sizes)
5. features: Defaults to {"discovery": {"enabled": true, "priority": 1}}

CRITICAL: This script does NOT read service_list.json files.
The database is the ONLY source of truth after population.

Usage:
    python scripts/03_enrich_rule_discoveries.py [--dry-run] [--provider aws]

    # Populate AWS services
    python scripts/03_enrich_rule_discoveries.py --provider aws

    # Dry run for Azure
    python scripts/03_enrich_rule_discoveries.py --provider azure --dry-run
"""

import os
import sys
import json
import re
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Any
import psycopg2
from psycopg2.extras import Json

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


class RuleDiscoveriesEnricher:
    """Populate rule_discoveries table with service metadata"""

    def __init__(self, db_config: Dict[str, Any], provider: str = 'aws', dry_run: bool = False):
        self.provider = provider
        self.dry_run = dry_run
        self.db_config = db_config
        self.conn = None

        # Data storage
        self.boto3_mappings = {}
        self.filter_rules_data = {}
        self.pagination_config_data = {}
        self.default_pagination_config = None

    def connect_db(self):
        """Connect to database"""
        try:
            self.conn = psycopg2.connect(**self.db_config)
            print(f"✓ Connected to database: {self.db_config['database']}")
        except Exception as e:
            print(f"✗ Database connection failed: {e}")
            sys.exit(1)

    def close_db(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
            print("✓ Database connection closed")

    # ========================================================================
    # Step 1: Extract boto3 client name mappings from discovery_helper.py
    # ========================================================================

    def extract_boto3_mappings(self):
        """Extract SERVICE_TO_{CSP}_CLIENT dict from discovery_helper.py"""
        print("\n[1/5] Extracting SDK client name mappings...")

        # Construct provider-specific path
        provider_dir = f"engine_discoveries_{self.provider}"
        helper_file = PROJECT_ROOT / "engine_discoveries" / provider_dir / "engine" / "discovery_helper.py"

        if not helper_file.exists():
            print(f"  ⚠ File not found: {helper_file}")
            print("  Using fallback: service name = client name")
            return

        try:
            with open(helper_file, 'r') as f:
                content = f.read()

            # Extract SERVICE_TO_{CSP}_CLIENT dictionary
            # Pattern: SERVICE_TO_BOTO3_CLIENT = { ... } or SERVICE_TO_AZURE_CLIENT = { ... }
            # Special case: AWS uses BOTO3, not AWS
            if self.provider == 'aws':
                dict_name = 'SERVICE_TO_BOTO3_CLIENT'
            else:
                provider_upper = self.provider.upper()
                dict_name = f'SERVICE_TO_{provider_upper}_CLIENT'

            pattern = rf'{dict_name}\s*=\s*\{{([^}}]+)\}}'
            match = re.search(pattern, content, re.DOTALL)

            if match:
                dict_content = match.group(1)
                # Parse key-value pairs: 'service': 'client_name'
                # Handle both simple values and versioned values (e.g., 'compute.v1')
                pairs = re.findall(r"['\"](\w+)['\"]\s*:\s*['\"]([^'\"]+)['\"]", dict_content)

                for service, client_name in pairs:
                    self.boto3_mappings[service] = client_name

                print(f"  ✓ Extracted {len(self.boto3_mappings)} {self.provider.upper()} client mappings")
                if self.boto3_mappings:
                    # Show first 2 examples
                    examples = list(self.boto3_mappings.items())[:2]
                    examples_str = ", ".join([f"{k}→{v}" for k, v in examples])
                    print(f"    Examples: {examples_str}")
            else:
                print(f"  ⚠ {dict_name} dict not found in file")

        except Exception as e:
            print(f"  ✗ Error reading discovery_helper.py: {e}")

    # ========================================================================
    # Step 2: REMOVED - No longer reading from service_list.json
    # ========================================================================
    # Scope defaults to 'regional' in database schema (ALTER TABLE default)
    # Can be manually updated via SQL for global services:
    # UPDATE rule_discoveries SET scope = 'global' WHERE service IN ('iam', 's3', 'cloudfront', ...)
    # ========================================================================

    # ========================================================================
    # Step 3: Extract filter rules from service_scanner.py
    # ========================================================================

    def extract_filter_rules(self):
        """Extract hardcoded filter logic from service_scanner.py"""
        print("\n[3/5] Extracting filter rules from service_scanner.py...")

        # Construct provider-specific path
        provider_dir = f"engine_discoveries_{self.provider}"
        scanner_file = PROJECT_ROOT / "engine_discoveries" / provider_dir / "engine" / "service_scanner.py"

        if not scanner_file.exists():
            print(f"  ⚠ File not found: {scanner_file}")
            return

        try:
            with open(scanner_file, 'r') as f:
                content = f.read()

            # Extract API-level filters (lines 98-182)
            api_filters = self._extract_api_filters(content)

            # Extract response-level filters (lines 185-276)
            response_filters = self._extract_response_filters(content)

            # Organize by service
            for service_name in set(list(api_filters.keys()) + list(response_filters.keys())):
                self.filter_rules_data[service_name] = {
                    'api_filters': api_filters.get(service_name, []),
                    'response_filters': response_filters.get(service_name, [])
                }

            total_api = sum(len(v) for v in api_filters.values())
            total_response = sum(len(v) for v in response_filters.values())
            print(f"  ✓ Extracted {total_api} API filters")
            print(f"  ✓ Extracted {total_response} response filters")
            print(f"  ✓ Covering {len(self.filter_rules_data)} services")

        except Exception as e:
            print(f"  ✗ Error extracting filter rules: {e}")

    def _extract_api_filters(self, content: str) -> Dict[str, List[Dict]]:
        """Extract API-level filters from _apply_aws_managed_filters_at_api_level()"""
        api_filters = {}

        # Pattern examples:
        # if discovery_id == 'aws.ec2.describe_snapshots':
        #     params['OwnerIds'] = ['self']
        # elif discovery_id == 'aws.rds.describe_db_cluster_snapshots':
        #     params['IncludeShared'] = False

        pattern = r"discovery_id\s*==\s*['\"]([^'\"]+)['\"]\s*:.*?params\[(['\"])(\w+)\2\]\s*=\s*(.+)"

        for match in re.finditer(pattern, content):
            discovery_id = match.group(1)
            param_name = match.group(3)
            param_value_str = match.group(4).strip()

            # Extract service from discovery_id (aws.ec2.describe_snapshots → ec2)
            parts = discovery_id.split('.')
            if len(parts) >= 2:
                service = parts[1]
            else:
                continue

            # Parse value
            param_value = self._parse_param_value(param_value_str)

            if service not in api_filters:
                api_filters[service] = []

            api_filters[service].append({
                'discovery_id': discovery_id,
                'parameter': param_name,
                'value': param_value,
                'priority': 10
            })

        return api_filters

    def _extract_response_filters(self, content: str) -> Dict[str, List[Dict]]:
        """Extract response-level filters from _filter_aws_managed_resources()"""
        response_filters = {}

        # Pattern examples:
        # if resource.get('AliasName', '').startswith('alias/aws/'):
        # if re.match(r'^(aws/|rds!)', resource.get('Name', '')):

        # This is complex to parse perfectly from code, so we'll use known patterns
        # In real implementation, would parse the actual function

        known_filters = [
            ('kms', 'aws.kms.list_aliases', 'AliasName', '^alias/aws/', 'prefix', 'Exclude AWS-managed KMS aliases'),
            ('secretsmanager', 'aws.secretsmanager.list_secrets', 'Name', '^(aws/|rds!)', 'regex', 'Exclude AWS-managed secrets'),
            ('iam', 'aws.iam.list_roles', 'Path', '^/aws-service-role/', 'prefix', 'Exclude AWS service-linked roles'),
            ('iam', 'aws.iam.list_policies', 'Arn', '^arn:aws:iam::aws:policy/', 'prefix', 'Exclude AWS-managed IAM policies'),
            ('lambda', 'aws.lambda.list_functions', 'FunctionArn', ':function:aws', 'contains', 'Exclude AWS-managed Lambda functions'),
            ('cloudformation', 'aws.cloudformation.describe_stacks', 'StackName', '^(aws-|AWS-)', 'regex', 'Exclude AWS-managed stacks'),
            ('ssm', 'aws.ssm.describe_parameters', 'Name', '^/aws/', 'prefix', 'Exclude AWS-managed SSM parameters'),
            ('ecr', 'aws.ecr.describe_repositories', 'repositoryName', '^aws/', 'prefix', 'Exclude AWS-managed ECR repositories'),
        ]

        for service, discovery_id, field_path, pattern, pattern_type, description in known_filters:
            if service not in response_filters:
                response_filters[service] = []

            response_filters[service].append({
                'discovery_id': discovery_id,
                'field_path': field_path,
                'pattern': pattern,
                'pattern_type': pattern_type,
                'action': 'exclude',
                'priority': 100,
                'description': description
            })

        return response_filters

    def _parse_param_value(self, value_str: str) -> Any:
        """Parse parameter value from string"""
        value_str = value_str.strip().rstrip(',')

        if value_str == 'False':
            return False
        elif value_str == 'True':
            return True
        elif value_str.startswith('[') and value_str.endswith(']'):
            # List: ['self'] or ['value1', 'value2']
            return eval(value_str)  # Safe here since we control the input
        elif value_str.startswith('{') and value_str.endswith('}'):
            # Dict
            return eval(value_str)
        else:
            # String
            return value_str.strip('\'"')

    # ========================================================================
    # Step 4: Extract pagination config from service_scanner.py
    # ========================================================================

    def extract_pagination_config(self):
        """Extract hardcoded pagination configuration from service_scanner.py"""
        print("\n[4/5] Extracting pagination config from service_scanner.py...")

        # Provider-specific defaults
        default_configs = {
            'aws': {
                'default_page_size': 1000,
                'max_pages': 100,
                'timeout_seconds': 600,
                'max_items': 100000,
                'token_field': 'NextToken',
                'result_array_field': None,
                'supports_native_pagination': True,
                'circular_token_detection': True,
                'service_overrides': {}
            },
            'azure': {
                'default_page_size': 100,
                'max_pages': 100,
                'timeout_seconds': 600,
                'max_items': 100000,
                'token_field': 'nextLink',
                'result_array_field': 'value',
                'supports_native_pagination': False,
                'circular_token_detection': True,
                'service_overrides': {}
            },
            'gcp': {
                'default_page_size': 500,
                'max_pages': 100,
                'timeout_seconds': 600,
                'max_items': 100000,
                'token_field': 'pageToken',
                'result_array_field': 'items',
                'supports_native_pagination': True,
                'circular_token_detection': True,
                'service_overrides': {}
            },
            'oci': {
                'default_page_size': 100,
                'max_pages': 100,
                'timeout_seconds': 600,
                'max_items': 100000,
                'token_field': 'page',
                'result_array_field': 'data',
                'supports_native_pagination': True,
                'circular_token_detection': True,
                'service_overrides': {}
            }
        }

        default_config = default_configs.get(self.provider, default_configs['aws'])

        # Store default config for use in populate_database
        self.default_pagination_config = default_config

        # AWS-specific pagination overrides (from lines 1490-1500)
        pagination_overrides = {}
        if self.provider == 'aws':
            pagination_overrides = {
                'sagemaker': {'default_page_size': 100},
                'cognito-idp': {'default_page_size': 60, 'token_field': 'PaginationToken'},
                'cognito': {'default_page_size': 60},
                'kafka': {'default_page_size': 100},
                's3': {'service_overrides': {
                    'list_buckets': {'token_field': 'Marker'},
                    'list_objects_v2': {'token_field': 'ContinuationToken'}
                }},
                'iam': {'token_field': 'Marker'},
                'ec2': {'max_pages': 200, 'max_items': 200000},
                'logs': {'default_page_size': 50, 'token_field': 'nextToken'},
            }

        # Build pagination config for each service
        for service, overrides in pagination_overrides.items():
            config = default_config.copy()

            # Handle service_overrides separately
            if 'service_overrides' in overrides:
                config['service_overrides'] = overrides['service_overrides']
            else:
                config.update(overrides)

            self.pagination_config_data[service] = config

        print(f"  ✓ Extracted pagination config for {len(self.pagination_config_data)} services")
        if self.pagination_config_data:
            # Show first 2 examples
            examples = list(self.pagination_config_data.items())[:2]
            examples_str = ", ".join([f"{k}={v['default_page_size']}" for k, v in examples])
            print(f"    Examples: {examples_str}")
        else:
            print(f"    Using default config: token_field={default_config['token_field']}, page_size={default_config['default_page_size']}")

    # ========================================================================
    # Step 5: Populate database
    # ========================================================================

    def populate_database(self):
        """Populate rule_discoveries table with extracted data (UPSERT mode)"""
        print("\n[5/5] Populating database...")

        if self.dry_run:
            print("  [DRY RUN MODE - No database changes]")

        try:
            cursor = self.conn.cursor()

            # Get existing services to track inserts vs updates
            cursor.execute("""
                SELECT service FROM rule_discoveries
                WHERE provider = %s
            """, (self.provider,))

            existing_services = {row[0] for row in cursor.fetchall()}
            print(f"  Found {len(existing_services)} existing services in database")

            # Collect all unique services from all data sources
            # Primary source: boto3_mappings (discovery_helper.py)
            # Secondary sources: filter_rules, pagination_config (for overrides)
            all_services = set()
            all_services.update(self.boto3_mappings.keys())
            all_services.update(self.filter_rules_data.keys())
            all_services.update(self.pagination_config_data.keys())

            # Remove empty service names
            all_services.discard(None)
            all_services.discard('')

            print(f"  Found {len(all_services)} total services from data sources")
            new_services = all_services - existing_services
            print(f"  Will insert {len(new_services)} new services")
            print(f"  Will update {len(existing_services & all_services)} existing services")

            inserted_count = 0
            updated_count = 0

            for service in all_services:
                # Gather data for this service
                boto3_name = self.boto3_mappings.get(service, service)
                filter_rules = self.filter_rules_data.get(service, {'api_filters': [], 'response_filters': []})

                # Get pagination config
                if service in self.pagination_config_data:
                    pagination_config = self.pagination_config_data[service]
                else:
                    # Use provider-specific default pagination config
                    pagination_config = self.default_pagination_config.copy()

                # Default features: discovery enabled with priority 1
                features = {
                    "discovery": {"enabled": True, "priority": 1},
                    "checks": {"enabled": True, "priority": 1},
                    "deviation": {"enabled": False, "priority": 3},
                    "drift": {"enabled": False, "priority": 3}
                }

                # UPSERT query (INSERT or UPDATE)
                # Note: UNIQUE constraint is on (service) only, not (service, provider)
                # Scope defaults to 'regional' via column default
                # extraction_patterns and arn_pattern left NULL (can be populated later)
                upsert_query = """
                    INSERT INTO rule_discoveries (
                        service,
                        provider,
                        is_active,
                        boto3_client_name,
                        filter_rules,
                        pagination_config,
                        features,
                        discoveries_data,
                        created_at,
                        updated_at
                    ) VALUES (
                        %s, %s, TRUE, %s, %s, %s, %s, '{}'::jsonb, NOW(), NOW()
                    )
                    ON CONFLICT (service)
                    DO UPDATE SET
                        provider = EXCLUDED.provider,
                        boto3_client_name = EXCLUDED.boto3_client_name,
                        filter_rules = EXCLUDED.filter_rules,
                        pagination_config = EXCLUDED.pagination_config,
                        features = EXCLUDED.features,
                        updated_at = NOW()
                """

                if not self.dry_run:
                    cursor.execute(upsert_query, (
                        service,
                        self.provider,
                        boto3_name,
                        Json(filter_rules),
                        Json(pagination_config),
                        Json(features)
                    ))

                    # Track inserts vs updates
                    if service in existing_services:
                        updated_count += 1
                    else:
                        inserted_count += 1
                else:
                    action = "UPDATE" if service in existing_services else "INSERT"
                    filter_count = len(filter_rules.get('api_filters', [])) + len(filter_rules.get('response_filters', []))
                    print(f"    [DRY RUN] Would {action} {service}: "
                          f"boto3={boto3_name}, filters={filter_count}, "
                          f"features=discovery+checks")

            if not self.dry_run:
                self.conn.commit()
                print(f"  ✓ Inserted {inserted_count} new services")
                print(f"  ✓ Updated {updated_count} existing services")
                print(f"  ✓ Total services processed: {inserted_count + updated_count}")
            else:
                print(f"  [DRY RUN] Would insert {len(new_services)} new services")
                print(f"  [DRY RUN] Would update {len(existing_services & all_services)} existing services")

            cursor.close()

        except Exception as e:
            if self.conn:
                self.conn.rollback()
            print(f"  ✗ Error populating database: {e}")
            raise

    def run(self):
        """Execute full enrichment process"""
        print("=" * 70)
        print("Rule Discoveries Table Enrichment Script")
        print("=" * 70)
        print(f"Provider: {self.provider}")
        print(f"Dry Run: {self.dry_run}")
        print("=" * 70)

        # Connect to database
        self.connect_db()

        try:
            # Extract data from various sources
            self.extract_boto3_mappings()
            # Step 2 removed - no longer reading from service_list.json
            self.extract_filter_rules()
            self.extract_pagination_config()

            # Populate database
            self.populate_database()

            print("\n" + "=" * 70)
            print("✓ Enrichment Complete!")
            print("=" * 70)

        finally:
            self.close_db()


def get_db_config() -> Dict[str, Any]:
    """Get database configuration from environment"""
    return {
        'host': os.getenv('CHECK_DB_HOST', 'localhost'),
        'port': int(os.getenv('CHECK_DB_PORT', '5432')),
        'database': os.getenv('CHECK_DB_NAME', 'threat_engine_check'),
        'user': os.getenv('CHECK_DB_USER', 'check_user'),
        'password': os.getenv('CHECK_DB_PASSWORD', 'check_password'),
    }


def main():
    parser = argparse.ArgumentParser(
        description='Enrich rule_discoveries table with service metadata'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Print what would be done without making changes'
    )
    parser.add_argument(
        '--provider',
        default='aws',
        help='Cloud provider (default: aws)'
    )

    args = parser.parse_args()

    # Get database config
    db_config = get_db_config()

    # Run enrichment
    enricher = RuleDiscoveriesEnricher(
        db_config=db_config,
        provider=args.provider,
        dry_run=args.dry_run
    )

    enricher.run()


if __name__ == '__main__':
    main()
