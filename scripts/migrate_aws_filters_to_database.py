#!/usr/bin/env python3
"""
Migrate AWS Hardcoded Filters to Database

This script extracts hardcoded filter logic from service_scanner.py
and migrates it to the rule_discoveries.filter_rules column.

Date: 2026-02-20
"""

import os
import sys
import psycopg2
import json
from psycopg2.extras import RealDictCursor

# AWS Filter Rules (migrated from hardcoded functions)
AWS_FILTER_RULES = {
    'ec2': {
        'api_filters': [
            {
                'discovery_id': 'aws.ec2.describe_snapshots',
                'parameter': 'OwnerIds',
                'value': ['self'],
                'reason': 'Only customer-owned EBS snapshots (exclude AWS public snapshots)',
                'priority': 1
            },
            {
                'discovery_id': 'aws.ec2.describe_images',
                'parameter': 'Owners',
                'value': ['self'],
                'reason': 'Only customer-owned AMIs (exclude AWS marketplace and public AMIs)',
                'priority': 1
            }
        ],
        'response_filters': [
            {
                'discovery_id': 'aws.ec2.describe_fpga_images',
                'field_path': 'Public',
                'pattern': 'true',
                'pattern_type': 'exact',
                'action': 'exclude',
                'reason': 'Exclude public FPGA images',
                'priority': 1,
                'additional_check': {
                    'field_path': 'OwnerId',
                    'compare_to': 'account_id',
                    'operator': 'not_equals'
                }
            }
        ]
    },
    'rds': {
        'api_filters': [
            {
                'discovery_id': 'aws.rds.describe_db_cluster_snapshots',
                'parameter': 'IncludeShared',
                'value': False,
                'reason': 'Exclude shared RDS cluster snapshots',
                'priority': 1
            },
            {
                'discovery_id': 'aws.rds.describe_db_cluster_snapshots',
                'parameter': 'IncludePublic',
                'value': False,
                'reason': 'Exclude public RDS cluster snapshots',
                'priority': 2
            }
        ]
    },
    'docdb': {
        'api_filters': [
            {
                'discovery_id': 'aws.docdb.describe_d_b_cluster_snapshots',
                'parameter': 'IncludeShared',
                'value': False,
                'reason': 'Exclude shared DocumentDB cluster snapshots',
                'priority': 1
            },
            {
                'discovery_id': 'aws.docdb.describe_d_b_cluster_snapshots',
                'parameter': 'IncludePublic',
                'value': False,
                'reason': 'Exclude public DocumentDB cluster snapshots',
                'priority': 2
            }
        ]
    },
    'neptune': {
        'api_filters': [
            {
                'discovery_id': 'aws.neptune.describe_d_b_cluster_snapshots',
                'parameter': 'IncludeShared',
                'value': False,
                'reason': 'Exclude shared Neptune cluster snapshots',
                'priority': 1
            },
            {
                'discovery_id': 'aws.neptune.describe_d_b_cluster_snapshots',
                'parameter': 'IncludePublic',
                'value': False,
                'reason': 'Exclude public Neptune cluster snapshots',
                'priority': 2
            }
        ]
    },
    'iam': {
        'api_filters': [
            {
                'discovery_id': 'aws.iam.list_policies',
                'parameter': 'Scope',
                'value': 'Local',
                'reason': 'Only customer-managed IAM policies (exclude AWS-managed)',
                'priority': 1
            }
        ],
        'response_filters': [
            {
                'discovery_id': 'aws.iam.list_policies',
                'field_path': 'Arn',
                'pattern': '/aws-service-role/',
                'pattern_type': 'contains',
                'action': 'exclude',
                'reason': 'Exclude AWS service-linked role policies',
                'priority': 1
            },
            {
                'discovery_id': 'aws.iam.list_policies',
                'field_path': 'PolicyName',
                'pattern': '^aws-',
                'pattern_type': 'regex',
                'action': 'exclude',
                'reason': 'Exclude AWS-managed policies by name prefix',
                'priority': 2
            }
        ]
    },
    'ssm': {
        'api_filters': [
            {
                'discovery_id': 'aws.ssm.list_documents',
                'parameter': 'Owner',
                'value': 'Self',
                'reason': 'Only customer-owned SSM documents (exclude AWS-managed)',
                'priority': 1
            },
            {
                'discovery_id': 'aws.ssm.describe_patch_baselines',
                'parameter': 'Owner',
                'value': 'Self',
                'reason': 'Only customer-owned patch baselines (exclude AWS-managed)',
                'priority': 1
            }
        ],
        'response_filters': [
            {
                'discovery_id': 'aws.ssm.describe_parameters',
                'field_path': 'Name',
                'pattern': '^/aws/',
                'pattern_type': 'regex',
                'action': 'exclude',
                'reason': 'Exclude AWS-managed SSM parameters',
                'priority': 1
            },
            {
                'discovery_id': 'aws.ssm.list_commands',
                'field_path': 'DocumentName',
                'pattern': '^AWS-',
                'pattern_type': 'regex',
                'action': 'exclude',
                'reason': 'Exclude AWS-managed automation documents',
                'priority': 1
            },
            {
                'discovery_id': 'aws.ssm.describe_automation_executions',
                'field_path': 'DocumentName',
                'pattern': '^AWS-',
                'pattern_type': 'regex',
                'action': 'exclude',
                'reason': 'Exclude AWS-managed automation executions',
                'priority': 1
            }
        ]
    },
    'cloudformation': {
        'api_filters': [
            {
                'discovery_id': 'aws.cloudformation.list_stacks',
                'parameter': 'StackStatusFilter',
                'value': [
                    'CREATE_COMPLETE',
                    'UPDATE_COMPLETE',
                    'UPDATE_ROLLBACK_COMPLETE',
                    'ROLLBACK_COMPLETE'
                ],
                'reason': 'Only active CloudFormation stacks (exclude deleted/failed)',
                'priority': 1
            }
        ]
    },
    'kms': {
        'response_filters': [
            {
                'discovery_id': 'aws.kms.list_aliases',
                'field_path': 'AliasName',
                'pattern': '^alias/aws/',
                'pattern_type': 'regex',
                'action': 'exclude',
                'reason': 'Exclude AWS-managed KMS key aliases',
                'priority': 1
            }
        ]
    },
    'secretsmanager': {
        'response_filters': [
            {
                'discovery_id': 'aws.secretsmanager.list_secrets',
                'field_path': 'Name',
                'pattern': '^(aws/|rds!)',
                'pattern_type': 'regex',
                'action': 'exclude',
                'reason': 'Exclude AWS-managed secrets (AWS and RDS automatic rotation)',
                'priority': 1
            }
        ]
    },
    'events': {
        'response_filters': [
            {
                'discovery_id': 'aws.events.list_event_buses',
                'field_path': 'Name',
                'pattern': 'default',
                'pattern_type': 'exact',
                'action': 'exclude',
                'reason': 'Exclude default EventBridge event bus',
                'priority': 1
            }
        ]
    },
    'athena': {
        'response_filters': [
            {
                'discovery_id': 'aws.athena.list_work_groups',
                'field_path': 'Name',
                'pattern': 'primary',
                'pattern_type': 'exact',
                'action': 'exclude',
                'reason': 'Exclude default primary Athena workgroup',
                'priority': 1
            }
        ]
    },
    'keyspaces': {
        'response_filters': [
            {
                'discovery_id': 'aws.keyspaces.list_keyspaces',
                'field_path': 'keyspaceName',
                'pattern': '^system_',
                'pattern_type': 'regex',
                'action': 'exclude',
                'reason': 'Exclude system keyspaces in Amazon Keyspaces',
                'priority': 1
            }
        ]
    },
    'logs': {
        'response_filters': [
            {
                'discovery_id': 'aws.logs.describe_log_groups',
                'field_path': 'logGroupName',
                'pattern': '^/aws/',
                'pattern_type': 'regex',
                'action': 'exclude',
                'reason': 'Exclude AWS service log groups',
                'priority': 1
            }
        ]
    }
}


def migrate_filters_to_database():
    """Migrate AWS filter rules to database"""

    print("=" * 80)
    print("AWS Filter Migration to Database")
    print("=" * 80)

    # Connect to database (check database)
    conn = psycopg2.connect(
        host='localhost',
        port=5432,
        database='threat_engine_check',
        user='apple',
        password=''
    )

    try:
        total_services = len(AWS_FILTER_RULES)
        updated_count = 0

        for service, filter_rules in AWS_FILTER_RULES.items():
            print(f"\nMigrating filters for service: {service}")
            print(f"  - API filters: {len(filter_rules.get('api_filters', []))}")
            print(f"  - Response filters: {len(filter_rules.get('response_filters', []))}")

            with conn.cursor() as cur:
                # Update filter_rules for this service
                cur.execute("""
                    UPDATE rule_discoveries
                    SET filter_rules = %s::jsonb,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE service = %s
                    AND provider = 'aws'
                    RETURNING service, provider
                """, (json.dumps(filter_rules), service))

                result = cur.fetchone()
                if result:
                    updated_count += 1
                    print(f"  ✅ Updated filter_rules for {service}")
                else:
                    print(f"  ⚠️  Service '{service}' not found in rule_discoveries table")

        conn.commit()

        print("\n" + "=" * 80)
        print(f"Migration Summary:")
        print(f"  - Total services: {total_services}")
        print(f"  - Successfully updated: {updated_count}")
        print(f"  - Not found: {total_services - updated_count}")
        print("=" * 80)

        # Verify migration
        print("\nVerifying migration...")
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT service,
                       jsonb_array_length(filter_rules->'api_filters') as api_count,
                       jsonb_array_length(filter_rules->'response_filters') as response_count
                FROM rule_discoveries
                WHERE provider = 'aws'
                AND filter_rules IS NOT NULL
                AND filter_rules != '{}'::jsonb
                ORDER BY service
            """)

            results = cur.fetchall()
            if results:
                print(f"\nServices with filters in database: {len(results)}")
                for row in results:
                    api_count = row['api_count'] if row['api_count'] else 0
                    response_count = row['response_count'] if row['response_count'] else 0
                    print(f"  - {row['service']}: {api_count} API filters, {response_count} response filters")
            else:
                print("⚠️  No services found with filter_rules")

    except Exception as e:
        print(f"\n❌ Error during migration: {e}")
        conn.rollback()
        raise

    finally:
        conn.close()


if __name__ == '__main__':
    migrate_filters_to_database()
