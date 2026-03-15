#!/usr/bin/env python3
"""
Deploy Credential Validation Fields to RDS

This script adds credential validation tracking fields to the cloud_accounts table.
"""

import psycopg2
import sys
import os

# Database connection parameters
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'threat-engine-onboarding.cynapfvl14hx.ap-south-1.rds.amazonaws.com'),
    'port': int(os.getenv('DB_PORT', '5432')),
    'user': os.getenv('DB_USER', 'postgres'),
    'password': os.getenv('DB_PASSWORD', ''),
    'database': os.getenv('DB_NAME', 'threat_engine_onboarding')
}


def deploy_validation_fields():
    """Add credential validation fields to cloud_accounts table"""

    print("=" * 70)
    print("DEPLOYING CREDENTIAL VALIDATION FIELDS")
    print("=" * 70)

    # Connect to database
    print(f"\n1. Connecting to database: {DB_CONFIG['database']} @ {DB_CONFIG['host']}")
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        print("✅ Connected successfully")
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        return False

    try:
        # Check if columns already exist
        print("\n2. Checking existing columns...")
        cur.execute("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'cloud_accounts'
              AND column_name IN (
                  'credential_validation_status',
                  'credential_validation_message',
                  'credential_validated_at',
                  'credential_validation_errors'
              )
            ORDER BY column_name;
        """)
        existing_columns = [row[0] for row in cur.fetchall()]

        if existing_columns:
            print(f"ℹ️  Found existing columns: {existing_columns}")
        else:
            print("ℹ️  No validation columns found (expected for new deployment)")

        # Add new columns
        print("\n3. Adding credential validation columns...")

        migrations = [
            {
                'name': 'credential_validation_status',
                'sql': """
                    ALTER TABLE cloud_accounts
                    ADD COLUMN IF NOT EXISTS credential_validation_status VARCHAR(50) DEFAULT 'pending';
                """,
                'verify': "SELECT COUNT(*) FROM cloud_accounts WHERE credential_validation_status = 'pending';"
            },
            {
                'name': 'credential_validation_message',
                'sql': """
                    ALTER TABLE cloud_accounts
                    ADD COLUMN IF NOT EXISTS credential_validation_message TEXT;
                """,
                'verify': "SELECT COUNT(*) FROM information_schema.columns WHERE table_name = 'cloud_accounts' AND column_name = 'credential_validation_message';"
            },
            {
                'name': 'credential_validated_at',
                'sql': """
                    ALTER TABLE cloud_accounts
                    ADD COLUMN IF NOT EXISTS credential_validated_at TIMESTAMP WITH TIME ZONE;
                """,
                'verify': "SELECT COUNT(*) FROM information_schema.columns WHERE table_name = 'cloud_accounts' AND column_name = 'credential_validated_at';"
            },
            {
                'name': 'credential_validation_errors',
                'sql': """
                    ALTER TABLE cloud_accounts
                    ADD COLUMN IF NOT EXISTS credential_validation_errors JSONB DEFAULT '[]';
                """,
                'verify': "SELECT COUNT(*) FROM cloud_accounts WHERE credential_validation_errors = '[]'::jsonb;"
            }
        ]

        for migration in migrations:
            print(f"  - Adding {migration['name']}...", end=" ")
            try:
                cur.execute(migration['sql'])
                conn.commit()

                # Verify
                cur.execute(migration['verify'])
                result = cur.fetchone()[0]
                print(f"✅ (verified: {result} rows)")
            except Exception as e:
                print(f"❌ {e}")
                return False

        # Add index
        print("\n4. Adding index on credential_validation_status...")
        try:
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_cloud_accounts_credential_validation
                ON cloud_accounts(credential_validation_status);
            """)
            conn.commit()
            print("✅ Index created")
        except Exception as e:
            print(f"❌ Index creation failed: {e}")
            return False

        # Verify final schema
        print("\n5. Verifying final schema...")
        cur.execute("""
            SELECT
                column_name,
                data_type,
                is_nullable,
                column_default
            FROM information_schema.columns
            WHERE table_name = 'cloud_accounts'
              AND column_name LIKE 'credential_validation%'
            ORDER BY ordinal_position;
        """)

        columns = cur.fetchall()
        print("\nCredential Validation Columns:")
        for col in columns:
            print(f"  - {col[0]}: {col[1]} (nullable: {col[2]}, default: {col[3]})")

        # Check total column count
        cur.execute("""
            SELECT COUNT(*)
            FROM information_schema.columns
            WHERE table_name = 'cloud_accounts';
        """)
        total_columns = cur.fetchone()[0]
        print(f"\n✅ Total columns in cloud_accounts: {total_columns}")

        # Test UPDATE operation
        print("\n6. Testing update_credential_validation()...")

        # Create test account if doesn't exist
        cur.execute("""
            INSERT INTO cloud_accounts (
                account_id, customer_id, customer_email, tenant_id, tenant_name,
                account_name, provider, credential_type, credential_ref
            ) VALUES (
                'test-validation-001', 'test-customer', 'test@example.com',
                'test-tenant', 'Test Tenant', 'Test Account',
                'aws', 'iam_role', 'arn:aws:iam::123456789012:role/TestRole'
            )
            ON CONFLICT (account_id) DO NOTHING;
        """)

        # Update with validation results
        cur.execute("""
            UPDATE cloud_accounts
            SET
                credential_validation_status = 'valid',
                credential_validation_message = 'Test validation successful',
                credential_validated_at = NOW(),
                credential_validation_errors = '[]'::jsonb
            WHERE account_id = 'test-validation-001'
            RETURNING
                account_id,
                credential_validation_status,
                credential_validation_message,
                credential_validated_at;
        """)

        test_result = cur.fetchone()
        if test_result:
            print(f"✅ Test update successful:")
            print(f"  Account ID: {test_result[0]}")
            print(f"  Status: {test_result[1]}")
            print(f"  Message: {test_result[2]}")
            print(f"  Validated At: {test_result[3]}")

        conn.commit()

        print("\n" + "=" * 70)
        print("✅ DEPLOYMENT COMPLETE!")
        print("=" * 70)
        print("\nNext steps:")
        print("1. Update code in EKS pod")
        print("2. Test with real validators")
        print("3. Add validation to Phase 2.5 of onboarding flow")

        return True

    except Exception as e:
        print(f"\n❌ Deployment failed: {e}")
        import traceback
        traceback.print_exc()
        conn.rollback()
        return False

    finally:
        cur.close()
        conn.close()


if __name__ == '__main__':
    # Get DB password from environment or prompt
    if not DB_CONFIG['password']:
        import getpass
        DB_CONFIG['password'] = getpass.getpass("Enter database password: ")

    success = deploy_validation_fields()
    sys.exit(0 if success else 1)
