"""
Migration 0008: Backfill NULL customer_id on users and tenants; ensure tenant_type column exists.

Steps:
  1. Backfill customer_id = CAST(id AS VARCHAR) on users where customer_id IS NULL.
  2. Backfill customer_id = CAST(id AS VARCHAR) on tenants where customer_id IS NULL.
  3. ADD COLUMN IF NOT EXISTS tenant_type VARCHAR(30) NOT NULL DEFAULT 'cloud' on tenants.
  4. Print verification marker readable in pod logs.

NOTE on table names:
  - users table: db_table='users' (not user_auth_users)
  - tenants table: db_table='tenants' (not tenant_management_tenants)

NOTE on tenant_type:
  - Column already exists in DB (added by raw SQL in 20260503_cspm_cleanup_and_org_foundation.sql).
  - ADD COLUMN IF NOT EXISTS is safe to run again — postgres no-ops if column exists.
  - Model defines max_length=50; VARCHAR(30) is a narrower constraint from the story spec.
    We use IF NOT EXISTS so existing installations with the wider column are unaffected.

NOTE: NOT NULL constraint on customer_id is intentionally NOT added here.
  Post-deploy manual SQL (run after confirming backfill):
    ALTER TABLE users ALTER COLUMN customer_id SET NOT NULL;
    ALTER TABLE tenants ALTER COLUMN customer_id SET NOT NULL;

story: auth-A1
blocks: auth-A2, auth-B4, onboarding-D1, onboarding-D4
"""

from django.db import migrations, models

BACKFILL_SQL = """
-- Step 1: Backfill customer_id on users
UPDATE users SET customer_id = CAST(id AS VARCHAR) WHERE customer_id IS NULL;

-- Step 2: Backfill customer_id on tenants
UPDATE tenants SET customer_id = CAST(id AS VARCHAR) WHERE customer_id IS NULL;

-- Step 3: Add tenant_type column (IF NOT EXISTS — safe to re-run)
ALTER TABLE tenants
  ADD COLUMN IF NOT EXISTS tenant_type VARCHAR(30) NOT NULL DEFAULT 'cloud';

-- Step 4: Verification marker
SELECT 'MIGRATION 0016 COMPLETE';
"""

REVERSE_SQL = """
-- Reverse: no destructive rollback; customer_id nulls cannot be reliably restored.
-- tenant_type removal is also deferred to avoid data loss.
SELECT 'MIGRATION 0016 REVERSE NOOP';
"""


class Migration(migrations.Migration):
    """Backfill customer_id and ensure tenant_type column exists on tenants.

    This migration uses RunSQL so both the backfill DML and the ADD COLUMN DDL
    run inside a single transaction managed by Django's migration framework.
    The migration is idempotent:
      - UPDATE ... WHERE customer_id IS NULL does nothing if already backfilled.
      - ADD COLUMN IF NOT EXISTS does nothing if column already exists.
    """

    dependencies = [
        ("tenant_management", "0007_tenant_type_customer_id_and_groups"),
    ]

    operations = [
        # Step A: Run the actual DB work — backfill + ensure column.
        migrations.RunSQL(
            sql=BACKFILL_SQL,
            reverse_sql=REVERSE_SQL,
        ),
        # Step B: Update Django migration state to reflect choices on tenant_type.
        # No DB DDL is emitted (choices are app-layer only); this keeps makemigrations clean.
        migrations.SeparateDatabaseAndState(
            state_operations=[
                migrations.AlterField(
                    model_name="tenants",
                    name="tenant_type",
                    field=models.CharField(
                        choices=[
                            ("cloud", "Cloud"),
                            ("vulnerability", "Vulnerability"),
                            ("secops", "SecOps"),
                        ],
                        default="cloud",
                        max_length=50,
                    ),
                ),
            ],
            database_operations=[],
        ),
    ]
