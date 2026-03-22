"""Drop resource_arn column — consolidate to resource_uid.

Revision ID: 0003_drop_resource_arn
Revises: 0002_enable_rls

resource_uid now holds the canonical ARN (or CSP-native identifier).
resource_arn is redundant. This migration:
1. Backfills resource_uid from resource_arn where resource_uid is NULL/empty
2. Drops the idx_cf_resource_arn_trgm GIN index
3. Drops the resource_arn column from compliance_findings
4. Creates a trgm index on resource_uid instead
"""
from alembic import op
from sqlalchemy import text

revision = "0003_drop_resource_arn"
down_revision = "0002_enable_rls"
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()

    # ── Step 1: Backfill resource_uid from resource_arn where missing ──────
    conn.execute(text("""
        UPDATE compliance_findings
        SET resource_uid = resource_arn
        WHERE (resource_uid IS NULL OR resource_uid = '')
          AND resource_arn IS NOT NULL
          AND resource_arn != ''
    """))

    # ── Step 2: Drop trgm index on resource_arn ───────────────────────────
    conn.execute(text("DROP INDEX IF EXISTS idx_cf_resource_arn_trgm"))

    # ── Step 3: Drop resource_arn column ───────────────────────────────────
    conn.execute(text(
        "ALTER TABLE compliance_findings DROP COLUMN IF EXISTS resource_arn"
    ))

    # ── Step 4: Create trgm index on resource_uid ──────────────────────────
    conn.execute(text(
        "CREATE INDEX IF NOT EXISTS idx_cf_resource_uid_trgm "
        "ON compliance_findings USING gin(resource_uid gin_trgm_ops)"
    ))


def downgrade():
    conn = op.get_bind()
    conn.execute(text("DROP INDEX IF EXISTS idx_cf_resource_uid_trgm"))
    conn.execute(text(
        "ALTER TABLE compliance_findings ADD COLUMN IF NOT EXISTS resource_arn TEXT"
    ))
    conn.execute(text(
        "CREATE INDEX IF NOT EXISTS idx_cf_resource_arn_trgm "
        "ON compliance_findings USING gin(resource_arn gin_trgm_ops)"
    ))
