"""Drop resource_arn column — consolidate to resource_uid.

Revision ID: 0003_drop_resource_arn
Revises: 0002_enable_rls

resource_uid now holds the canonical ARN (or CSP-native identifier).
resource_arn is redundant. This migration:
1. Backfills resource_uid from resource_arn where resource_uid is NULL/empty
2. Drops the idx_datasec_findings_resource index (on resource_arn)
3. Drops the resource_arn column from datasec_findings
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
        UPDATE datasec_findings
        SET resource_uid = resource_arn
        WHERE (resource_uid IS NULL OR resource_uid = '')
          AND resource_arn IS NOT NULL
          AND resource_arn != ''
    """))

    # ── Step 2: Drop index on resource_arn ─────────────────────────────────
    conn.execute(text("DROP INDEX IF EXISTS idx_datasec_findings_resource"))

    # ── Step 3: Drop resource_arn column ───────────────────────────────────
    conn.execute(text(
        "ALTER TABLE datasec_findings DROP COLUMN IF EXISTS resource_arn"
    ))


def downgrade():
    conn = op.get_bind()
    conn.execute(text(
        "ALTER TABLE datasec_findings ADD COLUMN IF NOT EXISTS resource_arn TEXT"
    ))
    conn.execute(text(
        "CREATE INDEX IF NOT EXISTS idx_datasec_findings_resource "
        "ON datasec_findings(resource_arn)"
    ))
