"""Drop resource_arn column — consolidate to resource_uid.

Revision ID: 0003_drop_resource_arn
Revises: 0002_enable_rls

resource_uid now holds the canonical ARN (or CSP-native identifier).
resource_arn is redundant. This migration:

threat_findings:
  - Has BOTH resource_arn and resource_uid → backfill uid from arn, drop arn

threat_detections:
  - Has ONLY resource_arn (no resource_uid) → add resource_uid, copy data,
    create index, drop old column + index
"""
from alembic import op
from sqlalchemy import text

revision = "0003_drop_resource_arn"
down_revision = "0002_enable_rls"
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()

    # ═══ threat_findings ═══════════════════════════════════════════════════

    # Step 1: Backfill resource_uid from resource_arn where missing
    conn.execute(text("""
        UPDATE threat_findings
        SET resource_uid = resource_arn
        WHERE (resource_uid IS NULL OR resource_uid = '')
          AND resource_arn IS NOT NULL
          AND resource_arn != ''
    """))

    # Step 2: Drop resource_arn column (no dedicated index on it)
    conn.execute(text(
        "ALTER TABLE threat_findings DROP COLUMN IF EXISTS resource_arn"
    ))

    # ═══ threat_detections ═════════════════════════════════════════════════

    # Step 3: Add resource_uid column
    conn.execute(text(
        "ALTER TABLE threat_detections ADD COLUMN IF NOT EXISTS resource_uid TEXT"
    ))

    # Step 4: Copy data from resource_arn → resource_uid
    conn.execute(text("""
        UPDATE threat_detections
        SET resource_uid = resource_arn
        WHERE resource_arn IS NOT NULL
          AND (resource_uid IS NULL OR resource_uid = '')
    """))

    # Step 5: Create index on new resource_uid column
    conn.execute(text(
        "CREATE INDEX IF NOT EXISTS idx_detection_resource_uid "
        "ON threat_detections(resource_uid)"
    ))

    # Step 6: Drop old index + column
    conn.execute(text("DROP INDEX IF EXISTS idx_detection_resource"))
    conn.execute(text(
        "ALTER TABLE threat_detections DROP COLUMN IF EXISTS resource_arn"
    ))


def downgrade():
    conn = op.get_bind()

    # Restore threat_findings.resource_arn
    conn.execute(text(
        "ALTER TABLE threat_findings ADD COLUMN IF NOT EXISTS resource_arn TEXT"
    ))

    # Restore threat_detections.resource_arn
    conn.execute(text(
        "ALTER TABLE threat_detections ADD COLUMN IF NOT EXISTS resource_arn TEXT"
    ))
    conn.execute(text("""
        UPDATE threat_detections SET resource_arn = resource_uid
        WHERE resource_arn IS NULL AND resource_uid IS NOT NULL
    """))
    conn.execute(text(
        "CREATE INDEX IF NOT EXISTS idx_detection_resource "
        "ON threat_detections(resource_arn)"
    ))

    # Drop resource_uid from threat_detections (was added in upgrade)
    conn.execute(text("DROP INDEX IF EXISTS idx_detection_resource_uid"))
    conn.execute(text(
        "ALTER TABLE threat_detections DROP COLUMN IF EXISTS resource_uid"
    ))
