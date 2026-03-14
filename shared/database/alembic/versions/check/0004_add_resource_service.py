"""Add resource_service column to check_findings and rule_metadata.

Revision ID: 0004_check_resource_service
Revises: 0003_check_rls

Tracks the actual AWS service a resource belongs to, which may differ
from the directory/discovery service for cross-service rules (e.g.,
EC2 rules evaluating IAM instance profile associations).
"""
from alembic import op

revision = "0004_check_resource_service"
down_revision = "0003_check_rls"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add resource_service to rule_metadata
    op.execute("""
        ALTER TABLE rule_metadata
        ADD COLUMN IF NOT EXISTS resource_service VARCHAR(100)
    """)

    # Add resource_service, service, discovery_id to check_findings
    op.execute("""
        ALTER TABLE check_findings
        ADD COLUMN IF NOT EXISTS resource_service VARCHAR(100)
    """)
    op.execute("""
        ALTER TABLE check_findings
        ADD COLUMN IF NOT EXISTS service VARCHAR(100)
    """)
    op.execute("""
        ALTER TABLE check_findings
        ADD COLUMN IF NOT EXISTS discovery_id VARCHAR(255)
    """)

    # Indexes
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_rm_resource_service
        ON rule_metadata(resource_service)
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_cf_resource_service
        ON check_findings(resource_service)
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_cf_service
        ON check_findings(service)
    """)

    # Backfill: resource_service = service where NULL
    op.execute("""
        UPDATE rule_metadata
        SET resource_service = service
        WHERE resource_service IS NULL
    """)
    op.execute("""
        UPDATE check_findings
        SET resource_service = resource_type
        WHERE resource_service IS NULL AND resource_type IS NOT NULL
    """)


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_cf_service")
    op.execute("DROP INDEX IF EXISTS idx_cf_resource_service")
    op.execute("DROP INDEX IF EXISTS idx_rm_resource_service")
    op.execute("ALTER TABLE check_findings DROP COLUMN IF EXISTS discovery_id")
    op.execute("ALTER TABLE check_findings DROP COLUMN IF EXISTS service")
    op.execute("ALTER TABLE check_findings DROP COLUMN IF EXISTS resource_service")
    op.execute("ALTER TABLE rule_metadata DROP COLUMN IF EXISTS resource_service")
