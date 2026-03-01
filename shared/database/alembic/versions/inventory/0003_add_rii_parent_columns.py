"""Add parent_service and parent_resource_type to resource_inventory_identifier.

Revision:  0003_inventory_rii_parent_cols
Previous:  0002_inventory_rii_table
Engine:    inventory
Database:  threat_engine_inventory

Description:
    Adds parent_service and parent_resource_type columns to
    resource_inventory_identifier so the inventory engine knows which parent
    resource to use when fetching sub-resources (Pass 2 enrichment).

    Sub-resources (e.g. bucket_versioning, security_group, role_policy) cannot
    be listed independently — they require the parent resource's identifier.
    By storing parent_resource_type the engine can:
      1. Find the parent asset in the assets index (Pass 1)
      2. Extract the required_param value from parent's emitted_fields
      3. Match the enrichment record back to the parent (Pass 2)

    Idempotent: uses ADD COLUMN IF NOT EXISTS.
"""
from __future__ import annotations
from alembic import op
import sqlalchemy as sa

revision = "0003_inventory_rii_parent_cols"
down_revision = "0002_inventory_rii_table"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE resource_inventory_identifier
            ADD COLUMN IF NOT EXISTS parent_service       VARCHAR(100),
            ADD COLUMN IF NOT EXISTS parent_resource_type VARCHAR(255)
    """)

    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_rii_parent
            ON resource_inventory_identifier(csp, parent_service, parent_resource_type)
            WHERE parent_resource_type IS NOT NULL
    """)

    op.execute("""
        COMMENT ON COLUMN resource_inventory_identifier.parent_service IS
        'Service name of the parent resource (NULL for root resources). '
        'e.g. "s3" for bucket_versioning, "ec2" for security_group.'
    """)

    op.execute("""
        COMMENT ON COLUMN resource_inventory_identifier.parent_resource_type IS
        'resource_type of the parent within parent_service (NULL for root resources). '
        'e.g. "bucket" for bucket_versioning, "vpc" for security_group, "role" for role_policy.'
    """)


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_rii_parent")
    op.execute("""
        ALTER TABLE resource_inventory_identifier
            DROP COLUMN IF EXISTS parent_service,
            DROP COLUMN IF EXISTS parent_resource_type
    """)
