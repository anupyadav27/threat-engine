"""Create resource_inventory_identifier table.

Revision:  0002_inventory_rii_table
Previous:  0001_inventory_baseline
Engine:    inventory
Database:  threat_engine_inventory

Description:
    Creates the resource_inventory_identifier (RII) table — the static step5
    resource catalog. Stores ARN entity paths, identifier patterns, and
    root/enrich operation lists per (csp, service, resource_type).

    The inventory engine reads this table at scan time to:
    - Determine which AWS API calls to make for each service
    - Extract ARN values from discovery_findings fields
    - Classify resources as PRIMARY / SUB_RESOURCE / CONFIGURATION / EPHEMERAL

    Idempotent: CREATE TABLE IF NOT EXISTS, CREATE INDEX IF NOT EXISTS.
"""
from __future__ import annotations
from alembic import op
import sqlalchemy as sa

revision = "0002_inventory_rii_table"
down_revision = "0001_inventory_baseline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Ensure the updated_at trigger function exists
    op.execute("""
        CREATE OR REPLACE FUNCTION update_inventory_updated_at_column()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.updated_at = NOW();
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
    """)

    op.execute("""
        CREATE TABLE IF NOT EXISTS resource_inventory_identifier (
            id                        BIGSERIAL PRIMARY KEY,

            csp                       VARCHAR(50)   NOT NULL,
            service                   VARCHAR(100)  NOT NULL,
            resource_type             VARCHAR(255)  NOT NULL,
            classification            VARCHAR(50)   NOT NULL,

            has_arn                   BOOLEAN       NOT NULL DEFAULT TRUE,
            arn_entity                VARCHAR(500),
            identifier_type           VARCHAR(50)   DEFAULT 'arn',
            primary_param             VARCHAR(255),
            identifier_pattern        VARCHAR(1000),

            can_inventory_from_roots  BOOLEAN NOT NULL DEFAULT TRUE,
            should_inventory          BOOLEAN NOT NULL DEFAULT TRUE,

            root_ops                  JSONB NOT NULL DEFAULT '[]',
            enrich_ops                JSONB NOT NULL DEFAULT '[]',
            raw_catalog               JSONB,

            loaded_at                 TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
            updated_at                TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

            CONSTRAINT rii_unique UNIQUE (csp, service, resource_type)
        )
    """)

    op.execute("CREATE INDEX IF NOT EXISTS idx_rii_csp_service ON resource_inventory_identifier(csp, service)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_rii_csp ON resource_inventory_identifier(csp)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_rii_classification ON resource_inventory_identifier(classification)")
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_rii_should_inventory
        ON resource_inventory_identifier(should_inventory)
        WHERE should_inventory = TRUE
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_rii_arn_entity
        ON resource_inventory_identifier(arn_entity)
        WHERE arn_entity IS NOT NULL
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_rii_root_ops_gin ON resource_inventory_identifier USING GIN(root_ops)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_rii_enrich_ops_gin ON resource_inventory_identifier USING GIN(enrich_ops)")

    op.execute("""
        DROP TRIGGER IF EXISTS update_rii_updated_at ON resource_inventory_identifier
    """)
    op.execute("""
        CREATE TRIGGER update_rii_updated_at
            BEFORE UPDATE ON resource_inventory_identifier
            FOR EACH ROW EXECUTE FUNCTION update_inventory_updated_at_column()
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS resource_inventory_identifier CASCADE")
