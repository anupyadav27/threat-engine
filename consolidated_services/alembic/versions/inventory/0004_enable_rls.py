"""Enable Row-Level Security on inventory engine tables.

Revision ID: 0004_inventory_rls
Revises: 0003_inventory_rii_parent_cols

Tables covered (all tenant_id VARCHAR(255) NOT NULL):
  inventory_report, inventory_scans, inventory_findings,
  inventory_relationships, inventory_asset_history, inventory_drift,
  inventory_asset_tags_index, inventory_asset_collections,
  inventory_asset_collection_membership, inventory_asset_metrics
"""
from alembic import op

revision = "0004_inventory_rls"
down_revision = "0003_inventory_rii_parent_cols"
branch_labels = None
depends_on = None

_TABLES = [
    "inventory_report",
    "inventory_scans",
    "inventory_findings",
    "inventory_relationships",
    "inventory_asset_history",
    "inventory_drift",
    "inventory_asset_tags_index",
    "inventory_asset_collections",
    "inventory_asset_collection_membership",
    "inventory_asset_metrics",
]


def upgrade() -> None:
    op.execute("ALTER ROLE postgres BYPASSRLS")

    for table in _TABLES:
        # Use IF EXISTS in case some tables don't exist yet on older deployments
        op.execute(f"""
            DO $$ BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.tables
                    WHERE table_name = '{table}'
                ) THEN
                    EXECUTE 'ALTER TABLE {table} ENABLE ROW LEVEL SECURITY';
                    EXECUTE 'ALTER TABLE {table} FORCE ROW LEVEL SECURITY';
                    EXECUTE $p$
                        CREATE POLICY tenant_isolation ON {table}
                            AS PERMISSIVE FOR ALL TO PUBLIC
                            USING (tenant_id = current_setting(''app.tenant_id'', TRUE))
                            WITH CHECK (tenant_id = current_setting(''app.tenant_id'', TRUE))
                    $p$;
                END IF;
            END $$
        """)


def downgrade() -> None:
    for table in reversed(_TABLES):
        op.execute(f"""
            DO $$ BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.tables
                    WHERE table_name = '{table}'
                ) THEN
                    EXECUTE 'DROP POLICY IF EXISTS tenant_isolation ON {table}';
                    EXECUTE 'ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY';
                    EXECUTE 'ALTER TABLE {table} DISABLE ROW LEVEL SECURITY';
                END IF;
            END $$
        """)
