"""Enable Row-Level Security on DataSec engine tables.

Revision ID: 0002_datasec_rls
Revises: 0001_datasec_baseline

Tables covered: datasec_report, datasec_findings
"""
from alembic import op

revision = "0002_datasec_rls"
down_revision = "0001_datasec_baseline"
branch_labels = None
depends_on = None

_TABLES = [
    "datasec_report",
    "datasec_findings",
]


def upgrade() -> None:
    op.execute("ALTER ROLE postgres BYPASSRLS")

    for table in _TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(f"""
            CREATE POLICY tenant_isolation ON {table}
                AS PERMISSIVE FOR ALL TO PUBLIC
                USING (tenant_id = current_setting('app.tenant_id', TRUE))
                WITH CHECK (tenant_id = current_setting('app.tenant_id', TRUE))
        """)


def downgrade() -> None:
    for table in reversed(_TABLES):
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
        op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
