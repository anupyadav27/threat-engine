"""Enable Row-Level Security on SecOps engine tables.

Revision ID: 0002_secops_rls
Revises: 0001_secops_baseline

Tables covered: secops_report, secops_findings
"""
from alembic import op

revision = "0002_secops_rls"
down_revision = "0001_secops_baseline"
branch_labels = None
depends_on = None

_TABLES = [
    "secops_report",
    "secops_findings",
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
