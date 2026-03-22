"""Enable Row-Level Security on check engine tables.

Revision ID: 0003_check_rls
Revises: 0002_check_filter_rules

Tables covered: check_report, check_findings

Note: rule_checks, rule_metadata, rule_discoveries are *shared configuration*
tables with nullable tenant_id — RLS is NOT applied to them.
"""
from alembic import op

revision = "0003_check_rls"
down_revision = "0002_check_filter_rules"
branch_labels = None
depends_on = None

_TABLES = [
    "check_report",
    "check_findings",
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
