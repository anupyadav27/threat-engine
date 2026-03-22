"""Enable Row-Level Security on onboarding engine tables.

Revision ID: 0002_onboarding_rls
Revises: 0001_onboarding_baseline

Tables covered: cloud_accounts, scan_orchestration
"""
from alembic import op

revision = "0002_onboarding_rls"
down_revision = "0001_onboarding_baseline"
branch_labels = None
depends_on = None

_TABLES = [
    "cloud_accounts",
    "scan_orchestration",
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
