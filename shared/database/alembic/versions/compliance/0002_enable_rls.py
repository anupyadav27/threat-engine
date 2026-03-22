"""Enable Row-Level Security on compliance engine tables.

Revision ID: 0002_compliance_rls
Revises: 0001_compliance_baseline

Tables covered:
  compliance_report, compliance_findings, compliance_assessments,
  control_assessment_results, remediation_tracking
"""
from alembic import op

revision = "0002_compliance_rls"
down_revision = "0001_compliance_baseline"
branch_labels = None
depends_on = None

_TABLES = [
    "compliance_report",
    "compliance_findings",
    "compliance_assessments",
    "control_assessment_results",
    "remediation_tracking",
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
