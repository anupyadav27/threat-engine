"""Enable Row-Level Security on threat engine tables.

Revision ID: 0002_threat_rls
Revises: 0001_threat_baseline

RLS strategy
------------
* ENABLE + FORCE ROW LEVEL SECURITY so the policy applies to *all* roles,
  including the table owner (``postgres``).
* ``ALTER ROLE postgres BYPASSRLS`` lets the postgres user skip RLS — existing
  engine code (which connects as postgres and does not call rls.py) continues
  to work unchanged.
* New application-level users must set ``app.tenant_id`` via rls.py helpers
  before querying these tables.

Tables covered (all have tenant_id VARCHAR(255) NOT NULL):
  threat_report, threat_findings, threat_intelligence, threat_detections,
  threat_analysis, threat_hunt_queries, threat_hunt_results
"""
from alembic import op

revision = "0002_threat_rls"
down_revision = "0001_threat_baseline"
branch_labels = None
depends_on = None

_TABLES = [
    "threat_report",
    "threat_findings",
    "threat_intelligence",
    "threat_detections",
    "threat_analysis",
    "threat_hunt_queries",
    "threat_hunt_results",
]


def upgrade() -> None:
    # postgres user bypasses RLS so existing code is unaffected
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
