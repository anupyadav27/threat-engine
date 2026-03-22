"""Add filter_rules column to rule_discoveries.

Revision:  0002_check_filter_rules
Previous:  0001_check_baseline
Engine:    check
Database:  threat_engine_check

Description:
    Adds a JSONB filter_rules column to rule_discoveries enabling database-
    driven filtering to replace hardcoded filter logic in the discoveries engine.
    The column stores api_filters (pre-call) and response_filters (post-call).

    Idempotent: uses ADD COLUMN IF NOT EXISTS and CREATE INDEX IF NOT EXISTS.
"""
from __future__ import annotations
from alembic import op
import sqlalchemy as sa

revision = "0002_check_filter_rules"
down_revision = "0001_check_baseline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE rule_discoveries
        ADD COLUMN IF NOT EXISTS filter_rules JSONB DEFAULT '{}'::jsonb
    """)

    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_rule_discoveries_filter_rules
        ON rule_discoveries USING gin(filter_rules)
    """)

    op.execute("""
        COMMENT ON COLUMN rule_discoveries.filter_rules IS
        'Database-driven filter rules for AWS-managed resource filtering. '
        'Contains api_filters (pre-call) and response_filters (post-call) arrays.'
    """)


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_rule_discoveries_filter_rules")
    op.execute("ALTER TABLE rule_discoveries DROP COLUMN IF EXISTS filter_rules")
