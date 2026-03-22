"""Baseline — marks existing check DB schema as applied.

Revision:  0001_check_baseline
Previous:  None (initial)
Engine:    check
Database:  threat_engine_check

Description:
    Baseline revision representing the state of threat_engine_check as of
    2026-03-01 (migrations 001–010 already applied via migration_runner.py).

    For EXISTING production DB:
        alembic -x engine=check stamp 0001_check_baseline
    Then future migrations will be tracked from here.

    For a BRAND NEW DB:
        1. Apply shared/database/schemas/check_schema.sql first
        2. Then: alembic -x engine=check upgrade head
        This migration is a no-op so it stamps safely after schema creation.
"""
from __future__ import annotations
from alembic import op

revision = "0001_check_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # No-op: schema already applied via check_schema.sql + migration_runner.py
    pass


def downgrade() -> None:
    # Cannot undo initial baseline
    pass
