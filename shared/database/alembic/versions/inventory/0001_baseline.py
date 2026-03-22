"""Baseline — marks existing inventory DB schema as applied.

Revision:  0001_inventory_baseline
Previous:  None (initial)
Engine:    inventory
Database:  threat_engine_inventory

Description:
    Baseline revision representing the state of threat_engine_inventory as of
    2026-03-01 (migrations 001–011 already applied via migration_runner.py).

    For EXISTING production DB:
        alembic -x engine=inventory stamp 0001_inventory_baseline
    Then future migrations will be tracked from here.

    For a BRAND NEW DB:
        1. Apply shared/database/schemas/inventory_schema.sql first
        2. Then: alembic -x engine=inventory upgrade head
"""
from __future__ import annotations
from alembic import op

revision = "0001_inventory_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
