"""Baseline — marks existing discoveries DB schema as applied.

Revision:  0001_discoveries_baseline
Previous:  None (initial)
Engine:    discoveries
Database:  threat_engine_discoveries
"""
from __future__ import annotations
from alembic import op

revision = "0001_discoveries_baseline"
down_revision = None
branch_labels = None
depends_on = None

def upgrade() -> None:
    pass

def downgrade() -> None:
    pass
