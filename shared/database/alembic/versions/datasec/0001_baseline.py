"""Baseline — marks existing datasec DB schema as applied.

Revision:  0001_datasec_baseline
Previous:  None (initial)
Engine:    datasec
Database:  threat_engine_datasec
"""
from __future__ import annotations
from alembic import op

revision = "0001_datasec_baseline"
down_revision = None
branch_labels = None
depends_on = None

def upgrade() -> None:
    pass

def downgrade() -> None:
    pass
