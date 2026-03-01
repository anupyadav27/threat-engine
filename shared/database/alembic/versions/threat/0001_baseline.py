"""Baseline — marks existing threat DB schema as applied.

Revision:  0001_threat_baseline
Previous:  None (initial)
Engine:    threat
Database:  threat_engine_threat
"""
from __future__ import annotations
from alembic import op

revision = "0001_threat_baseline"
down_revision = None
branch_labels = None
depends_on = None

def upgrade() -> None:
    pass

def downgrade() -> None:
    pass
