"""Baseline — marks existing secops DB schema as applied.

Revision:  0001_secops_baseline
Previous:  None (initial)
Engine:    secops
Database:  threat_engine_secops
"""
from __future__ import annotations
from alembic import op

revision = "0001_secops_baseline"
down_revision = None
branch_labels = None
depends_on = None

def upgrade() -> None:
    pass

def downgrade() -> None:
    pass
