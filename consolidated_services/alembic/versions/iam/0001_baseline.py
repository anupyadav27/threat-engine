"""Baseline — marks existing iam DB schema as applied.

Revision:  0001_iam_baseline
Previous:  None (initial)
Engine:    iam
Database:  threat_engine_iam
"""
from __future__ import annotations
from alembic import op

revision = "0001_iam_baseline"
down_revision = None
branch_labels = None
depends_on = None

def upgrade() -> None:
    pass

def downgrade() -> None:
    pass
