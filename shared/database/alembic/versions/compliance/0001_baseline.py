"""Baseline — marks existing compliance DB schema as applied.

Revision:  0001_compliance_baseline
Previous:  None (initial)
Engine:    compliance
Database:  threat_engine_compliance
"""
from __future__ import annotations
from alembic import op

revision = "0001_compliance_baseline"
down_revision = None
branch_labels = None
depends_on = None

def upgrade() -> None:
    pass

def downgrade() -> None:
    pass
