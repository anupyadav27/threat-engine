"""Add workflow columns to threat_findings.

Revision ID: 0004_add_workflow_columns
Revises: 0003_drop_resource_arn
Engine: threat
Database: threat_engine_threat

Description:
    Adds assignee, notes, status_changed_at, and status_changed_by columns
    to threat_findings so the PATCH /api/v1/threat/{threat_id} endpoint can
    persist workflow state directly in the row instead of only inside the
    report JSONB blob.

    Also adds partial indexes on assignee and status_changed_at for
    efficient filtering of assigned / recently-triaged findings.
"""
from __future__ import annotations

from alembic import op
from sqlalchemy import text


revision = "0004_add_workflow_columns"
down_revision = "0003_drop_resource_arn"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add workflow columns and indexes to threat_findings."""
    conn = op.get_bind()

    # -- New columns --------------------------------------------------------
    conn.execute(text(
        "ALTER TABLE threat_findings "
        "ADD COLUMN IF NOT EXISTS assignee VARCHAR(255) DEFAULT NULL"
    ))
    conn.execute(text(
        "ALTER TABLE threat_findings "
        "ADD COLUMN IF NOT EXISTS notes TEXT DEFAULT NULL"
    ))
    conn.execute(text(
        "ALTER TABLE threat_findings "
        "ADD COLUMN IF NOT EXISTS status_changed_at "
        "TIMESTAMP WITH TIME ZONE DEFAULT NULL"
    ))
    conn.execute(text(
        "ALTER TABLE threat_findings "
        "ADD COLUMN IF NOT EXISTS status_changed_by VARCHAR(255) DEFAULT NULL"
    ))

    # -- Indexes ------------------------------------------------------------
    conn.execute(text(
        "CREATE INDEX IF NOT EXISTS idx_tf_assignee "
        "ON threat_findings(assignee) WHERE assignee IS NOT NULL"
    ))
    conn.execute(text(
        "CREATE INDEX IF NOT EXISTS idx_tf_status "
        "ON threat_findings(status)"
    ))
    conn.execute(text(
        "CREATE INDEX IF NOT EXISTS idx_tf_status_changed "
        "ON threat_findings(status_changed_at DESC) "
        "WHERE status_changed_at IS NOT NULL"
    ))


def downgrade() -> None:
    """Remove workflow columns and indexes from threat_findings."""
    conn = op.get_bind()

    conn.execute(text("DROP INDEX IF EXISTS idx_tf_status_changed"))
    conn.execute(text("DROP INDEX IF EXISTS idx_tf_status"))
    conn.execute(text("DROP INDEX IF EXISTS idx_tf_assignee"))

    conn.execute(text(
        "ALTER TABLE threat_findings DROP COLUMN IF EXISTS status_changed_by"
    ))
    conn.execute(text(
        "ALTER TABLE threat_findings DROP COLUMN IF EXISTS status_changed_at"
    ))
    conn.execute(text(
        "ALTER TABLE threat_findings DROP COLUMN IF EXISTS notes"
    ))
    conn.execute(text(
        "ALTER TABLE threat_findings DROP COLUMN IF EXISTS assignee"
    ))
