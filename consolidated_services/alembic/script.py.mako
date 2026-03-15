"""${message}

Revision:      ${up_revision}
Previous:      ${down_revision | comma,n}
Date:          ${create_date}
Engine:        (set ALEMBIC_ENGINE or use -x engine=<name>)
Database:      threat_engine_<engine>

Description:
    (TODO: describe what this migration does)
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
${imports if imports else ""}

# revision identifiers, used by Alembic.
revision = ${repr(up_revision)}
down_revision = ${repr(down_revision)}
branch_labels = ${repr(branch_labels)}
depends_on = ${repr(depends_on)}


def upgrade() -> None:
    ${upgrades if upgrades else "pass"}


def downgrade() -> None:
    ${downgrades if downgrades else "pass"}
