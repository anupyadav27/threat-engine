"""
DB Writer — minimal write operations for vul_fix engine.

The vul_remediation table is no longer used.
All remediation output is stored in Git as Ansible playbooks.

This module retains only:
  drop_remediation_table() — one-time cleanup to remove the old table from the DB
"""

import logging

from .db_config import get_connection

logger = logging.getLogger(__name__)


def drop_remediation_table() -> bool:
    """
    Drop the vul_remediation table if it exists.
    Safe to call multiple times (idempotent).

    Returns True if the table was dropped, False if it did not exist.
    """
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT EXISTS (
                    SELECT 1 FROM information_schema.tables
                    WHERE table_name = 'vul_remediation'
                )
            """)
            exists = cur.fetchone()[0]
            if exists:
                cur.execute("DROP TABLE vul_remediation CASCADE")
                conn.commit()
                logger.info("vul_remediation table dropped successfully.")
                return True
            else:
                logger.info("vul_remediation table does not exist — nothing to drop.")
                return False
    except Exception as e:
        logger.error(f"Failed to drop vul_remediation table: {e}")
        raise
    finally:
        conn.close()
