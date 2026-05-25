"""
Database writer for the Attack Path Narrative Engine.

Writes LLM-generated narrative fields to the attack_paths table.
All queries are parameterized — no f-string SQL.
"""

import logging
import os

import psycopg2

logger = logging.getLogger("threat_narrative")


def _resolve_password(prefix: str) -> str:
    p = prefix.upper()
    return (
        os.getenv(f"{p}_DB_PASSWORD")
        or os.getenv("DB_PASSWORD")
        or os.getenv("DISCOVERIES_DB_PASSWORD", "")
    )


def _get_attack_path_conn() -> psycopg2.extensions.connection:
    """Open a connection to the attack_path DB."""
    return psycopg2.connect(
        host=os.getenv("ATTACK_PATH_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("ATTACK_PATH_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("ATTACK_PATH_DB_NAME", "threat_engine_attack_path"),
        user=os.getenv("ATTACK_PATH_DB_USER", os.getenv("DB_USER", "postgres")),
        password=_resolve_password("ATTACK_PATH"),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
        connect_timeout=10,
    )


def write_narrative(
    detection_id: str,
    chain: str,
    stakes: str,
    model: str,
) -> None:
    """Write narrative fields to attack_paths.

    Updates attack_story with the LLM-generated stakes narrative and sets
    narrative metadata. `detection_id` is a path_id in the new architecture.

    Args:
        detection_id: The path_id of the attack path to update.
        chain: The generated chain_of_consequence text (max 500 chars).
        stakes: The generated stakes_narrative text (max 4000 chars).
        model: The LLM model identifier used.

    Raises:
        psycopg2.OperationalError: If DB is unreachable (infrastructure failure).
    """
    conn = _get_attack_path_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE attack_paths
                SET attack_story = %s,
                    updated_at   = NOW() AT TIME ZONE 'UTC'
                WHERE path_id = %s
                """,
                (stakes or chain, detection_id),
            )
            updated = cur.rowcount
        conn.commit()

        if updated == 0:
            logger.warning(
                "write_narrative: path_id not found — skipping write",
                extra={"path_id": detection_id},
            )
        else:
            logger.info(
                "Attack path narrative written",
                extra={"path_id": detection_id, "model": model},
            )
    except psycopg2.OperationalError:
        conn.rollback()
        raise
    except Exception as exc:
        conn.rollback()
        logger.error(
            "Failed to write attack path narrative",
            extra={"path_id": detection_id, "error": str(exc)},
        )
        raise
    finally:
        conn.close()


def check_threat_db_connection() -> bool:
    """Test that the attack_path DB is reachable (used by /health/ready)."""
    try:
        conn = _get_attack_path_conn()
        conn.close()
        return True
    except Exception:
        return False
