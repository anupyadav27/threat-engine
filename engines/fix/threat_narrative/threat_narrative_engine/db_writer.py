"""
Database writer for the Threat Narrative Engine.

Writes LLM-generated narrative fields to the threat_detections table.
All queries are parameterized — no f-string SQL.
"""

import logging
import os

import psycopg2

logger = logging.getLogger("threat_narrative")


def _resolve_password(prefix: str) -> str:
    """Resolve DB password with three-level fallback.

    Args:
        prefix: DB env var prefix (e.g. "THREAT").

    Returns:
        Password string, may be empty if not configured.
    """
    p = prefix.upper()
    return (
        os.getenv(f"{p}_DB_PASSWORD")
        or os.getenv("DB_PASSWORD")
        or os.getenv("DISCOVERIES_DB_PASSWORD", "")
    )


def _get_threat_conn() -> psycopg2.extensions.connection:
    """Open a connection to the threat DB.

    Returns:
        An open psycopg2 connection.

    Raises:
        psycopg2.OperationalError: If connection fails.
    """
    return psycopg2.connect(
        host=os.getenv("THREAT_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("THREAT_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("THREAT_DB_NAME", "threat_engine_threat"),
        user=os.getenv("THREAT_DB_USER", os.getenv("DB_USER", "postgres")),
        password=_resolve_password("THREAT"),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
        connect_timeout=10,
    )


def write_narrative(
    detection_id: str,
    chain: str,
    stakes: str,
    model: str,
) -> None:
    """Write narrative fields to threat_detections.

    Updates chain_of_consequence, stakes_narrative, narrative_generated_at,
    and narrative_model for the given detection_id. If the detection is not
    found, logs a WARNING and returns silently.

    Args:
        detection_id: The UUID of the threat detection to update.
        chain: The generated chain_of_consequence text (max 500 chars).
        stakes: The generated stakes_narrative text (max 4000 chars).
        model: The LLM model identifier used (e.g. "claude-sonnet-4-6").

    Raises:
        psycopg2.OperationalError: If DB is unreachable (infrastructure failure).
    """
    conn = _get_threat_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE threat_detections
                SET chain_of_consequence  = %s,
                    stakes_narrative       = %s,
                    narrative_generated_at = NOW() AT TIME ZONE 'UTC',
                    narrative_model        = %s
                WHERE detection_id = %s::uuid
                """,
                (chain, stakes, model, detection_id),
            )
            updated = cur.rowcount
        conn.commit()

        if updated == 0:
            logger.warning(
                "write_narrative: detection_id not found — skipping write",
                extra={"detection_id": detection_id},
            )
        else:
            logger.info(
                "Narrative written successfully",
                extra={"detection_id": detection_id, "model": model},
            )
    except psycopg2.OperationalError:
        conn.rollback()
        raise
    except Exception as exc:
        conn.rollback()
        logger.error(
            "Failed to write narrative",
            extra={"detection_id": detection_id, "error": str(exc)},
        )
        raise
    finally:
        conn.close()


def check_threat_db_connection() -> bool:
    """Test that the threat DB is reachable.

    Used by the /health/ready endpoint.

    Returns:
        True if the DB is reachable, False otherwise.
    """
    try:
        conn = _get_threat_conn()
        conn.close()
        return True
    except Exception:
        return False
