"""
DI Identifier Helper — shared utility for downstream engine adapters.

Provides get_discovery_ids_for_engine() which replaces the 17+ hardcoded
discovery_id lists previously scattered across engine reader files.

Usage in any engine adapter:
    from engine_common.di_identifier_helper import get_discovery_ids_for_engine

    discovery_ids = get_discovery_ids_for_engine('network', provider)
    # Returns [] on any error — caller must handle empty list gracefully.

Returns [] (not raises) so a temporary inventory DB outage does not crash
downstream scans mid-flight. The caller can either skip or fall back to an
explicit hardcoded list at their discretion.
"""
from __future__ import annotations

import logging
import os
from typing import List

import psycopg2

logger = logging.getLogger("engine_common.di_identifier_helper")


def _get_inventory_conn() -> psycopg2.extensions.connection:
    return psycopg2.connect(
        host=os.getenv("INVENTORY_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("INVENTORY_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("INVENTORY_DB_NAME", "threat_engine_inventory"),
        user=os.getenv("INVENTORY_DB_USER", os.getenv("DB_USER", "postgres")),
        password=(
            os.getenv("INVENTORY_DB_PASSWORD")
            or os.getenv("DB_PASSWORD")
            or os.getenv("DISCOVERIES_DB_PASSWORD", "")
        ),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
        connect_timeout=5,
    )


def get_discovery_ids_for_engine(engine: str, provider: str) -> List[str]:
    """Return discovery_ids for resources used by the given engine + provider.

    The discovery_id is the computed key: '{csp}.{service}.{root_op}'.
    Downstream engine adapters use this to filter asset_inventory rows.

    Args:
        engine: Engine name as stored in used_by_engines JSONB:
                'check', 'network', 'iam', 'datasec', 'encryption',
                'dbsec', 'container', 'ai_security', 'attack_path', 'threat'
        provider: CSP name: 'aws', 'azure', 'gcp', 'oci', 'ibm', 'alicloud', 'k8s'

    Returns:
        List of discovery_id strings. Empty list on error.
    """
    try:
        conn = get_di_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT DISTINCT
                        csp || '.' || service || '.' || COALESCE(
                            root_ops->0->>'operation', 'unknown'
                        ) AS discovery_id
                    FROM di_resource_catalog
                    WHERE used_by_engines @> %s::jsonb
                      AND csp = %s
                      AND show_in_inventory = TRUE
                    """,
                    (f'["{engine}"]', provider),
                )
                rows = cur.fetchall()
        finally:
            conn.close()

        ids = [r[0] for r in rows if r[0] and "unknown" not in r[0]]
        logger.debug(
            "get_discovery_ids_for_engine engine=%s provider=%s → %d ids",
            engine, provider, len(ids),
        )
        return ids

    except Exception as e:
        logger.error(
            "get_discovery_ids_for_engine failed engine=%s provider=%s: %s",
            engine, provider, e,
        )
        return []


def get_di_conn() -> psycopg2.extensions.connection:
    """Return a connection to the DI database (threat_engine_di).

    Used by downstream engine adapters when DI_ENGINE_ENABLED=true.
    Raises on connection failure (no silent fallback at connection level).
    """
    return psycopg2.connect(
        host=os.getenv("DI_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("DI_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("DI_DB_NAME", "threat_engine_di"),
        user=os.getenv("DI_DB_USER", os.getenv("DB_USER", "postgres")),
        password=(
            os.getenv("DI_DB_PASSWORD")
            or os.getenv("DB_PASSWORD")
            or os.getenv("DISCOVERIES_DB_PASSWORD", "")
        ),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
        connect_timeout=10,
    )
