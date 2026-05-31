"""
DI Reader — reads from asset_inventory (threat_engine_di).

Drop-in replacement for InventoryReader. Returns the same dict shape from
read_discovery_records() so CheckEngine works without any other changes.

Active when DI_ENGINE_ENABLED=true on the engine pod.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

import psycopg2
import psycopg2.extras
from psycopg2.pool import SimpleConnectionPool

logger = logging.getLogger(__name__)


def _di_db_config() -> Dict[str, Any]:
    return {
        "host": os.getenv("DI_DB_HOST", os.getenv("DB_HOST", "localhost")),
        "port": int(os.getenv("DI_DB_PORT", os.getenv("DB_PORT", "5432"))),
        "database": os.getenv("DI_DB_NAME", "threat_engine_di"),
        "user": os.getenv("DI_DB_USER", os.getenv("DB_USER", "postgres")),
        "password": (
            os.getenv("DI_DB_PASSWORD")
            or os.getenv("DB_PASSWORD")
            or ""
        ),
    }


class DIReader:
    """Reads resources from asset_inventory in threat_engine_di.

    Same interface as InventoryReader — read_discovery_records() returns
    the same dict shape including emitted_fields already flattened.
    """

    def __init__(self, db_config: Optional[Dict] = None):
        self.db_config: Dict[str, Any] = db_config or _di_db_config()
        logger.info(
            "DIReader: %s on %s",
            self.db_config["database"],
            self.db_config["host"],
        )
        self._pool: Optional[SimpleConnectionPool] = None
        self._init_pool()

    def _init_pool(self) -> None:
        self._pool = SimpleConnectionPool(
            1, 5,
            host=self.db_config["host"],
            port=self.db_config["port"],
            database=self.db_config["database"],
            user=self.db_config["user"],
            password=self.db_config["password"],
            connect_timeout=10,
        )

    def _get_connection(self):
        if not self._pool:
            self._init_pool()
        return self._pool.getconn()

    def _return_connection(self, conn) -> None:
        if self._pool and conn:
            self._pool.putconn(conn)

    def read_discovery_records(
        self,
        discovery_id: str = None,
        tenant_id: str = None,
        account_id: str = None,
        scan_id: str = None,
        service: str = None,
    ) -> List[Dict]:
        """Read asset_inventory records in InventoryReader-compatible format.

        Each row in asset_inventory corresponds to exactly one discovery op.
        discovery_id matches the check rule's for_each value directly — no
        translation needed. emitted_fields contains only that op's output fields.
        psycopg2 auto-deserializes JSONB; never call json.loads() on emitted_fields.
        """
        conn = self._get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                query = """
                    SELECT resource_uid,
                           resource_uid AS resource_id,
                           resource_type AS service,
                           service AS svc_name,
                           region, scan_run_id, account_id, tenant_id,
                           emitted_fields, raw_response,
                           discovery_id
                    FROM   asset_inventory
                    WHERE  1=1
                """
                params: List[Any] = []

                if scan_id:
                    query += " AND scan_run_id = %s"
                    params.append(scan_id)
                if discovery_id:
                    query += " AND discovery_id = %s"
                    params.append(discovery_id)
                if tenant_id:
                    query += " AND tenant_id = %s"
                    params.append(tenant_id)
                # account_id filter skipped when scan_id is present — scan_run_id is
                # globally unique, and DI stores the cloud account number (e.g. "588989875114")
                # while check engine receives the internal UUID. Filtering by both would
                # return 0 rows due to the mismatch.
                if account_id and not scan_id:
                    query += " AND account_id = %s"
                    params.append(account_id)

                cur.execute(query, params)
                rows = cur.fetchall()

            result: List[Dict] = []
            for row in rows:
                rec = dict(row)

                # emitted_fields is JSONB — psycopg2 auto-deserializes, never json.loads()
                ef = rec.get("emitted_fields") or {}

                rec["emitted_fields"] = ef

                # Extract service from discovery_id for compatibility
                did = rec.get("discovery_id", "")
                if did and "." in did:
                    parts = did.split(".")
                    if len(parts) >= 2:
                        rec["service"] = parts[1]

                result.append(rec)

            logger.debug(
                "DIReader: %d records discovery_id=%s scan_id=%s",
                len(result), discovery_id, scan_id,
            )
            return result

        except Exception as exc:
            logger.error("DIReader.read_discovery_records failed: %s", exc)
            return []
        finally:
            self._return_connection(conn)

    def close(self) -> None:
        if self._pool:
            self._pool.closeall()
