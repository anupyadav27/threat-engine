"""
Inventory Reader — reads from inventory_findings table (inventory DB).

Drop-in replacement for DiscoveryReader. Returns the same dict shape so the
check engine can use either reader without changes. The `discovery_id` and
`emitted_fields` are extracted from the `properties` JSONB column.

Config from INVENTORY_DB_* env vars (with DB_* fallback).
"""

import os
import json
import logging
import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2.pool import SimpleConnectionPool
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class InventoryReader:
    """Reads resources from inventory_findings (inventory DB).

    Same interface as DiscoveryReader so the check engine can swap seamlessly.
    """

    def __init__(self, db_config: Optional[Dict] = None):
        self.db_config: Dict[str, Any] = db_config or {
            "host": os.getenv(
                "INVENTORY_DB_HOST",
                os.getenv("DB_HOST", "localhost"),
            ),
            "port": int(os.getenv(
                "INVENTORY_DB_PORT",
                os.getenv("DB_PORT", "5432"),
            )),
            "database": os.getenv(
                "INVENTORY_DB_NAME", "threat_engine_inventory",
            ),
            "user": os.getenv(
                "INVENTORY_DB_USER",
                os.getenv("DB_USER", "postgres"),
            ),
            "password": os.getenv(
                "INVENTORY_DB_PASSWORD",
                os.getenv("DB_PASSWORD", ""),
            ),
        }
        logger.info(
            "InventoryReader: %s on %s",
            self.db_config["database"],
            self.db_config["host"],
        )
        self._pool: Optional[SimpleConnectionPool] = None
        self._init_pool()

    def _init_pool(self) -> None:
        try:
            self._pool = SimpleConnectionPool(
                1, 5,
                host=self.db_config["host"],
                port=self.db_config["port"],
                database=self.db_config["database"],
                user=self.db_config["user"],
                password=self.db_config["password"],
                connect_timeout=10,
            )
        except Exception as exc:
            logger.error("InventoryReader pool init failed: %s", exc)
            raise

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
        """
        Read inventory records, returning them in DiscoveryReader-compatible format.

        Queries inventory_findings and extracts discovery_id + emitted_fields
        from the properties JSONB column.

        Filters by discovery_id by checking properties->>'discovery_id'.
        """
        conn = self._get_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                query = """
                    SELECT resource_uid, resource_id,
                           properties, configuration,
                           resource_type AS service,
                           region, scan_run_id,
                           account_id, tenant_id,
                           properties->>'discovery_id' AS discovery_id
                    FROM   inventory_findings
                    WHERE  1=1
                """
                params: List[Any] = []

                if scan_id:
                    query += " AND scan_run_id = %s"
                    params.append(scan_id)
                if discovery_id:
                    query += " AND properties->>'discovery_id' = %s"
                    params.append(discovery_id)
                if tenant_id:
                    query += " AND tenant_id = %s"
                    params.append(tenant_id)
                if account_id:
                    query += " AND account_id = %s"
                    params.append(account_id)

                cur.execute(query, params)
                rows = cur.fetchall()

            result: List[Dict] = []
            for row in rows:
                rec = dict(row)

                # Extract emitted_fields from properties JSONB
                props = rec.pop("properties", {}) or {}
                if isinstance(props, str):
                    try:
                        props = json.loads(props)
                    except (json.JSONDecodeError, TypeError):
                        props = {}

                ef = props.get("emitted_fields", {})
                if isinstance(ef, str):
                    try:
                        ef = json.loads(ef)
                    except (json.JSONDecodeError, TypeError):
                        ef = {}

                # Merge configuration into emitted_fields (enrichment data)
                config = rec.pop("configuration", {}) or {}
                if isinstance(config, str):
                    try:
                        config = json.loads(config)
                    except (json.JSONDecodeError, TypeError):
                        config = {}
                if config:
                    ef["_configuration"] = config

                rec["emitted_fields"] = ef
                rec["discovery_id"] = props.get("discovery_id", "")

                # Extract service from discovery_id (aws.ec2.describe_instances → ec2)
                did = rec.get("discovery_id", "")
                if did and "." in did:
                    parts = did.split(".")
                    if len(parts) >= 2:
                        rec["service"] = parts[1]

                result.append(rec)

            logger.debug(
                "InventoryReader: %d records for discovery_id=%s scan_id=%s",
                len(result), discovery_id, scan_id,
            )
            return result

        except Exception as exc:
            logger.error("InventoryReader.read_discovery_records failed: %s", exc)
            return []
        finally:
            self._return_connection(conn)

    def close(self) -> None:
        if self._pool:
            self._pool.closeall()
