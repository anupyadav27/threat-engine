"""
Discovery Reader — reads from discovery_findings table (discoveries DB).

Cross-engine integration: check engine reads what the discovery engine wrote.
All config from DISCOVERY_DB_* env vars (with DISCOVERIES_DB_* fallback).
"""

import os
import json
import logging
import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2.pool import SimpleConnectionPool
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class DiscoveryReader:
    """Reads discovered resources from the discoveries database."""

    def __init__(self, db_config: Optional[Dict] = None):
        self.db_config: Dict[str, Any] = db_config or {
            "host": os.getenv(
                "DISCOVERY_DB_HOST",
                os.getenv("DISCOVERIES_DB_HOST", "localhost"),
            ),
            "port": int(os.getenv(
                "DISCOVERY_DB_PORT",
                os.getenv("DISCOVERIES_DB_PORT", "5432"),
            )),
            "database": os.getenv(
                "DISCOVERY_DB_NAME",
                os.getenv("DISCOVERIES_DB_NAME", "threat_engine_discoveries"),
            ),
            "user": os.getenv(
                "DISCOVERY_DB_USER",
                os.getenv("DISCOVERIES_DB_USER", "postgres"),
            ),
            "password": os.getenv(
                "DISCOVERY_DB_PASSWORD",
                os.getenv("DISCOVERIES_DB_PASSWORD", ""),
            ),
        }
        logger.info(
            "DiscoveryReader: %s on %s",
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
            logger.error("DiscoveryReader pool init failed: %s", exc)
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
        hierarchy_id: str = None,
        scan_id: str = None,
        service: str = None,
    ) -> List[Dict]:
        """
        Read discovery records from discovery_findings.

        Returns one dict per record with 'emitted_fields' parsed to a dict.
        Prefers scan_id filter (most precise) over tenant/hierarchy filters.
        Uses DISTINCT ON (resource_uid) to deduplicate within a scan.
        """
        conn = self._get_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                if scan_id:
                    # Primary path: look up by scan_id (most precise)
                    query = """
                        SELECT DISTINCT ON (resource_uid)
                               resource_uid, resource_id,
                               emitted_fields, service, region,
                               discovery_id, discovery_scan_id,
                               hierarchy_id, tenant_id, account_id
                        FROM   discovery_findings
                        WHERE  discovery_scan_id = %s
                    """
                    params: List[Any] = [scan_id]
                    if discovery_id:
                        query += " AND discovery_id = %s"; params.append(discovery_id)
                    if service:
                        query += " AND service = %s"; params.append(service)
                    if tenant_id:
                        query += " AND tenant_id = %s"; params.append(tenant_id)
                    if hierarchy_id:
                        query += " AND hierarchy_id = %s"; params.append(hierarchy_id)
                    query += " ORDER BY resource_uid, scan_timestamp DESC"
                else:
                    # Fallback: latest records by tenant/hierarchy
                    logger.warning(
                        "DiscoveryReader: no scan_id provided — falling back to latest records"
                    )
                    query = """
                        SELECT DISTINCT ON (resource_uid)
                               resource_uid, resource_id,
                               emitted_fields, service, region,
                               discovery_id, discovery_scan_id,
                               hierarchy_id, tenant_id, account_id
                        FROM   discovery_findings
                        WHERE  1=1
                    """
                    params = []
                    if discovery_id:
                        query += " AND discovery_id = %s"; params.append(discovery_id)
                    if tenant_id:
                        query += " AND tenant_id = %s"; params.append(tenant_id)
                    if hierarchy_id:
                        query += " AND hierarchy_id = %s"; params.append(hierarchy_id)
                    if service:
                        query += " AND service = %s"; params.append(service)
                    query += " ORDER BY resource_uid, scan_timestamp DESC"

                cur.execute(query, params)
                rows = cur.fetchall()

            # Parse emitted_fields from JSONB / string to dict
            result: List[Dict] = []
            for row in rows:
                rec = dict(row)
                ef = rec.get("emitted_fields")
                if isinstance(ef, str):
                    try:
                        ef = json.loads(ef)
                    except (json.JSONDecodeError, TypeError):
                        ef = {}
                rec["emitted_fields"] = ef or {}
                result.append(rec)

            logger.debug(
                "DiscoveryReader: %d records for discovery_id=%s scan_id=%s",
                len(result), discovery_id, scan_id,
            )
            return result

        except Exception as exc:
            logger.error("DiscoveryReader.read_discovery_records failed: %s", exc)
            return []
        finally:
            self._return_connection(conn)

    def get_discovery_scan_info(self, discovery_scan_id: str) -> Optional[Dict]:
        """Return discovery_report metadata for a scan."""
        conn = self._get_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM discovery_report WHERE discovery_scan_id = %s",
                    (discovery_scan_id,),
                )
                row = cur.fetchone()
                return dict(row) if row else None
        except Exception as exc:
            logger.error("DiscoveryReader.get_discovery_scan_info failed: %s", exc)
            return None
        finally:
            self._return_connection(conn)

    def close(self) -> None:
        if self._pool:
            self._pool.closeall()
