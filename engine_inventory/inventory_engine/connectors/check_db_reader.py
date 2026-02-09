"""
Check DB Reader (Inventory)

Reads check results from the Check DB (threat_engine_check.check_findings) so Inventory
can enrich assets with posture summaries without calling cloud APIs.

=== DATABASE & TABLE MAP ===
Database: threat_engine_check (CHECK DB)
Env: CHECK_DB_HOST / CHECK_DB_PORT / CHECK_DB_NAME / CHECK_DB_USER / CHECK_DB_PASSWORD

Tables READ:
  - check_findings : get_posture_by_resource(scan_id, tenant_id)
                     — SELECT COALESCE(resource_uid, resource_arn) AS resource_uid,
                              COUNT(*) AS total,
                              COUNT(*) FILTER (WHERE status = 'PASS') AS passed,
                              COUNT(*) FILTER (WHERE status = 'FAIL') AS failed,
                              COUNT(*) FILTER (WHERE status = 'ERROR') AS errors
                       FROM check_findings
                       WHERE check_scan_id = %s AND tenant_id = %s
                       GROUP BY COALESCE(resource_uid, resource_arn)
                     Filters: check_scan_id, tenant_id, hierarchy_id (optional)

Tables WRITTEN: None (read-only connector)
===
"""

from __future__ import annotations

import os
from typing import Dict, Any, Optional

import psycopg2
from psycopg2.extras import RealDictCursor


def _db_url_with_search_path(url: str) -> str:
    """Append options=search_path to URL when DB_SCHEMA is set."""
    schema = (os.getenv("DB_SCHEMA") or "").strip()
    if not schema:
        return url
    sep = "&" if "?" in url else "?"
    opts = f"options=-c%20search_path%3D{schema.replace(',', '%2C')}"
    return f"{url}{sep}{opts}"


class CheckDBReader:
    """Reads check results from PostgreSQL check_findings table."""

    def __init__(self, db_url: Optional[str] = None):
        if db_url is None:
            host = os.getenv("CHECK_DB_HOST", "localhost")
            port = os.getenv("CHECK_DB_PORT", "5432")
            db = os.getenv("CHECK_DB_NAME", "threat_engine_check")
            user = os.getenv("CHECK_DB_USER", "check_user")
            pwd = os.getenv("CHECK_DB_PASSWORD", "check_password")
            db_url = f"postgresql://{user}:{pwd}@{host}:{port}/{db}"
        self.db_url = db_url
        self.conn = psycopg2.connect(_db_url_with_search_path(db_url))

    def get_posture_by_resource(
        self,
        *,
        scan_id: str,
        tenant_id: str,
        hierarchy_id: Optional[str] = None,
    ) -> Dict[str, Dict[str, Any]]:
        """
        Return a posture summary per resource_uid for a given check scan.

        Output format:
        {
          "<resource_uid>": {
            "total": int,
            "passed": int,
            "failed": int,
            "errors": int,
          },
          ...
        }
        """
        query = """
            SELECT
                COALESCE(resource_uid, resource_arn) AS resource_uid,
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE status = 'PASS') AS passed,
                COUNT(*) FILTER (WHERE status = 'FAIL') AS failed,
                COUNT(*) FILTER (WHERE status = 'ERROR') AS errors
            FROM check_findings
            WHERE check_scan_id = %s AND tenant_id = %s
        """
        params = [scan_id, tenant_id]
        if hierarchy_id:
            query += " AND hierarchy_id = %s"
            params.append(hierarchy_id)
        query += " GROUP BY COALESCE(resource_uid, resource_arn)"

        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(query, params)
            rows = cur.fetchall()

        result: Dict[str, Dict[str, Any]] = {}
        for r in rows:
            uid = r.get("resource_uid")
            if not uid:
                continue
            result[uid] = {
                "total": int(r.get("total") or 0),
                "passed": int(r.get("passed") or 0),
                "failed": int(r.get("failed") or 0),
                "errors": int(r.get("errors") or 0),
            }
        return result

    def close(self) -> None:
        try:
            self.conn.close()
        except Exception:
            pass

