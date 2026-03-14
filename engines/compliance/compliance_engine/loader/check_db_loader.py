"""
Check DB Loader

Reads check results from PostgreSQL (threat_engine_check.check_findings)
and converts them to the format expected by the compliance engine.

Use this for the Discovery → Check → Threat → Compliance flow when
all data is stored in local PostgreSQL. Configure via CHECK_DB_* env vars.
"""

import os
import json
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
from collections import defaultdict

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    PSYCOPG_AVAILABLE = True
except ImportError:
    PSYCOPG_AVAILABLE = False


def _check_db_connection_string() -> str:
    """Build Check DB connection string from env."""
    return (
        f"postgresql://{os.getenv('CHECK_DB_USER', 'check_user')}:"
        f"{os.getenv('CHECK_DB_PASSWORD', 'check_password')}@"
        f"{os.getenv('CHECK_DB_HOST', 'localhost')}:"
        f"{os.getenv('CHECK_DB_PORT', '5432')}/"
        f"{os.getenv('CHECK_DB_NAME', 'threat_engine_check')}"
    )


def _db_url_with_search_path(url: str) -> str:
    """Append options=search_path when DB_SCHEMA is set."""
    schema = (os.getenv("DB_SCHEMA") or "").strip()
    if not schema:
        return url
    sep = "&" if "?" in url else "?"
    opts = f"options=-c%20search_path%3D{schema.replace(',', '%2C')}"
    return f"{url}{sep}{opts}"


class CheckDBLoader:
    """
    Loads check results from threat_engine_check database.

    Environment variables:
        CHECK_DB_HOST, CHECK_DB_PORT, CHECK_DB_NAME,
        CHECK_DB_USER, CHECK_DB_PASSWORD
    """

    def __init__(self, db_url: Optional[str] = None):
        if db_url is None:
            db_url = _db_url_with_search_path(_check_db_connection_string())
        self.db_url = db_url
        self._connection = None

    def _get_conn(self):
        if self._connection is None or self._connection.closed:
            if not PSYCOPG_AVAILABLE:
                raise RuntimeError("psycopg2 is required for CheckDBLoader. Install psycopg2-binary.")
            # Use individual parameters to avoid DSN password encoding issues with %2O
            self._connection = psycopg2.connect(
                host=os.getenv('CHECK_DB_HOST', 'localhost'),
                port=int(os.getenv('CHECK_DB_PORT', '5432')),
                database=os.getenv('CHECK_DB_NAME', 'threat_engine_check'),
                user=os.getenv('CHECK_DB_USER', 'check_user'),
                password=os.getenv('CHECK_DB_PASSWORD', 'check_password')
            )
        return self._connection

    def close(self) -> None:
        if self._connection and not self._connection.closed:
            self._connection.close()
            self._connection = None

    def __enter__(self) -> "CheckDBLoader":
        return self

    def __exit__(self, *args) -> None:
        self.close()

    def _get_scan_timestamp(self, scan_id: str, tenant_id: str) -> Optional[str]:
        """Fetch scan_timestamp from check_report table."""
        try:
            conn = self._get_conn()
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT scan_timestamp FROM check_report WHERE check_scan_id = %s AND tenant_id = %s",
                    (scan_id, tenant_id),
                )
                row = cur.fetchone()
                if row and row[0]:
                    ts = row[0]
                    return ts.isoformat() + "Z" if hasattr(ts, "isoformat") else str(ts)
        except Exception:
            pass
        return None

    def load_check_results(
        self,
        scan_id: str,
        tenant_id: str,
        account_id: Optional[str] = None,
        region: Optional[str] = None,
        service: Optional[str] = None,
        status_filter: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Read check results from check_results table.

        scan_id: Check scan ID (or 'latest' to use most recent completed scan).
        tenant_id: Tenant identifier.
        """
        if not PSYCOPG_AVAILABLE:
            return []

        conn = self._get_conn()
        effective_scan_id = scan_id

        if scan_id == "latest":
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT check_scan_id FROM check_report
                    WHERE tenant_id = %s AND status = 'completed'
                      AND scan_type IN ('check', 'full')
                    ORDER BY scan_timestamp DESC
                    LIMIT 1
                    """,
                    (tenant_id,),
                )
                row = cur.fetchone()
                if not row:
                    return []
                effective_scan_id = row[0]

        query = """
            SELECT
                cr.check_scan_id, cr.customer_id, cr.tenant_id, cr.provider,
                cr.hierarchy_id, cr.hierarchy_type, cr.rule_id,
                cr.resource_uid, cr.resource_id, cr.resource_type,
                cr.status, cr.checked_fields, cr.finding_data, cr.created_at
            FROM check_findings cr
            WHERE cr.check_scan_id = %s AND cr.tenant_id = %s
        """
        params: List[Any] = [effective_scan_id, tenant_id]

        if account_id:
            query += " AND cr.hierarchy_id = %s"
            params.append(account_id)
        if region:
            pat = f"%:{region}:%"
            query += " AND cr.resource_uid::text LIKE %s"
            params.append(pat)
        if service:
            query += " AND cr.resource_type::text LIKE %s"
            params.append(f"%{service}%")
        if status_filter:
            query += " AND cr.status = %s"
            params.append(status_filter)

        query += " ORDER BY cr.created_at DESC, cr.resource_uid"

        rows: List[Dict[str, Any]] = []
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(query, params)
                for r in cur.fetchall():
                    rec = dict(r)
                    cf = rec.get("checked_fields")
                    fd = rec.get("finding_data")
                    if isinstance(cf, str):
                        try:
                            rec["checked_fields"] = json.loads(cf)
                        except (json.JSONDecodeError, TypeError):
                            rec["checked_fields"] = []
                    elif cf is None:
                        rec["checked_fields"] = []
                    if isinstance(fd, str):
                        try:
                            rec["finding_data"] = json.loads(fd)
                        except (json.JSONDecodeError, TypeError):
                            rec["finding_data"] = {}
                    elif fd is None:
                        rec["finding_data"] = {}
                    ts = rec.get("created_at")
                    if ts and hasattr(ts, "isoformat"):
                        rec["scan_timestamp"] = ts.isoformat() + "Z"
                    else:
                        rec["scan_timestamp"] = datetime.now(timezone.utc).isoformat() + "Z"
                    rows.append(rec)
        except Exception:
            return []

        return rows

    def convert_to_scan_results_format(
        self,
        check_results: List[Dict[str, Any]],
        csp: str = "aws",
        scan_id: Optional[str] = None,
        scanned_at: Optional[str] = None,
        account_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Convert DB check rows to compliance engine scan_results format."""
        if not check_results:
            return {
                "scan_id": scan_id or "",
                "csp": csp,
                "account_id": account_id or "",
                "scanned_at": scanned_at or datetime.now(timezone.utc).isoformat() + "Z",
                "results": [],
            }

        first = check_results[0]
        sid = scan_id or first.get("check_scan_id", "")
        acc = account_id or first.get("hierarchy_id", "")
        at = scanned_at or first.get("scan_timestamp", datetime.now(timezone.utc).isoformat() + "Z")
        if isinstance(at, datetime):
            at = at.isoformat() + "Z"

        service_region_map: Dict[str, Dict[str, List[Dict]]] = defaultdict(lambda: defaultdict(list))

        for rec in check_results:
            rule_id = rec.get("rule_id", "")
            status = rec.get("status", "UNKNOWN")
            resource_type = rec.get("resource_type") or "unknown"
            resource_id = rec.get("resource_id") or ""
            resource_uid = rec.get("resource_uid") or ""

            service = resource_type
            if not service or service == "unknown":
                parts = rule_id.split(".")
                service = parts[1] if len(parts) >= 2 else "unknown"

            region = "global"
            if resource_uid:
                arn_parts = resource_uid.split(":")
                if len(arn_parts) >= 4:
                    region = arn_parts[3] or "global"

            severity = "medium"
            if "high" in rule_id.lower() or "critical" in rule_id.lower():
                severity = "high"
            elif "low" in rule_id.lower():
                severity = "low"

            result = status if status in ("PASS", "FAIL", "ERROR") else "UNKNOWN"

            check_entry = {
                "rule_id": rule_id,
                "result": result,
                "severity": severity,
                "resource": {
                    "arn": resource_uid,
                    "id": resource_id,
                    "type": resource_type,
                    "uid": resource_uid,
                },
                "evidence": {
                    "checked_fields": rec.get("checked_fields", []),
                    "finding_data": rec.get("finding_data", {}),
                },
            }
            service_region_map[service][region].append(check_entry)

        results = []
        for svc, regions in service_region_map.items():
            for reg, checks in regions.items():
                results.append({"service": svc, "region": reg, "checks": checks})

        return {
            "scan_id": sid,
            "csp": csp,
            "account_id": acc,
            "scanned_at": at,
            "results": results,
        }

    def load_and_convert(
        self,
        scan_id: str,
        tenant_id: str,
        csp: str = "aws",
        account_id: Optional[str] = None,
        region: Optional[str] = None,
        service: Optional[str] = None,
        status_filter: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Load check results from DB and convert to compliance scan_results format.
        """
        rows = self.load_check_results(
            scan_id=scan_id,
            tenant_id=tenant_id,
            account_id=account_id,
            region=region,
            service=service,
            status_filter=status_filter,
        )
        if not rows:
            return self.convert_to_scan_results_format(
                [], csp=csp, scan_id=scan_id if scan_id != "latest" else None
            )

        effective_scan_id = rows[0].get("check_scan_id")
        scanned_at = self._get_scan_timestamp(effective_scan_id, tenant_id)
        if not scanned_at:
            scanned_at = rows[0].get("scan_timestamp")

        return self.convert_to_scan_results_format(
            rows,
            csp=csp,
            scan_id=effective_scan_id,
            scanned_at=scanned_at,
            account_id=account_id or (rows[0].get("hierarchy_id") if rows else None),
        )
