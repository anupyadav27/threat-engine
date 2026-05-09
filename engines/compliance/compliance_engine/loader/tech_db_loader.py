"""
Tech DB Loader

Reads tech_check_findings from the technology engine DB and converts
them to the compliance engine scan_results format so database security
findings (PostgreSQL, MySQL, Oracle, MSSQL, MongoDB, Cassandra CIS checks)
contribute to compliance scoring alongside cloud posture findings.

Configure via TECH_DB_* env vars:
    TECH_DB_HOST, TECH_DB_PORT, TECH_DB_NAME,
    TECH_DB_USER, TECH_DB_PASSWORD
"""

from __future__ import annotations

import json
import logging
import os
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    PSYCOPG_AVAILABLE = True
except ImportError:
    PSYCOPG_AVAILABLE = False


def _tech_db_connection_params() -> Dict[str, Any]:
    return {
        "host":     os.getenv("TECH_DB_HOST", "localhost"),
        "port":     int(os.getenv("TECH_DB_PORT", "5432")),
        "database": os.getenv("TECH_DB_NAME", "threat_engine_tech"),
        "user":     os.getenv("TECH_DB_USER", "tech_user"),
        "password": os.getenv("TECH_DB_PASSWORD", ""),
    }


class TechDBLoader:
    """
    Loads tech_check_findings from the technology engine database and converts
    them to the compliance engine scan_results format.

    Environment variables:
        TECH_DB_HOST, TECH_DB_PORT, TECH_DB_NAME,
        TECH_DB_USER, TECH_DB_PASSWORD
    """

    def __init__(self, db_params: Optional[Dict[str, Any]] = None) -> None:
        self._db_params = db_params or _tech_db_connection_params()
        self._conn: Optional[Any] = None

    def _get_conn(self) -> Any:
        if self._conn is None or self._conn.closed:
            if not PSYCOPG_AVAILABLE:
                raise RuntimeError(
                    "psycopg2 is required for TechDBLoader. Install psycopg2-binary."
                )
            self._conn = psycopg2.connect(**self._db_params)
        return self._conn

    def close(self) -> None:
        if self._conn and not self._conn.closed:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> "TechDBLoader":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def load_check_findings(
        self,
        scan_run_id: str,
        tenant_id: str,
        status_filter: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Read tech_check_findings rows for a given scan_run_id and tenant.

        Args:
            scan_run_id:   Pipeline scan run ID.
            tenant_id:     Tenant identifier.
            status_filter: Optional status filter ('PASS', 'FAIL', 'ERROR').

        Returns:
            List of raw finding dicts with normalized fields.
        """
        if not PSYCOPG_AVAILABLE:
            return []

        sql = """
            SELECT
                finding_id, scan_run_id, tenant_id, account_id,
                provider, tech_category, region,
                resource_uid, resource_type,
                rule_id, rule_title, cis_benchmark,
                severity, status, evidence, framework_mappings,
                remediation, first_seen_at, last_seen_at
            FROM tech_check_findings
            WHERE scan_run_id = %s AND tenant_id = %s
        """
        params: List[Any] = [scan_run_id, tenant_id]

        if status_filter:
            sql += " AND status = %s"
            params.append(status_filter)

        sql += " ORDER BY severity DESC, rule_id"

        try:
            conn = self._get_conn()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(sql, params)
                rows = []
                for r in cur.fetchall():
                    rec = dict(r)
                    for jsonb_col in ("evidence", "framework_mappings"):
                        val = rec.get(jsonb_col)
                        if isinstance(val, str):
                            try:
                                rec[jsonb_col] = json.loads(val)
                            except (json.JSONDecodeError, TypeError):
                                rec[jsonb_col] = {}
                        elif val is None:
                            rec[jsonb_col] = {}
                    rows.append(rec)
                return rows
        except Exception as exc:
            logger.warning("TechDBLoader: failed to load tech_check_findings: %s", exc)
            return []

    def convert_to_scan_results_format(
        self,
        findings: List[Dict[str, Any]],
        csp: str = "database",
        scan_run_id: str = "",
        account_id: str = "",
        scanned_at: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Convert tech_check_findings rows to compliance engine scan_results format.

        Groups findings by tech_category (service) and region for the same
        structure that CheckDBLoader produces.
        """
        if not findings:
            return {
                "scan_id":    scan_run_id,
                "csp":        csp,
                "account_id": account_id,
                "scanned_at": scanned_at or datetime.now(timezone.utc).isoformat() + "Z",
                "results":    [],
            }

        first = findings[0]
        sid = scan_run_id or first.get("scan_run_id", "")
        acc = account_id or first.get("account_id", "")
        ts  = scanned_at or (
            first["first_seen_at"].isoformat() + "Z"
            if isinstance(first.get("first_seen_at"), datetime)
            else datetime.now(timezone.utc).isoformat() + "Z"
        )

        service_region_map: Dict[str, Dict[str, List[Dict[str, Any]]]] = (
            defaultdict(lambda: defaultdict(list))
        )

        for rec in findings:
            rule_id      = rec.get("rule_id", "")
            status       = rec.get("status", "UNKNOWN")
            resource_uid = rec.get("resource_uid") or ""
            resource_type = rec.get("resource_type") or "database"
            tech_category = rec.get("tech_category") or "database"
            region        = rec.get("region") or "global"

            severity = (rec.get("severity") or "medium").lower()
            if severity not in ("low", "medium", "high", "critical"):
                severity = "medium"

            result = status if status in ("PASS", "FAIL", "ERROR") else "UNKNOWN"

            evidence = rec.get("evidence") or {}
            framework_mappings = rec.get("framework_mappings") or {}

            check_entry: Dict[str, Any] = {
                "rule_id":  rule_id,
                "result":   result,
                "severity": severity,
                "resource": {
                    "arn":   resource_uid,
                    "id":    resource_uid,
                    "type":  resource_type,
                    "uid":   resource_uid,
                },
                "evidence": {
                    "checked_fields":    evidence.get("checked_fields", []),
                    "finding_data":      evidence,
                    "cis_benchmark":     rec.get("cis_benchmark", ""),
                    "rule_title":        rec.get("rule_title", ""),
                    "remediation":       rec.get("remediation", ""),
                    "framework_mappings": framework_mappings,
                },
                "service": tech_category,
                "region":  region,
            }
            service_region_map[tech_category][region].append(check_entry)

        results = [
            {"service": svc, "region": reg, "checks": checks}
            for svc, regions in service_region_map.items()
            for reg, checks in regions.items()
        ]

        return {
            "scan_id":    sid,
            "csp":        csp,
            "account_id": acc,
            "scanned_at": ts,
            "results":    results,
        }

    def load_and_convert(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str = "",
        csp: str = "database",
        status_filter: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Load tech_check_findings and return in compliance scan_results format.

        Returns an empty results dict (not raises) when the DB is unavailable
        or there are no findings, so the compliance engine degrades gracefully.
        """
        try:
            findings = self.load_check_findings(
                scan_run_id=scan_run_id,
                tenant_id=tenant_id,
                status_filter=status_filter,
            )
            return self.convert_to_scan_results_format(
                findings,
                csp=csp,
                scan_run_id=scan_run_id,
                account_id=account_id,
            )
        except Exception as exc:
            logger.warning("TechDBLoader.load_and_convert failed (non-fatal): %s", exc)
            return {
                "scan_id":    scan_run_id,
                "csp":        csp,
                "account_id": account_id,
                "scanned_at": datetime.now(timezone.utc).isoformat() + "Z",
                "results":    [],
            }
