"""
Threat DB Loader

Reads threat reports from PostgreSQL (threat_reports.report_data),
extracts misconfig_findings, and converts to compliance scan_results format.

Use for Discovery → Check → Threat → Compliance when Threat writes to DB.
Configure via THREAT_DB_* env vars.
"""

from __future__ import annotations

import json
import os
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    PSYCOPG_AVAILABLE = True
except ImportError:
    PSYCOPG_AVAILABLE = False


def _threat_db_url() -> str:
    base = (
        f"postgresql://{os.getenv('THREAT_DB_USER', 'threat_user')}:"
        f"{os.getenv('THREAT_DB_PASSWORD', 'threat_password')}@"
        f"{os.getenv('THREAT_DB_HOST', 'localhost')}:"
        f"{os.getenv('THREAT_DB_PORT', '5432')}/"
        f"{os.getenv('THREAT_DB_NAME', 'threat_engine_threat')}"
    )
    schema = (os.getenv("DB_SCHEMA") or "engine_threat,engine_shared").strip()
    sep = "&" if "?" in base else "?"
    opts = f"options=-c%20search_path%3D{schema.replace(',', '%2C')}"
    return f"{base}{sep}{opts}"


class ThreatDBLoader:
    """
    Loads threat reports from Threat DB (threat_reports), extracts
    misconfig_findings, and converts to compliance scan_results format.
    """

    def __init__(self, db_url: Optional[str] = None):
        self.db_url = db_url or _threat_db_url()
        self._conn = None

    def _get_conn(self):
        if self._conn is None or self._conn.closed:
            if not PSYCOPG_AVAILABLE:
                raise RuntimeError("psycopg2 required for ThreatDBLoader. Install psycopg2-binary.")
            self._conn = psycopg2.connect(self.db_url)
        return self._conn

    def close(self) -> None:
        if self._conn and not self._conn.closed:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> "ThreatDBLoader":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def load_report(self, tenant_id: str, scan_run_id: str) -> Optional[Dict[str, Any]]:
        """Load full threat report dict from threat_reports by tenant_id and scan_run_id."""
        if not PSYCOPG_AVAILABLE:
            return None
        conn = self._get_conn()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT report_data, generated_at FROM threat_reports
                    WHERE tenant_id = %s AND scan_run_id = %s
                    """,
                    (tenant_id, scan_run_id),
                )
                row = cur.fetchone()
            if not row:
                return None
            data = row["report_data"]
            report = data if isinstance(data, dict) else json.loads(data)
            gen = row.get("generated_at")
            if gen and "generated_at" not in report:
                report["generated_at"] = gen.isoformat() + "Z" if hasattr(gen, "isoformat") else str(gen)
            return report
        except Exception:
            return None

    def list_scan_ids(self, tenant_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """List scan_run_ids (and generated_at) for a tenant."""
        if not PSYCOPG_AVAILABLE:
            return []
        conn = self._get_conn()
        out: List[Dict[str, Any]] = []
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT scan_run_id, generated_at, cloud
                    FROM threat_reports
                    WHERE tenant_id = %s
                    ORDER BY generated_at DESC
                    LIMIT %s
                    """,
                    (tenant_id, limit),
                )
                for r in cur.fetchall():
                    out.append({
                        "scan_run_id": r["scan_run_id"],
                        "generated_at": r["generated_at"].isoformat() + "Z" if hasattr(r["generated_at"], "isoformat") else str(r["generated_at"]),
                        "cloud": r["cloud"],
                    })
        except Exception:
            pass
        return out

    def misconfig_findings_to_scan_results(
        self,
        findings: List[Dict[str, Any]],
        csp: str = "aws",
        scan_run_id: str = "",
        account_id: str = "",
        scanned_at: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Convert misconfig_findings (from ThreatReport) to compliance scan_results format."""
        if not findings:
            return {
                "scan_id": scan_run_id,
                "csp": csp,
                "account_id": account_id,
                "scanned_at": scanned_at or datetime.now(timezone.utc).isoformat() + "Z",
                "results": [],
            }

        acc = account_id or (findings[0].get("account", "") if findings else "")
        at = scanned_at or datetime.now(timezone.utc).isoformat() + "Z"
        service_region: Dict[str, Dict[str, List[Dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))

        for f in findings:
            rule_id = f.get("rule_id", "")
            result = f.get("result", "UNKNOWN")
            if result not in ("PASS", "FAIL", "WARN"):
                result = "UNKNOWN"
            service = f.get("service") or "unknown"
            region = f.get("region") or "global"
            res = f.get("resource") or {}
            arn = res.get("resource_arn") or res.get("arn") or ""
            rid = res.get("resource_id") or res.get("id") or ""
            rtype = res.get("resource_type") or res.get("type") or "unknown"
            severity = (f.get("severity") or "medium")
            if isinstance(severity, dict) and "value" in severity:
                severity = severity["value"]
            severity = str(severity).lower()
            if severity not in ("low", "medium", "high", "critical"):
                severity = "medium"

            check_entry = {
                "rule_id": rule_id,
                "result": result,
                "severity": severity,
                "resource": {"arn": arn, "id": rid, "type": rtype},
                "evidence": {
                    "checked_fields": f.get("checked_fields") or [],
                    "finding_data": {},
                },
            }
            service_region[service][region].append(check_entry)

        results = []
        for svc, regions in service_region.items():
            for reg, checks in regions.items():
                results.append({"service": svc, "region": reg, "checks": checks})

        return {
            "scan_id": scan_run_id,
            "csp": csp,
            "account_id": acc,
            "scanned_at": at,
            "results": results,
        }

    def load_and_convert(
        self,
        tenant_id: str,
        scan_run_id: str,
        csp: str = "aws",
    ) -> Dict[str, Any]:
        """
        Load threat report from DB, extract misconfig_findings, convert to scan_results.
        """
        report = self.load_report(tenant_id, scan_run_id)
        if not report:
            return self.misconfig_findings_to_scan_results(
                [], csp=csp, scan_run_id=scan_run_id, account_id="", scanned_at=None
            )

        findings = report.get("misconfig_findings") or []
        ctx = report.get("scan_context") or {}
        sid = ctx.get("scan_run_id") or scan_run_id
        accounts = ctx.get("accounts") or []
        acc = accounts[0] if accounts else ""
        gen = report.get("generated_at")
        at = gen if isinstance(gen, str) else (gen.isoformat() + "Z" if gen and hasattr(gen, "isoformat") else None)

        return self.misconfig_findings_to_scan_results(
            findings,
            csp=csp,
            scan_run_id=sid,
            account_id=acc,
            scanned_at=at,
        )
