"""
DAST Report Writer
Persists DAST scan results to threat_engine_secops database.
Writes one row to secops_report and one row per finding to secops_findings.
"""

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import psycopg2
import psycopg2.extras

logger = logging.getLogger("DASTScanner.DB")


def _env(key: str, *fallbacks: str, default: str = "") -> str:
    for name in (key, *fallbacks):
        val = os.getenv(name)
        if val:
            return val
    return default


def _get_db_config() -> Dict[str, Any]:
    """Read DB config using same env var precedence as sast_engine/database/db_config.py."""
    return {
        "host":     _env("SECOPS_DB_HOST", "SHARED_DB_HOST", "DB_HOST", default="localhost"),
        "port":     int(_env("SECOPS_DB_PORT", "SHARED_DB_PORT", "DB_PORT", default="5432")),
        "dbname":   _env("SECOPS_DB_NAME", "DB_NAME", default="threat_engine_secops"),
        "user":     _env("SECOPS_DB_USER", "SHARED_DB_USER", "DB_USER", default="postgres"),
        "password": _env("SECOPS_DB_PASSWORD", "SHARED_DB_PASSWORD", "DB_PASSWORD", default=""),
        "sslmode":  _env("DB_SSLMODE", default="prefer"),
        "connect_timeout": 10,
    }


class DASTReportWriter:
    """Writes DAST scan results to secops_report and secops_findings tables."""

    def save(
        self,
        vulnerabilities: List[Any],
        scan_config: Optional[Dict[str, Any]],
        scan_stats: Optional[Dict[str, Any]],
        module_summary: Optional[List[Dict[str, Any]]] = None,
        tenant_id: str = "default",
    ) -> Optional[str]:
        """
        Persist scan to DB. Returns the secops_scan_id UUID string on success,
        or None if the DB is unreachable (non-fatal — local reports still saved).

        Args:
            vulnerabilities: List of normalised vulnerability dicts.
            scan_config:     Full scan configuration dict.
            scan_stats:      Stats dict from attack executor.
            module_summary:  Per-module findings breakdown.
            tenant_id:       Tenant identifier (from env or config).
        """
        from dast_engine.report.json_reporter import _normalize_vuln

        cfg = _get_db_config()
        scan_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)

        target_url = (scan_config or {}).get("target", {}).get("url", "unknown")
        tenant_id = (
            os.getenv("TENANT_ID")
            or (scan_config or {}).get("tenant_id", tenant_id)
        )

        # Normalise all vulnerabilities to flat dicts
        normalised = [_normalize_vuln(v) for v in vulnerabilities]

        # Build severity summary for the report row
        sev_counts: Dict[str, int] = {}
        for v in normalised:
            s = v.get("severity", "Info")
            sev_counts[s] = sev_counts.get(s, 0) + 1

        summary = {
            "total_findings": len(normalised),
            "severity_counts": sev_counts,
            "pages_crawled": (scan_stats or {}).get("pages_crawled", 0),
            "total_attacks": (scan_stats or {}).get("total_attacks", 0),
            "module_summary": module_summary or [],
        }

        try:
            conn = psycopg2.connect(**cfg)
            conn.autocommit = False
            cur = conn.cursor()

            # ── Insert scan report row ────────────────────────────────────────
            cur.execute(
                """
                INSERT INTO secops_report (
                    secops_scan_id, tenant_id,
                    project_name, repo_url,
                    scan_type, status,
                    scan_timestamp, completed_at,
                    total_findings,
                    summary, metadata
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    scan_id,
                    tenant_id,
                    target_url,          # project_name — reuse target URL
                    target_url,          # repo_url
                    "dast",
                    "completed",
                    now,
                    now,
                    len(normalised),
                    psycopg2.extras.Json(summary),
                    psycopg2.extras.Json({"scan_config": scan_config or {}}),
                ),
            )

            # ── Insert one finding row per vulnerability ───────────────────────
            if normalised:
                finding_rows = []
                for v in normalised:
                    metadata = {
                        "endpoint_url":    v.get("endpoint_url", ""),
                        "endpoint_method": v.get("endpoint_method", ""),
                        "parameter_name":  v.get("parameter_name", ""),
                        "parameter_location": v.get("parameter_location", ""),
                        "payload":         v.get("payload", ""),
                        "evidence":        v.get("evidence", ""),
                        "cvss":            v.get("cvss", {}),
                        "confidence":      v.get("confidence", 0.0),
                        "description":     v.get("description", ""),
                        "impact":          v.get("impact", ""),
                        "remediation":     v.get("remediation", ""),
                        "references":      v.get("references", []),
                    }
                    finding_rows.append((
                        scan_id,
                        tenant_id,
                        v.get("endpoint_url", ""),   # file_path — URL for DAST
                        "dast",                       # language field reused as scan origin
                        v.get("type", "Unknown"),     # rule_id
                        v.get("severity", "info").lower(),
                        v.get("type", "Unknown"),     # message
                        None,                         # line_number
                        "violation",                  # status
                        None,                         # resource
                        "dast",                       # scan_type
                        psycopg2.extras.Json(metadata),
                    ))

                psycopg2.extras.execute_values(
                    cur,
                    """
                    INSERT INTO secops_findings (
                        secops_scan_id, tenant_id,
                        file_path, language, rule_id,
                        severity, message,
                        line_number, status, resource,
                        scan_type, metadata
                    ) VALUES %s
                    """,
                    finding_rows,
                )

            conn.commit()
            cur.close()
            conn.close()
            logger.info(
                "DAST scan saved to DB: scan_id=%s findings=%d",
                scan_id, len(normalised),
            )
            return scan_id

        except Exception as exc:
            safe = str(exc).replace(cfg.get("password", ""), "***")
            logger.warning("Could not save DAST results to DB (non-fatal): %s", safe)
            return None
