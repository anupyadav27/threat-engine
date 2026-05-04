"""
TechDBManager — PostgreSQL access layer for the technology engine.

Covers all four sub-engines:
  tech-discovery  → tech_discovery_findings
  tech-inventory  → tech_inventory_assets
  tech-check      → tech_check_findings
  tech-ciem       → tech_ciem_findings

Mirrors: engines/discoveries/common/database/database_manager.py
Database: threat_engine_tech  (TECH_DB_NAME env)
"""
from __future__ import annotations

import logging
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Generator, List, Optional

import psycopg2
from psycopg2.extras import RealDictCursor, execute_values
from psycopg2.pool import ThreadedConnectionPool

from common.models.connector_interface import TechFinding

logger = logging.getLogger(__name__)

_MIN_CONN = 2
_MAX_CONN = 20


class TechDBManager:
    """Manages all database operations for the technology engine."""

    def __init__(self) -> None:
        self._config: Dict[str, Any] = {
            "host":     os.getenv("TECH_DB_HOST",     os.getenv("DB_HOST",     "localhost")),
            "port":     int(os.getenv("TECH_DB_PORT", os.getenv("DB_PORT",     "5432"))),
            "database": os.getenv("TECH_DB_NAME",                               "threat_engine_tech"),
            "user":     os.getenv("TECH_DB_USER",     os.getenv("DB_USER",     "postgres")),
            "password": os.getenv("TECH_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        }
        logger.info("TechDBManager connecting to %s @ %s", self._config["database"], self._config["host"])
        self._pool = ThreadedConnectionPool(_MIN_CONN, _MAX_CONN, **self._config)

    # ── context manager ──────────────────────────────────────────────────────

    @contextmanager
    def _conn(self) -> Generator[psycopg2.extensions.connection, None, None]:
        conn = self._pool.getconn()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self._pool.putconn(conn)

    # ── credential helpers ───────────────────────────────────────────────────

    def get_credential(self, account_id: str) -> Optional[Dict[str, Any]]:
        """Return the tech_credentials row for *account_id* (from onboarding)."""
        sql = """
            SELECT ca.account_id, ca.provider AS tech_type,
                   COALESCE(tc.tech_category, ca.provider) AS tech_category,
                   ca.tenant_id,
                   COALESCE(tc.host, '')  AS host,
                   tc.port,
                   tc.display_name,
                   tc.credential_type,
                   tc.credential_ref,
                   COALESCE(tc.sudo_required, false) AS sudo_required,
                   tc.status
            FROM   cloud_accounts ca
            LEFT JOIN tech_credentials tc USING (account_id)
            WHERE  ca.account_id = %s
            LIMIT  1
        """
        # tech_credentials may live in the onboarding DB; fall back to local if needed
        try:
            with self._conn() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute(sql, (account_id,))
                    row = cur.fetchone()
                    return dict(row) if row else None
        except Exception:
            # Onboarding data is in a separate DB — try tech_credentials only
            return self._get_local_credential(account_id)

    def _get_local_credential(self, account_id: str) -> Optional[Dict[str, Any]]:
        sql = """
            SELECT account_id, tech_type, tech_category, host, port,
                   display_name, credential_type, credential_ref,
                   COALESCE(sudo_required, false) AS sudo_required,
                   status,
                   NULL::text AS tenant_id
            FROM   tech_credentials
            WHERE  account_id = %s
            LIMIT  1
        """
        with self._conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(sql, (account_id,))
                row = cur.fetchone()
                return dict(row) if row else None

    # ── discovery findings ───────────────────────────────────────────────────

    def upsert_findings(self, scan_run_id: str, findings: List[TechFinding]) -> int:
        """Bulk-upsert tech_discovery_findings. Returns row count inserted."""
        if not findings:
            return 0

        rows = [
            (
                f.finding_id, f.scan_run_id, f.tenant_id, f.account_id,
                f.credential_ref, f.credential_type, f.provider, f.tech_category,
                f.region, f.resource_uid, f.resource_type, f.discovery_id,
                psycopg2.extras.Json(f.raw_data),
                f.error_message, f.severity, f.status,
            )
            for f in findings
        ]
        sql = """
            INSERT INTO tech_discovery_findings
              (finding_id, scan_run_id, tenant_id, account_id,
               credential_ref, credential_type, provider, tech_category,
               region, resource_uid, resource_type, discovery_id,
               raw_data, error_message, severity, status,
               first_seen_at, last_seen_at)
            VALUES %s
            ON CONFLICT (finding_id, scan_run_id) DO UPDATE SET
              raw_data      = EXCLUDED.raw_data,
              error_message = EXCLUDED.error_message,
              last_seen_at  = NOW()
        """
        template = "(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW(),NOW())"
        with self._conn() as conn:
            with conn.cursor() as cur:
                execute_values(cur, sql, rows, template=template)
                return cur.rowcount

    def list_findings(self, scan_run_id: str, tenant_id: str) -> List[Dict[str, Any]]:
        sql = """
            SELECT * FROM tech_discovery_findings
            WHERE  scan_run_id = %s AND tenant_id = %s
            ORDER  BY last_seen_at DESC
        """
        with self._conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(sql, (scan_run_id, tenant_id))
                return [dict(r) for r in cur.fetchall()]

    def get_findings_for_inventory(self, scan_run_id: str) -> List[Dict[str, Any]]:
        """Return discovery findings needed by the inventory normalizer."""
        sql = """
            SELECT finding_id, tenant_id, account_id, credential_ref,
                   credential_type, provider, tech_category, region,
                   resource_uid, resource_type, discovery_id, raw_data,
                   severity, status, first_seen_at
            FROM   tech_discovery_findings
            WHERE  scan_run_id = %s AND error_message IS NULL
            ORDER  BY provider, resource_uid
        """
        with self._conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(sql, (scan_run_id,))
                return [dict(r) for r in cur.fetchall()]

    # ── inventory assets ─────────────────────────────────────────────────────

    def upsert_assets(self, assets: List[Dict[str, Any]]) -> int:
        """Bulk-upsert tech_inventory_assets. Returns row count."""
        if not assets:
            return 0
        sql = """
            INSERT INTO tech_inventory_assets
              (asset_id, scan_run_id, tenant_id, account_id,
               credential_ref, credential_type, provider, tech_category,
               region, resource_uid, resource_type, asset_name,
               version, os_version, metadata, cloud_resource_uid,
               severity, status, first_seen_at, last_seen_at)
            VALUES %s
            ON CONFLICT (asset_id) DO UPDATE SET
              scan_run_id = EXCLUDED.scan_run_id,
              version     = EXCLUDED.version,
              os_version  = EXCLUDED.os_version,
              metadata    = EXCLUDED.metadata,
              last_seen_at = NOW()
        """
        rows = [
            (
                a["asset_id"], a["scan_run_id"], a["tenant_id"], a["account_id"],
                a.get("credential_ref"), a.get("credential_type"),
                a["provider"], a["tech_category"],
                a.get("region"), a["resource_uid"], a.get("resource_type"),
                a.get("asset_name"), a.get("version"), a.get("os_version"),
                psycopg2.extras.Json(a.get("metadata", {})),
                a.get("cloud_resource_uid"),
                a.get("severity", "info"), a.get("status", "active"),
            )
            for a in assets
        ]
        template = "(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW(),NOW())"
        with self._conn() as conn:
            with conn.cursor() as cur:
                execute_values(cur, sql, rows, template=template)
                return cur.rowcount

    def list_assets(self, tenant_id: str, provider: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM tech_inventory_assets WHERE tenant_id = %s"
        params: List[Any] = [tenant_id]
        if provider:
            sql += " AND provider = %s"
            params.append(provider)
        sql += " ORDER BY provider, resource_uid"
        with self._conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(sql, params)
                return [dict(r) for r in cur.fetchall()]

    # ── check rules ──────────────────────────────────────────────────────────

    def get_active_rules(self, tech_type: str) -> List[Dict[str, Any]]:
        """Return active tech_rule_metadata rows for a given tech_type."""
        sql = """
            SELECT rm.rule_id, rm.tech_type, rm.tech_category,
                   rm.title, rm.severity, rm.cis_benchmark, rm.cis_section,
                   rm.nist_controls, rm.soc2_criteria, rm.remediation, rm.rule_metadata,
                   rd.discovery_id, rd.action_type, rd.yaml_path
            FROM   tech_rule_metadata rm
            LEFT JOIN tech_rule_discoveries rd USING (rule_id)
            WHERE  rm.tech_type = %s AND rm.is_active = true
            ORDER  BY rm.cis_section
        """
        with self._conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(sql, (tech_type,))
                return [dict(r) for r in cur.fetchall()]

    # ── check findings ───────────────────────────────────────────────────────

    def upsert_check_findings(self, findings: List[Dict[str, Any]]) -> int:
        """Bulk-upsert tech_check_findings. Returns row count."""
        if not findings:
            return 0
        sql = """
            INSERT INTO tech_check_findings
              (finding_id, scan_run_id, tenant_id, account_id,
               credential_ref, credential_type, provider, tech_category,
               region, resource_uid, resource_type, rule_id, rule_title,
               cis_benchmark, severity, status, evidence,
               framework_mappings, remediation, first_seen_at, last_seen_at)
            VALUES %s
            ON CONFLICT (finding_id, scan_run_id) DO UPDATE SET
              status      = EXCLUDED.status,
              evidence    = EXCLUDED.evidence,
              last_seen_at = NOW()
        """
        rows = [
            (
                f["finding_id"], f["scan_run_id"], f["tenant_id"], f["account_id"],
                f.get("credential_ref"), f.get("credential_type"),
                f["provider"], f["tech_category"],
                f.get("region"), f["resource_uid"], f.get("resource_type"),
                f["rule_id"], f.get("rule_title"), f.get("cis_benchmark"),
                f.get("severity", "medium"), f.get("status", "FAIL"),
                psycopg2.extras.Json(f.get("evidence", {})),
                psycopg2.extras.Json(f.get("framework_mappings", {})),
                f.get("remediation"),
            )
            for f in findings
        ]
        template = "(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW(),NOW())"
        with self._conn() as conn:
            with conn.cursor() as cur:
                execute_values(cur, sql, rows, template=template)
                return cur.rowcount

    def list_check_findings(
        self, scan_run_id: str, tenant_id: str, status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        sql = """
            SELECT * FROM tech_check_findings
            WHERE  scan_run_id = %s AND tenant_id = %s
        """
        params: List[Any] = [scan_run_id, tenant_id]
        if status:
            sql += " AND status = %s"
            params.append(status)
        sql += " ORDER BY severity DESC, rule_id"
        with self._conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(sql, params)
                return [dict(r) for r in cur.fetchall()]

    # ── CIEM findings ────────────────────────────────────────────────────────

    def upsert_ciem_findings(self, findings: List[Dict[str, Any]]) -> int:
        """Bulk-upsert tech_ciem_findings. Returns row count."""
        if not findings:
            return 0
        sql = """
            INSERT INTO tech_ciem_findings
              (finding_id, scan_run_id, tenant_id, account_id,
               credential_ref, credential_type, provider, tech_category,
               region, resource_uid, resource_type, rule_id,
               mitre_technique, mitre_tactic, actor, source_ip,
               event_time, severity, status, evidence,
               first_seen_at, last_seen_at)
            VALUES %s
            ON CONFLICT (finding_id) DO UPDATE SET
              last_seen_at = NOW(),
              evidence     = EXCLUDED.evidence
        """
        rows = [
            (
                f["finding_id"], f["scan_run_id"], f["tenant_id"], f["account_id"],
                f.get("credential_ref"), f.get("credential_type"),
                f["provider"], f["tech_category"],
                f.get("region"), f["resource_uid"], f.get("resource_type"),
                f["rule_id"], f.get("mitre_technique"), f.get("mitre_tactic"),
                f.get("actor"), f.get("source_ip"),
                f.get("event_time"),
                f.get("severity", "high"), f.get("status", "open"),
                psycopg2.extras.Json(f.get("evidence", {})),
            )
            for f in findings
        ]
        template = "(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW(),NOW())"
        with self._conn() as conn:
            with conn.cursor() as cur:
                execute_values(cur, sql, rows, template=template)
                return cur.rowcount

    def list_ciem_findings(self, scan_run_id: str, tenant_id: str) -> List[Dict[str, Any]]:
        sql = """
            SELECT * FROM tech_ciem_findings
            WHERE  scan_run_id = %s AND tenant_id = %s
            ORDER  BY severity DESC, event_time DESC
        """
        with self._conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(sql, (scan_run_id, tenant_id))
                return [dict(r) for r in cur.fetchall()]

    # ── orchestration helpers ────────────────────────────────────────────────

    def mark_engine_completed(self, scan_run_id: str, engine: str, count: int) -> None:
        """Update tech_scan_orchestration (if table exists) — best effort."""
        try:
            sql = """
                UPDATE tech_scan_orchestration
                SET    completed_engines = completed_engines || jsonb_build_array(%s),
                       finding_counts    = finding_counts    || jsonb_build_object(%s, %s),
                       updated_at        = NOW()
                WHERE  scan_run_id = %s
            """
            with self._conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(sql, (engine, engine, count, scan_run_id))
        except Exception as exc:
            logger.debug("mark_engine_completed skipped (table may not exist): %s", exc)

    def mark_engine_failed(self, scan_run_id: str, engine: str, error: str) -> None:
        """Record engine failure in tech_scan_orchestration — best effort."""
        try:
            sql = """
                UPDATE tech_scan_orchestration
                SET    error_engines = error_engines || jsonb_build_object(%s, %s),
                       updated_at    = NOW()
                WHERE  scan_run_id = %s
            """
            with self._conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(sql, (engine, error, scan_run_id))
        except Exception as exc:
            logger.debug("mark_engine_failed skipped: %s", exc)

    def close(self) -> None:
        if self._pool:
            self._pool.closeall()
