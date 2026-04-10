"""
Risk Quantification ETL — STAGE 1: Transform

Reads:
  ALL *_findings tables via per-engine DB connections (standardized columns):
    threat_findings, iam_findings, datasec_findings, network_findings,
    check_findings + optional: container_findings, supplychain_findings, api_findings
  Enrichment from: inventory (asset criticality), datasec (data sensitivity),
    cloud_accounts (tenant/industry), vuln_cache (EPSS)
  Engine posture scores from: *_report tables (domain-level posture)

Writes:
  risk_input_transformed (one row per CRITICAL/HIGH finding with FAIR context)

Column mapping (standardized across ALL engine finding tables):
  finding_id, scan_run_id, tenant_id, account_id, credential_ref,
  credential_type, provider, region, resource_uid, resource_type,
  severity, status, first_seen_at, last_seen_at
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional, Tuple

import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)

# ── Per-engine DB connection config ──────────────────────────────────────────
# Each engine has its own database. The ETL opens separate connections.

ENGINE_DB_CONFIG = {
    "threat":     {"env_prefix": "THREAT",     "db_name": "threat_engine_threat",          "table": "threat_findings"},
    "iam":        {"env_prefix": "IAM",        "db_name": "threat_engine_iam",             "table": "iam_findings"},
    "datasec":    {"env_prefix": "DATASEC",    "db_name": "threat_engine_datasec",         "table": "datasec_findings"},
    "network":    {"env_prefix": "NETWORK",    "db_name": "threat_engine_network",         "table": "network_findings"},
    "check":      {"env_prefix": "CHECK",      "db_name": "threat_engine_check",           "table": "check_findings"},
    "compliance": {"env_prefix": "COMPLIANCE", "db_name": "threat_engine_compliance",      "table": "compliance_findings"},
    "container":  {"env_prefix": "CONTAINER",  "db_name": "threat_engine_container_security", "table": "container_sec_findings"},
    "encryption": {"env_prefix": "ENCRYPTION", "db_name": "threat_engine_encryption",      "table": "encryption_findings"},
    "database":   {"env_prefix": "DATABASE",   "db_name": "threat_engine_database_security", "table": "dbsec_findings"},
    "ai_security":{"env_prefix": "AI_SECURITY","db_name": "threat_engine_ai_security",     "table": "ai_security_findings"},
    "ciem":       {"env_prefix": "CIEM",       "db_name": "threat_engine_ciem",            "table": "ciem_findings"},
}

# Standardized finding query — same columns across ALL engine tables
FINDING_QUERY = """
    SELECT
        finding_id::text,
        scan_run_id::text,
        tenant_id,
        account_id,
        provider,
        region,
        resource_uid,
        resource_type,
        LOWER(severity) AS severity,
        status,
        rule_id,
        finding_data
    FROM {table}
    WHERE scan_run_id = %s
      AND tenant_id = %s
      AND UPPER(status) = 'FAIL'
      AND LOWER(severity) IN ('critical', 'high')
"""

# CIEM findings have different columns — use a separate query
CIEM_FINDING_QUERY = """
    SELECT
        finding_id::text,
        scan_run_id::text,
        tenant_id,
        account_id,
        provider,
        region,
        resource_uid,
        resource_type,
        LOWER(severity) AS severity,
        'FAIL' AS status,
        rule_id,
        '{}'::jsonb AS finding_data,
        title,
        actor_principal,
        operation,
        action_category,
        event_time
    FROM {table}
    WHERE tenant_id = %s
      AND LOWER(severity) IN ('critical', 'high')
      AND event_time > NOW() - INTERVAL '30 days'
    ORDER BY event_time DESC
    LIMIT 5000
"""


def _get_engine_conn(engine: str) -> Optional[psycopg2.extensions.connection]:
    """Create a connection to a specific engine's database."""
    cfg = ENGINE_DB_CONFIG.get(engine)
    if not cfg:
        return None

    prefix = cfg["env_prefix"]
    try:
        return psycopg2.connect(
            host=os.getenv(f"{prefix}_DB_HOST", os.getenv("DB_HOST", "localhost")),
            port=int(os.getenv(f"{prefix}_DB_PORT", os.getenv("DB_PORT", "5432"))),
            dbname=os.getenv(f"{prefix}_DB_NAME", cfg["db_name"]),
            user=os.getenv(f"{prefix}_DB_USER", os.getenv("DB_USER", "postgres")),
            password=os.getenv(f"{prefix}_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
            sslmode=os.getenv("DB_SSLMODE", "prefer"),
            connect_timeout=10,
        )
    except Exception as e:
        logger.warning("Cannot connect to %s DB: %s", engine, e)
        return None


class RiskETL:
    """
    Stage 1: Extract CRITICAL/HIGH findings from all engines, enrich
    with asset/data/tenant/posture context, write to risk_input_transformed.
    """

    def __init__(
        self,
        risk_conn,
        onboarding_conn=None,
        external_conn=None,
    ) -> None:
        self._risk_conn = risk_conn
        self._onboarding_conn = onboarding_conn
        self._external_conn = external_conn

    def run(
        self,
        scan_id: str,
        scan_run_id: str,
        tenant_id: str,
        account_id: str = "",
        provider: str = "aws",
    ) -> int:
        """Execute Stage 1 ETL. Returns number of transformed rows."""
        logger.info("Risk ETL started: scan_run_id=%s, tenant=%s", scan_run_id, tenant_id)

        # 1. Load enrichment data
        tenant_config = self._load_tenant_config(tenant_id)
        epss_cache = self._load_epss_cache()
        posture_scores = self._load_posture_scores(scan_run_id, tenant_id)

        # 2. Collect CRITICAL/HIGH findings from all engines
        all_findings = self._collect_findings(scan_run_id, tenant_id)
        logger.info("Collected %d CRITICAL/HIGH findings across %d engines",
                     len(all_findings), len(ENGINE_DB_CONFIG))

        if not all_findings:
            logger.info("No CRITICAL/HIGH findings to quantify")
            return 0

        # 3. Enrich each finding
        transformed_rows: List[Dict[str, Any]] = []
        for finding in all_findings:
            row = self._enrich_finding(
                finding, tenant_config, epss_cache, posture_scores,
                scan_id, scan_run_id, tenant_id,
            )
            transformed_rows.append(row)

        # 4. Write to risk_input_transformed
        count = self._write_transformed(transformed_rows, scan_id)
        logger.info("Risk ETL complete: %d transformed rows", count)
        return count

    # ------------------------------------------------------------------
    # Data collection
    # ------------------------------------------------------------------

    def _collect_findings(self, scan_run_id: str, tenant_id: str) -> List[Dict[str, Any]]:
        """Collect CRITICAL/HIGH findings from each engine's own DB."""
        findings: List[Dict[str, Any]] = []

        for engine_name, cfg in ENGINE_DB_CONFIG.items():
            conn = _get_engine_conn(engine_name)
            if not conn:
                continue

            try:
                table = cfg["table"]
                is_ciem = engine_name == "ciem"

                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    if is_ciem:
                        # CIEM uses time-based query (no scan_run_id filter)
                        cur.execute(
                            CIEM_FINDING_QUERY.format(table=table),
                            (tenant_id,),
                        )
                    else:
                        cur.execute(
                            FINDING_QUERY.format(table=table),
                            (scan_run_id, tenant_id),
                        )
                    rows = cur.fetchall()

                for row in rows:
                    fd = row.get("finding_data") or {}
                    if not isinstance(fd, dict):
                        fd = {}

                    # Extract title from finding_data or direct column
                    title = (
                        row.get("title")
                        or fd.get("title")
                        or fd.get("rule_name")
                        or row.get("rule_id", "")
                    )

                    finding = {
                        "source_finding_id": row["finding_id"],
                        "source_engine": engine_name,
                        "source_scan_id": row.get("scan_run_id", scan_run_id),
                        "rule_id": row.get("rule_id", ""),
                        "severity": row["severity"],
                        "title": title,
                        "asset_arn": row.get("resource_uid", ""),
                        "resource_type": row.get("resource_type", ""),
                        "account_id": row.get("account_id", ""),
                        "region": row.get("region", ""),
                        "provider": row.get("provider", "aws"),
                        "finding_data": fd,
                    }

                    # CIEM-specific fields
                    if is_ciem:
                        finding["actor_principal"] = row.get("actor_principal", "")
                        finding["operation"] = row.get("operation", "")
                        finding["action_category"] = row.get("action_category", "")

                    findings.append(finding)

                if rows:
                    logger.info("  %s: %d CRITICAL/HIGH findings", engine_name, len(rows))
            except Exception as e:
                logger.warning("Failed to query %s findings: %s", engine_name, e)
            finally:
                conn.close()

        return findings

    # ------------------------------------------------------------------
    # Enrichment data loading
    # ------------------------------------------------------------------

    def _load_tenant_config(self, tenant_id: str) -> Dict[str, Any]:
        """Load tenant industry context from cloud_accounts + risk_model_config."""
        config: Dict[str, Any] = {
            "industry": "default",
            "estimated_annual_revenue": 100_000_000,
            "applicable_regulations": ["GDPR"],
            "per_record_cost": 4.45,
            "downtime_cost_hr": 10000.0,
            "default_record_count": 1000,
            "sensitivity_multipliers": {},
        }

        # Try cloud_accounts for industry
        if self._onboarding_conn:
            try:
                with self._onboarding_conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("""
                        SELECT industry, revenue_range, applicable_regulations
                        FROM cloud_accounts
                        WHERE tenant_id = %s LIMIT 1
                    """, (tenant_id,))
                    row = cur.fetchone()
                    if row:
                        config["industry"] = row.get("industry") or "default"
                        config["applicable_regulations"] = row.get("applicable_regulations") or ["GDPR"]
            except Exception as e:
                logger.warning("Failed to load tenant config from onboarding: %s", e)

        # Load FAIR model config
        try:
            with self._risk_conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT per_record_cost, estimated_annual_revenue,
                           applicable_regs, downtime_cost_hr,
                           sensitivity_multipliers, default_record_count
                    FROM risk_model_config
                    WHERE (tenant_id = %s OR tenant_id IS NULL)
                      AND (industry = %s OR industry = 'default')
                    ORDER BY tenant_id NULLS LAST
                    LIMIT 1
                """, (tenant_id, config["industry"]))
                row = cur.fetchone()
                if row:
                    config["per_record_cost"] = float(row["per_record_cost"]) if row.get("per_record_cost") else 4.45
                    config["estimated_annual_revenue"] = float(row["estimated_annual_revenue"]) if row.get("estimated_annual_revenue") else 100_000_000
                    config["applicable_regulations"] = row.get("applicable_regs") or config["applicable_regulations"]
                    config["downtime_cost_hr"] = float(row["downtime_cost_hr"]) if row.get("downtime_cost_hr") else 10000.0
                    config["default_record_count"] = int(row["default_record_count"]) if row.get("default_record_count") else 1000
                    sm = row.get("sensitivity_multipliers")
                    if isinstance(sm, dict):
                        config["sensitivity_multipliers"] = sm
                    elif isinstance(sm, str):
                        config["sensitivity_multipliers"] = json.loads(sm)
        except Exception as e:
            logger.warning("Failed to load risk_model_config: %s", e)

        return config

    def _load_epss_cache(self) -> Dict[str, float]:
        """Load EPSS scores from vuln_cache (optional)."""
        epss: Dict[str, float] = {}
        if not self._external_conn:
            return epss
        try:
            with self._external_conn.cursor() as cur:
                cur.execute("SELECT cve_id, epss_score FROM vuln_cache WHERE epss_score IS NOT NULL")
                for row in cur.fetchall():
                    epss[row[0]] = float(row[1])
        except Exception as e:
            logger.warning("EPSS cache not available: %s", e)
        return epss

    def _load_posture_scores(self, scan_run_id: str, tenant_id: str) -> Dict[str, Dict[str, Any]]:
        """
        Load domain-level posture scores from each engine's report table.
        These are used to weight the FAIR exposure calculation.

        Returns:
            {engine_name: {"posture_score": 0-100, "total_findings": N, ...}}
        """
        scores: Dict[str, Dict[str, Any]] = {}

        # IAM posture
        conn = _get_engine_conn("iam")
        if conn:
            try:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("""
                        SELECT report_data FROM iam_report
                        WHERE scan_run_id = %s AND tenant_id = %s LIMIT 1
                    """, (scan_run_id, tenant_id))
                    row = cur.fetchone()
                    if row:
                        rd = row.get("report_data") or {}
                        scores["iam"] = {
                            "posture_score": rd.get("risk_score", 0),
                            "total_findings": rd.get("total_findings", 0),
                        }
            except Exception:
                pass
            finally:
                conn.close()

        # DataSec posture
        conn = _get_engine_conn("datasec")
        if conn:
            try:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("""
                        SELECT data_risk_score, total_findings,
                               encryption_score, access_score
                        FROM datasec_report
                        WHERE scan_run_id = %s AND tenant_id = %s LIMIT 1
                    """, (scan_run_id, tenant_id))
                    row = cur.fetchone()
                    if row:
                        scores["datasec"] = {
                            "posture_score": row.get("data_risk_score", 0),
                            "total_findings": row.get("total_findings", 0),
                            "encryption_score": row.get("encryption_score", 0),
                            "access_score": row.get("access_score", 0),
                        }
            except Exception:
                pass
            finally:
                conn.close()

        # Network posture
        conn = _get_engine_conn("network")
        if conn:
            try:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("""
                        SELECT posture_score, total_findings, firewall_score,
                               internet_exposed_resources
                        FROM network_report
                        WHERE scan_run_id = %s AND tenant_id = %s LIMIT 1
                    """, (scan_run_id, tenant_id))
                    row = cur.fetchone()
                    if row:
                        scores["network"] = {
                            "posture_score": row.get("posture_score", 0),
                            "total_findings": row.get("total_findings", 0),
                            "firewall_score": row.get("firewall_score", 0),
                            "internet_exposed": row.get("internet_exposed_resources", 0),
                        }
            except Exception:
                pass
            finally:
                conn.close()

        # Threat posture
        conn = _get_engine_conn("threat")
        if conn:
            try:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("""
                        SELECT total_findings, critical_findings, high_findings
                        FROM threat_report
                        WHERE scan_run_id = %s AND tenant_id = %s LIMIT 1
                    """, (scan_run_id, tenant_id))
                    row = cur.fetchone()
                    if row:
                        total = row.get("total_findings", 0) or 1
                        crit = row.get("critical_findings", 0)
                        high = row.get("high_findings", 0)
                        scores["threat"] = {
                            "posture_score": min(100, int((crit * 10 + high * 5) / total * 10)),
                            "total_findings": total,
                        }
            except Exception:
                pass
            finally:
                conn.close()

        # Container posture
        conn = _get_engine_conn("container")
        if conn:
            try:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("""
                        SELECT posture_score, total_findings
                        FROM container_sec_report
                        WHERE scan_run_id = %s AND tenant_id = %s LIMIT 1
                    """, (scan_run_id, tenant_id))
                    row = cur.fetchone()
                    if row:
                        scores["container"] = {
                            "posture_score": row.get("posture_score", 0),
                            "total_findings": row.get("total_findings", 0),
                        }
            except Exception:
                pass
            finally:
                conn.close()

        # Encryption posture
        conn = _get_engine_conn("encryption")
        if conn:
            try:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("""
                        SELECT risk_score, total_findings
                        FROM encryption_report
                        WHERE scan_run_id = %s AND tenant_id = %s LIMIT 1
                    """, (scan_run_id, tenant_id))
                    row = cur.fetchone()
                    if row:
                        scores["encryption"] = {
                            "posture_score": row.get("risk_score", 0),
                            "total_findings": row.get("total_findings", 0),
                        }
            except Exception:
                pass
            finally:
                conn.close()

        # Database Security posture
        conn = _get_engine_conn("database")
        if conn:
            try:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("""
                        SELECT posture_score, total_findings
                        FROM dbsec_report
                        WHERE scan_run_id = %s AND tenant_id = %s LIMIT 1
                    """, (scan_run_id, tenant_id))
                    row = cur.fetchone()
                    if row:
                        scores["database"] = {
                            "posture_score": row.get("posture_score", 0),
                            "total_findings": row.get("total_findings", 0),
                        }
            except Exception:
                pass
            finally:
                conn.close()

        # AI Security posture
        conn = _get_engine_conn("ai_security")
        if conn:
            try:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("""
                        SELECT risk_score, total_findings
                        FROM ai_security_report
                        WHERE scan_run_id = %s AND tenant_id = %s LIMIT 1
                    """, (scan_run_id, tenant_id))
                    row = cur.fetchone()
                    if row:
                        scores["ai_security"] = {
                            "posture_score": row.get("risk_score", 0),
                            "total_findings": row.get("total_findings", 0),
                        }
            except Exception:
                pass
            finally:
                conn.close()

        if scores:
            logger.info("Loaded posture scores: %s",
                        {k: v.get("posture_score", 0) for k, v in scores.items()})
        return scores

    # ------------------------------------------------------------------
    # Enrichment
    # ------------------------------------------------------------------

    def _enrich_finding(
        self,
        finding: Dict[str, Any],
        tenant_config: Dict[str, Any],
        epss_cache: Dict[str, float],
        posture_scores: Dict[str, Dict],
        scan_id: str,
        scan_run_id: str,
        tenant_id: str,
    ) -> Dict[str, Any]:
        """Enrich a finding with FAIR context."""
        engine = finding.get("source_engine", "check")
        fd = finding.get("finding_data") or {}

        # EPSS lookup
        cve_id = fd.get("cve_id") or finding.get("cve_id")
        epss_score = epss_cache.get(cve_id, 0.05) if cve_id else 0.05

        # Exposure factor from finding context
        is_public = fd.get("effective_internet_exposure", False) or fd.get("is_public", False)
        exposure_factor = 1.0 if is_public else 0.3

        # Data sensitivity from finding
        data_sensitivity = "internal"
        record_count = tenant_config.get("default_record_count", 1000)
        if engine == "datasec":
            data_sensitivity = fd.get("data_sensitivity", "internal")
            record_count = fd.get("estimated_record_count", record_count)
            classifications = fd.get("data_classification") or finding.get("data_classification") or []
            if any(c in ("PII", "PHI") for c in classifications):
                data_sensitivity = "restricted"
            elif any(c in ("PCI", "confidential") for c in classifications):
                data_sensitivity = "confidential"

        # Engine posture score as risk amplifier
        # Some engines use "risk_score" (higher = worse): threat, iam
        # Others use "posture_score" (higher = better): datasec, network, container, etc.
        # Normalize: convert all to "risk_factor" where higher = more risk
        engine_data = posture_scores.get(engine, {})
        raw_score = engine_data.get("posture_score", 50)
        is_risk_score = engine in ("threat", "iam")  # These use higher = worse
        risk_factor = raw_score if is_risk_score else (100 - raw_score)
        # Clamp to 0-100, then scale: 0 risk → 1.0x amplifier, 100 risk → 1.5x
        posture_amplifier = 1.0 + (max(0, min(100, risk_factor)) / 200.0)

        return {
            "risk_scan_id": scan_id,
            "tenant_id": tenant_id,
            "scan_run_id": scan_run_id,
            "source_finding_id": finding.get("source_finding_id"),
            "source_engine": engine,
            "source_scan_id": finding.get("source_scan_id"),
            "rule_id": finding.get("rule_id"),
            "severity": finding.get("severity"),
            "title": fd.get("title", "") or finding.get("title", ""),
            "finding_type": fd.get("finding_type"),
            "asset_id": finding.get("asset_arn", ""),
            "asset_type": finding.get("resource_type"),
            "asset_arn": finding.get("asset_arn", ""),
            "asset_criticality": "high" if is_public else "medium",
            "is_public": is_public,
            "data_sensitivity": data_sensitivity,
            "data_types": fd.get("data_types", []),
            "estimated_record_count": record_count,
            "industry": tenant_config.get("industry", "default"),
            "estimated_revenue": tenant_config.get("estimated_annual_revenue", 100_000_000),
            "applicable_regulations": tenant_config.get("applicable_regulations", []),
            "epss_score": epss_score,
            "cve_id": cve_id,
            "exposure_factor": exposure_factor * posture_amplifier,
            "engine_posture_score": raw_score,
            "engine_risk_factor": risk_factor,
            "account_id": finding.get("account_id"),
            "region": finding.get("region"),
            "csp": finding.get("provider", "aws"),
        }

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def _write_transformed(self, rows: List[Dict[str, Any]], scan_id: str) -> int:
        """Batch insert into risk_input_transformed."""
        if not rows:
            return 0

        # Clean old data for this scan
        with self._risk_conn.cursor() as cur:
            cur.execute("DELETE FROM risk_input_transformed WHERE risk_scan_id = %s", (scan_id,))
        self._risk_conn.commit()

        from engines.risk.db.risk_db_writer import RiskDBWriter
        writer = RiskDBWriter(self._risk_conn)
        return writer.batch_insert_transformed(rows)
