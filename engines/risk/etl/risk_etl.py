"""
Risk ETL — Task 5.4 [Phase 5 | BD] — STAGE 1: Transform

Reads:
  ALL *_findings tables (threat, iam, datasec, container, network, supplychain, api, check)
  inventory_findings (asset criticality)
  cloud_accounts (tenant/industry context)
  vuln_cache (EPSS scores)

Writes:
  risk_input_transformed (one row per CRITICAL/HIGH finding)
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# All engine finding tables to aggregate
ENGINE_FINDING_TABLES: List[Tuple[str, str, str]] = [
    # (table_name, scan_id_column, engine_name)
    ("threat_findings", "scan_run_id", "threat"),
    ("iam_findings", "scan_run_id", "iam"),
    ("datasec_findings", "scan_run_id", "datasec"),
    ("container_findings", "scan_run_id", "container"),
    ("network_findings", "scan_run_id", "network"),
    ("supplychain_findings", "scan_run_id", "supplychain"),
    ("api_findings", "scan_run_id", "api"),
    ("check_findings", "scan_run_id", "check"),
]


class RiskETL:
    """
    Stage 1: Extract CRITICAL/HIGH findings from all engines, enrich
    with asset/data/tenant context, write to risk_input_transformed.
    """

    def __init__(
        self,
        risk_conn,
        discovery_conn,
        onboarding_conn,
        external_conn=None,
    ) -> None:
        self._risk_conn = risk_conn
        self._discovery_conn = discovery_conn
        self._onboarding_conn = onboarding_conn
        self._external_conn = external_conn

    def run(
        self,
        scan_id: str,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        provider: str = "aws",
    ) -> int:
        """
        Execute Stage 1 ETL.

        Returns:
            Number of transformed rows written.
        """
        logger.info("Risk ETL started: scan_id=%s", scan_id)

        # 1. Load enrichment data
        tenant_config = self._load_tenant_config(tenant_id)
        epss_cache = self._load_epss_cache()
        asset_metadata = self._load_asset_metadata(scan_run_id)
        datasec_metadata = self._load_datasec_metadata(scan_run_id)

        # 2. Collect CRITICAL/HIGH findings from all engines
        all_findings = self._collect_findings(scan_run_id)
        logger.info("Collected %d CRITICAL/HIGH findings across all engines", len(all_findings))

        # 3. Enrich each finding
        transformed_rows: List[Dict[str, Any]] = []
        for finding in all_findings:
            row = self._enrich_finding(
                finding, tenant_config, epss_cache,
                asset_metadata, datasec_metadata,
                scan_id, scan_run_id, tenant_id,
            )
            transformed_rows.append(row)

        # 4. Write to risk_input_transformed
        count = self._write_transformed(transformed_rows)
        logger.info("Risk ETL complete: %d transformed rows", count)
        return count

    # ------------------------------------------------------------------
    # Data loading
    # ------------------------------------------------------------------

    def _collect_findings(self, scan_run_id: str) -> List[Dict[str, Any]]:
        """UNION CRITICAL/HIGH findings from all engine tables."""
        findings: List[Dict[str, Any]] = []

        # We need to read from each engine's DB. For simplicity,
        # each engine writes to its own DB but findings are accessible
        # via the discovery_conn (which has cross-DB access) or
        # we read from each DB separately.
        # Here we use the risk_conn which should have read access.
        cursor = self._discovery_conn.cursor()
        try:
            for table_name, scan_id_col, engine_name in ENGINE_FINDING_TABLES:
                try:
                    cursor.execute(f"""
                        SELECT
                            f.finding_id::text,
                            '{engine_name}' AS source_engine,
                            f.{scan_id_col}::text AS source_scan_id,
                            f.rule_id,
                            f.severity,
                            f.title,
                            COALESCE(f.resource_arn, '') AS asset_arn,
                            COALESCE(f.account_id, '') AS account_id,
                            COALESCE(f.region, '') AS region,
                            COALESCE(f.csp, 'aws') AS csp
                        FROM {table_name} f
                        WHERE f.scan_run_id = %s::uuid
                          AND f.result = 'FAIL'
                          AND f.severity IN ('critical', 'high')
                    """, (scan_run_id,))

                    for row in cursor.fetchall():
                        findings.append({
                            "source_finding_id": row[0],
                            "source_engine": row[1],
                            "source_scan_id": row[2],
                            "rule_id": row[3],
                            "severity": row[4],
                            "title": row[5],
                            "asset_arn": row[6],
                            "account_id": row[7],
                            "region": row[8],
                            "csp": row[9],
                        })
                except Exception as exc:
                    logger.warning("Failed to query %s: %s", table_name, exc)
                    continue

        finally:
            cursor.close()

        return findings

    def _load_tenant_config(self, tenant_id: str) -> Dict[str, Any]:
        """Load tenant context from cloud_accounts + risk_model_config."""
        config: Dict[str, Any] = {
            "industry": "default",
            "estimated_revenue": 100_000_000,
            "applicable_regulations": ["GDPR"],
        }

        # Try cloud_accounts first
        if self._onboarding_conn:
            cursor = self._onboarding_conn.cursor()
            try:
                cursor.execute("""
                    SELECT industry, revenue_range, applicable_regulations
                    FROM cloud_accounts
                    WHERE tenant_id = %s
                    LIMIT 1
                """, (tenant_id,))
                row = cursor.fetchone()
                if row:
                    config["industry"] = row[0] or "default"
                    config["revenue_range"] = row[1]
                    config["applicable_regulations"] = row[2] or ["GDPR"]
            except Exception as exc:
                logger.warning("Failed to load tenant config: %s", exc)
            finally:
                cursor.close()

        # Load FAIR model config for industry
        cursor = self._risk_conn.cursor()
        try:
            cursor.execute("""
                SELECT per_record_cost, estimated_annual_revenue,
                       applicable_regs, downtime_cost_hr,
                       sensitivity_multipliers, default_record_count
                FROM risk_model_config
                WHERE (tenant_id = %s OR tenant_id IS NULL)
                  AND (industry = %s OR industry = 'default')
                ORDER BY tenant_id NULLS LAST, industry = 'default' ASC
                LIMIT 1
            """, (tenant_id, config["industry"]))
            row = cursor.fetchone()
            if row:
                config["per_record_cost"] = float(row[0]) if row[0] else 4.45
                config["estimated_annual_revenue"] = float(row[1]) if row[1] else config.get("estimated_revenue", 100_000_000)
                config["applicable_regs"] = row[2] if isinstance(row[2], list) else json.loads(row[2]) if row[2] else []
                config["downtime_cost_hr"] = float(row[3]) if row[3] else 10000.0
                config["sensitivity_multipliers"] = row[4] if isinstance(row[4], dict) else json.loads(row[4]) if row[4] else {}
                config["default_record_count"] = int(row[5]) if row[5] else 1000
        except Exception as exc:
            logger.warning("Failed to load risk_model_config: %s", exc)
        finally:
            cursor.close()

        return config

    def _load_epss_cache(self) -> Dict[str, float]:
        """Load EPSS scores from vuln_cache (Tier 3)."""
        epss: Dict[str, float] = {}
        if not self._external_conn:
            return epss

        cursor = self._external_conn.cursor()
        try:
            cursor.execute("""
                SELECT cve_id, epss_score
                FROM vuln_cache
                WHERE epss_score IS NOT NULL
            """)
            for row in cursor.fetchall():
                epss[row[0]] = float(row[1])
        except Exception as exc:
            logger.warning("Failed to load EPSS cache: %s", exc)
        finally:
            cursor.close()

        return epss

    def _load_asset_metadata(self, scan_run_id: str) -> Dict[str, Dict]:
        """Load asset criticality and exposure from inventory_findings."""
        assets: Dict[str, Dict] = {}
        cursor = self._discovery_conn.cursor()
        try:
            cursor.execute("""
                SELECT resource_arn, resource_type, is_public, criticality
                FROM inventory_findings
                WHERE inventory_findings.scan_run_id = %s::uuid
            """, (scan_run_id,))
            for row in cursor.fetchall():
                assets[row[0]] = {
                    "asset_type": row[1],
                    "is_public": row[2] or False,
                    "asset_criticality": row[3] or "medium",
                }
        except Exception as exc:
            logger.warning("Failed to load asset metadata: %s", exc)
        finally:
            cursor.close()

        return assets

    def _load_datasec_metadata(self, scan_run_id: str) -> Dict[str, Dict]:
        """Load data sensitivity and record counts from datasec_findings."""
        datasec: Dict[str, Dict] = {}
        cursor = self._discovery_conn.cursor()
        try:
            cursor.execute("""
                SELECT resource_arn, data_sensitivity, data_types,
                       estimated_record_count
                FROM datasec_findings
                WHERE datasec_findings.scan_run_id = %s::uuid
                  AND data_sensitivity IS NOT NULL
            """, (scan_run_id,))
            for row in cursor.fetchall():
                datasec[row[0]] = {
                    "data_sensitivity": row[1] or "internal",
                    "data_types": row[2] or [],
                    "estimated_record_count": row[3] or 0,
                }
        except Exception as exc:
            logger.warning("Failed to load datasec metadata: %s", exc)
        finally:
            cursor.close()

        return datasec

    # ------------------------------------------------------------------
    # Enrichment
    # ------------------------------------------------------------------

    def _enrich_finding(
        self,
        finding: Dict[str, Any],
        tenant_config: Dict[str, Any],
        epss_cache: Dict[str, float],
        asset_metadata: Dict[str, Dict],
        datasec_metadata: Dict[str, Dict],
        scan_id: str,
        scan_run_id: str,
        tenant_id: str,
    ) -> Dict[str, Any]:
        """Enrich a finding with asset, data, tenant, and EPSS context."""
        asset_arn = finding.get("asset_arn", "")
        asset_info = asset_metadata.get(asset_arn, {})
        datasec_info = datasec_metadata.get(asset_arn, {})

        # EPSS lookup — use CVE from finding if available
        cve_id = finding.get("cve_id")
        epss_score = epss_cache.get(cve_id, 0.05) if cve_id else 0.05

        # Exposure factor: internet-exposed = 1.0, internal = 0.3
        is_public = asset_info.get("is_public", False)
        exposure_factor = 1.0 if is_public else 0.3

        return {
            "risk_scan_id": scan_id,
            "tenant_id": tenant_id,
            "scan_run_id": scan_run_id,
            "source_finding_id": finding.get("source_finding_id"),
            "source_engine": finding.get("source_engine"),
            "source_scan_id": finding.get("source_scan_id"),
            "rule_id": finding.get("rule_id"),
            "severity": finding.get("severity"),
            "title": finding.get("title"),
            "finding_type": finding.get("finding_type"),
            "asset_id": asset_arn,
            "asset_type": asset_info.get("asset_type"),
            "asset_arn": asset_arn,
            "asset_criticality": asset_info.get("asset_criticality", "medium"),
            "is_public": is_public,
            "data_sensitivity": datasec_info.get("data_sensitivity", "internal"),
            "data_types": datasec_info.get("data_types", []),
            "estimated_record_count": datasec_info.get("estimated_record_count", tenant_config.get("default_record_count", 1000)),
            "industry": tenant_config.get("industry", "default"),
            "estimated_revenue": tenant_config.get("estimated_annual_revenue", 100_000_000),
            "applicable_regulations": tenant_config.get("applicable_regulations") or tenant_config.get("applicable_regs", []),
            "epss_score": epss_score,
            "cve_id": cve_id,
            "exposure_factor": exposure_factor,
            "account_id": finding.get("account_id"),
            "region": finding.get("region"),
            "csp": finding.get("csp", "aws"),
        }

    # ------------------------------------------------------------------
    # Write transformed
    # ------------------------------------------------------------------

    def _write_transformed(self, rows: List[Dict[str, Any]]) -> int:
        """Batch insert into risk_input_transformed."""
        if not rows:
            return 0

        from engines.risk.db.risk_db_writer import RiskDBWriter
        writer = RiskDBWriter(self._risk_conn)
        return writer.batch_insert_transformed(rows)
