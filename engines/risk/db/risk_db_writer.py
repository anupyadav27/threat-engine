"""
Risk DB Writer — Batch writers for all risk engine tables.

Tables written:
  risk_input_transformed  (Stage 1 ETL output)
  risk_scenarios          (Stage 2 FAIR model output)
  risk_report             (Stage 3 scan summary)
  risk_summary            (Stage 3 per-engine aggregation)
  risk_trends             (Stage 3 time-series)
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import uuid4

logger = logging.getLogger(__name__)

# Batch size for multi-row inserts
BATCH_SIZE = 500


class RiskDBWriter:
    """Batch writer for risk engine database tables."""

    def __init__(self, conn) -> None:
        self._conn = conn

    # ------------------------------------------------------------------
    # Stage 1 — risk_input_transformed
    # ------------------------------------------------------------------

    def batch_insert_transformed(self, rows: List[Dict[str, Any]]) -> int:
        """Insert transformed findings into risk_input_transformed."""
        if not rows:
            return 0

        sql = """
            INSERT INTO risk_input_transformed (
                risk_scan_id, tenant_id, orchestration_id,
                source_finding_id, source_engine, source_scan_id,
                rule_id, severity, title, finding_type,
                asset_id, asset_type, asset_arn, asset_criticality, is_public,
                data_sensitivity, data_types, estimated_record_count,
                industry, estimated_revenue, applicable_regulations,
                epss_score, cve_id, exposure_factor,
                account_id, region, csp
            ) VALUES (
                %(risk_scan_id)s, %(tenant_id)s, %(orchestration_id)s,
                %(source_finding_id)s, %(source_engine)s, %(source_scan_id)s,
                %(rule_id)s, %(severity)s, %(title)s, %(finding_type)s,
                %(asset_id)s, %(asset_type)s, %(asset_arn)s, %(asset_criticality)s, %(is_public)s,
                %(data_sensitivity)s, %(data_types)s, %(estimated_record_count)s,
                %(industry)s, %(estimated_revenue)s, %(applicable_regulations)s,
                %(epss_score)s, %(cve_id)s, %(exposure_factor)s,
                %(account_id)s, %(region)s, %(csp)s
            )
        """

        count = 0
        for i in range(0, len(rows), BATCH_SIZE):
            batch = rows[i : i + BATCH_SIZE]
            prepared = [self._prepare_transformed_row(r) for r in batch]
            count += self._batch_execute(sql, prepared)

        logger.info("Inserted %d rows into risk_input_transformed", count)
        return count

    def _prepare_transformed_row(self, row: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare a row for risk_input_transformed insertion."""
        return {
            "risk_scan_id": row.get("risk_scan_id"),
            "tenant_id": row.get("tenant_id"),
            "orchestration_id": row.get("orchestration_id"),
            "source_finding_id": row.get("source_finding_id"),
            "source_engine": row.get("source_engine"),
            "source_scan_id": row.get("source_scan_id"),
            "rule_id": row.get("rule_id"),
            "severity": row.get("severity"),
            "title": row.get("title"),
            "finding_type": row.get("finding_type"),
            "asset_id": row.get("asset_id"),
            "asset_type": row.get("asset_type"),
            "asset_arn": row.get("asset_arn"),
            "asset_criticality": row.get("asset_criticality", "medium"),
            "is_public": row.get("is_public", False),
            "data_sensitivity": row.get("data_sensitivity", "internal"),
            "data_types": row.get("data_types", []),
            "estimated_record_count": row.get("estimated_record_count", 0),
            "industry": row.get("industry"),
            "estimated_revenue": row.get("estimated_revenue"),
            "applicable_regulations": row.get("applicable_regulations", []),
            "epss_score": row.get("epss_score", 0.05),
            "cve_id": row.get("cve_id"),
            "exposure_factor": row.get("exposure_factor", 1.0),
            "account_id": row.get("account_id"),
            "region": row.get("region"),
            "csp": row.get("csp", "aws"),
        }

    # ------------------------------------------------------------------
    # Stage 2 — risk_scenarios
    # ------------------------------------------------------------------

    def batch_insert_scenarios(self, rows: List[Dict[str, Any]], scan_id: str,
                                tenant_id: str, orchestration_id: str) -> int:
        """Insert FAIR model scenarios into risk_scenarios."""
        if not rows:
            return 0

        sql = """
            INSERT INTO risk_scenarios (
                scenario_id, risk_scan_id, tenant_id, orchestration_id,
                source_finding_id, source_engine,
                asset_id, asset_type, asset_arn,
                scenario_type,
                data_records_at_risk, data_sensitivity, data_types,
                loss_event_frequency,
                primary_loss_min, primary_loss_max, primary_loss_likely,
                regulatory_fine_min, regulatory_fine_max,
                applicable_regulations,
                total_exposure_min, total_exposure_max, total_exposure_likely,
                risk_tier, calculation_model,
                account_id, region, csp
            ) VALUES (
                %(scenario_id)s, %(risk_scan_id)s, %(tenant_id)s, %(orchestration_id)s,
                %(source_finding_id)s, %(source_engine)s,
                %(asset_id)s, %(asset_type)s, %(asset_arn)s,
                %(scenario_type)s,
                %(data_records_at_risk)s, %(data_sensitivity)s, %(data_types)s,
                %(loss_event_frequency)s,
                %(primary_loss_min)s, %(primary_loss_max)s, %(primary_loss_likely)s,
                %(regulatory_fine_min)s, %(regulatory_fine_max)s,
                %(applicable_regulations)s,
                %(total_exposure_min)s, %(total_exposure_max)s, %(total_exposure_likely)s,
                %(risk_tier)s, %(calculation_model)s,
                %(account_id)s, %(region)s, %(csp)s
            )
        """

        count = 0
        for i in range(0, len(rows), BATCH_SIZE):
            batch = rows[i : i + BATCH_SIZE]
            prepared = [
                self._prepare_scenario_row(r, scan_id, tenant_id, orchestration_id)
                for r in batch
            ]
            count += self._batch_execute(sql, prepared)

        logger.info("Inserted %d rows into risk_scenarios", count)
        return count

    def _prepare_scenario_row(self, row: Dict[str, Any], scan_id: str,
                               tenant_id: str, orchestration_id: str) -> Dict[str, Any]:
        """Prepare a scenario row for insertion."""
        calc_model = row.get("calculation_model", {})
        if isinstance(calc_model, dict):
            calc_model = json.dumps(calc_model)

        return {
            "scenario_id": str(uuid4()),
            "risk_scan_id": scan_id,
            "tenant_id": tenant_id,
            "orchestration_id": orchestration_id,
            "source_finding_id": row.get("source_finding_id"),
            "source_engine": row.get("source_engine"),
            "asset_id": row.get("asset_id"),
            "asset_type": row.get("asset_type"),
            "asset_arn": row.get("asset_arn"),
            "scenario_type": row.get("scenario_type"),
            "data_records_at_risk": row.get("data_records_at_risk", 0),
            "data_sensitivity": row.get("data_sensitivity", "internal"),
            "data_types": row.get("data_types", []),
            "loss_event_frequency": row.get("loss_event_frequency", 0),
            "primary_loss_min": row.get("primary_loss_min", 0),
            "primary_loss_max": row.get("primary_loss_max", 0),
            "primary_loss_likely": row.get("primary_loss_likely", 0),
            "regulatory_fine_min": row.get("regulatory_fine_min", 0),
            "regulatory_fine_max": row.get("regulatory_fine_max", 0),
            "applicable_regulations": row.get("applicable_regulations", []),
            "total_exposure_min": row.get("total_exposure_min", 0),
            "total_exposure_max": row.get("total_exposure_max", 0),
            "total_exposure_likely": row.get("total_exposure_likely", 0),
            "risk_tier": row.get("risk_tier", "low"),
            "calculation_model": calc_model,
            "account_id": row.get("account_id"),
            "region": row.get("region"),
            "csp": row.get("csp", "aws"),
        }

    # ------------------------------------------------------------------
    # Stage 3 — risk_report
    # ------------------------------------------------------------------

    def insert_report(self, report: Dict[str, Any]) -> None:
        """Insert or update the risk_report row for a scan."""
        sql = """
            INSERT INTO risk_report (
                risk_scan_id, orchestration_id, tenant_id, account_id, provider,
                total_scenarios, critical_scenarios, high_scenarios,
                medium_scenarios, low_scenarios,
                total_exposure_min, total_exposure_max, total_exposure_likely,
                total_regulatory_exposure,
                engine_breakdown, top_scenarios, scenario_type_breakdown,
                frameworks_at_risk,
                vs_previous_likely, vs_previous_pct,
                currency, started_at, completed_at, scan_duration_ms,
                status, error_message
            ) VALUES (
                %(risk_scan_id)s, %(orchestration_id)s, %(tenant_id)s,
                %(account_id)s, %(provider)s,
                %(total_scenarios)s, %(critical_scenarios)s, %(high_scenarios)s,
                %(medium_scenarios)s, %(low_scenarios)s,
                %(total_exposure_min)s, %(total_exposure_max)s, %(total_exposure_likely)s,
                %(total_regulatory_exposure)s,
                %(engine_breakdown)s, %(top_scenarios)s, %(scenario_type_breakdown)s,
                %(frameworks_at_risk)s,
                %(vs_previous_likely)s, %(vs_previous_pct)s,
                %(currency)s, %(started_at)s, %(completed_at)s, %(scan_duration_ms)s,
                %(status)s, %(error_message)s
            )
            ON CONFLICT (risk_scan_id) DO UPDATE SET
                total_scenarios = EXCLUDED.total_scenarios,
                critical_scenarios = EXCLUDED.critical_scenarios,
                high_scenarios = EXCLUDED.high_scenarios,
                medium_scenarios = EXCLUDED.medium_scenarios,
                low_scenarios = EXCLUDED.low_scenarios,
                total_exposure_min = EXCLUDED.total_exposure_min,
                total_exposure_max = EXCLUDED.total_exposure_max,
                total_exposure_likely = EXCLUDED.total_exposure_likely,
                total_regulatory_exposure = EXCLUDED.total_regulatory_exposure,
                engine_breakdown = EXCLUDED.engine_breakdown,
                top_scenarios = EXCLUDED.top_scenarios,
                scenario_type_breakdown = EXCLUDED.scenario_type_breakdown,
                frameworks_at_risk = EXCLUDED.frameworks_at_risk,
                vs_previous_likely = EXCLUDED.vs_previous_likely,
                vs_previous_pct = EXCLUDED.vs_previous_pct,
                completed_at = EXCLUDED.completed_at,
                scan_duration_ms = EXCLUDED.scan_duration_ms,
                status = EXCLUDED.status,
                error_message = EXCLUDED.error_message
        """

        params = self._prepare_report_row(report)
        cursor = self._conn.cursor()
        try:
            cursor.execute(sql, params)
            self._conn.commit()
            logger.info("Inserted risk_report for scan %s", report.get("risk_scan_id"))
        except Exception as exc:
            self._conn.rollback()
            logger.error("Failed to insert risk_report: %s", exc)
            raise
        finally:
            cursor.close()

    def _prepare_report_row(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare a report row for insertion."""
        def _jsonb(val):
            if val is None:
                return None
            return json.dumps(val) if isinstance(val, (dict, list)) else val

        return {
            "risk_scan_id": report.get("risk_scan_id"),
            "orchestration_id": report.get("orchestration_id"),
            "tenant_id": report.get("tenant_id"),
            "account_id": report.get("account_id"),
            "provider": report.get("provider", "aws"),
            "total_scenarios": report.get("total_scenarios", 0),
            "critical_scenarios": report.get("critical_scenarios", 0),
            "high_scenarios": report.get("high_scenarios", 0),
            "medium_scenarios": report.get("medium_scenarios", 0),
            "low_scenarios": report.get("low_scenarios", 0),
            "total_exposure_min": report.get("total_exposure_min", 0),
            "total_exposure_max": report.get("total_exposure_max", 0),
            "total_exposure_likely": report.get("total_exposure_likely", 0),
            "total_regulatory_exposure": report.get("total_regulatory_exposure", 0),
            "engine_breakdown": _jsonb(report.get("engine_breakdown")),
            "top_scenarios": _jsonb(report.get("top_scenarios")),
            "scenario_type_breakdown": _jsonb(report.get("scenario_type_breakdown")),
            "frameworks_at_risk": report.get("frameworks_at_risk", []),
            "vs_previous_likely": report.get("vs_previous_likely"),
            "vs_previous_pct": report.get("vs_previous_pct"),
            "currency": report.get("currency", "USD"),
            "started_at": report.get("started_at"),
            "completed_at": report.get("completed_at"),
            "scan_duration_ms": report.get("scan_duration_ms"),
            "status": report.get("status", "completed"),
            "error_message": report.get("error_message"),
        }

    # ------------------------------------------------------------------
    # Stage 3 — risk_summary (per-engine aggregation)
    # ------------------------------------------------------------------

    def batch_insert_summaries(self, summaries: List[Dict[str, Any]]) -> int:
        """Insert per-engine risk summaries."""
        if not summaries:
            return 0

        sql = """
            INSERT INTO risk_summary (
                risk_scan_id, tenant_id, orchestration_id,
                source_engine, scenario_count, critical_count, high_count,
                total_exposure_likely, total_regulatory_exposure,
                top_finding_types
            ) VALUES (
                %(risk_scan_id)s, %(tenant_id)s, %(orchestration_id)s,
                %(source_engine)s, %(scenario_count)s, %(critical_count)s, %(high_count)s,
                %(total_exposure_likely)s, %(total_regulatory_exposure)s,
                %(top_finding_types)s
            )
        """

        prepared = []
        for s in summaries:
            top_types = s.get("top_finding_types", [])
            if isinstance(top_types, (list, dict)):
                top_types = json.dumps(top_types)
            prepared.append({
                "risk_scan_id": s.get("risk_scan_id"),
                "tenant_id": s.get("tenant_id"),
                "orchestration_id": s.get("orchestration_id"),
                "source_engine": s.get("source_engine"),
                "scenario_count": s.get("scenario_count", 0),
                "critical_count": s.get("critical_count", 0),
                "high_count": s.get("high_count", 0),
                "total_exposure_likely": s.get("total_exposure_likely", 0),
                "total_regulatory_exposure": s.get("total_regulatory_exposure", 0),
                "top_finding_types": top_types,
            })

        count = self._batch_execute(sql, prepared)
        logger.info("Inserted %d risk_summary rows", count)
        return count

    # ------------------------------------------------------------------
    # Stage 3 — risk_trends
    # ------------------------------------------------------------------

    def insert_trend(self, trend: Dict[str, Any]) -> None:
        """Insert a risk trend data point."""
        sql = """
            INSERT INTO risk_trends (
                tenant_id, scan_date, risk_scan_id,
                total_exposure_likely, critical_scenarios, high_scenarios,
                top_risk_type, top_risk_engine
            ) VALUES (
                %(tenant_id)s, %(scan_date)s, %(risk_scan_id)s,
                %(total_exposure_likely)s, %(critical_scenarios)s, %(high_scenarios)s,
                %(top_risk_type)s, %(top_risk_engine)s
            )
        """
        cursor = self._conn.cursor()
        try:
            cursor.execute(sql, {
                "tenant_id": trend.get("tenant_id"),
                "scan_date": trend.get("scan_date", datetime.utcnow().date()),
                "risk_scan_id": trend.get("risk_scan_id"),
                "total_exposure_likely": trend.get("total_exposure_likely", 0),
                "critical_scenarios": trend.get("critical_scenarios", 0),
                "high_scenarios": trend.get("high_scenarios", 0),
                "top_risk_type": trend.get("top_risk_type"),
                "top_risk_engine": trend.get("top_risk_engine"),
            })
            self._conn.commit()
        except Exception as exc:
            self._conn.rollback()
            logger.error("Failed to insert risk_trend: %s", exc)
            raise
        finally:
            cursor.close()

    # ------------------------------------------------------------------
    # Stage 4 — Update orchestration
    # ------------------------------------------------------------------

    def update_orchestration(self, orchestration_id: str, scan_id: str, conn=None) -> None:
        """Update scan_orchestration with risk_scan_id."""
        target_conn = conn or self._conn
        cursor = target_conn.cursor()
        try:
            cursor.execute("""
                UPDATE scan_orchestration
                SET risk_scan_id = %s::uuid
                WHERE orchestration_id = %s::uuid
            """, (scan_id, orchestration_id))
            target_conn.commit()
            logger.info("Updated orchestration %s with risk_scan_id %s",
                        orchestration_id, scan_id)
        except Exception as exc:
            target_conn.rollback()
            logger.error("Failed to update orchestration: %s", exc)
            raise
        finally:
            cursor.close()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _batch_execute(self, sql: str, params_list: List[Dict[str, Any]]) -> int:
        """Execute a batch of parameterized inserts."""
        if not params_list:
            return 0

        cursor = self._conn.cursor()
        count = 0
        try:
            for params in params_list:
                cursor.execute(sql, params)
                count += 1
            self._conn.commit()
        except Exception as exc:
            self._conn.rollback()
            logger.error("Batch execute failed at row %d: %s", count, exc)
            raise
        finally:
            cursor.close()

        return count
