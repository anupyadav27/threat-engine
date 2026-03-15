"""
Risk Reporter — Task 5.6 [Phase 5 | BD] — STAGE 3: Report

Reads:
  risk_scenarios (Stage 2 output)

Writes:
  risk_report      (scan-level summary)
  risk_summary     (per-engine aggregation)
  risk_trends      (time-series data point)

Aggregates:
  - Scenario counts by tier (critical/high/medium/low)
  - Total exposure (min/likely/max)
  - Engine breakdown (exposure per source engine)
  - Scenario type breakdown (data_breach, ransomware, etc.)
  - Top N scenarios by exposure
  - Trending vs. previous scan
  - Frameworks at risk
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

TOP_SCENARIOS_LIMIT = 10


class RiskReporter:
    """
    Stage 3: Aggregate risk scenarios into reports, summaries, and trends.
    """

    def __init__(self, risk_conn) -> None:
        self._risk_conn = risk_conn

    def run(
        self,
        scan_id: str,
        orchestration_id: str,
        tenant_id: str,
        account_id: str,
        provider: str = "aws",
        started_at: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Execute Stage 3 reporting.

        Returns:
            The risk_report dict.
        """
        logger.info("Risk Reporter started: scan_id=%s", scan_id)

        # 1. Load all scenarios for this scan
        scenarios = self._load_scenarios(scan_id)
        logger.info("Loaded %d scenarios for reporting", len(scenarios))

        # 2. Aggregate
        tier_counts = self._count_by_tier(scenarios)
        exposure_totals = self._sum_exposure(scenarios)
        engine_breakdown = self._engine_breakdown(scenarios)
        scenario_type_breakdown = self._scenario_type_breakdown(scenarios)
        top_scenarios = self._top_scenarios(scenarios, TOP_SCENARIOS_LIMIT)
        frameworks = self._collect_frameworks(scenarios)
        regulatory_total = self._sum_regulatory_exposure(scenarios)

        # 3. Trending comparison
        previous = self._load_previous_report(tenant_id, scan_id)
        vs_previous_likely = None
        vs_previous_pct = None
        if previous:
            prev_likely = previous.get("total_exposure_likely", 0)
            curr_likely = exposure_totals["likely"]
            vs_previous_likely = round(curr_likely - prev_likely, 2)
            if prev_likely > 0:
                vs_previous_pct = round(
                    ((curr_likely - prev_likely) / prev_likely) * 100, 2
                )

        # 4. Build report
        completed_at = datetime.utcnow()
        duration_ms = None
        if started_at:
            duration_ms = int((completed_at - started_at).total_seconds() * 1000)

        report = {
            "risk_scan_id": scan_id,
            "orchestration_id": orchestration_id,
            "tenant_id": tenant_id,
            "account_id": account_id,
            "provider": provider,
            "total_scenarios": len(scenarios),
            "critical_scenarios": tier_counts.get("critical", 0),
            "high_scenarios": tier_counts.get("high", 0),
            "medium_scenarios": tier_counts.get("medium", 0),
            "low_scenarios": tier_counts.get("low", 0),
            "total_exposure_min": exposure_totals["min"],
            "total_exposure_max": exposure_totals["max"],
            "total_exposure_likely": exposure_totals["likely"],
            "total_regulatory_exposure": regulatory_total,
            "engine_breakdown": engine_breakdown,
            "top_scenarios": top_scenarios,
            "scenario_type_breakdown": scenario_type_breakdown,
            "frameworks_at_risk": frameworks,
            "vs_previous_likely": vs_previous_likely,
            "vs_previous_pct": vs_previous_pct,
            "currency": "USD",
            "started_at": started_at,
            "completed_at": completed_at,
            "scan_duration_ms": duration_ms,
            "status": "completed",
            "error_message": None,
        }

        # 5. Write report
        from engines.risk.db.risk_db_writer import RiskDBWriter
        writer = RiskDBWriter(self._risk_conn)
        writer.insert_report(report)

        # 6. Write per-engine summaries
        summaries = self._build_engine_summaries(
            scenarios, scan_id, orchestration_id, tenant_id
        )
        writer.batch_insert_summaries(summaries)

        # 7. Write trend data point
        top_type = max(scenario_type_breakdown, key=scenario_type_breakdown.get) if scenario_type_breakdown else None
        top_engine = max(engine_breakdown, key=engine_breakdown.get) if engine_breakdown else None
        writer.insert_trend({
            "tenant_id": tenant_id,
            "risk_scan_id": scan_id,
            "scan_date": completed_at.date(),
            "total_exposure_likely": exposure_totals["likely"],
            "critical_scenarios": tier_counts.get("critical", 0),
            "high_scenarios": tier_counts.get("high", 0),
            "top_risk_type": top_type,
            "top_risk_engine": top_engine,
        })

        logger.info("Risk Reporter complete: $%.2f total exposure (likely)",
                     exposure_totals["likely"])
        return report

    # ------------------------------------------------------------------
    # Aggregation helpers
    # ------------------------------------------------------------------

    def _count_by_tier(self, scenarios: List[Dict]) -> Dict[str, int]:
        """Count scenarios by risk tier."""
        counts: Dict[str, int] = defaultdict(int)
        for s in scenarios:
            tier = s.get("risk_tier", "low")
            counts[tier] += 1
        return dict(counts)

    def _sum_exposure(self, scenarios: List[Dict]) -> Dict[str, float]:
        """Sum total exposure across all scenarios."""
        total_min = sum(float(s.get("total_exposure_min", 0)) for s in scenarios)
        total_max = sum(float(s.get("total_exposure_max", 0)) for s in scenarios)
        total_likely = sum(float(s.get("total_exposure_likely", 0)) for s in scenarios)
        return {
            "min": round(total_min, 2),
            "max": round(total_max, 2),
            "likely": round(total_likely, 2),
        }

    def _sum_regulatory_exposure(self, scenarios: List[Dict]) -> float:
        """Sum regulatory fine exposure across all scenarios."""
        total = sum(float(s.get("regulatory_fine_max", 0)) for s in scenarios)
        return round(total, 2)

    def _engine_breakdown(self, scenarios: List[Dict]) -> Dict[str, float]:
        """Aggregate exposure by source engine."""
        breakdown: Dict[str, float] = defaultdict(float)
        for s in scenarios:
            engine = s.get("source_engine", "unknown")
            breakdown[engine] += float(s.get("total_exposure_likely", 0))
        return {k: round(v, 2) for k, v in breakdown.items()}

    def _scenario_type_breakdown(self, scenarios: List[Dict]) -> Dict[str, float]:
        """Aggregate exposure by scenario type."""
        breakdown: Dict[str, float] = defaultdict(float)
        for s in scenarios:
            stype = s.get("scenario_type", "unknown")
            breakdown[stype] += float(s.get("total_exposure_likely", 0))
        return {k: round(v, 2) for k, v in breakdown.items()}

    def _top_scenarios(self, scenarios: List[Dict], limit: int) -> List[Dict]:
        """Return top N scenarios by total_exposure_likely."""
        sorted_scenarios = sorted(
            scenarios,
            key=lambda s: float(s.get("total_exposure_likely", 0)),
            reverse=True,
        )
        return [
            {
                "scenario_id": s.get("scenario_id"),
                "source_engine": s.get("source_engine"),
                "source_finding_id": s.get("source_finding_id"),
                "asset_arn": s.get("asset_arn"),
                "scenario_type": s.get("scenario_type"),
                "total_exposure_likely": float(s.get("total_exposure_likely", 0)),
                "risk_tier": s.get("risk_tier"),
            }
            for s in sorted_scenarios[:limit]
        ]

    def _collect_frameworks(self, scenarios: List[Dict]) -> List[str]:
        """Collect unique regulatory frameworks at risk."""
        frameworks = set()
        for s in scenarios:
            regs = s.get("applicable_regulations", [])
            if isinstance(regs, list):
                frameworks.update(regs)
        return sorted(frameworks)

    # ------------------------------------------------------------------
    # Per-engine summaries
    # ------------------------------------------------------------------

    def _build_engine_summaries(
        self,
        scenarios: List[Dict],
        scan_id: str,
        orchestration_id: str,
        tenant_id: str,
    ) -> List[Dict[str, Any]]:
        """Build per-engine summary rows."""
        engine_groups: Dict[str, List[Dict]] = defaultdict(list)
        for s in scenarios:
            engine = s.get("source_engine", "unknown")
            engine_groups[engine].append(s)

        summaries = []
        for engine, group in engine_groups.items():
            critical_count = sum(1 for s in group if s.get("risk_tier") == "critical")
            high_count = sum(1 for s in group if s.get("risk_tier") == "high")
            total_exposure = sum(float(s.get("total_exposure_likely", 0)) for s in group)
            total_reg = sum(float(s.get("regulatory_fine_max", 0)) for s in group)

            # Top finding types by count
            type_counts: Dict[str, int] = defaultdict(int)
            for s in group:
                stype = s.get("scenario_type", "unknown")
                type_counts[stype] += 1
            top_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:5]

            summaries.append({
                "risk_scan_id": scan_id,
                "tenant_id": tenant_id,
                "orchestration_id": orchestration_id,
                "source_engine": engine,
                "scenario_count": len(group),
                "critical_count": critical_count,
                "high_count": high_count,
                "total_exposure_likely": round(total_exposure, 2),
                "total_regulatory_exposure": round(total_reg, 2),
                "top_finding_types": [{"type": t, "count": c} for t, c in top_types],
            })

        return summaries

    # ------------------------------------------------------------------
    # Data loading
    # ------------------------------------------------------------------

    def _load_scenarios(self, scan_id: str) -> List[Dict[str, Any]]:
        """Load all risk scenarios for this scan."""
        scenarios: List[Dict[str, Any]] = []
        cursor = self._risk_conn.cursor()
        try:
            cursor.execute("""
                SELECT
                    scenario_id::text, source_finding_id, source_engine,
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
                FROM risk_scenarios
                WHERE risk_scan_id = %s::uuid
            """, (scan_id,))

            for row in cursor.fetchall():
                scenarios.append({
                    "scenario_id": row[0],
                    "source_finding_id": row[1],
                    "source_engine": row[2],
                    "asset_id": row[3],
                    "asset_type": row[4],
                    "asset_arn": row[5],
                    "scenario_type": row[6],
                    "data_records_at_risk": row[7],
                    "data_sensitivity": row[8],
                    "data_types": row[9] or [],
                    "loss_event_frequency": float(row[10]) if row[10] else 0,
                    "primary_loss_min": float(row[11]) if row[11] else 0,
                    "primary_loss_max": float(row[12]) if row[12] else 0,
                    "primary_loss_likely": float(row[13]) if row[13] else 0,
                    "regulatory_fine_min": float(row[14]) if row[14] else 0,
                    "regulatory_fine_max": float(row[15]) if row[15] else 0,
                    "applicable_regulations": row[16] or [],
                    "total_exposure_min": float(row[17]) if row[17] else 0,
                    "total_exposure_max": float(row[18]) if row[18] else 0,
                    "total_exposure_likely": float(row[19]) if row[19] else 0,
                    "risk_tier": row[20],
                    "calculation_model": row[21],
                    "account_id": row[22],
                    "region": row[23],
                    "csp": row[24],
                })
        except Exception as exc:
            logger.error("Failed to load risk scenarios: %s", exc)
        finally:
            cursor.close()

        return scenarios

    def _load_previous_report(self, tenant_id: str, current_scan_id: str) -> Optional[Dict]:
        """Load the most recent previous risk report for trending."""
        cursor = self._risk_conn.cursor()
        try:
            cursor.execute("""
                SELECT total_exposure_likely, total_exposure_min, total_exposure_max,
                       total_scenarios, critical_scenarios, high_scenarios
                FROM risk_report
                WHERE tenant_id = %s
                  AND risk_scan_id != %s::uuid
                  AND status = 'completed'
                ORDER BY completed_at DESC
                LIMIT 1
            """, (tenant_id, current_scan_id))
            row = cursor.fetchone()
            if row:
                return {
                    "total_exposure_likely": float(row[0]) if row[0] else 0,
                    "total_exposure_min": float(row[1]) if row[1] else 0,
                    "total_exposure_max": float(row[2]) if row[2] else 0,
                    "total_scenarios": row[3] or 0,
                    "critical_scenarios": row[4] or 0,
                    "high_scenarios": row[5] or 0,
                }
        except Exception as exc:
            logger.warning("Failed to load previous report: %s", exc)
        finally:
            cursor.close()

        return None
