"""
Risk Evaluator — Task 5.5 [Phase 5 | BD] — STAGE 2: Evaluate

Reads:
  risk_input_transformed (Stage 1 output)
  risk_model_config (FAIR parameters)

Writes:
  risk_scenarios (one FAIR scenario per finding)

For each CRITICAL/HIGH finding, computes:
  - Loss Event Frequency (LEF) = EPSS × exposure_factor
  - Loss Magnitude (LM) = records × per_record_cost × sensitivity_multiplier
  - Regulatory fines (GDPR, HIPAA, PCI-DSS, CCPA, SOX)
  - Total exposure = (LM + regulatory_fine) × LEF
  - Risk tier classification (critical >$10M, high >$1M, medium >$100K, low)
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class RiskEvaluator:
    """
    Stage 2: Apply FAIR model to each transformed finding,
    produce risk_scenarios rows.
    """

    def __init__(self, risk_conn, discovery_conn=None) -> None:
        self._risk_conn = risk_conn
        self._discovery_conn = discovery_conn

    def run(
        self,
        scan_id: str,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        provider: str = "aws",
    ) -> int:
        """
        Execute Stage 2 evaluation.

        Returns:
            Number of risk scenarios written.
        """
        logger.info("Risk Evaluator started: scan_id=%s", scan_id)

        # 1. Load FAIR model configuration
        model_config = self._load_model_config(tenant_id)

        # 2. Load transformed findings from Stage 1
        findings = self._load_transformed_findings(scan_id)
        logger.info("Loaded %d transformed findings for evaluation", len(findings))

        if not findings:
            logger.warning("No transformed findings to evaluate")
            return 0

        # 3. Compute FAIR scenario for each finding
        from engines.risk.models.fair_model import compute_scenario

        scenarios: List[Dict[str, Any]] = []
        for finding in findings:
            scenario = compute_scenario(finding, model_config)
            scenarios.append(scenario)

        # 4. Write scenarios to risk_scenarios
        from engines.risk.db.risk_db_writer import RiskDBWriter
        writer = RiskDBWriter(self._risk_conn)
        count = writer.batch_insert_scenarios(
            scenarios, scan_id, tenant_id, scan_run_id
        )

        logger.info("Risk Evaluator complete: %d scenarios", count)
        return count

    # ------------------------------------------------------------------
    # Data loading
    # ------------------------------------------------------------------

    def _load_model_config(self, tenant_id: str) -> Dict[str, Any]:
        """Load FAIR model configuration for the tenant."""
        config: Dict[str, Any] = {
            "per_record_cost": 4.45,
            "estimated_annual_revenue": 100_000_000,
            "applicable_regs": [],
            "downtime_cost_hr": 10000.0,
            "sensitivity_multipliers": {
                "restricted": 3.0,
                "confidential": 2.0,
                "internal": 1.0,
                "public": 0.1,
            },
            "default_record_count": 1000,
        }

        cursor = self._risk_conn.cursor()
        try:
            cursor.execute("""
                SELECT per_record_cost, estimated_annual_revenue,
                       applicable_regs, downtime_cost_hr,
                       sensitivity_multipliers, default_record_count,
                       industry
                FROM risk_model_config
                WHERE (tenant_id = %s OR tenant_id IS NULL)
                ORDER BY tenant_id NULLS LAST
                LIMIT 1
            """, (tenant_id,))
            row = cursor.fetchone()
            if row:
                config["per_record_cost"] = float(row[0]) if row[0] else 4.45
                config["estimated_annual_revenue"] = float(row[1]) if row[1] else 100_000_000
                config["applicable_regs"] = (
                    row[2] if isinstance(row[2], list)
                    else json.loads(row[2]) if row[2]
                    else []
                )
                config["downtime_cost_hr"] = float(row[3]) if row[3] else 10000.0
                config["sensitivity_multipliers"] = (
                    row[4] if isinstance(row[4], dict)
                    else json.loads(row[4]) if row[4]
                    else config["sensitivity_multipliers"]
                )
                config["default_record_count"] = int(row[5]) if row[5] else 1000
                config["industry"] = row[6] or "default"
        except Exception as exc:
            logger.warning("Failed to load model config: %s", exc)
        finally:
            cursor.close()

        return config

    def _load_transformed_findings(self, scan_id: str) -> List[Dict[str, Any]]:
        """Load all transformed findings for this risk scan."""
        findings: List[Dict[str, Any]] = []
        cursor = self._risk_conn.cursor()
        try:
            cursor.execute("""
                SELECT
                    source_finding_id, source_engine, source_scan_id,
                    rule_id, severity, title, finding_type,
                    asset_id, asset_type, asset_arn, asset_criticality, is_public,
                    data_sensitivity, data_types, estimated_record_count,
                    industry, estimated_revenue, applicable_regulations,
                    epss_score, cve_id, exposure_factor,
                    account_id, region, csp
                FROM risk_input_transformed
                WHERE risk_scan_id = %s::uuid
            """, (scan_id,))

            for row in cursor.fetchall():
                findings.append({
                    "source_finding_id": row[0],
                    "source_engine": row[1],
                    "source_scan_id": row[2],
                    "rule_id": row[3],
                    "severity": row[4],
                    "title": row[5],
                    "finding_type": row[6],
                    "asset_id": row[7],
                    "asset_type": row[8],
                    "asset_arn": row[9],
                    "asset_criticality": row[10],
                    "is_public": row[11],
                    "data_sensitivity": row[12],
                    "data_types": row[13] or [],
                    "estimated_record_count": row[14] or 0,
                    "industry": row[15],
                    "estimated_revenue": float(row[16]) if row[16] else None,
                    "applicable_regulations": row[17] or [],
                    "epss_score": float(row[18]) if row[18] else 0.05,
                    "cve_id": row[19],
                    "exposure_factor": float(row[20]) if row[20] else 1.0,
                    "account_id": row[21],
                    "region": row[22],
                    "csp": row[23],
                })
        except Exception as exc:
            logger.error("Failed to load transformed findings: %s", exc)
        finally:
            cursor.close()

        return findings
