"""
Risk Evaluator — Task 5.5 [Phase 5 | BD] — STAGE 2: Evaluate

Reads:
  risk_input_transformed (Stage 1 output)
  risk_model_config (FAIR parameters)
  resource_security_posture (inventory DB — attack path graph signals)

Writes:
  risk_scenarios (one FAIR scenario per finding)

For each CRITICAL/HIGH finding, computes:
  - Loss Event Frequency (LEF) = EPSS × exposure_factor
  - Loss Magnitude (LM) = records × per_record_cost × sensitivity_multiplier
  - Regulatory fines (GDPR, HIPAA, PCI-DSS, CCPA, SOX)
  - Total exposure = (LM + regulatory_fine) × LEF
  - Risk tier classification (critical >$10M, high >$1M, medium >$100K, low)

Attack path graph signal boosts applied to exposure_factor (AP-P3-02):
  - is_on_attack_path=true       → +25 flat points (exposure amplified)
  - attack_path_count > 3        → +10 flat points
  - is_choke_point=true          → +15 flat points
  - has_active_cdr_actor=true    → +30 flat points
  - cert_days_to_expiry < 30     → +10 flat points
  - blast_radius_count > 50      → ×1.20 final multiplier
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional

import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)


class RiskEvaluator:
    """
    Stage 2: Apply FAIR model to each transformed finding,
    produce risk_scenarios rows.

    AP-P3-02: Also reads attack path graph signals from resource_security_posture
    (inventory DB) and applies them as exposure_factor boosts.
    """

    def __init__(self, risk_conn, discovery_conn=None) -> None:
        self._risk_conn = risk_conn
        self._discovery_conn = discovery_conn

    # ------------------------------------------------------------------
    # Attack path signal loading (AP-P3-02)
    # ------------------------------------------------------------------

    def _get_inventory_conn(self) -> Optional[psycopg2.extensions.connection]:
        """Open a connection to the inventory DB (threat_engine_inventory).

        Returns None (non-fatal) if the DB is unreachable.
        """
        try:
            return psycopg2.connect(
                host=os.getenv("INVENTORY_DB_HOST", os.getenv("DB_HOST", "localhost")),
                port=int(os.getenv("INVENTORY_DB_PORT", os.getenv("DB_PORT", "5432"))),
                dbname=os.getenv("INVENTORY_DB_NAME", "threat_engine_inventory"),
                user=os.getenv("INVENTORY_DB_USER", os.getenv("DB_USER", "postgres")),
                password=(
                    os.getenv("INVENTORY_DB_PASSWORD")
                    or os.getenv("DB_PASSWORD")
                    or os.getenv("DISCOVERIES_DB_PASSWORD", "")
                ),
                sslmode=os.getenv("DB_SSLMODE", "prefer"),
                connect_timeout=5,
            )
        except Exception as exc:
            logger.warning("AP signals: cannot connect to inventory DB: %s", exc)
            return None

    def _load_attack_path_signals(
        self,
        resource_uids: List[str],
        tenant_id: str,
    ) -> Dict[str, Dict[str, Any]]:
        """Read attack path posture signals from resource_security_posture.

        Returns a dict keyed by resource_uid with the 6 signal fields.
        If inventory DB is unreachable or the table is missing, returns {}.

        Multi-tenant: query scoped by tenant_id (AP-P3-02).
        """
        if not resource_uids:
            return {}

        conn = self._get_inventory_conn()
        if not conn:
            return {}

        signals: Dict[str, Dict[str, Any]] = {}
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT
                        resource_uid,
                        is_on_attack_path,
                        attack_path_count,
                        is_choke_point,
                        has_active_cdr_actor,
                        cert_days_to_expiry,
                        blast_radius_count
                    FROM resource_security_posture
                    WHERE tenant_id = %s
                      AND resource_uid = ANY(%s)
                """, (tenant_id, resource_uids))
                for row in cur.fetchall():
                    uid = row["resource_uid"]
                    signals[uid] = {
                        "is_on_attack_path":    bool(row.get("is_on_attack_path") or False),
                        "attack_path_count":    int(row.get("attack_path_count") or 0),
                        "is_choke_point":       bool(row.get("is_choke_point") or False),
                        "has_active_cdr_actor": bool(row.get("has_active_cdr_actor") or False),
                        "cert_days_to_expiry":  row.get("cert_days_to_expiry"),
                        "blast_radius_count":   int(row.get("blast_radius_count") or 0),
                    }
            logger.info(
                "AP signals: loaded posture rows for %d / %d resource UIDs",
                len(signals), len(resource_uids),
            )
        except Exception as exc:
            # Non-fatal: risk scan proceeds without attack path signals
            logger.warning("AP signals: failed to load from resource_security_posture: %s", exc)
        finally:
            conn.close()

        return signals

    @staticmethod
    def _apply_attack_path_boosts(
        exposure_factor: float,
        signals: Dict[str, Any],
    ) -> float:
        """Apply attack-path posture signal boosts to exposure_factor.

        Boost rules (AP-P3-02):
          +25 if is_on_attack_path
          +10 if attack_path_count > 3
          +15 if is_choke_point
          +30 if has_active_cdr_actor
          +10 if cert_days_to_expiry < 30 (and value is set)
          ×1.20 if blast_radius_count > 50

        The flat additions are applied as a percentage-point increase to
        exposure_factor (which normally ranges 0.0–1.5).  To avoid
        unbounded growth the additive boosts are expressed as a fraction
        of 100 so a +25 point boost = +0.25 to exposure_factor.

        Returns the boosted exposure_factor clamped to [original, 3.0].
        """
        if not signals:
            return exposure_factor

        flat_boost = 0.0
        if signals.get("is_on_attack_path"):
            flat_boost += 25.0
        if signals.get("attack_path_count", 0) > 3:
            flat_boost += 10.0
        if signals.get("is_choke_point"):
            flat_boost += 15.0
        if signals.get("has_active_cdr_actor"):
            flat_boost += 30.0
        if signals.get("active_cdr_actor_on_admin_role"):
            # Highest single risk signal: admin credential actively exploited
            flat_boost += 50.0
        cert_days = signals.get("cert_days_to_expiry")
        if cert_days is not None and 0 <= int(cert_days) < 30:
            flat_boost += 10.0

        # Convert flat points → exposure factor delta (divide by 100)
        boosted = exposure_factor + (flat_boost / 100.0)

        # Blast radius multiplier applied last
        if signals.get("blast_radius_count", 0) > 50:
            boosted *= 1.20

        return min(3.0, boosted)

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
        # AC-S2: tenant_id filter enforced inside _load_transformed_findings
        findings = self._load_transformed_findings(scan_id, tenant_id)
        logger.info("Loaded %d transformed findings for evaluation", len(findings))

        if not findings:
            logger.warning("No transformed findings to evaluate")
            return 0

        # 3. Compute FAIR scenario for each finding
        from engines.risk.models.fair_model import compute_scenario
        from engines.risk.blast_radius.neo4j_traversal import compute_blast_radius_batch

        # Deduplicate resource UIDs to avoid N Neo4j round-trips for identical assets
        # Many findings share the same resource (e.g. 50 check rules all fail on one RDS instance)
        unique_uids: list = list({
            (finding.get("asset_arn") or finding.get("asset_id") or "")
            for finding in findings
        })
        logger.info("Computing blast radius for %d unique resource UIDs (%d total findings)",
                    len(unique_uids), len(findings))

        # Batch Neo4j queries with a single driver (reused across all UIDs)
        # AC-S1: all Cypher uses $param syntax; AC-S3: credentials never logged
        blast_radius_cache: Dict[str, Dict[str, Any]] = compute_blast_radius_batch(unique_uids)

        # AP-P3-02: Load attack path posture signals from inventory DB
        # Non-fatal — signals are empty dict if inventory DB is unreachable
        ap_signals_cache: Dict[str, Dict[str, Any]] = self._load_attack_path_signals(
            resource_uids=unique_uids,
            tenant_id=tenant_id,
        )
        logger.info("AP signals: %d resources have attack path posture data", len(ap_signals_cache))

        scenarios: List[Dict[str, Any]] = []
        for finding in findings:
            # AP-P3-02: Apply attack path boosts to exposure_factor before FAIR computation
            resource_uid = finding.get("asset_arn") or finding.get("asset_id") or ""
            ap_sig = ap_signals_cache.get(resource_uid, {})
            if ap_sig:
                original_ef = finding.get("exposure_factor", 1.0)
                boosted_ef = self._apply_attack_path_boosts(original_ef, ap_sig)
                if boosted_ef != original_ef:
                    logger.debug(
                        "AP boost for %s: exposure_factor %.3f → %.3f (signals: %s)",
                        resource_uid, original_ef, boosted_ef,
                        {k: v for k, v in ap_sig.items() if v},
                    )
                    finding = {**finding, "exposure_factor": boosted_ef}

            scenario = compute_scenario(finding, model_config)

            # Neo4j blast radius — ONLY place in the platform that sets non-zero score
            # Falls back to 0 if Neo4j is unreachable or graph is empty (AC-S7: 0-100 clamp)
            resource_uid = finding.get("asset_arn") or finding.get("asset_id") or ""
            br = blast_radius_cache.get(resource_uid, {"blast_radius_score": 0, "sample_targets": []})

            # AC-S7: clamp to 0-100 before storing
            blast_score = max(0, min(100, int(br.get("blast_radius_score") or 0)))
            scenario["blast_radius_score"] = blast_score
            scenario["blast_radius_sample"] = br.get("sample_targets", [])

            # Populate attack_path from blast radius sample_targets (AC-F9)
            # Prepend the source resource so the path has at least 2 entries
            sample_targets = br.get("sample_targets") or []
            if sample_targets:
                attack_path = [resource_uid] + list(sample_targets[:9])
            else:
                attack_path = [resource_uid] if resource_uid else []
            scenario["attack_path"] = attack_path

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

    def _load_transformed_findings(self, scan_id: str, tenant_id: str = "") -> List[Dict[str, Any]]:
        """Load all transformed findings for this risk scan.

        AC-S2: query always includes tenant_id filter to prevent cross-tenant leakage.

        Args:
            scan_id: The risk_scan_id UUID.
            tenant_id: Tenant identifier — mandatory for row-level isolation.

        Returns:
            List of transformed finding dicts for FAIR evaluation.
        """
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
                  AND tenant_id = %s
            """, (scan_id, tenant_id))

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
