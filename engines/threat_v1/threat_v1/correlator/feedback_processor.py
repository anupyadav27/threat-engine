"""
FeedbackProcessor — per-tenant suppression from analyst FP verdicts (S2-10).

Reads from threat_incident_feedback (INSERT-only, immutable audit log).
If rolling-30d FP rate for a pattern within a tenant exceeds 30%:
  → INSERT row into threat_pattern_suppressions (tenant-scoped)

CP1-05 enforcement:
  NEVER set active=false on the shared threat_scenario_patterns row.
  Global deactivation requires SA approval + manual update.

Rate limit: enforced at the endpoint layer (10 verdicts/user/24h).
This class only processes the feedback — it does not enforce the rate limit.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

_FP_RATE_THRESHOLD = 0.30  # 30% false-positive rate triggers suppression
_ROLLING_WINDOW_DAYS = 30


class FeedbackProcessor:
    """Processes analyst feedback and auto-suppresses high-FP patterns per tenant."""

    def __init__(self, threat_conn: Any) -> None:
        self._conn = threat_conn

    def process(self, tenant_id: str) -> Dict[str, int]:
        """Evaluate FP rates for all patterns this tenant has reviewed.

        Returns:
            Dict with patterns_evaluated and patterns_suppressed.
        """
        rates = self._compute_fp_rates(tenant_id)
        suppressed = 0

        for pattern_id, fp_rate in rates.items():
            if fp_rate >= _FP_RATE_THRESHOLD:
                self._suppress_pattern(tenant_id, pattern_id, fp_rate)
                suppressed += 1

        logger.info(
            "FeedbackProcessor: evaluated %d patterns, suppressed %d for tenant %s",
            len(rates), suppressed, tenant_id,
        )
        return {"patterns_evaluated": len(rates), "patterns_suppressed": suppressed}

    def _compute_fp_rates(self, tenant_id: str) -> Dict[str, float]:
        """Compute rolling 30-day FP rate per pattern for this tenant."""
        cur = self._conn.cursor()
        cur.execute(
            """
            SELECT
                pattern_id,
                COUNT(*) FILTER (WHERE verdict = 'false_positive') AS fp_count,
                COUNT(*) AS total_count
            FROM threat_incident_feedback
            WHERE tenant_id  = %s
              AND created_at >= NOW() - INTERVAL '%s days'
            GROUP BY pattern_id
            HAVING COUNT(*) > 0
            """,
            (tenant_id, _ROLLING_WINDOW_DAYS),
        )
        rows = cur.fetchall()
        cur.close()

        return {
            row["pattern_id"]: row["fp_count"] / row["total_count"]
            for row in rows
            if row["total_count"] > 0
        }

    def _suppress_pattern(
        self,
        tenant_id: str,
        pattern_id: str,
        fp_rate: float,
    ) -> None:
        """Insert per-tenant suppression. NEVER touches threat_scenario_patterns."""
        reason = f"fp_rate:{fp_rate:.0%}_over_{_ROLLING_WINDOW_DAYS}d"
        cur = self._conn.cursor()
        cur.execute(
            """
            INSERT INTO threat_pattern_suppressions (
                tenant_id, pattern_id, reason, auto_generated, created_at
            ) VALUES (%s, %s, %s, true, NOW())
            ON CONFLICT (tenant_id, pattern_id) DO UPDATE
            SET reason     = EXCLUDED.reason,
                created_at = NOW()
            """,
            (tenant_id, pattern_id, reason),
        )
        self._conn.commit()
        cur.close()
        logger.warning(
            "Auto-suppressed pattern %s for tenant %s (fp_rate=%.0f%%)",
            pattern_id, tenant_id, fp_rate * 100,
        )
