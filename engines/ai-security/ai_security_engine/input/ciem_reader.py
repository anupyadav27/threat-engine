"""
CIEM DB Reader for AI Security Engine.

Reads CloudTrail AI/ML service events from the log_events table
in threat_engine_inventory (CIEM stores normalized events here).

Provides:
  - AI service invocation patterns per resource
  - Shadow AI detection (invocations with no matching discovery resource)
  - Anomaly detection for unusual AI API usage
"""

import os
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone, timedelta

import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)

# AI/ML services to track in CloudTrail
AI_CT_SERVICES = (
    "sagemaker", "bedrock", "comprehend", "rekognition", "textract",
    "translate", "transcribe", "polly", "lex", "kendra",
    "personalize", "forecast",
)

# High-value invocation operations that indicate active AI usage
AI_INVOKE_OPERATIONS = (
    "InvokeModel", "InvokeModelWithResponseStream",
    "InvokeEndpoint", "InvokeEndpointAsync",
    "Invoke", "Converse", "ConverseStream",
    "DetectEntities", "DetectSentiment", "DetectKeyPhrases",
    "DetectFaces", "RecognizeCelebrities", "DetectLabels",
    "AnalyzeDocument", "DetectDocumentText",
    "TranslateText", "StartTranscriptionJob",
    "SynthesizeSpeech", "RecognizeText", "RecognizeUtterance",
    "Query", "GetRecommendations", "CreateForecast",
)


def _get_ciem_conn():
    """Get connection to the CIEM / Inventory database."""
    return psycopg2.connect(
        host=os.getenv(
            "CIEM_DB_HOST",
            os.getenv("INVENTORY_DB_HOST", os.getenv("DB_HOST", "localhost")),
        ),
        port=int(os.getenv(
            "CIEM_DB_PORT",
            os.getenv("INVENTORY_DB_PORT", os.getenv("DB_PORT", "5432")),
        )),
        dbname=os.getenv(
            "CIEM_DB_NAME",
            os.getenv("INVENTORY_DB_NAME", "threat_engine_inventory"),
        ),
        user=os.getenv(
            "CIEM_DB_USER",
            os.getenv("INVENTORY_DB_USER", os.getenv("DB_USER", "postgres")),
        ),
        password=os.getenv(
            "CIEM_DB_PASSWORD",
            os.getenv("INVENTORY_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        ),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
    )


class AICIEMReader:
    """Reads AI/ML-related CloudTrail events from CIEM (log_events table)."""

    def __init__(self):
        self.conn = None

    def _ensure_conn(self):
        if self.conn is None or self.conn.closed:
            self.conn = _get_ciem_conn()

    def get_ai_invocation_patterns(
        self,
        tenant_id: str,
        account_id: Optional[str] = None,
        days: int = 30,
    ) -> List[Dict[str, Any]]:
        """Get per-resource invocation statistics for AI services.

        Groups CloudTrail events by resource_uid and operation to show
        total calls, unique callers, and time range.

        Args:
            tenant_id: Tenant identifier.
            account_id: Optional cloud account filter.
            days: Lookback window in days.

        Returns:
            List of dicts with resource_uid, operation, total_calls,
            unique_callers, first_seen, last_seen.
        """
        self._ensure_conn()
        since = datetime.now(timezone.utc) - timedelta(days=days)

        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                sql = """
                    SELECT
                        resource_uid,
                        operation,
                        service,
                        COUNT(*) AS total_calls,
                        COUNT(DISTINCT actor_principal) AS unique_callers,
                        MIN(event_time) AS first_seen,
                        MAX(event_time) AS last_seen
                    FROM log_events
                    WHERE tenant_id = %s
                      AND service = ANY(%s)
                      AND event_time >= %s
                """
                params: list = [tenant_id, list(AI_CT_SERVICES), since]

                if account_id:
                    sql += " AND actor_account_id = %s"
                    params.append(account_id)

                sql += """
                    GROUP BY resource_uid, operation, service
                    ORDER BY total_calls DESC
                    LIMIT 5000
                """

                cur.execute(sql, params)
                rows = cur.fetchall()
                logger.info(
                    f"CIEM: loaded {len(rows)} AI invocation pattern rows (last {days} days)"
                )
                return [dict(r) for r in rows]
        except Exception as e:
            logger.warning(f"Failed to load AI invocation patterns: {e}")
            return []

    def get_shadow_ai_calls(
        self,
        tenant_id: str,
        account_id: Optional[str] = None,
        days: int = 30,
    ) -> List[Dict[str, Any]]:
        """Find AI service invocations with NO matching discovery resource.

        Detects shadow AI usage by looking for high-value invoke operations
        where the resource_uid is NULL or empty, indicating the resource
        was not enumerated during discovery.

        Args:
            tenant_id: Tenant identifier.
            account_id: Optional cloud account filter.
            days: Lookback window in days.

        Returns:
            List of dicts with actor_principal, operation, service,
            resource_uid, call_count, first_seen, last_seen.
        """
        self._ensure_conn()
        since = datetime.now(timezone.utc) - timedelta(days=days)

        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                sql = """
                    SELECT
                        actor_principal,
                        actor_principal_type,
                        operation,
                        service,
                        resource_uid,
                        COUNT(*) AS call_count,
                        MIN(event_time) AS first_seen,
                        MAX(event_time) AS last_seen
                    FROM log_events
                    WHERE tenant_id = %s
                      AND service = ANY(%s)
                      AND operation = ANY(%s)
                      AND event_time >= %s
                      AND (resource_uid IS NULL OR resource_uid = '')
                """
                params: list = [
                    tenant_id, list(AI_CT_SERVICES),
                    list(AI_INVOKE_OPERATIONS), since,
                ]

                if account_id:
                    sql += " AND actor_account_id = %s"
                    params.append(account_id)

                sql += """
                    GROUP BY actor_principal, actor_principal_type,
                             operation, service, resource_uid
                    ORDER BY call_count DESC
                    LIMIT 1000
                """

                cur.execute(sql, params)
                rows = cur.fetchall()
                logger.info(f"CIEM: found {len(rows)} shadow AI call patterns")
                return [dict(r) for r in rows]
        except Exception as e:
            logger.warning(f"Failed to load shadow AI calls: {e}")
            return []

    def get_ai_anomalies(
        self,
        tenant_id: str,
        account_id: Optional[str] = None,
        days: int = 7,
    ) -> List[Dict[str, Any]]:
        """Detect anomalous AI API usage patterns.

        Looks for:
        - High error rates per principal/service
        - Unusual hours activity (outside 06:00-22:00 UTC)
        - High volume from a single principal

        Args:
            tenant_id: Tenant identifier.
            account_id: Optional cloud account filter.
            days: Lookback window in days.

        Returns:
            List of anomaly dicts with anomaly_type, actor_principal,
            service, detail metrics.
        """
        self._ensure_conn()
        since = datetime.now(timezone.utc) - timedelta(days=days)
        anomalies: List[Dict[str, Any]] = []

        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                # --- High error rates ---
                sql_errors = """
                    SELECT
                        actor_principal,
                        service,
                        COUNT(*) AS total_calls,
                        COUNT(*) FILTER (WHERE error_code IS NOT NULL AND error_code != '') AS error_count,
                        ROUND(
                            100.0 * COUNT(*) FILTER (WHERE error_code IS NOT NULL AND error_code != '')
                            / NULLIF(COUNT(*), 0), 2
                        ) AS error_rate_pct
                    FROM log_events
                    WHERE tenant_id = %s
                      AND service = ANY(%s)
                      AND event_time >= %s
                """
                params_err: list = [tenant_id, list(AI_CT_SERVICES), since]
                if account_id:
                    sql_errors += " AND actor_account_id = %s"
                    params_err.append(account_id)
                sql_errors += """
                    GROUP BY actor_principal, service
                    HAVING COUNT(*) >= 10
                       AND COUNT(*) FILTER (WHERE error_code IS NOT NULL AND error_code != '')
                           > 0.3 * COUNT(*)
                    ORDER BY error_rate_pct DESC
                    LIMIT 100
                """

                cur.execute(sql_errors, params_err)
                for row in cur.fetchall():
                    anomalies.append({
                        "anomaly_type": "high_error_rate",
                        "actor_principal": row["actor_principal"],
                        "service": row["service"],
                        "total_calls": row["total_calls"],
                        "error_count": row["error_count"],
                        "error_rate_pct": float(row["error_rate_pct"] or 0),
                    })

                # --- Unusual hours activity (outside 06:00-22:00 UTC) ---
                sql_hours = """
                    SELECT
                        actor_principal,
                        service,
                        COUNT(*) AS off_hours_calls,
                        MIN(event_time) AS first_seen,
                        MAX(event_time) AS last_seen
                    FROM log_events
                    WHERE tenant_id = %s
                      AND service = ANY(%s)
                      AND event_time >= %s
                      AND (EXTRACT(HOUR FROM event_time) < 6
                           OR EXTRACT(HOUR FROM event_time) >= 22)
                """
                params_hrs: list = [tenant_id, list(AI_CT_SERVICES), since]
                if account_id:
                    sql_hours += " AND actor_account_id = %s"
                    params_hrs.append(account_id)
                sql_hours += """
                    GROUP BY actor_principal, service
                    HAVING COUNT(*) >= 20
                    ORDER BY off_hours_calls DESC
                    LIMIT 100
                """

                cur.execute(sql_hours, params_hrs)
                for row in cur.fetchall():
                    anomalies.append({
                        "anomaly_type": "unusual_hours",
                        "actor_principal": row["actor_principal"],
                        "service": row["service"],
                        "off_hours_calls": row["off_hours_calls"],
                        "first_seen": row["first_seen"],
                        "last_seen": row["last_seen"],
                    })

                # --- High volume from single principal ---
                sql_volume = """
                    SELECT
                        actor_principal,
                        service,
                        COUNT(*) AS total_calls,
                        COUNT(DISTINCT operation) AS unique_operations,
                        MIN(event_time) AS first_seen,
                        MAX(event_time) AS last_seen
                    FROM log_events
                    WHERE tenant_id = %s
                      AND service = ANY(%s)
                      AND event_time >= %s
                """
                params_vol: list = [tenant_id, list(AI_CT_SERVICES), since]
                if account_id:
                    sql_volume += " AND actor_account_id = %s"
                    params_vol.append(account_id)
                sql_volume += """
                    GROUP BY actor_principal, service
                    HAVING COUNT(*) >= 1000
                    ORDER BY total_calls DESC
                    LIMIT 100
                """

                cur.execute(sql_volume, params_vol)
                for row in cur.fetchall():
                    anomalies.append({
                        "anomaly_type": "high_volume",
                        "actor_principal": row["actor_principal"],
                        "service": row["service"],
                        "total_calls": row["total_calls"],
                        "unique_operations": row["unique_operations"],
                        "first_seen": row["first_seen"],
                        "last_seen": row["last_seen"],
                    })

                logger.info(f"CIEM: detected {len(anomalies)} AI anomaly patterns")
                return anomalies
        except Exception as e:
            logger.warning(f"Failed to detect AI anomalies: {e}")
            return []

    def close(self):
        """Close the database connection."""
        if self.conn and not self.conn.closed:
            self.conn.close()
