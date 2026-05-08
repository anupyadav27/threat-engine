"""CIEM reader for AI Security Engine — AI/ML CloudTrail invocation events."""

import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from engine_common.base_reader import BaseDBReader
from engine_common.db_connections import get_ciem_conn
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)

AI_CT_SERVICES = (
    "sagemaker", "bedrock", "comprehend", "rekognition", "textract",
    "translate", "transcribe", "polly", "lex", "kendra",
    "personalize", "forecast",
)

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


class AICIEMReader(BaseDBReader):
    def __init__(self):
        super().__init__(get_ciem_conn)

    def get_ai_invocation_patterns(
        self,
        tenant_id: str,
        account_id: Optional[str] = None,
        days: int = 30,
    ) -> List[Dict[str, Any]]:
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
                sql += " GROUP BY resource_uid, operation, service ORDER BY total_calls DESC LIMIT 5000"
                cur.execute(sql, params)
                rows = cur.fetchall()
                logger.info("CIEM: loaded %d AI invocation pattern rows (last %d days)", len(rows), days)
                return [dict(r) for r in rows]
        except Exception as e:
            logger.warning("Failed to load AI invocation patterns: %s", e)
            if self.conn and not self.conn.closed:
                self.conn.rollback()
            return []

    def get_shadow_ai_calls(
        self,
        tenant_id: str,
        account_id: Optional[str] = None,
        days: int = 30,
    ) -> List[Dict[str, Any]]:
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
                params: list = [tenant_id, list(AI_CT_SERVICES), list(AI_INVOKE_OPERATIONS), since]
                if account_id:
                    sql += " AND actor_account_id = %s"
                    params.append(account_id)
                sql += " GROUP BY actor_principal, actor_principal_type, operation, service, resource_uid ORDER BY call_count DESC LIMIT 1000"
                cur.execute(sql, params)
                rows = cur.fetchall()
                logger.info("CIEM: found %d shadow AI call patterns", len(rows))
                return [dict(r) for r in rows]
        except Exception as e:
            logger.warning("Failed to load shadow AI calls: %s", e)
            if self.conn and not self.conn.closed:
                self.conn.rollback()
            return []

    def get_ai_anomalies(
        self,
        tenant_id: str,
        account_id: Optional[str] = None,
        days: int = 7,
    ) -> List[Dict[str, Any]]:
        self._ensure_conn()
        since = datetime.now(timezone.utc) - timedelta(days=days)
        anomalies: List[Dict[str, Any]] = []
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                # High error rates
                sql_errors = """
                    SELECT
                        actor_principal, service,
                        COUNT(*) AS total_calls,
                        COUNT(*) FILTER (WHERE error_code IS NOT NULL AND error_code != '') AS error_count,
                        ROUND(
                            100.0 * COUNT(*) FILTER (WHERE error_code IS NOT NULL AND error_code != '')
                            / NULLIF(COUNT(*), 0), 2
                        ) AS error_rate_pct
                    FROM log_events
                    WHERE tenant_id = %s AND service = ANY(%s) AND event_time >= %s
                """
                params_err: list = [tenant_id, list(AI_CT_SERVICES), since]
                if account_id:
                    sql_errors += " AND actor_account_id = %s"
                    params_err.append(account_id)
                sql_errors += " GROUP BY actor_principal, service HAVING COUNT(*) >= 10 AND COUNT(*) FILTER (WHERE error_code IS NOT NULL AND error_code != '') > 0.3 * COUNT(*) ORDER BY error_rate_pct DESC LIMIT 100"
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

                # Unusual hours (outside 06:00-22:00 UTC)
                sql_hours = """
                    SELECT actor_principal, service,
                        COUNT(*) AS off_hours_calls,
                        MIN(event_time) AS first_seen, MAX(event_time) AS last_seen
                    FROM log_events
                    WHERE tenant_id = %s AND service = ANY(%s) AND event_time >= %s
                      AND (EXTRACT(HOUR FROM event_time) < 6 OR EXTRACT(HOUR FROM event_time) >= 22)
                """
                params_hrs: list = [tenant_id, list(AI_CT_SERVICES), since]
                if account_id:
                    sql_hours += " AND actor_account_id = %s"
                    params_hrs.append(account_id)
                sql_hours += " GROUP BY actor_principal, service HAVING COUNT(*) >= 20 ORDER BY off_hours_calls DESC LIMIT 100"
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

                # High volume from single principal
                sql_volume = """
                    SELECT actor_principal, service,
                        COUNT(*) AS total_calls,
                        COUNT(DISTINCT operation) AS unique_operations,
                        MIN(event_time) AS first_seen, MAX(event_time) AS last_seen
                    FROM log_events
                    WHERE tenant_id = %s AND service = ANY(%s) AND event_time >= %s
                """
                params_vol: list = [tenant_id, list(AI_CT_SERVICES), since]
                if account_id:
                    sql_volume += " AND actor_account_id = %s"
                    params_vol.append(account_id)
                sql_volume += " GROUP BY actor_principal, service HAVING COUNT(*) >= 1000 ORDER BY total_calls DESC LIMIT 100"
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

                logger.info("CIEM: detected %d AI anomaly patterns", len(anomalies))
                return anomalies
        except Exception as e:
            logger.warning("Failed to detect AI anomalies: %s", e)
            if self.conn and not self.conn.closed:
                self.conn.rollback()
            return []
