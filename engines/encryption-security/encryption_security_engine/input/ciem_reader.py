"""CIEM reader for Encryption Security Engine — KMS CloudTrail events."""

import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

import psycopg2

from engine_common.base_reader import BaseDBReader
from engine_common.db_connections import get_ciem_conn
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)

KMS_USAGE_EVENTS = {
    "Encrypt", "Decrypt", "GenerateDataKey", "GenerateDataKeyWithoutPlaintext",
    "ReEncryptFrom", "ReEncryptTo",
}
KMS_LIFECYCLE_EVENTS = {
    "CreateKey", "DisableKey", "EnableKey", "ScheduleKeyDeletion",
    "CancelKeyDeletion", "DeleteImportedKeyMaterial",
    "ImportKeyMaterial", "UpdateKeyDescription",
}
KMS_POLICY_EVENTS = {
    "PutKeyPolicy", "CreateGrant", "RetireGrant", "RevokeGrant",
    "CreateAlias", "DeleteAlias", "UpdateAlias",
    "EnableKeyRotation", "DisableKeyRotation",
}
ENCRYPTION_CONFIG_EVENTS = {
    "PutBucketEncryption", "DeleteBucketEncryption",
    "ModifyDBInstance", "CreateDBInstance", "PutEncryptionConfiguration",
}
ALL_ENCRYPTION_EVENTS = KMS_USAGE_EVENTS | KMS_LIFECYCLE_EVENTS | KMS_POLICY_EVENTS | ENCRYPTION_CONFIG_EVENTS


class CIEMEncryptionReader(BaseDBReader):
    def __init__(self):
        super().__init__(get_ciem_conn)

    def load_kms_events(self, tenant_id: str, account_id: Optional[str] = None, days: int = 30) -> List[Dict[str, Any]]:
        self._ensure_conn()
        since = datetime.now(timezone.utc) - timedelta(days=days)
        sql = """
            SELECT event_id, event_name, event_source, event_time,
                   user_identity, source_ip_address,
                   request_parameters, response_elements,
                   resource_arn, resource_type, account_id, region, error_code
            FROM normalized_events
            WHERE tenant_id = %s AND event_source = 'kms.amazonaws.com' AND event_time >= %s
        """
        params: list = [tenant_id, since]
        if account_id:
            sql += " AND account_id = %s"
            params.append(account_id)
        sql += " ORDER BY event_time DESC LIMIT 5000"
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(sql, params)
                rows = cur.fetchall()
                logger.info("CIEM: loaded %d KMS events (last %d days)", len(rows), days)
                return [dict(r) for r in rows]
        except psycopg2.errors.UndefinedTable:
            logger.info("CIEM normalized_events not found — trying raw_events")
            if self.conn and not self.conn.closed:
                self.conn.rollback()
            return self._load_from_raw_events(tenant_id, account_id, since)
        except Exception as e:
            logger.warning("Failed to load CIEM KMS events: %s", e)
            if self.conn and not self.conn.closed:
                self.conn.rollback()
            return []

    def load_encryption_config_changes(self, tenant_id: str, account_id: Optional[str] = None, days: int = 30) -> List[Dict[str, Any]]:
        self._ensure_conn()
        since = datetime.now(timezone.utc) - timedelta(days=days)
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT event_id, event_name, event_source, event_time,
                           user_identity, request_parameters, response_elements,
                           resource_arn, account_id, region, error_code
                    FROM normalized_events
                    WHERE tenant_id = %s AND event_name = ANY(%s) AND event_time >= %s
                    ORDER BY event_time DESC LIMIT 1000
                """, (tenant_id, list(ENCRYPTION_CONFIG_EVENTS), since))
                rows = cur.fetchall()
                logger.info("CIEM: loaded %d encryption config change events", len(rows))
                return [dict(r) for r in rows]
        except Exception as e:
            logger.warning("Failed to load encryption config changes: %s", e)
            if self.conn and not self.conn.closed:
                self.conn.rollback()
            return []

    def load_key_usage_patterns(self, tenant_id: str, account_id: Optional[str] = None, days: int = 30) -> Dict[str, Dict[str, Any]]:
        self._ensure_conn()
        since = datetime.now(timezone.utc) - timedelta(days=days)
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT resource_arn, event_name,
                           COUNT(*) AS event_count,
                           COUNT(DISTINCT COALESCE(user_identity->>'arn', user_identity->>'principalId')) AS unique_callers,
                           MAX(event_time) AS last_used
                    FROM normalized_events
                    WHERE tenant_id = %s AND event_source = 'kms.amazonaws.com'
                      AND event_name = ANY(%s) AND event_time >= %s AND resource_arn IS NOT NULL
                    GROUP BY resource_arn, event_name ORDER BY event_count DESC
                """, (tenant_id, list(KMS_USAGE_EVENTS), since))
                rows = cur.fetchall()
                patterns: Dict[str, Dict[str, Any]] = {}
                for r in rows:
                    arn = r["resource_arn"]
                    if arn not in patterns:
                        patterns[arn] = {"total_ops": 0, "unique_callers": 0, "last_used": None, "ops_by_type": {}}
                    p = patterns[arn]
                    p["total_ops"] += r["event_count"]
                    p["unique_callers"] = max(p["unique_callers"], r["unique_callers"])
                    if r["last_used"] and (p["last_used"] is None or r["last_used"] > p["last_used"]):
                        p["last_used"] = r["last_used"]
                    p["ops_by_type"][r["event_name"]] = r["event_count"]
                logger.info("CIEM: usage patterns for %d keys", len(patterns))
                return patterns
        except Exception as e:
            logger.warning("Failed to load key usage patterns: %s", e)
            if self.conn and not self.conn.closed:
                self.conn.rollback()
            return {}

    def _load_from_raw_events(self, tenant_id: str, account_id: Optional[str], since: datetime) -> List[Dict[str, Any]]:
        self._ensure_conn()
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                sql = """
                    SELECT event_data FROM raw_events
                    WHERE tenant_id = %s
                      AND event_data->>'eventSource' = 'kms.amazonaws.com'
                      AND (event_data->>'eventTime')::timestamptz >= %s
                """
                params: list = [tenant_id, since]
                if account_id:
                    sql += " AND event_data->>'recipientAccountId' = %s"
                    params.append(account_id)
                sql += " ORDER BY (event_data->>'eventTime')::timestamptz DESC LIMIT 5000"
                cur.execute(sql, params)
                rows = cur.fetchall()
                events = []
                for r in rows:
                    ed = r.get("event_data") or {}
                    if isinstance(ed, dict):
                        events.append({
                            "event_name": ed.get("eventName"),
                            "event_source": ed.get("eventSource"),
                            "event_time": ed.get("eventTime"),
                            "user_identity": ed.get("userIdentity", {}),
                            "request_parameters": ed.get("requestParameters", {}),
                            "response_elements": ed.get("responseElements", {}),
                            "resource_arn": _extract_resource_arn(ed),
                            "account_id": ed.get("recipientAccountId"),
                            "region": ed.get("awsRegion"),
                            "error_code": ed.get("errorCode"),
                        })
                logger.info("CIEM raw: loaded %d KMS events", len(events))
                return events
        except Exception as e:
            logger.warning("Failed to load from raw_events: %s", e)
            if self.conn and not self.conn.closed:
                self.conn.rollback()
            return []


def _extract_resource_arn(event_data: dict) -> Optional[str]:
    for r in event_data.get("resources", []):
        if isinstance(r, dict) and r.get("type") == "AWS::KMS::Key":
            return r.get("ARN")
    req = event_data.get("requestParameters", {})
    if isinstance(req, dict):
        return req.get("keyId")
    return None
