"""
CIEM DB Reader for Encryption Engine.

Reads CloudTrail KMS-related events from the CIEM database for:
  - Key usage patterns (Encrypt, Decrypt, GenerateDataKey)
  - Key lifecycle events (CreateKey, DisableKey, ScheduleKeyDeletion)
  - Policy change events (PutKeyPolicy, CreateGrant, RetireGrant)
  - Encryption configuration changes (S3 encryption, RDS encryption)
"""

import os
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone, timedelta

import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)

# KMS-related CloudTrail event names
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
    "ModifyDBInstance",  # encryption changes
    "CreateDBInstance",
    "PutEncryptionConfiguration",
}

ALL_ENCRYPTION_EVENTS = (
    KMS_USAGE_EVENTS | KMS_LIFECYCLE_EVENTS |
    KMS_POLICY_EVENTS | ENCRYPTION_CONFIG_EVENTS
)


def _get_ciem_conn():
    """Get connection to the CIEM database."""
    return psycopg2.connect(
        host=os.getenv("CIEM_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("CIEM_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("CIEM_DB_NAME", "threat_engine_ciem"),
        user=os.getenv("CIEM_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("CIEM_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
    )


class CIEMEncryptionReader:
    """Reads encryption-related CloudTrail events from CIEM DB."""

    def __init__(self):
        self.conn = None

    def _ensure_conn(self):
        if self.conn is None or self.conn.closed:
            self.conn = _get_ciem_conn()

    def load_kms_events(
        self,
        tenant_id: str,
        account_id: Optional[str] = None,
        days: int = 30,
    ) -> List[Dict[str, Any]]:
        """Load KMS-related CloudTrail events from the last N days.

        Returns events for key usage, lifecycle, and policy changes.
        """
        self._ensure_conn()
        since = datetime.now(timezone.utc) - timedelta(days=days)

        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Try normalized_events table first
                sql = """
                    SELECT
                        event_id, event_name, event_source, event_time,
                        user_identity, source_ip_address,
                        request_parameters, response_elements,
                        resource_arn, resource_type,
                        account_id, region, error_code
                    FROM normalized_events
                    WHERE tenant_id = %s
                      AND event_source = 'kms.amazonaws.com'
                      AND event_time >= %s
                """
                params = [tenant_id, since]

                if account_id:
                    sql += " AND account_id = %s"
                    params.append(account_id)

                sql += " ORDER BY event_time DESC LIMIT 5000"

                cur.execute(sql, params)
                rows = cur.fetchall()
                logger.info(f"CIEM: loaded {len(rows)} KMS events (last {days} days)")
                return [dict(r) for r in rows]

        except psycopg2.errors.UndefinedTable:
            logger.info("CIEM normalized_events table not found — trying raw_events")
            return self._load_from_raw_events(tenant_id, account_id, since)
        except Exception as e:
            logger.warning(f"Failed to load CIEM KMS events: {e}")
            return []

    def load_encryption_config_changes(
        self,
        tenant_id: str,
        account_id: Optional[str] = None,
        days: int = 30,
    ) -> List[Dict[str, Any]]:
        """Load encryption configuration change events (S3, RDS, etc.)."""
        self._ensure_conn()
        since = datetime.now(timezone.utc) - timedelta(days=days)

        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                event_names = list(ENCRYPTION_CONFIG_EVENTS)
                cur.execute("""
                    SELECT
                        event_id, event_name, event_source, event_time,
                        user_identity, request_parameters, response_elements,
                        resource_arn, account_id, region, error_code
                    FROM normalized_events
                    WHERE tenant_id = %s
                      AND event_name = ANY(%s)
                      AND event_time >= %s
                    ORDER BY event_time DESC
                    LIMIT 1000
                """, (tenant_id, event_names, since))
                rows = cur.fetchall()
                logger.info(f"CIEM: loaded {len(rows)} encryption config change events")
                return [dict(r) for r in rows]
        except Exception as e:
            logger.warning(f"Failed to load encryption config changes: {e}")
            return []

    def load_key_usage_patterns(
        self,
        tenant_id: str,
        account_id: Optional[str] = None,
        days: int = 30,
    ) -> Dict[str, Dict[str, Any]]:
        """Aggregate KMS key usage patterns.

        Returns: {key_arn: {total_ops, unique_callers, last_used, ops_by_type}}
        """
        self._ensure_conn()
        since = datetime.now(timezone.utc) - timedelta(days=days)

        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT
                        resource_arn,
                        event_name,
                        COUNT(*) as event_count,
                        COUNT(DISTINCT COALESCE(user_identity->>'arn', user_identity->>'principalId')) as unique_callers,
                        MAX(event_time) as last_used
                    FROM normalized_events
                    WHERE tenant_id = %s
                      AND event_source = 'kms.amazonaws.com'
                      AND event_name = ANY(%s)
                      AND event_time >= %s
                      AND resource_arn IS NOT NULL
                    GROUP BY resource_arn, event_name
                    ORDER BY event_count DESC
                """, (tenant_id, list(KMS_USAGE_EVENTS), since))
                rows = cur.fetchall()

                patterns = {}
                for r in rows:
                    arn = r["resource_arn"]
                    if arn not in patterns:
                        patterns[arn] = {
                            "total_ops": 0,
                            "unique_callers": 0,
                            "last_used": None,
                            "ops_by_type": {},
                        }
                    p = patterns[arn]
                    p["total_ops"] += r["event_count"]
                    p["unique_callers"] = max(p["unique_callers"], r["unique_callers"])
                    if r["last_used"]:
                        if p["last_used"] is None or r["last_used"] > p["last_used"]:
                            p["last_used"] = r["last_used"]
                    p["ops_by_type"][r["event_name"]] = r["event_count"]

                logger.info(f"CIEM: usage patterns for {len(patterns)} keys")
                return patterns
        except Exception as e:
            logger.warning(f"Failed to load key usage patterns: {e}")
            return {}

    def _load_from_raw_events(
        self,
        tenant_id: str,
        account_id: Optional[str],
        since: datetime,
    ) -> List[Dict[str, Any]]:
        """Fallback: load from raw_events table."""
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                sql = """
                    SELECT event_data
                    FROM raw_events
                    WHERE tenant_id = %s
                      AND event_data->>'eventSource' = 'kms.amazonaws.com'
                      AND (event_data->>'eventTime')::timestamptz >= %s
                """
                params = [tenant_id, since]
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
                logger.info(f"CIEM raw: loaded {len(events)} KMS events")
                return events
        except Exception as e:
            logger.warning(f"Failed to load from raw_events: {e}")
            return []

    def close(self):
        if self.conn and not self.conn.closed:
            self.conn.close()


def _extract_resource_arn(event_data: dict) -> Optional[str]:
    """Extract KMS key ARN from CloudTrail event."""
    # Try resources array
    resources = event_data.get("resources", [])
    for r in resources:
        if isinstance(r, dict) and r.get("type") == "AWS::KMS::Key":
            return r.get("ARN")
    # Try request parameters
    req = event_data.get("requestParameters", {})
    if isinstance(req, dict):
        return req.get("keyId")
    return None
