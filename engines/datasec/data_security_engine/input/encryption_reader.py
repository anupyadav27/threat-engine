"""
DataSec — Encryption Engine Reader

Cross-references data store resources with the encryption engine's
key inventory and findings to determine detailed encryption posture:
  - KMS key type (aws_managed vs customer_managed)
  - Key rotation status
  - Key ARN
  - Encryption algorithm
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)


def _get_encryption_conn():
    return psycopg2.connect(
        host=os.getenv("ENCRYPTION_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("ENCRYPTION_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("ENCRYPTION_DB_NAME", "threat_engine_encryption"),
        user=os.getenv("ENCRYPTION_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("ENCRYPTION_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
        connect_timeout=10,
    )


class EncryptionCrossRefReader:
    """Read encryption status from the encryption engine's database."""

    def load_encryption_status(
        self,
        scan_run_id: str,
        tenant_id: str,
    ) -> Dict[str, Dict[str, Any]]:
        """
        Load encryption findings keyed by resource_uid.

        Returns:
            Dict keyed by resource_uid with:
            - encryption_status: encrypted_cmk | encrypted_managed | unencrypted
            - key_type: customer_managed | aws_managed | none
            - key_arn: KMS key ARN
            - rotation_compliant: bool
            - transit_enforced: bool
        """
        conn = _get_encryption_conn()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT resource_uid, resource_type,
                           encryption_status, key_type, algorithm,
                           rotation_compliant, transit_enforced,
                           finding_data
                    FROM encryption_findings
                    WHERE scan_run_id = %s AND tenant_id = %s
                """, [scan_run_id, tenant_id])
                rows = cur.fetchall()

            result: Dict[str, Dict[str, Any]] = {}
            for row in rows:
                uid = row.get("resource_uid", "")
                if not uid:
                    continue
                result[uid] = {
                    "encryption_status": row.get("encryption_status", "unknown"),
                    "key_type": row.get("key_type", "unknown"),
                    "algorithm": row.get("algorithm", ""),
                    "rotation_compliant": row.get("rotation_compliant"),
                    "transit_enforced": row.get("transit_enforced"),
                }

            logger.info("Loaded encryption status for %d resources", len(result))
            return result
        except Exception as e:
            logger.warning("Encryption engine cross-ref failed (non-fatal): %s", e)
            return {}
        finally:
            conn.close()

    def load_key_inventory(
        self,
        scan_run_id: str,
        tenant_id: str,
    ) -> Dict[str, Dict[str, Any]]:
        """
        Load KMS key inventory keyed by key_arn.

        Returns:
            Dict keyed by key_arn with key metadata.
        """
        conn = _get_encryption_conn()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT key_arn, key_id, key_alias, key_state,
                           key_manager, key_spec, rotation_enabled,
                           creation_date, enabled, cross_account_access,
                           dependent_resource_count
                    FROM encryption_key_inventory
                    WHERE scan_run_id = %s AND tenant_id = %s
                """, [scan_run_id, tenant_id])
                rows = cur.fetchall()

            return {row["key_arn"]: dict(row) for row in rows if row.get("key_arn")}
        except Exception as e:
            logger.warning("Encryption key inventory load failed (non-fatal): %s", e)
            return {}
        finally:
            conn.close()
