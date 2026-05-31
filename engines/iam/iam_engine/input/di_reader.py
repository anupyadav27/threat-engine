"""
IAM DI Reader — reads from asset_inventory (threat_engine_di).

Drop-in replacement for IAMInventoryReader. Returns the same dict structure
from load_iam_resources() so all downstream IAM parsers work unchanged.

Active when DI_ENGINE_ENABLED=true on the engine pod.
"""

from __future__ import annotations

import logging
import os
from collections import defaultdict
from typing import Any, Dict, List, Optional

import psycopg2
import psycopg2.extensions
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)


def _get_di_conn() -> psycopg2.extensions.connection:
    return psycopg2.connect(
        host=os.getenv("DI_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("DI_DB_PORT", os.getenv("DB_PORT", "5432"))),
        database=os.getenv("DI_DB_NAME", "threat_engine_di"),
        user=os.getenv("DI_DB_USER", os.getenv("DB_USER", "postgres")),
        password=(
            os.getenv("DI_DB_PASSWORD")
            or os.getenv("DB_PASSWORD")
            or ""
        ),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
    )


class IAMDIReader:
    """Reads IAM data from asset_inventory in threat_engine_di.

    Same interface as IAMInventoryReader — load_iam_resources() returns
    Dict[discovery_id, List[record]] and all get_*() helpers work identically.
    """

    def __init__(self):
        self._conn = None

    def _get_conn(self):
        if self._conn is not None and not self._conn.closed:
            if self._conn.info.transaction_status == psycopg2.extensions.TRANSACTION_STATUS_INERROR:
                self._conn.rollback()
            return self._conn
        self._conn = _get_di_conn()
        return self._conn

    def close(self):
        if self._conn and not self._conn.closed:
            self._conn.close()
            self._conn = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def load_iam_resources(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: Optional[str] = None,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Load all IAM assets grouped by discovery_id.

        Queries asset_inventory WHERE service = 'iam'.
        Returns same structure as IAMInventoryReader.load_iam_resources().
        """
        conn = self._get_conn()
        query = """
            SELECT discovery_id, resource_uid, resource_type,
                   emitted_fields, raw_response,
                   account_id, region
            FROM asset_inventory
            WHERE scan_run_id = %s
              AND tenant_id = %s
              AND service = 'iam'
        """
        params: list = [scan_run_id, tenant_id]
        # Skip account_id filter when scan_run_id is present — scan_run_id is globally
        # unique. DI stores the cloud account number; callers pass the internal UUID.
        if account_id and not scan_run_id:
            query += " AND account_id = %s"
            params.append(account_id)
        query += " ORDER BY discovery_id, resource_uid"

        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(query, params)
                rows = cur.fetchall()

            grouped: Dict[str, List[Dict]] = defaultdict(list)
            for row in rows:
                record = dict(row)
                did = record.get("discovery_id") or ""
                if not did:
                    continue
                # emitted_fields is JSONB — already a dict, never call json.loads()
                grouped[did].append(record)

            total = sum(len(v) for v in grouped.values())
            logger.info(
                "IAMDIReader: %d records across %d discovery_ids for scan %s",
                total, len(grouped), scan_run_id,
            )
            return dict(grouped)

        except Exception as exc:
            logger.error("IAMDIReader.load_iam_resources failed: %s", exc)
            conn.rollback()
            return {}

    def get_roles(self, resources: Dict[str, List[Dict]]) -> List[Dict]:
        auth_roles = resources.get("aws.iam.get_account_authorization_details_roles", [])
        if auth_roles:
            return [self._extract_fields(r) for r in auth_roles]
        return [self._extract_fields(r) for r in resources.get("aws.iam.list_roles", [])]

    def get_users(self, resources: Dict[str, List[Dict]]) -> List[Dict]:
        auth_users = resources.get("aws.iam.get_account_authorization_details", [])
        if auth_users:
            return [self._extract_fields(r) for r in auth_users]
        return [self._extract_fields(r) for r in resources.get("aws.iam.list_users", [])]

    def get_policies(self, resources: Dict[str, List[Dict]]) -> List[Dict]:
        auth_policies = resources.get("aws.iam.get_account_authorization_details_policies", [])
        if auth_policies:
            return [self._extract_fields(r) for r in auth_policies]

        version_records = resources.get("aws.iam.get_policy_version", [])
        if version_records:
            by_arn: Dict[str, Dict] = {}
            for r in version_records:
                rec = self._extract_fields(r)
                arn = rec.get("PolicyArn") or rec.get("policy_arn") or ""
                if not arn:
                    continue
                doc = rec.get("PolicyDocument") or rec.get("Document")
                is_default = rec.get("IsDefaultVersion", True)
                if arn not in by_arn:
                    by_arn[arn] = {
                        "Arn": arn,
                        "PolicyName": rec.get("PolicyName", ""),
                        "AttachmentCount": 1,
                        "PolicyVersionList": [],
                    }
                by_arn[arn]["PolicyVersionList"].append({
                    "Document": doc,
                    "IsDefaultVersion": is_default,
                    "VersionId": rec.get("VersionId", "v1"),
                })
            if by_arn:
                return list(by_arn.values())

        return [self._extract_fields(r) for r in resources.get("aws.iam.list_policies", [])]

    def get_role_managed_policy_attachments(
        self, resources: Dict[str, List[Dict]]
    ) -> List[Dict]:
        records = resources.get("aws.iam.list_attached_role_policies", [])
        return [self._extract_fields(r) for r in records]

    def get_groups(self, resources: Dict[str, List[Dict]]) -> List[Dict]:
        return [self._extract_fields(r) for r in resources.get("aws.iam.list_groups", [])]

    def get_access_keys(self, resources: Dict[str, List[Dict]]) -> List[Dict]:
        return [self._extract_fields(r) for r in resources.get("aws.iam.list_access_keys", [])]

    def get_mfa_devices(self, resources: Dict[str, List[Dict]]) -> List[Dict]:
        devices = resources.get("aws.iam.list_mfa_devices", [])
        devices += resources.get("aws.iam.list_virtual_mfa_devices", [])
        return [self._extract_fields(r) for r in devices]

    def get_instance_profiles(self, resources: Dict[str, List[Dict]]) -> List[Dict]:
        return [self._extract_fields(r) for r in resources.get("aws.iam.list_instance_profiles", [])]

    @staticmethod
    def _extract_fields(record: Dict) -> Dict:
        emitted = record.get("emitted_fields") or {}
        raw = record.get("raw_response") or {}
        merged = {**raw, **emitted}
        merged["_resource_uid"] = record.get("resource_uid", "")
        merged["_account_id"] = record.get("account_id", "")
        merged["_region"] = record.get("region", "global")
        merged["_discovery_id"] = record.get("discovery_id", "")
        return merged
