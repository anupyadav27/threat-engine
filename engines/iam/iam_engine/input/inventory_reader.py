"""
IAM Inventory Data Reader

Reads IAM-related resources from threat_engine_inventory.inventory_findings.
Drop-in replacement for IAMDiscoveryReader — same interface, different data source.

=== DATABASE & TABLE MAP ===
Database: threat_engine_inventory
Env: INVENTORY_DB_HOST / INVENTORY_DB_PORT / INVENTORY_DB_NAME / INVENTORY_DB_USER / INVENTORY_DB_PASSWORD

Tables READ:
  - inventory_findings : load_iam_resources() — SELECT ... WHERE resource_type LIKE 'iam.%'
Tables WRITTEN: None (read-only)
===
"""

import os
import json
import logging
from typing import Dict, List, Any, Optional
from collections import defaultdict

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    PSYCOPG_AVAILABLE = True
except ImportError:
    PSYCOPG_AVAILABLE = False

logger = logging.getLogger(__name__)


def _get_inventory_db_connection():
    return psycopg2.connect(
        host=os.getenv("INVENTORY_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("INVENTORY_DB_PORT", os.getenv("DB_PORT", "5432"))),
        database=os.getenv("INVENTORY_DB_NAME", "threat_engine_inventory"),
        user=os.getenv("INVENTORY_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("INVENTORY_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
    )


class IAMInventoryReader:
    """
    Reads IAM data from inventory_findings.

    Same interface as IAMDiscoveryReader so the IAM engine can swap seamlessly.
    Extracts discovery_id and emitted_fields from the properties JSONB column.
    """

    def __init__(self):
        self._conn = None

    def _get_conn(self):
        if self._conn is not None and not self._conn.closed:
            if self._conn.info.transaction_status == psycopg2.extensions.TRANSACTION_STATUS_INERROR:
                self._conn.rollback()
            return self._conn
        if not PSYCOPG_AVAILABLE:
            raise RuntimeError("psycopg2 required for IAMInventoryReader")
        self._conn = _get_inventory_db_connection()
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
        """
        Load all IAM inventory findings grouped by discovery_id.

        Returns same structure as IAMDiscoveryReader.load_iam_resources().
        """
        conn = self._get_conn()
        query = """
            SELECT resource_uid, resource_type,
                   properties, configuration,
                   account_id, region,
                   properties->>'discovery_id' AS discovery_id
            FROM inventory_findings
            WHERE scan_run_id = %s
              AND tenant_id = %s
              AND (resource_type LIKE 'iam.%%'
                   OR properties->>'discovery_id' LIKE 'aws.iam.%%')
        """
        params: list = [scan_run_id, tenant_id]

        if account_id:
            query += " AND account_id = %s"
            params.append(account_id)

        query += " ORDER BY properties->>'discovery_id', resource_uid"

        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(query, params)
                rows = cur.fetchall()

            grouped: Dict[str, List[Dict]] = defaultdict(list)
            for row in rows:
                record = dict(row)

                # Extract discovery_id from properties
                props = record.get("properties") or {}
                if isinstance(props, str):
                    props = json.loads(props)

                did = props.get("discovery_id", record.get("discovery_id", ""))
                if not did:
                    continue

                # Build a record compatible with IAMDiscoveryReader output
                ef = props.get("emitted_fields", {})
                if isinstance(ef, str):
                    ef = json.loads(ef)

                config = record.get("configuration") or {}
                if isinstance(config, str):
                    config = json.loads(config)

                compatible = {
                    "discovery_id": did,
                    "resource_uid": record.get("resource_uid", ""),
                    "resource_type": record.get("resource_type", ""),
                    "emitted_fields": ef,
                    "raw_response": props.get("_raw_response", {}),
                    "account_id": record.get("account_id", ""),
                    "region": record.get("region", "global"),
                }
                grouped[did].append(compatible)

            total = sum(len(v) for v in grouped.values())
            logger.info(
                f"Loaded {total} IAM inventory records across "
                f"{len(grouped)} discovery_ids for scan {scan_run_id}"
            )
            return dict(grouped)

        except Exception as e:
            logger.error(f"Error loading IAM inventory data: {e}")
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
        return [self._extract_fields(r) for r in resources.get("aws.iam.list_policies", [])]

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
