"""
IAM Discovery Data Reader

Reads IAM-related discovery findings from threat_engine_discoveries database.
Groups results by discovery_id for downstream parsing by policy_parser and trust_analyzer.

=== DATABASE & TABLE MAP ===
Database: threat_engine_discoveries
Env: DISCOVERIES_DB_HOST / DISCOVERIES_DB_PORT / DISCOVERIES_DB_NAME / DISCOVERIES_DB_USER / DISCOVERIES_DB_PASSWORD

Tables READ:
  - discovery_findings : load_iam_resources() — SELECT ... WHERE service='iam' AND scan_run_id=%s
Tables WRITTEN: None (read-only)
===
"""

import os
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


def _get_discoveries_db_connection():
    """Get Discoveries DB connection using individual parameters."""
    return psycopg2.connect(
        host=os.getenv("DISCOVERIES_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("DISCOVERIES_DB_PORT", os.getenv("DB_PORT", "5432"))),
        database=os.getenv("DISCOVERIES_DB_NAME", "threat_engine_discoveries"),
        user=os.getenv("DISCOVERIES_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("DISCOVERIES_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
    )


class IAMDiscoveryReader:
    """
    Reads IAM discovery data from threat_engine_discoveries.discovery_findings.

    Groups results by discovery_id so downstream parsers can access specific
    API call results (e.g., list_roles, get_account_authorization_details).
    """

    def __init__(self):
        self._conn = None

    def _get_conn(self):
        if self._conn is not None and not self._conn.closed:
            if self._conn.info.transaction_status == psycopg2.extensions.TRANSACTION_STATUS_INERROR:
                self._conn.rollback()
            return self._conn
        if not PSYCOPG_AVAILABLE:
            raise RuntimeError("psycopg2 required for IAMDiscoveryReader")
        self._conn = _get_discoveries_db_connection()
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
        Load all IAM discovery findings grouped by discovery_id.

        Args:
            scan_run_id: Discovery scan identifier
            tenant_id: Tenant identifier
            account_id: Optional account filter

        Returns:
            Dict mapping discovery_id (e.g. 'aws.iam.list_roles') to list of
            record dicts with keys: resource_uid, resource_type, emitted_fields,
            raw_response, account_id, region, discovery_id.
        """
        conn = self._get_conn()
        query = """
            SELECT discovery_id, resource_uid, resource_type,
                   emitted_fields, raw_response,
                   account_id, region
            FROM discovery_findings
            WHERE scan_run_id = %s
              AND tenant_id = %s
              AND service = 'iam'
        """
        params: list = [scan_run_id, tenant_id]

        if account_id:
            query += " AND account_id = %s"
            params.append(account_id)

        query += " ORDER BY discovery_id, resource_uid"

        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(query, params)
                rows = cur.fetchall()

            # Group by discovery_id
            grouped: Dict[str, List[Dict]] = defaultdict(list)
            for row in rows:
                record = dict(row)
                did = record["discovery_id"]
                grouped[did].append(record)

            total = sum(len(v) for v in grouped.values())
            logger.info(
                f"Loaded {total} IAM discovery records across "
                f"{len(grouped)} discovery_ids for scan {scan_run_id}"
            )
            return dict(grouped)

        except Exception as e:
            logger.error(f"Error loading IAM discovery data: {e}")
            conn.rollback()
            return {}

    def get_roles(self, resources: Dict[str, List[Dict]]) -> List[Dict]:
        """Extract role records, preferring auth_details_roles over list_roles."""
        # Prefer get_account_authorization_details_roles (has inline policies)
        auth_roles = resources.get("aws.iam.get_account_authorization_details_roles", [])
        if auth_roles:
            return [self._extract_fields(r) for r in auth_roles]
        # Fallback to list_roles
        return [self._extract_fields(r) for r in resources.get("aws.iam.list_roles", [])]

    def get_users(self, resources: Dict[str, List[Dict]]) -> List[Dict]:
        """Extract user records, preferring auth_details over list_users."""
        auth_users = resources.get("aws.iam.get_account_authorization_details", [])
        if auth_users:
            return [self._extract_fields(r) for r in auth_users]
        return [self._extract_fields(r) for r in resources.get("aws.iam.list_users", [])]

    def get_policies(self, resources: Dict[str, List[Dict]]) -> List[Dict]:
        """Extract managed policy records with policy documents."""
        # Prefer auth_details_policies (has PolicyVersionList with Documents)
        auth_policies = resources.get("aws.iam.get_account_authorization_details_policies", [])
        if auth_policies:
            return [self._extract_fields(r) for r in auth_policies]
        return [self._extract_fields(r) for r in resources.get("aws.iam.list_policies", [])]

    def get_groups(self, resources: Dict[str, List[Dict]]) -> List[Dict]:
        """Extract group records."""
        return [self._extract_fields(r) for r in resources.get("aws.iam.list_groups", [])]

    def get_access_keys(self, resources: Dict[str, List[Dict]]) -> List[Dict]:
        """Extract access key records."""
        return [self._extract_fields(r) for r in resources.get("aws.iam.list_access_keys", [])]

    def get_mfa_devices(self, resources: Dict[str, List[Dict]]) -> List[Dict]:
        """Extract MFA device records."""
        devices = resources.get("aws.iam.list_mfa_devices", [])
        devices += resources.get("aws.iam.list_virtual_mfa_devices", [])
        return [self._extract_fields(r) for r in devices]

    def get_instance_profiles(self, resources: Dict[str, List[Dict]]) -> List[Dict]:
        """Extract instance profile records."""
        return [self._extract_fields(r) for r in resources.get("aws.iam.list_instance_profiles", [])]

    @staticmethod
    def _extract_fields(record: Dict) -> Dict:
        """Merge emitted_fields and raw_response into a flat dict with metadata."""
        # psycopg2 auto-deserializes JSONB — never call json.loads()
        emitted = record.get("emitted_fields") or {}
        raw = record.get("raw_response") or {}
        merged = {**raw, **emitted}
        merged["_resource_uid"] = record.get("resource_uid", "")
        merged["_account_id"] = record.get("account_id", "")
        merged["_region"] = record.get("region", "global")
        merged["_discovery_id"] = record.get("discovery_id", "")
        return merged
