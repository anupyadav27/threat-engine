"""Integration tests — DB schema validation for the attack path engine (AP-P0-01 / AP-P2-01).

Verifies that migration SQL has been applied correctly and all tables, columns,
constraints, and indexes exist as specified in the architecture document.

Architecture reference:
    Section 7.1 — resource_security_posture (threat_engine_inventory DB)
    Section 7.2 — attack_paths (threat_engine_attack_path DB)
    Section 7.3 — attack_path_nodes (threat_engine_attack_path DB)
    Section 7.4 — attack_path_history (threat_engine_attack_path DB)
    Section 7.5 — crown_jewel_overrides (threat_engine_attack_path DB)

Prerequisites:
    - RDS accessible via port-forward or local test DB seeded from migration SQL
    - Environment variables: INVENTORY_DB_HOST, INVENTORY_DB_NAME, ATTACK_PATH_DB_HOST,
      ATTACK_PATH_DB_NAME (and corresponding _USER / _PASSWORD for each)
    - These tests are skipped automatically if DB env vars are not set

Run:
    pytest tests/integration/test_attack_path_engine/test_db_schema.py -v --timeout=60
"""

from __future__ import annotations

import os
import pytest
from typing import Set


# ── Skip guard — skip entire module if DB not configured ─────────────────────

def _has_db_config(prefix: str) -> bool:
    return bool(os.environ.get(f"{prefix}_DB_HOST"))


INVENTORY_DB_AVAILABLE   = _has_db_config("INVENTORY")
ATTACK_PATH_DB_AVAILABLE = _has_db_config("ATTACK_PATH")

pytestmark_inventory = pytest.mark.skipif(
    not INVENTORY_DB_AVAILABLE,
    reason="INVENTORY_DB_HOST not set — integration test skipped",
)

pytestmark_attack_path = pytest.mark.skipif(
    not ATTACK_PATH_DB_AVAILABLE,
    reason="ATTACK_PATH_DB_HOST not set — integration test skipped",
)


# ── DB connection fixtures ────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def inventory_conn():
    """psycopg2 connection to threat_engine_inventory DB."""
    try:
        import psycopg2
        import psycopg2.extras
    except ImportError:
        pytest.skip("psycopg2 not installed")

    conn = psycopg2.connect(
        host=os.environ.get("INVENTORY_DB_HOST", "localhost"),
        port=int(os.environ.get("INVENTORY_DB_PORT", "5432")),
        dbname=os.environ.get("INVENTORY_DB_NAME", "threat_engine_inventory"),
        user=os.environ.get("INVENTORY_DB_USER", "postgres"),
        password=os.environ.get("INVENTORY_DB_PASSWORD", ""),
        connect_timeout=10,
    )
    yield conn
    conn.close()


@pytest.fixture(scope="module")
def attack_path_conn():
    """psycopg2 connection to threat_engine_attack_path DB."""
    try:
        import psycopg2
        import psycopg2.extras
    except ImportError:
        pytest.skip("psycopg2 not installed")

    conn = psycopg2.connect(
        host=os.environ.get("ATTACK_PATH_DB_HOST", "localhost"),
        port=int(os.environ.get("ATTACK_PATH_DB_PORT", "5432")),
        dbname=os.environ.get("ATTACK_PATH_DB_NAME", "threat_engine_attack_path"),
        user=os.environ.get("ATTACK_PATH_DB_USER", "postgres"),
        password=os.environ.get("ATTACK_PATH_DB_PASSWORD", ""),
        connect_timeout=10,
    )
    yield conn
    conn.close()


# ── Helper: column introspection ─────────────────────────────────────────────

def _get_columns(conn, table_name: str) -> Set[str]:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT column_name FROM information_schema.columns
            WHERE table_schema = 'public' AND table_name = %s
            """,
            (table_name,),
        )
        return {row[0] for row in cur.fetchall()}


def _get_indexes(conn, table_name: str) -> Set[str]:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT indexname FROM pg_indexes
            WHERE schemaname = 'public' AND tablename = %s
            """,
            (table_name,),
        )
        return {row[0] for row in cur.fetchall()}


def _get_unique_constraints(conn, table_name: str) -> list[frozenset]:
    """Return list of frozensets, each representing columns in a UNIQUE constraint."""
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT array_agg(kcu.column_name::text ORDER BY kcu.ordinal_position)
            FROM information_schema.table_constraints tc
            JOIN information_schema.key_column_usage kcu
              ON tc.constraint_name = kcu.constraint_name
              AND tc.table_schema = kcu.table_schema
            WHERE tc.table_schema = 'public'
              AND tc.table_name = %s
              AND tc.constraint_type = 'UNIQUE'
            GROUP BY tc.constraint_name
            """,
            (table_name,),
        )
        return [frozenset(row[0]) for row in cur.fetchall() if row[0]]


def _table_exists(conn, table_name: str) -> bool:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT EXISTS (
                SELECT 1 FROM information_schema.tables
                WHERE table_schema = 'public' AND table_name = %s
            )
            """,
            (table_name,),
        )
        return cur.fetchone()[0]


# ── Tests: resource_security_posture (inventory DB) ──────────────────────────

@pytest.mark.skipif(not INVENTORY_DB_AVAILABLE, reason="Inventory DB not configured")
class TestResourceSecurityPostureSchema:
    def test_table_exists(self, inventory_conn):
        assert _table_exists(inventory_conn, "resource_security_posture"), \
            "resource_security_posture table must exist in threat_engine_inventory"

    def test_standard_columns_present(self, inventory_conn):
        cols = _get_columns(inventory_conn, "resource_security_posture")
        required = {
            "posture_id", "resource_uid", "scan_run_id", "tenant_id",
            "account_id", "provider", "resource_type",
        }
        missing = required - cols
        assert not missing, f"Standard columns missing: {missing}"

    def test_network_dimension_columns_present(self, inventory_conn):
        cols = _get_columns(inventory_conn, "resource_security_posture")
        required = {
            "is_internet_exposed", "is_onprem_reachable", "entry_point_type",
            "waf_protected", "network_detail",
        }
        missing = required - cols
        assert not missing, f"Network columns missing: {missing}"

    def test_iam_dimension_columns_present(self, inventory_conn):
        cols = _get_columns(inventory_conn, "resource_security_posture")
        required = {
            "attached_role_arn", "is_admin_role", "has_wildcard_policy",
            "has_permission_boundary", "mfa_required", "iam_reachable_count",
        }
        missing = required - cols
        assert not missing, f"IAM columns missing: {missing}"

    def test_cdr_dimension_columns_present(self, inventory_conn):
        cols = _get_columns(inventory_conn, "resource_security_posture")
        required = {
            "has_active_cdr_actor", "cdr_actor_last_seen",
            "cdr_actor_uid", "cdr_risk_score",
        }
        missing = required - cols
        assert not missing, f"CDR columns missing: {missing}"

    def test_attack_path_signal_columns_present(self, inventory_conn):
        cols = _get_columns(inventory_conn, "resource_security_posture")
        required = {
            "is_crown_jewel", "crown_jewel_type", "is_on_attack_path",
            "attack_path_count", "is_choke_point", "choke_point_path_count",
            "blast_radius_count", "crown_jewel_count",
        }
        missing = required - cols
        assert not missing, f"Attack path signal columns missing: {missing}"

    def test_scoring_helper_columns_present(self, inventory_conn):
        cols = _get_columns(inventory_conn, "resource_security_posture")
        required = {"max_epss", "critical_misconfig_count", "high_misconfig_count", "posture_score"}
        missing = required - cols
        assert not missing, f"Scoring helper columns missing: {missing}"

    def test_unique_constraint_on_resource_uid_scan_run_id_tenant_id(self, inventory_conn):
        constraints = _get_unique_constraints(inventory_conn, "resource_security_posture")
        target = frozenset(["resource_uid", "scan_run_id", "tenant_id"])
        assert target in constraints, \
            "UNIQUE constraint on (resource_uid, scan_run_id, tenant_id) must exist"

    def test_indexes_exist(self, inventory_conn):
        indexes = _get_indexes(inventory_conn, "resource_security_posture")
        # At minimum, check that tenant+scan composite index exists
        assert any("tenant" in idx.lower() and "scan" in idx.lower() for idx in indexes), \
            "Index on (tenant_id, scan_run_id) must exist"

    def test_jsonb_column_deserializes_to_dict(self, inventory_conn):
        """JSONB columns must deserialize to dict/list, not string."""
        with inventory_conn.cursor() as cur:
            # Insert a test row with a JSONB column
            cur.execute(
                """
                INSERT INTO resource_security_posture
                    (resource_uid, scan_run_id, tenant_id, network_detail)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (resource_uid, scan_run_id, tenant_id)
                DO UPDATE SET network_detail = EXCLUDED.network_detail
                RETURNING network_detail
                """,
                ("test-uid-schema", "00000000-0000-0000-0000-000000000001",
                 "test-tenant-schema", '{"vpc_id": "vpc-123"}'),
            )
            row = cur.fetchone()
            inventory_conn.rollback()  # do not persist test data

        assert row is not None
        network_detail = row[0]
        # psycopg2 with JSONB returns dict, not string
        assert isinstance(network_detail, dict), \
            f"JSONB column returned {type(network_detail).__name__}, expected dict"
        assert network_detail.get("vpc_id") == "vpc-123"

    def test_tenant_id_filter_isolation(self, inventory_conn):
        """Querying with a specific tenant_id must not return other tenants' rows."""
        with inventory_conn.cursor() as cur:
            cur.execute(
                """
                SELECT DISTINCT tenant_id FROM resource_security_posture
                WHERE tenant_id = %s
                LIMIT 10
                """,
                ("__nonexistent_tenant_isolation_test__",),
            )
            rows = cur.fetchall()
        assert len(rows) == 0, "Nonexistent tenant_id must return 0 rows"


# ── Tests: attack_paths (attack_path DB) ────────────────────────────────────

@pytest.mark.skipif(not ATTACK_PATH_DB_AVAILABLE, reason="Attack path DB not configured")
class TestAttackPathsTableSchema:
    def test_table_exists(self, attack_path_conn):
        assert _table_exists(attack_path_conn, "attack_paths"), \
            "attack_paths table must exist in threat_engine_attack_path"

    def test_required_columns_present(self, attack_path_conn):
        cols = _get_columns(attack_path_conn, "attack_paths")
        required = {
            "path_id", "scan_run_id", "tenant_id", "account_id", "provider",
            "entry_point_uid", "entry_point_type",
            "crown_jewel_uid", "crown_jewel_type",
            "chain_type", "depth",
            "node_uids", "node_types", "edge_types", "hop_categories",
            "path_score", "severity", "probability_score", "impact_score",
            "group_id", "group_size", "is_representative", "choke_node_uid", "absorbed_count",
            "max_epss", "misconfig_count", "threat_count", "has_active_cdr_actor",
            "data_classification",
            "first_seen_at", "last_seen_at", "status",
            "created_at", "updated_at",
        }
        missing = required - cols
        assert not missing, f"attack_paths missing columns: {missing}"

    def test_jsonb_columns_deserialize_to_list(self, attack_path_conn):
        """node_uids, node_types, hop_categories must deserialize to list not string."""
        with attack_path_conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO attack_paths (
                    path_id, scan_run_id, tenant_id, account_id, provider,
                    entry_point_uid, entry_point_type,
                    crown_jewel_uid, crown_jewel_type, chain_type,
                    depth, node_uids, node_types, edge_types, hop_categories,
                    path_score, severity
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb, %s, %s
                )
                ON CONFLICT (path_id) DO UPDATE SET updated_at = NOW()
                RETURNING node_uids, node_types
                """,
                (
                    "test-schema-path-id",
                    "00000000-0000-0000-0000-000000000099",
                    "test-tenant-schema",
                    "123456789012", "aws",
                    "entry-uid", "internet",
                    "crown-uid", "data", "internet_to_data",
                    3,
                    '["entry-uid", "mid-uid", "crown-uid"]',
                    '["ec2.instance", "iam.role", "s3.bucket"]',
                    '["ASSUMES", "CAN_ACCESS"]',
                    '["initial_access", "privilege_escalation"]',
                    87, "critical",
                ),
            )
            row = cur.fetchone()
            attack_path_conn.rollback()

        assert row is not None
        node_uids, node_types = row
        assert isinstance(node_uids, list), \
            f"node_uids JSONB returned {type(node_uids).__name__}, expected list"
        assert isinstance(node_types, list), \
            f"node_types JSONB returned {type(node_types).__name__}, expected list"
        assert len(node_uids) == 3
        assert "entry-uid" in node_uids

    def test_indexes_exist(self, attack_path_conn):
        indexes = _get_indexes(attack_path_conn, "attack_paths")
        assert any("tenant" in idx.lower() for idx in indexes), \
            "At least one index containing 'tenant' must exist on attack_paths"

    def test_tenant_id_filter_returns_only_own_rows(self, attack_path_conn):
        with attack_path_conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) FROM attack_paths WHERE tenant_id = %s",
                ("__nonexistent_tenant_filter_test__",),
            )
            count = cur.fetchone()[0]
        assert count == 0


# ── Tests: attack_path_nodes (attack_path DB) ────────────────────────────────

@pytest.mark.skipif(not ATTACK_PATH_DB_AVAILABLE, reason="Attack path DB not configured")
class TestAttackPathNodesTableSchema:
    def test_table_exists(self, attack_path_conn):
        assert _table_exists(attack_path_conn, "attack_path_nodes"), \
            "attack_path_nodes table must exist"

    def test_required_columns_present(self, attack_path_conn):
        cols = _get_columns(attack_path_conn, "attack_path_nodes")
        required = {
            "id", "path_id", "tenant_id", "hop_index", "node_uid", "node_name",
            "node_type", "edge_to_next", "edge_category",
            "traversal_reason", "policy_statement", "sg_rule",
            "misconfigs", "cves", "threat_detections",
            "cdr_actor_active", "cdr_actor_uid",
            "risk_score", "is_crown_jewel", "data_classification",
            "encrypted_by", "cert_expiry",
        }
        missing = required - cols
        assert not missing, f"attack_path_nodes missing columns: {missing}"

    def test_path_id_index_exists(self, attack_path_conn):
        indexes = _get_indexes(attack_path_conn, "attack_path_nodes")
        assert any("path" in idx.lower() for idx in indexes), \
            "Index on path_id must exist in attack_path_nodes"


# ── Tests: attack_path_history (attack_path DB) ──────────────────────────────

@pytest.mark.skipif(not ATTACK_PATH_DB_AVAILABLE, reason="Attack path DB not configured")
class TestAttackPathHistoryTableSchema:
    def test_table_exists(self, attack_path_conn):
        assert _table_exists(attack_path_conn, "attack_path_history"), \
            "attack_path_history table must exist"

    def test_required_columns_present(self, attack_path_conn):
        cols = _get_columns(attack_path_conn, "attack_path_history")
        required = {
            "id", "path_id", "tenant_id", "scan_run_id",
            "score", "severity", "node_uids", "node_count", "recorded_at",
        }
        missing = required - cols
        assert not missing, f"attack_path_history missing columns: {missing}"


# ── Tests: crown_jewel_overrides (attack_path DB) ────────────────────────────

@pytest.mark.skipif(not ATTACK_PATH_DB_AVAILABLE, reason="Attack path DB not configured")
class TestCrownJewelOverridesTableSchema:
    def test_table_exists(self, attack_path_conn):
        assert _table_exists(attack_path_conn, "crown_jewel_overrides"), \
            "crown_jewel_overrides table must exist"

    def test_required_columns_present(self, attack_path_conn):
        cols = _get_columns(attack_path_conn, "crown_jewel_overrides")
        required = {
            "id", "resource_uid", "tenant_id", "is_crown_jewel",
            "crown_jewel_type", "reason", "set_by",
            "created_at", "updated_at",
        }
        missing = required - cols
        assert not missing, f"crown_jewel_overrides missing columns: {missing}"

    def test_unique_constraint_on_resource_uid_tenant_id(self, attack_path_conn):
        constraints = _get_unique_constraints(attack_path_conn, "crown_jewel_overrides")
        target = frozenset(["resource_uid", "tenant_id"])
        assert target in constraints, \
            "UNIQUE constraint on (resource_uid, tenant_id) must exist in crown_jewel_overrides"
