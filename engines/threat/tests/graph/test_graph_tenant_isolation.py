"""Tenant isolation unit tests for the security graph subsystem (GRAPH-S3-04).

Verifies that:
1. Inventory queries are scoped strictly to tenant_id — no OR-bypass.
2. CVELoader writes tenant_id as a parameter in every Cypher call.
3. ExposureLoader scopes the Internet node MERGE by tenant_id.
4. No f-string Cypher interpolation exists in graph_builder.py or exposure modules.

Framework: pytest + unittest.mock (no live Neo4j or PostgreSQL required).
"""

from __future__ import annotations

import subprocess
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers to build minimal mocks
# ---------------------------------------------------------------------------


def _make_pg_mock(rows: list) -> MagicMock:
    """Return a mock psycopg2 connection whose cursor().fetchall() yields *rows*."""
    mock_conn = MagicMock()
    mock_cur = MagicMock()
    mock_cur.fetchall.return_value = rows
    mock_cur.description = [("col1",)]
    mock_conn.__enter__ = MagicMock(return_value=mock_conn)
    mock_conn.__exit__ = MagicMock(return_value=False)
    mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cur)
    mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
    return mock_conn, mock_cur


def _make_neo4j_session_mock() -> MagicMock:
    """Return a mock neo4j driver with a session() context manager."""
    mock_result = MagicMock()
    mock_result.single.return_value = {"merged": 0, "created": 0}
    mock_session = MagicMock()
    mock_session.run.return_value = mock_result
    mock_session.__enter__ = MagicMock(return_value=mock_session)
    mock_session.__exit__ = MagicMock(return_value=False)
    mock_driver = MagicMock()
    mock_driver.session.return_value = mock_session
    return mock_driver, mock_session


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------


class TestGraphTenantIsolation:
    """Unit tests verifying strict tenant_id scoping in every graph layer."""

    # ── inventory query isolation ──────────────────────────────────────────

    def test_inventory_query_contains_tenant_id_param(self) -> None:
        """_load_inventory_findings must bind tenant_id and not contain OR bypass."""
        import os

        os.environ.setdefault("NEO4J_URI", "bolt://localhost:7687")

        from engines.threat.threat_engine.graph.graph_builder import SecurityGraphBuilder

        builder = SecurityGraphBuilder.__new__(SecurityGraphBuilder)
        builder._uri = "bolt://localhost:7687"
        builder._user = "neo4j"
        builder._password = "test"
        builder._driver = None
        builder.vuln_db_config = {"host": ""}
        builder.network_db_config = {"host": ""}
        builder._config_schema = {}

        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_cur.fetchall.return_value = []
        mock_cur.description = [("asset_id",), ("resource_uid",)]
        mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cur)
        mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)

        with patch.object(builder, "_pg_conn", return_value=mock_conn):
            builder._load_inventory_findings("tenant-A")

        execute_call = mock_cur.execute.call_args
        assert execute_call is not None, "_load_inventory_findings must call cursor.execute"
        sql = execute_call[0][0]
        params = execute_call[0][1]

        # Must filter by tenant_id in the WHERE clause
        assert "tenant_id" in sql, "SQL must include 'tenant_id' in the WHERE clause"
        # Must not allow OR account_id bypass
        assert "OR account_id" not in sql, "SQL must not bypass with 'OR account_id'"
        # The actual tenant value must be a bound parameter
        assert "tenant-A" in params or "tenant-A" in str(params), (
            "tenant-A must appear in the bound parameters"
        )

    def test_inventory_query_no_tenant_b_leak(self) -> None:
        """tenant-A query must not reference tenant-B in any form."""
        import os

        os.environ.setdefault("NEO4J_URI", "bolt://localhost:7687")

        from engines.threat.threat_engine.graph.graph_builder import SecurityGraphBuilder

        builder = SecurityGraphBuilder.__new__(SecurityGraphBuilder)
        builder._uri = "bolt://localhost:7687"
        builder._user = "neo4j"
        builder._password = "test"
        builder._driver = None
        builder.vuln_db_config = {"host": ""}
        builder.network_db_config = {"host": ""}
        builder._config_schema = {}

        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_cur.fetchall.return_value = []
        mock_cur.description = [("asset_id",)]
        mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cur)
        mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)

        with patch.object(builder, "_pg_conn", return_value=mock_conn):
            builder._load_inventory_findings("tenant-A")

        execute_call = mock_cur.execute.call_args
        params_str = str(execute_call[0][1])
        assert "tenant-B" not in params_str, (
            "tenant-B must not appear in parameters when loading for tenant-A"
        )

    # ── CVELoader tenant scoping ───────────────────────────────────────────

    def test_cve_loader_query_binds_tenant_id(self) -> None:
        """CVELoader._query_vulnerabilities must pass tenant_id as a bound parameter."""
        from engines.threat.threat_engine.graph.cve_loader import CVELoader

        mock_driver, _ = _make_neo4j_session_mock()
        loader = CVELoader(
            neo4j_driver=mock_driver,
            vuln_db_config={"host": "vuln-host", "dbname": "vdb", "user": "u", "password": "p"},
        )

        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_cur.fetchall.return_value = []
        mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cur)
        mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
        mock_conn.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.__exit__ = MagicMock(return_value=False)

        with patch.object(loader, "_connect", return_value=mock_conn):
            loader._query_vulnerabilities("tenant-A", "scan-001")

        execute_call = mock_cur.execute.call_args
        assert execute_call is not None
        sql = execute_call[0][0]
        params = execute_call[0][1]

        # tenant_id must appear in the SQL (as %s or named param)
        assert "tenant_id" in sql or "%s" in sql, (
            "CVELoader query must include tenant_id parameter"
        )
        assert "tenant-A" in str(params), (
            "tenant-A must be bound in CVELoader query params"
        )

    def test_cve_loader_flush_resource_match_includes_tenant_id(self) -> None:
        """CVELoader._flush_batches Resource MATCH must include tenant_id parameter."""
        from engines.threat.threat_engine.graph.cve_loader import CVELoader

        mock_driver, mock_session = _make_neo4j_session_mock()
        loader = CVELoader(
            neo4j_driver=mock_driver,
            vuln_db_config={"host": ""},
        )

        cve_batch = [
            {
                "cve_id": "CVE-2024-0001",
                "severity": "critical",
                "cvss_score": 9.8,
                "epss_score": 0.5,
                "in_kev": True,
                "tenant_id": "tenant-A",
            }
        ]
        edge_batch = [{"resource_uid": "arn:aws:s3:::my-bucket", "cve_id": "CVE-2024-0001"}]

        loader._flush_batches(cve_batch, edge_batch, "tenant-A")

        # Collect all Cypher calls made to session.run
        all_calls = mock_session.run.call_args_list
        assert len(all_calls) >= 1, "_flush_batches must call session.run at least once"

        # Find the HAS_CVE edge call — it must pass tenant_id as a keyword param
        edge_call = all_calls[-1]  # edge MERGE is the second call
        kwargs = edge_call[1] if edge_call[1] else {}
        positional_args = edge_call[0] if edge_call[0] else ()
        cypher = positional_args[0] if positional_args else ""

        # tenant_id must appear in the Cypher as a parameter placeholder ($tenant_id)
        assert "$tenant_id" in cypher, (
            "HAS_CVE edge Cypher must use $tenant_id parameter in Resource MATCH"
        )
        # And the actual tenant value must be passed as tenant_id kwarg
        assert kwargs.get("tenant_id") == "tenant-A", (
            "tenant-A must be passed as tenant_id kwarg to session.run for HAS_CVE edges"
        )

    # ── ExposureLoader tenant scoping ──────────────────────────────────────

    def test_exposure_loader_internet_node_merge_includes_tenant_id(self) -> None:
        """ExposureLoader._write_exposes_edges Internet MERGE must include tenant_id."""
        from engines.threat.threat_engine.graph.exposure_loader import ExposureLoader

        mock_driver, mock_session = _make_neo4j_session_mock()
        # Return a written count
        mock_session.run.return_value.single.return_value = {"written": 1}

        loader = ExposureLoader(
            neo4j_driver=mock_driver,
            network_db_config={"host": "net-host", "dbname": "ndb", "user": "u", "password": "p"},
        )

        validated_rows = [
            {
                "resource_uid": "sg-1234abcd",
                "rule_id": "aws.sg.001",
                "severity": "critical",
                "sg_id": "sg-1234abcd",
                "cidr": "0.0.0.0/0",
                "port": "22",
                "protocol": "tcp",
                "exposed_resource_uid": None,
                "layer": "L4_security_group",
            }
        ]

        loader._write_exposes_edges(validated_rows, "tenant-A")

        all_calls = mock_session.run.call_args_list
        assert len(all_calls) >= 1

        edge_call = all_calls[0]
        positional_args = edge_call[0] if edge_call[0] else ()
        kwargs = edge_call[1] if edge_call[1] else {}
        cypher = positional_args[0] if positional_args else ""

        # Internet MERGE must be scoped by tenant_id
        assert "$tenant_id" in cypher, (
            "ExposureLoader EXPOSES Cypher must use $tenant_id for Internet node MERGE"
        )
        assert kwargs.get("tenant_id") == "tenant-A", (
            "tenant-A must be passed as tenant_id kwarg to session.run for EXPOSES edges"
        )

    # ── f-string Cypher grep assertions ───────────────────────────────────

    def test_no_fstring_where_cypher_in_graph_builder(self) -> None:
        """graph_builder.py must contain zero f-string WHERE clauses in Cypher."""
        result = subprocess.run(
            [
                "grep",
                "-n",
                r'f".*WHERE.*{',
                "/Users/apple/Desktop/threat-engine/engines/threat/threat_engine/graph/graph_builder.py",
            ],
            capture_output=True,
            text=True,
        )
        assert result.stdout == "", (
            f"f-string Cypher WHERE clause found in graph_builder.py:\n{result.stdout}"
        )

    def test_no_fstring_contains_cypher_in_exposure_modules(self) -> None:
        """exposure/ directory must contain zero f-string CONTAINS Cypher clauses."""
        result = subprocess.run(
            [
                "grep",
                "-rn",
                r'f".*CONTAINS.*{',
                "/Users/apple/Desktop/threat-engine/engines/threat/threat_engine/graph/exposure/",
            ],
            capture_output=True,
            text=True,
        )
        assert result.stdout == "", (
            f"f-string Cypher CONTAINS clause found in exposure/:\n{result.stdout}"
        )

    def test_exposure_loader_no_fstring_cypher(self) -> None:
        """exposure_loader.py must contain zero f-string Cypher queries."""
        result = subprocess.run(
            [
                "grep",
                "-n",
                r"f['\"].*MATCH\|f['\"].*MERGE\|f['\"].*CREATE",
                "/Users/apple/Desktop/threat-engine/engines/threat/threat_engine/graph/exposure_loader.py",
            ],
            capture_output=True,
            text=True,
        )
        assert result.stdout == "", (
            f"f-string Cypher found in exposure_loader.py:\n{result.stdout}"
        )

    def test_cve_loader_no_fstring_cypher(self) -> None:
        """cve_loader.py must contain zero f-string Cypher queries."""
        result = subprocess.run(
            [
                "grep",
                "-n",
                r"f['\"].*MATCH\|f['\"].*MERGE\|f['\"].*CREATE",
                "/Users/apple/Desktop/threat-engine/engines/threat/threat_engine/graph/cve_loader.py",
            ],
            capture_output=True,
            text=True,
        )
        assert result.stdout == "", (
            f"f-string Cypher found in cve_loader.py:\n{result.stdout}"
        )
