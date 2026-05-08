"""CVELoader unit tests (GRAPH-S3-04).

Tests:
  1. Graceful degradation when VULN_DB_HOST is empty → returns {cve_nodes:0, has_cve_edges:0}
  2. psycopg2 connection failure → returns zeros, does not raise
  3. UNWIND batch splitting: 1201 rows → 3 batches (500, 500, 201)
  4. CVE nodes with null epss_score → coerced to 0.0 in Neo4j params
  5. CVE nodes with null resource_uid → edge_batch entry is skipped

Framework: pytest + unittest.mock (no live DB or Neo4j required).
"""

from __future__ import annotations

from typing import Any, List, Tuple
from unittest.mock import MagicMock, call, patch

import pytest


def _make_neo4j_session_mock() -> Tuple[MagicMock, MagicMock]:
    """Return (mock_driver, mock_session) with session.run returning zero counts."""
    mock_result = MagicMock()
    mock_result.single.return_value = {"merged": 0, "created": 0}
    mock_session = MagicMock()
    mock_session.run.return_value = mock_result
    mock_session.__enter__ = MagicMock(return_value=mock_session)
    mock_session.__exit__ = MagicMock(return_value=False)
    mock_driver = MagicMock()
    mock_driver.session.return_value = mock_session
    return mock_driver, mock_session


def _make_loader(host: str = "vuln-host") -> Any:
    """Return a CVELoader with a mock neo4j driver."""
    from engines.threat.threat_engine.graph.cve_loader import CVELoader

    mock_driver, _ = _make_neo4j_session_mock()
    return CVELoader(
        neo4j_driver=mock_driver,
        vuln_db_config={
            "host": host,
            "dbname": "vulnerability_db",
            "user": "u",
            "password": "p",
            "port": 5432,
        },
    )


# ---------------------------------------------------------------------------
# Test 1 — Empty VULN_DB_HOST → graceful degradation
# ---------------------------------------------------------------------------


class TestCVELoaderEmptyHost:
    """CVELoader must degrade gracefully when VULN_DB_HOST is not configured."""

    def test_empty_host_returns_zero_cve_nodes(self) -> None:
        """load() returns {cve_nodes: 0, has_cve_edges: 0} when host is empty."""
        loader = _make_loader(host="")
        result = loader.load(tenant_id="tenant-A", scan_run_id="scan-001")
        assert result == {"cve_nodes": 0, "has_cve_edges": 0}

    def test_empty_host_does_not_raise(self) -> None:
        """load() must not raise any exception when host is empty."""
        loader = _make_loader(host="")
        try:
            loader.load(tenant_id="tenant-A", scan_run_id="scan-001")
        except Exception as exc:
            pytest.fail(f"load() raised unexpectedly with empty host: {exc}")

    def test_empty_host_never_calls_psycopg2(self) -> None:
        """load() must not attempt any DB connection when host is empty."""
        loader = _make_loader(host="")
        with patch("psycopg2.connect") as mock_connect:
            loader.load(tenant_id="tenant-A", scan_run_id="scan-001")
            mock_connect.assert_not_called()


# ---------------------------------------------------------------------------
# Test 2 — Connection failure → returns zeros, never raises
# ---------------------------------------------------------------------------


class TestCVELoaderConnectionFailure:
    """CVELoader must handle psycopg2.OperationalError without propagating it."""

    def test_connection_failure_returns_zero_counts(self) -> None:
        """_query_vulnerabilities returns [] on OperationalError; load() returns zeros."""
        import psycopg2

        loader = _make_loader(host="unreachable-host")
        with patch.object(
            loader, "_connect", side_effect=psycopg2.OperationalError("connection refused")
        ):
            result = loader.load(tenant_id="tenant-A", scan_run_id="scan-001")

        assert result == {"cve_nodes": 0, "has_cve_edges": 0}

    def test_connection_failure_does_not_raise(self) -> None:
        """load() must not propagate psycopg2.OperationalError to the caller."""
        import psycopg2

        loader = _make_loader(host="unreachable-host")
        with patch.object(
            loader, "_connect", side_effect=psycopg2.OperationalError("timed out")
        ):
            try:
                loader.load(tenant_id="tenant-A", scan_run_id="scan-001")
            except psycopg2.OperationalError as exc:
                pytest.fail(f"load() let OperationalError escape: {exc}")

    def test_query_failure_returns_empty_list(self) -> None:
        """_query_vulnerabilities catches psycopg2.Error and returns []."""
        import psycopg2

        loader = _make_loader(host="db-host")
        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_cur.execute.side_effect = psycopg2.Error("query error")
        mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cur)
        mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)

        with patch.object(loader, "_connect", return_value=mock_conn):
            rows = loader._query_vulnerabilities("tenant-A", "scan-001")

        assert rows == []


# ---------------------------------------------------------------------------
# Test 3 — Batch splitting: 1201 rows → 3 batches (500, 500, 201)
# ---------------------------------------------------------------------------


class TestCVELoaderBatchSplitting:
    """UNWIND batches must be capped at 500 rows per batch."""

    def _build_fake_rows(self, count: int) -> List[Tuple]:
        """Return *count* fake vulnerability tuples (resource_uid, cve_id, sev, cvss, epss, kev)."""
        return [
            (f"arn:aws:ec2:::{i}", f"CVE-2024-{i:04d}", "high", 7.5, 0.1, False)
            for i in range(count)
        ]

    def test_1201_rows_produces_three_flush_calls(self) -> None:
        """1201 input rows must trigger exactly 3 _flush_batches calls (500+500+201)."""
        loader = _make_loader(host="db-host")
        rows = self._build_fake_rows(1201)

        flush_call_sizes: List[int] = []

        original_flush = loader._flush_batches

        def _capture_flush(cve_batch, edge_batch, tenant_id):
            flush_call_sizes.append(len(cve_batch))
            return 0, 0  # return (cve_nodes, has_cve_edges)

        with patch.object(loader, "_flush_batches", side_effect=_capture_flush):
            loader._write_to_neo4j(rows, "tenant-A")

        assert len(flush_call_sizes) == 3, (
            f"Expected 3 flush calls for 1201 rows, got {len(flush_call_sizes)}: {flush_call_sizes}"
        )
        assert flush_call_sizes[0] == 500
        assert flush_call_sizes[1] == 500
        assert flush_call_sizes[2] == 201

    def test_batch_sizes_never_exceed_500(self) -> None:
        """No single batch passed to _flush_batches may contain more than 500 entries."""
        loader = _make_loader(host="db-host")
        rows = self._build_fake_rows(1500)

        flush_call_sizes: List[int] = []

        def _capture_flush(cve_batch, edge_batch, tenant_id):
            flush_call_sizes.append(len(cve_batch))
            return 0, 0

        with patch.object(loader, "_flush_batches", side_effect=_capture_flush):
            loader._write_to_neo4j(rows, "tenant-A")

        for size in flush_call_sizes:
            assert size <= 500, f"Batch size {size} exceeds 500-row cap"

    def test_exact_500_rows_produces_one_flush(self) -> None:
        """Exactly 500 rows must result in exactly 1 flush call."""
        loader = _make_loader(host="db-host")
        rows = self._build_fake_rows(500)

        flush_call_sizes: List[int] = []

        def _capture_flush(cve_batch, edge_batch, tenant_id):
            flush_call_sizes.append(len(cve_batch))
            return 0, 0

        with patch.object(loader, "_flush_batches", side_effect=_capture_flush):
            loader._write_to_neo4j(rows, "tenant-A")

        assert len(flush_call_sizes) == 1
        assert flush_call_sizes[0] == 500


# ---------------------------------------------------------------------------
# Test 4 — Null epss_score → coerced to 0.0
# ---------------------------------------------------------------------------


class TestCVELoaderNullEpssScore:
    """CVELoader must coerce None epss_score to 0.0 before writing to Neo4j."""

    def test_null_epss_coerced_to_zero_in_cve_batch(self) -> None:
        """CVE rows with epss_score=None must have epss_score=0.0 in the Neo4j batch."""
        loader = _make_loader(host="db-host")

        # Row: (resource_uid, cve_id, severity, cvss_score, epss_score=None, in_kev)
        rows = [("arn:aws:ec2:::i-001", "CVE-2024-0001", "high", 7.5, None, False)]

        captured_cve_batches: List[List] = []

        def _capture_flush(cve_batch, edge_batch, tenant_id):
            captured_cve_batches.append(list(cve_batch))
            return 0, 0

        with patch.object(loader, "_flush_batches", side_effect=_capture_flush):
            loader._write_to_neo4j(rows, "tenant-A")

        assert len(captured_cve_batches) == 1
        cve_entry = captured_cve_batches[0][0]
        assert cve_entry["epss_score"] == 0.0, (
            f"Expected epss_score=0.0 for null input, got {cve_entry['epss_score']}"
        )
        assert isinstance(cve_entry["epss_score"], float)

    def test_null_cvss_coerced_to_zero(self) -> None:
        """CVE rows with cvss_score=None must have cvss_score=0.0 in the Neo4j batch."""
        loader = _make_loader(host="db-host")
        rows = [("arn:aws:ec2:::i-001", "CVE-2024-0001", "high", None, 0.05, False)]

        captured_batches: List[List] = []

        def _capture_flush(cve_batch, edge_batch, tenant_id):
            captured_batches.append(list(cve_batch))
            return 0, 0

        with patch.object(loader, "_flush_batches", side_effect=_capture_flush):
            loader._write_to_neo4j(rows, "tenant-A")

        cve_entry = captured_batches[0][0]
        assert cve_entry["cvss_score"] == 0.0
        assert isinstance(cve_entry["cvss_score"], float)


# ---------------------------------------------------------------------------
# Test 5 — Null resource_uid → edge_batch entry skipped
# ---------------------------------------------------------------------------


class TestCVELoaderNullResourceUid:
    """Rows with null resource_uid must not produce HAS_CVE edge_batch entries."""

    def test_null_resource_uid_skips_edge_batch(self) -> None:
        """CVE rows with resource_uid=None must not create an edge_batch entry."""
        loader = _make_loader(host="db-host")

        # resource_uid is None — CVE node should still be created, but no edge entry
        rows = [(None, "CVE-2024-9999", "medium", 5.0, 0.02, False)]

        captured_edge_batches: List[List] = []

        def _capture_flush(cve_batch, edge_batch, tenant_id):
            captured_edge_batches.append(list(edge_batch))
            return len(cve_batch), 0

        with patch.object(loader, "_flush_batches", side_effect=_capture_flush):
            loader._write_to_neo4j(rows, "tenant-A")

        assert len(captured_edge_batches) == 1
        assert captured_edge_batches[0] == [], (
            "edge_batch must be empty when resource_uid is None"
        )

    def test_null_resource_uid_still_creates_cve_node(self) -> None:
        """Null resource_uid must not prevent the CVE node from being written."""
        loader = _make_loader(host="db-host")
        rows = [(None, "CVE-2024-9999", "medium", 5.0, 0.02, False)]

        captured_cve_batches: List[List] = []

        def _capture_flush(cve_batch, edge_batch, tenant_id):
            captured_cve_batches.append(list(cve_batch))
            return len(cve_batch), 0

        with patch.object(loader, "_flush_batches", side_effect=_capture_flush):
            loader._write_to_neo4j(rows, "tenant-A")

        assert len(captured_cve_batches) == 1
        assert len(captured_cve_batches[0]) == 1, (
            "CVE node entry must still be created even when resource_uid is None"
        )
        assert captured_cve_batches[0][0]["cve_id"] == "CVE-2024-9999"

    def test_mixed_rows_partial_edge_skip(self) -> None:
        """Only rows with non-null resource_uid produce edge_batch entries."""
        loader = _make_loader(host="db-host")
        rows = [
            (None, "CVE-2024-0001", "high", 8.0, 0.3, True),       # no edge
            ("arn:aws:ec2:::i-002", "CVE-2024-0002", "medium", 5.0, 0.1, False),  # edge
            ("", "CVE-2024-0003", "low", 3.0, 0.0, False),          # empty string → no edge
        ]

        captured_edge_batches: List[List] = []

        def _capture_flush(cve_batch, edge_batch, tenant_id):
            captured_edge_batches.append(list(edge_batch))
            return len(cve_batch), len(edge_batch)

        with patch.object(loader, "_flush_batches", side_effect=_capture_flush):
            loader._write_to_neo4j(rows, "tenant-A")

        # Only the row with a real resource_uid should produce an edge entry
        all_edges = [e for batch in captured_edge_batches for e in batch]
        assert len(all_edges) == 1, f"Expected 1 edge entry, got {len(all_edges)}: {all_edges}"
        assert all_edges[0]["resource_uid"] == "arn:aws:ec2:::i-002"
        assert all_edges[0]["cve_id"] == "CVE-2024-0002"
