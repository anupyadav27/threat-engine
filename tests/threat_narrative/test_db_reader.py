"""Unit tests for db_reader.py.

Mocks psycopg2 to verify correct queries and fallback defaults.
"""

import sys
import types
from unittest.mock import MagicMock, patch, call

import pytest

# ---------------------------------------------------------------------------
# The db_reader imports psycopg2 at module level — we need to mock it before
# importing the module under test. Use a module-level fixture.
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def mock_psycopg2(monkeypatch):
    """Provide a minimal psycopg2 mock so db_reader can be imported without a real DB."""
    mock_module = MagicMock()
    mock_module.extras = MagicMock()
    mock_module.extras.RealDictCursor = MagicMock()
    mock_module.OperationalError = Exception

    monkeypatch.setitem(sys.modules, "psycopg2", mock_module)
    monkeypatch.setitem(sys.modules, "psycopg2.extras", mock_module.extras)
    yield mock_module


def _make_conn_mock(rows_by_query: dict | None = None):
    """Build a psycopg2 connection mock that returns preset rows per query fragment."""
    rows_by_query = rows_by_query or {}

    conn = MagicMock()
    cursor = MagicMock()
    conn.__enter__ = MagicMock(return_value=conn)
    conn.__exit__ = MagicMock(return_value=False)
    conn.cursor.return_value.__enter__ = MagicMock(return_value=cursor)
    conn.cursor.return_value.__exit__ = MagicMock(return_value=False)

    # cursor.fetchone returns the first matching preset row
    def _fetchone():
        last_query = cursor.execute.call_args[0][0]
        for fragment, row in rows_by_query.items():
            if fragment in last_query:
                return row
        return None

    cursor.fetchone.side_effect = _fetchone
    cursor.fetchall.return_value = []
    return conn, cursor


class TestListDetectionIds:
    def test_returns_ids(self, mock_psycopg2):
        conn = MagicMock()
        cur = MagicMock()
        cur.fetchall.return_value = [("id1",), ("id2",)]
        conn.cursor.return_value.__enter__.return_value = cur
        conn.cursor.return_value.__exit__.return_value = False

        with patch(
            "threat_narrative_engine.db_reader._make_conn", return_value=conn
        ):
            from threat_narrative_engine import db_reader

            result = db_reader.list_detection_ids("scan-123")

        assert result == ["id1", "id2"]

    def test_empty_result(self, mock_psycopg2):
        conn = MagicMock()
        cur = MagicMock()
        cur.fetchall.return_value = []
        conn.cursor.return_value.__enter__.return_value = cur
        conn.cursor.return_value.__exit__.return_value = False

        with patch(
            "threat_narrative_engine.db_reader._make_conn", return_value=conn
        ):
            from threat_narrative_engine import db_reader

            result = db_reader.list_detection_ids("scan-empty")

        assert result == []


class TestReadDetectionContext:
    """Verify read_detection_context returns correct fields and safe fallbacks."""

    def test_returns_all_keys(self, mock_psycopg2):
        """All expected keys must be present in the returned context."""
        conn = MagicMock()
        cur = MagicMock()
        cur.fetchone.return_value = {
            "scenario_type": "data_exfil",
            "threat_category": "exfiltration",
            "attack_chain": [{"description": "Phishing"}],
            "mitre_techniques": [{"id": "T1078", "name": "Valid Accounts"}],
            "risk_score": 75,
            "resource_uid": "arn:aws:s3:::my-bucket",
            "resource_type": "S3 Bucket",
            "account_id": "123456789012",
            "region": "us-east-1",
        }
        cur.fetchall.return_value = []
        conn.cursor.return_value.__enter__.return_value = cur
        conn.cursor.return_value.__exit__.return_value = False

        with patch(
            "threat_narrative_engine.db_reader._make_conn", return_value=conn
        ):
            from threat_narrative_engine import db_reader

            ctx = db_reader.read_detection_context("scan-1", "det-1")

        required_keys = [
            "detection_id", "scan_run_id", "scenario_type", "resource_uid",
            "resource_type", "region", "attack_chain_description",
            "blast_radius_score", "affected_resource_count",
            "estimated_impact_display", "data_classification",
            "framework_list", "identity_description", "resource_name",
        ]
        for key in required_keys:
            assert key in ctx, f"Missing key: {key}"

    def test_fallback_when_threat_row_missing(self, mock_psycopg2):
        """Returns safe defaults when threat_detections has no row."""
        conn = MagicMock()
        cur = MagicMock()
        cur.fetchone.return_value = None
        cur.fetchall.return_value = []
        conn.cursor.return_value.__enter__.return_value = cur
        conn.cursor.return_value.__exit__.return_value = False

        with patch(
            "threat_narrative_engine.db_reader._make_conn", return_value=conn
        ):
            from threat_narrative_engine import db_reader

            ctx = db_reader.read_detection_context("scan-x", "det-x")

        assert ctx["resource_uid"] == ""
        assert ctx["blast_radius_score"] == 0
        assert ctx["data_classification"] == "unknown classification"
        assert ctx["framework_list"] == "none identified"
        assert ctx["identity_description"] == "no identity signal contributing"

    def test_attack_chain_description_built(self, mock_psycopg2):
        """attack_chain_description is built from attack_chain JSONB."""
        conn = MagicMock()
        cur = MagicMock()
        cur.fetchone.return_value = {
            "scenario_type": "lateral_movement",
            "threat_category": "movement",
            "attack_chain": [
                {"description": "Initial Compromise"},
                {"description": "Credential Dumping"},
            ],
            "mitre_techniques": [],
            "risk_score": 60,
            "resource_uid": "vm-001",
            "resource_type": "VM",
            "account_id": "acc-1",
            "region": "us-west-2",
        }
        cur.fetchall.return_value = []
        conn.cursor.return_value.__enter__.return_value = cur
        conn.cursor.return_value.__exit__.return_value = False

        with patch(
            "threat_narrative_engine.db_reader._make_conn", return_value=conn
        ):
            from threat_narrative_engine import db_reader

            ctx = db_reader.read_detection_context("scan-2", "det-2")

        assert "Initial Compromise" in ctx["attack_chain_description"]
        assert "Credential Dumping" in ctx["attack_chain_description"]

    def test_db_connection_error_propagates(self, mock_psycopg2):
        """OperationalError from threat DB must propagate (not swallowed)."""
        import psycopg2

        with patch(
            "threat_narrative_engine.db_reader._make_conn",
            side_effect=psycopg2.OperationalError("connection refused"),
        ):
            from threat_narrative_engine import db_reader

            with pytest.raises(psycopg2.OperationalError):
                db_reader.read_detection_context("scan-3", "det-3")
