"""Unit tests for db_writer.py.

Mocks psycopg2 to verify the correct UPDATE statement is issued.
"""

import sys
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def mock_psycopg2(monkeypatch):
    """Provide a minimal psycopg2 mock."""
    mock_module = MagicMock()
    mock_module.OperationalError = Exception
    monkeypatch.setitem(sys.modules, "psycopg2", mock_module)
    yield mock_module


class TestWriteNarrative:
    def _make_conn_mock(self, rowcount: int = 1):
        conn = MagicMock()
        cur = MagicMock()
        cur.rowcount = rowcount
        conn.cursor.return_value.__enter__.return_value = cur
        conn.cursor.return_value.__exit__.return_value = False
        return conn, cur

    def test_executes_correct_update(self, mock_psycopg2):
        conn, cur = self._make_conn_mock()
        mock_psycopg2.connect.return_value = conn

        from threat_narrative_engine import db_writer

        db_writer.write_narrative(
            detection_id="det-abc",
            chain="If this executes, attackers could breach your database.",
            stakes="The organization faces significant regulatory exposure...",
            model="claude-sonnet-4-6",
        )

        # Verify execute was called with an UPDATE statement
        call_args = cur.execute.call_args
        sql = call_args[0][0]
        params = call_args[0][1]

        assert "UPDATE threat_detections" in sql
        assert "chain_of_consequence" in sql
        assert "stakes_narrative" in sql
        assert "narrative_generated_at" in sql
        assert "narrative_model" in sql
        assert params[0] == "If this executes, attackers could breach your database."
        assert params[2] == "claude-sonnet-4-6"
        assert params[3] == "det-abc"

    def test_commits_on_success(self, mock_psycopg2):
        conn, cur = self._make_conn_mock()
        mock_psycopg2.connect.return_value = conn

        from threat_narrative_engine import db_writer

        db_writer.write_narrative("det-1", "chain", "stakes", "model")

        conn.commit.assert_called_once()

    def test_logs_warning_when_not_found(self, mock_psycopg2, caplog):
        conn, cur = self._make_conn_mock(rowcount=0)
        mock_psycopg2.connect.return_value = conn

        import logging
        from threat_narrative_engine import db_writer

        with caplog.at_level(logging.WARNING, logger="threat_narrative"):
            db_writer.write_narrative("det-missing", "c", "s", "m")

        assert any("not found" in r.message for r in caplog.records)

    def test_closes_connection(self, mock_psycopg2):
        conn, _ = self._make_conn_mock()
        mock_psycopg2.connect.return_value = conn

        from threat_narrative_engine import db_writer

        db_writer.write_narrative("det-1", "c", "s", "m")

        conn.close.assert_called_once()


class TestCheckThreatDbConnection:
    def test_returns_true_when_reachable(self, mock_psycopg2):
        conn = MagicMock()
        mock_psycopg2.connect.return_value = conn

        from threat_narrative_engine import db_writer

        assert db_writer.check_threat_db_connection() is True
        conn.close.assert_called_once()

    def test_returns_false_when_unreachable(self, mock_psycopg2):
        mock_psycopg2.connect.side_effect = Exception("connection refused")

        from threat_narrative_engine import db_writer

        assert db_writer.check_threat_db_connection() is False
