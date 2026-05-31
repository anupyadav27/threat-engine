"""
Unit tests for path_explainer._edge_context_signals and the
write_path_nodes edge_context extraction pipeline.
"""

from __future__ import annotations

import sys
import os
import types
from typing import Any, Dict, Optional
from unittest.mock import MagicMock, patch

import pytest

# Make the engine importable without installing it
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "engines", "attack-path"))


class _FakePosture:
    """Minimal posture-like object for testing _edge_context_signals."""

    def __init__(self, **kwargs: Any) -> None:
        defaults: Dict[str, Any] = {
            "is_encrypted_at_rest": True,
            "data_classification": None,
            "crown_jewel_type": "",
            "critical_misconfig_count": 0,
            "high_misconfig_count": 0,
            "waf_protected": True,
            "mfa_required": False,
            "has_permission_boundary": False,
            "has_active_cdr_actor": False,
            "max_epss": None,
        }
        defaults.update(kwargs)
        for k, v in defaults.items():
            setattr(self, k, v)


# Import the function directly
from attack_path_engine.core.path_explainer import _edge_context_signals


class TestEdgeContextSignals:
    """Tests for _edge_context_signals per edge type."""

    def test_attached_to_unencrypted_returns_high(self) -> None:
        src = _FakePosture()
        tgt = _FakePosture(is_encrypted_at_rest=False)
        ctx = _edge_context_signals("attached_to", src, tgt)
        assert ctx["risk_level"] == "high"
        assert any("encrypted" in s.lower() for s in ctx["signals"])

    def test_attached_to_pii_data_returns_critical(self) -> None:
        src = _FakePosture()
        tgt = _FakePosture(data_classification="pii")
        ctx = _edge_context_signals("attached_to", src, tgt)
        assert ctx["risk_level"] == "critical"
        assert any("PII" in s for s in ctx["signals"])

    def test_attached_to_clean_storage_returns_empty(self) -> None:
        src = _FakePosture()
        tgt = _FakePosture(is_encrypted_at_rest=True, data_classification=None)
        ctx = _edge_context_signals("attached_to", src, tgt)
        assert ctx == {}

    def test_assumes_identity_crown_jewel_returns_critical(self) -> None:
        src = _FakePosture()
        tgt = _FakePosture(crown_jewel_type="identity")
        ctx = _edge_context_signals("assumes", src, tgt)
        assert ctx["risk_level"] == "critical"

    def test_grants_decrypt_always_critical(self) -> None:
        ctx = _edge_context_signals("grants_decrypt_to", None, None)
        assert ctx["risk_level"] == "critical"
        assert len(ctx["signals"]) >= 1

    def test_peered_with_external_always_high(self) -> None:
        ctx = _edge_context_signals("peered_with_external", None, None)
        assert ctx["risk_level"] == "high"

    def test_source_cdr_actor_escalates_to_critical(self) -> None:
        src = _FakePosture(has_active_cdr_actor=True)
        tgt = _FakePosture()
        # Use a neutral edge type that wouldn't otherwise be critical
        ctx = _edge_context_signals("connected_via", src, tgt)
        assert ctx["risk_level"] == "critical"
        assert any("CDR" in s for s in ctx["signals"])

    def test_source_high_epss_escalates_to_high(self) -> None:
        src = _FakePosture(max_epss=0.85)
        tgt = _FakePosture()
        ctx = _edge_context_signals("worker_node_of", src, tgt)
        assert ctx["risk_level"] == "high"
        assert any("EPSS" in s for s in ctx["signals"])

    def test_worker_node_zero_misconfigs_returns_empty(self) -> None:
        src = _FakePosture()
        tgt = _FakePosture(critical_misconfig_count=0)
        ctx = _edge_context_signals("worker_node_of", src, tgt)
        assert ctx == {}

    def test_grants_access_to_financial_data_critical(self) -> None:
        src = _FakePosture()
        tgt = _FakePosture(data_classification="financial", crown_jewel_type="data")
        ctx = _edge_context_signals("grants_access_to", src, tgt)
        assert ctx["risk_level"] == "critical"

    def test_none_posture_does_not_raise(self) -> None:
        ctx = _edge_context_signals("attached_to", None, None)
        assert ctx == {}

    def test_unknown_edge_type_with_cdr_actor_fires(self) -> None:
        src = _FakePosture(has_active_cdr_actor=True)
        ctx = _edge_context_signals("some_unknown_edge", src, _FakePosture())
        assert ctx["risk_level"] == "critical"

    def test_unknown_edge_clean_posture_empty(self) -> None:
        ctx = _edge_context_signals("routes_to", _FakePosture(), _FakePosture())
        assert ctx == {}


class TestWriterEdgeContextExtraction:
    """Verify write_path_nodes extracts edge_context from explanation.steps."""

    def _make_path(self, edge_ctx_for_hop0: Optional[Dict]) -> Any:
        """Build a minimal Path-like object."""
        p = MagicMock()
        p.path_id = "test-path-001"
        p.node_uids = ["uid-ec2", "uid-iam-role", "uid-s3"]
        p.node_types = ["ec2.instance", "iam.role", "s3.bucket"]
        p.edge_types = ["has_role", "grants_access_to"]
        p.hop_evidence = []
        p.explanation = {
            "title": "Test path",
            "steps": [
                {"step": 1, "uid": "uid-ec2", "edge_context": edge_ctx_for_hop0}
                if edge_ctx_for_hop0
                else {"step": 1, "uid": "uid-ec2"},
                {"step": 2, "uid": "uid-iam-role"},
                {"step": 3, "uid": "uid-s3"},
            ],
        }
        return p

    def test_edge_context_written_when_present(self) -> None:
        """When step has edge_context, it goes into the INSERT row."""
        import importlib
        import psycopg2.extras

        ctx = {"risk_level": "high", "signals": ["Attached storage is unencrypted"]}
        p = self._make_path(ctx)

        rows_captured = []

        def fake_execute_values(cur, sql, rows, page_size=500):
            rows_captured.extend(rows)

        with patch("psycopg2.extras.execute_values", side_effect=fake_execute_values):
            conn = MagicMock()
            conn.cursor.return_value.__enter__ = lambda s: conn.cursor.return_value
            conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
            conn.cursor.return_value.execute = MagicMock()

            from attack_path_engine.db.writer import write_path_nodes
            write_path_nodes(conn, [p], "test-tenant-002")

        # Row tuple has 17 elements; edge_context is the last (index 16)
        assert len(rows_captured) == 3
        hop0_row = rows_captured[0]
        # edge_context is the last element
        edge_ctx_val = hop0_row[-1]
        assert edge_ctx_val is not None
        assert hasattr(edge_ctx_val, "adapted")  # psycopg2.extras.Json wrapper

    def test_no_edge_context_writes_none(self) -> None:
        """When step has no edge_context, None is written (not an empty dict)."""
        p = self._make_path(None)

        rows_captured = []

        def fake_execute_values(cur, sql, rows, page_size=500):
            rows_captured.extend(rows)

        with patch("psycopg2.extras.execute_values", side_effect=fake_execute_values):
            conn = MagicMock()
            conn.cursor.return_value.__enter__ = lambda s: conn.cursor.return_value
            conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
            conn.cursor.return_value.execute = MagicMock()

            from attack_path_engine.db.writer import write_path_nodes
            write_path_nodes(conn, [p], "test-tenant-002")

        hop0_row = rows_captured[0]
        edge_ctx_val = hop0_row[-1]
        assert edge_ctx_val is None
