"""BFF contract tests — enrichment fields for attack paths (AP-P5-03).

Verifies that confidence_level, attack_name, attack_story, attack_technique_chain,
and confirmed_paths KPI flow correctly from engine → BFF → response shape.

Root cause context (AP-P5-03):
  - Migration 026 adds the columns to attack_paths table ✓
  - path_enricher.py writes them on each scan ✓
  - routes.py _fetch_attack_paths() SELECT was missing them ← BUG (now fixed)
  - BFF attack_paths.py passes through whatever engine returns (no transform)

All engine HTTP calls are mocked — no real network required.
"""
from __future__ import annotations

import asyncio
import json
import sys
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

_REPO = os.path.join(os.path.dirname(__file__), "..", "..")
_ENGINE_PATH = os.path.join(_REPO, "engines", "attack-path")
sys.path.insert(0, _REPO)
sys.path.insert(0, _ENGINE_PATH)


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _auth_ctx(role: str = "analyst", tenant_id: str = "t-001") -> str:
    return json.dumps({
        "user_id": f"{role}-1",
        "email": f"{role}@cspm.local",
        "role": role,
        "level": 4,
        "scope_level": "tenant",
        "permissions": ["attack_path:read"],
        "tenant_ids": [tenant_id],
        "account_ids": None,
        "engine_tenant_id": tenant_id,
        "org_ids": None,
    })


def _engine_path_row(
    path_id: str = "p001",
    confidence: str = "confirmed",
    attack_name: str | None = "EC2 Lateral Movement to PII Store",
    attack_story: str | None = "An internet-exposed EC2 assumed a privileged role and accessed S3.",
    technique_chain: list | None = None,
) -> dict:
    if technique_chain is None:
        technique_chain = [
            {"technique_id": "T1190", "tactic": "Initial Access"},
            {"technique_id": "T1078", "tactic": "Defense Evasion"},
            {"technique_id": "T1537", "tactic": "Exfiltration"},
        ]
    return {
        "path_id": path_id,
        "severity": "critical",
        "path_score": 88,
        "chain_type": "internet_to_data",
        "entry_point_type": "internet",
        "depth": 3,
        "crown_jewel_uid": "arn:aws:s3:::prod-pii",
        "crown_jewel_type": "data",
        "data_classification": "pii",
        "group_id": "grp-001",
        "group_size": 1,
        "is_representative": True,
        "absorbed_count": 0,
        "choke_node_uid": "arn:aws:iam::123:role/web-role",
        "has_active_cdr_actor": True,
        "max_epss": 0.94,
        "misconfig_count": 3,
        "threat_count": 2,
        "first_seen_at": "2026-05-01T00:00:00Z",
        "last_seen_at": "2026-05-16T00:00:00Z",
        "open_days": 15,
        "confidence_level": confidence,
        "attack_name": attack_name,
        "attack_story": attack_story,
        "attack_technique_chain": technique_chain,
    }


def _engine_response(paths: list | None = None, confirmed_paths: int = 5) -> dict:
    if paths is None:
        paths = [_engine_path_row()]
    return {
        "paths": paths,
        "total": len(paths),
        "page": 1,
        "page_size": 25,
        "kpis": {
            "critical": 12,
            "high": 38,
            "choke_points": 5,
            "longest_open_days": 47,
            "paths_with_active_cdr": 3,
            "confirmed_paths": confirmed_paths,
        },
    }


def _make_request(role: str = "analyst", tenant_id: str = "t-001") -> MagicMock:
    req = MagicMock()
    ctx = _auth_ctx(role, tenant_id)
    req.headers = {"X-Auth-Context": ctx}
    req.state = MagicMock()
    req.state.auth_header = ctx
    return req


def _mock_httpx_client(paths_body: dict, choke_body: dict | None = None):
    """Return a mock httpx.AsyncClient context manager yielding mock responses."""
    import httpx

    if choke_body is None:
        choke_body = {"choke_points": []}

    paths_resp = MagicMock(spec=httpx.Response)
    paths_resp.status_code = 200
    paths_resp.json.return_value = paths_body

    choke_resp = MagicMock(spec=httpx.Response)
    choke_resp.status_code = 200
    choke_resp.json.return_value = choke_body

    mock_client = AsyncMock()
    # asyncio.gather(paths_task, choke_task) — each task is a coroutine from client.get()
    # We make client.get return the responses in order
    mock_client.get = AsyncMock(side_effect=[paths_resp, choke_resp])

    mock_ctx_mgr = AsyncMock()
    mock_ctx_mgr.__aenter__ = AsyncMock(return_value=mock_client)
    mock_ctx_mgr.__aexit__ = AsyncMock(return_value=False)
    return mock_ctx_mgr


def _run(engine_body: dict, role: str = "analyst") -> dict:
    from shared.api_gateway.bff.attack_paths import view_attack_paths

    mock_client_ctx = _mock_httpx_client(engine_body)

    with patch("shared.api_gateway.bff.attack_paths.resolve_tenant_id", return_value="t-001"), \
         patch("shared.api_gateway.bff.attack_paths.httpx.AsyncClient", return_value=mock_client_ctx):
        return asyncio.run(view_attack_paths(request=_make_request(role)))


# ── BFF pass-through: enrichment fields ──────────────────────────────────────

class TestEnrichmentFieldPassThrough:
    """BFF returns engine fields unchanged — confidence, name, story, chain."""

    def test_confidence_level_present_in_each_path(self):
        paths = [
            _engine_path_row("p001", confidence="confirmed"),
            _engine_path_row("p002", confidence="likely"),
            _engine_path_row("p003", confidence="speculative", attack_name=None, attack_story=None, technique_chain=None),
        ]
        result = _run(_engine_response(paths=paths, confirmed_paths=2))
        confidences = [p["confidence_level"] for p in result["paths"]]
        assert "confirmed" in confidences
        assert "likely" in confidences
        assert "speculative" in confidences

    def test_attack_name_passes_through(self):
        paths = [_engine_path_row("p001", confidence="confirmed", attack_name="EC2 Lateral Movement")]
        result = _run(_engine_response(paths=paths))
        assert result["paths"][0]["attack_name"] == "EC2 Lateral Movement"

    def test_attack_story_passes_through(self):
        story = "An internet-exposed EC2 assumed a privileged IAM role and accessed S3 PII bucket."
        paths = [_engine_path_row("p001", attack_story=story)]
        result = _run(_engine_response(paths=paths))
        assert result["paths"][0]["attack_story"] == story

    def test_attack_technique_chain_passes_through_as_list(self):
        chain = [
            {"technique_id": "T1190", "tactic": "Initial Access"},
            {"technique_id": "T1537", "tactic": "Exfiltration"},
        ]
        paths = [_engine_path_row("p001", technique_chain=chain)]
        result = _run(_engine_response(paths=paths))
        returned_chain = result["paths"][0]["attack_technique_chain"]
        assert isinstance(returned_chain, list), f"Expected list, got {type(returned_chain)}"
        assert returned_chain[0]["technique_id"] == "T1190"

    def test_speculative_path_returns_null_story_and_null_name(self):
        paths = [_engine_path_row("p001", confidence="speculative", attack_name=None, attack_story=None, technique_chain=None)]
        result = _run(_engine_response(paths=paths))
        p = result["paths"][0]
        assert p["confidence_level"] == "speculative"
        assert p["attack_name"] is None
        assert p["attack_story"] is None


# ── BFF pass-through: KPI ─────────────────────────────────────────────────────

class TestConfirmedPathsKpi:
    """kpis.confirmed_paths must be present in BFF response."""

    def test_confirmed_paths_kpi_present(self):
        result = _run(_engine_response(confirmed_paths=7))
        assert "kpis" in result
        assert "confirmed_paths" in result["kpis"], (
            "kpis.confirmed_paths missing — engine routes.py KPI query fix not applied (AP-P5-03)"
        )

    def test_confirmed_paths_kpi_value_matches_engine(self):
        result = _run(_engine_response(confirmed_paths=3))
        assert result["kpis"]["confirmed_paths"] == 3

    def test_confirmed_paths_zero_is_not_null(self):
        result = _run(_engine_response(confirmed_paths=0))
        assert result["kpis"]["confirmed_paths"] == 0

    def test_existing_kpi_fields_not_dropped(self):
        result = _run(_engine_response(confirmed_paths=2))
        kpis = result["kpis"]
        for field in ["critical", "high", "choke_points", "longest_open_days", "paths_with_active_cdr"]:
            assert field in kpis, f"Existing KPI field '{field}' dropped"


# ── Engine SQL inspection ─────────────────────────────────────────────────────

class TestEngineSqlContainsEnrichmentColumns:
    """Engine routes.py SELECT must include all enrichment columns (pins AP-P5-03 fix)."""

    @pytest.fixture(autouse=True)
    def _load_routes(self):
        import inspect
        from attack_path_engine.api import routes
        self._source = inspect.getsource(routes._fetch_attack_paths)

    def test_list_sql_includes_confidence_level(self):
        assert "confidence_level" in self._source, \
            "BUG AP-P5-03: _fetch_attack_paths SELECT missing confidence_level"

    def test_list_sql_includes_attack_name(self):
        assert "attack_name" in self._source, \
            "BUG AP-P5-03: _fetch_attack_paths SELECT missing attack_name"

    def test_list_sql_includes_attack_story(self):
        assert "attack_story" in self._source, \
            "BUG AP-P5-03: _fetch_attack_paths SELECT missing attack_story"

    def test_list_sql_includes_attack_technique_chain(self):
        assert "attack_technique_chain" in self._source, \
            "BUG AP-P5-03: _fetch_attack_paths SELECT missing attack_technique_chain"

    def test_kpi_sql_includes_confirmed_paths(self):
        assert "confirmed_paths" in self._source, \
            "BUG AP-P5-03: KPI query missing confirmed_paths count"

    def test_no_json_loads_on_jsonb_field(self):
        """JSONB deserialized by psycopg2 automatically — json.loads() must never be called on it."""
        import inspect
        from attack_path_engine.api import routes
        full_source = inspect.getsource(routes)
        # Check that json.loads is not applied to attack_technique_chain
        # (CSPM constitution: JSONB in psycopg2 is auto-deserialized)
        if "json.loads" in full_source:
            assert "attack_technique_chain" not in full_source.split("json.loads")[1][:200], \
                "json.loads() called on JSONB field attack_technique_chain — constitution violation"
