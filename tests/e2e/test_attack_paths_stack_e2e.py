"""Integration + E2E tests — Attack Path UI stack (AP-P5-03 / AP-P4-05 / AP-P4-06 / SF-P2-01).

Covers the full data flow:
  attack_paths DB table → engine API → BFF → UI (Playwright in .spec.ts companion)

Three test layers in this file:
  1. TestEngineApiShape       — live engine HTTP (port-forward required)
  2. TestGatewayBffShape      — live gateway BFF (SESSION_COOKIE required)
  3. TestAttackPathDbIntegrity — live DB query (ATTACK_PATH_DB_HOST required)

All tests skip when required env vars are absent — safe to run in CI without live infra.

Run with a live stack:
  GATEWAY_URL=http://localhost:8000 \\
  SESSION_COOKIE="access_token=..." \\
  ATTACK_PATH_DB_HOST=<rds-host> \\
  TENANT_ID=my-tenant \\
  SCAN_RUN_ID=<uuid> \\
    pytest tests/e2e/test_attack_paths_stack_e2e.py -v -m e2e
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

import pytest

# ── Env vars ──────────────────────────────────────────────────────────────────

GATEWAY_URL        = os.environ.get("GATEWAY_URL", "http://localhost:8000")
SESSION_COOKIE     = os.environ.get("SESSION_COOKIE")
TENANT_ID          = os.environ.get("TENANT_ID", "my-tenant")
OTHER_TENANT_ID    = os.environ.get("OTHER_TENANT_ID", "tenant-other")
SCAN_RUN_ID        = os.environ.get("SCAN_RUN_ID")
ATTACK_PATH_DB_HOST = os.environ.get("ATTACK_PATH_DB_HOST")
ENGINE_AP_URL      = os.environ.get("ENGINE_AP_URL", "http://localhost:8030")  # port-forward target

_SKIP_NO_GW    = pytest.mark.skipif(not SESSION_COOKIE,     reason="SESSION_COOKIE not set")
_SKIP_NO_SCAN  = pytest.mark.skipif(not SCAN_RUN_ID,        reason="SCAN_RUN_ID not set")
_SKIP_NO_AP_DB = pytest.mark.skipif(not ATTACK_PATH_DB_HOST, reason="ATTACK_PATH_DB_HOST not set")

pytestmark = pytest.mark.e2e


# ── HTTP helper ───────────────────────────────────────────────────────────────

def _get(url: str, *, cookie: str | None = None) -> tuple[int, dict]:
    req = urllib.request.Request(url)
    if cookie:
        req.add_header("Cookie", cookie)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read())
        except Exception:
            body = {}
        return e.code, body


def _ap_conn():
    import psycopg2
    return psycopg2.connect(
        host=ATTACK_PATH_DB_HOST,
        user=os.environ.get("ATTACK_PATH_DB_USER", "postgres"),
        password=os.environ.get("ATTACK_PATH_DB_PASSWORD", ""),
        dbname=os.environ.get("ATTACK_PATH_DB_NAME", "threat_engine_attack_path"),
        connect_timeout=5,
    )


# ── Layer 1: DB integrity ─────────────────────────────────────────────────────

class TestAttackPathDbIntegrity:
    """Verify DB state after a full pipeline scan."""

    @_SKIP_NO_SCAN
    @_SKIP_NO_AP_DB
    def test_attack_paths_rows_have_confidence_level(self):
        """Every row in attack_paths must have a non-null confidence_level (migration 026)."""
        conn = _ap_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT COUNT(*) FROM attack_paths WHERE tenant_id=%s AND confidence_level IS NULL",
            (TENANT_ID,),
        )
        null_count = cur.fetchone()[0]
        conn.close()
        assert null_count == 0, (
            f"{null_count} attack_paths rows have NULL confidence_level — "
            "migration 026 may not have been applied or path_enricher skipped"
        )

    @_SKIP_NO_SCAN
    @_SKIP_NO_AP_DB
    def test_confidence_level_values_are_valid(self):
        """confidence_level must be one of confirmed/likely/speculative — no stray values."""
        conn = _ap_conn()
        cur = conn.cursor()
        cur.execute(
            """SELECT DISTINCT confidence_level FROM attack_paths
               WHERE tenant_id=%s AND scan_run_id=%s""",
            (TENANT_ID, SCAN_RUN_ID),
        )
        values = {r[0] for r in cur.fetchall()}
        conn.close()
        if values:
            invalid = values - {"confirmed", "likely", "speculative"}
            assert not invalid, f"Invalid confidence_level values found: {invalid}"

    @_SKIP_NO_SCAN
    @_SKIP_NO_AP_DB
    def test_confirmed_paths_have_attack_name(self):
        """Confirmed paths must have a non-null attack_name (written by path_enricher)."""
        conn = _ap_conn()
        cur = conn.cursor()
        cur.execute(
            """SELECT COUNT(*) FROM attack_paths
               WHERE tenant_id=%s AND scan_run_id=%s
                 AND confidence_level='confirmed' AND attack_name IS NULL""",
            (TENANT_ID, SCAN_RUN_ID),
        )
        missing = cur.fetchone()[0]
        conn.close()
        assert missing == 0, (
            f"{missing} confirmed paths have NULL attack_name — "
            "path_enricher.py may not have populated attack_name for matched patterns"
        )

    @_SKIP_NO_SCAN
    @_SKIP_NO_AP_DB
    def test_confirmed_paths_have_attack_story(self):
        """Confirmed paths must have a non-null attack_story."""
        conn = _ap_conn()
        cur = conn.cursor()
        cur.execute(
            """SELECT COUNT(*) FROM attack_paths
               WHERE tenant_id=%s AND scan_run_id=%s
                 AND confidence_level='confirmed' AND attack_story IS NULL""",
            (TENANT_ID, SCAN_RUN_ID),
        )
        missing = cur.fetchone()[0]
        conn.close()
        assert missing == 0, (
            f"{missing} confirmed paths have NULL attack_story — AP-P5-02 build_attack_story failed"
        )

    @_SKIP_NO_SCAN
    @_SKIP_NO_AP_DB
    def test_confirmed_paths_have_technique_chain(self):
        """Confirmed paths must have a non-null attack_technique_chain JSONB array."""
        conn = _ap_conn()
        cur = conn.cursor()
        cur.execute(
            """SELECT COUNT(*) FROM attack_paths
               WHERE tenant_id=%s AND scan_run_id=%s
                 AND confidence_level='confirmed' AND attack_technique_chain IS NULL""",
            (TENANT_ID, SCAN_RUN_ID),
        )
        missing = cur.fetchone()[0]
        conn.close()
        assert missing == 0, (
            f"{missing} confirmed paths have NULL attack_technique_chain"
        )

    @_SKIP_NO_SCAN
    @_SKIP_NO_AP_DB
    def test_speculative_paths_have_null_story(self):
        """Speculative paths must NOT have an attack_story (no pattern matched)."""
        conn = _ap_conn()
        cur = conn.cursor()
        cur.execute(
            """SELECT COUNT(*) FROM attack_paths
               WHERE tenant_id=%s AND scan_run_id=%s
                 AND confidence_level='speculative' AND attack_story IS NOT NULL""",
            (TENANT_ID, SCAN_RUN_ID),
        )
        bad = cur.fetchone()[0]
        conn.close()
        assert bad == 0, (
            f"{bad} speculative paths have non-null attack_story — path_enricher logic error"
        )

    @_SKIP_NO_SCAN
    @_SKIP_NO_AP_DB
    def test_attack_story_length_under_limit(self):
        """attack_story must be ≤1000 chars (truncation applied by build_attack_story)."""
        conn = _ap_conn()
        cur = conn.cursor()
        cur.execute(
            """SELECT path_id, LENGTH(attack_story) AS len
               FROM attack_paths
               WHERE tenant_id=%s AND attack_story IS NOT NULL
               ORDER BY len DESC LIMIT 1""",
            (TENANT_ID,),
        )
        row = cur.fetchone()
        conn.close()
        if row:
            path_id, length = row
            assert length <= 1000, (
                f"attack_story for path {path_id} is {length} chars (max 1000) — "
                "build_attack_story truncation not applied"
            )

    @_SKIP_NO_SCAN
    @_SKIP_NO_AP_DB
    def test_tenant_isolation_attack_paths(self):
        """Other tenant must not see this tenant's scan_run_id rows."""
        conn = _ap_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT COUNT(*) FROM attack_paths WHERE tenant_id=%s AND scan_run_id=%s",
            (OTHER_TENANT_ID, SCAN_RUN_ID),
        )
        count = cur.fetchone()[0]
        conn.close()
        assert count == 0, (
            f"Cross-tenant leak: {OTHER_TENANT_ID} has {count} attack_paths rows for this scan_run_id"
        )


# ── Layer 2: BFF / Gateway ────────────────────────────────────────────────────

class TestGatewayBffShape:
    """Verify the BFF endpoint returns correct shape including enrichment fields."""

    @_SKIP_NO_GW
    def test_attack_paths_list_returns_200(self):
        """GET /api/v1/views/attack-paths must return 200 with valid auth."""
        status, body = _get(f"{GATEWAY_URL}/api/v1/views/attack-paths", cookie=SESSION_COOKIE)
        assert status == 200, f"Expected 200, got {status}: {body}"

    @_SKIP_NO_GW
    def test_attack_paths_list_has_required_top_level_fields(self):
        """Response must contain paths, total, kpis."""
        _, body = _get(f"{GATEWAY_URL}/api/v1/views/attack-paths", cookie=SESSION_COOKIE)
        for field in ["paths", "total", "kpis"]:
            assert field in body, f"Missing top-level field: {field}"

    @_SKIP_NO_GW
    def test_kpis_has_confirmed_paths(self):
        """kpis must include confirmed_paths (AP-P5-03 fix)."""
        _, body = _get(f"{GATEWAY_URL}/api/v1/views/attack-paths", cookie=SESSION_COOKIE)
        kpis = body.get("kpis", {})
        assert "confirmed_paths" in kpis, (
            "BUG AP-P5-03: kpis.confirmed_paths missing from BFF response — "
            "engine routes.py KPI query omits it"
        )
        assert isinstance(kpis["confirmed_paths"], int)

    @_SKIP_NO_GW
    def test_kpis_existing_fields_present(self):
        """Existing KPI fields must not be dropped."""
        _, body = _get(f"{GATEWAY_URL}/api/v1/views/attack-paths", cookie=SESSION_COOKIE)
        kpis = body.get("kpis", {})
        for field in ["critical", "high", "choke_points", "longest_open_days", "paths_with_active_cdr"]:
            assert field in kpis, f"Existing KPI field '{field}' dropped from response"

    @_SKIP_NO_GW
    def test_paths_have_confidence_level(self):
        """Each path object must include confidence_level (AP-P5-03)."""
        _, body = _get(f"{GATEWAY_URL}/api/v1/views/attack-paths", cookie=SESSION_COOKIE)
        paths = body.get("paths", [])
        if not paths:
            pytest.skip("No paths returned — cannot assert field presence")
        for path in paths[:5]:  # check first 5
            assert "confidence_level" in path, (
                f"path_id={path.get('path_id')} missing confidence_level — "
                "engine SELECT omits enrichment columns (AP-P5-03 bug)"
            )
            assert path["confidence_level"] in ("confirmed", "likely", "speculative"), (
                f"Invalid confidence_level: {path['confidence_level']!r}"
            )

    @_SKIP_NO_GW
    def test_confirmed_paths_have_attack_name_in_response(self):
        """Confirmed paths in API response must have attack_name set."""
        _, body = _get(f"{GATEWAY_URL}/api/v1/views/attack-paths", cookie=SESSION_COOKIE)
        paths = body.get("paths", [])
        confirmed = [p for p in paths if p.get("confidence_level") == "confirmed"]
        if not confirmed:
            pytest.skip("No confirmed paths returned in this response page")
        for path in confirmed:
            assert path.get("attack_name") is not None, (
                f"Confirmed path {path.get('path_id')} has null attack_name in API response"
            )

    @_SKIP_NO_GW
    def test_path_detail_has_enrichment_fields(self):
        """GET /views/attack-paths/{path_id} detail must include all enrichment fields."""
        _, list_body = _get(f"{GATEWAY_URL}/api/v1/views/attack-paths", cookie=SESSION_COOKIE)
        paths = list_body.get("paths", [])
        if not paths:
            pytest.skip("No paths returned — cannot test detail endpoint")
        path_id = paths[0]["path_id"]
        import urllib.parse
        status, detail = _get(
            f"{GATEWAY_URL}/api/v1/views/attack-paths/{urllib.parse.quote(path_id)}",
            cookie=SESSION_COOKIE,
        )
        assert status == 200, f"Detail endpoint returned {status}"
        for field in ["confidence_level", "attack_name", "attack_story", "attack_technique_chain"]:
            assert field in detail, (
                f"Detail endpoint missing field '{field}' — "
                "engine _fetch_path_detail SELECT incomplete (AP-P5-03)"
            )

    @_SKIP_NO_GW
    def test_attack_technique_chain_is_list_not_string(self):
        """attack_technique_chain must be a list (JSONB) not a JSON string."""
        _, list_body = _get(f"{GATEWAY_URL}/api/v1/views/attack-paths", cookie=SESSION_COOKIE)
        paths = list_body.get("paths", [])
        confirmed = [p for p in paths if p.get("confidence_level") == "confirmed"]
        if not confirmed:
            pytest.skip("No confirmed paths to test technique chain type")
        import urllib.parse
        path_id = confirmed[0]["path_id"]
        _, detail = _get(
            f"{GATEWAY_URL}/api/v1/views/attack-paths/{urllib.parse.quote(path_id)}",
            cookie=SESSION_COOKIE,
        )
        chain = detail.get("attack_technique_chain")
        if chain is not None:
            assert isinstance(chain, list), (
                f"attack_technique_chain is {type(chain).__name__}, not list — "
                "json.loads() called on JSONB (CSPM constitution violation)"
            )

    @_SKIP_NO_GW
    def test_attack_paths_requires_auth(self):
        """Without session cookie, must return 401 or 403."""
        url = f"{GATEWAY_URL}/api/v1/views/attack-paths"
        req = urllib.request.Request(url)
        try:
            with urllib.request.urlopen(req, timeout=10):
                pytest.fail("Expected 401/403 but got 200")
        except urllib.error.HTTPError as e:
            assert e.code in (401, 403), f"Expected 401/403, got {e.code}"

    @_SKIP_NO_GW
    def test_viewer_gets_no_paths_array(self):
        """Viewer role must receive summary only — no paths[] array."""
        # This test requires a separate viewer SESSION_COOKIE — skip if not provided
        viewer_cookie = os.environ.get("VIEWER_SESSION_COOKIE")
        if not viewer_cookie:
            pytest.skip("VIEWER_SESSION_COOKIE not set")
        _, body = _get(f"{GATEWAY_URL}/api/v1/views/attack-paths", cookie=viewer_cookie)
        assert "paths" not in body or body.get("paths") is None, (
            "Viewer should not receive paths[] array — RBAC not enforced"
        )

    @_SKIP_NO_GW
    def test_asset_findings_endpoint_returns_valid_shape(self):
        """GET /views/inventory/asset/{uid}/findings must return findings[], total, by_severity."""
        # Grab a real resource_uid from the attack paths entry points
        _, list_body = _get(f"{GATEWAY_URL}/api/v1/views/attack-paths", cookie=SESSION_COOKIE)
        paths = list_body.get("paths", [])
        if not paths:
            pytest.skip("No attack paths to get resource uid from")
        # Use the choke_node_uid if available, else the crown_jewel_uid
        uid = paths[0].get("choke_node_uid") or paths[0].get("crown_jewel_uid")
        if not uid:
            pytest.skip("No resource uid found in first path")
        import urllib.parse
        status, body = _get(
            f"{GATEWAY_URL}/api/v1/views/inventory/asset/{urllib.parse.quote(uid, safe='')}/findings",
            cookie=SESSION_COOKIE,
        )
        # 200 with findings or 404 if asset not in inventory — both acceptable
        assert status in (200, 404), f"Unexpected status {status}"
        if status == 200:
            assert "findings" in body
            assert isinstance(body["findings"], list)
            assert "total" in body


# ── Layer 3: Engine direct (port-forward) ────────────────────────────────────

class TestEngineApiDirect:
    """Verify engine API returns enrichment fields directly (bypasses BFF)."""

    def _engine_cookie(self) -> str | None:
        return os.environ.get("ENGINE_SESSION_COOKIE") or SESSION_COOKIE

    @pytest.mark.skipif(
        not os.environ.get("ENGINE_AP_URL") and not os.environ.get("SESSION_COOKIE"),
        reason="ENGINE_AP_URL or SESSION_COOKIE not set",
    )
    def test_engine_attack_paths_includes_confidence_level(self):
        """Engine /api/v1/attack-paths must include confidence_level in each path."""
        status, body = _get(
            f"{ENGINE_AP_URL}/api/v1/attack-paths",
            cookie=self._engine_cookie(),
        )
        if status == 401:
            pytest.skip("Engine requires auth header — use SESSION_COOKIE with correct X-Auth-Context")
        assert status == 200, f"Engine returned {status}"
        paths = body.get("paths", [])
        if not paths:
            pytest.skip("No paths in engine response")
        for path in paths[:3]:
            assert "confidence_level" in path, (
                "BUG AP-P5-03: Engine _fetch_attack_paths SELECT missing confidence_level"
            )

    @pytest.mark.skipif(
        not os.environ.get("ENGINE_AP_URL") and not os.environ.get("SESSION_COOKIE"),
        reason="ENGINE_AP_URL or SESSION_COOKIE not set",
    )
    def test_engine_kpis_include_confirmed_paths(self):
        """Engine KPI query must include confirmed_paths."""
        status, body = _get(
            f"{ENGINE_AP_URL}/api/v1/attack-paths",
            cookie=self._engine_cookie(),
        )
        if status in (401, 403):
            pytest.skip("Auth required")
        assert status == 200
        kpis = body.get("kpis", {})
        assert "confirmed_paths" in kpis, (
            "BUG AP-P5-03: Engine KPI query missing confirmed_paths count"
        )
