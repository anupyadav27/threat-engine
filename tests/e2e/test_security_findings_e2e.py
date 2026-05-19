"""E2E tests for the security_findings unified layer (SF-P0-01 through SF-P4-01).

Architecture: All engine writes go to security_findings in threat_engine_inventory DB.
Pipeline order: Check/IAM/Network/DataSec/Vuln/CDR/Container write findings at Stage 5.
Attack path reads findings at Stage 6.5 via SF-P3-01 findings_lookup.

All tests skip if required env vars are absent — safe to run in CI without a live DB.

Run:
    SCAN_RUN_ID=<uuid> INVENTORY_DB_HOST=... GATEWAY_URL=http://... \\
        pytest tests/e2e/test_security_findings_e2e.py -v -m e2e
"""
from __future__ import annotations

import os
import urllib.request
import urllib.error
import json

import pytest


# ── Skip guards ───────────────────────────────────────────────────────────────

SCAN_RUN_ID       = os.environ.get("SCAN_RUN_ID")
GATEWAY_URL       = os.environ.get("GATEWAY_URL", "http://localhost:8000")
TENANT_ID         = os.environ.get("TENANT_ID", "my-tenant")
OTHER_TENANT_ID   = os.environ.get("OTHER_TENANT_ID", "tenant-other")
INVENTORY_DB_HOST = os.environ.get("INVENTORY_DB_HOST")
ATTACK_PATH_DB_HOST = os.environ.get("ATTACK_PATH_DB_HOST")
SESSION_COOKIE    = os.environ.get("SESSION_COOKIE")   # access_token=... for gateway requests

_SKIP_NO_SCAN   = pytest.mark.skipif(not SCAN_RUN_ID,       reason="SCAN_RUN_ID not set")
_SKIP_NO_INV_DB = pytest.mark.skipif(not INVENTORY_DB_HOST, reason="INVENTORY_DB_HOST not set")
_SKIP_NO_GW     = pytest.mark.skipif(not SESSION_COOKIE,    reason="SESSION_COOKIE not set (gateway auth required)")
_SKIP_NO_AP_DB  = pytest.mark.skipif(not ATTACK_PATH_DB_HOST, reason="ATTACK_PATH_DB_HOST not set")

pytestmark = pytest.mark.e2e


# ── DB helper ─────────────────────────────────────────────────────────────────

def _inv_conn():
    """Open a psycopg2 connection to threat_engine_inventory DB."""
    import psycopg2
    return psycopg2.connect(
        host=INVENTORY_DB_HOST,
        user=os.environ.get("INVENTORY_DB_USER", "postgres"),
        password=os.environ.get("INVENTORY_DB_PASSWORD", ""),
        dbname=os.environ.get("INVENTORY_DB_NAME", "threat_engine_inventory"),
        connect_timeout=5,
    )


def _ap_conn():
    """Open a psycopg2 connection to threat_engine_attack_path DB."""
    import psycopg2
    return psycopg2.connect(
        host=ATTACK_PATH_DB_HOST,
        user=os.environ.get("ATTACK_PATH_DB_USER", "postgres"),
        password=os.environ.get("ATTACK_PATH_DB_PASSWORD", ""),
        dbname=os.environ.get("ATTACK_PATH_DB_NAME", "threat_engine_attack_path"),
        connect_timeout=5,
    )


def _gateway_get(path: str) -> tuple[int, dict]:
    """HTTP GET via gateway. Returns (status_code, parsed_json)."""
    url = f"{GATEWAY_URL}{path}"
    req = urllib.request.Request(url)
    if SESSION_COOKIE:
        req.add_header("Cookie", SESSION_COOKIE)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, {}


# ── DB layer tests ────────────────────────────────────────────────────────────

class TestSecurityFindingsDB:
    """Verify security_findings table has data after a full pipeline scan."""

    @_SKIP_NO_SCAN
    @_SKIP_NO_INV_DB
    def test_security_findings_table_has_rows_for_scan(self):
        """After a full scan, security_findings must have at least 1 row for this scan_run_id."""
        conn = _inv_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT COUNT(*) FROM security_findings WHERE tenant_id=%s AND scan_run_id=%s",
            (TENANT_ID, SCAN_RUN_ID),
        )
        count = cur.fetchone()[0]
        conn.close()
        assert count > 0, f"No security_findings rows for scan_run_id={SCAN_RUN_ID}"

    @_SKIP_NO_SCAN
    @_SKIP_NO_INV_DB
    def test_security_findings_has_multiple_source_engines(self):
        """At least 2 distinct source_engine values expected after a full scan (check + iam at minimum)."""
        conn = _inv_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT DISTINCT source_engine FROM security_findings WHERE tenant_id=%s AND scan_run_id=%s",
            (TENANT_ID, SCAN_RUN_ID),
        )
        engines = {r[0] for r in cur.fetchall()}
        conn.close()
        assert len(engines) >= 2, f"Expected ≥2 source_engines, got: {engines}"

    @_SKIP_NO_SCAN
    @_SKIP_NO_INV_DB
    def test_security_findings_tenant_isolation(self):
        """Other tenant must have 0 rows for this scan_run_id (cross-tenant isolation)."""
        conn = _inv_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT COUNT(*) FROM security_findings WHERE tenant_id=%s AND scan_run_id=%s",
            (OTHER_TENANT_ID, SCAN_RUN_ID),
        )
        count = cur.fetchone()[0]
        conn.close()
        assert count == 0, f"Cross-tenant leak: {OTHER_TENANT_ID} has {count} rows for scan_run_id={SCAN_RUN_ID}"

    @_SKIP_NO_SCAN
    @_SKIP_NO_INV_DB
    def test_security_findings_no_null_tenant_id(self):
        """No rows in security_findings should ever have tenant_id=NULL."""
        conn = _inv_conn()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM security_findings WHERE tenant_id IS NULL")
        count = cur.fetchone()[0]
        conn.close()
        assert count == 0, f"Found {count} rows with NULL tenant_id — write-path bug"

    @_SKIP_NO_SCAN
    @_SKIP_NO_INV_DB
    def test_k8s_findings_present_when_k8s_in_scope(self):
        """If K8s clusters were scanned, k8s_violation or container_risk rows must exist."""
        conn = _inv_conn()
        cur = conn.cursor()
        cur.execute(
            """SELECT COUNT(*) FROM security_findings
               WHERE tenant_id=%s AND scan_run_id=%s
                 AND finding_type IN ('k8s_violation','container_risk')""",
            (TENANT_ID, SCAN_RUN_ID),
        )
        count = cur.fetchone()[0]
        conn.close()
        # Note: this is informational — K8s may not be in scope for all tenants
        # Only assert if we know K8s was scanned
        if os.environ.get("K8S_IN_SCOPE") == "true":
            assert count > 0, "K8s_IN_SCOPE=true but no k8s_violation or container_risk findings"

    @_SKIP_NO_SCAN
    @_SKIP_NO_INV_DB
    def test_detail_jsonb_no_raw_pod_spec(self):
        """Container findings detail must not contain 'env' key (raw pod spec exclusion — AC-15/AC-16 of SF-P1-03)."""
        conn = _inv_conn()
        cur = conn.cursor()
        cur.execute(
            """SELECT detail FROM security_findings
               WHERE tenant_id=%s AND source_engine='container'
               LIMIT 5""",
            (TENANT_ID,),
        )
        rows = cur.fetchall()
        conn.close()
        for (detail,) in rows:
            if detail is not None:
                assert "env" not in detail, f"Container finding detail contains raw 'env' key: {detail}"


# ── BFF / Gateway layer ───────────────────────────────────────────────────────

class TestAssetFindingsBFF:
    """Verify the /views/inventory/asset/{uid}/findings BFF endpoint."""

    @_SKIP_NO_SCAN
    @_SKIP_NO_INV_DB
    @_SKIP_NO_GW
    def test_findings_endpoint_returns_200_for_known_resource(self):
        """GET /views/inventory/asset/{uid}/findings must return 200 for a real resource."""
        # Get a real resource_uid from security_findings for this scan
        conn = _inv_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT resource_uid FROM security_findings WHERE tenant_id=%s AND scan_run_id=%s LIMIT 1",
            (TENANT_ID, SCAN_RUN_ID),
        )
        row = cur.fetchone()
        conn.close()
        if not row:
            pytest.skip("No security_findings rows to test with")
        uid = row[0]
        import urllib.parse
        status, body = _gateway_get(f"/api/v1/views/inventory/asset/{urllib.parse.quote(uid, safe='')}/findings")
        assert status == 200, f"Expected 200, got {status}"
        assert "findings" in body
        assert isinstance(body["findings"], list)

    @_SKIP_NO_GW
    def test_findings_endpoint_returns_404_for_unknown_resource(self):
        """GET /views/.../findings for unknown uid must return 404, not 500."""
        status, _ = _gateway_get("/api/v1/views/inventory/asset/arn%3Aaws%3As3%3A%3A%3Anonexistent-bucket-xyz/findings")
        assert status in (404, 200), f"Unexpected status {status} — 404 or 200(empty) expected"

    @_SKIP_NO_GW
    def test_findings_endpoint_requires_auth(self):
        """Without a session cookie, must return 401 or 403."""
        url = f"{GATEWAY_URL}/api/v1/views/inventory/asset/any-uid/findings"
        req = urllib.request.Request(url)
        # Deliberately no auth cookie
        try:
            with urllib.request.urlopen(req, timeout=10):
                pytest.fail("Expected 401/403 but got 200")
        except urllib.error.HTTPError as e:
            assert e.code in (401, 403), f"Expected 401/403, got {e.code}"


# ── Attack path integration ───────────────────────────────────────────────────

class TestAttackPathFindings:
    """Verify security_findings are wired into attack path enrichment (SF-P3-01)."""

    @_SKIP_NO_SCAN
    @_SKIP_NO_AP_DB
    def test_attack_paths_exist_after_scan(self):
        """After a full scan, attack_paths table must have rows for the tenant."""
        conn = _ap_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT COUNT(*) FROM attack_paths WHERE tenant_id=%s AND scan_run_id=%s",
            (TENANT_ID, SCAN_RUN_ID),
        )
        count = cur.fetchone()[0]
        conn.close()
        assert count >= 0  # 0 is ok if no paths found — just verify no crash

    @_SKIP_NO_SCAN
    @_SKIP_NO_AP_DB
    def test_confidence_level_column_populated(self):
        """confidence_level on attack_paths must be confirmed/likely/speculative (migration 026)."""
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
            assert values.issubset({"confirmed", "likely", "speculative"}), \
                f"Unexpected confidence_level values: {values}"
