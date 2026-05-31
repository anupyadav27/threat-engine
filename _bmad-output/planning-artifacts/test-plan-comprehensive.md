# Comprehensive Test Plan — CSPM Platform
## Covers: Attack-Path Epic, Security Findings Sub-Project, Posture Coverage, Risk Engine

**Date**: 2026-05-16  
**Scope**: All active stories (AP, SF, RF, PC) + cross-cutting concerns (multi-tenant, multi-CSP/K8s, RBAC)  
**Primary framework**: pytest + FastAPI TestClient (existing pattern in `tests/`)  
**E2E UI**: Playwright (existing `tests/e2e/playwright.config.ts`)  
**E2E API**: pytest + `requests` port-forwarded to live gateway

---

## 1. Test Pyramid

```
                  ┌──────────────┐
                  │   UI E2E     │  Playwright — browser smoke (5–10 specs)
                 ┌┴──────────────┴┐
                 │  API E2E       │  pytest + requests → real gateway (10–15 tests)
                ┌┴────────────────┴┐
                │  Post-deploy     │  Shell + pytest smoke after every rollout
               ┌┴──────────────────┴┐
               │  RBAC matrix       │  5 roles × all endpoints (existing pattern)
              ┌┴────────────────────┴┐
              │  BFF contract        │  FastAPI TestClient, mocked engine (existing pattern)
             ┌┴──────────────────────┴┐
             │  Integration           │  Real DB in CI (pytest-postgresql or RDS test schema)
            ┌┴────────────────────────┴┐
            │  Unit                    │  Pure Python, no I/O, fast (< 5s total)
            └──────────────────────────┘
```

---

## 2. New Test Files — Full Map

### 2.1 Unit Tests (`tests/unit/`)

| File | Covers | Key cases |
|---|---|---|
| `test_security_findings_writer.py` | SF-P0-02 | batch 1100→3 chunks, ON CONFLICT never updates first_seen_at, unknown engine raises ValueError |
| `test_crown_jewel_classifier.py` | AP-P1-01 | each resource type (AWS+Azure+GCP+OCI+K8s), override suppresses auto-classify, k8s.secret with sensitive annotation |
| `test_threat_enricher.py` | AP-P5-02 | overlap_ratio(), confirmed≥0.70, likely≥0.50, speculative=0, empty incidents→speculative |
| `test_attack_story_builder.py` | AP-P5-02 | story length cap 1000 chars, story=null for speculative, multi-hop technique chain order |
| `test_risk_fair_classifier.py` | RF-P1-01 | cdr_confirmed_attack triggers 2.5× multiplier, KEV epss boost capped at 1.0, crown_jewel_type→AV tier mapping |
| `test_findings_fetcher.py` | RF-P1-01 | RiskInputRow merge: posture-only resource, findings-only resource, both present |

**Pattern** (follow existing `tests/test_posture_writer.py`):
```python
# tests/unit/test_security_findings_writer.py
import pytest
from unittest.mock import MagicMock, call
from engine_common.security_findings_writer import upsert_findings, FindingRow

def _make_row(i: int) -> FindingRow:
    return FindingRow(
        source_finding_id=f"find-{i}",
        resource_uid=f"arn:aws:ec2:us-east-1:123:instance/i-{i:04d}",
        finding_type="misconfig",
        severity="high",
        title=f"Finding {i}",
    )

def test_batches_correctly():
    conn = MagicMock()
    cur = conn.cursor.return_value.__enter__.return_value
    rows = [_make_row(i) for i in range(1100)]
    count = upsert_findings(conn, rows, "check", "tenant-1", "scan-uuid-1")
    assert cur.executemany.call_count == 3   # 500 + 500 + 100
    assert count == 1100

def test_never_updates_first_seen_at():
    # ON CONFLICT SET must not include first_seen_at
    from engine_common.security_findings_writer import _UPSERT_SQL
    assert "first_seen_at" not in _UPSERT_SQL.split("DO UPDATE")[1]

def test_rejects_unknown_engine():
    conn = MagicMock()
    with pytest.raises(ValueError, match="unknown"):
        upsert_findings(conn, [], "unknown", "tenant-1", "scan-1")

@pytest.mark.parametrize("engine", ["check","iam","network","datasec","vuln","cdr","container"])
def test_accepts_all_valid_engines(engine):
    conn = MagicMock()
    conn.cursor.return_value.__enter__.return_value = MagicMock()
    upsert_findings(conn, [], engine, "tenant-1", "scan-1")  # no raise
```

---

### 2.2 BFF Contract Tests (`tests/bff/`)

| File | Covers | Key assertions |
|---|---|---|
| `test_attack_paths_bff.py` | AP-P3-01 (exists) | Extend: `confidence_level` in paths[], `confirmed_paths` kpi, `attack_name` not null for confirmed paths |
| `test_asset_findings_bff.py` | SF-P2-01 | response shape, field stripping (viewer→detail=null,epss=null), analyst→CDR detail=null, 503 on engine down |
| `test_unified_findings_bff.py` | SF-P2-01 | pagination (page/page_size), severity filter, source_engine filter, kpis.open_cves_in_kev |
| `test_asset_posture_bff.py` | AP-P4-04 (exists) | Extend: `attack_path` sub-object shape validation |

**Pattern for `test_asset_findings_bff.py`** (follow `test_attack_paths_bff.py`):
```python
"""BFF contract tests for /views/inventory/asset/{uid}/findings (SF-P2-01).

Contract: GET /api/v1/views/inventory/asset/{uid}/findings must return:
  {
    "findings": [{finding_id, source_engine, finding_type, severity, rule_id,
                  title, epss_score, in_kev, mitre_technique_id, status,
                  first_seen_at, last_seen_at, detail}],
    "total": int,
    "by_engine": {"check": int, "iam": int, ...},
    "by_severity": {"critical": int, "high": int, "medium": int, "low": int}
  }

Field stripping rules:
  - viewer:         detail=null, epss_score=null for all rows
  - analyst:        detail=null for source_engine='cdr' rows only
  - tenant_admin:   full response
  - org_admin:      full response
  - platform_admin: full response
"""
import json, pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

VIEWER_CTX = lambda tid="t1": json.dumps({
    "role": "viewer", "level": 1, "engine_tenant_id": tid,
    "permissions": ["discoveries:read"], "tenant_ids": [tid],
})
ANALYST_CTX = lambda tid="t1": json.dumps({
    "role": "analyst", "level": 4, "engine_tenant_id": tid,
    "permissions": ["discoveries:read"], "tenant_ids": [tid],
})

MOCK_FINDINGS = [
    {"finding_id": "f1", "source_engine": "check", "finding_type": "misconfig",
     "severity": "critical", "rule_id": "aws-sg-ssh", "title": "SSH open",
     "epss_score": None, "in_kev": False, "mitre_technique_id": None,
     "status": "open", "first_seen_at": "2026-01-01T00:00:00Z",
     "last_seen_at": "2026-05-01T00:00:00Z", "detail": {"region": "us-east-1"}},
    {"finding_id": "f2", "source_engine": "cdr", "finding_type": "cdr_event",
     "severity": "high", "rule_id": None, "title": "Unusual API call",
     "epss_score": None, "in_kev": False, "mitre_technique_id": "T1078",
     "status": "open", "first_seen_at": "2026-02-01T00:00:00Z",
     "last_seen_at": "2026-05-10T00:00:00Z",
     "detail": {"actor_hash": "abc123", "event_type": "ConsoleLogin"}},
    {"finding_id": "f3", "source_engine": "vuln", "finding_type": "cve",
     "severity": "critical", "rule_id": "CVE-2024-1234", "title": "Log4j",
     "epss_score": 0.91, "in_kev": True, "mitre_technique_id": None,
     "status": "open", "first_seen_at": "2026-03-01T00:00:00Z",
     "last_seen_at": "2026-05-01T00:00:00Z", "detail": {"package": "log4j:2.14"}},
]

@pytest.fixture
def client():
    from shared.api_gateway.main import app
    return TestClient(app)

def test_response_shape(client):
    with patch("shared.api_gateway.bff.asset_findings._query_findings",
               return_value=MOCK_FINDINGS):
        r = client.get(
            "/api/v1/views/inventory/asset/arn:aws:ec2::/instance/i-1/findings",
            headers={"X-Auth-Context": ANALYST_CTX()}
        )
    assert r.status_code == 200
    body = r.json()
    assert "findings" in body and "total" in body
    assert "by_engine" in body and "by_severity" in body
    assert body["total"] == 3

def test_viewer_strips_detail_and_epss(client):
    with patch("shared.api_gateway.bff.asset_findings._query_findings",
               return_value=MOCK_FINDINGS):
        r = client.get(
            "/api/v1/views/inventory/asset/i-1/findings",
            headers={"X-Auth-Context": VIEWER_CTX()}
        )
    for f in r.json()["findings"]:
        assert f["detail"] is None
        assert f["epss_score"] is None
    # severity label must still be visible
    severities = {f["severity"] for f in r.json()["findings"]}
    assert "critical" in severities

def test_analyst_strips_cdr_detail_only(client):
    with patch("shared.api_gateway.bff.asset_findings._query_findings",
               return_value=MOCK_FINDINGS):
        r = client.get(
            "/api/v1/views/inventory/asset/i-1/findings",
            headers={"X-Auth-Context": ANALYST_CTX()}
        )
    findings_by_engine = {f["source_engine"]: f for f in r.json()["findings"]}
    assert findings_by_engine["cdr"]["detail"] is None       # stripped
    assert findings_by_engine["check"]["detail"] is not None  # present
    assert findings_by_engine["vuln"]["epss_score"] == 0.91   # visible for analyst

def test_cross_tenant_isolation(client):
    # tenant-2 cannot retrieve findings for tenant-1 resources
    with patch("shared.api_gateway.bff.asset_findings._query_findings",
               return_value=[]) as mock_q:
        r = client.get(
            "/api/v1/views/inventory/asset/i-1/findings",
            headers={"X-Auth-Context": ANALYST_CTX(tid="tenant-2")}
        )
    # query must have been called with tenant-2, not tenant-1
    call_kwargs = mock_q.call_args
    assert call_kwargs.kwargs.get("tenant_id") == "tenant-2" or \
           "tenant-2" in str(call_kwargs)

def test_503_on_db_unavailable(client):
    with patch("shared.api_gateway.bff.asset_findings._query_findings",
               side_effect=Exception("DB connection refused")):
        r = client.get(
            "/api/v1/views/inventory/asset/i-1/findings",
            headers={"X-Auth-Context": ANALYST_CTX()}
        )
    assert r.status_code == 503

def test_severity_filter(client):
    critical_only = [f for f in MOCK_FINDINGS if f["severity"] == "critical"]
    with patch("shared.api_gateway.bff.asset_findings._query_findings",
               return_value=critical_only):
        r = client.get(
            "/api/v1/views/inventory/asset/i-1/findings?severity=critical",
            headers={"X-Auth-Context": ANALYST_CTX()}
        )
    assert all(f["severity"] == "critical" for f in r.json()["findings"])
```

---

### 2.3 RBAC Matrix Tests (`tests/rbac/`)

| File | Covers | Endpoint count |
|---|---|---|
| `test_attack_path_rbac.py` | AP-P2-02 (exists) | Extend: add `GET /attack-paths?confidence_level=confirmed` filter |
| `test_asset_findings_rbac.py` | SF-P2-01 | 5 roles × 2 endpoints (asset findings + unified findings) |
| `test_security_findings_rbac.py` | SF-P2-01 | `GET /views/findings` — viewer 200 with stripped fields, all roles get 200 |

**RBAC matrix for SF-P2-01:**
```
| Role           | GET /asset/{uid}/findings | GET /views/findings |
|----------------|--------------------------|---------------------|
| platform_admin | 200 full                 | 200 full            |
| org_admin      | 200 full                 | 200 full            |
| tenant_admin   | 200 full                 | 200 full            |
| analyst        | 200 (CDR detail=null)    | 200 (CDR detail=null)|
| viewer         | 200 (detail=null,epss=null)| 200 stripped       |
```

**Pattern:**
```python
# tests/rbac/test_asset_findings_rbac.py
import pytest, json
from fastapi.testclient import TestClient
from unittest.mock import patch

ROLES = [
    ("platform_admin", 1, ["discoveries:read"]),
    ("org_admin",      2, ["discoveries:read"]),
    ("tenant_admin",   4, ["discoveries:read"]),
    ("analyst",        4, ["discoveries:read"]),
    ("viewer",         1, ["discoveries:read"]),
]

@pytest.fixture
def client():
    from shared.api_gateway.main import app
    return TestClient(app)

@pytest.mark.parametrize("role,level,perms", ROLES)
def test_asset_findings_all_roles_200(client, role, level, perms):
    ctx = json.dumps({"role": role, "level": level, "engine_tenant_id": "t1",
                      "permissions": perms, "tenant_ids": ["t1"]})
    with patch("shared.api_gateway.bff.asset_findings._query_findings", return_value=[]):
        r = client.get("/api/v1/views/inventory/asset/i-1/findings",
                       headers={"X-Auth-Context": ctx})
    assert r.status_code == 200, f"{role} got {r.status_code}"

def test_viewer_cannot_see_detail_or_epss(client):
    ctx = json.dumps({"role": "viewer", "level": 1, "engine_tenant_id": "t1",
                      "permissions": ["discoveries:read"], "tenant_ids": ["t1"]})
    mock_row = {"finding_id": "x", "source_engine": "vuln", "finding_type": "cve",
                "severity": "critical", "epss_score": 0.9, "detail": {"pkg": "log4j"},
                "title": "CVE", "rule_id": "CVE-1", "in_kev": True,
                "status": "open", "first_seen_at": "2026-01-01T00:00:00Z",
                "last_seen_at": "2026-05-01T00:00:00Z", "mitre_technique_id": None}
    with patch("shared.api_gateway.bff.asset_findings._query_findings",
               return_value=[mock_row]):
        r = client.get("/api/v1/views/inventory/asset/i-1/findings",
                       headers={"X-Auth-Context": ctx})
    f = r.json()["findings"][0]
    assert f["detail"] is None
    assert f["epss_score"] is None
    assert f["severity"] == "critical"  # severity label always visible
```

---

### 2.4 Integration Tests (`tests/integration/`)

These hit a real DB — run against RDS test schema or pytest-postgresql fixture.

| File | Covers | What it tests |
|---|---|---|
| `test_security_findings_table.py` | SF-P0-01 | migration applied, UNIQUE constraint, partial indexes exist |
| `test_findings_upsert_integration.py` | SF-P0-02 | real psycopg2 upsert, ON CONFLICT updates last_seen_at, first_seen_at preserved |
| `test_findings_loader.py` | SF-P3-01 | load_findings_by_resource() returns correct dict shape, empty scan→{} |
| `test_threat_incidents_loader.py` | AP-P5-02 | load_threat_incidents() filters tier≥2, returns empty for missing scan_run_id |
| `test_enrich_paths.py` | AP-P5-02 | full enrich_paths() cycle — writes confirmed/likely/speculative to attack_paths table |
| `test_risk_findings_fetcher.py` | RF-P1-01 | fetch_risk_inputs() aggregate query matches hand-computed counts |
| `test_posture_score_writeback.py` | RF-P1-01 | posture_score written to resource_security_posture after risk Stage 4 |

**Pattern for integration test with real DB:**
```python
# tests/integration/test_security_findings_table.py
"""Verifies migration 025_security_findings.sql was applied correctly."""
import psycopg2, os, pytest

@pytest.fixture(scope="module")
def inv_conn():
    conn = psycopg2.connect(
        host=os.environ["INVENTORY_DB_HOST"],
        user=os.environ["INVENTORY_DB_USER"],
        password=os.environ["INVENTORY_DB_PASSWORD"],
        dbname=os.environ["INVENTORY_DB_NAME"],
    )
    yield conn
    conn.close()

def test_table_exists(inv_conn):
    with inv_conn.cursor() as cur:
        cur.execute("""
            SELECT COUNT(*) FROM information_schema.tables
            WHERE table_schema='public' AND table_name='security_findings'
        """)
        assert cur.fetchone()[0] == 1

def test_unique_constraint_exists(inv_conn):
    with inv_conn.cursor() as cur:
        cur.execute("""
            SELECT COUNT(*) FROM pg_constraint
            WHERE conrelid = 'security_findings'::regclass
              AND contype = 'u'
        """)
        assert cur.fetchone()[0] >= 1

def test_required_indexes_exist(inv_conn):
    expected = {
        "idx_sf_tenant_scan", "idx_sf_resource_uid",
        "idx_sf_open", "idx_sf_epss"
    }
    with inv_conn.cursor() as cur:
        cur.execute("""
            SELECT indexname FROM pg_indexes
            WHERE tablename = 'security_findings'
        """)
        actual = {r[0] for r in cur.fetchall()}
    missing = expected - actual
    assert not missing, f"Missing indexes: {missing}"

@pytest.mark.parametrize("engine", ["check","iam","network","datasec","vuln","cdr","container"])
def test_upsert_roundtrip(inv_conn, engine):
    from engine_common.security_findings_writer import upsert_findings, FindingRow
    row = FindingRow(
        source_finding_id=f"test-{engine}-001",
        resource_uid="arn:aws:ec2:us-east-1:123:instance/i-test",
        finding_type="misconfig",
        severity="high",
        title=f"Integration test finding — {engine}",
    )
    count = upsert_findings(
        inv_conn, [row], engine, "test-tenant", "test-scan-uuid"
    )
    assert count == 1
    # cleanup
    with inv_conn.cursor() as cur:
        cur.execute("DELETE FROM security_findings WHERE source_finding_id = %s",
                    (f"test-{engine}-001",))
    inv_conn.commit()
```

---

### 2.5 E2E API Tests (`tests/e2e/`) — pytest + requests → live gateway

These run against the real cluster via `kubectl port-forward`. Use `GATEWAY_URL` env var.

**File**: `tests/e2e/test_security_findings_e2e.py`

```python
"""E2E tests: UI→BFF→APIGateway→Engine→DB data flow.

Requires:
  - kubectl port-forward svc/threat-engine-api-gateway 8080:80 -n threat-engine-engines
  - GATEWAY_URL=http://localhost:8080
  - E2E_TOKEN=<valid JWT for analyst role in test tenant>
  - E2E_TENANT_ID=<test tenant id>
  - E2E_RESOURCE_UID=<known resource with findings>

Run: pytest tests/e2e/test_security_findings_e2e.py -v --timeout=30
"""
import os, pytest, requests

BASE = os.environ.get("GATEWAY_URL", "http://localhost:8080")
TOKEN = os.environ.get("E2E_TOKEN", "")
TENANT = os.environ.get("E2E_TENANT_ID", "test-tenant")
RESOURCE_UID = os.environ.get("E2E_RESOURCE_UID", "")
HEADERS = {"Authorization": f"Bearer {TOKEN}"}

@pytest.mark.e2e
class TestAttackPathsFlow:
    """UI → BFF → attack-path engine → DB (attack_paths table)."""

    def test_gateway_live(self):
        r = requests.get(f"{BASE}/api/v1/health/live")
        assert r.status_code == 200

    def test_attack_paths_list_shape(self):
        r = requests.get(
            f"{BASE}/api/v1/views/attack-paths",
            headers=HEADERS,
            params={"tenant_id": TENANT, "page": 1, "page_size": 10}
        )
        assert r.status_code == 200
        body = r.json()
        assert "paths" in body and "total" in body and "kpis" in body
        assert isinstance(body["kpis"]["critical"], int)
        # AP-P5-02: confidence fields present
        assert "confirmed_paths" in body["kpis"]
        assert "speculative_paths" in body["kpis"]

    def test_attack_path_detail_has_attack_story(self):
        # Get first confirmed path
        r = requests.get(f"{BASE}/api/v1/views/attack-paths",
                         headers=HEADERS,
                         params={"tenant_id": TENANT, "confidence_level": "confirmed"})
        paths = r.json().get("paths", [])
        if not paths:
            pytest.skip("No confirmed paths in test tenant — run a scan first")
        path_id = paths[0]["path_id"]
        detail = requests.get(f"{BASE}/api/v1/views/attack-paths/{path_id}",
                              headers=HEADERS)
        assert detail.status_code == 200
        body = detail.json()
        assert body.get("attack_name") is not None
        assert body.get("attack_story") is not None
        assert len(body["attack_story"]) <= 1000

    def test_confidence_level_filter(self):
        for level in ("confirmed", "likely", "speculative"):
            r = requests.get(f"{BASE}/api/v1/views/attack-paths",
                             headers=HEADERS,
                             params={"confidence_level": level})
            assert r.status_code == 200
            for p in r.json().get("paths", []):
                assert p["confidence_level"] == level


@pytest.mark.e2e
class TestAssetFindingsFlow:
    """UI → BFF → security_findings table (SF-P2-01)."""

    def test_asset_findings_endpoint_200(self):
        if not RESOURCE_UID:
            pytest.skip("E2E_RESOURCE_UID not set")
        r = requests.get(
            f"{BASE}/api/v1/views/inventory/asset/{RESOURCE_UID}/findings",
            headers=HEADERS,
        )
        assert r.status_code == 200

    def test_asset_findings_shape(self):
        if not RESOURCE_UID:
            pytest.skip("E2E_RESOURCE_UID not set")
        r = requests.get(
            f"{BASE}/api/v1/views/inventory/asset/{RESOURCE_UID}/findings",
            headers=HEADERS,
        )
        body = r.json()
        assert "findings" in body and "total" in body
        assert "by_engine" in body and "by_severity" in body
        for f in body["findings"]:
            assert f["source_engine"] in {"check","iam","network","datasec",
                                           "vuln","cdr","container"}
            assert f["severity"] in {"critical","high","medium","low"}

    def test_unified_findings_pagination(self):
        r = requests.get(
            f"{BASE}/api/v1/views/findings",
            headers=HEADERS,
            params={"page": 1, "page_size": 20}
        )
        assert r.status_code == 200
        body = r.json()
        assert "findings" in body
        assert body["page"] == 1
        assert body["page_size"] == 20
        assert "kpis" in body
        assert "open_cves_in_kev" in body["kpis"]

    def test_findings_source_engine_filter(self):
        for engine in ("check", "iam", "vuln"):
            r = requests.get(
                f"{BASE}/api/v1/views/findings",
                headers=HEADERS,
                params={"source_engine": engine}
            )
            assert r.status_code == 200
            for f in r.json().get("findings", []):
                assert f["source_engine"] == engine

    def test_severity_ordering(self):
        r = requests.get(f"{BASE}/api/v1/views/findings", headers=HEADERS,
                         params={"page_size": 50})
        findings = r.json().get("findings", [])
        if len(findings) < 2:
            pytest.skip("Not enough findings for ordering check")
        order = {"critical": 1, "high": 2, "medium": 3, "low": 4}
        ranks = [order[f["severity"]] for f in findings]
        assert ranks == sorted(ranks), "Findings not returned in severity order"


@pytest.mark.e2e
class TestMultiTenantIsolation:
    """Verify that tenant boundaries are enforced across all new endpoints."""

    def test_findings_always_scoped_to_auth_tenant(self):
        # Analyst for tenant-A cannot retrieve findings by passing tenant-B in query
        r = requests.get(
            f"{BASE}/api/v1/views/findings",
            headers=HEADERS,
            params={"tenant_id": "other-tenant-b-uuid"}  # should be ignored
        )
        assert r.status_code == 200
        # All returned findings must belong to the token's tenant
        for f in r.json().get("findings", []):
            assert f.get("tenant_id") in (TENANT, None)  # tenant_id may be stripped

    def test_attack_paths_cross_tenant_path_id_returns_404(self):
        # path_id from another tenant should not be visible
        r = requests.get(
            f"{BASE}/api/v1/views/attack-paths/nonexistent-cross-tenant-id",
            headers=HEADERS,
        )
        assert r.status_code in (404, 403)


@pytest.mark.e2e
class TestMultiCSPAndK8s:
    """Verify multi-CSP and K8s findings appear correctly."""

    def test_k8s_findings_present_when_container_engine_ran(self):
        r = requests.get(
            f"{BASE}/api/v1/views/findings",
            headers=HEADERS,
            params={"source_engine": "container", "page_size": 5}
        )
        assert r.status_code == 200
        for f in r.json().get("findings", []):
            assert f["source_engine"] == "container"
            assert f["finding_type"] in ("k8s_violation", "container_risk")
            # K8s resource_uid format
            if f["finding_type"] == "k8s_violation":
                assert f["resource_uid"].startswith("k8s/")

    def test_attack_paths_include_k8s_resources(self):
        r = requests.get(f"{BASE}/api/v1/views/attack-paths", headers=HEADERS)
        paths = r.json().get("paths", [])
        k8s_paths = [p for p in paths if any(
            n.startswith("k8s/") for n in p.get("steps", [])
        )]
        # This is informational — skip if no K8s scan has run
        if not k8s_paths:
            pytest.skip("No K8s resources on attack paths — run K8s scan first")

    def test_crown_jewels_include_k8s_types(self):
        r = requests.get(
            f"{BASE}/api/v1/crown-jewels",
            headers=HEADERS,
        )
        assert r.status_code == 200
        types = {cj.get("crown_jewel_type") for cj in r.json().get("crown_jewels", [])}
        k8s_types = types & {"k8s_control_plane","k8s_secrets","k8s_cluster_admin",
                              "k8s_privileged_workload"}
        # informational — skip if no K8s account onboarded
        if not k8s_types:
            pytest.skip("No K8s crown jewels — onboard a K8s account first")
```

---

### 2.6 Post-Deploy Smoke (`tests/post_deploy/`)

Run after EVERY rollout of gateway, attack-path, risk, or any engine that writes security_findings.

**File**: `tests/post_deploy/validate_security_findings_deploy.sh`

```bash
#!/bin/bash
# Post-deploy smoke for security_findings sub-project.
# Usage: ./validate_security_findings_deploy.sh <gateway_url> <token>
set -e
BASE=${1:-http://localhost:8080}
TOKEN=${2:-""}

echo "=== POST-DEPLOY SMOKE: security_findings ==="

# 1. Gateway health
code=$(curl -s -o /dev/null -w "%{http_code}" $BASE/api/v1/health/live)
[ "$code" = "200" ] || { echo "FAIL: gateway health $code"; exit 1; }
echo "PASS: gateway live"

# 2. Unified findings endpoint accessible
code=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE/api/v1/views/findings?page_size=1")
[ "$code" = "200" ] || { echo "FAIL: /views/findings returned $code"; exit 1; }
echo "PASS: /views/findings 200"

# 3. Attack paths confidence field present
body=$(curl -s -H "Authorization: Bearer $TOKEN" \
  "$BASE/api/v1/views/attack-paths?page_size=1")
echo $body | python3 -c "
import json,sys
b=json.load(sys.stdin)
assert 'confirmed_paths' in b.get('kpis',{}), 'confirmed_paths missing from kpis'
print('PASS: attack-paths kpis has confirmed_paths')
"

echo "=== ALL POST-DEPLOY CHECKS PASSED ==="
```

---

## 3. CI Integration

### pytest.ini additions

```ini
[pytest]
markers =
    unit: pure Python, no I/O
    integration: requires real DB (INVENTORY_DB_* env vars)
    e2e: requires live cluster (GATEWAY_URL + E2E_TOKEN env vars)
    rbac: RBAC matrix tests
    contract: BFF contract shape tests

# Default: unit + contract + rbac (no env vars needed)
addopts = -m "not integration and not e2e"
```

### Run targets

```bash
# Fast (CI on every PR — < 30s):
pytest -m "unit or contract or rbac" -v

# Integration (CI on merge to main — needs DB):
pytest -m "integration" -v --timeout=60

# E2E (post-deploy — needs live cluster):
export GATEWAY_URL=http://localhost:8080
kubectl port-forward svc/threat-engine-api-gateway 8080:80 -n threat-engine-engines &
pytest -m "e2e" -v --timeout=30

# Full suite:
pytest tests/ -v
```

---

## 4. Coverage Matrix — Stories vs Tests

| Story | Unit | BFF Contract | RBAC | Integration | E2E | Post-Deploy |
|---|---|---|---|---|---|---|
| SF-P0-01 (migration) | — | — | — | `test_security_findings_table.py` | — | schema check in smoke |
| SF-P0-02 (writer util) | `test_security_findings_writer.py` | — | — | `test_findings_upsert_integration.py` | — | — |
| SF-P1-01 (check+iam) | — | — | — | `test_findings_upsert_integration.py` | `test_security_findings_e2e.py::source_engine=check` | — |
| SF-P1-02 (vuln+cdr+datasec) | — | — | — | — | `source_engine=vuln/cdr/datasec` | — |
| SF-P1-03 (container) | — | — | — | `test_upsert_roundtrip[container]` | `test_k8s_findings_present` | — |
| SF-P2-01 (BFF findings) | — | `test_asset_findings_bff.py` + `test_unified_findings_bff.py` | `test_asset_findings_rbac.py` | — | `TestAssetFindingsFlow` | `validate_security_findings_deploy.sh` |
| SF-P3-01 (attack-path integration) | — | — | — | `test_findings_loader.py` | — | — |
| AP-P1-01 (crown jewels) | `test_crown_jewel_classifier.py` | — | — | — | `test_crown_jewels_include_k8s_types` | — |
| AP-P3-01 (attack-paths BFF) | — | `test_attack_paths_bff.py` (exists) | `test_attack_path_rbac.py` (exists) | — | `TestAttackPathsFlow` | `validate_attack_path_deploy.sh` (exists) |
| AP-P5-01 (enrichment cols migration) | — | — | — | `test_security_findings_table.py` (extend) | — | — |
| AP-P5-02 (threat enrichment) | `test_threat_enricher.py` + `test_attack_story_builder.py` | extend `test_attack_paths_bff.py` | — | `test_enrich_paths.py` | `test_attack_path_detail_has_attack_story` | — |
| RF-P1-01 (risk unified model) | `test_risk_fair_classifier.py` + `test_findings_fetcher.py` | — | — | `test_risk_findings_fetcher.py` + `test_posture_score_writeback.py` | posture_score not null check | — |
| Multi-tenant isolation | — | `test_cross_tenant_isolation` in each BFF file | — | — | `TestMultiTenantIsolation` | — |
| Multi-CSP / K8s | `test_crown_jewel_classifier.py[k8s.*]` | k8s resource_uid format checks | — | `test_upsert_roundtrip[container]` | `TestMultiCSPAndK8s` | — |

---

## 5. Key Testing Rules (Non-Negotiable)

1. **BFF contract tests must mock all engine HTTP calls** — `patch("bff.module._query_*")` — no real network in unit/contract tests
2. **tenant_id always from AuthContext, never from query params** — every contract test must verify the `_query_*` mock was called with `tenant_id` from the auth header, not from the URL
3. **No fallback data** — every BFF test has a `test_503_on_engine_down` case; 503 must be returned, never empty array
4. **Viewer field stripping has its own test case in every BFF file** — never rely on "probably stripped" inference
5. **Multi-tenant isolation test in every E2E class** — attempt cross-tenant resource_uid access; assert 404 or 403, never 200 with wrong tenant data
6. **K8s resource_uid format** — integration and E2E tests assert `resource_uid.startswith("k8s/")` for container engine findings
7. **RBAC parametrize** — all 5 roles must be tested as `@pytest.mark.parametrize` — no copy-paste per role
