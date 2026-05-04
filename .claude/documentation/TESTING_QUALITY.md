# CSPM Testing & Quality Constitution

**Authority:** Governs all testing strategy, quality gates, and validation standards for the Threat Engine platform.
**Extends:** `CSPM_CONSTITUTION.md` (Section — quality) and `AGENT_BINDING.md` (quality gate sequence).
**Covers:** Unit → Integration → Scan Validation → BFF Contract → RBAC → Pipeline E2E → UI → Performance → Security → Post-Deploy.

---

## Why CSPM Testing Is Different

Standard web app testing (unit → integration → E2E) is insufficient for a scan pipeline platform. Key differences:

1. **Scan-first validation** — most quality checks require a real `scan_run_id` with actual findings in the DB. You cannot mock the pipeline and call it tested.
2. **8 separate databases** — cross-engine linking via `scan_run_id` must be verified end-to-end across every DB, not just the one you touched.
3. **Pipeline ordering is a correctness constraint** — if Check runs before Inventory, findings are wrong. Order is part of correctness, not just performance.
4. **BFF contract is the UI's only interface** — a broken BFF view silently returns empty charts. Contract testing is mandatory.
5. **Multi-tenant isolation is a security property** — not just a feature. Tenant isolation failures are critical vulnerabilities.
6. **Rule regression** — adding one check rule can silently break existing compliance scores. Every rule change needs regression coverage.

---

## Testing Levels — Full Stack

```
Level 0: Static Analysis           ← linting, type checks, constitution compliance
Level 1: Unit Tests                ← pure functions, rule logic, transforms
Level 2: Engine Integration        ← each engine against its own real DB
Level 3: BFF Contract Tests        ← BFF view shape validation per page
Level 4: RBAC & Tenant Tests       ← isolation and permission enforcement
Level 5: Scan Pipeline E2E         ← full Argo run: Discovery → Risk with real scan_run_id
Level 6: Rule Regression           ← existing findings counts unchanged by new rule
Level 7: UI Smoke Tests            ← all pages load, charts render, no console errors
Level 8: Performance Baselines     ← BFF latency, scan throughput, DB query time
Level 9: Security Tests            ← injection, SSRF, auth bypass, tenant leakage
Level 10: Post-Deploy Validation   ← smoke test after every kubectl rollout
```

Quality gate: **must pass Levels 0–5 before any merge**. Levels 6–10 run on schedule or on specific triggers.

---

## Level 0 — Static Analysis (pre-commit, always)

### What Runs

| Check | Tool | Failure blocks |
|---|---|---|
| Python linting | `ruff` or `flake8` | Commit |
| Type checking | `mypy` (engines using typed hints) | Commit |
| SQL parameterization | `grep` — flag any `f"SELECT...{var}"` patterns | PR |
| Constitution check | `cspm-standards-guardian` agent review | PR |
| No `json.loads` on JSONB | `grep` — flag `json.loads(result[` patterns | PR |
| No `latest` image tag | `grep` — flag `:latest` in any YAML | PR |
| No `DEV_BYPASS_AUTH` | `grep` — flag the string anywhere in codebase | PR |
| No hardcoded `tenant_id` | `grep` — flag UUID literals in Python engine code | PR |

### Commands

```bash
# Run from repo root
cd /Users/apple/Desktop/threat-engine

# Linting
ruff check engines/ shared/ platform/

# Constitution grep checks
grep -r "json\.loads(.*result\[" engines/ --include="*.py"
grep -r "DEV_BYPASS_AUTH" . --include="*.py" --include="*.js" --include="*.ts"
grep -r ":latest" deployment/ --include="*.yaml"
grep -rE "f['\"]SELECT.*\{" engines/ --include="*.py"
```

---

## Level 1 — Unit Tests

### Scope

Pure functions with no external dependencies: rule evaluation logic, BFF transform functions, scoring calculations, YAML rule parsing, severity mapping.

### Location

```
tests/
├── test_api_models.py          ← Pydantic model validation
├── test_circuit_breaker.py     ← retry/circuit breaker logic
├── test_retry_handler.py       ← retry logic
├── test_storage_paths.py       ← path utilities
└── bff/
    ├── test_threat_posture_delta.py
    ├── test_threat_command_room.py
    └── test_threat_scenario_detail.py
```

### Standards

- No real DB connections. No real HTTP calls. No `scan_run_id` fixtures.
- Use `pytest` fixtures for all test data.
- Every BFF transform function must have a unit test verifying input → output shape.
- Every severity mapping must have a test: `critical → #ef4444`, etc.
- Rule evaluation logic (PASS/FAIL decision) must be unit tested with both passing and failing resource configs.

```bash
pytest tests/test_api_models.py tests/test_circuit_breaker.py tests/test_retry_handler.py -v
pytest tests/bff/ -v
```

---

## Level 2 — Engine Integration Tests

### Scope

Each engine tested against its own real DB. Verifies: DB connection, table existence, column types, basic CRUD, query correctness.

### Location

```
tests/integration/
├── test_check_engine/
├── test_compliance_engine/
├── test_discoveries_engine/
├── test_inventory_engine/
├── test_threat_engine/
└── ...
```

### Standards

- **Real DB required** — no mocking. Use the RDS instance via port-forward or a local test DB seeded from migration SQL.
- Every engine integration test must verify:
  - All standard columns exist (`finding_id`, `scan_run_id`, `tenant_id`, `account_id`, `credential_ref`, `credential_type`, `provider`, `region`, `resource_uid`, `resource_type`, `severity`, `status`, `first_seen_at`, `last_seen_at`)
  - JSONB columns deserialize to dict (not string)
  - `tenant_id` filter returns only that tenant's rows
  - `scan_run_id` filter returns only that run's rows

### DB Schema Validation Pattern

```python
def test_standard_columns_present(db_conn, engine_table):
    cursor = db_conn.cursor()
    cursor.execute(f"""
        SELECT column_name FROM information_schema.columns
        WHERE table_name = '{engine_table}'
    """)
    cols = {row[0] for row in cursor.fetchall()}
    required = {
        'finding_id', 'scan_run_id', 'tenant_id', 'account_id',
        'credential_ref', 'credential_type', 'provider', 'region',
        'resource_uid', 'resource_type', 'severity', 'status',
        'first_seen_at', 'last_seen_at'
    }
    assert required.issubset(cols), f"Missing columns: {required - cols}"
```

```bash
pytest tests/integration/ -v --timeout=60
```

---

## Level 3 — BFF Contract Tests

### Why This Is Critical

The BFF is the UI's only data source for charts and dashboards. A broken BFF view returns a 200 with empty/null fields — the UI silently renders empty charts. Contract testing catches this.

### Location

```
tests/bff/
├── bff_shape_validator.py      ← shared shape validator utility
├── test_threat_posture_delta.py
├── test_threat_command_room.py
├── test_threat_scenario_detail.py
└── ... (one file per BFF view handler)
```

### Contract Test Pattern (every BFF view must have this)

```python
# Required fields for every BFF view response
REQUIRED_BASE_FIELDS = ['tenant_id', 'provider', 'account_id']

# Per-view required shape — define for every handler in bff/
VIEW_CONTRACTS = {
    'threats': {
        'required_fields': ['kpi_cards', 'severity_breakdown', 'findings'],
        'kpi_cards': ['total_threats', 'critical_count', 'high_count', 'mitre_tactics_hit'],
        'findings': ['finding_id', 'severity', 'resource_uid', 'mitre_technique', 'last_seen_at'],
    },
    'compliance': {
        'required_fields': ['frameworks', 'overall_score', 'failing_controls'],
        'frameworks': ['framework_id', 'name', 'score', 'passing', 'failing'],
    },
    'dashboard': {
        'required_fields': ['risk_score', 'findings_by_severity', 'top_engines', 'scan_status'],
    },
    # ... one entry per page in frontend/src/app/
}

def test_bff_view_shape(view_name, scan_run_id, tenant_id):
    contract = VIEW_CONTRACTS[view_name]
    response = call_bff_view(view_name, scan_run_id, tenant_id)
    
    assert response.status_code == 200
    data = response.json()
    
    for field in contract['required_fields']:
        assert field in data, f"Missing required field '{field}' in {view_name} view"
        assert data[field] is not None, f"Field '{field}' is None in {view_name} view"
    
    # Verify no fallback/mock data leaked through
    assert data.get('_is_mock') is None
    assert data.get('_fallback') is None
```

### Standards

- Every BFF view handler (`shared/api_gateway/bff/*.py`) **MUST** have a corresponding contract test.
- Contract tests run against a real scan_run_id — use the latest production scan_run_id from `scan_orchestration`.
- Any change to a BFF view handler **MUST** update its contract test.
- Missing BFF view for a frontend page is a **blocking defect** — must be fixed, not worked around with mock data.

---

## Level 4 — RBAC & Tenant Isolation Tests

### Why This Is a Security Test, Not Just a Feature Test

Tenant data leakage is a critical vulnerability. RBAC bypass is a critical vulnerability. These are tested here because they must be verified independently of feature work.

### RBAC Test Matrix (run for every new endpoint)

| Role | Endpoint Type | Expected HTTP Status |
|---|---|---|
| `viewer` | `discoveries:read` | 200 |
| `viewer` | `scans:create` | 403 |
| `viewer` | `datasec`, `secops`, `vuln`, `ai_security`, `encryption`, `dbsec`, `container` | 403 |
| `analyst` | Any engine read | 200 |
| `analyst` | `tenants:write` | 403 |
| `tenant_admin` | Own tenant write | 200 |
| `tenant_admin` | Cross-tenant read | 403 |
| `org_admin` | Multi-tenant read | 200 |
| `platform_admin` | All permissions | 200 |
| `unauthenticated` | Any endpoint | 401 |

### Tenant Isolation Test Pattern

```python
def test_tenant_isolation(engine_client, tenant_a_id, tenant_b_id, scan_run_id_a):
    # Tenant B must NOT be able to see Tenant A's findings
    response = engine_client.get(
        f"/api/v1/findings?scan_run_id={scan_run_id_a}",
        headers={"X-Auth-Context": build_auth_context(tenant_id=tenant_b_id)}
    )
    # Either 403 or empty results — never Tenant A's data
    if response.status_code == 200:
        findings = response.json().get('findings', [])
        for finding in findings:
            assert finding['tenant_id'] == str(tenant_b_id), \
                f"Tenant isolation breach: found tenant_a data in tenant_b response"
```

### `strip_sensitive_fields` Test

```python
def test_credential_ref_stripped_for_viewer(engine_client, viewer_token, scan_run_id):
    response = engine_client.get(
        f"/api/v1/findings?scan_run_id={scan_run_id}",
        headers={"X-Auth-Context": build_auth_context(role='viewer', token=viewer_token)}
    )
    for finding in response.json().get('findings', []):
        assert 'credential_ref' not in finding, "credential_ref must be stripped for viewer role"
```

---

## Level 5 — Scan Pipeline E2E Tests

### Scope

Full Argo pipeline run: Discovery → Inventory → Check → Threat → Compliance/IAM/DataSec/Network (parallel) → Risk. Verifies finding counts at each stage and `scan_run_id` threading.

### Pipeline Validation Checklist

After every full scan triggered with a known `scan_run_id`:

```python
PIPELINE_VALIDATION = {
    'discovery': {
        'table': 'discovery_findings',
        'db': 'threat_engine_discoveries',
        'min_rows': 1,
        'required_columns': STANDARD_COLUMNS,
    },
    'inventory': {
        'table': 'inventory_items',
        'db': 'threat_engine_inventory',
        'min_rows': 1,
    },
    'check': {
        'table': 'check_findings',
        'db': 'threat_engine_check',
        'min_rows': 1,
        'verify': lambda rows: all(r['status'] in ('PASS', 'FAIL') for r in rows),
    },
    'threat': {
        'table': 'threat_findings',
        'db': 'threat_engine_threat',
        'min_rows': 0,  # may be 0 if no threats detected — verify not an error
        'verify': lambda rows: all(r['finding_id'] is not None for r in rows),
    },
    'compliance': {
        'table': 'compliance_scores',
        'db': 'threat_engine_compliance',
        'min_rows': 1,
    },
    'risk': {
        'table': 'risk_summary',
        'db': 'threat_engine_risk', 
        'min_rows': 1,
        'verify': lambda rows: all(0 <= r['risk_score'] <= 100 for r in rows),
    },
}

def test_pipeline_e2e(scan_run_id):
    for engine, spec in PIPELINE_VALIDATION.items():
        rows = query_db(spec['db'], spec['table'], scan_run_id)
        assert len(rows) >= spec['min_rows'], f"{engine}: expected >={spec['min_rows']} rows, got {len(rows)}"
        if 'verify' in spec:
            assert spec['verify'](rows), f"{engine}: data verification failed"
        # Verify scan_run_id is correctly threaded
        for row in rows:
            assert row['scan_run_id'] == scan_run_id, f"{engine}: scan_run_id mismatch"
```

### scan_orchestration Completeness Check

```python
def test_scan_orchestration_complete(scan_run_id):
    row = query_scan_orchestration(scan_run_id)
    assert row['status'] == 'completed'
    completed = row['engines_completed']  # JSONB — already a dict/list
    for engine in ['discovery', 'inventory', 'check', 'threat', 'compliance', 'risk']:
        assert engine in completed, f"Engine '{engine}' not marked complete in scan_orchestration"
```

---

## Level 6 — Rule Regression Tests

### Why

Adding one check rule can change compliance scores for existing accounts. Rule regressions must be caught before production.

### Pattern

```python
BASELINE_FILE = 'tests/baselines/rule_finding_counts.json'

def test_rule_regression(scan_run_id, provider='aws'):
    """After adding a new rule, all previously-existing rules must find same count of resources."""
    current_counts = query_rule_finding_counts(scan_run_id, provider)
    
    with open(BASELINE_FILE) as f:
        baseline = json.load(f)
    
    for rule_id, baseline_count in baseline.items():
        current = current_counts.get(rule_id, 0)
        assert current == baseline_count, \
            f"Rule regression: {rule_id} found {current} resources, baseline was {baseline_count}"

def update_baseline(scan_run_id, provider='aws'):
    """Run this manually after intentional rule changes to update baseline."""
    counts = query_rule_finding_counts(scan_run_id, provider)
    with open(BASELINE_FILE, 'w') as f:
        json.dump(counts, f, indent=2)
```

### Trigger

Run rule regression tests whenever:
- A new check rule is added to `catalog/rule/`
- An existing rule's severity or logic changes
- The check engine is rebuilt

---

## Level 7 — UI Smoke Tests

### Scope

Every page in `frontend/src/app/` loads without errors. Charts render. Severity colors match constitution. No console errors. No blank data states that should have data.

### Tool

Playwright (preferred) or Cypress.

### Minimum Smoke Test per Page

```typescript
test(`${pageName} loads without error`, async ({ page }) => {
  await page.goto(`http://localhost:3000/${pageName}`);
  
  // No unhandled errors
  page.on('console', msg => {
    if (msg.type() === 'error') throw new Error(`Console error on ${pageName}: ${msg.text()}`);
  });
  
  // Skeleton screens appear (not blank)
  await expect(page.locator('[data-testid="skeleton"]').first()).toBeVisible();
  
  // KPI cards render (after load)
  await page.waitForSelector('[data-testid="kpi-card"]', { timeout: 5000 });
  
  // Severity badges use correct colors
  const badge = page.locator('[data-testid="severity-badge-critical"]').first();
  if (await badge.isVisible()) {
    const color = await badge.evaluate(el => getComputedStyle(el).backgroundColor);
    expect(color).toContain('239, 68, 68'); // #ef4444 = rgb(239,68,68)
  }
});
```

### Standards

- Run against a seeded environment with a known scan_run_id.
- Every new engine page must have a smoke test added before it ships.
- Smoke tests run as part of post-deploy validation (Level 10).

---

## Level 8 — Performance Baselines

### Targets (non-negotiable for competitive parity with Wiz/Orca)

| Metric | Target | Critical Threshold |
|---|---|---|
| BFF view response time | < 500ms p95 | > 2000ms = blocking |
| Dashboard load time (full page) | < 2000ms | > 5000ms = blocking |
| Engine findings API (page 1, 25 rows) | < 200ms p95 | > 1000ms = blocking |
| Full scan (AWS, ~500 resources) | < 10 minutes | > 30 minutes = blocking |
| Discovery engine throughput | > 400 resources/second | < 100/sec = blocking |
| DB query (findings by scan_run_id) | < 50ms p95 | > 500ms = blocking |

### Tool

`k6` for API load testing. Lighthouse for UI performance.

```javascript
// k6 script — BFF view baseline
import http from 'k6/http';
import { check } from 'k6';

export let options = { vus: 10, duration: '30s' };

export default function() {
  let res = http.get('http://localhost:8000/gateway/api/v1/views/threats', {
    headers: { 'Cookie': `access_token=${__ENV.TOKEN}` }
  });
  check(res, {
    'status 200': (r) => r.status === 200,
    'latency < 500ms': (r) => r.timings.duration < 500,
  });
}
```

---

## Level 9 — Security Tests

### Scope

Not a replacement for `bmad-security-reviewer` code review — these are automated tests that run on every build.

### Test Suite

```python
SECURITY_TESTS = [
    # SQL Injection
    {
        'name': 'sql_injection_scan_run_id',
        'payload': {'scan_run_id': "'; DROP TABLE check_findings; --"},
        'expect': 422,  # Pydantic validation catches it; never 500
    },
    # SSRF via account_id
    {
        'name': 'ssrf_account_id',
        'payload': {'account_id': 'http://169.254.169.254/latest/meta-data/'},
        'expect': 422,
    },
    # Auth bypass — no token
    {
        'name': 'no_auth_token',
        'headers': {},
        'expect': 401,
    },
    # Wrong tenant
    {
        'name': 'cross_tenant_access',
        'headers': {'X-Auth-Context': build_auth_context(tenant_id=WRONG_TENANT)},
        'expect_empty': True,  # 200 but empty results OR 403
    },
    # Viewer accessing restricted engine
    {
        'name': 'viewer_datasec_access',
        'role': 'viewer',
        'engine': 'datasec',
        'expect': 403,
    },
]
```

### Run

```bash
pytest tests/security/ -v --timeout=30
```

---

## Level 10 — Post-Deploy Validation

**This runs automatically after every `kubectl rollout status` returns success.**

### Checklist (agent: `cspm-deploy` runs these after every deploy)

```bash
# 1. Health check — liveness
curl http://engine-<name>:80/api/v1/health/live → expect {"status": "ok"}

# 2. Health check — readiness (verifies DB connection)
curl http://engine-<name>:80/api/v1/health/ready → expect {"status": "ready"}

# 3. Log check — no ERROR lines in first 60 seconds
kubectl logs -l app=engine-<name> -n threat-engine-engines --since=60s | grep -c "ERROR" → expect 0

# 4. BFF smoke — if engine feeds a BFF view
curl /gateway/api/v1/views/<page> → expect 200 with non-null kpi_cards

# 5. Scan_run_id threading — re-query latest scan_run_id findings for this engine
kubectl exec deployment/<engine> -n threat-engine-engines -- python3 -c "
from engine_common.db import get_connection
conn = get_connection()
cur = conn.cursor()
cur.execute('SELECT COUNT(*) FROM <findings_table> WHERE scan_run_id = (SELECT MAX(scan_run_id) FROM <findings_table>)')
print(cur.fetchone()[0])
" → expect > 0 (if scan has run)
```

---

## Quality Gates — Full Sequence

This is the mandatory sequence. Every gate must pass before the next opens.

```
CODE WRITTEN
     │
     ▼
[Gate 0] Static Analysis
  cspm-standards-guardian: constitution grep checks
  ruff linting, mypy types
  ─ FAIL → fix before continuing ─
     │
     ▼
[Gate 1] Unit Tests
  pytest tests/ (unit only, no DB)
  ─ FAIL → fix before continuing ─
     │
     ▼
[Gate 2] Code Review
  cspm-code-reviewer: CSPM patterns (JSONB, tenant_id, standard columns, BFF split)
  ─ FAIL → fix before continuing ─
     │
     ▼
[Gate 3] Security Review
  cspm-security-reviewer: CSPM security (tenant isolation, no-bypass, credential_ref)
  bmad-security-reviewer: OWASP Top 10, SLSA, CCM domain
  /security-review skill: full branch security scan
  ─ FAIL → fix before continuing ─
     │
     ▼
[Gate 4] Integration Tests
  pytest tests/integration/ (real DB, real engine)
  BFF contract tests: pytest tests/bff/
  RBAC tests: all 5 roles × affected endpoints
  ─ FAIL → fix before continuing ─
     │
     ▼
[Gate 5] QA Acceptance
  cspm-qa-engineer: scan validation — findings in DB, BFF view shape
  bmad-qa: formal AC verification against story file
  ─ FAIL → fix before continuing ─
     │
     ▼
[Gate 6] Deploy
  /cspm-deploy: build → push → apply → rollout → logs
     │
     ▼
[Gate 7] Post-Deploy Validation
  cspm-deploy: health checks, log check, BFF smoke, findings count
  ─ FAIL → immediate rollback ─
     │
     ▼
DONE ✓
```

---

## Agent Assignments for Testing

| Test Type | Agent | Skill |
|---|---|---|
| Static analysis / constitution check | `cspm-standards-guardian` | `/cspm-review` |
| Unit test authoring | `cspm-<engine>-engineer` + `bmad-dev` | — |
| BFF contract test authoring | `cspm-bff-dev` | — |
| Engine integration test authoring | `cspm-<engine>-engineer` | — |
| RBAC test authoring | `cspm-rbac-guardian` | — |
| Pipeline E2E test authoring | `cspm-pipeline-engineer` + `cspm-qa-engineer` | — |
| Rule regression test authoring | `cspm-rule-catalog-engineer` | — |
| UI smoke test authoring | `cspm-ui-dev` | — |
| Performance test authoring | `cspm-qa-engineer` | — |
| Security test authoring | `cspm-security-reviewer` + `bmad-security-reviewer` | `/security-review` |
| Post-deploy validation | `cspm-deploy` (automated) | `/cspm-deploy` |
| E2E test generation (new feature) | `bmad-qa-generate-e2e-tests` | — |
| Edge case hunting | `bmad-review-edge-case-hunter` | — |
| Adversarial review | `bmad-review-adversarial-general` | — |
| Formal AC verification | `cspm-qa-engineer` + `bmad-qa` | `/cspm-qa-validate` |

---

## Test File Locations — Canonical Map

```
tests/
├── conftest.py                         ← shared fixtures: DB connections, scan_run_id, tenant factories
├── requirements.txt                    ← pytest, playwright, k6 config
│
├── unit/                               ← Level 1: no external deps
│   ├── test_rule_evaluation.py
│   ├── test_bff_transforms.py
│   ├── test_severity_mapping.py
│   └── test_api_models.py
│
├── integration/                        ← Level 2: real DB per engine
│   ├── test_discoveries_engine/
│   ├── test_check_engine/
│   ├── test_inventory_engine/
│   ├── test_threat_engine/
│   ├── test_compliance_engine/
│   ├── test_network_engine/
│   ├── test_iam_engine/
│   ├── test_ciem_engine/
│   ├── test_risk_engine/
│   └── shared/
│       └── test_standard_columns.py    ← runs against ALL engine tables
│
├── bff/                                ← Level 3: BFF contracts
│   ├── bff_shape_validator.py          ← shared validator utility
│   ├── test_dashboard_view.py
│   ├── test_threats_view.py
│   ├── test_compliance_view.py
│   ├── test_inventory_view.py
│   ├── test_network_view.py
│   └── ... (one per BFF view handler)
│
├── rbac/                               ← Level 4: RBAC + tenant isolation
│   ├── test_role_permissions.py        ← all 5 roles × 27 permissions
│   ├── test_tenant_isolation.py        ← cross-tenant data leakage
│   └── test_strip_sensitive_fields.py  ← credential_ref stripping
│
├── e2e/                                ← Level 5: full pipeline
│   ├── test_pipeline_e2e.py            ← Discovery → Risk with real scan_run_id
│   └── test_scan_orchestration.py      ← completeness check in scan_orchestration
│
├── regression/                         ← Level 6: rule regression
│   ├── test_rule_regression.py
│   └── baselines/
│       └── rule_finding_counts.json    ← baseline counts per rule_id
│
├── ui/                                 ← Level 7: Playwright smoke tests
│   ├── playwright.config.ts
│   └── smoke/
│       ├── test_dashboard.spec.ts
│       ├── test_threats.spec.ts
│       └── ... (one per page)
│
├── performance/                        ← Level 8: k6 load tests
│   ├── bff_latency.js
│   └── scan_throughput.js
│
├── security/                           ← Level 9: automated security tests
│   ├── test_sql_injection.py
│   ├── test_ssrf.py
│   ├── test_auth_bypass.py
│   └── test_tenant_leakage.py
│
└── post_deploy/                        ← Level 10: post-deploy checks
    └── validate_deploy.sh              ← health + log + BFF smoke
```

---

## Quality Metrics — What Good Looks Like

| Metric | Target |
|---|---|
| Unit test coverage (engine logic) | > 80% |
| BFF view contract coverage | 100% — every view has a contract test |
| RBAC test coverage | 100% — all 5 roles × all engine endpoints |
| Pipeline E2E pass rate | 100% on latest scan_run_id |
| Rule regression failures | 0 — baseline must not drift |
| Post-deploy health check pass rate | 100% — any failure triggers rollback |
| Critical/High security test failures | 0 — zero tolerance |
| BFF response time p95 | < 500ms |
| Dashboard load time | < 2000ms |
