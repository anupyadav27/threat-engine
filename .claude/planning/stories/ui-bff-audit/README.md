# UI→BFF→Engine Verified Data Chain — Master Sprint Plan

## Goal

Every UI element on every page must trace to a verified data source:
`UI field → BFF handler line → DB table/column or engine endpoint`

No hardcoded mocks, no fabricated fallbacks, no direct engine calls from the browser for aggregation/summary data.

## Audit Summary (2026-05-16)

All ~40 security pages audited. Gaps found:

| Category | Count | Severity |
|----------|-------|----------|
| Pages bypassing BFF entirely | 3 | P1 Critical |
| Direct engine calls in page (no BFF) | 5 | P1 Critical |
| BFF fabricates/synthesizes data | 2 | P1 Constitution violation |
| Missing engine writers to security_findings | 5 | P1 |
| BFF reads from engine HTTP (not DB) | 7 | P2 |
| Missing/incomplete field mappings | 2 | P2 |
| Empty state / graceful handling gaps | 4 | P3 |

Pages with **no gaps** (fully verified):
- `/threats/*` (all 7 pages)
- `/inventory/[assetId]`, `/inventory/architecture`
- `/iam`, `/cdr`, `/cdr/identity/[principal]`
- `/container-security`, `/database-security`, `/ai-security`, `/api-security`
- `/cnapp`, `/cwpp`, `/suppressions`, `/scans/[scanId]`

---

## Delivery Sequence

### Sprint UIBFF-S01 — Fix Empty Sparklines (P1, ~1 week)

| Story | Title | Points | Status |
|-------|-------|--------|--------|
| [UIBFF-S01-01](UIBFF-S01-01-scan-history-trend.md) | BFF `fetch_scan_trend()` helper + wire inventory/misconfig/dashboard | 3 | ✅ ready-for-dev |
| [UIBFF-S01-02](UIBFF-S01-02-dashboard-mock-removal.md) | Remove 10+ hardcoded mock fallbacks from dashboard page | 5 | ✅ ready-for-dev |

**Build order:** S01-01 first (scan trend helper), then S01-02 (dashboard wires it).
**Gate:** After S01-01+S01-02 deploy — load dashboard after 2 scans, verify no sine wave.

---

### Sprint UIBFF-WRITER — Fill Missing Engine Writers (P1, ~1 week)

| Story | Title | Points | Status |
|-------|-------|--------|--------|
| [UIBFF-WRITER-01](UIBFF-WRITER-01-vuln-security-findings-writer.md) | Vulnerability → security_findings (requires deferred migration first) | 5 | ✅ ready-for-dev |
| [UIBFF-WRITER-02](UIBFF-WRITER-02-secops-security-findings-writer.md) | SecOps SAST+DAST → security_findings | 3 | ✅ ready-for-dev |
| [UIBFF-WRITER-03](UIBFF-WRITER-03-dbsec-security-findings-writer.md) | DBSec → security_findings | 2 | ✅ ready-for-dev |
| [UIBFF-WRITER-04](UIBFF-WRITER-04-encryption-security-findings-writer.md) | Encryption → security_findings | 2 | ✅ ready-for-dev |
| [UIBFF-WRITER-05](UIBFF-WRITER-05-ai-security-findings-writer.md) | AI Security → security_findings | 2 | ✅ ready-for-dev |

**Build order:** WRITER-03/04/05 can run in parallel. WRITER-01 blocked on vuln migration.
**Gate:** After all writers — query `SELECT source_engine, COUNT(*) FROM security_findings GROUP BY source_engine` — should show all 12 engines.

---

### Sprint UIBFF-FIX — Direct Engine Call Elimination (P1/P2, ~1.5 weeks)

| Story | Title | Points | Status |
|-------|-------|--------|--------|
| [UIBFF-FIX-01](UIBFF-FIX-01-compliance-control-bff-wrapper.md) | Compliance control detail — wrap direct engine calls in BFF | 3 | ✅ ready-for-dev |
| [UIBFF-FIX-02](UIBFF-FIX-02-risk-mitigation-synthetic-data.md) | Risk BFF — remove synthetic mitigation roadmap fallback | 2 | ✅ ready-for-dev |
| [UIBFF-FIX-03](UIBFF-FIX-03-datasec-lineage-chains-fix.md) | DataSec lineage — verify and fix lineage_chains structure | 2 | ✅ ready-for-dev |
| [UIBFF-FIX-04](UIBFF-FIX-04-encryption-key-detail-bff.md) | Encryption key detail — wrap direct engine calls in BFF | 3 | ✅ ready-for-dev |
| [UIBFF-FIX-05](UIBFF-FIX-05-vulnerability-page-bff-migration.md) | Vulnerability page — migrate from vulnFetch to BFF | 3 | ✅ ready-for-dev |
| [UIBFF-FIX-06](UIBFF-FIX-06-secops-findings-bff.md) | SecOps — create BFF findings endpoint, remove direct calls | 5 | ✅ ready-for-dev |
| [UIBFF-FIX-07](UIBFF-FIX-07-scans-page-bff-migration.md) | Scans page — migrate from 3 direct engine calls to BFF | 3 | ✅ ready-for-dev |
| [UIBFF-FIX-08](UIBFF-FIX-08-policies-page-fix.md) | Policies page — fix critical data mismatch (BFF returns wrong data) | 3 | ✅ ready-for-dev |
| [UIBFF-FIX-09](UIBFF-FIX-09-accounts-page-bff-migration.md) | Accounts page — migrate from raw fetch to BFF | 2 | ✅ ready-for-dev |

**Build order:** FIX-02/03 (no dependencies), FIX-01/04/07/09 (gateway changes only), FIX-05/06/08 (frontend + gateway).
**Gate:** `grep -rn "getFromEngine\|vulnFetch\|fetch.*gateway" frontend/src/app/` — count should be ~0 for aggregation/summary fetches.

---

### Sprint UIBFF-BFF — Shared Query Layer (P1, ~0.5 week)

| Story | Title | Points | Status |
|-------|-------|--------|--------|
| [UIBFF-BFF-01](UIBFF-BFF-01-read-findings-shared-helper.md) | `read_findings()` shared DB helper in BFF `_shared.py` | 3 | ✅ ready-for-dev |
| [UIBFF-BFF-02](UIBFF-BFF-02-read-posture-shared-helper.md) | `read_posture()` shared DB helper in BFF `_shared.py` | 2 | ✅ ready-for-dev |

**Build order:** BFF-01 first (used by BFF-02 tests pattern), then BFF-02.
**Gate:** `pytest shared/api_gateway/bff/tests/test_read_findings.py test_read_posture.py -v` — all green.

---

### Sprint UIBFF-ARCH — Two-Table BFF Architecture Migration (P2, ~2 weeks)

| Story | Title | Points | Status |
|-------|-------|--------|--------|
| [UIBFF-ARCH-01](UIBFF-ARCH-01-misconfig-bff-migrate.md) | Misconfig BFF — migrate to security_findings | 3 | ✅ ready-for-dev |
| [UIBFF-ARCH-02](UIBFF-ARCH-02-iam-bff-migrate.md) | IAM BFF — migrate to security_findings + resource_security_posture | 3 | ✅ ready-for-dev |
| [UIBFF-ARCH-03](UIBFF-ARCH-03-network-datasec-bff-migrate.md) | Network-Security + DataSec BFF — migrate to security_findings | 3 | ✅ ready-for-dev |
| [UIBFF-ARCH-04](UIBFF-ARCH-04-cdr-encryption-container-bff-migrate.md) | CDR + Encryption + Container BFF — migrate to security_findings | 3 | ✅ ready-for-dev |
| [UIBFF-ARCH-05](UIBFF-ARCH-05-inventory-dashboard-bff-migrate.md) | Inventory + Dashboard — add scanTrend + posture summary from tables | 3 | ✅ ready-for-dev |
| [UIBFF-ARCH-06](UIBFF-ARCH-06-remove-ui-data-endpoints.md) | Remove /ui-data endpoints from engines (post-migration cleanup) | 2 | ✅ ready-for-dev |

**Build order:** ARCH-01 through ARCH-05 can run in parallel (different BFF files). ARCH-06 is last — only after all migrations verified.
**Gate:** Kill one engine pod at a time — its page must still load from DB.

---

## Complete Story List (27 stories)

| # | Story ID | Sprint | Points | Priority |
|---|----------|--------|--------|----------|
| 1 | UIBFF-S01-01 | S01 | 3 | P1 ✅ done |
| 2 | UIBFF-S01-02 | S01 | 5 | P1 |
| 3 | UIBFF-WRITER-01 | WRITER | 5 | P1 |
| 4 | UIBFF-WRITER-02 | WRITER | 3 | P1 |
| 5 | UIBFF-WRITER-03 | WRITER | 2 | P1 |
| 6 | UIBFF-WRITER-04 | WRITER | 2 | P1 |
| 7 | UIBFF-WRITER-05 | WRITER | 2 | P1 |
| 8 | UIBFF-FIX-01 | FIX | 3 | P1 |
| 9 | UIBFF-FIX-02 | FIX | 2 | P1 |
| 10 | UIBFF-FIX-03 | FIX | 2 | P2 |
| 11 | UIBFF-FIX-04 | FIX | 3 | P1 |
| 12 | UIBFF-FIX-05 | FIX | 3 | P1 |
| 13 | UIBFF-FIX-06 | FIX | 5 | P1 |
| 14 | UIBFF-FIX-07 | FIX | 3 | P1 |
| 15 | UIBFF-FIX-08 | FIX | 3 | P1 |
| 16 | UIBFF-FIX-09 | FIX | 2 | P1 |
| 17 | UIBFF-BFF-01 | BFF | 3 | P1 |
| 18 | UIBFF-BFF-02 | BFF | 2 | P1 |
| 19 | UIBFF-ARCH-01 | ARCH | 3 | P2 |
| 20 | UIBFF-ARCH-02 | ARCH | 3 | P2 |
| 21 | UIBFF-ARCH-03 | ARCH | 3 | P2 |
| 22 | UIBFF-ARCH-04 | ARCH | 3 | P2 |
| 23 | UIBFF-ARCH-05 | ARCH | 3 | P2 |
| 24 | UIBFF-ARCH-06 | ARCH | 2 | P3 |

**Total: 69 story points across 24 stories (+ 1 done = 25)**

---

## How to Test Each Story (End-to-End Validation)

See **[TESTING-GUIDE.md](TESTING-GUIDE.md)** for the complete test procedure for each story.

Quick reference:

### Testing BFF Field Coverage (per page)
```bash
# 1. Port-forward to gateway
kubectl port-forward svc/api-gateway 8000:80 -n threat-engine-engines

# 2. Get a valid token (log in via UI, copy access_token cookie)
TOKEN="<paste token here>"

# 3. Fetch BFF view
python3 -c "
import urllib.request, json
req = urllib.request.Request(
    'http://localhost:8000/api/v1/views/<PAGE_NAME>',
    headers={'Cookie': f'access_token={TOKEN}'}
)
with urllib.request.urlopen(req) as r:
    data = json.loads(r.read())
    print(json.dumps(list(data.keys()), indent=2))
    # Then check specific fields:
    print('findings count:', len(data.get('findings', [])))
    print('scanTrend count:', len(data.get('scanTrend', [])))
"
```

### Testing Direct Engine Call Elimination
```bash
# After each FIX story, verify no direct engine calls remain:
grep -rn "getFromEngine\|vulnFetch\|fetch.*'/gateway/api" frontend/src/app/<PAGE>/
# Expected: 0 hits for aggregation/summary fetches (mutations are ok)
```

### Testing Tenant Isolation
```bash
# Connect to inventory DB and verify tenant scope:
kubectl exec -n threat-engine-engines deployment/inventory-engine -- python3 -c "
from engine_common.db_connections import get_inventory_conn
with get_inventory_conn() as c:
    with c.cursor() as cur:
        cur.execute('SELECT tenant_id, source_engine, COUNT(*) FROM security_findings GROUP BY tenant_id, source_engine ORDER BY tenant_id')
        for row in cur.fetchall():
            print(row)
"
```

### Testing Engine Resilience (after ARCH stories)
```bash
# Kill an engine, verify BFF still serves data from DB:
kubectl scale deployment engine-iam --replicas=0 -n threat-engine-engines
# Load /iam page in browser — should show data from security_findings
kubectl scale deployment engine-iam --replicas=1 -n threat-engine-engines
kubectl rollout status deployment/engine-iam -n threat-engine-engines
```

---

## Completion Criteria for Entire Epic

- [ ] `grep -rn "MOCK_\|mockTrend\|mockSvcEntries" frontend/src/app/dashboard/` → 0 hits
- [ ] `SELECT source_engine, COUNT(*) FROM security_findings GROUP BY source_engine` shows all 12 engines
- [ ] Every page listed in audit loads without error after all engine pods killed and restarted
- [ ] `grep -rn "getFromEngine" frontend/src/app/` → only mutations remain (RunNow, suppress, lift)
- [ ] `grep -rn "/ui-data" shared/api_gateway/bff/` → 0 hits
- [ ] All 24 story Definition of Done checklists completed