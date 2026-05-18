# UI→BFF→Engine Chain Testing Guide

## The Core Question

> "How do we test which elements from UI to BFF to engine are failing, returning no data, partial data, or missing required fields — after each build?"

This guide gives you a systematic 4-level approach to verify the entire chain.

---

## Level 1 — BFF Response Verification (Run After Every Gateway Deploy)

Fetch every BFF view directly and check that required top-level fields are present and non-empty.

### Setup (once per session)
```bash
# Port-forward gateway
kubectl port-forward svc/api-gateway 8000:80 -n threat-engine-engines &

# Get a token — log in via browser at http://localhost:3000
# Open DevTools → Application → Cookies → copy access_token value
TOKEN="eyJ..."   # paste here
```

### Run BFF health check for every page
```bash
python3 << 'EOF'
import urllib.request, json, sys

TOKEN = "PASTE_TOKEN_HERE"
BASE = "http://localhost:8000/api/v1/views"

# page → required fields → min item count
CHECKS = [
    ("misconfig",             ["kpiGroups", "findings", "scanTrend"],                  0),
    ("inventory",             ["assets", "summary", "scanTrend"],                      0),
    ("dashboard",             ["kpi", "trendData", "frameworks", "cloud_providers"],   0),
    ("iam",                   ["kpiGroups", "findings", "identities", "roles"],        0),
    ("cdr",                   ["kpiGroups", "findings", "identities"],                 0),
    ("network-security",      ["kpiGroups", "findings", "topology"],                   0),
    ("datasec",               ["findings", "catalog"],                                 0),
    ("encryption",            ["findings", "keys", "certificates"],                    0),
    ("container-security",    ["findings", "clusters"],                                0),
    ("database-security",     ["findings", "databases"],                               0),
    ("ai-security",           ["findings", "inventory", "coverage"],                   0),
    ("api_security",          ["report", "findings"],                                  0),
    ("risk",                  ["kpiGroups", "riskScore", "riskCategories"],             0),
    ("compliance",            ["frameworks"],                                           0),
    ("vulnerability",         ["agents", "scanSummary"],                               0),
    ("secops",                ["sastScans", "dastScans", "summary"],                   0),
    ("rules",                 ["rules", "summary"],                                    0),
    ("scans",                 ["scans", "schedules"],                                  0),
    ("suppressions",          ["rule_suppressions", "finding_suppressions"],           0),
    ("policies",              ["policies", "kpi"],                                     0),
    ("attack-paths",          ["kpis", "paths"],                                       0),
    ("onboarding/cloud_accounts", ["accounts"],                                        0),
]

results = []
for page, required_fields, min_count in CHECKS:
    url = f"{BASE}/{page}"
    try:
        req = urllib.request.Request(url, headers={"Cookie": f"access_token={TOKEN}"})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
        
        missing = [f for f in required_fields if f not in data]
        empty   = [f for f in required_fields if f in data and data[f] == [] or data[f] == {}]
        
        status = "OK" if not missing else "MISSING_FIELDS"
        results.append((page, status, missing, empty))
    except Exception as e:
        results.append((page, f"ERROR: {e}", [], []))

# Print report
print("\n=== BFF VIEW HEALTH CHECK ===\n")
print(f"{'Page':<35} {'Status':<20} {'Missing Fields':<30} {'Empty Fields'}")
print("-" * 100)
for page, status, missing, empty in results:
    icon = "✅" if status == "OK" else "❌"
    print(f"{icon} {page:<33} {status:<20} {str(missing):<30} {str(empty)}")

failures = [r for r in results if r[1] != "OK"]
print(f"\n{len(failures)}/{len(results)} views have issues")
EOF
```

**What to look for:**
- `MISSING_FIELDS` → the BFF handler does not return that field — check BFF code
- `ERROR` → BFF view doesn't exist or engine is down
- `empty fields` → BFF returned the field but it's `[]` or `{}` — could be no data or broken engine call

---

## Level 2 — Field-Level Depth Check (Run After BFF Passes Level 1)

For pages that pass Level 1 (fields present), check that the fields have the right shape and values.

```bash
python3 << 'EOF'
import urllib.request, json

TOKEN = "PASTE_TOKEN_HERE"
BASE = "http://localhost:8000/api/v1/views"

def fetch(page, params=""):
    req = urllib.request.Request(
        f"{BASE}/{page}{params}",
        headers={"Cookie": f"access_token={TOKEN}"}
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())

print("\n=== FIELD DEPTH CHECK ===\n")

# 1. Check findings have required sub-fields
findings_pages = ["misconfig", "iam", "network-security", "datasec", "cdr", "encryption"]
FINDING_REQUIRED = ["severity", "title", "resource_uid", "rule_id", "posture_category", "status"]

for page in findings_pages:
    data = fetch(page)
    findings = data.get("findings", [])
    if not findings:
        print(f"⚠️  {page}: findings empty — no data or engine not writing to security_findings")
        continue
    f = findings[0]
    missing = [k for k in FINDING_REQUIRED if k not in f or f[k] is None]
    if missing:
        print(f"❌ {page}: finding[0] missing sub-fields: {missing}")
    else:
        print(f"✅ {page}: finding shape OK ({len(findings)} findings, severities: {set(f['severity'] for f in findings[:10])})")

# 2. Check scanTrend shape
trend_pages = ["misconfig", "inventory", "iam", "network-security", "cdr", "encryption"]
for page in trend_pages:
    data = fetch(page)
    trend = data.get("scanTrend", [])
    if not trend:
        print(f"⚠️  {page}: scanTrend empty — no completed scans or fetch_scan_trend not wired")
        continue
    t = trend[0]
    missing = [k for k in ["date", "total", "critical"] if k not in t]
    if missing:
        print(f"❌ {page}: scanTrend[0] missing: {missing}")
    else:
        print(f"✅ {page}: scanTrend OK ({len(trend)} data points)")

# 3. Check dashboard has no mock sine-wave pattern
data = fetch("dashboard")
trend = data.get("trendData", [])
if len(trend) >= 3:
    # Sine wave has perfectly alternating values — real data won't
    deltas = [abs(trend[i+1].get("total",0) - trend[i].get("total",0)) for i in range(len(trend)-1)]
    max_delta = max(deltas) if deltas else 0
    if max_delta > 0 and max_delta == min(deltas):
        print("❌ dashboard: trendData looks like a sine wave (perfectly regular deltas)")
    elif not trend:
        print("⚠️  dashboard: trendData empty — no scan history yet")
    else:
        print(f"✅ dashboard: trendData has real data ({len(trend)} points)")

EOF
```

---

## Level 3 — Direct Engine Call Audit (Run After Each FIX Story)

Verify the frontend is no longer calling engines directly for summary/aggregation data.

```bash
echo "=== DIRECT ENGINE CALL AUDIT ==="

# These patterns should return 0 hits after all FIX stories ship:
echo ""
echo "getFromEngine for aggregation data (should be 0):"
grep -rn "getFromEngine" /Users/apple/Desktop/threat-engine/frontend/src/app/ \
  | grep -v "// mutation\|RunNow\|suppress\|lift\|delete\|post\|POST" \
  | grep -v ".test.\|test/" \
  | wc -l

echo ""
echo "vulnFetch calls (should be 0 for summary endpoints):"
grep -rn "vulnFetch.*agents\|vulnFetch.*stats\|vulnFetch.*scans" \
  /Users/apple/Desktop/threat-engine/frontend/src/app/ | wc -l

echo ""
echo "Raw fetch to gateway (should be 0 for data fetches):"
grep -rn "fetch.*'/gateway/api/v1/cloud-accounts\|fetch.*'/gateway/api/v1/scan-runs" \
  /Users/apple/Desktop/threat-engine/frontend/src/app/ | wc -l

echo ""
echo "Mock data usage in pages (should be 0):"
grep -rn "MOCK_DASHBOARD\|mockTrend\|mockSvcEntries\|mockFrameworks\|mockAssets\|mockRules" \
  /Users/apple/Desktop/threat-engine/frontend/src/app/ | wc -l

echo ""
echo "BFF fabricated/synthetic data (should be 0):"
grep -rn "MIT-[0-9]\|RISK_SCAN_TREND\|sine\|Math\.sin" \
  /Users/apple/Desktop/threat-engine/shared/api_gateway/bff/ | wc -l
```

---

## Level 4 — Tenant Isolation Verification (Run After Each ARCH Story)

Verify findings are correctly scoped per tenant.

```bash
kubectl exec -n threat-engine-engines deployment/inventory-engine -- python3 << 'EOF'
from engine_common.db_connections import get_inventory_conn

with get_inventory_conn() as conn:
    with conn.cursor() as cur:
        # 1. Findings coverage per engine
        cur.execute("""
            SELECT source_engine, COUNT(*) as findings, COUNT(DISTINCT tenant_id) as tenants
            FROM security_findings
            GROUP BY source_engine
            ORDER BY findings DESC
        """)
        print("\n=== security_findings coverage ===")
        print(f"{'Engine':<20} {'Findings':>10} {'Tenants':>10}")
        print("-" * 42)
        for row in cur.fetchall():
            print(f"{row[0]:<20} {row[1]:>10} {row[2]:>10}")

        # 2. Check tenant_id is never NULL
        cur.execute("SELECT COUNT(*) FROM security_findings WHERE tenant_id IS NULL")
        null_count = cur.fetchone()[0]
        print(f"\nFindings with NULL tenant_id: {null_count} (should be 0)")

        # 3. Posture table coverage
        cur.execute("""
            SELECT COUNT(*) as resources, COUNT(DISTINCT tenant_id) as tenants,
                   COUNT(CASE WHEN overall_posture_score IS NOT NULL THEN 1 END) as has_score
            FROM resource_security_posture
        """)
        row = cur.fetchone()
        print(f"\n=== resource_security_posture ===")
        print(f"Total resources: {row[0]}, Tenants: {row[1]}, With posture score: {row[2]}")
EOF
```

---

## Level 5 — Engine Resilience Check (Run After ARCH Stories)

Kill each engine one by one and verify the corresponding page still loads.

```bash
for engine in engine-iam engine-network-security engine-datasec engine-cdr engine-encryption engine-container-sec; do
  echo ""
  echo "=== Testing resilience: killing $engine ==="
  kubectl scale deployment $engine --replicas=0 -n threat-engine-engines
  sleep 5

  # BFF fetch (replace with actual page name)
  PAGE=$(echo $engine | sed 's/engine-//' | sed 's/-security//')
  python3 -c "
import urllib.request, json
TOKEN = 'PASTE_TOKEN'
req = urllib.request.Request(
    f'http://localhost:8000/api/v1/views/$PAGE',
    headers={'Cookie': f'access_token={TOKEN}'}
)
try:
    with urllib.request.urlopen(req, timeout=5) as r:
        data = json.loads(r.read())
        findings = data.get('findings', [])
        print(f'✅ $PAGE still works: {len(findings)} findings from DB')
except Exception as e:
    print(f'❌ $PAGE FAILED when $engine down: {e}')
"
  kubectl scale deployment $engine --replicas=1 -n threat-engine-engines
  kubectl rollout status deployment/$engine -n threat-engine-engines --timeout=60s
done
```

---

## Quick Pass/Fail Summary Script (Run After Full Epic)

```bash
#!/bin/bash
echo "=== FINAL EPIC COMPLETION CHECK ==="
PASS=0; FAIL=0

check() {
    local desc=$1; local cmd=$2; local expected=$3
    local result=$(eval "$cmd" 2>/dev/null)
    if [ "$result" = "$expected" ]; then
        echo "✅ $desc"
        PASS=$((PASS+1))
    else
        echo "❌ $desc (got: $result, expected: $expected)"
        FAIL=$((FAIL+1))
    fi
}

# Mock data eliminated
check "No MOCK_DASHBOARD in dashboard page" \
  "grep -c 'MOCK_DASHBOARD' /Users/apple/Desktop/threat-engine/frontend/src/app/dashboard/page.jsx" "0"

check "No mockTrend sine wave" \
  "grep -c 'Math\.sin\|mockTrend\|sine.wave' /Users/apple/Desktop/threat-engine/shared/api_gateway/bff/dashboard.py" "0"

check "No synthetic MIT- mitigations" \
  "grep -c 'MIT-' /Users/apple/Desktop/threat-engine/shared/api_gateway/bff/risk.py" "0"

# Direct engine calls eliminated
check "No vulnFetch for summary data" \
  "grep -c 'vulnFetch.*agents\|vulnFetch.*stats' /Users/apple/Desktop/threat-engine/frontend/src/app/vulnerability/page.jsx" "0"

check "No direct scan-runs call in scans page" \
  "grep -c 'getFromEngine.*scan-runs' /Users/apple/Desktop/threat-engine/frontend/src/app/scans/page.jsx" "0"

check "No raw cloud-accounts fetch in accounts page" \
  "grep -c \"fetch.*cloud-accounts\" /Users/apple/Desktop/threat-engine/frontend/src/app/accounts/page.jsx" "0"

# BFF architecture
check "No /ui-data calls in BFF after ARCH migration" \
  "grep -rc '/ui-data' /Users/apple/Desktop/threat-engine/shared/api_gateway/bff/ | grep -v ':0' | wc -l" "0"

echo ""
echo "Results: $PASS passed, $FAIL failed"
```

---

## Common Failure Patterns and Fixes

| Symptom | Root Cause | Fix |
|---------|-----------|-----|
| BFF view returns 500 | Engine is down + no DB fallback | Check engine logs; implement ARCH migration |
| `findings: []` on page with real data | BFF calling wrong engine or engine not writing to security_findings | Check `source_engine` in security_findings table; run WRITER story |
| `scanTrend: []` everywhere | `fetch_scan_trend()` not wired OR scan_orchestration has no completed rows | Wire S01-01; check scan_orchestration table |
| Field present in BFF but `undefined` in UI | Field name mismatch (snake_case vs camelCase) | Check BFF output vs page destructuring |
| `policies: undefined` on /policies page | BFF returns suppressions instead of policies | Run FIX-08 |
| Chart shows fake sine wave | `mockTrend` fallback still active | Run S01-02 |
| KPI shows "—" when data exists | `?? 0` fallback not wired | Remove `?? MOCK_DASHBOARD.x` fallbacks |
| Page crashes on empty array | Missing `|| []` guard or division by zero | Add null guards per FIX stories |
