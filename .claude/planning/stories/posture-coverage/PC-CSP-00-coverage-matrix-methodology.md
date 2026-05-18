# Story PC-CSP-00: CSP × Engine Coverage Matrix — Gap Calculation Methodology + Dashboard

## Status: done

## Metadata
- **Phase**: CSP Coverage Track (runs parallel to Posture Coverage stories)
- **Sprint**: Posture Coverage Enhancement
- **Points**: 5
- **Priority**: P1
- **Depends on**: Nothing — reads existing DB + catalog files
- **Blocks**: All PC-CSP-01..04 (this story establishes the gap baseline; other stories close specific gaps)
- **RACI**: R=DEV A=DL C=SA I=PO,QA

## Purpose

We need a repeatable, automated way to answer: **"For CSP X and engine dimension Y, what percentage of discovered resources have meaningful analysis coverage?"**

This story builds a gap calculation script + BFF endpoint that produces the coverage matrix. Every sprint, the matrix is re-run to show which gaps were closed.

## Actual Coverage State (baseline — 2026-05-16)

Derived from `catalog/rule/{csp}_rule_metadata/` file counts × engine dimension tags + code inspection of providers:

### Check Rule Coverage by Engine Dimension (metadata file counts)

| Engine Dimension | AWS | Azure | GCP | OCI | AliCloud | IBM | K8s |
|-----------------|-----|-------|-----|-----|----------|-----|-----|
| **Network** | 454 | 199 | 96 | 324 | ~71 | 107 | 7 |
| **IAM** | 14 | 11 | 17 | 28 | ~8 | 42 | 5 |
| **DataSec** | 1169 | 81 | 43 | 154 | ~12 | 71 | 11 |
| **Encryption** | 1599 | 381 | 261 | 669 | ~18 | 52 | 81 |
| **DBSec** | 55 | 60 | 21 | 198 | ~5 | **0** | **0** |
| **Container** | 124 | 125 | 109 | 60 | ~6 | 48 | 802 |
| **AI Security** | **0** | **0** | **0** | **0** | **0** | **0** | **0** |

### Network Topology Depth (L1 = check rules only; L2 = full 7-layer topology)

| CSP | L1 (Check Rules) | L2 (Topology) | Status |
|-----|-----------------|---------------|--------|
| AWS | ✅ | ✅ 7-layer | Complete |
| Azure | ✅ | ✅ 7-layer (VNet/NSG/AppGW/WAF/NetworkWatcher) | Complete |
| GCP | ✅ | ✅ 7-layer (VPC/Firewall/Routes/CloudArmor/FlowLogs) | Complete |
| OCI | ✅ | ✅ 7-layer (VCN/SecurityLists/NSG/WAAS/FlowLogs) | Complete |
| AliCloud | ✅ | ✅ 7-layer (VPC/SecurityGroups/SLB/WAF/ActionTrail) | Complete |
| IBM | ✅ | ❌ STUB — provider returns 0 findings | **Gap → PC-P2-03** |
| K8s | ✅ (7 rules only) | ❌ DEFERRED | **Gap → PC-P2-03** |

### Discovery File Coverage

| CSP | Discovery YAML Files | Check Rules | CDR Log Source | Vuln Scanning |
|-----|---------------------|------------|----------------|---------------|
| AWS | 512 | ✅ Full scope | ✅ CloudTrail | ✅ |
| Azure | 350 | ✅ Full scope | ✅ Azure Activity | ✅ |
| GCP | 355 | ✅ Full scope | ✅ GCP Audit Logs | ✅ |
| OCI | 208 | ✅ Full scope | ✅ OCI Audit | ✅ |
| AliCloud | 213 | ✅ Full scope | ✅ ActionTrail | ⚠️ Partial |
| IBM | 112 | ⚠️ 63 service dirs (some stubs) | ✅ IBM COS reader | ⚠️ Partial |
| K8s | 89 | ✅ K8s-specific | ✅ K8s Audit Logs | ✅ (image scan) |

### Posture Signal Coverage (which engines write posture for which CSPs)

| Engine | AWS | Azure | GCP | OCI | AliCloud | IBM | K8s |
|--------|-----|-------|-----|-----|----------|-----|-----|
| IAM | ✅ | ✅* | ✅* | ✅* | ✅* | ✅* | ✅* |
| Network | ✅ | ✅* | ✅* | ✅* | ✅* | ❌ IBM stub | ⚠️ K8s L1 only |
| DataSec | ✅ | ✅* | ✅* | ✅* | ✅* | ✅* | ✅* |
| CDR | ✅ | ✅* | ✅* | ✅* | ✅* | ✅* | ✅* |
| Encryption | ❌ No writer | ❌ No writer | ❌ No writer | ❌ No writer | ❌ No writer | ❌ No writer | ❌ No writer |
| DBSec | ❌ No writer | ❌ No writer | ❌ No writer | ❌ No writer | ❌ No writer | ❌ No writer | ❌ No writer |
| Container | ❌ No writer | ❌ No writer | ❌ No writer | ❌ No writer | ❌ No writer | ❌ No writer | ❌ No writer |
| Vulnerability | ❌ No writer | ❌ No writer | ❌ No writer | ❌ No writer | ❌ No writer | ❌ No writer | ❌ No writer |
| AI Security | ❌ No writer | ❌ No writer | ❌ No writer | ❌ No writer | ❌ No writer | ❌ No writer | ❌ No writer |

*✅ writer exists but produces output only for resources in that CSP's findings — multi-CSP by design.

## How to Calculate Gaps (Methodology)

### Dimension 1: Discovery Coverage %
```sql
-- % of rule_metadata services that have a matching discovery_findings resource_type
SELECT
    provider,
    COUNT(DISTINCT resource_type) AS discovered_types,
    COUNT(DISTINCT rm.service) AS rule_metadata_services,
    ROUND(COUNT(DISTINCT resource_type)::numeric / NULLIF(COUNT(DISTINCT rm.service), 0) * 100, 1) AS coverage_pct
FROM rule_metadata rm
LEFT JOIN discovery_findings df USING (provider)  -- join on service match
WHERE rm.active = true
GROUP BY provider;
```

### Dimension 2: Check Rule Coverage per Engine Dimension
```sql
-- For each (provider, engine_dimension): count rules tagged vs total rules
SELECT
    provider,
    'network' AS dimension,
    COUNT(*) FILTER (WHERE rule_metadata->'network_security'->>'applicable' = 'true') AS tagged,
    COUNT(*) AS total,
    ROUND(COUNT(*) FILTER (...) * 100.0 / COUNT(*), 1) AS pct
FROM rule_metadata WHERE active = true GROUP BY provider
UNION ALL
-- repeat for iam_security, data_security, dbsec, container_security, ai_security
```

### Dimension 3: CDR Log Source Completeness
```python
# Check which CSPs have both:
# 1. A log source reader file in engines/cdr/cdr_engine/reader/
# 2. A MITRE technique mapping in cdr_engine/parser/
# 3. At least 1 CDR finding in cdr_findings WHERE provider = {csp} in last 30 days
```

### Dimension 4: Posture Signal Gap
```sql
-- Check which engine×CSP combinations have zero posture rows after a scan
SELECT provider, 
    BOOL_OR(is_encrypted_at_rest) AS enc_writer_active,
    BOOL_OR(connected_db_count > 0) AS dbsec_writer_active,
    BOOL_OR(has_privileged_container) AS container_writer_active,
    BOOL_OR(vuln_critical_count > 0) AS vuln_writer_active
FROM resource_security_posture
WHERE scan_run_id = <latest_scan_run_id>
GROUP BY provider;
-- Zeros = missing posture writer for that (engine, provider) pair
```

### Dimension 5: Network Topology Depth
```python
# Per CSP: does network_findings have rows with network_modules containing 'topology_analysis'?
# If yes → L2 active. If all rows are from check_findings only → L1 only.
```

## Implementation

### Script: `scripts/generate_coverage_matrix.py`

```python
"""
Run: python3 scripts/generate_coverage_matrix.py > _bmad-output/coverage-matrix.json
Reads: rule_metadata DB, discovery_findings DB, cdr_findings DB, resource_security_posture DB
Outputs: JSON matrix with per-CSP × per-engine coverage scores
"""
```

Output schema:
```json
{
  "generated_at": "2026-05-16T...",
  "scan_run_id": "...",
  "csps": ["aws", "azure", "gcp", "oci", "alicloud", "ibm", "k8s"],
  "engines": ["network", "iam", "datasec", "encryption", "dbsec", "container", "ai_security", "cdr", "vulnerability"],
  "matrix": {
    "aws": {
      "network":    {"rule_count": 454, "topology_depth": "L2", "posture_writer": true,  "score": 95},
      "iam":        {"rule_count": 14,  "topology_depth": "N/A", "posture_writer": true, "score": 70},
      "ai_security":{"rule_count": 0,   "topology_depth": "N/A", "posture_writer": false,"score": 0}
    },
    "ibm": {
      "network":    {"rule_count": 107, "topology_depth": "L1",  "posture_writer": true, "score": 40},
      "dbsec":      {"rule_count": 0,   "topology_depth": "N/A", "posture_writer": false,"score": 0}
    }
  },
  "critical_gaps": [
    {"csp": "*",    "engine": "ai_security", "gap": "zero rules for any CSP"},
    {"csp": "ibm",  "engine": "network",     "gap": "L2 topology stub"},
    {"csp": "k8s",  "engine": "network",     "gap": "L2 topology deferred"},
    {"csp": "ibm",  "engine": "dbsec",       "gap": "zero rules"},
    {"csp": "k8s",  "engine": "dbsec",       "gap": "zero rules"},
    {"csp": "k8s",  "engine": "network",     "gap": "only 7 rules, very thin"}
  ]
}
```

### BFF Endpoint: `GET /api/v1/views/coverage-matrix`

New BFF view handler: `shared/api_gateway/bff/coverage_matrix.py`

Returns the JSON matrix for the UI dashboard. No engine DB calls at request time — reads from a pre-computed `coverage_matrix_cache` table updated by the script (run daily via CronJob).

### UI: Coverage Matrix Page (future — separate UI story)

Visual heatmap: CSP rows × Engine columns, colored by score (red = 0, yellow = partial, green = full).

## Acceptance Criteria

- [ ] AC-1: `scripts/generate_coverage_matrix.py` runs successfully and outputs valid JSON
- [ ] AC-2: Output includes all 7 CSPs × 9 engine dimensions = 63 cells
- [ ] AC-3: AI security shows `score: 0` for all CSPs (zero rules currently)
- [ ] AC-4: IBM dbsec shows `score: 0` (zero rules)
- [ ] AC-5: K8s network shows `topology_depth: "L1"` (deferred)
- [ ] AC-6: AWS network shows `topology_depth: "L2"` and `score > 90`
- [ ] AC-7: `critical_gaps` list correctly identifies the 6 highest-priority gaps
- [ ] AC-8: Script is idempotent — runs again same day produces same output (no side effects)

## Definition of Done
- [ ] `scripts/generate_coverage_matrix.py` committed
- [ ] Coverage matrix JSON output committed to `_bmad-output/coverage-matrix-baseline-2026-05-16.json`
- [ ] This baseline becomes the reference against which future sprints measure improvement
