# Session Handover — 2026-03-21 (Session B)

## What was done this session

### 1. IAM Engine Uplift (v-policy-parser)
- Built full IAM policy parser: `engines/iam/iam_engine/parsers/policy_parser.py`
  - Parses IAM policy documents from discovery_findings
  - Extracts Statement/Effect/Action/Resource/Condition
  - Detects wildcards, overly permissive actions, admin-level access
- Built trust relationship analyzer: flags cross-account trust, confused deputy, wildcard principals
- Created `iam_policy_statements` table (31 rows populated on first scan)
- Created Neo4j `CAN_ACCESS` edges from parsed policies
- Built, pushed, deployed: `yadavanup84/engine-iam:v-policy-parser`

### 2. DataSec Engine Fix (v-check-based)
- Built `check_findings_reader.py` — reads data-store findings from check engine
- Fixed `finding_id` → `id` column mismatch in check_findings
- Fixed `scan_run_id` NOT NULL violation in datasec_db_writer
- Added severity/account_id population from rule mapping
- Fallback: found 1,203 evaluations from 36 data stores, but DB write failed (scan_run_id null)
- Built, pushed, deployed: `yadavanup84/engine-datasec:v-check-based`

### 3. Discovery Noise Cleanup (Round 2)
- Disabled 8 additional noisy services: ram (52K findings), autoscaling (23K), plus 6 others
- Active AWS rules: ~380

### 4. Column Standardization (MAJOR — all 8 databases)
Renamed ALL engine finding tables to use uniform column names:

| Old Name | New Name | Scope |
|----------|----------|-------|
| `orchestration_id` | `scan_run_id` | scan_orchestration + all engine code |
| `{engine}_scan_id` (7 variants) | DROPPED | All finding tables now use `scan_run_id` |
| `hierarchy_id` | `account_id` | discovery, check, iam, onboarding |
| `scan_timestamp` | `first_seen_at` | discovery |
| `created_at` | `first_seen_at` | check |
| `first_discovered_at` | `first_seen_at` | inventory |
| `last_modified_at` | `last_seen_at` | inventory |
| `asset_id` | `finding_id` | inventory |

Added standard columns where missing: `credential_ref`, `credential_type`, `provider`, `severity`, `status`, `last_seen_at`

**Migration file**: `shared/database/migrations/001_standardize_column_names.sql`
**Code changes**: ~60 files across all engines + shared services + BFF

### 5. Agent & Documentation Updates
- Updated `onboarding.md` agent with post-standardization schema
- Created new `orchestration.md` agent (pipeline flow, trigger endpoints, K8s job pattern)
- Updated `CLAUDE.md` database design section
- Updated `MEMORY.md` with standardized column reference
- Created `column-standardization.md` memory file

---

## PENDING: Build, Push, Deploy All Engines

### What needs to happen
All engines need to be rebuilt with the column-standardized code. This is the biggest deployment in the project's history — every engine changes.

### Build order (all can be parallel)
```bash
# From repo root:
docker build -t yadavanup84/engine-discoveries:v-std-cols -f engines/discoveries/Dockerfile .
docker build -t yadavanup84/engine-check:v-std-cols -f engines/check/Dockerfile .
docker build -t yadavanup84/engine-check:v-std-cols-aws -f engines/check/engine_check_aws/Dockerfile .
docker build -t yadavanup84/inventory-engine:v-std-cols -f engines/inventory/Dockerfile .
docker build -t yadavanup84/engine-threat:v-std-cols -f engines/threat/Dockerfile .
docker build -t yadavanup84/threat-engine-compliance-engine:v-std-cols -f engines/compliance/Dockerfile .
docker build -t yadavanup84/engine-iam:v-std-cols -f engines/iam/Dockerfile .
docker build -t yadavanup84/engine-datasec:v-std-cols -f engines/datasec/Dockerfile .
docker build -t yadavanup84/threat-engine-onboarding-api:v-std-cols -f engines/onboarding/Dockerfile .
docker build -t yadavanup84/engine-risk:v-std-cols -f engines/risk/Dockerfile .
docker build -t yadavanup84/secops-scanner:v-std-cols -f engines/secops/Dockerfile .
docker build -t yadavanup84/threat-engine-api-gateway:v-std-cols -f shared/api_gateway/Dockerfile .
docker build -t yadavanup84/threat-engine-pipeline-worker:v-std-cols -f shared/pipeline_worker/Dockerfile .
```

### Deploy order (critical — DB already migrated)
1. Deploy shared services first (gateway, pipeline worker)
2. Deploy onboarding (orchestration hub)
3. Deploy upstream engines (discoveries, check, inventory)
4. Deploy downstream engines (threat, compliance, iam, datasec, risk)
5. Run full pipeline scan to verify

### Rollback plan
If any engine fails: the DB migration is backward-compatible in most cases (columns were renamed, not dropped — except `{engine}_scan_id` columns which ARE dropped). Rollback would require re-adding dropped columns:
```sql
ALTER TABLE scan_orchestration ADD COLUMN discovery_scan_id varchar;
-- etc. for all 7
```

---

## DONE: Column Standardization Code Updates

### Critical runtime fixes (all done)
1. `get_check_scan_id_from_orchestration()` in compliance — now returns `scan_run_id` directly
2. `_resolve_inventory_scan_id()` in threat — now returns `scan_run_id` directly
3. IAM/DataSec `_resolve_threat_scan_id()` — simplified to `_resolve_scan_run_id()`
4. All CLI args: `--orchestration-id`/`--{engine}-scan-id` → `--scan-run-id`
5. All Pydantic models: `orchestration_id` → `scan_run_id`
6. All `run_scan.py` files: removed lookups for per-engine scan IDs from metadata

### Remaining cosmetic refs (~170 engine_scan_id + ~110 orchestration_id)
These are in comments, docstrings, variable names, legacy folders (`engine_onboarding/`, `consolidated_services/`), and test files. None cause runtime errors. Can be cleaned in a follow-up pass.

---

## PENDING: DataSec Findings — Still 0

### Issue
datasec_findings = 0. Two bugs found and partially fixed:
1. `check_findings_reader.py` — `finding_id` column doesn't exist (fixed: use `id`)
2. Fallback path — `scan_run_id` NOT NULL violation (needs fix in datasec_db_writer)

### What worked
The fallback path DID find **1,203 FAIL evaluations from 36 data stores** — it just crashed on DB write.

### Fix needed
In `engines/datasec/data_security_engine/storage/datasec_db_writer.py`:
- Ensure `scan_run_id` is populated in INSERT (was `datasec_scan_id`)
- The column was renamed in the migration, code update may have fixed this

### Verify after deploy
Run DataSec scan, check logs and `datasec_findings` count.

---

## PENDING: Compliance Findings — Still 0

### Issue
`compliance_findings` table has 0 rows. `compliance_report.report_data` JSONB has 8,798 findings.

### Root cause
`db_exporter.py` reads from `report.findings` list which is empty. The data goes into JSONB but individual findings aren't extracted.

### Fix needed
In `engines/compliance/compliance_engine/exporter/db_exporter.py`:
- Extract findings from `framework_reports` dict (not the empty `report.findings` list)
- Same approach as `compliance_db_writer.py` which successfully saves to JSONB

---

## PENDING: Security Graph Improvements

### Current state
- Neo4j: 20,010 nodes, ~22K relationships
- Subgraph: 338 nodes, 39 edges (sparse)
- Internet node not appearing (EXPOSES → sgr-* not sg-*)

### What needs fixing
1. Internet exposure: Fix EXPOSES edge (sgr → parent SG traversal)
2. More relationship types in subgraph query
3. Topology-first approach: show all resources, overlay threats
4. Sensitivity classification from DataSec data
5. IAM CAN_ACCESS edges (from IAM uplift) in graph

---

## PENDING: Pipeline Orchestration Consolidation

### Issue discovered this session
Three separate orchestration implementations exist:
1. `engines/onboarding/orchestrator/engine_orchestrator.py` (inline HTTP)
2. `shared/pipeline_worker/worker.py` (standalone service)
3. `shared/api_gateway/orchestration.py` (gateway)

Each has slightly different pipeline orders and endpoint URLs. This is tech debt.

### Recommendation
Consolidate to the pipeline_worker as the single implementation. It's the most mature (stateless, proper JSONB tracking, better error handling).

---

## Current Production Image Tags (pre-standardization deploy)
| Engine | Image |
|--------|-------|
| discoveries | `yadavanup84/engine-discoveries:v11-multicloud` |
| check | `yadavanup84/engine-check:v-resource-svc` |
| iam | `yadavanup84/engine-iam:v-policy-parser` |
| datasec | `yadavanup84/engine-datasec:v-check-based` |
| threat | `yadavanup84/engine-threat:v-topo-graph` |
| compliance | `yadavanup84/threat-engine-compliance-engine:v-uid-fix` |
| inventory | `yadavanup84/inventory-engine:v11-blast-radius` |
| onboarding | `yadavanup84/threat-engine-onboarding-api:v-full-data` |
| secops | `yadavanup84/secops-scanner:v-uniform` |
| risk | `yadavanup84/engine-risk:v2.1-aliases` |
| frontend | `yadavanup84/cspm-frontend:v-graph-wiz` |
| gateway | `yadavanup84/threat-engine-api-gateway:v-graph-wiz` |

## Latest Orchestration
- **ID**: `f8b49727-4b8c-435f-848a-6151703a818f`
- **Tenant**: `test-tenant-002`
- **Account**: `588989875114`
- **Results**: discovery=4380, check=10840, threat=8779, iam=568, iam_policy_stmts=31, datasec=0, compliance=0

## Priority Order for Next Session
1. **Build + deploy all engines** with `v-std-cols` tag (DB already migrated, code updated)
2. **Run full pipeline scan** to verify standardization works end-to-end
3. **Fix DataSec DB write** (scan_run_id null) → re-scan
4. **Fix Compliance findings extraction** → re-scan
5. **Security Graph improvements** (internet exposure, topology-first)
6. **Clean remaining cosmetic old refs** (~280 in comments/legacy code)
7. **Pipeline orchestration consolidation** (optional, tech debt)
