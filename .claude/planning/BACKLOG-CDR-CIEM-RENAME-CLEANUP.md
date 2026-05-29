# Backlog: CDR/CIEM Rename Cleanup (Technical Debt)

**Priority:** Low — cosmetic, non-blocking  
**Effort:** ~1 sprint (2–3 days)  
**Created:** 2026-05-28

## Background

The CDR rename sprint (2026-05-09) correctly renamed:
- DB: `threat_engine_cdr` ✅
- Tables: `cdr_findings`, `cdr_report`, `cdr_actor_daily_stats`, `cdr_baselines`, `cdr_collection_watermark` ✅
- Engine: `engine-cdr` ✅
- K8s service and Argo pipeline ✅
- BFF: `/views/cdr` ✅
- Django migration 0015 (cdr:read + cdr:sensitive permissions) ✅

But many **internal code references were NOT renamed**, creating a disconnect between the public name (CDR) and internal variable/method/log names (CIEM).

## Known CIEM References to Clean Up

### Python code (variable/method names)
| File | Symbol | Fix |
|------|--------|-----|
| `engines/cdr/cdr_engine/flow_analysis_enricher.py` | `from engine_common.db_connections import get_ciem_conn` | Rename import to `get_cdr_conn` |
| `engines/iam/iam_engine/api_server.py` | `CIEMReader`, `ciem_conn`, `ciem_reader` | Rename to `CDRReader` / `cdr_conn` |
| `shared/api_gateway/bff/cdr.py` | Any `ciem_*` variables | Rename |
| `engines/*/run_scan.py` | `CIEM_DB_*` env var references | Update to `CDR_DB_*` |

### DB env vars (ConfigMap)
The ConfigMap and K8s deployments still use `CIEM_DB_HOST`, `CIEM_DB_NAME`, etc. as env var names. These still work because they point to `threat_engine_cdr`, but the naming is confusing.

### Log messages
Scattered `CIEM` references in log messages throughout CDR engine and consuming engines.

### `get_ciem_conn()` import error in `flow_analysis_enricher.py`
- Root cause: `engine_common.db_connections` only exports `get_cdr_conn()` post-rename
- `flow_analysis_enricher.py` still imports `get_ciem_conn` → raises `ImportError` 
- Impact: CDR flow analysis enrichment is silently skipped (Layer 2 of CDR scan)
- **This is the highest-priority item** — it's causing CDR enrichment to fail

## Proposed Fix Order

1. **Fix `get_ciem_conn` ImportError** (highest priority — breaks L2 enrichment):
   - Update `flow_analysis_enricher.py` to import `get_cdr_conn`
   - Rebuild + deploy CDR engine

2. **Update `CIEM_DB_*` env vars** in ConfigMap:
   - Rename to `CDR_DB_HOST`, `CDR_DB_NAME`, `CDR_DB_USER`, `CDR_DB_PASSWORD`
   - Update all engine deployments that consume them
   - This is a batch change across ~15 engine manifests

3. **Rename IAM engine CIEM references**:
   - `CIEMReader` → `CDRReader` in `iam_engine/api_server.py`
   - `ciem_conn`, `ciem_reader` → `cdr_conn`, `cdr_reader`

4. **Log message cleanup** — search+replace across all engines

## Acceptance Criteria

- `grep -r "ciem" engines/ --include="*.py"` returns 0 results (excluding comments)
- `grep -r "CIEM_DB" deployment/ --include="*.yaml"` returns 0 results
- CDR L2 flow analysis enrichment runs without ImportError
- All CDR log messages say "CDR" not "CIEM"