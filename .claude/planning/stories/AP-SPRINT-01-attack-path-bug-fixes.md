# AP-SPRINT-01 — Attack Path Engine: Bug Fixes (7 bugs)

## Story
As a platform operator, I need the attack-path engine to reliably produce scored paths on every pipeline run, so that security teams see accurate findings instead of perpetual 0-path scans.

## Priority
P0 — blocking production data

## Status
**DONE** — all 7 bugs fixed in this session (2026-05-24)

## Bugs Fixed

### Bug 1 — Composite flags computed only for current-scan resources
**File:** `engines/attack-path/attack_path_engine/db/posture_updater.py`
**Root cause:** `update_composite_flags()` filtered `WHERE scan_run_id = %s AND tenant_id = %s` — skipped all resources touched in prior scans.
**Fix:** Changed to `WHERE tenant_id = %s` only. `resource_security_posture` has UNIQUE(resource_uid, tenant_id); each resource has exactly one row that accumulates across scans.

### Bug 2 — `is_internet_exposed` marks never persisted when BFS finds 0 paths
**File:** `engines/attack-path/attack_path_engine/run_scan.py`
**Root cause:** `_mark_internet_exposed_from_discoveries()` ran the UPDATE but never committed. If BFS later found 0 paths and returned early, the `finally` block closed the connection → implicit ROLLBACK. Next scan sees 0 entry points → 0 paths → repeat.
**Fix:** Added `inventory_conn.commit()` immediately after the UPDATE, before returning the count.

### Bug 3 — `classify_attack_vector` called twice per path (×2 CPU waste)
**File:** `engines/attack-path/attack_path_engine/run_scan.py`
**Root cause:** Stage 4b called it to build MITRE chain; Stage 4c called it again to write nodes. For 500 paths = 1000 calls instead of 500.
**Fix:** Added `av_cache: Dict[int, Any] = {}` (keyed by `id(sp)`). Stage 4b stores result; Stage 4c reuses it.

### Bug 4a — BFS continued exploring from crown jewel nodes
**File:** `engines/attack-path/attack_path_engine/graph/pg_graph.py`
**Root cause:** After appending a completed path, the BFS did not `continue` — it queued crown jewel neighbors, producing invalid paths (CJ as intermediate hop).
**Fix:** Added `continue` after `paths.append(RawPath(...))`.

### Bug 4b — Entry type case mismatch dropped probability lookup
**File:** `engines/attack-path/attack_path_engine/core/scorer.py`
**Root cause:** `_ENTRY_BASE_P` had duplicate mixed-case keys; lookup used raw string without `.lower()`. DB-sourced entry types like "Internet" silently fell through to the 0.50 default.
**Fix:** Collapsed to 7 canonical lowercase keys; applied `.lower()` normalization before every lookup.

### Bug 5 — CDR `inv_conn`/`cdr_conn` not guaranteed to close on exception
**File:** `engines/cdr/run_scan.py`
**Root cause:** `inv_conn.close()` / `cdr_conn.close()` were inside the `try` block, after `upsert_findings()`. If upsert raised, connections leaked.
**Fix:** Wrapped upsert in nested `try/finally` so both connections close regardless.

### Bug 6 — Log message hardcoded "discovery_findings" (wrong in DI mode)
**File:** `engines/attack-path/attack_path_engine/run_scan.py`
**Root cause:** `_mark_internet_exposed_from_discoveries()` logged `"No internet-exposed resources in discovery_findings"` even when `DI_ENGINE_ENABLED=true` (table = `asset_inventory`).
**Fix:** Changed to `logger.info("No internet-exposed resources in %s tenant=%s", table, tenant_id)`.

### Bug 7 — `_build_findings_lookup` uses `AND status = 'open'` (case-sensitive)
**File:** `engines/attack-path/attack_path_engine/run_scan.py`
**Root cause:** CDR writes status as 'OPEN' (uppercase); query missed all CDR threat_detections.
**Fix:** Changed to `AND LOWER(status) = 'open'`.

## Acceptance Criteria
- [ ] After a full scan, `is_internet_exposed=true` rows exist in `resource_security_posture`
- [ ] Attack paths count > 0 for any tenant with internet-exposed resources and crown jewels
- [ ] Composite flags (unencrypted_pii_store, internet_exposed_with_pii, etc.) apply to ALL resources for the tenant, not just those touched in the current scan
- [ ] CDR threat_detections appear in findings_lookup when status is stored as 'OPEN'
- [ ] `attack-path` engine logs show "pg BFS complete: paths_found=N" with N > 0

## Files Changed
- `engines/attack-path/attack_path_engine/db/posture_updater.py`
- `engines/attack-path/attack_path_engine/run_scan.py`
- `engines/attack-path/attack_path_engine/graph/pg_graph.py`
- `engines/attack-path/attack_path_engine/core/scorer.py`
- `engines/cdr/run_scan.py`

## Deploy
Both `engine-attack-path` and `engine-cdr` require rebuilds.