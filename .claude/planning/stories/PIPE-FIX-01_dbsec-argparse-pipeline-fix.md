# PIPE-FIX-01 — DBSec run_scan.py: Accept Extra CLI Args (Pipeline Compatibility)

## Summary
DBSec's `run_scan.py` currently uses `parser.parse_args()` which exits with code 2
if any unrecognised argument is passed. The Argo pipeline's spot-node K8s Job runner
(and any ad-hoc operator invocation) may pass `--tenant-id`, `--account-id`,
`--provider` alongside `--scan-run-id`. The script already reads those values from
the DB (`scan_runs` table) — the extra CLI args are redundant but harmless. Switching
to `parse_known_args()` silences the exit-2 failure with zero logic change.

## Problem
```
python3 run_scan.py --scan-run-id X --tenant-id Y --account-id Z --provider aws
# → argparse exits 2: unrecognised arguments: --tenant-id Y ...
```

The API path (HTTP POST → background thread) is unaffected. This only triggers when
`run_scan.py` is invoked directly via `kubectl exec` or a future K8s Job template.

## Acceptance Criteria
- [ ] `run_scan.py` accepts and ignores `--tenant-id`, `--account-id`, `--provider` args
- [ ] Passing only `--scan-run-id` still works identically (backward compatible)
- [ ] Passing all four args exits 0 (not code 2)
- [ ] `tenant_id` and `account_id` continue to be read from `scan_runs` DB row (not CLI)
- [ ] No other logic changed in `run_scan.py`

## Implementation

**File**: `engines/dbsec/run_scan.py`

Change `parse_args()` → `parse_known_args()`:

```python
# BEFORE
args = parser.parse_args()
scan_run_id = args.scan_run_id

# AFTER
args, _unknown = parser.parse_known_args()
scan_run_id = args.scan_run_id
```

That is the entire code change. One line diff.

## Why parse_known_args, not add_argument for each extra flag
Adding explicit `--tenant-id` / `--account-id` / `--provider` args would silently
accept them but never use them — misleading. `parse_known_args()` makes it explicit
that extra args are tolerated but ignored, which is the correct semantic.

## Deploy
No Docker rebuild required for the pipeline HTTP path (API server is unchanged).
Rebuild is needed only if a new K8s Job-based runner will invoke `run_scan.py` directly.

If rebuilding: `docker build -t yadavanup84/engine-dbsec:<tag> -f engines/dbsec/Dockerfile .`

## Definition of Done
- [ ] `parse_known_args()` in place
- [ ] Manual test: `kubectl exec deployment/engine-dbsec -- python3 /app/run_scan.py --scan-run-id <id> --tenant-id X --account-id Y --provider aws` exits 0 and writes findings to DI DB
- [ ] No regression in API-triggered scan path