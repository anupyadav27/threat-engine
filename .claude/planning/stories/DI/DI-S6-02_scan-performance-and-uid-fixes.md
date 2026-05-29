# DI-S6-02 — Scan Performance: Pool Separation + Per-Service Workers + UID Template Fixes
**Sprint**: DI-S6 | **Type**: Performance + Bug Fix | **Status**: Planned
**Points**: 8 | **Priority**: High (AWS full scan ~35 min → target ~15 min)

---

## Goals

1. Separate global and regional task pools so they don't compete for the same semaphore
2. Wire up `max_discovery_workers` from DB per service (column already exists, not yet read)
3. Raise default `MAX_SCAN_WORKERS` from 15 → 30
4. Audit every `ResourceIdMissingError` service: fix Category A with `uid_template`, disable Category B with `is_active=false`

---

## Change 1 — Global / Regional Pool Separation

### Problem

Right now every task — whether it runs once account-wide (IAM, S3 global list, CloudFront)
or once per region (EC2, RDS, Lambda) — competes for the same `asyncio.Semaphore(15)`.

```
Current:
  Single semaphore(15)
  [IAM ×1] [S3 ×1] [CloudFront ×1]   ← global, runs once
  [EC2 ×17] [RDS ×17] [Lambda ×17]   ← regional, runs per region
  all mixed — global tasks hold slots
  that regional tasks need for parallelism
```

### Fix

Split `scan_tasks` into two lists in `run_phase0()` before dispatch:

```python
global_tasks   = [(ident, rgn) for ident, rgn in scan_tasks if rgn == "global"]
regional_tasks = [(ident, rgn) for ident, rgn in scan_tasks if rgn != "global"]

global_sem   = asyncio.Semaphore(int(os.getenv("MAX_GLOBAL_WORKERS", "10")))
regional_sem = asyncio.Semaphore(int(os.getenv("MAX_REGIONAL_WORKERS", "30")))
```

Run both pools concurrently via `asyncio.gather`:
```python
task_results = await asyncio.gather(
    *[_scan_task(ident, rgn, global_sem)   for ident, rgn in global_tasks],
    *[_scan_task(ident, rgn, regional_sem) for ident, rgn in regional_tasks],
    return_exceptions=True,
)
```

### New env vars (add to engine-di.yaml)

| Env var | Default | Purpose |
|---|---|---|
| `MAX_GLOBAL_WORKERS` | `10` | Concurrent global/account-level tasks |
| `MAX_REGIONAL_WORKERS` | `30` | Concurrent per-region tasks |
| Remove `MAX_SCAN_WORKERS` | — | Replaced by the two above |

---

## Change 2 — Per-Service `max_discovery_workers` from DB

### Problem

`rule_discoveries.max_discovery_workers` already stores a per-service concurrency cap
(e.g. CloudFormation = 3, because describe_type is slow and AWS rate-limits it hard).
The identifier_loader reads it but the enumerator never uses it.

### Current state

```python
# identifier_loader.py line 157 — loads the row but doesn't expose max_workers
cur.execute("SELECT service, boto3_client_name, discoveries_data FROM rule_discoveries ...")
```

`max_discovery_workers` is in the table but not in the SELECT.

### Fix — Step 1: expose in identifier_loader

```python
# Add max_discovery_workers to the SELECT
cur.execute("""
    SELECT service, boto3_client_name, discoveries_data, max_discovery_workers
    FROM   rule_discoveries
    WHERE  provider = %s AND is_active = TRUE AND service = ANY(%s)
""", (csp, list(check_services)))

# Store in identifier dict
identifiers[did]["max_workers"] = row["max_discovery_workers"] or 0
```

### Fix — Step 2: use in enumerator per-task

Build a per-identifier semaphore map at dispatch time:

```python
# Build per-service semaphores (fallback to global pool for services with no cap)
service_sems: Dict[str, asyncio.Semaphore] = {}
for ident, rgn in scan_tasks:
    svc = ident["service"]
    cap = ident.get("max_workers", 0)
    if cap > 0 and svc not in service_sems:
        service_sems[svc] = asyncio.Semaphore(cap)

def _pick_sem(ident, rgn):
    svc = ident["service"]
    if svc in service_sems:
        return service_sems[svc]          # per-service cap (e.g. cloudformation=3)
    return global_sem if rgn == "global" else regional_sem   # pool fallback
```

### DB values to set (UPDATE rule_discoveries)

| Service | Recommended `max_discovery_workers` | Reason |
|---|---|---|
| `cloudformation` | 3 | describe_type hits hard throttle |
| `budgets` | 5 | Non-critical, low value |
| `iam` | 10 | Global but many sub-resources |
| `ec2` | 20 | High-value, many regions, worth more workers |
| Everything else | 0 (uses pool default) | |

---

## Change 3 — Raise Default MAX_SCAN_WORKERS → 30

Simple env change in `engine-di.yaml`. After Change 1 ships, this becomes
`MAX_REGIONAL_WORKERS=30`. Until then, update the single env var.

```yaml
- name: MAX_SCAN_WORKERS
  value: "30"   # was 15
```

Expected gain: full AWS scan ~35 min → ~18 min (linear with worker count,
capped by AWS rate limits around 30-50 concurrent calls).

---

## Change 4 — ResourceIdMissingError Audit + UID Template Fixes

### Background

`ResourceIdMissingError` = service has active check rules, API call succeeds,
but UID builder can't extract a canonical ARN from the response.
Two categories:

**Category A** — Real resource with a real ARN, just in a non-standard field.
Fix: add `uid_template` to `rule_discoveries`.

**Category B** — Not a real deployed resource (catalog entry, schema definition).
Fix: `UPDATE rule_discoveries SET is_active=false WHERE service=X AND provider='aws'`.

### Known Category A fixes (uid_template to add)

| Service | Discovery ID | uid_template |
|---|---|---|
| `budgets` | `aws.budgets.describe_budget` | `arn:aws:budgets::{context.account_id}:budget/{item.BudgetName}` |
| `budgets` | `aws.budgets.describe_budget_action` | `arn:aws:budgets::{context.account_id}:budget/{item.BudgetName}/action/{item.ActionId}` |
| `cloudformation` | `aws.cloudformation.describe_stack_resources` | `arn:aws:cloudformation:{context.region}:{context.account_id}:stack/{item.StackName}/{item.PhysicalResourceId}` |

Apply as SQL on the check DB:
```sql
UPDATE rule_discoveries
SET    uid_template = 'arn:aws:budgets::{context.account_id}:budget/{item.BudgetName}'
WHERE  provider = 'aws' AND service = 'budgets'
  AND  discoveries_data::text LIKE '%describe_budget%'
  AND  discoveries_data::text NOT LIKE '%describe_budget_action%';

UPDATE rule_discoveries
SET    uid_template = 'arn:aws:budgets::{context.account_id}:budget/{item.BudgetName}/action/{item.ActionId}'
WHERE  provider = 'aws' AND service = 'budgets'
  AND  discoveries_data::text LIKE '%describe_budget_action%';
```

### Known Category B disables (is_active=false)

| Service | Discovery ID | Why |
|---|---|---|
| `cloudformation` | `aws.cloudformation.describe_type` | Returns type schema definitions from AWS registry, not deployed resources. No ARN exists. |

```sql
UPDATE rule_discoveries
SET    is_active = false
WHERE  provider = 'aws' AND service = 'cloudformation'
  AND  discoveries_data::text LIKE '%describe_type%';
```

### Full audit approach (for remaining unknowns)

After the scan completes, run:
```sql
SELECT service, error_message, count(*) as hits
FROM   di_scan_errors
WHERE  scan_run_id = '<SCAN_RUN_ID>'
  AND  error_type  = 'ResourceIdMissingError'
GROUP  BY service, error_message
ORDER  BY hits DESC;
```

For each service: check whether a real ARN format exists in AWS docs.
- ARN exists → add uid_template (Category A)
- No ARN → set is_active=false (Category B)

---

## Acceptance Criteria

- [ ] `run_phase0()` dispatches global and regional tasks to separate semaphores
- [ ] `MAX_GLOBAL_WORKERS` and `MAX_REGIONAL_WORKERS` env vars respected; `MAX_SCAN_WORKERS` removed
- [ ] `identifier_loader` includes `max_discovery_workers` in SELECT and exposes it in identifier dict
- [ ] Enumerator uses per-service semaphore when `max_workers > 0`, falls back to pool otherwise
- [ ] `MAX_REGIONAL_WORKERS=30` set in engine-di.yaml
- [ ] budgets and cloudformation uid_template SQL applied to check DB
- [ ] `describe_type` set to `is_active=false`
- [ ] Full AWS scan completes in < 20 minutes (measured from log timestamps)
- [ ] Zero `ResourceIdMissingError` for budgets and cloudformation describe_type
- [ ] `asset_inventory` budget rows have `resource_uid` starting with `arn:aws:budgets::`

---

## Files to Change

| File | Change |
|---|---|
| `engines/di/di_engine/phase0/enumerator.py` | Split into global+regional pools; per-service semaphore from `max_workers` |
| `engines/di/di_engine/phase0/identifier_loader.py` | Add `max_discovery_workers` to SELECT, expose in identifier dict |
| `deployment/aws/eks/engines/engine-di.yaml` | Replace `MAX_SCAN_WORKERS=15` with `MAX_GLOBAL_WORKERS=10`, `MAX_REGIONAL_WORKERS=30` |
| `rule_discoveries` (check DB) | SQL: uid_template for budgets, is_active=false for describe_type |

No schema changes to DI DB. No BFF changes.

---

## Expected Timing Gains

| Change | Estimated saving |
|---|---|
| Global/regional pool split | ~5 min (global no longer blocks regional slots) |
| MAX_REGIONAL_WORKERS 15→30 | ~8 min (linear throughput gain) |
| Per-service cap (CloudFormation=3) | Prevents 15s timeouts from consuming shared slots |
| uid_template for budgets | 51s recovered (17 regions × 3s wasted API calls now produce rows) |
| describe_type disabled | 255s recovered (17 regions × 15s timeout calls eliminated) |
| **Total estimated** | **~35 min → ~15 min** |