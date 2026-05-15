---
id: onboarding-D6
title: "Scan run history + re-run API (BFF)"
sprint: D
points: 1
depends_on: [onboarding-C7]
blocks: [onboarding-D11]
security_blocks: []
nist_csf: DE.AE
owasp_samm: Verification
csa_ccm: IAM-14
---

## Context

With C7 adding the run-now endpoint, the system can now trigger scans. But the frontend has no way to display scan history or allow re-running a failed scan. This story adds two BFF views: (1) `view_scan_history` — reads from `scan_orchestration` table (via the onboarding engine) and returns a formatted timeline of past scans per account, (2) `view_scan_detail` — returns per-engine status for a single scan run. The re-run capability is exposed by the BFF calling the C7 run-now endpoint with the same `account_id` as the historical scan. The BFF must not access the `scan_orchestration` table directly — all DB reads go through the onboarding engine API. No fallback or mock scan data.

## Acceptance Criteria

- [ ] AC1: BFF view `GET /gateway/api/v1/views/scan_history?account_id={id}` returns paginated scan run history for the specified account.
- [ ] AC2: Scan history response format:
  ```json
  {
    "scans": [
      {
        "scan_run_id": str,
        "account_id": str,
        "status": str,
        "engines_requested": [],
        "engines_completed": [],
        "created_at": str,
        "updated_at": str,
        "duration_seconds": int | null
      }
    ],
    "total": int,
    "page": int,
    "page_size": int
  }
  ```
- [ ] AC3: BFF view `GET /gateway/api/v1/views/scan_detail?scan_run_id={id}` returns single scan run with per-engine status breakdown.
- [ ] AC4: Re-run action: `POST /gateway/api/v1/views/scan_rerun` with body `{"scan_run_id": "<id>"}`. BFF looks up the `account_id` from that scan_run_id and calls the onboarding engine `POST /api/v1/scans/run-now` with that `account_id`. Returns 202.
- [ ] AC5: BFF does NOT return fallback/mock scan history — if the engine returns empty, return `{"scans": [], "total": 0}`.
- [ ] AC6: `duration_seconds` computed by BFF as `(updated_at - created_at).total_seconds()` if status is terminal (`completed`, `failed`), else `null`.
- [ ] AC7: `engines_requested` and `engines_completed` from `scan_orchestration` are JSONB — the onboarding engine returns them as dicts/lists; BFF passes them through as-is without calling `json.loads()`.
- [ ] AC8: BFF contract test exists verifying response shape including `engines_completed` as a list.
- [ ] AC9: Scan history is scoped to the caller's `tenant_id` (enforced by the onboarding engine — BFF just forwards auth context).

## Key Files

- `shared/api_gateway/bff/onboarding_cloud_accounts.py` — Add `view_scan_history()`, `view_scan_detail()`, `action_scan_rerun()` handlers
- `shared/api_gateway/bff/tests/test_scan_history.py` — BFF contract test

## Technical Notes

**Onboarding engine endpoints (must exist — or BFF can call scan_orchestration via a dedicated endpoint):**

Check if a scan history endpoint already exists on the onboarding engine:
```bash
grep -n "scan.*history\|scan_orchestration.*GET\|scans.*get" \
  /Users/apple/Desktop/threat-engine/engines/onboarding/api/scans.py
```

If not, the onboarding engine needs a `GET /api/v1/scans/history?account_id={id}` endpoint added as part of this story (minimal implementation — just reads from `scan_orchestration` filtered by `account_id` and `tenant_id`).

**Minimal onboarding engine scan history endpoint (add to scans.py if missing):**
```python
@router.get("/scans/history")
# RBAC: requires scans:read
async def scan_history(
    account_id: UUID,
    page: int = 1,
    page_size: int = 20,
    auth: AuthContext = Depends(require_permission("scans:read")),
    db=Depends(get_db),
):
    offset = (page - 1) * page_size
    rows = await db.fetch(
        """SELECT scan_run_id, account_id, status, engines_requested, engines_completed,
                  created_at, updated_at
           FROM scan_orchestration
           WHERE account_id = $1 AND tenant_id = $2
           ORDER BY created_at DESC
           LIMIT $3 OFFSET $4""",
        str(account_id), auth.tenant_id, page_size, offset
    )
    return [dict(r) for r in rows]
```

**JSONB columns in scan_orchestration:** `engines_requested` and `engines_completed` are JSONB. psycopg2 returns them as Python dicts/lists automatically — never call `json.loads()`. The BFF receives these from the engine as JSON and passes them through.

**BFF re-run handler:**
```python
def action_scan_rerun(scan_run_id: str, auth_context: dict) -> dict:
    # 1. Get account_id from scan history
    detail = _get_scan_detail(scan_run_id, auth_context)
    account_id = detail["account_id"]

    # 2. Trigger new scan via run-now
    headers = {"X-Auth-Context": json.dumps(auth_context)}
    resp = requests.post(
        f"{ONBOARDING_ENGINE_URL}/api/v1/scans/run-now",
        json={"account_id": account_id},
        headers=headers,
        timeout=15,
    )
    if resp.status_code != 202:
        raise ServiceUnavailableError("Scan trigger failed")
    return resp.json()
```

**duration_seconds computation (BFF-side):**
```python
from datetime import datetime

def _compute_duration(created_at: str, updated_at: str, status: str) -> int | None:
    if status not in ("completed", "failed"):
        return None
    dt_created = datetime.fromisoformat(created_at)
    dt_updated = datetime.fromisoformat(updated_at)
    return int((dt_updated - dt_created).total_seconds())
```

## Security Checklist

- [ ] BFF forwards `X-Auth-Context` — does not inject or override `tenant_id`
- [ ] Scan history is tenant-scoped (enforced by onboarding engine)
- [ ] Re-run uses the `account_id` from DB lookup — not from user-supplied request body
- [ ] No fallback/mock scan data
- [ ] No hardcoded secrets or credentials
- [ ] bmad-security-reviewer gate passed before merge

## Definition of Done

- [ ] All ACs pass
- [ ] BFF contract test covers `engines_completed` as list (not string)
- [ ] Re-run triggers a new scan_run_id (verify different from the original)
- [ ] No `json.loads()` calls on JSONB data in BFF
- [ ] bmad-security-reviewer: no BLOCKERs
- [ ] `kubectl rollout status deployment/api-gateway -n threat-engine-engines` shows AVAILABLE
- [ ] `GET /gateway/api/v1/views/scan_history?account_id={id}` returns 200 with scan list