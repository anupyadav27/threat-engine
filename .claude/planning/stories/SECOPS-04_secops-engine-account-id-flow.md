# Story: SECOPS-04 — SecOps Engine: account_id Flow, Ownership Validation, secops_latest_scan Upsert

## Status: done

## Context

With code-repo accounts now onboarded as `code_security` accounts (SECOPS-03), the SecOps engine's scan trigger must link every scan to its originating account. This story wires `account_id` into the scan lifecycle: `ScanRequest` accepts `account_id` (required); the engine calls the onboarding engine to verify the account belongs to the calling tenant (fail-closed); `persist_scan_report` writes `account_id` and enforces `customer_id = tenant_id`; `complete_scan_report` upserts a row into `secops_latest_scan` after each completed/failed scan. The `list_scans` and `list_dast_scans` endpoints are updated to query `secops_latest_scan` for the per-account summary view.

`repo_url` is removed from the public `ScanRequest` model (resolved internally from the onboarding engine's `auth_config.repo_url`) — this prevents callers from overriding it with a different URL than what was validated at onboarding time.

**Prerequisites**: SECOPS-01, SECOPS-02, SECOPS-03 all applied.

## Security Framework Tags

**OWASP SAMM Function**
- [ ] Governance  [ ] Design  [x] Implementation  [x] Verification  [ ] Operations

**NIST CSF 2.0 Function(s) this story covers**
- [ ] GV Govern  [x] ID Identify  [x] PR Protect  [x] DE Detect  [ ] RS Respond  [ ] RC Recover
PR.DS-1, PR.DS-2, PR.AC-3, PR.AC-4, DE.CM-1

**CSA CCM v4 Domain(s)**
- CCM: IAM-02 (Identity Inventories), IVS-04 (Network Security — cross-engine validation), DSP-07, SEF-02

## Threat Model

### STRIDE
| Threat | Component | Attack Scenario | Mitigation |
|--------|-----------|-----------------|------------|
| Spoofing | `ScanRequest.account_id` | Attacker supplies an `account_id` owned by a different tenant to trigger a scan against their repo | `_validate_account_ownership()` calls onboarding GET endpoint; 403 if tenant mismatch |
| Tampering | `persist_scan_report` | `customer_id` set to a different tenant's ID to poison cross-tenant aggregates | `customer_id` forced to `auth.engine_tenant_id` in code; never taken from request body |
| Info Disclosure | `list_scans` | Without `account_id` linkage, any scan result could be attributed to wrong tenant | `secops_latest_scan` PK is `(tenant_id, account_id, scan_type)` — reads always scoped by tenant |
| DoS | `_validate_account_ownership` | Onboarding engine is down; every scan hangs for minutes before failing | Hard 5-second timeout with fail-closed: 503 returned if timeout or connection error |

### PASTA (credentials/IAM/network)
| Stage | Adversary Goal | Attack Path | Countermeasure |
|-------|---------------|-------------|----------------|
| Cross-tenant scan | Scan a competitor's repo by supplying their account_id | POST /sast/scan with account_id=competitor | Onboarding GET validates tenant ownership; 403 if tenant mismatch |
| Credential bypass | Supply own repo_url instead of the validated one in auth_config | Old `ScanRequest.repo_url` field | `repo_url` removed from public model; resolved from onboarding `auth_config` internally |
| DoS via ownership check | Overwhelm onboarding endpoint to degrade scan availability | High-volume scan trigger requests | 5s timeout; fail-closed 503 (not hang); caller must retry |

## MITRE ATT&CK Techniques Addressed
| Technique ID | Name | D3FEND Countermeasure | How this story addresses it |
|-------------|------|----------------------|----------------------------|
| T1078.004 | Valid Accounts: Cloud Accounts | D3-UAP (User Account Provisioning) | account_id verified against onboarding API at scan time; scan rejected if account belongs to different tenant |
| T1190 | Exploit Public-Facing Application | D3-NTF (Network Traffic Filtering) | repo_url no longer accepted in ScanRequest; resolved from validated auth_config only |

## Acceptance Criteria (Functional)
- [ ] `ScanRequest` model gains `account_id: str` (required). `repo_url` field removed from public model (still passed internally after resolution).
- [ ] `scan_repo` endpoint calls `_validate_account_ownership(account_id, tenant_id, auth_header)` before clone. Returns HTTP 503 if onboarding call times out or returns non-2xx. Returns HTTP 403 if account exists but belongs to a different tenant.
- [ ] `_validate_account_ownership()` calls `GET http://engine-onboarding/api/v1/cloud-accounts/{account_id}` with a 5-second timeout. It compares response `tenant_id` against `auth.engine_tenant_id`. Raises `HTTPException(503)` on timeout/connection error. Raises `HTTPException(403)` on tenant mismatch. Raises `HTTPException(404)` if onboarding returns 404.
- [ ] `repo_url` is resolved from `response["auth_config"]["repo_url"]` in the onboarding response (not from `ScanRequest`). Used for clone and passed to `persist_scan_report`.
- [ ] `persist_scan_report()` writes `account_id` and `scan_run_id` to `secops_report`. `customer_id` is set to `tenant_id` from auth (ignores any `customer_id` in the request).
- [ ] `complete_scan_report()` calls `upsert_latest_scan()` after updating `secops_report`. `upsert_latest_scan()` upserts into `secops_latest_scan` using `ON CONFLICT (tenant_id, account_id, scan_type) DO UPDATE`.
- [ ] `upsert_latest_scan()` populates `critical_count`, `high_count`, `medium_count`, `low_count` from the `summary` dict (keys: `critical`, `high`, `medium`, `low`). Defaults to 0 if key absent.
- [ ] `GET /api/v1/secops/sast/scans?tenant_id=` endpoint queries `secops_latest_scan` (not `secops_report`) and returns one row per `(account_id, scan_type)`. Ordered by `last_seen_at DESC`.
- [ ] `GET /api/v1/secops/dast/scans?tenant_id=` endpoint same.
- [ ] New engine endpoint `GET /api/v1/secops/latest-scans?tenant_id=` returns all rows for the tenant from `secops_latest_scan` with flattened severity counts.
- [ ] DAST scan trigger (`/dast/scan`) also accepts `account_id` (optional for DAST — DAST scans may not have a code repo account); `upsert_latest_scan()` called on DAST completion if `account_id` is present.

## Acceptance Criteria (Security — must pass bmad-security-reviewer)
- [ ] `_validate_account_ownership` uses the ONBOARDING_ENGINE_URL env var (not a hardcoded hostname); defaults to `http://engine-onboarding`
- [ ] All DB queries in `upsert_latest_scan()` include `tenant_id` in the WHERE / conflict target
- [ ] `customer_id` in `persist_scan_report` is always overwritten to `auth.engine_tenant_id` — never accepted from request body
- [ ] `_validate_account_ownership` timeout is exactly 5 seconds; connection error raises 503 (fail-closed), not 200
- [ ] `account_id` written to `secops_report` and `secops_latest_scan` is the validated value returned from onboarding (not the raw request value, in case normalization occurs)
- [ ] No plaintext credentials in logs
- [ ] All new DB queries have tenant_id filter
- [ ] `secops_latest_scan` upsert uses parameterized query (no f-string SQL)
- [ ] Base image pinned (no `latest`) — SLSA Level 1
- [ ] New findings mapped to at least one CCM v4 control (via scan metadata)

## Technical Notes

### _validate_account_ownership implementation (sast.py)

```python
import os
import urllib.request
import urllib.error
import json as _json

ONBOARDING_ENGINE_URL = os.getenv("ONBOARDING_ENGINE_URL", "http://engine-onboarding")

def _validate_account_ownership(
    account_id: str,
    tenant_id: str,
    auth_header: Optional[str],
) -> dict:
    """Call onboarding engine to verify account belongs to tenant.

    Returns the cloud account dict (includes auth_config with repo_url).

    Raises:
        HTTPException(404): account not found
        HTTPException(403): account belongs to different tenant
        HTTPException(503): onboarding engine unreachable or timeout
    """
    url = f"{ONBOARDING_ENGINE_URL}/api/v1/cloud-accounts/{account_id}"
    req = urllib.request.Request(url)
    if auth_header:
        req.add_header("X-Auth-Context", auth_header)

    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = _json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise HTTPException(status_code=404, detail=f"Account {account_id} not found")
        raise HTTPException(status_code=503, detail="Onboarding engine error")
    except (urllib.error.URLError, TimeoutError, OSError):
        raise HTTPException(status_code=503, detail="Onboarding engine unreachable")

    if data.get("tenant_id") != tenant_id:
        raise HTTPException(status_code=403, detail="Account does not belong to this tenant")

    return data
```

### upsert_latest_scan (secops_db_writer.py)

New function added after `complete_scan_report`:

```python
def upsert_latest_scan(
    tenant_id: str,
    account_id: str,
    scan_type: str,
    secops_scan_id: str,
    scan_run_id: Optional[str],
    repo_url: Optional[str],
    project_name: Optional[str],
    default_branch: Optional[str],
    status: str,
    files_scanned: int,
    total_findings: int,
    languages_detected: List[str],
    summary: Dict[str, Any],
    completed_at: Optional[datetime] = None,
) -> None:
    """Upsert one row into secops_latest_scan for the (tenant, account, scan_type) triple."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO secops_latest_scan
                    (tenant_id, account_id, scan_type, repo_url, project_name,
                     default_branch, secops_scan_id, scan_run_id, status,
                     total_findings, critical_count, high_count, medium_count, low_count,
                     files_scanned, languages_detected, scan_timestamp, completed_at,
                     first_seen_at, last_seen_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW(),%s,NOW(),NOW())
                ON CONFLICT (tenant_id, account_id, scan_type) DO UPDATE SET
                    secops_scan_id     = EXCLUDED.secops_scan_id,
                    scan_run_id        = EXCLUDED.scan_run_id,
                    status             = EXCLUDED.status,
                    total_findings     = EXCLUDED.total_findings,
                    critical_count     = EXCLUDED.critical_count,
                    high_count         = EXCLUDED.high_count,
                    medium_count       = EXCLUDED.medium_count,
                    low_count          = EXCLUDED.low_count,
                    files_scanned      = EXCLUDED.files_scanned,
                    languages_detected = EXCLUDED.languages_detected,
                    scan_timestamp     = EXCLUDED.scan_timestamp,
                    completed_at       = EXCLUDED.completed_at,
                    last_seen_at       = NOW()
            """, (
                tenant_id, account_id, scan_type, repo_url, project_name,
                default_branch, secops_scan_id, scan_run_id, status,
                total_findings,
                int(summary.get("critical", 0) or 0),
                int(summary.get("high", 0) or 0),
                int(summary.get("medium", 0) or 0),
                int(summary.get("low", 0) or 0),
                files_scanned,
                _json.dumps(languages_detected),
                completed_at or datetime.now(timezone.utc),
            ))
        conn.commit()
    finally:
        conn.close()
```

### list_scans endpoint change

Replace the existing `SELECT ... FROM secops_report` query in `list_scans` with:

```sql
SELECT tenant_id, account_id, scan_type, repo_url, project_name,
       default_branch, secops_scan_id, scan_run_id, status,
       total_findings, critical_count, high_count, medium_count, low_count,
       files_scanned, languages_detected, scan_timestamp, completed_at,
       first_seen_at, last_seen_at
FROM secops_latest_scan
WHERE tenant_id = %s
  AND (scan_type IS NULL OR scan_type = 'sast')
ORDER BY last_seen_at DESC
LIMIT %s
```

## Key Files
- `/Users/apple/Desktop/threat-engine/engines/secops/sast_engine/routers/sast.py` — ScanRequest model, scan_repo endpoint, _validate_account_ownership, list_scans
- `/Users/apple/Desktop/threat-engine/engines/secops/sast_engine/routers/dast.py` — DastScanRequest.account_id, list_dast_scans
- `/Users/apple/Desktop/threat-engine/engines/secops/sast_engine/database/secops_db_writer.py` — persist_scan_report (add account_id, enforce customer_id), complete_scan_report (call upsert), upsert_latest_scan (new)

## Definition of Done
- [ ] Code implemented and builds locally
- [ ] Docker image built and pushed: `yadavanup84/secops-scanner:v-secops-repoacct2`
- [ ] K8s manifest updated with new image tag
- [ ] kubectl apply and rollout status clean
- [ ] bmad-security-reviewer: no BLOCKERS
- [ ] bmad-qa: all functional acceptance criteria verified — including a test scan that: (a) supplies a valid account_id, (b) verifies secops_latest_scan upserted, (c) verifies list_scans returns data from secops_latest_scan
- [ ] Post-deploy: `GET /api/v1/secops/latest-scans?tenant_id=<id>` returns 200
- [ ] Memory updated at `/Users/apple/.claude/projects/-Users-apple-Desktop-threat-engine/memory/`