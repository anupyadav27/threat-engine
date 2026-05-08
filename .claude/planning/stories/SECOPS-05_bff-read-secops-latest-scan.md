# Story: SECOPS-05 — BFF: Read from secops_latest_scan, Remove Python Dedup

## Status: done

## Context

The current `view_secops` BFF handler calls `GET /api/v1/secops/sast/scans` and `GET /api/v1/secops/dast/scans`, then deduplicates the result in Python using `_latest_per_repo()`. With SECOPS-04 shipping, both those endpoints now read from `secops_latest_scan` — which already returns one row per `(tenant_id, account_id, scan_type)`. The Python deduplication is therefore redundant and should be removed.

Additionally, SECOPS-04 adds a new engine endpoint `GET /api/v1/secops/latest-scans?tenant_id=` that returns all scan types in a single call. This story updates the BFF to use that single endpoint and removes the two separate calls when the new endpoint is available.

Severity counts (`critical_count`, `high_count`, `medium_count`, `low_count`) now come directly from dedicated columns in `secops_latest_scan` — no more JSONB `summary` parsing in the BFF.

The BFF cache key is unchanged (`secops:{tenant_id}`). No schema changes. No image change for the secops engine — this is a gateway-only change.

**Prerequisites**: SECOPS-01, SECOPS-02, SECOPS-03, SECOPS-04 all applied and deployed.

## Security Framework Tags

**OWASP SAMM Function**
- [ ] Governance  [ ] Design  [x] Implementation  [x] Verification  [ ] Operations

**NIST CSF 2.0 Function(s) this story covers**
- [ ] GV Govern  [ ] ID Identify  [x] PR Protect  [ ] DE Detect  [ ] RS Respond  [ ] RC Recover
PR.DS-1, PR.DS-2, PR.AC-3, PR.AC-4

**CSA CCM v4 Domain(s)**
- CCM: DSP-07 (Data Classification), IVS-01 (Infrastructure Security — gateway layer)

## Threat Model

### STRIDE
| Threat | Component | Attack Scenario | Mitigation |
|--------|-----------|-----------------|------------|
| Info Disclosure | BFF `view_secops` | BFF calls engine without forwarding tenant context; engine returns all tenants' data | `tenant_id` resolved from `AuthContext` via `resolve_tenant_id(request)`; passed as query param |
| Tampering | `_normalise_scan` | Old `_latest_per_repo` dedup keyed on `project` field which could be spoofed to collide rows | Removed; engine-side PK dedup is authoritative |
| DoS | BFF cache | Cache miss floods engine with requests during high load | Existing `cached_view` TTL unchanged; still in place |
| Info Disclosure | `secops_latest_scan` response | `account_id` returned in BFF response exposes internal account IDs to frontend | `account_id` is an opaque UUID — acceptable; not a secret; already returned by other engine endpoints |

### PASTA (credentials/IAM/network — N/A for BFF read-only change)
N/A — this story reads data, changes no credential or auth flows.

## MITRE ATT&CK Techniques Addressed
| Technique ID | Name | D3FEND Countermeasure | How this story addresses it |
|-------------|------|----------------------|----------------------------|
| T1190 | Exploit Public-Facing Application | D3-NTF (Network Traffic Filtering) | Tenant isolation enforced at BFF layer via `resolve_tenant_id`; engine endpoint also enforces it (defense in depth) |

## Acceptance Criteria (Functional)
- [ ] `view_secops` calls `GET /api/v1/secops/latest-scans?tenant_id=<id>` (single call) instead of two separate `/sast/scans` and `/dast/scans` calls
- [ ] If the `latest-scans` endpoint returns a non-2xx or is unavailable, BFF falls back to the two separate calls (graceful degradation — not a fallback with fabricated data)
- [ ] `_latest_per_repo()` function is removed from `shared/api_gateway/bff/secops.py`
- [ ] `_normalise_scan` reads `critical_count`, `high_count`, `medium_count`, `low_count` columns directly from the row (not from `summary` JSONB). Falls back to 0 if column absent (for backwards compat with old rows).
- [ ] `_aggregate_kpis` and `_build_scan_trend` are unchanged in logic — they still consume the normalised scan list
- [ ] `account_id` is included in each normalised scan object as `"account_id"` field (enables frontend to link back to account detail)
- [ ] `GET /api/v1/views/secops` returns `sastScans` and `dastScans` correctly split from the unified `latest-scans` response (filter by `scan_type` field)
- [ ] BFF smoke test: `GET /api/v1/views/secops` with valid auth returns 200 with `sastScans`, `dastScans`, `summary`, `kpiGroups`, `scanTrend`

## Acceptance Criteria (Security — must pass bmad-security-reviewer)
- [ ] `tenant_id` passed to engine as query param — resolved from `AuthContext`, never from request query string directly
- [ ] `_latest_per_repo` removed — no Python-level dedup that could mask a real cross-tenant data bug
- [ ] Engine call uses `fwd_headers` with `X-Auth-Context` forwarded (same as other BFF views)
- [ ] No new fallback data or mock data introduced — if engine returns empty list, BFF returns empty list (constitution rule: no BFF fallbacks to mask engine gaps)
- [ ] Cache key unchanged; cache TTL unchanged; no new cache bypass paths introduced
- [ ] `account_id` included in normalised scan response but `credential_ref` is NOT included (never expose credential references to frontend)
- [ ] Base image pinned (no `latest`) — SLSA Level 1 for gateway image

## Technical Notes

### view_secops change (secops.py)

Replace the two-call `fetch_many` block with a single call to `latest-scans`:

```python
raw_latest = await safe_get(
    "secops",
    f"/api/v1/secops/latest-scans",
    {"tenant_id": tenant_id},
    auth_headers=fwd_headers,
)

if raw_latest is None:
    # graceful degradation: fall back to the old two separate calls
    results = await fetch_many([
        ("secops", "/api/v1/secops/sast/scans", qs),
        ("secops", "/api/v1/secops/dast/scans", qs),
    ], auth_headers=fwd_headers)
    raw_sast, raw_dast = results
    raw_all = _extract(raw_sast) + _extract(raw_dast)
else:
    raw_all = _extract(raw_latest)
```

Then split by `scan_type` field to build `sast_scans` and `dast_scans`:

```python
# No _latest_per_repo call — engine guarantees one row per (account_id, scan_type)
sast_scans = [_normalise_scan(r, "sast") for r in raw_all if r.get("scan_type", "sast") == "sast"]
dast_scans = [_normalise_scan(r, "dast") for r in raw_all if r.get("scan_type") == "dast"]
```

### _normalise_scan severity resolution update

```python
def _normalise_scan(raw: dict, source: str) -> dict:
    # Prefer flat columns from secops_latest_scan; fall back to summary JSONB for old rows
    def _sev(col_key: str, summary_key: str) -> int:
        if raw.get(col_key) is not None:
            return int(raw[col_key])
        summary = raw.get("summary") or {}
        if isinstance(summary, str):
            try:
                summary = _j.loads(summary)
            except Exception:
                summary = {}
        return int(summary.get(summary_key) or 0)

    return {
        ...
        "account_id":     raw.get("account_id", ""),
        "critical":       _sev("critical_count", "critical"),
        "high":           _sev("high_count",     "high"),
        "medium":         _sev("medium_count",   "medium"),
        "low":            _sev("low_count",      "low"),
        ...
    }
```

### Gateway image tag

Gateway image after this story: `yadavanup84/threat-engine-api-gateway:v-bff-secops-repoacct1`

## Key Files
- `/Users/apple/Desktop/threat-engine/shared/api_gateway/bff/secops.py` — primary change: remove `_latest_per_repo`, update `view_secops`, update `_normalise_scan`

## Definition of Done
- [ ] Code implemented and builds locally
- [ ] Docker image built and pushed: `yadavanup84/threat-engine-api-gateway:v-bff-secops-repoacct1`
- [ ] K8s manifest updated with new image tag
- [ ] kubectl apply and rollout status clean
- [ ] bmad-security-reviewer: no BLOCKERS
- [ ] bmad-qa: BFF smoke test passes: `GET /api/v1/views/secops` returns 200 with expected shape
- [ ] Post-deploy: `_latest_per_repo` no longer appears in gateway pod logs
- [ ] Memory updated at `/Users/apple/.claude/projects/-Users-apple-Desktop-threat-engine/memory/`
