# CIEM-01 Security Architecture Review
## GET /api/v1/ciem/log-sources

**Story**: CIEM-01 — Log Sources Endpoint  
**Review date**: 2026-05-02  
**Reviewer**: bmad-security-architect  
**Gate status**: CONDITIONAL PASS — 3 blockers, 4 warnings. Blockers must be resolved before dev starts.

---

## 1. STRIDE Threat Model

### Component: GET /api/v1/ciem/log-sources

| STRIDE Category | Threat | Attack Vector | Mitigation | Status |
|-----------------|--------|---------------|------------|--------|
| **Spoofing** | Attacker spoofs tenant_id query parameter to retrieve another tenant's log source list | Unauthenticated/forged `tenant_id` in query string | `require_permission("ciem:read")` via `Depends()` forces valid `X-Auth-Context`; tenant_id in JWT claims must match param | BLOCKER: Endpoint must validate that `tenant_id` in query param == `auth.tenant_id` from the auth context. Current pattern in `/api/v1/ciem/findings` does NOT enforce this — an authenticated user of tenant A could pass tenant B's `tenant_id`. |
| **Spoofing** | BFF forwards request with no auth context (None `X-Auth-Context`) when gateway auth fails open | Gateway fail-open scenario | AuthMiddleware rejects all non-health paths when `_AUTH_AVAILABLE=True`; confirmed in `api_server.py` lines 97-98 | PASS — middleware is enforced |
| **Tampering** | Attacker manipulates `finding_data->>'source_type'` in `ciem_findings` to inject a false log source record | Malicious CIEM scan job writes crafted `source_type` value | `source_type` values are produced by internal scanner, not user input; but JSONB extraction in the query must use `->>'source_type'` operator, not `json_extract_path_text` with user-supplied key name | WARNING: Validate the `source_type` extraction uses a static JSONB key — confirmed as `finding_data->>'source_type'` which is safe. No user-supplied JSONB key path. |
| **Tampering** | SQL injection via `tenant_id` query parameter | Malformed UUID or string in `tenant_id` | Must use parameterized query `WHERE tenant_id = %s` — never f-string concatenation | BLOCKER: Enforce parameterized query — confirmed required by database-operations.md. No raw string building permitted. |
| **Repudiation** | Admin calls endpoint on behalf of another tenant; no audit trail | Authorized cross-tenant access via elevated role | `RequestLoggingMiddleware` + `CorrelationIDMiddleware` log all requests; no audit log specific to this query | WARNING: Add structured log entry at INFO level on each call: `logger.info("log-sources query", extra={"tenant_id": ..., "caller_level": auth.level, "result_count": ...})` |
| **Information Disclosure** | Response leaks `account_id` values for a tenant's cloud accounts to a low-privilege caller (viewer role) | Viewer (level 4) calls endpoint and sees account identifiers | `strip_sensitive_fields()` currently strips `credential_ref` and `event_raw` — does NOT strip `account_id` from log-source aggregation response | WARNING: `account_id` in log-sources response is an IAM-adjacent field. For auth level >= 4 (viewer), consider masking last 4 chars. Not a blocker if RBAC enforces `ciem:read` which excludes viewer. Verify: current permission matrix — if viewer has `ciem:read`, this is a blocker. |
| **Information Disclosure** | Response includes log bucket names / storage account names embedded in a future `log_source` field via log_source_finder | JSONB `finding_data->>'log_source'` leaks S3 bucket names or CloudWatch log group paths | Proposed endpoint aggregates by `source_type` only, not by `log_source` bucket name | PASS for v1 — bucket path not in response shape. Must be enforced in SQL `SELECT` column list. Do not SELECT `log_source` or `finding_data`. |
| **Information Disclosure** | `is_pending` flag combined with `account_id` leaks account onboarding timeline to an attacker who can query the endpoint | Authenticated attacker enumerates new accounts by watching `pending_first_ingest` accounts appear and disappear | BFF is the only caller; endpoint is not exposed directly on ELB | PASS — internal service mesh only. Document this assumption explicitly. |
| **Denial of Service** | Large number of `ciem_findings` rows causes GROUP BY aggregation to time out or consume excessive DB memory | Tenant with millions of findings triggers slow query | No LIMIT on aggregation GROUP BY query; PostgreSQL will full-scan without index | BLOCKER: Add `LIMIT 500` on the outer aggregation result. Add composite index `(tenant_id, account_id, last_seen_at)` on `ciem_findings`. Add `statement_timeout` (5s) on the DB connection for this query. |
| **Denial of Service** | BFF calls endpoint on every page load with no caching | High UI traffic hammers CIEM DB via repeated GROUP BY | BFF uses `cached_view()` with `TTL_CIEM` — same cache wraps this call | PASS — BFF caching already present. Confirm TTL_CIEM value is >= 60 seconds. |
| **Elevation of Privilege** | CIEM scan job (Kubernetes Job) can write arbitrary `source_type` values into `ciem_findings.finding_data`, then query `/log-sources` to observe its own injected data | Compromised scan job pollutes log-source aggregation | Scan job uses the same CIEM DB credentials as the API; no separate write-only credential for scanner | WARNING: Scanner should have INSERT-only permission on `ciem_findings`; API should have SELECT-only. Currently both use the same `CIEM_DB_*` env vars. File as tech debt. |
| **Elevation of Privilege** | `POST /api/v1/scan` and `POST /api/v1/scan/all` do NOT have `require_permission()` on them (api_server.py lines 144, 244) | Authenticated user with any permission triggers a scan Job | This is pre-existing — not introduced by CIEM-01. File separately. | OUT OF SCOPE for this story but noted. |

---

## 2. PASTA Adversary Model (Stages 3–5)

### Stage 3 — Application Decomposition

Data flows for `GET /api/v1/ciem/log-sources`:

```
Browser / BFF
  → Gateway AuthMiddleware (X-Auth-Context injection)
  → CIEM api_server.py: GET /api/v1/ciem/log-sources
  → psycopg2 → RDS ciem DB
      SELECT (tenant_id, account_id, provider, finding_data->>'source_type'),
             COUNT(*), MAX(last_seen_at)
      FROM ciem_findings
      WHERE tenant_id = %s
      GROUP BY ...
  → Optional cross-DB join: onboarding DB cloud_accounts (created_at for pending check)
  → Response: [{source_name, log_type, provider, account_id, status, finding_count, last_seen_at, is_pending}]
```

Trust boundaries crossed:
1. Internet → ELB → Gateway (auth enforced at gateway)
2. Gateway → CIEM pod (internal mesh, X-Auth-Context header injected)
3. CIEM pod → RDS ciem DB (private subnet, psycopg2)
4. CIEM pod → RDS onboarding DB (cross-DB query for pending check — second trust boundary)

### Stage 4 — Threat Analysis

**Adversary goal**: Discover which log sources are NOT being collected → identify detection blind spots → execute attacks in those gaps.

**Attack path 1 — Log Coverage Reconnaissance**:
- Attacker compromises a low-privilege CSPM user account (T1078.004 — Cloud Accounts)
- Calls `GET /api/v1/ciem/log-sources?tenant_id=<victim-tenant>`
- Observes `status: stale` on `vpc_flow` source for account `123456789012`
- Infers: VPC Flow Logs not recently processed → network-level attacks not being detected
- Pivots: Uses T1046 (Network Service Scanning) or T1040 (Network Sniffing) in that account, knowing VPC Flow gaps exist

**Attack path 2 — Tenant Enumeration via Status Drift**:
- Attacker with valid auth token polls `/log-sources` over time
- Correlates `pending_first_ingest` accounts appearing → learns when new cloud accounts are onboarded
- Times subsequent attack to the 72-hour grace window when CIEM detection is not yet active (T1562.008 — Disable Cloud Logs)

**Attack path 3 — Supply Chain via Stale Source Exploitation**:
- Source `cloudtrail` shows `status: stale` on 3 accounts
- Attacker injects malicious CloudTrail event format (T1565.001 — Stored Data Manipulation) knowing parser will skip stale sources
- Creates a detection gap that persists until next ingest cycle

**Attack path 4 — BFF Cache Poisoning**:
- If the BFF cache TTL is long (>5 min) and a log source goes stale, the UI continues showing `status: active`
- Attacker deliberately triggers log pipeline failure on one account
- UI operator sees green (cached active) while detection is actually down
- Window of exploitation matches cache TTL

### Stage 5 — Vulnerability and Weakness Analysis

| Weakness | Path | Exploitability | Impact |
|----------|------|----------------|--------|
| No tenant_id enforcement in JWT vs query param | Path 1 | Medium (requires valid auth) | High — cross-tenant data read |
| `is_pending` leaks onboarding timeline | Path 2 | Low (internal only) | Medium — timing of new accounts |
| Stale status not actionable — no alert | Path 3 | Low | High — silent detection gap |
| BFF cache hides real staleness | Path 4 | Medium | High — operator blind spot |
| No rate limit on this endpoint | Path 1 | Low | Medium — enumeration |

---

## 3. MITRE ATT&CK for Cloud — Detection Mapping

The `/log-sources` endpoint surfaces which log sources are active. The `source_type` field identifies which techniques each source DETECTS.

| source_type | ATT&CK Technique Detected | Sub-technique | Detection Method |
|-------------|--------------------------|---------------|------------------|
| `cloudtrail` | T1078 — Valid Accounts | T1078.004 Cloud Accounts | Unusual API call patterns, console logins |
| `cloudtrail` | T1530 — Data from Cloud Storage | — | S3:GetObject in bulk |
| `cloudtrail` | T1136 — Create Account | T1136.003 Cloud Account | iam:CreateUser, CreateAccessKey |
| `cloudtrail` | T1562 — Impair Defenses | T1562.008 Disable Cloud Logs | cloudtrail:StopLogging, DeleteTrail |
| `cloudtrail` | T1580 — Cloud Infrastructure Discovery | — | Describe* API calls at scale |
| `vpc_flow` | T1040 — Network Sniffing | — | Detection gap when missing (T1040 succeeds undetected) |
| `vpc_flow` | T1046 — Network Service Scanning | — | Port scan patterns in flow logs |
| `vpc_flow` | T1021 — Remote Services | T1021.007 Cloud Services | Unusual cross-VPC lateral movement |
| `alb` | T1190 — Exploit Public-Facing Application | — | HTTP error rate spikes, scanner patterns |
| `alb` | T1059 — Command and Scripting Interpreter | T1059.007 JavaScript | Web shell traffic in ALB access logs |
| `waf` | T1190 — Exploit Public-Facing Application | — | OWASP ruleset triggers |
| `guardduty` | T1595 — Active Scanning | — | GuardDuty recon finding types |
| `guardduty` | T1078 — Valid Accounts | T1078.004 Cloud Accounts | GuardDuty credential anomalies |
| `eks_audit` | T1610 — Deploy Container | — | Kubectl exec, privileged pod creation |
| `eks_audit` | T1613 — Container and Resource Discovery | — | Excessive API server enumeration |
| `rds_audit` | T1078 — Valid Accounts | — | DB login failures, privilege escalation |
| `cloudfront` | T1190 — Exploit Public-Facing Application | — | CDN-layer request anomalies |
| `azure_activity` | T1078 — Valid Accounts | T1078.004 Cloud Accounts | Azure AD sign-in anomalies |
| `gcp_audit` | T1562 — Impair Defenses | T1562.008 Disable Cloud Logs | Sink deletion, log exclusion |

### D3FEND Coverage Gaps (ATT&CK → D3FEND)

| ATT&CK | D3FEND Countermeasure | Coverage via `source_type` |
|--------|----------------------|---------------------------|
| T1040 (Network Sniffing) | D3-NTF (Network Traffic Filtering) | Requires `vpc_flow` to be active; stale = gap |
| T1562.008 (Disable Cloud Logs) | D3-LFCS (Log File Collection) | Detected by `cloudtrail` — meta-detection (detecting disablement) |
| T1078.004 (Cloud Accounts) | D3-UA (User Account Analysis) | `cloudtrail` + `azure_activity` + `gcp_audit` cover this |
| T1190 (Exploit Public-Facing) | D3-WSAA (Web Session Activity Analysis) | `alb` + `waf` required; if both stale = full gap |

**Critical gap**: If `vpc_flow` is stale AND `cloudtrail` is stale simultaneously, T1040 and T1046 have ZERO detection coverage. The log-sources endpoint should surface a `combined_coverage_gap` flag when two or more detection-critical sources are stale. This is a warning, not a blocker for CIEM-01 v1.

---

## 4. OWASP SAMM Design Review

### SD1 — Threat Assessment

| Check | Status | Notes |
|-------|--------|-------|
| STRIDE applied | PASS | See section 1 |
| PASTA adversary model completed | PASS | See section 2 |
| Attack surface documented | PASS | Two DB cross-references, one new endpoint |
| Trust boundaries identified | PASS | 4 boundaries documented |

### SD2 — Security Requirements

| Check | Status | Notes |
|-------|--------|-------|
| Authentication required | PASS | `require_permission("ciem:read")` via `Depends()` |
| Authorization: tenant isolation | BLOCKER | Must validate JWT tenant_id == query param tenant_id |
| Sensitive data fields defined | PASS | `account_id` in response is acceptable; `credential_ref` not in response |
| Input validation | PASS | `tenant_id` is a string param; JSONB key is static |
| Output encoding | PASS | FastAPI/Pydantic response model handles serialization |

### SD3 — Secure Architecture

| Check | Status | Notes |
|-------|--------|-------|
| No new DB schema (no migration risk) | PASS | Decision D-CIEM-4 confirmed |
| No new external calls (no SSRF surface) | PASS | DB query only; no cloud SDK calls |
| No new credential stores accessed | CONDITIONAL | Pending check accesses onboarding DB — same creds as existing scan/all pattern |
| DoS mitigated (LIMIT on query) | BLOCKER | Must add LIMIT 500 + statement_timeout |
| Error messages sanitized | PASS | `raise HTTPException(status_code=500, detail=str(e))` — str(e) may leak DB internals |

NOTE on error detail: `detail=str(e)` in exception handlers leaks PostgreSQL error text (table names, column names) to callers. Existing pattern in api_server.py. File as separate tech debt; not a blocker for this story specifically since pattern is pervasive.

---

## 5. NIST CSF 2.0 Function Tags

| Function | Category | Subcategory | Applicability to CIEM-01 |
|----------|----------|-------------|--------------------------|
| **ID.AM** — Asset Management | ID.AM-01 | Inventories of hardware assets | Log sources = inventory of data plane assets |
| **ID.AM** | ID.AM-07 | Inventories of data assets | `source_type` enumerates where data resides |
| **DE.CM** — Continuous Monitoring | DE.CM-01 | Networks are monitored | `vpc_flow` active/stale status directly maps to this |
| **DE.CM** | DE.CM-03 | Personnel activity is monitored | `cloudtrail` active/stale maps to this |
| **DE.CM** | DE.CM-09 | Computing hardware and software are monitored | `eks_audit` and `rds_audit` status |
| **DE.AE** — Adverse Event Analysis | DE.AE-02 | Potentially adverse events are analyzed | Stale sources create gaps in DE.AE coverage |
| **PR.DS** — Data Security | PR.DS-01 | Data at rest is protected | No new data at rest; existing `ciem_findings` |
| **RS.AN** — Incident Analysis | RS.AN-03 | Analysis of incident is performed | `stale` source status directly impairs incident analysis |
| **GV.OC** — Organizational Context | GV.OC-05 | Outcomes and security requirements understood | CIEM posture score driven by log coverage |

**RS/RC Gap filed**: When `status: stale` is returned, there is no automated alert or remediation path. This endpoint surfaces the gap but does not trigger a response. A follow-on story should add a webhook/alert when any source transitions to stale (RS.AN gap). File as CIEM-02.

---

## 6. CSA CCM v4 Domain Mapping

| CCM Domain | Control ID | Control Name | Applicability |
|------------|-----------|--------------|---------------|
| **LOG** — Logging and Monitoring | LOG-01 | Logging and Monitoring Policy | Log-sources endpoint makes CIEM log coverage observable |
| **LOG** | LOG-05 | Audit Log Access and Accountability | Endpoint itself must be audit-logged (caller, tenant, result_count) |
| **LOG** | LOG-06 | Security Information and Event Management | `status: stale` means SIEM has a gap — surface via this endpoint |
| **IAM** — Identity and Access Management | IAM-01 | Identity and Access Management Policy | `require_permission("ciem:read")` enforces IAM control |
| **IAM** | IAM-09 | User Access Authorization | tenant_id claim in JWT vs query param — cross-tenant enforcement |
| **IAM** | IAM-12 | Audit Logs for IAM | `cloudtrail` source_type specifically covers IAM audit (T1078) |
| **IVS** — Infrastructure and Virtualization Security | IVS-06 | Network Architecture | `vpc_flow` source status maps to IVS network visibility |
| **IVS** | IVS-07 | Network Defense | `waf` source status maps to IVS-07 — WAF log coverage |
| **DSP** — Data Security and Privacy | DSP-07 | Data Protection by Design | No new PII introduced; `account_id` is business identifier, not PII |
| **SEF** — Security Event Management | SEF-01 | Information Security Event Triage | Stale sources = gaps in SEF-01 triage capability |

---

## 7. Architecture Decision: source_type Extraction Strategy

### ADR-CIEM-01: JSONB Extraction at Query Time vs. New Column

**Context**: `source_type` exists inside `ciem_findings.finding_data` JSONB. The proposed endpoint aggregates by `finding_data->>'source_type'`. An alternative is to add a dedicated `source_type VARCHAR(50)` column.

**Options evaluated**:

| Option | Description | Pros | Cons |
|--------|-------------|------|------|
| A (Proposed) | Extract at query time: `finding_data->>'source_type'` in GROUP BY | No migration, no schema change (D-CIEM-4) | JSONB operator in GROUP BY is slightly slower; NULL rows if `source_type` missing; index needed |
| B | Add `source_type VARCHAR(50)` as a top-level column | Indexable directly; faster GROUP BY; schema is explicit | Requires migration + backfill; old rows have NULL; blocks parallelism with D-CIEM-4 |
| C | Persist a separate `ciem_log_sources` materialized table | Pre-aggregated; sub-millisecond reads | New table = new attack surface + sync logic + extra writes on every scan |

**Decision**: RECOMMEND Option A (JSONB extraction at query time) for v1, with these conditions:

1. The query must add a functional index: `CREATE INDEX IF NOT EXISTS idx_ciem_findings_source_type ON ciem_findings ((finding_data->>'source_type'), tenant_id, last_seen_at);`
2. The GROUP BY must filter out NULL source_type: `WHERE finding_data->>'source_type' IS NOT NULL`
3. If response time > 200ms at p99 after index is added, file CIEM-03 to promote to a real column.
4. Option B is the correct long-term target. When the next schema migration is already being done for another reason, add `source_type` column at the same time and backfill.

**Rationale**: Alignment with D-CIEM-4 (no schema migration) is the deciding factor. The index makes extraction fast. The JSONB key `source_type` is a static string — no injection risk. Option C adds write complexity without proportionate read benefit at current data volumes.

---

## 8. Security Requirements for Story Acceptance Criteria

These are required checks before the story can be closed. Each must be verified in code review.

### AC-S1 — Tenant Isolation (BLOCKER)
The SQL query MUST be:
```sql
SELECT
    account_id,
    provider,
    finding_data->>'source_type'   AS log_type,
    COUNT(*)                       AS finding_count,
    MAX(last_seen_at)              AS last_seen_at
FROM ciem_findings
WHERE tenant_id = %s
  AND finding_data->>'source_type' IS NOT NULL
GROUP BY account_id, provider, finding_data->>'source_type'
LIMIT 500
```
- `tenant_id = %s` is a required WHERE clause, parameterized — NOT an f-string.
- `LIMIT 500` must be present.
- No other tenant's data may appear in the result.
- `tenant_id` from the auth context (JWT) must be compared to the query parameter; if they differ and the caller is not `platform_admin` (level 1), return HTTP 403.

### AC-S2 — Permission Gate (BLOCKER)
```python
auth: Any = Depends(require_permission("ciem:read") if _AUTH_AVAILABLE else (lambda: None))
```
This `Depends()` must be present in the endpoint signature. Pattern is identical to existing `/api/v1/ciem/findings`. No fallback bypass.

### AC-S3 — DoS Protection (BLOCKER)
- `LIMIT 500` on aggregation result (one row per account+provider+source_type combination).
- DB connection for this query must have `statement_timeout` of 5000ms. Either set at connection time or use `SET LOCAL statement_timeout = 5000` before the query.
- If `statement_timeout` fires, return HTTP 504 with generic message, not the PostgreSQL exception text.

### AC-S4 — Credential Field Stripping (WARNING — fix before ship)
The response shape `{source_name, log_type, provider, account_id, status, finding_count, last_seen_at, is_pending}` must NOT include:
- `credential_ref`
- `credential_type`
- `finding_data` (raw JSONB)
- `scan_run_id`
- `resource_uid`

Pass the response through `strip_sensitive_fields()` or explicitly limit the SQL `SELECT` to the response shape columns only. Since this is an aggregation query (GROUP BY), raw finding fields are not in the result set by definition — but verify the SELECT list is explicit.

### AC-S5 — Pending Account Grace Period Query (WARNING)
The `pending` status derivation requires a JOIN to the onboarding DB `cloud_accounts` table. This is a cross-database query and carries additional risk:
- Must use parameterized query: `WHERE tenant_id = %s AND account_id = ANY(%s)` — never string-build the account list.
- If the onboarding DB is unreachable, the endpoint must NOT fail. Default all accounts to `status: active` or `status: stale` (skip the pending check) and log a warning. Never propagate the DB error to the caller.
- The onboarding DB query must also be protected by `statement_timeout` (3000ms).

### AC-S6 — Rate Limiting (WARNING — infra-level, not code-level)
This endpoint has a low cardinality result set but aggregates over potentially large tables. Apply rate limiting at the Gateway level:
- Per tenant_id: max 30 requests/minute.
- Gateway already has rate-limiting middleware; confirm this endpoint falls under the existing CIEM route rate limit.

### AC-S7 — Functional Index (WARNING — DB prerequisite)
Before deploying the endpoint, apply this index migration to the ciem DB:
```sql
CREATE INDEX IF NOT EXISTS idx_ciem_findings_source_type
    ON ciem_findings ((finding_data->>'source_type'), tenant_id, last_seen_at);
```
Without this index, the GROUP BY will do a full table scan for large tenants. This is a DB-side prerequisite, not a code change.

### AC-S8 — BFF Integration
The BFF at `/Users/apple/Desktop/threat-engine/shared/api_gateway/bff/ciem.py` must:
- Add `("ciem", "/api/v1/ciem/log-sources", qs)` to the `fetch_many` list.
- Replace `sources = None` (line 54) with the result.
- Pass `auth_headers=fwd_headers` so the downstream engine receives the `X-Auth-Context` header.
- Map the response: `"logSources": safe_get(sources, "sources", [])` — confirm the engine returns `{"sources": [...]}` at the top level.

### AC-S9 — Audit Log
Every call to `/api/v1/ciem/log-sources` must produce a structured INFO log with:
```
tenant_id=<id>, caller_level=<int>, result_count=<int>, duration_ms=<float>
```
This satisfies CSA CCM LOG-05 and NIST DE.CM audit requirements.

---

## Blockers (Must fix before dev starts)

| ID | Description | Location |
|----|-------------|----------|
| BLOCK-1 | tenant_id from JWT auth context must be enforced against the query parameter — cross-tenant access possible | `api_server.py` endpoint handler |
| BLOCK-2 | `LIMIT 500` + `statement_timeout` must be in the query — no unbounded GROUP BY | SQL query in endpoint |
| BLOCK-3 | `require_permission("ciem:read")` must be in the `Depends()` decorator | `api_server.py` endpoint signature |

## Warnings (Must fix before ship / can do in same PR)

| ID | Description | Priority |
|----|-------------|----------|
| WARN-1 | `strip_sensitive_fields()` or explicit SELECT columns — no raw JSONB or credential fields in response | High |
| WARN-2 | Onboarding DB cross-join must fail gracefully (timeout → default to stale, not error) | High |
| WARN-3 | Functional index on `ciem_findings(finding_data->>'source_type', tenant_id, last_seen_at)` must be applied before first traffic | High |
| WARN-4 | Structured audit log on every call (tenant_id, caller_level, result_count) | Medium |

---

## File Paths Reviewed

- `/Users/apple/Desktop/threat-engine/engines/ciem/ciem_engine/api_server.py`
- `/Users/apple/Desktop/threat-engine/engines/ciem/ciem_engine/source_discovery/log_source_finder.py`
- `/Users/apple/Desktop/threat-engine/shared/api_gateway/bff/ciem.py`
- `/Users/apple/Desktop/threat-engine/engines/ciem/ciem_engine/storage/event_writer.py`
- `/Users/apple/Desktop/threat-engine/.claude/worktrees/keen-dhawan-422cad/consolidated_services/database/schemas/onboarding_schema.sql` (cloud_accounts table — `created_at` column confirmed for grace period query)