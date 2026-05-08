# NET-01 Security Architecture Review
## Network Security UI Data Endpoint — Classified Finding Response

**Reviewer**: Security Architect (OWASP SAMM / STRIDE / PASTA)
**Date**: 2026-05-02
**Story**: NET-01 — Engine-side finding classification for `GET /api/v1/network-security/ui-data`
**Status**: GATE REVIEW — must pass before dev starts

---

## 1. STRIDE Threat Model

### Scope
Component: `GET /api/v1/network-security/ui-data` (ui_data_router.py) and downstream BFF at `shared/api_gateway/bff/network_security.py`.

The proposed change adds server-side classification of findings into four new top-level keys: `security_groups`, `internet_exposure`, `waf`, `topology_findings`. It also renames the existing `topology` key (VPC snapshots) to `topology_snapshots`.

### STRIDE Table

| # | Threat Category | Component | Threat Description | Current Mitigation | Proposed Change Impact | Status |
|---|---|---|---|---|---|---|
| S-1 | **Spoofing** | `_resolve_scan_ids` | Caller supplies `tenant_id` as a plain query parameter. A compromised or mis-configured upstream could supply any tenant_id and receive that tenant's classified findings. | `tenant_id` is passed to every query with `WHERE tenant_id = %s`. Auth middleware validates the JWT/session and attaches `AuthContext`. | No new attack surface — classification happens after findings are fetched and tenant-scoped. | PASS — provided `require_permission` is active |
| S-2 | **Spoofing** | `scan_id` parameter | Caller can supply an arbitrary `scan_id` (UUID). If they supply another tenant's scan_run_id, the second `WHERE tenant_id = %s` guard on network_findings prevents data return — but `network_report` query at line 222 does NOT filter by tenant_id. | network_findings query has `AND tenant_id = %s`; report query is `WHERE scan_run_id = ANY(%s)` — no tenant_id guard. | **BUG PRESENT IN CURRENT CODE, NOT INTRODUCED BY NET-01.** Classified arrays inherit from the findings set (tenant-scoped), but summary data from `network_report` may leak cross-tenant report metadata. | **BLOCKER — existing bug, must fix before ship** |
| T-1 | **Tampering** | `finding_id` in classification output | The new engine-side classification does not mutate `finding_id`. SHA256 determinism is preserved because classification is a read-only filter on DB rows. | finding_id = sha256(rule_id\|resource_uid)[:16] in `_fid()`. | Net zero change. | PASS |
| T-2 | **Tampering** | `effective_exposure` field | `effective_exposure` is read from the DB column (written by the analyzer). Proposed classification uses `effective_exposure = 'internet'` as a routing predicate for the `internet_exposure` array. An attacker who can write to `network_findings` (e.g. a compromised scan worker) could forge `effective_exposure='internet'` on a finding that is actually isolated, causing false positives that may suppress operator alerts for real exposures. | Scan worker writes findings via `to_db_row()`. No integrity check on the value. | Classification amplifies the impact of a tampered `effective_exposure` field — a crafted value directly controls which sub-tab array a finding appears in. | WARNING — integrity-check `effective_exposure` against the allowed enum set on read |
| T-3 | **Tampering** | `network_layer` routing | Proposed classification uses `network_layer IN ('L4_sg', ...)`. If `network_layer` in a DB row contains a value outside the `NetworkLayer` enum (e.g. a provider bug emits `"L4_SG"` in uppercase), that finding silently falls into no array. | `NetworkLayer` enum values are lowercase (`L4_sg`). Non-AWS providers that emit raw strings could mismatch. | Case-sensitivity of routing predicate must be normalised to lowercase. | WARNING — normalise with `.lower()` before routing |
| R-1 | **Repudiation** | Classification logic | Moving classification to the engine removes the BFF audit trace of which findings landed in which sub-tab. If a compliance audit asks "why was this SG finding not in the security_groups tab?", there is no engine-side log. | BFF logs at INFO level; no finding-level classification audit. | Engine should emit one log line: `INFO classified N findings: sg=%d, exposure=%d, waf=%d, topology=%d` with `scan_run_id` and `tenant_id` for post-incident traceability. | WARNING — add structured log |
| I-1 | **Information Disclosure** | `network_report` cross-tenant | As per S-2, `network_report` query lacks `tenant_id` guard. Summary fields (`internet_exposed_resources`, `orphaned_sg_count`) from another tenant could appear in the response. | network_findings query is correctly scoped. | Not introduced by NET-01 but must be fixed. | **BLOCKER** |
| I-2 | **Information Disclosure** | `finding_data` JSONB in classified arrays | The `security_groups` array now contains `finding_data.sg_posture` including `cidrs` (the exact open CIDR ranges), `attached_resource_count`, and `effective_internet_exposure: true`. For viewer-role users, this data must be stripped. | `strip_sensitive_fields()` strips `credential_ref` and `credential_type` for `level > 1`. Does NOT strip `effective_exposure` or `finding_data.sg_posture.cidrs` for viewer level. | Classification surfaces `cidrs` prominently in the `security_groups` sub-tab. Viewer-role should not see CIDR details. | **BLOCKER — viewer role must not receive sg_posture.cidrs** |
| I-3 | **Information Disclosure** | BFF response key rename | Renaming `topology` → `topology_snapshots` is a breaking change. Any BFF consumer that caches or reads the old key `topology` will silently receive an empty list. The BFF currently reads `raw_topology = safe_get(net_data, "topology", [])` at line 157 — this will break immediately. | BFF has `safe_get` defaults. | BFF must be updated atomically with the engine. Zero-day window where old BFF calls new engine will produce empty topology tab. | WARNING — coordinate deploy or add backwards-compat period |
| D-1 | **Denial of Service** | `limit` parameter | Endpoint accepts `limit: int = Query(10000)`. No upper bound validation. A caller can supply `limit=2147483647` to exhaust DB memory on the scan. | Default 10000, no max enforced. | Not changed by NET-01 but classification loop iterates the full returned list four times. With a malicious large limit the CPU cost quadruples. | WARNING — enforce `limit = min(limit, 10000)` |
| D-2 | **Denial of Service** | Classification loop | Proposed code classifies findings in Python with four `if/elif` branches per finding. For 10 000 findings this is ~40 000 branch evaluations in the async endpoint — acceptable, but the list is iterated four times if implemented naively as four separate comprehensions. | No finding count cap beyond the DB LIMIT. | Use a single-pass classification loop (one for-loop, four buckets). | WARNING — single-pass implementation required |
| D-3 | **Denial of Service** | Cache interaction | BFF caches on `cache_key("network-security", tenant_id, scan_id, ...)` with `TTL_NETWORK`. If engine is redeployed mid-cache-window, BFF may serve stale old-format response (with `topology` key, without `security_groups` key) for the cache TTL duration. | `TTL_NETWORK` cache in BFF. | NET-01 must invalidate or bypass the BFF cache at deploy time, or the BFF must handle both key names. | WARNING |
| E-1 | **Elevation of Privilege** | Classification does not add permissions | Classification is a read-only filter — no new DB writes, no new IAM calls. `require_permission("network:read")` remains the gate. | `require_permission` dependency on endpoint. | Net zero change. | PASS |
| E-2 | **Elevation of Privilege** | WAF findings now pre-labelled | An attacker with viewer access who can see `waf` array contents could identify which internet-facing ALBs have no WAF (`net.l6.internet_facing_alb_no_waf`). Combined with the LB ARN in `resource_uid`, they know exactly which ALBs are unprotected. | WAF findings exist in the flat `findings` array today — same disclosure. | No new elevation. Viewer-role strip policy for `effective_exposure` mitigates. | PASS (with I-2 fix) |

---

## 2. PASTA Adversary Model (Stages 3–5)

### Stage 3 — Application Decomposition / Attack Surface

**New attack surface introduced by NET-01:**

| Surface Element | Entry Point | Data Exposed |
|---|---|---|
| `security_groups` array key | `GET /ui-data?tenant_id=X` | sg_posture.cidrs, sg_posture.sg_name, attached_resource_count, effective_internet_exposure bool |
| `internet_exposure` array key | same endpoint | All findings where effective_exposure='internet' OR network_layer='L5_lb' — direct enumeration of public resources |
| `waf` array key | same endpoint | All ALBs with no WAF association, WAF ACL ARNs, logging state |
| `topology_snapshots` key (renamed) | same endpoint | VPC CIDR blocks, IGW IDs, flow_log_enabled bool, public_subnet_count |
| Classification predicate on `effective_exposure` column | DB value influenced by scan worker | Routing determines analyst visibility |

**Pre-existing attack surface unchanged by NET-01:**
- `network_report` without tenant_id guard (S-2 / I-1 — blocker independent of NET-01)
- `limit` parameter without upper bound (D-1)

### Stage 4 — Threat Analysis

**Adversary profile**: External attacker with read-only CSPM viewer credentials (valid JWT, viewer role, level > 1).

**Threat T-A: Reconnaissance via internet_exposure array**
- Goal: enumerate all internet-facing resources in the target tenant
- Path: `GET /api/v1/views/network-security?tenant_id=T` → BFF forwards to engine → receives `internet_exposure` array pre-filtered to `effective_exposure='internet'` + L5_lb findings
- Net-01 makes this trivially machine-readable. Previously the attacker had to parse `effective_exposure` from a flat 10 000-finding list; now it is a dedicated array.
- Mitigated by: viewer role stripping `effective_exposure` field (must be implemented — currently not done)

**Threat T-B: WAF gap enumeration**
- Goal: identify unprotected internet-facing ALBs
- Path: `waf` array — all `rule_id=net.l6.internet_facing_alb_no_waf` findings contain `resource_uid` = ALB ARN
- Combined with `internet_exposure` array, attacker has a complete list of ALBs with no Layer 7 protection
- Mitigated by: viewer role receiving only severity/count aggregates, not ARNs — currently NOT enforced for network findings

**Threat T-C: Tenant cross-contamination via network_report**
- Goal: discover another tenant's scan summary (posture score, exposed resource count)
- Path: guess or obtain another tenant's `scan_run_id` (UUIDs are random but could leak via logs/BFF responses), call `GET /ui-data?tenant_id=attacker_tenant&scan_id=victim_scan_run_id`
- `network_report` query returns summary data without tenant_id check — victim's posture_score, internet_exposed_resources count visible in `summary` block
- Not introduced by NET-01 but remains a blocker

**Threat T-D: Scan worker injection of effective_exposure**
- Goal: manipulate which findings appear in the `internet_exposure` sub-tab
- Path: compromise scan worker (e.g. via SSRF on cloud SDK, supply-chain attack on provider module) → write findings with forged `effective_exposure='internet'` on isolated resources, OR write `effective_exposure='isolated'` on truly internet-exposed resources (suppressing alerts)
- Impact: security analyst sees clean `internet_exposure` tab while real exposures are hidden in general findings
- Mitigated by: validate `effective_exposure` against `ExposureLevel` enum on read in the classification function

### Stage 5 — Attack Tree

```
Root: Obtain tenant network security posture without authorization

  [OR]
  +-- [1] Abuse viewer role for reconnaissance (T-A + T-B)
  |     +-- Authenticate as viewer (valid credentials)
  |     +-- Call GET /ui-data → receive internet_exposure + waf arrays
  |     +-- Extract: ALB ARNs with no WAF (T1190 reconnaissance)
  |     +-- Extract: SG IDs with SSH/RDP open to 0.0.0.0/0 (T1021 planning)
  |     Mitigation: strip ARNs from viewer role, strip effective_exposure

  +-- [2] Cross-tenant data leak via network_report (T-C)
  |     +-- Obtain any valid scan_run_id for target tenant (log leak, etc.)
  |     +-- Call GET /ui-data?tenant_id=own_tenant&scan_id=victim_scan_run_id
  |     +-- network_report returns victim summary (no tenant_id guard)
  |     Mitigation: add WHERE tenant_id = %s to network_report query

  +-- [3] Suppress internet exposure findings (T-D)
        +-- Compromise scan worker (supply chain / SSRF)
        +-- Write finding_data with effective_exposure='isolated' for exposed SG
        +-- Classification routes finding to topology_findings, not internet_exposure
        +-- Analyst sees zero internet_exposure findings
        Mitigation: validate effective_exposure enum on read; alert on
                    effective_exposure changes between scans for same resource_uid
```

---

## 3. MITRE ATT&CK for Cloud Mapping

### Techniques This Feature DETECTS

| Finding Rule ID | Finding Title | MITRE Technique | Sub-technique |
|---|---|---|---|
| `net.l4.sg_ssh_open_to_world` | SSH open to 0.0.0.0/0 | T1133 | External Remote Services |
| `net.l4.sg_rdp_open_to_world` | RDP open to 0.0.0.0/0 | T1133 | External Remote Services |
| `net.l4.sg_all_traffic_from_any` | All ports open to any | T1190 | Exploit Public-Facing Application |
| `net.l4.sg_cross_vpc_reference` | Cross-VPC SG reference | T1021 | Remote Services (lateral movement) |
| `net.l4.sg_outbound_all_traffic` | Unrestricted outbound | T1048 | Exfiltration Over Alternative Protocol |
| `net.l6.internet_facing_alb_no_waf` | ALB without WAF | T1190 + T1059 | Exploit Public-Facing + Command Injection |
| `net.l6.waf_all_rules_count_mode` | WAF not blocking | T1190 | Exploit Public-Facing Application |
| `net.l6.waf_no_rate_limiting` | No rate limiting rule | T1499 | Endpoint Denial of Service |
| `net.l6.waf_logging_disabled` | WAF logging disabled | T1562.008 | Disable or Modify Cloud Logs |
| `net.l6.waf_missing_owasp_ruleset` | No OWASP managed rule set | T1190 + T1059.007 | Web Shell / Command Injection |
| Internet-facing LB findings (L5) | TLS not enforced | T1040 | Network Sniffing (cleartext credentials) |
| No VPC flow logs (L7) | Flow monitoring gap | T1040 | Network Sniffing — detection gap |

### MITRE D3FEND Defensive Countermeasures (Required per Security Constitution)

| ATT&CK Technique Detected | D3FEND Countermeasure | Implementation |
|---|---|---|
| T1133 (Remote Services) | D3-NTF (Network Traffic Filtering) | SG rule restricts port 22/3389 to specific CIDR |
| T1190 (Exploit Public-Facing) | D3-WSAF (Web Application Firewall) | WAF with OWASP managed rule set |
| T1048 (Exfiltration) | D3-OFI (Outbound Traffic Filtering) | SG outbound rules, VPC endpoint routing |
| T1040 (Network Sniffing) | D3-NTA (Network Traffic Analysis) | VPC Flow Logs enabled + WAF logging |
| T1499 (DoS) | D3-RLI (Rate Limiting) | WAF rate-based rule |
| T1562.008 (Disable Logs) | D3-LEF (Log Event Filtering) | Immutable CloudWatch log groups, S3 bucket with no-delete policy |

### Techniques That COULD EXPLOIT This Feature (the endpoint itself)

| Technique | Description | Attack Path |
|---|---|---|
| T1078.004 (Valid Cloud Accounts) | Stolen viewer-role JWT used to enumerate exposed assets | Call GET /ui-data with stolen token; internet_exposure array gives target list |
| T1530 (Data from Cloud Storage) | Attacker reads internet_exposure array to find misconfigured S3 via LB findings | Pivot from WAF-less ALB findings to discover S3 endpoints |
| T1590.005 (Gather Network Information) | Viewer calls /ui-data to map VPC topology and public subnet count before lateral move | topology_snapshots exposes VPC CIDR, IGW presence, public_subnet_count |

---

## 4. OWASP SAMM Design Review

### Design Function — Security Architecture

| Control | Requirement | Current State | NET-01 Impact | Result |
|---|---|---|---|---|
| SA-1.1 | Identify all data stores and their sensitivity | network_findings (tenant data), network_topology_snapshot (topology), network_report (summary) identified | New sub-array keys expose same data in more accessible form | PASS |
| SA-1.2 | Data classification: PII / confidential / internal | SG CIDRs, resource ARNs are confidential configuration data — should not be viewer-accessible | internet_exposure and security_groups arrays expose ARNs and CIDRs directly | **GAP — viewer stripping not implemented for these fields** |
| SA-2.1 | Component authentication and authorization | `require_permission("network:read")` guards the endpoint | No change to auth gate | PASS |
| SA-2.2 | Least privilege: each role receives minimum data | Viewer role receives full finding including `sg_posture.cidrs` | Classification makes it easier to extract CIDR data systematically | **GAP** |
| SA-3.1 | Separation of concerns: classification logic ownership | Currently split: engine writes layer, BFF classifies. Proposed: engine classifies. | Single source of truth; BFF becomes a pass-through. Reduces complexity. | IMPROVEMENT |

### Design Function — Threat Assessment

| Control | Requirement | Result |
|---|---|---|
| TA-1.1 | STRIDE performed for new components | Done in this document | PASS |
| TA-1.2 | Attack tree for high-risk data flows | Done (PASTA Stage 5) | PASS |
| TA-2.1 | Risk rating assigned to each threat | Blockers vs Warnings distinguished | PASS |
| TA-2.2 | Threats tracked to mitigations | Each STRIDE row has mitigation and status | PASS |

### Design Function — Security Requirements

| Control | Requirement | Current State | Result |
|---|---|---|---|
| SR-1.1 | Security requirements derived from threat model | This review produces ACs below | PASS (via this review) |
| SR-1.2 | Requirements verified at design stage | Gate: no dev without this review | PASS |
| SR-2.1 | Input validation for all parameters | `limit` has no upper bound; `tenant_id` not validated for format | **GAP** |
| SR-2.2 | Output encoding / field stripping per role | `strip_sensitive_fields()` only strips credential fields; does not strip CIDR data or effective_exposure for viewer | **GAP** |

---

## 5. NIST CSF 2.0 Function Tags

| Story Acceptance Criterion | NIST CSF 2.0 Function | Category |
|---|---|---|
| Engine classifies findings into sg/exposure/waf/topology arrays | ID.RA — Risk Assessment | Identify |
| `effective_exposure` validated against enum on read | PR.DS — Data Security | Protect |
| `network_report` query gains `WHERE tenant_id = %s` | PR.AC — Identity Management & Access Control | Protect |
| Viewer role: strip `finding_data.sg_posture.cidrs`, strip `effective_exposure` | PR.AC-3 — Remote Access Managed | Protect |
| Classification log line emitted with scan_run_id + tenant_id | DE.CM — Security Continuous Monitoring | Detect |
| Alert fired when effective_exposure changes from non-internet to internet between scans for same resource_uid | DE.AE — Anomalies and Events | Detect |
| BFF updated atomically with engine (no key rename window) | RS.MI — Mitigation | Respond |
| `limit` parameter capped at 10 000 to prevent resource exhaustion | PR.PT — Protective Technology | Protect |

---

## 6. CSA CCM v4 Domain Mapping

| Finding / Control | CSA CCM v4 Domain | Control ID |
|---|---|---|
| Tenant isolation in every DB query | IAM — Identity & Access Management | IAM-07 |
| network_report tenant_id gap | IVS — Infrastructure & Virtualization Security | IVS-04 |
| Viewer role data stripping (CIDR, ARN) | DSP — Data Security and Privacy | DSP-07 |
| SG open to internet findings (L4) | IVS-06 — Network Security | IVS-06 |
| WAF coverage findings (L6) | IVS-09 — Traffic Inspection | IVS-09 |
| VPC Flow Log findings (L7) | LOG — Logging & Monitoring | LOG-05 |
| WAF logging disabled finding | LOG-01 — Audit Logging / Intrusion Detection | LOG-01 |
| effective_exposure integrity | CCC — Change Control & Configuration Management | CCC-07 |
| Classification logic single-source-of-truth (engine) | AIS — Application & Interface Security | AIS-04 |

---

## 7. Architecture Decision: Engine-side vs BFF-side Classification

### ADR-NET-01: Finding Classification Belongs in the Engine

**Status**: Recommended (ADOPT)

**Context**:
Currently, the network engine returns a flat `findings` array. The BFF at `bff/network_security.py` attempts to re-classify via `_classify()`, but the guard condition at line 160 (`if raw_findings and not (raw_sg or raw_exposure or raw_topology or raw_waf)`) never fires because `topology` (VPC snapshots from the engine) is always non-empty. As a result, the BFF sub-tabs (`security_groups`, `internet_exposure`, `waf`, `topology`) are always empty, and users see all findings only in the flat Findings tab.

**Decision**: Move classification to the engine (`ui_data_router.py`).

**Rationale**:

1. **Authoritative data is in the engine.** `network_layer` and `effective_exposure` are DB columns written by the analyzers. The BFF's `_classify()` function approximates layer attribution using heuristics on `service`, `resource_type`, `rule_id`, and `posture_category` strings — these are unreliable proxies. The engine has the ground-truth column values.

2. **The BFF guard bug is structural, not incidental.** The guard condition was designed to fire when the engine returns no sub-tab arrays, but the engine has always returned a non-empty `topology` key (VPC snapshots). This is a permanent false-negative in the guard. Fixing it requires either removing the guard or renaming the key — both changes are simpler to do in the engine's response shape.

3. **Dual-classification creates inconsistency.** When the BFF does classify (on the check engine fallback path), it uses service-name heuristics. When the engine classifies, it uses exact DB column values. A finding for the same resource can land in different sub-tabs depending on which code path runs — this is a security display inconsistency that can cause analysts to miss findings.

4. **Security principle: classification predicate is a security boundary.** Which findings appear in the `internet_exposure` tab determines which resources an analyst treats as urgent. This boundary must be derived from the authoritative `effective_exposure` column — not from string matching on `rule_id` or `service` in the BFF.

5. **Single responsibility.** The engine owns the network security domain model. The BFF owns presentation aggregation. Classification by `network_layer` is domain logic, not presentation logic.

**Consequences**:
- BFF `_classify()` function and the `_SG_SVCS`, `_TOPOLOGY_SVCS`, `_EXPOSURE_SVCS`, `_WAF_SVCS` constants become dead code after NET-01 ships — they must be removed, not left as fallback.
- The `topology` key rename (`topology` → `topology_snapshots`) is a breaking API change. BFF must be updated in the same deploy. Add a backwards-compatibility period (return both keys for one sprint cycle, then remove old key) if the frontend reads the key directly.
- The `if raw_findings and not (...)` guard in the BFF should be removed entirely. Its only remaining function would be the check engine fallback — which should be a monitoring alert (network engine not running) not a silent data merge.

**Rejected Alternative**: Keep classification in BFF with a bug fix to the guard condition.
- Reason: even with the guard fixed, the BFF's string-heuristic classification is less accurate than the engine's DB column attribution. String-matching `rule_id` for 'waf' to classify WAF findings works for AWS but breaks for Azure/GCP rule naming conventions. The engine's `network_layer=NetworkLayer.L6_WAF` enum value is CSP-agnostic.

---

## 8. Security Requirements — Story Acceptance Criteria Additions

These must be added to the NET-01 story file and verified before merge.

### BLOCKERS (must be resolved before any dev work ships)

**B-1: Fix network_report cross-tenant query**
- File: `engines/network-security/network_security_engine/api/ui_data_router.py` line 222
- Current: `SELECT * FROM network_report WHERE scan_run_id = ANY(%s)`
- Required: `SELECT * FROM network_report WHERE scan_run_id = ANY(%s) AND tenant_id = %s`
- Pass parameter: `(scan_ids, tenant_id)`
- This is a cross-tenant information disclosure bug independent of NET-01 but must be fixed in the same PR.

**B-2: Viewer role must not receive sg_posture.cidrs or finding_data security details**
- Extend `strip_sensitive_fields()` in `ui_data_router.py` to accept a `role_level` parameter from `auth.level`
- For `auth.level >= 3` (viewer = level 4 per platform RBAC): remove `finding_data.sg_posture.cidrs`, `finding_data.sg_posture.sg_name`, `effective_exposure` from each finding in `security_groups` and `internet_exposure` arrays
- Viewer should receive finding count and severity only for these sensitive sub-arrays
- Reference: RBAC.md — viewer role (l4), analyst role (l4, but feature:read only); strip policy should match datasec/iam pattern

**B-3: effective_exposure must be validated against enum before routing**
- In the classification function (engine-side), validate `effective_exposure` value against `ExposureLevel` enum members before using it as a routing predicate
- If value is not in `{internet, cross_vpc, vpc_internal, subnet_only, isolated}`, log a warning and route to `topology_findings` (safe default) — do not raise an exception that would break the response

### WARNINGS (must be resolved before ship, acceptable to fix in same sprint)

**W-1: limit parameter must be capped**
- `limit: int = Query(10000)` → add `le=10000` Pydantic validator: `limit: int = Query(default=500, ge=1, le=10000)`
- Default reduced from 10000 to 500 for the UI endpoint; callers needing full export should use a paginated export endpoint

**W-2: network_layer values must be lowercased before routing**
- Classification predicate: `(f.get("network_layer") or "").lower()` before comparison
- Prevents silent drop of findings from providers that emit layer values with different casing

**W-3: Single-pass classification loop required**
- Implement as one for-loop with four bucket lists, not four separate list comprehensions
- Reduces CPU cost at 10 000 findings from O(4n) iterations to O(n)

**W-4: Structured log on classification completion**
- After classification loop:
  ```python
  logger.info(
      "network findings classified",
      extra={
          "tenant_id": tenant_id,
          "scan_run_ids": scan_ids,
          "security_groups": len(sg_findings),
          "internet_exposure": len(exposure_findings),
          "waf": len(waf_findings),
          "topology_findings": len(topology_findings),
          "unclassified": len(general_findings),
      }
  )
  ```

**W-5: BFF backwards-compatibility window for topology key rename**
- During the one sprint transition, BFF must read `topology_snapshots` first, fall back to `topology` if absent:
  ```python
  raw_snapshots = safe_get(net_data, "topology_snapshots") or safe_get(net_data, "topology", [])
  ```
- After one full sprint cycle, remove the `safe_get(net_data, "topology", [])` fallback and remove the old `topology` key from the engine response entirely

**W-6: BFF dead code removal**
- After NET-01 ships, in a follow-up PR:
  - Remove `_SG_SVCS`, `_TOPOLOGY_SVCS`, `_EXPOSURE_SVCS`, `_WAF_SVCS` frozensets
  - Remove `_classify()` function
  - Remove `if raw_findings and not (raw_sg or raw_exposure or raw_topology or raw_waf):` guard block
  - Replace with a monitoring alert: if `security_groups` is empty AND `findings` is non-empty, emit a WARN log (engine classification returned no sg findings)
  - Do not replace with another silent BFF fallback (per no-bff-fallbacks constitution)

**W-7: BFF cache invalidation on deploy**
- TTL_NETWORK cache in BFF will serve stale old-format responses after engine is upgraded but before BFF is upgraded (or cache expires)
- Deploy order: upgrade engine first, then invalidate BFF cache (`cached_view(ck, None)` or restart BFF pod), then upgrade BFF

---

## Summary: Blockers vs Warnings

### Blockers (0 dev lines merge without these fixed)
| ID | Issue | File(s) |
|---|---|---|
| B-1 | `network_report` query missing `AND tenant_id = %s` | `ui_data_router.py` line 222 |
| B-2 | Viewer role receives `sg_posture.cidrs` and `effective_exposure` | `ui_data_router.py` `strip_sensitive_fields()` |
| B-3 | `effective_exposure` not validated against enum before routing | New classification function |

### Warnings (fix before ship, same sprint acceptable)
| ID | Issue | File(s) |
|---|---|---|
| W-1 | `limit` parameter has no upper bound | `ui_data_router.py` |
| W-2 | `network_layer` comparison not lowercased | New classification function |
| W-3 | Multi-pass classification loop (O(4n) instead of O(n)) | New classification function |
| W-4 | No structured log on classification | New classification function |
| W-5 | BFF topology key rename backwards-compat | `bff/network_security.py` |
| W-6 | BFF dead code not removed | `bff/network_security.py` |
| W-7 | BFF cache stale on deploy | Deploy runbook |