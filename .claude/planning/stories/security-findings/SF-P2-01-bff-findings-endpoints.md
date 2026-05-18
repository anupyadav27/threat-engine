# Story SF-P2-01: BFF Endpoints — Asset Findings + Unified Findings View

## Status: done

## Metadata
- **Phase**: P2 — BFF + API
- **Epic**: Security Findings Unified Layer (sub-project of Attack Path Engine Epic)
- **Points**: 5
- **Priority**: P1
- **Depends on**: SF-P1-01, SF-P1-02 (data in table), AP-P0-01 (posture table for count derivation)
- **Blocks**: SF-P3-01 (attack-path integration reads from same DB; BFF enables UI consumption)
- **Runs alongside**: AP-P4-04 (posture tabs) — this story adds the Findings tab to the same asset detail page
- **RACI**: R=DEV A=DL C=SA,SR I=PO,QA
- **Security Gate**: bmad-security-reviewer mandatory — new BFF endpoints touching cross-engine findings; field stripping required for viewer.

## User Story

As a security analyst, I want a unified findings API for any resource so I can see all misconfigs, CVEs, IAM violations, and CDR events for a resource in one sorted list without opening 5 separate engine dashboards. As a platform operator, I want a tenant-wide cross-engine findings view so I can query and filter all open findings in one place.

## Context

Currently the BFF calls per-engine APIs for findings (check engine for misconfigs, vuln engine for CVEs, etc.) and stitches them in the BFF layer. This story replaces that pattern for the asset detail page with a single DB query to `security_findings`.

Two new BFF endpoints:
1. `GET /api/v1/views/inventory/asset/{uid}/findings` — all findings for one resource (used in AP-P4-04 asset detail page alongside posture tabs)
2. `GET /api/v1/views/findings` — tenant-wide paginated cross-engine findings (powers a future "All Findings" page)

The BFF does NOT call engine APIs for these endpoints — it queries `security_findings` directly via the inventory DB connection (same connection used for `resource_security_posture` in AP-P4-04).

## Security Framework Tags

**OWASP SAMM Function**
- [ ] Governance  [ ] Design  [x] Implementation  [x] Verification  [ ] Operations

**NIST CSF 2.0 Function(s)**
- [ ] GV  [x] ID  [x] PR  [x] DE  [ ] RS  [ ] RC
ID.AM-1, PR.AC-4 (field stripping), DE.CM-1

**CSA CCM v4 Domain(s)**
- IAM-09, DSP-07, IVS-01, SEF-01

## Threat Model

### STRIDE
| Threat | Component | Attack Scenario | Mitigation |
|--------|-----------|-----------------|------------|
| Info Disclosure | cross-tenant | BFF uses resource_uid from URL to query findings — attacker guesses another tenant's resource_uid | Query always WHERE tenant_id = $tid from AuthContext; resource_uid alone is insufficient |
| Info Disclosure | detail JSONB | Viewer receives raw engine payload (may contain internal ARNs, policy content) | strip_sensitive_fields() strips detail JSONB for viewer role |
| Info Disclosure | CVE epss_score | Viewer sees exploitability score for unpatched CVE — could inform attacker | epss_score stripped for viewer (viewer sees severity only, not raw EPSS) |
| Injection | query params | severity filter value used in SQL | All filters via parameterized %s — no f-string interpolation |

## Acceptance Criteria

### Functional — Asset Findings Endpoint
- [ ] AC-1: `GET /api/v1/views/inventory/asset/{uid}/findings` implemented in `shared/api_gateway/bff/asset_findings.py` (new file)
- [ ] AC-2: Query: `SELECT * FROM security_findings WHERE resource_uid=%s AND tenant_id=%s AND status='open' ORDER BY severity_rank, last_seen_at DESC LIMIT 100` (severity_rank: critical=1, high=2, medium=3, low=4 — via CASE expression)
- [ ] AC-3: `tenant_id` taken from `AuthContext.engine_tenant_id` — never from query string
- [ ] AC-4: Response shape:
  ```json
  {
    "findings": [{
      "finding_id": "...",
      "source_engine": "check",
      "finding_type": "misconfig",
      "severity": "critical",
      "rule_id": "aws-sg-ssh-open",
      "title": "SSH open to 0.0.0.0/0",
      "epss_score": null,
      "in_kev": false,
      "mitre_technique_id": null,
      "status": "open",
      "first_seen_at": "...",
      "last_seen_at": "...",
      "detail": {...}
    }],
    "total": 14,
    "by_engine": {"check": 8, "vuln": 4, "iam": 2},
    "by_severity": {"critical": 3, "high": 6, "medium": 5, "low": 0}
  }
  ```
- [ ] AC-5: Permission: `discoveries:read` (all roles including viewer)
- [ ] AC-6: Field stripping for viewer: `detail` JSONB = null, `epss_score` = null (severity label retained)
- [ ] AC-7: Field stripping for analyst/tenant_admin: full response EXCEPT `detail` for `source_engine='cdr'` (CDR detail contains actor_hash — stripped for analyst)
- [ ] AC-8: `bff_contract.ndjson` updated with new view entry

### Functional — Unified Findings View
- [ ] AC-9: `GET /api/v1/views/findings` implemented (add to same `asset_findings.py` file)
- [ ] AC-10: Query params: `severity`, `finding_type`, `source_engine`, `status` (default 'open'), `resource_uid`, `page` (default 1), `page_size` (default 50, max 200)
- [ ] AC-11: All filter params use parameterized queries — no string interpolation
- [ ] AC-12: Response: `{ "findings": [...], "total": N, "page": N, "page_size": N, "kpis": {"critical": N, "high": N, "open_cves_in_kev": N, "open_cdr_events": N} }`
- [ ] AC-13: Permission: `discoveries:read`
- [ ] AC-14: Field stripping same rules as AC-6/AC-7

### RBAC Matrix (5 roles × 2 endpoints)
- [ ] AC-15: platform_admin — full response on both endpoints
- [ ] AC-16: org_admin — full response
- [ ] AC-17: tenant_admin — full response (detail included)
- [ ] AC-18: analyst — detail null for cdr rows; epss_score visible
- [ ] AC-19: viewer — detail null for all rows; epss_score null; severity label visible

### Image Tag
- [ ] AC-20: Gateway image rebuilt: `yadavanup84/threat-engine-api-gateway:v-bff-sf1`
- [ ] AC-21: No `latest` tag in manifest

### Health Check
- [ ] AC-22: `GET /api/v1/health/live` returns 200 after gateway redeploy
- [ ] AC-23: `GET /api/v1/views/inventory/asset/{known-uid}/findings` returns 200 with data after SF-P1-01/P1-02 complete

### Security Gate
- [ ] AC-24: bmad-security-reviewer: no BLOCKERS (field stripping correctness; cross-tenant guard)

## Technical Notes

**New BFF file**: `shared/api_gateway/bff/asset_findings.py`

**Inventory DB connection in BFF**: The BFF already has (or will have from AP-P4-04) a connection to `threat_engine_inventory` DB for posture queries. Reuse the same connection pool.

**Severity rank ORDER BY**:
```sql
ORDER BY
    CASE severity
        WHEN 'critical' THEN 1
        WHEN 'high'     THEN 2
        WHEN 'medium'   THEN 3
        ELSE 4
    END,
    last_seen_at DESC
```

**bff_contract.ndjson entries to add:**
```json
{"view":"inventory/asset/{uid}/findings","bff_file":"bff/asset_findings.py","engines":["security_findings"],"input_params":["uid","tenant_id","status"],"key_output_fields":["findings[]","total","by_engine{}","by_severity{}"],"rbac_min":"viewer","cache_ttl":"TTL_SHORT"}
{"view":"findings","bff_file":"bff/asset_findings.py","engines":["security_findings"],"input_params":["tenant_id","severity","finding_type","source_engine","status","page","page_size"],"key_output_fields":["findings[]","total","page","page_size","kpis{}"],"rbac_min":"viewer","cache_ttl":"TTL_SHORT"}
```

## Key Files
- `/Users/apple/Desktop/threat-engine/shared/api_gateway/bff/asset_findings.py` (create new)
- `/Users/apple/Desktop/threat-engine/.claude/context/bff_contract.ndjson` (add 2 new entries)
- `/Users/apple/Desktop/threat-engine/deployment/aws/eks/engines/cspm-portal.yaml` (update gateway image tag if applicable — check which manifest controls the gateway)

## Definition of Done
- [ ] `asset_findings.py` committed
- [ ] bff_contract.ndjson updated
- [ ] Gateway image built and pushed: `v-bff-sf1`
- [ ] Gateway K8s manifest updated and rolled out
- [ ] Both endpoints return 200 with real data post-deploy
- [ ] Viewer field stripping verified: detail is null, epss_score is null
- [ ] MEMORY.md updated with gateway image tag
- [ ] bmad-security-reviewer: no BLOCKERS