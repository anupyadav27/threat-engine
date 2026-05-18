# Story PC-INFRA-03: BFF — Expose Depth Analysis Posture Columns and New Finding Filters

## Status: done

## Metadata
- **Phase**: Infrastructure Track
- **Sprint**: Posture Coverage Enhancement
- **Points**: 3
- **Priority**: P2 — new posture columns and findings are in DB but invisible in UI until BFF exposes them
- **Depends on**: PC-INFRA-01 (migration 027 applied), PC-INFRA-02 (security_findings wired), SF-P2-01 (BFF findings endpoints exist), AP-P3-02 (/views/inventory/asset/{uid}/posture endpoint exists at gateway v-bff-ap1)
- **RACI**: R=DEV A=DL C=SA I=PO,QA
- **Security Gate**: bmad-security-reviewer (endpoint touches auth + multi-tenant DB)

## User Story

As a security analyst using the CSPM portal, I want the asset posture panel to show IAM privilege escalation paths, ECR scan coverage, and EKS AMI freshness signals alongside existing dimensions (network, encryption, CDR) so I can see the full security depth of a resource in one place. I also want the Findings page to let me filter by the new PC-DEPTH finding types (escalation paths, CDR sequences, cross-account S3).

## Context

The BFF currently has two relevant endpoints:

### Existing: `GET /api/v1/views/inventory/asset/{uid}/posture`

Handler: `shared/api_gateway/bff/attack_paths_bff.py` (or similar — see gateway v-bff-ap1 for exact module).

Returns a posture summary dict. Currently reads these `resource_security_posture` columns:
- Network: `is_internet_exposed`, `network_exposure_score`, `is_in_private_subnet`
- IAM: `is_admin_role`, `mfa_enforced`, `role_has_wildcard_policy`
- Encryption: `cert_days_remaining`, `tls_version`, `has_kms_managed_key`
- CDR: `has_active_cdr_actor`, `cdr_ttps`
- Attack path: `is_on_attack_path`, `is_choke_point`, `highest_path_score`

**Gap**: The 5 new columns from migration 027 (`has_priv_escalation_path`, `priv_escalation_hop_count`, `priv_escalation_cdr_confirmed`, `ecr_scan_on_push_enabled`, `eks_node_ami_outdated`) are not in the SELECT or the response.

### Existing: `GET /api/v1/views/findings` (SF-P2-01)

Returns a paginated findings list from `security_findings`. Currently filters by `finding_type`, `severity`, `source_engine`.

**Gap**: The new depth finding types (`aws.iam.role.privilege_escalation_*`, `aws.cdr.sequence.*`, `aws.ecr.repository.*`) need to surface in the findings feed and should be filterable by a new `category` query param (maps to rule_id prefix group).

---

## Changes Required

### 1. Update `GET /views/inventory/asset/{uid}/posture` handler

**File:** `shared/api_gateway/bff/` — the handler that reads `resource_security_posture`.

Add to the SELECT query and response dict:

```python
# New columns to add to the SELECT in posture_bff.py
NEW_POSTURE_COLS = [
    "has_priv_escalation_path",
    "priv_escalation_hop_count",
    "priv_escalation_cdr_confirmed",
    "ecr_scan_on_push_enabled",
    "eks_node_ami_outdated",
]
```

Response shape extension (added to existing `iam` and `container` sections):

```json
{
  "iam": {
    "is_admin_role": true,
    "mfa_enforced": false,
    "role_has_wildcard_policy": true,
    "has_priv_escalation_path": true,
    "priv_escalation_hop_count": 1,
    "priv_escalation_cdr_confirmed": true
  },
  "container": {
    "has_privileged_container": false,
    "k8s_rbac_overpermissive": true,
    "container_network_policy_missing": false,
    "ecr_scan_on_push_enabled": false,
    "eks_node_ami_outdated": true
  }
}
```

**Security**: Posture endpoint requires `require_permission("inventory:read")`. No change to auth. The new columns contain no credentials or PII — safe for all roles including `viewer`.

### 2. Update `GET /views/findings` to add `category` filter param

**File:** `shared/api_gateway/bff/` — the findings view handler.

Add a new optional query param `category` that maps to rule_id prefix groups:

```python
CATEGORY_PREFIXES = {
    "escalation":    ["aws.iam.role.privilege_escalation"],
    "cross_account": ["aws.s3.bucket.no_cross_account", "aws.s3.bucket.cross_account", "aws.lakeformation"],
    "container_ecr": ["aws.ecr.repository", "aws.eks.node_group", "azure.aks.cluster"],
    "cdr_sequence":  ["aws.cdr.sequence"],
}

# In handler:
if category := request.query_params.get("category"):
    prefixes = CATEGORY_PREFIXES.get(category, [])
    if prefixes:
        prefix_filter = " OR ".join(["sf.rule_id LIKE %s" for _ in prefixes])
        params.extend([f"{p}%" for p in prefixes])
        where_clauses.append(f"({prefix_filter})")
```

Response: unchanged shape (findings list + pagination). `category` param is additive with existing `finding_type`, `severity`, and `source_engine` filters.

### 3. Add `priv_escalation_hop_count` to findings list response

For `finding_type='iam_violation'` findings from escalation detector, include hop_count in the list item:

```json
{
  "finding_id": "...",
  "finding_type": "iam_violation",
  "severity": "critical",
  "title": "Privilege escalation path: iam:PassRole",
  "source_engine": "iam",
  "detail": {
    "escalation_action": "iam:PassRole",
    "target_identity": "arn:aws:iam::123:role/AdminRole",
    "hop_count": 1,
    "cdr_confirmed": true,
    "cdr_use_count": 7
  }
}
```

This is already in `security_findings.detail JSONB` — BFF just needs to pass it through (no additional DB query).

### 4. BFF contract update

Update `.claude/context/bff_contract.ndjson` after implementation to reflect:
- `/views/inventory/asset/{uid}/posture`: +5 new fields in response
- `/views/findings`: new optional `category` query param

---

## UI Components That Consume These Changes

After this BFF story is done, the UI stories can implement:

| Component | New data consumed |
|-----------|-----------------|
| `PostureTabs.jsx` — IAM tab | `has_priv_escalation_path`, `priv_escalation_hop_count`, `priv_escalation_cdr_confirmed` |
| `PostureTabs.jsx` — Container tab | `ecr_scan_on_push_enabled`, `eks_node_ami_outdated` |
| Findings page filter bar | `category` param: escalation / cross_account / container_ecr / cdr_sequence |
| Asset investigation panel findings tab | CDR sequence findings with stage detail |

The UI stories (PC-UI-01) are a separate story — this BFF story only implements the API layer.

---

## Acceptance Criteria

- [ ] AC-1: `GET /views/inventory/asset/{uid}/posture` response includes `has_priv_escalation_path`, `priv_escalation_hop_count`, `priv_escalation_cdr_confirmed` under `iam` key
- [ ] AC-2: Same endpoint includes `ecr_scan_on_push_enabled`, `eks_node_ami_outdated` under `container` key
- [ ] AC-3: Calling endpoint for a resource with no posture row returns safe defaults (`has_priv_escalation_path=false`, `ecr_scan_on_push_enabled=true`, `eks_node_ami_outdated=false`)
- [ ] AC-4: `GET /views/findings?category=escalation` returns only findings with `rule_id LIKE 'aws.iam.role.privilege_escalation%'`
- [ ] AC-5: `GET /views/findings?category=cdr_sequence` returns only `aws.cdr.sequence.*` findings
- [ ] AC-6: `GET /views/findings?category=INVALID` returns normal result (unknown categories are silently ignored — no 400 error)
- [ ] AC-7: Multi-tenant isolation: posture endpoint filters `WHERE resource_uid = %s AND tenant_id = %s AND scan_run_id = (latest scan for this tenant)` — never returns another tenant's data
- [ ] AC-8: BFF contract test `tests/bff/test_posture_bff.py` updated to assert new fields in response shape
- [ ] AC-9: `bff_contract.ndjson` updated with new fields after implementation

## RBAC Matrix

| Role | `/views/inventory/asset/{uid}/posture` | `/views/findings?category=escalation` |
|------|----------------------------------------|---------------------------------------|
| platform_admin | 200 + all fields | 200 |
| org_admin | 200 + all fields | 200 |
| tenant_admin | 200 + all fields (own tenant) | 200 (own tenant) |
| analyst | 200 + all fields (own tenant) | 200 (own tenant) |
| viewer | 200 + all fields EXCEPT `priv_escalation_cdr_confirmed` stripped by `strip_sensitive_fields()` | 200 (read-only) |

## Definition of Done
- [ ] Posture BFF handler updated to SELECT + return 5 new columns
- [ ] Findings BFF handler updated to accept and apply `category` query param
- [ ] `bff_contract.ndjson` updated
- [ ] BFF contract test updated
- [ ] Gateway rebuilt and deployed
- [ ] After deploy: `curl /views/inventory/asset/{test_uid}/posture` returns `has_priv_escalation_path` field in response