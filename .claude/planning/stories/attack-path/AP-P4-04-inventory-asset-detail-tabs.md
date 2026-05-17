# Story AP-P4-04: Inventory Asset Detail — 5-Dimension Posture Tabs

## Status: ready

## Metadata
- **Phase**: P4 — UI
- **Epic**: Attack Path Engine
- **Points**: 8
- **Priority**: P2
- **Depends on**: AP-P0-01 (posture table populated), AP-P3-01 (BFF can serve posture sub-endpoint)
- **Blocks**: nothing (terminal Phase 4 story)
- **RACI**: R=FE-DEV A=DL C=UX,SA,SR I=PO,QA
- **Security Gate**: bmad-security-reviewer mandatory — IAM tab renders attached_role_arn and policy details; strip_sensitive_fields() applies for analyst/viewer. bmad-security-architect must confirm field stripping rules for the new posture endpoint.

## User Story

As a security analyst, I want the inventory asset detail page for compute resources to show five posture tabs (Network, IAM, Encryption, Data, Database) populated from `resource_security_posture`, and for non-compute resources to show one relevant tab (S3→Data, RDS→Database, IAMRole→IAM, KMS→Encryption, ALB→Network), so that I can understand any asset's full security posture in one place without opening five separate engine dashboards.

## Context

The inventory asset detail page at `frontend/src/app/inventory/[assetId]/page.jsx` currently shows findings from the check engine but has no posture dimension view. This story adds dimension tabs powered by the new `resource_security_posture` table.

A new BFF sub-endpoint is needed: `GET /api/v1/views/inventory/asset/{uid}/posture` → reads `resource_security_posture` for the latest `scan_run_id` for the given resource_uid and tenant.

The posture data is served via BFF (not direct engine call) because:
1. It requires tenant resolution
2. It requires field stripping for role-based access (IAM fields stripped for analyst/viewer)
3. It follows the BFF-for-views constitution rule

## Security Framework Tags

**OWASP SAMM Function**
- [ ] Governance  [ ] Design  [x] Implementation  [x] Verification  [ ] Operations

**NIST CSF 2.0 Function(s)**
- [ ] GV  [x] ID  [x] PR  [x] DE  [ ] RS  [ ] RC
ID.AM-1 (asset inventory with full posture context), PR.AC-4 (access permissions managed — IAM tab field stripping)

**CSA CCM v4 Domain(s)**
- IAM-09 (Access Control), DSP-07 (Data Classification), IVS-01, AIS-04 (Application Security)

## Threat Model

### STRIDE
| Threat | Component | Attack Scenario | Mitigation |
|--------|-----------|-----------------|------------|
| Info Disclosure | IAM tab | analyst/viewer sees attached_role_arn and iam_detail JSONB — exposes internal IAM structure | strip_sensitive_fields() applied in BFF posture endpoint: analyst sees is_admin_role/mfa_required but NOT attached_role_arn/iam_detail; viewer sees nothing from IAM tab |
| Info Disclosure | cross-tenant posture | BFF posture endpoint returns posture for wrong tenant | tenant_id always from AuthContext.engine_tenant_id; posture query: WHERE resource_uid=$uid AND tenant_id=$tid |
| Spoofing | assetId in URL | Attacker manipulates assetId URL param to fetch another tenant's resource | Posture query is tenant-scoped; BFF validates tenant_id from AuthContext before query |

### PASTA Analysis
**Asset at risk**: attached_role_arn and iam_detail JSONB contain internal IAM role ARNs and policy content.
**Mitigation**: BFF posture endpoint applies strip_sensitive_fields() based on AuthContext.role_level before returning response.

## MITRE ATT&CK Techniques Addressed
| Technique ID | Name | How this story addresses it |
|-------------|------|-----------------------------|
| T1552.001 | Credentials in Files | IAM tab shows has_permission_boundary and mfa_required — missing controls visible to analyst |
| T1190 | Exploit Public-Facing Application | Network tab shows is_internet_exposed and waf_protected — network exposure visible in asset context |

## Acceptance Criteria

### Functional — New BFF Endpoint
- [ ] AC-1: `GET /api/v1/views/inventory/asset/{uid}/posture` implemented in BFF (add to `shared/api_gateway/bff/inventory.py` or create new file)
- [ ] AC-2: Query reads latest `resource_security_posture` row for `(resource_uid=uid, tenant_id=$tid)` ordered by `updated_at DESC LIMIT 1`
- [ ] AC-3: Response returns all posture columns grouped by dimension: `network{}`, `iam{}`, `encryption{}`, `data{}`, `database{}`, `attack_path{}`
- [ ] AC-4: Field stripping applied based on role level:
  - platform_admin/org_admin: all fields
  - tenant_admin/analyst: IAM tab omits `attached_role_arn`, `iam_detail` JSONB
  - viewer: IAM tab returns `{}` (empty); attack_path tab returns `is_on_attack_path`, `is_choke_point` only (no attack_path_count details)
- [ ] AC-5: `GET /api/v1/health/live` 200 after BFF deploy (gateway re-deploy)

### Functional — Compute Resource Tabs (5 tabs)
- [ ] AC-6: For compute resource types (ec2.instance, lambda.function, ecs.task-definition, eks.cluster, vm, gce.instance, oci.compute, oci.container_instance, azure.function, cloud_run.service): 5 tabs added to asset detail: Network, IAM, Encryption, Data, Database
- [ ] AC-7: Network tab: is_internet_exposed badge, entry_point_type, waf_protected, is_onprem_reachable
- [ ] AC-8: IAM tab (tenant_admin+): attached_role_arn (if available), is_admin_role badge, has_wildcard_policy badge, mfa_required, has_permission_boundary, iam_reachable_count
- [ ] AC-9: IAM tab (analyst/viewer): shows is_admin_role, mfa_required, has_permission_boundary only — no role ARN, no iam_detail
- [ ] AC-10: Encryption tab: volume_encrypted badge, encryption_type, cert_expiry_date, cert_days_remaining (red if < 30 days), in_transit_tls
- [ ] AC-11: Data tab: data_classification badge, can_access_pii, can_write_data, exfil_path_exists
- [ ] AC-12: Database tab: connected_db_uids count, db_auth_type, db_same_vpc

### Functional — Non-Compute Resource Tabs (1 relevant tab)
- [ ] AC-13: s3.bucket, blob.container, gcs.bucket, oci.object_storage → "Data" tab only
- [ ] AC-14: rds.instance, aurora.cluster, cloud_sql.instance, oci.autonomous_db, redshift.cluster → "Database" tab only
- [ ] AC-15: iam.role, iam.user → "IAM" tab only (with field stripping per AC-8/AC-9)
- [ ] AC-16: kms.key, key_vault.key, secretsmanager.secret → "Encryption" tab only
- [ ] AC-17: elasticloadbalancing.loadbalancer, alb, nlb, azure.load_balancer → "Network" tab only

### RBAC Matrix (5 roles × posture endpoint)
- [ ] AC-18: platform_admin — all fields in all tabs
- [ ] AC-19: org_admin — all fields in all tabs
- [ ] AC-20: tenant_admin — IAM tab: is_admin_role/mfa_required/has_permission_boundary (no ARN, no iam_detail)
- [ ] AC-21: analyst — same as tenant_admin for IAM tab
- [ ] AC-22: viewer — IAM tab: empty (`{}`); attack_path tab: is_on_attack_path + is_choke_point only

### Image Tag (mandatory)
- [ ] AC-23: Frontend image rebuilt with new tag (no `latest`)
- [ ] AC-24: Gateway image rebuilt with new tag if BFF file changed
- [ ] AC-25: K8s manifests updated

### Health Check (mandatory)
- [ ] AC-26: Asset detail page loads without console errors
- [ ] AC-27: `GET /api/v1/health/live` returns 200 on gateway after deploy

### Security Gate (mandatory)
- [ ] AC-28: bmad-security-reviewer: no BLOCKERS (field stripping correctness + IAM tab content review)
- [ ] AC-29: bmad-security-architect: posture endpoint design + field stripping rules sign-off

## Technical Notes

**New BFF endpoint location**: Add to `shared/api_gateway/bff/inventory.py` (or `bff/asset_posture.py` if inventory.py doesn't exist yet).

**Query pattern**:
```sql
SELECT * FROM resource_security_posture
WHERE resource_uid = %s AND tenant_id = %s
ORDER BY updated_at DESC
LIMIT 1
```

**Field stripping** — apply `strip_sensitive_fields()` pattern from RBAC.md. For the posture endpoint, extend strip_sensitive_fields to add:
- role_level < 4 (tenant_admin): strip `attached_role_arn`, `iam_detail`
- role = viewer: strip entire `iam` group EXCEPT `is_admin_role` and `mfa_required`

**Tab determination** — compute vs. non-compute in frontend:
```javascript
const COMPUTE_TYPES = ['ec2.instance','lambda.function','ecs.task-definition','eks.cluster','vm','gce.instance','oci.compute','oci.container_instance','azure.function','cloud_run.service'];
const isCompute = COMPUTE_TYPES.includes(resource_type);
```

**Loading state**: Each tab that hasn't been loaded yet shows a skeleton. Tabs are lazy-loaded — only fetch posture data when tab is first clicked (not on page load).

**Empty state per tab**: If posture data has no values for a dimension (e.g., Network: all nulls), show "No {dimension} signals collected yet. Ensure {engine} has run for this account."

**cert_days_remaining < 30**: Show orange badge "Expires in N days" if 0 < N < 30; red badge "EXPIRED" if N <= 0.

**bff_contract.ndjson entry to add**:
```json
{"view":"inventory/asset/{uid}/posture","engine":"resource_security_posture","engine_url":"DB query (inventory DB)","inputs":["uid","tenant_id"],"required_output_fields":["network","iam","encryption","data","database","attack_path"]}
```

## Key Files
- `/Users/apple/Desktop/threat-engine/shared/api_gateway/bff/asset_posture.py` (create new)
- `/Users/apple/Desktop/threat-engine/frontend/src/app/inventory/[assetId]/page.jsx` (modify — add dimension tabs)
- `/Users/apple/Desktop/threat-engine/frontend/src/app/inventory/[assetId]/PostureTabs.jsx` (create new)
- `/Users/apple/Desktop/threat-engine/.claude/context/bff_contract.ndjson` (add posture sub-endpoint)
- `/Users/apple/Desktop/threat-engine/deployment/aws/eks/engines/cspm-portal.yaml` (update frontend image tag)

## Definition of Done
- [ ] BFF posture endpoint implemented and returning correct shape
- [ ] Field stripping verified for analyst (no attached_role_arn) and viewer (no iam group)
- [ ] Compute resource shows all 5 tabs with real posture data
- [ ] Non-compute resources show correct single relevant tab
- [ ] cert_days_remaining < 30 shows warning badge
- [ ] Tabs lazy-loaded (no posture call until tab clicked)
- [ ] Empty state per tab when no posture signals
- [ ] All 5 RBAC roles tested against posture endpoint
- [ ] Frontend and gateway images rebuilt with new tags (no `latest`)
- [ ] bff_contract.ndjson updated
- [ ] MEMORY.md updated for all changed image tags
- [ ] bmad-security-reviewer: no BLOCKERS
- [ ] bmad-security-architect: field stripping sign-off recorded