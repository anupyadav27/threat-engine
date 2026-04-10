# Multi-CSP Sprint Master Task List (Revised — Post Round 2 Review)

## Review Loop Status
| Reviewer | Round 1 | Round 2 | Round 3 |
|----------|---------|---------|---------|
| Business Analyst | NEEDS_REVISION | NEEDS_REVISION | pending |
| Architect | NEEDS_REVISION | NEEDS_REVISION | pending |
| Lead Developer | NEEDS_REVISION | NEEDS_REVISION | pending |
| Customer | NEEDS_REVISION | NEEDS_REVISION | pending |

---

## SHARED Tasks (infrastructure, all CSPs)

### SHARED-01: Parameterize Argo cspm-pipeline.yaml for multi-CSP
- Owner: DevOps engineer
- File: `deployment/aws/eks/argo/cspm-pipeline.yaml`
- Change: Accept `provider` param (default: `aws`). Discovery step image becomes `engine-discoveries-{{provider}}`.
- Acceptance: `argo submit ... -p provider=aws` runs AWS scan identically to current behavior. `provider=azure` routes to `engine-discoveries-azure`.

### SHARED-02: Docker split — per-CSP Dockerfile structure
- Owner: DevOps engineer
- Files: `engines/discoveries/providers/{azure,gcp,k8s}/Dockerfile`
- Pattern: 3-stage build (base → CSP SDK layer → final). Non-root user.
- Acceptance: All 3 images build in CI. Smoke test: `docker run --rm <image> python -c 'import azure.mgmt.compute'` passes.

### SHARED-03: K8s secrets — azure-creds, gcp-creds
- Owner: DevOps engineer
- Note: K8s uses `in_cluster` auth — no k8s-creds secret created.
- Acceptance: `kubectl get secret azure-creds -n threat-engine-engines` returns non-empty. K8s pipeline uses `credential_type=in_cluster` with no external secret ref.

### SHARED-04: Rate limiting retry handlers (Azure ARM 429 + GCP quota)
- Owner: Python/cloud engineer (SME: azure-mgmt-* + google-cloud-*)
- Files: `engines/discoveries/providers/azure/pagination.py`, `engines/discoveries/providers/gcp/pagination.py`
- Change: Exponential backoff on HTTP 429 (Azure) and `googleapiclient.errors.HttpError` 429/403 (GCP). Max 3 retries, base delay 2s, max delay 30s.
- Acceptance: Unit test with mock client that raises 429 on first 2 calls, succeeds on 3rd. Must not fail after max retries exceeded — log and skip that resource.

### SHARED-05: Credential expiry detection + alerting (Azure SP + GCP SA)
- Owner: Backend engineer + Security analyst
- Mechanism: Check `credentials.expires_at` in Secrets Manager credential metadata before scan. If expired or within 7 days: write `scan_runs.overall_status = 'credential_expiry_warning'` + log WARNING. Do NOT silently proceed and return 0 findings.
- Acceptance: Mock test with `expires_at = now() - 1 day` → scan aborts with `credential_expiry_warning` status, not 0-finding success.

### SHARED-06: Fix Argo discovery URL to be provider-dynamic
- Owner: DevOps engineer
- File: `deployment/aws/eks/argo/cspm-pipeline.yaml`
- Change: Replace hardcoded `http://engine-discoveries/` with `http://engine-discoveries-{{workflow.parameters.provider}}/`
- Acceptance: Argo `discovery` step calls correct service URL per provider. Verified by dry-run with `--dry-run=client`.

### SHARED-07: Argo K8s in_cluster auth special-case
- Owner: DevOps engineer
- File: `deployment/aws/eks/argo/cspm-pipeline.yaml`
- Change: Pre-flight step checks if `provider=k8s` → skip credential secret validation. K8s discovery container sets `K8S_AUTH_MODE=in_cluster` env var, no `envFrom.secretRef` for k8s.
- Acceptance: K8s pipeline submits and discovery step starts without `k8s-creds` secret existing.

### SHARED-08: Argo pre-flight credential validation step [NEW — Arch Round 2]
- Owner: DevOps engineer
- File: `deployment/aws/eks/argo/cspm-pipeline.yaml`
- Change: Add `preflight-credential-check` DAG step before `discovery` for non-k8s providers. Validates `${provider}-creds` secret exists with `kubectl get secret`. Fails workflow if missing.
- Acceptance: Submit Azure pipeline with missing `azure-creds` → workflow fails at preflight step with clear error. Not silent 0-finding scan.

---

## AZURE Tasks (Priority #1 — credentials available)

### AZ-01: Bootstrap engines/discoveries/providers/azure/ directory
- SME: Python/azure-mgmt-* engineer
- Files to create:
  - `engines/discoveries/providers/azure/__init__.py`
  - `engines/discoveries/providers/azure/scanner/service_scanner.py` (replaces existing 4-handler stub — see AZ-01b)
  - `engines/discoveries/providers/azure/client_factory.py`
  - `engines/discoveries/providers/azure/pagination.py`
  - `engines/discoveries/providers/azure/requirements.txt`
- Acceptance: `from engines.discoveries.providers.azure.scanner.service_scanner import AzureDiscoveryScanner` imports without error.

### AZ-01b: Remove/replace existing Azure scanner stub [NEW — Dev Round 2]
- SME: Python/azure-mgmt-* engineer
- Context: `engines/discoveries/providers/azure/scanner/service_scanner.py` (343 lines) exists with 4 hardcoded handlers (`compute`, `sql`, `storage`, `resource_groups`). This stub must be REPLACED by the DB-driven scanner in AZ-04. Do not leave the stub alongside the new scanner.
- Acceptance: After AZ-04 merge, the 4 hardcoded handlers are gone. All service discovery is driven by `rule_discoveries` table (DB-driven, same as AWS).

### AZ-02: Implement AzureClientFactory — service → SDK client map
- SME: Python/azure-mgmt-* engineer
- Map: `compute` → `ComputeManagementClient`, `network` → `NetworkManagementClient`, etc. (see 14_AZURE_E2E_PLAN.md for full map)
- Auth: `ClientSecretCredential(tenant_id, client_id, client_secret)` from resolved credentials (see AZ-17b for resolution path)
- Acceptance: Factory returns correct client type for each service name. Unit-testable with mock credential.

### AZ-02b: Per-call timeout wrapper on Azure ThreadPoolExecutor [NEW — Dev Round 1]
- SME: Python/azure-mgmt-* engineer
- Change: All `executor.submit(...)` calls wrapped with `future.result(timeout=OPERATION_TIMEOUT)` where `OPERATION_TIMEOUT=10` (mirrors AWS scanner).
- Acceptance: Unit test — mock Azure client that sleeps 15s. Scanner must cancel after 10s and log timeout, not hang indefinitely.

### AZ-03: Azure pagination helpers — azure_list_all() + ItemPaged
- SME: Python/azure-mgmt-* engineer
- Pattern: `def azure_list_all(client_method, **kwargs) -> List[dict]` — iterates `ItemPaged`, calls `.as_dict()` on each item.
- Acceptance: Unit test with mock `ItemPaged` returning 3 pages of 10 items. Returns flat list of 30 dicts.

### AZ-04: Implement AzureDiscoveryScanner — DB-driven, server-side region filter
- SME: Python/azure-mgmt-* engineer
- Key requirement: Use **server-side region filtering** where Azure SDK supports it (e.g., `list_all()` then filter by location is NOT acceptable — use `list(resource_group_name=rg)` or pass `location` filter param). For services that don't support server-side filter, document explicitly.
- resource_type normalization: `Microsoft.Compute/virtualMachines` → `VirtualMachine` (see normalization map in 14_AZURE_E2E_PLAN.md)
- resource_uid: full Azure Resource ID (`/subscriptions/{sub}/resourceGroups/{rg}/providers/{type}/{name}`)
- Acceptance: Scans at least 10 distinct service types. Each result has `resource_uid` matching `/subscriptions/f6d24b5d/...` format.

### AZ-05: Register Azure provider in run_scan.py + noise removal
- SME: Backend engineer
- Change: `PROVIDER_SCANNERS['azure'] = AzureDiscoveryScanner` in `run_scan.py`
- Noise removal: `UPDATE rule_discoveries SET is_enabled=false WHERE provider='azure' AND service IN ('consumption', 'costmanagement', 'insights/metricDefinitions', 'advisor', 'resourcehealth', 'maintenance', 'locks')`
- Acceptance: `run_scan.py --provider azure` starts without import error.

### AZ-05b: Azure catalog YAML entries [NEW — Dev Round 1]
- SME: Python/azure-mgmt-* engineer + Security analyst
- Context: AWS discovery is driven by YAML rules in `catalog/aws/`. Azure needs equivalent `catalog/azure/` YAML entries for `DiscoveryConfigLoader` to enumerate which services to discover.
- Files: `catalog/azure/{compute,network,storage,keyvault,sql,iam,aks,appservice}/step*.discovery.yaml`
- Format: Mirror `catalog/aws/ec2/step6_ec2.discovery.yaml` structure with Azure service names.
- Acceptance: `DiscoveryConfigLoader.load(provider='azure')` returns >= 50 service configs.

### AZ-06: Seed Azure inventory relationship rules [PARALLEL with AZ-01..05]
- SME: DBA + Security analyst
- Table: `resource_security_relationship_rules`
- Rows: 15 rows for Azure (see 07_INVENTORY_RELATIONSHIPS.md for full spec)
- Migration gate: These rows MUST be present before inventory engine runs for Azure (hard prerequisite — see AZ-15b)
- Acceptance: `SELECT COUNT(*) FROM resource_security_relationship_rules WHERE provider='azure'` = 15.

### AZ-07: Seed Azure service_classification [PARALLEL with AZ-01..05]
- SME: DBA
- 14 Azure asset types (see 14_AZURE_E2E_PLAN.md Milestone 2.2 for full INSERT SQL)
- Acceptance: `SELECT COUNT(*) FROM service_classification WHERE csp='azure'` = 14.

### AZ-08: Seed CIS Azure 1.5 framework + controls + rule_control_mapping
- SME: Security analyst + DBA
- Sections: 1 (IAM), 2 (Security Center), 3 (Storage), 4 (DB), 5 (Logging), 6 (Networking), 7 (VMs), 8 (App Service), 9 (Key Vault)
- Acceptance: `SELECT COUNT(*) FROM compliance_controls WHERE framework_id='cis_azure_1_5'` >= 75 controls.

### AZ-08b: Seed NIST 800-53 + SOC 2 Azure framework mappings [NEW — Customer Round 1]
- SME: Security analyst + DBA
- Deliverables: `seed_nist_800_53_azure.sql` + `seed_soc2_azure.sql` with full Azure rule → control mappings
- Context: Enterprise customers require NIST and SOC 2 alongside CIS. CIS-only is insufficient for enterprise release.
- Acceptance: `SELECT COUNT(*) FROM rule_control_mapping WHERE framework_id='nist_800_53' AND provider='azure'` >= 100 mappings.

### AZ-09: Seed Azure check rules — quantified floor per service category
- SME: Security analyst
- Floors (no tildes): compute>=50, network>=60, storage>=40, keyvault>=30, sql>=40, iam>=80, aks>=30, appservice>=30, monitoring>=20
- Total floor: >= 500 rules (target ~600)
- Idempotent: Use `INSERT INTO rule_metadata ... ON CONFLICT (rule_id) DO UPDATE SET ...`
- Acceptance: `SELECT service, COUNT(*) FROM rule_metadata WHERE provider='azure' GROUP BY service` — each category meets floor. Total >= 500.

### AZ-10: Seed Azure IAM rules — EntraID, RBAC, Service Principals
- SME: Security analyst
- Coverage: MFA, stale guests, permanent admin roles, custom owner roles, SP credential rotation, managed identity preference, key vault RBAC model
- Acceptance: `SELECT COUNT(*) FROM rule_metadata WHERE provider='azure' AND (service='authorization' OR service='graph')` >= 80.

### AZ-11: Seed Azure threat rules — MITRE techniques
- SME: Threat analyst
- Techniques: T1078.004, T1537, T1530, T1190, T1580, T1136.003, T1098.001, T1619, T1562 (Impair Defenses — Azure Diagnostic Settings)
- Acceptance: `SELECT COUNT(DISTINCT mitre_technique) FROM rule_metadata WHERE provider='azure' AND mitre_technique IS NOT NULL` >= 8 distinct techniques.

### AZ-12: Build engine-discoveries-azure Docker image + deploy
- SME: DevOps
- Image: `yadavanup84/engine-discoveries-azure:v1.azure.{YYYYMMDD}`
- Acceptance: Image pushes to registry. K8s deployment rolls out. Health check `GET /api/v1/health/live` returns 200.

### AZ-13: E2E Azure discovery scan — quantified pass criteria
- SME: QA + Backend
- Pass criteria (ALL must be met):
  - >= 100 Azure resources in `discovery_findings WHERE provider='azure'`
  - `resource_uid` matches `/subscriptions/f6d24b5d.+` regex for all rows
  - Error rate in scan logs < 5% (errors / total API calls)
  - Scan completes in < 60 minutes
  - `scan_runs.overall_status = 'completed'` (not 'failed' or 'credential_expiry_warning')
- Acceptance: All 5 criteria verified via automated check script after scan.

### AZ-13b: Onboarding SLA definition [NEW — Customer + Dev Round 1]
- SME: QA + Full-stack
- SLA: A security engineer must be able to onboard an Azure subscription and receive a full posture report in < 30 minutes end-to-end.
- Milestone gates: Onboarding form submit → credentials stored (< 1 min) → scan triggered (< 2 min) → discovery complete (< 15 min) → full pipeline complete (< 25 min) → UI shows posture report (< 30 min total).
- Documented in: `20_TESTING_VALIDATION.md` Layer 5 acceptance criteria.
- Acceptance: Timed dry-run against Azure subscription f6d24b5d meets all gates.

### AZ-14: Validate full Azure pipeline
- SME: QA + Backend
- Steps: inventory → check → threat → compliance
- Acceptance: `check_findings WHERE provider='azure'` >= 200 findings. `compliance_scores WHERE framework_id='cis_azure_1_5'` score > 0. `threat_findings WHERE provider='azure'` >= 10 threat detections. Neo4j contains >= 50 azure Resource nodes.

### AZ-15: Fix Neo4j _neo4j_label() for multi-CSP types
- SME: Backend/Neo4j engineer
- File: `engines/threat/threat_engine/graph/graph_builder.py`
- Change: Handle non-dot resource types (VirtualMachine → VirtualMachine, not CloudResource fallback)
- Add: `provider` property to all Resource node MERGE/SET
- Pass criteria: After Azure scan, Neo4j contains nodes with labels `VirtualMachine`, `StorageAccount`, etc. AND `provider: 'azure'` property. Verified via Cypher: `MATCH (r:Resource {provider: 'azure'}) RETURN count(r)` > 0.

### AZ-15b: relationship_rules seed as migration gate [ADDED by Dev+Arch]
- This is a HARD prerequisite for inventory engine Azure support. AZ-06 seed (15 rows) must be applied as a database migration before the Azure pipeline is declared production-ready.
- Gate check: `SELECT COUNT(*) FROM resource_security_relationship_rules WHERE provider='azure'` = 15. Pipeline pre-flight fails if < 15.

### AZ-16: Seed Azure toxic combination patterns
- SME: Threat analyst + Backend
- Patterns: 5 Azure-specific + 2 cross-CSP (see 22_NEO4J_GRAPH_MULTICSP.md for full Cypher)
- CRITICAL: Use `tags @> to_jsonb(ARRAY['azure']::text[])` for provider filter in `_load_hunt_queries`. NOT `metadata->>'provider'` (column does not exist).
- Acceptance: `SELECT COUNT(*) FROM threat_hunt_queries WHERE hunt_type='toxic_combination' AND tags @> to_jsonb(ARRAY['azure']::text[])` = 7 (5 + 2 cross-CSP).

### AZ-17: Add ?provider=azure filter to all engine APIs
- SME: Backend engineer
- Endpoints: discoveries, check, inventory, threat, iam, datasec, compliance, risk
- New endpoint: `GET /api/v1/summary?provider=azure` (see 14_AZURE_E2E_PLAN.md Phase 8 for response spec)
- Acceptance: All 8 engine APIs return filtered results with `?provider=azure`. Gateway `/api/v1/summary?provider=azure` returns valid JSON with compliance_score, findings, resources.

### AZ-17b: Credential_ref → Azure SP resolution path [NEW — Dev Round 1]
- SME: Backend engineer + Security analyst
- Context: AWS uses `credential_ref=threat-engine/account/588989875114` → fetches from Secrets Manager. Azure must follow the same pattern.
- Resolution path: `credential_ref` in `scan_runs` → `aws secretsmanager get-secret-value --secret-id {credential_ref}` → JSON with `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_SUBSCRIPTION_ID` → passed to `ClientSecretCredential`.
- Documented in: `10_CREDENTIALS_CONTEXT.md`
- Acceptance: Azure scanner resolves credentials via Secrets Manager on EKS (not bare env vars). Integration test confirms scan starts with Secrets Manager-resolved credentials.

### AZ-18: BFF/UI — Azure frontend support
- SME: Full-stack engineer
- Deliverables: Azure CSP selector, VirtualMachine/StorageAccount/etc. resource icons, CIS Azure 1.5 + NIST 800-53 framework display, EntraID terminology (not "IAM roles")
- Acceptance: With `provider=azure` selected in UI: compliance page shows CIS Azure 1.5 score, IAM page shows "Service Principals" and "EntraID", resource icons match Azure types.

---

## CROSS-CSP Tasks

### CROSS-01: Multi-CSP compliance dashboard [NEW — BA + Customer Round 1]
- SME: Full-stack + Backend engineer
- Scope: Single pane of glass showing AWS + Azure (and later GCP) compliance scores side-by-side.
- BFF endpoint: `GET /api/v1/compliance/multi-csp?tenant_id={id}` → returns array of `{provider, framework, score, last_scan}` for all active providers.
- UI: Dashboard tab "Multi-Cloud Posture" with CSP cards showing score badges.
- Acceptance: With AWS + Azure scans complete, dashboard shows both CSP scores on one screen. Score delta between scans visible.

---

## GCP Tasks (Priority #2)

### GCP-00: Resolve GCP credential project mismatch [ADDED by BA — blocker]
- Owner: MUST BE ASSIGNED by sprint planning. Currently unowned.
- Blocker: GCP credential references `test-215908` project but target is `cloudsecurityapp-437319`. Until resolved, GCP-01 cannot start.
- Completion gate: `gcloud auth list` confirms correct project. `rule_discoveries WHERE provider='gcp'` uses correct project ID. Owner confirms in sprint sync.

### GCP-01 to GCP-08
(See 15_GCP_E2E_PLAN.md — structure mirrors Azure phases above)
- GCP-04 must also include NIST 800-53 mappings (same enterprise requirement as Azure)
- GCP-04 check rule floors: same quantified approach as AZ-09 (no tildes)

---

## K8s Tasks (Priority #3)

### K8S-01 to K8S-08
(See 16_K8S_E2E_PLAN.md)

### K8S-02b: K8s scanner SA `secrets` read access security review [ADDED by BA]
- SME: K8s security engineer
- Context: The K8s scanner ClusterRole includes `secrets` read access. This gives the scanner (and any attacker who compromises it) the ability to read all cluster secrets.
- Review: Is `secrets` read access required for security posture assessment? If yes, document the risk and mitigate with least-privilege namespace scope. If no, remove from ClusterRole.
- Acceptance: ClusterRole reviewed and either `secrets` removed or justified in writing with mitigation.

---

## Blocked CSPs

### OCI-01, IBM-01, ALICLOUD-01
Blocked pending credential provisioning. No sprint work until credentials available.

---

## Testing + Validation (ref: 20_TESTING_VALIDATION.md)

Layer 5 (E2E) acceptance criteria for each CSP:
- >= 100 resources discovered
- < 5% error rate
- Scan completes in < 60 minutes
- Onboard-to-posture-report SLA: < 30 minutes (AZ-13b)
- Compliance score > 0 for at least 1 framework
- >= 10 threat detections
- Neo4j contains provider-tagged resource nodes