# Azure CSP — Detailed Project Plan

## Context

- **Subscription:** `f6d24b5d-51ed-47b7-9f6a-0ad194156b5e` (Azure subscription 1)
- **Tenant:** `8370fdd5-e431-4b63-93ed-142aec69ab83`
- **Credentials available:** ✅ `az` CLI logged in on this laptop
- **Discovery configs in DB:** 174 (`rule_discoveries WHERE provider='azure'`)
- **Check rules in DB:** 1,573
- **Scanner current state:** Stub — 4 hardcoded service handlers, doesn't read DB catalog
- **Key scanner file:** `engines/discoveries/providers/azure/scanner/service_scanner.py` (343 lines)

## Milestone 1: Scanner Foundation (DB-driven, credential-complete)

**Goal:** Azure scanner reads from `rule_discoveries` DB exactly like AWS, with real
Azure SDK client factory, pagination, and 10s timeout ceiling.

**Estimated effort:** 5-7 days (1 senior Python + Azure SDK engineer)

### User Stories

**US-AZ-01: Azure SDK Client Factory**
- As the discovery engine, I need to instantiate Azure SDK clients dynamically for any
  service (Compute, Network, Storage, KeyVault, etc.) using the subscription credential,
  so that the scanner doesn't hardcode a fixed list of supported services.
- **Acceptance:** Given a service name string (e.g. `microsoft.compute`), the factory
  returns the correct Azure management client authenticated with the service principal.
- **Tasks:**
  - T1: Map `rule_discoveries.service` names to Azure SDK client classes
    (`azure.mgmt.compute.ComputeManagementClient`, etc.)
  - T2: Implement `AzureClientFactory.get_client(service, subscription_id, credential)`
  - T3: Handle credential types: service_principal (client_id/secret/tenant),
    managed_identity, certificate
  - T4: Implement connection timeout (10s) equivalent of AWS BOTO_CONFIG
- **SME:** Python engineer with `azure-mgmt-*` SDK experience
- **File:** `engines/discoveries/providers/azure/auth/azure_auth.py`

**US-AZ-02: DB Catalog Reader for Azure**
- As the discovery engine, I need to read Azure discovery configs from `rule_discoveries`
  table (provider='azure') and execute the API calls they define, so that adding new
  Azure services requires only a DB record, not a code change.
- **Acceptance:** Scanner iterates all 174 azure discovery configs, calls the mapped
  Azure SDK method, handles pagination, and returns results in standard discovery format.
- **Tasks:**
  - T1: Port `run_boto_discovery()` pattern to Azure SDK — implement
    `run_azure_discovery(client, action, params, discovery_config)`
  - T2: Implement Azure-specific pagination (`list()` returns `ItemPaged`, not tokens)
    — wrap in iterator with 1000-item limit
  - T3: Implement 10s per-call timeout using `ThreadPoolExecutor` + `Future.result(timeout=10)`
  - T4: Map `rule_discoveries.call` format (e.g. `list_all`, `get`) to Azure SDK method names
  - T5: Handle Azure-specific error types:
    `HttpResponseError`, `ResourceNotFoundError`, `PermissionError` → mark as permanent
- **SME:** Python engineer familiar with Azure Python SDK pagination patterns
- **File:** `engines/discoveries/providers/azure/scanner/service_scanner.py`

**US-AZ-03: Azure Region Enumeration**
- As the discovery engine, I need to dynamically enumerate available Azure regions for
  a subscription so that we only scan regions the customer has actually enabled/used.
- **Acceptance:** `list_available_regions()` calls `SubscriptionClient.subscriptions.list_locations()`
  and returns only enabled regions.
- **Tasks:**
  - T1: Implement `list_available_regions()` using Azure Subscription client
  - T2: Map Azure location names to standardised short names (`eastus` → `eastus`)
  - T3: Handle global services (AAD, Storage accounts) that are subscription-scoped not region-scoped
- **SME:** Azure infrastructure engineer
- **File:** `engines/discoveries/providers/azure/scanner/service_scanner.py`

---

## Milestone 2: Noise Removal — Non-Security APIs

**Goal:** Identify and disable Azure discovery configs that don't return security-relevant
data. Target: remove ~30-40% of 174 configs that are billing/monitoring/cost.

**Estimated effort:** 2 days (1 security engineer + 1 Python engineer)

### User Stories

**US-AZ-04: Azure Noise Audit**
- As a security platform, I should only collect discovery data that directly informs a
  security finding, IAM posture, or threat detection — not billing, diagnostics, or
  monitoring metadata.
- **Acceptance:** A reviewed list of azure discovery configs marked `enabled=false`
  for non-security APIs.
- **Tasks:**
  - T1: Review all 174 azure discovery configs — categorize each as:
    - KEEP: Returns resource attributes used by check rules, IAM, or threat engine
    - REMOVE: Billing, cost management, advisor recommendations, monitoring alerts,
      activity logs, diagnostic settings, resource locks (admin noise)
    - DEFER: May be useful but no current rule depends on it
  - T2: Update `rule_discoveries` DB: set `enabled=false` for noise configs
  - T3: Document removed configs with rationale in `09_NOISE_REMOVAL.md`
- **SME:** Azure security engineer (knows which Azure APIs expose security attributes)

---

## Milestone 3: Security Inventory Relationships

**Goal:** Add Azure-specific security relationship rules to `resource_security_relationship_rules`
table so inventory engine builds correct security graph.

**Estimated effort:** 3 days (1 cloud architect + 1 security engineer)

### User Stories

**US-AZ-05: Azure Security Relationships**
- As the inventory engine, I need Azure-specific security relationships defined (e.g.
  VM → NSG → Subnet → VNet, StorageAccount → PrivateEndpoint, KeyVault → Secret)
  so that the security graph correctly represents attack paths.
- **Key relationships to implement:**
  - VirtualMachine → NetworkInterface → NetworkSecurityGroup
  - VirtualMachine → ManagedDisk (encryption context)
  - StorageAccount → PrivateEndpoint
  - StorageAccount → BlobContainer
  - KeyVault → Secret / Key / Certificate
  - AppServicePlan → AppService → ManagedIdentity
  - AzureADApp → ServicePrincipal → RoleAssignment
  - Subnet → NetworkSecurityGroup
  - LoadBalancer → BackendPool → VirtualMachine
  - AKS Cluster → NodePool → VirtualMachine
- **Tasks:**
  - T1: Map all 174 azure discovery configs to resource types
  - T2: Define relationship rules SQL (parent_type, child_type, relationship_type,
    link_field, provider='azure')
  - T3: Insert into `resource_security_relationship_rules`
  - T4: Update inventory engine's relationship resolver to handle azure resource ID format
    (`/subscriptions/{sub}/resourceGroups/{rg}/providers/{type}/{name}`)
- **SME:** Azure cloud architect

---

## Milestone 4: End-to-End Pipeline Test

**Goal:** Run a full Azure pipeline scan (discovery → inventory → check → threat →
compliance → IAM → datasec) against the test Azure subscription.

**Estimated effort:** 3 days (end-to-end testing)

### User Stories

**US-AZ-06: Azure Pipeline Integration Test**
- As a platform operator, I can trigger a full Azure scan via the pipeline and see
  results in the UI with `overall_status=completed`.
- **Tasks:**
  - T1: Onboard Azure test subscription via onboarding engine API
  - T2: Store Azure service principal in K8s secret
  - T3: Trigger Argo pipeline with `provider=azure`
  - T4: Verify each engine processes azure findings correctly
  - T5: Verify UI shows Azure account findings in dashboard
- **Success criteria:**
  - discovery: >100 azure resources found
  - check: >500 check findings
  - threat: >10 threats detected
  - compliance: CIS Azure Benchmark scored
  - overall_status = completed

---

## Azure-Specific Technical Notes

- **Resource ID format:** `/subscriptions/{sub}/resourceGroups/{rg}/providers/{provider_ns}/{type}/{name}`
- **Pagination:** Azure SDK uses `ItemPaged` (iterator) — NOT token-based like AWS
- **Auth SDK:** `azure-identity` → `ClientSecretCredential` or `DefaultAzureCredential`
- **Global services (no region scope):** AAD (EntraID), Subscriptions, Management Groups,
  Policy Definitions, RBAC Role Definitions
- **Parallel scan:** Per resource-group, not per-region (Azure groups resources by RG,
  not region)
- **Rate limits:** Azure has per-subscription rate limits (12,000 req/hour for ARM)
- **Azure AD vs ARM:** Two separate APIs — ARM for infrastructure, Graph API for AAD
  identities. IAM engine needs Graph API for full RBAC posture.

## Docker Image

`yadavanup84/engine-discoveries-azure:v1.0` (separate from AWS)
Already started: `engine-discoveries.yaml` updated to `-aws:latest` pattern.