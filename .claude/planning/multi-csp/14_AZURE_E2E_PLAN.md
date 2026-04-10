# Azure — Full Stack E2E Plan

## Status
- Credentials: ✓ `az login` active, subscription f6d24b5d-51ed-47b7-9f6a-0ad194156b5e
- rule_discoveries in DB: ✓ 267 services (post-sync 2026-04-07)
- Scanner code: ✗ No provider directory exists — must be created
- Check rules: ✗ 0 Azure rules in rule_metadata
- Inventory relationships: ✗ 0 Azure rows in resource_security_relationship_rules
- Compliance frameworks: ✗ No CIS Azure in compliance_frameworks
- Priority: #1 (credentials available)

---

## Phase 1 — Discovery (Track A)

### Milestone 1.1: Azure Provider Directory Bootstrap

**US-AZ-DISC-01: Provider structure**
- Create `engines/discoveries/providers/azure/`
- Files needed:
  - `__init__.py`
  - `azure_scanner.py` — AzureDiscoveryScanner class (implements DiscoveryScanner interface)
  - `client_factory.py` — AzureClientFactory
  - `pagination.py` — Azure pagination helpers
  - `requirements.txt` — azure-mgmt-* packages
  - `Dockerfile`
- Register in `engines/discoveries/run_scan.py`: `PROVIDER_SCANNERS['azure'] = AzureDiscoveryScanner`
- SME: Python engineer with azure-mgmt-* SDK experience

**US-AZ-DISC-02: Azure Authentication**
- Azure auth uses `azure-identity` SDK (`DefaultAzureCredential` → falls back through: env vars → managed identity → CLI)
- For scanner: use `ClientSecretCredential(tenant_id, client_id, client_secret)` from env vars
- Env vars: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_SUBSCRIPTION_ID`
- All Azure SDK clients accept a credential + subscription_id

**US-AZ-DISC-03: Client Factory**

Map `rule_discoveries.service` → Azure SDK client:
```python
CLIENT_MAP = {
    'compute':          ComputeManagementClient,
    'network':          NetworkManagementClient,
    'storage':          StorageManagementClient,
    'keyvault':         KeyVaultManagementClient,
    'sql':              SqlManagementClient,
    'authorization':    AuthorizationManagementClient,
    'containerservice': ContainerServiceClient,
    'web':              WebSiteManagementClient,
    'cosmosdb':         CosmosDBManagementClient,
    'monitor':          MonitorManagementClient,
    'security':         SecurityCenter,
    'resources':        ResourceManagementClient,
    'msi':              ManagedServiceIdentityClient,
    'keyvault_data':    KeyClient,  # data-plane for keys/secrets/certs
    'dns':              DnsManagementClient,
    'cdn':              CdnManagementClient,
    'policy':           PolicyClient,
    'graph':            GraphServiceClient,  # EntraID via Microsoft Graph
}
```

Each client: `Client(credential, subscription_id)`, 30s timeout.

**US-AZ-DISC-04: Azure Pagination**
- Azure uses `list()` returning `ItemPaged` (lazy iterator)
- Pattern: `for item in client.virtual_machines.list_all(): yield item`
- Some methods need resource_group parameter — handled by first listing resource groups
- No token-based pagination needed — SDK handles it internally
- Implement `azure_list_all(client_method, **kwargs) → List[dict]`

**US-AZ-DISC-05: Resource Type Normalization**
- `resource_type` stored as Azure short name: `VirtualMachine`, `StorageAccount`, `KeyVault`
- NOT the full Azure provider string
- Normalization map in scanner:
  - `Microsoft.Compute/virtualMachines` → `VirtualMachine`
  - `Microsoft.Storage/storageAccounts` → `StorageAccount`
  - `Microsoft.Network/virtualNetworks` → `VirtualNetwork`
  - etc.

**US-AZ-DISC-06: resource_uid format**
- Use full Azure Resource ID: `/subscriptions/{sub}/resourceGroups/{rg}/providers/{type}/{name}`
- This is globally unique and consistent with Azure Portal URLs

**Noise removal (from 09_NOISE_REMOVAL.md):**
- Disable in rule_discoveries WHERE provider='azure' AND service IN:
  - `consumption`, `costmanagement` (billing)
  - `insights/metricDefinitions`, `insights/activityLogs` (monitoring)
  - `advisor` (not security-specific)
  - `resourcehealth`, `maintenance` (CSP-managed)
  - `locks` (admin, not security)

**Docker:**
- Image: `yadavanup84/engine-discoveries-azure:v1.azure.YYYYMMDD`
- Dockerfile at `engines/discoveries/providers/azure/Dockerfile`
- SDK packages: `azure-mgmt-compute`, `azure-mgmt-network`, `azure-mgmt-storage`, `azure-mgmt-keyvault`, `azure-mgmt-sql`, `azure-identity`, `azure-mgmt-authorization`, `azure-mgmt-containerservice`, `azure-mgmt-web`, `azure-mgmt-monitor`, `azure-mgmt-security`, `azure-mgmt-resource`, `azure-mgmt-cosmosdb`, `azure-mgmt-dns`, `msgraph-sdk`

**K8s Secret:**
```bash
kubectl create secret generic azure-creds -n threat-engine-engines \
  --from-literal=AZURE_TENANT_ID=<tenant-id> \
  --from-literal=AZURE_CLIENT_ID=<client-id> \
  --from-literal=AZURE_CLIENT_SECRET=<secret> \
  --from-literal=AZURE_SUBSCRIPTION_ID=f6d24b5d-51ed-47b7-9f6a-0ad194156b5e
```

---

## Phase 2 — Inventory (Track B)

### Milestone 2.1: Azure Relationship Rules

SQL: INSERT 15 rows into `resource_security_relationship_rules` (see 07_INVENTORY_RELATIONSHIPS.md).
File: `seed_azure_relationships.sql`

### Milestone 2.2: Azure Asset Classification

SQL: INSERT into `service_classification` for 14 Azure asset types:
```sql
INSERT INTO service_classification (csp, resource_type, category, subcategory, scope) VALUES
('azure', 'VirtualMachine', 'Compute', 'Virtual Machine', 'regional'),
('azure', 'StorageAccount', 'Storage', 'Object Storage', 'regional'),
('azure', 'SQLServer', 'Database', 'Relational DB', 'regional'),
('azure', 'KeyVault', 'Security', 'Key Management', 'regional'),
('azure', 'VirtualNetwork', 'Network', 'VPC', 'regional'),
('azure', 'NetworkSecurityGroup', 'Network', 'Firewall', 'regional'),
('azure', 'AppService', 'Compute', 'App Service', 'regional'),
('azure', 'AKSCluster', 'Container', 'Kubernetes', 'regional'),
('azure', 'CosmosDB', 'Database', 'NoSQL', 'global'),
('azure', 'LoadBalancer', 'Network', 'Load Balancer', 'regional'),
('azure', 'ApplicationGateway', 'Network', 'WAF/Gateway', 'regional'),
('azure', 'Subnet', 'Network', 'Subnet', 'regional'),
('azure', 'ManagedDisk', 'Storage', 'Block Storage', 'regional'),
('azure', 'ContainerRegistry', 'Container', 'Registry', 'regional');
```

### Milestone 2.3: Inventory Engine Azure Support

- Inventory engine reads from `discovery_findings` and normalizes into `inventory_findings`
- Ensure `resource_type` normalization works for Azure types
- Neo4j: Azure node labels = resource_type (VirtualMachine, StorageAccount, etc.)
- Relationship builder: reads `resource_security_relationship_rules WHERE provider='azure'`
- No code change needed IF discovery scanner writes correct resource_type + resource_uid

---

## Phase 3 — Check Engine (Track C)

### Milestone 3.1: Azure Check Rules

Write `rule_metadata` entries for Azure rules covering all 9 service categories.

**Acceptance criteria (quantified floors — no tildes):**
- Compute (VirtualMachine, VMSS): >= 50 rules
- Network (NSG, VNet, WAF, DDoS): >= 60 rules
- Storage (StorageAccount, BlobContainer): >= 40 rules
- KeyVault: >= 30 rules
- SQL / Managed DB: >= 40 rules
- IAM / EntraID: >= 80 rules
- AKS: >= 30 rules
- AppService: >= 30 rules
- Monitoring / Logging: >= 20 rules
- Total floor: >= 500 rules (target ~600, never accept < 500)

Rules covering:

**Compute (VirtualMachine, VMSS):**
- VM disk encryption (Azure Disk Encryption or SSE+CMK)
- VM boot diagnostics enabled
- VM endpoint protection installed
- Unmanaged disk usage

**Network (NSG, VNet, ApplicationGateway, WAF):**
- NSG: No inbound allow-all from internet (0.0.0.0/0)
- NSG: RDP (3389) restricted to known CIDRs
- NSG: SSH (22) restricted
- WAF enabled on Application Gateway
- DDoS Standard enabled
- Network Watcher enabled

**Storage (StorageAccount, BlobContainer):**
- Storage account public access disabled
- Storage account HTTPS-only traffic
- Storage account TLS version >= 1.2
- Storage account blob public access disabled
- Storage account soft delete enabled
- Storage account logging enabled (read/write/delete)
- Storage account CMK encryption

**KeyVault:**
- Key Vault soft delete enabled
- Key Vault purge protection enabled
- Key Vault key expiry date set
- Key Vault certificate expiry monitoring
- Key Vault private endpoint configured
- Key Vault RBAC authorization model (not access policies)

**SQL / Managed DB:**
- Azure SQL TDE enabled
- Azure SQL auditing enabled
- Azure SQL threat detection enabled
- Azure SQL firewall: no allow-all (0.0.0.0 - 255.255.255.255)
- Azure SQL vulnerability assessment enabled
- SQL server AAD admin set

**IAM / EntraID:**
- MFA enabled for all users (AAD)
- No legacy authentication protocols allowed
- Privileged Identity Management (PIM) for admin roles
- Guest user access reviewed
- Service principal credentials rotation
- Custom RBAC roles reviewed

**AKS:**
- AKS RBAC enabled
- AKS AAD integration enabled
- AKS network policy configured
- AKS private cluster enabled
- AKS node pools use managed identity

**AppService:**
- HTTPS-only enabled
- TLS minimum version 1.2
- Client certificate required
- Managed identity used (not credentials)
- FTP disabled

Each rule:
```python
{
  "rule_id": "azure_storage_public_access_disabled",
  "provider": "azure",
  "service": "storage",
  "resource_type": "StorageAccount",
  "check_title": "Ensure storage account public access is disabled",
  "severity": "high",
  "compliance_frameworks": {"cis_azure_1_5": ["3.5"], "nist_800_53": ["AC-3"]},
  "mitre_tactics": ["Initial Access"],
  "mitre_techniques": ["T1190"],
  "threat_category": "data_exposure"
}
```

### Milestone 3.2: Check Engine Azure Support

- Check engine (engine_check_aws) is AWS-specific in boto3 calls
- Azure check engine needs: `engine_check_azure/` provider directory
- Pattern mirrors engine_check_aws: reads `rule_metadata WHERE provider='azure'`, reads discovery data, evaluates rules
- Discovery data comes from `discovery_findings WHERE provider='azure'`
- Rule evaluation logic: field-level checks on Azure resource attributes

---

## Phase 4 — Threat Engine (Track C cont.)

### Milestone 4.1: Azure Threat Rules

Threat engine builds on check findings + discovery data. Need:

MITRE techniques relevant to Azure:
- T1078.004 — Valid Accounts: Cloud Accounts (Azure AD token theft)
- T1190 — Exploit Public-Facing Application (App Service, API Gateway)
- T1537 — Transfer Data to Cloud Account (Storage exfiltration)
- T1530 — Data from Cloud Storage Object (Storage blob access)
- T1580 — Cloud Infrastructure Discovery (Azure Resource Graph)
- T1136.003 — Create Account: Cloud Account (AAD user creation)
- T1098.001 — Account Manipulation: Azure AD (role assignment)
- T1619 — Cloud Storage Object Discovery

Update `mitre_technique_reference.azure_checks` with Azure rule IDs per technique.

### Milestone 4.2: Attack Paths (Azure)

Azure-specific attack path patterns:
1. **Public Blob → Data Exfiltration**: StorageAccount (public) → BlobContainer (sensitive data) → T1530
2. **Overprivileged SP → Lateral Movement**: ServicePrincipal (owner role) → ResourceGroup → T1098.001
3. **Unauthenticated App → Account Takeover**: AppService (no auth) → ManagedIdentity (privileged) → T1078.004
4. **Exposed SQL → Data Breach**: SQLServer (public IP + allow-all firewall) → Database → T1190

Attack path evaluation: inventory relationship graph (Neo4j) traversal + threat scores.

### Milestone 4.3: Blast Radius (Azure)

Blast radius = how many downstream resources are reachable from a compromised resource.
Azure blast radius examples:
- Compromised VirtualNetwork → all Subnets → all VMs in those subnets
- Compromised ServicePrincipal (owner) → all resources in subscription
- Compromised StorageAccount → all BlobContainers within it

Uses Neo4j graph traversal (`resource_security_relationship_rules`).

---

## Phase 5 — IAM Engine (Azure)

### Milestone 5.1: Azure IAM Rules

`rule_metadata` entries for Azure IAM (provider='azure', iam_modules includes 'azure_ad'):

EntraID (Azure AD):
- No accounts without MFA
- No stale guest accounts (>90 days inactive)
- No users with permanent admin roles (should use PIM)
- No custom admin roles with broad permissions
- Password not required: not set on cloud-only accounts
- Service principals: certificate preferred over password credential
- Service principals: no expired credentials
- App registrations: no expiring credentials
- Managed identities: prefer over service principals with credentials

RBAC:
- No direct user role assignments (should use groups)
- No custom owner-equivalent roles
- No role assignments at subscription scope for non-admin roles
- Key Vault: use RBAC model, not access policies

**IAM module name**: `azure_ad` (stored in `iam_modules` column of iam_findings)

---

## Phase 6 — DataSec Engine (Azure)

### Milestone 6.1: Azure DataSec

`datasec_data_store_services` already has Azure rows (blob, cosmos, sql, keyvault, etc.). ✓

DataSec rules in rule_metadata covering:
- Storage blob: detect public containers with PII
- Azure SQL: detect unencrypted databases
- Key Vault: detect secrets without expiry
- Cosmos DB: detect databases without encryption at rest
- Azure Data Lake: detect public access

DataSec engine reads discovery_findings for storage resources, runs classification rules.
No code change needed — provider='azure' filter handles it.

---

## Phase 7 — Compliance Engine (Azure)

### Milestone 7.1: CIS Azure 1.5 Framework

Seed `compliance_frameworks`:
```sql
INSERT INTO compliance_frameworks (framework_id, name, version, provider, description) VALUES
('cis_azure_1_5', 'CIS Microsoft Azure Foundations Benchmark', '1.5.0', 'azure',
 'CIS Benchmark for Azure cloud security configuration'),
('azure_security_benchmark', 'Microsoft Azure Security Benchmark', '3.0', 'azure',
 'Microsoft security best practices for Azure');
```

Seed `compliance_controls` — all CIS Azure 1.5 controls:
- Section 1: Identity and Access Management (1.1-1.25)
- Section 2: Security Center (2.1-2.15)
- Section 3: Storage Accounts (3.1-3.15)
- Section 4: Database Services (4.1-4.9)
- Section 5: Logging and Monitoring (5.1-5.6)
- Section 6: Networking (6.1-6.6)
- Section 7: Virtual Machines (7.1-7.7)
- Section 8: App Service (8.1-8.8)
- Section 9: Key Vault (9.1-9.4)

Seed `rule_control_mapping` — map each Azure rule → CIS Azure control.

---

## Phase 8 — API Layer

### Per-Engine API Changes

All engines already support `?provider=azure` query param (or will with minor addition).

**Discoveries API** (`engines/discoveries/common/api_server.py`):
- GET `/api/v1/discovery/{scan_run_id}` — returns `provider` field ✓ (no change)

**Check API** (`engines/check/common/api_server.py`):
- GET `/api/v1/check/findings?provider=azure` — add provider filter ✓
- GET `/api/v1/check/rules?provider=azure` — list Azure rules

**Inventory API** (`engines/inventory/inventory_engine/api/ui_data_router.py`):
- GET `/api/v1/inventory/assets?provider=azure` — filter by provider ✓
- GET `/api/v1/inventory/graph?provider=azure` — Azure security graph

**Threat API** (`engines/threat/threat_engine/api/`):
- GET `/api/v1/threat/findings?provider=azure` — filter by provider ✓
- GET `/api/v1/threat/attack-paths?provider=azure` — Azure attack paths

**IAM API** (`engines/iam/iam_engine/api/`):
- GET `/api/v1/iam/findings?provider=azure` — filter by provider ✓
- Response labels: use Azure terminology (EntraID, RBAC, Service Principal)

**Compliance API** (`engines/compliance/compliance_engine/api/`):
- GET `/api/v1/compliance/score?provider=azure&framework=cis_azure_1_5`
- GET `/api/v1/compliance/frameworks?provider=azure` — list Azure-applicable frameworks

**DataSec API** (`engines/datasec/data_security_engine/api/`):
- GET `/api/v1/datasec/findings?provider=azure` ✓

**Risk API** (`engines/risk/risk_engine/api/`):
- GET `/api/v1/risk/summary?provider=azure` ✓

**Gateway Summary Endpoint** (new, all-engine aggregate):
- GET `/api/v1/summary?provider=azure` — returns:
  ```json
  {
    "provider": "azure",
    "subscription_id": "f6d24b5d...",
    "last_scan": "2026-04-07T...",
    "compliance_score": 72,
    "findings": {"critical": 5, "high": 23, "medium": 41},
    "resources": {"total": 847, "critical": 12},
    "risk_exposure": 450000,
    "frameworks": [{"cis_azure_1_5": {"score": 68, "controls_passed": 42}}]
  }
  ```

---

## Phase 9 — BFF / UI

### BFF Changes

All engine `ui_data_router.py` files need provider filter support passed through.
Most already query with `provider` column — just need to accept `?provider=azure` param.

Specifically:
- Response should include CSP badge metadata: `{"provider": "azure", "icon": "azure", "label": "Azure"}`
- Resource type display: Azure-specific names (not EC2/S3 — show VirtualMachine/StorageAccount)
- Region display: Azure region names (`eastus`, `westeurope`) not AWS names

### UI Changes

The frontend is already multi-CSP at component level. For Azure support:

1. **CSP Selector**: Add Azure to cloud selector dropdown (icon + label)
2. **Resource type icons**: Map Azure resource types to icons (compute, storage, network, etc.)
3. **IAM page**: Show Azure AD terminology (Entra ID, Service Principals, RBAC instead of IAM roles)
4. **Compliance page**: Show CIS Azure 1.5 framework when Azure is selected
5. **Threat page**: Show Azure-specific MITRE techniques (T1078.004, T1537, etc.)
6. **Dashboard**: Azure-specific resource counts, compliance score per framework

No new pages needed — same layout, different data filtered by provider=azure.

---

## Milestone Order & Dependencies

```
M1: Provider bootstrap + auth (no deps)
M2: Client factory + pagination (after M1)
M3: Noise removal in rule_discoveries (no deps — DB update)
M4: DB seed: relationships + classification + CIS Azure framework (no deps)
M5: Azure check rules written + seeded into rule_metadata (no deps)
M6: Docker build + K8s secret creation (after M1+M2)
M7: E2E discovery scan with Azure creds (after M6)
M8: Inventory pipeline run (after M7 + M4)
M9: Check engine run (after M7 + M5)
M10: Threat + IAM + DataSec runs (after M9)
M11: Compliance report (after M9 + CIS framework seed)
M12: Risk score (after M10+M11)
M13: API provider filter additions (after M7)
M14: BFF/UI Azure labels + icons (after M13)
```

**Estimated effort:** 4-5 weeks (2 engineers: 1 backend/cloud, 1 full-stack)