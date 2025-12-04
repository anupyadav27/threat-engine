# Azure Compliance Engine - Implementation Plan

## 🎯 Objective
Create an Azure compliance engine similar to AWS boto3 engine, but adapted for Azure's multiple SDK packages and client architecture.

---

## 📊 Current State Analysis

### What We Have
- **1,831 rule YAML files** across 98 service folders
- Basic auth setup (azure_auth.py)
- Engine structure from AWS implementation
- Requirements.txt with 5 basic packages

### Key Differences: AWS vs Azure

| Aspect | AWS (boto3) | Azure SDK |
|--------|-------------|-----------|
| **Package Structure** | Single `boto3` package | 40+ separate packages |
| **Client Pattern** | `boto3.client('ec2')` | Import specific management client |
| **Service Discovery** | Dynamic | Must map service → package |
| **Authentication** | Session-based | Credential objects |
| **API Style** | Consistent | Varies (mgmt plane vs data plane) |

---

## 📋 Implementation Phases

### Phase 1: Foundation Setup ✅ (COMPLETED)

**Deliverables:**
1. ✅ Azure SDK Module Mapping document
2. ✅ Service Grouping by package
3. ✅ Azure Client Factory (azure_client_factory.py)
4. ✅ Complete requirements.txt

**Outcome:** We now have a clear mapping of all 98 services → Azure packages

---

### Phase 2: Service Cleanup & Consolidation 🔄 (NEXT)

**2.1 Remove Invalid Services**
```bash
# Services to remove (AWS-specific, not Azure)
services/eks/         # AWS EKS
services/lambda/      # AWS Lambda
services/s3/          # AWS S3
```

**2.2 Consolidate Duplicates**
Merge overlapping services:
- `compute` ← merge from: vm, virtualmachines, disk
- `function` ← merge from: functionapp, functions
- `webapp` ← merge from: app, appservice, application, site
- `security` ← merge from: securitycenter, defender
- `aad` ← merge from: ad, entra, entrad
- `cosmosdb` ← merge from: cosmos
- `redis` ← merge from: cache
- `sql` ← merge from: sqlserver
- `loadbalancer` ← merge from: load

**2.3 Handle "azure" folder**
- 205 rules in generic "azure" folder
- Need to redistribute to proper service folders
- Review and categorize each rule

**Estimated Effort:** 2-3 hours
**Impact:** Cleaner structure, reduced from 98 → ~50 service folders

---

### Phase 3: Update Rules YAML Structure 🔄

**Current AWS Format:**
```yaml
version: '1.0'
provider: aws
service: iam
discovery:
- discovery_id: aws.iam.users
  calls:
  - client: iam              # Single boto3 client name
    action: list_users
    save_as: users
```

**New Azure Format:**
```yaml
version: '1.0'
provider: azure
service: compute
package: azure-mgmt-compute           # NEW: Package name
client_class: ComputeManagementClient # NEW: Client class
discovery:
- discovery_id: azure.compute.vms
  calls:
  - client: compute                    # Maps to factory service name
    method: virtual_machines.list_all  # NEW: Resource group aware
    save_as: vms
```

**Changes Needed:**
1. Add `package` field to each service YAML
2. Add `client_class` field
3. Update `action` → `method` (Azure uses different naming)
4. Handle subscription_id and resource_group parameters

**Script to Generate:**
```python
# auto_update_rules_yaml.py
# - Read each service folder
# - Look up package/client from mapping
# - Add new fields to YAML
# - Update method names if needed
```

**Estimated Effort:** 1-2 hours scripting + testing
**Impact:** All 1,831 rules updated with Azure-specific metadata

---

### Phase 4: Adapt Engine for Azure 🔄

**4.1 Update Discovery Engine**

**Changes in `engine/azure_engine.py`:**

```python
# AWS version (simplified)
def execute_check(rule_yaml):
    client = boto3.client(rule['service'])
    response = client.list_users()
    
# Azure version
def execute_check(rule_yaml):
    from auth.azure_client_factory import get_azure_client
    
    client = get_azure_client(rule['service'])
    # Handle resource group iteration
    for rg in resource_groups:
        response = client.virtual_machines.list(rg)
```

**Key Adaptations:**
1. **Subscription Iteration**: Azure rules run per subscription
2. **Resource Group Awareness**: Many APIs require resource_group_name
3. **Pagination**: Azure uses different pagination (list vs list_next)
4. **Error Handling**: Different exception types
5. **Authentication**: Use credential objects, not sessions

**4.2 Handle Data Plane vs Control Plane**

```python
# Control plane (management) - standard
compute_client = get_azure_client('compute')

# Data plane (storage blob) - needs account URL
blob_client = BlobServiceClient(
    account_url=f"https://{account_name}.blob.core.windows.net",
    credential=credential
)
```

**4.3 Microsoft Graph Integration**

```python
# AAD/Entra ID services need MS Graph
from msgraph import GraphServiceClient

graph_client = GraphServiceClient(credential)
users = await graph_client.users.get()
```

**Estimated Effort:** 3-4 hours
**Impact:** Engine can execute Azure SDK calls correctly

---

### Phase 5: Method Name Mapping 🔄

**AWS → Azure Method Differences:**

| AWS (boto3) | Azure SDK |
|-------------|-----------|
| `list_instances()` | `virtual_machines.list()` |
| `describe_vpcs()` | `virtual_networks.list()` |
| `get_bucket_encryption()` | `storage_accounts.get_properties()` |

**Options:**
1. **Manual mapping in rules**: Update each YAML with correct Azure method
2. **Translation layer**: Build method_name translator
3. **Hybrid**: Common patterns translated, rest manual

**Recommended:** Hybrid approach
- Common patterns: `list_*, describe_*, get_*` → Azure equivalents
- Complex checks: Manual specification in YAML

**Estimated Effort:** 4-5 hours mapping + testing
**Impact:** Rules call correct Azure SDK methods

---

### Phase 6: Testing & Validation 🧪

**6.1 Unit Tests**
```python
# test_azure_client_factory.py
def test_compute_client_creation():
    factory = AzureClientFactory(subscription_id=test_sub)
    client = factory.get_client('compute')
    assert isinstance(client, ComputeManagementClient)

# test_service_mapping.py
def test_all_services_have_packages():
    for service_folder in services_dir:
        assert service in SERVICE_CLIENT_MAPPING
```

**6.2 Integration Tests**
```python
# test_real_azure.py
def test_list_vms_real():
    # Requires valid Azure credentials
    client = get_azure_client('compute')
    vms = client.virtual_machines.list_all()
    assert vms is not None
```

**6.3 Smoke Tests**
- Test 10 most common services
- Verify authentication works
- Check resource group iteration
- Validate error handling

**Estimated Effort:** 2-3 hours
**Impact:** Confidence in engine reliability

---

### Phase 7: Documentation & Examples 📚

**7.1 Update README**
- Azure-specific setup instructions
- Environment variable requirements
- Service principal creation guide

**7.2 Create Examples**
```bash
examples/
├── basic_vm_check.py
├── aad_user_check.py
├── storage_encryption_check.py
└── multi_subscription_scan.py
```

**7.3 Troubleshooting Guide**
- Common Azure SDK errors
- Authentication issues
- Package installation problems

**Estimated Effort:** 1-2 hours
**Impact:** Easy onboarding for new users

---

## 🔧 Technical Decisions Made

### 1. Client Factory Pattern
**Decision:** Create `AzureClientFactory` similar to boto3
**Rationale:** 
- Centralized client management
- Caching for performance
- Easy to test and mock

### 2. Service Name Consistency
**Decision:** Keep service names matching folder names
**Rationale:**
- Easy to map rule_id → service → package
- Consistent with AWS pattern
- Clear file organization

### 3. Package Installation
**Decision:** Include all packages in requirements.txt
**Rationale:**
- Avoid runtime installation issues
- Clear dependencies upfront
- ~40 packages = ~200MB (acceptable)

### 4. Authentication Strategy
**Decision:** Support both DefaultAzureCredential and Service Principal
**Rationale:**
- Flexibility for different environments
- DefaultAzure works for local dev
- Service Principal for CI/CD

---

## 📊 Estimated Timeline

| Phase | Task | Hours | Priority |
|-------|------|-------|----------|
| 1 | Foundation Setup | ✅ Done | Critical |
| 2 | Service Cleanup | 2-3h | High |
| 3 | Update Rules YAML | 1-2h | High |
| 4 | Adapt Engine | 3-4h | Critical |
| 5 | Method Mapping | 4-5h | High |
| 6 | Testing | 2-3h | Medium |
| 7 | Documentation | 1-2h | Low |

**Total Estimated Effort:** 13-19 hours
**Recommended Sprint:** 2-3 days

---

## 🚀 Quick Start Commands

```bash
# 1. Install dependencies
cd /Users/apple/Desktop/threat-engine/azure_compliance_python_engine
pip install -r requirements.txt

# 2. Set up Azure credentials
export AZURE_SUBSCRIPTION_ID="your-subscription-id"
export AZURE_TENANT_ID="your-tenant-id"
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-client-secret"

# 3. Test client factory
python auth/azure_client_factory.py

# 4. Run sample compliance check
python run_engine.py --service compute --region eastus
```

---

## 🎯 Success Criteria

- ✅ All Azure packages mapped to services
- ✅ Client factory can create clients for all services
- ⬜ Rules YAML updated with Azure metadata
- ⬜ Engine executes Azure SDK calls successfully
- ⬜ Can scan at least 10 core services
- ⬜ Error handling covers common Azure exceptions
- ⬜ Documentation complete

---

## 📝 Next Immediate Actions

1. **Test the client factory:**
   ```bash
   python auth/azure_client_factory.py
   ```

2. **Identify which services to test first:**
   - Start with: compute, storage, network, security, aad
   - These cover ~40% of rules

3. **Create a sample rules converter script:**
   - Read AWS-style rule
   - Output Azure-style rule
   - Test on 1 service

4. **Review one service folder in detail:**
   - Pick `compute` (52 rules)
   - Manually verify each rule makes sense
   - Update YAML format

---

## 🤔 Open Questions

1. **How to handle multi-subscription scenarios?**
   - Should engine scan all subscriptions in tenant?
   - Or require explicit subscription list?

2. **Resource group iteration strategy?**
   - List all RGs first, then iterate?
   - Or use `list_all()` methods where available?

3. **Microsoft Graph async pattern?**
   - MS Graph SDK is async (requires `await`)
   - Should engine be async for AAD checks?
   - Or use sync wrapper?

4. **Data plane authentication?**
   - Storage blobs need account-specific URLs
   - How to discover storage accounts first?
   - Cache account URLs?

---

## 📦 Deliverables Created So Far

1. ✅ `AZURE_SDK_MODULE_MAPPING.md` - Complete service → package mapping
2. ✅ `AZURE_SERVICE_GROUPS.yaml` - Logical grouping of services
3. ✅ `auth/azure_client_factory.py` - Client factory implementation
4. ✅ `requirements.txt` - All required Azure SDK packages
5. ✅ `AZURE_IMPLEMENTATION_PLAN.md` - This document

**Next:** Phase 2 - Service cleanup & consolidation

---

## 💡 Key Insights

1. **Azure is more complex than AWS:**
   - 40+ packages vs 1 package
   - Multiple client types (mgmt, data plane, Graph)
   - Resource group hierarchy

2. **But structure is clearer:**
   - Explicit package boundaries
   - Typed clients
   - Better separation of concerns

3. **Rule migration strategy:**
   - Can't be 100% automated
   - Need manual review of complex checks
   - But 70-80% can be scripted

4. **Testing is crucial:**
   - Azure SDK behavior differs from docs sometimes
   - Need real Azure environment for integration tests
   - Mock carefully for unit tests

---

**Ready to proceed to Phase 2?**

