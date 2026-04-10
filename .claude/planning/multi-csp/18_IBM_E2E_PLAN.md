# IBM Cloud — Full Stack E2E Plan

## Status
- Credentials: ✗ No account — needs provisioning (ibm.com/cloud Lite tier)
- rule_discoveries in DB: ✓ 63 services (aligned with catalog)
- Scanner code: Partial stub (360 lines, handler registry pattern)
- Check rules: ✗ 0 IBM rules in rule_metadata
- Inventory relationships: ✗ Not planned yet (small surface)
- Compliance frameworks: ✗ No IBM-specific frameworks
- Priority: #5 (blocked on credentials)

## Pre-Requisite: Account Setup

1. IBM Cloud Lite account: ibm.com/cloud
2. Create API key: `ibmcloud iam api-key-create cspm-scanner`
3. Note: API Key, Account ID, Resource Group ID
4. Create K8s secret:
   ```bash
   kubectl create secret generic ibm-creds -n threat-engine-engines \
     --from-literal=IBM_API_KEY=<api_key> \
     --from-literal=IBM_ACCOUNT_ID=<account_id> \
     --from-literal=IBM_RESOURCE_GROUP=Default
   ```

---

## Phase 1 — Discovery (Track A)

### Milestone 1.1: IBM Provider Completion

Check existing stub at `engines/discoveries/providers/ibm/`.

**US-IBM-DISC-01: Auth — Bearer Token from API Key**
```python
import requests

def get_ibm_token(api_key: str) -> str:
    resp = requests.post(
        "https://iam.cloud.ibm.com/identity/token",
        data={
            "grant_type": "urn:ibm:params:oauth:grant-type:apikey",
            "apikey": api_key,
        },
        headers={"Accept": "application/json"}
    )
    return resp.json()["access_token"]  # expires in 3600s, cache for 50 min
```

**US-IBM-DISC-02: Client Factory**
```python
IBM_CLIENT_MAP = {
    'vpc':                 ibm_vpc.VpcV1,
    'iam':                 ibm_platform_services.IamIdentityV1,
    'resource_controller': ibm_platform_services.ResourceControllerV2,
    'resource_manager':    ibm_platform_services.ResourceManagerV2,
    'object_storage':      ibm_boto3,  # via COS SDK
    'functions':           ibm_functions_client,
    'databases':           ibm_cloud_databases.CloudDatabasesV5,
    'container':           IKS REST API,
    'global_search':       ibm_platform_services.GlobalSearchV2,
    'global_tagging':      ibm_platform_services.GlobalTaggingV1,
}
```

**US-IBM-DISC-03: Resource Enumeration via Resource Controller**
IBM's primary inventory: `ResourceControllerV2.list_resource_instances()` — lists ALL resources across all types.
Then per-resource-type detail calls.

**US-IBM-DISC-04: IBM Pagination**
IBM uses `next_url` in response (cursor-based):
```python
def ibm_paginate(list_method, **kwargs) -> List[dict]:
    results, start = [], None
    while True:
        resp = list_method(start=start, limit=100, **kwargs).get_result()
        results.extend(resp.get('resources', []))
        next_url = resp.get('next_url') or resp.get('next')
        if not next_url:
            break
        start = next_url.split('start=')[1].split('&')[0]
    return results
```

**resource_uid format:** IBM CRN: `crn:v1:bluemix:public:{service}:{region}:a/{account}:{instance}/{resource}`

**Noise removal:** Remove activity tracker events, monitoring dashboards, billing reports.

**Docker:** `yadavanup84/engine-discoveries-ibm:v1.ibm.YYYYMMDD`
**SDK:** `ibm-platform-services`, `ibm-vpc`, `ibm-cloud-sdk-core`

---

## Phase 2 — Inventory (Track B)

IBM Relationship Rules (design):
| parent_type | child_type | relationship_type | provider |
|---|---|---|---|
| VPCInstance | SecurityGroup | PROTECTED_BY | ibm |
| VPCInstance | Subnet | ROUTES_TO | ibm |
| IBMFunction | ResourceGroup | CONTAINS | ibm |
| CossBucket | ResourceGroup | CONTAINS | ibm |
| DatabaseService | VPC | ROUTES_TO | ibm |

IBM Asset Classification:
- VSI (VPC instance), VPC, Subnet, Security Group, COS Bucket, DB instances (Databases for PostgreSQL, MySQL), Functions (IBM Cloud Functions/Code Engine), IKS Cluster

---

## Phase 3 — Check Engine (Track C)

### IBM Check Rules (~150 rules)

**VPC:**
- Security group: no inbound allow-all
- Security group: SSH/RDP restricted
- VPC: flow logs enabled
- Network ACL: no allow-all rules

**IAM:**
- API keys older than 90 days
- Users with admin access without MFA
- Service IDs with high-privilege policies
- IAM access group: review empty groups

**Object Storage (COS):**
- Bucket public access disabled
- Bucket activity tracking enabled
- Bucket cross-region replication for DR
- Bucket BYOK encryption

**Key Protect:**
- Keys: rotation enabled
- Keys: not accessible to all
- Key lifecycle: deletion protection

**Databases:**
- PostgreSQL: end-to-end encryption
- MongoDB: IP allowlist not 0.0.0.0/0
- Redis: TLS enabled

**Audit:**
- Activity Tracker: at least one instance per region
- Audit log retention configured
- Alerting for critical IAM events

---

## Phase 4 — Threat Engine

MITRE for IBM:
- T1078.004 — Cloud Accounts (API key theft)
- T1530 — COS bucket access
- T1580 — Cloud Infrastructure Discovery (Global Search API)
- T1190 — Exploit Public-Facing Application (Code Engine, API Connect)

---

## Phase 5 — IAM Engine (IBM)

IBM IAM:
- Access Groups, Service IDs, API Keys, Trusted Profiles
- Access policies: resource group-scoped, service-scoped
- MFA enforcement

Rules: API key age, admin MFA, overprivileged access groups, service ID credential rotation.
**IAM module name**: `ibm_iam`

---

## Phase 6 — DataSec Engine (IBM)

`datasec_data_store_services` has IBM rows (cos, postgresql, mysql, etc.). ✓

Rules: COS public bucket detection, DB encryption validation.

---

## Phase 7 — Compliance Engine (IBM)

```sql
INSERT INTO compliance_frameworks (framework_id, name, version, provider, description) VALUES
('cis_ibm_1_0', 'CIS IBM Cloud Foundations Benchmark', '1.0.0', 'ibm',
 'CIS Benchmark for IBM Cloud security configuration'),
('ibm_cloud_framework', 'IBM Cloud Security and Compliance Center', '1.0', 'ibm',
 'IBM Security and Compliance Center profile for IBM Cloud');
```

---

## Phases 8-9 — API + BFF/UI

Same pattern as Azure/GCP. IBM-specific:
- `?provider=ibm&account_id=<id>` filter
- Resource Group grouping in asset browser
- IBM resource type names (VSI, COS Bucket, VPC)
- IAM: Access Groups, Service IDs terminology

---

## Milestone Order (after credentials)

M0: IBM Cloud Lite account + API key + K8s secret
M1: Complete IBM scanner (auth + pagination + client map)
M2: DB seeds (relationships + classification)
M3: IBM check rules in rule_metadata
M4: Docker build
M5: E2E discovery + full pipeline
M6: API + BFF/UI

**Estimated effort:** 2-3 weeks (63 services = smallest surface of active CSPs)