# Cross-CSP Engine Comparison

## Overview

This document compares the compliance engines across all Cloud Service Providers (CSPs) in the threat-engine platform.

## Unified Architecture

All CSP engines now follow the **same generic, YAML-driven architecture**:

```
Generic Engine Architecture
│
├── Configuration Layer
│   ├── Load Service Catalog
│   └── Load Service Rules (YAML)
│
├── Discovery Layer
│   ├── Discover Organizational Structure
│   ├── Discover Accounts/Projects/Subscriptions
│   ├── Discover Regions
│   └── Discover Resources
│
├── Client Factory
│   ├── Dynamic Client Creation
│   └── Client Caching
│
├── Action Executor
│   ├── Dynamic Method Resolution
│   ├── Template Substitution
│   └── Paged Result Handling
│
├── Service Runner
│   ├── Discovery Phase (Inventory)
│   ├── Check Phase (Compliance)
│   └── Result Aggregation
│
└── Orchestrator
    ├── Multi-Account/Project/Subscription Scanning
    ├── Multi-Region Scanning
    └── Parallel Execution
```

## CSP-Specific Hierarchies

### AWS
```
Organization
└── Organizational Unit (OU)
    └── Account
        ├── Global Resources (IAM, S3, CloudFront)
        └── Region
            └── Regional Resources (EC2, RDS, VPC)
```

**Scope Values:**
- `global`: Account-wide, no region (IAM, S3)
- `regional`: Per-region resources (EC2, RDS)
- `organizational`: Organization-wide (AWS Organizations)

### GCP
```
Organization
├── Folder
│   └── Folder (recursive)
│       └── Project
│           ├── Global Resources (IAM, GCS)
│           └── Region
│               └── Regional Resources (Compute, SQL)
```

**Scope Values:**
- `global`: Project-wide, no region (IAM, GCS)
- `regional`: Per-region resources (Compute Engine)
- `organization`: Organization-wide (Org Policies)

### Azure
```
Tenant
├── Management Group
│   └── Management Group (recursive)
│       └── Subscription
│           ├── Global Resources (AAD, Policies)
│           ├── Resource Group
│           │   └── RG-scoped Resources
│           └── Region
│               └── Regional Resources (VMs, Networks)
```

**Scope Values:**
- `global`: Subscription-wide, no region
- `subscription`: Subscription-scoped (Storage, Key Vault)
- `regional`: Per-region resources (VMs, Networks)
- `tenant`: Tenant-wide (Azure AD via Graph API)
- `management_group`: Management Group-scoped (Policies)

### AliCloud
```
Resource Directory
└── Folder
    └── Account
        ├── Global Resources
        └── Region
            └── Regional Resources
```

### IBM Cloud
```
Enterprise
└── Account Group
    └── Account
        ├── Global Resources
        └── Region
            └── Regional Resources
```

### OCI (Oracle Cloud Infrastructure)
```
Tenancy
└── Compartment
    └── Compartment (recursive)
        ├── Global Resources
        └── Region
            └── Regional Resources
```

## Unified YAML Format

All CSPs use the **same YAML structure**:

```yaml
service_name:
  version: '1.0'
  provider: aws|gcp|azure|alicloud|ibm|oci
  service: <service_name>
  scope: global|regional|subscription|project|account|organization|tenant
  
  # CSP-Specific SDK Configuration
  # AWS: (uses boto3, no explicit config)
  # GCP:
  api_name: compute
  api_version: v1
  # OR
  sdk_package: google.cloud.storage
  client_class: Client
  
  # Azure:
  sdk_package: azure.mgmt.compute
  client_class: ComputeManagementClient
  api_type: management|data_plane|graph
  
  # AliCloud:
  sdk_package: alibabacloud_ecs20140526
  client_class: Client
  
  # Discovery
  discovery:
  - discovery_id: <csp>.<service>.<resource_type>
    calls:
    - action: <method_name>
      params:
        key: value
      fields:
      - path: <field_path>
  
  # Checks
  checks:
  - check_id: <csp>.<service>.<resource>.<check>
    title: <human_readable_title>
    severity: critical|high|medium|low
    for_each: <discovery_id>
    logic: AND|OR
    calls:
    - action: self|eval|<method_name>
      fields:
      - path: <field_path>
        operator: equals|exists|contains|gt|gte|lt|lte
        expected: <value>
```

## Engine Implementation Comparison

| Feature | AWS | GCP | Azure | Status |
|---------|-----|-----|-------|--------|
| **Generic Engine** | ✅ | ✅ | ✅ | Complete |
| **Unified YAML Format** | ✅ | ✅ | ✅ | Complete |
| **Dynamic Client Creation** | ✅ | ✅ | ✅ | Complete |
| **Dynamic Action Execution** | ✅ | ✅ | ✅ | Complete |
| **Template Substitution** | ✅ | ✅ | ✅ | Complete |
| **Multi-Account/Project/Sub** | ✅ | ✅ | ✅ | Complete |
| **Multi-Region** | ✅ | ✅ | ✅ | Complete |
| **Parallel Execution** | ✅ | ✅ | ✅ | Complete |
| **Filtering** | ✅ | ✅ | ✅ | Complete |
| **Caching** | ✅ | ✅ | ✅ | Complete |

## Engine Files

| CSP | Engine File | Lines | Type |
|-----|-------------|-------|------|
| **AWS** | `aws_compliance_python_engine/engine/boto3_engine_simple.py` | ~550 | Generic |
| **GCP** | `gcp_compliance_python_engine/engine/gcp_engine.py` | ~637 | Generic |
| **Azure** | `azure_compliance_python_engine/engine/azure_generic_engine.py` | ~700 | Generic |
| **AliCloud** | `alicloud_compliance_python_engine/engine/alicloud_engine.py` | TBD | Generic |
| **IBM** | `ibm_compliance_python_engine/engine/ibm_engine.py` | TBD | Generic |
| **OCI** | `oci_compliance_python_engine/engine/oci_engine.py` | TBD | Generic |

## Client Creation Patterns

### AWS (Boto3)
```python
import boto3

# Boto3 uses simple service names
client = boto3.client('s3', region_name=region)
client = boto3.client('ec2', region_name=region)
```

**YAML:**
```yaml
# No explicit client config needed
# Service name maps directly to boto3 client
service: s3
```

### GCP (Discovery API)
```python
from googleapiclient.discovery import build

# Discovery API
client = build('compute', 'v1', credentials=creds)
client = build('storage', 'v1', credentials=creds)
```

**YAML:**
```yaml
api_name: compute
api_version: v1
```

### GCP (SDK)
```python
from google.cloud import storage

# SDK client
client = storage.Client(project=project_id, credentials=creds)
```

**YAML:**
```yaml
sdk_package: google.cloud.storage
client_class: Client
```

### Azure (Management Plane)
```python
from azure.mgmt.compute import ComputeManagementClient

# Management plane
client = ComputeManagementClient(credential, subscription_id)
```

**YAML:**
```yaml
sdk_package: azure.mgmt.compute
client_class: ComputeManagementClient
api_type: management
```

### Azure (Data Plane)
```python
from azure.storage.blob import BlobServiceClient

# Data plane
client = BlobServiceClient(account_url=url, credential=cred)
```

**YAML:**
```yaml
sdk_package: azure.storage.blob
client_class: BlobServiceClient
api_type: data_plane
```

### Azure (Graph API)
```python
import requests

# Microsoft Graph (REST)
token = credential.get_token('https://graph.microsoft.com/.default')
response = requests.get(
    'https://graph.microsoft.com/v1.0/users',
    headers={'Authorization': f'Bearer {token.token}'}
)
```

**YAML:**
```yaml
api_type: graph
# No SDK package needed
```

## Action Execution Patterns

### AWS
```yaml
calls:
- action: list_buckets
  # → boto3.client('s3').list_buckets()

- action: describe_instances
  params:
    Filters: [{Name: 'instance-state-name', Values: ['running']}]
  # → boto3.client('ec2').describe_instances(Filters=[...])
```

### GCP (Discovery API)
```yaml
calls:
- action: list_firewalls
  # → client.firewalls().list(project=project_id).execute()

- action: aggregatedList_instances
  # → client.instances().aggregatedList(project=project_id).execute()
```

### GCP (SDK)
```yaml
calls:
- action: list_buckets
  # → [b.name for b in client.list_buckets(project=project_id)]

- action: get_bucket_iam_policy
  # → client.bucket(bucket_name).get_iam_policy()
```

### Azure
```yaml
calls:
- action: storage_accounts.list
  # → client.storage_accounts.list()

- action: virtual_machines.list
  params:
    resource_group_name: my-rg
  # → client.virtual_machines.list(resource_group_name='my-rg')
```

## Filtering Capabilities

All engines support the same filtering environment variables:

### Common Filters

| Filter Type | AWS | GCP | Azure |
|-------------|-----|-----|-------|
| **Services** | `AWS_ENGINE_FILTER_SERVICES` | `GCP_ENGINE_FILTER_SERVICES` | `AZURE_ENGINE_FILTER_SERVICES` |
| **Accounts/Projects/Subs** | `AWS_ENGINE_FILTER_ACCOUNTS` | `GCP_PROJECTS` | `AZURE_ENGINE_FILTER_SUBSCRIPTIONS` |
| **Regions** | `AWS_ENGINE_FILTER_REGIONS` | `GCP_ENGINE_FILTER_REGIONS` | `AZURE_ENGINE_FILTER_REGIONS` |
| **Check IDs** | `AWS_ENGINE_FILTER_CHECK_IDS` | `GCP_ENGINE_FILTER_CHECK_IDS` | `AZURE_ENGINE_FILTER_CHECK_IDS` |
| **Resource Names** | `AWS_ENGINE_FILTER_RESOURCE_NAME` | `GCP_ENGINE_FILTER_RESOURCE_NAME` | - |

### Examples

```bash
# AWS
export AWS_ENGINE_FILTER_SERVICES="s3,ec2,iam"
export AWS_ENGINE_FILTER_ACCOUNTS="123456789012"
export AWS_ENGINE_FILTER_REGIONS="us-east-1,us-west-2"

# GCP
export GCP_ENGINE_FILTER_SERVICES="compute,gcs,iam"
export GCP_PROJECTS="my-project-id"
export GCP_ENGINE_FILTER_REGIONS="us-central1,europe-west1"

# Azure
export AZURE_ENGINE_FILTER_SERVICES="storage,compute,network"
export AZURE_ENGINE_FILTER_SUBSCRIPTIONS="sub-id"
export AZURE_ENGINE_FILTER_REGIONS="eastus,westus"
```

## Performance Characteristics

| Aspect | AWS | GCP | Azure |
|--------|-----|-----|-------|
| **Parallelism** | 3-level | 3-level | 4-level |
| **Client Caching** | ✅ | ✅ | ✅ |
| **Result Caching** | ✅ | ❌ | ✅ |
| **Pagination Handling** | ✅ | ✅ | ✅ |
| **Rate Limiting** | SDK-level | SDK-level | SDK-level |
| **Error Handling** | Graceful | Graceful | Graceful |

### Parallelism Breakdown

**AWS:**
1. Accounts in parallel
2. Regions in parallel per account
3. Resources in parallel per region

**GCP:**
1. Projects in parallel
2. Regions in parallel per project
3. Resources in parallel per region

**Azure:**
1. Subscriptions in parallel
2. Services in parallel per subscription
3. Regions in parallel per service
4. Resources in parallel per region

## Output Format

All engines produce the **same output structure**:

```json
[
  {
    "service": "storage",
    "account": "123456789012",  // AWS
    "project": "my-project",     // GCP
    "subscription": "sub-id",    // Azure
    "region": "us-east-1",
    "scope": "regional",
    "inventory": {
      "aws.s3.buckets": ["bucket1", "bucket2"],
      "gcp.storage.buckets": ["bucket1", "bucket2"],
      "azure.storage.accounts": ["account1", "account2"]
    },
    "checks": [
      {
        "check_id": "aws.s3.bucket.encryption.enabled",
        "resource": "bucket1",
        "result": "PASS"
      },
      {
        "check_id": "gcp.storage.bucket.encryption.enabled",
        "resource": "bucket1",
        "result": "FAIL"
      }
    ]
  }
]
```

## Migration Status

| CSP | Old Engine | New Generic Engine | Migration Tool | Documentation | Status |
|-----|-----------|-------------------|----------------|---------------|--------|
| **AWS** | ✅ | ✅ | ✅ | ✅ | Complete |
| **GCP** | ✅ | ✅ | ✅ | ✅ | Complete |
| **Azure** | ✅ | ✅ | ✅ | ✅ | Complete |
| **AliCloud** | ✅ | ⏳ | ⏳ | ⏳ | In Progress |
| **IBM** | ✅ | ⏳ | ⏳ | ⏳ | In Progress |
| **OCI** | ✅ | ⏳ | ⏳ | ⏳ | In Progress |

## Key Benefits of Unified Architecture

### 1. Consistency
- Same YAML format across all CSPs
- Same engine architecture
- Same filtering capabilities
- Same output format

### 2. Maintainability
- Single pattern to learn
- Easy to port fixes between CSPs
- Reduced code duplication
- Centralized documentation

### 3. Extensibility
- Add new services with YAML only (no code)
- Add new CSPs following same pattern
- Easy to add new check types
- Modular architecture

### 4. Developer Experience
- Consistent development workflow
- Reusable components
- Clear separation of concerns
- Easy testing and debugging

### 5. Operational Efficiency
- Parallel execution at multiple levels
- Client and result caching
- Flexible filtering
- Graceful error handling

## Code Reusability

### Shared Components

These components can be shared across all CSPs:

```python
# Utility functions (100% reusable)
extract_value(obj, path)
evaluate_field(value, operator, expected)
substitute_templates(text, context)

# Discovery patterns (90% reusable)
discover_regions()
discover_accounts/projects/subscriptions()

# Execution patterns (80% reusable)
execute_action(client, action, params)
run_service_compliance(service_name, context)

# Orchestration (70% reusable)
run_for_account/project/subscription()
run()  # Main entry point
```

### CSP-Specific Components

These components are CSP-specific:

```python
# AWS
get_boto3_session()
create_boto3_client(service_name)

# GCP
build_discovery_api_client(api_name, api_version)
create_sdk_client(package, class_name)

# Azure
create_azure_client(sdk_package, client_class, subscription_id)
execute_graph_api(path, params)
```

## Testing Strategy

### Unit Tests
- Test utility functions (extract_value, evaluate_field)
- Test template substitution
- Test client creation
- Test action execution

### Integration Tests
- Test with real cloud resources
- Test discovery phase
- Test check phase
- Test result aggregation

### Comparison Tests
- Compare old vs new engine results
- Verify same checks pass/fail
- Verify same inventory discovered
- Performance comparison

### Cross-CSP Tests
- Verify consistent YAML format
- Verify consistent output format
- Verify consistent filtering
- Verify consistent error handling

## Future Roadmap

### Short Term (Q1 2025)
- [ ] Complete AliCloud generic engine
- [ ] Complete IBM generic engine
- [ ] Complete OCI generic engine
- [ ] Cross-CSP YAML validation tool
- [ ] Performance benchmarking suite

### Medium Term (Q2 2025)
- [ ] Unified CLI tool for all CSPs
- [ ] Web dashboard for results
- [ ] Automated rule generation from CSP docs
- [ ] Custom rule authoring UI
- [ ] Real-time compliance monitoring

### Long Term (Q3-Q4 2025)
- [ ] Multi-cloud compliance comparison
- [ ] Policy-as-code integration
- [ ] Remediation automation
- [ ] Compliance drift detection
- [ ] Cost optimization recommendations

## Conclusion

The **unified generic engine architecture** successfully provides:

✅ **Consistent experience** across all CSPs
✅ **Reduced maintenance burden** through code reuse
✅ **Faster service onboarding** via YAML-only changes
✅ **Better scalability** through parallel execution
✅ **Production-ready** implementation for AWS, GCP, and Azure

All three major CSPs (AWS, GCP, Azure) now have feature-complete generic engines that follow the same architecture and YAML format, making the threat-engine platform truly multi-cloud ready.

---

**Status**: AWS ✅ | GCP ✅ | Azure ✅ | AliCloud ⏳ | IBM ⏳ | OCI ⏳
**Last Updated**: December 5, 2024

