# Discovery Engine Architecture - Visual Guide

**Date:** 2026-02-20
**Purpose:** Visual representation of multi-CSP discovery architecture

---

## 🏗️ High-Level Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                          USER/ORCHESTRATOR                              │
│                 (Triggers discovery scan via API)                       │
└────────────────────────────────┬───────────────────────────────────────┘
                                 │
                                 │ POST /api/v1/discovery
                                 │ {orchestration_id: "uuid-123"}
                                 │
                                 ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     COMMON API SERVER (CSP-Agnostic)                    │
│                      common/api_server.py                               │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │ Provider Registry (PROVIDER_SCANNERS)                            │ │
│  │  - aws    → AWSDiscoveryScanner                                  │ │
│  │  - azure  → AzureDiscoveryScanner                                │ │
│  │  - gcp    → GCPDiscoveryScanner                                  │ │
│  │  - oci    → OCIDiscoveryScanner                                  │ │
│  └──────────────────────────────────────────────────────────────────┘ │
└────────────────────────────────┬───────────────────────────────────────┘
                                 │
                                 │ Fetch scan metadata
                                 │
                                 ▼
┌────────────────────────────────────────────────────────────────────────┐
│                    ONBOARDING DB (Input Database)                       │
│                  threat_engine_onboarding.scan_orchestration            │
│                                                                         │
│  Returns: customer_id, tenant_id, provider, account_id,                │
│           hierarchy_id, credential_ref, include_services,               │
│           include_regions                                               │
└────────────────────────────────┬───────────────────────────────────────┘
                                 │
                                 │ Get credentials
                                 │
                                 ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   AWS SECRETS MANAGER                                   │
│              (Stores cloud provider credentials)                        │
│                                                                         │
│  Returns: Access keys, IAM role ARN, Service Principal creds, etc.     │
└────────────────────────────────┬───────────────────────────────────────┘
                                 │
                                 │ Select scanner based on provider
                                 │
        ┌────────────────────────┼────────────────────────┐
        │                        │                        │
        │ provider='aws'         │ provider='azure'       │ provider='gcp'
        │                        │                        │
        ▼                        ▼                        ▼
┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│  AWS Scanner     │    │  Azure Scanner   │    │  GCP Scanner     │
│  (Implemented)   │    │  (Stub)          │    │  (Stub)          │
└──────────────────┘    └──────────────────┘    └──────────────────┘
        │
        │ Authenticate to cloud provider
        │
        ▼
┌────────────────────────────────────────────────────────────────────────┐
│                    COMMON DISCOVERY ENGINE                              │
│              common/orchestration/discovery_engine.py                   │
│                                                                         │
│  Flow:                                                                  │
│  1. Get enabled services for provider                                  │
│  2. For each service:                                                  │
│     a. Read discovery config from rule_discoveries                     │
│     b. Call scanner.scan_service() (CSP-specific)                      │
│     c. Store results in discovery_findings                             │
└────────────────────────────────┬───────────────────────────────────────┘
                                 │
                                 │ Read service configs
                                 │
                                 ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     CHECK DB (Config Database)                          │
│                 threat_engine_check.rule_discoveries                    │
│                                                                         │
│  Columns used:                                                          │
│  - service: Service name (ec2, s3, storage, compute)                   │
│  - provider: CSP (aws, azure, gcp, oci)                                │
│  - is_active: Enable/disable service                                   │
│  - boto3_client_name: SDK client name                                  │
│  - scope: regional or global                                           │
│  - discoveries_data: Complete discovery config (JSONB) ⭐              │
│  - filter_rules: API and response filters (JSONB)                      │
│  - pagination_config: Pagination settings (JSONB)                      │
│  - features: Feature flags (JSONB)                                     │
└────────────────────────────────┬───────────────────────────────────────┘
                                 │
                                 │ discoveries_data config
                                 │
                                 ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   CSP-SPECIFIC SCANNER (Provider Layer)                 │
│                  providers/{csp}/scanner/service_scanner.py             │
│                                                                         │
│  AWS Example:                                                           │
│  1. Get boto3 client: boto3.client('ec2', region='us-east-1')          │
│  2. Execute API calls from config:                                     │
│     - action: "describe_instances"                                     │
│     - params: {}                                                       │
│     - response_field: "Reservations[].Instances[]"                     │
│  3. Extract resources using jmespath                                   │
│  4. Generate ARN/ID/name for each resource                             │
│  5. Return list of discoveries                                         │
└────────────────────────────────┬───────────────────────────────────────┘
                                 │
                                 │ Return discoveries
                                 │
                                 ▼
┌────────────────────────────────────────────────────────────────────────┐
│                    COMMON DATABASE MANAGER                              │
│                 common/database/database_manager.py                     │
│                                                                         │
│  Stores results in discovery_findings table                            │
└────────────────────────────────┬───────────────────────────────────────┘
                                 │
                                 │ INSERT discoveries
                                 │
                                 ▼
┌────────────────────────────────────────────────────────────────────────┐
│                  DISCOVERIES DB (Output Database)                       │
│              threat_engine_discoveries.discovery_findings               │
│                                                                         │
│  Columns written:                                                       │
│  - discovery_scan_id: Scan UUID                                        │
│  - customer_id, tenant_id, provider, hierarchy_id                      │
│  - discovery_id: API call identifier (aws.ec2.describe_instances)      │
│  - resource_uid: Primary identifier (ARN/Resource ID/selfLink/OCID) ⭐ │
│  - resource_arn: AWS ARN (backward compatibility)                      │
│  - resource_id: Instance ID, Object ID, etc.                           │
│  - resource_type: instance, bucket, vm, etc.                           │
│  - service: ec2, storage, compute, etc.                                │
│  - region: Region/location                                             │
│  - emitted_fields: Extracted metadata (JSONB) ⭐                        │
│  - raw_response: Complete API response (JSONB)                         │
│  - config_hash: SHA256 hash for drift detection                        │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🔄 Data Flow by Layer

### Layer 1: API Entry Point (CSP-Agnostic)

```
┌─────────────────────────────────────────────────────────┐
│               common/api_server.py                       │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  Input:  orchestration_id                               │
│  Output: discovery_scan_id, status, provider            │
│                                                          │
│  Responsibilities:                                       │
│  ✓ Generate scan ID                                     │
│  ✓ Fetch orchestration metadata                         │
│  ✓ Retrieve credentials                                 │
│  ✓ Select CSP-specific scanner                          │
│  ✓ Launch discovery engine                              │
│  ✓ Return scan status                                   │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### Layer 2: Orchestration (CSP-Agnostic)

```
┌─────────────────────────────────────────────────────────┐
│      common/orchestration/discovery_engine.py            │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  Input:  scanner, metadata                              │
│  Output: scan_id                                        │
│                                                          │
│  Responsibilities:                                       │
│  ✓ Get enabled services from rule_discoveries           │
│  ✓ Read discovery config for each service               │
│  ✓ Call scanner.scan_service() (CSP-specific)           │
│  ✓ Store results via database_manager                   │
│  ✓ Track progress and errors                            │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### Layer 3: Database Operations (CSP-Agnostic)

```
┌─────────────────────────────────────────────────────────┐
│         common/database/                                 │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  check_db_reader.py:                                    │
│  ✓ Read discoveries_data from rule_discoveries          │
│  ✓ Get enabled services                                 │
│  ✓ Filter by provider and feature flags                 │
│                                                          │
│  database_manager.py:                                   │
│  ✓ Create scan record in discovery_report               │
│  ✓ Insert discoveries into discovery_findings           │
│  ✓ Update scan status                                   │
│  ✓ Handle batch operations                              │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### Layer 4: Provider Implementation (CSP-Specific)

```
┌───────────────────────────────────────────────────────────────────┐
│              providers/{csp}/scanner/service_scanner.py            │
├───────────────────────────────────────────────────────────────────┤
│                                                                    │
│  AWS (providers/aws/):                                            │
│  ✓ boto3 SDK integration                                          │
│  ✓ AWS authentication (STS AssumeRole, access keys)               │
│  ✓ ARN generation/extraction                                      │
│  ✓ AWS-specific pagination (NextToken)                            │
│                                                                    │
│  Azure (providers/azure/):                                        │
│  ✓ Azure SDK integration (TODO)                                   │
│  ✓ Service Principal authentication                               │
│  ✓ Resource ID extraction                                         │
│  ✓ Azure-specific pagination (nextLink)                           │
│                                                                    │
│  GCP (providers/gcp/):                                            │
│  ✓ GCP SDK integration (TODO)                                     │
│  ✓ Service Account authentication                                 │
│  ✓ selfLink extraction                                            │
│  ✓ GCP-specific pagination (pageToken)                            │
│                                                                    │
│  OCI (providers/oci/):                                            │
│  ✓ OCI SDK integration (TODO)                                     │
│  ✓ API Key authentication                                         │
│  ✓ OCID extraction                                                │
│  ✓ OCI-specific pagination                                        │
│                                                                    │
└───────────────────────────────────────────────────────────────────┘
```

---

## 📋 Database Schema Relationships

```
┌──────────────────────────────────────────────────────────────────────┐
│                        DATABASE ARCHITECTURE                          │
└──────────────────────────────────────────────────────────────────────┘

INPUT DATABASES (Read-Only):

┌─────────────────────────────────────────────────────────┐
│  threat_engine_onboarding.scan_orchestration            │
├─────────────────────────────────────────────────────────┤
│  orchestration_id (PK)                                  │
│  customer_id                                            │
│  tenant_id                                              │
│  provider ◄────────────────┐ (aws, azure, gcp, oci)    │
│  account_id                 │                           │
│  hierarchy_id               │                           │
│  credential_type            │                           │
│  credential_ref             │                           │
│  include_services           │                           │
│  include_regions            │                           │
│  discoveries_scan_id ◄──────┼───────┐ (updated)        │
└─────────────────────────────┼───────┼─────────────────┘
                              │       │
                              │       │
┌─────────────────────────────┼───────┼─────────────────┐
│  threat_engine_check.rule_discoveries                  │
├─────────────────────────────┼───────┼─────────────────┤
│  service                    │       │                  │
│  provider ◄─────────────────┘       │                  │
│  is_active                          │                  │
│  boto3_client_name                  │                  │
│  scope                              │                  │
│  arn_pattern                        │                  │
│  discoveries_data (JSONB) ⭐        │                  │
│  filter_rules (JSONB)               │                  │
│  pagination_config (JSONB)          │                  │
│  features (JSONB)                   │                  │
└─────────────────────────────────────┼─────────────────┘
                                      │
                                      │
OUTPUT DATABASE (Write):              │
                                      │
┌─────────────────────────────────────┼─────────────────┐
│  threat_engine_discoveries.discovery_report            │
├─────────────────────────────────────┼─────────────────┤
│  discovery_scan_id (PK) ◄───────────┘                 │
│  customer_id                                           │
│  tenant_id                                             │
│  provider                                              │
│  hierarchy_id                                          │
│  status                                                │
└─────────────────────────────────────┬─────────────────┘
                                      │
                                      │ FK: discovery_scan_id
                                      │
┌─────────────────────────────────────▼─────────────────┐
│  threat_engine_discoveries.discovery_findings          │
├────────────────────────────────────────────────────────┤
│  id (PK)                                               │
│  discovery_scan_id (FK) ◄── references discovery_report│
│  customer_id                                           │
│  tenant_id                                             │
│  provider                                              │
│  hierarchy_id                                          │
│  discovery_id                                          │
│  resource_uid ⭐ (ARN/Resource ID/selfLink/OCID)       │
│  resource_arn (AWS backward compat)                    │
│  resource_id                                           │
│  resource_type                                         │
│  service                                               │
│  region                                                │
│  emitted_fields (JSONB) ⭐                             │
│  raw_response (JSONB)                                  │
│  config_hash                                           │
└────────────────────────────────────────────────────────┘
```

---

## 🎯 Key Design Principles

### 1. Separation of Concerns

```
┌──────────────────────────────────────────────────────┐
│                COMMON LAYER                          │
│  (Orchestration, Database, Utilities)                │
│                                                      │
│  ✓ CSP-agnostic                                     │
│  ✓ Single source of truth                           │
│  ✓ Shared by all providers                          │
│  ✓ No provider-specific logic                       │
└──────────────────────────────────────────────────────┘
                        │
                        │ Uses
                        ▼
┌──────────────────────────────────────────────────────┐
│             PROVIDER INTERFACE                       │
│        (DiscoveryScanner ABC)                        │
│                                                      │
│  ✓ Defines contract                                 │
│  ✓ Enforces consistency                             │
│  ✓ Enables polymorphism                             │
└──────────────────────────────────────────────────────┘
                        │
                        │ Implemented by
                        ▼
┌──────────────────────────────────────────────────────┐
│            PROVIDER LAYER                            │
│   (AWS, Azure, GCP, OCI Scanners)                   │
│                                                      │
│  ✓ CSP-specific SDK calls                           │
│  ✓ Authentication methods                           │
│  ✓ Resource identifier extraction                   │
│  ✓ Pagination handling                              │
└──────────────────────────────────────────────────────┘
```

### 2. Data Flow Unidirectional

```
Request → Orchestration → Config → Scanner → Results → Database → Response
  (IN)        (COMMON)     (READ)   (CSP)     (DATA)    (WRITE)     (OUT)
```

### 3. Database-Driven Configuration

```
┌─────────────────────────────────────────────────────┐
│  rule_discoveries.discoveries_data (JSONB)          │
│                                                     │
│  {                                                  │
│    "discovery": [                                   │
│      {                                              │
│        "action": "describe_instances",              │
│        "response_field": "Reservations[].Instances[]",│
│        "params": {}                                 │
│      }                                              │
│    ]                                                │
│  }                                                  │
└─────────────────────────────────────────────────────┘
                    │
                    │ Read at runtime
                    ▼
        ┌───────────────────────┐
        │  Discovery Engine     │
        │  (No hardcoded logic) │
        └───────────────────────┘
```

---

## ✅ Architecture Benefits Summary

### Code Organization

| Aspect | Before | After |
|--------|--------|-------|
| **Common Code** | Duplicated 4x (~11,580 lines) | Shared 1x (~2,895 lines) |
| **CSP-Specific Code** | Mixed with common | Isolated in providers/ |
| **Configuration** | Hardcoded in Python | Database-driven (JSONB) |
| **Testing** | 4x duplication | Common tests + provider tests |

### Scalability

- ✅ Add new CSP: Implement DiscoveryScanner interface
- ✅ Add new service: Insert row in rule_discoveries
- ✅ Modify discovery: Update discoveries_data JSONB
- ✅ No code changes for config updates

### Maintainability

- ✅ Bug fixes in one place (common layer)
- ✅ Clear separation of CSP logic
- ✅ Easy to understand flow
- ✅ Self-documenting architecture

---

**Generated:** 2026-02-20
**Purpose:** Visual architecture guide for multi-CSP discovery engine
**Status:** ✅ Complete

