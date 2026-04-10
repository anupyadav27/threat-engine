# IBM Cloud — Detailed Project Plan

## Context

- **Credentials:** ❌ Not available — need IBM Cloud account
- **Discovery configs in DB:** 63 (lowest of active CSPs)
- **Check rules in DB:** 1,504
- **Scanner current state:** Partial stub (360 lines, uses handler registry)
- **Catalog YAMLs:** 126 services

## Pre-Requisite: Credential Setup

1. Create IBM Cloud account (ibm.com/cloud — Lite tier free)
2. Create API key: `ibmcloud iam api-key-create cspm-scanner`
3. Note: API Key, Resource Group, Account ID
4. For K8s clusters (IKS): get cluster kubeconfig
5. Store in K8s secret: `ibm-creds` with: `api_key`, `account_id`, `resource_group`

## IBM Architecture Notes

IBM Cloud uses a **different authentication model** — IAM API keys grant access to
all services (no per-service credentials). Resources are organised by:
- **Account** → **Resource Group** (≈ AWS resource group, not account)
- **Region** (standard regions: us-south, us-east, eu-de, eu-gb, jp-tok, au-syd)

## Milestone 1: IBM Scanner Foundation

**Estimated effort:** 4-5 days

### User Stories

**US-IBM-01: IBM Client Factory**
- IBM uses REST APIs authenticated with IAM bearer tokens (obtained from API key)
- **Tasks:**
  - T1: Implement token refresh: `POST https://iam.cloud.ibm.com/identity/token`
    with API key → get bearer token (expires in 1 hour)
  - T2: Map `rule_discoveries.service` to IBM SDK clients:
    - `vpc` → `ibm_vpc.VpcV1`
    - `iam` → `ibm_platform_services.IamIdentityV1`
    - `resource_controller` → `ibm_platform_services.ResourceControllerV2`
    - `object_storage` → COS SDK (`ibm_boto3`)
    - `functions` → `ibm_functions_client`
    - `kubernetes` → IKS REST API
    - `databases` → `ibm_cloud_databases.CloudDatabasesV5`
  - T3: Implement token caching (reuse within 50-min window)
  - T4: 10s timeout on all requests

**US-IBM-02: IBM Resource Enumeration**
- IBM's primary resource list is via **Resource Controller** (lists all resources across types)
- **Tasks:**
  - T1: `ResourceControllerV2.list_resource_instances()` — enumerate all resources
  - T2: For each resource type, fetch service-specific details
  - T3: Handle IBM's CRN (Cloud Resource Name) format as resource identifier

## Milestone 2: Noise Removal from 63 Configs

IBM discovery configs are fewer, but some are noise:
- **Remove:** Activity tracker events, monitoring dashboards, billing reports
- **Keep:** VPC resources, IAM policies, Cloud Functions, IKS, DB instances, COS buckets

## IBM Technical Notes

- **CRN format:** `crn:v1:bluemix:public:{service}:{region}:a/{account}:{instance}/{resource}`
- **IBM SDK Python:** `ibm-platform-services`, `ibm-vpc`, `ibm-cloud-sdk-core`
- **Smaller surface than AWS** — 63 configs is manageable in 1 sprint