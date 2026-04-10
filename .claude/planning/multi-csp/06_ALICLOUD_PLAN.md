# AliCloud (Alibaba Cloud) — Detailed Project Plan

## Context

- **Credentials:** Not available — need Alibaba Cloud account
- **Discovery configs in DB:** 136
- **Check rules in DB:** 1,306
- **Scanner current state:** No provider directory — needs to be created from scratch
- **Catalog YAMLs:** 272 services

## Pre-Requisite: Credential Setup

1. Create Alibaba Cloud account (alibabacloud.com — free tier)
2. Create RAM user + access key for CSPM scanning role
3. Note: AccessKeyId, AccessKeySecret, AccountID
4. Primary regions: cn-hangzhou, cn-beijing, cn-shanghai, ap-southeast-1 (Singapore)
5. Store in K8s secret: `alicloud-creds`

## Milestone 0: Provider Directory Bootstrap (NEW — no existing code)

Estimated effort: 1 day

Tasks:
- T1: Create directory structure under `engines/discoveries/providers/alicloud/`
- T2: Implement `AliCloudDiscoveryScanner` class using OCI scanner as template
- T3: Register `alicloud` in `run_scan.py` PROVIDER_SCANNERS dict
- T4: Add alicloud to `discovery_engine.py` DEFAULT_REGIONS and PRIMARY_REGIONS

## Milestone 1: AliCloud Scanner Foundation

Estimated effort: 5-6 days

### User Stories

**US-ALI-01: AliCloud Client Factory**
- As the discovery engine, I need to instantiate AliCloud SDK clients for any service
  using AccessKey credentials so the scanner reads from DB catalog.
- Tasks:
  - T1: Map rule_discoveries.service names to AliCloud SDK clients:
    ecs, vpc, ram, oss, rds, slb, sts, kms, actiontrail
  - T2: Implement AliCloudClientFactory.get_client(service, region, access_key, secret)
  - T3: Each client requires explicit region — AliCloud is strictly regional
  - T4: 10s timeout on all SDK requests
- SME: Python engineer with alibabacloud-* SDK experience

**US-ALI-02: AliCloud Pagination**
- AliCloud uses PageNumber + TotalCount + PageSize (not token-based like AWS)
- Tasks:
  - T1: Implement alicloud_paginate(client_method, page_size=100, **kwargs)
  - T2: Calculate total pages from TotalCount/PageSize, fetch all
  - T3: Respect service-specific max PageSize (usually 50-100)

## Milestone 2: Noise Removal

Remove from 136 configs:
- ActionTrail log entries
- Cloud Monitor metrics
- Billing and cost APIs
- Resource tagging APIs (metadata only)

Keep:
- ECS instances (security groups, public IP, disk encryption)
- VPC (security groups, ACLs, routes)
- RAM users, policies, roles, groups
- OSS buckets (ACL, encryption, versioning)
- RDS instances (public access, SSL, encryption)
- SLB (HTTPS configuration)
- KMS keys
- WAF instances

## AliCloud Technical Notes

- Resource ID format: acs:ecs:{region}:{account_id}:instance/{instance_id}
- SDK: alibabacloud-* packages (modern) or aliyunsdkcore (legacy)
- Regions: Primarily China (cn-*) + Singapore (ap-southeast-1) + other APAC
- China vs International: Some APIs differ between China and international regions
- PageSize max: typically 50-100 (not 1000 like AWS)