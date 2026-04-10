# AliCloud (Alibaba Cloud) — Full Stack E2E Plan

## Status
- Credentials: ✗ No account — needs provisioning (alibabacloud.com)
- rule_discoveries in DB: ✓ 136 services (aligned with catalog)
- Scanner code: ✗ No provider directory — must be created from scratch
- Check rules: ✗ 0 AliCloud rules in rule_metadata
- Inventory relationships: ✗ None
- Compliance frameworks: ✗ None
- Priority: #6 (no credentials + no scanner code)

## Pre-Requisite: Account Setup

1. Create Alibaba Cloud account: alibabacloud.com (free tier available)
2. Create RAM user: `cspm-scanner` with read-only permissions
3. Attach policy: `AliyunReadOnlyAccess` or custom CSPM read policy
4. Generate AccessKey: AccessKeyId + AccessKeySecret
5. Primary regions for scanning: cn-hangzhou, cn-beijing, cn-shanghai, ap-southeast-1 (Singapore)
6. Create K8s secret:
   ```bash
   kubectl create secret generic alicloud-creds -n threat-engine-engines \
     --from-literal=ALICLOUD_ACCESS_KEY_ID=<key_id> \
     --from-literal=ALICLOUD_ACCESS_KEY_SECRET=<key_secret> \
     --from-literal=ALICLOUD_ACCOUNT_ID=<account_id> \
     --from-literal=ALICLOUD_REGION=ap-southeast-1
   ```

---

## Phase 1 — Discovery (Track A)

### Milestone 1.1: AliCloud Provider Bootstrap (NEW)

No code exists — create from scratch.

**US-ALI-DISC-01: Provider structure**
- Create `engines/discoveries/providers/alicloud/`
- Files: `alicloud_scanner.py`, `client_factory.py`, `pagination.py`, `requirements.txt`, `Dockerfile`
- Register: `PROVIDER_SCANNERS['alicloud'] = AliCloudDiscoveryScanner`

**US-ALI-DISC-02: AliCloud Authentication**
```python
# Modern SDK (alibabacloud-* packages)
from alibabacloud_ecs20140526.client import Client as EcsClient
from alibabacloud_tea_openapi import models as open_api_models

config = open_api_models.Config(
    access_key_id=ALICLOUD_ACCESS_KEY_ID,
    access_key_secret=ALICLOUD_ACCESS_KEY_SECRET,
    region_id=ALICLOUD_REGION,
    connect_timeout=10000,  # ms
    read_timeout=10000,
)
client = EcsClient(config)
```

AliCloud uses regional clients — each region needs its own client instance.

**US-ALI-DISC-03: Client Factory**

AliCloud modern SDK packages (alibabacloud-* pattern):
```python
ALICLOUD_CLIENT_MAP = {
    'ecs':    ('alibabacloud_ecs20140526', 'Client', '2014-05-26'),
    'vpc':    ('alibabacloud_vpc20160428', 'Client', '2016-04-28'),
    'ram':    ('alibabacloud_ram20150501', 'Client', '2015-05-01'),
    'oss':    ('alibabacloud_oss20190517', 'Client', '2019-05-17'),
    'rds':    ('alibabacloud_rds20140815', 'Client', '2014-08-15'),
    'slb':    ('alibabacloud_slb20140515', 'Client', '2014-05-15'),
    'sts':    ('alibabacloud_sts20150401', 'Client', '2015-04-01'),
    'kms':    ('alibabacloud_kms20160120', 'Client', '2016-01-20'),
    'waf':    ('alibabacloud_waf-openapi20190910', 'Client', '2019-09-10'),
    'ack':    ('alibabacloud_cs20151215', 'Client', '2015-12-15'),  # K8s
    'cdn':    ('alibabacloud_cdn20180510', 'Client', '2018-05-10'),
    'polardb': ('alibabacloud_polardb20170801', 'Client', '2017-08-01'),
    'redis':  ('alibabacloud_r-kvstore20150101', 'Client', '2015-01-01'),
    'mongodb': ('alibabacloud_dds20151201', 'Client', '2015-12-01'),
    'actiontrail': ('alibabacloud_actiontrail20200706', 'Client', '2020-07-06'),
}
```

**US-ALI-DISC-04: AliCloud Pagination**

AliCloud uses PageNumber + TotalCount + PageSize (NOT token-based):
```python
def alicloud_paginate(request_class, client_method, page_size=50, **kwargs):
    results, page_number = [], 1
    while True:
        request = request_class(**kwargs, page_number=page_number, page_size=page_size)
        response = client_method(request)
        body = response.body
        items = getattr(body, 'instances', None) or getattr(body, 'items', None) or []
        if hasattr(items, 'instance'):
            items = items.instance
        results.extend(items)
        total = getattr(body, 'total_count', len(results))
        if page_number * page_size >= total:
            break
        page_number += 1
    return results
```

Note: Max PageSize varies — ECS: 100, RAM: 100, RDS: 100, VPC: 50.

**US-ALI-DISC-05: Resource Type Normalization**
- ECS instance → `ECSInstance`
- VPC → `AliVPC`
- OSS bucket → `OSSBucket`
- RDS instance → `RDSInstance`
- SLB → `LoadBalancer`
- KMS key → `KMSKey`
- RAM user → `RAMUser`
- ACK cluster → `ACKCluster`

**resource_uid format:** AliCloud ARN format:
`acs:{service}:{region}:{account_id}:{resource_type}/{resource_id}`

**Noise removal (from 09_NOISE_REMOVAL.md):**
Disable: ActionTrail log entries, Cloud Monitor metrics, Billing APIs, Resource Tags.

**China vs International regions:**
- China regions: cn-hangzhou, cn-beijing, cn-shanghai, cn-shenzhen
- International: ap-southeast-1 (Singapore), eu-central-1, us-west-1
- Some APIs differ between China and international — scanner must handle both
- Default scan: ap-southeast-1 (Singapore) as primary for non-China accounts

**Docker:** `yadavanup84/engine-discoveries-alicloud:v1.alicloud.YYYYMMDD`
**SDK:** `alibabacloud-tea-openapi`, `alibabacloud-ecs20140526`, `alibabacloud-vpc20160428`, `alibabacloud-ram20150501`, `alibabacloud-oss20190517`, `alibabacloud-rds20140815`

---

## Phase 2 — Inventory (Track B)

### Milestone 2.1: AliCloud Relationship Rules
```sql
INSERT INTO resource_security_relationship_rules
(provider, parent_type, child_type, relationship_type, link_field) VALUES
('alicloud', 'ECSInstance', 'SecurityGroup', 'PROTECTED_BY', 'instance.securityGroupIds'),
('alicloud', 'ECSInstance', 'Disk', 'CONTAINS', 'disk.instanceId'),
('alicloud', 'VPC', 'VSwitch', 'CONTAINS', 'vswitch.vpcId'),
('alicloud', 'VSwitch', 'SecurityGroup', 'PROTECTED_BY', 'sg.vpcId'),
('alicloud', 'OSSBucket', 'RAMPolicy', 'PROTECTED_BY', 'bucket.policy'),
('alicloud', 'RDSInstance', 'VPC', 'ROUTES_TO', 'rds.vpcId'),
('alicloud', 'RAMUser', 'RAMGroup', 'CONTAINS', 'groupMembership.userId'),
('alicloud', 'RAMGroup', 'RAMPolicy', 'ACCESSES', 'policy.attachedGroup');
```

### Milestone 2.2: AliCloud Asset Classification
```sql
INSERT INTO service_classification (csp, resource_type, category, subcategory, scope) VALUES
('alicloud', 'ECSInstance', 'Compute', 'Virtual Machine', 'regional'),
('alicloud', 'OSSBucket', 'Storage', 'Object Storage', 'regional'),
('alicloud', 'RDSInstance', 'Database', 'Relational DB', 'regional'),
('alicloud', 'VPC', 'Network', 'VPC', 'regional'),
('alicloud', 'LoadBalancer', 'Network', 'Load Balancer', 'regional'),
('alicloud', 'KMSKey', 'Security', 'Key Management', 'regional'),
('alicloud', 'ACKCluster', 'Container', 'Kubernetes', 'regional'),
('alicloud', 'RAMUser', 'Identity', 'RAM User', 'global');
```

---

## Phase 3 — Check Engine (Track C)

### AliCloud Check Rules (~200 rules)

**ECS (Compute):**
- No public IP on internal instances
- Disk encryption enabled
- Security group: no inbound allow-all (0.0.0.0/0)
- Security group: RDP (3389) / SSH (22) restricted
- ECS metadata service: IMDSv2 only
- Instance: not running as root user

**OSS (Object Storage):**
- Bucket ACL: not public-read or public-read-write
- Bucket: server-side encryption enabled
- Bucket: versioning enabled
- Bucket: logging enabled
- Bucket: HTTPS-only access
- Bucket: lifecycle policies set

**RAM (Identity):**
- No RAM users with AccessKeys older than 90 days
- No console users without MFA
- No RAM users with AdministratorAccess
- Custom policies: review AdministratorAccess equivalent
- RAM roles: restrict trust policies

**RDS (Database):**
- RDS: not publicly accessible
- RDS: SSL enabled
- RDS: automated backup enabled
- RDS: encrypted storage
- RDS: IP whitelist not 0.0.0.0/0

**KMS:**
- KMS key rotation enabled
- KMS keys not accessible to all
- Key material not imported (prefer AliCloud-managed)

**ActionTrail (Audit):**
- ActionTrail enabled for all regions
- Trail delivers to OSS bucket (audit log retention)
- Alert rules configured for sensitive operations

**WAF:**
- WAF attached to all public-facing ECS/SLB
- WAF in prevention mode (not detection-only)

---

## Phase 4 — Threat Engine

MITRE for AliCloud:
- T1078.004 — Cloud Accounts (AccessKey theft)
- T1530 — OSS bucket data access
- T1580 — Cloud Infrastructure Discovery (Resource Manager API)
- T1190 — Exploit Public-Facing Application

---

## Phase 5 — IAM Engine (AliCloud)

RAM (Resource Access Management):
- Users, Groups, Roles, Policies
- AccessKey management
- STS (temporary credentials)
- Role trust policies

Rules: AccessKey age, MFA, AdministratorAccess, STS session duration.
**IAM module name**: `alicloud_ram`

---

## Phase 6 — DataSec Engine (AliCloud)

`datasec_data_store_services` has AliCloud rows. ✓

Rules: OSS public bucket, RDS unencrypted, TableStore open access.

---

## Phase 7 — Compliance Engine (AliCloud)

```sql
INSERT INTO compliance_frameworks (framework_id, name, version, provider, description) VALUES
('cis_alicloud_1_0', 'CIS Alibaba Cloud Foundations Benchmark', '1.0.0', 'alicloud',
 'CIS Benchmark for Alibaba Cloud security configuration'),
('mlps_2_0', 'China MLPS 2.0 (等级保护)', '2.0', 'alicloud',
 'China Multi-Level Protection Scheme for cloud security');
```

Note: MLPS 2.0 is China's mandatory cybersecurity regulation — important for AliCloud.

---

## Phases 8-9 — API + BFF/UI

AliCloud-specific:
- `?provider=alicloud&account_id=<id>` filter
- Region names: cn-hangzhou, ap-southeast-1
- Resource type names: ECSInstance, OSSBucket, etc.
- IAM terminology: RAM User, RAM Role, AccessKey

---

## Milestone Order (after credential setup)

M0: AliCloud account + AccessKey + K8s secret
M1-M5: Provider directory bootstrap + auth + client factory + pagination + Dockerfile
M6: DB seeds (relationships + classification)
M7: AliCloud check rules + MLPS 2.0 framework in DB
M8: E2E discovery scan
M9: Full pipeline run
M10: API + BFF/UI

**Estimated effort:** 4-5 weeks (most complex — new provider dir + PageNumber pagination + China/international split)

## AliCloud Specific Risks

1. **China API differences**: Some AliCloud APIs behave differently in cn-* vs international regions
2. **PageSize limits**: max 50-100 vs AWS 1000 — more API calls needed
3. **SDK maturity**: alibabacloud-* (modern) vs aliyunsdkcore (legacy) — use modern
4. **MLPS compliance**: mandatory for China operations — different control framework
5. **Rate limiting**: AliCloud throttles at lower QPS than AWS — add 200ms delay between calls
