# ADR-IEDS-001 — Internet & External Exposure Detection System (IEDS)

**Status:** Proposed  
**Date:** 2026-05-28  
**Authors:** Platform Architecture  
**Supersedes:** Hardcoded exposure checks in attack-path `run_scan.py`

---

## 1. Context and Problem

The attack-path engine currently detects internet-exposed resources using hardcoded
resource-type strings and single-field JSONB checks inside `_mark_internet_exposed_from_discoveries()`.
This approach has produced recurring failures:

- Hardcoded type list (`apigateway.restapi`, `apigateway.v2api`) doesn't match actual
  resource types in `asset_inventory` (`apigatewayv2.item_stage`, `resource`)
- Only 4 EC2 instances marked internet-exposed despite 3 CloudFront distributions and
  multiple API GW REST APIs existing in the tenant's inventory
- No detection of VPN, Transit Gateway, Direct Connect, or external IAM origins
- AWS-only logic — Azure, GCP, OCI, AliCloud, IBM, K8s have no coverage
- Every new resource type requires a code change and redeploy
- No validation that discovery YAMLs actually emit the fields being checked
- Missing rules for new services are silently ignored — no audit mechanism

---

## 2. Decision

**The network engine owns all internet and external network exposure detection.**

- A YAML-based rule system (`network_exposure_rules`) defines exposure conditions for
  every resource type across all CSPs, using the same format as `rule_checks`
- Rules are stored in `threat_engine_network` DB and loaded at network engine scan time
- Network engine Phase L0 (new) evaluates rules, writes `is_internet_exposed` + `origin_type`
  to `resource_security_posture` in the DI DB, and writes `security_findings` rows
- Attack-path engine reads posture only — zero hardcoding of resource types
- A validator script (`validate_exposure_fields.py`) runs in CI and blocks merges when
  a rule references a field not emitted by the corresponding discovery YAML

---

## 3. Three-Tier Model

```
TIER 1 — Always public (catalog flag only, no YAML rule needed)
  Detection:  di_resource_catalog.network_exposure_tier = 1
  Method:     SQL JOIN, no field evaluation
  Examples:   CloudFront distribution, API GW (non-private), App Runner,
              GCP Cloud Run, Azure Front Door, OCI Public Load Balancer

TIER 2 — Single field determines exposure (YAML rule, field check only)
  Detection:  network_exposure_rules WHERE tier = 2
  Method:     Evaluate one emitted_fields condition per rule
  Examples:   ALB Scheme=internet-facing, RDS PubliclyAccessible=true,
              Lambda FunctionUrl, IAM role with external trust,
              Azure VM with publicIPAddress, GCP Compute with natIP

TIER 3 — Multi-condition chain (YAML rule, field + graph traversal)
  Detection:  network_exposure_rules WHERE tier = 3
  Method:     Evaluate ordered steps: field checks + asset_relationships traversal
  Examples:   EC2 public IP + IGW attached + route 0/0→IGW + NACL open + SG open
              AliCloud ECS + SLB + Security Group + ACL chain
```

---

## 4. Attack Origin Types

Every exposure rule declares an `origin_type`. BFS in attack-path engine starts from
nodes matching any of these.

```
internet           Public internet, 0.0.0.0/0 reachable
vpn                AWS Site-to-Site VPN, Client VPN, Azure VPN Gateway, GCP Cloud VPN
connected_network  Transit Gateway, VPC Peering, Azure VNet Peering, GCP VPC Peering
direct_connect     AWS Direct Connect, Azure ExpressRoute, GCP Dedicated Interconnect
external_iam       IAM role trust to external AWS account, SAML federation,
                   third-party vendor cross-account roles (DataDog, Splunk etc.)
supply_chain       Lambda layers from external accounts, public container images,
                   GitHub webhook triggers on CodePipeline
```

---

## 5. Data Model

### 5.1 `di_resource_catalog` additions (migration IEDS-M01)

```sql
ALTER TABLE di_resource_catalog
  ADD COLUMN IF NOT EXISTS network_exposure_tier   smallint,   -- 1 = always public
  ADD COLUMN IF NOT EXISTS origin_types            jsonb;      -- ['internet','vpn']
```

### 5.2 `network_exposure_rules` in `threat_engine_network` (migration IEDS-M02)

```sql
CREATE TABLE network_exposure_rules (
    rule_id                       text        PRIMARY KEY,
    provider                      text        NOT NULL,         -- aws/azure/gcp/oci/alicloud/ibm/k8s
    service                       text        NOT NULL,
    resource_type                 text        NOT NULL,         -- matches asset_inventory.resource_type
    tier                          smallint    NOT NULL,         -- 2 or 3 (tier1 = catalog only)
    origin_type                   text        NOT NULL,         -- see section 4
    severity                      text        NOT NULL DEFAULT 'high',
    title                         text        NOT NULL,
    description                   text,
    required_emitted_fields       jsonb,                        -- validator uses this
    required_relationship_fields  jsonb,                        -- validator uses this for tier3
    conditions                    jsonb       NOT NULL,         -- evaluated at scan time
    logic                         text        NOT NULL DEFAULT 'ALL',  -- ALL / ANY
    remediation                   text,
    references                    jsonb,
    is_active                     boolean     NOT NULL DEFAULT true,
    created_at                    timestamptz DEFAULT NOW(),
    updated_at                    timestamptz DEFAULT NOW()
);

CREATE INDEX idx_ner_provider_type  ON network_exposure_rules(provider, resource_type) WHERE is_active;
CREATE INDEX idx_ner_tier           ON network_exposure_rules(tier) WHERE is_active;
CREATE INDEX idx_ner_origin         ON network_exposure_rules(origin_type) WHERE is_active;
```

### 5.3 `network_exposure_findings` in `threat_engine_network` (migration IEDS-M03)

```sql
CREATE TABLE network_exposure_findings (
    finding_id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_run_id         uuid        NOT NULL,
    tenant_id           text        NOT NULL,
    account_id          text,
    provider            text        NOT NULL,
    region              text,
    resource_uid        text        NOT NULL,
    resource_type       text        NOT NULL,
    rule_id             text        NOT NULL REFERENCES network_exposure_rules(rule_id),
    tier                smallint    NOT NULL,
    origin_type         text        NOT NULL,
    severity            text        NOT NULL,
    status              text        NOT NULL DEFAULT 'open',
    failed_step         text,                  -- tier3: which step first failed (for closed findings)
    passed_steps        jsonb,                 -- tier3: audit trail of each step result
    exposure_detail     jsonb,                 -- matched field values, path taken
    first_seen_at       timestamptz DEFAULT NOW(),
    last_seen_at        timestamptz DEFAULT NOW(),
    UNIQUE (rule_id, resource_uid, tenant_id)
);

CREATE INDEX idx_nef_tenant_scan    ON network_exposure_findings(tenant_id, scan_run_id);
CREATE INDEX idx_nef_resource       ON network_exposure_findings(resource_uid, tenant_id);
CREATE INDEX idx_nef_origin         ON network_exposure_findings(origin_type, tenant_id);
```

---

## 6. YAML Rule Format

### 6.1 File layout

```
catalog/rule/network_exposure/
  aws/
    aws_tier1_catalog.yaml          (catalog UPDATE script, not a rule file)
    aws_tier2_internet.yaml
    aws_tier2_external_iam.yaml
    aws_tier2_connected_network.yaml
    aws_tier3_internet.yaml
  azure/
    azure_tier1_catalog.yaml
    azure_tier2_internet.yaml
    azure_tier3_internet.yaml
  gcp/
    gcp_tier1_catalog.yaml
    gcp_tier2_internet.yaml
    gcp_tier3_internet.yaml
  oci/
    oci_tier2_internet.yaml
    oci_tier3_internet.yaml
  alicloud/
    alicloud_tier2_internet.yaml
  ibm/
    ibm_tier2_internet.yaml
  k8s/
    k8s_tier2_internet.yaml
```

### 6.2 Tier 2 rule format

```yaml
- rule_id: aws-net-exp-t2-001
  title: ALB/NLB Internet-Facing
  provider: aws
  service: elbv2
  resource_type: elbv2_balancer      # must match asset_inventory.resource_type exactly
  tier: 2
  origin_type: internet
  severity: high
  description: >
    ELBv2 load balancer with Scheme=internet-facing is directly reachable
    from the public internet. All backends become potentially reachable.
  required_emitted_fields:           # VALIDATOR checks these exist in discovery YAML emit block
    - Scheme
    - Type
    - DNSName
  conditions:
    - field: Scheme
      check: equals
      value: internet-facing
  logic: ALL
  remediation: Change Scheme to internal unless internet access is required.
  references:
    - https://docs.aws.amazon.com/elasticloadbalancing/latest/userguide/load-balancer-update-scheme.html
```

### 6.3 Tier 3 rule format

```yaml
- rule_id: aws-net-exp-t3-001
  title: EC2 Instance Effectively Exposed to Internet
  provider: aws
  service: ec2
  resource_type: ec2_instance        # or ec2.instance — both checked via alias
  tier: 3
  origin_type: internet
  severity: critical
  description: >
    EC2 instance is effectively reachable from the public internet when ALL
    five network controls are open: public IP, IGW, route table, NACL, SG.
    Evaluates each layer independently — partial exposure is NOT flagged.
  required_emitted_fields:
    - PublicIpAddress
    - VpcId
    - SubnetId
    - SecurityGroups
  required_relationship_fields:
    - resource_type: ec2_security_group
      fields: [IpPermissions]
    - resource_type: ec2_subnet
      fields: [MapPublicIpOnLaunch, SubnetId]
    - resource_type: ec2_route_table
      fields: [Routes]
    - resource_type: ec2_internet_gateway
      fields: [Attachments]
  conditions:
    - step: 1
      label: has_public_ip
      type: field
      field: PublicIpAddress
      check: not_null
    - step: 2
      label: vpc_has_igw
      type: graph_edge_exists
      traverse:
        - relation: in_vpc
        - relation: has_igw
    - step: 3
      label: subnet_routes_to_igw
      type: graph_field_check
      traverse:
        - relation: in_subnet
        - relation: routes_via
      target_field: Routes
      check: any_item_matches
      match:
        DestinationCidrBlock: "0.0.0.0/0"
        GatewayId__startswith: "igw-"
    - step: 4
      label: nacl_allows_inbound
      type: graph_field_check
      traverse:
        - relation: in_subnet
        - relation: associated_with  # subnet → NACL
      target_field: Entries
      check: any_item_matches
      match:
        Egress: false
        RuleAction: allow
        CidrBlock: "0.0.0.0/0"
    - step: 5
      label: sg_allows_public_inbound
      type: graph_field_check
      traverse:
        - relation: has_sg
      target_field: IpPermissions
      check: any_item_matches
      match:
        IpRanges__contains: "0.0.0.0/0"
  logic: ALL
  remediation: >
    Remove public IP, or restrict SG to known CIDRs, or remove 0.0.0.0/0 route,
    or add NACL deny rule for inbound from internet.
```

---

## 7. Cross-CSP Coverage Matrix — Tier 2 Internet Origin

| CSP | Resource | resource_type (asset_inventory) | Check Field | Rule ID |
|-----|----------|----------------------------------|-------------|---------|
| **AWS** | EC2 Instance | ec2_instance / ec2.instance | PublicIpAddress | aws-net-exp-t2-001 |
| **AWS** | ALB / NLB | elbv2_balancer | Scheme = internet-facing | aws-net-exp-t2-002 |
| **AWS** | Classic ELB | elb_load_balancer | Scheme = internet-facing | aws-net-exp-t2-003 |
| **AWS** | RDS Instance | rds_instance | PubliclyAccessible = true | aws-net-exp-t2-004 |
| **AWS** | Lambda | lambda_function | FunctionUrl not null | aws-net-exp-t2-005 |
| **AWS** | ElasticSearch | es_domain | Endpoint not null | aws-net-exp-t2-006 |
| **AWS** | OpenSearch | opensearch_domain | Endpoint not null | aws-net-exp-t2-007 |
| **AWS** | ECS Task | ecs_task | networkConfiguration.AssignPublicIp = ENABLED | aws-net-exp-t2-008 |
| **AWS** | Redshift | redshift_cluster | PubliclyAccessible = true | aws-net-exp-t2-009 |
| **AWS** | SageMaker Endpoint | sagemaker_endpoint | EndpointConfigName + public | aws-net-exp-t2-010 |
| **AWS** | MSK Cluster | msk_cluster | BrokerNodeGroupInfo.ConnectivityInfo public | aws-net-exp-t2-011 |
| **AWS** | EMR Cluster | emr_cluster | Instances.MasterPublicDnsName not null | aws-net-exp-t2-012 |
| **AWS** | EKS Cluster | eks_cluster | ResourcesVpcConfig.EndpointPublicAccess = true | aws-net-exp-t2-013 |
| **AWS** | Global Accelerator | globalaccelerator_accelerator | Status = DEPLOYED | aws-net-exp-t2-014 |
| **Azure** | VM | azure_virtual_machine | properties.networkProfile publicIPAddress not null | az-net-exp-t2-001 |
| **Azure** | App Service | azure_app_service | properties.publicNetworkAccess = Enabled | az-net-exp-t2-002 |
| **Azure** | Function App | azure_function_app | properties.publicNetworkAccess = Enabled | az-net-exp-t2-003 |
| **Azure** | Azure SQL | azure_sql_server | publicNetworkAccess = Enabled | az-net-exp-t2-004 |
| **Azure** | Cosmos DB | azure_cosmos_db | publicNetworkAccess = Enabled | az-net-exp-t2-005 |
| **Azure** | AKS | azure_aks_cluster | apiServerAccessProfile.enablePrivateCluster = false | az-net-exp-t2-006 |
| **Azure** | Storage Account | azure_storage_account | allowBlobPublicAccess = true | az-net-exp-t2-007 |
| **Azure** | Container Instance | azure_container_instance | ipAddress.type = Public | az-net-exp-t2-008 |
| **Azure** | API Management | azure_api_management | sku != Isolated AND publicNetworkAccess = Enabled | az-net-exp-t2-009 |
| **GCP** | Compute Instance | gcp_compute_instance | networkInterfaces[].accessConfigs[].natIP not null | gcp-net-exp-t2-001 |
| **GCP** | Cloud SQL | gcp_cloud_sql | settings.ipConfiguration.ipv4Enabled = true | gcp-net-exp-t2-002 |
| **GCP** | GKE Cluster | gcp_gke_cluster | privateClusterConfig.enablePrivateEndpoint = false | gcp-net-exp-t2-003 |
| **GCP** | Cloud Storage | gcp_storage_bucket | iamConfiguration.publicAccessPrevention = inherited | gcp-net-exp-t2-004 |
| **GCP** | BigQuery Dataset | gcp_bigquery_dataset | access has allUsers or allAuthenticatedUsers | gcp-net-exp-t2-005 |
| **GCP** | Cloud Functions | gcp_cloud_function | httpsTrigger.securityLevel = SECURE_OPTIONAL | gcp-net-exp-t2-006 |
| **OCI** | Compute Instance | oci_compute_instance | publicIp not null | oci-net-exp-t2-001 |
| **OCI** | Object Storage | oci_object_storage | publicAccessType != NoPublicAccess | oci-net-exp-t2-002 |
| **OCI** | Autonomous DB | oci_autonomous_database | isAccessControlEnabled = false | oci-net-exp-t2-003 |
| **OCI** | OKE Cluster | oci_oke_cluster | endpointConfig.isPublicIpEnabled = true | oci-net-exp-t2-004 |
| **AliCloud** | ECS Instance | alicloud_ecs_instance | PublicIpAddress not null | ali-net-exp-t2-001 |
| **AliCloud** | SLB | alicloud_slb | AddressType = internet | ali-net-exp-t2-002 |
| **AliCloud** | OSS Bucket | alicloud_oss_bucket | acl != private | ali-net-exp-t2-003 |
| **AliCloud** | RDS Instance | alicloud_rds_instance | ConnectionString public endpoint | ali-net-exp-t2-004 |
| **IBM** | VSI | ibm_vsi | primaryNetworkInterface.primaryIpv4Address public | ibm-net-exp-t2-001 |
| **IBM** | COS Bucket | ibm_cos_bucket | publicAccessEnabled = true | ibm-net-exp-t2-002 |
| **K8s** | Service LB | k8s_service | spec.type = LoadBalancer AND status.loadBalancer.ingress not null | k8s-net-exp-t2-001 |
| **K8s** | Service NodePort | k8s_service | spec.type = NodePort AND node has external IP | k8s-net-exp-t2-002 |
| **K8s** | Ingress | k8s_ingress | status.loadBalancer.ingress not null | k8s-net-exp-t2-003 |
| **K8s** | Pod hostNetwork | k8s_pod | spec.hostNetwork = true AND node has public IP | k8s-net-exp-t2-004 |

---

## 8. Cross-CSP Coverage Matrix — External IAM Origin

| CSP | Resource | Check | Rule ID |
|-----|----------|-------|---------|
| **AWS** | IAM Role | AssumeRolePolicyDocument has Principal from different account | aws-net-exp-iam-001 |
| **AWS** | IAM Role | AssumeRolePolicyDocument has Principal: * | aws-net-exp-iam-002 |
| **AWS** | IAM Role | Trust policy has external federated IdP (SAML/OIDC) | aws-net-exp-iam-003 |
| **AWS** | Cognito Identity Pool | allowUnauthenticatedIdentities = true | aws-net-exp-iam-004 |
| **Azure** | Managed Identity | federated credentials with external subject | az-net-exp-iam-001 |
| **GCP** | Service Account | roles bound to allUsers or external domain | gcp-net-exp-iam-001 |
| **OCI** | Dynamic Group | matching rules include external tenancy | oci-net-exp-iam-001 |

---

## 9. Tier 1 Catalog Entries — All CSPs

Resources that are ALWAYS internet-facing by definition (catalog flag only, no YAML rule).

```
AWS:
  cloudfront     distribution          → CDN edge, always public
  apigateway     rest_api              → unless endpointType=PRIVATE
  apigateway     http_api              → always public
  apigateway     websocket_api         → always public
  apprunner      service               → always public
  amplify        app                   → always public
  lightsail      instance              → always public (static IP assigned)
  route53        hosted_zone           → DNS, always public
  globalaccelerator accelerator        → always public

Azure:
  azure_front_door     profile         → always public
  azure_cdn            profile         → always public
  azure_traffic_manager profile        → always public DNS

GCP:
  gcp_cloud_run        service         → ingress=all means always public
  gcp_app_engine       service         → always public
  gcp_cloud_endpoints  service         → always public

OCI:
  oci_api_gateway      gateway         → always public unless private
  oci_load_balancer    public_lb       → isPrivate=false always public

K8s:
  k8s_ingress          ingress         → always public (that's its purpose)
```

---

## 10. Required Emitted Fields Audit — Known Gaps

These fields are referenced by Tier 2/3 rules but NOT currently in discovery YAML `emit.item` blocks.
Must be fixed before the corresponding rule can be activated.

| Provider | Service | Resource Type | Missing Field | Discovery YAML to Fix |
|----------|---------|---------------|---------------|----------------------|
| aws | elbv2 | balancer | `Scheme`, `Type`, `DNSName` | aws.elbv2.describe_load_balancers |
| aws | ec2 | instance | `PublicIpAddress` | aws.ec2.describe_instances (verify emit) |
| aws | ec2 | security_group | `IpPermissions`, `IpPermissionsEgress` | aws.ec2.describe_security_groups |
| aws | ec2 | subnet | `MapPublicIpOnLaunch`, `SubnetId` | aws.ec2.describe_subnets |
| aws | ec2 | route_table | `Routes`, `Associations` | aws.ec2.describe_route_tables |
| aws | ec2 | internet_gateway | `Attachments` | aws.ec2.describe_internet_gateways |
| aws | ec2 | network_acl | `Entries`, `Associations` | aws.ec2.describe_network_acls |
| aws | rds | instance | `PubliclyAccessible`, `Endpoint` | aws.rds.describe_db_instances |
| aws | lambda | function | `FunctionUrl`, `AuthType` | aws.lambda.list_functions + get_function_url_config |
| aws | iam | role | `AssumeRolePolicyDocument` | aws.iam.list_roles + get_role |
| azure | virtual_machines | instance | `publicIPAddress`, `networkInterfaces` | azure.compute.list_virtual_machines |
| gcp | compute | instance | `networkInterfaces[].accessConfigs[].natIP` | gcp.compute.list_instances |
| oci | compute | instance | `publicIp` | oci.compute.list_instances |
| alicloud | ecs | instance | `PublicIpAddress` | alicloud.ecs.describe_instances |
| k8s | core | service | `status.loadBalancer.ingress` | k8s.core.list_services |

*This list is auto-generated by `validate_exposure_fields.py`. Must be re-run after every discovery YAML change.*

---

## 11. Project Plan

### Epic: IEDS — Internet & External Exposure Detection System

**Target:** 4 sprints, all CSPs, full Tier 1 + Tier 2 + Tier 3 (AWS) coverage.

---

### Sprint IEDS-0 — Foundation (1 week)

| Story | Title | Owner | AC |
|-------|-------|-------|----|
| IEDS-00 | This ADR + architecture document | Arch | Doc merged to main |
| IEDS-M01 | Migration: `di_resource_catalog` add `network_exposure_tier` + `origin_types` | Dev | Migration applied, no data loss |
| IEDS-M02 | Migration: `network_exposure_rules` table in `threat_engine_network` | Dev | Table created, indexes in place |
| IEDS-M03 | Migration: `network_exposure_findings` table in `threat_engine_network` | Dev | Table created, UNIQUE constraint verified |
| IEDS-V01 | `validate_exposure_fields.py` script | Dev | Script runs, reports gaps, blocks CI if FAIL |
| IEDS-L01 | YAML loader: reads `catalog/rule/network_exposure/**/*.yaml` → upserts `network_exposure_rules` | Dev | All CSP rule files load without error |

**Quality gates IEDS-0:**
- [ ] All migrations applied cleanly to prod RDS (no data dropped)
- [ ] `validate_exposure_fields.py` exits 0 on empty rules dir
- [ ] YAML loader handles schema validation errors with clear message
- [ ] Loader is idempotent (run twice = same result)

---

### Sprint IEDS-1 — Tier 1 + AWS Tier 2 (1 week)

| Story | Title | Owner | AC |
|-------|-------|-------|----|
| IEDS-T1-01 | Populate `network_exposure_tier=1` for all CSPs in catalog | Dev | All Tier 1 entries from section 9 set |
| IEDS-T1-02 | Network engine Phase L0: Tier 1 detection via catalog JOIN | Dev | CloudFront, API GW, AppRunner marked exposed |
| IEDS-T2-AWS-01 | AWS Tier 2 YAML rules (all 14 from section 7) | Dev | 14 rules loaded, validator passes |
| IEDS-T2-AWS-02 | Fix discovery YAMLs for AWS missing fields (section 10) | Dev | Validator exits 0 for all AWS Tier 2 rules |
| IEDS-T2-AWS-03 | Network engine Phase L0: Tier 2 evaluation engine | Dev | ALB, RDS, Lambda correctly marked in test scan |
| IEDS-P01 | Posture write: `is_internet_exposed`, `origin_type`, `exposure_tier` | Dev | `resource_security_posture` updated for all exposed resources |
| IEDS-F01 | Findings write: `network_exposure_findings` + `security_findings` (unified) | Dev | Findings row per exposed resource, UNIQUE constraint holds |

**Quality gates IEDS-1:**
- [ ] For test-tenant-002: CloudFront distributions marked `is_internet_exposed=true`
- [ ] For test-tenant-002: API GW REST APIs marked `is_internet_exposed=true`
- [ ] ALB with `Scheme=internet-facing` → marked; ALB with `Scheme=internal` → NOT marked
- [ ] RDS with `PubliclyAccessible=false` → NOT marked
- [ ] Validator passes for all 14 AWS Tier 2 rules (no missing fields)
- [ ] `security_findings` rows created with `source_engine='network'`
- [ ] `resource_security_posture` upsert does NOT overwrite other engine columns
- [ ] Attack path entry point count increases from 4 (verify with test scan)

---

### Sprint IEDS-2 — Azure + GCP + OCI + AliCloud + IBM + K8s Tier 2 (1 week)

| Story | Title | Owner | AC |
|-------|-------|-------|----|
| IEDS-T2-AZ-01 | Azure Tier 1 catalog + Tier 2 YAML rules (9 rules from section 7) | Dev | Rules loaded, validator passes |
| IEDS-T2-AZ-02 | Fix Azure discovery YAMLs for missing fields | Dev | Validator exits 0 for Azure Tier 2 |
| IEDS-T2-GCP-01 | GCP Tier 1 catalog + Tier 2 YAML rules (6 rules) | Dev | Rules loaded, validator passes |
| IEDS-T2-GCP-02 | Fix GCP discovery YAMLs for missing fields | Dev | Validator exits 0 for GCP Tier 2 |
| IEDS-T2-OCI-01 | OCI Tier 1 catalog + Tier 2 YAML rules (4 rules) | Dev | Rules loaded |
| IEDS-T2-ALI-01 | AliCloud Tier 2 YAML rules (4 rules) | Dev | Rules loaded |
| IEDS-T2-IBM-01 | IBM Tier 2 YAML rules (2 rules) | Dev | Rules loaded |
| IEDS-T2-K8S-01 | K8s Tier 2 YAML rules (4 rules) | Dev | Rules loaded |
| IEDS-T2-IAM-01 | AWS + Azure + GCP external IAM YAML rules (section 8) | Dev | External IAM roles detected in test account |

**Quality gates IEDS-2:**
- [ ] Azure VM with public IP → marked exposed for azure tenant
- [ ] GCP Compute with natIP → marked exposed for GCP tenant
- [ ] K8s Service type=LoadBalancer with external IP → marked exposed
- [ ] `validate_exposure_fields.py` passes for all CSPs (0 missing fields)
- [ ] AWS IAM role with `Principal: *` trust → marked `origin_type=external_iam`
- [ ] No false positives: internal Azure VMs, private GKE clusters NOT marked

---

### Sprint IEDS-3 — AWS Tier 3 + Attack Path Integration (1 week)

| Story | Title | Owner | AC |
|-------|-------|-------|----|
| IEDS-T3-AWS-01 | AWS Tier 3 YAML rules: EC2 full chain (5-step, rule aws-net-exp-t3-001) | Dev | Rule loaded, validator passes for all 5 steps |
| IEDS-T3-AWS-02 | Fix discovery YAMLs for Tier 3 relationship fields (SG, subnet, RT, IGW, NACL) | Dev | All required_relationship_fields emitted |
| IEDS-T3-AWS-03 | Network engine Tier 3 graph traversal evaluator | Dev | EC2 only marked when ALL 5 steps pass |
| IEDS-T3-AWS-04 | AWS Tier 3: ECS Task in public subnet chain | Dev | Rule + discovery fix + evaluator |
| IEDS-AP-01 | Attack-path: remove hardcoded `_mark_internet_exposed_from_discoveries` logic | Dev | Function reads posture only, zero resource_type strings |
| IEDS-AP-02 | Attack-path BFS: start from all `origin_type` values, not just internet | Dev | `origin_type=external_iam` nodes become BFS entry points |
| IEDS-AP-03 | Attack paths tagged by `origin_type` in `attack_paths` table | Dev | Path records show `entry_origin_type` column |
| IEDS-EDGE-01 | Write INTERNET_ACCESSIBLE / EXTERNAL_IAM_ACCESSIBLE edges to `asset_relationships` | Dev | Edges written, BFS graph includes them |

**Quality gates IEDS-3:**
- [ ] EC2 with public IP + open SG + open NACL + route to IGW → marked (5-step all pass)
- [ ] EC2 with public IP but SG restricted → NOT marked (step 5 fails, logged)
- [ ] EC2 with public IP, open SG but no IGW → NOT marked (step 2 fails, logged)
- [ ] `network_exposure_findings.passed_steps` shows which steps passed/failed per resource
- [ ] Attack path count for test-tenant-002 increases beyond 4 (target: 10+)
- [ ] Attack paths with `origin_type=external_iam` appear in results
- [ ] Zero hardcoded resource-type strings remain in attack-path engine

---

## 12. Audit & Quality Mechanisms

### 12.1 `validate_exposure_fields.py` — runs in CI (blocks merge)

```
For each active rule in network_exposure_rules:
  1. Extract required_emitted_fields + required_relationship_fields
  2. Lookup discovery YAML from rule_discoveries WHERE service=rule.service AND provider=rule.provider
  3. Parse emit.item keys from discoveries_data JSONB
  4. For each required field: check if it appears in emit.item OR known heuristic fields
  5. FAIL if any field missing — print: "MISSING: rule {id} needs {field} in {service} emit block"
EXIT 1 if any failures.
```

### 12.2 `audit_exposure_coverage.py` — runs weekly as K8s CronJob

```
For each DISTINCT resource_type in asset_inventory (across all tenants):
  1. Check if network_exposure_tier=1 in di_resource_catalog (covered)
  2. Check if network_exposure_rules has an active rule for this resource_type (covered)
  3. If neither: report as UNCOVERED
Report:
  - Total distinct resource_types: N
  - Covered by Tier 1: N
  - Covered by Tier 2: N
  - Covered by Tier 3: N
  - UNCOVERED: list with count of resources affected
  - Coverage %: must be > 80% (alert if below)
```

### 12.3 Regression check — runs after every network engine deploy

```
SELECT count(*) FROM resource_security_posture
WHERE tenant_id = 'test-tenant-002' AND is_internet_exposed = true;

Baseline: stored in tests/regression/baselines/internet_exposure_counts.json
  { "test-tenant-002": { "internet": 20, "external_iam": 5 } }

Alert if count drops by > 10% without explicit baseline update.
```

### 12.4 Mandatory story checklist (prevents "missing rules for new services" pattern)

Every story that adds a new resource type discovery YAML MUST include:

```
[ ] network_exposure_rules YAML: does this resource type need a Tier 1/2/3 rule?
    If yes: YAML rule file updated.
    If no: explicit comment in story file why exposure detection is not applicable.
[ ] validate_exposure_fields.py passes (CI gate)
[ ] audit_exposure_coverage.py coverage % does not drop
[ ] All CSPs with equivalent resource type covered (not AWS-only)
[ ] Required emitted fields added to discovery YAML emit.item block
[ ] Integration test: sample resource with expected exposure state verifies rule fires
```

This checklist is part of the story Definition of Done and checked by `cspm-qa` agent.

---

## 13. Engine Integration Summary

```
di_resource_catalog          (threat_engine_di)
  network_exposure_tier = 1  ─────────────────────┐
                                                   │
network_exposure_rules       (threat_engine_network)│
  tier = 2/3                 ─────────────────────┤
                                                   ▼
                                    NETWORK ENGINE Phase L0
                                    Evaluates Tier 1 (catalog JOIN)
                                    Evaluates Tier 2 (field check)
                                    Evaluates Tier 3 (graph traversal)
                                             │
                    ┌────────────────────────┼─────────────────────────┐
                    ▼                        ▼                         ▼
         network_exposure_findings   resource_security_posture   asset_relationships
         (threat_engine_network)     (threat_engine_di)          (threat_engine_di)
                                     is_internet_exposed=true    INTERNET_ACCESSIBLE
                                     origin_type                 EXTERNAL_IAM_ACCESSIBLE
                                     exposure_tier               VPN_ACCESSIBLE
                                             │
                                             ▼
                                    ATTACK PATH ENGINE
                                    BFS starts from all
                                    is_internet_exposed=true
                                    nodes across all origin_types
                                    Paths tagged by origin_type
```

---

## 14. Non-Goals

- This ADR does NOT cover egress/exfiltration paths (separate CDR concern)
- This ADR does NOT cover internal-network lateral movement detection (separate network engine L1–L7 concern)
- Tier 3 for non-AWS CSPs is deferred to IEDS Sprint 4+ (Azure/GCP VNet topology is more complex)
- Supply chain origin type (`supply_chain`) is deferred post-IEDS Sprint 3

---

*Next action: Implement IEDS-M01, IEDS-M02, IEDS-M03 migrations. Then run validator to confirm known gaps in section 10.*
