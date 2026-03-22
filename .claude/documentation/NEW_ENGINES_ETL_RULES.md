# New Engines — ETL & Rule/Check Framework
## Implementation Reference (ties together DATA_SOURCES + ARCHITECTURE docs)

**Date:** 2026-03-02
**Status:** Final specification — ready for feature branch implementation

---

## 1. How the Three Documents Fit Together

```
NEW_ENGINE_DATA_SOURCES.md    →  What to collect and how (Category A + B)
NEW_ENGINES_ARCHITECTURE.md   →  Block diagrams, DB schemas, file structure per engine
THIS FILE                     →  How data flows through ETL + rule evaluation logic
```

The implementation sequence per engine:
```
Step 1: Add Category A rows to rule_discoveries table (seeding SQL)
Step 2: Engine scan reads from discovery_findings using exact resource_types
Step 3: Transform + apply rule evaluator (condition-driven, no hardcoding)
Step 4: Write findings to engine-specific tables
Step 5: Update scan_orchestration.{engine}_scan_id
```

---

## 2. Rule/Check Framework (DB-Driven, Applies to ALL New Engines)

### 2.1 The Pattern (inherited from engine_check)

```
Rule stored in DB table {engine}_rules
           │
           ├── rule_id       (e.g., CONT-001, NET-003, API-002)
           ├── condition     JSONB  ← evaluated at runtime
           ├── severity      (critical/high/medium/low/info)
           ├── is_active     BOOLEAN  ← toggle without redeploy
           └── frameworks    TEXT[]   ← compliance mapping

Runtime:
  rule_loader.load_active_rules()  →  list of Rule objects
  rule_evaluator.evaluate(asset, rule)  →  PASS | FAIL | SKIP | ERROR
  if FAIL:
    write to {engine}_findings table
```

### 2.2 Rule Condition Types (4 variants, stored as JSONB)

```python
# Type 1 — Field comparison (most posture rules)
condition = {
    "field": "encryption_enabled",
    "operator": "eq",      # eq | ne | gt | lt | gte | lte | contains | in | not_in | is_null
    "value": False
}

# Type 2 — Nested field path (e.g., inside metadata JSONB)
condition = {
    "field": "inbound_rules[*].cidr",
    "operator": "contains",
    "value": "0.0.0.0/0"
}

# Type 3 — Threshold anomaly (runtime flow/API rules)
condition = {
    "metric": "outbound_bytes",
    "operator": "gt",
    "baseline_field": "baseline_bytes",
    "multiplier": 3.0       # trigger if > 3x baseline
}

# Type 4 — Set membership (CVE/package/IP blacklists)
condition = {
    "field": "cve_id",
    "operator": "in_set",
    "set_table": "cve_kev_list",    # DB table to query
    "set_column": "cve_id"
}
```

### 2.3 Standard Rule Table Schema (every new engine gets this)

```sql
-- Template: replace {engine} with container | network | supplychain | api
CREATE TABLE {engine}_rules (
    rule_id         VARCHAR(100) PRIMARY KEY,
    title           VARCHAR(255) NOT NULL,
    description     TEXT,
    category        VARCHAR(50),        -- engine-specific category
    severity        VARCHAR(20) NOT NULL
                    CHECK (severity IN ('critical','high','medium','low','info')),
    condition_type  VARCHAR(30) NOT NULL
                    CHECK (condition_type IN ('field_check','threshold','set_membership','composite')),
    condition       JSONB NOT NULL,     -- evaluated at runtime
    evidence_fields TEXT[],            -- which fields to include in evidence JSONB
    frameworks      TEXT[],            -- compliance frameworks this rule maps to
    remediation     TEXT,
    references      TEXT[],
    csp             TEXT[] DEFAULT ARRAY['all'],
    is_active       BOOLEAN DEFAULT true,
    created_at      TIMESTAMP DEFAULT NOW(),
    updated_at      TIMESTAMP DEFAULT NOW()
);

-- Standard finding result table (every engine)
CREATE TABLE {engine}_findings (
    finding_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    {engine}_scan_id UUID NOT NULL,
    tenant_id       UUID NOT NULL,
    orchestration_id UUID NOT NULL,
    resource_id     VARCHAR(255),
    resource_type   VARCHAR(100),
    resource_arn    VARCHAR(500),
    rule_id         VARCHAR(100) REFERENCES {engine}_rules(rule_id),
    result          VARCHAR(10) NOT NULL
                    CHECK (result IN ('FAIL','PASS','SKIP','ERROR')),
    severity        VARCHAR(20),
    title           TEXT,
    description     TEXT,
    evidence        JSONB,             -- {field, value, expected} from condition
    remediation     TEXT,
    account_id      VARCHAR(20),
    region          VARCHAR(50),
    csp             VARCHAR(20) DEFAULT 'aws',
    is_active       BOOLEAN DEFAULT true,  -- set false when resource is deleted
    created_at      TIMESTAMP DEFAULT NOW()
);
```

### 2.4 Rule Evaluator (shared utility — in shared/common/)

```python
# shared/common/rule_evaluator.py
from typing import Any, Dict, List

class RuleResult:
    result: str           # FAIL | PASS | SKIP | ERROR
    evidence: dict        # {field, actual_value, expected_value}
    severity: str

def evaluate_rule(asset: Dict[str, Any], rule: dict) -> RuleResult:
    """Evaluate a single rule against an asset dict."""
    ctype = rule["condition_type"]
    cond  = rule["condition"]

    if ctype == "field_check":
        actual = _get_nested(asset, cond["field"])
        passed = _compare(actual, cond["operator"], cond["value"])
        evidence = {"field": cond["field"], "actual": actual, "expected": cond["value"]}
        return RuleResult("PASS" if passed else "FAIL", evidence, rule["severity"])

    elif ctype == "threshold":
        metric   = asset.get(cond["metric"], 0)
        baseline = asset.get(cond["baseline_field"], 0)
        threshold = baseline * cond["multiplier"]
        passed = not _compare(metric, cond["operator"], threshold)
        evidence = {"metric": cond["metric"], "actual": metric,
                    "baseline": baseline, "threshold": threshold}
        return RuleResult("PASS" if passed else "FAIL", evidence, rule["severity"])

    elif ctype == "set_membership":
        # Caller must pre-load the set from DB and pass as rule["_set_values"]
        set_vals = rule.get("_set_values", [])
        actual   = asset.get(cond["field"])
        passed   = actual not in set_vals
        evidence = {"field": cond["field"], "actual": actual, "in_set": not passed}
        return RuleResult("PASS" if passed else "FAIL", evidence, rule["severity"])

    return RuleResult("ERROR", {"reason": f"unknown condition_type {ctype}"}, "info")
```

---

## 3. Per-Engine ETL — Precise Input/Output Mapping

### 3.1 engine_container

**Reads from discovery_findings (exact resource_types from Category A):**

```sql
-- Step 1: Get registries + images
SELECT df.resource_id, df.resource_arn, df.account_id, df.region,
       df.emitted_fields, df.raw_response
FROM discovery_findings df
JOIN scan_orchestration so ON so.discovery_scan_id = df.discovery_scan_id
WHERE so.orchestration_id = $1
  AND df.resource_type IN (
    'aws.ecr.repository',         -- A1: registries
    'aws.ecr.image',              -- A1: images (tags, digests, scan status)
    'aws.eks.pod',                -- A2: running pods with image refs
    'aws.eks.deployment',         -- A2: deployment specs
    'aws.ecs.task_definition'     -- A3: ECS task container defs
  );

-- Step 2: Also read K8s policy context
SELECT df.emitted_fields->>'containers' as containers_json,
       df.emitted_fields->>'security_context' as pod_security_context,
       df.emitted_fields->>'host_network' as host_network,
       df.emitted_fields->>'host_pid' as host_pid,
       df.emitted_fields->>'service_account' as service_account
FROM discovery_findings df
WHERE df.resource_type = 'aws.eks.pod'
  AND df.orchestration_id = $1;
```

**Transform pipeline:**

```
For each aws.ecr.image record:
  image_uri = emitted_fields.repository_uri + ":" + emitted_fields.image_tags[0]
  1. CHECK: image_scan_status = 'COMPLETE'? (if not, flag as unscanned)
  2. If Trivy scan not cached (check container_images.scanned_at < 24h ago):
     → run trivy_scan(image_uri, registry_auth) → CVE list + SBOM
  3. Load rules: SELECT * FROM container_rules WHERE is_active=TRUE
  4. For each CVE in trivy output:
     → evaluate CONT-CVE-* rules (threshold on CVSS score, KEV membership)
  5. Write to: container_images, container_findings, container_sbom

For each aws.eks.pod record:
  1. Parse containers[] from emitted_fields
  2. For each container: evaluate K8s policy rules (CONT-K8S-* rules)
     Rules check: privileged, runAsRoot, allowPrivEscalation, readOnlyRootFS,
                  hostNetwork, hostPID, no resource limits, service_account=default
  3. Write to: k8s_policy_findings
```

**Outputs:**

```
container_images         → 1 row per unique image:tag
container_findings       → 1 row per CVE or misconfiguration
container_sbom           → 1 row per package per image
k8s_policy_findings      → 1 row per K8s policy violation per pod/container
```

**Rule seed (initial container_rules rows):**

```sql
INSERT INTO container_rules VALUES
  -- K8s policy rules
  ('CONT-K8S-001', 'Container running as root',          'k8s_psp', 'high',
   'field_check', '{"field":"securityContext.runAsNonRoot","operator":"eq","value":false}',
   ARRAY['CIS_K8s_5.2.6','PCI-DSS']),
  ('CONT-K8S-002', 'Privileged container',               'k8s_psp', 'critical',
   'field_check', '{"field":"securityContext.privileged","operator":"eq","value":true}',
   ARRAY['CIS_K8s_5.2.1','PCI-DSS','SOC2']),
  ('CONT-K8S-003', 'Host network access enabled',        'k8s_psp', 'high',
   'field_check', '{"field":"hostNetwork","operator":"eq","value":true}',
   ARRAY['CIS_K8s_5.2.4']),
  ('CONT-K8S-004', 'Privilege escalation allowed',       'k8s_psp', 'high',
   'field_check', '{"field":"securityContext.allowPrivilegeEscalation","operator":"ne","value":false}',
   ARRAY['CIS_K8s_5.2.5']),
  ('CONT-K8S-005', 'No CPU/memory limits set',           'k8s_psp', 'medium',
   'field_check', '{"field":"resources.limits","operator":"is_null","value":null}',
   ARRAY['CIS_K8s_5.2.11']),
  ('CONT-K8S-006', 'Default service account used',       'k8s_psp', 'medium',
   'field_check', '{"field":"service_account","operator":"eq","value":"default"}',
   ARRAY['CIS_K8s_5.1.6']),
  ('CONT-K8S-007', 'Root filesystem writable',           'k8s_psp', 'medium',
   'field_check', '{"field":"securityContext.readOnlyRootFilesystem","operator":"ne","value":true}',
   ARRAY['CIS_K8s_5.2.3']),
  -- ECR posture rules
  ('CONT-ECR-001', 'ECR image scan on push disabled',    'registry', 'medium',
   'field_check', '{"field":"image_scan_on_push","operator":"eq","value":false}',
   ARRAY['PCI-DSS','CIS_AWS']),
  ('CONT-ECR-002', 'ECR image mutable tags enabled',     'registry', 'low',
   'field_check', '{"field":"image_tag_mutability","operator":"eq","value":"MUTABLE"}',
   ARRAY['CIS_AWS']),
  ('CONT-ECR-003', 'ECR repository not encrypted with CMK', 'registry', 'medium',
   'field_check', '{"field":"encryption_type","operator":"eq","value":"AES256"}',
   ARRAY['PCI-DSS','HIPAA']),
  -- CVE severity threshold rules
  ('CONT-CVE-001', 'Critical CVE in running container',  'cve_severity', 'critical',
   'field_check', '{"field":"cvss_score","operator":"gte","value":9.0}',
   ARRAY['PCI-DSS','HIPAA','SOC2']),
  ('CONT-CVE-002', 'CVE in CISA KEV catalog',            'cve_severity', 'critical',
   'set_membership', '{"field":"cve_id","operator":"in_set","set_table":"cve_kev_list","set_column":"cve_id"}',
   ARRAY['CISA_CE','PCI-DSS']),
  ('CONT-CVE-003', 'High CVE with fix available',        'cve_severity', 'high',
   'field_check', '{"field":"fixed_version","operator":"ne","value":null}',
   ARRAY['SOC2']);
```

---

### 3.2 engine_network

**Reads from discovery_findings (exact resource_types):**

```sql
-- Posture mode: read all network config from discoveries
SELECT df.resource_id, df.resource_type, df.resource_arn,
       df.emitted_fields, df.account_id, df.region
FROM discovery_findings df
JOIN scan_orchestration so ON so.discovery_scan_id = df.discovery_scan_id
WHERE so.orchestration_id = $1
  AND df.resource_type IN (
    'aws.ec2.security_group',         -- SG inbound/outbound rules
    'aws.ec2.vpc',                    -- VPC CIDR, flow log status
    'aws.ec2.subnet',                 -- public/private determination
    'aws.ec2.network_acl',            -- NACL rules
    'aws.ec2.internet_gateway',       -- IGW attachments
    'aws.ec2.nat_gateway',            -- NAT gateway
    'aws.ec2.vpc_peering_connection', -- VPC peering
    'aws.ec2.transit_gateway',        -- TGW
    'aws.ec2.flow_log',               -- A8: VPC flow log config (new)
    'aws.elbv2.listener',             -- A6: ALB listener TLS/ports
    'aws.wafv2.web_acl'               -- A7: WAF config + associations
  );
```

**Transform pipeline (Posture Mode):**

```
1. Build topology map:
   vpc_id → {subnets[], security_groups[], igw?, nat?, peerings[], flow_logs[]}

2. For each Security Group:
   → parse emitted_fields.ip_permissions (inbound rules)
   → parse emitted_fields.ip_permissions_egress (outbound rules)
   → evaluate NET-SG-* rules

3. For each VPC:
   → check flow_logs[]: if empty or all FAILED → NET-VPC-001 FAIL
   → check igw attached to private subnet → NET-VPC-002

4. For each NACL:
   → evaluate NET-NACL-* rules (permissive ALLOW rules on sensitive ports)

5. Build network_topology rows (one per network resource)
6. Write network_findings for all FAIL results
```

**Runtime Mode (VPC Flow Logs — B1 source):**

```
Separate worker: network-flow-worker (SQS consumer)

Per S3 event:
  1. s3.get_object → decompress .gz → read space-separated flow log lines
  2. Parse each line → {src_ip, dst_ip, dst_port, protocol, bytes, action, timestamp}
  3. Skip action=REJECT (or flag separately for scanning detection)
  4. Aggregate into 5-minute windows:
     GROUP BY (src_ip, dst_ip, dst_port, protocol) → {total_bytes, total_packets, flow_count}
  5. IP → resource resolution:
     SELECT resource_id FROM discovery_findings
     WHERE emitted_fields->>'private_ip_address' = $src_ip
       AND orchestration_id = (latest for tenant)
  6. Anomaly detection:
     a. Compare against network_baselines (14-day rolling avg)
     b. If total_bytes > baseline_bytes * 3.0 → network_anomaly (data exfiltration)
     c. Lookup src/dst in threat_intel IOC cache → if match → malicious_ip anomaly
     d. If >100 unique dst_ports from single src in 5min → port scan anomaly
  7. Write to: network_events, network_anomalies
```

**Rule seed (initial network_rules rows):**

```sql
INSERT INTO network_rules VALUES
  -- Security Group rules (posture)
  ('NET-SG-001', 'SSH open to internet (0.0.0.0/0 on port 22)',     'exposure', 'critical',
   'field_check', '{"field":"inbound_rules","operator":"contains_match",
                    "match":{"port":22,"cidr":"0.0.0.0/0"}}',
   ARRAY['CIS_AWS_4.1','PCI-DSS','NIST_800-53']),
  ('NET-SG-002', 'RDP open to internet (0.0.0.0/0 on port 3389)',   'exposure', 'critical',
   'field_check', '{"field":"inbound_rules","operator":"contains_match",
                    "match":{"port":3389,"cidr":"0.0.0.0/0"}}',
   ARRAY['CIS_AWS_4.2','PCI-DSS']),
  ('NET-SG-003', 'All traffic allowed inbound (0.0.0.0/0 all ports)','exposure', 'critical',
   'field_check', '{"field":"inbound_rules","operator":"contains_match",
                    "match":{"port":-1,"cidr":"0.0.0.0/0"}}',
   ARRAY['CIS_AWS','PCI-DSS','SOC2']),
  ('NET-SG-004', 'All traffic allowed outbound',                     'exposure', 'medium',
   'field_check', '{"field":"outbound_rules","operator":"contains_match",
                    "match":{"port":-1,"cidr":"0.0.0.0/0"}}',
   ARRAY['CIS_AWS']),
  -- VPC rules
  ('NET-VPC-001', 'VPC Flow Logs disabled',                          'logging', 'high',
   'field_check', '{"field":"flow_logs_enabled","operator":"eq","value":false}',
   ARRAY['CIS_AWS_2.9','PCI-DSS','HIPAA','SOC2']),
  ('NET-VPC-002', 'VPC does not have DNS resolution enabled',        'configuration', 'low',
   'field_check', '{"field":"enable_dns_support","operator":"eq","value":false}',
   ARRAY['CIS_AWS']),
  -- NACL rules
  ('NET-NACL-001', 'NACL allows unrestricted inbound on all ports',  'exposure', 'high',
   'field_check', '{"field":"inbound_rules","operator":"contains_match",
                    "match":{"rule_action":"allow","cidr":"0.0.0.0/0","port_range":"0-65535"}}',
   ARRAY['CIS_AWS','PCI-DSS']),
  -- ALB / TLS rules
  ('NET-ALB-001', 'ALB listener using HTTP (not HTTPS)',             'encryption', 'high',
   'field_check', '{"field":"protocol","operator":"eq","value":"HTTP"}',
   ARRAY['PCI-DSS','HIPAA','SOC2']),
  ('NET-ALB-002', 'ALB TLS policy allows TLS 1.0 or 1.1',           'encryption', 'medium',
   'field_check', '{"field":"ssl_policy","operator":"in","value":
                    ["ELBSecurityPolicy-2016-08","ELBSecurityPolicy-TLS-1-0-2015-04"]}',
   ARRAY['PCI-DSS','NIST_800-53']),
  -- Runtime anomaly rules
  ('NET-ANOM-001', 'Outbound data spike > 3x baseline',             'anomaly', 'high',
   'threshold', '{"metric":"total_bytes","operator":"gt",
                  "baseline_field":"baseline_bytes","multiplier":3.0}',
   ARRAY['SOC2','ISO27001']),
  ('NET-ANOM-002', 'Connection to known malicious IP (threat intel)','threat', 'critical',
   'set_membership', '{"field":"dst_ip","operator":"in_set",
                       "set_table":"threat_intel_ioc","set_column":"indicator_value"}',
   ARRAY['CISA_CE','PCI-DSS']),
  ('NET-ANOM-003', 'Port scan detected (>100 unique dst ports in 5min)','anomaly', 'high',
   'threshold', '{"metric":"unique_dst_ports","operator":"gt",
                  "baseline_field":null,"multiplier":null,"absolute_threshold":100}',
   ARRAY['ISO27001','SOC2']);
```

---

### 3.3 engine_supplychain

**Reads from discovery_findings (exact resource_types):**

```sql
-- Primary collection sources
SELECT df.resource_id, df.resource_type, df.resource_arn,
       df.emitted_fields, df.account_id, df.region
FROM discovery_findings df
JOIN scan_orchestration so ON so.discovery_scan_id = df.discovery_scan_id
WHERE so.orchestration_id = $1
  AND df.resource_type IN (
    'aws.ecr.image',                        -- A1: images (get SBOM from engine_container)
    'aws.lambda.function_code',             -- A4: Lambda ZIP code location
    'aws.codecommit.manifest_file',         -- A9: CodeCommit package files
    'aws.codeartifact.repository',          -- A10: internal package registries
    'aws.codeartifact.package',             -- A10: internal packages (dep confusion check)
    'github.repository.manifest_file'       -- B4: GitHub/GitLab manifests (via secops)
  );

-- Also cross-reference engine_container SBOM (read after container scan)
SELECT cs.package_name, cs.package_version, cs.package_type, cs.purl,
       cs.is_direct_dep, ci.registry_url, ci.repository, ci.tag
FROM container_sbom cs
JOIN container_images ci ON ci.image_id = cs.image_id
WHERE ci.orchestration_id = $1;
```

**Transform pipeline:**

```
For each manifest source (lambda_function_code, codecommit.manifest_file, github.manifest_file):

  1. Parse manifest → normalized dependency list
     manifest_parser.parse(file_content, file_type)  →  List[{name, version, ecosystem}]

  2. For each Lambda function:
     a. Read code_location URL from emitted_fields
     b. Download ZIP via S3 presigned URL (or s3.get_object if bucket/key known)
     c. Extract: requirements.txt / package.json / go.mod etc.
     d. Parse → dependency list

  3. Build sbom_manifests row (one per artifact):
     source_type = 'lambda' | 'code_repo' | 'container_image' | 'package_registry'

  4. For each package in dependency list:
     a. Load rules: SELECT * FROM supplychain_rules WHERE is_active=TRUE
     b. Evaluate SC-CVE-* rules (package in CVE DB)
     c. Evaluate SC-MAL-* rules (package in malicious package DB)
     d. Evaluate SC-LIC-* rules (copyleft license for commercial product)
     e. Evaluate SC-PROV-* rules (unpinned, unsigned, abandoned)
     f. Evaluate SC-CONF-* rules (dependency confusion — internal name on public registry)

  5. Write sbom_manifests, sbom_components, supplychain_findings
```

**Lambda ZIP download approach:**

```python
def download_lambda_package(function_arn: str, code_location: str) -> bytes:
    """Download Lambda deployment ZIP. code_location is a 1-hour pre-signed S3 URL."""
    import urllib.request
    # Direct URL download (no boto3 needed for presigned URL)
    with urllib.request.urlopen(code_location, timeout=30) as resp:
        return resp.read()

def extract_manifests_from_zip(zip_bytes: bytes) -> dict:
    """Return {filename: content} for all package manifest files found in ZIP."""
    import zipfile, io
    manifests = {}
    MANIFEST_NAMES = {
        'package.json', 'requirements.txt', 'go.mod', 'pom.xml',
        'Gemfile', 'Cargo.toml', 'composer.json', 'build.gradle',
        'pyproject.toml', 'packages.config', 'yarn.lock', 'poetry.lock'
    }
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for name in zf.namelist():
            basename = name.split('/')[-1]
            if basename in MANIFEST_NAMES:
                manifests[name] = zf.read(name).decode('utf-8', errors='replace')
    return manifests
```

**Rule seed (initial supplychain_rules rows):**

```sql
INSERT INTO supplychain_rules VALUES
  -- CVE/vulnerability rules
  ('SC-CVE-001', 'Package with critical CVE',               'vulnerability', 'critical',
   'field_check', '{"field":"vulnerability_count","operator":"gt","value":0,
                    "filter":{"severity":"critical"}}',
   ARRAY['PCI-DSS','HIPAA','SOC2']),
  ('SC-CVE-002', 'Package CVE in CISA KEV catalog',         'vulnerability', 'critical',
   'set_membership', '{"field":"cve_ids","operator":"in_set",
                       "set_table":"cve_kev_list","set_column":"cve_id"}',
   ARRAY['CISA_CE','PCI-DSS']),
  -- Malicious package rules
  ('SC-MAL-001', 'Known malicious package',                 'malicious', 'critical',
   'set_membership', '{"field":"purl","operator":"in_set",
                       "set_table":"malicious_packages","set_column":"purl"}',
   ARRAY['PCI-DSS','SOC2']),
  ('SC-MAL-002', 'Package name typosquatting pattern',      'malicious', 'high',
   'field_check', '{"field":"is_typosquat_suspect","operator":"eq","value":true}',
   ARRAY['PCI-DSS']),
  -- Provenance rules
  ('SC-PROV-001', 'Dependency pinned to inexact version (*)', 'provenance', 'medium',
   'field_check', '{"field":"is_pinned","operator":"eq","value":false}',
   ARRAY['SOC2','ISO27001']),
  ('SC-PROV-002', 'Abandoned package (>2 years no update)', 'provenance', 'medium',
   'field_check', '{"field":"days_since_update","operator":"gt","value":730}',
   ARRAY['SOC2']),
  ('SC-PROV-003', 'Package not signed',                     'provenance', 'low',
   'field_check', '{"field":"is_signed","operator":"eq","value":false}',
   ARRAY['NIST_800-53']),
  -- Dependency confusion rules
  ('SC-CONF-001', 'Internal package name exists on public registry', 'dep_confusion', 'high',
   'field_check', '{"field":"public_registry_exists","operator":"eq","value":true}',
   ARRAY['NIST_800-53','SOC2']),
  -- License rules
  ('SC-LIC-001', 'Copyleft license (GPL) in commercial product', 'license', 'high',
   'field_check', '{"field":"license_category","operator":"eq","value":"copyleft"}',
   ARRAY['ISO27001']),
  ('SC-LIC-002', 'Unknown or unrecognized license',          'license', 'medium',
   'field_check', '{"field":"license_category","operator":"eq","value":"unknown"}',
   ARRAY['ISO27001']);
```

---

### 3.4 engine_api

**Reads from discovery_findings (exact resource_types):**

```sql
-- API inventory sources
SELECT df.resource_id, df.resource_type, df.resource_arn,
       df.emitted_fields, df.account_id, df.region
FROM discovery_findings df
JOIN scan_orchestration so ON so.discovery_scan_id = df.discovery_scan_id
WHERE so.orchestration_id = $1
  AND df.resource_type IN (
    -- Existing (already in discoveries)
    'aws.apigateway.rest_api',            -- REST APIs (base info)
    'aws.apigatewayv2.api',               -- HTTP/WebSocket APIs
    'aws.elbv2.load_balancer',            -- Application Load Balancers
    'aws.appsync.graphql_api',            -- GraphQL APIs (basic)
    -- New (Category A additions)
    'aws.apigateway.stage',               -- A5: stage-level config (logging, caching, WAF)
    'aws.apigateway.authorizer',          -- A5: authorizer config (auth type, TTL)
    'aws.apigatewayv2.route',             -- A5: HTTP API routes (auth type per route)
    'aws.elbv2.listener',                 -- A6: ALB listener (port, protocol, TLS policy)
    'aws.elbv2.listener_rule',            -- A6: routing rules
    'aws.wafv2.web_acl',                  -- A7: WAF rules + associated resources
    'aws.appsync.graphql_api',            -- A11: detailed config (auth, logging, WAF)
    'aws.logs.log_group'                  -- A12: access log group existence
  );
```

**Transform pipeline:**

```
1. Build api_inventory (one per API):
   For each REST API:
     → Find all stages from discovery_findings WHERE resource_type='aws.apigateway.stage'
       AND emitted_fields->>'rest_api_id' = api_id
     → Find authorizers WHERE emitted_fields->>'rest_api_id' = api_id
     → Find WAF from wafv2.web_acl.associated_resources that includes this API ARN
     → Compute: has_waf, has_rate_limiting, auth_types, tls_minimum, logging_enabled

2. Build api_endpoints (one per route/method):
   For each stage → get resources (from API GW API if needed)
   OR for APIGWv2 → read routes from discovery_findings
   → endpoint_id, path, method, auth_required, auth_type, rate_limited

3. Evaluate OWASP API rules:
   For each endpoint:
     API-001: auth_required = false → FAIL (OWASP API2)
     API-002: auth_type = 'NONE' on sensitive paths → FAIL (OWASP API1)
     API-003: rate_limited = false AND no WAF rate rule → FAIL (OWASP API4)
     API-006: TLS < 1.2 on ALB listener → FAIL (OWASP API7)
     API-007: request_validator = false → FAIL (OWASP API8)
     API-008: logging_enabled = false on stage → FAIL (OWASP API10)
     API-009: stage_name matches /v1|v2/ AND older version still has routes → FAIL (OWASP API9)

4. B5 (access log runtime analysis — on-demand during scan):
   For each stage with access_log_arn set:
     → query CloudWatch Logs (last 24h window)
     → aggregate: error_rate, top_4xx_paths, top_5xx_paths, p99_latency
     → write to api_access_summary table
     → evaluate API-RUNTIME-* rules (error spike, unusual methods)

5. Write api_inventory, api_endpoints, api_findings, api_access_summary
```

**Rule seed (initial api_rules rows):**

```sql
INSERT INTO api_rules VALUES
  -- OWASP API Top 10 — one rule per category minimum
  ('API-001', 'API endpoint has no authorizer (Broken Object Auth)',     'API2', 'high',
   'field_check', '{"field":"auth_required","operator":"eq","value":false}',
   ARRAY['OWASP_API_2023','PCI-DSS','SOC2']),
  ('API-002', 'API uses API_KEY only (no IAM/Cognito/JWT auth)',         'API2', 'medium',
   'field_check', '{"field":"auth_types","operator":"not_contains","value":"COGNITO_USER_POOLS"}',
   ARRAY['OWASP_API_2023','SOC2']),
  ('API-003', 'No WAF associated with API',                              'API7', 'high',
   'field_check', '{"field":"has_waf","operator":"eq","value":false}',
   ARRAY['OWASP_API_2023','PCI-DSS']),
  ('API-004', 'No rate limiting (usage plan) configured',                'API4', 'high',
   'field_check', '{"field":"has_rate_limiting","operator":"eq","value":false}',
   ARRAY['OWASP_API_2023','PCI-DSS']),
  ('API-005', 'API access logging not enabled',                          'API10','high',
   'field_check', '{"field":"logging_enabled","operator":"eq","value":false}',
   ARRAY['OWASP_API_2023','PCI-DSS','HIPAA','SOC2']),
  ('API-006', 'TLS 1.0 or 1.1 allowed on listener',                     'API7', 'high',
   'field_check', '{"field":"tls_minimum","operator":"in",
                    "value":["TLS_1_0","TLS_1_1","ELBSecurityPolicy-2016-08"]}',
   ARRAY['OWASP_API_2023','PCI-DSS','NIST_800-53']),
  ('API-007', 'No request validator configured on API',                  'API8', 'medium',
   'field_check', '{"field":"request_validator","operator":"eq","value":false}',
   ARRAY['OWASP_API_2023']),
  ('API-008', 'CORS wildcard origin (*) configured',                     'API7', 'high',
   'field_check', '{"field":"cors_policy.allow_origins","operator":"contains","value":"*"}',
   ARRAY['OWASP_API_2023','SOC2']),
  ('API-009', 'X-Ray tracing disabled on API stage',                     'API10','low',
   'field_check', '{"field":"xray_tracing_enabled","operator":"eq","value":false}',
   ARRAY['SOC2']),
  ('API-010', 'AppSync field-level logging not enabled',                 'API10','medium',
   'field_check', '{"field":"log_config.fieldLogLevel","operator":"in","value":["NONE",null]}',
   ARRAY['OWASP_API_2023','SOC2']),
  -- Deprecated API detection (OWASP API9)
  ('API-011', 'Old API version still active alongside newer version',    'API9', 'medium',
   'field_check', '{"field":"has_newer_version","operator":"eq","value":true}',
   ARRAY['OWASP_API_2023']),
  -- Runtime anomaly rules
  ('API-RT-001', 'API error rate spike > 10% in last 24h',              'API7', 'medium',
   'threshold', '{"metric":"error_rate_pct","operator":"gt",
                  "baseline_field":null,"absolute_threshold":10.0}',
   ARRAY['SOC2','ISO27001']);
```

---

### 3.5 engine_risk

**Reads from ALL engine finding tables — no new discovery needed:**

```sql
-- Cross-engine finding aggregation (per orchestration_id)
-- Run AFTER all other engines complete

-- 1. Get all findings with severity
SELECT 'threat'   AS engine, finding_id, severity, resource_type, resource_arn,
       account_id, region, title
FROM threat_findings WHERE orchestration_id = $1

UNION ALL SELECT 'iam', finding_id, severity, resource_type, resource_arn,
       account_id, region, title
FROM iam_findings WHERE orchestration_id = $1

UNION ALL SELECT 'datasec', finding_id::varchar, severity, resource_type, resource_arn,
       account_id, region, finding_type
FROM datasec_findings WHERE orchestration_id = $1

UNION ALL SELECT 'container', finding_id::varchar, severity, resource_type, null,
       account_id, region, title
FROM container_findings WHERE orchestration_id = $1

UNION ALL SELECT 'network', finding_id::varchar, severity, resource_type, resource_arn,
       account_id, region, title
FROM network_findings WHERE orchestration_id = $1

UNION ALL SELECT 'api', finding_id::varchar, severity, resource_type, resource_arn,
       account_id, region, title
FROM api_findings WHERE orchestration_id = $1;

-- 2. Data classification for each affected asset
SELECT resource_id, data_types, estimated_record_count, sensitivity_level,
       data_classification
FROM datasec_findings
WHERE orchestration_id = $1
  AND result = 'FAIL';

-- 3. Asset criticality from inventory
SELECT asset_id, resource_type, resource_arn, tags,
       (tags->>'Criticality')::varchar AS criticality_tag
FROM inventory_findings
WHERE orchestration_id = $1;

-- 4. Tenant configuration (industry + applicable regs)
SELECT ca.tenant_id, ca.account_id, ca.cloud_provider,
       ca.metadata->>'industry' AS industry,
       ca.metadata->>'revenue_range' AS revenue_range
FROM cloud_accounts ca
WHERE ca.tenant_id = $1;
```

**Transform pipeline (FAIR model):**

```python
# engine_risk/risk_engine/models/fair_model.py

PER_RECORD_COST = {
    "healthcare":  10.93,
    "finance":      6.08,
    "technology":   4.88,
    "retail":       3.28,
    "default":      4.45
}

REGULATORY_MODELS = {
    "GDPR":    lambda revenue, records: min(0.04 * revenue, 20_000_000),
    "HIPAA":   lambda revenue, records: min(records * 100, 1_900_000),
    "PCI_DSS": lambda revenue, records: records * 0.005,  # $5/record
    "CCPA":    lambda revenue, records: min(records * 750, 7_500_000),
}

def compute_scenario(finding: dict, asset_data: dict,
                     datasec_data: dict, tenant_config: dict) -> dict:
    """Compute FAIR risk scenario for one critical/high finding."""
    industry = tenant_config.get("industry", "default")
    revenue  = tenant_config.get("annual_revenue_usd", 0)

    # Loss Event Frequency
    epss = finding.get("epss_score", 0.05)  # default 5% if not enriched
    internet_exposed = asset_data.get("is_public", False)
    lef = epss * (1.0 if internet_exposed else 0.3)

    # Primary loss: data records × per-record cost
    records = datasec_data.get("estimated_record_count", 1000)  # conservative default
    sensitivity_mult = {"restricted": 3.0, "confidential": 2.0,
                        "internal": 1.0, "public": 0.1}.get(
                         datasec_data.get("sensitivity_level", "internal"), 1.0)
    per_record = PER_RECORD_COST.get(industry, PER_RECORD_COST["default"])
    primary_loss = records * per_record * sensitivity_mult

    # Regulatory fine
    applicable_regs = tenant_config.get("applicable_regulations", [])
    reg_fines = [REGULATORY_MODELS[r](revenue, records)
                 for r in applicable_regs if r in REGULATORY_MODELS]
    regulatory_fine = max(reg_fines) if reg_fines else 0

    total_likely = (primary_loss + regulatory_fine) * lef

    return {
        "loss_event_frequency":  lef,
        "primary_loss_likely":   primary_loss,
        "regulatory_fine_max":   regulatory_fine,
        "total_exposure_likely": total_likely,
        "total_exposure_min":    total_likely * 0.1,
        "total_exposure_max":    total_likely * 5.0,
        "risk_tier":             _tier(total_likely),
        "applicable_regulations": applicable_regs,
    }

def _tier(exposure: float) -> str:
    if exposure >= 10_000_000: return "critical"   # >$10M
    if exposure >= 1_000_000:  return "high"       # >$1M
    if exposure >= 100_000:    return "medium"     # >$100K
    return "low"
```

**engine_risk has no traditional rule table.** Instead it uses `risk_model_config` (per-tenant overrides for cost parameters) and only produces findings as risk scenarios — not PASS/FAIL evaluations. The risk tier (critical/high/medium/low) serves as the severity signal.

---

## 4. scan_orchestration Table Changes

Each new engine requires a new `_scan_id` column in `scan_orchestration`. Single migration:

```sql
-- Migration: add new engine scan ID columns to scan_orchestration
-- File: shared/database/migrations/014_add_new_engine_scan_ids.sql

ALTER TABLE scan_orchestration
    ADD COLUMN IF NOT EXISTS container_scan_id  VARCHAR(255),
    ADD COLUMN IF NOT EXISTS network_scan_id    VARCHAR(255),
    ADD COLUMN IF NOT EXISTS supplychain_scan_id VARCHAR(255),
    ADD COLUMN IF NOT EXISTS api_scan_id        VARCHAR(255),
    ADD COLUMN IF NOT EXISTS risk_scan_id       VARCHAR(255);

-- Index for cross-engine lookups
CREATE INDEX IF NOT EXISTS idx_scan_orch_container_scan
    ON scan_orchestration(container_scan_id) WHERE container_scan_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_scan_orch_network_scan
    ON scan_orchestration(network_scan_id) WHERE network_scan_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_scan_orch_supplychain_scan
    ON scan_orchestration(supplychain_scan_id) WHERE supplychain_scan_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_scan_orch_api_scan
    ON scan_orchestration(api_scan_id) WHERE api_scan_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_scan_orch_risk_scan
    ON scan_orchestration(risk_scan_id) WHERE risk_scan_id IS NOT NULL;
```

---

## 5. pipeline_worker Changes (adding new stages)

New stages to add to `shared/pipeline_worker/worker.py` and `handlers.py`:

```python
# shared/pipeline_worker/handlers.py — new trigger functions

async def trigger_container(orchestration_id: str, csp: str = "aws",
                            timeout: float = 600.0) -> dict:
    """Trigger container engine. Long timeout — Trivy scan takes time."""
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(
            f"{_url('container')}/api/v1/scan",
            json={"orchestration_id": orchestration_id, "csp": csp},
        )
        resp.raise_for_status()
        return resp.json()

async def trigger_network(orchestration_id: str, csp: str = "aws",
                          timeout: float = 300.0) -> dict:
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(
            f"{_url('network')}/api/v1/scan",
            json={"orchestration_id": orchestration_id, "csp": csp,
                  "mode": "posture"},  # posture only in pipeline; runtime is SQS-driven
        )
        resp.raise_for_status()
        return resp.json()

async def trigger_supplychain(orchestration_id: str, csp: str = "aws",
                               timeout: float = 300.0) -> dict:
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(
            f"{_url('supplychain')}/api/v1/scan",
            json={"orchestration_id": orchestration_id, "csp": csp},
        )
        resp.raise_for_status()
        return resp.json()

async def trigger_api_engine(orchestration_id: str, csp: str = "aws",
                              timeout: float = 300.0) -> dict:
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(
            f"{_url('api_engine')}/api/v1/scan",
            json={"orchestration_id": orchestration_id, "csp": csp},
        )
        resp.raise_for_status()
        return resp.json()

async def trigger_risk(orchestration_id: str, timeout: float = 120.0) -> dict:
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(
            f"{_url('risk')}/api/v1/scan",
            json={"orchestration_id": orchestration_id},
        )
        resp.raise_for_status()
        return resp.json()
```

**Updated pipeline stage ordering in `worker.py`:**

```python
# Stage order after adding new engines:
#
# Layer 1 (parallel after discoveries):
#   inventory, container, api_engine
#
# Layer 2 (parallel after Layer 1):
#   check, iam, secops, network
#
# Layer 3 (parallel after Layer 2):
#   threat, datasec, supplychain
#
# Layer 4 (parallel after Layer 3):
#   compliance, risk

PIPELINE_STAGES = [
    {"name": "inventory",    "layer": 1, "fn": trigger_inventory},
    {"name": "container",    "layer": 1, "fn": trigger_container},    # NEW
    {"name": "api_engine",   "layer": 1, "fn": trigger_api_engine},   # NEW
    {"name": "check",        "layer": 2, "fn": trigger_check},
    {"name": "iam",          "layer": 2, "fn": trigger_iam},
    {"name": "secops",       "layer": 2, "fn": trigger_secops},        # TODO: add to handlers
    {"name": "network",      "layer": 2, "fn": trigger_network},       # NEW
    {"name": "threat",       "layer": 3, "fn": trigger_threat},
    {"name": "datasec",      "layer": 3, "fn": trigger_datasec},
    {"name": "supplychain",  "layer": 3, "fn": trigger_supplychain},   # NEW
    {"name": "compliance",   "layer": 4, "fn": trigger_compliance},
    {"name": "risk",         "layer": 4, "fn": trigger_risk},          # NEW
]
```

---

## 6. Secrets Manager & K8s Changes Per New Engine

For each new engine, follow the checklist from MEMORY:

```bash
# 1. Add DB password to Secrets Manager (threat-engine/rds-credentials)
aws secretsmanager update-secret \
  --secret-id threat-engine/rds-credentials \
  --secret-string '{ ..., "CONTAINER_DB_PASSWORD": "same_password",
                         "NETWORK_DB_PASSWORD": "same_password",
                         "SUPPLYCHAIN_DB_PASSWORD": "same_password",
                         "API_DB_PASSWORD": "same_password",
                         "RISK_DB_PASSWORD": "same_password" }'

# 2. Add key to external-secret manifest
# deployment/aws/eks/external-secret.yaml — add remoteRef for each new key

# 3. Add DB env vars to ConfigMap
# deployment/aws/eks/configmap.yaml — add CONTAINER_DB_NAME etc.

# 4. Create engine K8s manifest
# deployment/aws/eks/engines/engine-{name}.yaml
# Standard structure: Deployment + Service + ConfigMap refs + external-secret refs

# 5. Add ingress path to nginx
# deployment/aws/eks/ingress.yaml — add /{engine}(/|$)(.*) → engine service
```

---

## 7. Shared DB Seeding Scripts (Category A rule_discoveries rows)

Rather than adding Category A rows manually, use seeding SQL files:

```sql
-- File: shared/database/seeds/seed_rule_discoveries_new_engines.sql
-- Run once after deployment to add new discovery types to check DB

-- A1: ECR Images
INSERT INTO rule_discoveries (
    rule_id, service_name, provider, boto3_client_name,
    arn_identifier, arn_identifier_independent_methods,
    arn_identifier_dependent_methods, is_active
) VALUES (
    'aws.ecr.describe_repositories', 'ecr', 'aws', 'ecr',
    'arn:aws:ecr:{region}:{account}:repository/{repository_name}',
    '[{"action":"describe_repositories","save_as":"repos","params":{"maxResults":100}}]'::jsonb,
    '[]'::jsonb,
    true
),
(
    'aws.ecr.describe_images', 'ecr', 'aws', 'ecr',
    'arn:aws:ecr:{region}:{account}:repository/{repository_name}/image/{image_digest}',
    '[]'::jsonb,
    '[{"action":"describe_images","save_as":"images","params":{"repositoryName":"{{repository_name}}","filter":{"tagStatus":"ANY"}}}]'::jsonb,
    true
);

-- A8: VPC Flow Logs
INSERT INTO rule_discoveries (
    rule_id, service_name, provider, boto3_client_name,
    arn_identifier, arn_identifier_independent_methods,
    arn_identifier_dependent_methods, is_active
) VALUES (
    'aws.ec2.describe_flow_logs', 'ec2', 'aws', 'ec2',
    '{flow_log_id}',
    '[{"action":"describe_flow_logs","save_as":"flow_logs","params":{"MaxResults":100}}]'::jsonb,
    '[]'::jsonb,
    true
);

-- ... (add remaining A4-A12 rows following same pattern)
```

---

## 8. Quick Reference: Which Document to Read for What

| Question | Read |
|----------|------|
| What resource_types does engine X read? | **This file (Section 3.x)** |
| Exact boto3 calls to collect resource_type Y? | **NEW_ENGINE_DATA_SOURCES.md (Category A.x)** |
| SQL schema for engine X output tables? | **NEW_ENGINES_ARCHITECTURE.md (Engine X Schema)** |
| Block diagram of engine X? | **NEW_ENGINES_ARCHITECTURE.md (Engine X Diagram)** |
| Rule seed SQL for engine X? | **This file (Section 3.x Rule seed)** |
| How does FAIR model work? | **This file (Section 3.5)** |
| scan_orchestration columns to add? | **This file (Section 4)** |
| Pipeline worker changes? | **This file (Section 5)** |
| K8s / Secrets Manager checklist? | **This file (Section 6)** |
| DB seeding for Category A sources? | **This file (Section 7)** |
