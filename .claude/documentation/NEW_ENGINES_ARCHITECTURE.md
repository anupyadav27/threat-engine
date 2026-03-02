# New Engines — Architecture & Design Specification

**Status:** Planning
**Date:** 2026-03-02
**Scope:** 5 new engines (threatintel_worker removed — covered by check engine metadata)

---

## Verification: Engines Already Built

Before designing new engines, the following were verified against the codebase:

| Engine | Status | Evidence |
|--------|--------|---------|
| **engine_attackpath** (Engine 2) | ✅ **FULLY BUILT** | `graph_builder.py` (1,921 lines) — Neo4j graph, 18 edge builders, BFS blast radius, 6 pre-built hunt queries, internet exposure inference, multi-CSP (38 resource types) |
| **engine_threatintel** (Engine 4) | ✅ **COVERED** | `check_engine` rule metadata already carries CVE IDs, MITRE technique IDs, severity baselines, and compliance framework mappings per rule. The threat engine reads from `rule_metadata` in the check DB directly — no separate feed ingestor service needed. |

**Action:** Neither engine needs new work. threatintel_worker is dropped from scope.

---

## Updated Engine Roadmap

```
EXISTING (production):
  engine_discoveries  → cloud resource enumeration (414 AWS services, multi-CSP)
  engine_check        → misconfiguration rules (PASS/FAIL)
  engine_inventory    → asset normalization + drift detection
  engine_threat       → MITRE mapping + attack path + blast radius (Neo4j)
  engine_compliance   → framework reports (13 frameworks)
  engine_iam          → IAM posture (57 rules)
  engine_datasec      → data classification + lineage
  engine_secops       → IaC + secret scanning (14 languages)
  vulnerability       → CVE agent (real-time host scanning)

TO BUILD (this document):
  engine_container    → container image CVE + K8s runtime security
  engine_network      → VPC flow analysis + network anomaly detection
  engine_supplychain  → SBOM + dependency chain security
  engine_risk         → financial risk quantification (dollar exposure)
  engine_api          → OWASP API Top 10 + API inventory

NOTE:
  threatintel_worker  → NOT NEEDED. CVE/MITRE/KEV mappings already live in
                        check_engine rule_metadata. Threat engine reads that
                        directly for enrichment context.
```

---

## Pipeline Position (Full Updated Flow)

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         THREAT ENGINE — FULL PIPELINE                          │
└─────────────────────────────────────────────────────────────────────────────────┘

LAYER 0 — TRIGGER
  onboarding ──SQS──► pipeline_worker

LAYER 1 — DISCOVERY (what exists)
  discoveries ──────────────────────────────────────────────────────────────────►
                  │                                                              │
                  ├── inventory (normalize + drift)                              │
                  ├── [NEW] engine_container (image scan ECR/GCR/ACR)           │
                  └── [NEW] engine_api (API Gateway/ALB inventory)              │

LAYER 2 — POSTURE CHECK (is it configured correctly?)
  check ────────────────────────────────────────────────────────────────────────►
  iam ──────────────────────────────────────────────────────────────────────────►
  secops ───────────────────────────────────────────────────────────────────────►
  vulnerability ────────────────────────────────────────────────────────────────►
  [NEW] engine_network (SG/NACL posture + VPC flow anomalies) ─────────────────►

LAYER 3 — ENRICHMENT & CORRELATION
  datasec ──────────────────────────────────────────────────────────────────────►
  threat ───────────────────────────────────────────────────────────────────────►  (MITRE + attack path)
  [COMPLETE] threatintel_worker ────────────────────────────────────────────────►  (CISA KEV + EPSS enrichment)
  [NEW] engine_supplychain (SBOM cross-ref) ────────────────────────────────────►

LAYER 4 — AGGREGATION (consumes all prior outputs)
  compliance ──────────────────────────────────────────────────────────────────►
  [NEW] engine_risk (financial exposure from all findings) ────────────────────►

OUTPUT
  Reports / Dashboards / Alerts / API
```

---

## Rule & Check Framework (Applies to All New Engines)

All new engines follow the same DB-driven rule pattern as `engine_check`:

```
┌──────────────────────────────────────────────────────────────────┐
│                    RULE EVALUATION PATTERN                        │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  DB Table: {engine}_rules                                        │
│  ┌─────────────┬────────────┬──────────────┬──────────────────┐ │
│  │ rule_id     │ rule_type  │ severity     │ is_active        │ │
│  │ title       │ framework  │ condition    │ remediation      │ │
│  │ description │ csp        │ threshold    │ references       │ │
│  └─────────────┴────────────┴──────────────┴──────────────────┘ │
│                                                                  │
│  Runtime:                                                        │
│  1. Rule loader reads is_active=TRUE rules from DB              │
│  2. Rule evaluator runs condition against asset/event data      │
│  3. Finding written with rule_id, evidence, severity            │
│  4. No rule changes require code deploy — only DB updates       │
│                                                                  │
│  Severity levels: critical / high / medium / low / info         │
│  Result values:   FAIL / PASS / SKIP / ERROR                    │
└──────────────────────────────────────────────────────────────────┘
```

**Rule condition types:**
```yaml
# Type 1: Field comparison (most rules)
condition:
  field: "encryption_enabled"
  operator: "eq"
  value: false

# Type 2: Threshold (anomaly/metric rules)
condition:
  field: "outbound_bytes"
  operator: "gt"
  baseline_multiplier: 3.0     # > 3x normal = anomaly

# Type 3: Set membership (IP/CVE/package allowlists)
condition:
  field: "cve_id"
  operator: "in_set"
  set_source: "cisa_kev"       # dynamic set from threatintel cache

# Type 4: Graph traversal (attack path rules)
condition:
  type: "cypher"
  query: "MATCH (n:EC2)-[:GRANTS_ACCESS]->(r:S3 {public: true}) RETURN n"
```

---

---

# ENGINE 1: `engine_container`
## Container Image Security & K8s Runtime

---

### Purpose
Scan container images for CVEs, secrets, and misconfigurations before and after deployment. Monitor running containers in Kubernetes for policy violations.

### Architecture Block Diagram

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                         engine_container                                      │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  DATA SOURCES                  PROCESSING                  OUTPUT DB         │
│  ┌─────────────┐               ┌─────────────────┐         ┌──────────────┐ │
│  │ discoveries │──registry───► │  Image Puller   │──────►  │container_    │ │
│  │ (ECR/GCR/   │               │  (manifest +    │         │images        │ │
│  │  ACR found) │               │   layer digest) │         └──────────────┘ │
│  └─────────────┘               └────────┬────────┘                          │
│                                         │                  ┌──────────────┐ │
│  ┌─────────────┐               ┌────────▼────────┐         │container_    │ │
│  │ K8s API     │──pods/specs►  │  CVE Scanner    │──────►  │findings      │ │
│  │ (running    │               │  (Trivy/Grype   │         │              │ │
│  │  containers)│               │   as library)   │         └──────────────┘ │
│  └─────────────┘               └────────┬────────┘                          │
│                                         │                  ┌──────────────┐ │
│  ┌─────────────┐               ┌────────▼────────┐         │container_    │ │
│  │ secops      │──Dockerfile►  │  Config Checker │──────►  │sbom          │ │
│  │ (linked     │               │  (CIS Docker    │         │              │ │
│  │  repo)      │               │   Benchmark)    │         └──────────────┘ │
│  └─────────────┘               └────────┬────────┘                          │
│                                         │                  ┌──────────────┐ │
│  ┌─────────────┐               ┌────────▼────────┐         │k8s_policy_   │ │
│  │ threatintel │──KEV/EPSS───► │  Risk Scorer    │──────►  │findings      │ │
│  │ cache       │               │  (exploitability│         │              │ │
│  │             │               │   enrichment)   │         └──────────────┘ │
│  └─────────────┘               └─────────────────┘                          │
│                                                                              │
│  TRIGGER: post-discoveries (new image found) + scheduled daily               │
│  PORT: 8006   NAMESPACE: threat-engine-engines                               │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Data Already Available (from existing engines)

| Data Needed | Source | Available? |
|-------------|--------|-----------|
| ECR/GCR/ACR repository list | `engine_discoveries` | ✅ Yes — already enumerated |
| K8s cluster list | `engine_discoveries` | ✅ Yes |
| Running pod specs (image refs) | `engine_inventory` asset graph | ✅ Partial |
| Repo/Dockerfile (if linked) | `engine_secops` | ✅ Yes |
| CVE exploitability (KEV/EPSS) | `threatintel_worker` (to be completed) | ⚠️ After threatintel done |

### New Data Pipelines Needed

| Pipeline | Mechanism | Frequency |
|----------|-----------|-----------|
| Pull image manifest + layers | Docker Registry API (no agent needed) | On discovery + daily |
| K8s pod spec scrape | K8s API (`/api/v1/pods`) via IRSA | On discovery + hourly |
| CVE database | Embed Trivy DB (updates daily, local cache) | Daily refresh |
| CIS Docker benchmark | Embedded ruleset (static YAML in DB) | On schema load |

### ETL Design

```
EXTRACT:
  Input:
    - discovery_findings WHERE resource_type IN ('ecr.repository','gcr.repository','acr.repository')
    - K8s pods from cluster API: {image_ref, namespace, pod_name, is_privileged, security_context}
    - Dockerfile content from secops scan results (if available)

TRANSFORM:
  For each image:
    1. Pull manifest → extract layer digests
    2. Pull each layer → run Trivy scanner → CVE list
    3. Extract all installed packages → SBOM component list
    4. Run CIS Docker Benchmark checks against config
    5. Check if image is currently running in K8s
    6. Enrich CVEs with EPSS/KEV from threatintel cache

LOAD:
  → container_images (one row per image:tag)
  → container_findings (one row per CVE/misconfiguration)
  → container_sbom (one row per package)
  → k8s_policy_findings (one row per K8s policy violation)
  → Update scan_orchestration.container_scan_id
```

### Input / Output Schema

```sql
-- INPUT (read from existing tables)
SELECT resource_id, resource_arn, resource_name, metadata
FROM discovery_findings
WHERE resource_type IN ('ecr.repository', 'container_registry')
  AND orchestration_id = $1;

-- OUTPUT TABLES

container_images (
  image_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  container_scan_id UUID NOT NULL,
  tenant_id         UUID NOT NULL,
  orchestration_id  UUID NOT NULL,
  registry_type     VARCHAR(20),       -- ecr | gcr | acr | dockerhub
  registry_url      VARCHAR(500),
  repository        VARCHAR(255),
  tag               VARCHAR(128),
  digest            VARCHAR(128),      -- sha256:abc123...
  base_image        VARCHAR(255),      -- FROM python:3.11-slim
  os_family         VARCHAR(50),
  os_version        VARCHAR(50),
  total_layers      INT,
  total_packages    INT,
  is_running        BOOLEAN DEFAULT false,
  running_in        TEXT[],            -- ['prod-cluster/namespace/pod-name']
  critical_cve_count INT DEFAULT 0,
  high_cve_count    INT DEFAULT 0,
  risk_score        INT,               -- 0-100
  last_pushed_at    TIMESTAMP,
  scanned_at        TIMESTAMP DEFAULT NOW(),
  created_at        TIMESTAMP DEFAULT NOW()
);

container_findings (
  finding_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  container_scan_id UUID NOT NULL,
  image_id          UUID REFERENCES container_images(image_id),
  tenant_id         UUID NOT NULL,
  finding_type      VARCHAR(30),       -- cve | misconfiguration | secret | malware
  rule_id           VARCHAR(100),
  severity          VARCHAR(20),
  cve_id            VARCHAR(30),       -- CVE-2024-1234
  package_name      VARCHAR(255),
  package_version   VARCHAR(100),
  fixed_version     VARCHAR(100),
  cvss_score        DECIMAL(3,1),
  epss_score        DECIMAL(6,5),      -- from threatintel cache
  is_in_kev         BOOLEAN DEFAULT false,
  exploit_maturity  VARCHAR(30),       -- none | poc | functional | weaponized
  layer_hash        VARCHAR(128),
  title             TEXT,
  description       TEXT,
  remediation       TEXT,
  csp               VARCHAR(20),
  region            VARCHAR(50),
  is_running        BOOLEAN DEFAULT false,  -- CVE in live container?
  created_at        TIMESTAMP DEFAULT NOW()
);

container_sbom (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  image_id          UUID REFERENCES container_images(image_id),
  container_scan_id UUID NOT NULL,
  package_name      VARCHAR(255),
  package_version   VARCHAR(100),
  package_type      VARCHAR(30),       -- deb | rpm | npm | pip | go | jar | apk
  license           VARCHAR(200),
  purl              VARCHAR(500),      -- pkg:pypi/requests@2.28.0
  cpe               VARCHAR(300),
  is_direct_dep     BOOLEAN,
  has_vulnerabilities BOOLEAN DEFAULT false,
  vulnerability_count INT DEFAULT 0
);

k8s_policy_findings (
  finding_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  container_scan_id UUID NOT NULL,
  tenant_id         UUID NOT NULL,
  cluster_id        VARCHAR(255),
  namespace         VARCHAR(128),
  resource_kind     VARCHAR(50),       -- Pod | Deployment | DaemonSet
  resource_name     VARCHAR(255),
  rule_id           VARCHAR(100),
  severity          VARCHAR(20),
  title             TEXT,
  evidence          JSONB,             -- {field: "securityContext.runAsRoot", value: true}
  remediation       TEXT,
  created_at        TIMESTAMP DEFAULT NOW()
);
```

### Rules Table

```sql
container_rules (
  rule_id           VARCHAR(100) PRIMARY KEY,
  title             VARCHAR(255),
  description       TEXT,
  category          VARCHAR(50),   -- cve_severity | docker_cis | k8s_psp | secrets
  severity          VARCHAR(20),
  condition_type    VARCHAR(30),   -- field_check | threshold | set_membership
  condition         JSONB,
  frameworks        TEXT[],        -- ['CIS_Docker_1.6','PCI-DSS','SOC2']
  remediation       TEXT,
  references        TEXT[],
  csp               TEXT[],        -- ['aws','gcp','azure'] or ['all']
  is_active         BOOLEAN DEFAULT true,
  created_at        TIMESTAMP DEFAULT NOW()
);

-- Seed example:
INSERT INTO container_rules VALUES (
  'CONT-001', 'Container running as root', '...', 'k8s_psp', 'high',
  'field_check', '{"field":"runAsRoot","operator":"eq","value":true}',
  ARRAY['CIS_K8s_5.2.6','PCI-DSS'], 'Set runAsNonRoot: true in securityContext', ...
);
```

### Feature Branch
```
feature/engine-container
  engine_container/
    container_engine/
      api_server.py          # FastAPI, port 8006
      scanner/
        image_puller.py      # registry API + manifest download
        cve_scanner.py       # Trivy wrapper (subprocess or grpc)
        config_checker.py    # CIS Docker benchmark
        k8s_scraper.py       # K8s API pod spec reader
      db/
        container_db_writer.py
        container_db_reader.py
        rule_loader.py
      enricher/
        threatintel_enricher.py  # read from threatintel cache, add EPSS/KEV
    requirements.txt
    Dockerfile
  deployment/aws/eks/engines/engine-container.yaml
  shared/database/schemas/container_schema.sql
```

---

---

# ENGINE 2: `engine_network`
## Network Security Posture & Flow Anomaly Detection

---

### Purpose
Two modes: (1) **Posture** — evaluate Security Group/NACL rules, VPC topology for misconfigurations. (2) **Runtime** — analyze VPC Flow Logs for lateral movement, data exfiltration, beaconing.

> Note: Posture mode can be delivered first (Q1). Runtime mode is a separate sub-feature (Q2).

### Architecture Block Diagram

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                         engine_network                                        │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────── POSTURE MODE ────────────────────────────────┐ │
│  │                                                                         │ │
│  │  discoveries           Topology Builder          network_topology DB   │ │
│  │  (SG/NACL/VPC ──────►  build directed graph  ──► nodes: VPC,subnet,    │ │
│  │   RouteTable            of network resources      SG,IGW,NAT,TGW       │ │
│  │   found)                                          edges: routes,rules  │ │
│  │                                ▼                                       │ │
│  │                         Rule Evaluator      ──►  network_findings DB   │ │
│  │                         (SG open to 0/0/0,       (FAIL/PASS per rule)  │ │
│  │                          VPC flow logs off,                            │ │
│  │                          IGW on private subnet)                        │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
│  ┌─────────────────────────── RUNTIME MODE ────────────────────────────────┐ │
│  │                                                                         │ │
│  │  VPC Flow Logs         Flow Processor           Anomaly Detector       │ │
│  │  (S3 bucket) ────────► parse + normalize ──────► baseline compare  ──► │ │
│  │                         {src_ip,dst_ip,           (3x spike = alert)   │ │
│  │                          port,bytes,action}                            │ │
│  │                                ▼                      ▼                │ │
│  │  threatintel cache     IOC Matcher              network_events DB      │ │
│  │  (malicious IPs) ────► match src/dst IPs   ──►  network_anomalies DB  │ │
│  │                                                                         │ │
│  │  TRIGGER: S3 event notification → SQS → engine_network worker          │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
│  PORT: 8007   NAMESPACE: threat-engine-engines                               │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Data Already Available

| Data Needed | Source | Available? |
|-------------|--------|-----------|
| VPC, Subnet, RouteTable resources | `engine_discoveries` | ✅ Yes |
| Security Group rules (inbound/outbound) | `engine_discoveries` discovery_findings | ✅ Yes (in metadata JSONB) |
| NACL rules | `engine_discoveries` | ✅ Yes |
| Internet Gateway, NAT Gateway | `engine_discoveries` | ✅ Yes |
| Transit Gateway | `engine_discoveries` | ✅ Yes |
| Network topology relationships | `engine_inventory` inventory_relationships | ✅ Partial |
| Malicious IP lists | `threatintel_worker` (to complete) | ⚠️ After threatintel |

### New Data Pipelines Needed

| Pipeline | Mechanism | Frequency | Priority |
|----------|-----------|-----------|---------|
| VPC Flow Log ingestion | S3 → SQS → consumer | Continuous | Q2 |
| DNS query log ingestion | Route53 → CloudWatch → S3 → consumer | Continuous | Q3 |
| Baseline computation | Scheduled job (daily, 14-day rolling) | Daily | Q2 |
| SG/NACL rule extraction | Already in discovery_findings.metadata | On scan | Q1 |

### ETL Design

```
POSTURE MODE:
  EXTRACT:
    - discovery_findings WHERE resource_type IN
      ('ec2.security_group','vpc','subnet','network_acl',
       'internet_gateway','nat_gateway','vpc_peering','transit_gateway')
    - Parse metadata JSONB → extract inbound_rules, outbound_rules, routes

  TRANSFORM:
    - Build adjacency map: {resource} → {connected_resources, via}
    - Run rule evaluator against each SG/NACL/VPC config
    - Flag: 0.0.0.0/0 on port 22/3389, flow_logs=false, private subnet has IGW

  LOAD:
    → network_topology (graph of network resources)
    → network_findings (posture violations)

RUNTIME MODE:
  EXTRACT:
    - VPC Flow Log files from S3 (triggered by S3 event notification)
    - Parse: version, account, interface, srcaddr, dstaddr, srcport, dstport,
             protocol, packets, bytes, start, end, action, log-status

  TRANSFORM:
    - Aggregate by src-dst pair over 5-minute windows
    - Compare to baseline (rolling 14-day average)
    - Match dst/src IPs against threatintel IOC cache
    - Apply anomaly rules (spike, beaconing, scanning patterns)

  LOAD:
    → network_events (raw aggregated flow records)
    → network_anomalies (detected anomalies with severity)
```

### Input / Output Schema

```sql
-- INPUT (read from existing tables)
SELECT resource_id, resource_type, resource_arn, metadata, account_id, region
FROM discovery_findings
WHERE resource_type IN ('ec2.security_group','vpc','subnet','network_acl',
                        'internet_gateway','nat_gateway','vpc_peering_connection')
  AND orchestration_id = $1;

-- OUTPUT TABLES

network_topology (
  node_id           VARCHAR(255) PRIMARY KEY,  -- resource_id
  network_scan_id   UUID NOT NULL,
  tenant_id         UUID NOT NULL,
  resource_type     VARCHAR(80),
  resource_arn      VARCHAR(500),
  vpc_id            VARCHAR(50),
  account_id        VARCHAR(20),
  region            VARCHAR(50),
  cidr_block        VARCHAR(50),
  is_public         BOOLEAN,
  has_igw           BOOLEAN,
  flow_logs_enabled BOOLEAN,
  inbound_rules     JSONB,       -- [{port, protocol, cidr, description}]
  outbound_rules    JSONB,
  connected_to      JSONB,       -- [{node_id, connection_type: route|peer|tgw}]
  created_at        TIMESTAMP DEFAULT NOW()
);

network_findings (
  finding_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  network_scan_id   UUID NOT NULL,
  tenant_id         UUID NOT NULL,
  resource_id       VARCHAR(255),
  resource_type     VARCHAR(80),
  resource_arn      VARCHAR(500),
  rule_id           VARCHAR(100),
  finding_type      VARCHAR(30),   -- misconfiguration | anomaly | threat
  severity          VARCHAR(20),
  title             TEXT,
  description       TEXT,
  evidence          JSONB,         -- {port: 22, cidr: "0.0.0.0/0", rule_idx: 0}
  remediation       TEXT,
  account_id        VARCHAR(20),
  region            VARCHAR(50),
  csp               VARCHAR(20),
  created_at        TIMESTAMP DEFAULT NOW()
);

network_events (
  event_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         UUID NOT NULL,
  account_id        VARCHAR(20),
  vpc_id            VARCHAR(50),
  src_ip            INET,
  dst_ip            INET,
  src_port          INT,
  dst_port          INT,
  protocol          VARCHAR(10),
  total_bytes       BIGINT,
  total_packets     BIGINT,
  flow_count        INT,
  action            VARCHAR(10),   -- ACCEPT | REJECT
  window_start      TIMESTAMP,
  window_end        TIMESTAMP,
  src_resource_id   VARCHAR(255),  -- resolved from IP → resource
  dst_resource_id   VARCHAR(255),
  ingested_at       TIMESTAMP DEFAULT NOW()
);

network_anomalies (
  anomaly_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         UUID NOT NULL,
  account_id        VARCHAR(20),
  anomaly_type      VARCHAR(50),   -- data_exfil | lateral_movement | beaconing |
                                   -- port_scan | dns_tunnel | malicious_ip
  severity          VARCHAR(20),
  src_ip            INET,
  dst_ip            INET,
  dst_port          INT,
  bytes_total       BIGINT,
  baseline_bytes    BIGINT,
  deviation_factor  DECIMAL(6,2),  -- 5.3 = 5.3x above baseline
  is_malicious_ip   BOOLEAN DEFAULT false,
  threat_intel_source VARCHAR(100),
  src_resource_id   VARCHAR(255),
  dst_resource_id   VARCHAR(255),
  rule_id           VARCHAR(100),
  evidence          JSONB,
  detected_at       TIMESTAMP DEFAULT NOW(),
  is_active         BOOLEAN DEFAULT true
);

network_baselines (
  baseline_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         UUID NOT NULL,
  resource_id       VARCHAR(255),
  metric_type       VARCHAR(50),   -- outbound_bytes | connection_count | unique_dst
  window_days       INT DEFAULT 14,
  baseline_avg      DECIMAL(20,2),
  baseline_p95      DECIMAL(20,2),
  std_deviation     DECIMAL(20,2),
  sample_count      INT,
  computed_at       TIMESTAMP DEFAULT NOW()
);
```

### Rules Table

```sql
network_rules (
  rule_id           VARCHAR(100) PRIMARY KEY,
  title             VARCHAR(255),
  description       TEXT,
  mode              VARCHAR(20),  -- posture | runtime
  category          VARCHAR(50),  -- exposure | encryption | logging | anomaly | threat
  severity          VARCHAR(20),
  condition_type    VARCHAR(30),  -- field_check | threshold | pattern
  condition         JSONB,
  frameworks        TEXT[],
  remediation       TEXT,
  csp               TEXT[],
  is_active         BOOLEAN DEFAULT true
);

-- Seed examples:
-- NET-001: Unrestricted SSH from internet (posture)
-- NET-002: VPC Flow Logs disabled (posture)
-- NET-003: Outbound data spike > 3x baseline (runtime)
-- NET-004: Connection to known malicious IP (runtime + threatintel)
-- NET-005: Port scanning pattern (runtime)
-- NET-006: Private subnet has direct Internet Gateway route (posture)
```

### Feature Branch
```
feature/engine-network
  engine_network/
    network_engine/
      api_server.py              # FastAPI, port 8007
      posture/
        topology_builder.py      # build network graph from discoveries
        rule_evaluator.py        # SG/NACL/VPC rule checks
      runtime/
        flow_processor.py        # parse VPC flow log files
        anomaly_detector.py      # baseline comparison + spike detection
        ioc_matcher.py           # match IPs against threatintel cache
        baseline_computer.py     # rolling 14-day baseline job
      db/
        network_db_writer.py
        network_db_reader.py
    requirements.txt
    Dockerfile
  deployment/aws/eks/engines/engine-network.yaml
  deployment/aws/eks/engines/network-flow-worker.yaml  # separate SQS consumer for logs
  shared/database/schemas/network_schema.sql
```

---

---

# ENGINE 3: `engine_supplychain`
## SBOM & Software Supply Chain Security

---

### Purpose
Generate a complete Software Bill of Materials (SBOM) across all deployed artifacts — container images, Lambda functions, running applications — and detect supply chain risks: vulnerable dependencies, malicious packages, license violations, abandoned libraries.

### Architecture Block Diagram

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                       engine_supplychain                                      │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  DATA SOURCES              COLLECTORS               ANALYZERS               │
│  ┌──────────────┐          ┌────────────────┐       ┌────────────────────┐  │
│  │ engine_      │          │ Code Repo      │       │ Dependency Analyzer│  │
│  │ container    │──SBOM──► │ Collector      │──────►│ (transitive depth, │  │
│  │ (image SBOM) │          │ (package.json, │       │  vulnerability     │  │
│  └──────────────┘          │  requirements, │       │  chain)            │  │
│                            │  go.mod, pom,  │       └────────────────────┘  │
│  ┌──────────────┐          │  Gemfile, etc) │                 │             │
│  │ engine_      │          └────────────────┘                 ▼             │
│  │ secops       │                                    ┌────────────────────┐  │
│  │ (code repos, │          ┌────────────────┐        │ Package Safety     │  │
│  │  IaC)        │──deps──► │ Lambda         │──────► │ Checker            │  │
│  └──────────────┘          │ Collector      │        │ (typosquatting,    │  │
│                            │ (unzip + scan  │        │  malicious pkg,    │  │
│  ┌──────────────┐          │  package files)│        │  license)          │  │
│  │ discoveries  │          └────────────────┘        └────────────────────┘  │
│  │ (Lambda      │                                              │             │
│  │  functions,  │          ┌────────────────┐                 ▼             │
│  │  CodeArtifact│──pkgs──► │ Registry       │       ┌────────────────────┐  │
│  │  repos found)│          │ Scanner        │──────►│ Provenance Checker │  │
│  └──────────────┘          │ (internal pkg  │       │ (signed? pinned?   │  │
│                            │  registries)   │       │  known source?)    │  │
│                            └────────────────┘       └─────────┬──────────┘  │
│                                                               │             │
│  threatintel cache ────────────────────────────────────────►  │             │
│  (CVE/malicious pkg lists)                                    ▼             │
│                                                     OUTPUT TABLES           │
│                                                     sbom_manifests          │
│                                                     sbom_components         │
│                                                     supplychain_findings    │
│                                                                              │
│  PORT: 8008 (or 8009 - check conflicts)   TRIGGERED: post-secops + post-container │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Data Already Available

| Data Needed | Source | Available? |
|-------------|--------|-----------|
| Container image package list | `engine_container` SBOM output | ✅ After engine_container built |
| Code repo package manifests | `engine_secops` scan results | ✅ Partial — secops finds secrets, can be extended |
| Lambda function list | `engine_discoveries` | ✅ Yes |
| Lambda code (S3 ZIP location) | `engine_discoveries` discovery metadata | ✅ ARN + code location in metadata |
| CodeArtifact/internal registries | `engine_discoveries` | ✅ If discovered |

### New Data Pipelines Needed

| Pipeline | Mechanism | Frequency |
|----------|-----------|-----------|
| Package manifest parsing (npm/pip/go/java) | Pull from VCS API (GitHub/GitLab API) | On scan |
| Lambda ZIP extraction | Download from S3 via Lambda ARN → unzip | On scan |
| Malicious package list | OSS Malicious Packages DB (npm advisories, PyPI safety DB) | Daily refresh |
| License compliance DB | SPDX license DB (embedded) | Monthly refresh |

### ETL Design

```
EXTRACT:
  Source 1 — container_sbom table (from engine_container)
    SELECT * FROM container_sbom WHERE container_scan_id = $1

  Source 2 — code repos (via secops engine or VCS API)
    For each repo discovered:
      → GET /repos/{owner}/{repo}/contents/package.json (GitHub API)
      → GET /repos/{owner}/{repo}/contents/requirements.txt
      → GET /repos/{owner}/{repo}/contents/go.mod
      (and pom.xml, Gemfile, Cargo.toml, composer.json, etc.)

  Source 3 — Lambda functions (from discoveries)
    For each lambda_function in discovery_findings:
      → Get S3 location from metadata.CodeLocation
      → Download ZIP
      → Extract package files from ZIP

TRANSFORM:
  For each package manifest:
    1. Parse → normalize to {name, version, type, is_direct, depth}
    2. Build dependency tree (npm ls / pip-compile / go mod graph)
    3. For each package:
       a. Check CVE list (from container_findings or NVD cache)
       b. Check malicious package list (OSS Malicious Packages DB)
       c. Check license (from SPDX DB)
       d. Check if pinned (exact version vs range/*)
       e. Check last published date (abandoned if > 2 years)
       f. Check if signed (npm provenance, pip signatures)
    4. Detect dependency confusion:
       Check if internal package names exist on public registries

LOAD:
  → sbom_manifests (one per scanned artifact)
  → sbom_components (one per package per artifact)
  → supplychain_findings (one per violation)
  → Update scan_orchestration.supplychain_scan_id
```

### Input / Output Schema

```sql
sbom_manifests (
  manifest_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  supplychain_scan_id UUID NOT NULL,
  tenant_id         UUID NOT NULL,
  orchestration_id  UUID NOT NULL,
  source_type       VARCHAR(30),    -- container_image | lambda | code_repo | package_registry
  source_id         VARCHAR(500),   -- image_id | function_arn | repo_url
  source_name       VARCHAR(255),
  sbom_format       VARCHAR(20),    -- spdx-2.3 | cyclonedx-1.4 | syft
  total_components  INT DEFAULT 0,
  direct_deps       INT DEFAULT 0,
  transitive_deps   INT DEFAULT 0,
  critical_findings INT DEFAULT 0,
  high_findings     INT DEFAULT 0,
  sbom_json         JSONB,          -- full SBOM in CycloneDX format
  generated_at      TIMESTAMP DEFAULT NOW()
);

sbom_components (
  component_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  manifest_id       UUID REFERENCES sbom_manifests(manifest_id),
  supplychain_scan_id UUID NOT NULL,
  package_name      VARCHAR(255),
  package_version   VARCHAR(100),
  package_type      VARCHAR(30),    -- npm | pypi | maven | go | nuget | deb | rpm | gem | cargo
  purl              VARCHAR(500),   -- pkg:pypi/requests@2.28.0
  cpe               VARCHAR(300),
  license           VARCHAR(200),
  license_category  VARCHAR(20),    -- permissive | copyleft | commercial | unknown
  is_direct_dep     BOOLEAN,
  dep_depth         INT,            -- 1=direct, 2=transitive, etc.
  supplier          VARCHAR(255),
  is_signed         BOOLEAN,
  is_pinned         BOOLEAN,        -- exact version vs. range
  last_published_at TIMESTAMP,
  days_since_update INT,            -- computed
  is_abandoned      BOOLEAN,        -- > 730 days without update
  has_vulnerabilities BOOLEAN DEFAULT false,
  vulnerability_count INT DEFAULT 0,
  is_malicious      BOOLEAN DEFAULT false
);

supplychain_findings (
  finding_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  supplychain_scan_id UUID NOT NULL,
  manifest_id       UUID REFERENCES sbom_manifests(manifest_id),
  component_id      UUID REFERENCES sbom_components(component_id),
  tenant_id         UUID NOT NULL,
  rule_id           VARCHAR(100),
  finding_type      VARCHAR(40),    -- vulnerable_dep | malicious_pkg | license_violation |
                                    -- abandoned | unpinned | dep_confusion | unsigned
  severity          VARCHAR(20),
  title             TEXT,
  description       TEXT,
  cve_ids           TEXT[],
  evidence          JSONB,
  remediation       TEXT,
  affected_services TEXT[],         -- which services/functions use this package
  created_at        TIMESTAMP DEFAULT NOW()
);
```

### Feature Branch
```
feature/engine-supplychain
  engine_supplychain/
    supplychain_engine/
      api_server.py
      collectors/
        manifest_parser.py       # parse npm/pip/go/maven/etc manifests
        lambda_extractor.py      # download + unzip Lambda packages
        container_sbom_reader.py # read from engine_container output
      analyzers/
        vulnerability_linker.py  # link packages to CVEs
        malicious_pkg_checker.py # check OSS malicious package DB
        license_checker.py       # SPDX license compliance
        provenance_checker.py    # signed/pinned/known-source
        dep_confusion_detector.py
      db/
        supplychain_db_writer.py
        supplychain_db_reader.py
    requirements.txt
    Dockerfile
  deployment/aws/eks/engines/engine-supplychain.yaml
  shared/database/schemas/supplychain_schema.sql
```

---

---

# ENGINE 4: `engine_risk`
## Financial Risk Quantification

---

### Purpose
Translate all security findings into dollar-denominated risk exposure. Gives CISOs a business-language view of risk. No competitor does this well at the infrastructure level.

### Architecture Block Diagram

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                           engine_risk                                         │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ALL ENGINE OUTPUTS          RISK MODELER               OUTPUT DB            │
│                                                                              │
│  threat_findings ──────►  ┌─────────────────────┐      ┌─────────────────┐  │
│  iam_findings ─────────►  │  Asset Criticality   │      │  risk_scenarios  │  │
│  datasec_findings ──────► │  Scorer              │ ──►  │  (per finding)  │  │
│  container_findings ────► │  (what data is here? │      └─────────────────┘  │
│  network_findings ──────► │   what workload?)    │                          │
│  supplychain_findings ──► └─────────────────────┘      ┌─────────────────┐  │
│                                    +                    │  risk_summary   │  │
│  inventory (asset meta) ────►  ┌─────────────────────┐ │  (per scan,     │  │
│                                │  Exposure Calculator │ │   per tenant)   │  │
│  datasec classification ────►  │  FAIR model:         │ └─────────────────┘  │
│  (record counts,               │  - loss event freq   │                      │
│   data sensitivity) ───────►   │  - loss magnitude    │ ┌─────────────────┐  │
│                                │  - regulatory fines  │ │  risk_trends    │  │
│  threatintel enrichment ────►  │  - op. downtime cost │ │  (over time)    │  │
│  (EPSS scores) ──────────────► └─────────────────────┘ └─────────────────┘  │
│                                         +                                    │
│  tenant metadata ──────────►  ┌─────────────────────┐                       │
│  (industry, region,            │  Regulatory Fine     │                      │
│   revenue estimate) ────────►  │  Calculator          │                      │
│                                │  (GDPR 4% revenue,   │                      │
│                                │   HIPAA, PCI, etc.)  │                      │
│                                └─────────────────────┘                       │
│                                                                              │
│  RUNS LAST in pipeline (Layer 4)   PORT: 8009                                │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Risk Model (FAIR-based)

```
FAIR Model Simplified:
  Risk = Loss Event Frequency × Loss Magnitude

  Loss Event Frequency:
    = Threat Event Frequency × Vulnerability (EPSS score × exploitability)

  Loss Magnitude:
    = Primary Loss + Secondary Loss
    Primary  = data_records × per_record_cost[industry] × data_sensitivity_multiplier
    Secondary = regulatory_fine + reputational_cost + operational_downtime

  Per-record cost benchmarks (IBM Cost of Breach 2024):
    Healthcare:  $10.93/record
    Finance:     $6.08/record
    Technology:  $4.88/record
    Retail:      $3.28/record
    Default:     $4.45/record  (global average)

  Regulatory fine models:
    GDPR:      min(4% annual_revenue, €20M) per incident
    HIPAA:     $100–$50,000 per violation (up to $1.9M/category/year)
    PCI-DSS:   $5,000–$100,000/month until compliant + per-record fines
    CCPA:      $100–$750/consumer/incident
    SOC2:      no direct fine, but contract liability
```

### Data Already Available

| Data Needed | Source | Available? |
|-------------|--------|-----------|
| All findings (severity, asset, type) | All engine output tables | ✅ Yes |
| Data classification (PII, PHI, financial) | `engine_datasec` datasec_findings | ✅ Yes |
| Asset criticality / resource type | `engine_inventory` inventory_findings | ✅ Yes |
| EPSS scores (exploitation probability) | `threatintel_worker` (to complete) | ⚠️ After threatintel |
| Framework violations | `engine_compliance` | ✅ Yes |
| Tenant industry/region | `cloud_accounts` onboarding DB | ✅ Yes (can add industry field) |

### New Data Needed

| Data | Source | How |
|------|--------|-----|
| Data record count estimates | Approximate from datasec (S3 object count × avg record size) | Computed |
| Annual revenue estimate | Add to tenant onboarding (`revenue_range` field) | New tenant field |
| Applicable regulations | Derive from industry + region + frameworks enabled | Rule table |

### ETL Design

```
EXTRACT:
  1. All findings from this scan across all engines:
     SELECT * FROM {engine}_findings WHERE orchestration_id = $1
  2. Asset data from inventory:
     SELECT asset_id, resource_type, resource_arn, tags, criticality_tier
     FROM inventory_findings WHERE orchestration_id = $1
  3. Data classification from datasec:
     SELECT resource_id, data_types, estimated_record_count, sensitivity_level
     FROM datasec_findings WHERE orchestration_id = $1
  4. Tenant metadata:
     SELECT industry, region, revenue_range, applicable_frameworks
     FROM cloud_accounts WHERE tenant_id = $1
  5. EPSS/KEV enrichment:
     SELECT * FROM finding_enrichments WHERE orchestration_id = $1

TRANSFORM:
  For each CRITICAL/HIGH finding:
    1. Identify affected asset
    2. Check if asset holds sensitive data (join with datasec output)
    3. Compute: loss_event_frequency = EPSS × (1 if internet-exposed else 0.3)
    4. Compute: primary_loss = records_at_risk × per_record_cost[industry]
    5. Compute: regulatory_fine = apply_regulatory_model(frameworks, records)
    6. Compute: total_exposure = (primary + regulatory) × loss_event_frequency
    7. Assign risk_tier based on total_exposure value

  Aggregate:
    Sum all scenarios → risk_summary (min/max/likely total exposure)
    Compare to previous scan → delta trend

LOAD:
  → risk_scenarios (one per material finding)
  → risk_summary (one per scan)
  → risk_trends (append-only, for charting)
  → Update scan_orchestration.risk_scan_id
```

### Input / Output Schema

```sql
risk_scenarios (
  scenario_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  risk_scan_id          UUID NOT NULL,
  tenant_id             UUID NOT NULL,
  orchestration_id      UUID NOT NULL,
  source_finding_id     VARCHAR(255),   -- FK to whichever engine produced it
  source_engine         VARCHAR(30),    -- threat|iam|container|network|datasec|check
  asset_id              VARCHAR(255),
  asset_type            VARCHAR(100),
  asset_arn             VARCHAR(500),
  scenario_type         VARCHAR(40),    -- data_breach | ransomware | account_takeover |
                                        -- compliance_fine | service_disruption
  data_records_at_risk  BIGINT,
  data_sensitivity      VARCHAR(20),    -- public | internal | confidential | restricted
  data_types            TEXT[],         -- ['PII','PHI','PCI']
  loss_event_frequency  DECIMAL(6,5),   -- probability (0-1) per year
  primary_loss_min      DECIMAL(15,2),
  primary_loss_max      DECIMAL(15,2),
  primary_loss_likely   DECIMAL(15,2),
  regulatory_fine_min   DECIMAL(15,2),
  regulatory_fine_max   DECIMAL(15,2),
  applicable_regulations TEXT[],        -- ['GDPR','HIPAA','PCI-DSS']
  total_exposure_min    DECIMAL(15,2),
  total_exposure_max    DECIMAL(15,2),
  total_exposure_likely DECIMAL(15,2),
  risk_tier             VARCHAR(20),    -- critical(>10M) | high(>1M) | medium | low
  calculation_model     JSONB,          -- full FAIR breakdown for audit
  created_at            TIMESTAMP DEFAULT NOW()
);

risk_summary (
  summary_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  risk_scan_id          UUID NOT NULL,
  tenant_id             UUID NOT NULL,
  orchestration_id      UUID NOT NULL,
  total_scenarios       INT,
  critical_scenarios    INT,
  total_exposure_min    DECIMAL(15,2),
  total_exposure_max    DECIMAL(15,2),
  total_exposure_likely DECIMAL(15,2),
  top_risk_asset_id     VARCHAR(255),
  top_risk_scenario_type VARCHAR(40),
  total_regulatory_exposure DECIMAL(15,2),
  frameworks_at_risk    TEXT[],
  currency              VARCHAR(5) DEFAULT 'USD',
  vs_previous_likely    DECIMAL(15,2),  -- change vs. last scan (positive = worse)
  vs_previous_pct       DECIMAL(6,2),   -- % change
  generated_at          TIMESTAMP DEFAULT NOW()
);

risk_trends (
  id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id             UUID NOT NULL,
  scan_date             DATE,
  total_exposure_likely DECIMAL(15,2),
  critical_scenarios    INT,
  high_scenarios        INT,
  top_risk_type         VARCHAR(40),
  recorded_at           TIMESTAMP DEFAULT NOW()
);
```

### No Traditional Rule Table — Model-Driven Config

```sql
-- Risk model config (editable per tenant, not per-finding rules)
risk_model_config (
  config_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         UUID,               -- NULL = global default
  industry          VARCHAR(50),
  per_record_cost   DECIMAL(10,2),      -- USD
  revenue_range     VARCHAR(30),        -- '<10M'|'10M-100M'|'100M-1B'|'>1B'
  applicable_regs   JSONB,              -- {GDPR: true, HIPAA: false, PCI: true}
  downtime_cost_hr  DECIMAL(12,2),      -- USD per hour of downtime
  updated_at        TIMESTAMP DEFAULT NOW()
);
```

### Feature Branch
```
feature/engine-risk
  engine_risk/
    risk_engine/
      api_server.py
      models/
        fair_model.py            # FAIR loss event frequency + magnitude
        regulatory_calculator.py # GDPR/HIPAA/PCI fine models
        asset_criticality.py     # classify asset tier from inventory + datasec
        exposure_aggregator.py   # sum scenarios → risk_summary
      db/
        risk_db_writer.py
        risk_db_reader.py
        findings_aggregator.py   # cross-engine finding collector
    requirements.txt
    Dockerfile
  deployment/aws/eks/engines/engine-risk.yaml
  shared/database/schemas/risk_schema.sql
```

---

---

# ENGINE 5: `engine_api`
## API Security Posture (OWASP API Top 10)

---

### Purpose
Inventory all APIs exposed by the cloud account (API Gateway, ALB, AppSync, GraphQL) and evaluate them against OWASP API Security Top 10. Also detects unauthenticated endpoints, rate-limiting gaps, and API key misuse.

### Architecture Block Diagram

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                           engine_api                                          │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  DATA SOURCES              API INVENTORY             SECURITY CHECKS        │
│                                                                              │
│  discoveries ──────────►  ┌──────────────────┐      ┌──────────────────┐   │
│  (API GW, ALB,             │  API Inventory   │      │  Auth Checker    │   │
│   AppSync, App             │  Builder         │ ──►  │  OWASP API1-2    │   │
│   Runner found)            │  - endpoints     │      │  (no auth, broken│   │
│                            │  - methods       │      │   authn)         │   │
│  check findings ─────────► │  - auth types    │      └──────────────────┘   │
│  (SG rules,                │  - rate limiting │                             │
│   WAF config)              │  - TLS version   │      ┌──────────────────┐   │
│                            └──────────────────┘      │  Rate Limit      │   │
│  CloudTrail logs ────────►        +             ──►  │  Checker         │   │
│  (API call patterns,              │                  │  OWASP API4      │   │
│   error spikes,                   ▼                  └──────────────────┘   │
│   unusual methods)         ┌──────────────────┐                             │
│                            │  OpenAPI Spec    │      ┌──────────────────┐   │
│  secops / repos ─────────► │  Parser          │ ──►  │  Endpoint Tester │   │
│  (swagger/openapi           │  (if available   │      │  OWASP API3,6,7  │   │
│   files found)             │  from repo scan) │      │  (data exposure, │   │
│                            └──────────────────┘      │  mass assignment)│   │
│                                                       └──────────────────┘   │
│                                                              │               │
│                                                              ▼               │
│                                                       OUTPUT TABLES          │
│                                                       api_inventory          │
│                                                       api_endpoints          │
│                                                       api_findings           │
│                                                                              │
│  PORT: 8010 (check if conflicts with secops)   TRIGGERED: post-discoveries   │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Data Already Available

| Data Needed | Source | Available? |
|-------------|--------|-----------|
| API Gateway resources | `engine_discoveries` | ✅ Yes (REST + HTTP + WebSocket) |
| ALB listener rules | `engine_discoveries` | ✅ Yes |
| AppSync GraphQL APIs | `engine_discoveries` | ✅ Yes |
| WAF association | `engine_discoveries` (metadata) | ✅ Yes |
| TLS policy on ALB/API GW | `engine_check` findings | ✅ Yes |
| OpenAPI/Swagger files | `engine_secops` (if in repo) | ✅ Partial |
| API access log patterns | CloudTrail → needs new pipeline | ⚠️ New pipeline |

### New Data Pipelines Needed

| Pipeline | Mechanism | Frequency |
|----------|-----------|-----------|
| API Gateway access logs | API GW logs → CloudWatch → pull on scan | On scan |
| CloudTrail API patterns | CloudTrail S3 → query for API call anomalies | On scan |
| OpenAPI spec extraction | Already in secops (extend) | On scan |

### ETL Design

```
EXTRACT:
  Source 1 — discoveries output:
    SELECT resource_id, resource_type, resource_arn, metadata
    FROM discovery_findings
    WHERE resource_type IN ('apigateway.restapi','apigateway.v2api','apigateway.stage',
                            'elasticloadbalancing.loadbalancer',
                            'appsync.graphqlapi','apprunner.service')
      AND orchestration_id = $1

  Source 2 — API Gateway API calls:
    aws apigateway get-stages --rest-api-id {id}
    aws apigateway get-resources --rest-api-id {id}
    aws apigateway get-authorizers --rest-api-id {id}
    aws apigatewayv2 get-routes --api-id {id}

  Source 3 — OpenAPI spec (from secops if available):
    SELECT metadata FROM secops_findings
    WHERE finding_type = 'openapi_spec' AND source_repo = $repo

TRANSFORM:
  For each API:
    1. Build endpoint inventory (path, method, auth type, rate limit, TLS)
    2. Check each endpoint against OWASP API rules:
       API1: object-level auth (does each endpoint require resource-level authz?)
       API2: broken auth (no authorizer attached?)
       API3: excessive data (response schema analysis if OpenAPI available)
       API4: rate limiting missing (no usage plan / no WAF rate rule)
       API5: function-level auth (admin endpoints accessible to non-admins?)
       API7: security misconfiguration (TLS 1.0, debug enabled, CORS *)
       API8: injection risk (no request validation configured)
       API9: asset management (deprecated/versioned APIs still active)
       API10: logging insufficient (no access logs configured)

LOAD:
  → api_inventory (one per API)
  → api_endpoints (one per endpoint/method)
  → api_findings (one per violation)
  → Update scan_orchestration.api_scan_id
```

### Input / Output Schema

```sql
api_inventory (
  api_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  api_scan_id       UUID NOT NULL,
  tenant_id         UUID NOT NULL,
  orchestration_id  UUID NOT NULL,
  resource_id       VARCHAR(255),
  resource_arn      VARCHAR(500),
  api_name          VARCHAR(255),
  api_type          VARCHAR(30),    -- rest | http | websocket | graphql | grpc
  gateway_type      VARCHAR(30),    -- api-gateway | alb | appsync | app-runner
  base_url          VARCHAR(500),
  total_endpoints   INT DEFAULT 0,
  auth_types        TEXT[],         -- ['COGNITO_USER_POOLS','AWS_IAM','API_KEY','NONE']
  has_waf           BOOLEAN DEFAULT false,
  has_rate_limiting BOOLEAN DEFAULT false,
  tls_minimum       VARCHAR(10),    -- TLS_1_0 | TLS_1_2 | TLS_1_3
  logging_enabled   BOOLEAN DEFAULT false,
  cors_policy       JSONB,          -- {allow_origins: ['*']}  ← OWASP API7
  is_public         BOOLEAN,
  stage_name        VARCHAR(50),
  csp               VARCHAR(20),
  account_id        VARCHAR(20),
  region            VARCHAR(50),
  scanned_at        TIMESTAMP DEFAULT NOW()
);

api_endpoints (
  endpoint_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  api_id            UUID REFERENCES api_inventory(api_id),
  api_scan_id       UUID NOT NULL,
  path              VARCHAR(500),
  method            VARCHAR(10),    -- GET | POST | PUT | DELETE | PATCH | ANY
  auth_required     BOOLEAN,
  auth_type         VARCHAR(50),
  rate_limited      BOOLEAN,
  request_validator BOOLEAN,        -- input validation configured?
  has_model_schema  BOOLEAN,        -- response schema defined?
  is_deprecated     BOOLEAN,
  openapi_operation JSONB           -- full OpenAPI operation spec if available
);

api_findings (
  finding_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  api_scan_id       UUID NOT NULL,
  tenant_id         UUID NOT NULL,
  api_id            UUID REFERENCES api_inventory(api_id),
  endpoint_id       UUID REFERENCES api_endpoints(endpoint_id),
  rule_id           VARCHAR(100),
  owasp_category    VARCHAR(10),    -- API1 through API10
  severity          VARCHAR(20),
  title             TEXT,
  description       TEXT,
  evidence          JSONB,          -- {field: "authorizer", value: null, path: "/admin/users"}
  remediation       TEXT,
  csp               VARCHAR(20),
  account_id        VARCHAR(20),
  region            VARCHAR(50),
  created_at        TIMESTAMP DEFAULT NOW()
);
```

### Rules Table

```sql
api_rules (
  rule_id           VARCHAR(100) PRIMARY KEY,
  title             VARCHAR(255),
  description       TEXT,
  owasp_category    VARCHAR(10),    -- API1 | API2 | ... | API10
  severity          VARCHAR(20),
  condition_type    VARCHAR(30),
  condition         JSONB,
  frameworks        TEXT[],         -- ['OWASP_API_2023','PCI-DSS','SOC2']
  remediation       TEXT,
  csp               TEXT[],
  is_active         BOOLEAN DEFAULT true
);

-- 10 mandatory seed rules (one per OWASP category):
-- API-001: No authorizer on endpoint (API1 - Broken Object Level Auth)
-- API-002: No authentication on API (API2 - Broken Authentication)
-- API-003: CORS wildcard origin configured (API7 - Security Misconfiguration)
-- API-004: No usage plan / rate limiting (API4 - Unrestricted Resource Consumption)
-- API-005: No WAF associated (API7 - Security Misconfiguration)
-- API-006: TLS 1.0 or 1.1 enabled (API7)
-- API-007: No request validator configured (API8 - Security Misconfiguration)
-- API-008: No access logging enabled (API10 - Unsafe Consumption)
-- API-009: Deprecated API version still active (API9 - Improper Asset Management)
-- API-010: API key in URL parameter (API2 - Credential Exposure)
```

### Feature Branch
```
feature/engine-api
  engine_api/
    api_security_engine/
      api_server.py              # FastAPI, port 8010
      inventory/
        api_discoverer.py        # query API GW + ALB from discoveries output
        endpoint_mapper.py       # map routes/resources to endpoint list
        openapi_parser.py        # parse OpenAPI/Swagger specs from secops
      checks/
        owasp_checker.py         # OWASP API1-10 evaluation
        auth_checker.py          # authentication/authorization analysis
        config_checker.py        # TLS, CORS, logging, WAF checks
      db/
        api_db_writer.py
        api_db_reader.py
    requirements.txt
    Dockerfile
  deployment/aws/eks/engines/engine-api.yaml
  shared/database/schemas/api_schema.sql
```

---

---

# ~~COMPLETION: `threatintel_worker`~~ — NOT REQUIRED

> **Decision:** The `check_engine` rule metadata (`rule_metadata` table in check DB) already
> carries CVE IDs, MITRE technique IDs, severity baselines, compliance framework mappings,
> and remediation guidance per rule — baked in at rule authoring time.
>
> The threat engine reads from `rule_metadata` directly for enrichment context.
> No separate external feed ingestion service is needed.
>
> If specific CISA KEV / EPSS lookups are needed in future, they can be added as
> a lightweight enrichment pass inside `engine_risk` (which already reads all findings)
> rather than a standalone worker.

---

---

## Updated Full Pipeline (All Engines)

```
LAYER 0    onboarding ──SQS──► pipeline_worker

LAYER 1    discoveries ──────────────────────────────────────────────┐
           (parallel):  inventory                                     │
                        engine_container  [NEW]                      │
                        engine_api        [NEW]                      │
                                                                      │
LAYER 2    check ────────────────────────────────────────────────────┤
           (parallel):  iam                                          │
                        secops                                        │
                        vulnerability                                 │
                        engine_network    [NEW]                      │
                                                                      │
LAYER 3    threat ───────────────────────────────────────────────────┤
           (parallel):  datasec                                      │
                        engine_supplychain  [NEW]                    │
                        (threatintel context from check rule_metadata │
                         — no separate pass needed)                  │
                                                                      │
LAYER 4    compliance ───────────────────────────────────────────────┤
           (parallel):  engine_risk  [NEW]                           │
                                                                      ▼
OUTPUT     Reports / Dashboard / Alerts / API
```

---

## Feature Branch Summary

| Engine | Branch | Port | DB Name | Priority |
|--------|--------|------|---------|---------|
| `engine_container` | `feature/engine-container` | 8006 | `threat_engine_container` | P1 — Q1 |
| ~~`threatintel_worker`~~ | ~~dropped~~ | — | check DB rule_metadata (existing) | ✅ Already covered |
| `engine_network` | `feature/engine-network` | 8007 | `threat_engine_network` | P2 — Q2 |
| `engine_supplychain` | `feature/engine-supplychain` | 8008 | `threat_engine_supplychain` | P2 — Q2 |
| `engine_risk` | `feature/engine-risk` | 8009 | `threat_engine_risk` | P3 — Q3 |
| `engine_api` | `feature/engine-api` | 8010 | `threat_engine_api` | P3 — Q3 |

---

## What Each Engine Reuses From Platform

All new engines inherit the following for free:
- `external-secret` for DB passwords (add key to Secrets Manager)
- `threat-engine-db-config` ConfigMap for DB host/port
- `engine-sa` ServiceAccount for IRSA (S3 + SecretsManager + SQS access)
- `scan_orchestration` table as pipeline coordination hub (add `{engine}_scan_id` column)
- `shared/common/` — SQS client, orchestration update, DB connection pool
- ELB + nginx ingress (add `/{engine}` path prefix)
- OpenTelemetry tracing (`OTEL_SERVICE_NAME` env var)
- Standard health endpoints: `/health`, `/api/v1/health`, `/api/v1/health/live`, `/api/v1/health/ready`
