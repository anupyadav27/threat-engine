# Threat Engine — Enhanced Project Plan
## CSPM Platform: 5 New Engines + 3-Tier Data Collection

**Date:** 2026-03-03
**Status:** Active Development
**Execution Model:** AI Agent-driven — one task at a time, role-specific agents

**Agent Roles:** `BD` Backend Developer | `DE` Data Engineer | `AD` API Developer | `DO` DevOps Engineer | `QA` QA Engineer | `PE` Platform Engineer
**Full role definitions & execution sequence:** See [AGENT_ROLES_AND_EXECUTION.md](AGENT_ROLES_AND_EXECUTION.md)

---

## Executive Summary

Enhance the existing CSPM platform (9 production engines) with 5 new security engines covering container, network, supply chain, API, and financial risk.

The platform uses a **3-tier collection model** to feed all engines:

- **Tier 1 — CSP Config Collector** (existing discoveries engine): boto3/SDK API calls → point-in-time configuration snapshots
- **Tier 2 — Log & Event Collector** (NEW shared service): CloudTrail, VPC flow logs, API access logs → time-series event streams
- **Tier 3 — External Source Collector** (NEW shared service): Docker Hub, GitHub/GitLab, NVD/CVE DB, public package registries → non-CSP data

Each engine then follows the standard ETL pattern: **Extract** from collector output tables → **Transform** by applying DB-driven rules → **Load** findings in standardized format.

All work executed by AI agents — no human resource allocation needed.

---

## 3-Tier Data Collection Architecture

### Why 3 Tiers?

The existing platform treats everything as CSP config (boto3 → discovery_findings). But the 5 new engines need fundamentally different data types:

| Data Type | Example | Volume | Shape | Auth | Current Coverage |
|-----------|---------|--------|-------|------|-----------------|
| CSP Config | Security groups, VPCs, ECR repos | Low (1000s of records) | JSON snapshot | IAM roles (boto3) | ✅ discovery_findings |
| Log/Event Streams | VPC flow logs, CloudTrail, API access logs | Very High (millions/day) | Time-series, needs aggregation | IAM roles (S3/CW) | ❌ NOT covered |
| External Sources | Docker Hub images, GitHub repos, NVD CVEs, npm/PyPI packages | Medium | REST API responses | PATs, API keys, public | ❌ NOT covered |

Putting log streams into discovery_findings would blow up the table. Calling Docker Hub via boto3 makes no sense. Each tier needs its own collection pattern, auth model, and storage.

### The 3-Tier Model

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        DATA COLLECTION LAYER                            │
│                                                                         │
│  TIER 1: CSP Config Collector          TIER 2: Log & Event Collector    │
│  (existing discoveries engine)         (NEW — shared/log_collector)     │
│  Port 8001                             Port 8030                        │
│  ┌─────────────────────────┐           ┌──────────────────────────┐     │
│  │ boto3/SDK API calls     │           │ VPC Flow Logs (S3→parse) │     │
│  │ → discovery_findings    │           │ CloudTrail events (S3)   │     │
│  │                         │           │ API access logs (CW)     │     │
│  │ SGs, VPCs, ECR repos,  │           │ K8s audit logs           │     │
│  │ API GW stages, WAF,    │           │                          │     │
│  │ ALB listeners, etc.    │           │ → log_events table       │     │
│  │                         │           │ → event_aggregations     │     │
│  │ Auth: IAM roles (IRSA) │           │ Auth: IAM roles (S3/CW)  │     │
│  └─────────────────────────┘           └──────────────────────────┘     │
│                                                                         │
│  TIER 3: External Source Collector                                      │
│  (NEW — shared/external_collector)                                      │
│  Port 8031                                                              │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │ Container Registries: Docker Hub, ECR, GCR, ACR, Quay          │    │
│  │   → registry HTTP API → image manifests, tags, layers          │    │
│  │   Auth: registry tokens (ECR get_authorization_token,          │    │
│  │         Docker Hub PAT, GCR service account)                   │    │
│  │                                                                 │    │
│  │ Code Repositories: GitHub, GitLab, Bitbucket                   │    │
│  │   → REST API → repo metadata, manifest files (package.json,   │    │
│  │     requirements.txt, go.mod, etc.)                            │    │
│  │   Auth: GitHub App / PAT, GitLab token (Secrets Manager)      │    │
│  │                                                                 │    │
│  │ Vulnerability Databases: NVD, OSV, GitHub Advisory, EPSS       │    │
│  │   → REST API / bulk download → CVE records, CVSS scores       │    │
│  │   Auth: NVD API key (free), public APIs                       │    │
│  │                                                                 │    │
│  │ Package Registries: npm, PyPI, Maven Central, crates.io       │    │
│  │   → REST API → package existence check (for dep confusion),   │    │
│  │     latest version, publish date, maintainer count            │    │
│  │   Auth: public (no auth needed for reads)                     │    │
│  │                                                                 │    │
│  │ Threat Intel Feeds: CISA KEV, AbuseIPDB, OTX, VirusTotal     │    │
│  │   → REST API → IOC indicators, malicious IPs, domains        │    │
│  │   Auth: API keys (Secrets Manager)                            │    │
│  │                                                                 │    │
│  │ → external_findings table                                      │    │
│  │ → vuln_cache, package_metadata, threat_intel_ioc tables       │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
                    │                    │                    │
                    ▼                    ▼                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         ENGINE LAYER (ETL)                               │
│                                                                         │
│  Each engine reads from one or more collector output tables:            │
│                                                                         │
│  engine_container:  Tier 1 (ecr.image, eks.pod)                        │
│                   + Tier 3 (registry manifests, Trivy CVE scan)        │
│                                                                         │
│  engine_network:    Tier 1 (SGs, VPCs, NACLs, flow_log config)        │
│                   + Tier 2 (VPC flow log events, CloudTrail)           │
│                   + Tier 3 (threat intel IOCs for IP matching)         │
│                                                                         │
│  engine_supplychain: Tier 1 (CodeCommit, CodeArtifact, Lambda)         │
│                    + Tier 3 (GitHub repos, npm/PyPI, NVD CVEs)         │
│                                                                         │
│  engine_api:        Tier 1 (API GW stages, ALB, WAF, AppSync)         │
│                   + Tier 2 (API access logs from CloudWatch)           │
│                                                                         │
│  engine_risk:       Reads ALL engine output tables (no collectors)      │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Collector Output Tables (Where Data Lands)

| Tier | Table | Written By | Read By | Retention |
|------|-------|------------|---------|-----------|
| **Tier 1** | `discovery_findings` | discoveries engine | ALL engines | Per scan (replaced each cycle) |
| **Tier 2** | `log_events` | log_collector | network, api | 30 days rolling |
| **Tier 2** | `event_aggregations` | log_collector | network, api | 90 days rolling |
| **Tier 2** | `cloudtrail_events` | log_collector | threat, network | 30 days rolling |
| **Tier 3** | `external_findings` | external_collector | container, supplychain | Per scan |
| **Tier 3** | `vuln_cache` | external_collector | container, supplychain, risk | 24h TTL (refreshed daily) |
| **Tier 3** | `package_metadata` | external_collector | supplychain | 24h TTL |
| **Tier 3** | `threat_intel_ioc` | external_collector | network, threat | 6h TTL |
| **Tier 3** | `registry_images` | external_collector | container | Per scan |

### Credential Management (Per Tier)

| Tier | Credential Source | Secrets Manager Key | Notes |
|------|------------------|--------------------|----|
| Tier 1 | AWS IAM Roles (IRSA) | `threat-engine/rds-credentials` | Existing — no change |
| Tier 2 | AWS IAM Roles (IRSA) | Same as Tier 1 (S3/CW access via role) | Same IRSA role, different permissions |
| Tier 3 — Docker Hub | Docker Hub PAT | `threat-engine/dockerhub-token` | NEW — read-only PAT |
| Tier 3 — GitHub | GitHub App or PAT | `threat-engine/github-token` | NEW — repo read access |
| Tier 3 — GitLab | GitLab token | `threat-engine/gitlab-token` | NEW — repo read access |
| Tier 3 — NVD | NVD API key | `threat-engine/nvd-api-key` | NEW — free registration |
| Tier 3 — Threat Intel | AbuseIPDB/OTX keys | `threat-engine/threatintel-keys` | NEW — API keys |

---

## Full Pipeline (Updated with 3 Tiers)

```
LAYER 0    onboarding ──SQS──► pipeline_worker

LAYER 0.5  COLLECTION (parallel — all 3 tiers run simultaneously)
           ┌─ Tier 1: discoveries engine (CSP config via boto3)
           ├─ Tier 2: log_collector (VPC flow logs, CloudTrail, API access logs)
           └─ Tier 3: external_collector (Docker Hub, GitHub, NVD, npm/PyPI, threat intel)

LAYER 1 — POST-COLLECTION (parallel, all collector data available)
           inventory
           engine_container  [NEW — Port 8006]
           engine_api        [NEW — Port 8021]

LAYER 2 — POSTURE CHECK
           check
           iam
           secops
           vulnerability
           engine_network    [NEW — Port 8007]

LAYER 3 — ENRICHMENT & CORRELATION
           threat
           datasec
           engine_supplychain  [NEW — Port 8008]

LAYER 4 — AGGREGATION
           compliance
           engine_risk  [NEW — Port 8009]

OUTPUT     Reports / Dashboard / Alerts / API
```

**Key change:** Layer 0.5 is new — all 3 collectors run in parallel *before* any engine starts. This guarantees every engine has all the data it needs (CSP config + logs + external) when it runs.

### Per-Engine 4-Stage Processing Model

Unlike discoveries (which extracts fields during the API call), the new engines separate collection from processing. Each engine runs 4 distinct stages:

```
STAGE 1 — ETL (Transform)
  Read raw data from multiple collector tables (Tier 1 + 2 + 3) and other engine tables
  Join, enrich, normalize into engine-specific input shape
  Write → {engine}_input_transformed  (intermediate table, engine-owned)

STAGE 2 — EVALUATE (Apply Rules)
  Read {engine}_rules (DB-driven, is_active toggle)
  Evaluate conditions against {engine}_input_transformed rows
  Write → {engine}_findings  (PASS/FAIL/SKIP/ERROR per rule per resource)

STAGE 3 — REPORT (Aggregate)
  Aggregate findings: counts by severity, top failing rules, trends
  Write → {engine}_report  (one row per scan, matches existing convention)

STAGE 4 — COORDINATE
  Update scan_orchestration.{engine}_scan_id
  Notify pipeline_worker: "done"
```

**Why separate ETL from evaluation?**
- Multiple collectors dump raw data in different shapes
- ETL joins across Tier 1 + 2 + 3 + other engines into a single flat/enriched input
- Rules engine evaluates against this clean, pre-joined data
- Different engines can ETL the same raw data differently for their needs

### Table Naming Convention (Matches Existing Engines)

```
Existing pattern (from discoveries, check, threat, compliance, etc.):
  {engine}_report              → scan-level metadata (1 row per scan)
  {engine}_findings            → individual results (PASS/FAIL per rule per resource)
  {engine}_rules / rule_*      → rule definitions

New pattern (adds ETL intermediate):
  {engine}_report              → scan-level summary and metadata
  {engine}_input_transformed   → ETL output: joined, enriched, ready for rule evaluation
  {engine}_rules               → rule definitions (condition JSONB, severity, frameworks)
  {engine}_findings            → rule evaluation results (PASS/FAIL with evidence)
  {engine}_*                   → engine-specific output tables (topology, sbom, etc.)
```

### Complete Per-Engine Table Map

| Engine | _report | _input_transformed | _rules | _findings | Engine-Specific Tables |
|--------|---------|-------------------|--------|-----------|----------------------|
| **container** | container_report | container_input_transformed | container_rules | container_findings | container_images, container_sbom, k8s_policy_findings |
| **network** | network_report | network_input_transformed | network_rules | network_findings | network_topology, network_anomalies, network_baselines |
| **supplychain** | supplychain_report | supplychain_input_transformed | supplychain_rules | supplychain_findings | sbom_manifests, sbom_components |
| **api** | api_report | api_input_transformed | api_rules | api_findings | api_inventory, api_endpoints, api_access_summary |
| **risk** | risk_report | risk_input_transformed | risk_model_config | risk_scenarios | risk_summary, risk_trends |

---

## Phase 0: Foundation — 3-Tier Collection Infrastructure

### 0.1 Tier 1 Enhancement — New rule_discoveries Rows
Extend the existing discoveries engine with new CSP config collection points required by the new engines. No new code — only DB seeding rows that the existing discoveries engine will execute.

Each task adds new resource_type rows to the `rule_discoveries` table, following the existing boto3 pattern from NEW_ENGINE_DATA_SOURCES.md Category A.

#### Task 0.1.1: Seed ECR Image Discovery `[Seq 1 | BD]`
**Story:** As the discoveries engine, I need to enumerate images within ECR repositories so that engine_container knows which images to scan for CVEs before and after they're deployed.

**Implementation Details:**
- Location: `shared/database/seeds/seed_rule_discoveries_new_engines.sql`
- Rule type: boto3 pattern (no code change)
- Primary API call: `ecr:describe_repositories` → list all repos
- Detail API call: `ecr:describe_images` per repository → list image tags, digests, push dates, scan status
- Output: `discovery_findings` table rows with `resource_type='aws.ecr.repository'` and `'aws.ecr.image'`
- Emitted fields: repository_name, repository_arn, registry_id, image_digest, image_tags, image_size_bytes, pushed_at, scan_status, image_scan_on_push, encryption_type
- Dependencies: None (existing discoveries engine used as-is)
- Consumed by: engine_container (Stage 1 ETL), engine_supplychain (cross-engine for SBOM aggregation)
- Reference: NEW_ENGINE_DATA_SOURCES.md Category A1 (Container Registry Images)

#### Task 0.1.2: Seed K8s Workload Discovery `[Seq 2 | BD]`
**Story:** As the discoveries engine, I need to enumerate running Kubernetes pods, deployments, and daemonsets from EKS clusters so that engine_container knows which container images are live and can verify their security contexts.

**Implementation Details:**
- Location: `shared/database/seeds/seed_rule_discoveries_new_engines.sql`
- Rule type: Kubernetes client pattern (differs from boto3 — uses K8s API)
- Primary: For each EKS cluster in `discovery_findings WHERE resource_type='aws.eks.cluster'`, use cluster endpoint + IRSA token
- K8s API calls: `list_pod_for_all_namespaces`, `list_deployments_for_all_namespaces`, `list_daemonsets_for_all_namespaces`
- Output: `discovery_findings` with `resource_type='aws.eks.pod'`, `'aws.eks.deployment'`, `'aws.eks.daemonset'`
- Emitted fields per pod: namespace, pod_name, cluster_name, node_name, phase, service_account, containers (image, ports, security_context.privileged, security_context.runAsRoot, resources.limits/requests), host_network, host_pid
- Dependencies: EKS clusters must already be in discovery_findings (existing discoveries engine seeds new resource types)
- Consumed by: engine_container (pod security context checks, image inventory)
- Reference: NEW_ENGINE_DATA_SOURCES.md Category A2 (Kubernetes Workloads)

#### Task 0.1.3: Seed ECS Task Definition Discovery `[Seq 3 | BD]`
**Story:** As the discoveries engine, I need to extract container definitions from ECS task definitions so that engine_container can assess image security and engine_supplychain can find manifest files in code references.

**Implementation Details:**
- Location: `shared/database/seeds/seed_rule_discoveries_new_engines.sql`
- Rule type: boto3 pattern
- Primary API call: `ecs:list_task_definitions` → list ARNs
- Detail API call: `ecs:describe_task_definition` per ARN → extract container definitions
- Output: `discovery_findings` with `resource_type='aws.ecs.task_definition'`
- Emitted fields: task_definition_arn, family, revision, containers (name, image, image_pull_policy, environment, mount_points, security_context), execution_role_arn, task_role_arn, requires_compatibilities
- Dependencies: None
- Consumed by: engine_container (image/security context inventory), engine_supplychain (manifest reference tracking)
- Reference: NEW_ENGINE_DATA_SOURCES.md Category A3 (ECS Task Definitions)

#### Task 0.1.4: Seed Lambda Code Location Discovery `[Seq 4 | BD]`
**Story:** As the discoveries engine, I need to identify Lambda functions and their deployment packages so that engine_supplychain can extract and scan manifests from Lambda code archives.

**Implementation Details:**
- Location: `shared/database/seeds/seed_rule_discoveries_new_engines.sql`
- Rule type: boto3 pattern
- Primary API call: `lambda:list_functions` → list all functions
- Detail API call: `lambda:get_function` per function → extract code location (S3 bucket, key) and runtime
- Output: `discovery_findings` with `resource_type='aws.lambda.function_code'`
- Emitted fields: function_name, function_arn, runtime, code_location (s3_bucket, s3_key), code_size, last_updated, environment_variables (names only, not values)
- Dependencies: None
- Consumed by: engine_supplychain (Stage 1 ETL: download Lambda ZIP → extract manifests)
- Reference: NEW_ENGINE_DATA_SOURCES.md Category A4 (Lambda Function Code)

#### Task 0.1.5: Seed API Gateway Detailed Config Discovery `[Seq 5 | BD]`
**Story:** As the discoveries engine, I need to enumerate API Gateway REST/HTTP APIs, stages, authorizers, and routes so that engine_api can assess API security posture including auth, logging, and WAF integration.

**Implementation Details:**
- Location: `shared/database/seeds/seed_rule_discoveries_new_engines.sql`
- Rule type: boto3 pattern (multiple API calls per API)
- Primary calls: `apigateway:get_rest_apis` (REST APIs), `apigatewayv2:get_apis` (HTTP APIs)
- Detail calls per API:
  - `apigateway:get_stages` → stage config (logging enabled, caching, TLS version)
  - `apigateway:get_authorizers` → auth type (JWT, OAuth, Lambda, IAM), TTL
  - `apigatewayv2:get_routes` → route details (auth type per route, CORS config)
- Output: `discovery_findings` with `resource_type='aws.apigateway.rest_api'`, `'aws.apigateway.stage'`, `'aws.apigateway.authorizer'`, `'aws.apigatewayv2.route'`, `'aws.apigatewayv2.api'`
- Emitted fields: api_id, api_name, api_type (REST|HTTP|WebSocket), stage_name, stage_settings (logging_level, data_trace_enabled, cache_enabled, cache_size, throttle_settings), authorizer_name, auth_type, api_key_selection_expression, minimum_compression_size
- Dependencies: None
- Consumed by: engine_api (Stage 1 ETL: build unified API inventory with auth/logging/TLS config)
- Reference: NEW_ENGINE_DATA_SOURCES.md Category A5 (API Gateway Config)

#### Task 0.1.6: Seed ALB Listeners & Rules Discovery `[Seq 6 | BD]`
**Story:** As the discoveries engine, I need to enumerate ALB listeners and routing rules so that engine_api knows the API endpoints exposed via ALB and their TLS configuration, and engine_network can assess listener security posture.

**Implementation Details:**
- Location: `shared/database/seeds/seed_rule_discoveries_new_engines.sql`
- Rule type: boto3 pattern (ELBv2 API)
- Primary call: `elbv2:describe_load_balancers` → ALBs
- Detail calls per ALB:
  - `elbv2:describe_listeners` → listener config (port, protocol, TLS version, certificate)
  - `elbv2:describe_listener_rules` per listener → routing rules (path/host/header conditions, target groups)
- Output: `discovery_findings` with `resource_type='aws.elbv2.load_balancer'`, `'aws.elbv2.listener'`, `'aws.elbv2.listener_rule'`
- Emitted fields for listener: load_balancer_name, load_balancer_arn, listener_port, listener_protocol, ssl_policy, certificate_arn; for rule: rule_priority, conditions (path_pattern, host_header), target_group_arn
- Dependencies: None
- Consumed by: engine_api (listener inventory with TLS version), engine_network (exposed port checks, WAF association verification)
- Reference: NEW_ENGINE_DATA_SOURCES.md Category A6 (ALB Listeners & Rules)

#### Task 0.1.7: Seed WAF Web ACL Discovery `[Seq 7 | BD]`
**Story:** As the discoveries engine, I need to map WAF Web ACLs to associated resources (ALB, API GW, CloudFront) so that engine_api and engine_network can verify WAF is protecting APIs and network entry points.

**Implementation Details:**
- Location: `shared/database/seeds/seed_rule_discoveries_new_engines.sql`
- Rule type: boto3 pattern (WAFv2 API)
- Primary call: `wafv2:list_web_acls` per region/scope (REGIONAL|CLOUDFRONT)
- Detail calls per WAF:
  - `wafv2:get_web_acl` → ACL rules, IP sets, regex patterns
  - `wafv2:list_resources_for_web_acl` → associated ALBs/API GWs/CloudFront distributions
- Output: `discovery_findings` with `resource_type='aws.wafv2.web_acl'`
- Emitted fields: web_acl_id, web_acl_arn, web_acl_name, scope (REGIONAL|CLOUDFRONT), rules (count, priority, names), default_action (ALLOW|BLOCK), associated_resources (ARN list)
- Dependencies: None
- Consumed by: engine_api (WAF coverage verification), engine_network (WAF association checks)
- Reference: NEW_ENGINE_DATA_SOURCES.md Category A7 (WAF Web ACLs)

#### Task 0.1.8: Seed VPC Flow Log Config Discovery `[Seq 8 | BD]`
**Story:** As the discoveries engine, I need to identify VPC Flow Log configurations so that engine_network can assess which VPCs have logging enabled and detect anomalies in the flow log data stream collected by Tier 2.

**Implementation Details:**
- Location: `shared/database/seeds/seed_rule_discoveries_new_engines.sql`
- Rule type: boto3 pattern (EC2 API)
- Primary call: `ec2:describe_flow_logs` → list all flow logs
- Output: `discovery_findings` with `resource_type='aws.ec2.flow_log'`
- Emitted fields: flow_log_id, flow_log_status (ACTIVE|FAILED), resource_id (VPC/subnet/ENI), resource_type, traffic_type (ACCEPT|REJECT|ALL), log_destination (S3 bucket, CloudWatch log group), log_destination_type, log_format, tags
- Dependencies: None
- Consumed by: engine_network (Stage 1 ETL: verify which VPCs have flow logging enabled, join to log_events table)
- Reference: NEW_ENGINE_DATA_SOURCES.md Category A8 (VPC Flow Log Config)

#### Task 0.1.9: Seed CodeCommit Repositories & Manifest Files Discovery `[Seq 9 | BD]`
**Story:** As the discoveries engine, I need to enumerate CodeCommit repositories and extract manifest files so that engine_supplychain can scan dependencies and detect supply chain risks in internal code repositories.

**Implementation Details:**
- Location: `shared/database/seeds/seed_rule_discoveries_new_engines.sql`
- Rule type: boto3 pattern (CodeCommit API)
- Primary call: `codecommit:list_repositories` → list all repos
- Detail calls per repo:
  - `codecommit:get_repository_metadata` → repo info
  - `codecommit:get_file` for manifest files (package.json, requirements.txt, go.mod, pom.xml, Gemfile, Cargo.toml, composer.json) → extract contents
- Output: `discovery_findings` with `resource_type='aws.codecommit.repository'`, `'aws.codecommit.manifest_file'`
- Emitted fields for repo: repository_name, repository_arn, clone_url_https, default_branch, creation_date; for manifest: file_path, file_content (raw text)
- Dependencies: None
- Consumed by: engine_supplychain (Stage 1 ETL: manifest_parser extracts dependencies, cross-references against vuln_cache)
- Reference: NEW_ENGINE_DATA_SOURCES.md Category A9 (CodeCommit Repos & Manifests)

#### Task 0.1.10: Seed CodeArtifact Packages Discovery `[Seq 10 | BD]`
**Story:** As the discoveries engine, I need to enumerate internal CodeArtifact packages so that engine_supplychain can detect dependency confusion attacks where external packages shadow internal packages.

**Implementation Details:**
- Location: `shared/database/seeds/seed_rule_discoveries_new_engines.sql`
- Rule type: boto3 pattern (CodeArtifact API)
- Primary calls: `codeartifact:list_repositories` → repositories, `codeartifact:list_domains` → domains
- Detail calls per repo: `codeartifact:list_packages` per domain/repo → package list
- Output: `discovery_findings` with `resource_type='aws.codeartifact.repository'`, `'aws.codeartifact.package'`
- Emitted fields for repo: domain, repository_name, repository_arn, description; for package: package_name, format (npm|pypi|maven|generic), latest_version
- Dependencies: None
- Consumed by: engine_supplychain (Stage 1 ETL: check against package_metadata for dep confusion — flag if internal name exists on public registry)
- Reference: NEW_ENGINE_DATA_SOURCES.md Category A10 (CodeArtifact Packages)

#### Task 0.1.11: Seed AppSync GraphQL API Discovery `[Seq 11 | BD]`
**Story:** As the discoveries engine, I need to enumerate AppSync GraphQL APIs and their auth configurations so that engine_api can verify API security including auth type and logging setup.

**Implementation Details:**
- Location: `shared/database/seeds/seed_rule_discoveries_new_engines.sql`
- Rule type: boto3 pattern (AppSync API)
- Primary call: `appsync:list_graphql_apis` → list APIs
- Detail calls per API: `appsync:get_graphql_api` → auth config, logging config
- Output: `discovery_findings` with `resource_type='aws.appsync.graphql_api'`
- Emitted fields: api_id, api_name, auth_type (API_KEY|AWS_IAM|OPENID_CONNECT|AMAZON_COGNITO_USER_POOLS|AWS_LAMBDA), logging_enabled, log_role_arn, waf_enabled
- Dependencies: None
- Consumed by: engine_api (auth type inventory, logging verification)
- Reference: NEW_ENGINE_DATA_SOURCES.md Category A11 (AppSync GraphQL API)

#### Task 0.1.12: Seed CloudWatch Log Groups Discovery `[Seq 12 | BD]`
**Story:** As the discoveries engine, I need to identify CloudWatch log groups so that engine_api and engine_network know which APIs and endpoints have logging enabled and from which log groups the log_collector should ingest API access logs.

**Implementation Details:**
- Location: `shared/database/seeds/seed_rule_discoveries_new_engines.sql`
- Rule type: boto3 pattern (CloudWatch Logs API)
- Primary call: `logs:describe_log_groups` → list all log groups
- Output: `discovery_findings` with `resource_type='aws.logs.log_group'`
- Emitted fields: log_group_name, retention_in_days, stored_bytes, creation_time, kms_key_id
- Dependencies: None
- Consumed by: engine_api (Stage 1 ETL: verify API GW/ALB have associated log groups), engine_network (Stage 1 ETL: verify which log groups contain flow logs, API access logs)
- Reference: NEW_ENGINE_DATA_SOURCES.md Category A12 (CloudWatch Log Groups)

**Deliverable:** `shared/database/seeds/seed_rule_discoveries_new_engines.sql` containing all 12 rule_discoveries insert statements

---

### 0.2 Tier 2 — Log & Event Collector Service (NEW)
**Location:** `shared/log_collector/`
**Port:** 8030 | **DB:** `threat_engine_logs`
**K8s:** `log-collector.yaml` (Deployment + Service) + `log-collector-worker.yaml` (SQS consumer)

A single shared service that collects ALL log/event stream data from AWS. Engines never touch S3 or CloudWatch directly — they read from the collector's output tables. Tier 2 follows the 3-tier model architecture (see PROJECT_PLAN.md lines 26-47 and NEW_ENGINES_ARCHITECTURE.md).

#### Task 0.2.1: Create Log Collector Database Schema `[Seq 13 | DE]`
**Story:** As the log_collector service, I need a dedicated database with properly indexed tables to store parsed events from VPC flow logs, CloudTrail, API access logs, and K8s audit logs so that all other services can read aggregated data without duplicating collection logic.

**Implementation Details:**
- Location: `shared/database/schemas/log_collector_schema.sql`
- Tables created: log_events, event_aggregations, cloudtrail_events, log_collection_status, log_sources
- Indexes: (source_type, tenant_id, event_time), (src_ip, dst_ip), (event_name), partial index on event_time for time-range queries
- Schema reference: Inline at lines 290-333 of this file (OUTPUT TABLES section of Phase 0.2)
- Dependencies: None (first task in Tier 2)
- Consumed by: Tasks 0.2.2-0.2.12 (write to these tables), Tasks 2.1-2.10 (engine_network reads log_events/event_aggregations), Tasks 4.1-4.10 (engine_api reads event_aggregations)
- Validation: Run `pg_dump --schema-only threat_engine_logs` to verify 5 tables created with correct columns and indexes

#### Task 0.2.2: Build Log Source Registry `[Seq 14 | BD]`
**Story:** As the log_collector service, I need to track which log sources are configured (S3 buckets, CloudWatch log groups) and their collection schedule so that processors know where to fetch data and when to refresh.

**Implementation Details:**
- Location: `shared/log_collector/log_source_registry.py`
- Input: AWS Secrets Manager references (S3 bucket names, log group names, collection intervals)
- Table: log_sources (source_type, source_name, source_config JSONB, is_active, collection_schedule_minutes, last_collection_time)
- Logic: Read from configmap or environment variables → populate log_sources table with sources like:
  - vpc_flow → S3 bucket containing VPC Flow Logs (from 0.1.8 discovery)
  - cloudtrail → S3 bucket containing CloudTrail events
  - api_access → CloudWatch log group names (from 0.1.12 discovery)
  - k8s_audit → CloudWatch log group name (EKS control plane audit logs)
- Dependencies: 0.2.1 (table must exist)
- Consumed by: 0.2.3-0.2.6 (each processor reads log_sources to know which buckets/groups to check)

#### Task 0.2.3: Build VPC Flow Log Processor `[Seq 15 | BD]`
**Story:** As the log_collector service, I need to download VPC flow log files from S3, decompress and parse the space-separated records, aggregate them into 5-minute windows, and write results to log_events + event_aggregations tables so that engine_network can analyze traffic patterns without touching S3 directly.

**Implementation Details:**
- Location: `shared/log_collector/processors/vpc_flow_processor.py`
- Input: S3 object key from SQS event notification (gz compressed flow log file)
- Processing:
  - s3.get_object(Bucket, Key) → download gz file
  - gzip decompress → text stream
  - Parse space-separated format: version, account-id, interface-id, srcaddr, dstaddr, srcport, dstport, protocol, packets, bytes, start, end, action, log-status
  - Validate each field (e.g., action must be ACCEPT|REJECT)
  - For each record: insert into log_events (source_type='vpc_flow', src_ip, dst_ip, src_port, dst_port, protocol, action, bytes_transferred, packets, event_time from 'start' field)
- Aggregation: GROUP BY (src_ip, dst_ip, dst_port, protocol) per 5-minute window → compute total_bytes, total_packets, flow_count, unique_sources, unique_destinations → insert into event_aggregations
- Output tables: log_events (raw parsed records), event_aggregations (5-min summaries)
- Error handling: skip malformed lines, log parse errors to stderr, continue processing remaining records
- Dependencies: 0.2.1 (DB schema must exist), 0.2.2 (know which S3 bucket to query)
- Consumed by: engine_network (reads event_aggregations for traffic pattern analysis and anomaly detection)
- Reference: NEW_ENGINE_DATA_SOURCES.md Category B1 (VPC Flow Logs)

#### Task 0.2.4: Build CloudTrail Processor `[Seq 16 | BD]`
**Story:** As the log_collector service, I need to download CloudTrail event files from S3, parse the JSON events, normalize the records, and write them to cloudtrail_events table so that engine_threat and engine_network can correlate security events with infrastructure changes.

**Implementation Details:**
- Location: `shared/log_collector/processors/cloudtrail_processor.py`
- Input: S3 object key (CloudTrail multi-file delivery, typically .json.gz)
- Processing:
  - s3.get_object → download gz file
  - gzip decompress → parse JSON (CloudTrail wraps events in { "Records": [{ ... }, ...] })
  - For each event: normalize fields and insert into cloudtrail_events (source_type='cloudtrail', event_name, event_source, event_time, user_identity JSONB, resource_type, resource_id, request_parameters, response_elements, error_code, error_message)
- Normalization: extract common fields (event_name, source, time, user) regardless of service
- Output table: cloudtrail_events (source_type='cloudtrail')
- Error handling: skip malformed JSON, log parse errors, continue
- Dependencies: 0.2.1 (DB schema), 0.2.2 (know which S3 bucket)
- Consumed by: engine_threat (detects suspicious API activity like assume_role, create_access_key), engine_network (detects infrastructure changes affecting network config)
- Reference: NEW_ENGINE_DATA_SOURCES.md Category B5 (CloudTrail Events)

#### Task 0.2.5: Build API Access Log Processor `[Seq 17 | BD]`
**Story:** As the log_collector service, I need to query API access logs from CloudWatch Logs (for API Gateway and ALB access logs), parse the JSON/CLF format, aggregate by endpoint, and write summaries to event_aggregations so that engine_api can assess runtime anomalies like error rate spikes and latency degradation.

**Implementation Details:**
- Location: `shared/log_collector/processors/api_access_processor.py`
- Input: CloudWatch log group names (from log_sources table) for API Gateway and ALB
- Processing:
  - logs.filter_log_events(logGroupName, startTime=now()-24h) → fetch last 24h of logs
  - Parse two formats:
    - API Gateway CloudWatch format (JSON): {"requestId", "ip", "requestTime", "httpMethod", "resourcePath", "status", "protocol", "responseLength", "integrationLatency"}
    - ALB access logs (CLF-based): fields include request_time, elb, client_ip, client_port, target_ip, target_port, request_time_sec, target_processing_time, response_time, elb_status_code, target_status_code, request (METHOD path HTTP/version), user_agent, ssl_cipher, ssl_protocol
  - For each parsed log: insert into log_events (source_type='api_access', event_time, src_ip, dst_port=endpoint, bytes_transferred, protocol, error indicator from status code)
  - Aggregation: GROUP BY (endpoint, method) per 5-minute window → compute error_count (4xx/5xx), p99_latency_ms, unique_sources → insert into event_aggregations
- Output table: event_aggregations (source_type='api_access')
- Dependencies: 0.2.1 (DB schema), 0.2.2 (know which log groups), 0.1.12 (CloudWatch log groups discovered)
- Consumed by: engine_api (runtime anomaly detection, error rate trending)
- Reference: NEW_ENGINE_DATA_SOURCES.md Category B2 (API Access Logs from CloudWatch)

#### Task 0.2.6: Build K8s Audit Log Processor `[Seq 18 | BD]`
**Story:** As the log_collector service, I need to query K8s audit logs from CloudWatch (EKS control plane audit), parse and normalize them, and write to cloudtrail_events table so that engine_threat can correlate pod security events with RBAC changes and detect privilege escalation attempts.

**Implementation Details:**
- Location: `shared/log_collector/processors/k8s_audit_processor.py`
- Input: CloudWatch log group name for EKS control plane audit logs (e.g., /aws/eks/cluster_name/cluster)
- Processing:
  - logs.filter_log_events(logGroupName, startTime=now()-24h) → fetch last 24h
  - Parse K8s audit format (JSON): { "level", "timestamp", "verb", "user", "objectRef", "requestObject", "responseObject", "annotations" }
  - Normalize and insert into cloudtrail_events (source_type='k8s_audit', event_name=verb, event_source='kubernetes', user_identity={username, groups}, resource_type=kind from objectRef, resource_id=name from objectRef, raw_fields=full audit record)
- Output table: cloudtrail_events (source_type='k8s_audit')
- Error handling: skip malformed JSON, log errors, continue
- Dependencies: 0.2.1 (DB schema), EKS audit logging must be enabled (pre-requisite, not this task)
- Consumed by: engine_threat (detects RBAC changes, privilege escalation), engine_network (detects pod security policy changes)
- Reference: NEW_ENGINE_DATA_SOURCES.md Category B5 (K8s Audit Logs)

#### Task 0.2.7: Build SQS Consumer Worker `[Seq 19 | BD]`
**Story:** As the log_collector service, I need to listen for S3 event notifications on an SQS queue, parse the event to extract the S3 object key, and route to the correct processor (VPC flow, CloudTrail, API access) based on the bucket/prefix pattern so that flow log ingestion happens in real-time without polling.

**Implementation Details:**
- Location: `shared/log_collector/sqs_worker.py`
- Architecture: Long-running process that calls `sqs.receive_message(QueueUrl, MaxNumberOfMessages=10, WaitTimeSeconds=20)` in a loop
- Processing per message:
  - Parse SQS body (S3 event notification JSON)
  - Extract bucket name and object key
  - Match key pattern to source_type: if key contains "AWSLogs/.../VPCFlowLogs/" → vpc_flow; if "cloudtrail/" → cloudtrail; etc.
  - Instantiate correct processor (vpc_flow_processor, cloudtrail_processor, etc.)
  - Call processor.process(bucket, key)
  - Delete message from queue on success
  - Re-drive to DLQ on error after 3 retries
- K8s deployment: log-collector-worker.yaml (separate Deployment from API pod, scale 1-3 with HPA based on queue depth)
- Dependencies: 0.2.3-0.2.6 (all processors must exist)
- Consumed by: api_server.py (coordinates with SQS workers)

#### Task 0.2.8: Build IP Resolver `[Seq 20 | BD]`
**Story:** As the log_collector service, I need to resolve IP addresses in flow logs to AWS resource IDs (EC2 instance IDs, RDS endpoints, ALB names) by joining against discovery_findings so that findings correlate network events to specific resources.

**Implementation Details:**
- Location: `shared/log_collector/ip_resolver.py`
- Logic: When processing log_events (vpc_flow, api_access), for each src_ip/dst_ip:
  - Query discovery_findings WHERE resource_type IN ('aws.ec2.instance', 'aws.rds.db_instance', 'aws.elbv2.load_balancer', ...) and emitted_fields contains the IP
  - Cache results in a local dict (max 10k entries, 1h TTL) to avoid N+1 queries
  - If found: set resource_id in log_events
  - If not found: leave resource_id NULL (external IP)
- Input: log_events rows with src_ip/dst_ip but resource_id=NULL
- Output: Updated log_events rows with resource_id populated (or NULL if unresolvable)
- Dependencies: 0.2.1 (log_events table), Tier 1 discoveries (discovery_findings table must be populated)
- Consumed by: 0.2.7 (before inserting into log_events, call ip_resolver)

#### Task 0.2.9: Build Retention Manager `[Seq 21 | BD]`
**Story:** As the log_collector service, I need to automatically delete old log events beyond the retention window so that the log_events table doesn't grow unboundedly and stays performant.

**Implementation Details:**
- Location: `shared/log_collector/retention_manager.py`
- Schedule: Cron job running daily at 02:00 UTC
- Logic:
  - DELETE FROM log_events WHERE source_type='vpc_flow' AND created_at < NOW() - INTERVAL '30 days'
  - DELETE FROM event_aggregations WHERE source_type='api_access' AND created_at < NOW() - INTERVAL '90 days'
  - DELETE FROM cloudtrail_events WHERE created_at < NOW() - INTERVAL '30 days'
  - Log number of rows deleted
- K8s deployment: CronJob resource in log-collector.yaml
- Dependencies: 0.2.1 (tables exist)
- Consumed by: 0.2.10 (API server coordinates with retention manager)

#### Task 0.2.10: Build API Server `[Seq 22 | AD]`
**Story:** As the log_collector service, I need to expose a FastAPI server on port 8030 that accepts on-demand collection requests from the pipeline_worker so that log collection can be triggered synchronously as part of the scan orchestration.

**Implementation Details:**
- Location: `shared/log_collector/api_server.py`
- Endpoints:
  - `POST /api/v1/collect` → trigger collection for all log sources (VPC flow, CloudTrail, API access, K8s audit) sequentially
  - `POST /api/v1/collect/{source_type}` → trigger collection for specific source (vpc_flow|cloudtrail|api_access|k8s_audit)
  - `GET /api/v1/status` → return status of last collection per source_type (success|failed, row count, duration)
  - `GET /api/v1/health/live` and `GET /api/v1/health/ready` → Kubernetes probes
- Implementation: FastAPI async endpoints, each calls the corresponding processor module
- Error handling: Return 500 if processor fails, include error message in response
- Dependencies: 0.2.3-0.2.9 (all processors and utilities)
- Consumed by: Task 0.2.11 (Dockerfile), Task 0.2.12 (unit tests), Task 6.1 (pipeline_worker trigger functions)

#### Task 0.2.11: Create Dockerfile & K8s Manifests `[Seq 23 | DO]`
**Story:** As the DevOps/infrastructure team, I need to package the log_collector service as a Docker image and create Kubernetes manifests for API and SQS worker deployments so that the service can run in EKS.

**Implementation Details:**
- Location:
  - `shared/log_collector/Dockerfile` (multi-stage, Python 3.11, ~150MB)
  - `deployment/aws/eks/engines/log-collector.yaml` (Deployment for API, 1 replica, port 8030)
  - `deployment/aws/eks/engines/log-collector-worker.yaml` (Deployment for SQS consumer, 1-3 replicas with HPA)
- Dockerfile:
  - Base: python:3.11-slim
  - Install: boto3, psycopg2, fastapi, uvicorn, pydantic
  - Copy: shared/log_collector/, shared/common/, shared/database/
  - Entrypoint: configurable (api_server.py or sqs_worker.py)
- K8s Deployment (API):
  - Namespace: threat-engine-engines
  - Image: yadavanup84/threat-engine-log-collector:latest
  - Resources: requests {cpu: 500m, memory: 512Mi}, limits {cpu: 1000m, memory: 1Gi}
  - Env: TH_LOG_COLLECTOR_PORT=8030, TH_DB_* (from ConfigMap), AWS_ROLE_ARN, AWS_WEB_IDENTITY_TOKEN_FILE (IRSA)
  - Liveness/Readiness probes: /api/v1/health/live and /api/v1/health/ready (every 30s)
  - Service: ClusterIP on port 8030
- K8s Deployment (SQS worker):
  - Namespace: threat-engine-engines
  - Image: same as API
  - Entrypoint: sqs_worker.py
  - Resources: requests {cpu: 250m, memory: 256Mi}, limits {cpu: 500m, memory: 512Mi}
  - Replicas: 1, HPA target: 3 when SQS queue depth > 100 messages
  - Env: TH_SQS_QUEUE_URL, TH_DB_* (from ConfigMap)
- Dependencies: 0.2.10 (api_server.py complete)
- Consumed by: Task 0.2.12 (unit tests), Task 6.6 (ingress routing), Task 6.5 (ConfigMap references)

#### Task 0.2.12: Unit Tests `[Seq 24 | QA]`
**Story:** As the QA/testing team, I need to write unit tests for log_collector processors and utilities to verify correctness of parsing and aggregation logic before deployment.

**Implementation Details:**
- Location: `shared/log_collector/tests/`
- Test files:
  - `test_vpc_flow_processor.py` (10 tests): parse valid/invalid records, aggregation logic, edge cases (zero packets, timeout events)
  - `test_cloudtrail_processor.py` (8 tests): parse JSON, extract event_name/user_identity, skip malformed
  - `test_api_access_processor.py` (8 tests): parse API GW format and ALB CLF format, error rate calculation, p99 latency
  - `test_ip_resolver.py` (6 tests): mock discovery_findings queries, caching behavior
  - `test_rule_evaluator.py` (already in shared/common/tests, reuse)
- Mocking: Use pytest fixtures for s3.get_object, logs.filter_log_events, DB connection
- Coverage target: >80%
- Run: `pytest shared/log_collector/tests/ -v`
- Dependencies: 0.2.10 (all code complete)
- Consumed by: Tasks 2.1-2.10 (engine_network depends on log_collector running), Tasks 4.1-4.10 (engine_api depends on log_collector running), Task 6.7 (pipeline integration test)

**Key Design — Tier 2 Architecture:**
- Two deployment modes: API pod (on-demand), SQS worker (real-time)
- Processors are stateless — can be scaled independently
- Output tables are append-only (no updates), enabling simple retention management
- Aggregation is lossy by design (5-min windows) to manage volume
- All log data is time-windowed and keyed by (tenant_id, account_id, region) for multi-tenancy

**Output Tables (from lines 290-333):** log_events, event_aggregations, cloudtrail_events

---

### 0.3 Tier 3 — External Source Collector Service (NEW)
**Location:** `shared/external_collector/`
**Port:** 8031 | **DB:** `threat_engine_external`
**K8s:** `external-collector.yaml` (Deployment + Service)

A single shared service that handles ALL non-CSP external API calls (container registries, GitHub, NVD, npm, PyPI, threat intel feeds). Manages its own credential rotation, rate limiting, and caching per NEW_ENGINES_ARCHITECTURE.md and NEW_ENGINE_DATA_SOURCES.md Category B2-B4.

#### Task 0.3.1: Create External Collector Database Schema `[Seq 25 | DE]`
**Story:** As the external_collector service, I need a dedicated database with tables for storing external data (container images, CVE records, package info, threat intel IOCs) and their refresh status so that engines can query cached data and the service knows what needs refreshing.

**Implementation Details:**
- Location: `shared/database/schemas/external_collector_schema.sql`
- Tables created: registry_images, vuln_cache, package_metadata, threat_intel_ioc, collection_status
- Indexes: (registry_type, repository), (cve_id), (purl), (indicator_value), unique constraints per table
- Schema reference: Inline at lines 366-434 of this file (OUTPUT TABLES section of Phase 0.3)
- Dependencies: None (first task in Tier 3)
- Consumed by: Tasks 0.3.2-0.3.17 (write to these tables), Tasks 1.1-1.10 (engine_container reads registry_images/vuln_cache), Tasks 2.1-2.10 (engine_network reads threat_intel_ioc), Tasks 3.1-3.11 (engine_supplychain reads vuln_cache/package_metadata), Tasks 5.1-5.11 (engine_risk reads vuln_cache for EPSS)

#### Task 0.3.2: Build Credential Manager `[Seq 26 | BD]`
**Story:** As the external_collector service, I need to securely retrieve and rotate authentication tokens from AWS Secrets Manager so that API calls to external services are authenticated without hardcoding credentials in code.

**Implementation Details:**
- Location: `shared/external_collector/credential_manager.py`
- Credentials managed (from Secrets Manager):
  - `threat-engine/dockerhub-token` (Docker Hub PAT)
  - `threat-engine/github-token` (GitHub PAT or App key)
  - `threat-engine/gitlab-token` (GitLab token)
  - `threat-engine/nvd-api-key` (NVD API key)
  - `threat-engine/threatintel-keys` (AbuseIPDB, OTX API keys)
- Logic:
  - On service startup: load all credentials from Secrets Manager
  - Store in memory with refresh timestamp
  - Every 1 hour: check if any credential is stale (>55min old) → refresh from Secrets Manager
  - Provide method: `get_credential(service_name)` → returns token
  - Error handling: Log refresh failures, retry on next interval, fall back to in-memory value
- Dependencies: AWS IAM role with `secretsmanager:GetSecretValue` permission (IRSA)
- Consumed by: Tasks 0.3.3, 0.3.5, 0.3.6, 0.3.9, 0.3.10 (all adapters requiring authentication)

#### Task 0.3.3: Build Container Registry Adapter `[Seq 27 | BD]`
**Story:** As the external_collector service, I need to fetch container image metadata (manifests, tags, layers, sizes) from multiple registries (Docker Hub, ECR, GCR, ACR, Quay) via their HTTP APIs so that engine_container knows what images are available to scan.

**Implementation Details:**
- Location: `shared/external_collector/adapters/registry_adapter.py`
- Unified interface for 5 registries:
  - **Docker Hub**: REST API `/v2/token` (auth), `/v2/{name}/manifests/{reference}` (get manifest), `/v2/{name}/tags/list` (list tags)
  - **ECR**: AWS API (boto3) `describe_images` (already in Tier 1, but also refresh manifest via registry API)
  - **GCR**: OAuth + REST API `https://gcr.io/v2/{project}/{image}/...`
  - **ACR**: Azure token endpoint + REST API
  - **Quay**: REST API with API key auth
- Input: {registry_type, repository, tag}
- Output: {digest, layers, config, media_type, os, architecture, size_bytes, pushed_at}
- Auth:
  - Docker Hub: Use PAT via credential_manager
  - ECR: boto3 get_authorization_token (IRSA)
  - GCR: OAuth2 service account (IRSA)
  - ACR: Azure token (credential from Secrets Manager)
  - Quay: API key (credential from Secrets Manager)
- Caching: 24h TTL in memory (not DB) for manifests
- Rate limiting: Per-registry limits (Docker Hub 200/6hr, others higher)
- Dependencies: 0.3.2 (credential_manager)

#### Task 0.3.4: Build Trivy Scanner Wrapper `[Seq 28 | BD]`
**Story:** As the external_collector service, I need to run Trivy vulnerability scanner on container images to extract CVE lists and Software Bill of Materials (SBOM) so that engine_container and engine_supplychain can assess image and dependency security.

**Implementation Details:**
- Location: `shared/external_collector/scanners/trivy_scanner.py`
- Integration:
  - Trivy binary embedded in Dockerfile (curl + download latest)
  - Trivy DB embedded (~120MB) in image, updated daily via init container
  - Each scan: run `trivy image --format json {image:tag}` as subprocess
  - Parse JSON output:
    - Extract CVE list (cve_id, package_name, installed_version, severity, fixed_version)
    - Extract SBOM (package list with versions, ecosystem)
    - Store trivy_output JSONB in registry_images table
    - Extract sbom as JSONB in CycloneDX format
- Input: {registry_type, repository, tag, digest}
- Output: {cve_list, sbom, scan_status, scan_time}
- Error handling: Capture stderr, log scan errors, mark as scan_status='failed'
- Performance: Scans run in parallel (up to 3 concurrent Trivy processes)
- Dependencies: 0.3.3 (registry_adapter must fetch image first), 0.3.1 (DB table to store results)

#### Task 0.3.5: Build GitHub/GitLab Adapter `[Seq 29 | BD]`
**Story:** As the external_collector service, I need to fetch repository metadata and manifest files from GitHub and GitLab so that engine_supplychain can extract and scan dependencies from code repositories.

**Implementation Details:**
- Location: `shared/external_collector/adapters/code_repo_adapter.py`
- APIs:
  - **GitHub**: GraphQL API (higher rate limit than REST)
    - Query: `query { repositories(first: 100) { nodes { name, url, owner { login } } } }` → list repos
    - Per repo: fetch manifest files (package.json, requirements.txt, go.mod, pom.xml, Gemfile, Cargo.toml, composer.json)
    - Rate limit: 5000 points/hour (GraphQL tokens)
  - **GitLab**: REST API `/api/v4/projects` → list projects, `/api/v4/projects/{id}/repository/tree` → list files, `/api/v4/projects/{id}/repository/files/{path}/raw` → get file content
    - Rate limit: 600/minute
- Input: {git_provider, org_or_account_id} (or auto-discover from Tier 1)
- Output: Insert rows into external_findings table with {repo_name, repo_url, manifest_file, file_content}
- Error handling: Skip private repos (403 Forbidden), log rate limit hits, respect Retry-After headers
- Caching: 24h TTL for manifest file contents
- Dependencies: 0.3.2 (credential_manager for GitHub/GitLab tokens), 0.3.1 (DB table)

#### Task 0.3.6: Build NVD/CVE Adapter `[Seq 30 | BD]`
**Story:** As the external_collector service, I need to fetch CVE data from the National Vulnerability Database (NVD) including CVSS scores, affected CPE versions, and fix versions so that engine_container and engine_supplychain can assess which packages/images are vulnerable.

**Implementation Details:**
- Location: `shared/external_collector/adapters/nvd_adapter.py`
- API: NVD REST API v1.0 (`https://services.nvd.nist.gov/rest/json/cves/2.0`)
- Modes:
  - **On-demand**: Query by CVE ID (`/cves/2.0?cveId=CVE-2024-1234`)
  - **Bulk refresh**: Download full CVE dataset (daily), parse into vuln_cache table
- Fields extracted per CVE: cve_id, cvss_v3_score, cvss_v3_vector, severity, description, affected_cpe[] (CPE URI list), fix_versions[]
- Output: Insert/update vuln_cache table with CVE data
- Rate limiting: 50 requests per 30 seconds (free tier), use API key to increase if available
- Caching: 24h TTL on vuln_cache table (refreshed daily via scheduler)
- Dependencies: 0.3.2 (credential_manager for NVD API key), 0.3.1 (vuln_cache table)

#### Task 0.3.7: Build EPSS Adapter `[Seq 31 | BD]`
**Story:** As the external_collector service, I need to fetch EPSS (Exploit Prediction Scoring System) scores from FIRST.org so that engine_container and engine_risk can prioritize vulnerabilities by likelihood of exploitation.

**Implementation Details:**
- Location: `shared/external_collector/adapters/epss_adapter.py`
- Data source: EPSS CSV file (`https://api.first.org/data/v1/epss/`)
- Process:
  - Download CSV daily (typically 150KB)
  - Parse rows: cve_id, epss_score (0-1), epss_percentile (0-100)
  - For each row: UPDATE vuln_cache SET epss_score = {score} WHERE cve_id = {cve_id}
- Timing: Run after NVD adapter (to ensure CVEs exist before adding EPSS scores)
- Dependencies: 0.3.6 (CVEs must exist in vuln_cache), 0.3.1 (DB table)

#### Task 0.3.8: Build KEV Adapter `[Seq 32 | BD]`
**Story:** As the external_collector service, I need to fetch the CISA Known Exploited Vulnerabilities (KEV) catalog so that engine_container, engine_supplychain, and engine_risk can flag vulnerabilities that are actively being exploited in the wild.

**Implementation Details:**
- Location: `shared/external_collector/adapters/kev_adapter.py`
- Data source: CISA KEV JSON (`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`)
- Process:
  - Download JSON daily
  - Parse: { "vulnerabilities": [ { "cveID", "knownRansomwareCampaignUse", "dateAdded", "dueDate" } ] }
  - For each KEV entry: UPDATE vuln_cache SET is_kev=true, kev_due_date={dueDate} WHERE cve_id={cveID}
- Output: Mark KEV CVEs in vuln_cache table
- Timing: Run after NVD adapter
- Dependencies: 0.3.6 (CVEs must exist), 0.3.1 (DB table)

#### Task 0.3.9: Build Package Registry Adapter `[Seq 33 | BD]`
**Story:** As the external_collector service, I need to query public package registries (npm, PyPI, Maven Central, crates.io) to detect dependency confusion attacks where internal package names are shadowed by public packages, and to gather package metadata for provenance checks.

**Implementation Details:**
- Location: `shared/external_collector/adapters/package_registry_adapter.py`
- APIs:
  - **npm**: `https://registry.npmjs.org/{package_name}` (JSON)
  - **PyPI**: `https://pypi.org/pypi/{package_name}/json`
  - **Maven Central**: `https://central.maven.org/search/solrsearch/select?q=a:{package_name}`
  - **crates.io**: `https://crates.io/api/v1/crates/{package_name}`
- Per package: Extract {latest_version, publish_date, maintainer_count, license, weekly_downloads, deprecated}
- Output: INSERT into package_metadata table
- Use case: engine_supplychain checks if internal package name (e.g., @acmecorp/auth) exists on public registry (dep confusion check)
- Caching: 24h TTL on package_metadata
- Dependencies: 0.3.1 (DB table), 0.3.2 (rate limiting)

#### Task 0.3.10: Build Threat Intel Adapter `[Seq 34 | BD]`
**Story:** As the external_collector service, I need to fetch threat intelligence indicators (malicious IPs, domains, file hashes) from multiple sources (CISA KEV, AbuseIPDB, OTX) so that engine_network and engine_threat can detect communication with known malicious entities.

**Implementation Details:**
- Location: `shared/external_collector/adapters/threat_intel_adapter.py`
- Sources:
  - **CISA KEV**: Already handled by 0.3.8 (marks CVEs as exploited)
  - **AbuseIPDB**: REST API, query by IP address → confidence score, threat_types (malware, spambot, scanner, etc.)
  - **OTX (AlienVault)**: REST API `/api/v1/pulses/subscribed` → fetch IOC feeds (IPs, domains, file hashes)
  - **VirusTotal**: REST API `/api/v3/domains/{domain}` or `/api/v3/ips/{ip}` (optional, if we have API key)
- Process:
  - Fetch IOC feeds from each source
  - Parse and insert into threat_intel_ioc table (indicator_value, indicator_type, source, confidence, threat_type)
  - 6h TTL refresh (IOCs change rapidly)
- Output: threat_intel_ioc table (used by engine_network to match src/dst IPs in flow logs)
- Dependencies: 0.3.2 (credential_manager), 0.3.1 (DB table)

#### Task 0.3.11: Build Lambda ZIP Downloader `[Seq 35 | BD]`
**Story:** As the external_collector service, I need to download and extract Lambda function deployment packages from S3 to locate manifest files (package.json, requirements.txt, go.mod) so that engine_supplychain can analyze Lambda dependencies.

**Implementation Details:**
- Location: `shared/external_collector/handlers/lambda_zip_handler.py`
- Input: {account_id, function_name, code_s3_bucket, code_s3_key} (from Tier 1 discovery)
- Process:
  - Use STS assume_role to get credentials for target account
  - Download ZIP from S3 (assume <50MB, stream to memory)
  - Extract ZIP in memory (do not write to disk)
  - Scan entries for manifest files (package.json, requirements.txt, go.mod, pom.xml, Gemfile, Cargo.toml, composer.json)
  - Extract matching files, return file contents
  - Cache results (24h) in package_metadata table (as reference)
- Error handling: Skip if function uses container image (no ZIP), skip if ZIP > 100MB (too large), log errors
- Dependencies: STS assume_role permission (IRSA), 0.3.1 (DB table)

#### Task 0.3.12: Build Cache Manager `[Seq 36 | BD]`
**Story:** As the external_collector service, I need to manage cache refresh schedules and TTL expiration for vuln_cache, package_metadata, and threat_intel_ioc tables so that data stays fresh without continuously hitting external APIs.

**Implementation Details:**
- Location: `shared/external_collector/cache_manager.py`
- TTL policies:
  - vuln_cache: 24h refresh (NVD + EPSS + KEV daily)
  - package_metadata: 24h refresh (npm, PyPI, Maven queries as-needed, cached by day)
  - threat_intel_ioc: 6h refresh (AbuseIPDB, OTX feeds change frequently)
- Scheduled jobs:
  - Daily 02:00 UTC: Run NVD bulk download → update vuln_cache
  - Daily 03:00 UTC: Run EPSS download → update EPSS scores
  - Daily 03:30 UTC: Run KEV download → flag known exploited vulns
  - Every 6 hours: Run threat intel adapter → refresh IOCs
- Staleness detection: Query refreshed_at timestamp, warn if stale beyond TTL
- Implementation: APScheduler or similar, tracks job status in DB (collection_status table)
- Dependencies: 0.3.6-0.3.10 (all adapters), 0.3.1 (DB table)

#### Task 0.3.13: Build Rate Limiter `[Seq 37 | BD]`
**Story:** As the external_collector service, I need to enforce per-source rate limits so that external API calls don't exceed rate limit thresholds and get blacklisted.

**Implementation Details:**
- Location: `shared/external_collector/rate_limiter.py`
- Rate limits (configured per source):
  - GitHub GraphQL: 5000 points/hour
  - GitLab REST: 600/minute
  - NVD REST: 50/30s (free tier) → 5000/30s with API key
  - npm registry: unlimited (public)
  - PyPI: 60/minute recommended
  - Docker Hub: 200/6 hours (unauthenticated) → higher with token
  - AbuseIPDB: 4000/24h (free)
  - OTX: depends on plan (assume 100/hour)
- Algorithm: Token bucket per source
  - On API call: check if tokens available
  - If yes: decrement and call API
  - If no: sleep and retry, or return cached value
  - Refill: Every interval (depends on rate limit duration)
- Dependencies: 0.3.3-0.3.10 (all adapters)

#### Task 0.3.14: Build API Server `[Seq 38 | AD]`
**Story:** As the external_collector service, I need to expose a FastAPI server on port 8031 that accepts on-demand collection requests from the pipeline_worker so that external data can be refreshed synchronously as part of the scan orchestration.

**Implementation Details:**
- Location: `shared/external_collector/api_server.py`
- Endpoints:
  - `POST /api/v1/collect/{source_type}` (source_type: registry|github|gitlab|nvd|npm|docker_hub|threat_intel) → trigger refresh for specific source
  - `POST /api/v1/collect/all` → trigger all collection tasks in parallel (use asyncio)
  - `GET /api/v1/cache/status` → return cache freshness per source (last_refresh_time, next_scheduled_refresh)
  - `GET /api/v1/health/live` and `/api/v1/health/ready` → K8s probes
- Implementation: FastAPI async, each endpoint spawns background task (does not block response)
- Response: 202 Accepted with task_id, caller can poll `/api/v1/collection/{task_id}/status`
- Error handling: Retry failed collections, return error in status response
- Dependencies: 0.3.3-0.3.13 (all adapters, cache, rate limiter)
- Consumed by: Task 0.3.15 (Dockerfile), Task 0.3.17 (unit tests), Task 6.1 (pipeline_worker trigger functions)

#### Task 0.3.15: Create Dockerfile & K8s Manifest `[Seq 39 | DO]`
**Story:** As the DevOps/infrastructure team, I need to package the external_collector service as a Docker image and create a Kubernetes manifest so that the service runs in EKS.

**Implementation Details:**
- Location:
  - `shared/external_collector/Dockerfile` (multi-stage)
  - `deployment/aws/eks/engines/external-collector.yaml` (Deployment)
- Dockerfile:
  - Base: python:3.11-slim
  - Install: boto3, psycopg2, fastapi, uvicorn, pydantic, requests, cryptography
  - Download: Trivy binary (`curl -fsSL https://github.com/aquasecurity/trivy/releases/download/v0.{version}/trivy_Linux-64bit.tar.gz`)
  - Download: Trivy DB (init container pattern for daily refresh)
  - Copy: shared/external_collector/, shared/common/, shared/database/
  - Entrypoint: api_server.py, background scheduler for cache refresh
  - Total size: ~250MB (Trivy DB is 120MB)
- K8s Deployment:
  - Namespace: threat-engine-engines
  - Image: yadavanup84/threat-engine-external-collector:latest
  - Resources: requests {cpu: 500m, memory: 1Gi}, limits {cpu: 2000m, memory: 2Gi} (for Trivy)
  - Env: TH_EXTERNAL_COLLECTOR_PORT=8031, TH_DB_* (from ConfigMap), credential paths
  - Volumes: Mount Trivy DB from ConfigMap or EmptyDir (refresh daily via init container)
  - InitContainer: Refresh Trivy DB from GitHub releases
  - Liveness/Readiness: /api/v1/health/live (every 30s)
  - Service: ClusterIP on port 8031
  - Security: Read-only root filesystem, non-root user
- Dependencies: 0.3.14 (api_server.py complete)
- Consumed by: Task 0.3.17 (unit tests), Task 6.6 (ingress routing), Task 6.5 (ConfigMap references)

#### Task 0.3.16: Add Secrets Manager Entries `[Seq 40 | DO]`
**Story:** As the infrastructure/security team, I need to create Secrets Manager entries for external API tokens so that the external_collector can authenticate to Docker Hub, GitHub, GitLab, NVD, and threat intel services.

**Implementation Details:**
- Location: (AWS Secrets Manager, created via CloudFormation or Terraform, not code)
- Secrets to create:
  - `threat-engine/dockerhub-token`: Docker Hub Personal Access Token (read-only, image list/pull)
  - `threat-engine/github-token`: GitHub Personal Access Token (repo read access) or GitHub App credentials
  - `threat-engine/gitlab-token`: GitLab token (api access)
  - `threat-engine/nvd-api-key`: NVD API key (free from nvd.nist.gov)
  - `threat-engine/threatintel-keys`: JSON object {abuseipdb_key, otx_api_key, ...}
- Each secret should have:
  - Resource-based policy allowing threat-engine EKS role (IRSA) to read
  - Rotation policy (optional, for manual rotation)
  - Tagging for governance
- K8s integration: ExternalSecrets operator (Helm chart) syncs Secrets Manager → K8s Secret resources
- Dependencies: credential_manager (0.3.2) expects these secrets to exist

#### Task 0.3.17: Unit Tests `[Seq 41 | QA]`
**Story:** As the QA/testing team, I need to write unit tests for external_collector adapters and utilities to verify API response parsing and error handling before deployment.

**Implementation Details:**
- Location: `shared/external_collector/tests/`
- Test files:
  - `test_registry_adapter.py` (12 tests): Docker Hub auth flow, manifest parsing, caching
  - `test_trivy_scanner.py` (8 tests): subprocess execution, JSON parsing, SBOM extraction, timeout handling
  - `test_code_repo_adapter.py` (10 tests): GitHub GraphQL queries, GitLab REST calls, manifest file extraction
  - `test_nvd_adapter.py` (8 tests): NVD API response parsing, bulk download, CPE matching
  - `test_package_registry_adapter.py` (6 tests): npm, PyPI, Maven API parsing
  - `test_threat_intel_adapter.py` (6 tests): IOC feed parsing, deduplication
  - `test_cache_manager.py` (8 tests): TTL expiration, refresh scheduling
  - `test_rate_limiter.py` (8 tests): token bucket, per-source limits
- Mocking: Use pytest-vcr for recording/replaying HTTP responses, mock subprocess calls
- Coverage: >80%
- Run: `pytest shared/external_collector/tests/ -v`
- Dependencies: 0.3.14 (all code complete)
- Consumed by: Tasks 1.1-1.10 (engine_container depends on external_collector running), Tasks 2.1-2.10 (engine_network reads threat_intel_ioc), Tasks 3.1-3.11 (engine_supplychain depends on external_collector), Tasks 5.1-5.11 (engine_risk reads vuln_cache/EPSS), Task 6.7 (pipeline integration test)

**Key Design — Tier 3 Architecture:**
- Single service, multiple adapters for each external source
- Credential manager centralized, credentials never hardcoded
- Rate limiting enforced per source to avoid API blacklisting
- Caching with TTL reduces external API calls (24h vuln, 6h IOCs)
- Trivy embedded in Docker image for air-gapped environments
- All output is cached in DB, engines query cache only (never hit external APIs directly)

**Output Tables (from lines 366-434):** registry_images, vuln_cache, package_metadata, threat_intel_ioc

---

### 0.4 Database Migration (scan_orchestration)
Extend the central scan orchestration table with new columns for the 5 new engines and 2 new collectors.

#### Task 0.4.1: Add scan_orchestration Columns `[Seq 42 | DE]`
**Story:** As the pipeline orchestrator, I need to track scan IDs for the new engines and collectors in the scan_orchestration table so that dependent services know when each stage has completed and can coordinate their start times.

**Implementation Details:**
- Location: `shared/database/migrations/014_add_new_engine_scan_ids.sql`
- Columns added to `scan_orchestration` table:
  - `log_collection_id` UUID (Tier 2) — reference to log_collector scan
  - `external_collection_id` UUID (Tier 3) — reference to external_collector scan
  - `container_scan_id` UUID (engine_container)
  - `network_scan_id` UUID (engine_network)
  - `supplychain_scan_id` UUID (engine_supplychain)
  - `api_scan_id` UUID (engine_api)
  - `risk_scan_id` UUID (engine_risk)
  - `container_scan_status` VARCHAR (PENDING|IN_PROGRESS|COMPLETED|FAILED)
  - `network_scan_status` VARCHAR (same)
  - ... (similar status columns for all 5 new engines)
- Migration type: Non-blocking ALTER TABLE (adds columns with defaults, doesn't lock table during peak)
- Rollback: DROP COLUMN (reversible)
- Data: All new columns default to NULL initially (populated by respective engines during Phase 1-5)

#### Task 0.4.2: Create Partial Indexes `[Seq 43 | DE]`
**Story:** As the pipeline orchestrator, I need indexes on the new scan_id columns so that queries to find pending scans (WHERE container_scan_id IS NULL) and completed scans run efficiently.

**Implementation Details:**
- Indexes created:
  - `CREATE INDEX idx_scan_orch_log_coll_id ON scan_orchestration(log_collection_id) WHERE log_collection_id IS NOT NULL;`
  - `CREATE INDEX idx_scan_orch_ext_coll_id ON scan_orchestration(external_collection_id) WHERE external_collection_id IS NOT NULL;`
  - `CREATE INDEX idx_scan_orch_container ON scan_orchestration(container_scan_id) WHERE container_scan_id IS NOT NULL;`
  - (similar for network, supplychain, api, risk)
  - `CREATE INDEX idx_scan_orch_status ON scan_orchestration(container_scan_status, network_scan_status, ...);` (multi-column for status checks)
- Why partial: Most scans complete, so IS NOT NULL filters out majority of rows
- Impact: Minimal (only indexes populated rows, smaller index size)

**Deliverable:** `shared/database/migrations/014_add_new_engine_scan_ids.sql` (idempotent — can run multiple times safely)
- **Dependencies:** Task 0.4.1 (columns must exist before indexing)
- **Consumed by:** Tasks 1.1-1.10, 2.1-2.10, 3.1-3.11, 4.1-4.10, 5.1-5.11 (all engines write scan_ids to orchestration), Task 6.1-6.2 (pipeline_worker reads/writes orchestration)

---

### 0.5 Shared Utilities
Build reusable Python modules in `shared/common/` that all new engines (and existing engines) can use for rule evaluation, rule loading, and finding writing.

#### Task 0.5.1: Build Shared Rule Evaluator `[Seq 44 | BD]`
**Story:** As a shared utility, I need to provide a generic rule evaluation function that all engines can use without reimplementing condition logic, supporting 4 types of rule conditions (field_check, threshold, set_membership, composite).

**Implementation Details:**
- Location: `shared/common/rule_evaluator.py`
- Class: RuleEvaluator
- Method: `evaluate(asset: Dict[str, Any], rule: Dict[str, Any]) -> RuleResult`
- Supports 4 condition types (per NEW_ENGINES_ETL_RULES.md section 2.2):
  1. **field_check**: Compare asset field against expected value (eq, ne, gt, lt, gte, lte, contains, in, not_in, is_null)
  2. **threshold**: Compare metric against baseline × multiplier (for anomaly detection)
  3. **set_membership**: Check if field value is in a set (loaded from DB or passed as _set_values)
  4. **composite**: AND/OR of multiple conditions (recursive)
- Return type: RuleResult (result: PASS|FAIL|SKIP|ERROR, evidence: dict, severity: str)
- Evidence includes: actual value, expected value, baseline/threshold (for anomaly), set membership status
- Error handling: Catch KeyError (missing field) → return SKIP; other errors → return ERROR
- Testing: 15+ unit tests covering all condition types
- Usage:
  ```python
  evaluator = RuleEvaluator()
  result = evaluator.evaluate(asset_dict, rule_dict)
  if result.result == "FAIL":
    # write finding
  ```
- Dependencies: None (standalone utility)
- Consumed by: Tasks 1.4, 2.4, 3.5, 4.4, 5.5 (all engine evaluators use rule_evaluator)

#### Task 0.5.2: Build Shared Rule Loader `[Seq 45 | BD]`
**Story:** As a shared utility, I need to provide a generic rule loader function that all engines can use to fetch active rules from their respective {engine}_rules tables without duplicating SQL logic.

**Implementation Details:**
- Location: `shared/common/rule_loader.py`
- Class: RuleLoader
- Method: `load_rules(db_connection, engine_name: str, filter_csp: str = 'all') -> List[Rule]`
- Query: `SELECT * FROM {engine}_rules WHERE is_active = TRUE AND (csp='all' OR 'all'=ANY(csp))`
- Returns: List of Rule objects (pydantic models with type hints)
- Caching: Optional in-memory cache (1 min TTL) to reduce DB queries if same rules loaded multiple times
- For set_membership rules: Load referenced set from DB (e.g., if `set_table='cisa_kev'`, query that table)
- Error handling: Log missing {engine}_rules table, return empty list
- Testing: Unit tests with mock DB
- Usage:
  ```python
  loader = RuleLoader(db_connection)
  rules = loader.load_rules('container')  # load from container_rules table
  for rule in rules:
    result = evaluator.evaluate(asset, rule)
  ```
- Dependencies: psycopg2 (DB connection), pydantic (data models)
- Consumed by: Tasks 1.4, 2.4, 3.5, 4.4, 5.5 (all engine evaluators load rules via rule_loader)

#### Task 0.5.3: Build Shared Finding Writer `[Seq 46 | BD]`
**Story:** As a shared utility, I need to provide a generic function that all engines can use to write findings to their respective {engine}_findings tables with consistent schema and batch optimization.

**Implementation Details:**
- Location: `shared/common/finding_writer.py`
- Class: FindingWriter
- Method: `write_findings(db_connection, engine_name: str, findings: List[Finding]) -> int`
- Batch insert: Use `executemany()` with parameterized queries to insert multiple findings at once (avoid N+1 queries)
- Fields written (standard schema):
  - finding_id (UUID, auto-generated)
  - {engine}_scan_id (provided by caller)
  - tenant_id, orchestration_id (provided by caller)
  - resource_id, resource_type, resource_arn
  - rule_id, result (FAIL|PASS|SKIP|ERROR), severity, title, description
  - evidence (JSONB)
  - remediation, account_id, region, csp
  - created_at (NOW())
- Validation: Check all required fields present before insert
- Error handling: Rollback transaction on error, log and re-raise
- Performance: Insert 1000+ findings in single batch (test with 10K finding load)
- Testing: Unit tests with mock DB
- Usage:
  ```python
  writer = FindingWriter(db_connection)
  findings = [Finding(...), Finding(...)]
  count = writer.write_findings('container', findings)
  print(f"Wrote {count} findings")
  ```
- Dependencies: psycopg2, pydantic
- Consumed by: Tasks 1.4, 2.4, 3.5, 4.4, 5.5 (all engine evaluators batch-write findings via finding_writer)

**Deliverables:**
- `shared/common/rule_evaluator.py` (with tests)
- `shared/common/rule_loader.py` (with tests)
- `shared/common/finding_writer.py` (with tests)
- `shared/common/tests/test_rule_evaluator.py` (15+ tests)
- `shared/common/tests/test_rule_loader.py` (8+ tests)
- `shared/common/tests/test_finding_writer.py` (8+ tests)

---

## Phase 1: engine_container (P1)
**Branch:** `feature/engine-container`
**Port:** 8006 | **DB:** `threat_engine_container`
**Layer:** 1 (runs after all 3 collectors complete)

### Data Sources (What it reads — never collects itself)
```
FROM Tier 1 (discovery_findings):
  aws.ecr.repository   → registry metadata, scan-on-push config
  aws.ecr.image         → image digests, tags, push dates
  aws.eks.pod           → running pods with container specs + security contexts
  aws.eks.deployment    → deployment specs
  aws.ecs.task_definition → ECS container definitions

FROM Tier 3 (external_collector output):
  registry_images       → Docker Hub / GCR / ACR image metadata + Trivy scan results
  vuln_cache            → CVE details, CVSS scores, EPSS, KEV status
```

### 4-Stage Processing Flow
```
STAGE 1 — ETL (container_etl.py)
  READ:  discovery_findings WHERE resource_type IN (ecr.repository, ecr.image, eks.pod,
         eks.deployment, ecs.task_definition) [Tier 1]
       + registry_images [Tier 3]
       + vuln_cache [Tier 3]
  JOIN:  Merge ECR images with registry_images (by digest/tag), enrich CVEs with
         EPSS/KEV from vuln_cache, attach K8s pod security contexts
  WRITE: → container_input_transformed
         (one row per image/pod/task with all enriched fields flattened)

STAGE 2 — EVALUATE (container_evaluator.py)
  READ:  container_rules WHERE is_active = TRUE
  EVAL:  Apply each rule against container_input_transformed rows
         CONT-K8S-*: pod security context checks (privileged, runAsRoot, hostNetwork)
         CONT-ECR-*: registry posture (scan-on-push, tag mutability, encryption)
         CONT-CVE-*: critical/high CVE presence, KEV match, EPSS threshold
  WRITE: → container_findings (PASS/FAIL/SKIP/ERROR per rule per resource)

STAGE 3 — REPORT (container_reporter.py)
  READ:  container_findings for current scan
  AGG:   Count by severity, top failing rules, image CVE summary, SBOM stats
  WRITE: → container_report (one row per scan)
         → container_sbom (extracted SBOMs per image for cross-engine use)
         → container_images (denormalized image inventory)

STAGE 4 — COORDINATE
  UPDATE: scan_orchestration.container_scan_id
  NOTIFY: pipeline_worker "container done"
```

### Technical Tasks (Expanded)

#### Task 1.1: Create Container Engine Database Schema `[Seq 47 | DE]`
**Story:** As the container engine, I need dedicated database tables to store image metadata, CVE findings, Kubernetes policy violations, and rule evaluations so that multiple scans can be tracked and findings can be correlated across images and running containers.

**Implementation Details:**
- Location: `shared/database/schemas/container_schema.sql`
- Tables created:
  - `container_report` (scan-level summary: 1 row per scan_id)
  - `container_input_transformed` (ETL output: flattened, enriched image + pod data)
  - `container_rules` (rule definitions with JSONB conditions)
  - `container_findings` (rule evaluation results: PASS/FAIL per rule per image)
  - `container_images` (normalized image inventory with risk scores)
  - `container_sbom` (package inventory per image: name, version, type, license, CVE count)
  - `k8s_policy_findings` (K8s security context violations: privileged, runAsRoot, hostNetwork, etc.)
- Schema reference: NEW_ENGINES_ARCHITECTURE.md Engine 1 schema section (lines 296-404)
- Indexes: (container_scan_id, tenant_id), (image_id), (resource_id), partial index on severity='critical'
- Constraints: FK to container_rules (rule_id), FK container_images to orchestration (container_scan_id)
- Dependencies: 0.4 (shared database infrastructure must exist)
- Consumed by: All tasks 1.2-1.10 (all write to these tables)
- Reference: NEW_ENGINES_ARCHITECTURE.md section "Engine 1 Input / Output Schema"

#### Task 1.2: Seed Container Rules `[Seq 48 | DE]`
**Story:** As the container engine, I need initial rule definitions so that scans can start evaluating container security posture without manual rule creation. Rules cover K8s pod security contexts, ECR registry configuration, and CVE severity thresholds.

**Implementation Details:**
- Location: `shared/database/seeds/seed_container_rules.sql`
- Insert 13 initial rules into container_rules table:
  - **K8s Pod Security Context Rules (7 rules)**
    - CONT-K8S-001: Container running as root (runAsNonRoot=false) — high severity
    - CONT-K8S-002: Privileged container (privileged=true) — critical severity
    - CONT-K8S-003: Host network access enabled (hostNetwork=true) — high severity
    - CONT-K8S-004: Privilege escalation allowed (allowPrivilegeEscalation!=false) — high severity
    - CONT-K8S-005: No CPU/memory limits set (resources.limits=null) — medium severity
    - CONT-K8S-006: Default service account used (service_account='default') — medium severity
    - CONT-K8S-007: Root filesystem writable (readOnlyRootFilesystem!=true) — medium severity
  - **ECR Registry Posture Rules (3 rules)**
    - CONT-ECR-001: ECR image scan on push disabled — medium severity
    - CONT-ECR-002: ECR image mutable tags enabled — low severity
    - CONT-ECR-003: ECR repository not encrypted with CMK — medium severity
  - **CVE Severity Rules (3 rules)**
    - CONT-CVE-001: Critical CVE in running container (CVSS >= 9.0) — critical severity
    - CONT-CVE-002: CVE in CISA KEV catalog (in_set condition) — critical severity
    - CONT-CVE-003: High CVE with fix available (fixed_version != null) — high severity
- Rule format: Each rule includes rule_id, title, category, severity, condition_type, condition (JSONB), frameworks (CIS_K8s, PCI-DSS, HIPAA, SOC2, etc.), remediation text
- Condition examples from NEW_ENGINES_ETL_RULES.md Section 3.1 (lines 252-296)
- Dependencies: 1.1 (table must exist)
- Consumed by: 1.4 (container_evaluator.py loads these rules)
- Reference: NEW_ENGINES_ETL_RULES.md Section 3.1 "Rule seed" subsection

#### Task 1.3: Build container_etl.py (STAGE 1 — Transform) `[Seq 49 | BD]`
**Story:** As the container ETL stage, I need to read raw discovery data from multiple Tier 1 and Tier 3 sources, join them by image digest/tag, enrich CVEs with exploitability data, and produce a clean, normalized table ready for rule evaluation.

**Implementation Details:**
- Location: `engines/engine_container/etl/container_etl.py`
- Input tables:
  - `discovery_findings` WHERE resource_type IN ('aws.ecr.repository', 'aws.ecr.image', 'aws.eks.pod', 'aws.eks.deployment', 'aws.ecs.task_definition')
  - `registry_images` (from Tier 3: external_collector) — contains image digest, manifest, Trivy scan results in trivy_output JSONB
  - `vuln_cache` (from Tier 3) — contains CVE details: cve_id, cvss_score, epss_score, is_in_kev, exploit_maturity
  - `container_sbom` (from previous scans or external_collector) — optional for cross-reference
- Processing steps:
  1. **Query ECR images** (AWS resource types): SELECT image_digest, image_tags, repository_uri FROM discovery_findings WHERE resource_type='aws.ecr.image'
  2. **Join with registry_images**: Match on (digest, tag) pairs to get Trivy scan output (CVE list, package list)
  3. **Enrich CVEs**: For each CVE in trivy_output, LEFT JOIN vuln_cache to get CVSS, EPSS, KEV status, exploit_maturity
  4. **Parse SBOM**: Extract package_name, package_version, package_type from trivy_output → prepare for container_sbom table
  5. **Query K8s workloads** (AWS resource types): SELECT FROM discovery_findings WHERE resource_type IN ('aws.eks.pod', 'aws.eks.deployment', 'aws.ecs.task_definition')
  6. **Flatten K8s specs**: For each pod/deployment: parse containers[] array → extract image refs, security_context (privileged, runAsRoot, runAsNonRoot, readOnlyRootFilesystem), resource limits, service_account, host_network, host_pid
  7. **Match pod images to ECR images**: For each pod container image ref, find matching row in registry_images (by tag or digest), attach running pod metadata (cluster_name, namespace, pod_name, node_name)
  8. **Write container_input_transformed**: One row per image/pod combination with all enriched fields: [image_id, image_uri, registry_type, digest, all_tags[], os_family, os_version, total_packages, critical_cve_count, high_cve_count, cves[] (array of CVE details with EPSS/KEV), security_context JSON, resource_limits, is_running, running_in (cluster/namespace/pod name list)]
- SQL patterns from NEW_ENGINES_ETL_RULES.md Section 3.1 (lines 194-240)
- Output: `container_input_transformed` with one row per unique image (or image + pod combination for running context)
- Error handling: Skip images with missing digest, skip malformed security contexts, log warnings, continue processing
- Performance: Use batch reads (LIMIT 1000), streaming writes to avoid memory overload on large registries
- Dependencies: 0.3 (external_collector Tier 3 must complete), 1.1 (schema exists)
- Consumed by: 1.4 (container_evaluator.py reads this table)
- Reference: NEW_ENGINES_ETL_RULES.md Section 3.1 "Transform pipeline"

#### Task 1.4: Build container_evaluator.py (STAGE 2 — Evaluate) `[Seq 50 | BD]`
**Story:** As the container evaluator, I need to load active rules from the database, apply them against the transformed image/pod data, record PASS/FAIL/SKIP/ERROR results, and write findings so operators know which containers violate security policies.

**Implementation Details:**
- Location: `engines/engine_container/evaluator/container_evaluator.py`
- Input tables:
  - `container_rules` WHERE is_active = TRUE — load all active rules at scan start
  - `container_input_transformed` — the prepared data from STAGE 1
  - `cve_kev_list` (optional, from threatintel cache) — for set_membership conditions on CISA KEV checks
- Processing steps:
  1. **Load rules**: Read all container_rules WHERE is_active=TRUE → build Rule objects with condition_type, condition JSONB, severity, frameworks
  2. **For each row in container_input_transformed**:
     - For each active rule:
       a. Call `shared/common/rule_evaluator.evaluate_rule(asset, rule)` passing the image/pod row and rule object
       b. Receive RuleResult: (result=PASS|FAIL|SKIP|ERROR, evidence=dict, severity=string)
       c. If result=FAIL: build finding JSONB with evidence (actual value, expected value, field name)
       d. Write to container_findings: (finding_id, container_scan_id, image_id, rule_id, result, severity, evidence, title, description, remediation)
  3. **Handle multi-rule failures**: One image may FAIL multiple rules (e.g., both running as root AND privileged) — write separate finding rows for each
  4. **SKIP logic**: If resource doesn't apply to rule (e.g., K8s rule on ECS task), result=SKIP
  5. **ERROR logic**: If rule condition is malformed or missing referenced column, result=ERROR with reason in evidence
- Rule condition types evaluated:
  - `field_check`: Compare field value against operator + value (eq, ne, gt, lt, gte, lte, contains, is_null, in)
  - `threshold`: Compare metric against baseline_field * multiplier (for spike detection if applied here)
  - `set_membership`: Check if field value exists in set (for KEV, malicious packages, etc.)
- Use shared utility: Import from `shared/common/rule_evaluator.py` — RuleEvaluator class with evaluate_rule(asset, rule) method
- Batch writing: Use container_db_writer.batch_insert_findings() to insert all findings per 1000-row batch
- Dependencies: 1.2 (rules must exist), 1.3 (transformed data must exist), 0.5 (shared/common/rule_evaluator.py must exist)
- Consumed by: 1.5 (container_reporter.py reads findings)
- Reference: NEW_ENGINES_ETL_RULES.md Section 2.2-2.4 "Rule condition types" and "Rule Evaluator" subsection

#### Task 1.5: Build container_reporter.py (STAGE 3 — Report) `[Seq 51 | BD]`
**Story:** As the container reporter, I need to aggregate findings into scan-level summaries, extract SBOM data, denormalize image inventory, and prepare reports for compliance/dashboard consumption.

**Implementation Details:**
- Location: `engines/engine_container/reporter/container_reporter.py`
- Input tables:
  - `container_findings` WHERE container_scan_id = $scan_id — all findings from this scan
  - `container_input_transformed` — for per-image CVE/package counts
  - `vuln_cache` — for CVE details and exploitability info (already loaded in 1.3)
- Processing steps:
  1. **Build container_report (1 row per scan)**:
     - SELECT container_scan_id, tenant_id, orchestration_id, scan_start_time = NOW()
     - Count findings by severity: COUNT(*) WHERE severity='critical' AS critical_count, etc.
     - COUNT(*) WHERE result='FAIL' AS total_failures
     - COUNT DISTINCT image_id AS total_images_scanned
     - COUNT DISTINCT resource_id (pods/deployments/tasks) AS total_resources_scanned
     - Top 5 failing rules by occurrence: GROUP BY rule_id ORDER BY COUNT(*) DESC LIMIT 5
     - SBOM stats: COUNT DISTINCT packages from container_sbom AS total_unique_packages
     - CVE stats: SUM(critical_cve_count) AS total_critical_cves, SUM(high_cve_count) AS total_high_cves
     - Risk score: Compute weighted aggregate (critical × 10 + high × 5 + medium × 2 + low × 1) / total_findings, capped at 100
     - Write to container_report
  2. **Extract container_sbom** (detailed SBOM per image):
     - For each image in container_input_transformed:
       - Parse trivy_output SBOM component list
       - For each package: INSERT into container_sbom (image_id, package_name, package_version, package_type, license, purl, is_direct_dep)
       - Flag has_vulnerabilities based on vuln_cache lookup
       - Count vulnerability_count per package
  3. **Populate container_images** (denormalized inventory):
     - For each unique image (by digest): INSERT container_images row with:
       - image_id, registry_type, registry_url, repository, tag[], digest, base_image, os_family, os_version
       - total_layers (from Trivy output), total_packages (COUNT from SBOM)
       - is_running (TRUE if appears in any running pod/deployment), running_in (array of pod refs)
       - critical_cve_count, high_cve_count, risk_score (0-100 based on CVEs)
       - last_pushed_at, scanned_at=NOW()
  4. **Optional k8s_policy_findings post-processing**:
     - If container_findings contains K8s-specific failures, extract to separate k8s_policy_findings table for K8s-focused dashboards
     - Each row: cluster_id, namespace, resource_kind (Pod|Deployment|DaemonSet), resource_name, rule_id, severity, evidence JSON
- Aggregation logic:
  - CASE expressions to bucket findings by severity (critical/high/medium/low/info)
  - Window functions to rank rules by failure frequency
  - Array aggregation for tag lists, pod references, CVE lists
- Dependencies: 1.4 (findings must be written)
- Consumed by: 1.7 (api_server.py returns report in API response), dashboard (reads container_report, container_images, container_sbom)
- Reference: NEW_ENGINES_ARCHITECTURE.md "Output tables" section (lines 296-376)

#### Task 1.6: Build container_db_writer.py `[Seq 52 | BD]`
**Story:** As the database writer utility, I need reusable batch insert functions so the ETL/Evaluator/Reporter stages can efficiently write large volumes of findings and artifacts without duplicating SQL code.

**Implementation Details:**
- Location: `engines/engine_container/db/container_db_writer.py`
- Functions (class methods):
  - `batch_insert_transformed(rows: List[dict], batch_size=1000)` — insert into container_input_transformed from ETL stage
  - `batch_insert_findings(rows: List[dict], batch_size=1000)` — insert into container_findings from evaluator stage
  - `batch_insert_sbom(rows: List[dict], batch_size=1000)` — insert into container_sbom from reporter stage
  - `batch_insert_images(rows: List[dict], batch_size=500)` — insert/upsert into container_images (slower due to computed fields)
  - `batch_insert_report(row: dict)` — single-row insert into container_report
  - `batch_insert_k8s_findings(rows: List[dict], batch_size=1000)` — insert into k8s_policy_findings
  - `update_orchestration(scan_id: UUID)` — UPDATE scan_orchestration SET container_scan_id=$scan_id
- Implementation: Use asyncpg or psycopg2 with prepared statements, handle constraint violations (duplicates skipped with ON CONFLICT DO NOTHING where needed)
- Error handling: Retry on transient DB errors, log failures, never fail the entire scan on one row error
- Dependencies: 1.1 (schema), psycopg2 or asyncpg library
- Consumed by: 1.3, 1.4, 1.5 (all stages use these functions)
- Testing: Unit test each function with mock rows

#### Task 1.7: Build api_server.py (Container Engine API) `[Seq 53 | AD]`
**Story:** As the FastAPI server, I need to expose HTTP endpoints so the pipeline_worker can trigger scans, check health, and retrieve metrics without direct database access.

**Implementation Details:**
- Location: `engines/engine_container/api_server.py`
- Framework: FastAPI (Python)
- Port: 8006
- Endpoints:
  - **POST /api/v1/scan** — Main entry point for pipeline
    - Input: `{orchestration_id: UUID, discovery_scan_id: UUID, container_scan_id: UUID}`
    - Logic: Call container_etl.run() → container_evaluator.run() → container_reporter.run() → container_db_writer.update_orchestration() in sequence
    - Output: `{status: "success", container_scan_id: UUID, findings_count: int, critical_count: int, scan_duration_ms: int, timestamp: ISO8601}`
    - Errors: Return 400 if missing params, 500 if any stage fails with detailed error message
  - **GET /api/v1/health/live** — Liveness probe
    - Returns: `{status: "ok"}` if service is running
  - **GET /api/v1/health/ready** — Readiness probe (includes DB check)
    - Connects to RDS, runs SELECT 1, returns `{status: "ready", db: "ok"}` or `{status: "notready", db: "unreachable"}`
  - **GET /api/v1/metrics** — Prometheus metrics
    - Returns text format metrics: `container_scans_total, container_findings_total, scan_duration_seconds_bucket, container_rule_evaluations_total`
  - **GET /api/v1/report/{scan_id}** — Retrieve scan report (for dashboard)
    - Returns JSON: container_report row, top findings, SBOM summary, image inventory
- Error handling: Try/except around each stage, log exceptions, return meaningful HTTP error codes
- Async: Use async/await for I/O-heavy operations (DB reads, joins)
- Dependencies: 1.3-1.6 (all processing modules), FastAPI, asyncpg or psycopg2
- Testing: Integration test with mock database
- Reference: See engine_check api_server.py pattern for FastAPI structure

#### Task 1.8: Create Dockerfile and Kubernetes Manifest `[Seq 54 | DO]`
**Story:** As the deployment artifact, I need a containerized image and K8s manifest so the container engine can be deployed to the EKS cluster and orchestrated by pipeline_worker.

**Implementation Details:**
- Location:
  - `engines/engine_container/Dockerfile` (multi-stage build)
  - `deployment/aws/eks/engines/engine-container.yaml` (K8s Deployment + Service)
- Dockerfile:
  - Base image: `python:3.11-slim`
  - Stage 1 (build): Install dev dependencies, create virtual env, pip install requirements.txt
  - Stage 2 (runtime): Copy venv from stage 1, add non-root user (appuser:appuser), EXPOSE 8006, ENTRYPOINT ["python", "-m", "uvicorn", "engines.engine_container.api_server:app", "--host", "0.0.0.0", "--port", "8006"]
  - Security: No root user, read-only filesystem where possible, minimal layers
- Kubernetes manifest (engine-container.yaml):
  - Deployment: name=engine-container, namespace=threat-engine-engines, replicas=1
  - Image: `<ecr-uri>/engine-container:v1.0` (to be built and pushed)
  - Resources: requests (cpu: 500m, memory: 512Mi), limits (cpu: 2, memory: 2Gi) — adjust based on typical scan volume
  - Environment variables: DB_HOST, DB_PORT, DB_NAME, DB_USER (from ConfigMap), DB_PASSWORD (from Secret)
  - Health checks: livenessProbe (GET /api/v1/health/live, initialDelaySeconds=30), readinessProbe (GET /api/v1/health/ready, initialDelaySeconds=60)
  - Service: type=ClusterIP, port=8006, targetPort=8006, selector app=engine-container
  - RBAC: ServiceAccount, no special permissions needed (discovery data already available)
- Dependencies: 1.7 (api_server.py must exist)
- Consumed by: 1.10 (integration test pulls the image), deployment pipeline (kubectl apply)

#### Task 1.9: Unit Tests `[Seq 55 | QA]`
**Story:** As the test suite, I need comprehensive unit tests covering ETL joins, rule evaluation logic, aggregation, and SBOM extraction so changes can be safely made without regressions.

**Implementation Details:**
- Location: `engines/engine_container/tests/` with test files:
  - `test_container_etl.py` — test ETL joins, enrichment, flattening
  - `test_container_evaluator.py` — test rule evaluation per condition type (field_check, threshold, set_membership)
  - `test_container_reporter.py` — test aggregation logic, risk scoring, SBOM extraction
  - `test_container_db_writer.py` — test batch insert functions
- Test data: Use pytest fixtures with mock discovery_findings, registry_images, vuln_cache rows
- Coverage: Aim for >85% code coverage
- Key test cases:
  - ETL: Verify join on digest/tag produces correct image_id, verify EPSS enrichment from vuln_cache, verify K8s security context parsing
  - Evaluator: Verify FAIL result for container_running_as_root rule, verify PASS for proper security context, verify SKIP for non-applicable rules, verify ERROR handling
  - Reporter: Verify critical_count aggregation, verify top 5 failing rules ordering, verify SBOM extraction with correct package counts, verify risk_score computation
  - DB Writer: Verify batch insert splits large lists, verify ON CONFLICT handling, verify atomic failures
- Framework: pytest with conftest.py fixtures for DB mocking
- Run: `pytest engines/engine_container/tests/ -v --cov=engines.engine_container --cov-report=term-missing`

#### Task 1.10: Integration Test `[Seq 56 | QA]`
**Story:** As the end-to-end test, I need a full pipeline simulation to ensure all four stages work together correctly when fed with realistic Tier 1 + Tier 3 data.

**Implementation Details:**
- Location: `engines/engine_container/tests/test_integration.py`
- Setup:
  - Create temporary PostgreSQL database (docker-compose with postgres:15 service)
  - Run container_schema.sql migration
  - Seed with sample data:
    - 3 ECR repositories (Tier 1: discovery_findings rows with resource_type='aws.ecr.repository')
    - 5 ECR images (Tier 1) with scan_status='COMPLETE'
    - 2 EKS pods (Tier 1) with container specs, security contexts (one privileged, one secure)
    - 5 registry_images rows (Tier 3) with trivy_output JSONB containing CVE list (numpy-1.24.3 with CVE-2021-12345)
    - 5 vuln_cache rows with CVSS, EPSS, KEV status
    - 13 container_rules rows (from seed_container_rules.sql)
- Execution:
  - Call container_etl.run(orchestration_id, discovery_scan_id) — verify container_input_transformed has correct row count and enriched fields
  - Call container_evaluator.run(container_scan_id) — verify container_findings has expected FAIL/PASS counts
    - Expect: CONT-K8S-002 FAIL for privileged pod, CONT-CVE-001 FAIL for images with CVSS>=9.0, etc.
  - Call container_reporter.run(container_scan_id) — verify container_report aggregation, container_sbom extraction
    - Expect: critical_count=1 (privileged pod), total_packages>=15 (from SBOM), risk_score computed correctly
  - Verify scan_orchestration.container_scan_id is updated
- Assertions:
  - container_input_transformed row count == 2 (1 per image+pod, or 2 images separately — verify exact logic)
  - container_findings has >= 1 FAIL finding for privileged pod
  - container_findings has >= 1 FAIL finding for CVE with CVSS>=9.0
  - container_report critical_count >= 1
  - container_sbom has rows for numpy and other packages
  - SBOM package_type correctly identified (pip for numpy, etc.)
  - container_images has 2+ rows with risk_score populated
  - risk_score >= 50 for images with critical CVEs
- Cleanup: Drop temp database
- Run: `pytest engines/engine_container/tests/test_integration.py -v -s`
- Duration: Should complete in <30 seconds (no real API calls, all local DB)

**Note:** engine_container no longer embeds Trivy. The external_collector (Tier 3) runs Trivy scans and writes results to `registry_images.trivy_output`. The ETL stage reads those results and joins them into `container_input_transformed`.

---

## Phase 2: engine_network (P2)
**Branch:** `feature/engine-network`
**Port:** 8007 | **DB:** `threat_engine_network`
**Layer:** 2 (runs after Layer 1)

### Data Sources
```
FROM Tier 1 (discovery_findings):
  aws.ec2.security_group      → SG inbound/outbound rules
  aws.ec2.vpc                  → VPC CIDR, DNS settings
  aws.ec2.subnet               → public/private determination
  aws.ec2.network_acl          → NACL rules
  aws.ec2.internet_gateway     → IGW attachments
  aws.ec2.nat_gateway          → NAT gateways
  aws.ec2.vpc_peering_connection → VPC peering
  aws.ec2.transit_gateway      → TGW
  aws.ec2.flow_log             → flow log config (enabled/disabled)
  aws.elbv2.listener           → ALB listener TLS/ports
  aws.wafv2.web_acl            → WAF config + associations

FROM Tier 2 (log_collector output):
  log_events                   → parsed VPC flow log records
  event_aggregations           → 5-min window traffic summaries

FROM Tier 3 (external_collector output):
  threat_intel_ioc             → malicious IP/domain indicators for matching
```

### 4-Stage Processing Flow
```
STAGE 1 — ETL (network_etl.py)
  READ:  discovery_findings WHERE resource_type IN (ec2.security_group, ec2.vpc,
         ec2.subnet, ec2.network_acl, ec2.internet_gateway, ec2.nat_gateway,
         ec2.vpc_peering_connection, ec2.transit_gateway, ec2.flow_log,
         elbv2.listener, wafv2.web_acl) [Tier 1]
       + event_aggregations [Tier 2] — pre-computed traffic summaries
       + log_events [Tier 2] — raw flow records for IOC matching
       + threat_intel_ioc [Tier 3] — malicious IP indicators
       + network_baselines [self] — rolling 14-day traffic baselines
  JOIN:  Build directed adjacency graph from SGs/NACLs/VPCs, attach flow
         summaries per resource, match src/dst IPs against IOCs, compute
         deviation from baselines
  WRITE: → network_input_transformed
         (one row per network resource with topology context, flow stats,
          IOC matches, baseline deviation flags)
       → network_topology (adjacency graph — engine-specific output)

STAGE 2 — EVALUATE (network_evaluator.py)
  READ:  network_rules WHERE is_active = TRUE
  EVAL:  Apply each rule against network_input_transformed rows
         NET-SG-*: open port checks (0.0.0.0/0 on 22, 3389, all ports)
         NET-VPC-*: flow log disabled, DNS resolution logging
         NET-NACL-*: overly permissive NACLs
         NET-ALB-*: TLS version, WAF association
         NET-ANOM-*: traffic spike vs baseline, IOC IP communication
  WRITE: → network_findings (PASS/FAIL/SKIP/ERROR per rule per resource)

STAGE 3 — REPORT (network_reporter.py)
  READ:  network_findings for current scan
  AGG:   Count by severity, top failing rules, anomaly summary, IOC match count
  WRITE: → network_report (one row per scan)
         → network_anomalies (detected anomalies with evidence)
         → UPDATE network_baselines (rolling 14-day recompute)

STAGE 4 — COORDINATE
  UPDATE: scan_orchestration.network_scan_id
  NOTIFY: pipeline_worker "network done"
```

### Technical Tasks (Expanded)

#### Task 2.1: Create Network Engine Database Schema `[Seq 57 | DE]`
**Story:** As the network engine, I need dedicated database tables to store network topology, posture findings, runtime anomalies, and baselines so that network security can be tracked across scans and compared for trend analysis.

**Implementation Details:**
- Location: `shared/database/schemas/network_schema.sql`
- Tables created:
  - `network_report` (scan-level summary: 1 row per scan_id)
  - `network_input_transformed` (ETL output: flattened SG/VPC/NACL rules + flow stats + IOC matches)
  - `network_rules` (rule definitions with JSONB conditions for posture and runtime modes)
  - `network_findings` (rule evaluation results: PASS/FAIL per rule per resource)
  - `network_topology` (adjacency graph: nodes and edges representing network structure)
  - `network_anomalies` (detected runtime anomalies: data exfiltration, beaconing, port scanning)
  - `network_baselines` (rolling 14-day traffic statistics for anomaly baseline comparison)
- Schema reference: NEW_ENGINES_ARCHITECTURE.md Engine 2 schema section (lines 548-682)
- Indexes: (network_scan_id, tenant_id), (vpc_id), (src_ip, dst_ip), (anomaly_type), partial index on severity='critical'
- Constraints: FK to network_rules (rule_id), FK resource_id to discovery findings, temporal constraints on baseline computation
- Dependencies: 0.4 (shared database infrastructure must exist), 0.2 (log_collector schema must exist for event_aggregations reference)
- Consumed by: All tasks 2.2-2.10 (all write to these tables)
- Reference: NEW_ENGINES_ARCHITECTURE.md section "Engine 2 Input / Output Schema"

#### Task 2.2: Seed Network Rules `[Seq 58 | DE]`
**Story:** As the network engine, I need initial rule definitions covering both posture mode (static SG/NACL/VPC checks) and runtime mode (flow anomaly detection, IOC matching) so network security assessments can start without manual rule configuration.

**Implementation Details:**
- Location: `shared/database/seeds/seed_network_rules.sql`
- Insert 12+ initial rules into network_rules table:
  - **Security Group Posture Rules (4 rules)**
    - NET-SG-001: SSH open to internet (0.0.0.0/0 on port 22) — critical severity, mode=posture
    - NET-SG-002: RDP open to internet (0.0.0.0/0 on port 3389) — critical severity, mode=posture
    - NET-SG-003: All traffic allowed inbound (0.0.0.0/0 all ports) — critical severity, mode=posture
    - NET-SG-004: All traffic allowed outbound — medium severity, mode=posture
  - **VPC/NACL Posture Rules (3 rules)**
    - NET-VPC-001: VPC Flow Logs disabled — high severity, mode=posture
    - NET-VPC-002: VPC does not have DNS resolution enabled — low severity, mode=posture
    - NET-NACL-001: NACL allows unrestricted inbound on all ports — high severity, mode=posture
  - **ALB / TLS Posture Rules (2 rules)**
    - NET-ALB-001: ALB listener using HTTP (not HTTPS) — high severity, mode=posture
    - NET-ALB-002: ALB TLS policy allows TLS 1.0 or 1.1 — medium severity, mode=posture
  - **Runtime Anomaly Rules (3+ rules)**
    - NET-ANOM-001: Outbound data spike > 3x baseline — high severity, mode=runtime, category=anomaly
    - NET-ANOM-002: Connection to known malicious IP (threat intel IOC match) — critical severity, mode=runtime, category=threat
    - NET-ANOM-003: Port scan detected (>100 unique dst ports in 5min window) — high severity, mode=runtime, category=anomaly
- Rule format: Each rule includes rule_id, title, mode (posture|runtime), category (exposure|encryption|logging|anomaly|threat), severity, condition_type, condition (JSONB), frameworks (CIS_AWS, PCI-DSS, HIPAA, SOC2, NIST_800-53, ISO27001), remediation text
- Condition examples from NEW_ENGINES_ETL_RULES.md Section 3.2 (lines 371-425)
- Dependencies: 2.1 (table must exist)
- Consumed by: 2.4 (network_evaluator.py loads these rules)
- Reference: NEW_ENGINES_ETL_RULES.md Section 3.2 "Rule seed" subsection

#### Task 2.3: Build network_etl.py (STAGE 1 — Transform) `[Seq 59 | BD]`
**Story:** As the network ETL stage, I need to read network configuration from Tier 1 (discoveries), flow statistics from Tier 2 (log_collector), threat intelligence from Tier 3, and baselines from previous scans, then produce a unified normalized table with topology context, flow stats, IOC matches, and baseline deviations ready for rule evaluation. Process both posture mode (static SG/VPC config) and runtime mode (flow analysis).

**Implementation Details:**
- Location: `engines/engine_network/etl/network_etl.py`
- Input tables:
  - **Tier 1 (discovery_findings)**:
    - WHERE resource_type IN ('aws.ec2.security_group', 'aws.ec2.vpc', 'aws.ec2.subnet', 'aws.ec2.network_acl', 'aws.ec2.internet_gateway', 'aws.ec2.nat_gateway', 'aws.ec2.vpc_peering_connection', 'aws.ec2.transit_gateway', 'aws.ec2.flow_log', 'aws.elbv2.listener', 'aws.wafv2.web_acl')
  - **Tier 2 (log_collector output)**:
    - `event_aggregations` — pre-computed 5-minute traffic summaries (src_ip, dst_ip, dst_port, protocol, total_bytes, total_packets, flow_count)
    - `log_events` — raw VPC flow records (for detailed IOC matching if needed)
  - **Tier 3 (external_collector output)**:
    - `threat_intel_ioc` — malicious IP/domain indicators (indicator_value, indicator_type='ipv4'|'ipv6'|'domain', source, severity)
  - **Self (network_baselines)**:
    - Rolling 14-day traffic baseline from previous scans: resource_id, metric_type, baseline_avg, baseline_p95, std_deviation
- Processing steps:

  **POSTURE MODE (Static Configuration Analysis):**
  1. **Build network topology graph**:
     - Nodes: VPC, Subnet, SG, NACL, IGW, NAT, Transit Gateway, Route Table (from discovery_findings)
     - Edges: route → subnet → vpc → igw, sg → (inbound/outbound rules), peering, TGW attachment
     - For each VPC: SELECT vpc_id, cidr_block FROM discovery_findings WHERE resource_type='aws.ec2.vpc'
     - For each SG: SELECT sg_id, vpc_id, inbound_rules, outbound_rules FROM discovery_findings WHERE resource_type='aws.ec2.security_group' (parse emitted_fields JSONB)
     - Build adjacency_map: vpc_id → {subnets[], sgs[], igw, nat, peerings[]}
  2. **Parse SG/NACL rules**:
     - For each SG: SELECT inbound_rules[*] (array of {port, protocol, cidr, description})
     - Flatten: For each inbound rule, extract (port, protocol, cidr) → check against NET-SG-* rule patterns (port==22 AND cidr=='0.0.0.0/0' → FAIL)
     - For each NACL: SELECT inbound_rules[] and outbound_rules[], check for overly permissive patterns
  3. **Check flow log configuration**:
     - For each VPC: SELECT flow_log_config FROM discovery_findings WHERE resource_type='aws.ec2.flow_log' AND resource_id LIKE vpc_id
     - If flow_logs_enabled=FALSE → flag for NET-VPC-001 rule
  4. **Check ALB listener TLS**:
     - For each ALB listener in discovery_findings WHERE resource_type='aws.elbv2.listener'
     - Extract protocol, ssl_policy, certificate
     - If protocol='HTTP' → flag for NET-ALB-001
     - If ssl_policy matches old TLS versions → flag for NET-ALB-002
  5. **Write posture-focused rows to network_input_transformed**:
     - One row per network resource (SG, VPC, NACL, etc.) with: [resource_id, resource_type, vpc_id, inbound_rules JSONB, outbound_rules JSONB, flow_logs_enabled BOOL, attached_igw BOOL, is_public BOOL, connected_to JSONB]

  **RUNTIME MODE (Flow Analysis):**
  6. **Read flow aggregations from Tier 2**:
     - SELECT src_ip, dst_ip, dst_port, protocol, total_bytes, total_packets, flow_count, window_start, window_end FROM event_aggregations WHERE ingested_at > NOW()-1HOUR (last hour of data)
  7. **IP resolution** (optional, enrichment):
     - For each src_ip/dst_ip, try to resolve to resource_id (EC2 instance, ENI, etc.):
     - SELECT resource_id FROM discovery_findings WHERE emitted_fields->>'private_ip_address'=$src_ip OR emitted_fields->>'public_ip_address'=$src_ip
     - Write to network_input_transformed additional column: src_resource_id, dst_resource_id
  8. **Baseline comparison**:
     - For each src_ip, dst_ip, dst_port triple: SELECT baseline_avg FROM network_baselines WHERE resource_id=$src_ip AND metric_type='outbound_bytes'
     - Compute deviation: actual_bytes / baseline_avg = deviation_factor
     - If deviation_factor > 3.0 → flag potential data exfiltration
  9. **IOC matching** (threat intel):
     - For each src_ip in event_aggregations: SELECT * FROM threat_intel_ioc WHERE indicator_value=$src_ip
     - If match found: record is_malicious_ip=TRUE, threat_intel_source='AbuseIPDB' (or similar)
     - For each dst_ip: same check (identify connections TO malicious servers)
  10. **Port scanning pattern detection**:
     - GROUP BY src_ip, window_5min: COUNT DISTINCT dst_port
     - If unique_dst_ports > 100 in 5-min window → potential port scan
  11. **Write runtime-focused rows to network_input_transformed**:
     - Append columns: total_bytes, baseline_bytes, deviation_factor, is_malicious_ip, threat_intel_source, unique_dst_ports, port_scan_flag
     - Each row represents a 5-minute flow window with computed anomaly features

- **Write network_topology** (separate table, for graph-based queries later):
  - For each node (VPC, Subnet, SG, IGW, etc.): node_id, resource_type, vpc_id, inbound_rules, outbound_rules, connected_to (JSONB array of {node_id, edge_type})
  - For each edge: from_node, to_node, edge_type (route, sg_rule, peering, tgw_attachment)

- Output: `network_input_transformed` with one row per network resource (posture) or flow window (runtime), and `network_topology` with graph adjacency
- Error handling: Skip resources with missing required fields, log warnings, continue processing
- Performance: Batch reads from flow aggregations (they're pre-computed by Tier 2), use indexes on (src_ip, dst_ip) for IOC matching
- Dependencies: 0.2 (log_collector must exist and populate event_aggregations), 0.3 (external_collector must populate threat_intel_ioc), 2.1 (schema exists)
- Consumed by: 2.4 (network_evaluator.py)
- Reference: NEW_ENGINES_ETL_RULES.md Section 3.2 "Transform pipeline" (lines 326-369)

#### Task 2.4: Build network_evaluator.py (STAGE 2 — Evaluate) `[Seq 60 | BD]`
**Story:** As the network evaluator, I need to load active network rules (both posture and runtime), apply them against the transformed network/flow data, and write findings so operators can see SG misconfigurations, anomalies, and threat intel matches.

**Implementation Details:**
- Location: `engines/engine_network/evaluator/network_evaluator.py`
- Input tables:
  - `network_rules` WHERE is_active = TRUE — load all rules (filter by mode='posture' or mode='runtime' if in separate phases)
  - `network_input_transformed` — prepared data from ETL stage
  - `threat_intel_ioc` — for dynamic set_membership checks (already loaded during ETL enrichment)
- Processing steps:
  1. **Load rules**: Read network_rules WHERE is_active=TRUE → build Rule objects with category (exposure, encryption, logging, anomaly, threat), mode, condition
  2. **Separate posture from runtime rules** (optional optimization):
     - Posture rules apply to static network config (SG/NACL/VPC rows)
     - Runtime rules apply to flow aggregation rows
  3. **For each row in network_input_transformed**:
     - For each applicable rule (filter by mode or category):
       a. Call `shared/common/rule_evaluator.evaluate_rule(asset, rule)` passing the resource/flow row and rule
       b. Receive RuleResult: (result=PASS|FAIL|SKIP|ERROR, evidence, severity)
       c. If result=FAIL: build finding JSONB with evidence (e.g., {port: 22, cidr: "0.0.0.0/0", rule_index: 0} for SG rules)
       d. Write to network_findings: (finding_id, network_scan_id, resource_id, resource_type, rule_id, result, severity, evidence, title, description, remediation)
  4. **Special handling for threshold/anomaly rules**:
     - NET-ANOM-001 (outbound spike): Check if deviation_factor > 3.0 → FAIL
     - NET-ANOM-002 (malicious IP): Check if is_malicious_ip=TRUE → FAIL
     - NET-ANOM-003 (port scan): Check if unique_dst_ports > 100 → FAIL
  5. **Cross-resource rules** (optional, Layer 3+):
     - NET-VPC-006: Private subnet has direct IGW route (requires checking subnet → IGW edge in topology)
     - May use network_topology graph for traversals
  6. **SKIP logic**: Runtime rules skipped on posture-mode rows (and vice versa)
- Use shared utility: Import from `shared/common/rule_evaluator.py`
- Batch writing: Use network_db_writer.batch_insert_findings() with batch_size=1000
- Dependencies: 2.2 (rules must exist), 2.3 (transformed data), 0.5 (shared rule_evaluator)
- Consumed by: 2.5 (network_reporter.py)
- Reference: NEW_ENGINES_ETL_RULES.md Section 2.4 "Rule Evaluator"

#### Task 2.5: Build network_reporter.py (STAGE 3 — Report) `[Seq 61 | BD]`
**Story:** As the network reporter, I need to aggregate findings into scan-level summaries, extract detailed anomalies, update baselines for next scan, and prepare reports for compliance/threat dashboard consumption.

**Implementation Details:**
- Location: `engines/engine_network/reporter/network_reporter.py`
- Input tables:
  - `network_findings` WHERE network_scan_id = $scan_id — all findings from this scan
  - `network_anomalies` (if populated by evaluator, or built here)
  - `network_baselines` — current baselines for comparison
  - `event_aggregations` — raw flow data for baseline recomputation
- Processing steps:
  1. **Build network_report (1 row per scan)**:
     - SELECT network_scan_id, tenant_id, orchestration_id, scan_start_time=NOW()
     - Count findings by severity: COUNT(*) WHERE severity='critical' AS critical_count, etc.
     - COUNT(*) WHERE result='FAIL' AS total_failures
     - COUNT DISTINCT resource_id WHERE finding_type='misconfiguration' AS failed_sg_count, failed_nacl_count, etc.
     - Anomaly stats: COUNT(*) WHERE finding_type='anomaly' AS anomaly_count
     - IOC match count: COUNT(*) WHERE finding_type='threat' AND is_malicious_ip=TRUE AS malicious_ip_connections
     - Top 5 failing rules: GROUP BY rule_id ORDER BY COUNT(*) DESC LIMIT 5
     - Risk score: Weighted (critical×10 + high×5 + medium×2 + low×1) / total_findings, capped at 100
     - Exposed ports summary: ARRAY_AGG(DISTINCT port) WHERE violation='open_to_internet'
  2. **Extract network_anomalies** (detailed anomaly rows):
     - For each FAIL finding WHERE finding_type='anomaly':
       - INSERT network_anomalies: (tenant_id, anomaly_type, severity, src_ip, dst_ip, dst_port, bytes_total, baseline_bytes, deviation_factor, src_resource_id, dst_resource_id, rule_id, evidence, is_active=TRUE)
     - For each FAIL finding WHERE finding_type='threat' AND is_malicious_ip=TRUE:
       - INSERT network_anomalies: (anomaly_type='malicious_ip', threat_intel_source, src_ip or dst_ip, rule_id, is_active=TRUE)
  3. **Update network_baselines** (rolling 14-day computation):
     - For each unique src_ip in event_aggregations (last 14 days rolling window):
       - Compute rolling statistics: PERCENTILE(total_bytes, 0.5) as baseline_avg, PERCENTILE(total_bytes, 0.95) as baseline_p95, STDDEV(total_bytes)
       - INSERT or UPDATE network_baselines: (resource_id=$src_ip, metric_type='outbound_bytes', baseline_avg, baseline_p95, std_deviation, sample_count=row_count(), computed_at=NOW())
     - For each src_ip: also compute 'connection_count' and 'unique_dst' metrics
     - Query: `SELECT src_ip, COUNT(*) as flow_count, SUM(total_bytes) as total_bytes, AVG(total_bytes) as avg_bytes FROM event_aggregations WHERE window_start > NOW()-14DAYS GROUP BY src_ip`
     - This data is used by next scan's ETL for deviation detection
  4. **Trend analysis** (optional):
     - Compare current scan findings to previous scan (if available)
     - Track delta: new failures, resolved findings, recurring issues
- Aggregation logic: CASE expressions for severity bucketing, window functions for ranking, array aggregation for lists
- Dependencies: 2.4 (findings must be written)
- Consumed by: 2.7 (api_server.py), dashboard (reads network_report, network_anomalies)
- Reference: NEW_ENGINES_ARCHITECTURE.md "Engine 2 Output tables" (lines 560-655)

#### Task 2.6: Build network_db_writer.py `[Seq 62 | BD]`
**Story:** As the database writer utility, I need reusable batch insert functions so ETL/Evaluator/Reporter stages can efficiently write large volumes of network data without code duplication.

**Implementation Details:**
- Location: `engines/engine_network/db/network_db_writer.py`
- Functions (class methods):
  - `batch_insert_transformed(rows: List[dict], batch_size=1000)` — insert into network_input_transformed
  - `batch_insert_topology(nodes: List[dict], edges: List[dict], batch_size=500)` — insert into network_topology (nodes and edges, or denormalized adjacency)
  - `batch_insert_findings(rows: List[dict], batch_size=1000)` — insert into network_findings
  - `batch_insert_anomalies(rows: List[dict], batch_size=1000)` — insert into network_anomalies
  - `batch_insert_baselines(rows: List[dict], upsert=True, batch_size=500)` — insert or update network_baselines (upsert logic for rolling recompute)
  - `batch_insert_report(row: dict)` — single-row insert into network_report
  - `update_orchestration(scan_id: UUID)` — UPDATE scan_orchestration SET network_scan_id=$scan_id
- Implementation: asyncpg or psycopg2 with prepared statements, ON CONFLICT handling for baseline upsert
- Error handling: Retry on transient DB errors, skip duplicates where safe, log all failures
- Dependencies: 2.1 (schema), asyncpg/psycopg2 library
- Consumed by: 2.3, 2.4, 2.5

#### Task 2.7: Build api_server.py (Network Engine API) `[Seq 63 | AD]`
**Story:** As the FastAPI server, I need to expose HTTP endpoints so the pipeline_worker can trigger network scans, check health, and retrieve findings without direct database access.

**Implementation Details:**
- Location: `engines/engine_network/api_server.py`
- Framework: FastAPI (Python)
- Port: 8007
- Endpoints:
  - **POST /api/v1/scan** — Main entry point for pipeline
    - Input: `{orchestration_id: UUID, discovery_scan_id: UUID, network_scan_id: UUID, mode: 'posture'|'runtime'|'both'}`
    - Optional: mode param to run only posture checks (faster, Q1) or wait for runtime flow data (Q2)
    - Logic: Call network_etl.run() → network_evaluator.run() → network_reporter.run() → network_db_writer.update_orchestration() in sequence
    - Output: `{status: "success", network_scan_id: UUID, findings_count: int, critical_count: int, anomaly_count: int, scan_duration_ms: int, timestamp: ISO8601}`
  - **GET /api/v1/health/live** — Liveness probe
    - Returns: `{status: "ok"}`
  - **GET /api/v1/health/ready** — Readiness probe
    - Connects to RDS, returns `{status: "ready", db: "ok"}` or error
  - **GET /api/v1/metrics** — Prometheus metrics
    - Returns: `network_scans_total, network_findings_total, network_anomalies_total, scan_duration_seconds_bucket, rule_evaluations_total`
  - **GET /api/v1/report/{scan_id}** — Retrieve scan report
    - Returns JSON: network_report row, top failing rules, top anomalies, exposed ports summary, risk score
  - **GET /api/v1/topology/{scan_id}** — Retrieve network topology (for visualization)
    - Returns: network_topology nodes and edges in JSON format (compatible with D3.js or Cytoscape.js)
  - **GET /api/v1/baselines/{account_id}** — Current baseline stats per IP (for debugging anomaly sensitivity)
    - Returns: network_baselines rows for transparency
- Error handling: Try/except around each stage, log exceptions, meaningful HTTP error codes
- Async: Use async/await for I/O
- Dependencies: 2.3-2.6, FastAPI, asyncpg
- Reference: engine_check api_server.py pattern

#### Task 2.8: Create Dockerfile and Kubernetes Manifest `[Seq 64 | DO]`
**Story:** As the deployment artifact, I need a containerized image and K8s manifest so the network engine can be deployed to EKS and triggered by pipeline_worker.

**Implementation Details:**
- Location:
  - `engines/engine_network/Dockerfile` (multi-stage build)
  - `deployment/aws/eks/engines/engine-network.yaml` (K8s Deployment + Service)
- Dockerfile:
  - Base: `python:3.11-slim`
  - Stage 1 (build): Install dependencies, create venv, pip install requirements.txt
  - Stage 2 (runtime): Copy venv, add non-root user, EXPOSE 8007, ENTRYPOINT for uvicorn
  - No additional services (unlike engine_container which might embed Trivy — not applicable here)
- Kubernetes manifest:
  - Deployment: name=engine-network, namespace=threat-engine-engines, replicas=1
  - Image: `<ecr-uri>/engine-network:v1.0`
  - Resources: requests (cpu: 1000m, memory: 1Gi) — more CPU for topology building and flow processing
  - Limits (cpu: 4, memory: 4Gi)
  - Environment: DB_HOST, DB_PORT, DB_NAME, DB_USER (ConfigMap), DB_PASSWORD (Secret)
  - Health checks: livenessProbe (GET /api/v1/health/live), readinessProbe (GET /api/v1/health/ready)
  - Service: type=ClusterIP, port=8007
- Dependencies: 2.7 (api_server.py)
- Consumed by: 2.10 (integration test), deployment

#### Task 2.9: Unit Tests `[Seq 65 | QA]`
**Story:** As the test suite, I need comprehensive unit tests covering topology building, IOC matching, baseline deviation detection, rule evaluation, and anomaly extraction so changes don't introduce regressions.

**Implementation Details:**
- Location: `engines/engine_network/tests/`
  - `test_network_etl.py` — topology builder, flow aggregation joins, baseline deviations, IOC matching
  - `test_network_evaluator.py` — rule evaluation (field_check, threshold, set_membership for IOCs)
  - `test_network_reporter.py` — aggregation, baseline recomputation, anomaly extraction
  - `test_network_db_writer.py` — batch insert functions
- Test data: pytest fixtures with mock discovery_findings (SGs, NACLs, VPCs), event_aggregations, threat_intel_ioc
- Key test cases:
  - ETL topology: Verify adjacency map correctly links VPC→subnets→SGs, verify IGW attachment detection
  - IOC matching: Verify src_ip match against threat_intel_ioc, verify is_malicious_ip flag set
  - Baseline deviation: Verify deviation_factor = actual / baseline, verify 3.0x threshold triggers anomaly
  - Evaluator: Verify NET-SG-001 FAIL for SSH open to 0.0.0.0/0, verify NET-ANOM-001 FAIL for spike, verify SKIP for inapplicable rules
  - Reporter: Verify critical_count aggregation, verify baseline recomputation with correct PERCENTILE logic, verify network_anomalies extraction
  - Port scan detection: Verify >100 unique dst_ports in 5min triggers NET-ANOM-003
- Framework: pytest with conftest fixtures for DB mocking
- Coverage: >85% code coverage
- Run: `pytest engines/engine_network/tests/ -v --cov=engines.engine_network`

#### Task 2.10: Integration Test `[Seq 66 | QA]`
**Story:** As the end-to-end test, I need a full pipeline simulation to verify all stages work together with realistic Tier 1 (network config) + Tier 2 (flow logs) + Tier 3 (threat intel) data.

**Implementation Details:**
- Location: `engines/engine_network/tests/test_integration.py`
- Setup:
  - Temporary PostgreSQL database with all schemas applied (network_schema.sql + log_collector_schema.sql + external_collector tables)
  - Seed data:
    - 2 VPCs (Tier 1: discovery_findings)
    - 1 VPC with flow logs enabled, 1 without (for NET-VPC-001 check)
    - 3 Security Groups (Tier 1): one with SSH open to 0.0.0.0/0 (fail NET-SG-001), one secure
    - 1 ALB listener with HTTP protocol (fail NET-ALB-001)
    - 1 NACL with unrestricted inbound (fail NET-NACL-001)
    - event_aggregations: 10 rows representing flow data over 1 hour (src_ip, dst_ip, bytes, etc.)
    - event_aggregations with one spike: src_ip making 1000x normal bytes in 5min (for NET-ANOM-001)
    - threat_intel_ioc: 5 malicious IPs, one matches dst_ip in event_aggregations (for NET-ANOM-002)
    - network_baselines: pre-populate with 14-day rolling stats so deviation can be computed
    - 12+ network_rules rows (from seed_network_rules.sql)
- Execution (POSTURE MODE):
  - Call network_etl.run(orchestration_id, mode='posture') → verify network_input_transformed has SG/VPC/NACL rows with rule fields
  - Call network_evaluator.run(network_scan_id, mode='posture') → verify findings:
    - Expect: 1 FAIL for NET-SG-001 (SSH open)
    - Expect: 1 FAIL for NET-VPC-001 (flow logs off)
    - Expect: 1 FAIL for NET-ALB-001 (HTTP)
    - Expect: 1 FAIL for NET-NACL-001 (unrestricted)
  - Call network_reporter.run(network_scan_id, mode='posture') → verify report:
    - critical_count >= 1 (SSH open)
    - total_failures == 4
  - Verify network_topology graph is built with correct node and edge count
- Execution (RUNTIME MODE):
  - Call network_etl.run(orchestration_id, mode='runtime') → verify flow aggregation rows in network_input_transformed with deviation_factor, is_malicious_ip flags
  - Call network_evaluator.run(network_scan_id, mode='runtime') → verify findings:
    - Expect: 1 FAIL for NET-ANOM-001 (outbound spike 1000x > 3x threshold)
    - Expect: 1 FAIL for NET-ANOM-002 (malicious IP match)
  - Call network_reporter.run(network_scan_id, mode='runtime') → verify anomalies extracted:
    - network_anomalies has 2+ rows (data exfiltration + malicious IP)
    - anomaly_type correct (data_exfil, malicious_ip)
    - deviation_factor populated correctly
  - Verify network_baselines updated with new rolling stats
- Assertions:
  - network_input_transformed row count >= 6 (at least SG, VPC, NACL, ALB listener, + flow rows)
  - Findings count >= 4 for posture, >= 2 for runtime
  - network_topology nodes >= 4, edges >= 3
  - network_anomalies has entries with correct anomaly_type and severity
  - network_report risk_score >= 50 (multiple critical findings)
  - Baseline recomputation updated baseline_avg and baseline_p95
- Cleanup: Drop temp database
- Run: `pytest engines/engine_network/tests/test_integration.py -v -s`
- Duration: <30 seconds (local DB, no API calls)

**Note:** engine_network no longer has its own SQS flow worker. The log_collector (Tier 2) handles all flow log parsing and aggregation. The ETL stage reads pre-processed data and joins it into `network_input_transformed`.

---

## Phase 3: engine_supplychain (P2)
**Branch:** `feature/engine-supplychain`
**Port:** 8008 | **DB:** `threat_engine_supplychain`
**Layer:** 3 (runs after container + secops)

### Data Sources
```
FROM Tier 1 (discovery_findings):
  aws.lambda.function_code     → Lambda ZIP code locations
  aws.codecommit.manifest_file → CodeCommit package manifests
  aws.codeartifact.repository  → internal package registries
  aws.codeartifact.package     → internal packages (dep confusion check)

FROM Tier 3 (external_collector output):
  external_findings            → GitHub/GitLab repo manifests
  registry_images.sbom         → container image SBOMs (from Trivy)
  vuln_cache                   → CVE data for package vulnerability matching
  package_metadata             → public registry data (dep confusion, provenance)

FROM engine_container (cross-engine):
  container_sbom               → image-level SBOM for aggregation
```

### 4-Stage Processing Flow
```
STAGE 1 — ETL (supplychain_etl.py)
  READ:  discovery_findings WHERE resource_type IN (lambda.function_code,
         codecommit.manifest_file, codeartifact.repository,
         codeartifact.package) [Tier 1]
       + external_findings [Tier 3] — GitHub/GitLab repo manifests
       + registry_images.sbom [Tier 3] — container image SBOMs
       + vuln_cache [Tier 3] — CVE/EPSS/KEV for package matching
       + package_metadata [Tier 3] — public registry metadata
       + container_sbom [cross-engine from engine_container]
  PARSE: manifest_parser extracts {name, version, ecosystem} from all manifest
         formats (package.json, requirements.txt, go.mod, pom.xml, Gemfile,
         Cargo.toml, composer.json)
  JOIN:  Merge all SBOMs into unified component list, cross-reference each
         package against vuln_cache (CVE matches), package_metadata (dep
         confusion, provenance, license), threat_intel_ioc (malicious packages)
  WRITE: → supplychain_input_transformed
         (one row per package with source, version, CVE matches, dep confusion
          flag, provenance score, license type, malicious flag)
       → sbom_manifests (parsed manifest inventory)
       → sbom_components (normalized component list)

STAGE 2 — EVALUATE (supplychain_evaluator.py)
  READ:  supplychain_rules WHERE is_active = TRUE
  EVAL:  Apply each rule against supplychain_input_transformed rows
         SC-CVE-*: critical/high CVE in dependencies, KEV match
         SC-MAL-*: known malicious package, typosquat detection
         SC-PROV-*: unpinned version, stale dependency, low maintainer count
         SC-CONF-*: dependency confusion (internal name exists on public registry)
         SC-LIC-*: copyleft license in commercial project, unknown license
  WRITE: → supplychain_findings (PASS/FAIL/SKIP/ERROR per rule per package)

STAGE 3 — REPORT (supplychain_reporter.py)
  READ:  supplychain_findings for current scan
  AGG:   Total packages, vulnerable count by severity, dep confusion hits,
         license breakdown, SBOM coverage percentage
  WRITE: → supplychain_report (one row per scan)

STAGE 4 — COORDINATE
  UPDATE: scan_orchestration.supplychain_scan_id
  NOTIFY: pipeline_worker "supplychain done"
```

### Technical Tasks

#### Task 3.1: Create Database Schema `[Seq 67 | DE]`
**Story:** Establish persistent storage for supply chain artifacts (manifests, components, rules, findings). This is the foundation for all subsequent ETL stages and enables cross-scan trending of supply chain risks.

**Implementation Details:**
- **Location:** `/sessions/sharp-eloquent-ramanujan/mnt/threat-engine/shared/database/schemas/supplychain_schema.sql`
- **Input:** Schema template from NEW_ENGINES_ARCHITECTURE.md Engine 3 section (sbom_manifests, sbom_components core tables)
- **Processing:**
  1. Create `supplychain_rules` table (ID, name, category, severity, condition JSONB, frameworks array)
  2. Create `supplychain_input_transformed` table (scan_id, package_name, version, source_type, source_arn, cve_matches JSONB, dep_confusion bool, is_pinned bool, license_category, malicious_flag bool)
  3. Create `supplychain_findings` table (scan_id, rule_id, package_id, result ENUM[PASS/FAIL/SKIP/ERROR], matched_condition JSONB, severity, frameworks)
  4. Create `sbom_manifests` table (manifest_id, scan_id, source_type, source_id, sbom_format, total_components, direct_deps, transitive_deps, critical_findings, high_findings, sbom_json JSONB)
  5. Create `sbom_components` table (component_id, manifest_id, package_name, version, ecosystem, purl, is_direct, depth_level, license, cve_count)
  6. Create `supplychain_report` table (scan_id, total_packages, vulnerable_count_critical, vulnerable_count_high, dep_confusion_hits, license_violations, sbom_coverage_pct, scanned_at)
  7. Add foreign keys: `_findings.rule_id → supplychain_rules.rule_id`, `sbom_components.manifest_id → sbom_manifests.manifest_id`
  8. Add indexes: `(scan_id, package_name)` on `_input_transformed`, `(scan_id, result)` on `_findings`
- **Output:** PostgreSQL schema in threat_engine_supplychain database
- **Key considerations:**
  - JSONB columns for vuln_cache, dep_confusion metadata, license details allow flexibility
  - Use UUID for consistency with other engines
  - Manifest source type enum: container_image | lambda | code_repo | package_registry
- **Dependencies:** Task 0.4 (DB infrastructure)
- **Consumed by:** All subsequent supply chain tasks (3.2-3.11)
- **Reference:** NEW_ENGINES_ARCHITECTURE.md § Engine 3, lines 836-880

#### Task 3.2: Seed supplychain_rules Table `[Seq 68 | DE]`
**Story:** Pre-populate the rule engine with 10 initial supply chain security rules covering CVE detection, malicious packages, dependency provenance, license compliance, and dependency confusion. DB-driven rules enable toggling detections without redeployment.

**Implementation Details:**
- **Location:** `/sessions/sharp-eloquent-ramanujan/mnt/threat-engine/shared/database/seeds/supplychain_rules_seed.sql`
- **Input:** Rule definitions from NEW_ENGINES_ETL_RULES.md Section 3.3, lines 514-553
- **Processing:**
  1. Insert SC-CVE-001: "Package with critical CVE" → field_check on vulnerability_count > 0 with severity=critical → maps to PCI-DSS, HIPAA, SOC2
  2. Insert SC-CVE-002: "Package CVE in CISA KEV catalog" → set_membership check against cve_kev_list → critical severity → CISA_CE, PCI-DSS
  3. Insert SC-MAL-001: "Known malicious package" → set_membership against malicious_packages table → critical severity
  4. Insert SC-MAL-002: "Package name typosquatting pattern" → field_check is_typosquat_suspect = true → high severity
  5. Insert SC-PROV-001: "Dependency pinned to inexact version" → field_check is_pinned = false → medium severity → SOC2, ISO27001
  6. Insert SC-PROV-002: "Abandoned package (>2 years no update)" → field_check days_since_update > 730 → medium severity
  7. Insert SC-PROV-003: "Package not signed" → field_check is_signed = false → low severity → NIST_800-53
  8. Insert SC-CONF-001: "Internal package name exists on public registry" → field_check public_registry_exists = true → high severity → dep_confusion detection
  9. Insert SC-LIC-001: "Copyleft license (GPL) in commercial product" → field_check license_category = copyleft → high severity → ISO27001
  10. Insert SC-LIC-002: "Unknown or unrecognized license" → field_check license_category = unknown → medium severity
- **Output:** 10 rows inserted into supplychain_rules table
- **Key considerations:**
  - Rule IDs must be unique and follow SC-{CATEGORY}-{NUMBER} pattern
  - Condition JSONB must be validatable by rule_evaluator.py shared utility
  - Include frameworks array for compliance mapping
- **Dependencies:** Task 3.1 (schema)
- **Consumed by:** Task 3.5 (evaluator reads rules)
- **Reference:** NEW_ENGINES_ETL_RULES.md § 3.3, lines 512-553

#### Task 3.3: Build manifest_parser.py Module `[Seq 69 | BD]`
**Story:** Create a multi-format manifest parser that normalizes package dependencies from all major ecosystems (npm, pip, Go, Maven, Ruby, Rust, PHP, Java) into a canonical {name, version, ecosystem} format. This enables downstream rules to be ecosystem-agnostic.

**Implementation Details:**
- **Location:** `/sessions/sharp-eloquent-ramanujan/mnt/threat-engine/engine_supplychain/supplychain_engine/manifest_parser.py`
- **Input:** Raw manifest file content (string), file name or type hint
- **Processing:**
  1. Detect manifest type from filename or parse syntax:
     - package.json → npm | yarn | pnpm
     - requirements.txt → pip
     - Pipfile / poetry.lock → poetry
     - go.mod → Go modules
     - pom.xml → Maven
     - Gemfile / Gemfile.lock → Ruby Bundler
     - Cargo.toml / Cargo.lock → Rust Cargo
     - composer.json / composer.lock → PHP Composer
     - build.gradle / gradle.properties → Gradle (Java)
     - pyproject.toml → Python (setuptools, poetry, hatch)
     - packages.config → NuGet (.NET)
     - yarn.lock → Yarn (npm variant)
  2. Parse each format:
     - JSON formats (package.json, composer.json): Parse JSON, extract dependencies object
     - TOML formats (Cargo.toml, pyproject.toml): Use tomllib or equivalent parser
     - Lock files (Gemfile.lock, Cargo.lock, poetry.lock): Parse key-value pairs
     - XML (pom.xml): Use ElementTree XML parser, extract dependency section
     - Plain text (requirements.txt, go.mod): Line-by-line split on whitespace/newlines
  3. For each dependency, extract: name (package ID), version (constraint or exact), is_direct (true if in top-level deps, false if transitive)
  4. Normalize version constraints: ^ (npm caret), ~ (npm tilde), >= (Python), == (exact), * (wildcard) → flag as_pinned=true only if exact version (no ^, ~, *, >=, <=)
  5. Return list of dicts: [{"name": "lodash", "version": "^4.17.21", "ecosystem": "npm", "is_direct": true, "is_pinned": false}, ...]
- **Output:** Normalized dependency list suitable for SBOM generation and rule evaluation
- **Key considerations:**
  - Handle missing/empty manifests gracefully (return empty list, not exception)
  - Lock files provide pinned versions—mark is_pinned=true for lock file entries
  - Transitive dependency detection: if manifest is a lock file, set is_direct=false for all entries
  - Test each format independently (see Task 3.10)
- **Dependencies:** None (standalone module)
- **Consumed by:** Task 3.4 (ETL parser invocation)
- **Reference:** NEW_ENGINES_ETL_RULES.md § 3.3, lines 459-483

#### Task 3.4: Build supplychain_etl.py (STAGE 1 — Transform) `[Seq 70 | BD]`
**Story:** Extract, parse, and normalize all supply chain artifacts (Lambda code, Git manifests, container SBOMs) into a unified input table ready for rule evaluation. This is the data transformation layer that handles the complexity of multi-source SBOM aggregation.

**Implementation Details:**
- **Location:** `/sessions/sharp-eloquent-ramanujan/mnt/threat-engine/engine_supplychain/supplychain_engine/supplychain_etl.py`
- **Input:**
  - `discovery_findings` WHERE resource_type IN ('aws.ecr.image', 'aws.lambda.function_code', 'aws.codecommit.manifest_file', 'aws.codeartifact.repository', 'aws.codeartifact.package', 'github.repository.manifest_file') [Tier 1]
  - `container_sbom` (from engine_container output) — contains: image_id, package_name, package_version, package_type, purl, is_direct_dep [cross-engine read]
  - `vuln_cache` (Tier 3 external_collector) — columns: purl, cve_id, severity, epss_score
  - `package_metadata` (Tier 3 external_collector) — columns: package_name, ecosystem, latest_version, last_publish_date, maintainer_count, license
  - `threat_intel_ioc` (Tier 3 external_collector) — columns: ioc_type ('malicious_package'), value, threat_level
- **Processing:**
  1. **Query Lambda functions (Tier 1):**
     ```sql
     SELECT df.resource_id as function_arn, df.emitted_fields->>'CodeLocation' as code_location_url
     FROM discovery_findings df
     WHERE df.resource_type = 'aws.lambda.function_code'
     AND df.orchestration_id = $1
     ```
  2. **Download and extract Lambda ZIP files:**
     - For each function_arn, invoke manifest_parser.download_lambda_package(code_location_url)
     - Use new urllib method from ETL_RULES Section 3.3, lines 488-509
     - Extract all manifest files (package.json, requirements.txt, etc.) from ZIP
     - For each extracted manifest, call manifest_parser.parse() to get normalized deps
  3. **Query and parse CodeCommit manifests (Tier 1):**
     ```sql
     SELECT df.resource_id as manifest_path, df.emitted_fields->>'FileContent' as content
     FROM discovery_findings df
     WHERE df.resource_type = 'aws.codecommit.manifest_file'
     AND df.orchestration_id = $1
     ```
     - Call manifest_parser.parse(content, manifest_path) for each
  4. **Query GitHub/GitLab manifests (Tier 3):**
     ```sql
     SELECT ef.resource_id as repo_url, ef.emitted_fields->>'ManifestContent' as content,
            ef.resource_type
     FROM external_findings ef
     WHERE ef.orchestration_id = $1 AND ef.resource_type LIKE 'github.%manifest%'
     ```
     - Call manifest_parser.parse(content, filename) for each
  5. **Read container image SBOMs (cross-engine):**
     ```sql
     SELECT cs.package_name, cs.package_version, cs.package_type, cs.purl, cs.is_direct_dep,
            ci.image_id, ci.repository, ci.tag
     FROM container_sbom cs
     JOIN container_images ci ON ci.image_id = cs.image_id
     WHERE ci.orchestration_id = $1
     ```
  6. **Build sbom_manifests table:**
     - One row per artifact (Lambda function, repo, container image)
     - source_type: 'lambda' | 'code_repo' | 'container_image' | 'package_registry'
     - total_components: count of unique packages after parsing
     - direct_deps: count where is_direct_dep = true
     - transitive_deps: count where is_direct_dep = false
  7. **Build supplychain_input_transformed table:**
     - For each unique (package_name, version) pair across all sources:
       ```sql
       INSERT INTO supplychain_input_transformed VALUES (
         scan_id, package_name, version, source_type, source_arn,
         cve_count, cve_matches (JSONB array of {cve_id, severity}),
         is_pinned, is_signed, is_typosquat_suspect,
         license_category, days_since_last_update,
         public_registry_exists (bool for dep confusion),
         is_malicious (bool from threat_intel_ioc)
       )
       ```
  8. **Cross-reference against Tier 3 data:**
     - For each package, LEFT JOIN vuln_cache ON purl = purl → collect CVE_IDs
     - LEFT JOIN package_metadata ON (name, ecosystem) → get license, last_publish_date, maintainer_count
     - LEFT JOIN threat_intel_ioc WHERE value = package_name → check for malicious flag
     - For internal package detection: check if package_name exists in package_metadata for public ecosystem (indicates dep confusion risk)
  9. **Populate computed fields:**
     - is_pinned: true if version contains exact specifier (no ^, ~, >=, etc.)
     - days_since_last_update: current date minus last_publish_date from package_metadata
     - is_typosquat_suspect: check package_name against common typosquatting patterns (Jaro-Winkler distance from popular package names)
     - is_signed: mark true if npm package has npm provenance signature (requires external check)
- **Output:**
  - `supplychain_input_transformed`: One row per (package_name, version, source) combination
  - `sbom_manifests`: One row per scanned artifact (6 columns: manifest_id, scan_id, source_type, source_id, sbom_format, component counts)
  - `sbom_components`: One row per unique package (component_id, manifest_id, package_name, version, ecosystem, purl, is_direct, depth, license, cve_count)
- **Key considerations:**
  - Lambda ZIP downloads use presigned URLs (1-hour TTL) — must handle timeout gracefully
  - Transitive dependencies from lock files should be marked is_direct_dep=false for provenance tracking
  - CVE matching uses PURL (Package URL) standard for consistent cross-ecosystem lookup
  - Malicious package detection requires exact name match in threat_intel_ioc
  - Set default TTL on cache reads (e.g., vuln_cache refreshed daily, check staleness)
- **Dependencies:** Task 3.1 (schema), Task 3.3 (manifest_parser), Tasks 0.1.1-0.1.12 (discoveries engine configured), Tasks 0.3.1-0.3.17 (external_collector running)
- **Consumed by:** Task 3.5 (evaluator reads _input_transformed)
- **Reference:** NEW_ENGINES_ETL_RULES.md § 3.3, lines 434-483; NEW_ENGINES_ARCHITECTURE.md § Engine 3, lines 784-833

#### Task 3.5: Build supplychain_evaluator.py (STAGE 2 — Evaluate) `[Seq 71 | BD]`
**Story:** Apply all active supply chain security rules against the normalized input table and generate findings (PASS/FAIL/SKIP/ERROR) per rule per package. Rules are loaded from the database, allowing non-code-based rule updates.

**Implementation Details:**
- **Location:** `/sessions/sharp-eloquent-ramanujan/mnt/threat-engine/engine_supplychain/supplychain_engine/supplychain_evaluator.py`
- **Input:**
  - `supplychain_rules` WHERE is_active = TRUE (loaded via shared/common/rule_loader.py)
  - `supplychain_input_transformed` for current scan_id
- **Processing:**
  1. **Load all active rules:**
     ```python
     from shared.common.rule_loader import load_rules
     rules = load_rules('supplychain', db_conn, is_active=True)
     # Returns: [{'rule_id': 'SC-CVE-001', 'condition': {...}, 'severity': 'critical', ...}, ...]
     ```
  2. **For each rule, evaluate against all _input_transformed rows:**
     - Use shared/common/rule_evaluator.py to evaluate condition JSONB
     - Condition types: field_check, set_membership, threshold, composite
     - Field check: {"field": "cve_count", "operator": "gt", "value": 0}
     - Set membership: {"field": "purl", "operator": "in_set", "set_table": "malicious_packages", "set_column": "purl"}
  3. **Example rule evaluation flows:**
     - **SC-CVE-001** (critical CVE): For each row, check cve_matches JSONB array, count entries where severity='critical', if count > 0 → FAIL
     - **SC-MAL-002** (typosquatting): Check is_typosquat_suspect bool field, if true → FAIL
     - **SC-CONF-001** (dep confusion): Check public_registry_exists bool, if true AND source = internal_registry → FAIL
     - **SC-LIC-001** (copyleft): Check license_category field, if = 'copyleft' AND project_type = 'commercial' → FAIL (project_type from discovery_findings.emitted_fields)
  4. **Write findings:**
     ```python
     for rule in rules:
       for row in input_transformed:
         result = evaluate_condition(rule['condition'], row)
         insert_finding(
           scan_id, rule_id, package_id (purl or name),
           result, matched_condition_json, rule['severity'], rule['frameworks']
         )
     ```
     - Result: PASS (all conditions met), FAIL (some conditions not met), SKIP (condition N/A for this resource), ERROR (evaluation exception)
  5. **Batch insert via shared utility:**
     ```python
     from shared.common.finding_writer import batch_insert_findings
     batch_insert_findings(findings_list, target_table='supplychain_findings', batch_size=1000)
     ```
- **Output:** `supplychain_findings` table (scan_id, rule_id, package_id, result, matched_condition JSONB, severity, frameworks)
- **Key considerations:**
  - Reuse shared rule_evaluator and rule_loader from shared/common/—do not duplicate logic
  - Handle rules that are N/A for a resource gracefully (SKIP result)
  - Capture matched_condition JSON for audit trail
  - Batch writes for performance (1000 rows per insert)
- **Dependencies:** Task 3.1 (schema), Task 3.2 (rules seeded), Task 3.4 (ETL), Tasks 0.5.1-0.5.3 (shared utilities), Tasks 0.3.1-0.3.17 (external_collector)
- **Consumed by:** Task 3.6 (reporter)
- **Reference:** NEW_ENGINES_ARCHITECTURE.md § Engine 3, lines 812-821

#### Task 3.6: Build supplychain_reporter.py (STAGE 3 — Report) `[Seq 72 | BD]`
**Story:** Aggregate rule evaluation results into a scan-level summary (one row per scan) with metrics on vulnerable packages, license violations, and SBOM coverage. The summary drives dashboarding and trending.

**Implementation Details:**
- **Location:** `/sessions/sharp-eloquent-ramanujan/mnt/threat-engine/engine_supplychain/supplychain_engine/supplychain_reporter.py`
- **Input:** `supplychain_findings` WHERE scan_id = $1
- **Processing:**
  1. **Count findings by result and severity:**
     ```sql
     SELECT result, severity, COUNT(*) as count
     FROM supplychain_findings
     WHERE scan_id = $1
     GROUP BY result, severity
     ```
  2. **Compute metrics:**
     - total_packages: COUNT(DISTINCT package_id) from supplychain_input_transformed
     - vulnerable_count_critical: COUNT(*) WHERE result='FAIL' AND severity='critical'
     - vulnerable_count_high: COUNT(*) WHERE result='FAIL' AND severity='high'
     - dep_confusion_hits: COUNT(*) WHERE result='FAIL' AND rule_id='SC-CONF-001'
     - license_violations: COUNT(*) WHERE result='FAIL' AND rule_id LIKE 'SC-LIC-%'
     - sbom_coverage_pct: (total_manifests_parsed / total_artifacts_scanned) * 100
  3. **Build supplychain_report row:**
     ```python
     INSERT INTO supplychain_report (scan_id, total_packages, vulnerable_count_critical,
       vulnerable_count_high, dep_confusion_hits, license_violations, sbom_coverage_pct, scanned_at)
     VALUES ($scan_id, $total_packages, $vuln_crit, $vuln_high, $dep_confusion,
       $license_violations, $sbom_coverage_pct, NOW())
     ```
- **Output:** `supplychain_report` (1 row per scan with aggregated metrics)
- **Key considerations:**
  - Coverage percentage: (successfully parsed manifests / discovered artifacts) × 100; if missing manifests, coverage < 100%
  - Include temporal stamp (scanned_at) for trending
- **Dependencies:** Task 3.5 (findings generated)
- **Consumed by:** Task 3.8 (API endpoint returns report), Task 6.1 (pipeline integration)
- **Reference:** NEW_ENGINES_ARCHITECTURE.md § Engine 3, lines 823-829

#### Task 3.7: Build supplychain_db_writer.py `[Seq 73 | BD]`
**Story:** Provide batch insert utilities for all 6 output tables with retry logic, transaction handling, and deduplication. This standardizes data writing across all stages.

**Implementation Details:**
- **Location:** `/sessions/sharp-eloquent-ramanujan/mnt/threat-engine/engine_supplychain/supplychain_engine/supplychain_db_writer.py`
- **Input:** Lists of dictionaries to insert (rules, manifests, components, findings, input_transformed rows, reports)
- **Processing:**
  1. Implement batch insert functions for each table with transaction handling
  2. Deduplication: Check for existing (scan_id, package_id) before insert to avoid duplication across re-runs
  3. Retry logic: 3 attempts with exponential backoff on connection errors
  4. Return inserted count and any errors
- **Output:** Standardized insert interface callable from all ETL/reporter stages
- **Key considerations:** Reuse shared/common/db_helpers pattern for consistency
- **Dependencies:** Task 3.1 (schema)
- **Consumed by:** Tasks 3.4, 3.5, 3.6 (all writing stages)
- **Reference:** Similar writers in engine_container, engine_network, etc.

#### Task 3.8: Build api_server.py (FastAPI Service) `[Seq 74 | AD]`
**Story:** Create the HTTP API entry point for supply chain scanning. The /api/v1/scan endpoint orchestrates ETL → Evaluate → Report → Coordinate stages in sequence.

**Implementation Details:**
- **Location:** `/sessions/sharp-eloquent-ramanujan/mnt/threat-engine/engine_supplychain/api_server.py`
- **Input:** POST /api/v1/scan with JSON payload: {orchestration_id, scan_id}
- **Processing:**
  1. Validate scan_id exists in scan_orchestration
  2. Call supplychain_etl.run(scan_id) → populates _input_transformed, sbom_manifests, sbom_components
  3. Call supplychain_evaluator.run(scan_id) → populates _findings
  4. Call supplychain_reporter.run(scan_id) → populates _report
  5. Update scan_orchestration.supplychain_scan_id = scan_id, supplychain_status = 'completed'
  6. Emit SQS message to pipeline_worker: {"engine": "supplychain", "scan_id": scan_id, "status": "completed"}
  7. Return JSON: {scan_id, status, metrics: {total_packages, vulnerable_count_critical, vulnerable_count_high}}
- **Endpoints:**
  - POST /api/v1/scan — trigger supply chain scan
  - GET /api/v1/health/live — K8s liveness probe
  - GET /api/v1/health/ready — K8s readiness probe (checks DB connectivity)
  - GET /api/v1/metrics — Prometheus metrics
- **Key considerations:**
  - Use FastAPI async patterns for non-blocking I/O (DB reads, Lambda ZIP downloads)
  - Implement 30-min timeout for scanning (Lambda downloads can be slow)
  - Log all exceptions for debugging
- **Dependencies:** Tasks 3.4-3.7 (processing modules)
- **Consumed by:** Task 3.9 (Dockerfile), Task 6.1 (pipeline_worker integration)
- **Reference:** api_server patterns in engine_container, engine_threat, etc.

#### Task 3.9: Create Dockerfile + Kubernetes Manifest `[Seq 75 | DO]`
**Story:** Containerize the engine and deploy to EKS cluster with proper resource limits, health checks, and environment variable configuration.

**Implementation Details:**
- **Location:**
  - Dockerfile: `/sessions/sharp-eloquent-ramanujan/mnt/threat-engine/engines/engine_supplychain/Dockerfile`
  - K8s manifest: `/sessions/sharp-eloquent-ramanujan/mnt/threat-engine/deployment/aws/eks/engines/engine-supplychain.yaml`
- **Processing:**
  1. **Dockerfile multi-stage build:**
     - Stage 1 (builder): Python 3.11, install requirements.txt (SQLAlchemy, FastAPI, pydantic, boto3, etc.)
     - Stage 2 (runtime): Copy from builder, create non-root user (appuser:appuser), expose port 8008
  2. **K8s deployment manifest:**
     - Replicas: 1 (supply chain scans typically sequential)
     - Container: `yadavanup84/threat-engine:engine-supplychain-v1.0`
     - Port: 8008
     - Env vars: DB_HOST, DB_PORT, DB_NAME (threat_engine_supplychain), DB_USER (from Secret), AWS_REGION
     - Resources: requests {cpu: 500m, memory: 1Gi}, limits {cpu: 2, memory: 4Gi}
     - Health checks: livenessProbe (GET /api/v1/health/live every 10s), readinessProbe (GET /api/v1/health/ready every 5s)
     - Service: ClusterIP port 8008
- **Output:** Container image + K8s deployment ready for kubectl apply
- **Key considerations:**
  - Set memory limits generous (4Gi) due to ZIP downloads and SBOM parsing
  - Use readinessProbe to avoid traffic during startup
- **Dependencies:** Task 3.8 (api_server.py must be complete)
- **Consumed by:** Task 3.10 (testing), Task 6.1 (cluster deployment)
- **Reference:** engine-container, engine-threat Dockerfile patterns

#### Task 3.10: Unit Tests `[Seq 76 | QA]`
**Story:** Validate each component (manifest parser, ETL, evaluator, reporter) in isolation with mock data and known inputs/outputs.

**Implementation Details:**
- **Location:** `/sessions/sharp-eloquent-ramanujan/mnt/threat-engine/engines/engine_supplychain/tests/`
- **Test files:**
  1. `test_manifest_parser.py`: Test each manifest format (npm, pip, go, maven, ruby, rust, php, java, python) with sample manifests
  2. `test_supplychain_etl.py`: Mock discovery_findings, container_sbom, vuln_cache; verify _input_transformed output
  3. `test_supplychain_evaluator.py`: Load sample rules, evaluate against synthetic input, verify PASS/FAIL results
  4. `test_supplychain_reporter.py`: Generate sample findings, verify report metrics calculation
  5. `test_api_server.py`: FastAPI TestClient, POST /api/v1/scan with mock orchestration_id, verify response
- **Test data:** Use realistic sample manifests (package.json, requirements.txt from public repos)
- **Coverage:** Aim for 80%+ code coverage
- **Key considerations:** Mock DB writes to avoid test DB side effects
- **Dependencies:** Task 3.8 (api_server)
- **Consumed by:** Task 3.11 (integration test), Tasks 6.1, 6.2, 6.7 (pipeline validation)
- **Reference:** Existing test patterns in engine_container_tests/, engine_threat_tests/

#### Task 3.11: Integration Test `[Seq 77 | QA]`
**Story:** End-to-end test seeding Tier 1, Tier 3, and container_sbom data, triggering a full scan, and verifying outputs in all 6 tables match expectations.

**Implementation Details:**
- **Location:** `/sessions/sharp-eloquent-ramanujan/mnt/threat-engine/engines/engine_supplychain/tests/test_integration.py`
- **Test scenario:**
  1. **Seed Tier 1 discovery_findings:**
     - AWS Lambda function with package.json in ZIP (mocked download)
     - AWS CodeCommit repo with requirements.txt
     - AWS CodeArtifact internal package reference
  2. **Seed Tier 3 external_collector data:**
     - vuln_cache rows: lodash@4.17.20 → CVE-2021-23337 (critical)
     - package_metadata: lodash → GPL license, abandoned
     - threat_intel_ioc: malicious-pkg-name → malicious package entry
  3. **Seed container_sbom (from engine_container):**
     - Sample image SBOM with 50 packages, 2 with known CVEs
  4. **Trigger scan:** POST /api/v1/scan with orchestration_id
  5. **Verify outputs:**
     - supplychain_input_transformed: 50+ rows (all packages from all sources)
     - sbom_manifests: 4 rows (lambda ZIP, codecommit manifest, container image, codeartifact)
     - sbom_components: 50+ rows (one per unique package)
     - supplychain_findings: All rules evaluated, expected FAILs for CVEs, malicious packages, abandoned deps
     - supplychain_report: metrics match (total_packages ~50, vulnerable_count_critical ≥ 2, etc.)
  6. **Verify scan_orchestration.supplychain_scan_id updated**
- **Assertions:**
  - Row counts match expectations
  - Severity levels correct (critical CVEs marked critical)
  - Frameworks arrays populated (PCI-DSS, HIPAA, etc.)
  - Timestamps present and recent
- **Dependencies:** All tasks 3.1-3.10
- **Consumed by:** Tasks 6.1, 6.2, 6.7 (full pipeline integration)
- **Reference:** Similar integration tests in engine_container_tests/, engine_network_tests/

---

## Phase 4: engine_api (P3)
**Branch:** `feature/engine-api`
**Port:** 8021 | **DB:** `threat_engine_api`
**Layer:** 1 (runs after collectors complete)

### Data Sources
```
FROM Tier 1 (discovery_findings):
  aws.apigateway.rest_api       → REST APIs (base info)
  aws.apigatewayv2.api          → HTTP/WebSocket APIs
  aws.apigateway.stage          → stage config (logging, caching, WAF)
  aws.apigateway.authorizer     → authorizer config (auth type, TTL)
  aws.apigatewayv2.route        → HTTP API routes (auth type per route)
  aws.elbv2.load_balancer       → ALBs
  aws.elbv2.listener            → ALB listener (port, protocol, TLS)
  aws.elbv2.listener_rule       → routing rules
  aws.wafv2.web_acl             → WAF rules + associated resources
  aws.appsync.graphql_api       → GraphQL API config (auth, logging)
  aws.logs.log_group            → access log group existence

FROM Tier 2 (log_collector output):
  event_aggregations            → API access log summaries (error rate, p99 latency, top paths)
```

### 4-Stage Processing Flow
```
STAGE 1 — ETL (api_etl.py)
  READ:  discovery_findings WHERE resource_type IN (apigateway.rest_api,
         apigatewayv2.api, apigateway.stage, apigateway.authorizer,
         apigatewayv2.route, elbv2.load_balancer, elbv2.listener,
         elbv2.listener_rule, wafv2.web_acl, appsync.graphql_api,
         logs.log_group) [Tier 1]
       + event_aggregations WHERE source_type = 'api_access' [Tier 2]
  JOIN:  Build unified API inventory (API GW + ALB + AppSync), map each
         endpoint with auth type, rate limit, TLS config, WAF association,
         logging status. Attach runtime stats (error rate, p99 latency,
         request volume) from event_aggregations per endpoint.
  WRITE: → api_input_transformed
         (one row per API endpoint with config + runtime stats flattened)
       → api_inventory (denormalized API service list)
       → api_endpoints (per-endpoint detail with auth/rate-limit metadata)

STAGE 2 — EVALUATE (api_evaluator.py)
  READ:  api_rules WHERE is_active = TRUE
  EVAL:  Apply each rule against api_input_transformed rows
         API-001→010: OWASP API Top 10 (broken auth, excessive data exposure,
           broken function-level auth, mass assignment, security misconfiguration,
           injection, improper asset mgmt, lack of rate limiting, etc.)
         API-011: WAF not associated
         API-RT-001: runtime anomaly (error rate spike, unusual HTTP methods)
  WRITE: → api_findings (PASS/FAIL/SKIP/ERROR per rule per endpoint)

STAGE 3 — REPORT (api_reporter.py)
  READ:  api_findings for current scan
  AGG:   Total APIs, endpoint count, auth coverage %, WAF coverage %,
         OWASP compliance score, top failing rules
  WRITE: → api_report (one row per scan)
         → api_access_summary (runtime stats snapshot for trending)

STAGE 4 — COORDINATE
  UPDATE: scan_orchestration.api_scan_id
  NOTIFY: pipeline_worker "api done"
```

### Technical Tasks

#### Task 4.1: Create Database Schema `[Seq 78 | DE]`
**Story:** Establish persistent storage for API inventory, endpoint configurations, security rules, and findings. Enables tracking of OWASP API Top 10 compliance across all API types (REST, HTTP, GraphQL, ALB).

**Implementation Details:**
- **Location:** `/sessions/sharp-eloquent-ramanujan/mnt/threat-engine/shared/database/schemas/api_schema.sql`
- **Input:** Schema template from NEW_ENGINES_ARCHITECTURE.md (Engine 5 section — note: Engine 5 is the api engine despite the naming)
- **Processing:**
  1. Create `api_rules` table (ID, title, owasp_category, severity, condition JSONB, frameworks array)
  2. Create `api_input_transformed` table (scan_id, endpoint_id, api_type, api_name, path, method, auth_required, auth_types JSONB, has_rate_limiting, tls_minimum, has_waf, logging_enabled, error_rate_pct, p99_latency_ms, request_volume)
  3. Create `api_findings` table (scan_id, rule_id, endpoint_id, result ENUM[PASS/FAIL/SKIP/ERROR], matched_condition JSONB, severity, frameworks)
  4. Create `api_inventory` table (api_id, scan_id, api_type, api_name, api_arn, resource_count, endpoints_count, auth_coverage_pct, waf_coverage_pct, created_at)
  5. Create `api_endpoints` table (endpoint_id, api_id, scan_id, path, method, auth_required, auth_type, rate_limited, tls_policy, cors_policy JSONB, logging_enabled, has_request_validator)
  6. Create `api_access_summary` table (summary_id, scan_id, endpoint_id, error_rate_pct, p99_latency_ms, request_volume, top_4xx_paths JSONB, top_5xx_paths JSONB, snapshot_timestamp)
  7. Create `api_report` table (scan_id, total_apis, total_endpoints, auth_coverage_pct, waf_coverage_pct, logging_coverage_pct, owasp_compliance_score, top_failing_rules JSONB, scanned_at)
  8. Add foreign keys: `_findings.rule_id → api_rules.rule_id`, `api_endpoints.api_id → api_inventory.api_id`
  9. Add indexes: `(scan_id, endpoint_id)` on `_input_transformed`, `(scan_id, result)` on `_findings`
- **Output:** PostgreSQL schema in threat_engine_api database
- **Key considerations:**
  - auth_types JSONB array stores all applicable auth mechanisms (IAM, Cognito, API_KEY, etc.)
  - Use enum for api_type: 'rest' | 'http' | 'websocket' | 'alb' | 'graphql'
  - CORS policy stored as JSONB for flexible querying
- **Dependencies:** Task 0.4 (DB infrastructure)
- **Consumed by:** All subsequent API tasks (4.2-4.10)
- **Reference:** NEW_ENGINES_ARCHITECTURE.md § Engine 5

#### Task 4.2: Seed api_rules Table `[Seq 79 | DE]`
**Story:** Pre-populate with 12 OWASP API Top 10 rules plus runtime anomaly detection. Each rule maps to specific OWASP categories (API1-10) covering authentication, authorization, injection, exposure, misconfiguration, logging, deprecation.

**Implementation Details:**
- **Location:** `/sessions/sharp-eloquent-ramanujan/mnt/threat-engine/shared/database/seeds/api_rules_seed.sql`
- **Input:** Rule definitions from NEW_ENGINES_ETL_RULES.md Section 3.4, lines 625-667
- **Processing:**
  1. Insert API-001: "API endpoint has no authorizer (Broken Object Auth)" → API2 → high severity → field_check auth_required = false
  2. Insert API-002: "API uses API_KEY only (no Cognito/JWT)" → API2 → medium severity → auth_types not contains COGNITO_USER_POOLS
  3. Insert API-003: "No WAF associated with API" → API7 → high severity → has_waf = false → PCI-DSS, OWASP
  4. Insert API-004: "No rate limiting configured" → API4 → high severity → has_rate_limiting = false → PCI-DSS
  5. Insert API-005: "API access logging not enabled" → API10 → high severity → logging_enabled = false
  6. Insert API-006: "TLS 1.0 or 1.1 allowed on listener" → API7 → high severity → tls_minimum in ['TLS_1_0', 'TLS_1_1']
  7. Insert API-007: "No request validator configured" → API8 → medium severity → request_validator = false
  8. Insert API-008: "CORS wildcard origin (*) configured" → API7 → high severity → cors_policy.allow_origins contains '*'
  9. Insert API-009: "X-Ray tracing disabled on API stage" → API10 → low severity → xray_tracing_enabled = false
  10. Insert API-010: "AppSync field-level logging not enabled" → API10 → medium severity → log_config.fieldLogLevel in ['NONE', null]
  11. Insert API-011: "Old API version still active alongside newer" → API9 → medium severity → has_newer_version = true (deprecation detection)
  12. Insert API-RT-001: "API error rate spike > 10% in 24h" → API7 → medium severity → threshold metric error_rate_pct > 10.0
- **Output:** 12 rows inserted into api_rules table
- **Key considerations:**
  - Rule IDs follow API-{NUMBER} pattern
  - OWASP categories are strings: API1, API2, ..., API10
  - Severity distribution: 7 high, 3 medium, 1 low
- **Dependencies:** Task 4.1 (schema)
- **Consumed by:** Task 4.4 (evaluator reads rules)
- **Reference:** NEW_ENGINES_ETL_RULES.md § 3.4, lines 623-667

#### Task 4.3: Build api_etl.py (STAGE 1 — Transform) `[Seq 80 | BD]`
**Story:** Unify API resources from three sources (API Gateway, ALB, AppSync) with their configurations (auth, TLS, WAF, logging) and runtime statistics (error rates, latency from Tier 2 logs) into a single endpoint-centric table for rule evaluation.

**Implementation Details:**
- **Location:** `/sessions/sharp-eloquent-ramanujan/mnt/threat-engine/engine_api/api_engine/api_etl.py`
- **Input:**
  - `discovery_findings` for resource types: aws.apigateway.rest_api, aws.apigatewayv2.api, aws.apigateway.stage, aws.apigateway.authorizer, aws.apigatewayv2.route, aws.elbv2.load_balancer, aws.elbv2.listener, aws.elbv2.listener_rule, aws.wafv2.web_acl, aws.appsync.graphql_api, aws.logs.log_group [Tier 1]
  - `event_aggregations` WHERE source_type = 'api_access' [Tier 2 from log_collector]
- **Processing:**
  1. **Query API Gateway REST APIs:**
     ```sql
     SELECT df.resource_id as api_id, df.resource_arn, df.emitted_fields->>'Name' as api_name
     FROM discovery_findings df
     WHERE df.resource_type = 'aws.apigateway.rest_api' AND df.orchestration_id = $1
     ```
  2. **For each REST API, retrieve stages and authorizers:**
     ```sql
     SELECT df.resource_id as stage_id, df.emitted_fields->>'StageName' as stage_name,
            df.emitted_fields->>'LoggingLevel' as logging_level
     FROM discovery_findings df
     WHERE df.resource_type = 'aws.apigateway.stage'
     AND df.emitted_fields->>'RestApiId' = $api_id
     ```
  3. **For each stage, find associated authorizer and WAF:**
     ```sql
     SELECT df.resource_id as authorizer_id, df.emitted_fields->>'Type' as auth_type,
            df.emitted_fields->>'AuthorizerCredentials' as creds
     FROM discovery_findings df
     WHERE df.resource_type = 'aws.apigateway.authorizer'
     AND df.emitted_fields->>'RestApiId' = $api_id
     ```
  4. **Query ALB listeners and associate WAF:**
     ```sql
     SELECT df.resource_id as listener_id, df.resource_arn,
            df.emitted_fields->>'Protocol' as protocol,
            df.emitted_fields->>'Port' as port
     FROM discovery_findings df
     WHERE df.resource_type = 'aws.elbv2.listener'
     ```
  5. **Find WAF associations:**
     ```sql
     SELECT df.resource_id as waf_id, df.emitted_fields->>'AssociatedResourceArn' as resource_arn
     FROM discovery_findings df
     WHERE df.resource_type = 'aws.wafv2.web_acl'
     ```
  6. **Query AppSync GraphQL APIs:**
     ```sql
     SELECT df.resource_id as api_id, df.resource_arn, df.emitted_fields->>'Name' as api_name,
            df.emitted_fields->>'AuthenticationType' as auth_type
     FROM discovery_findings df
     WHERE df.resource_type = 'aws.appsync.graphql_api'
     ```
  7. **Read runtime stats from Tier 2 event_aggregations:**
     ```sql
     SELECT ea.resource_id as endpoint_id, ea.error_rate_pct, ea.p99_latency_ms,
            ea.request_volume, ea.top_4xx_paths, ea.top_5xx_paths
     FROM event_aggregations ea
     WHERE ea.orchestration_id = $1 AND ea.source_type = 'api_access'
     ```
  8. **Build api_inventory table (one row per API):**
     - api_type: 'rest' | 'http' | 'websocket' | 'alb' | 'graphql'
     - resource_count: count of endpoints for this API
     - auth_coverage_pct: (endpoints with auth required / total endpoints) × 100
     - waf_coverage_pct: (endpoints with WAF / total endpoints) × 100
  9. **Build api_endpoints table (one row per method-path combination):**
     - For REST APIs, query API resources and methods (requires API GW API call or discovery has these)
     - For ALB, infer from listener rules and discovered routes
     - For AppSync, infer from fields/mutations in schema (may skip this for MVP)
     - For HTTP APIs, query routes from discovery_findings WHERE resource_type = 'aws.apigatewayv2.route'
  10. **Build api_input_transformed table (flatten endpoint config + runtime stats):**
     ```python
     INSERT INTO api_input_transformed VALUES (
       scan_id, endpoint_id, api_type, api_name, path, method,
       auth_required, auth_types (JSONB array), has_rate_limiting,
       tls_minimum, has_waf, logging_enabled,
       error_rate_pct, p99_latency_ms, request_volume
     )
     ```
     - Join _endpoints with event_aggregations on endpoint_id to attach runtime metrics
     - Default missing metrics to null (SKIP in rule eval)
- **Output:**
  - `api_inventory`: One row per API (REST, HTTP, ALB, GraphQL)
  - `api_endpoints`: One row per endpoint (path+method)
  - `api_input_transformed`: One row per endpoint with flat config + runtime stats
- **Key considerations:**
  - API Gateway resources may not be discoverable for all APIs (list-apis permission required)—handle gracefully with partial discovery
  - Runtime stats are optional (Tier 2 may not have data for all endpoints)—use null/default
  - WAF association is transitive: stage → WAF ACL or ALB listener → WAF ACL
  - TLS minimum policy: ELBSecurityPolicy-2016-08 → TLS 1.0; ELBSecurityPolicy-TLS-1-2-* → TLS 1.2
- **Dependencies:** Tasks 0.1.5, 0.1.6 (discoveries engine fully configured), Tasks 0.2.1-0.2.12 (log_collector running)
- **Consumed by:** Task 4.4 (evaluator reads _input_transformed)
- **Reference:** NEW_ENGINES_ETL_RULES.md § 3.4, lines 560-620

#### Task 4.4: Build api_evaluator.py (STAGE 2 — Evaluate) `[Seq 81 | BD]`
**Story:** Load OWASP API Top 10 rules and evaluate each endpoint against all active rules, generating findings that drive compliance scoring and vulnerability reports.

**Implementation Details:**
- **Location:** `/sessions/sharp-eloquent-ramanujan/mnt/threat-engine/engine_api/api_engine/api_evaluator.py`
- **Input:**
  - `api_rules` WHERE is_active = TRUE
  - `api_input_transformed` for current scan_id
- **Processing:**
  1. **Load all active rules via shared utility**
  2. **For each rule, evaluate against all _input_transformed rows:**
     - **API-001** (no auth): Check auth_required field, if FALSE → FAIL
     - **API-002** (API_KEY only): Check auth_types array, if not contains 'COGNITO_USER_POOLS' or 'AWS_IAM' → FAIL
     - **API-003** (no WAF): Check has_waf field, if FALSE → FAIL
     - **API-004** (no rate limit): Check has_rate_limiting field, if FALSE → FAIL
     - **API-005** (no logging): Check logging_enabled field, if FALSE → FAIL
     - **API-006** (weak TLS): Check tls_minimum field, if in ['TLS_1_0', 'TLS_1_1'] → FAIL
     - **API-007** (no request validator): Check request_validator field, if FALSE → FAIL
     - **API-008** (CORS wildcard): Check cors_policy.allow_origins array, if contains '*' → FAIL
     - **API-009** (X-Ray disabled): Check xray_tracing_enabled field, if FALSE → FAIL
     - **API-010** (AppSync logging): Check log_config.fieldLogLevel field, if in ['NONE', null] → FAIL
     - **API-011** (deprecated API): Check has_newer_version field, if TRUE → FAIL
     - **API-RT-001** (error spike): Check error_rate_pct field, if > 10.0 → FAIL
  3. **Batch insert findings via shared utility**
- **Output:** `api_findings` table (scan_id, rule_id, endpoint_id, result, matched_condition JSONB, severity, frameworks)
- **Key considerations:**
  - Reuse shared rule_evaluator and rule_loader—do not duplicate
  - Handle SKIP for rules not applicable (e.g., no rate limiting config on ALB → SKIP, not ERROR)
  - Batch insert 1000 rows per commit
- **Dependencies:** Task 4.1 (schema), Task 4.2 (rules), Task 4.3 (ETL), Tasks 0.5.1-0.5.3 (shared utilities)
- **Consumed by:** Task 4.5 (reporter)
- **Reference:** NEW_ENGINES_ARCHITECTURE.md § Engine 5

#### Task 4.5: Build api_reporter.py (STAGE 3 — Report) `[Seq 82 | BD]`
**Story:** Aggregate findings into a scan-level report with OWASP compliance score, endpoint coverage metrics, and access pattern snapshots for trending.

**Implementation Details:**
- **Location:** `/sessions/sharp-eloquent-ramanujan/mnt/threat-engine/engine_api/api_engine/api_reporter.py`
- **Input:** `api_findings` WHERE scan_id = $1 and api_findings joined with api_inventory
- **Processing:**
  1. **Calculate OWASP compliance score:**
     ```sql
     SELECT COUNT(*) FILTER (WHERE result='PASS')::float / COUNT(*) * 100 as compliance_pct
     FROM api_findings
     WHERE scan_id = $1
     ```
  2. **Calculate coverage metrics:**
     - auth_coverage_pct: (endpoints with PASS on API-001 / total endpoints) × 100
     - waf_coverage_pct: (endpoints with PASS on API-003 / total endpoints) × 100
     - logging_coverage_pct: (endpoints with PASS on API-005 / total endpoints) × 100
  3. **Get top failing rules:**
     ```sql
     SELECT rule_id, COUNT(*) as fail_count
     FROM api_findings WHERE scan_id = $1 AND result = 'FAIL'
     GROUP BY rule_id
     ORDER BY fail_count DESC
     LIMIT 5
     ```
  4. **Build api_report row:**
     ```python
     INSERT INTO api_report VALUES (
       scan_id, total_apis, total_endpoints, auth_coverage_pct,
       waf_coverage_pct, logging_coverage_pct, owasp_compliance_score,
       top_failing_rules (JSONB), scanned_at
     )
     ```
  5. **Build api_access_summary snapshot (one row per endpoint):**
     ```python
     INSERT INTO api_access_summary SELECT
       scan_id, endpoint_id, error_rate_pct, p99_latency_ms, request_volume,
       top_4xx_paths, top_5xx_paths, NOW()
     FROM api_input_transformed
     WHERE scan_id = $1 AND error_rate_pct IS NOT NULL
     ```
- **Output:** `api_report` (1 row), `api_access_summary` (multiple rows, one per endpoint)
- **Key considerations:**
  - OWASP compliance score is simple pass rate across all rules (can be weighted later)
  - Access summary enables time-series charts of error rates, latency
- **Dependencies:** Task 4.4 (findings)
- **Consumed by:** Task 4.8 (API endpoint returns report), Task 6.1 (pipeline)
- **Reference:** NEW_ENGINES_ARCHITECTURE.md § Engine 5

#### Task 4.6: Build api_db_writer.py `[Seq 83 | BD]`
**Story:** Provide batch insert utilities for all 7 output tables with transaction handling and deduplication.

**Implementation Details:**
- **Location:** `/sessions/sharp-eloquent-ramanujan/mnt/threat-engine/engine_api/api_engine/api_db_writer.py`
- **Input:** Lists of dicts for each table (rules, inventory, endpoints, findings, input_transformed, report, access_summary)
- **Processing:**
  1. Implement batch insert functions for each table
  2. Deduplication: Check for existing (scan_id, endpoint_id) before insert
  3. Retry logic: 3 attempts with exponential backoff
- **Output:** Standardized insert interface
- **Key considerations:** Follow shared/common/db_helpers pattern
- **Dependencies:** Task 4.1 (schema)
- **Consumed by:** Tasks 4.3, 4.4, 4.5 (all writing stages)
- **Reference:** Shared db_helpers pattern

#### Task 4.7: Build api_server.py (FastAPI Service) `[Seq 84 | AD]`
**Story:** HTTP API entry point for API security scanning. The /api/v1/scan endpoint orchestrates ETL → Evaluate → Report → Coordinate.

**Implementation Details:**
- **Location:** `/sessions/sharp-eloquent-ramanujan/mnt/threat-engine/engine_api/api_server.py`
- **Input:** POST /api/v1/scan with JSON payload: {orchestration_id, scan_id}
- **Processing:**
  1. Validate scan_id exists
  2. Call api_etl.run(scan_id) → populates _input_transformed, api_inventory, api_endpoints
  3. Call api_evaluator.run(scan_id) → populates _findings
  4. Call api_reporter.run(scan_id) → populates _report, _access_summary
  5. Update scan_orchestration.api_scan_id
  6. Emit SQS message: {"engine": "api", "scan_id": scan_id, "status": "completed"}
  7. Return JSON: {scan_id, status, metrics: {total_apis, total_endpoints, auth_coverage_pct, owasp_compliance_score}}
- **Endpoints:**
  - POST /api/v1/scan
  - GET /api/v1/health/live
  - GET /api/v1/health/ready
  - GET /api/v1/metrics
- **Key considerations:**
  - 30-min timeout for scans
  - Async FastAPI patterns for I/O
- **Dependencies:** Tasks 4.3-4.6
- **Consumed by:** Task 4.8 (Dockerfile), Task 6.1 (pipeline)
- **Reference:** Similar patterns in engine_container, engine_threat

#### Task 4.8: Create Dockerfile + Kubernetes Manifest `[Seq 85 | DO]`
**Story:** Containerize and deploy engine_api to EKS with proper health checks and resource allocation.

**Implementation Details:**
- **Location:**
  - Dockerfile: `/sessions/sharp-eloquent-ramanujan/mnt/threat-engine/engines/engine_api/Dockerfile`
  - K8s: `/sessions/sharp-eloquent-ramanujan/mnt/threat-engine/deployment/aws/eks/engines/engine-api.yaml`
- **Processing:**
  1. Multi-stage Dockerfile: Python 3.11, FastAPI, SQLAlchemy, boto3
  2. K8s deployment: 1 replica, port 8021, 500m/1Gi requests, 2/4Gi limits
  3. Health checks: liveness every 10s, readiness every 5s
- **Output:** Container + K8s deployment
- **Dependencies:** Task 4.7
- **Consumed by:** Task 4.9, Tasks 6.1, 6.2, 6.7 (pipeline integration)

#### Task 4.9: Unit Tests `[Seq 86 | QA]`
**Story:** Test ETL endpoint mapping, OWASP rule evaluation, runtime anomaly detection in isolation with mock data.

**Implementation Details:**
- **Location:** `/sessions/sharp-eloquent-ramanujan/mnt/threat-engine/engines/engine_api/tests/`
- **Test files:**
  1. `test_api_etl.py`: Mock discovery_findings for API GW/ALB/AppSync, verify api_input_transformed output
  2. `test_api_evaluator.py`: Load rules, evaluate against synthetic endpoints, verify PASS/FAIL
  3. `test_api_reporter.py`: Synthetic findings, verify metrics (coverage %, compliance score)
  4. `test_api_server.py`: TestClient POST /api/v1/scan, verify response
  5. `test_runtime_stats.py`: Event aggregations, verify error_rate_pct and latency calculations
- **Coverage:** 80%+
- **Dependencies:** Task 4.7
- **Consumed by:** Task 4.10

#### Task 4.10: Integration Test `[Seq 87 | QA]`
**Story:** End-to-end test seeding Tier 1 (API resources) + Tier 2 (event aggregations), triggering scan, and verifying all output tables.

**Implementation Details:**
- **Location:** `/sessions/sharp-eloquent-ramanujan/mnt/threat-engine/engines/engine_api/tests/test_integration.py`
- **Test scenario:**
  1. Seed discovery_findings: 2 REST APIs, 1 ALB, 1 AppSync
  2. Seed event_aggregations: Error rates, latencies for endpoints
  3. Trigger POST /api/v1/scan
  4. Verify outputs:
     - api_inventory: 4 rows (one per API)
     - api_endpoints: 10+ rows (endpoints from APIs)
     - api_findings: Rules evaluated, expected FAILs for unauth endpoints, no WAF, etc.
     - api_report: Compliance score, coverage metrics
     - api_access_summary: Runtime stats present
  5. Verify scan_orchestration.api_scan_id updated
- **Assertions:** Row counts, severity levels, frameworks, metrics
- **Dependencies:** All tasks 4.1-4.9
- **Consumed by:** Tasks 6.1, 6.2, 6.7 (pipeline integration)

---

## Phase 5: engine_risk (P3)
**Branch:** `feature/engine-risk`
**Port:** 8009 | **DB:** `threat_engine_risk`
**Layer:** 4 (runs LAST — consumes ALL other engine outputs)

### Data Sources
```
FROM ALL engine output tables:
  threat_findings, iam_findings, datasec_findings,
  container_findings, network_findings, supplychain_findings,
  api_findings, check_findings, vulnerability_findings

FROM Tier 1: inventory_findings (asset criticality), cloud_accounts (tenant config)
FROM Tier 3: vuln_cache (EPSS scores for probability enrichment)
```

### 4-Stage Processing Flow
```
STAGE 1 — ETL (risk_etl.py)
  READ:  ALL *_findings tables: threat_findings, iam_findings, datasec_findings,
         container_findings, network_findings, supplychain_findings,
         api_findings, check_findings, vulnerability_findings
       + inventory_findings [Tier 1] — asset metadata (type, exposure, data class)
       + cloud_accounts — tenant config (industry, revenue_range)
       + vuln_cache [Tier 3] — EPSS scores for probability enrichment
  JOIN:  UNION all CRITICAL/HIGH findings across engines, attach asset
         criticality tier (from inventory + datasec), enrich with EPSS
         probability where CVE-linked, attach tenant industry/revenue context
  WRITE: → risk_input_transformed
         (one row per finding-asset pair with severity, asset tier, EPSS,
          exposure factor, data sensitivity, industry context)

STAGE 2 — EVALUATE (risk_evaluator.py)
  READ:  risk_model_config (FAIR parameters, per-industry cost benchmarks,
         regulatory fine schedules)
  EVAL:  For each risk_input_transformed row:
         1. Compute LEF (Loss Event Frequency) = EPSS × exposure_factor
         2. Compute LM (Loss Magnitude) = records × per_record_cost × sensitivity
         3. Compute ALE (Annual Loss Expectancy) = LEF × LM
         4. Apply regulatory fine model (GDPR, HIPAA, PCI-DSS, CCPA)
         5. Generate min/likely/max range (Monte Carlo or parametric)
  WRITE: → risk_scenarios (one row per finding-asset with dollar exposure)

STAGE 3 — REPORT (risk_reporter.py)
  READ:  risk_scenarios for current scan
  AGG:   Sum total exposure (min/likely/max), top risk scenarios by ALE,
         breakdown by engine source, delta vs previous scan, trend lines
  WRITE: → risk_report (one row per scan — total dollar exposure summary)
         → risk_summary (aggregated by category: container, network, etc.)
         → risk_trends (time-series for dashboard charts)

STAGE 4 — COORDINATE
  UPDATE: scan_orchestration.risk_scan_id
  NOTIFY: pipeline_worker "risk done — full pipeline complete"
```

### Technical Tasks

#### Task 5.1: Create Database Schema `[Seq 88 | DE]`
**Story:** Establish persistent storage for risk quantification (FAIR model) spanning all engines and regulatory frameworks. Enables financial exposure trending and comparison across tenants and industries.

**Implementation Details:**
- **Location:** `/sessions/sharp-eloquent-ramanujan/mnt/threat-engine/shared/database/schemas/risk_schema.sql`
- **Input:** Schema from NEW_ENGINES_ARCHITECTURE.md Engine 4 section (risk_scenarios, risk_summary, risk_trends, risk_model_config)
- **Processing:**
  1. Create `risk_model_config` table (config_id, tenant_id, industry VARCHAR, cost_per_record_usd DECIMAL, regulatory_framework VARCHAR, fine_formula JSONB, created_at, updated_at)
  2. Create `risk_input_transformed` table (scan_id, finding_id, engine_source, severity, resource_type, resource_arn, asset_criticality, epss_score DECIMAL, internet_exposed BOOL, estimated_records INT, data_sensitivity VARCHAR, industry VARCHAR, applicable_regulations ARRAY[VARCHAR])
  3. Create `risk_scenarios` table (scenario_id, scan_id, finding_id, engine_source, severity, lef DECIMAL, loss_magnitude_likely DECIMAL, regulatory_fine_max DECIMAL, ale_likely DECIMAL, ale_min DECIMAL, ale_max DECIMAL, risk_tier VARCHAR, applicable_regulations ARRAY[VARCHAR], computed_at)
  4. Create `risk_report` table (scan_id, total_exposure_likely DECIMAL, total_exposure_min DECIMAL, total_exposure_max DECIMAL, critical_findings_count INT, high_findings_count INT, top_risk_scenarios JSONB, engine_breakdown JSONB, delta_vs_previous DECIMAL, scanned_at)
  5. Create `risk_summary` table (summary_id, scan_id, engine_source, engine_finding_count INT, total_exposure_by_engine DECIMAL, risk_tier_breakdown JSONB, top_rules JSONB, created_at)
  6. Create `risk_trends` table (trend_id, scan_id, scan_date, total_exposure DECIMAL, critical_count INT, high_count INT, medium_count INT, low_count INT, engine_breakdown JSONB, delta DECIMAL)
  7. Add indexes: `(scan_id, engine_source)` on `_input_transformed`, `(scan_id, risk_tier)` on `risk_scenarios`
- **Output:** PostgreSQL schema in threat_engine_risk database
- **Key considerations:**
  - DECIMAL(14,2) for all monetary fields ($0.01 precision)
  - risk_tier enum: 'critical' ($10M+), 'high' ($1M+), 'medium' ($100K+), 'low' (<$100K)
  - applicable_regulations array stores framework names: 'GDPR', 'HIPAA', 'PCI_DSS', 'CCPA', etc.
- **Dependencies:** Task 0.4 (DB infrastructure)
- **Consumed by:** All subsequent risk tasks (5.2-5.11)
- **Reference:** NEW_ENGINES_ARCHITECTURE.md § Engine 4

#### Task 5.2: Seed risk_model_config Table `[Seq 89 | DE]`
**Story:** Pre-populate per-industry cost benchmarks and regulatory fine parameters based on empirical data. Enables non-code FAIR model customization per tenant/industry without redeployment.

**Implementation Details:**
- **Location:** `/sessions/sharp-eloquent-ramanujan/mnt/threat-engine/shared/database/seeds/risk_model_config_seed.sql`
- **Input:** Industry cost data and regulatory models from NEW_ENGINES_ETL_RULES.md Section 3.5, lines 731-744
- **Processing:**
  1. Insert healthcare row:
     - industry: 'healthcare'
     - cost_per_record_usd: 10.93 (empirical breach cost per record)
     - regulatory_frameworks: HIPAA, GDPR (if EU operations)
     - hipaa_fine_formula: min(records * 100, 1_900_000)
     - gdpr_fine_formula: min(0.04 * annual_revenue, 20_000_000)
  2. Insert finance row:
     - cost_per_record_usd: 6.08
     - frameworks: PCI_DSS, GDPR, SOC2
     - pci_formula: records * 0.005 ($5/record)
  3. Insert technology row:
     - cost_per_record_usd: 4.88
     - frameworks: GDPR, SOC2
  4. Insert retail row:
     - cost_per_record_usd: 3.28
     - frameworks: GDPR, CCPA
     - ccpa_formula: min(records * 750, 7_500_000)
  5. Insert default row:
     - cost_per_record_usd: 4.45
     - frameworks: GDPR
- **Output:** 5 rows in risk_model_config table
- **Key considerations:**
  - Cost per record from Verizon DBIR / IBM Cost of Breach studies
  - Regulatory formulas stored as JSONB for flexibility (can be extended without migration)
  - Default row used if tenant industry not specified
- **Dependencies:** Task 5.1 (schema)
- **Consumed by:** Task 5.5 (evaluator loads config)
- **Reference:** NEW_ENGINES_ETL_RULES.md § 3.5, lines 728-744

#### Task 5.3: Add Tenant Metadata Fields `[Seq 90 | DE]`
**Story:** Extend cloud_accounts table with industry and revenue_range fields required for regulatory mapping and cost estimation.

**Implementation Details:**
- **Location:** Database migration file (not a new file, alters existing cloud_accounts)
- **Input:** Existing cloud_accounts table
- **Processing:**
  1. Add column `industry` VARCHAR(50) to cloud_accounts (values: healthcare, finance, technology, retail, unknown)
  2. Add column `revenue_range` VARCHAR(50) to cloud_accounts (values: <$1M, $1M-$10M, $10M-$100M, >$100M)
  3. Add column `applicable_regulations` TEXT[] to cloud_accounts (array of regulation codes)
  4. Set defaults: industry='unknown', revenue_range='unknown', applicable_regulations=ARRAY['GDPR'] (if EU region)
  5. Update scan_orchestration join logic to pull these fields
- **Output:** cloud_accounts table with 3 new columns
- **Key considerations:**
  - These fields are set during onboarding (Phase 0 task) and editable by tenant admin
  - Defaults to GDPR for safety (most restrictive)
- **Dependencies:** None (independent alteration)
- **Consumed by:** Task 5.4 (ETL joins cloud_accounts)
- **Reference:** Related to Phase 0 onboarding

#### Task 5.4: Build risk_etl.py (STAGE 1 — Transform) `[Seq 91 | BD]`
**Story:** Cross-engine UNION of all critical and high findings with asset criticality enrichment, EPSS probability attachment, and regulatory context mapping. This is the largest aggregation task in the platform.

**Implementation Details:**
- **Location:** `/sessions/sharp-eloquent-ramanujan/mnt/threat-engine/engine_risk/risk_engine/risk_etl.py`
- **Input:**
  - `threat_findings` WHERE severity IN ('critical', 'high')
  - `iam_findings` WHERE severity IN ('critical', 'high')
  - `datasec_findings` WHERE severity IN ('critical', 'high')
  - `container_findings` WHERE severity IN ('critical', 'high')
  - `network_findings` WHERE severity IN ('critical', 'high')
  - `supplychain_findings` WHERE severity IN ('critical', 'high')
  - `api_findings` WHERE severity IN ('critical', 'high')
  - `check_findings` WHERE severity IN ('critical', 'high')
  - `vulnerability_findings` WHERE severity IN ('critical', 'high')
  - `inventory_findings` (asset metadata, criticality tags)
  - `cloud_accounts` (industry, revenue_range, applicable_regulations)
  - `vuln_cache` (EPSS scores)
- **Processing:**
  1. **UNION all findings with engine source tag:**
     ```sql
     -- From NEW_ENGINES_ETL_RULES.md Section 3.5, lines 676-703
     SELECT 'threat'   AS engine_source, finding_id, severity, resource_type, resource_arn,
            account_id, region, title
     FROM threat_findings WHERE orchestration_id = $1
       AND severity IN ('critical', 'high')
     UNION ALL
     SELECT 'iam', finding_id, severity, resource_type, resource_arn,
            account_id, region, title
     FROM iam_findings WHERE orchestration_id = $1
       AND severity IN ('critical', 'high')
     UNION ALL
     SELECT 'datasec', finding_id::varchar, severity, resource_type, resource_arn,
            account_id, region, finding_type
     FROM datasec_findings WHERE orchestration_id = $1
       AND severity IN ('critical', 'high')
     -- ... etc for all 9 finding tables
     ```
  2. **Join with inventory_findings to get asset criticality:**
     ```sql
     LEFT JOIN inventory_findings ifind ON ifind.resource_arn = findings.resource_arn
     → extract tags->>'Criticality' = 'mission-critical' | 'business-critical' | 'standard' | 'low'
     ```
  3. **Join with datasec_findings for data classification (for findings lacking it):**
     ```sql
     LEFT JOIN datasec_findings dsf ON dsf.resource_arn = findings.resource_arn
     → extract (estimated_record_count, sensitivity_level)
     ```
  4. **Join with cloud_accounts for tenant context:**
     ```sql
     JOIN cloud_accounts ca ON ca.account_id = findings.account_id
     → extract (industry, revenue_range, applicable_regulations)
     ```
  5. **Enrich with EPSS scores from vuln_cache (for CVE-related findings):**
     ```sql
     LEFT JOIN vuln_cache vc ON vc.cve_id = findings.cve_id
     → extract epss_score (0.0-1.0)
     ```
     - If no EPSS match, default to 0.05 (5%) for non-CVE findings
  6. **Compute exposure factor:**
     ```python
     internet_exposed = is_public_resource(resource_arn)  # From inventory tags
     exposure_factor = 1.0 if internet_exposed else 0.3
     ```
  7. **Insert into risk_input_transformed:**
     ```python
     INSERT INTO risk_input_transformed (scan_id, finding_id, engine_source, severity,
       resource_type, resource_arn, asset_criticality, epss_score, internet_exposed,
       estimated_records, data_sensitivity, industry, applicable_regulations)
     VALUES (...)
     ```
     - asset_criticality: from inventory tags or 'standard' default
     - epss_score: from vuln_cache or 0.05 default
     - internet_exposed: true if tags contain 'Public' or security group allows 0.0.0.0
     - estimated_records: from datasec_findings or 1000 (conservative default)
     - data_sensitivity: from datasec_findings ('restricted' | 'confidential' | 'internal' | 'public') or 'internal' default
     - industry: from cloud_accounts
     - applicable_regulations: from cloud_accounts
- **Output:** `risk_input_transformed` (one row per CRITICAL/HIGH finding across all engines)
- **Key considerations:**
  - UNION requires careful schema alignment—some engines may lack certain fields (use CASE WHEN to normalize)
  - Asset criticality defaults to 'standard' if not tagged
  - EPSS scores highly valuable for probability but optional (use 0.05 if missing)
  - Estimated_records defaults to 1000 if datasec hasn't classified the resource (conservative estimate)
  - exposure_factor reflects whether resource is internet-exposed (critical adjustment to LEF)
- **Dependencies:** Tasks 1.1-1.10 (engine_container), Tasks 2.1-2.10 (engine_network), Tasks 3.1-3.11 (engine_supplychain), Tasks 4.1-4.10 (engine_api), Tasks 0.3.1-0.3.17 (external_collector for vuln_cache)
- **Consumed by:** Task 5.5 (evaluator reads _input_transformed)
- **Reference:** NEW_ENGINES_ETL_RULES.md § 3.5, lines 674-723; NEW_ENGINES_ARCHITECTURE.md § Engine 4

#### Task 5.5: Build risk_evaluator.py (STAGE 2 — Evaluate with FAIR Model) `[Seq 92 | BD]`
**Story:** Compute financial exposure (FAIR model) for each finding: Loss Event Frequency (LEF) × Loss Magnitude (LM) = Annual Loss Expectancy (ALE), plus regulatory fine quantification. This drives dollar-denominated risk reporting.

**Implementation Details:**
- **Location:** `/sessions/sharp-eloquent-ramanujan/mnt/threat-engine/engine_risk/risk_engine/risk_evaluator.py`
- **Input:**
  - `risk_input_transformed` (one row per CRITICAL/HIGH finding with asset/industry/regulatory context)
  - `risk_model_config` (per-industry cost benchmarks, regulatory fine formulas)
- **Processing:**
  1. **Load risk_model_config for tenant's industry:**
     ```python
     config = risk_model_config.filter(industry = finding.industry)
     per_record_cost = config.cost_per_record_usd
     # From NEW_ENGINES_ETL_RULES.md lines 731-737
     PER_RECORD_COST = {
         "healthcare":  10.93,
         "finance":      6.08,
         "technology":   4.88,
         "retail":       3.28,
         "default":      4.45
     }
     ```
  2. **Compute LEF (Loss Event Frequency):**
     ```python
     # LEF = probability of loss event occurring × exposure factor (is_public?)
     epss_score = finding.epss_score or 0.05  # default to 5%
     internet_exposed = finding.internet_exposed
     exposure_factor = 1.0 if internet_exposed else 0.3
     lef = epss_score * exposure_factor
     # Result: range [0, 1.0] representing annual probability
     ```
  3. **Compute LM (Loss Magnitude):**
     ```python
     # LM = estimated records × cost per record × sensitivity multiplier
     records = finding.estimated_records or 1000
     sensitivity_mult = {
         "restricted": 3.0,
         "confidential": 2.0,
         "internal": 1.0,
         "public": 0.1
     }.get(finding.data_sensitivity, 1.0)
     per_record = PER_RECORD_COST.get(finding.industry, PER_RECORD_COST["default"])
     loss_magnitude = records * per_record * sensitivity_mult
     # Result: dollars
     ```
  4. **Compute ALE (Annual Loss Expectancy):**
     ```python
     # ALE = LEF × LM — primary quantification
     ale = lef * loss_magnitude
     ```
  5. **Apply regulatory fine model:**
     ```python
     # From NEW_ENGINES_ETL_RULES.md lines 739-744
     REGULATORY_MODELS = {
         "GDPR":    lambda revenue, records: min(0.04 * revenue, 20_000_000),
         "HIPAA":   lambda revenue, records: min(records * 100, 1_900_000),
         "PCI_DSS": lambda revenue, records: records * 0.005,
         "CCPA":    lambda revenue, records: min(records * 750, 7_500_000),
     }

     applicable_regs = finding.applicable_regulations  # ['GDPR', 'HIPAA', ...]
     annual_revenue = cloud_accounts[finding.account_id].revenue_usd or 1_000_000

     reg_fines = [
         REGULATORY_MODELS[r](annual_revenue, records)
         for r in applicable_regs if r in REGULATORY_MODELS
     ]
     regulatory_fine_max = max(reg_fines) if reg_fines else 0
     ```
  6. **Compute total exposure with regulatory component:**
     ```python
     total_exposure_likely = (loss_magnitude + regulatory_fine_max) * lef
     # Min/Max range for uncertainty (parametric or Monte Carlo):
     total_exposure_min = total_exposure_likely * 0.1  # 10% of likely
     total_exposure_max = total_exposure_likely * 5.0  # 5x likely
     ```
  7. **Determine risk_tier:**
     ```python
     # From NEW_ENGINES_ETL_RULES.md lines 784-788
     def tier(exposure):
         if exposure >= 10_000_000: return "critical"   # >$10M
         if exposure >= 1_000_000:  return "high"       # >$1M
         if exposure >= 100_000:    return "medium"     # >$100K
         return "low"
     risk_tier = tier(total_exposure_likely)
     ```
  8. **Insert into risk_scenarios:**
     ```python
     INSERT INTO risk_scenarios (scan_id, finding_id, engine_source, severity,
       lef, loss_magnitude_likely, regulatory_fine_max, ale_likely,
       ale_min, ale_max, risk_tier, applicable_regulations, computed_at)
     VALUES (...)
     ```
- **Output:** `risk_scenarios` (one row per finding with full FAIR quantification)
- **Key considerations:**
  - LEF is probability, multiply by 1.0 for 100% annual frequency assumption (adjust if multi-year assessment needed)
  - Sensitivity multiplier (3x for restricted data) reflects liability difference
  - Regulatory fine is MAX across applicable frameworks (assume worst case)
  - Min/Max range uses parametric bounds (10%, 5x) for conservatism—can be refined with Monte Carlo later
  - Handle division by zero / null fields gracefully (use defaults)
- **Dependencies:** Task 5.2 (config loaded), Task 5.4 (input_transformed), Task 5.3 (cloud_accounts enriched)
- **Consumed by:** Task 5.6 (reporter aggregates scenarios)
- **Reference:** NEW_ENGINES_ETL_RULES.md § 3.5, lines 728-790

#### Task 5.6: Build risk_reporter.py (STAGE 3 — Report) `[Seq 93 | BD]`
**Story:** Aggregate risk scenarios into scan-level and category-level summaries with trending (delta vs previous scan). Drives executive dashboards showing total financial exposure and top-risk findings.

**Implementation Details:**
- **Location:** `/sessions/sharp-eloquent-ramanujan/mnt/threat-engine/engine_risk/risk_engine/risk_reporter.py`
- **Input:** `risk_scenarios` WHERE scan_id = $1, previous scan (if exists) for delta calculation
- **Processing:**
  1. **Calculate total exposure:**
     ```sql
     SELECT SUM(ale_likely) as total_likely,
            SUM(ale_min) as total_min,
            SUM(ale_max) as total_max,
            COUNT(*) FILTER (WHERE severity='critical') as critical_count,
            COUNT(*) FILTER (WHERE severity='high') as high_count
     FROM risk_scenarios
     WHERE scan_id = $1
     ```
  2. **Build engine_breakdown (exposure by source engine):**
     ```sql
     SELECT engine_source, SUM(ale_likely) as exposure, COUNT(*) as finding_count
     FROM risk_scenarios
     WHERE scan_id = $1
     GROUP BY engine_source
     ```
  3. **Identify top risk scenarios (ALE ranked):**
     ```sql
     SELECT finding_id, engine_source, ale_likely, risk_tier, severity
     FROM risk_scenarios
     WHERE scan_id = $1
     ORDER BY ale_likely DESC
     LIMIT 10
     ```
  4. **Calculate delta vs previous scan:**
     ```python
     previous_scan = risk_report WHERE scan_id = (
       SELECT MAX(scan_id) FROM risk_report
       WHERE orchestration_id = $current_orchestration_id
       AND scan_id != $current_scan_id
     )
     delta = current_total_likely - (previous_scan.total_exposure_likely or 0)
     ```
  5. **Build risk_report row:**
     ```python
     INSERT INTO risk_report (scan_id, total_exposure_likely, total_exposure_min,
       total_exposure_max, critical_findings_count, high_findings_count,
       top_risk_scenarios (JSONB), engine_breakdown (JSONB), delta_vs_previous,
       scanned_at)
     VALUES (...)
     ```
  6. **Build risk_summary rows (one per engine):**
     ```python
     for engine_source in engines:
       exposure = sum(ale_likely WHERE engine_source = $engine)
       INSERT INTO risk_summary (scan_id, engine_source, engine_finding_count,
         total_exposure_by_engine, risk_tier_breakdown (JSONB), top_rules (JSONB))
       VALUES (...)
     ```
  7. **Build risk_trends row (for charting):**
     ```python
     INSERT INTO risk_trends (scan_id, scan_date, total_exposure, critical_count,
       high_count, medium_count, low_count, engine_breakdown (JSONB), delta)
     VALUES (...)
     ```
- **Output:**
  - `risk_report` (1 row per scan with total exposures, deltas)
  - `risk_summary` (N rows, one per engine, with engine-specific metrics)
  - `risk_trends` (1 row per scan for time-series charting)
- **Key considerations:**
  - delta_vs_previous allows trending (positive = risk increased, negative = improved)
  - Top risk scenarios JSONB should include finding_id, engine, ale_likely, resource_arn for drill-down
  - engine_breakdown JSONB keyed by engine name for dashboard charts
  - risk_tier_breakdown: {critical: count, high: count, medium: count, low: count}
- **Dependencies:** Task 5.5 (risk_scenarios)
- **Consumed by:** Task 5.8 (API endpoint returns report), Task 6.1 (pipeline), dashboards
- **Reference:** NEW_ENGINES_ARCHITECTURE.md § Engine 4

#### Task 5.7: Build risk_db_writer.py `[Seq 94 | BD]`
**Story:** Batch insert utilities for all 6 output tables (risk_input_transformed, risk_scenarios, risk_report, risk_summary, risk_trends, plus config writes).

**Implementation Details:**
- **Location:** `/sessions/sharp-eloquent-ramanujan/mnt/threat-engine/engine_risk/risk_engine/risk_db_writer.py`
- **Input:** Lists of dicts for each table
- **Processing:**
  1. Batch insert functions for each table
  2. Deduplication: (scan_id, finding_id) check
  3. Retry logic: 3 attempts with exponential backoff
- **Output:** Standardized insert interface
- **Key considerations:** Follow shared/common/db_helpers pattern
- **Dependencies:** Task 5.1 (schema)
- **Consumed by:** Tasks 5.4, 5.5, 5.6 (all writing stages)
- **Reference:** Shared db_helpers pattern

#### Task 5.8: Build api_server.py (FastAPI Service) `[Seq 95 | AD]`
**Story:** HTTP API entry point for risk quantification. The /api/v1/scan endpoint orchestrates ETL → Evaluate (FAIR) → Report → Coordinate.

**Implementation Details:**
- **Location:** `/sessions/sharp-eloquent-ramanujan/mnt/threat-engine/engine_risk/api_server.py`
- **Input:** POST /api/v1/scan with JSON payload: {orchestration_id, scan_id}
- **Processing:**
  1. Validate scan_id exists, all prior engines have completed
  2. Call risk_etl.run(scan_id) → populates _input_transformed
  3. Call risk_evaluator.run(scan_id) → populates risk_scenarios
  4. Call risk_reporter.run(scan_id) → populates _report, _summary, _trends
  5. Update scan_orchestration.risk_scan_id
  6. Emit SQS message: {"engine": "risk", "scan_id": scan_id, "status": "completed", "final": true}
  7. Return JSON: {scan_id, status, metrics: {total_exposure_likely, critical_count, engine_breakdown}}
- **Endpoints:**
  - POST /api/v1/scan
  - GET /api/v1/health/live
  - GET /api/v1/health/ready
  - GET /api/v1/metrics
- **Key considerations:**
  - 60-min timeout (cross-engine UNION can be slow for large tenants)
  - Check that all prior engine scan_ids are set (non-null) before starting
  - Log FAIR calculations for audit (per-finding exposure shown in response)
- **Dependencies:** Tasks 5.4-5.7
- **Consumed by:** Task 5.9 (Dockerfile), Task 6.1 (pipeline)
- **Reference:** Similar patterns in other engines

#### Task 5.9: Create Dockerfile + Kubernetes Manifest `[Seq 96 | DO]`
**Story:** Containerize engine_risk and deploy to EKS with higher resource limits (cross-engine aggregation is compute-heavy).

**Implementation Details:**
- **Location:**
  - Dockerfile: `/sessions/sharp-eloquent-ramanujan/mnt/threat-engine/engines/engine_risk/Dockerfile`
  - K8s: `/sessions/sharp-eloquent-ramanujan/mnt/threat-engine/deployment/aws/eks/engines/engine-risk.yaml`
- **Processing:**
  1. Multi-stage Dockerfile: Python 3.11, FastAPI, SQLAlchemy, numpy (for FAIR calcs)
  2. K8s deployment: 1 replica, port 8009, 1/2Gi requests, 4/8Gi limits (higher than other engines)
  3. Health checks: liveness every 10s, readiness every 5s
- **Output:** Container + K8s deployment
- **Dependencies:** Task 5.8
- **Consumed by:** Task 5.10, Tasks 6.1, 6.2, 6.7 (pipeline integration)

#### Task 5.10: Unit Tests `[Seq 97 | QA]`
**Story:** Validate FAIR model math, regulatory fine calculations, cross-engine UNION, and trend computation with synthetic scenarios.

**Implementation Details:**
- **Location:** `/sessions/sharp-eloquent-ramanujan/mnt/threat-engine/engines/engine_risk/tests/`
- **Test files:**
  1. `test_fair_model.py`: Synthetic findings, verify LEF/LM/ALE math (e.g., epss=0.5, cost=$10/record, 1000 records → verify ALE)
  2. `test_regulatory_fines.py`: Test GDPR/HIPAA/PCI formulas with various inputs
  3. `test_risk_etl.py`: Mock findings from 5 engines, verify UNION output
  4. `test_risk_evaluator.py`: Compute scenarios, verify risk_tier assignment
  5. `test_risk_reporter.py`: Aggregate scenarios, verify report metrics
  6. `test_api_server.py`: TestClient POST /api/v1/scan, verify response
- **Coverage:** 85%+ (FAIR math critical)
- **Dependencies:** Task 5.8
- **Consumed by:** Task 5.11

#### Task 5.11: Integration Test `[Seq 98 | QA]`
**Story:** End-to-end test creating findings across 5 different engines, triggering risk quantification, and verifying financial exposure calculations and regulatory fine estimates.

**Implementation Details:**
- **Location:** `/sessions/sharp-eloquent-ramanujan/mnt/threat-engine/engines/engine_risk/tests/test_integration.py`
- **Test scenario:**
  1. **Seed findings across multiple engines:**
     - 1 threat_findings: CRITICAL (unpatched EC2 CVE-2024-XXXX, EPSS 0.95)
     - 1 iam_findings: HIGH (root user active)
     - 1 datasec_findings: CRITICAL (unencrypted S3 bucket, 1M customer records, Confidential)
     - 1 api_findings: HIGH (API without authentication)
     - 1 supplychain_findings: CRITICAL (known malicious npm package)
  2. **Seed asset metadata:**
     - EC2 instance: tag Criticality=mission-critical, is_public=true
     - S3 bucket: tag Criticality=business-critical, not public
     - RDS: tag Criticality=business-critical
  3. **Seed cloud_accounts:**
     - industry='finance', revenue_range='$100M-$1B', applicable_regulations=['PCI_DSS', 'GDPR']
  4. **Trigger POST /api/v1/scan**
  5. **Verify outputs:**
     - risk_input_transformed: 5 rows (one per finding)
     - risk_scenarios: 5 rows with computed ALEs
       - EC2 CVE: LEF=0.95×1.0 (public)=0.95, LM=1×6.08 (finance)=6.08, ALE=5.78 + max(PCI/GDPR fine) → risk_tier='critical'
       - S3 bucket: LEF=0.5×0.3 (not public)=0.15, LM=1_000_000×6.08×2.0 (confidential)=12.16M, ALE=1.82M + GDPR_fine(4% rev)=$4M → risk_tier='critical'
       - Total exposure >$10M → critical overall
     - risk_report: total_exposure_likely >= $10M, critical_count=5 (or filtered to CRITICAL/HIGH)
     - risk_summary: finance_findings_count=5, finance_exposure=sum(ALEs)
     - risk_trends: one row, deltas relative to previous scan
  6. **Verify SQS message sent**
- **Assertions:**
  - FAIR math correct: ALE matches hand-calculated value
  - Regulatory fines applied correctly per framework
  - Tier assignments match exposure ranges
  - Trends capture delta vs previous (if this is not first scan)
- **Dependencies:** All tasks 5.1-5.10
- **Consumed by:** Tasks 6.1, 6.2, 6.7 (pipeline integration)

---

## Phase 6: Pipeline Integration & Testing
**Goal:** Wire all 3 collectors (Tier 1-3) + 5 new engines into the pipeline_worker and validate end-to-end flow from account onboarding through risk quantification.

#### Task 6.1: Update pipeline_worker handlers.py — Collector & Engine Trigger Functions `[Seq 99 | PE]`
**Story:** The pipeline_worker needs trigger functions for all new services (3 collectors + 5 engines). These async HTTP calls orchestrate the entire data flow and must handle service discovery, timeouts, and error propagation.

**Implementation Details:**
- Location: `shared/pipeline_worker/handlers.py`
- Add 7 new async trigger functions:
  ```python
  async def trigger_log_collector(orchestration_id: str, timeout: float = 300.0) -> dict:
      """Trigger Tier 2 log collection (VPC flow, CloudTrail, API access logs)."""
      async with httpx.AsyncClient(timeout=timeout) as client:
          resp = await client.post(
              f"{_url('log_collector')}/api/v1/scan",
              json={"orchestration_id": orchestration_id},
          )
          resp.raise_for_status()
          return resp.json()

  async def trigger_external_collector(orchestration_id: str, timeout: float = 600.0) -> dict:
      """Trigger Tier 3 external collection (Docker Hub, GitHub, NVD, npm/PyPI, threat intel).
      Longer timeout — external APIs vary in speed."""
      async with httpx.AsyncClient(timeout=timeout) as client:
          resp = await client.post(
              f"{_url('external_collector')}/api/v1/scan",
              json={"orchestration_id": orchestration_id},
          )
          resp.raise_for_status()
          return resp.json()

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
      """Trigger network engine (posture mode in pipeline; runtime is SQS-driven)."""
      async with httpx.AsyncClient(timeout=timeout) as client:
          resp = await client.post(
              f"{_url('network')}/api/v1/scan",
              json={"orchestration_id": orchestration_id, "csp": csp, "mode": "posture"},
          )
          resp.raise_for_status()
          return resp.json()

  async def trigger_supplychain(orchestration_id: str, csp: str = "aws",
                                timeout: float = 300.0) -> dict:
      """Trigger supply chain security engine (SBOM, dependency confusion, malicious packages)."""
      async with httpx.AsyncClient(timeout=timeout) as client:
          resp = await client.post(
              f"{_url('supplychain')}/api/v1/scan",
              json={"orchestration_id": orchestration_id, "csp": csp},
          )
          resp.raise_for_status()
          return resp.json()

  async def trigger_api_engine(orchestration_id: str, csp: str = "aws",
                               timeout: float = 300.0) -> dict:
      """Trigger API security engine (OWASP Top 10, auth/rate-limit posture)."""
      async with httpx.AsyncClient(timeout=timeout) as client:
          resp = await client.post(
              f"{_url('api_engine')}/api/v1/scan",
              json={"orchestration_id": orchestration_id, "csp": csp},
          )
          resp.raise_for_status()
          return resp.json()

  async def trigger_risk(orchestration_id: str, timeout: float = 120.0) -> dict:
      """Trigger risk engine (FAIR-model financial quantification across all findings)."""
      async with httpx.AsyncClient(timeout=timeout) as client:
          resp = await client.post(
              f"{_url('risk')}/api/v1/scan",
              json={"orchestration_id": orchestration_id},
          )
          resp.raise_for_status()
          return resp.json()
  ```
- Key considerations:
  - Use service discovery via `_url()` helper (resolve from ConfigMap or DNS)
  - Timeouts: collectors 300-600s (external APIs slower); engines 120-600s
  - Pass `orchestration_id` to all; risk engine does NOT need `csp` (aggregates all findings)
  - All trigger functions are async to prevent blocking
  - Implement exponential backoff for transient failures (408, 429, 5xx)

**Dependencies:** Tasks 0.1.1-0.1.12 (discoveries), Tasks 0.2.1-0.2.12 (log_collector), Tasks 0.3.1-0.3.17 (external_collector), Tasks 0.4.1-0.4.2 (DB infrastructure), Tasks 0.5.1-0.5.3 (shared utilities), Tasks 1.1-1.10 (engine_container), Tasks 2.1-2.10 (engine_network), Tasks 3.1-3.11 (engine_supplychain), Tasks 4.1-4.10 (engine_api), Tasks 5.1-5.11 (engine_risk)
**Consumed by:** Task 6.2
**Reference:** NEW_ENGINES_ETL_RULES.md Section 5

---

#### Task 6.2: Update pipeline_worker worker.py — PIPELINE_STAGES with Layer 0.5 `[Seq 100 | PE]`
**Story:** The pipeline orchestration logic must be updated to add Layer 0.5 (collectors run in parallel immediately after discoveries) before Layer 1 engines start. This ensures all collector data is available for engines to read from.

**Implementation Details:**
- Location: `shared/pipeline_worker/worker.py`
- Update PIPELINE_STAGES array to include collectors + new engines in correct layer order:
  ```python
  # Layer 0.5 (parallel immediately after discoveries — all 3 tiers simultaneous)
  # Layer 1   (parallel after Layer 0.5 — inventory, container, api_engine)
  # Layer 2   (parallel after Layer 1 — check, iam, secops, network)
  # Layer 3   (parallel after Layer 2 — threat, datasec, supplychain)
  # Layer 4   (parallel after Layer 3 — compliance, risk)

  PIPELINE_STAGES = [
      # Layer 0.5 — Collectors (NEW)
      {"name": "log_collector",       "layer": 0.5, "fn": trigger_log_collector},
      {"name": "external_collector",  "layer": 0.5, "fn": trigger_external_collector},
      # (Tier 1 discoveries runs before this, already in PIPELINE_STAGES)

      # Layer 1
      {"name": "inventory",           "layer": 1, "fn": trigger_inventory},
      {"name": "container",           "layer": 1, "fn": trigger_container},         # NEW
      {"name": "api_engine",          "layer": 1, "fn": trigger_api_engine},        # NEW

      # Layer 2
      {"name": "check",               "layer": 2, "fn": trigger_check},
      {"name": "iam",                 "layer": 2, "fn": trigger_iam},
      {"name": "secops",              "layer": 2, "fn": trigger_secops},
      {"name": "network",             "layer": 2, "fn": trigger_network},           # NEW

      # Layer 3
      {"name": "threat",              "layer": 3, "fn": trigger_threat},
      {"name": "datasec",             "layer": 3, "fn": trigger_datasec},
      {"name": "supplychain",         "layer": 3, "fn": trigger_supplychain},       # NEW

      # Layer 4
      {"name": "compliance",          "layer": 4, "fn": trigger_compliance},
      {"name": "risk",                "layer": 4, "fn": trigger_risk},              # NEW
  ]
  ```
- Update execution logic:
  - Group stages by layer
  - For each layer, run all stages in parallel (asyncio.gather)
  - Wait for layer to complete before moving to next
  - Update `scan_orchestration` with scan_id from each stage response (container_scan_id, network_scan_id, etc.)
- Input/Output:
  - Input: orchestration_id from onboarding
  - Process: Execute layers sequentially; each layer triggers in parallel
  - Output: Update orchestration record with all scan_ids; send completion message to SQS

**Dependencies:** Task 6.1
**Consumed by:** Task 6.7
**Reference:** NEW_ENGINES_ETL_RULES.md Section 5, CLAUDE.md Architecture Patterns

---

#### Task 6.3: Update Secrets Manager — New DB Passwords & External API Tokens `[Seq 101 | DO]`
**Story:** Each new service (collectors + engines) needs database credentials and external service tokens stored securely in AWS Secrets Manager for K8s external-secrets to inject.

**Implementation Details:**
- Location: AWS Secrets Manager secret `threat-engine/rds-credentials`
- Add new keys to JSON:
  ```json
  {
    "CONTAINER_DB_PASSWORD": "same_password_as_other_engines",
    "NETWORK_DB_PASSWORD": "same_password_as_other_engines",
    "SUPPLYCHAIN_DB_PASSWORD": "same_password_as_other_engines",
    "API_DB_PASSWORD": "same_password_as_other_engines",
    "RISK_DB_PASSWORD": "same_password_as_other_engines",
    "LOG_COLLECTOR_DB_PASSWORD": "same_password_as_other_engines",
    "EXTERNAL_COLLECTOR_DB_PASSWORD": "same_password_as_other_engines"
  }
  ```
- Location: AWS Secrets Manager secret `threat-engine/external-api-credentials` (NEW)
- Add new keys for external data sources:
  ```json
  {
    "GITHUB_TOKEN": "github_pat_...",
    "DOCKERHUB_USERNAME": "username",
    "DOCKERHUB_PASSWORD": "password",
    "NVD_API_KEY": "nvd_api_key",
    "THREATINTEL_API_KEY": "feed_api_key",
    "NPM_REGISTRY_TOKEN": "npm_token",
    "PYPI_API_TOKEN": "pypi_token"
  }
  ```
- AWS CLI command:
  ```bash
  aws secretsmanager update-secret \
    --secret-id threat-engine/rds-credentials \
    --secret-string '{"CONTAINER_DB_PASSWORD":"...", "NETWORK_DB_PASSWORD":"...", ...}'

  aws secretsmanager create-secret \
    --name threat-engine/external-api-credentials \
    --secret-string '{"GITHUB_TOKEN":"...", "DOCKERHUB_USERNAME":"...", ...}'
  ```
- Key considerations:
  - Use same RDS master password for all engines + collectors (single shared user)
  - Create separate secret for external API credentials (different lifetime)
  - Store in Secrets Manager, not ConfigMap
  - Rotate periodically (quarterly for external tokens)

**Dependencies:** None (can be done in parallel)
**Consumed by:** Task 6.4
**Reference:** CLAUDE.md Security & Access Control, NEW_ENGINES_ETL_RULES.md Section 6

---

#### Task 6.4: Update external-secret.yaml — RemoteRef Entries for All Secrets `[Seq 102 | DO]`
**Story:** K8s external-secrets controller must be configured to fetch all new secrets from AWS Secrets Manager and inject them as environment variables into pod deployments.

**Implementation Details:**
- Location: `deployment/aws/eks/external-secret.yaml`
- Update ExternalSecret resource to include remoteRef for all new keys:
  ```yaml
  apiVersion: external-secrets.io/v1beta1
  kind: ExternalSecret
  metadata:
    name: threat-engine-secrets
    namespace: threat-engine-engines
  spec:
    secretStoreRef:
      name: aws-secret-store
      kind: SecretStore
    target:
      name: threat-engine-secrets
      creationPolicy: Owner
    data:
      # Existing DB passwords
      - secretKey: DISCOVERIES_DB_PASSWORD
        remoteRef:
          key: threat-engine/rds-credentials
          property: DISCOVERIES_DB_PASSWORD
      # ... (existing entries)

      # NEW DB passwords
      - secretKey: CONTAINER_DB_PASSWORD
        remoteRef:
          key: threat-engine/rds-credentials
          property: CONTAINER_DB_PASSWORD
      - secretKey: NETWORK_DB_PASSWORD
        remoteRef:
          key: threat-engine/rds-credentials
          property: NETWORK_DB_PASSWORD
      - secretKey: SUPPLYCHAIN_DB_PASSWORD
        remoteRef:
          key: threat-engine/rds-credentials
          property: SUPPLYCHAIN_DB_PASSWORD
      - secretKey: API_DB_PASSWORD
        remoteRef:
          key: threat-engine/rds-credentials
          property: API_DB_PASSWORD
      - secretKey: RISK_DB_PASSWORD
        remoteRef:
          key: threat-engine/rds-credentials
          property: RISK_DB_PASSWORD
      - secretKey: LOG_COLLECTOR_DB_PASSWORD
        remoteRef:
          key: threat-engine/rds-credentials
          property: LOG_COLLECTOR_DB_PASSWORD
      - secretKey: EXTERNAL_COLLECTOR_DB_PASSWORD
        remoteRef:
          key: threat-engine/rds-credentials
          property: EXTERNAL_COLLECTOR_DB_PASSWORD

      # NEW external API tokens
      - secretKey: GITHUB_TOKEN
        remoteRef:
          key: threat-engine/external-api-credentials
          property: GITHUB_TOKEN
      - secretKey: DOCKERHUB_USERNAME
        remoteRef:
          key: threat-engine/external-api-credentials
          property: DOCKERHUB_USERNAME
      - secretKey: DOCKERHUB_PASSWORD
        remoteRef:
          key: threat-engine/external-api-credentials
          property: DOCKERHUB_PASSWORD
      - secretKey: NVD_API_KEY
        remoteRef:
          key: threat-engine/external-api-credentials
          property: NVD_API_KEY
      - secretKey: THREATINTEL_API_KEY
        remoteRef:
          key: threat-engine/external-api-credentials
          property: THREATINTEL_API_KEY
      - secretKey: NPM_REGISTRY_TOKEN
        remoteRef:
          key: threat-engine/external-api-credentials
          property: NPM_REGISTRY_TOKEN
      - secretKey: PYPI_API_TOKEN
        remoteRef:
          key: threat-engine/external-api-credentials
          property: PYPI_API_TOKEN
  ```
- Verify: Run `kubectl get externalsecret -n threat-engine-engines` and check logs
- Key considerations:
  - One ExternalSecret resource per secret source (can have multiple spec.data entries)
  - secretKey = environment variable name in pods
  - remoteRef.property = JSON key in Secrets Manager secret
  - Refresh interval is automatic (check controller settings)

**Dependencies:** Task 6.3
**Consumed by:** Task 6.5, 6.6 (all engine manifests reference these secrets)
**Reference:** Kubernetes ExternalSecrets documentation, CLAUDE.md Kubernetes Operations

---

#### Task 6.5: Update configmap.yaml — DB Names & External Source Configuration `[Seq 103 | DO]`
**Story:** ConfigMap stores non-secret configuration (database hostnames, external API endpoints, log collection settings) that all services need.

**Implementation Details:**
- Location: `deployment/aws/eks/configmap.yaml`
- Add new database configuration entries:
  ```yaml
  apiVersion: v1
  kind: ConfigMap
  metadata:
    name: threat-engine-config
    namespace: threat-engine-engines
  data:
    # Database configurations
    CONTAINER_DB_HOST: "postgres.threat-engine-engines.svc.cluster.local"
    CONTAINER_DB_PORT: "5432"
    CONTAINER_DB_NAME: "threat_engine_container"
    CONTAINER_DB_USER: "threat_engine"

    NETWORK_DB_HOST: "postgres.threat-engine-engines.svc.cluster.local"
    NETWORK_DB_PORT: "5432"
    NETWORK_DB_NAME: "threat_engine_network"
    NETWORK_DB_USER: "threat_engine"

    SUPPLYCHAIN_DB_HOST: "postgres.threat-engine-engines.svc.cluster.local"
    SUPPLYCHAIN_DB_PORT: "5432"
    SUPPLYCHAIN_DB_NAME: "threat_engine_supplychain"
    SUPPLYCHAIN_DB_USER: "threat_engine"

    API_DB_HOST: "postgres.threat-engine-engines.svc.cluster.local"
    API_DB_PORT: "5432"
    API_DB_NAME: "threat_engine_api"
    API_DB_USER: "threat_engine"

    RISK_DB_HOST: "postgres.threat-engine-engines.svc.cluster.local"
    RISK_DB_PORT: "5432"
    RISK_DB_NAME: "threat_engine_risk"
    RISK_DB_USER: "threat_engine"

    LOG_COLLECTOR_DB_HOST: "postgres.threat-engine-engines.svc.cluster.local"
    LOG_COLLECTOR_DB_PORT: "5432"
    LOG_COLLECTOR_DB_NAME: "threat_engine_logs"
    LOG_COLLECTOR_DB_USER: "threat_engine"

    EXTERNAL_COLLECTOR_DB_HOST: "postgres.threat-engine-engines.svc.cluster.local"
    EXTERNAL_COLLECTOR_DB_PORT: "5432"
    EXTERNAL_COLLECTOR_DB_NAME: "threat_engine_external"
    EXTERNAL_COLLECTOR_DB_USER: "threat_engine"

    # External API endpoints
    GITHUB_API_URL: "https://api.github.com"
    DOCKERHUB_API_URL: "https://hub.docker.com/v2"
    NVD_API_URL: "https://services.nvd.nist.gov/rest/json/cves/2.0"
    THREATINTEL_API_URL: "https://certs.mitre.org/data/definitions/"
    NPM_REGISTRY_URL: "https://registry.npmjs.org"
    PYPI_REGISTRY_URL: "https://pypi.org/pypi"

    # Log collection settings
    LOG_COLLECTOR_S3_BUCKET: "threat-engine-logs"
    LOG_COLLECTOR_SQS_QUEUE: "https://sqs.us-east-1.amazonaws.com/ACCOUNT/threat-engine-logs"
    LOG_COLLECTOR_CLOUDTRAIL_BUCKET: "threat-engine-cloudtrail"

    # Cache configuration
    CACHE_REFRESH_INTERVAL_HOURS: "24"
    CACHE_TTL_DAYS: "7"
    VULN_CACHE_MAX_AGE_DAYS: "7"
    THREAT_INTEL_CACHE_MAX_AGE_DAYS: "3"
    PACKAGE_METADATA_CACHE_MAX_AGE_DAYS: "30"
  ```
- Key considerations:
  - Use K8s service DNS names (internal cluster communication)
  - ConfigMap is not secret — do NOT include passwords, API keys, or tokens
  - All services share same Postgres instance but have separate databases
  - External API URLs should be non-regional defaults (may be overridden by service)

**Dependencies:** Task 6.3 (secrets in place), Task 6.4 (external-secret.yaml updated)
**Consumed by:** Task 6.6 (all engine manifests reference ConfigMap)
**Reference:** CLAUDE.md Database Design, deployment patterns

---

#### Task 6.6: Update ingress.yaml — Path Prefixes for All New Services `[Seq 104 | DO]`
**Story:** K8s Ingress exposes each service (collectors + engines) at unique HTTP path prefixes so external clients and pipeline_worker can reach them by hostname + path.

**Implementation Details:**
- Location: `deployment/aws/eks/ingress.yaml`
- Add new path rules for 7 services:
  ```yaml
  apiVersion: networking.k8s.io/v1
  kind: Ingress
  metadata:
    name: threat-engine-ingress
    namespace: threat-engine-engines
    annotations:
      nginx.ingress.kubernetes.io/rewrite-target: /$2
  spec:
    ingressClassName: nginx
    rules:
      - host: "threat-engine.internal"
        http:
          paths:
            # Existing paths (discoveries, check, compliance, threat, etc.)
            - path: /discoveries(/|$)(.*)
              pathType: Prefix
              backend:
                service:
                  name: engine-discoveries
                  port:
                    number: 8001
            # ... existing ...

            # NEW paths for collectors
            - path: /log-collector(/|$)(.*)
              pathType: Prefix
              backend:
                service:
                  name: log-collector
                  port:
                    number: 8030
            - path: /external-collector(/|$)(.*)
              pathType: Prefix
              backend:
                service:
                  name: external-collector
                  port:
                    number: 8031

            # NEW paths for new engines
            - path: /container(/|$)(.*)
              pathType: Prefix
              backend:
                service:
                  name: engine-container
                  port:
                    number: 8006
            - path: /network(/|$)(.*)
              pathType: Prefix
              backend:
                service:
                  name: engine-network
                  port:
                    number: 8007
            - path: /supplychain(/|$)(.*)
              pathType: Prefix
              backend:
                service:
                  name: engine-supplychain
                  port:
                    number: 8008
            - path: /api-engine(/|$)(.*)
              pathType: Prefix
              backend:
                service:
                  name: engine-api
                  port:
                    number: 8021
            - path: /risk(/|$)(.*)
              pathType: Prefix
              backend:
                service:
                  name: engine-risk
                  port:
                    number: 8009
  ```
- Service discovery in handlers.py uses path prefix:
  ```python
  def _url(service_name: str) -> str:
      """Resolve service URL from ConfigMap."""
      host = os.getenv("THREAT_ENGINE_HOST", "threat-engine.internal")
      paths = {
          "log_collector": "/log-collector",
          "external_collector": "/external-collector",
          "container": "/container",
          "network": "/network",
          "supplychain": "/supplychain",
          "api_engine": "/api-engine",
          "risk": "/risk",
      }
      return f"http://{host}{paths.get(service_name, f'/{service_name}')}"
  ```
- Key considerations:
  - Ingress rewrites paths using `rewrite-target` annotation
  - Internal K8s clients (pipeline_worker) use service DNS: `http://service-name:port/api/v1/scan`
  - External clients use ingress: `http://threat-engine.internal/container/api/v1/scan`
  - Verify ingress after deployment: `kubectl get ingress -n threat-engine-engines`

**Dependencies:** Task 6.5 (ConfigMap must exist first)
**Consumed by:** Task 6.7 (pipeline test uses these paths)
**Reference:** CLAUDE.md API Patterns, Kubernetes Ingress documentation

---

#### Task 6.7: Full Pipeline Integration Test `[Seq 105 | QA]`
**Story:** Validate that the entire 5-layer pipeline (onboarding → 3 collectors → 9 engines → compliance + risk) completes successfully end-to-end with real data flowing through all stages.

**Implementation Details:**
- Location: `tests/integration/test_full_pipeline.py` (NEW)
- Test plan (sequential):
  1. **Setup:** Create test AWS account credentials in Secrets Manager
  2. **Onboarding:** POST `/api/v1/onboard` → get orchestration_id
  3. **Trigger discovery:** POST `/api/v1/scan` → get discovery_scan_id
  4. **Verify Layer 0.5 (collectors):**
     - Check that log_collector and external_collector start (check K8s pod events)
     - Poll their `/api/v1/health/ready` endpoints until healthy
     - Verify log_events, registry_images tables have data after 5+ minutes
  5. **Verify Layer 1 (inventory, container, api_engine):**
     - Poll inventory `/api/v1/health/ready`
     - Check inventory_input_transformed table for enriched resources
     - Verify container_scan_id populated in scan_orchestration
     - Verify api_scan_id populated in scan_orchestration
  6. **Verify Layer 2 (check, iam, secops, network):**
     - Poll check endpoint
     - Verify check_findings table has PASS/FAIL rows
     - Verify network_findings has findings from VPC flow logs (Tier 2)
  7. **Verify Layer 3 (threat, datasec, supplychain):**
     - Check supplychain_findings references container_sbom (cross-engine)
     - Verify threat_findings has MITRE technique mappings
  8. **Verify Layer 4 (compliance, risk):**
     - Verify compliance_report generated for all frameworks
     - Verify risk_report has FAIR calculations (ALE, exposure_likely, tier)
     - Verify risk_summary aggregates all findings
  9. **End-to-end assertions:**
     - discovery_findings count > 100 (real AWS resources)
     - Collector data flows: log_events >= 10, registry_images >= 5
     - Engine outputs: container_findings >= 5, network_findings >= 10
     - Risk exposure_likely > $0 (at least one finding with financial impact)
     - SQS message sent for downstream handlers

- Test code outline:
  ```python
  import asyncio
  import httpx
  import time
  from datetime import datetime

  async def test_full_pipeline_integration():
      """E2E test: onboarding → collectors → engines → compliance + risk."""

      # 1. Onboard
      async with httpx.AsyncClient() as client:
          resp = await client.post("http://api-gateway:8000/api/v1/onboard", json={
              "account_id": "999999999999",
              "provider": "aws",
              "role_arn": "arn:aws:iam::999999999999:role/ThreatEngineRole"
          })
          assert resp.status_code == 200
          onboarding_id = resp.json()["onboarding_id"]

      # 2. Trigger discovery
      async with httpx.AsyncClient() as client:
          resp = await client.post("http://engine-discoveries:8001/api/v1/scan", json={
              "onboarding_id": onboarding_id
          })
          assert resp.status_code == 200
          discovery_scan_id = resp.json()["scan_id"]

      # 3. Get orchestration_id from DB
      db = psycopg2.connect(...)
      cur = db.cursor()
      cur.execute("SELECT orchestration_id FROM scan_orchestration WHERE discovery_scan_id = %s",
                  (discovery_scan_id,))
      orchestration_id = cur.fetchone()[0]

      # 4. Trigger pipeline_worker
      async with httpx.AsyncClient() as client:
          resp = await client.post("http://pipeline-worker:8025/api/v1/trigger-pipeline", json={
              "orchestration_id": orchestration_id
          })
          assert resp.status_code == 200

      # 5. Poll for completion (timeout 30 min)
      for attempt in range(180):  # 3 hours total
          time.sleep(10)
          cur.execute("""
              SELECT container_scan_id, network_scan_id, supplychain_scan_id,
                     api_scan_id, risk_scan_id, completion_time
              FROM scan_orchestration WHERE orchestration_id = %s
          """, (orchestration_id,))
          row = cur.fetchone()
          if row and row[5]:  # completion_time is not null
              container_id, network_id, supplychain_id, api_id, risk_id, _ = row
              break
      else:
          raise AssertionError("Pipeline did not complete within 3 hours")

      # 6. Verify outputs
      cur.execute("SELECT COUNT(*) FROM container_findings WHERE container_scan_id = %s",
                  (container_id,))
      container_count = cur.fetchone()[0]
      assert container_count >= 5, f"Expected >= 5 container findings, got {container_count}"

      cur.execute("SELECT COUNT(*) FROM risk_findings WHERE risk_scan_id = %s",
                  (risk_id,))
      risk_count = cur.fetchone()[0]
      assert risk_count > 0, "Expected risk findings"

      cur.execute("SELECT exposure_likely FROM risk_report WHERE risk_scan_id = %s",
                  (risk_id,))
      exposure = cur.fetchone()[0]
      assert exposure > 0, "Expected positive financial exposure"

      db.commit()
      db.close()
  ```

- Manual validation steps:
  ```bash
  # 1. Check all K8s services are running
  kubectl get deployments -n threat-engine-engines

  # 2. Check health of each service
  for svc in engine-container engine-network engine-supplychain engine-api engine-risk \
             log-collector external-collector; do
      kubectl exec -it svc/$svc -- curl localhost:PORT/api/v1/health/ready
  done

  # 3. Check database tables populated
  kubectl exec -it svc/postgres -- psql -U threat_engine -d threat_engine_container \
      -c "SELECT COUNT(*) FROM container_input_transformed;"

  # 4. Check orchestration record
  kubectl exec -it svc/postgres -- psql -U threat_engine -d threat_engine_check \
      -c "SELECT * FROM scan_orchestration ORDER BY created_at DESC LIMIT 1 \gx"

  # 5. Tail logs
  kubectl logs -f -l app=engine-risk -n threat-engine-engines --tail=50
  ```

**Dependencies:** Tasks 6.1-6.6 (all infrastructure in place)
**Consumed by:** Task 6.8
**Reference:** Test file patterns from existing engine tests, CLAUDE.md Debugging & Troubleshooting

---

#### Task 6.8: Performance Benchmarking — Scan Time & Resource Usage `[Seq 106 | QA]`
**Story:** Measure end-to-end pipeline latency, per-layer timings, and resource utilization to identify bottlenecks and validate SLA targets (full scan < 30 minutes).

**Implementation Details:**
- Location: `tests/integration/benchmark_pipeline.py` (NEW)
- Metrics to measure:
  - **End-to-end:** Time from onboarding to risk report completion (target: < 30 min)
  - **Per-layer:** Time for each layer to complete in parallel
    - Layer 0.5 (collectors): 5-10 min (external APIs vary)
    - Layer 1 (inventory, container, api): 5 min
    - Layer 2 (check, iam, secops, network): 5 min
    - Layer 3 (threat, datasec, supplychain): 5 min
    - Layer 4 (compliance, risk): 3 min
  - **Per-engine:** Individual engine scan time (sorted by duration)
  - **Resource:** CPU/memory usage per pod (from K8s metrics-server)
  - **Database:** Query times for large ETL joins (e.g., network input_transformed)
  - **Throughput:** Findings per second generated by check, threat engines

- Benchmark script:
  ```python
  import time
  import asyncio
  import psycopg2
  import json
  from datetime import datetime
  import subprocess

  async def benchmark_pipeline():
      """Measure pipeline latency and resource usage."""

      timestamps = {}

      # Phase 1: Trigger pipeline
      timestamps["start"] = datetime.utcnow()
      async with httpx.AsyncClient() as client:
          resp = await client.post("http://pipeline-worker:8025/api/v1/trigger-pipeline", json={
              "orchestration_id": orchestration_id
          })
          assert resp.status_code == 200

      # Phase 2: Poll for layer completion
      db = psycopg2.connect(...)
      cur = db.cursor()

      for layer in [0.5, 1, 2, 3, 4]:
          layer_complete = False
          for attempt in range(180):
              time.sleep(5)
              # Check if all services in layer have completed
              if layer == 0.5:
                  query = """
                      SELECT created_at FROM log_events
                      WHERE orchestration_id = %s ORDER BY created_at DESC LIMIT 1
                  """
              elif layer == 1:
                  query = """
                      SELECT MAX(completed_at) FROM container_findings
                      WHERE container_scan_id IN (
                          SELECT container_scan_id FROM scan_orchestration
                          WHERE orchestration_id = %s
                      )
                  """
              # ... etc for other layers

              cur.execute(query, (orchestration_id,))
              result = cur.fetchone()
              if result and result[0]:
                  layer_complete = True
                  timestamps[f"layer_{layer}_complete"] = result[0]
                  break

          if not layer_complete:
              print(f"Layer {layer} did not complete within timeout")

      timestamps["end"] = datetime.utcnow()

      # Phase 3: Gather resource metrics
      resource_metrics = {}
      for pod in ["engine-container", "engine-network", "engine-supplychain", "engine-api", "engine-risk"]:
          # Use kubectl top
          result = subprocess.run(
              f"kubectl top pod -l app={pod} -n threat-engine-engines --no-headers",
              shell=True, capture_output=True, text=True
          )
          for line in result.stdout.strip().split("\n"):
              if line:
                  parts = line.split()
                  resource_metrics[pod] = {
                      "cpu_m": int(parts[1][:-1]),  # Remove 'm'
                      "memory_mi": int(parts[2][:-2])  # Remove 'Mi'
                  }

      # Phase 4: Database query performance
      cur.execute("""
          SELECT COUNT(*) FROM network_input_transformed
          WHERE network_scan_id = %s
      """, (network_scan_id,))
      network_input_count = cur.fetchone()[0]

      # Phase 5: Report results
      report = {
          "orchestration_id": orchestration_id,
          "timestamps": {k: v.isoformat() for k, v in timestamps.items()},
          "total_time_seconds": (timestamps["end"] - timestamps["start"]).total_seconds(),
          "per_layer_time_seconds": {
              layer: (timestamps[f"layer_{layer}_complete"] - timestamps.get(f"layer_{layer-1}_complete", timestamps["start"])).total_seconds()
              for layer in [0.5, 1, 2, 3, 4]
          },
          "resource_usage": resource_metrics,
          "findings_summary": {
              "container": container_count,
              "network": network_count,
              "risk": risk_count,
          },
          "database_stats": {
              "network_input_transformed_rows": network_input_count,
          }
      }

      # Write report to file
      with open(f"benchmark_{orchestration_id}.json", "w") as f:
          json.dump(report, f, indent=2)

      # Print summary
      print(f"Pipeline completed in {report['total_time_seconds']:.1f}s")
      for layer, duration in report["per_layer_time_seconds"].items():
          print(f"  Layer {layer}: {duration:.1f}s")

      db.close()
      return report
  ```

- Acceptance criteria:
  - Total pipeline time < 30 minutes
  - No layer takes > 10 minutes
  - CPU usage per pod < 2 cores average
  - Memory usage per pod < 2 GB
  - Database query times < 5s for all transforms
  - Zero failed/timeout scans in 3 consecutive runs

- Bottleneck identification:
  - If Layer 0.5 is slow → external API rate limits or network bandwidth
  - If Layer 2-3 slow → database ETL joins need indexing
  - If engine slow → rule evaluation logic needs optimization or parallelization
  - If memory high → increase pod resource requests

**Dependencies:** Task 6.7 (test framework in place)
**Consumed by:** Tasks 7.1-7.6 (optimization work if needed)
**Reference:** K8s metrics-server, Prometheus query patterns

---

## Phase 7: Hardening & Observability
**Goal:** Add distributed tracing, Prometheus metrics, alert rules, rate limiting, retry logic, and cache health monitoring. Prepare system for production.

#### Task 7.1: OpenTelemetry Distributed Tracing — Per-Service Instrumentation `[Seq 107 | PE]`
**Story:** Add distributed tracing to all services (collectors + engines) so operators can visualize request paths through the entire pipeline and identify latency issues.

**Implementation Details:**
- Location: All service `api_server.py` files
- Install OTEL dependencies:
  ```bash
  pip install opentelemetry-api opentelemetry-sdk opentelemetry-exporter-jaeger \
              opentelemetry-instrumentation-fastapi opentelemetry-instrumentation-requests \
              opentelemetry-instrumentation-sqlalchemy
  ```
- Add OTEL initialization to each service:
  ```python
  import os
  from opentelemetry import trace, metrics
  from opentelemetry.sdk.trace import TracerProvider
  from opentelemetry.sdk.trace.export import BatchSpanProcessor
  from opentelemetry.exporter.jaeger.thrift import JaegerExporter
  from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
  from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
  from opentelemetry.instrumentation.requests import RequestsInstrumentor

  # Set service name from environment
  SERVICE_NAME = os.getenv("OTEL_SERVICE_NAME", "unknown-service")

  # Initialize tracer
  jaeger_exporter = JaegerExporter(
      agent_host_name=os.getenv("JAEGER_AGENT_HOST", "localhost"),
      agent_port=int(os.getenv("JAEGER_AGENT_PORT", 6831)),
  )

  trace.set_tracer_provider(TracerProvider())
  trace.get_tracer_provider().add_span_processor(BatchSpanProcessor(jaeger_exporter))

  # Instrument FastAPI
  FastAPIInstrumentor.instrument_app(app)

  # Instrument database
  SQLAlchemyInstrumentor().instrument()

  # Instrument external HTTP calls
  RequestsInstrumentor().instrument()
  ```

- ConfigMap environment variables per service:
  ```yaml
  OTEL_SERVICE_NAME: "engine-container"
  OTEL_EXPORTER_OTLP_ENDPOINT: "http://jaeger-collector:4317"  # OTLP gRPC endpoint
  OTEL_TRACES_EXPORTER: "jaeger"
  JAEGER_AGENT_HOST: "jaeger-agent.monitoring.svc.cluster.local"
  JAEGER_AGENT_PORT: "6831"
  OTEL_ENABLED: "true"
  ```

- Service name per deployment (update in K8s manifest env):
  ```yaml
  spec:
    containers:
      - name: engine-container
        env:
          - name: OTEL_SERVICE_NAME
            value: "engine-container"
          - name: OTEL_EXPORTER_OTLP_ENDPOINT
            valueFrom:
              configMapKeyRef:
                name: threat-engine-config
                key: JAEGER_ENDPOINT
  ```

- Trace propagation (W3C Trace Context standard):
  ```python
  # In pipeline_worker handlers, pass trace context in HTTP headers
  from opentelemetry import trace
  from opentelemetry.propagate import inject

  async def trigger_container(orchestration_id: str, csp: str = "aws",
                              timeout: float = 600.0) -> dict:
      headers = {}
      inject(headers)  # Add W3C Trace Context headers

      async with httpx.AsyncClient(timeout=timeout) as client:
          resp = await client.post(
              f"{_url('container')}/api/v1/scan",
              json={"orchestration_id": orchestration_id, "csp": csp},
              headers=headers,
          )
          resp.raise_for_status()
          return resp.json()
  ```

- Deployment checklist:
  - [ ] Deploy Jaeger all-in-one or distributed components (collector, agent, UI)
  - [ ] Configure jaeger-agent in ConfigMap
  - [ ] Update all 12 service manifests with OTEL_SERVICE_NAME
  - [ ] Test trace creation: curl service → check Jaeger UI for trace
  - [ ] Set sampling rate (production: 1%, staging: 100%)

- Service name list (OTEL_SERVICE_NAME values):
  1. engine-discoveries
  2. engine-check
  3. engine-iam
  4. engine-datasec
  5. engine-secops
  6. engine-threat
  7. engine-compliance
  8. engine-container (NEW)
  9. engine-network (NEW)
  10. engine-supplychain (NEW)
  11. engine-api (NEW)
  12. engine-risk (NEW)
  13. log-collector (NEW)
  14. external-collector (NEW)
  15. pipeline-worker
  16. inventory

**Dependencies:** Task 6.6 (all services deployed)
**Consumed by:** Task 7.2, 7.3 (metrics + alerts use traces)
**Reference:** OpenTelemetry documentation, Jaeger deployment guide

---

#### Task 7.2: Prometheus Metrics — Per-Service Gauges & Histograms `[Seq 108 | PE]`
**Story:** Export Prometheus metrics from each service to enable dashboard monitoring and alert triggers for scan duration, findings count, error rate, and cache age.

**Implementation Details:**
- Location: All service `api_server.py` files + shared metrics utilities in `shared/common/metrics.py` (NEW)
- Install Prometheus client:
  ```bash
  pip install prometheus-client prometheus-fastapi-instrumentor
  ```

- Create shared metrics module:
  ```python
  # shared/common/metrics.py
  from prometheus_client import Counter, Gauge, Histogram, generate_latest
  import os

  SERVICE_NAME = os.getenv("OTEL_SERVICE_NAME", "unknown-service")

  # Global metrics (shared across all services)
  scan_duration_seconds = Histogram(
      name=f"{SERVICE_NAME}_scan_duration_seconds",
      documentation="Time taken to complete a scan in seconds",
      buckets=(10, 30, 60, 120, 300, 600, 1800),
      labelnames=["csp", "scan_type", "status"]
  )

  findings_count = Gauge(
      name=f"{SERVICE_NAME}_findings_count",
      documentation="Number of findings generated in last scan",
      labelnames=["csp", "severity", "framework"]
  )

  scan_errors_total = Counter(
      name=f"{SERVICE_NAME}_scan_errors_total",
      documentation="Total number of scan errors",
      labelnames=["csp", "error_type"]
  )

  cache_age_seconds = Gauge(
      name=f"{SERVICE_NAME}_cache_age_seconds",
      documentation="Age of cache data in seconds",
      labelnames=["cache_name", "source"]
  )

  api_request_duration_seconds = Histogram(
      name=f"{SERVICE_NAME}_api_request_duration_seconds",
      documentation="API request latency in seconds",
      buckets=(0.01, 0.05, 0.1, 0.5, 1, 2, 5),
      labelnames=["method", "endpoint", "status"]
  )

  database_query_duration_seconds = Histogram(
      name=f"{SERVICE_NAME}_database_query_duration_seconds",
      documentation="Database query latency in seconds",
      buckets=(0.01, 0.05, 0.1, 0.5, 1, 2, 5, 10),
      labelnames=["table", "operation", "status"]
  )
  ```

- Integrate into FastAPI:
  ```python
  # In api_server.py
  from fastapi import FastAPI
  from prometheus_fastapi_instrumentor import Instrumentor
  from shared.common.metrics import scan_duration_seconds, findings_count
  import time

  app = FastAPI()

  # Auto-instrument all endpoints
  Instrumentor().instrument(app).expose()

  # Custom instrumentation for scan endpoint
  @app.post("/api/v1/scan")
  async def scan(request: ScanRequest):
      start = time.time()
      try:
          # Run scan
          result = await run_scan(request.orchestration_id, request.csp)

          duration = time.time() - start
          scan_duration_seconds.labels(
              csp=request.csp,
              scan_type=self.SCAN_TYPE,
              status="success"
          ).observe(duration)

          findings_count.labels(
              csp=request.csp,
              severity="high",
              framework="cis"
          ).set(result.findings_count)

          return result
      except Exception as e:
          duration = time.time() - start
          scan_duration_seconds.labels(
              csp=request.csp,
              scan_type=self.SCAN_TYPE,
              status="error"
          ).observe(duration)

          scan_errors_total.labels(
              csp=request.csp,
              error_type=type(e).__name__
          ).inc()

          raise
  ```

- Expose metrics endpoint:
  ```python
  from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

  @app.get("/api/v1/metrics")
  async def metrics():
      return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
  ```

- Update Prometheus scrape config (in `deployment/aws/eks/prometheus-values.yaml`):
  ```yaml
  prometheus:
    prometheusSpec:
      serviceMonitorSelector:
        matchLabels:
          monitoring: "true"
  ```

- Create ServiceMonitor for each service:
  ```yaml
  apiVersion: monitoring.coreos.com/v1
  kind: ServiceMonitor
  metadata:
    name: engine-container-metrics
    namespace: threat-engine-engines
    labels:
      monitoring: "true"
  spec:
    selector:
      matchLabels:
        app: engine-container
    endpoints:
      - port: http
        path: /api/v1/metrics
        interval: 30s
  ```

- Metrics dashboard (Grafana):
  - Create dashboard: "Threat Engine Pipeline"
  - Panels:
    - Scan duration by engine (line chart)
    - Findings count by severity (stacked bar)
    - Error rate by service (time series)
    - Cache age for vuln_cache, threat_intel_ioc (gauge)

- Query examples (PromQL):
  ```promql
  # P95 scan duration per engine
  histogram_quantile(0.95, rate(engine_scan_duration_seconds_bucket[5m]))

  # Error rate by service
  rate(engine_scan_errors_total[5m]) / rate(engine_scan_duration_seconds_count[5m])

  # Cache staleness alert
  (time() - external_collector_cache_age_seconds{cache_name="vuln_cache"}) / 86400 > 7
  ```

**Dependencies:** Task 7.1 (tracing framework in place)
**Consumed by:** Task 7.3 (alerts), dashboards
**Reference:** Prometheus documentation, Grafana best practices

---

#### Task 7.3: Prometheus Alert Rules — Scan Failures, Timeouts, Error Rates, Cache Staleness `[Seq 109 | PE]`
**Story:** Define Prometheus alert rules for operational health (scan failures, error rate > 5%, external API timeouts, cache data older than TTL). Wire to Slack/PagerDuty for on-call escalation.

**Implementation Details:**
- Location: `deployment/aws/eks/prometheus-rules.yaml` (NEW)
- Create PrometheusRule resource with alert groups:
  ```yaml
  apiVersion: monitoring.coreos.com/v1
  kind: PrometheusRule
  metadata:
    name: threat-engine-alerts
    namespace: threat-engine-engines
  spec:
    groups:
      - name: threat-engine.rules
        interval: 30s
        rules:
          # Alert 1: Scan failure rate
          - alert: ScanFailureRateHigh
            expr: |
              (
                rate(engine_scan_errors_total[5m]) /
                rate(engine_scan_duration_seconds_count[5m])
              ) > 0.05
            for: 5m
            labels:
              severity: critical
              team: platform
            annotations:
              summary: "Scan failure rate > 5% for {{ $labels.instance }}"
              description: |
                Service {{ $labels.job }} has error rate {{ $value | humanizePercentage }}
                This indicates either bad credentials, permission issues, or service instability.
              dashboard: "https://grafana.internal/d/threat-engine-pipeline"

          # Alert 2: Scan timeout
          - alert: ScanTimeoutDetected
            expr: |
              histogram_quantile(0.95, rate(engine_scan_duration_seconds_bucket[10m])) > 600
            for: 10m
            labels:
              severity: warning
              team: platform
            annotations:
              summary: "P95 scan time > 10 minutes for {{ $labels.scan_type }}"
              description: |
                Scans for {{ $labels.scan_type }} are taking > 600s.
                This may be due to external API rate limits or database slow queries.
                Review: https://prometheus.internal/graph?g0.expr=...

          # Alert 3: Cache data too old
          - alert: VulnerabilityCacheTooOld
            expr: |
              (time() - external_collector_cache_age_seconds{cache_name="vuln_cache"}) / 86400 > 7
            for: 1h
            labels:
              severity: warning
              team: security
            annotations:
              summary: "Vulnerability cache data is > 7 days old"
              description: |
                The NVD/CVE cache has not been refreshed since {{ $value | humanizeDuration }} ago.
                This may mean the external_collector service is down or has failed.
                Check logs: kubectl logs -f -l app=external-collector

          - alert: ThreatIntelCacheTooOld
            expr: |
              (time() - external_collector_cache_age_seconds{cache_name="threat_intel_ioc"}) / 86400 > 3
            for: 30m
            labels:
              severity: warning
              team: security
            annotations:
              summary: "Threat intelligence cache is > 3 days old"
              description: "Threat intel feed has not been refreshed. Check external_collector."

          # Alert 4: Service health
          - alert: ServiceNotReady
            expr: |
              up{job=~"engine-.*"} == 0
            for: 2m
            labels:
              severity: critical
              team: platform
            annotations:
              summary: "Service {{ $labels.job }} is not responding"
              description: |
                {{ $labels.job }} has been down for > 2 minutes.
                Check pod status: kubectl get pod -l app={{ $labels.job }} -n threat-engine-engines

          # Alert 5: Database connection failures
          - alert: DatabaseConnectionFailures
            expr: |
              increase(engine_database_query_errors_total{error_type="connection"}[5m]) > 5
            for: 5m
            labels:
              severity: critical
              team: platform
            annotations:
              summary: "Database connection failures in {{ $labels.job }}"
              description: |
                {{ $labels.job }} has had {{ $value }} DB connection errors in the last 5 minutes.
                Check RDS status and network connectivity.

          # Alert 6: Slow ETL transformation
          - alert: SlowETLTransformation
            expr: |
              histogram_quantile(0.95, rate(engine_etl_duration_seconds_bucket[10m])) > 300
            for: 10m
            labels:
              severity: warning
              team: platform
            annotations:
              summary: "ETL for {{ $labels.engine }} taking > 5 minutes (P95)"
              description: |
                Data transformation in {{ $labels.engine }} is slow.
                May need to add database indexes or optimize join logic.

          # Alert 7: Finding evaluation slow
          - alert: SlowFindingEvaluation
            expr: |
              histogram_quantile(0.95, rate(engine_evaluation_duration_seconds_bucket{stage="evaluate"}[10m])) > 120
            for: 10m
            labels:
              severity: warning
              team: platform
            annotations:
              summary: "Finding evaluation for {{ $labels.engine }} taking > 2 minutes"
              description: |
                Rule evaluation in {{ $labels.engine }} is slow.
                Check rule complexity and row counts in input_transformed table.
  ```

- Configure AlertManager (in Prometheus Helm values or separate manifest):
  ```yaml
  apiVersion: v1
  kind: ConfigMap
  metadata:
    name: alertmanager-config
    namespace: monitoring
  data:
    alertmanager.yml: |
      global:
        resolve_timeout: 5m
      route:
        receiver: 'default'
        group_by: ['alertname', 'cluster', 'service']
        group_wait: 10s
        group_interval: 10s
        repeat_interval: 12h
        routes:
          - match:
              severity: critical
            receiver: 'pagerduty'
            continue: true
          - match:
              severity: warning
            receiver: 'slack'
      receivers:
        - name: 'default'
          slack_configs:
            - api_url: 'https://hooks.slack.com/services/...'
              channel: '#threat-engine-alerts'
              title: 'Alert: {{ .GroupLabels.alertname }}'
              text: '{{ .CommonAnnotations.description }}'
        - name: 'pagerduty'
          pagerduty_configs:
            - service_key: 'PAGERDUTY_SERVICE_KEY'
  ```

- Testing alerts locally:
  ```bash
  # Port forward Prometheus
  kubectl port-forward svc/prometheus 9090:9090 -n monitoring

  # View alert rules
  curl http://localhost:9090/api/v1/rules | jq '.data.groups[0].rules'

  # Test alert firing (manually)
  curl -X POST http://localhost:9093/api/v1/alerts \
    -H 'Content-Type: application/json' \
    -d '[{"labels":{"alertname":"TestAlert","severity":"critical"},"annotations":{"summary":"Test"}}]'
  ```

**Dependencies:** Task 7.2 (metrics in place)
**Consumed by:** Operations handoff
**Reference:** Prometheus alerting rules, AlertManager documentation

---

#### Task 7.4: Rate Limiting — Per-Endpoint Limits + External API Budget `[Seq 110 | PE]`
**Story:** Prevent abuse and ensure fair resource consumption by rate-limiting scan trigger endpoints and enforcing external API call budgets (e.g., max 100 GitHub API calls/hour, max 500 NVD queries/day).

**Implementation Details:**
- Location: `shared/api_gateway/rate_limiter.py` (NEW) + K8s ServicePolicy or ingress annotations
- Per-endpoint rate limits:
  ```python
  # shared/api_gateway/rate_limiter.py
  from slowapi import Limiter
  from slowapi.util import get_remote_address
  from slowapi.errors import RateLimitExceeded
  from fastapi import FastAPI, HTTPException
  import os

  limiter = Limiter(key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])

  # Rate limit rules per endpoint (stricter for expensive operations)
  RATE_LIMIT_RULES = {
      "/api/v1/scan": "5 per hour",  # Prevent scan spam (each scan takes 1-10 min)
      "/api/v1/health/ready": "100 per minute",  # Health checks OK
      "/api/v1/metrics": "100 per minute",  # Prometheus scrape OK
  }

  def get_rate_limit(endpoint: str) -> str:
      return RATE_LIMIT_RULES.get(endpoint, "200 per day")

  # Middleware to apply rate limits
  @app.middleware("http")
  async def rate_limit_middleware(request: Request, call_next):
      limit = get_rate_limit(request.url.path)
      if not limiter.hit(f"{get_remote_address(request)}:{request.url.path}", limit):
          raise HTTPException(status_code=429, detail="Rate limit exceeded")
      return await call_next(request)
  ```

- External API call budget (per external_collector):
  ```python
  # shared/common/external_api_budget.py
  import psycopg2
  from datetime import datetime, timedelta
  import os

  class APIBudgetTracker:
      """Track API calls against daily/hourly budgets."""

      BUDGETS = {
          "github": {"per_hour": 60, "per_day": 1000},  # GitHub API rate limit
          "dockerhub": {"per_hour": 100, "per_day": 2000},
          "nvd": {"per_day": 500},  # NVD has daily limit
          "npm": {"per_hour": 100, "per_day": 5000},
          "pypi": {"per_hour": 100, "per_day": 5000},
      }

      def __init__(self):
          self.db = psycopg2.connect(os.getenv("EXTERNAL_COLLECTOR_DATABASE_URL"))

      def log_call(self, source: str, call_count: int = 1):
          """Log API call to database."""
          cur = self.db.cursor()
          cur.execute("""
              INSERT INTO api_call_log (source, call_time, call_count)
              VALUES (%s, NOW(), %s)
          """, (source, call_count))
          self.db.commit()

      def check_budget(self, source: str) -> bool:
          """Check if source has budget remaining."""
          cur = self.db.cursor()

          # Check hourly budget
          if "per_hour" in self.BUDGETS[source]:
              cur.execute("""
                  SELECT COUNT(*) FROM api_call_log
                  WHERE source = %s AND call_time > NOW() - INTERVAL '1 hour'
              """, (source,))
              hourly_calls = cur.fetchone()[0]
              if hourly_calls >= self.BUDGETS[source]["per_hour"]:
                  return False

          # Check daily budget
          cur.execute("""
              SELECT COUNT(*) FROM api_call_log
              WHERE source = %s AND call_time > NOW() - INTERVAL '1 day'
          """, (source,))
          daily_calls = cur.fetchone()[0]
          if daily_calls >= self.BUDGETS[source]["per_day"]:
              return False

          return True
  ```

- Database schema for tracking:
  ```sql
  CREATE TABLE api_call_log (
      id SERIAL PRIMARY KEY,
      source VARCHAR(50) NOT NULL,  -- 'github', 'dockerhub', 'nvd', etc.
      call_time TIMESTAMP NOT NULL DEFAULT NOW(),
      call_count INT DEFAULT 1,
      response_status INT,
      response_time_ms INT,
      INDEX idx_source_time (source, call_time)
  );
  ```

- Ingress rate limiting annotation (Nginx):
  ```yaml
  apiVersion: networking.k8s.io/v1
  kind: Ingress
  metadata:
    name: threat-engine-ingress
    namespace: threat-engine-engines
    annotations:
      nginx.ingress.kubernetes.io/limit-rps: "10"  # 10 requests per second globally
      nginx.ingress.kubernetes.io/limit-connections: "5"  # 5 concurrent connections
      nginx.ingress.kubernetes.io/limit-whitelist: "10.0.0.0/8"  # Allow K8s internal IPs
  ```

- ServicePolicy for fine-grained control (Kubernetes NetworkPolicy or Istio VirtualService):
  ```yaml
  # Using Istio (if deployed)
  apiVersion: networking.istio.io/v1beta1
  kind: VirtualService
  metadata:
    name: engine-container-vs
    namespace: threat-engine-engines
  spec:
    hosts:
      - engine-container
    http:
      - match:
          - uri:
              prefix: /api/v1/scan
        fault:
          delay:
            percentage: 0.1
            fixedDelay: 5s
        timeout: 600s
        retries:
          attempts: 3
          perTryTimeout: 120s
  ```

**Dependencies:** Task 6.6 (ingress in place), Task 7.2 (metrics for monitoring)
**Consumed by:** Operations, production deployment
**Reference:** slowapi library, Nginx rate limiting, Istio traffic management

---

#### Task 7.5: Retry Logic — SQS Dead-Letter Queue + External API Exponential Backoff `[Seq 111 | PE]`
**Story:** Implement resilient retry handling for transient failures (network blips, external API rate limits, database connection resets) without losing data or causing duplicate processing.

**Implementation Details:**
- Location: `shared/pipeline_worker/retry_handler.py` (NEW) + queue setup
- SQS dead-letter queue setup:
  ```python
  # In K8s/CloudFormation (setup once)
  # deployment/aws/eks/sqs-dlq.yaml or use boto3
  import boto3

  sqs = boto3.client('sqs')

  # Create main queue
  main_queue = sqs.create_queue(
      QueueName='threat-engine-pipeline',
      Attributes={
          'VisibilityTimeout': '300',  # 5 minutes
          'MessageRetentionPeriod': '86400',  # 1 day
          'RedrivePolicy': {
              'deadLetterTargetArn': 'arn:aws:sqs:REGION:ACCOUNT:threat-engine-dlq',
              'maxReceiveCount': '3'  # Move to DLQ after 3 failures
          }
      }
  )

  # Create DLQ
  dlq = sqs.create_queue(
      QueueName='threat-engine-dlq',
      Attributes={
          'MessageRetentionPeriod': '604800'  # 7 days (long retention for investigation)
      }
  )
  ```

- Exponential backoff retry logic:
  ```python
  # shared/pipeline_worker/retry_handler.py
  import asyncio
  import httpx
  import logging
  from typing import Callable, Any, TypeVar, Coroutine
  import random

  T = TypeVar('T')

  logger = logging.getLogger(__name__)

  class RetryConfig:
      """Backoff configuration for retries."""
      max_attempts: int = 5
      initial_delay_seconds: float = 1
      max_delay_seconds: float = 60
      exponential_base: float = 2
      jitter: bool = True  # Add randomness to prevent thundering herd

  async def retry_with_backoff(
      fn: Callable[..., Coroutine[Any, Any, T]],
      *args,
      config: RetryConfig = RetryConfig(),
      **kwargs
  ) -> T:
      """Retry an async function with exponential backoff."""

      last_exception = None

      for attempt in range(1, config.max_attempts + 1):
          try:
              return await fn(*args, **kwargs)
          except (httpx.TimeoutException, httpx.ConnectError, httpx.ReadTimeout) as e:
              last_exception = e
              is_retryable = True
          except httpx.HTTPStatusError as e:
              # Retry on 429 (rate limit), 503 (service unavailable), 504 (gateway timeout)
              is_retryable = e.response.status_code in [429, 503, 504]
              last_exception = e
              if not is_retryable:
                  raise
          except Exception as e:
              # Don't retry on other errors (auth, validation, etc.)
              raise

          if attempt >= config.max_attempts:
              break

          # Calculate backoff with jitter
          delay = min(
              config.initial_delay_seconds * (config.exponential_base ** (attempt - 1)),
              config.max_delay_seconds
          )

          if config.jitter:
              delay = delay * (0.5 + random.random())  # Add ±50% jitter

          logger.warning(
              f"Attempt {attempt} failed: {last_exception}. "
              f"Retrying in {delay:.1f}s... (max {config.max_attempts})"
          )

          await asyncio.sleep(delay)

      raise last_exception

  # Usage in pipeline_worker
  async def trigger_container_with_retry(orchestration_id: str, csp: str = "aws") -> dict:
      """Trigger container engine with automatic retry."""
      return await retry_with_backoff(
          trigger_container,
          orchestration_id,
          csp,
          config=RetryConfig(
              max_attempts=5,
              initial_delay_seconds=2,
              max_delay_seconds=30
          )
      )
  ```

- DLQ monitoring and alerting:
  ```python
  # shared/common/dlq_monitor.py
  import boto3
  import logging

  sqs = boto3.client('sqs')
  logger = logging.getLogger(__name__)

  async def monitor_dlq():
      """Periodically check DLQ for stuck messages."""
      while True:
          try:
              response = sqs.get_queue_attributes(
                  QueueUrl='arn:aws:sqs:REGION:ACCOUNT:threat-engine-dlq',
                  AttributeNames=['ApproximateNumberOfMessages']
              )
              dlq_size = int(response['Attributes']['ApproximateNumberOfMessages'])

              if dlq_size > 10:
                  logger.error(f"DLQ has {dlq_size} messages! Manual intervention needed.")
                  # Send alert to Slack/PagerDuty

              # Expose as Prometheus metric
              dlq_messages.set(dlq_size)
          except Exception as e:
              logger.exception(f"Error checking DLQ: {e}")

          await asyncio.sleep(300)  # Check every 5 minutes
  ```

- Retry middleware for FastAPI endpoints:
  ```python
  # shared/api_gateway/retry_middleware.py
  from fastapi import Request, Response
  from starlette.middleware.base import BaseHTTPMiddleware
  import asyncio

  class RetryMiddleware(BaseHTTPMiddleware):
      async def dispatch(self, request: Request, call_next) -> Response:
          max_retries = 3
          for attempt in range(max_retries):
              try:
                  return await call_next(request)
              except Exception as e:
                  if attempt == max_retries - 1:
                      raise
                  await asyncio.sleep(2 ** attempt)  # Exponential backoff
  ```

- Database connection retry (for SQLAlchemy):
  ```python
  # shared/database/connection.py
  from sqlalchemy.pool import QueuePool
  from sqlalchemy import create_engine, event
  import logging

  logger = logging.getLogger(__name__)

  engine = create_engine(
      DATABASE_URL,
      poolclass=QueuePool,
      pool_size=10,
      max_overflow=20,
      pool_pre_ping=True,  # Test connection before using
      pool_recycle=3600,  # Recycle connections every hour
      pool_retry_on_connect=True,  # Retry on connection failure
      echo_pool=True,  # Log pool operations
  )

  @event.listens_for(engine, "connect")
  def receive_connect(dbapi_conn, connection_record):
      """Set connection timeout."""
      dbapi_conn.settimeout(10)
  ```

**Dependencies:** Task 6.1, 6.2 (pipeline_worker in place)
**Consumed by:** Production deployment
**Reference:** AWS SQS DLQ, asyncio retry patterns, exponential backoff algorithms

---

#### Task 7.6: Cache Health Monitoring — TTL Verification for External Data `[Seq 112 | PE]`
**Story:** Implement health checks and alerts for the 3 critical external data caches (vuln_cache, threat_intel_ioc, package_metadata) to detect stale data and collection failures.

**Implementation Details:**
- Location: `shared/common/cache_health.py` (NEW) + health check endpoints
- Cache health check module:
  ```python
  # shared/common/cache_health.py
  import psycopg2
  from datetime import datetime, timedelta
  import logging
  import os

  logger = logging.getLogger(__name__)

  class CacheHealthMonitor:
      """Monitor health and freshness of external data caches."""

      CACHES = {
          "vuln_cache": {
              "db": "threat_engine_external",
              "table": "vuln_cache",
              "max_age_days": 7,
              "min_rows": 10000,
              "last_refresh_col": "last_refresh",
          },
          "threat_intel_ioc": {
              "db": "threat_engine_external",
              "table": "threat_intel_ioc",
              "max_age_days": 3,
              "min_rows": 1000,
              "last_refresh_col": "last_refresh",
          },
          "package_metadata": {
              "db": "threat_engine_external",
              "table": "package_metadata",
              "max_age_days": 30,
              "min_rows": 100,
              "last_refresh_col": "last_refresh",
          },
      }

      def __init__(self):
          self.db = psycopg2.connect(os.getenv("EXTERNAL_COLLECTOR_DATABASE_URL"))

      def check_cache_health(self, cache_name: str) -> dict:
          """Check health of a single cache."""
          cache_config = self.CACHES[cache_name]
          cur = self.db.cursor()

          # Check row count
          cur.execute(f"""
              SELECT COUNT(*) FROM {cache_config['table']}
          """)
          row_count = cur.fetchone()[0]

          # Check last refresh time
          cur.execute(f"""
              SELECT MAX({cache_config['last_refresh_col']}) FROM {cache_config['table']}
          """)
          last_refresh = cur.fetchone()[0]

          if not last_refresh:
              age_days = None
              is_stale = True
              status = "EMPTY"
          else:
              age_days = (datetime.utcnow() - last_refresh).days
              is_stale = age_days > cache_config["max_age_days"]
              status = "STALE" if is_stale else "HEALTHY"

          return {
              "cache_name": cache_name,
              "status": status,
              "row_count": row_count,
              "min_rows_expected": cache_config["min_rows"],
              "age_days": age_days,
              "max_age_days": cache_config["max_age_days"],
              "is_stale": is_stale,
              "last_refresh": last_refresh.isoformat() if last_refresh else None,
          }

      def check_all_caches(self) -> dict:
          """Check health of all caches."""
          results = {}
          has_issues = False

          for cache_name in self.CACHES:
              health = self.check_cache_health(cache_name)
              results[cache_name] = health

              if health["is_stale"] or health["row_count"] < health["min_rows_expected"]:
                  has_issues = True
                  logger.warning(
                      f"Cache health issue in {cache_name}: {health['status']}"
                  )

          return {
              "timestamp": datetime.utcnow().isoformat(),
              "overall_status": "UNHEALTHY" if has_issues else "HEALTHY",
              "caches": results,
          }
  ```

- Add health check endpoint to external_collector API:
  ```python
  # engines/external_collector/api_server.py
  from shared.common.cache_health import CacheHealthMonitor
  from fastapi import FastAPI

  app = FastAPI()
  monitor = CacheHealthMonitor()

  @app.get("/api/v1/health/cache-status")
  async def health_cache_status():
      """Detailed cache health status."""
      return monitor.check_all_caches()

  @app.get("/api/v1/health/ready")
  async def health_ready():
      """Readiness check (K8s use)."""
      health = monitor.check_all_caches()

      if health["overall_status"] == "UNHEALTHY":
          return {"status": "not_ready", "reason": "Cache is stale"}

      return {"status": "ready"}
  ```

- Prometheus metrics for cache health:
  ```python
  # shared/common/metrics.py
  from prometheus_client import Gauge

  cache_age_seconds = Gauge(
      name="external_collector_cache_age_seconds",
      documentation="Age of cache data in seconds",
      labelnames=["cache_name"]
  )

  cache_row_count = Gauge(
      name="external_collector_cache_row_count",
      documentation="Number of rows in cache",
      labelnames=["cache_name"]
  )

  # In external_collector scan loop:
  health = monitor.check_all_caches()
  for cache_name, cache_health in health["caches"].items():
      if cache_health["age_days"]:
          cache_age_seconds.labels(cache_name=cache_name).set(
              cache_health["age_days"] * 86400
          )
      cache_row_count.labels(cache_name=cache_name).set(
          cache_health["row_count"]
      )
  ```

- Grafana dashboard panel (cache staleness):
  ```promql
  # Show cache age as gauge
  (time() - external_collector_cache_age_seconds) / 86400

  # Alert when cache > max age
  (time() - external_collector_cache_age_seconds) / 86400 > 7
  ```

- Manual cache refresh trigger:
  ```bash
  # POST /api/v1/refresh endpoint
  curl -X POST http://external-collector:8031/api/v1/refresh \
    -H 'Content-Type: application/json' \
    -d '{"sources": ["github", "dockerhub", "nvd"]}'
  ```

**Dependencies:** Task 7.2 (metrics in place)
**Consumed by:** Task 7.3 (alert rules)
**Reference:** Cache invalidation strategies, TTL management

---

#### Task 7.7: Documentation Update — API Reference & Operational Runbook `[Seq 113 | PE]`
**Story:** Update all documentation to reflect new services, endpoints, metrics, and operational procedures for running the full 14-service pipeline.

**Implementation Details:**
- Location: `.claude/documentation/API_REFERENCE_ALL_ENGINES.md` (update), `.claude/documentation/OPERATIONS_RUNBOOK.md` (NEW)

- Update API_REFERENCE_ALL_ENGINES.md:
  - Add sections for log_collector, external_collector (5 new service docs)
  - Document new engine endpoints: engine-container, engine-network, engine-supplychain, engine-api, engine-risk (5 more sections)
  - Each section includes:
    - Base URL / port
    - Health endpoints
    - Scan endpoint signature (method, path, request/response schemas)
    - Metrics endpoint
    - Example curl commands
  - Add table: "Service Discovery & Ports"
    ```markdown
    | Service | Port | Health | Scan | Metrics |
    |---------|------|--------|------|---------|
    | log-collector | 8030 | GET /health/ready | POST /scan | GET /metrics |
    | external-collector | 8031 | GET /health/ready | POST /scan | GET /metrics |
    | engine-container | 8006 | GET /health/ready | POST /scan | GET /metrics |
    ... (12 total)
    ```

- Create OPERATIONS_RUNBOOK.md (NEW):
  ```markdown
  # Threat Engine Operations Runbook

  ## Daily Operations

  ### Health Check
  ```bash
  # Check all services are healthy
  kubectl get pods -n threat-engine-engines -o wide

  # Detailed health per service
  for svc in log-collector external-collector engine-container engine-network \
             engine-supplychain engine-api engine-risk; do
    echo "=== $svc ==="
    kubectl exec -it svc/$svc -- curl -s localhost:PORT/api/v1/health/ready | jq .
  done
  ```

  ### Monitor Scan Progress
  ```bash
  # Watch orchestration table for current scan
  kubectl exec -it svc/postgres -- psql -U threat_engine -d threat_engine_check \
    -c "SELECT * FROM scan_orchestration ORDER BY created_at DESC LIMIT 1 \gx"

  # Check findings count per engine
  kubectl exec -it svc/postgres -- psql -U threat_engine -d threat_engine_check -c \
    "SELECT
      (SELECT COUNT(*) FROM container_findings) as container,
      (SELECT COUNT(*) FROM network_findings) as network,
      (SELECT COUNT(*) FROM risk_findings) as risk;"
  ```

  ## Troubleshooting

  ### Scan Stuck or Taking Too Long
  1. Check pipeline_worker logs:
     ```bash
     kubectl logs -f deployment/pipeline-worker -n threat-engine-engines
     ```
  2. Check specific engine logs (whichever layer is slow):
     ```bash
     kubectl logs -f svc/engine-network -n threat-engine-engines
     ```
  3. Check database query performance:
     ```bash
     kubectl exec -it svc/postgres -- psql ... -c "SELECT * FROM pg_stat_statements ORDER BY mean_time DESC LIMIT 10;"
     ```

  ### Cache Stale
  1. Check cache health:
     ```bash
     curl http://external-collector:8031/api/v1/health/cache-status | jq .
     ```
  2. Trigger manual refresh:
     ```bash
     curl -X POST http://external-collector:8031/api/v1/refresh \
       -d '{"sources": ["nvd"]}'
     ```
  3. Monitor refresh progress:
     ```bash
     kubectl logs -f svc/external-collector -n threat-engine-engines
     ```

  ### Service Not Responding
  1. Check pod status:
     ```bash
     kubectl describe pod POD_NAME -n threat-engine-engines
     ```
  2. Check logs for errors:
     ```bash
     kubectl logs -p POD_NAME -n threat-engine-engines  # Previous logs if crashed
     ```
  3. Check resource limits:
     ```bash
     kubectl top pod POD_NAME -n threat-engine-engines
     ```
  4. Restart service:
     ```bash
     kubectl rollout restart deployment/engine-network -n threat-engine-engines
     ```

  ### High Error Rate
  1. Check Prometheus alerts:
     ```
     http://prometheus:9090/alerts
     ```
  2. View error logs:
     ```bash
     kubectl logs svc/engine-X -n threat-engine-engines | grep -i error | tail -50
     ```
  3. Check database connectivity:
     ```bash
     kubectl exec -it svc/engine-X -- pg_isready -h postgres -p 5432
     ```

  ## Incident Response

  ### Critical: Service Down (status = not_ready)
  - [ ] Page on-call engineer
  - [ ] Check if RDS is up: `aws rds describe-db-instances --query 'DBInstances[0].DBInstanceStatus'`
  - [ ] Check network connectivity: `kubectl exec pod -- nc -zv postgres 5432`
  - [ ] Rollback last deployment if recent change
  - [ ] Check CloudWatch logs for AWS API errors

  ### Warning: High Error Rate (> 5%)
  - [ ] Check if external API is down (GitHub, Docker Hub, NVD)
  - [ ] Check rate limiting: `curl -I http://github.com/rate_limit`
  - [ ] Increase retry attempts in retry_handler.py
  - [ ] Monitor fix and verify error rate returns to < 1%

  ### Warning: Cache Stale (> max_age_days)
  - [ ] Manual refresh: `curl -X POST .../refresh`
  - [ ] Check external_collector logs for fetch errors
  - [ ] Verify external API credentials in Secrets Manager
  - [ ] Set reminder to refresh cache on schedule

  ## Scaling

  ### Increase Scan Throughput
  ```bash
  # Scale log_collector worker pods
  kubectl scale deployment log-collector-worker --replicas=5 -n threat-engine-engines

  # Check HPA status
  kubectl get hpa -n threat-engine-engines
  ```

  ### Reduce Scan Duration
  1. Add indexes to slow ETL tables:
     ```sql
     CREATE INDEX idx_network_resource_id ON network_input_transformed(resource_id);
     ```
  2. Profile slow queries in Prometheus / RDS Performance Insights
  3. Optimize rule evaluation logic (reduce rule count or complexity)

  ## Backup & Disaster Recovery

  ### Backup RDS Daily
  ```bash
  aws rds create-db-snapshot --db-instance-identifier threat-engine-postgres \
    --db-snapshot-identifier threat-engine-backup-$(date +%Y%m%d)
  ```

  ### Restore from Backup
  ```bash
  aws rds restore-db-instance-from-db-snapshot \
    --db-instance-identifier threat-engine-postgres-restored \
    --db-snapshot-identifier threat-engine-backup-20260301
  ```

  ## Metrics & Dashboards

  - **Main Dashboard:** http://grafana.internal/d/threat-engine-pipeline
  - **Alerts:** http://prometheus.internal/alerts
  - **Traces:** http://jaeger.internal/search
  - **Logs:** http://loki.internal/explore (if using Loki)
  ```

- Update CLAUDE.md:
  - Add new service sections in Repository Structure
  - Update data flow diagrams with Layer 0.5
  - Document new database names and schemas
  - Add troubleshooting section for new services

- Update DEPLOYMENT_GUIDE.md:
  - Add step-by-step for deploying collectors + new engines
  - Add K8s manifest validation checklist
  - Add post-deployment validation steps

**Dependencies:** All tasks 6.1-7.6 (implementation complete)
**Consumed by:** Operations team, runbooks, knowledge base
**Reference:** Existing documentation structure, OpenAPI/Swagger patterns

---

## Execution Summary

### Service Inventory (Total: 14 K8s deployments + 2 collectors)

| Service | Type | Port | DB | Pod Count |
|---------|------|------|-----|-----------|
| engine-discoveries | Engine | 8001 | threat_engine_check | 1 |
| engine-check | Engine | 8002 | threat_engine_check | 1 |
| engine-iam | Engine | 8001 | threat_engine_check | 1 |
| engine-datasec | Engine | 8003 | threat_engine_check | 1 |
| engine-secops | Engine | 8005 | threat_engine_check | 1 |
| engine-threat | Engine | 8020 | threat_engine_check | 1 |
| engine-compliance | Engine | 8000 | threat_engine_check | 1 |
| log_collector (API) | Shared collector | 8030 | threat_engine_logs | 1 |
| log_collector (SQS worker) | Shared collector | — | threat_engine_logs | 1-3 (HPA) |
| external_collector | Shared collector | 8031 | threat_engine_external | 1 |
| engine-container | Engine | 8006 | threat_engine_container | 1 |
| engine-network | Engine | 8007 | threat_engine_network | 1 |
| engine-supplychain | Engine | 8008 | threat_engine_supplychain | 1 |
| engine-api | Engine | 8021 | threat_engine_api | 1 |
| engine-risk | Engine | 8009 | threat_engine_risk | 1 |

### Build Priority & Dependencies
```
P0 (build first):   Tier 2 log_collector + Tier 3 external_collector
                    (everything else depends on collector output)

P1 (next):          engine_container (feeds supplychain with SBOM)

P2 (next):          engine_network + engine_supplychain (parallel)

P3 (last):          engine_api + engine_risk (parallel, risk depends on all)

P4 (hardening):     Observability stack (Prometheus, Jaeger, AlertManager)
```

### Key Design Principles
1. **3-tier collection** — CSP config (boto3), log streams (S3/CW), external APIs (REST) are fundamentally different and handled by separate services.
2. **Engines never collect** — Engines only read from collector output tables. No boto3, no S3, no external API calls inside engines.
3. **4-stage per-engine processing** — ETL (→ `_input_transformed`) → Evaluate (→ `_findings`) → Report (→ `_report`) → Coordinate. Clean separation of data prep from rule evaluation.
4. **Cross-source ETL** — Each engine's ETL reads from multiple collector tables (Tier 1 + 2 + 3) and other engine tables to build its `_input_transformed` view. Different engines can join the same raw data differently.
5. **DB-driven rules** — All rules in {engine}_rules tables. Toggle via is_active flag without redeploy.
6. **Shared utilities** — rule_evaluator.py, rule_loader.py, finding_writer.py in shared/common/.
7. **Layered pipeline** — Tier 1 discoveries → Layer 0.5 (Tier 2 + 3 collectors) → Layer 1→2→3→4 engines. Dependency order guaranteed.
8. **Cache-first for external** — vuln_cache, package_metadata, threat_intel_ioc refreshed on schedule. Engines read cache, never hit external APIs directly.
9. **Separate pods, shared data** — Each service is its own K8s deployment with its own DB. Shared database instance (RDS) holds separate schemas per service.
10. **AI agents for everything** — Implementation, testing, deployment, monitoring all agent-driven.

### Anti-Duplication Model (3-Tier Collect Once, Read Many)
```
┌──────────────────────────────────────────────────────────────────────┐
│                    COLLECTION LAYER (Layer 0.5)                       │
│                                                                      │
│  Tier 1: discoveries    Tier 2: log_collector   Tier 3: external     │
│  → discovery_findings   → log_events            → registry_images    │
│    (CSP config)         → event_aggregations    → vuln_cache         │
│                         → cloudtrail_events     → package_metadata   │
│                                                  → threat_intel_ioc   │
│                                                  → external_findings  │
└───────────┬────────────────────┬────────────────────────┬────────────┘
            │                    │                        │
            ▼                    ▼                        ▼
┌──────────────────────────────────────────────────────────────────────┐
│                    ENGINE LAYER (reads only, never collects)          │
│                                                                      │
│  container:     Tier 1 (ecr, eks, ecs) + Tier 3 (registry, vuln)    │
│  network:       Tier 1 (sg, vpc, nacl) + Tier 2 (flow) + Tier 3 (ioc)│
│  supplychain:   Tier 1 (codecommit, λ) + Tier 3 (github, vuln, pkg) │
│  api:           Tier 1 (apigw, alb, waf) + Tier 2 (access logs)    │
│  risk:          ALL engine findings + Tier 3 (EPSS)                  │
└──────────────────────────────────────────────────────────────────────┘
```

### Shared Resource_Types (Multi-Consumer)

| Data Source | Collected By | Consumed By |
|-------------|-------------|-------------|
| `aws.wafv2.web_acl` | Tier 1 (discoveries) | engine_network, engine_api |
| `aws.elbv2.listener` | Tier 1 (discoveries) | engine_network, engine_api |
| `aws.ecr.image` | Tier 1 (discoveries) | engine_container, engine_supplychain |
| `aws.ecs.task_definition` | Tier 1 (discoveries) | engine_container, engine_supplychain |
| `aws.logs.log_group` | Tier 1 (discoveries) | engine_network, engine_api |
| VPC flow logs (parsed) | Tier 2 (log_collector) | engine_network |
| API access logs (aggregated) | Tier 2 (log_collector) | engine_api |
| CloudTrail events | Tier 2 (log_collector) | engine_network, threat engine |
| registry_images + Trivy results | Tier 3 (external_collector) | engine_container, engine_supplychain |
| vuln_cache (CVE/EPSS/KEV) | Tier 3 (external_collector) | engine_container, engine_supplychain, engine_risk |
| package_metadata | Tier 3 (external_collector) | engine_supplychain |
| threat_intel_ioc | Tier 3 (external_collector) | engine_network, threat engine |
| container_sbom (cross-engine) | engine_container | engine_supplychain |
| ALL `*_findings` tables | respective engines | engine_risk |

---

## Reference Documents
- Architecture & schemas: `.claude/documentation/NEW_ENGINES_ARCHITECTURE.md`
- Data sources (Category A + B): `.claude/documentation/NEW_ENGINE_DATA_SOURCES.md`
- ETL rules & implementation: `.claude/documentation/NEW_ENGINES_ETL_RULES.md`
- Database schema reference: `.claude/documentation/DATABASE_SCHEMA.md`
- API reference: `.claude/documentation/API_REFERENCE_ALL_ENGINES.md`

