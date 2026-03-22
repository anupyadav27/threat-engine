# New Engine Data Sources — Collection Specification

**Approach:** Follow the same pattern as existing CSP discovery.
All data collected first → stored in `discovery_findings` (or dedicated log tables for high-volume streams).
Engines read from `discovery_findings` as their primary input.

---

## How the Existing Pattern Works (reference)

```
rule_discoveries table (check DB)
  └── discoveries_data JSONB
        ├── boto3_client_name    → which SDK client to create
        ├── arn_identifier       → how to build the resource ARN
        ├── arn_identifier_independent_methods  → primary list API calls
        └── arn_identifier_dependent_methods    → detail calls (need ID from primary)

discoveries engine
  1. reads rule_discoveries WHERE is_active = TRUE
  2. creates boto3/SDK client
  3. calls independent methods → resource list
  4. calls dependent methods per resource → detail
  5. emits fields → stores to discovery_findings
        resource_type     (aws.ecr.image, aws.eks.pod, etc.)
        emitted_fields    JSONB  ← all collected fields
        raw_response      JSONB  ← full API response
        resource_uid      (ARN or unique key)
        config_hash       (SHA256 for drift detection)
```

---

## Source Classification

```
Category A — Standard pattern (new rule_discoveries rows)
  → boto3/SDK API call → discovery_findings
  → add to existing discoveries engine, no new code except rule DB rows

Category B — New collection pipeline needed
  → log files / file downloads / streaming data
  → too voluminous or wrong shape for discovery_findings
  → separate lightweight collector → dedicated table
```

---

## Category A: Standard Discovery Sources
### (Add as new rows in `rule_discoveries` table)

---

### A1 — Container Registry Images

**Why needed:** Registries already discovered. Need the *image list* per registry — tags, digests, push dates, sizes — so `engine_container` knows what to scan.

| Field | Value |
|-------|-------|
| **resource_type** | `aws.ecr.image` |
| **boto3_client_name** | `ecr` |
| **provider** | `aws` |

**independent_methods (primary list):**
```yaml
discovery_id: aws.ecr.describe_repositories
calls:
  - action: describe_repositories
    save_as: repos
    params:
      maxResults: 100
emit:
  items_for: "{{ repos.repositories }}"
  resource_type: aws.ecr.repository
  item:
    repository_name:    "{{ item.repositoryName }}"
    repository_arn:     "{{ item.repositoryArn }}"
    registry_id:        "{{ item.registryId }}"
    repository_uri:     "{{ item.repositoryUri }}"
    image_tag_mutability: "{{ item.imageTagMutability }}"
    image_scan_on_push: "{{ item.imageScanningConfiguration.scanOnPush }}"
    encryption_type:    "{{ item.encryptionConfiguration.encryptionType }}"
    created_at:         "{{ item.createdAt }}"
```

**dependent_methods (per repo):**
```yaml
discovery_id: aws.ecr.describe_images
calls:
  - action: describe_images
    save_as: images
    params:
      repositoryName: "{{ repository_name }}"
      filter:
        tagStatus: ANY
emit:
  items_for: "{{ images.imageDetails }}"
  resource_type: aws.ecr.image
  item:
    repository_name:    "{{ repository_name }}"
    image_digest:       "{{ item.imageDigest }}"
    image_tags:         "{{ item.imageTags }}"
    image_size_bytes:   "{{ item.imageSizeInBytes }}"
    pushed_at:          "{{ item.imagePushedAt }}"
    last_pulled_at:     "{{ item.lastRecordedPullTime }}"
    scan_status:        "{{ item.imageScanStatus.status }}"
    artifact_media_type: "{{ item.artifactMediaType }}"
```

**arn_identifier:** `arn:aws:ecr:{region}:{account}:repository/{repository_name}`

**Azure equivalent:** `azure.acr.repository` via Azure Container Registry REST API
**GCP equivalent:** `gcp.artifactregistry.repository` via Artifact Registry API

---

### A2 — Kubernetes Workloads (Pods, Deployments, DaemonSets)

**Why needed:** EKS clusters already discovered. Need the *running workloads* to know which container images are live, and their security contexts.

| Field | Value |
|-------|-------|
| **resource_type** | `aws.eks.pod`, `aws.eks.deployment`, `aws.eks.daemonset` |
| **client** | K8s Python client (not boto3 — uses cluster endpoint + IRSA token) |
| **provider** | `aws` |

**Collection approach:** For each EKS cluster found in `discovery_findings WHERE resource_type='aws.eks.cluster'`, use the cluster endpoint + `eks:get-token` (IRSA) to call the K8s API.

```yaml
discovery_id: aws.eks.list_pods
client_type: kubernetes          # flag: use k8s client, not boto3
calls:
  - action: list_pod_for_all_namespaces
    save_as: pods
emit:
  items_for: "{{ pods.items }}"
  resource_type: aws.eks.pod
  item:
    name:               "{{ item.metadata.name }}"
    namespace:          "{{ item.metadata.namespace }}"
    cluster_name:       "{{ cluster_name }}"            # injected from parent
    node_name:          "{{ item.spec.nodeName }}"
    phase:              "{{ item.status.phase }}"
    service_account:    "{{ item.spec.serviceAccountName }}"
    containers:         "{{ item.spec.containers }}"     # list: name, image, ports, env
    init_containers:    "{{ item.spec.initContainers }}"
    security_context:   "{{ item.spec.securityContext }}"  # runAsUser, fsGroup
    host_network:       "{{ item.spec.hostNetwork }}"
    host_pid:           "{{ item.spec.hostPID }}"
    volumes:            "{{ item.spec.volumes }}"
    labels:             "{{ item.metadata.labels }}"
    annotations:        "{{ item.metadata.annotations }}"
    created_at:         "{{ item.metadata.creationTimestamp }}"
```

**Container-level security fields to emit (per container in pod):**
```
name, image (full image:tag), imagePullPolicy,
securityContext.privileged, securityContext.runAsRoot,
securityContext.allowPrivilegeEscalation, securityContext.readOnlyRootFilesystem,
securityContext.capabilities.add[], resources.limits, resources.requests,
env[] (name only — not values, values may be secrets), volumeMounts[]
```

**resource_uid:** `{cluster_name}/{namespace}/{pod_name}`

---

### A3 — ECS Task Definitions & Running Tasks

**Why needed:** Image references in ECS task definitions are not extracted in current discoveries — only the cluster/service level. Need image names + security config to feed container engine.

| Field | Value |
|-------|-------|
| **resource_type** | `aws.ecs.task_definition`, `aws.ecs.task` |
| **boto3_client_name** | `ecs` |

```yaml
discovery_id: aws.ecs.describe_task_definition
calls:
  - action: list_task_definitions
    save_as: task_defs
    params:
      status: ACTIVE
      maxResults: 100
  - action: describe_task_definition
    save_as: detail
    params:
      taskDefinition: "{{ item }}"   # from task_defs.taskDefinitionArns
    for_each: task_defs.taskDefinitionArns
emit:
  resource_type: aws.ecs.task_definition
  item:
    task_definition_arn:  "{{ detail.taskDefinition.taskDefinitionArn }}"
    family:               "{{ detail.taskDefinition.family }}"
    revision:             "{{ detail.taskDefinition.revision }}"
    network_mode:         "{{ detail.taskDefinition.networkMode }}"
    requires_compatibilities: "{{ detail.taskDefinition.requiresCompatibilities }}"
    cpu:                  "{{ detail.taskDefinition.cpu }}"
    memory:               "{{ detail.taskDefinition.memory }}"
    execution_role_arn:   "{{ detail.taskDefinition.executionRoleArn }}"
    task_role_arn:        "{{ detail.taskDefinition.taskRoleArn }}"
    container_definitions: "{{ detail.taskDefinition.containerDefinitions }}"
      # Per container: name, image, cpu, memory, portMappings,
      #                environment, secrets, logConfiguration,
      #                privileged, readonlyRootFilesystem, user
    volumes:              "{{ detail.taskDefinition.volumes }}"
```

---

### A4 — Lambda Function Code Locations

**Why needed:** Lambda functions discovered but `Code.Location` (S3 pre-signed URL for ZIP) not stored. Needed by supplychain engine to download and scan package manifests.

| Field | Value |
|-------|-------|
| **resource_type** | `aws.lambda.function_code` |
| **boto3_client_name** | `lambda` |
| **extends** | Existing `aws.lambda.function` discovery |

```yaml
discovery_id: aws.lambda.get_function_code
calls:
  - action: get_function
    save_as: func
    params:
      FunctionName: "{{ function_name }}"   # from existing aws.lambda.function
    for_each: existing_lambda_functions
emit:
  resource_type: aws.lambda.function_code
  item:
    function_name:      "{{ func.Configuration.FunctionName }}"
    function_arn:       "{{ func.Configuration.FunctionArn }}"
    runtime:            "{{ func.Configuration.Runtime }}"
    handler:            "{{ func.Configuration.Handler }}"
    code_size:          "{{ func.Configuration.CodeSize }}"
    code_location:      "{{ func.Code.Location }}"    # S3 pre-signed URL (1hr TTL)
    code_repository_type: "{{ func.Code.RepositoryType }}"
    layers:             "{{ func.Configuration.Layers }}"
    environment_keys:   "{{ func.Configuration.Environment.Variables | keys }}"
```

**Note on code_location:** Pre-signed URL expires in 1 hour. `engine_supplychain` must download within that window. Alternatively store the S3 bucket/key from the function's deployment source directly.

---

### A5 — API Gateway Detailed Configuration

**Why needed:** Current discoveries collect API list. `engine_api` needs stages, methods, authorizers, usage plans — the detailed config per endpoint.

| Field | Value |
|-------|-------|
| **resource_type** | `aws.apigateway.stage`, `aws.apigateway.method`, `aws.apigateway.authorizer` |
| **boto3_client_name** | `apigateway` |

**independent: get stages per API**
```yaml
discovery_id: aws.apigateway.get_stages
calls:
  - action: get_stages
    save_as: stages
    params:
      restApiId: "{{ rest_api_id }}"   # from existing aws.apigateway.restapi
emit:
  items_for: "{{ stages.item }}"
  resource_type: aws.apigateway.stage
  item:
    rest_api_id:              "{{ rest_api_id }}"
    stage_name:               "{{ item.stageName }}"
    deployment_id:            "{{ item.deploymentId }}"
    description:              "{{ item.description }}"
    cache_cluster_enabled:    "{{ item.cacheClusterEnabled }}"
    cache_cluster_size:       "{{ item.cacheClusterSize }}"
    xray_tracing_enabled:     "{{ item.tracingEnabled }}"
    logging_level:            "{{ item.defaultRouteSettings.loggingLevel }}"
    data_trace_enabled:       "{{ item.defaultRouteSettings.dataTraceEnabled }}"
    throttling_burst_limit:   "{{ item.defaultRouteSettings.throttlingBurstLimit }}"
    throttling_rate_limit:    "{{ item.defaultRouteSettings.throttlingRateLimit }}"
    access_log_arn:           "{{ item.accessLogSettings.destinationArn }}"
    waf_arn:                  "{{ item.webAclArn }}"
    client_cert_id:           "{{ item.clientCertificateId }}"
    method_settings:          "{{ item.methodSettings }}"
    variables:                "{{ item.variables }}"
```

**dependent: get authorizers per API**
```yaml
discovery_id: aws.apigateway.get_authorizers
calls:
  - action: get_authorizers
    save_as: authz
    params:
      restApiId: "{{ rest_api_id }}"
emit:
  items_for: "{{ authz.items }}"
  resource_type: aws.apigateway.authorizer
  item:
    rest_api_id:    "{{ rest_api_id }}"
    authorizer_id:  "{{ item.id }}"
    name:           "{{ item.name }}"
    type:           "{{ item.type }}"          # TOKEN | REQUEST | COGNITO_USER_POOLS
    provider_arns:  "{{ item.providerARNs }}"
    auth_type:      "{{ item.authType }}"
    ttl_seconds:    "{{ item.authorizerResultTtlInSeconds }}"
```

**Same pattern for APIGateway v2 (HTTP/WebSocket):**
- `apigatewayv2` client
- `get_apis` → `get_stages` → `get_routes` → `get_authorizers`
- resource_types: `aws.apigatewayv2.api`, `aws.apigatewayv2.stage`, `aws.apigatewayv2.route`

---

### A6 — ALB Listeners & Rules

**Why needed:** ALBs discovered at the load balancer level. Need listener-level detail (TLS policy, certificates, routing rules) for `engine_api` and `engine_network`.

| Field | Value |
|-------|-------|
| **resource_type** | `aws.elbv2.listener`, `aws.elbv2.listener_rule` |
| **boto3_client_name** | `elbv2` |

```yaml
discovery_id: aws.elbv2.describe_listeners
calls:
  - action: describe_listeners
    save_as: listeners
    params:
      LoadBalancerArn: "{{ load_balancer_arn }}"
emit:
  items_for: "{{ listeners.Listeners }}"
  resource_type: aws.elbv2.listener
  item:
    listener_arn:             "{{ item.ListenerArn }}"
    load_balancer_arn:        "{{ item.LoadBalancerArn }}"
    port:                     "{{ item.Port }}"
    protocol:                 "{{ item.Protocol }}"      # HTTP | HTTPS | TCP | TLS
    ssl_policy:               "{{ item.SslPolicy }}"    # ELBSecurityPolicy-TLS13-...
    certificates:             "{{ item.Certificates }}"
    default_actions:          "{{ item.DefaultActions }}"
    alpn_policy:              "{{ item.AlpnPolicy }}"

# dependent: rules per listener
discovery_id: aws.elbv2.describe_rules
calls:
  - action: describe_rules
    save_as: rules
    params:
      ListenerArn: "{{ listener_arn }}"
emit:
  items_for: "{{ rules.Rules }}"
  resource_type: aws.elbv2.listener_rule
  item:
    rule_arn:       "{{ item.RuleArn }}"
    listener_arn:   "{{ listener_arn }}"
    priority:       "{{ item.Priority }}"
    conditions:     "{{ item.Conditions }}"
    actions:        "{{ item.Actions }}"
    is_default:     "{{ item.IsDefault }}"
```

---

### A7 — WAF Web ACLs & Associations

**Why needed:** WAF existence checked but rules and resource associations not collected. Needed by `engine_api` (is API GW protected by WAF?) and `engine_network`.

| Field | Value |
|-------|-------|
| **resource_type** | `aws.wafv2.web_acl`, `aws.wafv2.web_acl_association` |
| **boto3_client_name** | `wafv2` |

```yaml
discovery_id: aws.wafv2.list_web_acls
calls:
  - action: list_web_acls
    save_as: acls
    params:
      Scope: REGIONAL    # also run with: CLOUDFRONT (us-east-1 only)
      Limit: 100
  - action: get_web_acl
    save_as: detail
    params:
      Name: "{{ item.Name }}"
      Scope: REGIONAL
      Id: "{{ item.Id }}"
    for_each: acls.WebACLs
  - action: list_resources_for_web_acl
    save_as: associations
    params:
      WebACLArn: "{{ item.ARN }}"
    for_each: acls.WebACLs
emit:
  resource_type: aws.wafv2.web_acl
  item:
    web_acl_id:           "{{ detail.WebACL.Id }}"
    web_acl_arn:          "{{ detail.WebACL.ARN }}"
    name:                 "{{ detail.WebACL.Name }}"
    description:          "{{ detail.WebACL.Description }}"
    default_action:       "{{ detail.WebACL.DefaultAction }}"   # Allow | Block
    rules:                "{{ detail.WebACL.Rules }}"           # rule list with actions
    visibility_config:    "{{ detail.WebACL.VisibilityConfig }}"
    capacity:             "{{ detail.WebACL.Capacity }}"
    associated_resources: "{{ associations.ResourceArns }}"     # ALB/API GW ARNs
    managed_rule_groups:  "{{ detail.WebACL.Rules | select('ManagedRuleGroupStatement') }}"
```

---

### A8 — VPC Flow Log Configuration

**Why needed:** Know whether flow logging is enabled per VPC, where logs go (S3 or CloudWatch), and the log format. This feeds both `engine_network` (posture: is logging enabled?) and the Category B flow log collector (where to look for logs).

| Field | Value |
|-------|-------|
| **resource_type** | `aws.ec2.flow_log` |
| **boto3_client_name** | `ec2` |

```yaml
discovery_id: aws.ec2.describe_flow_logs
calls:
  - action: describe_flow_logs
    save_as: flow_logs
    params:
      MaxResults: 100
emit:
  items_for: "{{ flow_logs.FlowLogs }}"
  resource_type: aws.ec2.flow_log
  item:
    flow_log_id:          "{{ item.FlowLogId }}"
    resource_id:          "{{ item.ResourceId }}"       # vpc-xxx or subnet-xxx
    resource_type:        "{{ item.ResourceType }}"     # VPC | Subnet | NetworkInterface
    traffic_type:         "{{ item.TrafficType }}"      # ALL | ACCEPT | REJECT
    log_destination_type: "{{ item.LogDestinationType }}" # s3 | cloud-watch-logs
    log_destination:      "{{ item.LogDestination }}"   # S3 ARN or CW log group ARN
    log_format:           "{{ item.LogFormat }}"        # field list
    deliver_logs_status:  "{{ item.DeliverLogsStatus }}" # SUCCESS | FAILED
    log_group_name:       "{{ item.LogGroupName }}"
    deliver_logs_permission_arn: "{{ item.DeliverLogsPermissionArn }}"
    creation_time:        "{{ item.CreationTime }}"
```

---

### A9 — CodeCommit Repositories & File Manifests

**Why needed:** Code repositories are a primary source for package manifests (requirements.txt, package.json, go.mod, etc.). CodeCommit is the AWS-native VCS — covered by boto3 pattern.

| Field | Value |
|-------|-------|
| **resource_type** | `aws.codecommit.repository`, `aws.codecommit.manifest_file` |
| **boto3_client_name** | `codecommit` |

```yaml
# List all repos
discovery_id: aws.codecommit.list_repositories
calls:
  - action: list_repositories
    save_as: repos
emit:
  items_for: "{{ repos.repositories }}"
  resource_type: aws.codecommit.repository
  item:
    repository_id:    "{{ item.repositoryId }}"
    repository_name:  "{{ item.repositoryName }}"
    clone_url_http:   "{{ item.cloneUrlHttp }}"
    default_branch:   "{{ item.defaultBranch }}"
    last_modified:    "{{ item.lastModifiedDate }}"

# Dependent: get known manifest file paths per repo
discovery_id: aws.codecommit.get_manifest_files
calls:
  - action: get_file
    save_as: file
    params:
      repositoryName: "{{ repository_name }}"
      filePath: "{{ manifest_path }}"
      commitSpecifier: "HEAD"
    for_each:
      manifest_paths:    # check for each of these standard manifest filenames
        - package.json
        - requirements.txt
        - go.mod
        - pom.xml
        - Gemfile
        - Cargo.toml
        - composer.json
        - build.gradle
        - pyproject.toml
        - packages.config
    on_error: continue   # skip if file doesn't exist in this repo
emit:
  resource_type: aws.codecommit.manifest_file
  item:
    repository_name:  "{{ repository_name }}"
    file_path:        "{{ manifest_path }}"
    file_content:     "{{ file.fileContent | base64decode }}"  # decoded content
    commit_id:        "{{ file.commitId }}"
    file_size:        "{{ file.fileSize }}"
```

---

### A10 — CodeArtifact Package Repositories

**Why needed:** Internal package repositories — needed to detect dependency confusion (internal package name also exists on public npm/PyPI) and to audit internal package versions.

| Field | Value |
|-------|-------|
| **resource_type** | `aws.codeartifact.repository`, `aws.codeartifact.package` |
| **boto3_client_name** | `codeartifact` |

```yaml
discovery_id: aws.codeartifact.list_repositories
calls:
  - action: list_repositories
    save_as: repos
emit:
  items_for: "{{ repos.repositories }}"
  resource_type: aws.codeartifact.repository
  item:
    domain_name:       "{{ item.domainName }}"
    repository_name:   "{{ item.name }}"
    arn:               "{{ item.arn }}"
    format:            "{{ item.format }}"    # npm | pypi | maven | nuget
    upstream_repos:    "{{ item.upstreams }}" # including public npm/pypi upstreams
    external_connections: "{{ item.externalConnections }}"

# Dependent: list packages per repo
discovery_id: aws.codeartifact.list_packages
calls:
  - action: list_packages
    save_as: packages
    params:
      domain: "{{ domain_name }}"
      repository: "{{ repository_name }}"
      maxResults: 100
emit:
  items_for: "{{ packages.packages }}"
  resource_type: aws.codeartifact.package
  item:
    domain_name:       "{{ domain_name }}"
    repository_name:   "{{ repository_name }}"
    package_name:      "{{ item.package }}"
    package_format:    "{{ item.format }}"
    namespace:         "{{ item.namespace }}"
    latest_version:    "{{ item.latestVersion }}"
    origin_type:       "{{ item.originConfiguration.restrictions.publish }}"
```

---

### A11 — AppSync GraphQL APIs (Detailed)

**Why needed:** AppSync discovery exists but auth config and logging details not extracted. `engine_api` needs these for OWASP API2 (broken auth) and API10 (logging) checks.

| Field | Value |
|-------|-------|
| **resource_type** | `aws.appsync.graphql_api` (extend existing) |
| **boto3_client_name** | `appsync` |

```yaml
discovery_id: aws.appsync.get_graphql_api_detail
calls:
  - action: list_graphql_apis
    save_as: apis
  - action: get_graphql_api
    save_as: detail
    params:
      apiId: "{{ item.apiId }}"
    for_each: apis.graphqlApis
emit:
  resource_type: aws.appsync.graphql_api
  item:
    api_id:               "{{ detail.graphqlApi.apiId }}"
    name:                 "{{ detail.graphqlApi.name }}"
    api_type:             "{{ detail.graphqlApi.apiType }}"
    authentication_type:  "{{ detail.graphqlApi.authenticationType }}"  # API_KEY | AWS_IAM | COGNITO_USER_POOLS | OPENID_CONNECT
    additional_auth_providers: "{{ detail.graphqlApi.additionalAuthenticationProviders }}"
    log_config:           "{{ detail.graphqlApi.logConfig }}"      # cloudWatchLogsRoleArn, fieldLogLevel
    xray_enabled:         "{{ detail.graphqlApi.xrayEnabled }}"
    waf_web_acl_arn:      "{{ detail.graphqlApi.wafWebAclArn }}"
    lambda_authorizer:    "{{ detail.graphqlApi.lambdaAuthorizerConfig }}"
    visibility:           "{{ detail.graphqlApi.visibility }}"     # GLOBAL | PRIVATE
    uris:                 "{{ detail.graphqlApi.uris }}"
```

---

### A12 — CloudWatch Log Groups (API & Network Logs)

**Why needed:** Know which log groups exist for API access logs and VPC flow logs so `engine_api` and `engine_network` can query them for runtime analysis.

| Field | Value |
|-------|-------|
| **resource_type** | `aws.logs.log_group` |
| **boto3_client_name** | `logs` |

```yaml
discovery_id: aws.logs.describe_log_groups
calls:
  - action: describe_log_groups
    save_as: groups
    params:
      limit: 50
emit:
  items_for: "{{ groups.logGroups }}"
  resource_type: aws.logs.log_group
  item:
    log_group_name:       "{{ item.logGroupName }}"
    log_group_arn:        "{{ item.arn }}"
    retention_in_days:    "{{ item.retentionInDays }}"
    stored_bytes:         "{{ item.storedBytes }}"
    kms_key_id:           "{{ item.kmsKeyId }}"
    creation_time:        "{{ item.creationTime }}"
    metric_filter_count:  "{{ item.metricFilterCount }}"
    # Classify by naming pattern:
    # /aws/apigateway/*   → API access log
    # /aws/vpc/flowlogs/* → VPC flow log
    # /aws/eks/*          → K8s control plane log
```

---

## Category B: New Pipeline Sources
### (Cannot follow boto3→discovery_findings pattern)

---

### B1 — VPC Flow Log Records

**Why:** Log files, not API responses. Volume is too high for `discovery_findings`. Need streaming parse → time-windowed aggregation.

**Source:** S3 bucket (from `aws.ec2.flow_log.log_destination` in discovery_findings)
**Format:** Space-separated text or Parquet, fields: version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status

**Collection Mechanism:**
```
Trigger:   S3 event notification → SQS → flow_log_collector worker
           OR scheduled: query S3 for new objects every 5 minutes

Per file:
  1. Download log file from S3 (boto3 s3.get_object)
  2. Decompress (.gz)
  3. Parse each line → structured record
  4. Aggregate: group by (src_ip, dst_ip, dst_port, protocol) per 5-min window
  5. Resolve IPs → resource_ids (join against discovery_findings.emitted_fields)
  6. Store aggregated records

Storage: network_events table (NOT discovery_findings — volume too high)
```

**New table: `network_events`** (defined in engine_network schema)

---

### B2 — Container Image Layer Content (CVE Scanning)

**Why:** CVE scanning requires pulling actual image layers and running a scanner binary (Trivy). Cannot be represented as a boto3 API call or stored as a single JSON row.

**Source:** Container registries (ECR/GCR/ACR/Docker Hub)
**Trigger:** New image found in `discovery_findings WHERE resource_type = 'aws.ecr.image'`

**Collection Mechanism:**
```
engine_container processing (not discoveries):
  1. Read aws.ecr.image records from discovery_findings
  2. Get registry credentials: aws ecr get-login-password | boto3.ecr.get_authorization_token
  3. Pull image manifest via registry HTTP API (no image download needed for manifest)
  4. Run Trivy scan:
       Option A: trivy image --format json {image_uri}  (requires Docker daemon)
       Option B: trivy image --input {layer_tar} --format json (offline, no daemon)
       Option C: trivy fs --format json {extracted_layer_path}  (extract layers first)
  5. Parse Trivy output → CVE list per package
  6. Store to container_findings, container_sbom

Storage: container_findings, container_sbom (engine_container schema)
```

**Key design decision:** Run Trivy as a subprocess inside engine_container pod. The Trivy DB (~250MB) is bundled in the Docker image and refreshed daily via an init container. No separate scanning infrastructure needed.

---

### B3 — Lambda Function Package Content (Dependency Manifests)

**Why:** Lambda code is a ZIP file in S3. Need to download it, extract it, and find package manifest files inside. Not a single API call result.

**Source:** `aws.lambda.function_code.code_location` in discovery_findings
**Trigger:** engine_supplychain scan trigger, reads from discovery_findings

**Collection Mechanism:**
```
engine_supplychain processing:
  1. Read aws.lambda.function_code from discovery_findings
  2. Download ZIP from code_location (pre-signed S3 URL, valid 1hr)
     OR use: s3.get_object(Bucket=bucket, Key=key) if deployment from S3
  3. Extract ZIP in memory (zipfile module, no disk write needed for <50MB)
  4. Scan for manifest files:
       package.json, package-lock.json, yarn.lock   → Node.js
       requirements.txt, Pipfile, pyproject.toml    → Python
       go.mod, go.sum                                → Go
       pom.xml, build.gradle                         → Java
  5. Parse each manifest → dependency list
  6. Store to sbom_manifests, sbom_components

Storage: sbom_manifests, sbom_components (engine_supplychain schema)
Note: code_location URL expires in 1 hour — engine_supplychain must process promptly
      after discovery completes, or re-fetch via get_function API
```

---

### B4 — GitHub / GitLab Repository Manifests

**Why:** Many teams use GitHub/GitLab rather than CodeCommit. These require REST API calls with OAuth tokens — not boto3. Credentials stored in Secrets Manager.

**Source:** GitHub REST API / GitLab REST API
**Credentials:** GitHub PAT or GitHub App token in Secrets Manager (`threat-engine/github-token`)

**Collection Mechanism:**
```
New collector: repo_manifest_collector
  (runs as part of engine_supplychain, or as a new discoveries sub-collector)

  1. Read GitHub org/repos from Secrets Manager config OR
     read from existing secops scan results (secops already scans repos)
  2. For each repo:
     GET /repos/{owner}/{repo}/contents/{manifest_path}
       ?ref=HEAD (or default branch)
     Headers: Authorization: Bearer {token}
  3. If file exists: base64 decode content → raw manifest text
  4. Store to discovery_findings:
       resource_type: github.repository.manifest_file
       emitted_fields: {
         repo_full_name, file_path, file_content, sha, size,
         html_url, default_branch, languages
       }
  5. OR: if secops already has repo list + manifest content,
     engine_supplychain reads directly from secops_findings

Storage: discovery_findings (resource_type = github.repository.manifest_file)
         OR reads from secops_findings if secops is already doing this
```

**Integration with secops engine:**
- `engine_secops` already scans repositories for IaC misconfigurations and secrets
- Extend secops to also emit `manifest_file` records to discovery_findings
- This avoids a separate repo connection from supplychain engine
- **Preferred approach:** secops engine adds manifest file collection, engine_supplychain reads from discovery_findings

---

### B5 — API Gateway Access Logs (CloudWatch)

**Why:** Access logs need time-range queries against CloudWatch Logs. Too voluminous for discovery_findings. Used by `engine_api` for runtime analysis.

**Source:** CloudWatch Logs (log group ARN from `aws.apigateway.stage.access_log_arn`)
**Trigger:** Scheduled (daily summary) or on-demand during scan

**Collection Mechanism:**
```
engine_api runtime analysis:
  1. Read aws.apigateway.stage from discovery_findings
     → get access_log_arn (CloudWatch log group)
  2. Query CloudWatch Logs (last 24h window):
     logs.filter_log_events(
       logGroupName=log_group,
       startTime=yesterday_ms,
       endTime=now_ms,
       limit=10000
     )
  3. Parse log format (JSON or CLF depending on stage config)
  4. Aggregate: top endpoints by call count, error rate, latency p99
  5. Store summary to api_access_summary table
     (full logs NOT stored — only aggregated metrics)

Storage: api_access_summary (engine_api schema) — NOT discovery_findings
```

---

## Complete Source Inventory

### Category A — What to Add to `rule_discoveries`

| # | resource_type | boto3_client | Independent Methods | Dependent Methods | Engine(s) |
|---|--------------|-------------|--------------------|--------------------|-----------|
| A1 | `aws.ecr.repository` | `ecr` | `describe_repositories` | — | container |
| A1 | `aws.ecr.image` | `ecr` | — | `describe_images` (per repo) | container |
| A2 | `aws.eks.pod` | k8s client | `list_pod_for_all_namespaces` | — | container |
| A2 | `aws.eks.deployment` | k8s client | `list_deployment_for_all_namespaces` | — | container |
| A3 | `aws.ecs.task_definition` | `ecs` | `list_task_definitions` | `describe_task_definition` | container, supplychain |
| A4 | `aws.lambda.function_code` | `lambda` | — | `get_function` (per function) | supplychain |
| A5 | `aws.apigateway.stage` | `apigateway` | — | `get_stages` (per API) | api |
| A5 | `aws.apigateway.authorizer` | `apigateway` | — | `get_authorizers` (per API) | api |
| A5 | `aws.apigatewayv2.route` | `apigatewayv2` | — | `get_routes` (per API) | api |
| A6 | `aws.elbv2.listener` | `elbv2` | — | `describe_listeners` (per ALB) | api, network |
| A6 | `aws.elbv2.listener_rule` | `elbv2` | — | `describe_rules` (per listener) | api, network |
| A7 | `aws.wafv2.web_acl` | `wafv2` | `list_web_acls` | `get_web_acl`, `list_resources_for_web_acl` | api, network |
| A8 | `aws.ec2.flow_log` | `ec2` | `describe_flow_logs` | — | network |
| A9 | `aws.codecommit.repository` | `codecommit` | `list_repositories` | — | supplychain |
| A9 | `aws.codecommit.manifest_file` | `codecommit` | — | `get_file` (per manifest path × repo) | supplychain |
| A10 | `aws.codeartifact.repository` | `codeartifact` | `list_repositories` | — | supplychain |
| A10 | `aws.codeartifact.package` | `codeartifact` | — | `list_packages` (per repo) | supplychain |
| A11 | `aws.appsync.graphql_api` | `appsync` | `list_graphql_apis` | `get_graphql_api` | api |
| A12 | `aws.logs.log_group` | `logs` | `describe_log_groups` | — | api, network |

### Category B — New Pipeline Workers

| # | Source | Mechanism | Trigger | Storage | Engine(s) |
|---|--------|-----------|---------|---------|-----------|
| B1 | VPC Flow Logs | S3 file download → parse → aggregate | S3 event → SQS | `network_events` | network |
| B2 | Container image layers | Trivy scan (subprocess) | On new ecr.image in discovery_findings | `container_findings`, `container_sbom` | container |
| B3 | Lambda ZIP packages | S3 download → unzip in memory → parse | engine_supplychain scan | `sbom_manifests`, `sbom_components` | supplychain |
| B4 | GitHub/GitLab manifests | REST API → secops engine extension | Post-secops or separate collector | `discovery_findings` (github.repository.manifest_file) | supplychain |
| B5 | API access logs | CloudWatch Logs query (last 24h) | engine_api scan | `api_access_summary` | api |

---

## Already Available (No New Collection Needed)

The following resource types are **already in `discovery_findings`** and can be read directly by new engines:

| resource_type | Engine that reads it |
|--------------|---------------------|
| `aws.ec2.security_group` | network (posture) |
| `aws.ec2.vpc` | network |
| `aws.ec2.subnet` | network |
| `aws.ec2.network_acl` | network |
| `aws.ec2.internet_gateway` | network |
| `aws.ec2.nat_gateway` | network |
| `aws.ec2.vpc_peering_connection` | network |
| `aws.ec2.transit_gateway` | network |
| `aws.eks.cluster` | container (as parent for pod collection) |
| `aws.ecr.repository` (basic) | container (A1 extends this) |
| `aws.lambda.function` (basic) | supplychain (A4 extends this) |
| `aws.apigateway.rest_api` | api (A5 extends this) |
| `aws.apigatewayv2.api` | api |
| `aws.elbv2.load_balancer` | api, network |
| `aws.s3.bucket` | supplychain (check for source code buckets) |
| `aws.iam.role`, `aws.iam.policy` | risk (blast radius) |
| All findings from existing engines | risk (reads from all findings tables) |

---

## Next Step: For Each New Engine

With sources defined, each engine's design becomes straightforward:

```
engine_container:
  INPUT:  discovery_findings WHERE resource_type IN
            ('aws.ecr.image', 'aws.eks.pod', 'aws.ecs.task_definition')
  PROCESS: B2 (Trivy scan per image found)
  OUTPUT:  container_findings, container_sbom, k8s_policy_findings

engine_network:
  INPUT:  discovery_findings WHERE resource_type IN
            ('aws.ec2.security_group','aws.ec2.vpc','aws.ec2.flow_log',
             'aws.elbv2.listener','aws.wafv2.web_acl', ...)
  PROCESS: posture rules (immediate) + B1 (flow log streaming)
  OUTPUT:  network_topology, network_findings, network_events, network_anomalies

engine_supplychain:
  INPUT:  discovery_findings WHERE resource_type IN
            ('aws.ecr.image', 'aws.lambda.function_code',
             'aws.codecommit.manifest_file', 'github.repository.manifest_file',
             'aws.codeartifact.package')
          + container_sbom (from engine_container)
  PROCESS: B3 (Lambda ZIP), B4 (GitHub), merge + analyze
  OUTPUT:  sbom_manifests, sbom_components, supplychain_findings

engine_api:
  INPUT:  discovery_findings WHERE resource_type IN
            ('aws.apigateway.stage','aws.apigateway.authorizer',
             'aws.apigatewayv2.route','aws.elbv2.listener',
             'aws.appsync.graphql_api','aws.wafv2.web_acl')
  PROCESS: OWASP API rule evaluation + B5 (access log query)
  OUTPUT:  api_inventory, api_endpoints, api_findings

engine_risk:
  INPUT:  ALL findings tables (threat, iam, datasec, container, network,
          supplychain, api, check, vulnerability)
          + inventory_findings (asset criticality)
          + datasec_findings (data classification, record count estimates)
          + cloud_accounts (tenant industry, region)
  PROCESS: FAIR model computation
  OUTPUT:  risk_scenarios, risk_summary, risk_trends
```
