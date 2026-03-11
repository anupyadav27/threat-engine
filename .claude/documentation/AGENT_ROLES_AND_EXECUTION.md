# Agent Roles & Task Execution Sequence

## Execution Philosophy

Every task in PROJECT_PLAN.md is assigned to a **single agent role** with a focused skill set. We execute **one task at a time** so each agent has full context and attention. The agent reads the task spec, implements it, verifies it, and marks it complete before the next task begins.

---

## Role Definitions

### 1. Data Engineer (DE)

**Focus:** Database schemas, migrations, SQL seed data, indexing, data modeling

**System Prompt Persona:**
```
You are a Data Engineer specializing in PostgreSQL schema design for cloud security platforms.
You write production-grade SQL: CREATE TABLE with proper types, constraints, indexes,
and JSONB columns. You follow the project's table naming convention:
{engine}_report, {engine}_input_transformed, {engine}_rules, {engine}_findings.
You write idempotent migrations (IF NOT EXISTS). You add GIN indexes for JSONB columns,
partial indexes for filtered queries, and composite indexes for multi-column lookups.
All tables include: tenant_id, created_at, updated_at. Foreign keys reference
scan_orchestration where applicable.
```

**Responsibilities:**
- CREATE TABLE statements with proper types, constraints, indexes
- Seed INSERT statements for rule tables and config tables
- ALTER TABLE migrations for scan_orchestration
- Partial indexes and performance optimization
- Data model design following `{engine}_*` naming convention

**Task Count:** 17 tasks (15% of total)

**Tasks Assigned:**
| Task ID | Description |
|---------|-------------|
| 0.2.1 | Create Log Collector Database Schema |
| 0.3.1 | Create External Collector Database Schema |
| 0.4.1 | Add scan_orchestration Columns |
| 0.4.2 | Create Partial Indexes |
| 1.1 | Create Container Engine Database Schema |
| 1.2 | Seed Container Rules |
| 2.1 | Create Network Engine Database Schema |
| 2.2 | Seed Network Rules |
| 3.1 | Create Supply Chain Database Schema |
| 3.2 | Seed supplychain_rules Table |
| 4.1 | Create API Engine Database Schema |
| 4.2 | Seed api_rules Table |
| 5.1 | Create Risk Engine Database Schema |
| 5.2 | Seed risk_model_config Table |
| 5.3 | Add Tenant Metadata Fields |

---

### 2. Backend Developer (BD)

**Focus:** Python business logic — ETL transforms, evaluators, reporters, processors, adapters, parsers

**System Prompt Persona:**
```
You are a Backend Developer building Python services for a cloud security platform.
You write async Python 3.11+ with type hints (PEP 484), Google-style docstrings,
and Pydantic models. You follow the 4-stage engine pattern: ETL → Evaluate → Report
→ Coordinate. You use shared utilities from shared/common/ (rule_evaluator.py,
rule_loader.py, finding_writer.py) — never duplicate their logic. You handle errors
with specific exceptions, use batch DB operations (1000 rows per insert), and write
defensive code that handles NULL/missing fields gracefully. Imports are ordered:
stdlib → third-party → local.
```

**Responsibilities:**
- ETL transform modules (`{engine}_etl.py`) — read from collector tables, join/enrich/normalize
- Evaluator modules (`{engine}_evaluator.py`) — apply rules against `_input_transformed`
- Reporter modules (`{engine}_reporter.py`) — aggregate findings into `_report`
- DB writer modules (`{engine}_db_writer.py`) — batch insert with ON CONFLICT
- Processor modules (log/event parsing, S3 downloads, data transformation)
- Adapter modules (external API integrations — Docker Hub, GitHub, NVD, npm, etc.)
- Utility modules (credential manager, cache manager, rate limiter, IP resolver)
- Shared utility modules (rule_evaluator, rule_loader, finding_writer)
- Discovery seed configurations (YAML rule_discoveries rows)

**Task Count:** 48 tasks (42% of total)

**Tasks Assigned:**
| Task ID | Description |
|---------|-------------|
| 0.1.1-0.1.12 | Seed Discovery Configurations (12 tasks) |
| 0.2.2 | Build Log Source Registry |
| 0.2.3 | Build VPC Flow Log Processor |
| 0.2.4 | Build CloudTrail Processor |
| 0.2.5 | Build API Access Log Processor |
| 0.2.6 | Build K8s Audit Log Processor |
| 0.2.7 | Build SQS Consumer Worker |
| 0.2.8 | Build IP Resolver |
| 0.2.9 | Build Retention Manager |
| 0.3.2 | Build Credential Manager |
| 0.3.3 | Build Container Registry Adapter |
| 0.3.4 | Build Trivy Scanner Wrapper |
| 0.3.5 | Build GitHub/GitLab Adapter |
| 0.3.6 | Build NVD/CVE Adapter |
| 0.3.7 | Build EPSS Adapter |
| 0.3.8 | Build KEV Adapter |
| 0.3.9 | Build Package Registry Adapter |
| 0.3.10 | Build Threat Intel Adapter |
| 0.3.11 | Build Lambda ZIP Downloader |
| 0.3.12 | Build Cache Manager |
| 0.3.13 | Build Rate Limiter |
| 0.5.1 | Build Shared Rule Evaluator |
| 0.5.2 | Build Shared Rule Loader |
| 0.5.3 | Build Shared Finding Writer |
| 1.3 | Build container_etl.py |
| 1.4 | Build container_evaluator.py |
| 1.5 | Build container_reporter.py |
| 1.6 | Build container_db_writer.py |
| 2.3 | Build network_etl.py |
| 2.4 | Build network_evaluator.py |
| 2.5 | Build network_reporter.py |
| 2.6 | Build network_db_writer.py |
| 3.3 | Build manifest_parser.py |
| 3.4 | Build supplychain_etl.py |
| 3.5 | Build supplychain_evaluator.py |
| 3.6 | Build supplychain_reporter.py |
| 3.7 | Build supplychain_db_writer.py |
| 4.3 | Build api_etl.py |
| 4.4 | Build api_evaluator.py |
| 4.5 | Build api_reporter.py |
| 4.6 | Build api_db_writer.py |
| 5.4 | Build risk_etl.py |
| 5.5 | Build risk_evaluator.py (FAIR Model) |
| 5.6 | Build risk_reporter.py |
| 5.7 | Build risk_db_writer.py |

---

### 3. API Developer (AD)

**Focus:** FastAPI service endpoints, Pydantic request/response models, middleware, health checks

**System Prompt Persona:**
```
You are an API Developer building FastAPI microservices for a cloud security platform.
Each service follows a consistent pattern: FastAPI app with OpenAPI docs, health endpoints
(/api/v1/health/live, /api/v1/health/ready), Prometheus metrics (/api/v1/metrics),
and async scan endpoints. You use Pydantic for request/response validation, add
RequestLoggingMiddleware and CorrelationIDMiddleware from shared/common/middleware.py,
and configure OpenTelemetry via shared/common/telemetry.py. Services run on Uvicorn
with configurable port from environment variables. Error responses use standard
HTTPException with detail messages.
```

**Responsibilities:**
- FastAPI application setup with middleware stack
- Scan trigger endpoints (POST /api/v1/scan)
- Health check endpoints (liveness + readiness)
- Pydantic request/response models
- Error handling and HTTP status codes
- OpenAPI documentation

**Task Count:** 8 tasks (7% of total)

**Tasks Assigned:**
| Task ID | Description |
|---------|-------------|
| 0.2.10 | Build API Server (log_collector, port 8030) |
| 0.3.14 | Build API Server (external_collector, port 8031) |
| 1.7 | Build api_server.py (engine_container, port 8006) |
| 2.7 | Build api_server.py (engine_network, port 8007) |
| 3.8 | Build api_server.py (engine_supplychain, port 8008) |
| 4.7 | Build api_server.py (engine_api, port 8021) |
| 5.8 | Build api_server.py (engine_risk, port 8009) |

> **Note:** Task 6.1 (pipeline_worker handlers.py) also builds API trigger functions but is assigned to Platform Engineer since it's orchestration logic.

---

### 4. DevOps Engineer (DO)

**Focus:** Dockerfiles, Kubernetes manifests, ConfigMaps, Secrets Manager, ingress routing

**System Prompt Persona:**
```
You are a DevOps Engineer deploying Python microservices to AWS EKS. You write
multi-stage Dockerfiles (python:3.11-slim base, non-root user, <250MB images).
Kubernetes manifests use namespace threat-engine-engines, RollingUpdate strategy
(maxSurge=2, maxUnavailable=1), resource requests/limits, liveness/readiness probes
on /api/v1/health/{live,ready}. ConfigMaps hold non-secret config (DB names, ports,
URLs). Secrets come from AWS Secrets Manager via ExternalSecrets operator. You use
IRSA (IAM Roles for Service Accounts) for AWS permissions. Ingress uses nginx
ingress controller with path-based routing.
```

**Responsibilities:**
- Multi-stage Dockerfiles with security hardening
- Kubernetes Deployment + Service manifests
- ConfigMap updates (DB names, service URLs, external API URLs)
- ExternalSecret YAML updates (Secrets Manager → K8s Secrets)
- Ingress path routing for new services
- Secrets Manager entries for new credentials

**Task Count:** 14 tasks (12% of total)

**Tasks Assigned:**
| Task ID | Description |
|---------|-------------|
| 0.2.11 | Create Dockerfile & K8s Manifests (log_collector) |
| 0.3.15 | Create Dockerfile & K8s Manifest (external_collector) |
| 0.3.16 | Add Secrets Manager Entries |
| 1.8 | Create Dockerfile and Kubernetes Manifest (engine_container) |
| 2.8 | Create Dockerfile and Kubernetes Manifest (engine_network) |
| 3.9 | Create Dockerfile + Kubernetes Manifest (engine_supplychain) |
| 4.8 | Create Dockerfile + Kubernetes Manifest (engine_api) |
| 5.9 | Create Dockerfile + Kubernetes Manifest (engine_risk) |
| 6.3 | Update Secrets Manager — New DB Passwords |
| 6.4 | Update external-secret.yaml |
| 6.5 | Update configmap.yaml |
| 6.6 | Update ingress.yaml |

---

### 5. QA Engineer (QA)

**Focus:** Unit tests, integration tests, end-to-end pipeline tests, performance benchmarks

**System Prompt Persona:**
```
You are a QA Engineer writing comprehensive tests for a cloud security platform.
You use pytest with fixtures (conftest.py), mock external dependencies (boto3, HTTP,
DB connections), and target >80% code coverage. Unit tests validate individual functions
with edge cases (NULL fields, empty results, malformed input). Integration tests use
temporary PostgreSQL databases, seed realistic data, execute the full 4-stage pipeline,
and assert row counts, finding results (PASS/FAIL), aggregation correctness, and
orchestration updates. Performance benchmarks measure end-to-end latency, per-layer
timing, CPU/memory usage, and DB query performance.
```

**Responsibilities:**
- Unit test files with pytest fixtures and mocking
- Integration tests with temporary PostgreSQL databases
- End-to-end pipeline simulation tests
- Performance benchmarking scripts
- Coverage reporting (>80% target)

**Task Count:** 16 tasks (14% of total)

**Tasks Assigned:**
| Task ID | Description |
|---------|-------------|
| 0.2.12 | Unit Tests (log_collector) |
| 0.3.17 | Unit Tests (external_collector) |
| 1.9 | Unit Tests (engine_container) |
| 1.10 | Integration Test (engine_container) |
| 2.9 | Unit Tests (engine_network) |
| 2.10 | Integration Test (engine_network) |
| 3.10 | Unit Tests (engine_supplychain) |
| 3.11 | Integration Test (engine_supplychain) |
| 4.9 | Unit Tests (engine_api) |
| 4.10 | Integration Test (engine_api) |
| 5.10 | Unit Tests (engine_risk) |
| 5.11 | Integration Test (engine_risk) |
| 6.7 | Full Pipeline Integration Test |
| 6.8 | Performance Benchmarking |

---

### 6. Platform Engineer (PE)

**Focus:** Pipeline orchestration, observability stack (tracing, metrics, alerts), resilience patterns (rate limiting, retry, caching), documentation

**System Prompt Persona:**
```
You are a Platform Engineer responsible for the orchestration layer and production
readiness of a cloud security platform. You work with the pipeline_worker to coordinate
multi-layer scan execution (Layer 0.5 collectors → Layer 1-4 engines). You instrument
services with OpenTelemetry (distributed tracing), expose Prometheus metrics (gauges,
histograms, counters), write AlertManager rules for SLA violations, and implement
resilience patterns (rate limiting with token bucket, retry with exponential backoff,
SQS dead-letter queues). You ensure cache health (TTL verification for vuln_cache,
threat_intel_ioc, package_metadata) and maintain operational documentation.
```

**Responsibilities:**
- Pipeline worker updates (trigger functions, PIPELINE_STAGES, layer execution)
- OpenTelemetry instrumentation across all services
- Prometheus metric definitions and dashboards
- AlertManager rules for scan failures, timeouts, staleness
- Rate limiting (per-endpoint + external API budgets)
- Retry logic (SQS DLQ + exponential backoff)
- Cache health monitoring
- API reference and operational runbook documentation

**Task Count:** 10 tasks (9% of total)

**Tasks Assigned:**
| Task ID | Description |
|---------|-------------|
| 6.1 | Update pipeline_worker handlers.py |
| 6.2 | Update pipeline_worker worker.py — PIPELINE_STAGES |
| 7.1 | OpenTelemetry Distributed Tracing |
| 7.2 | Prometheus Metrics |
| 7.3 | Prometheus Alert Rules |
| 7.4 | Rate Limiting |
| 7.5 | Retry Logic — SQS DLQ + Backoff |
| 7.6 | Cache Health Monitoring |
| 7.7 | Documentation Update |

---

## Execution Sequence

### How to Read This Section

- **Seq#** = Global execution order (1-102)
- **Gate** = Dependency checkpoint — all tasks before the gate must complete
- Tasks within the same batch can optionally run in parallel (same Seq#) but we execute **one at a time** for focus
- Each task takes the full PROJECT_PLAN.md spec as input

### Phase 0: Foundation Infrastructure

```
┌─────────────────────────────────────────────────────────────┐
│  BATCH 0A: Discovery Seeds (Seq 1-12)                       │
│  Role: BD (Backend Developer)                                │
│  All 12 tasks are independent — execute sequentially         │
│                                                              │
│  0.1.1 → 0.1.2 → 0.1.3 → ... → 0.1.12                     │
└─────────────────────────────────────────────────────────────┘
                            │
                     ═══ GATE A ═══
          (all discovery seeds complete)
                            │
┌─────────────────────────────────────────────────────────────┐
│  BATCH 0B: Log Collector (Seq 13-24)                         │
│  Sequential — each step depends on previous                  │
│                                                              │
│  DE: 0.2.1 (schema)                                          │
│   → BD: 0.2.2 (registry) → 0.2.3 (vpc) → 0.2.4 (trail)    │
│   → BD: 0.2.5 (api_access) → 0.2.6 (k8s) → 0.2.7 (sqs)   │
│   → BD: 0.2.8 (resolver) → 0.2.9 (retention)               │
│   → AD: 0.2.10 (api_server)                                  │
│   → DO: 0.2.11 (docker+k8s)                                  │
│   → QA: 0.2.12 (unit tests)                                  │
└─────────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────────┐
│  BATCH 0C: External Collector (Seq 25-41)                    │
│  Sequential — each adapter builds on schema + cred mgr       │
│                                                              │
│  DE: 0.3.1 (schema)                                          │
│   → BD: 0.3.2 (cred_mgr) → 0.3.3 (registry) → 0.3.4 (trivy)│
│   → BD: 0.3.5 (github) → 0.3.6 (nvd) → 0.3.7 (epss)       │
│   → BD: 0.3.8 (kev) → 0.3.9 (pkg_reg) → 0.3.10 (threat)   │
│   → BD: 0.3.11 (lambda_zip) → 0.3.12 (cache) → 0.3.13 (rate)│
│   → AD: 0.3.14 (api_server)                                  │
│   → DO: 0.3.15 (docker+k8s) → 0.3.16 (secrets)              │
│   → QA: 0.3.17 (unit tests)                                  │
└─────────────────────────────────────────────────────────────┘
                            │
                     ═══ GATE B ═══
        (all collectors + discovery seeds complete)
                            │
┌─────────────────────────────────────────────────────────────┐
│  BATCH 0D: DB Migration + Shared Utilities (Seq 42-46)       │
│                                                              │
│  DE: 0.4.1 (orchestration cols) → 0.4.2 (indexes)           │
│  BD: 0.5.1 (rule_evaluator) → 0.5.2 (rule_loader)          │
│   → 0.5.3 (finding_writer)                                   │
└─────────────────────────────────────────────────────────────┘
                            │
                     ═══ GATE C ═══
            (all Phase 0 foundation complete)
```

### Phases 1-5: Engine Implementation

Each engine follows the **identical 10-11 task pattern**:

```
For each engine (container → network → supplychain → api → risk):

  DE: Schema → Rules/Config seed
   → BD: ETL → Evaluator → Reporter → DB Writer
   → AD: API Server
   → DO: Dockerfile + K8s Manifest
   → QA: Unit Tests → Integration Test

  ═══ ENGINE GATE ═══ (engine complete before next phase)
```

**Detailed Sequence:**

```
┌─────────────────────────────────────────────────────────────┐
│  PHASE 1: engine_container (Seq 47-56)                       │
│                                                              │
│  DE: 1.1 (schema) → 1.2 (rules)                             │
│   → BD: 1.3 (etl) → 1.4 (evaluator) → 1.5 (reporter)      │
│   → BD: 1.6 (db_writer)                                      │
│   → AD: 1.7 (api_server)                                     │
│   → DO: 1.8 (docker+k8s)                                     │
│   → QA: 1.9 (unit) → 1.10 (integration)                     │
└─────────────────────────────────────────────────────────────┘
                     ═══ GATE D ═══
                            │
┌─────────────────────────────────────────────────────────────┐
│  PHASE 2: engine_network (Seq 57-66)                         │
│                                                              │
│  DE: 2.1 → 2.2                                               │
│   → BD: 2.3 → 2.4 → 2.5 → 2.6                              │
│   → AD: 2.7                                                   │
│   → DO: 2.8                                                   │
│   → QA: 2.9 → 2.10                                           │
└─────────────────────────────────────────────────────────────┘
                     ═══ GATE E ═══
                            │
┌─────────────────────────────────────────────────────────────┐
│  PHASE 3: engine_supplychain (Seq 67-77)                     │
│                                                              │
│  DE: 3.1 → 3.2                                               │
│   → BD: 3.3 (manifest_parser) → 3.4 → 3.5 → 3.6 → 3.7     │
│   → AD: 3.8                                                   │
│   → DO: 3.9                                                   │
│   → QA: 3.10 → 3.11                                          │
└─────────────────────────────────────────────────────────────┘
                     ═══ GATE F ═══
                            │
┌─────────────────────────────────────────────────────────────┐
│  PHASE 4: engine_api (Seq 78-87)                             │
│                                                              │
│  DE: 4.1 → 4.2                                               │
│   → BD: 4.3 → 4.4 → 4.5 → 4.6                              │
│   → AD: 4.7                                                   │
│   → DO: 4.8                                                   │
│   → QA: 4.9 → 4.10                                           │
└─────────────────────────────────────────────────────────────┘
                     ═══ GATE G ═══
                            │
┌─────────────────────────────────────────────────────────────┐
│  PHASE 5: engine_risk (Seq 88-98)                            │
│                                                              │
│  DE: 5.1 → 5.2 → 5.3                                        │
│   → BD: 5.4 → 5.5 (FAIR) → 5.6 → 5.7                       │
│   → AD: 5.8                                                   │
│   → DO: 5.9                                                   │
│   → QA: 5.10 → 5.11                                          │
└─────────────────────────────────────────────────────────────┘
                     ═══ GATE H ═══
              (all 5 engines complete)
```

### Phase 6: Pipeline Integration

```
┌─────────────────────────────────────────────────────────────┐
│  PHASE 6: Integration (Seq 99-106)                           │
│                                                              │
│  PE: 6.1 (handlers) → 6.2 (pipeline_stages)                 │
│  DO: 6.3 (secrets) → 6.4 (ext-secret) → 6.5 (configmap)    │
│   → 6.6 (ingress)                                            │
│  QA: 6.7 (full pipeline test) → 6.8 (perf benchmark)        │
└─────────────────────────────────────────────────────────────┘
                     ═══ GATE I ═══
             (pipeline integration verified)
```

### Phase 7: Hardening & Observability

```
┌─────────────────────────────────────────────────────────────┐
│  PHASE 7: Hardening (Seq 107-113)                            │
│                                                              │
│  PE: 7.1 (tracing) → 7.2 (metrics) → 7.3 (alerts)          │
│   → 7.4 (rate_limit) → 7.5 (retry) → 7.6 (cache_health)   │
│   → 7.7 (documentation)                                      │
└─────────────────────────────────────────────────────────────┘
                     ═══ DONE ═══
```

---

## Complete Execution Sequence (Flat List)

This is the master checklist. Execute one task at a time, top to bottom.

| Seq | Task ID | Role | Description | Gate |
|-----|---------|------|-------------|------|
| 1 | 0.1.1 | BD | Seed ECR Image Discovery | |
| 2 | 0.1.2 | BD | Seed K8s Workload Discovery | |
| 3 | 0.1.3 | BD | Seed ECS Task Definition Discovery | |
| 4 | 0.1.4 | BD | Seed Lambda Code Location Discovery | |
| 5 | 0.1.5 | BD | Seed API Gateway Detailed Config Discovery | |
| 6 | 0.1.6 | BD | Seed ALB Listeners & Rules Discovery | |
| 7 | 0.1.7 | BD | Seed WAF Web ACL Discovery | |
| 8 | 0.1.8 | BD | Seed VPC Flow Log Config Discovery | |
| 9 | 0.1.9 | BD | Seed CodeCommit Repositories Discovery | |
| 10 | 0.1.10 | BD | Seed CodeArtifact Packages Discovery | |
| 11 | 0.1.11 | BD | Seed AppSync GraphQL API Discovery | |
| 12 | 0.1.12 | BD | Seed CloudWatch Log Groups Discovery | |
| — | — | — | **═══ GATE A: Discovery seeds complete ═══** | A |
| 13 | 0.2.1 | DE | Create Log Collector Database Schema | |
| 14 | 0.2.2 | BD | Build Log Source Registry | |
| 15 | 0.2.3 | BD | Build VPC Flow Log Processor | |
| 16 | 0.2.4 | BD | Build CloudTrail Processor | |
| 17 | 0.2.5 | BD | Build API Access Log Processor | |
| 18 | 0.2.6 | BD | Build K8s Audit Log Processor | |
| 19 | 0.2.7 | BD | Build SQS Consumer Worker | |
| 20 | 0.2.8 | BD | Build IP Resolver | |
| 21 | 0.2.9 | BD | Build Retention Manager | |
| 22 | 0.2.10 | AD | Build API Server (log_collector) | |
| 23 | 0.2.11 | DO | Create Dockerfile & K8s Manifests (log_collector) | |
| 24 | 0.2.12 | QA | Unit Tests (log_collector) | |
| 25 | 0.3.1 | DE | Create External Collector Database Schema | |
| 26 | 0.3.2 | BD | Build Credential Manager | |
| 27 | 0.3.3 | BD | Build Container Registry Adapter | |
| 28 | 0.3.4 | BD | Build Trivy Scanner Wrapper | |
| 29 | 0.3.5 | BD | Build GitHub/GitLab Adapter | |
| 30 | 0.3.6 | BD | Build NVD/CVE Adapter | |
| 31 | 0.3.7 | BD | Build EPSS Adapter | |
| 32 | 0.3.8 | BD | Build KEV Adapter | |
| 33 | 0.3.9 | BD | Build Package Registry Adapter | |
| 34 | 0.3.10 | BD | Build Threat Intel Adapter | |
| 35 | 0.3.11 | BD | Build Lambda ZIP Downloader | |
| 36 | 0.3.12 | BD | Build Cache Manager | |
| 37 | 0.3.13 | BD | Build Rate Limiter | |
| 38 | 0.3.14 | AD | Build API Server (external_collector) | |
| 39 | 0.3.15 | DO | Create Dockerfile & K8s Manifest (external_collector) | |
| 40 | 0.3.16 | DO | Add Secrets Manager Entries | |
| 41 | 0.3.17 | QA | Unit Tests (external_collector) | |
| — | — | — | **═══ GATE B: All collectors complete ═══** | B |
| 42 | 0.4.1 | DE | Add scan_orchestration Columns | |
| 43 | 0.4.2 | DE | Create Partial Indexes | |
| 44 | 0.5.1 | BD | Build Shared Rule Evaluator | |
| 45 | 0.5.2 | BD | Build Shared Rule Loader | |
| 46 | 0.5.3 | BD | Build Shared Finding Writer | |
| — | — | — | **═══ GATE C: Phase 0 foundation complete ═══** | C |
| 47 | 1.1 | DE | Create Container Engine Database Schema | |
| 48 | 1.2 | DE | Seed Container Rules | |
| 49 | 1.3 | BD | Build container_etl.py | |
| 50 | 1.4 | BD | Build container_evaluator.py | |
| 51 | 1.5 | BD | Build container_reporter.py | |
| 52 | 1.6 | BD | Build container_db_writer.py | |
| 53 | 1.7 | AD | Build api_server.py (container) | |
| 54 | 1.8 | DO | Create Dockerfile + K8s Manifest | |
| 55 | 1.9 | QA | Unit Tests (container) | |
| 56 | 1.10 | QA | Integration Test (container) | |
| — | — | — | **═══ GATE D: engine_container complete ═══** | D |
| 57 | 2.1 | DE | Create Network Engine Database Schema | |
| 58 | 2.2 | DE | Seed Network Rules | |
| 59 | 2.3 | BD | Build network_etl.py | |
| 60 | 2.4 | BD | Build network_evaluator.py | |
| 61 | 2.5 | BD | Build network_reporter.py | |
| 62 | 2.6 | BD | Build network_db_writer.py | |
| 63 | 2.7 | AD | Build api_server.py (network) | |
| 64 | 2.8 | DO | Create Dockerfile + K8s Manifest | |
| 65 | 2.9 | QA | Unit Tests (network) | |
| 66 | 2.10 | QA | Integration Test (network) | |
| — | — | — | **═══ GATE E: engine_network complete ═══** | E |
| 67 | 3.1 | DE | Create Supply Chain Database Schema | |
| 68 | 3.2 | DE | Seed supplychain_rules Table | |
| 69 | 3.3 | BD | Build manifest_parser.py | |
| 70 | 3.4 | BD | Build supplychain_etl.py | |
| 71 | 3.5 | BD | Build supplychain_evaluator.py | |
| 72 | 3.6 | BD | Build supplychain_reporter.py | |
| 73 | 3.7 | BD | Build supplychain_db_writer.py | |
| 74 | 3.8 | AD | Build api_server.py (supplychain) | |
| 75 | 3.9 | DO | Create Dockerfile + K8s Manifest | |
| 76 | 3.10 | QA | Unit Tests (supplychain) | |
| 77 | 3.11 | QA | Integration Test (supplychain) | |
| — | — | — | **═══ GATE F: engine_supplychain complete ═══** | F |
| 78 | 4.1 | DE | Create API Engine Database Schema | |
| 79 | 4.2 | DE | Seed api_rules Table | |
| 80 | 4.3 | BD | Build api_etl.py | |
| 81 | 4.4 | BD | Build api_evaluator.py | |
| 82 | 4.5 | BD | Build api_reporter.py | |
| 83 | 4.6 | BD | Build api_db_writer.py | |
| 84 | 4.7 | AD | Build api_server.py (api_engine) | |
| 85 | 4.8 | DO | Create Dockerfile + K8s Manifest | |
| 86 | 4.9 | QA | Unit Tests (api_engine) | |
| 87 | 4.10 | QA | Integration Test (api_engine) | |
| — | — | — | **═══ GATE G: engine_api complete ═══** | G |
| 88 | 5.1 | DE | Create Risk Engine Database Schema | |
| 89 | 5.2 | DE | Seed risk_model_config Table | |
| 90 | 5.3 | DE | Add Tenant Metadata Fields | |
| 91 | 5.4 | BD | Build risk_etl.py | |
| 92 | 5.5 | BD | Build risk_evaluator.py (FAIR Model) | |
| 93 | 5.6 | BD | Build risk_reporter.py | |
| 94 | 5.7 | BD | Build risk_db_writer.py | |
| 95 | 5.8 | AD | Build api_server.py (risk) | |
| 96 | 5.9 | DO | Create Dockerfile + K8s Manifest | |
| 97 | 5.10 | QA | Unit Tests (risk) | |
| 98 | 5.11 | QA | Integration Test (risk) | |
| — | — | — | **═══ GATE H: All 5 engines complete ═══** | H |
| 99 | 6.1 | PE | Update pipeline_worker handlers.py | |
| 100 | 6.2 | PE | Update pipeline_worker worker.py | |
| 101 | 6.3 | DO | Update Secrets Manager | |
| 102 | 6.4 | DO | Update external-secret.yaml | |
| 103 | 6.5 | DO | Update configmap.yaml | |
| 104 | 6.6 | DO | Update ingress.yaml | |
| 105 | 6.7 | QA | Full Pipeline Integration Test | |
| 106 | 6.8 | QA | Performance Benchmarking | |
| — | — | — | **═══ GATE I: Pipeline integration verified ═══** | I |
| 107 | 7.1 | PE | OpenTelemetry Distributed Tracing | |
| 108 | 7.2 | PE | Prometheus Metrics | |
| 109 | 7.3 | PE | Prometheus Alert Rules | |
| 110 | 7.4 | PE | Rate Limiting | |
| 111 | 7.5 | PE | Retry Logic — SQS DLQ + Backoff | |
| 112 | 7.6 | PE | Cache Health Monitoring | |
| 113 | 7.7 | PE | Documentation Update | |
| — | — | — | **═══ DONE ═══** | — |

---

## Agent Invocation Pattern

When implementing a task, invoke the agent like this:

```
Role: {ROLE_NAME}
Task: {TASK_ID} — {TASK_DESCRIPTION}
Seq: {SEQ_NUMBER} of 113

Read the full task specification from:
  .claude/documentation/PROJECT_PLAN.md → Task {TASK_ID}

Context files to read first:
  - .claude/documentation/NEW_ENGINES_ARCHITECTURE.md (for schema/architecture context)
  - .claude/documentation/NEW_ENGINES_ETL_RULES.md (for rule definitions and ETL logic)
  - .claude/documentation/NEW_ENGINE_DATA_SOURCES.md (for data source details)

Existing code patterns to follow:
  - engines/check/ (reference engine implementation)
  - engines/compliance/ (reference for reporting pattern)
  - shared/common/ (shared utilities to import, never duplicate)

Implementation rules:
  1. Read the task spec carefully — it contains exact file paths, input/output, code examples
  2. Follow the code standards in CLAUDE.md (type hints, docstrings, import order)
  3. Create the file at the specified location
  4. Include inline comments referencing the source doc (e.g., "# Per NEW_ENGINES_ETL_RULES.md line 434")
  5. Do NOT create files for other tasks — stay focused on this one task only
  6. After implementation, verify the file is syntactically correct (python -c "import ast; ast.parse(open('file').read())")
```

---

## Role Distribution Chart

```
Backend Developer (BD)  ████████████████████████████████████████████  48 tasks (42%)
Data Engineer (DE)      █████████████████                             17 tasks (15%)
QA Engineer (QA)        ████████████████                              16 tasks (14%)
DevOps Engineer (DO)    ██████████████                                14 tasks (12%)
Platform Engineer (PE)  ██████████                                    10 tasks  (9%)
API Developer (AD)      ████████                                       8 tasks  (7%)
                        ─────────────────────────────────────────────
                        Total: 113 tasks
```

---

## Dependency Gate Summary

| Gate | After Task | What's Complete | What Unlocks |
|------|-----------|-----------------|--------------|
| A | 0.1.12 | All 12 discovery seeds | Log collector, external collector |
| B | 0.3.17 | Both collectors built & tested | DB migration, shared utilities |
| C | 0.5.3 | All Phase 0 foundation | Engine implementation (Phases 1-5) |
| D | 1.10 | engine_container complete | engine_network (Phase 2) |
| E | 2.10 | engine_network complete | engine_supplychain (Phase 3) |
| F | 3.11 | engine_supplychain complete | engine_api (Phase 4) |
| G | 4.10 | engine_api complete | engine_risk (Phase 5) |
| H | 5.11 | All 5 engines complete | Pipeline integration (Phase 6) |
| I | 6.8 | Pipeline tested & benchmarked | Hardening & observability (Phase 7) |

---

## Getting Started

To begin implementation, start with **Seq 1 — Task 0.1.1** using the **Backend Developer (BD)** role:

```
Implement Task 0.1.1: Seed ECR Image Discovery

Role: Backend Developer
Read spec: PROJECT_PLAN.md → Task 0.1.1
Output: rule_discoveries INSERT row for aws.ecr.image resource type
```
