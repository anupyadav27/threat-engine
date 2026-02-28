# Architectural Decision Records (ADR)

> **Purpose:** Document key architectural decisions, rationale, alternatives considered, and consequences
> **Last Updated:** 2026-02-20

---

## Table of Contents

1. [ADR-001: AWS Secrets Manager for Credential Storage](#adr-001-aws-secrets-manager-for-credential-storage)
2. [ADR-002: PostgreSQL as Primary Database](#adr-002-postgresql-as-primary-database)
3. [ADR-003: Consolidated NLB vs Multiple Classic ELBs](#adr-003-consolidated-nlb-vs-multiple-classic-elbs)
4. [ADR-004: scan_orchestration Table as Central Hub](#adr-004-scan_orchestration-table-as-central-hub)
5. [ADR-005: Database-per-Engine Pattern](#adr-005-database-per-engine-pattern)
6. [ADR-006: S3 Sidecar Pattern for Output Storage](#adr-006-s3-sidecar-pattern-for-output-storage)
7. [ADR-007: FastAPI for All Engine APIs](#adr-007-fastapi-for-all-engine-apis)
8. [ADR-008: Neo4j for Threat Graph Analysis](#adr-008-neo4j-for-threat-graph-analysis)
9. [ADR-009: EKS over Self-Managed Kubernetes](#adr-009-eks-over-self-managed-kubernetes)
10. [ADR-010: Multi-Tenant Single-Cluster Design](#adr-010-multi-tenant-single-cluster-design)

---

## ADR-001: AWS Secrets Manager for Credential Storage

### Status
**Accepted** | Date: 2025-12

### Context

The threat engine requires secure storage for:
- Database passwords (RDS PostgreSQL)
- Cloud provider credentials (AWS, Azure, GCP, OCI, AliCloud, IBM)
- API keys for integrations
- Service account credentials

**Requirements:**
- Centralized credential management
- Automatic rotation support
- Encryption at rest and in transit
- Fine-grained access control
- Audit logging
- Integration with Kubernetes

### Decision

**Use AWS Secrets Manager** as the single source of truth for all secrets.

**Implementation:**
- Store all credentials in Secrets Manager with structured naming: `threat-engine/<env>/<component>/<type>`
- Encrypt with AWS KMS (customer-managed key)
- Use External Secrets Operator to sync to Kubernetes Secrets
- Pods consume via environment variables or mounted files
- Enable automatic rotation for database passwords (90 days)

### Alternatives Considered

1. **Kubernetes Secrets (native)**
   - ❌ Not encrypted at rest by default
   - ❌ No rotation mechanism
   - ❌ Credentials visible in etcd
   - ❌ No centralized management
   - ✅ Native Kubernetes integration

2. **HashiCorp Vault**
   - ✅ Advanced secret management features
   - ✅ Dynamic secrets support
   - ✅ Fine-grained policies
   - ❌ Additional infrastructure to manage
   - ❌ Higher operational complexity
   - ❌ Separate cost for licensing

3. **AWS Systems Manager Parameter Store**
   - ✅ Simpler than Secrets Manager
   - ✅ Lower cost for standard parameters
   - ❌ No automatic rotation for secrets
   - ❌ 10k parameter limit per account
   - ✅ KMS integration

4. **Environment Variables in ConfigMaps**
   - ❌ Credentials stored in plain text
   - ❌ Visible in kubectl get/describe
   - ❌ No encryption
   - ❌ **SECURITY RISK - REJECTED**

### Consequences

**Positive:**
- ✅ Centralized secret management across AWS services
- ✅ Automatic rotation reduces credential exposure window
- ✅ KMS encryption ensures data-at-rest security
- ✅ CloudTrail logs all access for audit compliance
- ✅ IAM policies provide fine-grained access control
- ✅ External Secrets Operator enables seamless Kubernetes integration

**Negative:**
- ⚠️ Additional AWS service dependency
- ⚠️ Cost: ~$0.40/secret/month + API call charges
- ⚠️ Vendor lock-in to AWS ecosystem
- ⚠️ Requires External Secrets Operator maintenance

**Mitigation:**
- Document all secrets for easy migration if needed
- Use secret naming convention for portability
- Monitor costs via AWS Cost Explorer

---

## ADR-002: PostgreSQL as Primary Database

### Status
**Accepted** | Date: 2025-11

### Context

The threat engine needs a relational database for:
- Structured security findings (discoveries, checks, threats)
- Complex queries and joins across engines
- JSONB support for flexible schema evolution
- ACID transactions for data integrity
- Scalability to billions of rows

### Decision

**Use PostgreSQL 15** on AWS RDS as the primary database.

**Key features leveraged:**
- JSONB columns for flexible metadata storage
- Advanced indexing (B-tree, GIN, GIST)
- Partitioning for large tables
- Foreign key constraints for referential integrity
- Full-text search capabilities

### Alternatives Considered

1. **MySQL/MariaDB**
   - ✅ Mature ecosystem
   - ✅ Good performance
   - ❌ Limited JSONB support (JSON type less capable)
   - ❌ Weaker full-text search
   - ❌ Less advanced indexing options

2. **NoSQL (MongoDB, DynamoDB)**
   - ✅ Schema flexibility
   - ✅ Horizontal scalability
   - ❌ No native joins (requires application-level logic)
   - ❌ Weaker consistency guarantees
   - ❌ Complex aggregations difficult
   - ❌ Poor fit for compliance reporting (requires complex queries)

3. **Amazon Aurora PostgreSQL**
   - ✅ PostgreSQL compatible
   - ✅ Better scalability and performance
   - ✅ Auto-scaling storage
   - ❌ Higher cost (~2x RDS PostgreSQL)
   - ⚠️ Considered for future migration

4. **TimescaleDB (PostgreSQL extension)**
   - ✅ Optimized for time-series data
   - ✅ Better compression for historical data
   - ❌ Additional complexity
   - ⚠️ Considered for future optimization

### Consequences

**Positive:**
- ✅ JSONB enables flexible schema evolution without migrations
- ✅ Advanced indexing (GIN on JSONB) enables fast queries
- ✅ ACID transactions ensure data integrity across engines
- ✅ Mature ecosystem with excellent tooling
- ✅ Strong open-source community support

**Negative:**
- ⚠️ Vertical scaling limits (need read replicas for high load)
- ⚠️ Partitioning requires careful design
- ⚠️ JSONB queries can be slower than native columns

**Mitigation:**
- Use read replicas for analytics queries
- Implement table partitioning for large tables (discoveries, findings)
- Consider Aurora PostgreSQL for future scale needs

---

## ADR-003: Consolidated NLB vs Multiple Classic ELBs

### Status
**Accepted** | Date: 2026-01

### Context

Initially deployed with **6 separate Classic Load Balancers** (one per engine group):
- Discoveries ELB
- Check ELB
- Compliance ELB
- Threat ELB
- IAM/DataSec ELB
- Onboarding ELB

**Problems:**
- High cost (~$20/month × 6 = $120/month)
- Complex DNS management
- Difficult to maintain
- Poor resource utilization

### Decision

**Replace all Classic ELBs with a single Network Load Balancer (NLB)** + nginx Ingress Controller.

**Architecture:**
```
Internet → NLB (port 80) → nginx Ingress → Path-based routing → Engine Services
```

**Path-based routing:**
- `/api/v1/discovery/*` → engine-discoveries
- `/api/v1/check/*` → engine-check
- `/api/v1/compliance/*` → engine-compliance
- `/api/v1/threat/*` → engine-threat
- (etc.)

### Alternatives Considered

1. **Keep Multiple Classic ELBs**
   - ✅ Simple isolation per engine
   - ❌ High cost ($120/month)
   - ❌ Operational complexity
   - ❌ Classic ELB is deprecated

2. **Application Load Balancer (ALB)**
   - ✅ Path-based routing native
   - ✅ HTTP/HTTPS features
   - ❌ Higher cost than NLB (~$30/month)
   - ❌ OSI Layer 7 overhead

3. **Network Load Balancer (NLB) - CHOSEN**
   - ✅ Lower cost (~$20/month total)
   - ✅ Better performance (OSI Layer 4)
   - ✅ Static IP support
   - ✅ TLS termination support
   - ⚠️ Requires nginx ingress for path routing

4. **Service Mesh (Istio, Linkerd)**
   - ✅ Advanced traffic management
   - ✅ mTLS between services
   - ❌ High complexity
   - ❌ Resource overhead
   - ❌ Overkill for current scale

### Consequences

**Positive:**
- ✅ **Cost savings:** $120/month → $20/month (83% reduction)
- ✅ Single DNS endpoint for all services
- ✅ Simplified certificate management
- ✅ Better performance (NLB is Layer 4)
- ✅ Easier maintenance

**Negative:**
- ⚠️ nginx Ingress is a single point of failure (mitigated by HA deployment)
- ⚠️ Path-based routing config in nginx instead of native LB
- ⚠️ Additional component to maintain (ingress controller)

**Mitigation:**
- Deploy nginx Ingress with 2+ replicas
- Use liveness/readiness probes
- Monitor ingress controller health

---

## ADR-004: scan_orchestration Table as Central Hub

### Status
**Accepted** | Date: 2025-12

### Context

**Problem:** Engines need to pass scan context between each other, but direct coupling creates tight dependencies.

**Requirements:**
- Each engine should be independently deployable
- Scan context (tenant, account, credentials, scope) must flow through pipeline
- Engines need to discover upstream scan IDs (e.g., threat engine needs check_scan_id)
- Support for partial pipeline execution (e.g., run only compliance engine)

### Decision

**Use `scan_orchestration` table** as the single source of truth for scan lifecycle and engine coordination.

**Design:**
```sql
CREATE TABLE scan_orchestration (
    orchestration_id UUID PRIMARY KEY,
    tenant_id UUID,
    account_id VARCHAR,
    provider VARCHAR,
    credential_ref VARCHAR,
    include_services TEXT[],
    include_regions TEXT[],

    -- Engine scan IDs (populated by each engine)
    discovery_scan_id UUID,
    check_scan_id UUID,
    inventory_scan_id UUID,
    threat_scan_id UUID,
    compliance_scan_id UUID,
    iam_scan_id UUID,
    datasec_scan_id UUID,

    -- Orchestration state
    engines_requested TEXT[],
    engines_completed TEXT[],
    overall_status VARCHAR,
    started_at TIMESTAMP,
    completed_at TIMESTAMP
);
```

**Flow:**
1. Onboarding creates `orchestration_id` with all context
2. Each engine calls `get_scan_context(orchestration_id)` to hydrate parameters
3. Each engine writes its `<engine>_scan_id` back to orchestration table
4. Downstream engines lookup upstream scan IDs via orchestration

### Alternatives Considered

1. **Direct Database Queries Between Engines**
   - ❌ Tight coupling between engines
   - ❌ Hard to change engine order
   - ❌ Difficult to test independently

2. **Message Queue (SQS, RabbitMQ)**
   - ✅ Decoupling via events
   - ✅ Asynchronous processing
   - ❌ Complex state management
   - ❌ Difficult to query scan state
   - ❌ Additional infrastructure

3. **REST API Calls Between Engines**
   - ❌ Synchronous coupling
   - ❌ Network dependency
   - ❌ Cascading failures

4. **Orchestration Table (CHOSEN)**
   - ✅ Single source of truth
   - ✅ Easy to query scan state
   - ✅ Engines remain independent
   - ✅ Simple to implement

### Consequences

**Positive:**
- ✅ Engines decoupled (only depend on orchestration table)
- ✅ Easy to add new engines (just add `<engine>_scan_id` column)
- ✅ Simple to query scan status
- ✅ Supports partial execution (skip engines if scan_id is NULL)
- ✅ Auditability (all scan context in one place)

**Negative:**
- ⚠️ Orchestration table schema changes require all engines to update
- ⚠️ Potential bottleneck if thousands of concurrent scans

**Mitigation:**
- Use database indexes on orchestration_id
- Partition table by created_at if scale exceeds 10M rows

---

## ADR-005: Database-per-Engine Pattern

### Status
**Accepted** | Date: 2025-12

### Context

**Question:** Should all engines share one database, or have separate databases?

**Requirements:**
- Data isolation between engines
- Independent schema evolution
- Clear ownership boundaries
- Support for future microservice extraction

### Decision

**Use separate databases per engine** on the same RDS instance.

**Databases:**
- `threat_engine_discoveries`
- `threat_engine_check`
- `threat_engine_inventory`
- `threat_engine_threat`
- `threat_engine_compliance`
- `threat_engine_iam`
- `threat_engine_datasec`
- `threat_engine_shared` (onboarding, orchestration)

### Alternatives Considered

1. **Single Database, Shared Tables**
   - ❌ Schema conflicts between engines
   - ❌ Difficult to manage migrations
   - ❌ Tight coupling

2. **Single Database, Schema-per-Engine (PostgreSQL schemas)**
   - ✅ Logical separation
   - ❌ Still coupled in one database
   - ❌ Harder to extract to separate instances later

3. **Separate Databases (CHOSEN)**
   - ✅ Clear ownership boundaries
   - ✅ Independent schema evolution
   - ✅ Easy to migrate to separate instances
   - ⚠️ Requires cross-database queries (via orchestration table)

4. **Separate RDS Instances per Engine**
   - ✅ Complete isolation
   - ❌ Very high cost
   - ❌ Operational complexity

### Consequences

**Positive:**
- ✅ Each engine owns its schema
- ✅ Migrations isolated (no conflicts)
- ✅ Easy to extract to separate instances in future
- ✅ Clear data ownership

**Negative:**
- ⚠️ Cross-database joins not possible (must use orchestration pattern)
- ⚠️ Backup/restore must handle multiple databases

**Mitigation:**
- Use orchestration table pattern for cross-engine data
- Backup all databases together via RDS snapshots

---

## ADR-006: S3 Sidecar Pattern for Output Storage

### Status
**Accepted** | Date: 2025-12

### Context

**Requirements:**
- Persist scan results for audit and historical analysis
- Decouple storage from database (avoid filling up RDS)
- Support for large NDJSON files (100MB+)
- Cost-effective long-term storage

### Decision

**Use S3 for scan output storage with sidecar containers.**

**Pattern:**
```yaml
spec:
  containers:
  - name: engine-compliance
    image: yadavanup84/threat-engine-compliance-engine:latest
    volumeMounts:
    - name: output
      mountPath: /app/output

  - name: s3-sync
    image: amazon/aws-cli:latest
    volumeMounts:
    - name: output
      mountPath: /app/output
    command:
      - /bin/sh
      - -c
      - |
        while true; do
          aws s3 sync /app/output/ s3://cspm-lgtech/engine_output/compliance/
          sleep 300
        done
```

### Alternatives Considered

1. **Store All Results in Database**
   - ❌ Large JSONB columns slow down queries
   - ❌ High RDS storage cost
   - ❌ Difficult to archive old data

2. **Direct S3 Upload from Engine**
   - ✅ Simple
   - ❌ Adds AWS SDK dependency to every engine
   - ❌ Tight coupling to S3

3. **Sidecar Container (CHOSEN)**
   - ✅ Separation of concerns
   - ✅ No AWS SDK in engine code
   - ✅ Can swap storage backend easily
   - ⚠️ Additional container overhead

4. **External Service (Fluentd, Logstash)**
   - ✅ Centralized logging
   - ❌ Complex setup
   - ❌ Overhead for structured data

### Consequences

**Positive:**
- ✅ Engines remain cloud-agnostic
- ✅ Easy to swap S3 for Azure Blob or GCP Cloud Storage
- ✅ Low-cost long-term storage
- ✅ Lifecycle policies for automatic archival

**Negative:**
- ⚠️ Additional CPU/memory per pod (~50MB)
- ⚠️ 5-minute sync delay (files not immediately in S3)

**Mitigation:**
- Set sync interval based on urgency (default 5 minutes)
- Use S3 lifecycle policies to move old data to Glacier

---

## ADR-007: FastAPI for All Engine APIs

### Status
**Accepted** | Date: 2025-11

### Context

**Requirements:**
- RESTful API for each engine
- Async I/O for cloud API calls
- Automatic OpenAPI/Swagger docs
- Type validation
- High performance

### Decision

**Use FastAPI** for all engine API servers.

**Benefits:**
- Native async/await support
- Automatic OpenAPI schema generation
- Pydantic data validation
- High performance (based on Starlette + uvicorn)
- Type hints enforced

### Alternatives Considered

1. **Flask**
   - ✅ Mature ecosystem
   - ❌ No native async support
   - ❌ Manual OpenAPI docs

2. **Django + DRF**
   - ✅ Full-featured framework
   - ❌ Heavy for simple APIs
   - ❌ Async support limited

3. **FastAPI (CHOSEN)**
   - ✅ Native async
   - ✅ Auto docs
   - ✅ Fast performance
   - ✅ Modern Python

### Consequences

**Positive:**
- ✅ Consistent API patterns across all engines
- ✅ Automatic OpenAPI docs for integration
- ✅ Type validation reduces bugs
- ✅ High performance for I/O-bound workloads

**Negative:**
- ⚠️ Smaller ecosystem than Flask/Django
- ⚠️ Requires Python 3.7+

---

## ADR-008: Neo4j for Threat Graph Analysis

### Status
**Accepted** | Date: 2026-01

### Context

**Requirements:**
- Model attack paths as graphs (resource → attack technique → lateral movement)
- Query relationships efficiently (shortest path, pattern matching)
- Visualize security posture as connected graph

### Decision

**Use Neo4j** for threat graph database.

**Credentials:**
- Username: `neo4j`
- Password: `i12CZ4vrIgGrWSbN8UB9yPochaNSeCa00avAj67r6zs`
- Protocol: Bolt (neo4j://...)

**Use Case:**
- Threat engine writes resource relationships as graph nodes/edges
- Query attack chains: `MATCH path = (start)-[:EXPLOITS*1..5]->(target) RETURN path`

### Alternatives Considered

1. **PostgreSQL with Recursive CTEs**
   - ✅ No additional database
   - ❌ Poor performance for deep graph queries
   - ❌ Difficult to visualize

2. **Neo4j (CHOSEN)**
   - ✅ Native graph database
   - ✅ Cypher query language
   - ✅ Graph visualization tools
   - ⚠️ Additional database to manage

3. **Amazon Neptune**
   - ✅ Managed graph database
   - ❌ Higher cost
   - ❌ Limited query language support

### Consequences

**Positive:**
- ✅ Fast graph traversal queries
- ✅ Attack path visualization
- ✅ MITRE ATT&CK technique mapping

**Negative:**
- ⚠️ Additional database to maintain
- ⚠️ Dual-write pattern (PostgreSQL + Neo4j)

---

## ADR-009: EKS over Self-Managed Kubernetes

### Status
**Accepted** | Date: 2025-11

### Context

**Requirements:**
- Kubernetes for container orchestration
- High availability
- Minimal operational overhead
- Integration with AWS services

### Decision

**Use Amazon EKS** (Elastic Kubernetes Service).

**Cluster:** `vulnerability-eks-cluster`

### Alternatives Considered

1. **Self-Managed Kubernetes (kubeadm, kops)**
   - ✅ Full control
   - ❌ High operational complexity
   - ❌ Manual upgrades and patching

2. **Amazon EKS (CHOSEN)**
   - ✅ Managed control plane
   - ✅ Automatic upgrades
   - ✅ AWS service integration
   - ⚠️ Additional cost ($75/month)

3. **ECS (Elastic Container Service)**
   - ✅ Simpler than Kubernetes
   - ❌ Vendor lock-in
   - ❌ Limited ecosystem

### Consequences

**Positive:**
- ✅ AWS manages control plane (etcd, API server, etc.)
- ✅ Seamless IAM integration (IRSA)
- ✅ CloudWatch integration
- ✅ Automated upgrades

**Negative:**
- ⚠️ Cost: $75/month cluster fee + nodes
- ⚠️ AWS vendor lock-in

---

## ADR-010: Multi-Tenant Single-Cluster Design

### Status
**Accepted** | Date: 2025-12

### Context

**Question:** Should each customer/tenant have a separate EKS cluster, or share one cluster?

### Decision

**Single EKS cluster with multi-tenant support.**

**Isolation:**
- Logical separation via `tenant_id` in all database tables
- Kubernetes RBAC for administrative separation
- Network policies for pod isolation (future)

### Alternatives Considered

1. **Cluster-per-Tenant**
   - ✅ Complete isolation
   - ❌ Very high cost ($75/cluster/month)
   - ❌ Operational complexity

2. **Single Cluster, Multi-Tenant (CHOSEN)**
   - ✅ Cost-effective
   - ✅ Simplified operations
   - ⚠️ Requires careful data isolation

### Consequences

**Positive:**
- ✅ Lower cost
- ✅ Easier to manage

**Negative:**
- ⚠️ Security risk if tenant_id filtering fails (requires thorough testing)
- ⚠️ Resource contention (mitigated by resource quotas)

---

## Summary

These architectural decisions form the foundation of the threat-engine platform. All decisions prioritize:
1. **Security first** (Secrets Manager, encryption, RBAC)
2. **Cost optimization** (consolidated NLB, shared RDS)
3. **Operational simplicity** (managed services, FastAPI consistency)
4. **Scalability** (PostgreSQL, separate databases, orchestration pattern)
5. **Flexibility** (multi-cloud design, decoupled engines)

**Next Review:** 2026-06 (quarterly architecture review)
