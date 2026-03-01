# Changelog

All notable changes to the CSPM Threat Engine platform.

---

## [Unreleased]

### Added
- **Alembic Schema Migrations** — per-engine Alembic version directories under `shared/database/alembic/versions/{engine}/`; `env.py` connects via `DATABASE_URL` env var; each of the 9 engine DBs has its own migration chain; run `alembic upgrade head` per DB before every deploy
- **PgBouncer Connection Pooler** — K8s Deployment (2 replicas, HA) in `deployment/aws/eks/pgbouncer/`; transaction mode, 500 max client conns, 20 real RDS conns per DB; all engine ConfigMaps updated to point to `pgbouncer.threat-engine-engines.svc.cluster.local:5432`
- **PostgreSQL Row-Level Security (RLS)** — ENABLE + FORCE RLS on all tenant tables across 9 engine DBs; policy: `USING (tenant_id = current_setting('app.tenant_id', TRUE))`; `ALTER ROLE postgres BYPASSRLS` preserves existing engine writes; `shared/common/rls.py` provides `tenant_cursor()` (psycopg2) and `tenant_acquire()` (asyncpg) helpers using `set_config(..., TRUE)` for PgBouncer-safe transaction-scoped context
- **SQS Async Pipeline** — `shared/common/sqs.py` (FIFO SQS wrapper), `shared/common/pipeline_events.py` (PipelineEvent Pydantic models), `shared/pipeline_worker/` microservice (polls `threat-engine-scan-requests.fifo`, runs full pipeline); onboarding orchestrator short-circuits to SQS when `SQS_PIPELINE_QUEUE_URL` is set; DLQ for failed messages; `scripts/create-sqs-queues.sh` provisions all queues; backward-compatible (inline HTTP pipeline when env var absent)
- **OpenTelemetry Distributed Tracing** — `shared/common/telemetry.py`: TracerProvider + MeterProvider with OTLP gRPC export, auto-instruments FastAPI/httpx/psycopg2/logging, graceful no-op fallbacks if packages absent; OTel Collector Contrib at `deployment/aws/eks/otel/otel-collector.yaml` (OTLP gRPC 4317 + HTTP 4318, Prometheus metrics on 8889); all 9 engines: OTel packages in requirements.txt, `configure_telemetry()` wired in api_server.py, `OTEL_SERVICE_NAME` + 5 otel-config env vars in K8s manifests (all `optional: true`)
- **API Uniformity (v-uniform)** — All 9 engines expose all 4 standard health paths; IAM adds `/api/v1/iam/*` + `/api/v1/scan` aliases; DataSec adds `/api/v1/datasec/*` + `/api/v1/scan` aliases; `csp`/`scan_id` params made optional; K8s probes standardised to `live`/`ready` endpoints
- **Compliance Engine (DB-backed)** — 13 frameworks, 960 controls, 4,015 rule-to-control mappings loaded from compliance DB
- **Compliance Controls Enrichment** — 570 controls enriched with testing_procedures, implementation_guidance, severity from CIS/NIST/PCI JSON sources
- **IAM Security Engine** — Tested and verified: 2,088 findings, 57 rules, 6 modules (privilege escalation, MFA, password policy, root, SSO)
- **DataSec Engine** — Tested and verified: 300 findings, 62 rules, 7 modules (classification, lineage, residency, activity)
- **Single NLB Architecture** — All traffic routes through one nginx ingress NLB (eliminated 6 Classic ELBs)
- **Batch Compliance DB Writer** — `execute_values` with 500/batch for 10x faster compliance_findings inserts
- **Security Graph (Neo4j)** — Attack path analysis, blast radius, toxic combinations, threat hunting
- **Threat Analysis** — Composite risk scoring (0-100), verdict classification, attack chain builder
- **Threat Intelligence** — IOC/TTP ingestion, MITRE technique correlation
- **Threat Hunting** — 5 predefined hunts, custom Cypher queries, saved hunts with results
- **Neo4j Integration** — Graph builder populates from PostgreSQL, graph queries via API
- **Multi-CSP MITRE enrichment** — Full Azure + GCP MITRE technique mapping for threat engine
- **Hunt query generation** — Auto-generated Cypher hunt queries from threat detections
- **Comprehensive API Documentation** — Per-engine docs with folder structures, endpoints, sample responses

### Changed
- **FrameworkLoader** — Added DB fallback chain: CSV → YAML → `rule_control_mapping` table → metadata files
- **Threat pipeline** — Auto-runs analysis after detection in `/generate` endpoint
- **API routes** — Analysis endpoints moved before wildcard to prevent route conflicts
- **Rule metadata** — MITRE technique/tactic columns added, loaded from PostgreSQL instead of 42MB YAML
- **Graph builder** — Fixed column name `cf.id AS finding_id` and severity from `rm.severity` JOIN
- **threat_analysis upsert** — Fixed conflict key to `(detection_id, analysis_type)`

### Removed
- **6 Classic ELBs** — Consolidated to single NLB via nginx ingress
- **24 old Docker Hub images** — Cleaned up superseded/duplicate images
- **13 Virginia KMS keys** — Scheduled for deletion (no resources in us-east-1)
- **Dead deployments** — vulnerability-engine (CrashLoopBackOff), incremental-update-orchestrator (no pods)
- **Old postgres DB schema** — Dropped `engine_pythonsdk` schema from default postgres database
- **threat_rules.yaml** — 42MB file replaced by PostgreSQL `rule_metadata` table
- **131 root MD files** — Temp documentation cleaned up
- **data_pythonsdk/** — 12,000+ data files removed (not needed in repo)
- **data_compliance/** — 109 data files removed
- **archive/ directories** — Removed from all engine folders

---

## [1.0.0] - 2025-02-05

### Added
- **Database-first architecture** — All engines read/write PostgreSQL
- **Multi-provider rule loading** — Rules loaded from DB instead of local YAML
- **MITRE ATT&CK mapping** — 46 techniques mapped to security rules
- **Metadata enrichment** — JOIN check_findings with rule_metadata for severity, MITRE
- **Misconfig normalizer** — Normalize findings with MITRE JSONB handling
- **Threat detector** — Group findings by resource, assign MITRE techniques
- **API server** — FastAPI with 60+ endpoints
- **Docker support** — Dockerfile + docker-compose for all engines
- **EKS deployment** — Kubernetes manifests for production

### Initial Engines
- engine_discoveries (AWS resource discovery)
- engine_check (compliance checking)
- engine_inventory (asset inventory)
- engine_threat (threat detection)
- engine_compliance (compliance reporting)
- engine_rule (YAML rule builder)
- engine_onboarding (account management)
- engine_datasec (data security)
- engine_iam (IAM security)
- engine_secops (IaC scanning)
- api_gateway (service routing)
