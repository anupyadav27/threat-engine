# CSPM Platform — Architecture Improvement Roadmap

> **Status**: Planned — implement after current code cleanup
> **Last reviewed**: 2026-03-01
> **Scope**: 5 structural improvements + 3 debt items
> **Excluded**: RDS split into two instances (deferred — cost concern, only needed at 10+ concurrent tenants)

---

## Overview

These improvements were identified during an architecture review (2026-03-01).
The platform foundation is solid. These changes address scale, security, and operability
**before onboarding real enterprise customers**.

| # | Improvement | Priority | Effort | Risk Addressed |
|---|-------------|----------|--------|----------------|
| 1 | [Alembic migrations](#1-alembic-schema-migrations) | Immediate | 2 days | Schema drift, manual errors |
| 2 | [PgBouncer](#2-pgbouncer-connection-pooling) | Before scaling | 1 day | RDS connection limit |
| 3 | [PostgreSQL RLS](#3-postgresql-row-level-security) | Before first customer | 3 days | Tenant data leakage |
| 4 | [SQS pipeline](#4-sqs-between-pipeline-stages) | Before multi-tenant | 1 week | Scan reliability, concurrency |
| 5 | [OpenTelemetry](#5-opentelemetry-observability) | After above | 2 days | Debugging, visibility |
| 6 | [Debt items](#6-architectural-debt) | Ongoing | varies | Performance, correctness |

---

## 1. Alembic Schema Migrations

### Problem
13 migration SQL files exist (`001_` → `013_`) but no runner. Migrations are applied manually
via psql. No record of what's been applied to which DB. Risk of running twice = data corruption.
Staging vs production schema drift is undetectable.

### Solution
Alembic (Python) — maintains `alembic_version` table in each engine DB. Only applies
missing migrations, in order, safely. Supports rollback via `downgrade()`.

### Implementation

**Directory structure:**
```
consolidated_services/database/
├── alembic.ini
├── alembic/
│   ├── env.py              # connects to each engine DB via DATABASE_URL env
│   └── versions/
│       ├── 001_initial_schema.py
│       ├── 002_add_scan_orchestration.py
│       └── ...013_add_rii_parent_columns.py
```

**Migration file format:**
```python
# alembic/versions/013_add_rii_parent_columns.py
def upgrade():
    op.add_column('resource_inventory_identifier',
        sa.Column('parent_resource_type', sa.String(255))
    )

def downgrade():
    op.drop_column('resource_inventory_identifier', 'parent_resource_type')
```

**Apply to all 9 engine DBs (run before every kubectl apply):**
```bash
for DB in check compliance discoveries inventory threat iam datasec secops onboarding; do
    DATABASE_URL="postgresql://postgres:$PW@$RDS_HOST/threat_engine_$DB" \
    alembic upgrade head
done
```

**CI/CD integration**: Run migration script as a pre-deploy step before `kubectl apply`.
New pods only start after schema is confirmed up-to-date.

### Why first
Prevents schema drift between environments TODAY. Zero cost, minimal risk.

---

## 2. PgBouncer Connection Pooling

### Problem
Each engine pod opens direct psycopg2 connections to RDS. At current 1 replica per engine:
- engine-discoveries: up to 60 connections (ThreadPoolExecutor scan)
- All other engines: up to 10 each = 80 more
- **Total: ~140-150 direct connections**
- RDS t3.medium `max_connections` ≈ 170

Adding one more engine replica or one concurrent tenant scan → RDS rejects connections.

### Solution
PgBouncer in **transaction mode** between pods and RDS. Multiplexes 500 app-side connections
into ~20 real RDS connections. **No code changes in engines** — just change the DB host.

### Implementation

**Deploy as K8s service:**
```yaml
# deployment/aws/eks/pgbouncer/pgbouncer.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pgbouncer
  namespace: threat-engine-engines
spec:
  replicas: 2   # HA — run 2 instances
  template:
    spec:
      containers:
      - name: pgbouncer
        image: pgbouncer/pgbouncer:1.22.0
        env:
        - name: POSTGRESQL_HOST
          value: postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com
        - name: PGBOUNCER_POOL_MODE
          value: transaction
        - name: PGBOUNCER_MAX_CLIENT_CONN
          value: "500"
        - name: PGBOUNCER_DEFAULT_POOL_SIZE
          value: "20"        # real RDS connections per DB
---
apiVersion: v1
kind: Service
metadata:
  name: pgbouncer
  namespace: threat-engine-engines
spec:
  ports:
  - port: 5432
    targetPort: 5432
```

**One-line change per engine ConfigMap:**
```bash
# Before
THREAT_DB_HOST=postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com

# After
THREAT_DB_HOST=pgbouncer.threat-engine-engines.svc.cluster.local
```

### Caveat with RLS
Transaction-mode PgBouncer does not support `SET app.tenant_id` (session-level setting needed
for Row Level Security). Two options:
1. Use `SET LOCAL` inside explicit transactions (preferred)
2. Start with session mode (less efficient, fully compatible)

Implement RLS first in session mode, then tune to transaction mode using `SET LOCAL`.

---

## 3. PostgreSQL Row Level Security

### Problem
All tenant isolation relies on `WHERE tenant_id = %s` in application code. One developer
writing a query without this filter → Tenant A reads Tenant B's security findings.
In a CSPM platform handling AWS credentials and posture data, this is a data breach.

Tenant isolation is currently a **convention enforced by code** — not a database guarantee.

### Solution
PostgreSQL Row Level Security (RLS) — the database itself enforces tenant isolation.
Even if application code omits the filter, the DB returns only the current tenant's rows.
Zero change to existing application queries (they continue to work as before).

### Implementation

**Enable RLS on every engine table (migration per engine DB):**
```sql
-- Example: threat DB
ALTER TABLE threat_findings       ENABLE ROW LEVEL SECURITY;
ALTER TABLE threat_report         ENABLE ROW LEVEL SECURITY;
ALTER TABLE threat_detections     ENABLE ROW LEVEL SECURITY;
ALTER TABLE threat_analysis       ENABLE ROW LEVEL SECURITY;

-- Policy: each connection only sees its tenant's rows
CREATE POLICY tenant_isolation ON threat_findings
    USING (tenant_id = current_setting('app.tenant_id', true));

-- Repeat for every table in every engine DB
```

**Set tenant context in engine_common DB pool (one change to engine_common):**
```python
# engine_common/database.py
def get_connection(tenant_id: str):
    conn = pool.getconn()
    with conn.cursor() as cur:
        cur.execute("SET app.tenant_id = %s", (tenant_id,))
    return conn
```

**Admin/pipeline bypass (background workers process all tenants):**
```sql
-- Background job role bypasses RLS
CREATE ROLE cspm_pipeline;
ALTER ROLE cspm_pipeline BYPASSRLS;

-- OR: use a special admin sentinel value
CREATE POLICY admin_bypass ON threat_findings
    USING (current_setting('app.tenant_id', true) = '__pipeline__');
```

**In pipeline workers:**
```python
# Scan pipeline workers (not tenant-scoped)
conn.cursor().execute("SET app.tenant_id = '__pipeline__'")
```

### Tables to cover (by DB)
- `threat`: threat_findings, threat_report, threat_detections, threat_analysis, threat_intelligence
- `iam`: iam_findings, iam_report
- `datasec`: datasec_findings, datasec_report, data_assets
- `inventory`: inventory_findings, inventory_relationships, inventory_report
- `compliance`: compliance_reports, compliance_findings
- `check`: check_findings, check_report
- `discoveries`: discovery_findings, discovery_report
- `onboarding`: cloud_accounts, scan_orchestration

### Required before
Any paying customer or multi-tenant production use.

---

## 4. SQS Between Pipeline Stages

### Problem
The scan pipeline is fully synchronous REST. The caller must:
- Hold HTTP connections open for 3-4 hour scans (timeout risk)
- Know the correct engine sequence and trigger each manually
- Restart the entire pipeline from scratch if any stage fails
- Manage concurrency manually for multiple simultaneous tenant scans

A discovery crash at hour 3 = 3 hours wasted; must restart from zero.

### Solution
Use SQS queues between pipeline stages. Each engine publishes a completion message
when done. The next engine polls its input queue and starts automatically.
Caller fires one POST and walks away.

### Queue Architecture

```
cspm-scan-trigger         ← cron/UI publishes here to start a scan
cspm-discovery-complete   ← discoveries publishes here when done
cspm-check-complete       ← check publishes here when done
cspm-inventory-complete   ← inventory publishes here when done
cspm-analysis-complete    ← threat/iam/datasec each publish here when done
cspm-dlq                  ← dead letter queue (failed messages after 3 attempts)
```

**For fan-out** (check-complete triggers threat + IAM + datasec in parallel), use SNS → SQS:
```
SNS Topic: cspm-check-complete
    ├──► SQS: cspm-check-complete-threat
    ├──► SQS: cspm-check-complete-iam
    └──► SQS: cspm-check-complete-datasec
```

### Message Format
```json
{
  "orchestration_id": "337a7425-5a53-4664-8569-04c1f0d6abf0",
  "tenant_id": "5a8b072b-8867-4476-a52f-f331b1cbacb3",
  "account_id": "588989875114",
  "provider": "aws",
  "stage": "discovery",
  "status": "completed",
  "scan_id": "d1a2b3c4-...",
  "completed_at": "2026-03-01T10:45:00Z",
  "findings_count": 42000
}
```

### Worker Pattern (add to each engine)
```python
# engine_check/worker.py — runs alongside FastAPI in same pod
import boto3, json, asyncio

sqs = boto3.client("sqs", region_name="ap-south-1")
QUEUE_URL = "https://sqs.ap-south-1.amazonaws.com/588989875114/cspm-discovery-complete"

async def poll_and_trigger():
    while True:
        response = sqs.receive_message(
            QueueUrl=QUEUE_URL,
            MaxNumberOfMessages=5,
            WaitTimeSeconds=20      # long-polling — no cost when queue is empty
        )
        for msg in response.get("Messages", []):
            payload = json.loads(msg["Body"])
            await run_check_scan(orchestration_id=payload["orchestration_id"])
            sqs.delete_message(
                QueueUrl=QUEUE_URL,
                ReceiptHandle=msg["ReceiptHandle"]
            )
        await asyncio.sleep(1)
```

### Publish on completion (add to each engine)
```python
# At end of engine-discoveries scan:
sqs.send_message(
    QueueUrl="https://sqs.../cspm-discovery-complete",
    MessageBody=json.dumps({
        "orchestration_id": orchestration_id,
        "scan_id": scan_id,
        "findings_count": findings_count,
        "completed_at": datetime.utcnow().isoformat()
    })
)
```

### Benefits
| Aspect | Before (sync REST) | After (SQS) |
|--------|-------------------|-------------|
| Stage failure | Restart full pipeline | Retry from failed stage only |
| Multi-tenant concurrency | Manual coordination | N pods × queue (automatic) |
| Failed scan visibility | Silent | DLQ + CloudWatch alarm |
| Scheduled scans | Cron drives full sequence | Cron fires one message |
| New analysis engine | Update orchestrator code | Subscribe to check-complete queue |
| HTTP timeout risk | Real (3-4 hour scan) | None — fire and forget |

### Migration Path (incremental — no big bang)
```
Phase 1 (1 week):   discoveries → check  only — validate pattern
Phase 2 (1 week):   check → [threat, iam, datasec] fan-out via SNS
Phase 3 (optional): inventory in queue, scan-trigger queue for cron
```

### Cost
~$0.01/month at current scan volume (1M SQS requests = $0.40; 1,000 messages/month typical).

---

## 5. OpenTelemetry Observability

### Problem
Structured logs go to CloudWatch but there is no distributed tracing. Debugging a failed
scan across 5 engines requires manually grepping 5 separate log groups by orchestration_id.
No metrics dashboard. No alerting on scan failure. Blind spots everywhere.

### Solution
OpenTelemetry SDK in engine_common — auto-instruments FastAPI, psycopg2, and boto3.
Every HTTP call, DB query, and AWS API call becomes a traced span. Export to AWS X-Ray (tracing)
and CloudWatch Metrics. One-time setup in engine_common; engines add one line each.

### Implementation

**Add to engine_common:**
```python
# engine_common/telemetry.py
from opentelemetry import trace, metrics
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.psycopg2 import Psycopg2Instrumentor
from opentelemetry.instrumentation.boto3 import Boto3Instrumentor

def setup_telemetry(app, engine_name: str):
    provider = TracerProvider()
    provider.add_span_processor(
        BatchSpanProcessor(OTLPSpanExporter(endpoint="http://otel-collector:4317"))
    )
    trace.set_tracer_provider(provider)
    FastAPIInstrumentor.instrument_app(app)   # auto: every HTTP request = span
    Psycopg2Instrumentor().instrument()        # auto: every DB query = span
    Boto3Instrumentor().instrument()           # auto: every AWS API call = span
```

**Each engine — one line:**
```python
# api_server.py (every engine)
from engine_common.telemetry import setup_telemetry
setup_telemetry(app, engine_name="engine-threat")
```

**Custom metrics in engine_common:**
```python
meter = metrics.get_meter("cspm.engine")
scan_duration  = meter.create_histogram("cspm.scan.duration_seconds")
findings_total = meter.create_counter("cspm.findings.total")

# Usage in engines:
findings_total.add(count, {"engine": "threat", "severity": "critical", "tenant": tenant_id})
```

**Deploy OTel Collector in K8s:**
```yaml
# deployment/aws/eks/otel/otel-collector.yaml
# Routes spans → AWS X-Ray
# Routes metrics → CloudWatch Metrics
```

### What you gain
- **X-Ray trace waterfall**: full scan journey across all engines in one view
- **CloudWatch dashboard**: scan duration per tenant, findings by severity over time, error rate
- **Alerting**: CloudWatch alarm on `cspm.scan.errors > 0` → SNS → email/PagerDuty
- **Query**: "show me all scans that failed in threat engine this week" — instant answer

### Cost
AWS X-Ray: $5/million traces recorded (~$2-5/month at current volume).
CloudWatch custom metrics: $0.30/metric/month.

---

## 6. Architectural Debt

### 6a. discovery_findings table partitioning

**Problem**: Single unpartitioned table. At 400k rows per scan × N scans, queries degrade
significantly beyond 10M rows.

**Fix**: PostgreSQL range partitioning by month:
```sql
CREATE TABLE discovery_findings (...) PARTITION BY RANGE (created_at);

CREATE TABLE discovery_findings_2026_03
    PARTITION OF discovery_findings
    FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');

-- Old partitions: drop or archive to S3 after 90 days
```

Apply same pattern to: `check_findings`, `threat_findings`, `iam_findings`, `datasec_findings`.

---

### 6b. Compliance framework endpoint — file to DB

**Problem**: `GET /compliance/api/v1/compliance/framework/{fw}/status` reads S3 NDJSON files
written during scan. Returns 500 when file doesn't exist (new orchestration_id, different scan).

**Fix**: Read from `compliance_findings` table filtered by `framework_id`:
```python
# Replace: open(f"/output/{framework}_report.ndjson")
# With:
cursor.execute(
    """SELECT * FROM compliance_findings
       WHERE framework_id = %s AND compliance_scan_id = %s""",
    (framework_id, compliance_scan_id)
)
```

---

### 6c. Alembic runner in CI/CD

Once Alembic is set up, add to GitHub Actions / deployment pipeline:
```yaml
# .github/workflows/deploy.yml
- name: Run DB migrations
  run: |
    for DB in check compliance discoveries inventory threat iam datasec secops onboarding; do
      DATABASE_URL="postgresql://postgres:${{ secrets.RDS_PASSWORD }}@$RDS_HOST/threat_engine_$DB" \
      alembic upgrade head
    done

- name: Deploy to EKS
  run: kubectl apply -f deployment/aws/eks/engines/
```

Schema is always migrated before new pods start. Never have a pod running against wrong schema.

---

## Implementation Order

```
NOW (before any other work):
  └── Alembic migrations setup (2 days)
       └── Convert existing 013 SQL files to Alembic versions
       └── Add CI/CD pre-deploy step

BEFORE SCALING (next sprint):
  └── PgBouncer deployment (1 day)
       └── Deploy pgbouncer K8s manifest
       └── Update all engine ConfigMaps to point to pgbouncer service

BEFORE FIRST CUSTOMER:
  └── PostgreSQL RLS (3 days)
       └── Write RLS migration for all engine DBs
       └── Update engine_common/database.py to set tenant context
       └── Test: verify cross-tenant query isolation

BEFORE MULTI-TENANT SCALE:
  └── SQS pipeline (1 week)
       └── Phase 1: discoveries → check
       └── Phase 2: check → threat/iam/datasec fan-out
       └── Add DLQ + CloudWatch alarm

AFTER ABOVE:
  └── OpenTelemetry (2 days)
       └── Add engine_common/telemetry.py
       └── Deploy OTel Collector
       └── Wire up X-Ray + CloudWatch dashboard

ONGOING DEBT:
  └── discovery_findings partitioning (when row count > 5M)
  └── Compliance framework endpoint → DB-first
  └── CI/CD migration runner
```

---

## What Is NOT in This Document

- **RDS split into two instances** (discoveries + check on separate instance): deferred.
  Only needed when 10+ tenants run concurrent scans. Significant cost increase.
  Revisit when platform reaches that scale.
