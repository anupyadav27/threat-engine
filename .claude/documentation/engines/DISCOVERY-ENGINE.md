# Discovery Engine — Architecture & Parallel Scanning

> Cloud resource discovery and enumeration engine.
> Last updated: 2026-03-17

---

## Overview

The discovery engine enumerates cloud resources across 40+ AWS services (and 5 other CSPs).
It produces `discovery_findings` rows — one per discovered resource — and a `discovery_report` summary.

- **Port**: 8001
- **Database**: `threat_engine_discoveries`
- **Image**: `yadavanup84/engine-discoveries-aws:v11-multicloud`
- **K8s manifest**: `deployment/aws/eks/engines/engine-discoveries.yaml`

---

## Source Layout

```
engines/discoveries/
├── common/                    # Shared scanning logic
│   ├── api_server.py          # FastAPI app (standard + parallel endpoints)
│   ├── database/
│   │   ├── database_manager.py  # DB writes (discovery_findings, discovery_report)
│   │   └── discovery_reader.py  # Read prior scans
│   ├── models/                # Pydantic models
│   ├── orchestration/
│   │   └── discovery_engine.py  # Main single-pod scan orchestrator
│   └── utils/
│       ├── condition_evaluator.py
│       └── phase_logger.py
├── engine_discoveries_aws/    # AWS-specific provider
│   ├── api_server.py          # AWS entry point (extends common)
│   ├── auth/aws_auth.py       # Credential resolution (Secrets Manager)
│   ├── config/                # scan_config.json, service_list.json
│   └── engine/
│       ├── discovery_engine.py
│       ├── service_scanner.py  # Per-service boto3 scanning
│       └── discovery_helper.py
├── providers/                 # Multi-CSP provider adapters
├── utils/                     # Shared utilities
├── parallel/                  # ── NEW: Parallel scanning ──
│   ├── __init__.py
│   ├── dispatcher.py          # Fan-out: account×region×service → SQS
│   └── worker.py              # Single-task worker (KEDA ScaledJob pods)
├── Dockerfile                 # Main API image
└── Dockerfile.worker          # Lightweight worker image
```

---

## Two Scanning Modes

### Mode 1: Single-Pod (Original)

```
POST /api/v1/discovery
  → BackgroundTasks.add_task(run_scan)
  → 3-level async parallelism inside ONE pod:
      services (semaphore:10) → regions (semaphore:5) → API calls (ThreadPool:100)
  → ~25-40 min for 414 services × 18 regions
```

**Why multi-pod replicas don't help**: The scan runs as a single in-memory background task.
Extra replicas just create idle API servers.

### Mode 2: Parallel Fan-Out (NEW — SQS + KEDA)

```
POST /api/v1/discovery/parallel
  → Dispatcher: enumerate account × enabled_regions × active_services
  → SQS FIFO Queue: ~7,000 messages (1 per service-region combo)
  → KEDA ScaledJob: auto-scales 0→50+ worker pods on spot nodes
  → Each worker: scan 1 service in 1 region → write to DB → ACK message
  → Aggregator: atomic counter in discovery_report.metadata → mark complete
  → ~3-5 min with 50 workers
```

---

## Parallel Architecture Details

### Dispatcher (`parallel/dispatcher.py`)

Entry: `dispatch(orchestration_id, tenant_id, account_id, provider, db_config)`

1. **Get credentials** from onboarding DB (via `cloud_accounts.credential_ref`)
2. **Enumerate enabled regions**: Calls `ec2.describe_regions()` with filter `opt-in-status != not-opted-in`
3. **Get active services**: Reads `rule_discoveries` table where `is_active = TRUE`
4. **Build work items**: `account × region × service` combinations (~7,000 for 1 account × 18 regions × 400+ services)
   - Global services (IAM, Route53, CloudFront, etc.) → only primary region
5. **Publish to SQS**: Batch of 10 messages (SQS limit), FIFO with `MessageGroupId = account_id`
6. **Create scan record**: `discovery_report` row with `metadata.total_tasks` counter

### Worker (`parallel/worker.py`)

Entry: `python -m parallel.worker --once`

1. **Receive** 1 SQS message (long-poll 20s, visibility timeout 300s)
2. **Parse** task: `{account_id, region, service, tenant_id, orchestration_id, credential_ref}`
3. **Scan**: Create boto3 client → call discovery APIs → collect resources
4. **Write**: INSERT into `discovery_findings` (one row per resource)
5. **Progress**: Atomic `jsonb_set(metadata, '{completed_tasks}', completed + 1)` on `discovery_report`
6. **ACK**: Delete SQS message
7. **Exit** (Job completes, pod terminates)

### Progress Tracking

```
GET /api/v1/discovery/parallel/{scan_id}/progress
→ {
    "scan_id": "...",
    "total_tasks": 7452,
    "completed_tasks": 3200,
    "failed_tasks": 12,
    "progress_pct": 42.9,
    "status": "running"
  }
```

---

## Infrastructure Components

### SQS FIFO Queue
- **Name**: `threat-engine-discovery-tasks.fifo`
- **URL**: `https://sqs.ap-south-1.amazonaws.com/588989875114/threat-engine-discovery-tasks.fifo`
- **Config**: ContentBasedDeduplication=false, VisibilityTimeout=300, RetentionPeriod=86400
- **Throughput**: `perMessageGroupId` (high throughput FIFO)

### KEDA ScaledJob
- **Manifest**: `deployment/aws/eks/keda/discovery-worker-scaledjob.yaml`
- **Trigger**: `aws-sqs-queue`, queueLength=1 (1 message = 1 pod)
- **Max replicas**: 50 (configurable)
- **Strategy**: `accurate` (not eager)
- **Pod resources**: 250m CPU / 512Mi memory request; 500m / 1Gi limit
- **Deadline**: 600s (10 min max per task)
- **Retry**: backoffLimit=2

### Spot Node Group
- **Name**: `vulnerability-spot-scanners`
- **Instance types**: t3.2xlarge, m5.2xlarge, c5.2xlarge, m5a.2xlarge, c5a.2xlarge
- **Scaling**: min=0, max=20 (scales to zero)
- **Taint**: `spot-scanner=true:NoSchedule`
- **Labels**: `workload-type=scan`, `node-type=spot`
- **Fits ~30 worker pods per node** (8 vCPU, 32GB)

### Scaling Math

| Workers | Spot Nodes | Time (414 svc × 18 regions) | Cost/scan |
|---------|-----------|------------------------------|-----------|
| 50      | 2         | ~30 min                      | $0.03     |
| 100     | 4         | ~15 min                      | $0.05     |
| 200     | 7         | ~5 min                       | $0.05     |
| 500     | 17        | ~2 min                       | $0.06     |

---

## Database Schema

### `discovery_report`
| Column | Type | Notes |
|--------|------|-------|
| discovery_scan_id | UUID | PK |
| tenant_id | UUID | |
| account_id | VARCHAR | |
| provider | VARCHAR | aws/azure/gcp/... |
| status | VARCHAR | running/completed/failed |
| metadata | JSONB | `{total_tasks, completed_tasks, failed_tasks}` for parallel |
| created_at | TIMESTAMP | |
| completed_at | TIMESTAMP | |

### `discovery_findings`
| Column | Type | Notes |
|--------|------|-------|
| id | SERIAL | PK |
| discovery_scan_id | UUID | FK → discovery_report |
| tenant_id | UUID | |
| service | VARCHAR | e.g. "ec2", "s3" |
| resource_type | VARCHAR | e.g. "instance", "bucket" |
| resource_uid | VARCHAR | ARN or unique identifier |
| region | VARCHAR | |
| configuration | JSONB | Raw API response |
| tags | JSONB | Resource tags |
| account_id | VARCHAR | |
| created_at | TIMESTAMP | |

---

## Global Services

These services are region-independent and only scanned in the primary region (us-east-1):

```python
GLOBAL_SERVICES = {
    "iam", "sts", "organizations", "route53", "route53domains",
    "cloudfront", "waf", "wafv2", "shield", "globalaccelerator",
    "budgets", "ce", "cur", "account", "health", "trustedadvisor",
    "support", "artifact", "pricing"
}
```

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/discovery` | Original single-pod scan (backward compatible) |
| POST | `/api/v1/discovery/parallel` | Parallel fan-out scan via SQS |
| GET | `/api/v1/discovery/parallel/{scan_id}/progress` | Parallel scan progress |
| GET | `/api/v1/discovery/{scan_id}` | Get scan report |
| GET | `/api/v1/discovery/{scan_id}/findings` | Get findings |
| GET | `/health` | Simple health check |
| GET | `/api/v1/health/live` | K8s liveness |
| GET | `/api/v1/health/ready` | K8s readiness (DB ping) |

---

## Deployment Runbook

See: `deployment/aws/eks/keda/DEPLOYMENT-RUNBOOK.md`

Quick steps:
1. Create SQS FIFO queue
2. Update IAM policies (engine-sa + KEDA role)
3. Install KEDA via Helm
4. Build & push worker image: `docker build -t yadavanup84/discovery-worker:v1 -f engines/discoveries/Dockerfile.worker .`
5. Build & push updated API image: `docker build -t yadavanup84/engine-discoveries-aws:v-parallel -f engines/discoveries/Dockerfile .`
6. Apply manifests: `kubectl apply -f deployment/aws/eks/keda/`
7. Trigger: `POST /api/v1/discovery/parallel`

---

## Integration with Pipeline

The discovery engine is Stage 1 in the scan pipeline:

```
Onboarding (creates orchestration_id)
  → POST /api/v1/discovery/parallel {orchestration_id}
    → dispatcher publishes SQS tasks
    → KEDA scales workers
    → workers write to discovery_findings
    → progress counter reaches total_tasks
    → scan status = "completed"
  → Pipeline worker polls progress, then triggers Stage 2 (Check + Inventory)
```

The discovery engine writes `discovery_scan_id` back to `scan_orchestration` table.
Downstream engines (Check, Inventory) read `discovery_scan_id` from orchestration to find their input data.

---

## Credential Resolution

1. Onboarding stores `credential_ref` in `cloud_accounts` (points to AWS Secrets Manager)
2. Discovery reads the secret: `secretsmanager.get_secret_value(SecretId=credential_ref)`
3. Secret contains `{access_key_id, secret_access_key, session_token?}`
4. Worker creates boto3 session with these credentials
5. For assume-role accounts: STS `assume_role()` with the stored role ARN

---

## Troubleshooting

**Workers not scaling**: Check KEDA operator logs (`kubectl logs -n keda -l app=keda-operator`), verify TriggerAuthentication IAM role can read SQS queue attributes.

**Workers failing**: Check `kubectl logs -n threat-engine-engines -l app=discovery-worker`, common issues: missing DB credentials, IAM permission denied, boto3 throttling.

**Progress stuck**: Check SQS dead-letter queue for failed messages. Verify `SQS_VISIBILITY_TIMEOUT` is long enough for slow services.

**Spot nodes not scaling**: Check cluster-autoscaler logs (`kubectl logs -n kube-system -l app=cluster-autoscaler`), verify node group max size.
