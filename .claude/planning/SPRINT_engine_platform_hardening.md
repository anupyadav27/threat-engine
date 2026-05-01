# Sprint Prompt: Enterprise Engine Platform Hardening
## Pass this file to `bmad-security-po` to generate individual story files

---

## Sprint Objective

Bring every remaining engine to **enterprise CNAPP/CSPM grade** — genuine multi-CSP coverage (AWS, Azure, GCP, OCI, AliCloud, K8s), structured multi-layer analysis, and finding quality matching tools like Wiz, Prisma Cloud, Lacework, and Orca.

Current state: most engines are AWS-heavy with stub implementations for other CSPs. Target: each engine runs its full analysis logic for all 6 providers and produces validated findings per CSP.

---

## Enterprise Benchmark Reference

| Engine | Wiz approach | Prisma approach | Lacework approach | Orca approach | Our target |
|--------|-------------|-----------------|-------------------|--------------|------------|
| DataSec (DSPM) | Graph-based data classification, cross-cloud residency | Agent + agentless classification, DLP policies | Behavioral data access tracking | Agentless snapshot scan, PII detection | 8-module DSPM: classify → encrypt → access → residency → activity → lifecycle → lineage → governance |
| DBSec | Graph: DB exposed paths, encryption posture | Prisma DB Anomaly (agent-based) | DB query behavioral baseline | Snapshot-based DB config scan | 5-pillar: exposure → encryption → auth → activity → compliance |
| Container-Sec | Container graph, image vuln, runtime context | Defender agent: runtime + registry | Behavioral container policies | Agentless image scan | CIS K8s Benchmark layers: image → config → runtime → network → RBAC |
| Risk | Graph risk score, blast radius from graph traversal | Asset risk index (CVE × exposure) | ML anomaly risk score | Crown jewel identification | FAIR model: LEF × LM, regulatory multipliers, Neo4j blast radius |
| AI-Security | AI model exposure, training data risk | AI governance policies | (Limited AI coverage) | (Limited AI coverage) | MITRE ATLAS 5-pillar: model → data → inference → supply chain → governance |
| CNAPP/CWPP | Unified graph, graceful pillar degradation | Unified console, pillar health | Unified platform | Unified agentless | Aggregator with graceful degradation: score=None when pillar unavailable |

---

## Sprint Execution Order

```
Week 1: DataSec (DSPM 8-module, all 6 CSPs)
Week 2: DBSec (5-pillar, per-CSP DB discovery IDs)
Week 3: Container-Sec (CIS K8s layers, all CSPs)
Week 4: Risk (FAIR model, Neo4j blast radius, all CSPs)
Week 5: AI-Security (MITRE ATLAS, all CSPs)
Week 6: CNAPP/CWPP (graceful degradation, unified scoring)
Week 7: Validate full pipeline E2E — all 6 CSPs producing findings
```

Each week: implement → build → push → deploy → test per CSP → move on.

---

## Pre-Sprint Diagnosis (run before implementing each engine)

```sql
-- What findings does the engine currently produce?
-- Run in the engine's DB
SELECT provider, COUNT(*) findings, COUNT(DISTINCT resource_type) rtypes
FROM <engine>_findings
WHERE scan_run_id = '<latest>'
GROUP BY provider ORDER BY findings DESC;

-- Are discovery IDs mapping correctly?
SELECT provider, resource_type, COUNT(*) c
FROM discovery_findings
WHERE scan_run_id = '<latest>'
  AND resource_type IN (<expected_types_for_engine>)
GROUP BY provider, resource_type;
```

If engine returns 0 findings: check (1) discovery ID mapping, (2) rule_discoveries active=true, (3) provider routing in providers/<csp>.py, (4) DB connection using correct DB host env var.

---

## Engine 1: DataSec (DSPM)

**Image:** `yadavanup84/engine-datasec:v-schema-fix3` → target `v-dspm-enterprise`
**Port:** 8003
**DB:** `threat_engine_datasec` → table `datasec_findings`

### Step 0 — Diagnose 0 findings root cause (do this first)
```bash
kubectl logs -f -l app=engine-datasec -n threat-engine-engines --tail=200
kubectl exec -n threat-engine-engines deployment/engine-datasec -- \
  python3 -c "
import os, psycopg2
conn = psycopg2.connect(host=os.environ['DATASEC_DB_HOST'],
  dbname=os.environ['DATASEC_DB_NAME'],
  user=os.environ['DATASEC_DB_USER'],
  password=os.environ['DATASEC_DB_PASSWORD'])
cur = conn.cursor()
cur.execute('SELECT COUNT(*) FROM datasec_findings')
print('findings:', cur.fetchone())
cur.execute('SELECT DISTINCT provider FROM datasec_findings')
print('providers:', cur.fetchall())
"
```

### 8-Module DSPM Architecture

```
Module 1: Data Classification     — identify PII, PHI, financial, confidential by resource type
Module 2: Encryption Posture      — at-rest + in-transit encryption status per resource
Module 3: Access Control Analysis — public access, overly permissive policies, cross-account
Module 4: Data Residency          — region compliance (GDPR EU, HIPAA US, etc.)
Module 5: Data Activity Logging   — audit trail enabled, CloudTrail/Monitor/Audit Logs active
Module 6: Data Lifecycle          — versioning, retention policies, backup enabled
Module 7: Data Lineage            — cross-service data flows (S3→Lambda→RDS patterns)
Module 8: Governance Scoring      — aggregate DSPM score per account/region/provider
```

### Per-CSP Discovery Resource Types

| CSP | Discovery resource_types to scan |
|-----|----------------------------------|
| AWS | `S3::Bucket`, `RDS::DBInstance`, `DynamoDB::Table`, `Redshift::Cluster`, `Glue::Database`, `ElasticSearch::Domain`, `Kinesis::Stream` |
| Azure | `Storage::BlobContainer`, `SQL::Database`, `CosmosDB::Account`, `DataLake::Store`, `Synapse::Workspace`, `KeyVault::Vault` |
| GCP | `Storage::Bucket`, `CloudSQL::Instance`, `BigQuery::Dataset`, `Spanner::Instance`, `Firestore::Database`, `SecretManager::Secret` |
| OCI | `ObjectStorage::Bucket`, `Database::AutonomousDatabase`, `NoSQL::Table`, `Streaming::Stream` |
| AliCloud | `OSS::Bucket`, `RDS::DBInstance`, `PolarDB::Cluster`, `TableStore::Instance`, `MaxCompute::Project` |
| K8s | `ConfigMap` (secrets-in-configmap), `Secret`, `PersistentVolumeClaim`, `StatefulSet` (DB workloads) |

### providers/ file structure
```
engines/datasec/datasec_engine/providers/
├── __init__.py
├── aws.py      # S3, RDS, DynamoDB, Redshift, Glue, ElasticSearch, Kinesis
├── azure.py    # BlobStorage, SQL, CosmosDB, DataLake, Synapse, KeyVault
├── gcp.py      # GCS, CloudSQL, BigQuery, Spanner, Firestore, SecretManager
├── oci.py      # ObjectStorage, AutonomousDB, NoSQL, Streaming
├── alicloud.py # OSS, RDS, PolarDB, TableStore, MaxCompute
└── k8s.py      # Secrets, ConfigMaps, PVCs, StatefulSets
```

### analyze() method contract (each provider must implement)
```python
def analyze(self, scan_run_id: str, tenant_id: str, account_id: str,
            discovery_scan_id: str) -> list[dict]:
    """
    Returns list of findings, each with:
    {
      'finding_id': sha256(rule_id|resource_uid|account|region)[:16],
      'scan_run_id': scan_run_id,
      'tenant_id': tenant_id,
      'account_id': account_id,
      'provider': 'aws',  # or azure/gcp/oci/alicloud/k8s
      'region': str,
      'resource_uid': str,
      'resource_type': str,
      'severity': 'CRITICAL|HIGH|MEDIUM|LOW|INFO',
      'status': 'FAIL|PASS|NOT_APPLICABLE',
      'dspm_module': str,  # which of the 8 modules triggered this
      'classification_labels': list[str],  # ['PII', 'PHI', 'FINANCIAL']
      'encryption_status': str,
      'public_access': bool,
      'blast_radius_score': 0,  # ALWAYS 0 — risk engine owns this
      'first_seen_at': datetime,
      'last_seen_at': datetime,
    }
    """
```

### Image tag progression
`v-schema-fix3` → diagnose 0-findings → `v-dspm-aws` (AWS working) → `v-dspm-multicloud` (all CSPs) → `v-dspm-enterprise` (all 8 modules)

---

## Engine 2: DBSec (Database Security)

**Image:** `yadavanup84/engine-dbsec:v-modular` → target `v-dbsec-enterprise`
**DB:** `threat_engine_database_security` → table `dbsec_findings`

### 5-Pillar DBSec Architecture

```
Pillar 1: Network Exposure    — is DB publicly accessible? IP allowlist? VPC-only?
Pillar 2: Encryption          — at-rest encryption, in-transit TLS, key rotation
Pillar 3: Authentication      — password policies, MFA, IAM auth, default users disabled
Pillar 4: Audit & Activity    — query logging, performance insights, CloudWatch integration
Pillar 5: Compliance Posture  — backup retention ≥7 days, deletion protection, multi-AZ
```

### Per-CSP DB Discovery IDs

| CSP | Primary DB resource_types |
|-----|--------------------------|
| AWS | `RDS::DBInstance`, `RDS::DBCluster`, `Redshift::Cluster`, `DynamoDB::Table`, `ElastiCache::Cluster`, `DocumentDB::Cluster` |
| Azure | `SQL::Server`, `SQL::Database`, `CosmosDB::Account`, `PostgreSQL::Server`, `MySQL::Server`, `MariaDB::Server` |
| GCP | `CloudSQL::Instance`, `Spanner::Instance`, `Bigtable::Instance`, `Firestore::Database`, `Memorystore::Instance` |
| OCI | `Database::DbSystem`, `Database::AutonomousDatabase`, `MySQL::DbSystem`, `NoSQL::Table` |
| AliCloud | `RDS::DBInstance`, `PolarDB::Cluster`, `MongoDB::DBInstance`, `Memcache::Instance` |
| K8s | StatefulSets with labels: `app in (mysql, postgres, redis, mongodb, elasticsearch)` |

### Verification query
```sql
SELECT provider, pillar, severity, COUNT(*) findings
FROM dbsec_findings
WHERE scan_run_id = '<id>'
GROUP BY provider, pillar, severity
ORDER BY provider, findings DESC;
```

---

## Engine 3: Container-Sec

**Image:** `yadavanup84/engine-container-sec:v-modular` → target `v-container-enterprise`
**DB:** `threat_engine_container_security` → table `container_sec_findings`

### CIS Kubernetes Benchmark Layers

```
Layer 1: Control Plane Security   — API server flags, etcd encryption, audit logging
Layer 2: Node Configuration       — kubelet auth, node OS hardening, runtime security
Layer 3: RBAC & Service Accounts  — least-privilege roles, default SA tokens, ClusterRoleBindings
Layer 4: Pod Security Standards   — privileged containers, hostNetwork/hostPID, root containers
Layer 5: Network Policies         — default-deny, ingress/egress policies, CNI config
Layer 6: Secrets Management       — secrets in env vars, external secrets operator, encryption at rest
Layer 7: Image Security           — base image age, known CVEs, image signing, registry policies
```

### Per-CSP Container Discovery IDs

| CSP | Managed K8s resource_types |
|-----|---------------------------|
| AWS | `EKS::Cluster`, `EKS::NodeGroup`, `ECR::Repository` |
| Azure | `ContainerService::ManagedCluster`, `ContainerRegistry::Registry` |
| GCP | `Container::Cluster`, `ArtifactRegistry::Repository` |
| OCI | `ContainerEngine::Cluster`, `Artifacts::ContainerRepository` |
| AliCloud | `ACK::Cluster`, `ACR::Repository` |
| K8s (native) | `Pod`, `Deployment`, `StatefulSet`, `DaemonSet`, `Job`, `CronJob`, `ServiceAccount`, `ClusterRole`, `NetworkPolicy` |

### Key checks per layer (examples)
```python
# Layer 4 — Pod Security
CRITICAL_CHECKS = [
    ('privileged_container', 'spec.containers[*].securityContext.privileged == true'),
    ('host_network', 'spec.hostNetwork == true'),
    ('host_pid', 'spec.hostPID == true'),
    ('root_container', 'spec.containers[*].securityContext.runAsNonRoot != true'),
    ('host_path_volume', 'spec.volumes[*].hostPath exists'),
]
```

---

## Engine 4: Risk

**Image:** `yadavanup84/engine-risk:v-etl-fix` → target `v-risk-enterprise`
**DB:** `threat_engine_risk` → tables `risk_scenarios`, `risk_summary`
**Neo4j:** `neo4j+s://17ec5cbb.databases.neo4j.io` (blast radius traversal)

### FAIR Risk Model Implementation

```
Risk Score = Loss Event Frequency (LEF) × Loss Magnitude (LM)

LEF = Threat Event Frequency (TEF) × Vulnerability (V)
LM  = Primary Loss (PL) × Secondary Loss (SL)

Regulatory multipliers (applied to LM):
- GDPR violation: 4% of global annual turnover cap → multiply by 1.5
- HIPAA violation: $1.9M/violation cap → multiply by 1.3
- PCI-DSS violation: $5-100k/month → multiply by 1.2
- CCPA violation: $7,500/intentional → multiply by 1.1
- SOX violation: criminal penalties → multiply by 1.4
```

### Per-CSP Asset Valuation (for LM calculation)

| CSP | High-value resource types | Base valuation |
|-----|--------------------------|----------------|
| AWS | RDS, Secrets, S3 (sensitive), EKS | 10x multiplier |
| Azure | SQL, KeyVault, AKS, Blob (sensitive) | 10x multiplier |
| GCP | CloudSQL, SecretManager, GKE, BigQuery | 10x multiplier |
| OCI | AutonomousDB, Vault, OKE | 10x multiplier |
| AliCloud | RDS, KMS, ACK, OSS | 10x multiplier |
| K8s | Secrets, privileged Pods, ClusterRoles | 10x multiplier |

### Neo4j blast radius query pattern
```cypher
MATCH path = (source:Resource {resource_uid: $resource_uid})
  -[:EXPOSES|CONNECTS_TO|HAS_ACCESS_TO*1..4]->
  (target:Resource)
WHERE target.sensitivity IN ['HIGH', 'CRITICAL']
RETURN COUNT(DISTINCT target) AS blast_radius,
       COLLECT(DISTINCT target.resource_uid)[..10] AS sample_targets
```

### Risk finding structure
```python
{
  'scenario_type': 'data_exfiltration|lateral_movement|privilege_escalation|denial_of_service',
  'attack_path': list[str],          # resource_uid chain
  'blast_radius_score': int,         # 0-100 — THIS engine owns it (only engine that sets != 0)
  'fair_lef': float,
  'fair_lm': float,
  'fair_risk_score': float,
  'regulatory_flags': list[str],     # ['GDPR', 'HIPAA']
  'mitre_techniques': list[str],     # ['T1190', 'T1078']
}
```

---

## Engine 5: AI-Security

**Image:** `yadavanup84/engine-ai-security:v-modular` → target `v-ai-enterprise`
**DB:** `threat_engine_ai_security` → table `ai_security_findings`
**Framework:** MITRE ATLAS (Adversarial Threat Landscape for AI Systems)

### MITRE ATLAS 5-Pillar Implementation

```
Pillar 1: Model Security         — model access controls, versioning, signing, drift detection
Pillar 2: Training Data Security — data poisoning exposure, training pipeline integrity
Pillar 3: Inference Security     — prompt injection surface, model inversion risk, adversarial inputs
Pillar 4: Supply Chain           — third-party model/dataset provenance, registry security
Pillar 5: AI Governance          — model cards, audit logging, bias monitoring, explainability
```

### Per-CSP AI Service Discovery IDs

| CSP | AI/ML resource_types |
|-----|---------------------|
| AWS | `SageMaker::Model`, `SageMaker::Endpoint`, `SageMaker::NotebookInstance`, `Bedrock::Model`, `Comprehend::*`, `Rekognition::*` |
| Azure | `MachineLearning::Workspace`, `CognitiveServices::Account`, `OpenAI::Account`, `Bot::BotService` |
| GCP | `AIPlatform::Model`, `AIPlatform::Endpoint`, `VertexAI::Dataset`, `AutoML::Model` |
| OCI | `DataScience::Model`, `DataScience::Project`, `AnomalyDetection::Model` |
| AliCloud | `PAI::Workspace`, `MachineLearning::*`, `NLP::*`, `Vision::*` |
| K8s | Deployments with labels: `app in (mlflow, kubeflow, jupyter, ray)`, GPU node workloads |

### MITRE ATLAS technique mappings (sample)
```yaml
AML.T0000: Model Evasion → severity: HIGH → pillar: inference_security
AML.T0001: Data Poisoning → severity: CRITICAL → pillar: training_data_security
AML.T0002: Model Inversion → severity: HIGH → pillar: inference_security
AML.T0003: Model Stealing → severity: MEDIUM → pillar: model_security
AML.T0004: Backdoor ML Model → severity: CRITICAL → pillar: supply_chain
AML.T0005: Poison Training Data → severity: CRITICAL → pillar: training_data_security
```

---

## Engine 6: CNAPP / CWPP (Aggregation Engines)

**CNAPP:** Aggregates: DataSec + DBSec + Container-Sec + Risk + AI-Security + Check + IAM + Network
**CWPP:** Aggregates: Container-Sec + AI-Security (workload-focused subset)

### Graceful Degradation Pattern (CRITICAL)

```python
# WRONG — current behavior: pillar down = score 0 (looks like perfect security)
def compute_cnapp_score(pillars):
    return sum(p['score'] for p in pillars) / len(pillars)

# CORRECT — pillar down = score None → UI shows "N/A" not 0
def compute_cnapp_score(pillars):
    available = [p for p in pillars if p['score'] is not None]
    if not available:
        return None  # All pillars down
    return sum(p['score'] for p in available) / len(available)
    # Also return: {'available_pillars': len(available), 'total_pillars': len(pillars)}
```

### Pillar health check pattern
```python
PILLAR_ENDPOINTS = {
    'datasec':      'http://engine-datasec/api/v1/health/ready',
    'dbsec':        'http://engine-dbsec/api/v1/health/ready',
    'container_sec':'http://engine-container-sec/api/v1/health/ready',
    'risk':         'http://engine-risk/api/v1/health/ready',
    'ai_security':  'http://engine-ai-security/api/v1/health/ready',
    'check':        'http://engine-check-aws/api/v1/health/ready',
    'iam':          'http://engine-iam/api/v1/health/ready',
    'network':      'http://engine-network-security/api/v1/health/ready',
}

async def check_pillar_health() -> dict[str, bool]:
    # Returns {pillar: True/False} — False = unavailable → score=None for that pillar
```

### Unified CNAPP score structure
```json
{
  "overall_score": 62,
  "provider": "aws",
  "scan_run_id": "...",
  "pillars": {
    "cloud_security": {"score": 71, "findings": 234, "source": "check"},
    "network_security": {"score": 58, "findings": 89, "source": "network"},
    "data_security": {"score": null, "findings": null, "source": "datasec", "reason": "engine_unavailable"},
    "identity_security": {"score": 65, "findings": 45, "source": "iam"},
    "workload_security": {"score": 70, "findings": 12, "source": "container_sec"},
    "risk_posture": {"score": 55, "findings": 8, "source": "risk"}
  },
  "available_pillars": 5,
  "total_pillars": 6
}
```

---

## Build, Deploy, Validate Pattern (all engines)

### Build & push
```bash
# From repo root (ALWAYS build from root — Dockerfiles use COPY shared/...)
docker build -t yadavanup84/<engine>:<new-tag> -f engines/<engine>/Dockerfile .
docker push yadavanup84/<engine>:<new-tag>
```

### Deploy
```bash
# Update image tag in manifest
# engines/<engine>/Dockerfile → deployment/aws/eks/engines/engine-<name>.yaml
kubectl apply -f deployment/aws/eks/engines/engine-<name>.yaml
kubectl rollout status deployment/engine-<name> -n threat-engine-engines
kubectl logs -f -l app=engine-<name> -n threat-engine-engines --tail=50
```

### Validate per CSP (run for each of 6 CSPs)
```bash
# Port forward
kubectl port-forward svc/engine-<name> <port>:80 -n threat-engine-engines

# Trigger scan (use Python — curl not available)
python3 -c "
import urllib.request, json
data = json.dumps({'scan_run_id': '<id>', 'csp': 'aws'}).encode()
req = urllib.request.Request('http://localhost:<port>/api/v1/scan',
    data=data, headers={'Content-Type': 'application/json'}, method='POST')
print(urllib.request.urlopen(req).read().decode())
"

# Check findings
kubectl exec -n threat-engine-engines deployment/engine-<name> -- python3 -c "
import os, psycopg2, json
conn = psycopg2.connect(host=os.environ['<ENGINE>_DB_HOST'],
  dbname=os.environ['<ENGINE>_DB_NAME'],
  user=os.environ['<ENGINE>_DB_USER'],
  password=os.environ['<ENGINE>_DB_PASSWORD'])
cur = conn.cursor()
cur.execute('''SELECT provider, severity, COUNT(*) FROM <engine>_findings
               WHERE scan_run_id = %s GROUP BY provider, severity''', ('<scan_run_id>',))
for row in cur.fetchall(): print(row)
"
```

### Acceptance criteria per engine (all must pass before "done")
- [ ] Docker build completes without error
- [ ] `kubectl rollout status` clean
- [ ] Each of 6 CSPs returns > 0 findings (or documented reason why 0 is correct)
- [ ] `finding_id` is unique within scan_run_id (no dedup errors)
- [ ] `blast_radius_score = 0` in all engine findings except Risk engine
- [ ] `tenant_id` filter present on ALL DB queries (multi-tenant isolation)
- [ ] No plaintext credentials in logs
- [ ] `/api/v1/health/ready` returns 200

---

## Security Requirements (apply to all engines)

```python
# 1. ALWAYS filter by tenant_id
cur.execute("SELECT * FROM <engine>_findings WHERE scan_run_id = %s AND tenant_id = %s",
            (scan_run_id, tenant_id))

# 2. finding_id — deduplicate before INSERT
finding_id = hashlib.sha256(f"{rule_id}|{resource_uid}|{account_id}|{region}".encode()).hexdigest()[:16]

# 3. blast_radius_score — only Risk engine sets non-zero; all others hardcode 0
'blast_radius_score': 0  # risk engine owns this

# 4. JSONB — never call json.loads() on psycopg2 JSONB results
# psycopg2 auto-deserializes JSONB → already a dict

# 5. Upsert findings (idempotent — scans can re-run)
INSERT INTO <engine>_findings (...) VALUES (...)
ON CONFLICT (finding_id, scan_run_id) DO UPDATE SET last_seen_at = EXCLUDED.last_seen_at
```

---

## MITRE ATT&CK Mappings for New Finding Types

| Finding type | Technique | Tactic |
|-------------|-----------|--------|
| Public S3 bucket with PII | T1530 (Data from Cloud Storage) | Collection |
| Unencrypted DB | T1486 (Data Encrypted for Impact) | Impact |
| Privileged container | T1611 (Escape to Host) | Privilege Escalation |
| Over-privileged IAM | T1078 (Valid Accounts) | Defense Evasion |
| AI model endpoint public | T1190 (Exploit Public-Facing App) | Initial Access |
| No audit logging | T1562.008 (Impair Defenses: Disable Logging) | Defense Evasion |
| Exposed DB port | T1190 (Exploit Public-Facing App) | Initial Access |
| Secrets in K8s configmap | T1552.007 (Unsecured Credentials: Container) | Credential Access |

---

## Sprint Readiness Checklist (before starting each engine)

1. Read current engine code: `engines/<name>/`
2. Check current image tag in `deployment/aws/eks/engines/engine-<name>.yaml`
3. Run pre-sprint diagnosis SQL (check current findings count per CSP)
4. Check `providers/` subdirectory exists and has per-CSP files
5. Verify DB env vars in K8s manifest match what code reads
6. Identify which discovery resource_types the engine needs (from table above)
7. Confirm latest scan_run_id per CSP (from scan_orchestration or memory/latest_scan_run_ids.md)

---

## Story File Naming Convention

```
ENG-10_datasec_dspm_enterprise.md
ENG-11_dbsec_5pillar_enterprise.md
ENG-12_container_sec_cis_k8s.md
ENG-13_risk_fair_neo4j.md
ENG-14_ai_security_atlas.md
ENG-15_cnapp_graceful_degradation.md
```

Pass sprint prompt file to `bmad-security-po` agent to generate these story files.
Pass story files to `bmad-dev` agent to implement one at a time.
Pass completed story files to `bmad-qa` agent to verify acceptance criteria.

---

## Context for Next Session

- Network engine sprint (SPRINT_network_engine_full_fix.md) runs in parallel with this sprint
- consolidated_services migration (SPRINT_consolidated_services_migration.md) is a prerequisite for datasec/dbsec — ensure engine_common imports work before touching engine code
- Latest scan_run_ids: see `memory/latest_scan_run_ids.md` — refresh from DB each session
- All 6 engines above should produce findings in ALL 6 CSPs — if a CSP has 0 findings, investigate before marking done
- Risk engine is the ONLY engine allowed to set `blast_radius_score != 0`
