# Story PC-ARCH-01: Engine Provider Architecture — How CSP Dispatch Works

## Status: reference (not a dev story — architecture documentation)

## Purpose

This document explains how domain engines dispatch per-CSP analysis. Every dev implementing a gap story MUST read this first.

---

## The Two Provider Patterns

### Pattern A — `analyze()` dispatch (IAM, DataSec, DBSec, AI-Security)

```
run_scan.py
  ↓ reads scan_run_id from args
  ↓ get_orchestration_metadata(scan_run_id) → {tenant_id, provider, account_id, ...}
  ↓ get_provider(provider)  ← factory in providers/__init__.py
  ↓ provider.analyze(scan_run_id, tenant_id, account_id) → List[Finding]
  ↓ save_findings_to_db(findings)
  ↓ write_X_posture_signals(scan_run_id, tenant_id, account_id, provider)
```

The **provider owns the domain analysis**. Each CSP file (aws.py, azure.py, etc.) reads discovery_findings + check_findings for that CSP and applies its own analysis logic. The provider is selected at runtime based on `provider` from orchestration metadata.

### Pattern B — service-list dispatch (Encryption, Container Security)

```
run_scan.py
  ↓ reads scan_run_id from args
  ↓ get_orchestration_metadata(scan_run_id) → {tenant_id, provider, account_id, ...}
  ↓ get_provider(provider)  ← factory returns provider with service lists ONLY
  ↓ disc_reader.load_all_encryption_resources(services=provider.all_services)
  ↓  [run_scan.py itself drives the analysis — not the provider]
  ↓ save_findings_to_db(findings)
```

The **provider only declares which discovery services to load**. The analysis logic lives in `run_scan.py` and is **CSP-agnostic** — it runs the same checks on whatever discovery data was loaded. This is why Encryption and Container Security "work" for all CSPs today — the analysis is generic, not CSP-specific.

**Consequence:** Encryption and Container Security produce the same quality analysis for all CSPs — but that quality is only as deep as what check_findings + generic discovery-field inspection can give. For KMS-specific analysis (key rotation state, imported key material, multi-region keys) you need Pattern A.

---

## Provider Factory Pattern (Pattern A engines)

```python
# providers/__init__.py  — identical structure across all Pattern A engines
def get_provider(provider_name: str) -> BaseXProvider:
    name = (provider_name or "aws").lower()
    if name == "aws":
        from .aws import AWSXProvider; return AWSXProvider()
    if name == "azure":
        from .azure import AzureXProvider; return AzureXProvider()
    # ... etc
    logger.warning(f"Unknown provider '{provider_name}', returning stub")
    return _StubXProvider()
```

**For Pattern B engines**, the factory does the same but the returned object only needs to define properties (service lists), not `analyze()`.

---

## Full Engine × CSP Provider Status Matrix

### IAM Engine — Pattern A (analyze() per CSP)

| CSP | Status | What analyze() does |
|-----|--------|---------------------|
| AWS | ✅ FULL | Parses managed + inline + trust policies; admin access; cross-account trust; writes iam_policy_statements |
| Azure | ✅ FULL | RBAC role assignments, guest accounts, Owner/Contributor at subscription scope |
| GCP | ✅ FULL | Primitive roles (owner/editor), public principals (allUsers), SA admin rights |
| OCI | ✅ FULL | MFA enforcement, broad policies, admin group membership, API key rotation |
| K8s | ✅ FULL | ClusterAdmin bindings, wildcard roles, default ServiceAccount usage |
| AliCloud | ❌ STUB | Returns empty. Should cover: RAM user/role/policy over-permission, AccessKey rotation |
| IBM | ❌ STUB | Returns empty. Should cover: Service IDs, API key rotation, IAM conditions |

### DataSec Engine — Pattern A (analyze() per CSP)

| CSP | Status | What analyze() does |
|-----|--------|---------------------|
| AWS | ✅ FULL | 8-module DSPM on S3, RDS, DynamoDB, Redshift, Glue, ElasticSearch, Kinesis |
| Azure | ✅ FULL | 8-module DSPM on Blob, SQL, CosmosDB, DataLake, Synapse, KeyVault |
| GCP | ✅ FULL | 8-module DSPM on Storage, CloudSQL, BigQuery, Spanner, Firestore, SecretManager |
| OCI | ✅ FULL | 8-module DSPM on Object Storage, AutonomousDB, NoSQL, Streams |
| K8s | ✅ FULL | 8-module on ConfigMaps, Secrets, PVCs, StatefulSets (credential detection) |
| AliCloud | ✅ FULL | 8-module on OSS, RDS, PolarDB, TableStore, MaxCompute |
| IBM | ⚠️ PARTIAL | Service definitions only — no analyze() method. Should cover: COS, Db2, Cloudant, Event Streams |

### Encryption Security Engine — Pattern B (service-list only; run_scan.py drives analysis)

| CSP | Status | Service list defined | CSP-specific gaps |
|-----|--------|--------------------|-------------------|
| AWS | ⚠️ PARTIAL | KMS, CloudHSM, ACM, ACM-PCA, SecretsManager, SSM | KMS rotation policy logic, imported key material detection |
| Azure | ⚠️ PARTIAL | KeyVault (keys/certs/secrets), ManagedIdentity, DiskEncryption | Key vault soft-delete/purge-protection, cert auto-renewal |
| GCP | ⚠️ PARTIAL | CloudKMS, CertificateManager, SecretManager | KMS key rotation schedule, CMEK enforcement per service |
| OCI | ⚠️ PARTIAL | Vault, KMS, Certificates | OCI Vault key version rotation, HSM-backed vs software keys |
| K8s | ⚠️ PARTIAL | Secrets, cert-manager Certificates, CertificateRequests | etcd encryption at rest, Sealed Secrets usage |
| AliCloud | ⚠️ PARTIAL | KMS, CAS (Certificate Authority Service) | KMS key rotation period, CAS certificate auto-renewal |
| IBM | ⚠️ PARTIAL | KeyProtect, HPCS, CertificateManager, SecretsManager | KeyProtect rotation policy, HPCS HSM attestation |

**The Pattern B gap:** No CSP has a deep encryption analyze() — all rely on check_findings. To get cert expiry days, KMS rotation state, TLS version from actual resource data, each CSP needs analyze() added.

### DBSec Engine — Pattern A (analyze() per CSP)

| CSP | Status | What analyze() does |
|-----|--------|---------------------|
| AWS | ✅ FULL | 5-pillar on RDS, Aurora, Redshift, DynamoDB, ElastiCache, Glue, Keyspaces |
| Azure | ✅ FULL | 5-pillar on SQL Server/DB, CosmosDB, PostgreSQL, MySQL, MariaDB, Storage, KeyVault |
| GCP | ✅ FULL | 5-pillar on CloudSQL, Spanner, Bigtable, Firestore, Memorystore, BigQuery, SecretManager |
| OCI | ✅ FULL | 5-pillar on DbSystem, AutonomousDB, MySQL, NoSQL, Object Storage |
| K8s | ✅ FULL | 5-pillar on DB workloads (Pods/Services/StatefulSets, credential detection in Secrets) |
| AliCloud | ✅ FULL | 5-pillar on RDS, PolarDB, MongoDB, Memcache with KMS, RAM, VPC |
| IBM | ❌ MISSING | No ibm.py file. Should cover: IBM Cloud Databases, Db2, Cloudant (5-pillar) |

### Container Security Engine — Pattern B (service-list only; run_scan.py drives analysis)

| CSP | Status | Service list defined | CSP-specific gaps |
|-----|--------|--------------------|-------------------|
| AWS | ⚠️ PARTIAL | EKS, ECS, ECR, Fargate, Batch, Lambda | EKS node group AMI age, ECR scan-on-push, Fargate task isolation |
| Azure | ⚠️ PARTIAL | AKS, Container Registry, Container Instances, Container Service | AKS RBAC integration, ACR geo-replication security |
| GCP | ⚠️ PARTIAL | GKE, Artifact Registry, Cloud Run | GKE binary authorization, Workload Identity |
| OCI | ⚠️ PARTIAL | OKE, Artifacts | OKE node pool security, OCI Registry vulnerability scanning |
| K8s | ⚠️ PARTIAL | Pods, Deployments, DaemonSets, StatefulSets, Namespaces, ServiceAccounts, Roles, NetworkPolicies | No runtime analysis, no image digest pinning check |
| AliCloud | ⚠️ PARTIAL | CS (Container Service), ACR | ACR security scanning, CS managed node security |
| IBM | ⚠️ PARTIAL | Kubernetes Service, Container Registry | IKS node pool security, ICR vulnerability scanning |

### AI Security Engine — Pattern A (analyze() per CSP)

| CSP | Status | What analyze() does |
|-----|--------|---------------------|
| AWS | ✅ FULL | 5-pillar MITRE ATLAS on SageMaker (notebooks, domains, training jobs, endpoints, models), Bedrock, Comprehend |
| Azure | ✅ FULL | 5-pillar ATLAS on ML Workspaces, CognitiveServices, OpenAI, Bot Services |
| GCP | ✅ FULL | 5-pillar ATLAS on Vertex AI, AI Platform Models/Endpoints, AutoML, Notebooks |
| OCI | ✅ FULL | 5-pillar ATLAS on DataScience (Models/Projects), AnomalyDetection |
| K8s | ✅ FULL | 5-pillar ATLAS on ML workloads (MLflow, Kubeflow, Jupyter, Ray, PyTorch, KServe) |
| AliCloud | ✅ FULL | 5-pillar ATLAS on PAI Workspace, ML Jobs, NLP/Vision Models |
| IBM | ⚠️ PARTIAL | Service definitions only — no analyze(). Should cover: Watson Studio, Watson ML, NLU |

### Vulnerability Engine — No Providers Pattern

| CSP | Status | Notes |
|-----|--------|-------|
| AWS | ✅ Agent-based | SBOM via agent on EC2/Lambda, CVE match, EPSS, DAST |
| Azure | ⚠️ Partial | Agent support limited |
| GCP | ⚠️ Partial | Agent support limited |
| OCI | ❌ Not started | No agent deployment for OCI workloads |
| K8s | ✅ Image scan | ECR/ACR scan results + in-cluster agent |
| AliCloud | ❌ Not started | No agent deployment |
| IBM | ❌ Not started | No agent deployment |

The vulnerability engine uses **agent-based scanning** (not a providers/ pattern) — the agent runs on the VM/container and sends results to the engine. Different architecture entirely.

---

## Orchestration Flow (complete)

```
Argo Workflow (cspm-pipeline.yaml)
  stage 5 (parallel):
    ├── IAM job     → engine-iam pod      → run_scan.py → get_provider(provider) → AWSIAMProvider.analyze()
    ├── DataSec job → engine-datasec pod  → run_scan.py → get_provider(provider) → AWSDataSecProvider.analyze()
    ├── Network job → engine-network pod  → run_scan.py → get_provider(provider) → AWSNetworkProvider.analyze()
    ├── Encrypt job → engine-encryption pod → run_scan.py → get_provider(provider) → AWSEncryptionProvider.service_list → generic analysis
    ├── DBSec job   → engine-dbsec pod    → run_scan.py → get_provider(provider) → AWSDBSecProvider.analyze()
    ├── Container job → engine-container pod → run_scan.py → get_provider(provider) → AWSContainerProvider.service_list → generic analysis
    ├── AI-Sec job  → engine-ai-security pod → run_scan.py → get_provider(provider) → AWSSAISecProvider.analyze()
    └── CDR (separate cron) → engine-cdr pod → own pipeline
  stage 5.end (all above finish):
    each engine calls write_X_posture_signals() → resource_security_posture (merged row)
  stage 6.5:
    attack-path engine reads merged posture → BFS → crown jewel scoring
  stage 7:
    risk engine reads posture + composite flags → FAIR exposure
```

**Key:** `get_orchestration_metadata(scan_run_id)` reads `scan_orchestration` table which has `provider` field. Every engine uses the same scan_run_id and the same provider. No engine hardcodes the CSP.

---

## Gap Priority (what to implement next)

### Highest ROI (Pattern A stubs → full analyze())

| Story | Engine | CSP | Effort | Impact |
|-------|--------|-----|--------|--------|
| PC-GAP-01 | IAM | AliCloud | 3 pts | RAM policy analysis |
| PC-GAP-01 | IAM | IBM | 3 pts | Service ID + API key rotation |
| PC-GAP-02 | DataSec | IBM | 3 pts | COS + Db2 + Cloudant DSPM |
| PC-GAP-03 | AI-Security | IBM | 3 pts | Watson Studio + Watson ML |
| PC-GAP-04 | DBSec | IBM | 4 pts | ibm.py creation (5-pillar) |

### Medium ROI (Pattern B → Pattern A upgrade for deepest analysis)

| Story | Engine | CSPs | Effort | Impact |
|-------|--------|------|--------|--------|
| PC-GAP-05 | Encryption | AWS (first, then others) | 5 pts per CSP | KMS rotation, cert expiry from actual API |
| PC-GAP-06 | Container | K8s (first) | 5 pts | Runtime workload analysis, image pinning |

### Lower ROI (Pattern B stays; check rules close the gap cheaper)

| Item | Why lower priority |
|------|-------------------|
| Container Pattern B → A for AWS/Azure/GCP | Check rules already cover most findings; analyze() adds marginal value vs effort |
| Encryption Pattern B → A for non-AWS | Non-AWS KMS APIs vary widely; check rules catch 80% of issues |
