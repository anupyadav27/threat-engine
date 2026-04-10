# GCP — Full Stack E2E Plan

## Status
- Credentials: ✓ `gcloud auth` active, project cloudsecurityapp-437319 (switch needed: `gcloud config set project cloudsecurityapp-437319`)
- rule_discoveries in DB: ✓ 286 services (post-sync 2026-04-07)
- Scanner code: ✗ No provider directory — must be created
- Check rules: ✗ 0 GCP rules in rule_metadata
- Inventory relationships: ✗ 0 GCP rows in resource_security_relationship_rules
- Compliance frameworks: ✗ No CIS GCP in compliance_frameworks
- Priority: #2 (credentials available)

---

## Phase 1 — Discovery (Track A)

### Milestone 1.1: GCP Provider Directory Bootstrap

**US-GCP-DISC-01: Provider structure**
- Create `engines/discoveries/providers/gcp/`
- Files:
  - `__init__.py`
  - `gcp_scanner.py` — GCPDiscoveryScanner class
  - `client_factory.py` — GCPClientFactory
  - `pagination.py` — GCP pagination helpers
  - `requirements.txt`
  - `Dockerfile`
- Register in `run_scan.py`: `PROVIDER_SCANNERS['gcp'] = GCPDiscoveryScanner`

**US-GCP-DISC-02: GCP Authentication**
- Auth: `google.oauth2.service_account.Credentials` from JSON key file
- OR: `google.auth.default()` for Application Default Credentials (ADC)
- Env var: `GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa-key.json`
- Scopes required: `https://www.googleapis.com/auth/cloud-platform`
- For EKS deployment: store service account JSON in K8s secret `gcp-creds`

**US-GCP-DISC-03: Client Factory**

GCP has two SDK patterns — choose per service:

```python
# Pattern A: google-cloud-* libraries (preferred)
from google.cloud import compute_v1, storage, container_v1
CLIENT_MAP_LIBRARY = {
    'compute':          compute_v1.InstancesClient,
    'storage':          storage.Client,
    'container':        container_v1.ClusterManagerClient,
    'iam':              iam_admin_v1.IAMClient,
    'cloudkms':         kms_v1.KeyManagementServiceClient,
    'secretmanager':    secretmanager_v1.SecretManagerServiceClient,
    'run':              run_v2.ServicesClient,
    'cloudfunctions':   functions_v1.CloudFunctionsServiceClient,
    'sqladmin':         None,  # REST API via discovery
    'dns':              None,  # REST API via discovery
    'bigquery':         bigquery.Client,
    'pubsub':           pubsub_v1.SubscriberClient,
    'logging':          logging_v2.Client,
    'monitoring':       monitoring_v3.MetricServiceClient,
    'cloudresourcemanager': resourcemanager_v3.ProjectsClient,
}

# Pattern B: google-api-python-client (for services without library)
from googleapiclient.discovery import build
CLIENT_MAP_API = {
    'sqladmin':   build('sqladmin', 'v1'),
    'dns':        build('dns', 'v1'),
    'cloudscheduler': build('cloudscheduler', 'v1'),
    'artifactregistry': build('artifactregistry', 'v1'),
}
```

**US-GCP-DISC-04: GCP Pagination**

GCP uses different patterns per client type:
- Library clients: `list()` returns pager objects → `for page in pager: for item in page`
- API clients: `pageToken` in response → pass to next request

```python
def gcp_paginate_library(pager) -> List[dict]:
    """Paginate google-cloud-* library responses."""
    results = []
    for item in pager:
        results.append(type(item).to_dict(item))
    return results

def gcp_paginate_api(method, **kwargs) -> List[dict]:
    """Paginate googleapiclient responses via nextPageToken."""
    results, page_token = [], None
    while True:
        resp = method(**kwargs, pageToken=page_token).execute()
        results.extend(resp.get('items', []))
        page_token = resp.get('nextPageToken')
        if not page_token:
            break
    return results
```

**US-GCP-DISC-05: Resource Type Normalization**
- GCP uses long type names: normalize to short form for `resource_type`
  - Compute instance → `GCEInstance`
  - Cloud SQL instance → `CloudSQLInstance`
  - GCS bucket → `GCSBucket`
  - GKE cluster → `GKECluster`
  - Cloud Function → `CloudFunction`
  - Cloud Run service → `CloudRunService`
  - KMS key ring → `KMSKeyRing`
  - BigQuery dataset → `BigQueryDataset`

**US-GCP-DISC-06: resource_uid format**
- Use GCP's self_link or name: `//compute.googleapis.com/projects/{proj}/zones/{zone}/instances/{name}`
- Alternative (shorter): `projects/{project}/zones/{zone}/instances/{name}`
- Use GCP Cloud Asset Inventory format as canonical: `//serviceaccount.googleapis.com/projects/-/serviceAccounts/{email}`

**US-GCP-DISC-07: Project vs Region enumeration**
- GCP is project-scoped (not account-scoped like AWS)
- Regions: `us-central1`, `us-east1`, `europe-west1`, `asia-east1`, etc.
- Zonal resources: need zone iteration within each region
- Multi-project support: list projects via `resourcemanager.projects.list()`
- For single-project mode: use `GOOGLE_CLOUD_PROJECT` env var

**Noise removal (from 09_NOISE_REMOVAL.md):**
- Disable in rule_discoveries WHERE provider='gcp' AND service IN:
  - `monitoring` (time series metrics — not resources)
  - `logging/entries` (log entries — not config)
  - `clouderrorreporting`, `cloudtrace`, `cloudprofiler` (observability, not security)
  - `cloudbilling` (unless budget alerts needed)

**Docker:**
- Image: `yadavanup84/engine-discoveries-gcp:v1.gcp.YYYYMMDD`
- SDK packages: `google-cloud-compute`, `google-cloud-storage`, `google-cloud-container`, `google-cloud-iam`, `google-cloud-kms`, `google-cloud-secret-manager`, `google-cloud-run`, `google-cloud-functions`, `google-cloud-bigquery`, `google-cloud-dns`, `google-cloud-pubsub`, `google-api-python-client`, `google-auth`

**K8s Secret:**
```bash
kubectl create secret generic gcp-creds -n threat-engine-engines \
  --from-file=service-account.json=/path/to/sa-key.json
# Scanner reads: GOOGLE_APPLICATION_CREDENTIALS=/var/secrets/gcp/service-account.json
```

---

## Phase 2 — Inventory (Track B)

### Milestone 2.1: GCP Relationship Rules

SQL: INSERT 13 rows into `resource_security_relationship_rules` (see 07_INVENTORY_RELATIONSHIPS.md).

### Milestone 2.2: GCP Asset Classification

```sql
INSERT INTO service_classification (csp, resource_type, category, subcategory, scope) VALUES
('gcp', 'GCEInstance', 'Compute', 'Virtual Machine', 'zonal'),
('gcp', 'CloudSQLInstance', 'Database', 'Relational DB', 'regional'),
('gcp', 'GCSBucket', 'Storage', 'Object Storage', 'multi-regional'),
('gcp', 'GKECluster', 'Container', 'Kubernetes', 'regional'),
('gcp', 'CloudFunction', 'Compute', 'Serverless', 'regional'),
('gcp', 'CloudRunService', 'Compute', 'Serverless Container', 'regional'),
('gcp', 'VPCNetwork', 'Network', 'VPC', 'global'),
('gcp', 'KMSKeyRing', 'Security', 'Key Management', 'regional'),
('gcp', 'BigQueryDataset', 'Analytics', 'Data Warehouse', 'regional'),
('gcp', 'PubSubTopic', 'Messaging', 'Message Queue', 'regional'),
('gcp', 'CloudSpanner', 'Database', 'NewSQL', 'regional'),
('gcp', 'ArtifactRegistry', 'Container', 'Registry', 'regional'),
('gcp', 'Firewall', 'Network', 'Firewall Rule', 'global');
```

### Milestone 2.3: GCP Asset Inventory API Accelerator

GCP has **Cloud Asset Inventory API** — lists ALL resources in a project with type and metadata.
This is a significant accelerator vs. querying each service individually:

```python
from google.cloud import asset_v1
client = asset_v1.AssetServiceClient()
# List all resources of all types in a project
response = client.list_assets(
    request=asset_v1.ListAssetsRequest(
        parent=f"projects/{project_id}",
        asset_types=[],  # empty = all types
        content_type=asset_v1.ContentType.RESOURCE,
    )
)
```

Use Asset Inventory for initial enumeration, then query service-specific APIs for security details.

---

## Phase 3 — Check Engine (Track C)

### Milestone 3.1: GCP Check Rules

`rule_metadata` entries for ~500 GCP rules:

**Compute (GCEInstance, Firewall):**
- VM instances: no default service account with broad scopes
- VM instances: project-wide SSH keys disabled
- VM instances: serial port access disabled
- VM instances: full API access scope not used
- VM instances: disk encryption with CMEK
- VM instances: shielded VM enabled (Secure Boot, vTPM, Integrity Monitoring)
- Firewall: no allow-all from internet (0.0.0.0/0 for port 22/3389)
- Firewall: no wildcard ingress rules
- Firewall: no ingress rules with source range 0.0.0.0/0 on privileged ports
- Default network: custom VPC should be used (not default)

**Storage (GCSBucket):**
- Bucket uniform bucket-level access enabled
- Bucket public access prevention enforced
- Bucket logging enabled
- Bucket versioning enabled for sensitive data
- Bucket CMEK encryption
- Bucket not allUsers/allAuthenticatedUsers accessible
- Bucket retention policy set

**IAM (ServiceAccount, IAMPolicy):**
- No service account keys older than 90 days
- No service accounts with admin roles at project level
- No user accounts as service account keys
- No primitive roles (owner/editor/viewer) assigned to users
- Service account with roles/owner → critical finding
- Workload Identity used instead of service account keys

**Cloud SQL:**
- Cloud SQL: no public IP
- Cloud SQL: SSL required
- Cloud SQL: automated backups enabled
- Cloud SQL: point-in-time recovery enabled
- Cloud SQL: authorized networks restricted
- Cloud SQL: PostgreSQL: log_checkpoints, log_connections, log_disconnections on

**GKE:**
- GKE: private cluster enabled
- GKE: master authorized networks enabled
- GKE: Workload Identity enabled
- GKE: Binary Authorization enabled
- GKE: network policy enabled
- GKE: intranode visibility enabled
- GKE: shielded nodes enabled
- GKE: auto-upgrade enabled
- GKE: logging/monitoring enabled

**KMS:**
- KMS: key rotation period <= 90 days
- KMS: keys accessible to allUsers → critical

**BigQuery:**
- Dataset: not publicly accessible
- Dataset: CMEK encryption
- Dataset: no allUsers access

**Logging / Monitoring:**
- Log sink for admin activity exists
- Log metric + alert for project ownership changes
- Log metric + alert for custom role changes
- Log metric + alert for VPC firewall changes
- Log metric + alert for Cloud Storage IAM changes

### Milestone 3.2: GCP Check Engine

Similar to Azure — need `engine_check_gcp/` provider directory.
Reads `discovery_findings WHERE provider='gcp'` + `rule_metadata WHERE provider='gcp'`.

---

## Phase 4 — Threat Engine

### Milestone 4.1: GCP Threat Rules

MITRE techniques for GCP:
- T1078.004 — Valid Accounts: Cloud Accounts (service account key theft)
- T1537 — Transfer Data to Cloud Account (GCS exfiltration)
- T1530 — Data from Cloud Storage Object (public bucket access)
- T1580 — Cloud Infrastructure Discovery (Asset Inventory API)
- T1619 — Cloud Storage Object Discovery
- T1190 — Exploit Public-Facing Application (Cloud Run, App Engine)
- T1098.001 — Account Manipulation (IAM policy change)
- T1552.005 — Unsecured Credentials: Cloud Instance Metadata API (metadata server access)

Update `mitre_technique_reference.gcp_checks` per technique.

### Milestone 4.2: GCP Attack Paths

1. **Public GCS → Data Exfiltration**: GCSBucket (allUsers) → sensitive data → T1530
2. **Overprivileged SA → Privilege Escalation**: ServiceAccount (owner) → Project → T1078.004
3. **GCE Metadata Server → SA Takeover**: GCEInstance (default SA + broad scopes) → metadata API → T1552.005
4. **Default SA → Project-wide Access**: GCEInstance (default SA) → Project (editor) → all resources

### Milestone 4.3: Blast Radius (GCP)

- Compromised VPC → all subnets → all instances in those subnets
- Compromised project-level owner SA → all resources in project
- Compromised GCS bucket → all objects (data store)

---

## Phase 5 — IAM Engine (GCP)

### Milestone 5.1: GCP IAM Rules

`rule_metadata` entries for GCP IAM (provider='gcp', iam_modules includes 'gcp_iam'):

- No service account keys for human users
- No service accounts with project owner role
- No primitive roles (Owner/Editor/Viewer) assigned directly
- Service account key age > 90 days
- Service accounts not enabled for all APIs
- No cross-project service account impersonation abuse
- Workload Identity: prefer over SA keys for GKE
- Custom roles: review permissions quarterly
- Org policies: require OS Login, disable VM external IP

**IAM module name**: `gcp_iam`

---

## Phase 6 — DataSec Engine (GCP)

### Milestone 6.1: GCP DataSec

`datasec_data_store_services` has GCP rows (storage, bigquery, firestore, etc.). ✓

DataSec rules:
- Cloud Storage: detect public buckets with sensitive data
- BigQuery: detect datasets with allUsers access
- Cloud SQL: detect unencrypted databases
- Firestore: detect open rules

---

## Phase 7 — Compliance Engine (GCP)

### Milestone 7.1: CIS GCP 1.3 Framework

```sql
INSERT INTO compliance_frameworks (framework_id, name, version, provider, description) VALUES
('cis_gcp_1_3', 'CIS Google Cloud Platform Foundation Benchmark', '1.3.0', 'gcp',
 'CIS Benchmark for GCP security configuration'),
('gcp_security_foundations', 'Google Cloud Security Foundations Blueprint', '2.0', 'gcp',
 'Google Security Foundations recommendations');
```

CIS GCP 1.3 sections:
- Section 1: IAM (1.1-1.17)
- Section 2: Logging and Monitoring (2.1-2.16)
- Section 3: Networking (3.1-3.10)
- Section 4: Virtual Machines (4.1-4.11)
- Section 5: Storage (5.1-5.3)
- Section 6: Cloud SQL (6.1-6.7)
- Section 7: BigQuery (7.1-7.2)

---

## Phase 8 — API Layer

Same pattern as Azure (see 14_AZURE_E2E_PLAN.md Phase 8):
- All endpoints support `?provider=gcp`
- GCP-specific: `?project_id=cloudsecurityapp-437319` filter
- Region names: `us-central1`, not AWS-style
- Resource types: GCEInstance, CloudSQLInstance, etc.

**GCP-specific summary endpoint:**
```json
{
  "provider": "gcp",
  "project_id": "cloudsecurityapp-437319",
  "last_scan": "...",
  "compliance_score": 68,
  "frameworks": [{"cis_gcp_1_3": {"score": 65, "controls_passed": 48}}]
}
```

---

## Phase 9 — BFF / UI

Same pattern as Azure (see 14_AZURE_E2E_PLAN.md Phase 9):
- GCP icons and resource names in asset list
- IAM page: show GCP IAM terminology (Service Accounts, Workload Identity, IAM Bindings)
- Compliance page: CIS GCP 1.3 framework
- Threat page: GCP-specific MITRE techniques
- Region display: GCP region names

---

## Milestone Order & Dependencies

Same as Azure but GCP-specific:
M1-M6: Provider bootstrap + auth + client factory + pagination + noise removal + Docker
M7: E2E discovery scan with GCP service account
M8: Inventory pipeline + GCP relationships + classification seeded
M9: Check engine with GCP rules
M10: Threat + IAM + DataSec + Compliance
M11: API provider filters
M12: BFF/UI GCP labels

**Estimated effort:** 3-4 weeks (leverages Azure work as template; GCP SDK is cleaner)

## GCP vs Azure Differences (Technical Notes)

| Aspect | Azure | GCP |
|--------|-------|-----|
| Auth | ClientSecretCredential (SP) | ServiceAccount JSON / ADC |
| Pagination | ItemPaged iterator | pageToken + pager objects |
| Resource hierarchy | Subscription > RG > Resource | Org > Folder > Project > Resource |
| Resource ID | /subscriptions/.../resourceId | self_link or name |
| Regions | eastus, westeurope | us-central1, europe-west1 |
| IAM model | RBAC (role assignments) | IAM bindings (member+role+resource) |
| K8s SDK | azure-mgmt-containerservice | google-cloud-container |
| Accelerator | None | Cloud Asset Inventory API |
