# OCI (Oracle Cloud) — Full Stack E2E Plan

## Status
- Credentials: ✗ No account — needs provisioning (oracle.com/cloud/free)
- rule_discoveries in DB: ✓ 164 services (post-sync 2026-04-07)
- Scanner code: Partial stub exists at `engines/discoveries/providers/oci/`
- Check rules: ✗ 0 OCI rules in rule_metadata
- Inventory relationships: ✗ 0 OCI rows in resource_security_relationship_rules
- Compliance frameworks: ✗ No CIS OCI in compliance_frameworks
- Priority: #4 (blocked on credential provisioning)

## Pre-Requisite: Account Setup

1. Create Oracle Cloud account: oracle.com/cloud/free (Always Free includes 2 VMs, Object Storage, autonomous DB)
2. Create IAM user for CSPM scanning: `cspm-scanner`
3. Assign policy: `Allow group CspmGroup to inspect all-resources in tenancy`
4. Generate API signing key: `oci setup keys`
5. Get: Tenancy OCID, User OCID, Key Fingerprint, Private Key, Region
6. Create K8s secret:
   ```bash
   kubectl create secret generic oci-creds -n threat-engine-engines \
     --from-literal=OCI_TENANCY_ID=ocid1.tenancy.oc1... \
     --from-literal=OCI_USER_ID=ocid1.user.oc1... \
     --from-literal=OCI_FINGERPRINT=xx:xx:xx:... \
     --from-literal=OCI_REGION=ap-mumbai-1 \
     --from-file=OCI_KEY_FILE=/path/to/oci_api_key.pem
   ```

---

## Phase 1 — Discovery (Track A)

### Milestone 1.1: OCI Provider Directory

**US-OCI-DISC-01: Provider structure**
- `engines/discoveries/providers/oci/`
- Files: `oci_scanner.py`, `client_factory.py`, `pagination.py`, `requirements.txt`, `Dockerfile`
- Register: `PROVIDER_SCANNERS['oci'] = OCIDiscoveryScanner`

**US-OCI-DISC-02: OCI Authentication**
- Config via `oci.config` dict or `~/.oci/config` file
- API key signing: RSA key pair (not username/password)
- Pattern:
  ```python
  import oci
  config = {
      "tenancy": OCI_TENANCY_ID,
      "user": OCI_USER_ID,
      "fingerprint": OCI_FINGERPRINT,
      "key_file": OCI_KEY_FILE,
      "region": OCI_REGION,
  }
  oci.config.validate_config(config)
  client = oci.core.ComputeClient(config)
  ```
- For instance principal (if scanner runs in OCI): `oci.auth.signers.InstancePrincipalsSecurityTokenSigner`

**US-OCI-DISC-03: Client Factory**

```python
import oci
CLIENT_MAP = {
    'compute':       oci.core.ComputeClient,
    'network':       oci.core.VirtualNetworkClient,
    'identity':      oci.identity.IdentityClient,
    'objectstorage': oci.object_storage.ObjectStorageClient,
    'database':      oci.database.DatabaseClient,
    'kms':           oci.key_management.KmsVaultClient,
    'certificates':  oci.certificates.CertificatesClient,
    'waas':          oci.waas.WaasClient,
    'bastions':      oci.bastion.BastionClient,
    'logging':       oci.logging.LoggingManagementClient,
    'events':        oci.events.EventsClient,
    'ons':           oci.ons.NotificationDataPlaneClient,
    'audit':         oci.audit.AuditClient,
    'monitoring':    oci.monitoring.MonitoringClient,
    'resourcesearch': oci.resource_search.ResourceSearchClient,
    'analytics':     oci.analytics.AnalyticsClient,
    'nosql':         oci.nosql.NosqlClient,
    'mysql':         oci.mysql.DbSystemClient,
    'functions':     oci.functions.FunctionsManagementClient,
    'datacatalog':   oci.data_catalog.DataCatalogClient,
    'streaming':     oci.streaming.StreamAdminClient,
    'apigateway':    oci.apigateway.ApiGatewayClient,
    'containerengine': oci.container_engine.ContainerEngineClient,
    'artifacts':     oci.artifacts.ArtifactsClient,
    'vault':         oci.vault.VaultsClient,
    'secrets':       oci.secrets.SecretsClient,
    'loadbalancer':  oci.load_balancer.LoadBalancerClient,
}
```

**US-OCI-DISC-04: OCI Pagination**
- OCI uses `page` token (similar to AWS `NextToken`)
- SDK handles via `oci.pagination.list_call_get_all_results()`
- Or manual: while `response.has_next_page: response = client.list_*(page=response.next_page)`

**US-OCI-DISC-05: OCI Resource Hierarchy**
- OCI uses **Compartments** (not resource groups or projects)
- Tenancy is root compartment (OCID: `ocid1.tenancy.oc1...`)
- Resources live in compartments — must enumerate all compartments recursively
- Compartment enumeration: `identity.list_compartments(compartment_id=tenancy_id, compartment_id_in_subtree=True)`
- Region: OCI is multi-region, same as AWS/Azure

**resource_uid format:** Use OCI OCID: `ocid1.instance.oc1.ap-mumbai-1.{unique}`

**Noise removal (from 09_NOISE_REMOVAL.md):**
Disable: `audit/events`, `monitoring/metrics`, `usage/reports`, `announcements`, `work-requests`

**Docker:**
- Image: `yadavanup84/engine-discoveries-oci:v1.oci.YYYYMMDD`
- SDK: `oci>=2.120`

---

## Phase 2 — Inventory (Track B)

### Milestone 2.1: OCI Relationship Rules
SQL: INSERT 8 rows (see 07_INVENTORY_RELATIONSHIPS.md).

### Milestone 2.2: OCI Asset Classification
```sql
INSERT INTO service_classification (csp, resource_type, category, subcategory, scope) VALUES
('oci', 'Instance', 'Compute', 'Virtual Machine', 'availability_domain'),
('oci', 'BootVolume', 'Storage', 'Block Storage', 'availability_domain'),
('oci', 'BlockVolume', 'Storage', 'Block Storage', 'availability_domain'),
('oci', 'VCN', 'Network', 'VPC', 'regional'),
('oci', 'Subnet', 'Network', 'Subnet', 'availability_domain'),
('oci', 'Bucket', 'Storage', 'Object Storage', 'namespace'),
('oci', 'DBSystem', 'Database', 'Relational DB', 'availability_domain'),
('oci', 'AutonomousDatabase', 'Database', 'Autonomous DB', 'regional'),
('oci', 'LoadBalancer', 'Network', 'Load Balancer', 'regional'),
('oci', 'Function', 'Compute', 'Serverless', 'regional');
```

---

## Phase 3 — Check Engine (Track C)

### Milestone 3.1: OCI Check Rules

~250 rules covering:

**Compute:**
- Instance: no public IP on sensitive instances
- Instance: disk encryption (in-transit + at-rest)
- Instance: IMDSv1 disabled (only IMDSv2 allowed)
- Boot volume: encryption enabled

**Network:**
- Security list: no inbound allow-all (0.0.0.0/0)
- Security list: RDP/SSH restricted
- VCN: flow logs enabled
- Subnet: private subnet for sensitive workloads
- Network Security Group over Security Lists (preferred)

**Identity/IAM:**
- No API keys older than 90 days
- MFA for all console users
- No API keys for tenancy admin
- IAM policy: least privilege (not `manage all-resources`)
- IAM group: empty groups reviewed

**Object Storage:**
- Bucket: not publicly accessible
- Bucket: versioning enabled
- Bucket: replication for DR
- Bucket: lifecycle policies set
- Bucket: CMEK encryption

**Database:**
- DB system: private subnet
- DB system: backup enabled
- Autonomous DB: access control list set
- Autonomous DB: CMEK

**Audit / Logging:**
- Audit log retention >= 365 days
- Logging enabled for VCN flow logs, Object Storage events
- Events service: notifications for IAM changes

---

## Phase 4 — Threat Engine

### Milestone 4.1: OCI Threat Rules

MITRE for OCI:
- T1078.004 — Valid Accounts: Cloud Accounts (API key theft)
- T1530 — Data from Cloud Storage Object (public bucket)
- T1580 — Cloud Infrastructure Discovery (OCI Resource Search)
- T1190 — Exploit Public-Facing Application

Add `oci_checks` column to `mitre_technique_reference` (schema change from 13_DB_GAPS.md).

### Milestone 4.2: OCI Attack Paths

1. **Public Bucket → Exfiltration**: Bucket (public) → Object → T1530
2. **Overprivileged API Key → Takeover**: User (old API key + manage all-resources policy) → T1078.004
3. **Public Instance → Lateral Movement**: Instance (public IP + open security list) → internal VCN → T1190

---

## Phase 5 — IAM Engine (OCI)

OCI IAM:
- Users, Groups, Policies (compartment-scoped)
- API keys for users
- Federation with IdP (SAML)
- Dynamic Groups (for instances)

Rules: no tenancy admin API keys, no users with full manage access, API key rotation, MFA for all users.
**IAM module name**: `oci_iam`

---

## Phase 6 — DataSec Engine (OCI)

`datasec_data_store_services` has OCI rows. ✓

Rules:
- Object Storage bucket: public access detection
- Autonomous DB: encryption check
- Vault: secrets expiry

---

## Phase 7 — Compliance Engine (OCI)

```sql
INSERT INTO compliance_frameworks (framework_id, name, version, provider, description) VALUES
('cis_oci_1_2', 'CIS Oracle Cloud Infrastructure Foundations Benchmark', '1.2.0', 'oci',
 'CIS Benchmark for OCI security configuration');
```

CIS OCI 1.2 sections:
- 1: Identity and Access Management
- 2: Networking
- 3: Logging and Monitoring
- 4: Storage
- 5: Asset Management (Tags)
- 6: Database Services

---

## Phases 8-9 — API + BFF/UI

Same pattern as Azure/GCP. OCI-specific:
- `?provider=oci&tenancy_id=<ocid>` filter
- Compartment hierarchy in asset browser
- OCI resource type names (Instance, Bucket, VCN)

---

## Milestone Order (after credential setup)

M0: OCI account + API key + K8s secret
M1-M5: Provider directory + auth + client factory + pagination + Docker
M6: DB seeds (relationships + classification + CIS OCI)
M7: OCI rules in rule_metadata
M8: E2E discovery scan
M9: Full pipeline run
M10: API + BFF/UI

**Estimated effort:** 3-4 weeks (after credentials available)