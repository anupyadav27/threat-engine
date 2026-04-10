# GCP CSP — Detailed Project Plan

## Context

- **Project:** `cloudsecurityapp-437319` (CloudSecurityApp) — primary test project
- **Account:** `yadav.anup@gmail.com` (active), `anup.yadav@lgtech.in` (secondary)
- **Credentials:** ✅ `gcloud` CLI logged in, ADC available
- **Discovery configs in DB:** 126 (`rule_discoveries WHERE provider='gcp'`)
- **Check rules in DB:** 1,576
- **Scanner current state:** Stub — 4 hardcoded service handlers, doesn't read DB catalog
- **Key scanner file:** `engines/discoveries/providers/gcp/scanner/service_scanner.py` (392 lines)

## Milestone 1: Scanner Foundation

**Goal:** GCP scanner reads from `rule_discoveries` DB, uses google-cloud Python SDKs
with proper pagination and 10s timeout ceiling.

**Estimated effort:** 4-6 days (1 senior Python + GCP SDK engineer)

### User Stories

**US-GCP-01: GCP Client Factory**
- As the discovery engine, I need to instantiate GCP client libraries dynamically for
  any GCP service using service account credentials, so new GCP services require only
  a DB record change.
- **Tasks:**
  - T1: Map `rule_discoveries.service` names to GCP client classes:
    - `compute` → `google.cloud.compute_v1`
    - `iam` → `google.cloud.iam_v1`
    - `storage` → `google.cloud.storage`
    - `bigquery` → `google.cloud.bigquery`
    - `cloudfunctions` → `google.cloud.functions_v1`
    - `cloudrun` → `google.cloud.run_v2`
    - `gke` → `google.cloud.container_v1`
    - `cloudsql` → `google.cloud.sql_v1`
    - (all 126 configured services)
  - T2: Implement `GCPClientFactory.get_client(service, project_id, credentials)`
  - T3: Handle credential types: service_account_key (JSON), workload_identity,
    application_default_credentials
  - T4: Implement request timeout (10s) via `timeout` param on GCP client calls
- **SME:** Python engineer with google-cloud SDK experience

**US-GCP-02: DB Catalog Reader for GCP**
- As the discovery engine, I need to execute GCP API calls defined in `rule_discoveries`
  and handle GCP-specific pagination (`next_page_token`).
- **Tasks:**
  - T1: Implement `run_gcp_discovery(client, action, params, discovery_config)` —
    equivalent of AWS `run_boto_discovery`
  - T2: GCP pagination: most REST APIs use `pageToken` / `nextPageToken` — implement
    consistent paginator wrapper
  - T3: Handle GCP-specific errors: `google.api_core.exceptions.GoogleAPICallError`,
    `PermissionDenied`, `NotFound` → permanent (no retry)
  - T4: Handle GCP projects vs organizations vs folders hierarchy
  - T5: Handle regional vs zonal vs global resources:
    - Global: IAM, DNS, Security Policies, Firewall Rules
    - Regional: Subnets, Cloud SQL, Pub/Sub
    - Zonal: Compute instances, Persistent Disks
- **SME:** Python engineer familiar with GCP REST/gRPC pagination

**US-GCP-03: GCP Region/Zone Enumeration**
- As the discovery engine, I need to enumerate GCP regions and zones where the project
  has resources, so we don't scan 30+ empty regions.
- **Tasks:**
  - T1: Use `compute_v1.RegionsClient.list(project)` to get enabled regions
  - T2: Separately enumerate zones per region
  - T3: Build region→zone mapping for zonal resource scanning
- **SME:** GCP infrastructure engineer

---

## Milestone 2: Noise Removal

**Goal:** Review 126 GCP discovery configs — remove non-security APIs.

**Estimated effort:** 2 days

### User Stories

**US-GCP-04: GCP Noise Audit**
- **Remove (typical GCP noise):**
  - Cloud Billing API (cost data)
  - Cloud Monitoring metrics
  - Cloud Logging log entries (not security events)
  - Error Reporting
  - Cloud Trace
  - Resource Manager tags (metadata only)
  - Cloud Scheduler jobs (unless SSRF risk)
- **Keep (security-relevant):**
  - IAM policy bindings (all resources)
  - Compute firewall rules, security policies
  - VPC networks, subnets, routes
  - GKE cluster config, node pools, RBAC
  - Cloud KMS keys and key rings
  - Secret Manager secrets
  - Cloud Storage bucket IAM + public access
  - BigQuery dataset ACLs
  - Cloud SQL instances (public IP, SSL, auth)
  - CloudRun service account bindings
  - Organization policies
  - VPC Service Controls

---

## Milestone 3: GCP Security Relationships

**Goal:** Define GCP resource security graph in `resource_security_relationship_rules`.

### User Stories

**US-GCP-05: GCP Security Relationships**
- **Key relationships:**
  - GCE Instance → ServiceAccount → IAMRole
  - GCE Instance → Firewall Rule → VPC Network
  - GKE Cluster → NodePool → ServiceAccount
  - CloudFunction → ServiceAccount → IAMRole
  - CloudRun Service → ServiceAccount
  - CloudSQL Instance → VPC Network (private IP)
  - Storage Bucket → IAMPolicy (public access chain)
  - VPC Network → Subnet → Private Google Access
  - BigQuery Dataset → IAMPolicy
  - KMS KeyRing → CryptoKey → Resource (encryption)
  - Project → IAMPolicy → Member (service account / user)

---

## Milestone 4: End-to-End Test

**Goal:** Full GCP pipeline on `cloudsecurityapp-437319` project.

**Tasks:**
- T1: Onboard GCP project via onboarding API (service account JSON)
- T2: Store GCP SA key in K8s secret
- T3: Trigger pipeline with `provider=gcp`
- T4: Verify 100+ resources discovered
- T5: Check CIS GCP Benchmark scoring

## GCP-Specific Technical Notes

- **Resource naming:** `projects/{project}/locations/{region}/resources/{name}`
- **Two API styles:** REST (most services) and gRPC (newer services like CloudRun v2)
- **Org-level vs project-level:** Many security findings require org-level API
  (Organization Policies, Asset Inventory, Security Command Center)
- **GCP Asset Inventory API:** `cloudasset.googleapis.com` — can enumerate ALL resources
  in a project in one call — consider as Phase 2 accelerator
- **Auth:** `google.oauth2.service_account.Credentials` for SA key,
  `google.auth.default()` for ADC
- **Rate limits:** Per-project, per-API quotas (varies widely)
- **Parallel scan:** Per-zone for zonal resources, per-region for regional, per-project for global