# Story PC-GAP-02: DataSec Engine — IBM Cloud analyze() Implementation

## Status: done

## Metadata
- **Phase**: CSP Coverage Track — Provider Gap Closure
- **Sprint**: Posture Coverage Enhancement
- **Points**: 3
- **Priority**: P1 — Highest ROI (Pattern A partial → full analyze())
- **Depends on**: None (datasec engine has Pattern A architecture; IBM provider exists but has no analyze())
- **RACI**: R=DEV A=DL C=SA I=PO,QA
- **Security Gate**: bmad-security-po + bmad-security-reviewer

## Gap Being Closed

`engines/datasec/data_security_engine/providers/ibm.py` has **service definitions only** — it defines the list of IBM Cloud data services (COS, Db2, Cloudant, Event Streams) but has **no `analyze()` method**.

Current state (confirmed):
- AWS DataSec: ✅ 8-module DSPM on S3, RDS, DynamoDB, Redshift, Glue, ElasticSearch, Kinesis
- Azure DataSec: ✅ 8-module DSPM on Blob, SQL, CosmosDB, DataLake, Synapse
- GCP DataSec: ✅ 8-module DSPM on Storage, CloudSQL, BigQuery, Spanner, Firestore
- OCI DataSec: ✅ 8-module DSPM on Object Storage, AutonomousDB, NoSQL, Streams
- AliCloud DataSec: ✅ 8-module DSPM on OSS, RDS, PolarDB, TableStore, MaxCompute
- IBM DataSec: ⚠️ **Service definitions only — no analyze()**

## DSPM 8-Module Framework (same for all CSPs)

| Module | What it checks |
|--------|---------------|
| M1: Classification | Sensitive data tags, data type labels (PII/PHI/PCI) |
| M2: Encryption | Server-side encryption, CMK vs default key |
| M3: Access Control | Public access, IAM policies, bucket policies |
| M4: Lifecycle | Retention policies, TTL, archival tiers |
| M5: Residency | Region constraint, cross-region replication |
| M6: Lineage | Audit logs enabled, data movement tracking |
| M7: Secrets | Environment variables, unencrypted secrets |
| M8: DLP | Sensitive pattern detection (before native DLP — PC-P3-04) |

---

## IBM Cloud Data Services

### IBM Cloud Object Storage (COS)

**Discovery IDs:**
- `ibm.cos.list_buckets` — all buckets per resource group
- `ibm.cos.get_bucket_config` — ACL, versioning, lifecycle rules
- `ibm.cos.get_bucket_protection` — WORM / immutable object storage
- `ibm.cos.get_bucket_activity_tracking` — Activity Tracker integration

**Findings to generate:**

| Rule ID | Module | Check | Severity |
|---------|--------|-------|---------|
| `ibm.cos.bucket.public_access_blocked` | M3 | Bucket ACL not `public-read` or `public-read-write` | critical |
| `ibm.cos.bucket.server_side_encryption_kp` | M2 | SSE using IBM Key Protect (not default IBM-managed key) | high |
| `ibm.cos.bucket.versioning_enabled` | M4 | Object versioning enabled | medium |
| `ibm.cos.bucket.activity_tracking_enabled` | M6 | Activity Tracker events enabled for read/write | high |
| `ibm.cos.bucket.lifecycle_policy_set` | M4 | At least one lifecycle rule exists | low |

### IBM Db2 on Cloud

**Discovery IDs:**
- `ibm.db2.list_instances` — all Db2 instances
- `ibm.db2.get_instance_details` — config: SSL enforcement, public access, IP allowlists

**Findings to generate:**

| Rule ID | Module | Check | Severity |
|---------|--------|-------|---------|
| `ibm.db2.instance.ssl_enforced` | M2 | SSL-only connections enforced | high |
| `ibm.db2.instance.public_connectivity_disabled` | M3 | No public endpoint configured | critical |
| `ibm.db2.instance.ip_allowlist_configured` | M3 | IP allowlist not empty | high |
| `ibm.db2.instance.audit_logging_enabled` | M6 | DB activity audit enabled | high |

### IBM Cloudant (NoSQL)

**Discovery IDs:**
- `ibm.cloudant.list_instances` — all Cloudant instances
- `ibm.cloudant.get_instance_config` — CORS settings, authentication type, capacity

**Findings to generate:**

| Rule ID | Module | Check | Severity |
|---------|--------|-------|---------|
| `ibm.cloudant.instance.cors_restricted` | M3 | CORS `origins` not `["*"]` | medium |
| `ibm.cloudant.instance.https_only` | M2 | Legacy HTTP access disabled | high |
| `ibm.cloudant.instance.iam_only_auth` | M3 | Authentication mode = IAM only (not legacy credentials) | high |
| `ibm.cloudant.instance.autoscale_capacity_limited` | M4 | Capacity tier not unlimited (prevents data exfil via bulk read) | medium |

### IBM Event Streams (Kafka)

**Discovery IDs:**
- `ibm.eventstreams.list_instances` — all Event Streams instances
- `ibm.eventstreams.get_instance_details` — plan tier, endpoints

**Findings to generate:**

| Rule ID | Module | Check | Severity |
|---------|--------|-------|---------|
| `ibm.eventstreams.instance.private_endpoints_only` | M3 | Using private endpoint (Enterprise plan) not public | high |
| `ibm.eventstreams.instance.schema_registry_enabled` | M1 | Schema Registry enforced for topic data validation | medium |

---

## Implementation Steps

1. **Open** `engines/datasec/data_security_engine/providers/ibm.py`
2. Add `analyze(self, scan_run_id, tenant_id, account_id) -> List[DataSecFinding]` method
3. Call `get_discovery_findings(scan_run_id, 'ibm')` to load COS/Db2/Cloudant/EventStreams discovery data
4. Implement 4 service analyzers (COS, Db2, Cloudant, EventStreams)
5. Return combined findings list

**Pattern to follow:** `engines/datasec/data_security_engine/providers/oci.py` — most similar scope (object storage + managed DB + NoSQL)

## DataSecFinding fields

Same as other providers — `resource_uid`, `resource_type` (`cos_bucket` / `db2_instance` / `cloudant_instance`), `rule_id`, `severity`, `status`, `module` (M1–M8), `raw_evidence` (JSONB).

## Posture Signals Produced

After `analyze()`, the existing `write_datasec_posture_signals()` aggregates from `datasec_findings`:
- `data_classification` — from classification module findings
- `can_access_pii` — from access control module
- `has_exfil_path` — from public access + cross-region replication
- `secrets_in_env_vars` — from secrets module

**No changes needed to posture_signals.py** — already CSP-agnostic.

## Acceptance Criteria

- [ ] AC-1: `IBMDataSecProvider.analyze()` returns findings for COS, Db2, Cloudant, Event Streams resource types
- [ ] AC-2: `ibm.cos.bucket.public_access_blocked` fires for publicly accessible COS buckets
- [ ] AC-3: `ibm.db2.instance.public_connectivity_disabled` fires for publicly reachable Db2 instances
- [ ] AC-4: `ibm.cloudant.instance.iam_only_auth` fires for Cloudant with legacy credentials enabled
- [ ] AC-5: After IBM scan: `SELECT resource_type, COUNT(*) FROM datasec_findings WHERE provider='ibm' GROUP BY resource_type` shows all 4 resource types
- [ ] AC-6: `resource_security_posture` updated with `data_classification` for IBM resources after scan

## MITRE ATT&CK
| Technique | Addressed by |
|-----------|-------------|
| T1530 | Data from Cloud Storage Object — public COS bucket detection |
| T1020 | Automated Exfiltration — Event Streams without private endpoints |
| T1552.001 | Credentials In Files — Cloudant legacy credential detection |

## Definition of Done
- [ ] IBM `analyze()` implemented (COS + Db2 + Cloudant + Event Streams)
- [ ] Unit test in `tests/unit/datasec/test_ibm_provider.py`
- [ ] DataSec engine rebuilt and deployed
- [ ] After IBM scan: `SELECT COUNT(*) FROM datasec_findings WHERE provider='ibm'` > 0