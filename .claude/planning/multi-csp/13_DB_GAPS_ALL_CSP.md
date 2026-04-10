# Database Gaps — All Engines, All CSPs

## Summary

The DB schemas are structurally multi-CSP (provider column on all tables, no hostile UNIQUE constraints).
The gaps are DATA gaps, not schema gaps — rules, frameworks, relationships, and classifications
that only exist for AWS today need to be seeded for every new CSP.

## Gap Matrix

| Engine | DB | What needs data per new CSP |
|--------|----|------------------------------|
| discoveries | threat_engine_discoveries | `discovery_findings` auto-populated by scanner |
| check | threat_engine_check | `rule_metadata` (CSP rules), `rule_discoveries` (done ✓) |
| inventory | threat_engine_inventory | `resource_security_relationship_rules`, `service_classification` |
| threat | threat_engine_threat | `threat_findings` (auto), `mitre_technique_reference` (CSP checks columns) |
| iam | threat_engine_iam | `iam_findings` (auto), IAM-specific rules in `rule_metadata` |
| datasec | threat_engine_datasec | `datasec_data_store_services` (has CSP rows already), `datasec_findings` (auto) |
| compliance | threat_engine_compliance | `compliance_frameworks` (CSP-specific CIS benchmarks), `rule_control_mapping` |
| risk | threat_engine_risk | No seed data needed — computed from findings |
| onboarding | threat_engine_onboarding | `cloud_accounts` (per-tenant, user-provided) |

## Engine-by-Engine Gap Detail

---

### 1. Discoveries (`threat_engine_discoveries`)

**Schema status:** Multi-CSP ready (provider, account_id, region, resource_uid, resource_type).

**What's needed per CSP:**
- Scanner code that writes to `discovery_findings` with correct provider
- `resource_type` must be normalized per CSP:
  - Azure: `Microsoft.Compute/virtualMachines` → normalize to `VirtualMachine`
  - GCP: `compute.googleapis.com/Instance` → normalize to `GCEInstance`
  - K8s: `Pod`, `Deployment`, `Service` (already short names)
- `resource_uid` format per CSP:
  - Azure: `/subscriptions/{sub}/resourceGroups/{rg}/providers/...`
  - GCP: `//compute.googleapis.com/projects/{proj}/zones/{zone}/instances/{name}`
  - K8s: `{namespace}/{kind}/{name}`

**Action:** Scanner (Track A) handles this — no schema change needed.

---

### 2. Check (`threat_engine_check`)

**Schema status:** Multi-CSP ready.

**What's needed per CSP:**

`rule_metadata` — Currently ~2,000 AWS rules. Need:
- **Azure**: ~500-800 rules covering CIS Azure 1.5, Azure Security Benchmark, NIST SP 800-53
- **GCP**: ~400-600 rules covering CIS GCP 1.3, Google Cloud Security Foundations
- **K8s**: ~150-200 rules covering CIS K8s 1.8, NSA K8s Hardening Guide
- **OCI**: ~200-300 rules
- **IBM**: ~150-200 rules
- **AliCloud**: ~200-300 rules

Each `rule_metadata` row needs:
```
rule_id, provider, service, check_type, severity,
resource_type, check_title, check_description,
compliance_frameworks (JSONB), mitre_tactics (JSONB), mitre_techniques (JSONB),
remediation_steps (JSONB), threat_category
```

`rule_control_mapping` — Links `rule_id` → `control_id` (compliance framework controls).
Needs new rows per CSP for framework mapping.

**Action:** Write/seed rule YAML files per CSP service. Load via `populate_rule_metadata.py`.

---

### 3. Inventory (`threat_engine_inventory`)

**Schema status:** Multi-CSP ready (provider/csp on all tables).

**What's needed per CSP:**

`resource_security_relationship_rules` — Currently 2,055 AWS-only rows. Need:
- Azure: 15 rules (from 07_INVENTORY_RELATIONSHIPS.md)
- GCP: 13 rules
- K8s: 12 rules
- OCI: 8 rules

`service_classification` — Controls what appears in Assets tab per CSP. Need entries for:
- Azure: VirtualMachine, StorageAccount, SQLServer, KeyVault, etc.
- GCP: GCEInstance, CloudSQLInstance, GCSBucket, GKECluster, etc.
- K8s: Pod, Deployment, Service, Namespace, etc.
- OCI: Instance, BootVolume, VCN, Bucket, etc.

`resource_inventory_identifier` — Step5 catalog entries (csp, service, resource_type).
Exists in `threat_engine_pythonsdk` — needs Azure/GCP/K8s entries.

**Action:** SQL INSERT seed files per CSP. Already designed in 07_INVENTORY_RELATIONSHIPS.md.

---

### 4. Threat (`threat_engine_threat`)

**Schema status:** Multi-CSP ready. `mitre_technique_reference` already has `azure_checks`, `gcp_checks` JSONB columns.

**What's needed per CSP:**

`mitre_technique_reference` — Currently `aws_checks` populated. Need:
- Fill `azure_checks` array with Azure rule_ids that detect each technique
- Fill `gcp_checks` array with GCP rule_ids
- Add `k8s_checks` column (not yet in schema?)

`threat_hunt_queries` — Contains KQL/SQL threat hunting queries. Need:
- Azure: KQL queries for Sentinel (T1078, T1190, T1566, etc.)
- GCP: Chronicle/Log Analytics queries
- K8s: kubectl-based and Falco-based queries

**Schema change needed:**
```sql
ALTER TABLE mitre_technique_reference 
ADD COLUMN IF NOT EXISTS k8s_checks JSONB DEFAULT '[]',
ADD COLUMN IF NOT EXISTS oci_checks JSONB DEFAULT '[]';
```

**Action:** Populate MITRE reference table per CSP after rules are written.

---

### 5. IAM (`threat_engine_iam`)

**Schema status:** Multi-CSP ready (provider, account_id, region on findings).

**What's needed per CSP:**

IAM-specific rules in `rule_metadata` (tagged with iam_modules array). Need:
- **Azure**: EntraID rules (MFA, PIM, Guest users, SP credential expiry, Managed Identity misconfig)
- **GCP**: Service account rules (key age, project owner bindings, Workload Identity)
- **K8s**: RBAC rules (wildcard permissions, cluster-admin overuse, automountToken)
- **OCI**: IAM policy rules (admin group membership, policy scope)

`iam_report` schema — Currently works for AWS. Multi-CSP needs:
- `iam_modules` JSONB to carry Azure AD / GCP IAM module names
- `findings_by_module` already JSONB — works for any CSP module names

**Action:** Write IAM rule YAMLs per CSP. Load into `rule_metadata` with correct `provider`.

---

### 6. DataSec (`threat_engine_datasec`)

**Schema status:** `datasec_data_store_services` already has multi-CSP rows (Azure, GCP, OCI, IBM, AliCloud). ✓

**What's needed per CSP:**

DataSec rules in `rule_metadata` covering:
- **Azure**: Storage public access, Azure SQL TDE, Key Vault soft-delete, Cosmos DB encryption
- **GCP**: Cloud Storage uniform bucket-level access, BigQuery encryption, Cloud SQL backup encryption
- **K8s**: Secrets in plaintext ConfigMaps, etcd encryption at rest

**Action:** Write datasec rule YAMLs per CSP. Auto-populated at scan time otherwise.

---

### 7. Compliance (`threat_engine_compliance`)

**Schema status:** Frameworks are CSP-agnostic (NIST, ISO, SOC2, PCI, HIPAA). But needs CSP-specific frameworks.

**What's needed per CSP:**

`compliance_frameworks` — Need to add:
- `cis_azure_1_5` — CIS Azure Foundations Benchmark 1.5
- `cis_gcp_1_3` — CIS Google Cloud Foundations 1.3
- `cis_k8s_1_8` — CIS Kubernetes Benchmark 1.8
- `azure_security_benchmark` — Microsoft Defender for Cloud baseline
- `gcp_security_foundations` — Google Security Foundations blueprint
- `nsa_k8s_hardening` — NSA/CISA Kubernetes Hardening Guidance

`compliance_controls` — Framework controls for each above.

`rule_control_mapping` — Map every new CSP rule → framework control.

**Action:** Write framework seed SQL per CSP. `upload_aws_compliance_to_db.py` equivalent needed per CSP.

---

### 8. Risk (`threat_engine_risk`)

**Schema status:** Fully multi-CSP. `risk_input_transformed.csp` field, scenarios are CSP-agnostic.

**What's needed:** Nothing — risk engine computes from findings across all engines. As Azure/GCP findings flow in, risk scores are computed automatically.

**Action:** None — just ensure scanner, check, and threat are working for the CSP.

---

## Schema Changes Needed (actual ALTER TABLE)

```sql
-- threat_engine_threat: add k8s/oci checks columns
ALTER TABLE mitre_technique_reference
  ADD COLUMN IF NOT EXISTS k8s_checks JSONB DEFAULT '[]',
  ADD COLUMN IF NOT EXISTS oci_checks JSONB DEFAULT '[]',
  ADD COLUMN IF NOT EXISTS ibm_checks JSONB DEFAULT '[]',
  ADD COLUMN IF NOT EXISTS alicloud_checks JSONB DEFAULT '[]';

-- threat_engine_compliance: cloud column rename/expand
-- compliance_report.cloud defaults to 'aws' — needs to be provider
ALTER TABLE compliance_report
  ALTER COLUMN cloud SET DEFAULT 'aws';
-- Already handled by writing provider field explicitly — no change needed.

-- threat_engine_inventory: ensure resource_security_relationship_rules has provider
-- Already has provider column per schema audit.
```

## Seed Files Needed

| File | Target Table | Content |
|------|-------------|---------|
| `seed_azure_rules.sql` | rule_metadata | ~600 Azure check rules |
| `seed_gcp_rules.sql` | rule_metadata | ~500 GCP check rules |
| `seed_k8s_rules.sql` | rule_metadata | ~150 K8s check rules |
| `seed_azure_relationships.sql` | resource_security_relationship_rules | 15 rules |
| `seed_gcp_relationships.sql` | resource_security_relationship_rules | 13 rules |
| `seed_k8s_relationships.sql` | resource_security_relationship_rules | 12 rules |
| `seed_azure_asset_classification.sql` | service_classification | ~15 asset types |
| `seed_gcp_asset_classification.sql` | service_classification | ~13 asset types |
| `seed_k8s_asset_classification.sql` | service_classification | ~10 asset types |
| `seed_cis_azure.sql` | compliance_frameworks + controls | CIS Azure 1.5 |
| `seed_cis_gcp.sql` | compliance_frameworks + controls | CIS GCP 1.3 |
| `seed_cis_k8s.sql` | compliance_frameworks + controls | CIS K8s 1.8 |
| `seed_azure_rule_mappings.sql` | rule_control_mapping | rule → CIS/NIST control |
| `seed_gcp_rule_mappings.sql` | rule_control_mapping | rule → CIS/NIST control |
| `seed_k8s_rule_mappings.sql` | rule_control_mapping | rule → CIS control |