# Database Schema Reference

> All PostgreSQL databases, tables, columns, and relationships used across the CSPM platform.

---

## Database Inventory

| Database | Tables | Used By |
|----------|--------|---------|
| `discoveries` | 5 | engine_discoveries |
| `threat_engine_check` | 5 | engine_check, engine_threat, engine_compliance, engine_iam, engine_datasec |
| `threat_engine_inventory` | 11 | engine_inventory |
| `threat` | 9 | engine_threat |
| `threat_engine_compliance` | 9 | engine_compliance |
| `threat_engine_iam` | 3 | engine_iam |
| `threat_engine_datasec` | 3 | engine_datasec |
| `threat_engine_pythonsdk` | 8 | engine_inventory (resource classification), scripts |
| `threat_engine_onboarding` | - | engine_onboarding |
| `threat_engine_shared` | - | Cross-engine shared data |

**Connection:** `postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com:5432`

---

## Pipeline Flow (Scan ID Chain)

```
Discovery Engine                 Check Engine                  Threat Engine
  discovery_scan_id ──────────► check_report.discovery_scan_id
                                 check_scan_id ──────────────► threat_report.check_scan_id
                                                                threat_scan_id ──► IAM / DataSec / Compliance
```

Each engine's `*_report` table links upstream via FK-like columns:
- `check_report.discovery_scan_id` → `discovery_report.discovery_scan_id`
- `threat_report.check_scan_id` → `check_report.check_scan_id`
- `compliance_report.check_scan_id` → `check_report.check_scan_id`
- `iam_report.threat_scan_id` → `threat_report.threat_scan_id`
- `datasec_report.threat_scan_id` → `threat_report.threat_scan_id`

---

## discoveries (5 tables)

### discovery_report
Scan-level discovery report metadata.

| Column | Type | PK/FK | Description |
|--------|------|-------|-------------|
| discovery_scan_id | varchar(255) | PK | UUID from API server |
| customer_id | varchar(255) | FK | Customer ID |
| tenant_id | varchar(255) | FK | Tenant isolation key |
| provider | varchar(50) | | Cloud provider (aws/azure/gcp) |
| hierarchy_id | varchar(255) | | Account/subscription ID |
| hierarchy_type | varchar(50) | | account/subscription/project |
| region | varchar(50) | | Target region |
| service | varchar(100) | | Target service |
| scan_timestamp | timestamptz | | Scan start time |
| scan_type | varchar(50) | | Default: 'discovery' |
| status | varchar(50) | | running/completed/failed |
| metadata | jsonb | | Scan metadata |

### discovery_findings
Individual discovered resources (one row per resource per discovery function).

| Column | Type | PK/FK | Description |
|--------|------|-------|-------------|
| id | serial | PK | Auto-increment ID |
| discovery_scan_id | varchar(255) | FK | Links to discovery_report |
| customer_id | varchar(255) | FK | Customer ID |
| tenant_id | varchar(255) | FK | Tenant isolation key |
| provider | varchar(50) | | Cloud provider |
| hierarchy_id | varchar(255) | | Account/subscription ID |
| hierarchy_type | varchar(50) | | account/subscription/project |
| discovery_id | varchar(255) | | Discovery function ID (e.g., aws.s3.list_buckets) |
| resource_uid | text | | Primary resource identifier (ARN for AWS) |
| resource_arn | text | | AWS ARN |
| resource_id | varchar(255) | | Short resource ID |
| resource_type | varchar(100) | | Resource type |
| service | varchar(100) | | Service name |
| region | varchar(50) | | Region |
| emitted_fields | jsonb | | Extracted configuration fields |
| raw_response | jsonb | | Full API response |
| config_hash | varchar(64) | | SHA256 of config for drift detection |
| version | integer | | Schema version (default: 1) |
| scan_timestamp | timestamptz | | Scan timestamp |

### discovery_history
Configuration drift tracking across scans.

| Column | Type | Description |
|--------|------|-------------|
| id | serial | PK |
| discovery_scan_id | varchar(255) | FK to discovery_report |
| discovery_id | varchar(255) | Discovery function ID |
| resource_uid | text | Resource identifier |
| config_hash | varchar(64) | Current config hash |
| previous_hash | varchar(64) | Previous config hash |
| change_type | varchar(50) | created/modified/unchanged |
| diff_summary | jsonb | Config change diff |

### rule_definitions
Discovery rule YAML storage.

| Column | Type | Description |
|--------|------|-------------|
| id | serial | PK |
| csp | varchar(50) | Cloud provider |
| service | varchar(100) | Service name |
| file_path | varchar(512) | Rule file path |
| content_yaml | text | Full YAML content |

### customers, tenants
Core identity tables (FK targets).

---

## threat_engine_check (5 tables)

### check_report
Check scan metadata with link to discovery scan.

| Column | Type | PK/FK | Description |
|--------|------|-------|-------------|
| check_scan_id | varchar(255) | PK | UUID from API server |
| customer_id | varchar(255) | FK | Customer ID |
| tenant_id | varchar(255) | FK | Tenant isolation key |
| provider | varchar(50) | | Cloud provider |
| hierarchy_id | varchar(255) | | Account/subscription ID |
| hierarchy_type | varchar(50) | | account/subscription/project |
| scan_timestamp | timestamptz | | Scan time |
| scan_type | varchar(50) | | Default: 'check' |
| status | varchar(50) | | running/completed/failed |
| discovery_scan_id | varchar(255) | | Links to discovery_report |
| metadata | jsonb | | Scan metadata |

### check_findings
Individual check results (PASS/FAIL per rule per resource).

| Column | Type | PK/FK | Description |
|--------|------|-------|-------------|
| id | serial | PK | Auto-increment ID |
| check_scan_id | varchar(255) | FK | Links to check_report |
| customer_id | varchar(255) | FK | Customer ID |
| tenant_id | varchar(255) | FK | Tenant isolation key |
| provider | varchar(50) | | Cloud provider |
| hierarchy_id | varchar(255) | | Account/subscription ID |
| rule_id | varchar(255) | | Rule that generated finding |
| resource_uid | text | | Resource identifier |
| resource_arn | text | | AWS ARN |
| resource_type | varchar(100) | | Resource type |
| status | varchar(50) | | PASS/FAIL/ERROR |
| checked_fields | jsonb | | Fields that were checked |
| finding_data | jsonb | | Full finding details |
| scan_timestamp | timestamptz | | Scan timestamp |
| metadata_source | varchar(50) | | Rule source (default) |

### rule_metadata
Security rule definitions with severity, MITRE mappings, and compliance framework links.

| Column | Type | Description |
|--------|------|-------------|
| id | serial | PK |
| rule_id | varchar(255) | Unique rule identifier |
| service | varchar(100) | AWS service |
| provider | varchar(50) | Cloud provider |
| severity | varchar(20) | critical/high/medium/low |
| title | text | Rule title |
| description | text | Rule description |
| remediation | text | Fix instructions |
| compliance_frameworks | jsonb | Framework mappings |
| data_security | jsonb | Data security tags |
| threat_category | varchar(50) | Threat category |
| threat_tags | jsonb | Threat tags |
| risk_score | integer | Risk score (0-100) |
| mitre_tactics | jsonb | MITRE ATT&CK tactics |
| mitre_techniques | jsonb | MITRE ATT&CK techniques |

### rule_checks
Check rule configurations loaded from YAML or custom overrides.

### customers, tenants
Core identity tables (FK targets).

---

## threat_engine_inventory (11 tables)

### inventory_report
Scan-level inventory report metadata.

| Column | Type | PK/FK | Description |
|--------|------|-------|-------------|
| inventory_scan_id | varchar(255) | PK | Inventory scan identifier |
| tenant_id | varchar(255) | FK | Tenant isolation key |
| discovery_scan_id | varchar(255) | | Links to upstream discovery scan |
| customer_id | varchar(255) | | Customer ID |
| execution_id | varchar(255) | | Pipeline execution ID |
| started_at | timestamptz | | Scan start time |
| completed_at | timestamptz | | Scan end time |
| status | varchar(50) | | running/completed/failed |
| total_assets | integer | | Total assets discovered |
| total_relationships | integer | | Total relationships found |
| assets_by_provider | jsonb | | Asset counts by provider |
| assets_by_resource_type | jsonb | | Asset counts by type |
| assets_by_region | jsonb | | Asset counts by region |
| scan_metadata | jsonb | | Full scan metadata |

### inventory_scans
Lightweight scan tracking.

| Column | Type | Description |
|--------|------|-------------|
| scan_run_id | varchar(255) | PK |
| tenant_id | varchar(255) | FK |
| discovery_scan_id | varchar(255) | Upstream discovery scan |
| status | varchar(50) | Scan status |
| total_assets | integer | Asset count |
| total_relationships | integer | Relationship count |

### inventory_findings
Cloud resource inventory (latest state per resource_uid).

| Column | Type | PK/FK | Description |
|--------|------|-------|-------------|
| asset_id | uuid | PK | Auto-generated UUID |
| tenant_id | varchar(255) | FK | Tenant isolation key |
| resource_uid | text | UNIQUE | Resource identifier (with tenant_id) |
| provider | varchar(50) | | Cloud provider |
| account_id | varchar(255) | | Account ID |
| region | varchar(100) | | Region |
| resource_type | varchar(255) | | Resource type |
| resource_id | varchar(255) | | Short resource ID |
| name | varchar(255) | | Resource name |
| tags | jsonb | | Resource tags |
| properties | jsonb | | Resource properties |
| configuration | jsonb | | Resource configuration |
| compliance_status | varchar(50) | | compliant/non_compliant/unknown |
| risk_score | integer | | 0-100 |
| criticality | varchar(20) | | low/medium/high/critical |
| environment | varchar(50) | | production/staging/development |
| inventory_scan_id | varchar(255) | | Links to inventory_report |

### inventory_relationships
Connections between cloud resources.

| Column | Type | Description |
|--------|------|-------------|
| relationship_id | uuid | PK |
| tenant_id | varchar(255) | FK |
| inventory_scan_id | varchar(255) | Links to scan |
| relation_type | varchar(100) | attached_to/member_of/depends_on/contains |
| from_uid | text | Source resource UID |
| to_uid | text | Target resource UID |
| relationship_strength | varchar(20) | weak/medium/strong |
| bidirectional | boolean | Whether relationship is bidirectional |

### inventory_drift
Configuration drift between scans.

| Column | Type | Description |
|--------|------|-------------|
| id | serial | PK |
| drift_id | uuid | Drift event ID |
| inventory_scan_id | varchar(255) | Current scan |
| previous_scan_id | varchar(255) | Previous scan |
| change_type | varchar(50) | added/removed/modified |
| previous_state | jsonb | Before state |
| current_state | jsonb | After state |
| severity | varchar(20) | low/medium/high/critical |

### Other inventory tables
- `inventory_asset_history` — Asset change history tracking
- `inventory_asset_tags_index` — Efficient tag-based queries
- `inventory_asset_collections` — Business logic asset grouping
- `inventory_asset_collection_membership` — Asset-to-collection mapping
- `inventory_asset_metrics` — Asset performance/utilization metrics

---

## threat (9 tables)

### threat_report
Scan-level threat report summary.

| Column | Type | PK/FK | Description |
|--------|------|-------|-------------|
| threat_scan_id | varchar(255) | PK | Threat scan identifier |
| execution_id | varchar(255) | | Pipeline execution ID |
| discovery_scan_id | varchar(255) | | Upstream discovery scan |
| check_scan_id | varchar(255) | | Upstream check scan |
| tenant_id | varchar(255) | FK | Tenant isolation key |
| customer_id | varchar(255) | | Customer ID |
| provider | varchar(50) | | Cloud provider |
| scan_run_id | varchar(255) | | External scan run ID |
| started_at | timestamptz | | Scan start time |
| completed_at | timestamptz | | Scan end time |
| status | varchar(50) | | completed/failed/running |
| total_findings | integer | | Total findings |
| critical_findings | integer | | Critical count |
| high_findings | integer | | High count |
| medium_findings | integer | | Medium count |
| low_findings | integer | | Low count |
| threat_score | integer | | Overall threat score |
| report_data | jsonb | | Full report JSON |

### threat_findings
Individual threat findings with MITRE ATT&CK mapping.

| Column | Type | PK/FK | Description |
|--------|------|-------|-------------|
| id | serial | PK | Auto-increment |
| finding_id | varchar(255) | | Finding identifier |
| threat_scan_id | varchar(255) | | Links to threat_report |
| tenant_id | varchar(255) | FK | Tenant isolation key |
| rule_id | varchar(255) | | Rule that generated finding |
| threat_category | varchar(100) | | misconfiguration/exposure/etc. |
| severity | varchar(20) | | critical/high/medium/low |
| status | varchar(50) | | PASS/FAIL/ERROR |
| resource_type | varchar(100) | | Resource type |
| resource_arn | text | | Resource ARN |
| resource_uid | text | | Resource UID |
| account_id | varchar(255) | | Account ID |
| region | varchar(50) | | Region |
| mitre_tactics | jsonb | | MITRE ATT&CK tactics |
| mitre_techniques | jsonb | | MITRE ATT&CK techniques |
| evidence | jsonb | | Finding evidence |
| finding_data | jsonb | | Full finding data |

### threat_detections
Real-time threat detections.

| Column | Type | Description |
|--------|------|-------------|
| detection_id | uuid | PK |
| scan_id | varchar(255) | Linked scan |
| detection_type | varchar(50) | configuration/behavioral/signature |
| severity | varchar(20) | critical/high/medium/low |
| confidence | varchar(20) | high/medium/low |
| status | varchar(50) | open/investigating/resolved |
| threat_category | varchar(100) | Category |
| mitre_tactics | jsonb | MITRE tactics |
| mitre_techniques | jsonb | MITRE techniques |
| evidence | jsonb | Detection evidence |

### threat_analysis
Risk scoring and attack chain analysis per threat.

| Column | Type | Description |
|--------|------|-------------|
| analysis_id | uuid | PK |
| detection_id | uuid | FK to threat_detections |
| risk_score | integer | 0-100 |
| verdict | varchar(50) | malicious/suspicious/benign/unknown |
| analysis_results | jsonb | blast_radius, mitre_analysis, etc. |
| recommendations | jsonb | [{priority, action, description}] |
| attack_chain | jsonb | [{step, resource, action}] |

### mitre_technique_reference
MITRE ATT&CK technique taxonomy for cross-cloud mapping.

| Column | Type | Description |
|--------|------|-------------|
| id | serial | PK |
| technique_id | varchar(50) | UNIQUE, e.g., T1190 |
| technique_name | text | Technique name |
| tactics | jsonb | Related tactics |
| aws_checks | jsonb | AWS-specific check mappings |
| azure_checks | jsonb | Azure-specific check mappings |
| gcp_checks | jsonb | GCP-specific check mappings |
| aws_service_coverage | jsonb | Service coverage data |
| detection_keywords | jsonb | Detection keywords |

### Other threat tables
- `threat_intelligence` — External threat intelligence feeds and IOCs
- `threat_hunt_queries` — Saved threat hunting queries
- `threat_hunt_results` — Hunt execution results

---

## threat_engine_compliance (9 tables)

### compliance_report
Compliance scan metadata with links to check/discovery scans.

| Column | Type | PK/FK | Description |
|--------|------|-------|-------------|
| compliance_scan_id | varchar(255) | PK | Compliance scan identifier |
| tenant_id | varchar(255) | FK | Tenant isolation key |
| scan_run_id | varchar(255) | | External scan run ID |
| cloud | varchar(50) | | Cloud provider |
| check_scan_id | varchar(255) | | Upstream check scan |
| discovery_scan_id | varchar(255) | | Upstream discovery scan |
| customer_id | varchar(255) | | Customer ID |
| provider | varchar(50) | | Cloud provider |
| status | varchar(50) | | completed/failed/running |
| total_controls | integer | | Total controls assessed |
| controls_passed | integer | | Controls passed |
| controls_failed | integer | | Controls failed |
| total_findings | integer | | Total findings |
| report_data | jsonb | | Full report JSON |

### compliance_findings
Individual compliance findings mapped to frameworks.

| Column | Type | PK/FK | Description |
|--------|------|-------|-------------|
| finding_id | varchar(255) | PK | Finding identifier |
| compliance_scan_id | varchar(255) | | Links to compliance_report |
| tenant_id | varchar(255) | FK | Tenant isolation key |
| rule_id | varchar(255) | | Check rule ID |
| severity | varchar(20) | | critical/high/medium/low |
| status | varchar(20) | | PASS/FAIL/WARN |
| resource_type | varchar(100) | | Resource type |
| resource_arn | text | | Resource ARN |
| resource_uid | text | | Resource UID |
| compliance_framework | varchar(255) | | Framework (e.g., nist_csf_1_1) |
| control_id | varchar(255) | | Control ID |
| control_name | varchar(500) | | Control name |
| account_id | varchar(255) | | Account ID |
| finding_data | jsonb | | Full finding data |

### compliance_frameworks
Compliance framework definitions (NIST, ISO, SOC2, PCI-DSS, HIPAA).

### compliance_controls
Individual controls within frameworks.

### rule_control_mapping
Mapping between check rules and compliance controls.

### Other compliance tables
- `compliance_assessments` — Formal compliance assessment tracking
- `control_assessment_results` — Assessment results per control
- `remediation_tracking` — Remediation tracking for compliance gaps
- `tenants` — Tenant isolation

---

## threat_engine_iam (3 tables)

### iam_report
IAM security scan metadata.

| Column | Type | PK/FK | Description |
|--------|------|-------|-------------|
| iam_scan_id | varchar(255) | PK | IAM scan identifier |
| tenant_id | varchar(255) | FK | Tenant isolation key |
| scan_run_id | varchar(255) | | External scan run ID |
| cloud | varchar(50) | | Cloud provider |
| check_scan_id | varchar(255) | | Upstream check scan |
| threat_scan_id | varchar(255) | | Upstream threat scan |
| discovery_scan_id | varchar(255) | | Upstream discovery scan |
| customer_id | varchar(255) | | Customer ID |
| provider | varchar(50) | | Cloud provider |
| status | varchar(50) | | completed/failed/running |
| total_findings | integer | | Total IAM findings |
| iam_relevant_findings | integer | | IAM-relevant count |
| critical_findings | integer | | Critical count |
| high_findings | integer | | High count |
| findings_by_module | jsonb | | {least_privilege: 10, mfa: 5, ...} |
| findings_by_status | jsonb | | {PASS: 50, FAIL: 30, ...} |
| report_data | jsonb | | Full report JSON |

### iam_findings
Individual IAM security findings.

| Column | Type | PK/FK | Description |
|--------|------|-------|-------------|
| finding_id | varchar(255) | PK | Finding identifier |
| iam_scan_id | varchar(255) | | Links to iam_report |
| tenant_id | varchar(255) | FK | Tenant isolation key |
| rule_id | varchar(255) | | Check rule ID |
| iam_modules | text[] | | IAM modules (least_privilege, mfa, etc.) |
| severity | varchar(20) | | critical/high/medium/low |
| status | varchar(20) | | PASS/FAIL/WARN |
| resource_type | varchar(100) | | Resource type |
| resource_arn | text | | Resource ARN |
| resource_uid | text | | Resource UID |
| finding_data | jsonb | | Full finding data |

---

## threat_engine_datasec (3 tables)

### datasec_report
Data security scan metadata.

| Column | Type | PK/FK | Description |
|--------|------|-------|-------------|
| datasec_scan_id | varchar(255) | PK | DataSec scan identifier |
| tenant_id | varchar(255) | FK | Tenant isolation key |
| scan_run_id | varchar(255) | | External scan run ID |
| cloud | varchar(50) | | Cloud provider |
| check_scan_id | varchar(255) | | Upstream check scan |
| threat_scan_id | varchar(255) | | Upstream threat scan |
| discovery_scan_id | varchar(255) | | Upstream discovery scan |
| customer_id | varchar(255) | | Customer ID |
| provider | varchar(50) | | Cloud provider |
| status | varchar(50) | | completed/failed/running |
| total_findings | integer | | Total findings |
| datasec_relevant_findings | integer | | Data-security-relevant count |
| classified_resources | integer | | Resources with classification |
| total_data_stores | integer | | Total data stores found |
| findings_by_module | jsonb | | {data_protection: 10, ...} |
| classification_summary | jsonb | | {PII: 5, PCI: 3, PHI: 2} |
| residency_summary | jsonb | | {compliant: 10, non_compliant: 5} |
| report_data | jsonb | | Full report JSON |

### datasec_findings
Individual data security findings.

| Column | Type | PK/FK | Description |
|--------|------|-------|-------------|
| finding_id | varchar(255) | PK | Finding identifier |
| datasec_scan_id | varchar(255) | | Links to datasec_report |
| tenant_id | varchar(255) | FK | Tenant isolation key |
| rule_id | varchar(255) | | Check rule ID |
| datasec_modules | text[] | | Modules (data_protection, classification, etc.) |
| severity | varchar(20) | | critical/high/medium/low |
| status | varchar(20) | | PASS/FAIL/WARN |
| resource_type | varchar(100) | | Resource type |
| resource_arn | text | | Resource ARN |
| resource_uid | text | | Resource UID |
| data_classification | text[] | | Classifications (PII, PCI, PHI, etc.) |
| sensitivity_score | decimal(3,1) | | 0.0 to 10.0 |
| finding_data | jsonb | | Full finding data |

---

## threat_engine_pythonsdk (8 tables)

Cloud provider SDK metadata for resource classification, dependency analysis, and field inspection.
Populated by: `scripts/populate_pythonsdk_db.py` (services, operations, fields, dependency_index, direct_vars)
              `scripts/generate_resource_inventory_all_csp.py` (resource_inventory, enhancement_indexes)

### csp
Cloud service provider metadata.

| Column | Type | PK/FK | Description |
|--------|------|-------|-------------|
| csp_id | varchar(50) | PK | Provider identifier (aws, azure, gcp, k8s, oci, ibm, alicloud) |
| csp_name | varchar(100) | | Display name |
| description | text | | Provider description |
| sdk_version | varchar(50) | | SDK version used |
| total_services | integer | | Total services for this CSP |
| metadata | jsonb | | Additional metadata |

### services
SDK service modules per CSP.

| Column | Type | PK/FK | Description |
|--------|------|-------|-------------|
| service_id | varchar(100) | PK | Unique service ID (e.g., aws.s3, azure.compute) |
| csp_id | varchar(50) | FK | Links to csp |
| service_name | varchar(100) | | Service name (e.g., s3, compute) |
| service_full_name | varchar(200) | | Full SDK module name |
| sdk_module | varchar(200) | | Python SDK module path |
| total_operations | integer | | Total API operations |
| discovery_operations | integer | | Discovery-capable operations |

### operations
SDK API operations per service.

| Column | Type | PK/FK | Description |
|--------|------|-------|-------------|
| id | bigserial | PK | Auto-increment |
| service_id | varchar(100) | FK | Links to services |
| operation_name | varchar(200) | | Operation name (e.g., list_buckets) |
| python_method | varchar(200) | | Python method name |
| operation_type | varchar(20) | | independent/dependent |
| is_discovery | boolean | | Whether operation discovers resources |
| is_root_operation | boolean | | Whether operation is a root (no params) |
| required_params | jsonb | | Required parameters list |
| depends_on | jsonb | | Operation dependencies |
| main_output_field | varchar(200) | | Primary output field name |
| output_structure | jsonb | | Response structure |
| UNIQUE | | | (service_id, operation_name) |

### fields
Emitted configuration fields per operation.

| Column | Type | PK/FK | Description |
|--------|------|-------|-------------|
| id | bigserial | PK | Auto-increment |
| service_id | varchar(100) | FK | Links to services |
| operation_name | varchar(200) | | Source operation |
| field_name | varchar(200) | | Field name |
| field_path | varchar(500) | | Dot-notation path |
| field_type | varchar(50) | | Data type |
| compliance_category | varchar(100) | | Compliance category (encryption, logging, etc.) |
| security_impact | varchar(20) | | Security impact level |
| compliance_frameworks | jsonb | | Framework mappings |
| target_category | varchar(50) | | properties/configuration/tags |

### resource_inventory
Resource type classification per service (one row per service).

| Column | Type | PK/FK | Description |
|--------|------|-------|-------------|
| id | bigserial | PK | Auto-increment |
| service_id | varchar(100) | FK/UNIQUE | Links to services (one row per service) |
| inventory_data | jsonb | | Classification data with resource_types[] |
| total_resource_types | integer | | Total resource types found |
| total_operations | integer | | Total operations |
| discovery_operations | integer | | Discovery operations |

`inventory_data` JSON structure:
```json
{
  "service_id": "aws.s3",
  "csp_id": "aws",
  "resource_types": [
    {
      "resource_type": "Bucket",
      "resource_classification": "PRIMARY_RESOURCE",
      "operations": ["list_buckets"],
      "primary_identifier": "Name"
    }
  ]
}
```

Classification values: `PRIMARY_RESOURCE`, `SUB_RESOURCE`, `CONFIGURATION`, `EPHEMERAL`

### dependency_index
Operation dependency graph per service.

| Column | Type | PK/FK | Description |
|--------|------|-------|-------------|
| id | bigserial | PK | Auto-increment |
| service_id | varchar(100) | FK/UNIQUE | Links to services |
| dependency_data | jsonb | | Full dependency graph |
| total_functions | integer | | Total operations |
| independent_functions | integer | | No-param operations |
| dependent_functions | integer | | Operations requiring params |

### direct_vars
Compliance and security field aggregation per service.

| Column | Type | PK/FK | Description |
|--------|------|-------|-------------|
| id | bigserial | PK | Auto-increment |
| service_id | varchar(100) | FK/UNIQUE | Links to services |
| direct_vars_data | jsonb | | Field variable data |
| total_fields | integer | | Total fields |
| compliance_fields | integer | | Compliance-tagged fields |
| security_fields | integer | | Security-tagged fields |

### enhancement_indexes
Pre-built classification indexes per CSP.

| Column | Type | PK/FK | Description |
|--------|------|-------|-------------|
| id | bigserial | PK | Auto-increment |
| index_type | varchar(100) | | Index type (e.g., inventory_classification) |
| csp_id | varchar(50) | FK | Links to csp |
| index_data | jsonb | | Pre-built classification lookup |
| total_entries | integer | | Total entries in index |
| UNIQUE | | | (index_type, csp_id) |

### Current data (as of deployment)

| Table | Rows | Coverage |
|-------|------|----------|
| csp | 7 | All 7 CSPs |
| services | 991 | All CSPs |
| operations | 29,577 | All CSPs |
| fields | 55,198 | All CSPs |
| resource_inventory | 960 | All 7 CSPs |
| dependency_index | 989 | All CSPs |
| direct_vars | 989 | All CSPs |
| enhancement_indexes | 7 | All 7 CSPs (1 per CSP) |

---

## Cross-Database Relationships

```
discoveries                 threat_engine_check
  discovery_report                          check_report
    .discovery_scan_id ──────────────────► .discovery_scan_id
                                            .check_scan_id ──────────► threat_report.check_scan_id
                                                                       compliance_report.check_scan_id

threat                      threat_engine_iam / threat_engine_datasec
  threat_report                             iam_report / datasec_report
    .threat_scan_id ─────────────────────► .threat_scan_id

threat_engine_inventory
  inventory_report
    .discovery_scan_id ──────────────────► discovery_report.discovery_scan_id

Cross-engine resource linking:
  inventory_findings.resource_uid ═══════ check_findings.resource_uid
  check_findings.rule_id ═══════════════ rule_metadata.rule_id
  threat_findings.rule_id ══════════════ rule_metadata.rule_id

threat_engine_pythonsdk (SDK metadata — used by inventory engine for resource classification):
  resource_inventory.inventory_data ───► inventory engine ResourceClassifier
  enhancement_indexes.index_data ──────► inventory engine fast classification lookup
```

---

## Schema SQL Files

Located at `shared/database/schemas/`:

| File | Database | Tables |
|------|----------|--------|
| `discoveries_schema.sql` | discoveries | discovery_report, discovery_findings, discovery_history, rule_definitions |
| `check_schema.sql` | threat_engine_check | check_report, check_findings, rule_checks, rule_metadata |
| `inventory_schema.sql` | threat_engine_inventory | inventory_report, inventory_scans, inventory_findings, inventory_relationships, inventory_drift, inventory_asset_* |
| `threat_schema.sql` | threat | threat_report, threat_findings, threat_detections, threat_analysis, threat_intelligence, threat_hunt_*, mitre_technique_reference |
| `compliance_schema.sql` | threat_engine_compliance | compliance_report, compliance_findings, compliance_frameworks, compliance_controls, compliance_assessments, rule_control_mapping, remediation_tracking |
| `iam_schema.sql` | threat_engine_iam | iam_report, iam_findings |
| `datasec_schema.sql` | threat_engine_datasec | datasec_report, datasec_findings |
| `pythonsdk_schema.sql` | threat_engine_pythonsdk | csp, services, operations, fields, resource_inventory, dependency_index, direct_vars, enhancement_indexes |
| `shared_schema.sql` | threat_engine_shared | Shared tables |

---

## Naming Convention

All engines follow a consistent naming pattern:

| Pattern | Example |
|---------|---------|
| Report table | `{engine}_report` |
| Findings table | `{engine}_findings` |
| Scan ID column | `{engine}_scan_id` |
| Cross-reference | `{upstream_engine}_scan_id` |
| Env vars | `{ENGINE}_DB_HOST`, `{ENGINE}_DB_PORT`, etc. |

Pipeline order: **Discovery** → **Check** → **Inventory** → **Threat** → **Compliance** + **IAM** + **DataSec** (parallel)
