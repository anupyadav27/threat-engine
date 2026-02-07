# Database Schema Reference

> All PostgreSQL databases, tables, columns, and relationships used across the CSPM platform.

---

## Database Inventory

| Database | Owner | Tables | Total Rows | Used By |
|----------|-------|--------|-----------|---------|
| `threat_engine_threat` | threat_user | 9 | 965 | engine_threat |
| `threat_engine_check` | check_user | 5 | 22,066 | engine_check, engine_threat, engine_compliance |
| `threat_engine_inventory` | inventory_user | 11 | 1,159 | engine_inventory, engine_threat |
| `threat_engine_compliance` | compliance_user | - | - | engine_compliance |
| `threat_engine_discoveries` | discoveries_user | - | - | engine_discoveries |
| `threat_engine_onboarding` | postgres | - | - | engine_onboarding |
| `threat_engine_datasec` | datasec_user | - | - | engine_datasec |
| `threat_engine_iam` | iam_user | - | - | engine_iam |
| `threat_engine_shared` | shared_user | - | - | Cross-engine shared data |
| `threat_engine_pythonsdk` | postgres | - | - | engine_pythonsdk |

**Connection:** `postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com:5432`

---

## threat_engine_threat (9 tables)

### threat_report
Scan-level threat report summary.

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| threat_scan_id | varchar | NO | | Primary key (scan identifier) |
| execution_id | varchar | YES | | Pipeline execution ID |
| discovery_scan_id | varchar | YES | | Linked discovery scan |
| check_scan_id | varchar | YES | | Linked check scan |
| tenant_id | varchar | NO | | Tenant isolation key |
| customer_id | varchar | YES | | Customer ID |
| provider | varchar | YES | | Cloud provider (aws/azure/gcp) |
| scan_run_id | varchar | YES | | External scan run ID |
| started_at | timestamptz | YES | | Scan start time |
| completed_at | timestamptz | YES | | Scan end time |
| status | varchar | YES | | completed/failed/running |
| total_findings | int | YES | | Total findings processed |
| critical_findings | int | YES | | Critical severity count |
| high_findings | int | YES | | High severity count |
| medium_findings | int | YES | | Medium severity count |
| low_findings | int | YES | | Low severity count |
| threat_score | int | YES | | Overall threat score |
| report_data | jsonb | YES | | Full report JSON |
| created_at | timestamptz | YES | now() | Record creation time |

**Rows:** 3

### threat_detections
Individual threat detections (one per resource).

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| detection_id | uuid | NO | uuid_generate_v4() | Primary key |
| tenant_id | varchar | NO | | Tenant isolation key |
| scan_id | varchar | YES | | Linked scan ID |
| detection_type | varchar | YES | | misconfiguration/exposure |
| rule_id | varchar | YES | | Primary rule ID |
| rule_name | varchar | YES | | Rule display name |
| resource_arn | varchar | YES | | AWS resource ARN |
| resource_id | varchar | YES | | Resource identifier |
| resource_type | varchar | YES | | s3/iam/ec2/rds/etc. |
| account_id | varchar | YES | | AWS account ID |
| region | varchar | YES | | AWS region |
| provider | varchar | YES | | Cloud provider |
| severity | varchar | YES | | critical/high/medium/low |
| confidence | varchar | YES | | high/medium/low |
| status | varchar | YES | | open/investigating/resolved |
| threat_category | varchar | YES | | misconfiguration/exposure |
| mitre_tactics | jsonb | YES | | ["initial-access", "defense-evasion"] |
| mitre_techniques | jsonb | YES | | ["T1190", "T1562"] |
| indicators | jsonb | YES | | IOC data |
| evidence | jsonb | YES | | Remediation + finding_refs |
| context | jsonb | YES | | Additional context |
| detection_timestamp | timestamptz | YES | | When detected |
| first_seen_at | timestamptz | YES | | First occurrence |
| last_seen_at | timestamptz | YES | | Latest occurrence |
| resolved_at | timestamptz | YES | | Resolution time |
| resolved_by | varchar | YES | | Resolver identity |
| resolution_notes | text | YES | | Resolution notes |
| created_at | timestamptz | YES | now() | |
| updated_at | timestamptz | YES | now() | |

**Rows:** 21

### threat_findings
Links threat detections to underlying check findings.

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| id | serial | NO | auto | Primary key |
| finding_id | varchar | YES | | Check finding ID |
| threat_scan_id | varchar | YES | | Linked threat scan |
| tenant_id | varchar | NO | | Tenant isolation key |
| customer_id | varchar | YES | | Customer ID |
| scan_run_id | varchar | YES | | Scan run ID |
| rule_id | varchar | YES | | Rule that generated finding |
| threat_category | varchar | YES | | Threat category |
| severity | varchar | YES | | Severity level |
| status | varchar | YES | | PASS/FAIL/ERROR |
| resource_type | varchar | YES | | Resource type |
| resource_id | varchar | YES | | Resource ID |
| resource_arn | varchar | YES | | Resource ARN |
| resource_uid | varchar | YES | | Resource UID |
| account_id | varchar | YES | | Account ID |
| region | varchar | YES | | Region |
| mitre_tactics | jsonb | YES | | MITRE tactics |
| mitre_techniques | jsonb | YES | | MITRE techniques |
| evidence | jsonb | YES | | Finding evidence |
| finding_data | jsonb | YES | | Full finding data |
| first_seen_at | timestamptz | YES | | |
| last_seen_at | timestamptz | YES | | |
| created_at | timestamptz | YES | now() | |

**Rows:** 827

### threat_analysis
Risk scoring and attack chain analysis per threat.

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| analysis_id | uuid | NO | uuid_generate_v4() | Primary key |
| detection_id | uuid | YES | | FK to threat_detections |
| tenant_id | varchar | NO | | Tenant isolation key |
| analysis_type | varchar | YES | | risk_analysis/blast_radius |
| analyzer | varchar | YES | | Analyzer module name |
| analysis_status | varchar | YES | | completed/failed |
| risk_score | int | YES | | Composite risk score (0-100) |
| verdict | varchar | YES | | critical_action_required/high_risk/medium_risk/low_risk/informational |
| analysis_results | jsonb | YES | | blast_radius, mitre_analysis, reachability, formula |
| recommendations | jsonb | YES | | [{priority, action, description}] |
| related_threats | jsonb | YES | | Related threat IDs |
| attack_chain | jsonb | YES | | [{step, resource, action}] |
| started_at | timestamptz | YES | | |
| completed_at | timestamptz | YES | | |
| created_at | timestamptz | YES | now() | |

**Rows:** 63

### threat_intelligence
External threat intelligence feeds.

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| intel_id | uuid | NO | uuid_generate_v4() | Primary key |
| tenant_id | varchar | NO | | Tenant isolation key |
| source | varchar | YES | | cisa_kev/mitre_attack_ics/custom |
| intel_type | varchar | YES | | vulnerability/campaign/indicator |
| category | varchar | YES | | credential_abuse/ransomware |
| severity | varchar | YES | | critical/high/medium/low |
| confidence | varchar | YES | | high/medium/low |
| value_hash | varchar | YES | | SHA256 dedup hash |
| threat_data | jsonb | YES | | {name, cve_ids, description} |
| indicators | jsonb | YES | | IOC data |
| ttps | jsonb | YES | | MITRE technique IDs |
| tags | jsonb | YES | | Classification tags |
| first_seen_at | timestamptz | YES | | |
| last_seen_at | timestamptz | YES | | |
| expires_at | timestamptz | YES | | TTL for intel |
| is_active | boolean | YES | | Active flag |
| created_at | timestamptz | YES | now() | |
| updated_at | timestamptz | YES | now() | |

**Rows:** 2

### threat_hunt_queries
Saved threat hunting queries (Cypher).

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| hunt_id | uuid | NO | uuid_generate_v4() | Primary key |
| tenant_id | varchar | NO | | Tenant isolation key |
| query_name | varchar | YES | | Human-readable name |
| description | text | YES | | What the query hunts for |
| hunt_type | varchar | YES | | graph/sql/custom |
| query_language | varchar | YES | | cypher/sql |
| query_text | text | YES | | Actual query |
| target_data_sources | jsonb | YES | | Data sources to query |
| mitre_tactics | jsonb | YES | | Related tactics |
| mitre_techniques | jsonb | YES | | Related techniques |
| tags | jsonb | YES | | Classification tags |
| schedule_cron | varchar | YES | | CRON schedule (optional) |
| is_active | boolean | YES | | Active flag |
| last_executed_at | timestamptz | YES | | Last run time |
| execution_count | int | YES | | Total runs |
| hit_count | int | YES | | Total positive results |
| created_by | varchar | YES | | Creator identity |
| created_at | timestamptz | YES | now() | |
| updated_at | timestamptz | YES | now() | |

**Rows:** 1

### threat_hunt_results
Hunt execution results.

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| result_id | uuid | NO | uuid_generate_v4() |
| hunt_id | uuid | YES | |
| tenant_id | varchar | NO | |
| execution_timestamp | timestamptz | YES | |
| total_results | int | YES | |
| new_detections | int | YES | |
| execution_time_ms | float | YES | |
| results_data | jsonb | YES | |
| status | varchar | YES | |
| error_message | text | YES | |
| created_at | timestamptz | YES | now() |

**Rows:** 1

### mitre_technique_reference
MITRE ATT&CK technique taxonomy.

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| id | serial | NO | auto |
| technique_id | varchar | YES | |
| technique_name | varchar | YES | |
| tactics | jsonb | YES | |
| sub_techniques | jsonb | YES | |
| description | text | YES | |
| url | varchar | YES | |
| platforms | jsonb | YES | |
| aws_checks | jsonb | YES | |
| azure_checks | jsonb | YES | |
| gcp_checks | jsonb | YES | |
| ibm_keywords | jsonb | YES | |
| k8s_keywords | jsonb | YES | |
| ocp_keywords | jsonb | YES | |
| aws_service_coverage | jsonb | YES | |
| detection_keywords | jsonb | YES | |
| created_at | timestamptz | YES | now() |
| updated_at | timestamptz | YES | now() |

**Rows:** 46

### tenants

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| tenant_id | varchar | NO | |
| tenant_name | varchar | YES | |
| created_at | timestamptz | YES | now() |

**Rows:** 1

---

## threat_engine_check (5 tables)

### check_findings
Individual check results (PASS/FAIL per rule per resource).

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| id | serial | NO | auto |
| check_scan_id | varchar | YES | |
| customer_id | varchar | YES | |
| tenant_id | varchar | YES | |
| provider | varchar | YES | |
| hierarchy_id | varchar | YES | |
| hierarchy_type | varchar | YES | |
| rule_id | varchar | YES | |
| resource_uid | text | YES | |
| resource_arn | text | YES | |
| resource_id | varchar | YES | |
| resource_type | varchar | YES | |
| status | varchar | YES | |
| checked_fields | jsonb | YES | |
| finding_data | jsonb | YES | |
| created_at | timestamptz | YES | now() |

**Rows:** 1,572

### rule_metadata
Security rule definitions with MITRE mappings.

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| id | serial | NO | auto |
| rule_id | varchar | YES | |
| service | varchar | YES | |
| provider | varchar | YES | |
| resource | varchar | YES | |
| severity | varchar | YES | |
| title | varchar | YES | |
| description | text | YES | |
| remediation | text | YES | |
| rationale | text | YES | |
| domain | varchar | YES | |
| subcategory | varchar | YES | |
| requirement | text | YES | |
| assertion_id | varchar | YES | |
| compliance_frameworks | jsonb | YES | |
| data_security | jsonb | YES | |
| iam_security | jsonb | YES | |
| references | jsonb | YES | |
| metadata_source | varchar | YES | |
| source | varchar | YES | |
| generated_by | varchar | YES | |
| customer_id | varchar | YES | |
| tenant_id | varchar | YES | |
| created_at | timestamptz | YES | now() |
| updated_at | timestamptz | YES | now() |
| threat_category | varchar | YES | |
| threat_tags | jsonb | YES | |
| risk_score | int | YES | |
| risk_indicators | jsonb | YES | |
| version | varchar | YES | |
| mitre_tactics | jsonb | YES | |
| mitre_techniques | jsonb | YES | |

**Rows:** 9,943

### check_report, rule_checks, rule_discoveries
Scan metadata, rule configurations, and discovery rule definitions.

**Rows:** check_report(11), rule_checks(10,440), rule_discoveries(100)

---

## threat_engine_inventory (11 tables)

### inventory_findings (Primary asset table)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| asset_id | uuid | NO | uuid_generate_v4() |
| tenant_id | varchar | NO | |
| resource_uid | text | NO | |
| provider | varchar | NO | |
| account_id | varchar | NO | |
| region | varchar | YES | |
| resource_type | varchar | NO | |
| resource_id | varchar | NO | |
| name | varchar | YES | |
| display_name | varchar | YES | |
| description | text | YES | |
| tags | jsonb | YES | {}::jsonb |
| labels | jsonb | YES | {}::jsonb |
| properties | jsonb | YES | {}::jsonb |
| configuration | jsonb | YES | {}::jsonb |
| compliance_status | varchar | YES | |
| risk_score | int | YES | |
| criticality | varchar | YES | |
| environment | varchar | YES | |
| cost_center | varchar | YES | |
| owner | varchar | YES | |
| business_unit | varchar | YES | |
| latest_scan_run_id | varchar | YES | |
| first_discovered_at | timestamptz | YES | now() |
| last_modified_at | timestamptz | YES | |
| updated_at | timestamptz | YES | now() |
| inventory_scan_id | varchar | YES | |
| customer_id | varchar | YES | |

**Rows:** 301

### inventory_relationships

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| relationship_id | uuid | NO | uuid_generate_v4() |
| tenant_id | varchar | NO | |
| inventory_scan_id | varchar | NO | |
| provider | varchar | NO | |
| account_id | varchar | NO | |
| region | varchar | YES | |
| relation_type | varchar | NO | |
| from_uid | text | NO | |
| to_uid | text | NO | |
| from_resource_type | varchar | YES | |
| to_resource_type | varchar | YES | |
| relationship_strength | varchar | YES | 'strong' |
| bidirectional | boolean | YES | false |
| properties | jsonb | YES | {}::jsonb |
| metadata | jsonb | YES | {}::jsonb |
| first_discovered_at | timestamptz | YES | now() |
| last_confirmed_at | timestamptz | YES | now() |
| created_at | timestamptz | YES | now() |

**Rows:** 814

### Other inventory tables
- `inventory_drift` — Configuration change records (1 row)
- `inventory_report` — Scan reports (19 rows)
- `inventory_scans` — Scan metadata (3 rows)
- `inventory_asset_history` — Change history (5 rows)
- `inventory_asset_collections` — Asset collections (4 rows)
- `inventory_asset_collection_membership` — Collection membership (2 rows)
- `inventory_asset_metrics` — Asset metrics (6 rows)
- `inventory_asset_tags_index` — Tag search index (0 rows)

---

## Cross-Database Relationships

```
threat_engine_check.check_findings.check_scan_id ──► threat_engine_threat.threat_report.check_scan_id
threat_engine_check.rule_metadata.rule_id ──► threat_engine_check.check_findings.rule_id
threat_engine_threat.threat_detections.scan_id ──► threat_engine_check.check_report.check_scan_id
threat_engine_threat.threat_findings.rule_id ──► threat_engine_check.rule_metadata.rule_id
threat_engine_threat.threat_analysis.detection_id ──► threat_engine_threat.threat_detections.detection_id
threat_engine_inventory.inventory_findings.resource_uid ──► threat_engine_check.check_findings.resource_uid
```

---

## Schema SQL Files

Located at `consolidated_services/database/schemas/`:

| File | Database |
|------|----------|
| `threat_schema.sql` | threat_engine_threat |
| `check_schema.sql` | threat_engine_check |
| `inventory_schema.sql` | threat_engine_inventory |
| `compliance_schema.sql` | threat_engine_compliance |
| `discoveries_schema.sql` | threat_engine_discoveries |
| `datasec_schema.sql` | threat_engine_datasec |
| `iam_schema.sql` | threat_engine_iam |
| `shared_schema.sql` | threat_engine_shared |
