# Engine Prerequisite Data — Complete Reference

All seed data, reference tables, config files, and YAML catalogs that engines depend on to function.

## Quick Reference

| Data | Location | Loader | Engines Using |
|------|----------|--------|---------------|
| Rule metadata | `rule_metadata` (check DB) | `scripts/populate_rule_metadata.py` | Check, Compliance, Threat, IAM, DataSec |
| Discovery patterns | `rule_discoveries` (check DB) | `shared/database/seeds/seed_rule_discoveries_new_engines.sql` | Discoveries, Check |
| CSP catalog YAMLs | `catalog/{csp}/{service}/step6_*.yaml` | File system (loaded by discovery engine) | Discoveries |
| Compliance mappings | `compliance_control_mappings` (check DB) | CSV import via migration `006_compliance_control_mappings.sql` | Compliance |
| DataSec rules | `datasec_rules` (datasec DB) | `shared/database/seeds/seed_datasec_enhanced_rules.sql` | DataSec |
| MITRE techniques | `mitre_technique_reference` (threat DB) | `scripts/seed_mitre_reference.py` (reads JSON) | Threat |
| Threat intelligence | `threat_intelligence` (threat DB) | `scripts/seed_threat_intelligence.py` | Threat |
| Hunt queries | `threat_hunt_queries` (threat DB) | `engines/threat/scripts/seed_hunt_queries.py` | Threat |
| Relationship rules | `resource_relationship_templates` (inventory DB) | Migration `002_seed_relationship_templates.sql` | Inventory |
| Service classification | `resource_inventory` (pythonsdk DB) | `scripts/generate_resource_inventory_all_csp.py` | Inventory |
| K8s ConfigMaps | `deployment/aws/eks/configmaps/` | `kubectl apply` | All engines |
| DB connection config | ConfigMap `threat-engine-db-config` | K8s | All engines |

---

## 1. DISCOVERY ENGINE

### Files consumed directly:
- **CSP Catalog YAMLs**: `catalog/{csp}/{service}/step6_*.discovery.yaml`
  - Define what AWS/Azure/GCP API calls to make for each service
  - Fields: `boto3_client_name`, `arn_identifier`, `api_filters`, `response_filters`
  - ~380 active AWS rules, plus Azure/GCP/OCI/AliCloud/IBM
  - Disabled services list in MEMORY.md

### DB tables read:
- **`rule_discoveries`** (check DB, 1,087 rows)
  - Maps services → boto3 API calls → response parsing
  - JSONB `discoveries_data` with Jinja2 templates
  - Loaded from: `shared/database/seeds/seed_rule_discoveries_new_engines.sql`

### Config:
- `DISCOVERY_SCANNER_IMAGE` env var → Docker image for K8s scan Jobs
- `SCANNER_NAMESPACE`, `SCANNER_CPU_REQUEST`, `SCANNER_MEM_REQUEST`

---

## 2. CHECK ENGINE

### DB tables read (prerequisite):
- **`rule_metadata`** (check DB, 10,440 rows)
  - All check rules: rule_id, service, provider, severity, title, remediation
  - JSONB: `compliance_frameworks`, `data_security`, `mitre_tactics`, `mitre_techniques`
  - Loaded from: `scripts/populate_rule_metadata.py` (reads YAML metadata files)
  - Source YAMLs: `engine_input/engine_configscan_aws/input/rule_db/default/services/*/metadata/*.yaml`

- **`rule_discoveries`** (check DB, 1,087 rows)
  - Same as discovery — maps services to API calls
  - Check engine reads this to know which discoveries to evaluate

- **`rule_checks`** (check DB, 10,440 rows)
  - Per-rule check config (JSONB)
  - Allows tenant-specific rule overrides
  - Populated by check engine on-demand from YAML or custom configs

### Files consumed:
- Check evaluation logic is in Python code, not YAML files
- Check rules are defined in `engines/check/providers/aws/evaluator/` Python modules

---

## 3. THREAT ENGINE

### DB tables read (prerequisite):
- **`mitre_technique_reference`** (threat DB, 102 rows)
  - MITRE ATT&CK IaaS matrix: technique_id, name, tactics, description, aws_examples
  - Loaded from: `scripts/seed_mitre_reference.py` (reads `mitre_attack_iaas_matrix.json`)

- **`threat_intelligence`** (threat DB, 160 rows)
  - 5 categories: MITRE Cloud Matrix, CISA KEV, Cloud Campaigns, Misconfig Patterns, Ransomware
  - Loaded from: `scripts/seed_threat_intelligence.py` (hardcoded)

- **`threat_hunt_queries`** (threat DB, 111 rows)
  - Cypher queries for toxic combination detection
  - Loaded from: `engines/threat/scripts/seed_hunt_queries.py`

### Files consumed:
- Threat rules are defined in Python code (`threat_engine/analyzer/threat_analyzer.py`)
- MITRE mapping logic is code-based, enriched by `mitre_technique_reference` table

---

## 4. COMPLIANCE ENGINE

### DB tables read (prerequisite):
- **`compliance_control_mappings`** (check DB, 4,067 rows)
  - Maps framework → controls → rule_ids
  - 13+ frameworks: CIS, PCI-DSS, HIPAA, NIST-800-53, ISO-27001, SOC-2, GDPR, CANADA-PBMM, etc.
  - Loaded from: CSV import via migration `006_compliance_control_mappings.sql`

- **`compliance_frameworks`** (compliance DB, 18 rows)
  - Framework definitions (id, name, version, description)

- **`compliance_controls`** (compliance DB, 960 rows)
  - Control definitions per framework

- **`rule_metadata`** (check DB) — reads severity, title, remediation for report generation

---

## 5. IAM ENGINE

### DB tables read (prerequisite):
- **`rule_metadata`** (check DB) — reads IAM-specific rules (57 rules where service='iam')

### Files consumed:
- IAM evaluation rules defined in Python code
- Policy parser logic in `engines/iam/iam_engine/parsers/policy_parser.py`
- No separate YAML rule files

---

## 6. DATASEC ENGINE

### DB tables read (prerequisite):
- **`datasec_rules`** (datasec DB, 95 rows)
  - 35 enhanced rules across 7 categories: DLP, encryption, lineage, minimization, classification, access, cross-border
  - Loaded from: `shared/database/seeds/seed_datasec_enhanced_rules.sql`

- **`datasec_sensitive_data_types`** (datasec DB, 26 rows)
  - PII, PHI, PCI pattern definitions
  - Populated during datasec setup

- **`datasec_data_store_services`** (datasec DB, 75 rows)
  - Maps cloud services to data store types (S3, RDS, DynamoDB, etc.)

---

## 7. INVENTORY ENGINE

### DB tables read (prerequisite):
- **`resource_relationship_templates`** (inventory DB, 150+ rows)
  - AWS relationship patterns: attached_to, contained_by, uses, routes_to, triggers, etc.
  - Loaded from: Migration `002_seed_relationship_templates.sql`

- **`service_classification`** (inventory DB, 6,705 rows)
  - Classifies resource types: PRIMARY_RESOURCE, SUB_RESOURCE, CONFIGURATION, EPHEMERAL
  - Used by ResourceClassifier to filter what goes into inventory

- **`resource_inventory`** (pythonsdk DB)
  - SDK metadata for all CSPs (AWS 430 services, Azure 160, GCP 143, etc.)
  - Loaded from: `scripts/generate_resource_inventory_all_csp.py`

---

## 8. RISK ENGINE

### DB tables read (prerequisite):
- **`risk_model_config`** (risk DB, 0 rows currently)
  - Risk scoring model parameters
  - Loaded from: `shared/database/seeds/seed_risk_model_config.sql`

- Reads from threat, check, compliance, inventory DBs for aggregation

---

## 9. SHARED / CROSS-ENGINE

### K8s ConfigMaps (`deployment/aws/eks/configmaps/`):
- **`threat-engine-db-config`** — DB connection strings for all 9 databases
- **`platform-config`** — AWS account ID, log level, secrets manager prefix
- **`sqs-config`** — SQS queue URLs (currently unused, SQS removed)
- **`otel-config`** — OpenTelemetry collector config

### Seed SQL files (`shared/database/seeds/`):
| File | Target | Rows |
|------|--------|------|
| `seed_rule_discoveries_new_engines.sql` | rule_discoveries | 380+ |
| `seed_datasec_enhanced_rules.sql` | datasec_rules | 35 |
| `seed_network_rules.sql` | rule_metadata | Network rules |
| `seed_container_rules.sql` | rule_metadata | Container rules |
| `seed_supplychain_rules.sql` | rule_metadata | Supply chain rules |
| `seed_api_rules.sql` | rule_metadata | API rules |
| `seed_ai_security_rules.sql` | rule_metadata | AI security rules |
| `seed_risk_model_config.sql` | risk_model_config | Risk params |

### Seed Python scripts (`scripts/`):
| Script | Target | Source |
|--------|--------|--------|
| `populate_rule_metadata.py` | rule_metadata | YAML files |
| `seed_mitre_reference.py` | mitre_technique_reference | JSON matrix |
| `seed_mitre_guidance.py` | mitre guidance | Hardcoded |
| `seed_threat_intelligence.py` | threat_intelligence | Hardcoded |
| `generate_resource_inventory_all_csp.py` | resource_inventory | SDK introspection |

---

## Loading Order (for fresh deployment)

```
1. K8s ConfigMaps (DB connection strings)
2. Database schemas (CREATE TABLE)
3. Seed data (in order):
   a. rule_discoveries (SQL seed)
   b. rule_metadata (Python script from YAML)
   c. compliance_control_mappings (CSV import)
   d. datasec_rules (SQL seed)
   e. mitre_technique_reference (Python script)
   f. threat_intelligence (Python script)
   g. threat_hunt_queries (Python script)
   h. resource_relationship_templates (SQL migration)
   i. service_classification (Python script)
   j. risk_model_config (SQL seed)
4. CSP Catalog YAMLs (file system)
5. Engine deployments
```
