# Database migrations reference

Use this as the single reference for rules and compliance tables to avoid drift later.

## ConfigScan database (`threat_engine_configscan`)

| Migration | Table | Purpose |
|-----------|--------|---------|
| `002_add_rule_metadata.sql` | `rule_metadata` | Rule metadata (severity, title, description, remediation). Used by threat/enrichment. |
| `002_add_rule_metadata.sql` | `check_results` | + `metadata_source` column. |
| **`009_rule_definitions.sql`** | **`rule_definitions`** | **Full rule YAML per service (csp, service, file_path, content_yaml). Source: engine_input/.../rule_db/default/services. Configscan engines load from DB first.** |
| configscan_schema.sql | `checks`, `check_results`, `discoveries`, etc. | Core scan storage. |

## Compliance database (`threat_engine_compliance`)

| Migration | Table | Purpose |
|-----------|--------|---------|
| **`006_compliance_control_mappings.sql`** | **`compliance_control_mappings`** | **Control→rule mappings from CSV (unique_compliance_id, compliance_framework, requirement_*, final_aws_check, rule_ids, etc.). Source: data_compliance/aws/aws_consolidated_rules_with_final_checks.csv. Compliance engine loads from DB first.** |
| compliance_schema.sql | `report_index`, `finding_index`, `compliance_frameworks`, etc. | Reports and assessments. |

## Data flow

- **Rules**: Upload YAMLs from `engine_input/engine_configscan_aws/input/rule_db/default/services/` → `rule_definitions` (script). Configscan AWS (and others) call DB in `load_service_rules()` first, then file.
- **Compliance**: Upload CSV `data_compliance/aws/aws_consolidated_rules_with_final_checks.csv` → `compliance_control_mappings` (script). Compliance engine `ConsolidatedCSVLoader` reads from DB first, then CSV file.

## Applying migrations

- Base schemas: `consolidated_services/database/schemas/<engine>_schema.sql` (via migration_runner or deploy).
- Numbered migrations (002, 006, 009): run SQL against the correct DB (configscan vs compliance) during deploy or once manually.

## Upload scripts (use after migrations)

- **Rules**: `python consolidated_services/database/scripts/upload_aws_rules_to_db.py [--services-dir PATH]`  
  Inserts into `rule_definitions` (configscan DB). Source: `engine_input/engine_configscan_aws/input/rule_db/default/services/`.
- **Compliance**: `python consolidated_services/database/scripts/upload_aws_compliance_to_db.py [--csv PATH] [--truncate]`  
  Inserts into `compliance_control_mappings` (compliance DB). Source: `data_compliance/aws/aws_consolidated_rules_with_final_checks.csv`.
