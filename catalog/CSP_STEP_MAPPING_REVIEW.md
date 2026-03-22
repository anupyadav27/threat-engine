# CSP Pipeline Step Mapping — GCP → AWS → Azure
> Review document: maps current AWS/Azure file names to GCP step1–step6 naming convention

---

## GCP Pipeline — Reference Model

Each service folder (e.g. `gcp/compute/`) contains exactly 7 files:

| Step File | Script that builds it | What it contains |
|---|---|---|
| `step1_api_driven_registry.json` | `build_step1_from_github_cache.py` | All operations from Discovery API — full op metadata, HTTP paths, params, schemas |
| `step2_read_operation_registry.json` | `build_api_driven_registry.py` | Read-only ops filtered from step1 |
| `step2_write_operation_registry.json` | `build_api_driven_registry.py` | Write/mutate ops filtered from step1 |
| `step3_read_operation_dependency_chain_independent.json` | `build_op_dependency_chains.py` | Dependency chains — which ops are independent (roots) vs dependent, chain resolution |
| `step4_fields_produced_index.json` | `build_fields_index.py` | Fields produced per operation — entity names, field types, producer/consumer mappings |
| `step5_resource_catalog_inventory_enrich.json` | `build_resource_catalog.py` | Resource catalog — identifier type, full_identifier template, anchor params, enrich ops |
| `step6_{service}.discovery.yaml` | `build_discovery_yaml.py` | Jinja2 inventory + enrich YAML for execution engine |

---

## AWS — Current Files → Proposed Step Names

### Per-Service Folder (e.g. `aws/ec2/`, `aws/iam/`, ...)

| Current File | Proposed Step Name | Notes |
|---|---|---|
| `boto3_dependencies_with_python_names_fully_enriched.json` | `step1_api_driven_registry.json` | All operations with python method names, required/optional params, output fields, independent/dependent classification |
| `resource_operations_prioritized.json` | `step2_resource_operations_registry.json` | Root ops + yaml_discovery_operations + primary/other resources — equivalent to GCP read/write split merged |
| `dependency_index.json` | `step3_read_operation_dependency_chain.json` | Dependency chains — roots list (independent ops), entity_paths (what each entity needs to be fetched) |
| `direct_vars.json` | `step4_fields_produced_index.json` | Fields index — seed_from_list + enriched_from_get/describe fields, field_mappings, dependency_index_entity names |
| `arn_identifier.json` | `step5_resource_catalog_inventory_enrich.json` | Resource identifier catalog — ARN pattern, resource_identifiers, independent/dependent methods. **AWS-specific = ARN** |
| `minimal_operations_list.json` | `step5b_minimal_operations_catalog.json` | Extended step5 — minimal ops set, yaml_discovery_operations, arn_deduplication summary |
| `{service}_discovery.yaml` | `step6_{service}.discovery.yaml` | Discovery YAML — same role as GCP |

### AWS-Only Files (no GCP equivalent — to keep as-is or archive)

| Current File | Category | Notes |
|---|---|---|
| `resource_arn_mapping.json` | Analysis | ARN-to-resource type mapping analysis + expert analysis. AWS-specific, no GCP equivalent |
| `field_operator_value_table.csv` | Analysis | Field × operator × value combinations for query building |
| `resource_inventory_report.json/.csv/.md` | Report | Human-readable inventory summary — output artifact |
| `minimal_operations_list.csv/.md` | Report | Human-readable minimal ops — output artifact |
| `{service}_discovery.yaml.backup` | Backup | Can be moved to temp/backup subfolder |

### AWS Root-Level Files (cross-service aggregates)

| Current File | Proposed Name | Notes |
|---|---|---|
| `boto3_dependencies_with_python_names.json` | `aws_step1_all_services_registry.json` | Cross-service aggregate of step1 (raw, pre-enrichment) |
| `boto3_dependencies_with_python_names_fully_enriched.json` | `aws_step1_all_services_registry_enriched.json` | Cross-service aggregate of step1 (fully enriched) |
| `direct_vars_all_services.json` | `aws_step4_all_services_fields_index.json` | Cross-service aggregate of step4 |

### AWS Root-Level Scripts → `temp_code/`

| Current Script | Role in Pipeline | GCP Equivalent |
|---|---|---|
| `regenerate_boto3_dependencies.py` | Builds step1 per-service | `build_step1_from_*.py` |
| `split_by_service.py` | Splits global registry into per-service folders | `build_step1_from_*.py` (inline) |
| `generate_dependency_index.py` | Builds step3 | `build_op_dependency_chains.py` |
| `generate_minimal_operations_list.py` | Builds step5b | `build_resource_catalog.py` |
| `generate_resource_operations_prioritized.py` | Builds step2 | `build_api_driven_registry.py` |
| `generate_resource_operations_prioritized_all.py` | Builds step2 for all services | `build_api_driven_registry.py` |
| `generate_all_services_minimal_operations.py` | Builds step5b all services | `build_resource_catalog.py` |
| `generate_all_services_yaml_discovery.py` | Builds step6 all services | `build_discovery_yaml.py` |
| `generate_discovery_yaml.py` (also in service folder) | Builds step6 | `build_discovery_yaml.py` |
| `generate_field_operator_value_table.py` | Builds field_operator table | `build_fields_index.py` |
| `generate_fields_reference_csv.py` | Generates CSV reference | Analysis helper |
| `generate_lineage.py` | Generates lineage graph | `build_dependency_chain.py` |
| `generate_resource_inventory_reports.py` | Report generation | Reporting helper |
| `generate_accessanalyzer_yaml.py` | One-off YAML | Dev/debug helper |
| `enrich_discovery_yaml.py` | Enriches step6 YAML | `enhance_yaml_quality.py` |
| `enrich_fields_with_operations.py` | Enriches step4 | `enrich_name_identifier.py` |
| `enhance_minimal_operations_with_arns.py` | Enriches step5b with ARNs | `build_resource_catalog.py` (inline) |
| `filter_direct_vars_read_only.py` | Filters step4 to read-only | `build_api_driven_registry.py` (inline) |
| `fix_dependency_index.py` | Fix/patch step3 | Fix helper |
| `fix_entity_naming_mismatches.py` | Fix entity names in step3/4 | Fix helper |
| `fix_all_parameter_types.py` | Fix param types in step1 | Fix helper |
| `fix_read_operations_dependency_index.py` | Fix read ops in step3 | Fix helper |
| `deduplicate_arns_with_priority.py` | Dedup ARN patterns in step5 | Fix helper |
| `organize_service_folders.py` | File organization | Utility |
| `split_by_service.py` | Split global → per-service | Utility |
| `analyze_direct_vars_operation_types.py` | Analysis of step4 | Analysis |
| `analyze_fields_without_operations.py` | Analysis of step4 | Analysis |
| `analyze_missing_entities.py` | Analysis of step3/4 | Analysis |
| `analyze_yaml_checks.py` | Analysis of step6 | Analysis |
| `clarify_dependencies_logic.py` | Analysis/debug | Analysis |
| `comprehensive_validation.py` | Cross-step validation | Validation |
| `validate_dependency_index.py` | Validate step3 | Validation |
| `validate_direct_vars_traceability.py` | Validate step4 | Validation |
| `validate_read_operations_dependency_index.py` | Validate step3 read ops | Validation |
| `test_resource_arn_mapping.py` | Test ARN mappings | Test |

---

## Azure — Current Files → Proposed Step Names

### Per-Service Folder (e.g. `azure/compute/`, `azure/storage/`, ...)

| Current File | Proposed Step Name | Notes |
|---|---|---|
| `operation_registry.json` | `step1_api_driven_registry.json` | All operations with kind_rules, entity_aliases, overrides — equivalent to GCP step1 |
| `adjacency.json` | `step2_operation_adjacency_registry.json` | Op-level consumes/produces + entity-level consumers/producers + external entities — combines GCP step2+step4 concepts |
| `dependency_index.json` | `step3_read_operation_dependency_chain.json` | Same structure as AWS — roots (independent ops), entity_paths (dependency resolution) |
| `direct_vars.json` | `step4_fields_produced_index.json` | Fields index — seed_from_list + enriched fields, same role as AWS direct_vars and GCP step4 |
| `id_identifier.json` | `step5_resource_catalog_inventory_enrich.json` | Resource identifier catalog — Azure Resource ID pattern, resource_identifiers, methods. **Azure-specific = /subscriptions/.../resourceType/name** |
| `minimal_operations_list.json` | `step5b_minimal_operations_catalog.json` | Minimal ops set for inventory — same role as AWS step5b |
| `resource_operations_prioritized.json` | `step2b_resource_operations_registry.json` | Root ops + yaml discovery ops — same as AWS step2 (only present for ~160/268 services) |
| `{service}_discovery.yaml` | `step6_{service}.discovery.yaml` | Discovery YAML — same role as GCP |

### Azure-Only Files (no GCP equivalent)

| Current File | Category | Notes |
|---|---|---|
| `azure_dependencies_with_python_names_fully_enriched.json` | Cross-ref | Azure SDK method names enriched — per-service copy of root aggregate |
| `manual_review.json` | QA | Alias candidates, issues, suggested overrides — Azure-specific manual review output |
| `validation_report.json` | QA | Per-service validation results |
| `field_operator_value_table.csv` | Analysis | Field × operator table — same as AWS |
| `resource_inventory_report.json` | Report | Inventory report (present for ~230 services) |
| `{service}_discovery.yaml.backup` | Backup | Can be moved to temp/backup subfolder |

### Azure Root-Level Scripts → `temp_code/`

| Current Script | Role in Pipeline | GCP Equivalent |
|---|---|---|
| `generate_resource_operations_prioritized.py` | Builds step2b | `build_api_driven_registry.py` |
| `generate_minimal_operations_list.py` | Builds step5b | `build_resource_catalog.py` |
| `generate_field_operator_value_table.py` | Builds field table | `build_fields_index.py` |
| `generate_discovery_yaml.py` | Builds step6 | `build_discovery_yaml.py` |

### Azure Root-Level Data Files

| Current File | Status | Notes |
|---|---|---|
| `azure_dependencies_with_python_names_fully_enriched.json` | Keep at root | Cross-service aggregate (same as AWS root-level boto3 file) |
| `all_services.json` | Keep at root | Service inventory list |
| `data_quality_report.json` | Keep at root | Cross-service quality report |
| `dependency_index_build_results.json` | → `temp_code/` | Build result/log file |
| `dependency_index_report.json` | → `temp_code/` | Build result/log file |
| `manual_review_global_summary.json` | → `temp_code/` | Build result/log file |

---

## Cross-CSP Step Equivalence Summary

```
STEP │ GCP                                          │ AWS                                          │ AZURE
─────┼──────────────────────────────────────────────┼──────────────────────────────────────────────┼──────────────────────────────────────────────
  1  │ step1_api_driven_registry.json               │ boto3_dependencies_with_python_names_         │ operation_registry.json
     │ (from Discovery API / GitHub cache)           │ fully_enriched.json                          │ (from Azure SDK / ARM spec)
     │ keys: service,version,csp,operations[]        │ keys: {service: {independent[], dependent[]}}│ keys: service,kind_rules,entity_aliases,ops
─────┼──────────────────────────────────────────────┼──────────────────────────────────────────────┼──────────────────────────────────────────────
  2  │ step2_read_operation_registry.json            │ resource_operations_prioritized.json         │ resource_operations_prioritized.json
     │ step2_write_operation_registry.json           │ (merged read+write, root_ops+yaml_ops)        │ + adjacency.json (op_consumes/produces)
     │ (read/write split)                            │                                              │ (only ~160/268 services have step2b)
─────┼──────────────────────────────────────────────┼──────────────────────────────────────────────┼──────────────────────────────────────────────
  3  │ step3_read_operation_dependency_chain_        │ dependency_index.json                        │ dependency_index.json
     │ independent.json                              │ keys: roots[], entity_paths{}                │ keys: roots[], entity_paths{}
     │ keys: chains[], independent_ops[], dep_ops[]  │ (same concept, slightly different schema)    │ (same schema as AWS)
─────┼──────────────────────────────────────────────┼──────────────────────────────────────────────┼──────────────────────────────────────────────
  4  │ step4_fields_produced_index.json              │ direct_vars.json                             │ direct_vars.json
     │ keys: fields{}, stats                         │ keys: seed_from_list, enriched_from_get,     │ keys: seed_from_list, enriched_from_get,
     │                                              │       fields{}, field_mappings               │       final_union, fields{}
─────┼──────────────────────────────────────────────┼──────────────────────────────────────────────┼──────────────────────────────────────────────
  5  │ step5_resource_catalog_inventory_enrich.json  │ arn_identifier.json                          │ id_identifier.json
     │ keys: anchors, services{templates,enrich_ops} │ identifier_type: arn                         │ identifier_type: azure_resource_id
     │                                              │ + minimal_operations_list.json (step5b)      │ + minimal_operations_list.json (step5b)
─────┼──────────────────────────────────────────────┼──────────────────────────────────────────────┼──────────────────────────────────────────────
  6  │ step6_{service}.discovery.yaml               │ {service}_discovery.yaml                     │ {service}_discovery.yaml
     │ (Jinja2 inventory+enrich YAML)                │ (same structure/role)                        │ (same structure/role)
─────┴──────────────────────────────────────────────┴──────────────────────────────────────────────┴──────────────────────────────────────────────
```

---

## Key Differences & Gaps

### AWS vs GCP
| Difference | GCP | AWS | Action |
|---|---|---|---|
| Read/Write split | step2 is split into two files | Single `resource_operations_prioritized.json` | Could split into step2_read + step2_write OR keep merged as step2 |
| Dependency chains | step3 has full `chains[]` array with resolution order | `dependency_index.json` has `entity_paths{}` (entity-centric view) | Same concept, different lens — both are step3 |
| Resource identifier | step5 has full template with enrich operations | `arn_identifier.json` = ARN pattern only; `minimal_operations_list.json` = enrich ops | Merge both into step5 OR keep as step5 + step5b |
| Per-service registry copy | GCP step1 is per-service only | AWS has root aggregate + per-service copy of enriched | Root aggregate = `aws_step1_all_services_registry_enriched.json` |
| Field table | No CSV output | `field_operator_value_table.csv` | AWS-specific output, keep as-is |

### Azure vs GCP
| Difference | GCP | Azure | Action |
|---|---|---|---|
| Adjacency file | No separate adjacency — baked into step3 chains | `adjacency.json` = op_consumes/produces + entity graph | Azure step2 = operation_registry; step2b = adjacency.json |
| Operation registry | step1 = raw ops from discovery | `operation_registry.json` = ops + kind_rules + entity_aliases | Azure step1 is richer — includes classification rules |
| Manual review | No equivalent | `manual_review.json` per service | Azure-specific QA artifact, keep as-is |
| Validation | No per-service validation | `validation_report.json` per service | Azure-specific QA artifact |
| Per-service SDK copy | Not present | `azure_dependencies_with_python_names_fully_enriched.json` per service | Same as AWS per-service boto3 copy — redundant with root aggregate |

---

## Proposed Rename Actions

### AWS — Rename per service folder (429 service folders × ~5 files)
```
boto3_dependencies_with_python_names_fully_enriched.json  →  step1_api_driven_registry.json
resource_operations_prioritized.json                      →  step2_resource_operations_registry.json
dependency_index.json                                     →  step3_read_operation_dependency_chain.json
direct_vars.json                                          →  step4_fields_produced_index.json
arn_identifier.json                                       →  step5_resource_catalog_inventory_enrich.json
minimal_operations_list.json                              →  step5b_minimal_operations_catalog.json
{service}_discovery.yaml                                  →  step6_{service}.discovery.yaml  (already named correctly for many)
```

### Azure — Rename per service folder (268 service folders × ~5 files)
```
operation_registry.json                                   →  step1_api_driven_registry.json
adjacency.json                                            →  step2_operation_adjacency_registry.json
dependency_index.json                                     →  step3_read_operation_dependency_chain.json
direct_vars.json                                          →  step4_fields_produced_index.json
id_identifier.json                                        →  step5_resource_catalog_inventory_enrich.json
minimal_operations_list.json                              →  step5b_minimal_operations_catalog.json
resource_operations_prioritized.json                      →  step2b_resource_operations_registry.json  (only ~160 services)
{service}_discovery.yaml                                  →  step6_{service}.discovery.yaml  (already named correctly for many)
```

### AWS Root-level
```
boto3_dependencies_with_python_names_fully_enriched.json  →  aws_step1_all_services_registry_enriched.json
boto3_dependencies_with_python_names.json                 →  aws_step1_all_services_registry.json
direct_vars_all_services.json                             →  aws_step4_all_services_fields_index.json
```

### Both — Move to temp_code/
```
All *.py scripts  →  temp_code/
dependency_index_build_results.json  →  temp_code/
dependency_index_report.json  →  temp_code/
dependency_index_validation_report.json  →  temp_code/  (AWS)
manual_review_global_summary.json  →  temp_code/  (Azure)
*.yaml.backup  →  temp_code/  (or delete)
```

---

## Questions for Review

1. **AWS step2 split**: Should `resource_operations_prioritized.json` stay as ONE file (step2) or be split into `step2_read` + `step2_write` to match GCP exactly?

2. **Azure step2 vs adjacency**: `operation_registry` is clearly step1. But `adjacency.json` — should it be step2 (since it's the op consumes/produces layer), or should `resource_operations_prioritized.json` be step2 and `adjacency.json` be step2b?

3. **step5 merge**: For AWS, `arn_identifier.json` + `minimal_operations_list.json` together form the GCP step5 concept. Should they be merged into one `step5_resource_catalog_inventory_enrich.json`, or kept as step5 + step5b?

4. **Backup YAMLs**: Move `.yaml.backup` files to `temp_code/` or just delete them?

5. **Per-service SDK copy**: Azure has `azure_dependencies_with_python_names_fully_enriched.json` in every service folder AND at root. AWS similarly has `boto3_dependencies_*` per service AND at root. These per-service copies are redundant. Remove them once renamed at root?
