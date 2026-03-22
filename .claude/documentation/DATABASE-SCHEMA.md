# Database Schema Reference

Auto-generated from live RDS. Last updated: 2026-03-21

Host: postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com


## threat_engine_discoveries


### customers (1 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| customer_id | varchar | NO |  |
| customer_name | varchar | YES |  |
| metadata | jsonb | YES | '{}'::jsonb |
| created_at | timestamp | YES | CURRENT_TIMESTAMP |
| updated_at | timestamp | YES | CURRENT_TIMESTAMP |

**Indexes:** 1
- `customers_pkey`

**PK:** customer_id

### discovery_findings (1,422,775 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| id | integer | NO | nextval('discoveries_id_seq'::regclass) |
| discovery_scan_id | varchar | NO |  |
| customer_id | varchar | NO |  |
| tenant_id | varchar | NO |  |
| provider | varchar | NO |  |
| hierarchy_id | varchar | YES |  |
| hierarchy_type | varchar | YES |  |
| discovery_id | varchar | NO |  |
| resource_uid | text | YES |  |
| resource_id | varchar | YES |  |
| resource_type | varchar | YES |  |
| service | varchar | YES |  |
| region | varchar | YES |  |
| emitted_fields | jsonb | YES |  |
| raw_response | jsonb | YES |  |
| config_hash | varchar | YES |  |
| version | integer | YES | 1 |
| scan_timestamp | timestamptz | YES | now() |
| account_id | varchar | YES |  |

**Indexes:** 14
- `discoveries_pkey`
- `idx_discoveries_scan`
- `idx_discoveries_tenant`
- `idx_discoveries_resource_uid`
- `idx_discoveries_hash`
- `idx_discoveries_service`
- `idx_discoveries_raw_response_gin`
- `idx_discoveries_emitted_fields_gin`
- `idx_disc_reader_lookup`
- `idx_disc_latest_version`
- `idx_df_lookup`
- `idx_df_latest`
- `idx_df_account_id`
- `idx_df_account_region`

**PK:** id

### discovery_history (1,998,740 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| id | integer | NO | nextval('discovery_history_id_seq'::regc |
| customer_id | varchar | NO |  |
| tenant_id | varchar | NO |  |
| provider | varchar | NO |  |
| hierarchy_id | varchar | YES |  |
| hierarchy_type | varchar | YES |  |
| discovery_id | varchar | NO |  |
| resource_uid | text | YES |  |
| discovery_scan_id | varchar | NO |  |
| config_hash | varchar | NO |  |
| raw_response | jsonb | YES |  |
| emitted_fields | jsonb | YES |  |
| scan_timestamp | timestamptz | YES | now() |
| version | integer | NO |  |
| change_type | varchar | YES |  |
| previous_hash | varchar | YES |  |
| diff_summary | jsonb | YES |  |

**Indexes:** 5
- `discovery_history_pkey`
- `idx_history_tenant`
- `idx_history_timestamp`
- `idx_history_hash`
- `idx_history_diff_summary_gin`

**PK:** id

### discovery_report (221 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| discovery_scan_id | varchar | NO |  |
| customer_id | varchar | YES |  |
| tenant_id | varchar | YES |  |
| provider | varchar | YES |  |
| hierarchy_id | varchar | YES |  |
| hierarchy_type | varchar | YES |  |
| region | varchar | YES |  |
| service | varchar | YES |  |
| scan_type | varchar | YES | 'discovery'::character varying |
| status | varchar | YES | 'running'::character varying |
| metadata | jsonb | YES | '{}'::jsonb |
| scan_timestamp | timestamp | YES | CURRENT_TIMESTAMP |
| created_at | timestamp | YES | CURRENT_TIMESTAMP |

**Indexes:** 1
- `scans_pkey`

**PK:** discovery_scan_id

### discovery_report_legacy (36 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| discovery_scan_id | varchar | NO |  |
| customer_id | varchar | NO |  |
| tenant_id | varchar | NO |  |
| provider | varchar | NO |  |
| hierarchy_id | varchar | YES |  |
| hierarchy_type | varchar | YES |  |
| region | varchar | YES |  |
| service | varchar | YES |  |
| scan_timestamp | timestamptz | YES | now() |
| scan_type | varchar | YES | 'discovery'::character varying |
| status | varchar | YES |  |
| metadata | jsonb | YES |  |
| execution_id | varchar | YES |  |

**Indexes:** 4
- `discoveries_report_pkey`
- `idx_discoveries_report_customer_tenant`
- `idx_discoveries_report_timestamp`
- `idx_discoveries_execution_id`

**PK:** discovery_scan_id

### rule_definitions (0 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| id | integer | NO | nextval('rule_definitions_id_seq'::regcl |
| csp | varchar | NO | 'aws'::character varying |
| service | varchar | NO |  |
| file_path | varchar | NO |  |
| content_yaml | text | NO |  |
| created_at | timestamptz | YES | now() |
| updated_at | timestamptz | YES | now() |

**Indexes:** 4
- `rule_definitions_pkey`
- `rule_definitions_csp_service_file_path_key`
- `idx_rule_definitions_csp_service`
- `idx_rule_definitions_csp`

**PK:** id
**UNIQUE:** csp, service, file_path

### tenants (1 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| tenant_id | varchar | NO |  |
| customer_id | varchar | YES |  |
| provider | varchar | YES |  |
| tenant_name | varchar | YES |  |
| metadata | jsonb | YES | '{}'::jsonb |
| created_at | timestamp | YES | CURRENT_TIMESTAMP |
| updated_at | timestamp | YES | CURRENT_TIMESTAMP |

**Indexes:** 1
- `tenants_pkey`

**PK:** tenant_id

## threat_engine_check


### check_findings (649,753 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| id | integer | NO | nextval('check_findings_id_seq'::regclas |
| check_scan_id | varchar | NO |  |
| customer_id | varchar | NO |  |
| tenant_id | varchar | NO |  |
| provider | varchar | NO |  |
| hierarchy_id | varchar | YES |  |
| hierarchy_type | varchar | YES |  |
| rule_id | varchar | NO |  |
| resource_uid | text | YES |  |
| resource_id | varchar | YES |  |
| resource_type | varchar | YES |  |
| status | varchar | NO |  |
| checked_fields | jsonb | YES |  |
| finding_data | jsonb | NO |  |
| created_at | timestamp | YES | now() |
| service | varchar | YES |  |
| discovery_id | varchar | YES |  |
| actual_values | jsonb | YES |  |
| region | varchar | YES |  |
| resource_service | varchar | YES |  |

**Indexes:** 11
- `check_findings_pkey`
- `idx_check_findings_check_scan_id`
- `idx_check_findings_tenant`
- `idx_check_findings_status`
- `idx_check_findings_rule_id`
- `idx_check_findings_resource_uid`
- `idx_check_findings_tenant_uid`
- `idx_check_findings_finding_data_gin`
- `idx_check_findings_service`
- `idx_check_findings_discovery_id`
- `idx_cf_resource_service`

**PK:** id
**FK:** check_scan_id (check_findings_check_scan_id_fkey)

### check_report (66 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| check_scan_id | varchar | NO |  |
| customer_id | varchar | NO |  |
| tenant_id | varchar | NO |  |
| provider | varchar | NO |  |
| hierarchy_id | varchar | YES |  |
| hierarchy_type | varchar | YES |  |
| region | varchar | YES |  |
| service | varchar | YES |  |
| scan_timestamp | timestamptz | YES | now() |
| scan_type | varchar | YES | 'check'::character varying |
| status | varchar | YES |  |
| metadata | jsonb | YES |  |
| execution_id | varchar | YES |  |
| discovery_scan_id | varchar | YES |  |

**Indexes:** 3
- `check_report_pkey`
- `idx_check_report_customer_tenant`
- `idx_check_report_check_scan_id_timestamp`

**PK:** check_scan_id

### rule_checks (10,440 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| id | integer | NO | nextval('rule_checks_id_seq'::regclass) |
| rule_id | varchar | NO |  |
| service | varchar | NO |  |
| provider | varchar | NO | 'aws'::character varying |
| check_type | varchar | YES | 'default'::character varying |
| customer_id | varchar | YES |  |
| tenant_id | varchar | YES |  |
| check_config | jsonb | NO | '{}'::jsonb |
| is_active | boolean | YES | true |
| created_at | timestamptz | YES | now() |
| updated_at | timestamptz | YES | now() |
| version | varchar | YES | '1.0'::character varying |
| source | varchar | NO | 'default'::character varying |
| generated_by | varchar | YES | 'default'::character varying |

**Indexes:** 8
- `rule_checks_pkey`
- `rule_checks_rule_id_customer_id_tenant_id_key`
- `idx_rule_checks_rule_id`
- `idx_rule_checks_service`
- `idx_rule_checks_customer`
- `idx_rule_checks_rule_id_unique`
- `idx_rule_checks_service_provider`
- `idx_rule_checks_active`

**PK:** id
**UNIQUE:** rule_id, customer_id, tenant_id

### rule_discoveries (1,087 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| id | integer | NO | nextval('rule_discoveries_id_seq'::regcl |
| service | varchar | NO |  |
| provider | varchar | NO | 'aws'::character varying |
| version | varchar | YES |  |
| discoveries_data | jsonb | NO | '[]'::jsonb |
| customer_id | varchar | YES |  |
| tenant_id | varchar | YES |  |
| created_at | timestamptz | YES | now() |
| updated_at | timestamptz | YES | now() |
| source | varchar | NO | 'default'::character varying |
| generated_by | varchar | YES | 'default'::character varying |
| is_active | boolean | YES | true |
| boto3_client_name | varchar | YES |  |
| arn_identifier | varchar | YES |  |
| arn_identifier_independent_methods | ARRAY | YES |  |
| arn_identifier_dependent_methods | ARRAY | YES |  |
| filter_rules | jsonb | YES | '{}'::jsonb |

**Indexes:** 9
- `rule_discoveries_pkey`
- `rule_discoveries_service_provider_customer_id_tenant_id_key`
- `idx_rule_discoveries_service`
- `idx_rule_discoveries_provider`
- `idx_rule_discoveries_customer_tenant`
- `idx_rule_disc_service_provider`
- `idx_rule_discoveries_boto3_client`
- `idx_rule_discoveries_arn_identifier`
- `idx_rule_discoveries_filter_rules`

**PK:** id
**UNIQUE:** service, provider, customer_id, tenant_id

### rule_metadata (10,440 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| id | integer | NO | nextval('rule_metadata_id_seq'::regclass |
| rule_id | varchar | NO |  |
| service | varchar | NO |  |
| provider | varchar | NO | 'aws'::character varying |
| resource | varchar | YES |  |
| severity | varchar | NO | 'medium'::character varying |
| title | text | NO |  |
| description | text | YES |  |
| remediation | text | YES |  |
| rationale | text | YES |  |
| domain | varchar | YES |  |
| subcategory | varchar | YES |  |
| requirement | varchar | YES |  |
| assertion_id | varchar | YES |  |
| compliance_frameworks | jsonb | YES |  |
| data_security | jsonb | YES |  |
| iam_security | jsonb | YES | '{}'::jsonb |
| references | jsonb | YES |  |
| metadata_source | varchar | NO | 'default'::character varying |
| source | varchar | NO | 'default'::character varying |
| generated_by | varchar | YES | 'default'::character varying |
| customer_id | varchar | YES |  |
| tenant_id | varchar | YES |  |
| created_at | timestamptz | YES | now() |
| updated_at | timestamptz | YES | now() |
| threat_category | varchar | YES |  |
| threat_tags | jsonb | YES | '[]'::jsonb |
| risk_score | integer | YES | 50 |
| risk_indicators | jsonb | YES | '{}'::jsonb |
| version | varchar | YES | '1.0'::character varying |
| mitre_tactics | jsonb | YES | '[]'::jsonb |
| mitre_techniques | jsonb | YES | '[]'::jsonb |
| posture_category | varchar | YES |  |
| resource_service | varchar | YES |  |

**Indexes:** 14
- `rule_metadata_pkey`
- `rule_metadata_rule_id_customer_id_tenant_id_key`
- `idx_rule_metadata_rule_id`
- `idx_rule_metadata_service`
- `idx_rule_metadata_severity`
- `idx_rule_metadata_source`
- `idx_rule_metadata_provider`
- `idx_rule_metadata_threat_category`
- `idx_rule_metadata_risk_score`
- `idx_rule_metadata_customer_tenant`
- `idx_rule_meta_rule_id`
- `idx_rule_meta_service`
- `idx_rule_metadata_posture`
- `idx_rm_resource_service`

**PK:** id
**UNIQUE:** rule_id, customer_id, tenant_id

## threat_engine_inventory


### inventory_asset_collection_membership (2 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| membership_id | uuid | NO | uuid_generate_v4() |
| collection_id | uuid | NO |  |
| asset_id | uuid | NO |  |
| tenant_id | varchar | NO |  |
| membership_reason | varchar | YES |  |
| added_by | varchar | YES |  |
| added_at | timestamptz | YES | now() |

**Indexes:** 4
- `asset_collection_membership_pkey`
- `asset_collection_membership_collection_id_asset_id_key`
- `idx_membership_collection`
- `idx_membership_asset`

**PK:** membership_id
**UNIQUE:** collection_id, asset_id
**FK:** collection_id (fk_collection_membership)
**FK:** asset_id (fk_asset_membership)
**FK:** tenant_id (fk_tenant_membership)

### inventory_asset_collections (4 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| collection_id | uuid | NO | uuid_generate_v4() |
| tenant_id | varchar | NO |  |
| name | varchar | NO |  |
| collection_type | varchar | NO |  |
| description | text | YES |  |
| collection_criteria | jsonb | YES |  |
| is_dynamic | boolean | YES | true |
| owner | varchar | YES |  |
| business_criticality | varchar | YES |  |
| created_at | timestamptz | YES | now() |
| updated_at | timestamptz | YES | now() |
| filters | jsonb | YES | '{}'::jsonb |
| auto_assign | boolean | YES | false |

**Indexes:** 7
- `asset_collections_pkey`
- `asset_collections_tenant_id_collection_name_key`
- `idx_collection_tenant`
- `idx_collection_type`
- `idx_collection_criticality`
- `idx_collection_criteria_gin`
- `idx_collection_name_trgm`

**PK:** collection_id
**UNIQUE:** tenant_id, name
**FK:** tenant_id (fk_tenant_collection)

### inventory_asset_history (5 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| history_id | uuid | NO | uuid_generate_v4() |
| asset_id | uuid | NO |  |
| tenant_id | varchar | NO |  |
| resource_uid | text | NO |  |
| inventory_scan_id | varchar | NO |  |
| change_type | varchar | NO |  |
| previous_state | jsonb | YES |  |
| current_state | jsonb | NO |  |
| changes_summary | jsonb | YES | '{}'::jsonb |
| detected_at | timestamptz | YES | now() |

**Indexes:** 5
- `asset_history_pkey`
- `idx_history_asset`
- `idx_history_tenant`
- `idx_history_change_type`
- `idx_history_changes_gin`

**PK:** history_id
**FK:** asset_id (fk_asset_history)
**FK:** tenant_id (fk_tenant_history)
**FK:** inventory_scan_id (fk_inventory_report_history)

### inventory_asset_metrics (6 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| metric_id | uuid | NO | uuid_generate_v4() |
| asset_id | uuid | NO |  |
| tenant_id | varchar | NO |  |
| scan_run_id | varchar | YES |  |
| metric_type | varchar | NO |  |
| metric_name | varchar | NO |  |
| metric_value | numeric | YES |  |
| metric_unit | varchar | YES |  |
| metric_timestamp | timestamptz | NO |  |
| aggregation_period | varchar | YES |  |
| metadata | jsonb | YES | '{}'::jsonb |
| created_at | timestamptz | YES | now() |

**Indexes:** 4
- `asset_metrics_pkey`
- `idx_metrics_asset`
- `idx_metrics_type`
- `idx_metrics_timestamp`

**PK:** metric_id
**FK:** asset_id (fk_asset_metric)
**FK:** tenant_id (fk_tenant_metric)

### inventory_asset_tags_index (0 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| tag_id | uuid | NO | uuid_generate_v4() |
| asset_id | uuid | NO |  |
| tenant_id | varchar | NO |  |
| tag_key | varchar | NO |  |
| tag_value | varchar | YES |  |
| tag_source | varchar | YES | 'provider'::character varying |
| created_at | timestamptz | YES | now() |
| resource_uid | text | YES |  |
| inventory_scan_id | varchar | YES |  |

**Indexes:** 6
- `asset_tags_index_pkey`
- `asset_tags_index_asset_id_tag_key_key`
- `idx_tags_asset`
- `idx_tags_key_value`
- `idx_tags_tenant`
- `idx_tags_scan`

**PK:** tag_id
**UNIQUE:** asset_id, tag_key
**FK:** asset_id (fk_asset_tag)
**FK:** tenant_id (fk_tenant_tag)

### inventory_drift (45,094 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| id | integer | NO | nextval('inventory_drift_id_seq'::regcla |
| drift_id | uuid | YES | uuid_generate_v4() |
| inventory_scan_id | varchar | NO |  |
| previous_scan_id | varchar | YES |  |
| tenant_id | varchar | NO |  |
| customer_id | varchar | YES |  |
| asset_id | uuid | YES |  |
| resource_uid | text | NO |  |
| provider | varchar | YES |  |
| resource_type | varchar | YES |  |
| change_type | varchar | NO |  |
| previous_state | jsonb | YES |  |
| current_state | jsonb | YES |  |
| changes_summary | jsonb | YES | '{}'::jsonb |
| severity | varchar | YES | 'info'::character varying |
| detected_at | timestamptz | YES | now() |
| created_at | timestamptz | YES | now() |

**Indexes:** 10
- `inventory_drift_pkey`
- `inventory_drift_drift_id_key`
- `idx_inventory_drift_scan`
- `idx_inventory_drift_tenant`
- `idx_inventory_drift_resource_uid`
- `idx_inventory_drift_asset`
- `idx_inventory_drift_change_type`
- `idx_inventory_drift_severity`
- `idx_inventory_drift_detected`
- `idx_inventory_drift_provider_type`

**PK:** id
**UNIQUE:** drift_id

### inventory_findings (14,768 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| asset_id | uuid | NO | uuid_generate_v4() |
| tenant_id | varchar | NO |  |
| resource_uid | text | NO |  |
| provider | varchar | NO |  |
| account_id | varchar | NO |  |
| region | varchar | YES |  |
| resource_type | varchar | NO |  |
| resource_id | varchar | NO |  |
| name | varchar | YES |  |
| display_name | varchar | YES |  |
| description | text | YES |  |
| tags | jsonb | YES | '{}'::jsonb |
| labels | jsonb | YES | '{}'::jsonb |
| properties | jsonb | YES | '{}'::jsonb |
| configuration | jsonb | YES | '{}'::jsonb |
| compliance_status | varchar | YES |  |
| risk_score | integer | YES |  |
| criticality | varchar | YES |  |
| environment | varchar | YES |  |
| cost_center | varchar | YES |  |
| owner | varchar | YES |  |
| business_unit | varchar | YES |  |
| latest_scan_run_id | varchar | YES |  |
| first_discovered_at | timestamptz | YES | now() |
| last_modified_at | timestamptz | YES |  |
| updated_at | timestamptz | YES | now() |
| inventory_scan_id | varchar | YES |  |
| customer_id | varchar | YES |  |

**Indexes:** 25
- `asset_index_latest_pkey`
- `asset_index_latest_resource_uid_tenant_id_key`
- `idx_asset_tenant`
- `idx_asset_resource_uid`
- `idx_asset_provider`
- `idx_asset_resource_type`
- `idx_asset_region`
- `idx_asset_account`
- `idx_asset_environment`
- `idx_asset_criticality`
- `idx_asset_compliance`
- `idx_asset_risk_score`
- `idx_asset_owner`
- `idx_asset_tenant_type`
- `idx_asset_tenant_region`
- `idx_asset_tenant_provider`
- `idx_asset_criticality_compliance`
- `idx_asset_tags_gin`
- `idx_asset_labels_gin`
- `idx_asset_properties_gin`
- `idx_asset_configuration_gin`
- `idx_asset_name_trgm`
- `idx_asset_display_name_trgm`
- `idx_asset_description_trgm`
- `idx_inventory_findings_scan_id`

**PK:** asset_id
**UNIQUE:** resource_uid, tenant_id
**FK:** tenant_id (fk_tenant_asset)
**FK:** inventory_scan_id (fk_inventory_report)

### inventory_relationships (4,294 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| relationship_id | uuid | NO | uuid_generate_v4() |
| tenant_id | varchar | NO |  |
| inventory_scan_id | varchar | NO |  |
| provider | varchar | NO |  |
| account_id | varchar | NO |  |
| region | varchar | YES |  |
| relation_type | varchar | NO |  |
| from_uid | text | NO |  |
| to_uid | text | NO |  |
| from_resource_type | varchar | YES |  |
| to_resource_type | varchar | YES |  |
| relationship_strength | varchar | YES | 'strong'::character varying |
| bidirectional | boolean | YES | false |
| properties | jsonb | YES | '{}'::jsonb |
| metadata | jsonb | YES | '{}'::jsonb |
| first_discovered_at | timestamptz | YES | now() |
| last_confirmed_at | timestamptz | YES | now() |
| created_at | timestamptz | YES | now() |
| source_resource_uid | text | YES |  |
| target_resource_uid | text | YES |  |
| relationship_type | varchar | YES |  |

**Indexes:** 10
- `relationship_index_latest_pkey`
- `idx_rel_tenant`
- `idx_rel_from_uid`
- `idx_rel_to_uid`
- `idx_rel_type`
- `idx_rel_bidirectional`
- `idx_relationship_properties_gin`
- `idx_rel_source_uid`
- `idx_rel_target_uid`
- `idx_rel_relationship_type`

**PK:** relationship_id
**FK:** tenant_id (fk_tenant_rel)
**FK:** inventory_scan_id (fk_scan_run_rel)
**FK:** inventory_scan_id (fk_inventory_report_relationship)

### inventory_report (62 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| inventory_scan_id | varchar | NO |  |
| tenant_id | varchar | NO |  |
| started_at | timestamptz | NO |  |
| completed_at | timestamptz | YES |  |
| status | varchar | NO |  |
| total_assets | integer | NO | 0 |
| total_relationships | integer | NO | 0 |
| assets_by_provider | jsonb | YES | '{}'::jsonb |
| assets_by_resource_type | jsonb | YES | '{}'::jsonb |
| assets_by_region | jsonb | YES | '{}'::jsonb |
| providers_scanned | jsonb | YES | '[]'::jsonb |
| accounts_scanned | jsonb | YES | '[]'::jsonb |
| regions_scanned | jsonb | YES | '[]'::jsonb |
| errors_count | integer | NO | 0 |
| scan_metadata | jsonb | YES | '{}'::jsonb |
| created_at | timestamptz | YES | now() |
| execution_id | varchar | YES |  |
| discovery_scan_id | varchar | YES |  |
| customer_id | varchar | YES |  |

**Indexes:** 7
- `inventory_run_index_pkey`
- `idx_run_tenant`
- `idx_run_completed_at`
- `idx_run_status`
- `idx_run_assets_by_provider_gin`
- `idx_run_assets_by_type_gin`
- `idx_inventory_report_discovery_scan_id`

**PK:** inventory_scan_id
**FK:** tenant_id (fk_tenant)

### inventory_scan_data (39,081 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| id | integer | NO | nextval('inventory_scan_data_id_seq'::re |
| inventory_scan_id | varchar | NO |  |
| tenant_id | varchar | NO |  |
| asset_id | uuid | NO |  |
| resource_uid | text | NO |  |
| provider | varchar | YES |  |
| account_id | varchar | YES |  |
| region | varchar | YES |  |
| resource_type | varchar | YES |  |
| resource_id | varchar | YES |  |
| name | varchar | YES |  |
| tags | jsonb | YES | '{}'::jsonb |
| labels | jsonb | YES | '{}'::jsonb |
| properties | jsonb | YES | '{}'::jsonb |
| configuration | jsonb | YES | '{}'::jsonb |
| created_at | timestamptz | YES | now() |

**Indexes:** 4
- `inventory_scan_data_pkey`
- `idx_scan_data_scan`
- `idx_scan_data_resource`
- `idx_scan_data_tenant`

**PK:** id
**FK:** inventory_scan_id (inventory_scan_data_inventory_scan_id_fkey)

### inventory_scans (3 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| scan_run_id | varchar | NO |  |
| tenant_id | varchar | NO |  |
| discovery_scan_id | varchar | YES |  |
| status | varchar | NO |  |
| total_assets | integer | YES | 0 |
| total_relationships | integer | YES | 0 |
| started_at | timestamptz | NO |  |
| completed_at | timestamptz | YES |  |
| error_message | text | YES |  |
| created_at | timestamptz | YES | now() |

**Indexes:** 3
- `inventory_scans_pkey`
- `idx_scans_tenant`
- `idx_scans_status`

**PK:** scan_run_id
**FK:** tenant_id (fk_scans_tenant)

### resource_inventory_identifier (6,686 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| id | bigint | NO | nextval('resource_inventory_identifier_i |
| csp | varchar | NO |  |
| service | varchar | NO |  |
| resource_type | varchar | NO |  |
| classification | varchar | NO |  |
| has_arn | boolean | NO | true |
| arn_entity | varchar | YES |  |
| identifier_type | varchar | YES | 'arn'::character varying |
| primary_param | varchar | YES |  |
| identifier_pattern | varchar | YES |  |
| can_inventory_from_roots | boolean | NO | true |
| should_inventory | boolean | NO | true |
| root_ops | jsonb | NO | '[]'::jsonb |
| enrich_ops | jsonb | NO | '[]'::jsonb |
| raw_catalog | jsonb | YES |  |
| loaded_at | timestamptz | NO | now() |
| updated_at | timestamptz | NO | now() |
| parent_service | varchar | YES |  |
| parent_resource_type | varchar | YES |  |
| canonical_type | varchar | YES |  |
| scope | varchar | YES |  |
| category | varchar | YES |  |
| subcategory | varchar | YES |  |
| service_model | varchar | YES |  |
| managed_by | varchar | YES |  |
| access_pattern | varchar | YES |  |
| encryption_scope | varchar | YES |  |
| is_container | boolean | YES | false |
| container_parent | varchar | YES |  |
| diagram_priority | smallint | YES | 5 |
| csp_category | varchar | YES |  |
| asset_category | varchar | YES |  |

**Indexes:** 16
- `resource_inventory_identifier_pkey`
- `rii_unique`
- `idx_rii_csp_service`
- `idx_rii_csp`
- `idx_rii_classification`
- `idx_rii_should_inventory`
- `idx_rii_arn_entity`
- `idx_rii_root_ops_gin`
- `idx_rii_enrich_ops_gin`
- `idx_rii_parent`
- `idx_rii_canonical_type`
- `idx_rii_csp_category`
- `idx_rii_scope`
- `idx_rii_diagram_priority`
- `idx_rii_container_parent`
- `idx_rii_service_model`

**PK:** id
**UNIQUE:** csp, service, resource_type

### resource_relationship_rules (2,041 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| rule_id | bigint | NO | nextval('resource_relationship_rules_rul |
| csp | varchar | NO |  |
| service | varchar | YES |  |
| from_resource_type | varchar | NO |  |
| relation_type | varchar | NO |  |
| to_resource_type | varchar | NO |  |
| source_field | varchar | NO |  |
| source_field_item | varchar | YES |  |
| target_uid_pattern | text | NO |  |
| is_active | boolean | NO | true |
| rule_source | varchar | NO | 'auto'::character varying |
| rule_metadata | jsonb | NO | '{}'::jsonb |
| created_at | timestamptz | NO | now() |
| updated_at | timestamptz | NO | now() |
| attack_path_category | varchar | YES |  |

**Indexes:** 4
- `resource_relationship_rules_pkey`
- `uq_resource_rel_rule`
- `idx_rrr_csp_from_type`
- `idx_rrr_csp`

**PK:** rule_id
**UNIQUE:** csp, from_resource_type, relation_type, to_resource_type, source_field

### service_classification (6,705 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| id | integer | NO | nextval('service_classification_id_seq': |
| csp | varchar | NO |  |
| resource_type | varchar | NO |  |
| service | varchar | NO |  |
| resource_name | varchar | NO |  |
| display_name | varchar | YES |  |
| scope | varchar | NO | 'regional'::character varying |
| category | varchar | NO |  |
| subcategory | varchar | YES |  |
| service_model | varchar | YES | 'PaaS'::character varying |
| managed_by | varchar | YES | 'shared'::character varying |
| access_pattern | varchar | YES | 'private'::character varying |
| is_container | boolean | YES | false |
| container_parent | varchar | YES |  |
| encryption_scope | varchar | YES |  |
| diagram_priority | smallint | YES | 3 |
| csp_category | varchar | YES |  |
| created_at | timestamp | YES | now() |
| updated_at | timestamp | YES | now() |
| resource_role | varchar | YES | 'primary'::character varying |

**Indexes:** 9
- `service_classification_pkey`
- `idx_svc_class_csp_category`
- `idx_svc_class_scope`
- `idx_svc_class_priority`
- `idx_svc_class_container`
- `idx_svc_class_service_model`
- `uq_service_classification`
- `idx_svc_class_resource_type`
- `idx_sc_resource_role`

**PK:** id
**UNIQUE:** csp, resource_type

### tenants (10 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| tenant_id | varchar | NO |  |
| tenant_name | varchar | YES |  |
| created_at | timestamptz | YES | now() |

**Indexes:** 1
- `tenants_pkey`

**PK:** tenant_id

## threat_engine_threat


### mitre_technique_reference (102 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| id | integer | NO | nextval('mitre_technique_reference_id_se |
| technique_id | varchar | NO |  |
| technique_name | text | NO |  |
| tactics | jsonb | YES | '[]'::jsonb |
| sub_techniques | jsonb | YES | '[]'::jsonb |
| description | text | YES |  |
| url | text | YES |  |
| platforms | jsonb | YES | '[]'::jsonb |
| aws_checks | jsonb | YES | '[]'::jsonb |
| azure_checks | jsonb | YES | '[]'::jsonb |
| gcp_checks | jsonb | YES | '[]'::jsonb |
| ibm_keywords | jsonb | YES | '[]'::jsonb |
| k8s_keywords | jsonb | YES | '[]'::jsonb |
| ocp_keywords | jsonb | YES | '[]'::jsonb |
| aws_service_coverage | jsonb | YES | '{}'::jsonb |
| detection_keywords | jsonb | YES | '[]'::jsonb |
| created_at | timestamp | YES | now() |
| updated_at | timestamp | YES | now() |
| detection_guidance | jsonb | YES | '{}'::jsonb |
| remediation_guidance | jsonb | YES | '{}'::jsonb |
| severity_base | varchar | YES |  |

**Indexes:** 4
- `mitre_technique_reference_pkey`
- `mitre_technique_reference_technique_id_key`
- `idx_mitre_technique_id`
- `idx_mitre_tactics`

**PK:** id
**UNIQUE:** technique_id

### tenants (6 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| tenant_id | varchar | NO |  |
| tenant_name | varchar | YES |  |
| created_at | timestamptz | YES | now() |

**Indexes:** 1
- `tenants_pkey`

**PK:** tenant_id

### threat_analysis (3,618 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| analysis_id | uuid | NO | uuid_generate_v4() |
| detection_id | uuid | NO |  |
| tenant_id | varchar | NO |  |
| analysis_type | varchar | NO |  |
| analyzer | varchar | YES |  |
| analysis_status | varchar | NO | 'pending'::character varying |
| risk_score | integer | YES |  |
| verdict | varchar | YES |  |
| analysis_results | jsonb | NO |  |
| recommendations | jsonb | YES | '[]'::jsonb |
| related_threats | jsonb | YES | '[]'::jsonb |
| attack_chain | jsonb | YES | '[]'::jsonb |
| started_at | timestamptz | NO | now() |
| completed_at | timestamptz | YES |  |
| created_at | timestamptz | YES | now() |

**Indexes:** 6
- `threat_analysis_pkey`
- `idx_analysis_detection`
- `idx_analysis_status`
- `idx_analysis_verdict`
- `idx_analysis_results_gin`
- `uq_detection_analysis_type`

**PK:** analysis_id
**UNIQUE:** detection_id, analysis_type
**FK:** detection_id (fk_detection_analysis)
**FK:** tenant_id (fk_tenant_analysis)

### threat_detections (3,618 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| detection_id | uuid | NO | uuid_generate_v4() |
| tenant_id | varchar | NO |  |
| scan_id | varchar | YES |  |
| detection_type | varchar | NO |  |
| rule_id | varchar | YES |  |
| rule_name | varchar | YES |  |
| resource_id | varchar | YES |  |
| resource_type | varchar | YES |  |
| account_id | varchar | YES |  |
| region | varchar | YES |  |
| provider | varchar | YES |  |
| severity | varchar | NO |  |
| confidence | varchar | NO |  |
| status | varchar | NO | 'open'::character varying |
| threat_category | varchar | YES |  |
| mitre_tactics | jsonb | YES | '[]'::jsonb |
| mitre_techniques | jsonb | YES | '[]'::jsonb |
| indicators | jsonb | YES | '[]'::jsonb |
| evidence | jsonb | NO |  |
| context | jsonb | YES | '{}'::jsonb |
| detection_timestamp | timestamptz | NO | now() |
| first_seen_at | timestamptz | NO | now() |
| last_seen_at | timestamptz | NO | now() |
| resolved_at | timestamptz | YES |  |
| resolved_by | varchar | YES |  |
| resolution_notes | text | YES |  |
| created_at | timestamptz | YES | now() |
| updated_at | timestamptz | YES | now() |
| resource_uid | text | YES |  |

**Indexes:** 11
- `threat_detections_pkey`
- `idx_detection_tenant`
- `idx_detection_status_severity`
- `idx_detection_timestamp`
- `idx_detection_rule`
- `idx_detection_account`
- `idx_detection_evidence_gin`
- `idx_detection_indicators_gin`
- `idx_detection_mitre_gin`
- `idx_detection_rule_name_trgm`
- `idx_detection_resource_uid`

**PK:** detection_id
**FK:** tenant_id (fk_tenant_detection)

### threat_findings (38,551 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| id | integer | NO | nextval('threat_findings_id_seq'::regcla |
| finding_id | varchar | NO |  |
| threat_scan_id | varchar | NO |  |
| tenant_id | varchar | NO |  |
| customer_id | varchar | YES |  |
| scan_run_id | varchar | NO |  |
| rule_id | varchar | NO |  |
| threat_category | varchar | YES |  |
| severity | varchar | NO |  |
| status | varchar | NO |  |
| resource_type | varchar | YES |  |
| resource_id | varchar | YES |  |
| resource_uid | text | YES |  |
| account_id | varchar | YES |  |
| region | varchar | YES |  |
| mitre_tactics | jsonb | YES | '[]'::jsonb |
| mitre_techniques | jsonb | YES | '[]'::jsonb |
| evidence | jsonb | NO | '{}'::jsonb |
| finding_data | jsonb | NO | '{}'::jsonb |
| first_seen_at | timestamptz | YES | now() |
| last_seen_at | timestamptz | YES | now() |
| created_at | timestamptz | YES | now() |

**Indexes:** 6
- `threat_findings_pkey`
- `threat_findings_finding_id_key`
- `idx_threat_findings_scan_id`
- `idx_threat_findings_resource_uid`
- `idx_threat_findings_tenant`
- `idx_threat_findings_severity`

**PK:** id
**UNIQUE:** finding_id
**FK:** threat_scan_id (fk_threat_report_findings)
**FK:** tenant_id (fk_tenant_threat_findings)

### threat_hunt_queries (111 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| hunt_id | uuid | NO | uuid_generate_v4() |
| tenant_id | varchar | NO |  |
| query_name | varchar | NO |  |
| description | text | YES |  |
| hunt_type | varchar | NO |  |
| query_language | varchar | NO |  |
| query_text | text | NO |  |
| target_data_sources | jsonb | YES | '[]'::jsonb |
| mitre_tactics | jsonb | YES | '[]'::jsonb |
| mitre_techniques | jsonb | YES | '[]'::jsonb |
| tags | jsonb | YES | '[]'::jsonb |
| schedule_cron | varchar | YES |  |
| is_active | boolean | YES | true |
| last_executed_at | timestamptz | YES |  |
| execution_count | integer | YES | 0 |
| hit_count | integer | YES | 0 |
| created_by | varchar | YES |  |
| created_at | timestamptz | YES | now() |
| updated_at | timestamptz | YES | now() |

**Indexes:** 5
- `threat_hunt_queries_pkey`
- `idx_hunt_tenant_active`
- `idx_hunt_schedule`
- `idx_hunt_last_executed`
- `idx_hunt_query_name_trgm`

**PK:** hunt_id
**FK:** tenant_id (fk_tenant_hunt)

### threat_hunt_results (1 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| result_id | uuid | NO | uuid_generate_v4() |
| hunt_id | uuid | NO |  |
| tenant_id | varchar | NO |  |
| execution_timestamp | timestamptz | NO | now() |
| total_results | integer | NO | 0 |
| new_detections | integer | NO | 0 |
| execution_time_ms | integer | YES |  |
| results_data | jsonb | NO |  |
| status | varchar | NO | 'completed'::character varying |
| error_message | text | YES |  |
| created_at | timestamptz | YES | now() |

**Indexes:** 4
- `threat_hunt_results_pkey`
- `idx_hunt_results_hunt`
- `idx_hunt_results_tenant`
- `idx_hunt_results_data_gin`

**PK:** result_id
**FK:** hunt_id (fk_hunt_result)
**FK:** tenant_id (fk_tenant_hunt_result)

### threat_intelligence (160 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| intel_id | uuid | NO | uuid_generate_v4() |
| tenant_id | varchar | NO |  |
| source | varchar | NO |  |
| intel_type | varchar | NO |  |
| category | varchar | YES |  |
| severity | varchar | NO |  |
| confidence | varchar | NO |  |
| value_hash | varchar | NO |  |
| threat_data | jsonb | NO |  |
| indicators | jsonb | YES | '[]'::jsonb |
| ttps | jsonb | YES | '[]'::jsonb |
| tags | jsonb | YES | '[]'::jsonb |
| first_seen_at | timestamptz | NO | now() |
| last_seen_at | timestamptz | NO | now() |
| expires_at | timestamptz | YES |  |
| is_active | boolean | YES | true |
| created_at | timestamptz | YES | now() |
| updated_at | timestamptz | YES | now() |

**Indexes:** 9
- `threat_intelligence_pkey`
- `idx_intel_tenant`
- `idx_intel_type_severity`
- `idx_intel_hash`
- `idx_intel_active`
- `idx_intel_expires`
- `idx_intel_data_gin`
- `idx_intel_indicators_gin`
- `idx_intel_ttps_gin`

**PK:** intel_id
**FK:** tenant_id (fk_tenant_intel)

### threat_report (13 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| threat_scan_id | varchar | NO |  |
| execution_id | varchar | YES |  |
| discovery_scan_id | varchar | YES |  |
| check_scan_id | varchar | YES |  |
| tenant_id | varchar | NO |  |
| customer_id | varchar | YES |  |
| provider | varchar | NO |  |
| scan_run_id | varchar | NO |  |
| started_at | timestamptz | NO | now() |
| completed_at | timestamptz | YES |  |
| status | varchar | YES | 'completed'::character varying |
| total_findings | integer | YES | 0 |
| critical_findings | integer | YES | 0 |
| high_findings | integer | YES | 0 |
| medium_findings | integer | YES | 0 |
| low_findings | integer | YES | 0 |
| threat_score | integer | YES | 0 |
| report_data | jsonb | NO | '{}'::jsonb |
| created_at | timestamptz | YES | now() |

**Indexes:** 5
- `threat_report_pkey`
- `idx_threat_report_tenant`
- `idx_threat_report_execution_id`
- `idx_threat_report_discovery_scan_id`
- `idx_threat_report_check_scan_id`

**PK:** threat_scan_id
**FK:** tenant_id (fk_tenant_threat_report)

## threat_engine_compliance


### compliance_assessments (0 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| assessment_id | uuid | NO | uuid_generate_v4() |
| tenant_id | varchar | NO |  |
| framework_id | varchar | NO |  |
| assessment_name | varchar | NO |  |
| assessment_type | varchar | NO |  |
| scope_description | text | YES |  |
| assessor | varchar | YES |  |
| status | varchar | NO | 'draft'::character varying |
| started_at | timestamptz | NO |  |
| target_completion_at | timestamptz | YES |  |
| completed_at | timestamptz | YES |  |
| total_controls | integer | YES | 0 |
| controls_implemented | integer | YES | 0 |
| controls_not_applicable | integer | YES | 0 |
| controls_deficient | integer | YES | 0 |
| overall_score | numeric | YES |  |
| assessment_data | jsonb | YES | '{}'::jsonb |
| created_at | timestamptz | YES | now() |
| updated_at | timestamptz | YES | now() |

**Indexes:** 5
- `compliance_assessments_pkey`
- `idx_assessment_tenant`
- `idx_assessment_framework`
- `idx_assessment_completion`
- `idx_assessment_data_gin`

**PK:** assessment_id
**FK:** tenant_id (fk_tenant_assessment)
**FK:** framework_id (fk_framework_assessment)

### compliance_controls (960 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| control_id | varchar | NO |  |
| framework_id | varchar | NO |  |
| control_number | varchar | YES |  |
| control_name | varchar | NO |  |
| control_description | text | YES |  |
| control_type | varchar | YES |  |
| severity | varchar | YES |  |
| control_family | varchar | YES |  |
| implementation_guidance | text | YES |  |
| testing_procedures | text | YES |  |
| is_active | boolean | YES | true |
| control_data | jsonb | YES | '{}'::jsonb |
| created_at | timestamptz | YES | now() |
| updated_at | timestamptz | YES | now() |

**Indexes:** 6
- `compliance_controls_pkey`
- `idx_controls_framework`
- `idx_controls_severity`
- `idx_controls_family`
- `idx_control_data_gin`
- `idx_control_name_trgm`

**PK:** control_id
**FK:** framework_id (fk_framework)

### compliance_data (1,733 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| unique_compliance_id | text | NO |  |
| technology | text | YES |  |
| compliance_framework | text | NO |  |
| framework_id | text | NO |  |
| framework_version | text | YES |  |
| requirement_id | text | NO |  |
| requirement_name | text | NO |  |
| requirement_description | text | YES |  |
| section | text | YES |  |
| service | text | YES |  |
| total_checks | integer | YES | 0 |
| automation_type | text | YES |  |
| confidence_score | text | YES |  |
| references_text | text | YES |  |
| source_file | text | YES |  |
| csp | text | NO | 'aws'::text |
| mapped_rules | text | YES |  |
| created_at | timestamptz | NO | now() |

**Indexes:** 4
- `compliance_data_pkey`
- `idx_cd_framework_id`
- `idx_cd_compliance_fw`
- `idx_cd_csp`

**PK:** unique_compliance_id

### compliance_findings (61,023 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| finding_id | varchar | NO |  |
| compliance_scan_id | varchar | NO |  |
| tenant_id | varchar | NO |  |
| scan_run_id | varchar | NO |  |
| rule_id | varchar | NO |  |
| rule_version | varchar | YES |  |
| category | varchar | YES |  |
| severity | varchar | NO |  |
| confidence | varchar | NO |  |
| status | varchar | NO | 'open'::character varying |
| first_seen_at | timestamptz | NO |  |
| last_seen_at | timestamptz | NO |  |
| resource_type | varchar | YES |  |
| resource_id | varchar | YES |  |
| region | varchar | YES |  |
| finding_data | jsonb | NO |  |
| created_at | timestamptz | YES | now() |
| customer_id | varchar | YES |  |
| resource_uid | text | YES |  |
| compliance_framework | varchar | YES |  |
| control_id | varchar | YES |  |
| control_name | varchar | YES |  |
| account_id | varchar | YES |  |

**Indexes:** 14
- `finding_index_pkey`
- `idx_finding_tenant_scan`
- `idx_finding_severity`
- `idx_finding_status`
- `idx_finding_rule_id`
- `idx_finding_resource_type`
- `idx_finding_last_seen`
- `idx_finding_data_gin`
- `idx_finding_severity_status`
- `idx_finding_rule_status`
- `idx_finding_tenant_severity`
- `idx_compliance_findings_resource_uid`
- `idx_compliance_findings_scan_id`
- `idx_cf_resource_uid_trgm`

**PK:** finding_id
**FK:** tenant_id (fk_tenant_finding)
**FK:** compliance_scan_id (fk_compliance_report)

### compliance_frameworks (18 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| framework_id | varchar | NO |  |
| framework_name | varchar | NO |  |
| version | varchar | YES |  |
| description | text | YES |  |
| authority | varchar | YES |  |
| category | varchar | YES |  |
| is_active | boolean | YES | true |
| framework_data | jsonb | NO |  |
| created_at | timestamptz | YES | now() |
| updated_at | timestamptz | YES | now() |

**Indexes:** 2
- `compliance_frameworks_pkey`
- `idx_framework_data_gin`

**PK:** framework_id

### compliance_report (20 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| compliance_scan_id | varchar | NO | uuid_generate_v4() |
| tenant_id | varchar | NO |  |
| scan_run_id | varchar | NO |  |
| cloud | varchar | YES | 'aws'::character varying |
| trigger_type | varchar | NO |  |
| collection_mode | varchar | NO |  |
| started_at | timestamptz | NO |  |
| completed_at | timestamptz | NO |  |
| total_controls | integer | NO | 0 |
| controls_passed | integer | NO | 0 |
| controls_failed | integer | NO | 0 |
| total_findings | integer | NO | 0 |
| report_data | jsonb | NO |  |
| created_at | timestamptz | YES | now() |
| discovery_scan_id | varchar | YES |  |
| customer_id | varchar | YES |  |
| provider | varchar | YES | 'aws'::character varying |
| status | varchar | YES | 'completed'::character varying |
| execution_id | varchar | YES |  |
| check_scan_id | varchar | YES |  |

**Indexes:** 8
- `idx_report_tenant_scan`
- `idx_report_completed_at`
- `idx_report_cloud`
- `idx_report_data_gin`
- `idx_compliance_report_discovery_scan_id`
- `idx_compliance_report_execution_id`
- `idx_compliance_report_check_scan_id`
- `report_index_pkey`

**PK:** compliance_scan_id
**FK:** tenant_id (fk_tenant)

### compliance_rule_data_mapping (16,435 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| id | integer | NO | nextval('compliance_rule_data_mapping_id |
| rule_id | text | NO |  |
| unique_compliance_id | text | NO |  |
| framework_id | text | NO |  |
| compliance_framework | text | NO |  |
| csp | text | NO | 'aws'::text |
| created_at | timestamptz | NO | now() |

**Indexes:** 6
- `compliance_rule_data_mapping_pkey`
- `compliance_rule_data_mapping_rule_id_unique_compliance_id_key`
- `idx_crdm_rule_id`
- `idx_crdm_framework_id`
- `idx_crdm_compliance_fw`
- `idx_crdm_rule_framework`

**PK:** id
**UNIQUE:** rule_id, unique_compliance_id
**FK:** unique_compliance_id (compliance_rule_data_mapping_unique_compliance_id_fkey)

### control_assessment_results (0 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| result_id | uuid | NO | uuid_generate_v4() |
| assessment_id | uuid | NO |  |
| control_id | varchar | NO |  |
| tenant_id | varchar | NO |  |
| implementation_status | varchar | NO |  |
| effectiveness | varchar | YES |  |
| test_method | varchar | YES |  |
| test_results | text | YES |  |
| deficiencies | text | YES |  |
| recommendations | text | YES |  |
| evidence_references | jsonb | YES | '[]'::jsonb |
| residual_risk | varchar | YES |  |
| compensating_controls | text | YES |  |
| target_remediation_date | date | YES |  |
| actual_remediation_date | date | YES |  |
| assessed_by | varchar | YES |  |
| assessed_at | timestamptz | YES |  |
| reviewed_by | varchar | YES |  |
| reviewed_at | timestamptz | YES |  |
| result_data | jsonb | YES | '{}'::jsonb |
| created_at | timestamptz | YES | now() |
| updated_at | timestamptz | YES | now() |

**Indexes:** 5
- `control_assessment_results_pkey`
- `idx_control_results_assessment`
- `idx_control_results_status`
- `idx_control_results_risk`
- `idx_result_data_gin`

**PK:** result_id
**FK:** assessment_id (fk_assessment_result)
**FK:** control_id (fk_control_result)
**FK:** tenant_id (fk_tenant_result)

### remediation_tracking (0 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| remediation_id | uuid | NO | uuid_generate_v4() |
| tenant_id | varchar | NO |  |
| finding_id | varchar | YES |  |
| control_id | varchar | YES |  |
| issue_type | varchar | NO |  |
| priority | varchar | NO |  |
| status | varchar | NO | 'open'::character varying |
| title | varchar | NO |  |
| description | text | YES |  |
| remediation_plan | text | YES |  |
| assigned_to | varchar | YES |  |
| target_date | date | YES |  |
| actual_completion_date | date | YES |  |
| effort_estimate_hours | integer | YES |  |
| actual_effort_hours | integer | YES |  |
| cost_estimate | numeric | YES |  |
| actual_cost | numeric | YES |  |
| business_justification | text | YES |  |
| technical_details | jsonb | YES | '{}'::jsonb |
| progress_notes | jsonb | YES | '[]'::jsonb |
| verification_method | varchar | YES |  |
| verification_status | varchar | YES |  |
| verified_by | varchar | YES |  |
| verified_at | timestamptz | YES |  |
| created_by | varchar | YES |  |
| created_at | timestamptz | YES | now() |
| updated_at | timestamptz | YES | now() |

**Indexes:** 6
- `remediation_tracking_pkey`
- `idx_remediation_tenant`
- `idx_remediation_priority`
- `idx_remediation_assigned`
- `idx_remediation_finding`
- `idx_remediation_technical_gin`

**PK:** remediation_id
**FK:** tenant_id (fk_tenant_remediation)
**FK:** control_id (fk_control_remediation)

### rule_control_mapping (4,067 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| mapping_id | uuid | NO | uuid_generate_v4() |
| rule_id | text | NO |  |
| control_id | varchar | NO |  |
| framework_id | varchar | NO |  |
| mapping_type | varchar | YES | 'direct'::character varying |
| coverage_percentage | integer | YES | 100 |
| mapping_notes | text | YES |  |
| is_active | boolean | YES | true |
| created_at | timestamptz | YES | now() |
| updated_at | timestamptz | YES | now() |

**Indexes:** 4
- `rule_control_mapping_pkey`
- `idx_mapping_control`
- `rule_control_mapping_rule_id_control_id_key`
- `idx_mapping_rule`

**PK:** mapping_id
**UNIQUE:** rule_id, control_id
**FK:** control_id (fk_control_mapping)
**FK:** framework_id (fk_framework_mapping)

### tenants (6 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| tenant_id | varchar | NO |  |
| tenant_name | varchar | YES |  |
| created_at | timestamptz | YES | now() |

**Indexes:** 1
- `tenants_pkey`

**PK:** tenant_id

## threat_engine_iam


### iam_findings (19,789 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| finding_id | varchar | NO |  |
| iam_scan_id | varchar | NO |  |
| tenant_id | varchar | NO |  |
| scan_run_id | varchar | NO |  |
| rule_id | varchar | NO |  |
| iam_modules | ARRAY | YES |  |
| severity | varchar | NO |  |
| status | varchar | NO |  |
| resource_type | varchar | YES |  |
| resource_id | varchar | YES |  |
| account_id | varchar | YES |  |
| region | varchar | YES |  |
| finding_data | jsonb | NO |  |
| first_seen_at | timestamptz | YES | now() |
| last_seen_at | timestamptz | YES | now() |
| customer_id | varchar | YES |  |
| resource_uid | text | YES |  |
| hierarchy_id | varchar | YES |  |
| provider | varchar | YES | 'aws'::character varying |

**Indexes:** 10
- `iam_findings_pkey`
- `idx_iam_findings_tenant`
- `idx_iam_findings_rule`
- `idx_iam_findings_severity`
- `idx_iam_finding_data_gin`
- `idx_iam_findings_resource_uid`
- `idx_iam_findings_report`
- `idx_iam_findings_scan_id`
- `idx_iam_findings_provider`
- `idx_iam_findings_hierarchy`

**PK:** finding_id
**FK:** tenant_id (fk_tenant_finding)
**FK:** iam_scan_id (fk_iam_report)

### iam_report (33 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| iam_scan_id | varchar | NO | uuid_generate_v4() |
| tenant_id | varchar | NO |  |
| scan_run_id | varchar | NO |  |
| cloud | varchar | YES | 'aws'::character varying |
| generated_at | timestamptz | YES | now() |
| total_findings | integer | YES | 0 |
| iam_relevant_findings | integer | YES | 0 |
| critical_findings | integer | YES | 0 |
| high_findings | integer | YES | 0 |
| findings_by_module | jsonb | YES |  |
| findings_by_status | jsonb | YES |  |
| report_data | jsonb | NO |  |
| created_at | timestamptz | YES | now() |
| discovery_scan_id | varchar | YES |  |
| customer_id | varchar | YES |  |
| check_scan_id | varchar | YES |  |
| threat_scan_id | varchar | YES |  |
| status | varchar | YES | 'completed'::character varying |
| execution_id | varchar | YES |  |
| provider | varchar | YES | 'aws'::character varying |

**Indexes:** 8
- `idx_iam_reports_tenant`
- `idx_iam_reports_generated`
- `idx_iam_report_data_gin`
- `idx_iam_report_discovery_scan_id`
- `idx_iam_report_check_scan_id`
- `idx_iam_report_threat_scan_id`
- `iam_reports_pkey`
- `idx_iam_report_execution_id`

**PK:** iam_scan_id
**FK:** tenant_id (fk_tenant)

### tenants (6 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| tenant_id | varchar | NO |  |
| tenant_name | varchar | YES |  |
| created_at | timestamptz | YES | now() |

**Indexes:** 1
- `tenants_pkey`

**PK:** tenant_id

## threat_engine_datasec


### datasec_data_store_services (75 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| id | integer | NO | nextval('datasec_data_store_services_id_ |
| csp | varchar | NO | 'aws'::character varying |
| service_name | varchar | NO |  |
| is_active | boolean | NO | true |
| created_at | timestamptz | YES | now() |

**Indexes:** 3
- `datasec_data_store_services_pkey`
- `uq_datasec_svc`
- `idx_datasec_svc_csp`

**PK:** id
**UNIQUE:** csp, service_name

### datasec_findings (3,520 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| finding_id | varchar | NO |  |
| datasec_scan_id | varchar | NO |  |
| tenant_id | varchar | NO |  |
| scan_run_id | varchar | NO |  |
| rule_id | varchar | NO |  |
| datasec_modules | ARRAY | YES |  |
| severity | varchar | NO |  |
| status | varchar | NO |  |
| resource_type | varchar | YES |  |
| resource_id | varchar | YES |  |
| account_id | varchar | YES |  |
| region | varchar | YES |  |
| data_classification | ARRAY | YES |  |
| sensitivity_score | numeric | YES |  |
| finding_data | jsonb | NO |  |
| first_seen_at | timestamptz | YES | now() |
| last_seen_at | timestamptz | YES | now() |
| customer_id | varchar | YES |  |
| resource_uid | text | YES |  |

**Indexes:** 9
- `datasec_findings_pkey`
- `idx_datasec_findings_tenant`
- `idx_datasec_findings_rule`
- `idx_datasec_findings_severity`
- `idx_datasec_findings_classification`
- `idx_datasec_finding_data_gin`
- `idx_datasec_findings_resource_uid`
- `idx_datasec_findings_report`
- `idx_datasec_findings_scan_id`

**PK:** finding_id
**FK:** tenant_id (fk_tenant_finding)
**FK:** datasec_scan_id (fk_datasec_report)

### datasec_report (24 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| datasec_scan_id | varchar | NO | uuid_generate_v4() |
| tenant_id | varchar | NO |  |
| scan_run_id | varchar | NO |  |
| cloud | varchar | YES | 'aws'::character varying |
| generated_at | timestamptz | YES | now() |
| total_findings | integer | YES | 0 |
| datasec_relevant_findings | integer | YES | 0 |
| classified_resources | integer | YES | 0 |
| total_data_stores | integer | YES | 0 |
| findings_by_module | jsonb | YES |  |
| classification_summary | jsonb | YES |  |
| residency_summary | jsonb | YES |  |
| report_data | jsonb | NO |  |
| created_at | timestamptz | YES | now() |
| discovery_scan_id | varchar | YES |  |
| customer_id | varchar | YES |  |
| check_scan_id | varchar | YES |  |
| threat_scan_id | varchar | YES |  |
| status | varchar | YES | 'completed'::character varying |
| execution_id | varchar | YES |  |
| provider | varchar | YES | 'aws'::character varying |

**Indexes:** 8
- `idx_datasec_reports_tenant`
- `idx_datasec_reports_generated`
- `idx_datasec_report_data_gin`
- `idx_datasec_report_discovery_scan_id`
- `idx_datasec_report_check_scan_id`
- `idx_datasec_report_threat_scan_id`
- `datasec_reports_pkey`
- `idx_datasec_report_execution_id`

**PK:** datasec_scan_id
**FK:** tenant_id (fk_tenant)

### datasec_rules (95 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| id | integer | NO | nextval('datasec_rules_id_seq'::regclass |
| rule_id | varchar | NO |  |
| csp | varchar | NO | 'aws'::character varying |
| service | varchar | NO |  |
| resource_type | varchar | YES |  |
| category | varchar | NO |  |
| subcategory | varchar | YES |  |
| severity | varchar | NO | 'medium'::character varying |
| title | text | NO |  |
| description | text | YES |  |
| remediation | text | YES |  |
| condition | jsonb | NO | '{}'::jsonb |
| condition_type | varchar | YES | 'field_check'::character varying |
| compliance_frameworks | jsonb | YES | '[]'::jsonb |
| sensitive_data_types | jsonb | YES | '[]'::jsonb |
| domain | varchar | YES |  |
| check_rule_id | varchar | YES |  |
| tenant_id | varchar | YES |  |
| is_active | boolean | NO | true |
| version | varchar | YES | '1.0'::character varying |
| created_at | timestamptz | YES | now() |
| updated_at | timestamptz | YES | now() |

**Indexes:** 10
- `datasec_rules_pkey`
- `uq_datasec_rule`
- `idx_datasec_rules_csp_active`
- `idx_datasec_rules_category`
- `idx_datasec_rules_service`
- `idx_datasec_rules_tenant`
- `idx_datasec_rules_severity`
- `idx_datasec_rules_condition_gin`
- `idx_datasec_rules_frameworks_gin`
- `idx_datasec_rules_data_types_gin`

**PK:** id
**UNIQUE:** rule_id, csp, tenant_id

### datasec_sensitive_data_types (26 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| id | integer | NO | nextval('datasec_sensitive_data_types_id |
| category | varchar | NO |  |
| type_key | varchar | NO |  |
| display_name | varchar | NO |  |
| detection_pattern | text | YES |  |
| confidence_weight | numeric | YES | 0.80 |
| is_active | boolean | YES | true |

**Indexes:** 2
- `datasec_sensitive_data_types_pkey`
- `uq_datasec_data_type`

**PK:** id
**UNIQUE:** category, type_key

### tenants (6 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| tenant_id | varchar | NO |  |
| tenant_name | varchar | YES |  |
| created_at | timestamptz | YES | now() |

**Indexes:** 1
- `tenants_pkey`

**PK:** tenant_id

## threat_engine_onboarding


### account_hierarchy (0 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| id | bigint | NO | nextval('account_hierarchy_id_seq'::regc |
| tenant_id | varchar | NO |  |
| customer_id | varchar | YES |  |
| node_id | varchar | NO |  |
| node_name | varchar | YES |  |
| node_type | varchar | NO |  |
| parent_node_id | varchar | YES |  |
| hierarchy_path | text | YES |  |
| depth | smallint | YES | 0 |
| provider | varchar | NO |  |
| provider_org_id | varchar | YES |  |
| status | varchar | YES | 'active'::character varying |
| metadata | jsonb | YES | '{}'::jsonb |
| discovered_at | timestamptz | YES | now() |
| updated_at | timestamptz | YES | now() |

**Indexes:** 7
- `account_hierarchy_pkey`
- `ah_unique_node`
- `idx_ah_tenant_parent`
- `idx_ah_tenant_provider`
- `idx_ah_tenant_type`
- `idx_ah_hierarchy_path`
- `idx_ah_depth`

**PK:** id
**UNIQUE:** tenant_id, provider, node_id

### cloud_accounts (16 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| account_id | varchar | NO |  |
| customer_id | varchar | NO |  |
| customer_email | varchar | NO |  |
| customer_name | varchar | YES |  |
| customer_organization | varchar | YES |  |
| tenant_id | varchar | NO |  |
| tenant_name | varchar | NO |  |
| tenant_description | text | YES |  |
| account_name | varchar | NO |  |
| account_number | varchar | YES |  |
| account_hierarchy_name | varchar | YES |  |
| provider | varchar | NO |  |
| credential_type | varchar | NO |  |
| credential_ref | varchar | NO |  |
| account_status | varchar | NO | 'pending'::character varying |
| account_onboarding_status | varchar | NO | 'pending'::character varying |
| account_onboarding_id | varchar | YES |  |
| account_last_validated_at | timestamptz | YES |  |
| schedule_id | varchar | YES |  |
| schedule_name | varchar | YES |  |
| schedule_cron_expression | varchar | YES |  |
| schedule_timezone | varchar | YES | 'UTC'::character varying |
| schedule_include_services | jsonb | YES |  |
| schedule_include_regions | jsonb | YES |  |
| schedule_exclude_services | jsonb | YES |  |
| schedule_exclude_regions | jsonb | YES |  |
| schedule_engines_requested | jsonb | YES | '["discovery", "check", "inventory", "th |
| schedule_enabled | boolean | YES | true |
| schedule_status | varchar | YES | 'active'::character varying |
| schedule_next_run_at | timestamptz | YES |  |
| schedule_last_run_at | timestamptz | YES |  |
| schedule_run_count | integer | YES | 0 |
| schedule_success_count | integer | YES | 0 |
| schedule_failure_count | integer | YES | 0 |
| schedule_notify_on_success | boolean | YES | false |
| schedule_notify_on_failure | boolean | YES | true |
| schedule_notification_emails | jsonb | YES |  |
| created_at | timestamptz | YES | now() |
| updated_at | timestamptz | YES | now() |
| credential_validation_status | varchar | YES | 'pending'::character varying |
| credential_validation_message | text | YES |  |
| credential_validated_at | timestamptz | YES |  |
| credential_validation_errors | jsonb | YES | '[]'::jsonb |

**Indexes:** 18
- `cloud_accounts_pkey`
- `unique_customer_tenant_account`
- `idx_cloud_accounts_customer`
- `idx_cloud_accounts_tenant`
- `idx_cloud_accounts_customer_tenant`
- `idx_cloud_accounts_provider`
- `idx_cloud_accounts_status`
- `idx_cloud_accounts_credential_type`
- `idx_cloud_accounts_schedule_id`
- `idx_cloud_accounts_schedule_enabled`
- `idx_cloud_accounts_schedule_status`
- `idx_cloud_accounts_engines_gin`
- `idx_cloud_accounts_services_gin`
- `idx_cloud_accounts_regions_gin`
- `idx_cloud_accounts_customer_email`
- `idx_cloud_accounts_tenant_name`
- `idx_cloud_accounts_account_name`
- `idx_cloud_accounts_credential_validation`

**PK:** account_id
**UNIQUE:** customer_id, tenant_id, account_name

### scan_orchestration (27 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| orchestration_id | uuid | NO | uuid_generate_v4() |
| tenant_id | varchar | NO |  |
| scan_name | varchar | YES |  |
| scan_type | varchar | NO | 'full'::character varying |
| trigger_type | varchar | NO | 'scheduled'::character varying |
| engines_requested | jsonb | NO | '["discovery", "check", "inventory", "th |
| engines_completed | jsonb | YES | '[]'::jsonb |
| overall_status | varchar | NO | 'pending'::character varying |
| started_at | timestamptz | NO | now() |
| completed_at | timestamptz | YES |  |
| results_summary | jsonb | YES | '{}'::jsonb |
| error_details | jsonb | YES | '{}'::jsonb |
| created_at | timestamptz | YES | now() |
| execution_id | uuid | YES |  |
| customer_id | varchar | YES |  |
| provider | varchar | NO |  |
| hierarchy_id | varchar | NO |  |
| account_id | varchar | NO |  |
| include_services | jsonb | YES |  |
| include_regions | jsonb | YES |  |
| discovery_scan_id | varchar | YES |  |
| check_scan_id | varchar | YES |  |
| inventory_scan_id | varchar | YES |  |
| threat_scan_id | varchar | YES |  |
| compliance_scan_id | varchar | YES |  |
| iam_scan_id | varchar | YES |  |
| datasec_scan_id | varchar | YES |  |
| credential_type | varchar | NO |  |
| credential_ref | varchar | NO |  |
| exclude_services | jsonb | YES |  |
| exclude_regions | jsonb | YES |  |
| schedule_id | varchar | YES |  |

**Indexes:** 14
- `scan_orchestration_pkey`
- `idx_orchestration_tenant`
- `idx_orchestration_status`
- `idx_orchestration_execution`
- `idx_orchestration_schedule`
- `idx_orchestration_discovery`
- `idx_orchestration_check`
- `idx_orchestration_inventory`
- `idx_orchestration_threat`
- `idx_orchestration_compliance`
- `idx_orchestration_iam`
- `idx_orchestration_datasec`
- `idx_orchestration_engines_gin`
- `idx_orchestration_results_gin`

**PK:** orchestration_id

## threat_engine_risk


### risk_input_transformed (0 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| id | bigint | NO | nextval('risk_input_transformed_id_seq': |
| risk_scan_id | uuid | NO |  |
| tenant_id | varchar | NO |  |
| orchestration_id | uuid | NO |  |
| source_finding_id | varchar | YES |  |
| source_engine | varchar | NO |  |
| source_scan_id | uuid | YES |  |
| rule_id | varchar | YES |  |
| severity | varchar | YES |  |
| title | text | YES |  |
| finding_type | varchar | YES |  |
| asset_id | varchar | YES |  |
| asset_type | varchar | YES |  |
| asset_arn | varchar | YES |  |
| asset_criticality | varchar | YES |  |
| is_public | boolean | YES | false |
| data_sensitivity | varchar | YES |  |
| data_types | ARRAY | YES | '{}'::text[] |
| estimated_record_count | bigint | YES | 0 |
| industry | varchar | YES |  |
| estimated_revenue | numeric | YES |  |
| applicable_regulations | ARRAY | YES | '{}'::text[] |
| epss_score | numeric | YES | 0.05 |
| cve_id | varchar | YES |  |
| exposure_factor | numeric | YES | 1.0 |
| account_id | varchar | YES |  |
| region | varchar | YES |  |
| csp | varchar | YES | 'aws'::character varying |
| scanned_at | timestamp | YES | now() |

**Indexes:** 1
- `risk_input_transformed_pkey`

**PK:** id

### risk_model_config (0 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| config_id | uuid | NO | gen_random_uuid() |
| tenant_id | varchar | YES |  |
| industry | varchar | NO |  |
| per_record_cost | numeric | NO | 4.45 |
| revenue_range | varchar | YES |  |
| estimated_annual_revenue | numeric | YES |  |
| applicable_regs | jsonb | YES | '[]'::jsonb |
| downtime_cost_hr | numeric | YES | 10000.00 |
| sensitivity_multipliers | jsonb | YES | '{"public": 0.1, "internal": 1.0, "restr |
| default_record_count | integer | YES | 1000 |
| is_default | boolean | YES | false |
| created_at | timestamp | YES | now() |
| updated_at | timestamp | YES | now() |

**Indexes:** 1
- `risk_model_config_pkey`

**PK:** config_id

### risk_report (0 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| risk_scan_id | uuid | NO |  |
| orchestration_id | uuid | NO |  |
| tenant_id | varchar | NO |  |
| account_id | varchar | YES |  |
| provider | varchar | YES | 'aws'::character varying |
| total_scenarios | integer | YES | 0 |
| critical_scenarios | integer | YES | 0 |
| high_scenarios | integer | YES | 0 |
| medium_scenarios | integer | YES | 0 |
| low_scenarios | integer | YES | 0 |
| total_exposure_min | numeric | YES | 0 |
| total_exposure_max | numeric | YES | 0 |
| total_exposure_likely | numeric | YES | 0 |
| total_regulatory_exposure | numeric | YES | 0 |
| engine_breakdown | jsonb | YES |  |
| top_scenarios | jsonb | YES |  |
| scenario_type_breakdown | jsonb | YES |  |
| frameworks_at_risk | ARRAY | YES | '{}'::text[] |
| vs_previous_likely | numeric | YES |  |
| vs_previous_pct | numeric | YES |  |
| currency | varchar | YES | 'USD'::character varying |
| started_at | timestamp | YES |  |
| completed_at | timestamp | YES |  |
| scan_duration_ms | integer | YES |  |
| status | varchar | YES | 'pending'::character varying |
| error_message | text | YES |  |
| created_at | timestamp | YES | now() |

**Indexes:** 1
- `risk_report_pkey`

**PK:** risk_scan_id

### risk_scenarios (0 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| scenario_id | uuid | NO | gen_random_uuid() |
| risk_scan_id | uuid | NO |  |
| tenant_id | varchar | NO |  |
| orchestration_id | uuid | NO |  |
| source_finding_id | varchar | YES |  |
| source_engine | varchar | YES |  |
| asset_id | varchar | YES |  |
| asset_type | varchar | YES |  |
| asset_arn | varchar | YES |  |
| scenario_type | varchar | YES |  |
| data_records_at_risk | bigint | YES | 0 |
| data_sensitivity | varchar | YES |  |
| data_types | ARRAY | YES | '{}'::text[] |
| loss_event_frequency | numeric | YES | 0 |
| primary_loss_min | numeric | YES | 0 |
| primary_loss_max | numeric | YES | 0 |
| primary_loss_likely | numeric | YES | 0 |
| regulatory_fine_min | numeric | YES | 0 |
| regulatory_fine_max | numeric | YES | 0 |
| applicable_regulations | ARRAY | YES | '{}'::text[] |
| total_exposure_min | numeric | YES | 0 |
| total_exposure_max | numeric | YES | 0 |
| total_exposure_likely | numeric | YES | 0 |
| risk_tier | varchar | NO | 'low'::character varying |
| calculation_model | jsonb | YES |  |
| account_id | varchar | YES |  |
| region | varchar | YES |  |
| csp | varchar | YES | 'aws'::character varying |
| created_at | timestamp | YES | now() |

**Indexes:** 1
- `risk_scenarios_pkey`

**PK:** scenario_id

### risk_summary (0 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| summary_id | uuid | NO | gen_random_uuid() |
| risk_scan_id | uuid | NO |  |
| tenant_id | varchar | NO |  |
| orchestration_id | uuid | NO |  |
| source_engine | varchar | NO |  |
| scenario_count | integer | YES | 0 |
| critical_count | integer | YES | 0 |
| high_count | integer | YES | 0 |
| total_exposure_likely | numeric | YES | 0 |
| total_regulatory_exposure | numeric | YES | 0 |
| top_finding_types | jsonb | YES |  |
| created_at | timestamp | YES | now() |

**Indexes:** 1
- `risk_summary_pkey`

**PK:** summary_id

### risk_trends (0 rows)

| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| id | uuid | NO | gen_random_uuid() |
| tenant_id | varchar | NO |  |
| scan_date | date | NO |  |
| risk_scan_id | uuid | NO |  |
| total_exposure_likely | numeric | YES | 0 |
| critical_scenarios | integer | YES | 0 |
| high_scenarios | integer | YES | 0 |
| top_risk_type | varchar | YES |  |
| top_risk_engine | varchar | YES |  |
| created_at | timestamp | YES | now() |

**Indexes:** 1
- `risk_trends_pkey`

**PK:** id
