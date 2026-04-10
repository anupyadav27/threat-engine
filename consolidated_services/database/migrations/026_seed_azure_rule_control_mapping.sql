-- Migration 026: Map Azure check rules to CIS Azure 1.5 and NIST 800-53 controls
-- Depends on: migration 025 (CIS framework seeded), AZ-09 rules seeded
-- Safe to re-run: ON CONFLICT (rule_id, control_id) DO NOTHING

-- ============================================================================
-- CIS Azure 1.5 Mappings
-- ============================================================================

INSERT INTO rule_control_mapping (rule_id, control_id, framework_id, mapping_type, coverage_percentage)
VALUES

-- Section 1: IAM
('azure_iam_mfa_all_users',                     'cis_azure_1_5_1_1',  'cis_azure_1_5', 'direct', 100),
('azure_iam_security_defaults_enabled',          'cis_azure_1_5_1_1',  'cis_azure_1_5', 'direct', 90),
('azure_iam_conditional_access_require_mfa',     'cis_azure_1_5_1_1',  'cis_azure_1_5', 'direct', 100),
('azure_iam_mfa_privileged_users',               'cis_azure_1_5_1_2',  'cis_azure_1_5', 'direct', 100),
('azure_iam_no_legacy_auth_protocols',           'cis_azure_1_5_1_22', 'cis_azure_1_5', 'direct', 100),
('azure_iam_conditional_access_block_legacy_auth','cis_azure_1_5_1_22','cis_azure_1_5', 'direct', 100),
('azure_iam_password_protection_enabled',        'cis_azure_1_5_1_7',  'cis_azure_1_5', 'direct', 100),
('azure_iam_sspr_two_methods',                   'cis_azure_1_5_1_6',  'cis_azure_1_5', 'direct', 100),
('azure_iam_no_guest_invite_without_admin',      'cis_azure_1_5_1_14', 'cis_azure_1_5', 'direct', 100),
('azure_iam_guest_users_reviewed',               'cis_azure_1_5_1_8',  'cis_azure_1_5', 'direct', 100),
('azure_iam_no_app_self_service_consent',        'cis_azure_1_5_1_10', 'cis_azure_1_5', 'direct', 100),
('azure_iam_no_user_app_registration',           'cis_azure_1_5_1_12', 'cis_azure_1_5', 'direct', 100),
('azure_iam_restrict_admin_portal_access',       'cis_azure_1_5_1_16', 'cis_azure_1_5', 'direct', 100),
('azure_iam_no_custom_owner_role',               'cis_azure_1_5_1_17', 'cis_azure_1_5', 'direct', 100),
('azure_iam_subscription_owner_max_3',           'cis_azure_1_5_1_18', 'cis_azure_1_5', 'direct', 100),
('azure_iam_sp_credential_expiry_set',           'cis_azure_1_5_1_19', 'cis_azure_1_5', 'direct', 100),
('azure_sp_no_expired_credentials',              'cis_azure_1_5_1_19', 'cis_azure_1_5', 'direct', 80),
('azure_iam_sp_no_owner_contributor_subscription','cis_azure_1_5_1_20','cis_azure_1_5', 'direct', 100),
('azure_iam_managed_identity_preferred',         'cis_azure_1_5_1_21', 'cis_azure_1_5', 'direct', 100),
('azure_iam_no_permanent_global_admin',          'cis_azure_1_5_1_25', 'cis_azure_1_5', 'direct', 100),
('azure_iam_pim_for_privileged_roles',           'cis_azure_1_5_1_23', 'cis_azure_1_5', 'direct', 100),
('azure_rbac_no_subscription_owner_without_pim', 'cis_azure_1_5_1_23', 'cis_azure_1_5', 'direct', 90),

-- Section 2: Defender for Cloud
('azure_vm_vulnerability_assessment_installed',  'cis_azure_1_5_2_1',  'cis_azure_1_5', 'direct', 80),
('azure_vm_endpoint_protection',                 'cis_azure_1_5_2_1',  'cis_azure_1_5', 'indirect', 70),
('azure_sql_defender_advanced_data_security',    'cis_azure_1_5_2_3',  'cis_azure_1_5', 'direct', 100),
('azure_sql_vulnerability_assessment_enabled',   'cis_azure_1_5_2_3',  'cis_azure_1_5', 'indirect', 80),
('azure_monitor_security_center_integration',    'cis_azure_1_5_2_13', 'cis_azure_1_5', 'direct', 80),
('azure_monitor_diagnostic_setting_subscription','cis_azure_1_5_2_13', 'cis_azure_1_5', 'indirect', 60),

-- Section 3: Storage
('azure_storage_https_only',                     'cis_azure_1_5_3_1',  'cis_azure_1_5', 'direct', 100),
('azure_storage_access_key_rotation',            'cis_azure_1_5_3_2',  'cis_azure_1_5', 'direct', 100),
('azure_storage_queue_logging_read',             'cis_azure_1_5_3_3',  'cis_azure_1_5', 'direct', 100),
('azure_storage_queue_logging_write',            'cis_azure_1_5_3_3',  'cis_azure_1_5', 'direct', 100),
('azure_storage_queue_logging_delete',           'cis_azure_1_5_3_3',  'cis_azure_1_5', 'direct', 100),
('azure_storage_sas_expiry_1hour',               'cis_azure_1_5_3_4',  'cis_azure_1_5', 'direct', 100),
('azure_storage_public_access_disabled',         'cis_azure_1_5_3_5',  'cis_azure_1_5', 'direct', 100),
('azure_storage_no_anonymous_access_blobs',      'cis_azure_1_5_3_5',  'cis_azure_1_5', 'direct', 100),
('azure_storage_network_default_deny',           'cis_azure_1_5_3_6',  'cis_azure_1_5', 'direct', 100),
('azure_storage_trusted_microsoft_services',     'cis_azure_1_5_3_7',  'cis_azure_1_5', 'direct', 100),
('azure_storage_blob_soft_delete',               'cis_azure_1_5_3_8',  'cis_azure_1_5', 'direct', 100),
('azure_storage_container_soft_delete',          'cis_azure_1_5_3_8',  'cis_azure_1_5', 'direct', 100),
('azure_storage_cmk_encryption',                 'cis_azure_1_5_3_9',  'cis_azure_1_5', 'direct', 100),
('azure_storage_blob_logging_read',              'cis_azure_1_5_3_10', 'cis_azure_1_5', 'direct', 100),
('azure_storage_blob_logging_write',             'cis_azure_1_5_3_10', 'cis_azure_1_5', 'direct', 100),
('azure_storage_blob_logging_delete',            'cis_azure_1_5_3_10', 'cis_azure_1_5', 'direct', 100),
('azure_storage_table_logging_read',             'cis_azure_1_5_3_11', 'cis_azure_1_5', 'direct', 100),
('azure_storage_table_logging_write',            'cis_azure_1_5_3_11', 'cis_azure_1_5', 'direct', 100),
('azure_storage_table_logging_delete',           'cis_azure_1_5_3_11', 'cis_azure_1_5', 'direct', 100),
('azure_storage_tls_version_12',                 'cis_azure_1_5_3_12', 'cis_azure_1_5', 'direct', 100),
('azure_storage_infrastructure_encryption',      'cis_azure_1_5_3_14', 'cis_azure_1_5', 'direct', 100),

-- Section 4: Database
('azure_sql_auditing_enabled',                   'cis_azure_1_5_4_1',  'cis_azure_1_5', 'direct', 100),
('azure_sql_tde_enabled',                        'cis_azure_1_5_4_2',  'cis_azure_1_5', 'direct', 100),
('azure_sql_threat_detection_all_types',         'cis_azure_1_5_4_3',  'cis_azure_1_5', 'direct', 100),
('azure_sql_threat_alert_emails_set',            'cis_azure_1_5_4_4',  'cis_azure_1_5', 'direct', 100),
('azure_sql_threat_email_service_admins',        'cis_azure_1_5_4_5',  'cis_azure_1_5', 'direct', 100),
('azure_sql_audit_retention_90days',             'cis_azure_1_5_4_6',  'cis_azure_1_5', 'direct', 100),
('azure_sql_aad_admin_configured',               'cis_azure_1_5_4_7',  'cis_azure_1_5', 'direct', 100),
('azure_sql_no_public_network_access',           'cis_azure_1_5_4_8',  'cis_azure_1_5', 'direct', 100),
('azure_sql_no_allow_all_firewall',              'cis_azure_1_5_4_8',  'cis_azure_1_5', 'direct', 100),
('azure_sql_mysql_tls_version_12',               'cis_azure_1_5_4_9',  'cis_azure_1_5', 'direct', 100),

-- Section 5: Logging and Monitoring
('azure_monitor_diagnostic_setting_subscription','cis_azure_1_5_5_1',  'cis_azure_1_5', 'direct', 100),
('azure_monitor_activity_log_administrative',    'cis_azure_1_5_5_2',  'cis_azure_1_5', 'direct', 100),
('azure_monitor_activity_log_security',          'cis_azure_1_5_5_2',  'cis_azure_1_5', 'direct', 100),
('azure_monitor_activity_log_policy',            'cis_azure_1_5_5_2',  'cis_azure_1_5', 'direct', 100),
('azure_monitor_log_storage_not_public',         'cis_azure_1_5_5_3',  'cis_azure_1_5', 'direct', 100),
('azure_monitor_log_storage_cmk',                'cis_azure_1_5_5_4',  'cis_azure_1_5', 'direct', 100),
('azure_monitor_keyvault_logging',               'cis_azure_1_5_5_5',  'cis_azure_1_5', 'direct', 100),
('azure_keyvault_logging_enabled',               'cis_azure_1_5_5_5',  'cis_azure_1_5', 'direct', 100),
('azure_monitor_activity_log_retention_1year',   'cis_azure_1_5_5_6',  'cis_azure_1_5', 'direct', 100),

-- Section 6: Networking
('azure_nsg_rdp_restricted',                     'cis_azure_1_5_6_1',  'cis_azure_1_5', 'direct', 100),
('azure_nsg_ssh_restricted',                     'cis_azure_1_5_6_2',  'cis_azure_1_5', 'direct', 100),
('azure_nsg_udp_restricted',                     'cis_azure_1_5_6_3',  'cis_azure_1_5', 'direct', 100),
('azure_nsg_http_restricted',                    'cis_azure_1_5_6_4',  'cis_azure_1_5', 'indirect', 80),
('azure_nsg_flow_log_retention_90days',          'cis_azure_1_5_6_5',  'cis_azure_1_5', 'direct', 100),
('azure_nsg_flow_logs_enabled',                  'cis_azure_1_5_6_5',  'cis_azure_1_5', 'direct', 100),
('azure_network_watcher_enabled',                'cis_azure_1_5_6_6',  'cis_azure_1_5', 'direct', 100),
('azure_nsg_no_allow_all_inbound',               'cis_azure_1_5_6_1',  'cis_azure_1_5', 'direct', 90),
('azure_appgw_waf_enabled',                      'cis_azure_1_5_6_6',  'cis_azure_1_5', 'indirect', 70),

-- Section 7: Virtual Machines
('azure_vm_managed_disk',                        'cis_azure_1_5_7_1',  'cis_azure_1_5', 'direct', 100),
('azure_vm_os_disk_cmk_encryption',              'cis_azure_1_5_7_2',  'cis_azure_1_5', 'direct', 100),
('azure_vm_data_disk_cmk_encryption',            'cis_azure_1_5_7_2',  'cis_azure_1_5', 'direct', 100),
('azure_vm_disk_encryption_azure_disk',          'cis_azure_1_5_7_2',  'cis_azure_1_5', 'direct', 90),
('azure_vm_unattached_disk_encrypted',           'cis_azure_1_5_7_3',  'cis_azure_1_5', 'direct', 100),
('azure_vm_approved_extensions_only',            'cis_azure_1_5_7_4',  'cis_azure_1_5', 'direct', 100),
('azure_vm_latest_os_patches',                   'cis_azure_1_5_7_5',  'cis_azure_1_5', 'direct', 100),
('azure_vm_endpoint_protection',                 'cis_azure_1_5_7_6',  'cis_azure_1_5', 'direct', 100),

-- Section 8: App Service
('azure_appservice_authentication_enabled',      'cis_azure_1_5_8_1',  'cis_azure_1_5', 'direct', 100),
('azure_functionapp_authentication_enabled',     'cis_azure_1_5_8_1',  'cis_azure_1_5', 'direct', 100),
('azure_appservice_latest_http_version',         'cis_azure_1_5_8_2',  'cis_azure_1_5', 'direct', 100),
('azure_appservice_https_only',                  'cis_azure_1_5_8_3',  'cis_azure_1_5', 'direct', 100),
('azure_appservice_tls_minimum_12',              'cis_azure_1_5_8_3',  'cis_azure_1_5', 'direct', 100),
('azure_functionapp_https_only',                 'cis_azure_1_5_8_3',  'cis_azure_1_5', 'direct', 100),
('azure_appservice_client_cert_required',        'cis_azure_1_5_8_4',  'cis_azure_1_5', 'direct', 100),
('azure_appservice_managed_identity',            'cis_azure_1_5_8_5',  'cis_azure_1_5', 'direct', 100),
('azure_appservice_latest_php_version',          'cis_azure_1_5_8_6',  'cis_azure_1_5', 'direct', 100),
('azure_appservice_latest_python_version',       'cis_azure_1_5_8_7',  'cis_azure_1_5', 'direct', 100),
('azure_appservice_latest_java_version',         'cis_azure_1_5_8_8',  'cis_azure_1_5', 'direct', 100),

-- Section 9: Key Vault
('azure_keyvault_key_expiry_set',                'cis_azure_1_5_9_1',  'cis_azure_1_5', 'direct', 100),
('azure_keyvault_secret_expiry_set',             'cis_azure_1_5_9_2',  'cis_azure_1_5', 'direct', 100),
('azure_keyvault_soft_delete_enabled',           'cis_azure_1_5_9_3',  'cis_azure_1_5', 'direct', 100),
('azure_keyvault_purge_protection_enabled',      'cis_azure_1_5_9_4',  'cis_azure_1_5', 'direct', 100)

ON CONFLICT (rule_id, control_id) DO NOTHING;


-- ============================================================================
-- Tag IAM rules for IAM engine (iam_security JSONB column)
-- ============================================================================

UPDATE rule_metadata
SET iam_security = '{"module": "azure_ad", "iam_category": "identity"}'::jsonb
WHERE provider = 'azure'
  AND service IN ('iam', 'authorization', 'msi')
  AND (iam_security IS NULL OR iam_security = '{}'::jsonb);

UPDATE rule_metadata
SET iam_security = jsonb_set(iam_security, '{iam_category}', '"rbac"', true)
WHERE provider = 'azure'
  AND rule_id LIKE 'azure_rbac_%';
