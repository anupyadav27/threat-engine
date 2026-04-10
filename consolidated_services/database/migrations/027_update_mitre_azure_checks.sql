-- Migration 027: Populate azure_checks column in mitre_technique_reference
-- Maps Azure rule_ids to MITRE ATT&CK techniques for the threat engine
-- Depends on: AZ-09 rules seeded, mitre_technique_reference table populated

-- Add azure_checks column if not present (schema guard)
ALTER TABLE mitre_technique_reference
  ADD COLUMN IF NOT EXISTS azure_checks JSONB DEFAULT '[]'::jsonb;

-- ── Credential Access ─────────────────────────────────────────────────────────

UPDATE mitre_technique_reference
SET azure_checks = '["azure_iam_mfa_all_users", "azure_iam_mfa_privileged_users",
    "azure_iam_conditional_access_require_mfa", "azure_iam_security_defaults_enabled",
    "azure_iam_no_legacy_auth_protocols", "azure_iam_conditional_access_block_legacy_auth"]'::jsonb
WHERE technique_id = 'T1078';

UPDATE mitre_technique_reference
SET azure_checks = '["azure_iam_no_permanent_global_admin", "azure_iam_pim_for_privileged_roles",
    "azure_iam_sp_no_owner_contributor_subscription", "azure_rbac_no_subscription_owner_without_pim",
    "azure_iam_managed_identity_preferred", "azure_sp_certificate_preferred_over_secret"]'::jsonb
WHERE technique_id = 'T1078.004';

UPDATE mitre_technique_reference
SET azure_checks = '["azure_iam_sp_credential_expiry_set", "azure_sp_no_expired_credentials",
    "azure_sp_certificate_preferred_over_secret", "azure_iam_app_registration_credential_expiry",
    "azure_keyvault_key_expiry_set", "azure_keyvault_secret_expiry_set",
    "azure_storage_cmk_encryption", "azure_vm_os_disk_cmk_encryption"]'::jsonb
WHERE technique_id = 'T1552';

UPDATE mitre_technique_reference
SET azure_checks = '["azure_iam_sp_no_owner_contributor_subscription",
    "azure_iam_no_custom_owner_role", "azure_iam_subscription_owner_max_3",
    "azure_rbac_no_direct_user_assignment", "azure_iam_pim_for_privileged_roles",
    "azure_iam_app_registration_credential_expiry"]'::jsonb
WHERE technique_id = 'T1098.001';

UPDATE mitre_technique_reference
SET azure_checks = '["azure_keyvault_key_expiry_set", "azure_keyvault_secret_expiry_set",
    "azure_vm_os_disk_cmk_encryption", "azure_vm_data_disk_cmk_encryption",
    "azure_sql_tde_enabled", "azure_storage_cmk_encryption"]'::jsonb
WHERE technique_id = 'T1552.001';

-- ── Initial Access ────────────────────────────────────────────────────────────

UPDATE mitre_technique_reference
SET azure_checks = '["azure_nsg_rdp_restricted", "azure_nsg_ssh_restricted",
    "azure_sql_no_allow_all_firewall", "azure_sql_no_public_network_access",
    "azure_aks_private_cluster", "azure_aks_authorized_ip_ranges",
    "azure_appservice_authentication_enabled", "azure_storage_network_default_deny",
    "azure_keyvault_no_public_network_access", "azure_nsg_no_allow_all_inbound"]'::jsonb
WHERE technique_id = 'T1190';

UPDATE mitre_technique_reference
SET azure_checks = '["azure_iam_mfa_all_users", "azure_iam_no_legacy_auth_protocols",
    "azure_iam_password_protection_enabled", "azure_iam_security_defaults_enabled"]'::jsonb
WHERE technique_id = 'T1110';

UPDATE mitre_technique_reference
SET azure_checks = '["azure_iam_no_app_self_service_consent", "azure_iam_no_user_app_registration",
    "azure_iam_no_guest_invite_without_admin"]'::jsonb
WHERE technique_id = 'T1566';

-- ── Collection / Data Exfiltration ────────────────────────────────────────────

UPDATE mitre_technique_reference
SET azure_checks = '["azure_storage_public_access_disabled", "azure_storage_blob_soft_delete",
    "azure_storage_no_anonymous_access_blobs", "azure_storage_cmk_encryption",
    "azure_storage_network_default_deny", "azure_storage_private_endpoint",
    "azure_sql_tde_enabled", "azure_sql_no_public_network_access"]'::jsonb
WHERE technique_id = 'T1530';

UPDATE mitre_technique_reference
SET azure_checks = '["azure_storage_network_default_deny", "azure_storage_private_endpoint",
    "azure_storage_public_access_disabled"]'::jsonb
WHERE technique_id = 'T1537';

UPDATE mitre_technique_reference
SET azure_checks = '["azure_storage_https_only", "azure_appservice_https_only",
    "azure_appservice_tls_minimum_12", "azure_storage_tls_version_12",
    "azure_sql_mysql_tls_version_12"]'::jsonb
WHERE technique_id = 'T1040';

-- ── Defense Evasion ──────────────────────────────────────────────────────────

UPDATE mitre_technique_reference
SET azure_checks = '["azure_monitor_diagnostic_setting_subscription",
    "azure_monitor_activity_log_administrative", "azure_monitor_activity_log_security",
    "azure_monitor_keyvault_logging", "azure_monitor_activity_log_retention_1year",
    "azure_nsg_flow_logs_enabled", "azure_nsg_flow_log_retention_90days",
    "azure_sql_auditing_enabled", "azure_sql_audit_retention_90days",
    "azure_keyvault_logging_enabled"]'::jsonb
WHERE technique_id = 'T1562';

-- ── Privilege Escalation ─────────────────────────────────────────────────────

UPDATE mitre_technique_reference
SET azure_checks = '["azure_vm_latest_os_patches", "azure_vmss_automatic_os_upgrades",
    "azure_vm_vulnerability_assessment_installed"]'::jsonb
WHERE technique_id = 'T1068';

UPDATE mitre_technique_reference
SET azure_checks = '["azure_aks_no_privileged_containers", "azure_aks_rbac_enabled",
    "azure_aks_aad_integration_enabled"]'::jsonb
WHERE technique_id = 'T1611';

-- ── Discovery ─────────────────────────────────────────────────────────────────

UPDATE mitre_technique_reference
SET azure_checks = '["azure_iam_restrict_admin_portal_access", "azure_iam_no_user_app_registration"]'::jsonb
WHERE technique_id = 'T1580';

-- ── Lateral Movement ─────────────────────────────────────────────────────────

UPDATE mitre_technique_reference
SET azure_checks = '["azure_aks_network_policy_calico_or_azure", "azure_subnet_no_default_nsg",
    "azure_nsg_no_allow_all_inbound", "azure_vm_just_in_time_access"]'::jsonb
WHERE technique_id = 'T1021';

-- ── Execution ────────────────────────────────────────────────────────────────

UPDATE mitre_technique_reference
SET azure_checks = '["azure_vm_approved_extensions_only", "azure_appservice_remote_debugging_disabled",
    "azure_vm_endpoint_protection"]'::jsonb
WHERE technique_id = 'T1059';

-- ── Impact ───────────────────────────────────────────────────────────────────

UPDATE mitre_technique_reference
SET azure_checks = '["azure_storage_blob_soft_delete", "azure_storage_container_soft_delete",
    "azure_keyvault_soft_delete_enabled", "azure_keyvault_purge_protection_enabled"]'::jsonb
WHERE technique_id = 'T1485';

UPDATE mitre_technique_reference
SET azure_checks = '["azure_ddos_standard_enabled"]'::jsonb
WHERE technique_id = 'T1498';

-- ── Persistence ──────────────────────────────────────────────────────────────

UPDATE mitre_technique_reference
SET azure_checks = '["azure_iam_no_permanent_global_admin", "azure_iam_pim_for_privileged_roles",
    "azure_iam_sp_credential_expiry_set", "azure_iam_app_registration_credential_expiry",
    "azure_iam_no_orphaned_service_principals"]'::jsonb
WHERE technique_id = 'T1136';
