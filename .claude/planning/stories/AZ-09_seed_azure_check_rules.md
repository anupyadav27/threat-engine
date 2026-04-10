---
story_id: AZ-09
title: Seed Azure Check Rules into rule_metadata (~500+ rules)
status: done
sprint: azure-track-wave-3
depends_on: []
blocks: [AZ-11, AZ-13]
sme: Security engineer / Cloud SME
estimate: 3 days
---

# Story: Seed Azure Check Rules into rule_metadata

## Context
The check engine evaluates `rule_metadata` rules against `discovery_findings`. Currently ~2,000 AWS
rules exist; Azure has 0. Without rules, Azure check scans produce 0 findings and compliance
scoring cannot work.

Target: >= 500 rules total. Stretch: ~600.

## Files to Create

- `consolidated_services/database/scripts/seed_azure_check_rules.py`

## Rule Coverage Required (from 14_AZURE_E2E_PLAN.md)

| Service | resource_type | Target |
|---------|--------------|--------|
| compute | VirtualMachine, VMSS | ≥ 50 |
| network | NetworkSecurityGroup, VirtualNetwork, ApplicationGateway | ≥ 60 |
| storage | StorageAccount, BlobContainer | ≥ 40 |
| keyvault | KeyVault | ≥ 30 |
| sql | SQLServer, SQLDatabase, MySQLServer | ≥ 40 |
| iam | ServicePrincipal, ManagedIdentity, User (AAD) | ≥ 80 |
| containerservice | AKSCluster | ≥ 30 |
| web | AppService, FunctionApp | ≥ 30 |
| monitor | DiagnosticSetting, ActivityLog, AlertRule | ≥ 20 |

## Implementation Notes

Script pattern: same as `seed_hunt_queries.py` — connect via env vars, upsert with
`ON CONFLICT (rule_id, customer_id, tenant_id) DO UPDATE`.

tenant_id = NULL (global rules, apply to all tenants).
customer_id = NULL.

Key rule_metadata columns needed per rule:
```python
{
    "rule_id":             "azure_storage_public_access_disabled",
    "service":             "storage",
    "provider":            "azure",
    "resource":            "StorageAccount",
    "severity":            "high",          # critical/high/medium/low
    "title":               "...",
    "description":         "...",
    "remediation":         "...",
    "compliance_frameworks": {"cis_azure_1_5": ["3.5"], "nist_800_53": ["AC-3"]},
    "mitre_tactics":       ["Initial Access"],
    "mitre_techniques":    ["T1190"],
    "threat_category":     "data_exposure",  # or iam_misconfiguration, network_exposure, etc.
}
```

## Key Rules per Service (non-exhaustive — implement all)

**Storage:**
- azure_storage_public_access_disabled (high) — CIS 3.5
- azure_storage_https_only (high) — CIS 3.1
- azure_storage_tls_version_12 (medium) — CIS 3.2
- azure_storage_blob_soft_delete (medium) — CIS 3.9
- azure_storage_cmk_encryption (medium) — CIS 3.7
- azure_storage_logging_read_write_delete (medium) — CIS 3.11/3.12/3.13
- azure_storage_trusted_services_bypass (low)

**Network:**
- azure_nsg_no_allow_all_inbound (critical) — CIS 6.1
- azure_nsg_rdp_restricted (high) — CIS 6.2
- azure_nsg_ssh_restricted (high) — CIS 6.3
- azure_nsg_udp_restricted (medium)
- azure_network_watcher_enabled (medium) — CIS 6.5
- azure_ddos_standard_enabled (medium) — CIS 6.4
- azure_appgw_waf_enabled (high) — CIS 6.6

**Compute:**
- azure_vm_disk_encryption_enabled (high) — CIS 7.1/7.2
- azure_vm_managed_disk_used (medium) — CIS 7.3
- azure_vm_boot_diagnostics_enabled (low) — CIS 7.4
- azure_vm_endpoint_protection (high) — CIS 7.5
- azure_vmss_automatic_os_updates (medium)

**KeyVault:**
- azure_keyvault_soft_delete_enabled (high) — CIS 9.1
- azure_keyvault_purge_protection_enabled (high) — CIS 9.2
- azure_keyvault_key_expiry_set (medium) — CIS 9.3
- azure_keyvault_certificate_expiry_set (medium)
- azure_keyvault_rbac_authorization (medium)
- azure_keyvault_private_endpoint (medium) — CIS 9.4

**SQL:**
- azure_sql_tde_enabled (high) — CIS 4.1
- azure_sql_auditing_enabled (high) — CIS 4.2
- azure_sql_threat_detection_enabled (high) — CIS 4.3
- azure_sql_no_allow_all_firewall (critical) — CIS 4.4
- azure_sql_vulnerability_assessment_enabled (medium) — CIS 4.5
- azure_sql_aad_admin_configured (medium) — CIS 4.8

**IAM/EntraID (also used by AZ-10 IAM engine):**
- azure_iam_mfa_all_users (critical) — CIS 1.1
- azure_iam_no_legacy_auth (high) — CIS 1.3
- azure_iam_no_permanent_admin (high) — CIS 1.7 (PIM)
- azure_iam_guest_users_reviewed (medium) — CIS 1.8
- azure_iam_sp_credential_rotation (medium) — CIS 1.15
- azure_iam_no_custom_broad_roles (medium) — CIS 1.22
- azure_iam_subscription_owner_max_3 (high)
- azure_iam_mfa_privileged_users (critical) — CIS 1.2

**AKS:**
- azure_aks_rbac_enabled (high) — CIS + NIST
- azure_aks_aad_integration (high)
- azure_aks_network_policy (high)
- azure_aks_private_cluster (medium)
- azure_aks_node_pool_managed_identity (medium)
- azure_aks_no_public_api_server (high)

**AppService:**
- azure_appservice_https_only (high) — CIS 8.1
- azure_appservice_tls_12 (high) — CIS 8.2
- azure_appservice_managed_identity (medium) — CIS 8.3
- azure_appservice_ftp_disabled (medium) — CIS 8.4
- azure_appservice_client_cert_required (medium) — CIS 8.5
- azure_appservice_auth_enabled (high) — CIS 8.7

**Monitoring:**
- azure_monitor_diagnostic_settings_kvault (medium) — CIS 5.1
- azure_monitor_activity_log_retention_365 (medium) — CIS 5.2
- azure_monitor_alerts_create_policy (medium) — CIS 5.3
- azure_monitor_alerts_delete_policy (medium) — CIS 5.4
- azure_monitor_alerts_nsg_changes (medium) — CIS 5.5
- azure_monitor_alerts_security_solution (medium) — CIS 5.6

## Acceptance Criteria
- [ ] `SELECT count(*) FROM rule_metadata WHERE provider='azure'` >= 500
- [ ] Rules exist for all 9 service categories
- [ ] Each rule has non-null severity, title, compliance_frameworks
- [ ] Script is idempotent (re-run safe)
- [ ] CIS control references correct (e.g., `cis_azure_1_5: ["3.5"]`)

## Definition of Done
- [ ] Script committed and run against RDS
- [ ] Rule count meets floor (>=500)
- [ ] AZ-11 can map rules to CIS controls