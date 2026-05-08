#!/usr/bin/env python3
"""
generate_azure_ciem.py

Generates Azure CIEM log-detection rule YAMLs into:
  catalog/rule/azure_rule_ciem/{service}/azure.{service}.{log_source}.{op_slug}.yaml

Log sources:
  activity_log  — Azure Activity Log (Microsoft.*/write|delete|action)
  entra_audit   — Microsoft Entra ID (Azure AD) audit log
  aks_audit     — Kubernetes audit log from AKS

Usage:
    python3 generate_azure_ciem.py              # generate all
    python3 generate_azure_ciem.py --dry-run    # print counts only
    python3 generate_azure_ciem.py --service iam
"""

import argparse
from pathlib import Path
from typing import Dict, List, Tuple

import yaml

CATALOG_DIR = Path(__file__).parent

# ─────────────────────────────────────────────────────────────────────────────
# Operation map
# Key   : op_slug (used in rule_id and filename)
# Value : (service_dir, log_source_type, azure_operation_value,
#          threat_category, mitre_tactics, mitre_techniques,
#          severity, risk_score, resource, description)
# ─────────────────────────────────────────────────────────────────────────────

_OP_MAP: Dict[str, Tuple] = {

    # ═══════════════════════════════════════════════════════════════════════
    # IAM — Entra ID (Azure AD) audit log
    # ═══════════════════════════════════════════════════════════════════════
    "user_create": (
        "iam", "entra_audit", "microsoft.directory/users/create",
        "identity_manipulation", ["persistence", "initial_access"], ["T1136.003", "T1078.004"],
        "high", 75, "entra_user",
        "New Entra ID user created — attacker may be establishing persistent identity."),
    "user_delete": (
        "iam", "entra_audit", "microsoft.directory/users/delete",
        "defense_evasion", ["defense_evasion"], ["T1531"],
        "high", 65, "entra_user",
        "Entra ID user deleted — account removed, potentially covering attacker tracks."),
    "user_password_reset": (
        "iam", "entra_audit", "microsoft.directory/users/password/update",
        "credential_access", ["credential_access"], ["T1098.001"],
        "high", 78, "entra_user",
        "User password reset — attacker may have taken over account via credential reset."),
    "user_upn_update": (
        "iam", "entra_audit", "microsoft.directory/users/userPrincipalName/update",
        "defense_evasion", ["defense_evasion"], ["T1078.004"],
        "medium", 55, "entra_user",
        "User principal name changed — identity renamed, may evade detection based on username."),
    "user_mfa_update": (
        "iam", "entra_audit", "microsoft.directory/users/mfa/update",
        "defense_evasion", ["defense_evasion"], ["T1556.006"],
        "high", 80, "entra_user",
        "MFA settings updated for user — attacker may have disabled or changed MFA to maintain access."),
    "user_auth_method_update": (
        "iam", "entra_audit", "microsoft.directory/users/authenticationMethods/update",
        "defense_evasion", ["defense_evasion"], ["T1556.006"],
        "high", 78, "entra_user",
        "Authentication method updated — MFA device or method changed, potentially disabling second factor."),
    "user_disable": (
        "iam", "entra_audit", "microsoft.directory/users/accountEnabled/update",
        "impact", ["impact"], ["T1531"],
        "high", 65, "entra_user",
        "User account enabled/disabled — service disruption or attacker-controlled lockout."),
    "group_create": (
        "iam", "entra_audit", "microsoft.directory/groups/create",
        "persistence", ["persistence"], ["T1136.003"],
        "medium", 50, "entra_group",
        "Entra ID group created — new group may be used to grant bulk permissions."),
    "group_member_add": (
        "iam", "entra_audit", "microsoft.directory/groups/members/add",
        "privilege_escalation", ["privilege_escalation"], ["T1098.003"],
        "high", 72, "entra_group",
        "User added to Entra ID group — group membership may grant elevated permissions."),
    "group_member_remove": (
        "iam", "entra_audit", "microsoft.directory/groups/members/remove",
        "defense_evasion", ["defense_evasion"], ["T1531"],
        "medium", 45, "entra_group",
        "User removed from Entra ID group — access revoked or attacker removing legitimate users."),
    "group_owner_add": (
        "iam", "entra_audit", "microsoft.directory/groups/owners/add",
        "privilege_escalation", ["privilege_escalation"], ["T1098.003"],
        "high", 75, "entra_group",
        "Owner added to Entra ID group — owner can manage group membership and permissions."),
    "app_registration_create": (
        "iam", "entra_audit", "microsoft.directory/applications/create",
        "persistence", ["persistence"], ["T1550.001"],
        "high", 78, "entra_app",
        "App registration created — new OAuth/OIDC application may be used for persistent access."),
    "app_registration_delete": (
        "iam", "entra_audit", "microsoft.directory/applications/delete",
        "defense_evasion", ["defense_evasion"], ["T1578.004"],
        "medium", 55, "entra_app",
        "App registration deleted — legitimate application removed, potentially disrupting access controls."),
    "app_credential_add": (
        "iam", "entra_audit", "microsoft.directory/applications/credentials/update",
        "persistence", ["persistence", "credential_access"], ["T1550.001", "T1552.007"],
        "critical", 90, "entra_app",
        "Credential added to app registration — new secret or certificate enables long-lived application access."),
    "app_owner_add": (
        "iam", "entra_audit", "microsoft.directory/applications/owners/add",
        "privilege_escalation", ["privilege_escalation"], ["T1098.003"],
        "high", 75, "entra_app",
        "Owner added to application registration — owner can modify app credentials and permissions."),
    "app_permission_grant": (
        "iam", "entra_audit", "microsoft.directory/servicePrincipals/appRoleAssignments/update",
        "privilege_escalation", ["privilege_escalation"], ["T1098.003"],
        "high", 80, "entra_app",
        "Application role assigned — OAuth2 permission granted to service principal."),
    "app_oauth_consent": (
        "iam", "entra_audit", "microsoft.directory/oAuth2PermissionGrants/allProperties/update",
        "initial_access", ["initial_access", "persistence"], ["T1078.004", "T1550.001"],
        "critical", 88, "entra_app",
        "OAuth2 consent granted to application — application can act on behalf of user or access tenant data."),
    "service_principal_create": (
        "iam", "entra_audit", "microsoft.directory/servicePrincipals/create",
        "persistence", ["persistence"], ["T1550.001"],
        "high", 72, "entra_service_principal",
        "Service principal created — workload identity provisioned, may be used for persistent cloud access."),
    "service_principal_credential_update": (
        "iam", "entra_audit", "microsoft.directory/servicePrincipals/credentials/update",
        "credential_access", ["credential_access", "persistence"], ["T1552.007", "T1550.001"],
        "critical", 88, "entra_service_principal",
        "Service principal credentials updated — new secret or certificate enables impersonation of workload."),
    "service_principal_owner_add": (
        "iam", "entra_audit", "microsoft.directory/servicePrincipals/owners/add",
        "privilege_escalation", ["privilege_escalation"], ["T1098.003"],
        "high", 75, "entra_service_principal",
        "Owner added to service principal — owner can rotate credentials and modify permissions."),
    "directory_role_member_add": (
        "iam", "entra_audit", "microsoft.directory/directoryRoles/members/add",
        "privilege_escalation", ["privilege_escalation"], ["T1098.003"],
        "critical", 90, "entra_user",
        "User assigned to Entra ID directory role — privileged role assignment grants tenant-wide permissions."),
    "domain_federation_update": (
        "iam", "entra_audit", "microsoft.directory/domains/federation/update",
        "persistence", ["persistence", "initial_access"], ["T1556.007"],
        "critical", 95, "entra_tenant",
        "Domain federation configuration updated — attacker may establish rogue identity provider for persistent access."),
    "external_identity_provider_add": (
        "iam", "entra_audit", "microsoft.aadiam/identityProviders/write",
        "persistence", ["persistence"], ["T1556.007"],
        "critical", 90, "entra_tenant",
        "External identity provider added — new federated trust allows external principals to authenticate as tenant users."),
    "tenant_policy_update": (
        "iam", "entra_audit", "microsoft.directory/organization/dirSync/update",
        "defense_evasion", ["defense_evasion"], ["T1484.002"],
        "high", 70, "entra_tenant",
        "Tenant directory sync policy updated — synchronization settings change may introduce on-prem compromise path."),
    "admin_consent_grant": (
        "iam", "entra_audit", "microsoft.directory/servicePrincipals/managePermissionGrantsForAll.microsoft-company-admin/action",
        "privilege_escalation", ["privilege_escalation", "persistence"], ["T1098.003", "T1550.001"],
        "critical", 92, "entra_tenant",
        "Admin consent granted for application — application receives tenant-wide API access without per-user consent."),

    # ═══════════════════════════════════════════════════════════════════════
    # AUTHORIZATION — Azure Activity Log (RBAC + Policy)
    # ═══════════════════════════════════════════════════════════════════════
    "role_assignment_write": (
        "authorization", "activity_log", "Microsoft.Authorization/roleAssignments/write",
        "privilege_escalation", ["privilege_escalation"], ["T1098.003"],
        "high", 78, "azure_rbac",
        "RBAC role assignment created — principal granted permissions at subscription, resource group, or resource scope."),
    "role_assignment_delete": (
        "authorization", "activity_log", "Microsoft.Authorization/roleAssignments/delete",
        "defense_evasion", ["defense_evasion"], ["T1531"],
        "medium", 50, "azure_rbac",
        "RBAC role assignment deleted — permissions revoked, may indicate account cleanup or removal of legitimate access."),
    "role_definition_write": (
        "authorization", "activity_log", "Microsoft.Authorization/roleDefinitions/write",
        "privilege_escalation", ["privilege_escalation"], ["T1484.001"],
        "high", 80, "azure_rbac",
        "Custom RBAC role created or modified — broad permissions may bypass least-privilege controls."),
    "role_definition_delete": (
        "authorization", "activity_log", "Microsoft.Authorization/roleDefinitions/delete",
        "defense_evasion", ["defense_evasion"], ["T1484.001"],
        "medium", 45, "azure_rbac",
        "Custom RBAC role deleted — access control definition removed."),
    "policy_assignment_write": (
        "authorization", "activity_log", "Microsoft.Authorization/policyAssignments/write",
        "defense_evasion", ["defense_evasion"], ["T1484.001"],
        "high", 70, "azure_policy",
        "Azure Policy assignment created or modified — security control enforcement changed."),
    "policy_assignment_delete": (
        "authorization", "activity_log", "Microsoft.Authorization/policyAssignments/delete",
        "defense_evasion", ["defense_evasion"], ["T1484.001"],
        "high", 72, "azure_policy",
        "Azure Policy assignment deleted — security policy enforcement removed from scope."),
    "policy_definition_write": (
        "authorization", "activity_log", "Microsoft.Authorization/policyDefinitions/write",
        "defense_evasion", ["defense_evasion"], ["T1484.001"],
        "medium", 60, "azure_policy",
        "Custom Azure Policy definition created or modified — security evaluation logic changed."),
    "resource_lock_write": (
        "authorization", "activity_log", "Microsoft.Authorization/locks/write",
        "impact", ["impact"], ["T1485"],
        "medium", 45, "azure_resource",
        "Resource lock created — resource protected from deletion or modification."),
    "resource_lock_delete": (
        "authorization", "activity_log", "Microsoft.Authorization/locks/delete",
        "impact", ["impact"], ["T1485"],
        "high", 72, "azure_resource",
        "Resource lock deleted — deletion protection removed, resource now vulnerable to destruction."),
    "elevate_access_action": (
        "authorization", "activity_log", "Microsoft.Authorization/elevateAccess/action",
        "privilege_escalation", ["privilege_escalation"], ["T1548"],
        "critical", 92, "azure_rbac",
        "User Access Administrator elevation invoked — caller elevated to tenant-wide User Access Admin role."),
    "deny_assignment_write": (
        "authorization", "activity_log", "Microsoft.Authorization/denyAssignments/write",
        "defense_evasion", ["defense_evasion"], ["T1484.001"],
        "medium", 50, "azure_rbac",
        "Deny assignment created — explicit deny rule overrides allow permissions for principals."),
    "blueprint_assignment_write": (
        "authorization", "activity_log", "Microsoft.Blueprint/blueprintAssignments/write",
        "defense_evasion", ["defense_evasion"], ["T1484.001"],
        "medium", 55, "azure_resource",
        "Azure Blueprint assignment created — environment governance policy applied or changed."),

    # ═══════════════════════════════════════════════════════════════════════
    # IDENTITY — Conditional Access, PIM, Managed Identity
    # ═══════════════════════════════════════════════════════════════════════
    "conditional_access_create": (
        "identity", "entra_audit", "microsoft.directory/conditionalAccessPolicies/create",
        "defense_evasion", ["defense_evasion"], ["T1556.006"],
        "high", 70, "entra_conditional_access",
        "Conditional access policy created — new access rule applied to user sign-in flow."),
    "conditional_access_update": (
        "identity", "entra_audit", "microsoft.directory/conditionalAccessPolicies/update",
        "defense_evasion", ["defense_evasion"], ["T1556.006"],
        "high", 75, "entra_conditional_access",
        "Conditional access policy modified — MFA enforcement, trusted location, or device compliance requirements changed."),
    "conditional_access_delete": (
        "identity", "entra_audit", "microsoft.directory/conditionalAccessPolicies/delete",
        "defense_evasion", ["defense_evasion"], ["T1556.006"],
        "critical", 88, "entra_conditional_access",
        "Conditional access policy deleted — MFA or compliance requirement removed, access control weakened."),
    "named_location_create": (
        "identity", "entra_audit", "microsoft.directory/namedLocations/create",
        "defense_evasion", ["defense_evasion"], ["T1556.006"],
        "medium", 55, "entra_conditional_access",
        "Named location created — trusted IP range or country added, may bypass conditional access controls."),
    "named_location_update": (
        "identity", "entra_audit", "microsoft.directory/namedLocations/update",
        "defense_evasion", ["defense_evasion"], ["T1556.006"],
        "medium", 58, "entra_conditional_access",
        "Named location modified — trusted network boundary changed, may expand attacker-controlled trusted range."),
    "pim_role_activate": (
        "identity", "entra_audit", "microsoft.directory/privilegedIdentityManagement/allProperties/update",
        "privilege_escalation", ["privilege_escalation"], ["T1548"],
        "high", 72, "entra_pim",
        "Privileged Identity Management role activated — just-in-time privileged access granted."),
    "pim_settings_update": (
        "identity", "entra_audit", "microsoft.azure.privilegedIdentityManagement/privilegedIdentityManagementV3/policyUpdate/action",
        "defense_evasion", ["defense_evasion"], ["T1484.002"],
        "high", 78, "entra_pim",
        "PIM role settings modified — approval requirements, duration, or MFA enforcement changed."),
    "managed_identity_assign": (
        "identity", "activity_log", "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action",
        "privilege_escalation", ["privilege_escalation"], ["T1098.003"],
        "high", 72, "azure_managed_identity",
        "Managed identity assigned to resource — resource gains access to Azure services via identity permissions."),
    "managed_identity_write": (
        "identity", "activity_log", "Microsoft.ManagedIdentity/userAssignedIdentities/write",
        "persistence", ["persistence"], ["T1550.001"],
        "medium", 55, "azure_managed_identity",
        "User-assigned managed identity created or updated — new workload identity provisioned."),
    "federated_credential_write": (
        "identity", "activity_log", "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write",
        "persistence", ["persistence"], ["T1556.007"],
        "high", 78, "azure_managed_identity",
        "Federated identity credential added to managed identity — external OIDC issuer trusted for token exchange."),
    "access_review_create": (
        "identity", "entra_audit", "microsoft.directory/accessReviews/create",
        "discovery", ["discovery"], ["T1087.004"],
        "low", 25, "entra_access_review",
        "Access review created — periodic review of user access rights initiated."),
    "emergency_account_used": (
        "identity", "entra_audit", "microsoft.directory/signIns/breakGlassAccount/action",
        "initial_access", ["initial_access"], ["T1078.004"],
        "critical", 92, "entra_user",
        "Break-glass emergency account sign-in detected — highly privileged emergency account used outside of authorized incident."),

    # ═══════════════════════════════════════════════════════════════════════
    # KEY VAULT — Azure Activity Log
    # ═══════════════════════════════════════════════════════════════════════
    "keyvault_secret_read": (
        "keyvault", "activity_log", "Microsoft.KeyVault/vaults/secrets/read",
        "credential_access", ["credential_access"], ["T1552.001"],
        "high", 78, "azure_key_vault",
        "Key Vault secret read — sensitive credential or token accessed from vault."),
    "keyvault_secret_write": (
        "keyvault", "activity_log", "Microsoft.KeyVault/vaults/secrets/write",
        "persistence", ["persistence"], ["T1552.001"],
        "medium", 55, "azure_key_vault",
        "Key Vault secret written — new or updated secret stored in vault."),
    "keyvault_secret_delete": (
        "keyvault", "activity_log", "Microsoft.KeyVault/vaults/secrets/delete",
        "data_destruction", ["impact"], ["T1485"],
        "high", 72, "azure_key_vault",
        "Key Vault secret deleted — credential removed, may impact dependent services."),
    "keyvault_key_read": (
        "keyvault", "activity_log", "Microsoft.KeyVault/vaults/keys/read",
        "credential_access", ["credential_access"], ["T1552.004"],
        "high", 75, "azure_key_vault",
        "Key Vault encryption key read — cryptographic key accessed, potential exfiltration path."),
    "keyvault_key_backup": (
        "keyvault", "activity_log", "Microsoft.KeyVault/vaults/keys/backup/action",
        "data_exfiltration", ["collection", "exfiltration"], ["T1552.004", "T1567"],
        "high", 80, "azure_key_vault",
        "Key Vault key backed up — key material exported to blob, potential off-vault exfiltration."),
    "keyvault_delete": (
        "keyvault", "activity_log", "Microsoft.KeyVault/vaults/delete",
        "data_destruction", ["impact"], ["T1485"],
        "critical", 90, "azure_key_vault",
        "Key Vault deleted — all secrets, keys, and certificates in vault destroyed."),
    "keyvault_purge": (
        "keyvault", "activity_log", "Microsoft.KeyVault/vaults/purge/action",
        "data_destruction", ["impact"], ["T1485"],
        "critical", 95, "azure_key_vault",
        "Key Vault purged — soft-deleted vault permanently destroyed, bypassing recovery window."),
    "keyvault_access_policy_write": (
        "keyvault", "activity_log", "Microsoft.KeyVault/vaults/accessPolicies/write",
        "privilege_escalation", ["privilege_escalation"], ["T1098.003"],
        "high", 78, "azure_key_vault",
        "Key Vault access policy modified — principal granted read/write/delete access to vault contents."),
    "keyvault_write": (
        "keyvault", "activity_log", "Microsoft.KeyVault/vaults/write",
        "defense_evasion", ["defense_evasion"], ["T1484.001"],
        "medium", 50, "azure_key_vault",
        "Key Vault created or updated — vault properties or network rules changed."),
    "keyvault_hsm_key_backup": (
        "keyvault", "activity_log", "Microsoft.KeyVault/managedHsms/keys/backup/action",
        "data_exfiltration", ["collection", "exfiltration"], ["T1552.004"],
        "critical", 88, "azure_key_vault",
        "Managed HSM key backed up — hardware-protected key material exported."),
    "keyvault_certificate_delete": (
        "keyvault", "activity_log", "Microsoft.KeyVault/vaults/certificates/delete",
        "impact", ["impact"], ["T1485"],
        "high", 70, "azure_key_vault",
        "Key Vault certificate deleted — TLS certificate removed, potential service disruption."),

    # ═══════════════════════════════════════════════════════════════════════
    # COMPUTE — Azure Activity Log
    # ═══════════════════════════════════════════════════════════════════════
    "vm_extension_write": (
        "compute", "activity_log", "Microsoft.Compute/virtualMachines/extensions/write",
        "execution", ["execution", "persistence"], ["T1651", "T1546.004"],
        "high", 80, "azure_vm",
        "VM extension installed or updated — code execution capability added to virtual machine."),
    "vm_run_command": (
        "compute", "activity_log", "Microsoft.Compute/virtualMachines/runCommand/action",
        "execution", ["execution"], ["T1651"],
        "high", 82, "azure_vm",
        "VM Run Command executed — arbitrary script executed on virtual machine via Azure management plane."),
    "vm_capture": (
        "compute", "activity_log", "Microsoft.Compute/virtualMachines/capture/action",
        "data_exfiltration", ["collection"], ["T1005"],
        "high", 78, "azure_vm",
        "VM image captured — full disk image of running VM created, may contain sensitive data."),
    "vm_delete": (
        "compute", "activity_log", "Microsoft.Compute/virtualMachines/delete",
        "data_destruction", ["impact"], ["T1485"],
        "high", 75, "azure_vm",
        "Virtual machine deleted — compute resource destroyed."),
    "vm_write": (
        "compute", "activity_log", "Microsoft.Compute/virtualMachines/write",
        "execution", ["execution"], ["T1578.002"],
        "medium", 50, "azure_vm",
        "Virtual machine created or modified — new compute instance provisioned or configuration changed."),
    "disk_snapshot_write": (
        "compute", "activity_log", "Microsoft.Compute/snapshots/write",
        "data_exfiltration", ["collection"], ["T1005"],
        "high", 78, "azure_disk",
        "Disk snapshot created — point-in-time copy of managed disk made, potential data exfiltration vector."),
    "disk_snapshot_delete": (
        "compute", "activity_log", "Microsoft.Compute/snapshots/delete",
        "data_destruction", ["impact"], ["T1485"],
        "medium", 55, "azure_disk",
        "Disk snapshot deleted — backup copy destroyed."),
    "disk_export": (
        "compute", "activity_log", "Microsoft.Compute/disks/beginGetAccess/action",
        "data_exfiltration", ["collection", "exfiltration"], ["T1005", "T1567"],
        "critical", 88, "azure_disk",
        "Managed disk SAS URL generated — disk contents can be downloaded directly via URL."),
    "vm_deallocate": (
        "compute", "activity_log", "Microsoft.Compute/virtualMachines/deallocate/action",
        "impact", ["impact"], ["T1489"],
        "medium", 55, "azure_vm",
        "Virtual machine deallocated — VM stopped and compute resources released."),
    "image_write": (
        "compute", "activity_log", "Microsoft.Compute/galleries/images/write",
        "persistence", ["persistence"], ["T1578.002"],
        "medium", 55, "azure_vm",
        "VM gallery image created or updated — shared image may be used to deploy backdoored instances."),
    "vm_reimage": (
        "compute", "activity_log", "Microsoft.Compute/virtualMachines/reimage/action",
        "impact", ["impact"], ["T1485"],
        "high", 70, "azure_vm",
        "Virtual machine reimaged — OS disk replaced, may destroy forensic evidence."),

    # ═══════════════════════════════════════════════════════════════════════
    # STORAGE — Azure Activity Log
    # ═══════════════════════════════════════════════════════════════════════
    "storage_list_keys": (
        "storage", "activity_log", "Microsoft.Storage/storageAccounts/listKeys/action",
        "credential_access", ["credential_access"], ["T1552.001"],
        "critical", 88, "azure_storage",
        "Storage account keys listed — full read/write/delete access keys to storage account retrieved."),
    "storage_regenerate_key": (
        "storage", "activity_log", "Microsoft.Storage/storageAccounts/regenerateKey/action",
        "credential_access", ["credential_access"], ["T1552.001"],
        "high", 75, "azure_storage",
        "Storage account key regenerated — existing key rotated, may lock out legitimate applications."),
    "storage_generate_sas": (
        "storage", "activity_log", "Microsoft.Storage/storageAccounts/generateSas/action",
        "credential_access", ["credential_access"], ["T1552.001"],
        "high", 80, "azure_storage",
        "Storage account SAS token generated — time-limited credential created for direct storage access."),
    "storage_account_delete": (
        "storage", "activity_log", "Microsoft.Storage/storageAccounts/delete",
        "data_destruction", ["impact"], ["T1485"],
        "critical", 90, "azure_storage",
        "Storage account deleted — all blobs, tables, queues and files permanently destroyed."),
    "storage_account_write": (
        "storage", "activity_log", "Microsoft.Storage/storageAccounts/write",
        "defense_evasion", ["defense_evasion"], ["T1484.001"],
        "medium", 50, "azure_storage",
        "Storage account created or modified — network rules, encryption, or access settings changed."),
    "storage_container_delete": (
        "storage", "activity_log", "Microsoft.Storage/storageAccounts/blobServices/containers/delete",
        "data_destruction", ["impact"], ["T1485"],
        "high", 80, "azure_storage",
        "Blob storage container deleted — all objects in container permanently destroyed."),
    "storage_container_public_write": (
        "storage", "activity_log", "Microsoft.Storage/storageAccounts/blobServices/containers/write",
        "initial_access", ["initial_access"], ["T1190"],
        "high", 75, "azure_storage",
        "Blob container access level changed — container may have been set to public access."),
    "storage_file_share_delete": (
        "storage", "activity_log", "Microsoft.Storage/storageAccounts/fileServices/shares/delete",
        "data_destruction", ["impact"], ["T1485"],
        "high", 78, "azure_storage",
        "Azure file share deleted — all files in share destroyed."),
    "storage_blob_service_write": (
        "storage", "activity_log", "Microsoft.Storage/storageAccounts/blobServices/write",
        "defense_evasion", ["defense_evasion"], ["T1484.001"],
        "medium", 50, "azure_storage",
        "Blob service properties modified — soft delete, versioning, or CORS settings changed."),
    "storage_management_policy_delete": (
        "storage", "activity_log", "Microsoft.Storage/storageAccounts/managementPolicies/delete",
        "data_destruction", ["impact"], ["T1485"],
        "medium", 55, "azure_storage",
        "Storage lifecycle policy deleted — automated data deletion or tiering rules removed."),

    # ═══════════════════════════════════════════════════════════════════════
    # CONTAINER — AKS Activity Log + Kubernetes Audit
    # ═══════════════════════════════════════════════════════════════════════
    "aks_cluster_write": (
        "container", "activity_log", "Microsoft.ContainerService/managedClusters/write",
        "defense_evasion", ["defense_evasion"], ["T1578.001"],
        "high", 70, "aks_cluster",
        "AKS cluster created or modified — cluster configuration, RBAC, or network policy changed."),
    "aks_cluster_delete": (
        "container", "activity_log", "Microsoft.ContainerService/managedClusters/delete",
        "data_destruction", ["impact"], ["T1485"],
        "critical", 88, "aks_cluster",
        "AKS cluster deleted — Kubernetes workloads and persistent volumes destroyed."),
    "aks_admin_credential_list": (
        "container", "activity_log", "Microsoft.ContainerService/managedClusters/listClusterAdminCredential/action",
        "credential_access", ["credential_access"], ["T1552.007"],
        "critical", 92, "aks_cluster",
        "AKS cluster admin credentials retrieved — kubeconfig with cluster-admin access obtained."),
    "aks_user_credential_list": (
        "container", "activity_log", "Microsoft.ContainerService/managedClusters/listClusterUserCredential/action",
        "credential_access", ["credential_access"], ["T1552.007"],
        "high", 75, "aks_cluster",
        "AKS cluster user credentials retrieved — kubeconfig for cluster access obtained."),
    "aks_access_profile_read": (
        "container", "activity_log", "Microsoft.ContainerService/managedClusters/accessProfiles/read",
        "credential_access", ["credential_access"], ["T1552.007"],
        "high", 78, "aks_cluster",
        "AKS access profile read — cluster authentication profile accessed."),
    "k8s_pod_exec": (
        "container", "aks_audit", "pods/exec",
        "execution", ["execution"], ["T1059.013"],
        "high", 82, "k8s_pod",
        "kubectl exec in Kubernetes pod — interactive shell or command executed inside running container."),
    "k8s_secret_access": (
        "container", "aks_audit", "secrets/get",
        "credential_access", ["credential_access"], ["T1552.007"],
        "high", 80, "k8s_secret",
        "Kubernetes secret accessed via API — token, certificate, or sensitive config read from cluster."),
    "k8s_clusterrolebinding_create": (
        "container", "aks_audit", "clusterrolebindings/create",
        "privilege_escalation", ["privilege_escalation"], ["T1098.006"],
        "critical", 90, "k8s_rbac",
        "Kubernetes ClusterRoleBinding created — cluster-wide permissions granted to subject."),
    "k8s_rolebinding_create": (
        "container", "aks_audit", "rolebindings/create",
        "privilege_escalation", ["privilege_escalation"], ["T1098.006"],
        "high", 75, "k8s_rbac",
        "Kubernetes RoleBinding created — namespace-scoped permissions granted to subject."),
    "k8s_clusterrole_write": (
        "container", "aks_audit", "clusterroles/create",
        "privilege_escalation", ["privilege_escalation"], ["T1098.006"],
        "high", 78, "k8s_rbac",
        "Kubernetes ClusterRole created — new cluster-wide permission set defined."),
    "k8s_privileged_pod_create": (
        "container", "aks_audit", "pods/create",
        "privilege_escalation", ["privilege_escalation"], ["T1611"],
        "high", 78, "k8s_pod",
        "Kubernetes privileged pod created — container with host-level access may escape namespace isolation."),
    "k8s_namespace_delete": (
        "container", "aks_audit", "namespaces/delete",
        "data_destruction", ["impact"], ["T1485"],
        "critical", 88, "k8s_namespace",
        "Kubernetes namespace deleted — all workloads and resources in namespace destroyed."),
    "k8s_service_account_token_create": (
        "container", "aks_audit", "serviceaccounts/token",
        "credential_access", ["credential_access"], ["T1552.007"],
        "high", 78, "k8s_service_account",
        "Kubernetes service account token created — JWT credential issued for API server authentication."),
    "k8s_daemonset_write": (
        "container", "aks_audit", "daemonsets/create",
        "persistence", ["persistence"], ["T1610"],
        "high", 75, "k8s_workload",
        "Kubernetes DaemonSet created — workload deployed to every node in cluster."),

    # ═══════════════════════════════════════════════════════════════════════
    # NETWORK — Azure Activity Log
    # ═══════════════════════════════════════════════════════════════════════
    "nsg_write": (
        "network", "activity_log", "Microsoft.Network/networkSecurityGroups/write",
        "defense_evasion", ["defense_evasion"], ["T1562.007"],
        "high", 70, "azure_nsg",
        "Network security group created or modified — inbound/outbound traffic rules changed."),
    "nsg_rule_write": (
        "network", "activity_log", "Microsoft.Network/networkSecurityGroups/securityRules/write",
        "defense_evasion", ["defense_evasion"], ["T1562.007"],
        "high", 72, "azure_nsg",
        "NSG security rule created or modified — specific allow/deny traffic rule added."),
    "nsg_delete": (
        "network", "activity_log", "Microsoft.Network/networkSecurityGroups/delete",
        "defense_evasion", ["defense_evasion"], ["T1562.007"],
        "high", 75, "azure_nsg",
        "Network security group deleted — all traffic filtering rules for associated subnets removed."),
    "vnet_peering_write": (
        "network", "activity_log", "Microsoft.Network/virtualNetworks/virtualNetworkPeerings/write",
        "lateral_movement", ["lateral_movement"], ["T1021.007"],
        "high", 78, "azure_vnet",
        "Virtual network peering created — lateral movement path established between VNets."),
    "firewall_rule_write": (
        "network", "activity_log", "Microsoft.Network/azureFirewalls/write",
        "defense_evasion", ["defense_evasion"], ["T1562.004"],
        "high", 75, "azure_firewall",
        "Azure Firewall policy created or modified — network traffic filtering rules changed."),
    "bastion_write": (
        "network", "activity_log", "Microsoft.Network/bastionHosts/write",
        "initial_access", ["initial_access"], ["T1133"],
        "medium", 55, "azure_bastion",
        "Azure Bastion host created or modified — browser-based RDP/SSH access point provisioned."),
    "public_ip_write": (
        "network", "activity_log", "Microsoft.Network/publicIPAddresses/write",
        "initial_access", ["initial_access"], ["T1190"],
        "medium", 50, "azure_network",
        "Public IP address created or associated — internet-routable IP assigned to resource."),
    "route_table_write": (
        "network", "activity_log", "Microsoft.Network/routeTables/write",
        "lateral_movement", ["lateral_movement"], ["T1557"],
        "high", 72, "azure_network",
        "Route table created or modified — custom routing rules may redirect traffic through attacker-controlled path."),
    "dns_zone_write": (
        "network", "activity_log", "Microsoft.Network/privateDnsZones/write",
        "lateral_movement", ["lateral_movement"], ["T1071.004"],
        "medium", 58, "azure_dns",
        "Private DNS zone created or modified — DNS resolution for internal resources changed."),
    "express_route_write": (
        "network", "activity_log", "Microsoft.Network/expressRouteCircuits/write",
        "lateral_movement", ["lateral_movement"], ["T1021.007"],
        "medium", 60, "azure_network",
        "ExpressRoute circuit modified — dedicated on-premises to Azure network connectivity changed."),
    "vpn_gateway_write": (
        "network", "activity_log", "Microsoft.Network/virtualNetworkGateways/write",
        "lateral_movement", ["lateral_movement"], ["T1133"],
        "medium", 60, "azure_network",
        "VPN gateway created or modified — site-to-site or point-to-site VPN configuration changed."),
    "ddos_protection_delete": (
        "network", "activity_log", "Microsoft.Network/ddosProtectionPlans/delete",
        "impact", ["impact"], ["T1498"],
        "high", 70, "azure_network",
        "DDoS protection plan deleted — volumetric attack protection removed from subscription."),

    # ═══════════════════════════════════════════════════════════════════════
    # MONITOR — Azure Activity Log (Defense Evasion via logging manipulation)
    # ═══════════════════════════════════════════════════════════════════════
    "diagnostic_setting_delete": (
        "monitor", "activity_log", "Microsoft.Insights/diagnosticSettings/delete",
        "defense_evasion", ["defense_evasion"], ["T1562.008"],
        "critical", 90, "azure_monitor",
        "Diagnostic setting deleted — resource audit log forwarding to Log Analytics or Storage stopped."),
    "diagnostic_setting_write": (
        "monitor", "activity_log", "Microsoft.Insights/diagnosticSettings/write",
        "defense_evasion", ["defense_evasion"], ["T1562.008"],
        "high", 70, "azure_monitor",
        "Diagnostic setting modified — log categories or destination changed, may reduce visibility."),
    "activity_log_alert_delete": (
        "monitor", "activity_log", "Microsoft.Insights/activityLogAlerts/delete",
        "defense_evasion", ["defense_evasion"], ["T1562.008"],
        "critical", 88, "azure_monitor",
        "Activity log alert deleted — alerting on critical Azure operations removed."),
    "scheduled_query_rule_delete": (
        "monitor", "activity_log", "Microsoft.Insights/scheduledQueryRules/delete",
        "defense_evasion", ["defense_evasion"], ["T1562.008"],
        "high", 80, "azure_monitor",
        "Scheduled query alert rule deleted — automated threat detection rule removed from Log Analytics."),
    "log_analytics_workspace_delete": (
        "monitor", "activity_log", "Microsoft.OperationalInsights/workspaces/delete",
        "defense_evasion", ["defense_evasion"], ["T1562.008"],
        "critical", 92, "azure_monitor",
        "Log Analytics workspace deleted — centralized logging repository destroyed."),
    "log_analytics_purge": (
        "monitor", "activity_log", "Microsoft.OperationalInsights/workspaces/purge/action",
        "defense_evasion", ["defense_evasion"], ["T1562.008"],
        "critical", 93, "azure_monitor",
        "Log Analytics data purged — log records permanently deleted from workspace."),
    "action_group_delete": (
        "monitor", "activity_log", "Microsoft.Insights/actionGroups/delete",
        "defense_evasion", ["defense_evasion"], ["T1562.008"],
        "high", 72, "azure_monitor",
        "Action group deleted — alert notification targets (email, webhook, ITSM) removed."),
    "metric_alert_delete": (
        "monitor", "activity_log", "Microsoft.Insights/metricAlerts/delete",
        "defense_evasion", ["defense_evasion"], ["T1562.008"],
        "high", 70, "azure_monitor",
        "Metric alert deleted — performance or security threshold alerting removed."),
    "log_analytics_data_export_delete": (
        "monitor", "activity_log", "Microsoft.OperationalInsights/workspaces/dataExports/delete",
        "defense_evasion", ["defense_evasion"], ["T1562.008"],
        "medium", 60, "azure_monitor",
        "Log Analytics data export rule deleted — log data pipeline to external storage stopped."),

    # ═══════════════════════════════════════════════════════════════════════
    # SQL — Azure Activity Log
    # ═══════════════════════════════════════════════════════════════════════
    "sql_auditing_write": (
        "sql", "activity_log", "Microsoft.Sql/servers/auditingSettings/write",
        "defense_evasion", ["defense_evasion"], ["T1562.008"],
        "high", 75, "azure_sql",
        "SQL Server audit settings modified — database activity logging configuration changed."),
    "sql_admin_write": (
        "sql", "activity_log", "Microsoft.Sql/servers/administrators/write",
        "privilege_escalation", ["privilege_escalation"], ["T1098.003"],
        "critical", 88, "azure_sql",
        "SQL Server Active Directory administrator added or changed — full admin access to all databases granted."),
    "sql_firewall_rule_write": (
        "sql", "activity_log", "Microsoft.Sql/servers/firewallRules/write",
        "initial_access", ["initial_access"], ["T1190"],
        "high", 72, "azure_sql",
        "SQL Server firewall rule created or modified — database network access policy changed."),
    "sql_vulnerability_assessment_delete": (
        "sql", "activity_log", "Microsoft.Sql/servers/vulnerabilityAssessments/delete",
        "defense_evasion", ["defense_evasion"], ["T1562.001"],
        "high", 75, "azure_sql",
        "SQL vulnerability assessment deleted — automated security scanning for database disabled."),
    "sql_threat_protection_write": (
        "sql", "activity_log", "Microsoft.Sql/servers/advancedThreatProtectionSettings/write",
        "defense_evasion", ["defense_evasion"], ["T1562.001"],
        "high", 72, "azure_sql",
        "SQL Advanced Threat Protection settings changed — anomaly detection for database modified."),
    "sql_database_delete": (
        "sql", "activity_log", "Microsoft.Sql/servers/databases/delete",
        "data_destruction", ["impact"], ["T1485"],
        "critical", 88, "azure_sql",
        "SQL database deleted — all database data permanently destroyed."),
    "sql_server_delete": (
        "sql", "activity_log", "Microsoft.Sql/servers/delete",
        "data_destruction", ["impact"], ["T1485"],
        "critical", 92, "azure_sql",
        "SQL Server deleted — all databases and data permanently destroyed."),
    "sql_tde_write": (
        "sql", "activity_log", "Microsoft.Sql/servers/databases/transparentDataEncryption/write",
        "defense_evasion", ["defense_evasion"], ["T1600"],
        "high", 70, "azure_sql",
        "SQL Transparent Data Encryption settings changed — database encryption configuration modified."),
    "sql_server_write": (
        "sql", "activity_log", "Microsoft.Sql/servers/write",
        "initial_access", ["initial_access"], ["T1190"],
        "medium", 50, "azure_sql",
        "SQL Server created or modified — server configuration including AD authentication changed."),

    # ═══════════════════════════════════════════════════════════════════════
    # SECSVC — Security Center / Defender for Cloud (Activity Log)
    # ═══════════════════════════════════════════════════════════════════════
    "security_contact_delete": (
        "secsvc", "activity_log", "Microsoft.Security/securityContacts/delete",
        "defense_evasion", ["defense_evasion"], ["T1562.001"],
        "high", 75, "azure_defender",
        "Security contact deleted — email notification for security alerts removed."),
    "defender_plan_write": (
        "secsvc", "activity_log", "Microsoft.Security/pricings/write",
        "defense_evasion", ["defense_evasion"], ["T1562.001"],
        "high", 78, "azure_defender",
        "Defender for Cloud plan modified — threat detection coverage for resource type changed."),
    "security_automation_delete": (
        "secsvc", "activity_log", "Microsoft.Security/automations/delete",
        "defense_evasion", ["defense_evasion"], ["T1562.001"],
        "high", 75, "azure_defender",
        "Security automation deleted — automated response to security alerts removed."),
    "security_alert_dismiss": (
        "secsvc", "activity_log", "Microsoft.Security/locations/alerts/dismiss/action",
        "defense_evasion", ["defense_evasion"], ["T1562.001"],
        "high", 72, "azure_defender",
        "Defender for Cloud alert dismissed — security alert suppressed without investigation."),
    "security_policy_write": (
        "secsvc", "activity_log", "Microsoft.Security/policies/write",
        "defense_evasion", ["defense_evasion"], ["T1562.001"],
        "high", 70, "azure_defender",
        "Security policy modified — compliance requirements or recommendation enforcement changed."),
    "workspace_settings_delete": (
        "secsvc", "activity_log", "Microsoft.Security/workspaceSettings/delete",
        "defense_evasion", ["defense_evasion"], ["T1562.008"],
        "high", 72, "azure_defender",
        "Security Center workspace settings deleted — Log Analytics integration for Defender removed."),
    "just_in_time_policy_write": (
        "secsvc", "activity_log", "Microsoft.Security/locations/jitNetworkAccessPolicies/write",
        "initial_access", ["initial_access"], ["T1133"],
        "high", 75, "azure_defender",
        "Just-In-Time VM access policy modified — controlled management port access policy changed."),
    "jit_access_initiate": (
        "secsvc", "activity_log", "Microsoft.Security/locations/jitNetworkAccessPolicies/initiate/action",
        "initial_access", ["initial_access"], ["T1133"],
        "medium", 55, "azure_defender",
        "Just-In-Time VM access request initiated — temporary RDP/SSH port access requested."),
    "regulatory_compliance_assess": (
        "secsvc", "activity_log", "Microsoft.Security/complianceResults/delete",
        "defense_evasion", ["defense_evasion"], ["T1562.001"],
        "medium", 50, "azure_defender",
        "Compliance assessment result deleted — security posture record removed."),

    # ═══════════════════════════════════════════════════════════════════════
    # PAAS — App Service, Functions, Logic Apps, API Management
    # ═══════════════════════════════════════════════════════════════════════
    "app_service_config_write": (
        "paas", "activity_log", "Microsoft.Web/sites/config/write",
        "persistence", ["persistence"], ["T1546"],
        "high", 72, "azure_app_service",
        "App Service configuration modified — app settings, connection strings, or auth config changed."),
    "app_publish_xml": (
        "paas", "activity_log", "Microsoft.Web/sites/publishxml/action",
        "credential_access", ["credential_access"], ["T1552.001"],
        "high", 80, "azure_app_service",
        "App Service publish credentials retrieved — FTP/WebDeploy credentials accessed."),
    "app_function_key_write": (
        "paas", "activity_log", "Microsoft.Web/sites/functions/keys/write",
        "credential_access", ["credential_access"], ["T1552.001"],
        "high", 75, "azure_function",
        "Azure Function key created or modified — invocation credential for function changed."),
    "logic_app_write": (
        "paas", "activity_log", "Microsoft.Logic/workflows/write",
        "persistence", ["persistence", "execution"], ["T1546", "T1651"],
        "medium", 55, "azure_logic_app",
        "Logic App workflow created or modified — automated business process or integration flow changed."),
    "logic_app_delete": (
        "paas", "activity_log", "Microsoft.Logic/workflows/delete",
        "impact", ["impact"], ["T1489"],
        "high", 70, "azure_logic_app",
        "Logic App deleted — automated workflow and its integrations destroyed."),
    "logic_app_run": (
        "paas", "activity_log", "Microsoft.Logic/workflows/triggers/run/action",
        "execution", ["execution"], ["T1651"],
        "medium", 50, "azure_logic_app",
        "Logic App trigger executed — workflow run initiated via management plane."),
    "apim_write": (
        "paas", "activity_log", "Microsoft.ApiManagement/service/write",
        "defense_evasion", ["defense_evasion"], ["T1484.001"],
        "medium", 55, "azure_apim",
        "API Management service modified — API gateway policies or backend configuration changed."),
    "function_app_write": (
        "paas", "activity_log", "Microsoft.Web/sites/write",
        "persistence", ["persistence"], ["T1546"],
        "medium", 50, "azure_function",
        "Azure Function App created or modified — serverless application configuration changed."),
    "app_service_delete": (
        "paas", "activity_log", "Microsoft.Web/sites/delete",
        "impact", ["impact"], ["T1485"],
        "high", 70, "azure_app_service",
        "App Service deleted — web application and all deployed code destroyed."),
    "automation_runbook_write": (
        "paas", "activity_log", "Microsoft.Automation/automationAccounts/runbooks/write",
        "execution", ["execution", "persistence"], ["T1651", "T1546"],
        "high", 75, "azure_automation",
        "Automation runbook created or modified — scheduled or event-driven script added."),
    "automation_runbook_publish": (
        "paas", "activity_log", "Microsoft.Automation/automationAccounts/runbooks/publish/action",
        "execution", ["execution"], ["T1651"],
        "high", 72, "azure_automation",
        "Automation runbook published — runbook activated and available for execution."),

    # ═══════════════════════════════════════════════════════════════════════
    # DATASEC — Data Lake, Synapse, Purview, Cosmos
    # ═══════════════════════════════════════════════════════════════════════
    "data_lake_store_delete": (
        "datasec", "activity_log", "Microsoft.DataLakeStore/accounts/delete",
        "data_destruction", ["impact"], ["T1485"],
        "critical", 90, "azure_data_lake",
        "Data Lake Store account deleted — all analytics data permanently destroyed."),
    "synapse_workspace_write": (
        "datasec", "activity_log", "Microsoft.Synapse/workspaces/write",
        "initial_access", ["initial_access"], ["T1190"],
        "medium", 50, "azure_synapse",
        "Synapse Analytics workspace created or modified — analytics platform configuration changed."),
    "synapse_firewall_write": (
        "datasec", "activity_log", "Microsoft.Synapse/workspaces/firewallRules/write",
        "initial_access", ["initial_access"], ["T1190"],
        "high", 70, "azure_synapse",
        "Synapse workspace firewall rule modified — network access policy to analytics platform changed."),
    "purview_account_write": (
        "datasec", "activity_log", "Microsoft.Purview/accounts/write",
        "defense_evasion", ["defense_evasion"], ["T1484.001"],
        "medium", 50, "azure_purview",
        "Purview account created or modified — data governance configuration changed."),
    "cosmos_db_delete": (
        "datasec", "activity_log", "Microsoft.DocumentDB/databaseAccounts/delete",
        "data_destruction", ["impact"], ["T1485"],
        "critical", 92, "azure_cosmos_db",
        "Cosmos DB account deleted — all NoSQL data permanently destroyed."),
    "cosmos_db_key_list": (
        "datasec", "activity_log", "Microsoft.DocumentDB/databaseAccounts/listKeys/action",
        "credential_access", ["credential_access"], ["T1552.001"],
        "critical", 88, "azure_cosmos_db",
        "Cosmos DB account keys listed — master read/write keys to database retrieved."),
    "redis_key_list": (
        "datasec", "activity_log", "Microsoft.Cache/redis/listKeys/action",
        "credential_access", ["credential_access"], ["T1552.001"],
        "high", 75, "azure_redis",
        "Azure Cache for Redis keys listed — full access keys to cache retrieved."),
    "service_bus_key_list": (
        "datasec", "activity_log", "Microsoft.ServiceBus/namespaces/authorizationRules/listkeys/action",
        "credential_access", ["credential_access"], ["T1552.001"],
        "high", 72, "azure_service_bus",
        "Service Bus authorization rule keys listed — messaging access keys retrieved."),

    # ═══════════════════════════════════════════════════════════════════════
    # DEVOPS — ARM Deployments, Azure DevOps, Resource Groups
    # ═══════════════════════════════════════════════════════════════════════
    "arm_deployment_write": (
        "devops", "activity_log", "Microsoft.Resources/deployments/write",
        "execution", ["execution"], ["T1651"],
        "medium", 55, "azure_resource",
        "ARM template deployment executed — infrastructure-as-code deployment applied to subscription."),
    "arm_deployment_delete": (
        "devops", "activity_log", "Microsoft.Resources/deployments/delete",
        "defense_evasion", ["defense_evasion"], ["T1070"],
        "medium", 45, "azure_resource",
        "ARM deployment history deleted — infrastructure deployment record removed."),
    "resource_group_delete": (
        "devops", "activity_log", "Microsoft.Resources/subscriptions/resourceGroups/delete",
        "data_destruction", ["impact"], ["T1485"],
        "critical", 92, "azure_resource",
        "Resource group deleted — all resources contained in group permanently destroyed."),
    "subscription_policy_write": (
        "devops", "activity_log", "Microsoft.Resources/subscriptions/write",
        "defense_evasion", ["defense_evasion"], ["T1484.001"],
        "high", 70, "azure_subscription",
        "Subscription configuration modified — billing, management group, or metadata changed."),
    "devops_pipeline_write": (
        "devops", "activity_log", "Microsoft.DevOps/pipelines/write",
        "execution", ["execution", "persistence"], ["T1651", "T1546"],
        "high", 75, "azure_devops",
        "Azure DevOps pipeline created or modified — CI/CD workflow changed, potential supply chain risk."),
    "acr_push": (
        "devops", "activity_log", "Microsoft.ContainerRegistry/registries/push/write",
        "persistence", ["persistence"], ["T1525"],
        "high", 75, "azure_container_registry",
        "Container image pushed to Azure Container Registry — new or modified image available for deployment."),
    "acr_delete": (
        "devops", "activity_log", "Microsoft.ContainerRegistry/registries/delete",
        "data_destruction", ["impact"], ["T1485"],
        "high", 78, "azure_container_registry",
        "Container registry deleted — all container images permanently destroyed."),
    "acr_credential_list": (
        "devops", "activity_log", "Microsoft.ContainerRegistry/registries/listCredentials/action",
        "credential_access", ["credential_access"], ["T1552.001"],
        "high", 78, "azure_container_registry",
        "Container registry admin credentials listed — registry username and passwords retrieved."),
    "managed_environment_write": (
        "devops", "activity_log", "Microsoft.App/managedEnvironments/write",
        "persistence", ["persistence"], ["T1610"],
        "medium", 50, "azure_container_apps",
        "Container Apps environment created or modified — serverless container runtime configuration changed."),

    # ═══════════════════════════════════════════════════════════════════════
    # THREAT — High-value L1 standalone threat operations
    # ═══════════════════════════════════════════════════════════════════════
    "subscription_transfer": (
        "threat", "activity_log", "Microsoft.Subscription/cancel/action",
        "impact", ["impact"], ["T1531"],
        "critical", 95, "azure_subscription",
        "Azure subscription cancelled — all resources across subscription scheduled for deletion."),
    "tenant_transfer": (
        "threat", "activity_log", "Microsoft.Resources/subscriptions/move/action",
        "defense_evasion", ["defense_evasion"], ["T1484.002"],
        "critical", 95, "azure_subscription",
        "Subscription moved to different tenant — all resources transferred outside of current organization control."),
    "management_group_write": (
        "threat", "activity_log", "Microsoft.Management/managementGroups/write",
        "privilege_escalation", ["privilege_escalation"], ["T1484.001"],
        "high", 80, "azure_management_group",
        "Management group created or modified — top-level governance structure for subscriptions changed."),
    "management_group_subscription_write": (
        "threat", "activity_log", "Microsoft.Management/managementGroups/subscriptions/write",
        "privilege_escalation", ["privilege_escalation"], ["T1484.001"],
        "high", 78, "azure_management_group",
        "Subscription added to management group — subscription brought under management group policy scope."),
    "defender_for_cloud_disable": (
        "threat", "activity_log", "Microsoft.Security/pricings/delete",
        "defense_evasion", ["defense_evasion"], ["T1562.001"],
        "critical", 92, "azure_defender",
        "Defender for Cloud plan deleted — threat detection for resource type completely disabled."),
    "classic_admin_write": (
        "threat", "activity_log", "Microsoft.Authorization/classicAdministrators/write",
        "privilege_escalation", ["privilege_escalation"], ["T1098.003"],
        "critical", 88, "azure_rbac",
        "Classic administrator added — legacy admin role grants broad subscription-wide permissions."),
    "key_vault_network_rule_write": (
        "threat", "activity_log", "Microsoft.KeyVault/vaults/networkRuleSet/write",
        "defense_evasion", ["defense_evasion"], ["T1562.007"],
        "high", 72, "azure_key_vault",
        "Key Vault network rules modified — firewall or virtual network access rules for vault changed."),
    "storage_cors_write": (
        "threat", "activity_log", "Microsoft.Storage/storageAccounts/blobServices/write",
        "initial_access", ["initial_access"], ["T1190"],
        "high", 72, "azure_storage",
        "Storage CORS policy modified — cross-origin resource sharing rules changed, may allow untrusted domains."),
    "mfa_reset_by_admin": (
        "threat", "entra_audit", "microsoft.directory/users/strongAuthenticationPhoneAppDetail/update",
        "credential_access", ["credential_access"], ["T1556.006"],
        "critical", 88, "entra_user",
        "Admin reset user MFA authenticator app — user's second factor cleared, account may be accessible with only password."),
    "global_admin_role_add": (
        "threat", "entra_audit", "microsoft.directory/directoryRoles/members/add",
        "privilege_escalation", ["privilege_escalation"], ["T1098.003"],
        "critical", 95, "entra_user",
        "Global Administrator role assigned — tenant-wide unrestricted access granted to principal."),

}

# ─────────────────────────────────────────────────────────────────────────────
# L2 Correlation rules (log_correlation check_type)
# Key: rule_slug  Value: (sequence_rules, threat_cat, tactics, techniques,
#                         severity, risk_score, resource, title, description)
# ─────────────────────────────────────────────────────────────────────────────

_CORRELATION_MAP: Dict[str, Tuple] = {
    "privilege_escalation_chain": (
        ["azure.authorization.activity_log.role_assignment_write",
         "azure.identity.entra_audit.conditional_access_delete",
         "azure.iam.entra_audit.user_mfa_update"],
        "privilege_escalation", ["privilege_escalation"], ["T1548", "T1098.003"],
        "critical", 95, "multi_resource",
        "Privilege Escalation Chain",
        "Correlated privilege escalation: RBAC role assigned + conditional access deleted + MFA disabled by same principal within 30 minutes."),
    "credential_exfil_chain": (
        ["azure.keyvault.activity_log.keyvault_secret_read",
         "azure.storage.activity_log.storage_list_keys",
         "azure.sql.activity_log.sql_admin_write"],
        "data_exfiltration", ["collection", "exfiltration"], ["T1552.001", "T1567"],
        "critical", 95, "multi_resource",
        "Credential Exfiltration Chain",
        "Credential mass-harvest: Key Vault secrets read + Storage keys listed + SQL admin added by same principal."),
    "defense_evasion_chain": (
        ["azure.monitor.activity_log.diagnostic_setting_delete",
         "azure.monitor.activity_log.activity_log_alert_delete",
         "azure.secsvc.activity_log.defender_for_cloud_disable"],
        "defense_evasion", ["defense_evasion"], ["T1562.008", "T1562.001"],
        "critical", 95, "multi_resource",
        "Defense Evasion Chain",
        "Logging and detection disabled: Diagnostic settings deleted + activity log alerts deleted + Defender plan disabled."),
    "data_destruction_chain": (
        ["azure.storage.activity_log.storage_account_delete",
         "azure.sql.activity_log.sql_database_delete",
         "azure.keyvault.activity_log.keyvault_purge"],
        "data_destruction", ["impact"], ["T1485"],
        "critical", 98, "multi_resource",
        "Data Destruction Chain",
        "Ransomware-like destruction: Storage account deleted + SQL database deleted + Key Vault purged by same principal within 30 minutes."),
    "identity_takeover_chain": (
        ["azure.iam.entra_audit.app_credential_add",
         "azure.iam.entra_audit.admin_consent_grant",
         "azure.iam.entra_audit.domain_federation_update"],
        "initial_access", ["initial_access", "persistence"], ["T1556.007", "T1550.001"],
        "critical", 97, "multi_resource",
        "Identity Takeover Chain",
        "Tenant identity compromise: Application credentials added + admin consent granted + domain federation updated."),
    "lateral_movement_chain": (
        ["azure.network.activity_log.vnet_peering_write",
         "azure.authorization.activity_log.role_assignment_write",
         "azure.container.activity_log.aks_admin_credential_list"],
        "lateral_movement", ["lateral_movement"], ["T1021.007", "T1098.003"],
        "critical", 90, "multi_resource",
        "Lateral Movement Chain",
        "Cross-resource lateral movement: VNet peered + RBAC role assigned + AKS admin credentials retrieved."),
    "supply_chain_attack": (
        ["azure.devops.activity_log.devops_pipeline_write",
         "azure.devops.activity_log.acr_push",
         "azure.container.activity_log.aks_cluster_write"],
        "execution", ["execution", "persistence"], ["T1651", "T1525"],
        "critical", 92, "multi_resource",
        "Supply Chain Attack Chain",
        "Pipeline-to-cluster supply chain: CI/CD pipeline modified + container image pushed + AKS cluster updated."),
}

# ─────────────────────────────────────────────────────────────────────────────
# Service → resource default + title prefix
# ─────────────────────────────────────────────────────────────────────────────

_SERVICE_TITLE = {
    "iam":           "IAM",
    "authorization": "Authorization",
    "identity":      "Identity",
    "keyvault":      "Key Vault",
    "compute":       "Compute",
    "storage":       "Storage",
    "container":     "Container",
    "network":       "Network",
    "monitor":       "Monitor",
    "sql":           "SQL",
    "secsvc":        "Security",
    "paas":          "PaaS",
    "datasec":       "DataSec",
    "devops":        "DevOps",
    "threat":        "Threat",
    "ciem":          "CIEM",
}

_UPPER_WORDS = {"iam", "sql", "rbac", "mfa", "arm", "dns", "vpn", "cors",
                "apim", "acr", "sas", "tde", "jit", "pim"}


def _pretty_op(slug: str) -> str:
    words = slug.split("_")
    return " ".join(w.upper() if w in _UPPER_WORDS else w.capitalize() for w in words)


def _make_l1_yaml(op_slug: str, meta: Tuple) -> dict:
    (service, log_src, operation, threat_cat, tactics, techniques,
     severity, risk_score, resource, description) = meta

    op_pretty   = _pretty_op(op_slug)
    svc_label   = _SERVICE_TITLE.get(service, service.upper())
    title       = f"{svc_label}: {op_pretty}"
    rule_id     = f"azure.{service}.{log_src}.{op_slug}"

    return {
        "rule_id":          rule_id,
        "service":          service,
        "provider":         "azure",
        "check_type":       "log",
        "severity":         severity,
        "title":            title,
        "description":      description,
        "threat_category":  threat_cat,
        "mitre_tactics":    tactics,
        "mitre_techniques": techniques,
        "risk_score":       risk_score,
        "resource":         resource,
        "source":           "default",
        "is_active":        True,
        "check_config": {
            "conditions": {
                "all": [
                    {"op": "equals", "field": "operation", "value": operation}
                ]
            },
            "log_source_type": log_src,
        },
        "version": "1.0",
    }


def _make_correlation_yaml(slug: str, meta: Tuple) -> dict:
    (sequence, threat_cat, tactics, techniques,
     severity, risk_score, resource, title, description) = meta

    rule_id = f"azure.ciem.correlation.{slug}"

    return {
        "rule_id":          rule_id,
        "service":          "ciem",
        "provider":         "azure",
        "check_type":       "log_correlation",
        "severity":         severity,
        "title":            f"Correlation: {title}",
        "description":      description,
        "threat_category":  threat_cat,
        "mitre_tactics":    tactics,
        "mitre_techniques": techniques,
        "risk_score":       risk_score,
        "resource":         resource,
        "source":           "default",
        "is_active":        True,
        "check_config": {
            "type":                   "correlation",
            "for_each":               "log_events",
            "match_by":               "actor.principal",
            "sequence":               [{"rule_id": r} for r in sequence],
            "min_events":             len(sequence),
            "time_window_minutes":    30,
            "log_source_type":        "activity_log",
        },
        "version": "1.0",
    }


class _OrderedDumper(yaml.Dumper):
    pass

def _str_representer(dumper, data):
    if "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)

_OrderedDumper.add_representer(str, _str_representer)


def _write_yaml(path: Path, data: dict) -> None:
    # Fixed key order
    order = ["rule_id", "service", "provider", "check_type", "severity",
             "title", "description", "threat_category", "mitre_tactics",
             "mitre_techniques", "risk_score", "resource", "source",
             "is_active", "check_config", "version"]
    ordered = {k: data[k] for k in order if k in data}
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(ordered, f, Dumper=_OrderedDumper,
                  default_flow_style=False, allow_unicode=True,
                  sort_keys=False, width=120)


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description="Generate Azure CIEM rule YAMLs")
    p.add_argument("--dry-run",  action="store_true")
    p.add_argument("--service",  default=None, help="Generate only this service dir")
    args = p.parse_args()

    services_seen: Dict[str, int] = {}

    # L1 rules
    for op_slug, meta in _OP_MAP.items():
        service = meta[0]
        if args.service and service != args.service:
            continue
        log_src = meta[1]
        rule_id = f"azure.{service}.{log_src}.{op_slug}"
        out_path = CATALOG_DIR / service / f"{rule_id}.yaml"
        services_seen[service] = services_seen.get(service, 0) + 1
        if not args.dry_run:
            data = _make_l1_yaml(op_slug, meta)
            _write_yaml(out_path, data)

    # L2 correlation rules
    if not args.service or args.service == "ciem":
        for slug, meta in _CORRELATION_MAP.items():
            rule_id  = f"azure.ciem.correlation.{slug}"
            out_path = CATALOG_DIR / "ciem" / f"{rule_id}.yaml"
            services_seen["ciem"] = services_seen.get("ciem", 0) + 1
            if not args.dry_run:
                data = _make_correlation_yaml(slug, meta)
                _write_yaml(out_path, data)

    total = sum(services_seen.values())
    print(f"{'[DRY RUN] ' if args.dry_run else ''}Generated {total} Azure CIEM rules:")
    for svc in sorted(services_seen):
        print(f"  {svc:15s}  {services_seen[svc]:3d} rules")
    print(f"  {'TOTAL':15s}  {total:3d}")


if __name__ == "__main__":
    main()
