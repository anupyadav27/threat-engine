# IAM - Minimal Operations List

**Generated:** 2026-01-20T19:31:01.845334

**Total Fields:** 133
**Total Operations Needed:** 38
**Independent Operations:** 20
**Dependent Operations:** 18
**Coverage:** 69.4%

---

## ✅ Independent Operations (Root Operations)

These operations can be called without any dependencies:

### 1. ListDelegationRequests

- **Type:** Independent (Root)
- **Entities Covered:** 20
- **Covers:** iam.delegation_request_approver_id, iam.delegation_request_delegation_request_id, iam.delegation_request_description, iam.delegation_request_notes, iam.delegation_request_only_send_by_owner...

### 2. ListPolicies

- **Type:** Independent (Root)
- **Entities Covered:** 12
- **Covers:** iam.group, iam.policies_granting_service_acces_policies, iam.policy_attachment_count, iam.policy_default_version_id, iam.policy_is_attachable...

### 3. ListRoles

- **Type:** Independent (Root)
- **Entities Covered:** 7
- **Covers:** iam.instance_profil_roles, iam.rol_assume_role_policy_document, iam.rol_max_session_duration, iam.rol_role_id, iam.rol_role_last_used...

### 4. GetAccountAuthorizationDetails

- **Type:** Independent (Root)
- **Entities Covered:** 5
- **Covers:** iam.user_detail_list_attached_managed_policies, iam.user_detail_list_group_list, iam.user_detail_list_user_id, iam.user_detail_list_user_name, iam.user_detail_list_user_policy_list

### 5. ListUsers

- **Type:** Independent (Root)
- **Entities Covered:** 2
- **Covers:** iam.user_password_last_used, iam.users

### 6. GetAccountPasswordPolicy

- **Type:** Independent (Root)
- **Entities Covered:** 11
- **Covers:** iam.password_policy, iam.password_policy_allow_users_to_change_password, iam.password_policy_expire_passwords, iam.password_policy_hard_expiry, iam.password_policy_max_password_age...

### 7. ListServiceSpecificCredentials

- **Type:** Independent (Root)
- **Entities Covered:** 6
- **Covers:** iam.access_key_metadata_status, iam.service_specific_credential_expiration_date, iam.service_specific_credential_service_credential_alias, iam.service_specific_credential_service_name, iam.service_specific_credential_service_specific_credential_id...

### 8. GetUser

- **Type:** Independent (Root)
- **Entities Covered:** 1
- **Covers:** iam.virtual_mfa_devic_user

### 9. ListInstanceProfiles

- **Type:** Independent (Root)
- **Entities Covered:** 2
- **Covers:** iam.instance_profil_instance_profile_id, iam.instance_profil_instance_profile_name

### 10. ListServerCertificates

- **Type:** Independent (Root)
- **Entities Covered:** 4
- **Covers:** iam.server_certificate_metadata_list_expiration, iam.server_certificate_metadata_list_server_certificate_id, iam.server_certificate_metadata_list_server_certificate_name, iam.ssh_public_key_upload_date

### 11. ListVirtualMFADevices

- **Type:** Independent (Root)
- **Entities Covered:** 4
- **Covers:** iam.mfa_devic_enable_date, iam.mfa_devic_serial_number, iam.virtual_mfa_devic_base32_string_seed, iam.virtual_mfa_devic_qr_code_png

### 12. ListGroups

- **Type:** Independent (Root)
- **Entities Covered:** 2
- **Covers:** iam.group_group_id, iam.group_group_name

### 13. ListSigningCertificates

- **Type:** Independent (Root)
- **Entities Covered:** 2
- **Covers:** iam.certificat_certificate_body, iam.certificat_certificate_id

### 14. ListAccessKeys

- **Type:** Independent (Root)
- **Entities Covered:** 1
- **Covers:** iam.access_key_metadata_access_key_id

### 15. ListSSHPublicKeys

- **Type:** Independent (Root)
- **Entities Covered:** 1
- **Covers:** iam.ssh_public_key_ssh_public_key_id

### 16. GetLoginProfile

- **Type:** Independent (Root)
- **Entities Covered:** 2
- **Covers:** iam.login_profile, iam.login_profile_password_reset_required

### 17. ListSAMLProviders

- **Type:** Independent (Root)
- **Entities Covered:** 1
- **Covers:** iam.saml_provider_list_valid_until

### 18. GetCredentialReport

- **Type:** Independent (Root)
- **Entities Covered:** 1
- **Covers:** iam.content

### 19. GetOutboundWebIdentityFederationInfo

- **Type:** Independent (Root)
- **Entities Covered:** 1
- **Covers:** iam.issuer_identifier

### 20. GetAccountSummary

- **Type:** Independent (Root)
- **Entities Covered:** 1
- **Covers:** iam.summary_map

## ⚠️  Dependent Operations

These operations require inputs from other operations:

### 1. GetOrganizationsAccessReport

- **Type:** Dependent
- **Entities Covered:** 6
- **Covers:** iam.access_detail_entity_path, iam.access_detail_error_details, iam.access_detail_last_authenticated_time, iam.access_detail_service_namespace, iam.access_detail_total_authenticated_entities...

### 2. GetServiceLastAccessedDetails

- **Type:** Dependent
- **Entities Covered:** 4
- **Covers:** iam.services_last_accessed_last_authenticated, iam.services_last_accessed_last_authenticated_entity, iam.services_last_accessed_last_authenticated_region, iam.services_last_accessed_tracked_actions_last_accessed

### 3. GetSSHPublicKey

- **Type:** Dependent
- **Entities Covered:** 3
- **Covers:** iam.ssh_public_key, iam.ssh_public_key_fingerprint, iam.ssh_public_key_ssh_public_key_body
- **Requires:** iam.ssh_public_key_ssh_public_key_id, iam.user_detail_list_user_name
- **Dependencies:** iam.ssh_public_key_ssh_public_key_id, iam.user_detail_list_user_name

### 4. GetSAMLProvider

- **Type:** Dependent
- **Entities Covered:** 3
- **Covers:** iam.private_key_list_key_id, iam.private_key_list_private_key_list, iam.private_key_list_timestamp

### 5. GetHumanReadableSummary

- **Type:** Dependent
- **Entities Covered:** 3
- **Covers:** iam.summary_content_locale, iam.summary_content_summary_content, iam.summary_content_summary_state

### 6. GetAccessKeyLastUsed

- **Type:** Dependent
- **Entities Covered:** 2
- **Covers:** iam.access_key_last_used, iam.access_key_last_used_last_used_date
- **Requires:** iam.access_key_metadata_access_key_id
- **Dependencies:** iam.access_key_metadata_access_key_id

### 7. ListRoleTags

- **Type:** Dependent
- **Entities Covered:** 2
- **Covers:** iam.tag_key, iam.tag_value
- **Requires:** iam.rol_role_name
- **Dependencies:** iam.rol_role_name

### 8. GetServerCertificate

- **Type:** Dependent
- **Entities Covered:** 2
- **Covers:** iam.server_certificate_certificate_chain, iam.server_certificate_server_certificate_metadata
- **Requires:** iam.server_certificate_metadata_list_server_certificate_name
- **Dependencies:** iam.server_certificate_metadata_list_server_certificate_name

### 9. GetServiceLinkedRoleDeletionStatus

- **Type:** Dependent
- **Entities Covered:** 2
- **Covers:** iam.reason_reason, iam.reason_role_usage_list

### 10. GetRole

- **Type:** Dependent
- **Entities Covered:** 1
- **Covers:** iam.role_arn
- **Requires:** iam.rol_role_name
- **Dependencies:** iam.rol_role_name

### 11. ListAttachedUserPolicies

- **Type:** Dependent
- **Entities Covered:** 1
- **Covers:** iam.attached_policy_policy_arn
- **Requires:** iam.user_detail_list_user_name
- **Dependencies:** iam.user_detail_list_user_name

### 12. ListPolicyVersions

- **Type:** Dependent
- **Entities Covered:** 3
- **Covers:** iam.policy_version_document, iam.policy_version_is_default_version, iam.policy_version_version_id
- **Requires:** iam.attached_policy_policy_arn
- **Dependencies:** iam.attached_policy_policy_arn

### 13. GetPolicy

- **Type:** Dependent
- **Entities Covered:** 1
- **Covers:** iam.policy
- **Requires:** iam.attached_policy_policy_arn
- **Dependencies:** iam.attached_policy_policy_arn

### 14. GetPolicyVersion

- **Type:** Dependent
- **Entities Covered:** 1
- **Covers:** iam.policy_version
- **Requires:** iam.attached_policy_policy_arn, iam.policy_version_version_id
- **Dependencies:** iam.attached_policy_policy_arn, iam.policy_version_version_id

### 15. GetMFADevice

- **Type:** Dependent
- **Entities Covered:** 1
- **Covers:** iam.user_name_certifications
- **Requires:** iam.mfa_devic_serial_number
- **Dependencies:** iam.mfa_devic_serial_number

### 16. GetServiceLastAccessedDetailsWithEntities

- **Type:** Dependent
- **Entities Covered:** 1
- **Covers:** iam.entity_details_list_entity_info
- **Requires:** iam.access_detail_service_namespace
- **Dependencies:** iam.access_detail_service_namespace

### 17. GetGroupPolicy

- **Type:** Dependent
- **Entities Covered:** 1
- **Covers:** iam.policy_document
- **Requires:** iam.group_group_name, iam.policy_policy_name
- **Dependencies:** iam.group_group_name, iam.policy_policy_name

### 18. GetOpenIDConnectProvider

- **Type:** Dependent
- **Entities Covered:** 1
- **Covers:** iam.client_id_list_url

---

## 📋 Complete Operations List (In Order)

### Independent Operations:
1. `ListDelegationRequests`
1. `ListPolicies`
1. `ListRoles`
1. `GetAccountAuthorizationDetails`
1. `ListUsers`
1. `GetAccountPasswordPolicy`
1. `ListServiceSpecificCredentials`
1. `GetUser`
1. `ListInstanceProfiles`
1. `ListServerCertificates`
1. `ListVirtualMFADevices`
1. `ListGroups`
1. `ListSigningCertificates`
1. `ListAccessKeys`
1. `ListSSHPublicKeys`
1. `GetLoginProfile`
1. `ListSAMLProviders`
1. `GetCredentialReport`
1. `GetOutboundWebIdentityFederationInfo`
1. `GetAccountSummary`

### Dependent Operations:
1. `GetOrganizationsAccessReport`
1. `GetServiceLastAccessedDetails`
1. `GetSSHPublicKey`
1. `GetSAMLProvider`
1. `GetHumanReadableSummary`
1. `GetAccessKeyLastUsed`
1. `ListRoleTags`
1. `GetServerCertificate`
1. `GetServiceLinkedRoleDeletionStatus`
1. `GetRole`
1. `ListAttachedUserPolicies`
1. `ListPolicyVersions`
1. `GetPolicy`
1. `GetPolicyVersion`
1. `GetMFADevice`
1. `GetServiceLastAccessedDetailsWithEntities`
1. `GetGroupPolicy`
1. `GetOpenIDConnectProvider`
