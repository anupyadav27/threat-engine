# IAM - Resource Inventory Report

**Generated:** 2026-01-20T19:24:28.811962

**Root Operations:** GetAccountAuthorizationDetails, GetAccountPasswordPolicy, GetAccountSummary, GetCredentialReport, GetLoginProfile, GetOutboundWebIdentityFederationInfo, GetUser, ListAccessKeys, ListAccountAliases, ListDelegationRequests, ListGroups, ListInstanceProfiles, ListMFADevices, ListOpenIDConnectProviders, ListPolicies, ListRoles, ListSAMLProviders, ListSSHPublicKeys, ListServerCertificates, ListServiceSpecificCredentials, ListSigningCertificates, ListUsers, ListVirtualMFADevices

---

## Primary Resource

### attached_policy_policy

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `iam.attached_policy_policy_arn`

#### ❌ Cannot be produced from root operations

#### ⚠️  Requires DEPENDENT operations:

- `ListAttachedGroupPolicies`
- `ListAttachedRolePolicies`
- `ListAttachedUserPolicies`

---

### delegation_request_role_permission_restrictions

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `iam.delegation_request_role_permission_restriction_arns`

#### ✅ Can be produced from ROOT operations:

- `ListDelegationRequests`

---

### role

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `iam.role_arn`

#### ❌ Cannot be produced from root operations

#### ⚠️  Requires DEPENDENT operations:

- `GetRole`

---

### user_detail_list

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `iam.user_detail_list_arn`

#### ✅ Can be produced from ROOT operations:

- `GetAccountAuthorizationDetails`
- `GetUser`
- `ListGroups`
- `ListInstanceProfiles`
- `ListOpenIDConnectProviders`
- `ListPolicies`
- `ListRoles`
- `ListSAMLProviders`
- `ListServerCertificates`
- `ListUsers`

---

## Ephemeral

### delegation_request_delegation_request

- **Status:** ❌ Not in inventory 
- **Classification:** EPHEMERAL
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `ListDelegationRequests`

---

### policy_default_version

- **Status:** ❌ Not in inventory 
- **Classification:** EPHEMERAL
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `ListPolicies`

---

### policy_version_version

- **Status:** ❌ Not in inventory 
- **Classification:** EPHEMERAL
- **Has ARN:** No

#### ❌ Cannot be produced from root operations

#### ⚠️  Requires DEPENDENT operations:

- `GetPolicyVersion`
- `ListPolicyVersions`

---

## Sub Resource

### access_key_metadata_access_key

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `ListAccessKeys`

---

### certificat_certificate

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `ListSigningCertificates`

---

### delegation_request_approver

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `ListDelegationRequests`

---

### delegation_request_owner

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `ListDelegationRequests`

---

### delegation_request_owner_account

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `ListDelegationRequests`

---

### delegation_request_requestor

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `ListDelegationRequests`

---

### group_group

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `ListGroups`

---

### instance_profil_instance_profile

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `ListInstanceProfiles`

---

### issuerentifier

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `GetOutboundWebIdentityFederationInfo`

---

### policy_policy

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `ListPolicies`

---

### private_key_list_key

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ❌ Cannot be produced from root operations

#### ⚠️  Requires DEPENDENT operations:

- `GetSAMLProvider`

---

### rol_role

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `ListRoles`

---

### server_certificate_metadata_list_server_certificate

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `ListServerCertificates`

---

### service_specific_credential_service

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `ListServiceSpecificCredentials`

---

### service_specific_credential_service_specific_credential

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `ListServiceSpecificCredentials`

---

### service_specific_credential_service_user

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `ListServiceSpecificCredentials`

---

### ssh_public_key_ssh_public_key

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `ListSSHPublicKeys`

---

### user_detail_list_user

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `GetAccountAuthorizationDetails`
- `GetLoginProfile`
- `GetUser`
- `ListAccessKeys`
- `ListMFADevices`
- `ListSSHPublicKeys`
- `ListServiceSpecificCredentials`
- `ListSigningCertificates`
- `ListUsers`

---
