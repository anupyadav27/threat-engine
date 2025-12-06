# AAD Service - Graph API Conversion Status

## Progress: 6/72 Checks Converted (8.3%)

### ✅ Completed Conversions (6 checks)

1. `azure.aad.identity_service_principal.access_service_account_no_user_long_lived_keys`
   - `service_principals.by_service_principal_id.password_credentials.get`
   - → `/v1.0/servicePrincipals/{{id}}/passwordCredentials`

2. `azure.graph.api.365.group.creation.restriction.check`
   - `groups.get`
   - → `/v1.0/groups`

3. `azure.aad.user.access_user_console_password_present_only_if_required`
   - `users.by_user_id.authentication.password_methods.get`
   - → `/v1.0/users/{{id}}/authentication/passwordMethods`

4. `azure.aad.directory_tenant.access_password_policy_max_age_90_days_or_less`
   - `policies.authorization_policy.get`
   - → `/v1.0/policies/authorizationPolicy`

5. `azure.aad.app_registration.access_oidc_allowed_client_ids_audiences_restricted`
   - `applications.by_application_id.get`
   - → `/v1.0/applications/{{id}}`

6. `azure.aad.app_registration.access_oidc_issuer_https_and_matches_discovery`
   - `self` (uses resource from discovery)
   - Field paths updated to camelCase

### ⏳ Remaining: 66 checks

### Conversion Pattern Established

Graph API paths follow these patterns:
- List resources: `/v1.0/{resource}` (e.g., `/v1.0/servicePrincipals`)
- Get by ID: `/v1.0/{resource}/{id}` (e.g., `/v1.0/users/{id}`)
- Nested resources: `/v1.0/{resource}/{id}/{nested}` (e.g., `/v1.0/users/{id}/authentication/passwordMethods`)
- Policies: `/v1.0/policies/{policyType}` (e.g., `/v1.0/policies/authorizationPolicy`)

Field names converted to camelCase:
- `end_date_time` → `endDateTime`
- `redirect_uris` → `redirectUris`
- `identifier_uris` → `identifierUris`

### Next Steps

Continue converting remaining 66 checks systematically. Each check needs:
1. Action path conversion to Graph API REST endpoint
2. Field path updates (snake_case → camelCase)
3. Parameter template updates (if needed)
4. Testing after conversion

