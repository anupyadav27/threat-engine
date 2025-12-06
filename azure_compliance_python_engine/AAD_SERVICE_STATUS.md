# AAD Service Validation Status

## Current Status: ⏳ IN PROGRESS

**Service:** aad (Azure Active Directory / Entra ID)  
**Checks:** 72  
**Discoveries:** 5  
**API Type:** Microsoft Graph API  
**Scope:** Tenant (but configured as subscription in YAML)

## Issues Identified

1. **Graph API Path Conversion Required**
   - Current YAML uses dot notation: `service_principals.list`
   - Needs Graph API REST paths: `/v1.0/servicePrincipals`
   - All 72 checks need path conversion

2. **Response Format**
   - Graph API returns `{"value": [...]}` format
   - Need to extract from `value` array
   - Pagination handling required (`@odata.nextLink`)

3. **Authentication**
   - Requires Graph API scope: `https://graph.microsoft.com/.default`
   - Different from ARM API authentication

4. **Scope Mismatch**
   - YAML says `scope: subscription`
   - Graph API is tenant-scoped
   - Should be `scope: tenant`

## Discovery Actions Fixed

✅ Updated discovery actions to use Graph API paths:
- `/v1.0/servicePrincipals` - for service principals
- `/v1.0/applications` - for applications
- `/v1.0/users` - for users
- `/v1.0/organization` - for organization/tenant config

## Next Steps

1. **Fix Scope**: Change `scope: subscription` → `scope: tenant`
2. **Test Discovery**: Verify Graph API calls work
3. **Convert Check Actions**: Convert all 72 check actions to Graph API paths
4. **Handle Pagination**: Add pagination support for Graph API responses
5. **Fix Field Paths**: Update field extraction paths for Graph API response format

## Recommendation

Given the complexity (72 checks, Graph API conversion), consider:
- Option A: Continue fixing aad service (will take significant time)
- Option B: Mark as "needs Graph API conversion" and validate simpler ARM services first
- Option C: Create helper script to auto-convert Graph API actions

## Graph API Path Reference

Common endpoints needed:
- `/v1.0/servicePrincipals`
- `/v1.0/servicePrincipals/{id}/passwordCredentials`
- `/v1.0/applications`
- `/v1.0/users`
- `/v1.0/users/{id}/authentication/passwordMethods`
- `/v1.0/organization`
- `/v1.0/policies/authorizationPolicy`
- `/v1.0/policies/authenticationMethodsPolicy`
- `/v1.0/directoryRoles`
- `/v1.0/groups`
- `/beta/identity/conditionalAccess/policies`

See: https://learn.microsoft.com/en-us/graph/api/overview

