# Role-Based Access Control (RBAC)

## Overview

Scope-based RBAC system matching the platform's resource hierarchy. Roles define **what level** you operate at; permissions define **what you can do** (read/write/execute). Admin/viewer distinction is handled by permission assignment, not separate roles.

---

## Resource Hierarchy

```
Platform (SaaS provider)
  +-- Organization (customer company, e.g. "Acme Corp")
        +-- Tenant (cloud provider: AWS, GCP, Azure...)
              +-- Account (individual cloud account: 123456789012)
```

Maps to database tables:
- `organizations` -- customer company
- `tenants` -- cloud provider workspace (FK to organizations)
- `accounts` -- individual cloud accounts (FK to tenants via providers)

---

## Roles (5 Scope-Based)

| Level | Role | Scope | Description |
|-------|------|-------|-------------|
| 1 | `platform_admin` | Platform | SaaS provider admin -- full access to all orgs, tenants, accounts |
| 2 | `org_admin` | Organization | Customer org admin -- manages all tenants + accounts under their org |
| 3 | `group_admin` | Selected | Manages a selected group of orgs, tenants, or accounts (flexible) |
| 4 | `tenant_admin` | Tenant | Manages one tenant (e.g., AWS) and all accounts under it |
| 5 | `account_admin` | Account | Manages one specific cloud account only |

### Read-Only Variants (No Separate Viewer Roles)

Instead of `org_admin` + `org_viewer`, assign permission subsets:
- `org_admin` with **all permissions** = full access (read + write + execute)
- `org_admin` with **read-only permissions** = viewer (effectively `org_viewer`)

Configured via the `role_permissions` table.

### `group_admin` -- Flexible Grouping

`group_admin` can be scoped to any combination via the `user_admin_scope` table:
- Multiple orgs: scope = [org_1, org_2]
- Multiple tenants: scope = [tenant_aws, tenant_gcp]
- Multiple accounts: scope = [account_1, account_2]
- Mixed: scope = [org_1, tenant_gcp_of_org_2]

### Legacy Role Mapping

| Old Role | New Role |
|----------|----------|
| `super_landlord` | `platform_admin` |
| `landlord` | `org_admin` |
| `customer_admin` | `org_admin` |
| `group_admin` | `group_admin` |
| `tenant` | `tenant_admin` |
| TenantUsers (no role) | `account_admin` |

---

## Permissions -- `{scope}:{feature}:{action}` Format

**Actions:** `read` (view), `write` (create/update/delete), `execute` (trigger operations)

### Platform Scope (14 permissions -- platform_admin only)

| Key | Description |
|-----|-------------|
| `platform:orgs:read` | View all organizations |
| `platform:orgs:write` | Create/update/delete organizations |
| `platform:users:read` | View all users across platform |
| `platform:users:write` | Create/update/delete any user |
| `platform:roles:read` | View role definitions |
| `platform:roles:write` | Modify role definitions |
| `platform:settings:read` | View platform settings |
| `platform:settings:write` | Modify platform settings |
| `platform:billing:read` | View billing for all orgs |
| `platform:billing:write` | Modify billing |
| `platform:audit:read` | View platform audit logs |
| `platform:engines:read` | View engine status |
| `platform:engines:write` | Manage engines |
| `platform:engines:execute` | Start/stop engines |

### Organization Scope (12 permissions)

| Key | Description |
|-----|-------------|
| `org:tenants:read` | View tenants in org |
| `org:tenants:write` | Create/update/delete tenants |
| `org:users:read` | View org users |
| `org:users:write` | Manage org users + invite |
| `org:settings:read` | View org settings |
| `org:settings:write` | Modify org settings |
| `org:billing:read` | View org billing |
| `org:audit:read` | View org audit logs |
| `org:dashboard:read` | View org-level dashboard |
| `org:reports:read` | View org-level reports |
| `org:reports:write` | Create/export reports |
| `org:policies:write` | Manage org-wide policies |

### Tenant Scope (14 permissions)

| Key | Description |
|-----|-------------|
| `tenant:accounts:read` | View accounts under tenant |
| `tenant:accounts:write` | Onboard/remove accounts |
| `tenant:users:read` | View tenant users |
| `tenant:users:write` | Manage tenant users |
| `tenant:settings:read` | View tenant settings |
| `tenant:settings:write` | Modify tenant settings |
| `tenant:scans:read` | View scan results |
| `tenant:scans:execute` | Trigger scans |
| `tenant:schedules:read` | View scan schedules |
| `tenant:schedules:write` | Create/modify schedules |
| `tenant:dashboard:read` | View tenant dashboard |
| `tenant:reports:read` | View tenant reports |
| `tenant:policies:read` | View tenant policies |
| `tenant:policies:write` | Manage tenant policies |

### Account Scope (16 permissions)

| Key | Description |
|-----|-------------|
| `account:dashboard:read` | View account dashboard |
| `account:assets:read` | View discovered assets |
| `account:threats:read` | View threat findings |
| `account:threats:write` | Update threat status/notes |
| `account:compliance:read` | View compliance results |
| `account:compliance:write` | Manage compliance rules |
| `account:inventory:read` | View resource inventory |
| `account:datasec:read` | View data security findings |
| `account:datasec:write` | Manage data security rules |
| `account:secops:read` | View SecOps scan results |
| `account:secops:execute` | Trigger SecOps scans |
| `account:scans:read` | View scan history |
| `account:scans:execute` | Trigger account scan |
| `account:settings:read` | View account settings |
| `account:settings:write` | Modify account config |
| `account:credentials:write` | Update cloud credentials |

### Default Permission Assignment

| Role | Permissions | Count |
|------|------------|-------|
| `platform_admin` | All scopes (platform + org + tenant + account) | 56 |
| `org_admin` | org:* + tenant:* + account:* | 42 |
| `group_admin` | Same as org_admin (scope limits access) | 42 |
| `tenant_admin` | tenant:* + account:* | 30 |
| `account_admin` | account:* | 16 |

---

## Database Schema

```
IDENTITY + RBAC LAYER

  users -----> user_roles <----- roles
  id           user_id (FK)      id
  email        role_id (FK)      name
  password                       level (1-5)
                                 scope_level
       |                              |
       v                              v
  user_admin_scope          role_permissions
  user_id (FK)              role_id (FK)
  scope_type                permission_id (FK)
    (org|tenant|account)          |
  scope_id                        v
                            permissions
                            id
                            key (scope:feature:action)


RESOURCE HIERARCHY LAYER

  organizations --> tenants --> accounts
  id                id          id
  name              org_id      tenant_id
  status            name        name
  plan              provider    status


SESSION LAYER (Performance Cache)

  user_sessions
  id, user_id (FK), token (hashed), refresh_token
  token_hint (first 8 chars -- indexed for fast lookup)
  permissions_cache (JSON -- ["org:users:write", ...])
  scope_cache (JSON -- {org_ids, tenant_ids, account_ids})
  expires_at, revoked
```

### Key Tables

| Table | Purpose |
|-------|---------|
| `roles` | 5 role definitions with level + scope_level |
| `permissions` | 56 permission keys |
| `role_permissions` | Maps roles to their default permissions |
| `user_roles` | Assigns a role to a user |
| `user_admin_scope` | Defines which orgs/tenants/accounts a user can access |
| `user_sessions` | Active sessions with cached permissions + scope |
| `user_invitations` | Pending invitations with token + role + scope |
| `organizations` | Customer organizations |

---

## Request Flow (Zero Extra DB Queries at Runtime)

### Login (Permission Resolution)

```
1. User authenticates (email/password or Google OAuth)
2. Resolve: user_roles -> roles -> role_permissions -> permissions
3. Resolve: user_admin_scope -> org_ids, tenant_ids, account_ids
4. Cache both as JSON in user_sessions row
5. Store token_hint (first 8 chars of raw token) for fast lookup
6. Set HTTPOnly cookies (access_token + refresh_token)
```

### API Request (Permission Check)

```
1. Extract access_token from cookie
2. SELECT from user_sessions WHERE token_hint = first_8_chars
3. Verify full token hash (PBKDF2)
4. Read permissions_cache -> ["org:users:write", "tenant:threats:read", ...]
5. Read scope_cache -> {org_ids: ["o1"], tenant_ids: ["t1","t2"], account_ids: null}
6. Check: required permission in permissions_cache?
7. Check: requested resource in scope_cache?
8. Allow or Deny -- NO joins, NO extra queries
```

### Performance

- `token_hint` column is indexed -- O(1) session lookup
- Permissions and scope are pre-resolved JSON -- no runtime joins
- `platform_admin` has `null` scope = unrestricted access (no scope check needed)

---

## Shared Auth Package -- `engine_auth/`

Shared between Django (portals) and FastAPI (API gateway/engines).

```
engine_auth/
  __init__.py
  core/
    models.py             # AuthContext dataclass
    token_validator.py    # Validate token via token_hint + hash
    permission_checker.py # has_permission(), can_access_resource()
    scope_resolver.py     # resolve_permissions(), resolve_scope()
  django/
    authentication.py     # CookieTokenAuthentication (DRF backend)
    permissions.py        # RequirePermission factory
  fastapi/
    dependencies.py       # require_permission() Depends
    middleware.py          # AuthMiddleware for API gateway
```

### AuthContext

```python
@dataclass
class AuthContext:
    user_id: str
    email: str
    role: str               # 'platform_admin', 'org_admin', etc.
    level: int              # 1-5
    scope_level: str        # 'platform', 'organization', 'tenant', 'account'
    permissions: list[str]  # ['org:users:write', 'account:threats:read', ...]
    org_ids: list[str] | None     # None = all (platform_admin)
    tenant_ids: list[str] | None
    account_ids: list[str] | None
```

### RequirePermission (Django/DRF)

```python
# Usage in views:
class ThreatListView(APIView):
    permission_classes = [RequirePermission("account:threats:read")]
```

Factory returns a DRF permission class that:
1. Reads `request.auth_context` (set by CookieTokenAuthentication)
2. Checks `permission_key` in `auth_context.permissions`
3. Auto scope-checks based on `tenant_id` / `account_id` query params

### API Gateway Middleware (FastAPI)

The gateway's `AuthMiddleware`:
1. Extracts cookie from request
2. Validates token via shared DB
3. Builds `AuthContext`
4. Sets `X-Auth-Context` header (base64 JSON) for downstream engines
5. Engines trust the header on internal network

---

## Authentication Methods

| Method | Endpoint | Flow |
|--------|----------|------|
| Email/Password | `POST /api/auth/login/` | Verify credentials -> create session -> set cookies |
| Google OAuth2 | `GET /api/auth/google/login/` | Redirect to Google -> callback creates session -> set cookies |
| Token Refresh | `POST /api/auth/refresh/` | Verify refresh cookie -> issue new access token |
| Logout | `POST /api/auth/logout/` | Delete session -> clear cookies |

All methods share the same session-creation logic: generate tokens, hash for storage, cache permissions + scope in session row.

---

## Invitation Flow

### Invite User

```
POST /api/auth/invite/
Body: {email, role, scope_type, scope_id}

1. Verify inviter has *:users:write at target scope level
2. Verify inviter's role level <= invited role level
3. Create user_invitations row with:
   - Secure random token (72h expiry)
   - Target role + scope
4. Return invitation details (email sending via SES -- future)
```

### Accept Invitation

```
POST /api/auth/invite/accept/
Body: {token, password, name_first, name_last}

1. Validate token (not expired, status=pending)
2. Create user + user_role + user_admin_scope
3. Mark invitation as accepted
4. Auto-login: create session + cache permissions
5. Return auth cookies
```

---

## Endpoint Permission Map

### User Portal (`engine_userportal`)

| Endpoint | Method | Permission |
|----------|--------|------------|
| `/api/threats/` | GET | `account:threats:read` |
| `/api/threats/` | PUT | `account:threats:write` |
| `/api/assets/` | GET | `account:assets:read` |
| `/api/compliance/` | GET | `account:compliance:read` |
| `/api/datasec/` | GET | `account:datasec:read` |
| `/api/secops/` | GET | `account:secops:read` |
| `/api/secops/scan` | POST | `account:secops:execute` |
| `/api/inventory/` | GET | `account:inventory:read` |
| `/api/tenants/` | GET | `org:tenants:read` |
| `/api/tenants/` | POST/PUT/DELETE | `org:tenants:write` |
| `/api/auth/me/` | GET | (authenticated) |
| `/api/auth/invite/` | POST | `*:users:write` (scope-dependent) |

### API Gateway

All requests validated by `AuthMiddleware`. Public paths excluded:
- `/gateway/*` (health checks)
- `/docs`, `/openapi.json`

---

## Migration History

| Migration | What |
|-----------|------|
| `user_auth/0004_rbac_schema` | organizations table, role level+scope fields, session caching columns, user_invitations table |
| `user_auth/0005_seed_permissions` | 5 roles, 56 permissions, role_permissions mappings |
| `user_auth/0006_migrate_roles` | Old role names -> new, user_admin_scope type migration |
| `tenant_management/0003_add_organization_fk` | organizations FK on tenants table |
