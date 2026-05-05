# Role-Based Access Control (RBAC)

> **Status:** Live as of 2026-05-01. Django migrations 0008 + 0009 applied to production DB.
> Implemented across all 18 deployed engine images (tag suffix `-rbac1`).

---

## Overview

Session-based RBAC (not JWT). Roles define **what level** a user operates at; permissions define
**what they can do**. On login, permissions and scope are resolved once and cached in the
`user_sessions` row — all subsequent requests read from the cache with zero extra DB joins.

Tokens are opaque hashes stored in HTTPOnly cookies. The first 8 characters are stored as
`token_hint` in a partial index for fast O(1) session lookup.

---

## Resource Hierarchy

```
Platform (SaaS provider)
  +-- Organization (customer company, e.g. "Acme Corp")
        +-- Tenant (cloud provider: AWS, GCP, Azure...)
              +-- Account (individual cloud account: 123456789012)
```

Maps to database tables:
- `organizations` — customer company
- `tenants` — cloud provider workspace (FK to organizations)
- `accounts` — individual cloud accounts (FK to tenants via providers)

---

## Roles (5 Seeded via Migration 0009)

| Level | Role | `scope_level` | Description |
|-------|------|---------------|-------------|
| 1 | `platform_admin` | `platform` | Full access to all orgs, tenants, accounts; all 30 permissions |
| 2 | `org_admin` | `organization` | Cross-tenant read + scans:delete + tenants:read + rules:write |
| 4 | `tenant_admin` | `tenant` | All read + sensitive + scans:create + users + rules + settings |
| 4 | `analyst` | `tenant` | All read permissions + datasec:sensitive + rules:read |
| 4 | `viewer` | `tenant` | 9 core read-only permissions |

`group_admin` (level 3) is defined in the schema but not seeded — reserved for future use.

---

## Permissions (30 Keys)

| Permission Key | viewer | analyst | tenant_admin | org_admin | platform_admin |
|---------------|:------:|:-------:|:------------:|:---------:|:--------------:|
| `discoveries:read` | Y | Y | Y | Y | Y |
| `check:read` | Y | Y | Y | Y | Y |
| `threat:read` | Y | Y | Y | Y | Y |
| `inventory:read` | Y | Y | Y | Y | Y |
| `compliance:read` | Y | Y | Y | Y | Y |
| `iam:read` | Y | Y | Y | Y | Y |
| `ciem:read` | Y | Y | Y | Y | Y |
| `ciem:sensitive` | — | Y | Y | Y | Y |
| `network:read` | Y | Y | Y | Y | Y |
| `risk:read` | Y | Y | Y | Y | Y |
| `datasec:read` | — | Y | Y | Y | Y |
| `datasec:sensitive` | — | Y | Y | Y | Y |
| `secops:read` | — | Y | Y | Y | Y |
| `vulnerability:read` | — | Y | Y | Y | Y |
| `ai_security:read` | — | Y | Y | Y | Y |
| `encryption:read` | — | Y | Y | Y | Y |
| `dbsec:read` | — | Y | Y | Y | Y |
| `container:read` | — | Y | Y | Y | Y |
| `rules:read` | — | Y | Y | Y | Y |
| `scans:create` | — | — | Y | Y | Y |
| `users:read` | — | — | Y | Y | Y |
| `users:write` | — | — | Y | Y | Y |
| `settings:read` | — | — | Y | Y | Y |
| `settings:write` | — | — | Y | Y | Y |
| `scans:delete` | — | — | — | Y | Y |
| `tenants:read` | — | — | — | Y | Y |
| `rules:write` | — | — | — | Y | Y |
| `tenants:write` | — | — | — | — | Y |
| `billing:read` | — | — | Y | Y | Y |
| `billing:write` | — | — | — | Y | Y |
| `platform:admin` | — | — | — | — | Y |

---

## Sensitive Data Permissions

`ciem:sensitive` is the platform's first **data-classification permission** — orthogonal to `<engine>:read` and checked separately at the BFF layer with mandatory audit logging on every access.

### What `ciem:sensitive` unlocks

| Field | Sensitivity | Routes that check |
|---|---|---|
| `identity_arn` | CSA CCM IAM-09 — infra metadata | `/api/v1/views/inventory/asset/{uid}/ciem`, `/api/v1/views/inventory_ciem`, `/api/v1/views/ciem_identity` |
| `privilege_level` | recon-grade | same as above |
| `last_used_days` | recon-grade | same as above |
| `unused_permission_count` | recon-grade | same as above |

### Granted to (per migration 0013)

analyst, tenant_admin, org_admin, platform_admin

**Denied** for: viewer, auditor, dev, security_engineer.

Rationale: analysts run identity-entitlement investigations; denying breaks the investigation journey. The 4 granted roles already see same-class data (threat findings, IAM findings) — no new data class exposure.

### Permission inheritance rule

`ciem:sensitive` does **NOT** imply `ciem:read`. Permission strings are matched exactly (no wildcard expansion). If an endpoint needs both, both must be present in `auth_context.permissions`.

### Audit-log requirement (MANDATORY on every access)

Every BFF route that gates `ciem:sensitive` MUST emit an audit log entry on **both 200 and 403** with these fields:

```json
{
  "timestamp": "2026-05-04T14:30:00Z",   // UTC ISO8601
  "user_id": "...",
  "tenant_id": "...",
  "endpoint": "GET /api/v1/views/ciem_identity",
  "asset_id_or_principal": "...",
  "result": 200,
  "request_id": "...",                   // correlation header
  "top_5_identity_arns": [...]           // on 200 only
}
```

Logger: `logging.getLogger("api-gateway.audit")`. JSON-serialize the entry via `json.dumps`. Never `print()`.

### Future similar permissions follow the same pattern

When adding any new data-classification permission (e.g. `secrets:reveal`, `pii:export`, `customer_data:read`):
1. Add the permission row to the matrix above with the same Y/N pattern.
2. Add a "What it unlocks" subsection here.
3. Gate at BFF (not at engine) and emit the same audit-log shape.
4. Ship audit log to durable store within one sprint of the new permission going live.

---

## Auth Flow (Step by Step)

### Login (Permission Resolution)

```
1. User POSTs credentials (email/password, Google OAuth, or SAML)
2. Django resolves: user_roles → roles → role_permissions → permissions
3. Django resolves: user_admin_scope → tenant_ids, account_ids
4. Writes to user_sessions:
   - token_hint = first 8 chars of raw token (indexed)
   - permissions_cache = ["discoveries:read", "threat:read", ...]
   - scope_cache = {"tenant_ids": ["t1", "t2"], "account_ids": null}
5. Sets HTTPOnly cookies: access_token + refresh_token
```

### GET /api/auth/me/ Response

```json
{
  "user_id": "...",
  "email": "...",
  "role": "analyst",
  "level": 4,
  "permissions": ["discoveries:read", "check:read", "datasec:sensitive", ...],
  "tenant_ids": ["my-tenant"]
}
```

### API Request Flow (Gateway → Engine)

```
1. Browser sends access_token cookie to API Gateway
2. Gateway AuthMiddleware:
   a. SELECT user_sessions WHERE token_hint = first_8_chars(cookie) AND revoked = false
   b. Verify full token hash (PBKDF2)
   c. Build AuthContext from permissions_cache + scope_cache
   d. Set X-Auth-Context: <base64-JSON> header on upstream request
3. Engine receives X-Auth-Context
4. FastAPI Depends(require_permission("engine:read")):
   a. Decode AuthContext from header
   b. Check: permission in ctx.permissions → 403 if missing
   c. Check: requested tenant_id in ctx.tenant_ids → 403 if out-of-scope
5. Engine applies strip_sensitive_fields(data, auth) before returning response
```

### AuthContext Dataclass

```python
@dataclass
class AuthContext:
    user_id: str
    email: str
    role: str               # 'platform_admin', 'analyst', etc.
    level: int              # 1-5
    scope_level: str        # 'platform', 'organization', 'tenant', 'account'
    permissions: list[str]  # ['discoveries:read', 'threat:read', ...]
    tenant_ids: list[str] | None   # None = unrestricted (platform_admin)
    account_ids: list[str] | None
```

---

## Engine Enforcement Table

All engines live as of 2026-05-01. `X-Auth-Context` header is required on all protected endpoints.

| Engine | Permission Required | viewer blocked (403) | Fields stripped for analyst/viewer |
|--------|--------------------|-----------------------|------------------------------------|
| discoveries | `discoveries:read` | `raw_data`, `credential_ref` | `credential_ref` |
| check | `check:read` | `evidence`, `credential_ref` | `credential_ref` |
| threat | `threat:read` | `credential_ref` | `credential_ref` |
| inventory | `inventory:read` | `credential_ref` | — |
| compliance | `compliance:read` | — | — |
| iam | `iam:read` | `policy_document`, `credential_ref` | `credential_ref` |
| ciem | `ciem:read` | `event_raw`, `credential_ref` | `credential_ref` |
| network-security | `network:read` | `credential_ref` | — |
| risk | `risk:read` | `calculation_model`, `blast_radius_sample`, `credential_ref` | `credential_ref` |
| datasec | `datasec:read` | entire endpoint = 403 | `finding_data`, `credential_ref` |
| secops | `secops:read` | entire endpoint = 403 | `credential_ref` |
| vulnerability | `vulnerability:read` | entire endpoint = 403 | `credential_ref` |
| ai-security | `ai_security:read` | entire endpoint = 403 | `credential_ref` |
| encryption | `encryption:read` | entire endpoint = 403 | `credential_ref` |
| dbsec | `dbsec:read` | entire endpoint = 403 | — |
| container-sec | `container:read` | entire endpoint = 403 | — |
| fix/secops_fix | `scans:create` | 403 | — |
| fix/vul_fix | `scans:create` | 403 | — |

HTTP response codes:
- **401**: Missing or expired session (no valid cookie)
- **403**: Valid session but insufficient permission or tenant_id not in scope

---

## BFF Forwarding Pattern

All 34 BFF view handlers in `shared/api_gateway/bff/` now:

1. Extract `X-Auth-Context` from the incoming browser request
2. Forward it to all downstream engine calls via `fetch_many(auth_headers={"X-Auth-Context": ctx})`
3. Include `role_level` in the BFF cache key to prevent cross-role cache poisoning

Engines MUST NOT be called directly by clients — all requests flow through the gateway which
sets the `X-Auth-Context` header. Engines trust the header on the internal cluster network.

---

## Frontend Integration

- `ROLE_CAPABILITIES` hardcoded map removed
- `usePermissions()` hook fetches `permissions[]` from `GET /api/auth/me`
- `hasPermission(key)` checks the API-sourced list
- `DEV_BYPASS_AUTH` removed from `middleware.js` and `auth-context.js` — **never add it back**
- Fallback: if `/api/auth/me` returns empty permissions, treat as viewer (9 read-only permissions)

---

## DB Schema Changes (Migrations 0008 + 0009)

### `roles` table (2 new columns)

| Column | Type | Default | Description |
|--------|------|---------|-------------|
| `level` | INTEGER NOT NULL | 4 | Hierarchy level: 1=platform, 2=org, 3=group, 4=tenant, 5=account |
| `scope_level` | VARCHAR(50) NOT NULL | `'tenant'` | One of: platform, organization, tenant, account |

### `user_sessions` table (3 new columns)

| Column | Type | Default | Description |
|--------|------|---------|-------------|
| `token_hint` | VARCHAR(8) NULL | — | First 8 chars of raw token; partial index `idx_user_sessions_token_hint WHERE revoked = false` |
| `permissions_cache` | JSONB NULL | `'[]'` | Flat list of permission keys, e.g. `["discoveries:read", "threat:read"]` |
| `scope_cache` | JSONB NULL | `'{}'` | `{"tenant_ids": ["t1"], "account_ids": null}` — null account_ids = all accounts under tenant |

### Index

```sql
CREATE INDEX idx_user_sessions_token_hint
  ON user_sessions(token_hint)
  WHERE revoked = false;
```

---

## Key Tables (unchanged structure)

| Table | Purpose |
|-------|---------|
| `roles` | 5 seeded role definitions with level + scope_level |
| `permissions` | 27 permission keys |
| `role_permissions` | Maps roles to their default permissions |
| `user_roles` | Assigns a role to a user |
| `user_admin_scope` | Defines which tenants/accounts a user can access |
| `user_sessions` | Active sessions with cached permissions + scope |
| `user_invitations` | Pending invitations with token + role + scope |
| `organizations` | Customer organizations |

---

## Applying Django Migrations (Production)

```bash
# Find a running cspm-backend pod
kubectl get pods -n threat-engine-engines -l app=cspm-backend

# Run migrations
kubectl exec -n threat-engine-engines deployment/cspm-backend -- \
  python manage.py migrate user_auth

# Verify
kubectl exec -n threat-engine-engines deployment/cspm-backend -- \
  python manage.py showmigrations user_auth
```

Migration files:
- `platform/cspm-backend/user_auth/migrations/0008_roles_level_scope_sessions_cache.py`
- `platform/cspm-backend/user_auth/migrations/0009_seed_roles_permissions.py`
- `platform/cspm-backend/user_auth/migrations/0010_billing_permissions.py` (billing:read, billing:write, platform:admin)
- `platform/cspm-backend/user_auth/migrations/0013_ciem_sensitive_permission.py` (ciem:sensitive — analyst+)

---

## Authentication Methods

| Method | Endpoint | Flow |
|--------|----------|------|
| Email/Password | `POST /api/auth/login/` | Verify credentials → create session → set cookies |
| Google OAuth2 | `GET /api/auth/google/login/` | Redirect to Google → callback creates session → set cookies |
| Token Refresh | `POST /api/auth/refresh/` | Verify refresh cookie → issue new access token |
| Logout | `POST /api/auth/logout/` | Delete session → clear cookies |

---

## Deployed Image Tags (RBAC Sprint)

| Component | Tag |
|-----------|-----|
| cspm-backend | `v-engine-tenant-rbac1` |
| api-gateway | `v-bff-fix6-rbac1` |
| cspm-frontend | `v-engine-tenant-rbac1` |
| engine-check | `v-check-fix2-rbac1` |
| engine-discoveries | `v-disc-net5-rbac1` |
| engine-threat | `v-multicsp3-rbac1` |
| engine-inventory | `v-graph-fix-rbac1` |
| engine-compliance | `v-compliance-fix2-rbac1` |
| engine-iam | `v-iam-oci-rbac1` |
| engine-ciem | `v-ciem-alicloud-rbac1` |
| engine-network | `v-net-fix14-rbac1` |
| engine-risk | `v-risk-enterprise-rbac1` |
| engine-datasec | `v-dspm-enterprise-rbac1` |
| engine-secops | `v-unified-fix2-rbac1` |
| engine-ai-security | `v-ai-tenant-fix-rbac1` |
| engine-encryption | `v-multicsp1-rbac1` |
| engine-dbsec | `v-dbsec-enterprise-rbac1` |
| engine-container-sec | `v-csec-dbfix-rbac1` |