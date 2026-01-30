# Multi-Tenant Isolation: Customer, Tenant, User Segregation

## 1. Hierarchy and Segregation Model

### Data Model

```
Customer (org / billing entity)
  └── Tenant (per CSP: AWS account, Azure subscription, GCP project, etc.)
        └── User (via TenantUsers: user ↔ tenant)
```

- **`engine_shared.customers`**: Top-level org. One row per customer.
- **`engine_shared.tenants`**: FK `customer_id` → customers. One tenant per CSP scope (e.g. one AWS account, one Azure sub).
- **Users** (`user_auth.Users`): Identity. No direct customer_id.
- **`TenantUsers`** (`tenant_management`): Links user ↔ tenant. A user can have access to **multiple tenants** (even across customers, if we allow it; typically we restrict to one customer).

**Segregation rule**:  
- **Customer-level**: All data for customer C = rows where `customer_id = C` (or `tenant_id` in tenants of C).  
- **Tenant-level**: All data for tenant T = rows where `tenant_id = T`.  
- **User-level**: User U can only access data for **tenants** (and thus customers) they are linked to via `TenantUsers`.

### How we segregate today

| Layer | What we do | What's missing |
|-------|------------|----------------|
| **DB** | Tables have `tenant_id` / `customer_id`. FKs enforce consistency. | No RLS; any DB user can read all rows. |
| **Engines** | Queries filter by `tenant_id` (and sometimes `customer_id`) when **caller passes them**. | Engines do **not** verify "caller allowed for this tenant". |
| **User Portal API** | Views receive `tenant_id` / `customer_id` from **query params or body** and forward to engines. | We **do not** resolve "current user → allowed tenants" nor **validate** that the requested tenant/customer is in that set. |

So today: **isolation is only as good as the caller**. If the backend blindly forwards `tenant_id` from the request without checking that the authenticated user is allowed to access that tenant, one customer can access another’s data.

---

## 2. How to Ensure One Customer Can’t Access Another’s Data

### 2.1. Resolve “current user” → allowed tenants (and customers)

1. **Auth**: Every API request identifies the user (JWT, session, API key, etc.).
2. **Allowed scope**: From DB, compute:
   - `allowed_tenant_ids`: tenants linked via `TenantUsers` for this user.
   - `allowed_customer_ids`: customers that own those tenants (from `engine_shared.tenants`).
3. **Optional**: Restrict users to a single customer (e.g. `user.customer_id` or "primary customer"). Then `allowed_customer_ids` is at most one.

### 2.2. Enforce on every request

**Option A – Explicit tenant/customer in request (recommended)**  
- API requires `tenant_id` (and optionally `customer_id`) per request (query, body, or header).  
- **Before** calling any engine or DB:
  1. Resolve user → `allowed_tenant_ids` (and `allowed_customer_ids`).
  2. **Validate**: `tenant_id` ∈ `allowed_tenant_ids`. If `customer_id` is provided, also validate it matches the tenant’s customer.
  3. If invalid → **403 Forbidden**.  
  4. If valid → pass `tenant_id` / `customer_id` to engines and DB reads.

**Option B – Implicit from context**  
- User has a "current" tenant (e.g. selected in UI, stored in session).  
- Backend resolves user → allowed tenants, checks "current" ∈ allowed, then uses that tenant for all engine/DB calls.  
- Still need to **validate** "current" tenant on login/switch.

**Rule**: Never use `tenant_id` or `customer_id` from the client without checking it against the user’s allowed set.

### 2.3. Where to enforce

| Place | Action |
|-------|--------|
| **User Portal backend** | Middleware or view decorator: resolve user → allowed tenants/customers; validate `tenant_id`/`customer_id` on each request; inject into request context. |
| **Engine clients** | Always receive `tenant_id` (and `customer_id` when needed) from the **backend only**, after validation. Engines treat them as trusted. |
| **Engines** | Continue to filter all reads/writes by `tenant_id` (and `customer_id` where present). No auth logic in engines; they assume caller is already validated. |
| **Admin Portal** | Same idea: resolve admin → allowed customers/tenants (e.g. all, or a subset); validate before using. |

### 2.4. Optional: Row-Level Security (RLS)

To add a **DB-level** safeguard:

1. Use a single DB user per application (no per-tenant DB users).
2. Before each request (or per connection): `SET app.current_tenant_id = '...'` and/or `SET app.current_customer_id = '...'` (e.g. in Django middleware, or in a connection wrapper).
3. Add RLS policies on engine tables, e.g.:
   - `SELECT`: `tenant_id = current_setting('app.current_tenant_id')` (or `customer_id` for customer-scoped tables).
   - Similarly for `UPDATE` / `DELETE` where applicable.

RLS is **optional**; application-level checks are **required** regardless.

---

## 3. Concrete Checklist

- [ ] **User → Tenant resolution**: Query `TenantUsers` (+ `engine_shared.tenants`) to get `allowed_tenant_ids` and `allowed_customer_ids` for the current user. Cache per request/session if needed.
- [ ] **Middleware / decorator**: Run after auth; validate `tenant_id` (and `customer_id` if present) against allowed set; return 403 if invalid; store validated ids in `request.tenant_id` / `request.customer_id`.
- [ ] **Views**: Use only `request.tenant_id` / `request.customer_id` when calling engine clients or DB. Never use raw query params for tenant/customer without validation.
- [ ] **SecOps / Inventory / etc.**: Same pattern: backend validates, then passes tenant/customer to engines.
- [ ] **Admin Portal**: Define admin→customer/tenant scope; validate before any admin read/write.
- [ ] **Optional**: Add RLS using `app.current_tenant_id` / `app.current_customer_id` for defense in depth.

---

## 4. Summary

- **Segregation**: Customer → Tenants → Users (via TenantUsers). Data is scoped by `customer_id` and `tenant_id`.
- **Isolation**: One customer cannot access another’s data **only if** we always:
  1. Resolve **current user** → **allowed tenants (and customers)**,
  2. **Validate** every `tenant_id` / `customer_id` used in APIs against that set,
  3. Use **only** validated ids in engines and DB.

Today we have the **data model** (customers, tenants, tenant_id on tables) but **not** the **enforcement** (auth-based resolution + validation). Adding the middleware/decorator and using it consistently across User Portal and Admin Portal closes that gap.
