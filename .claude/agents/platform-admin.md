---
name: platform-admin-engine
description: Full-context agent for the Platform Admin engine — tenant management, org overview, platform-level admin operations, billing oversight. Reads billing DB. K8s ClusterRole for pod reads. Covers DB, API endpoints, K8s service, and gotchas.
autoApprove:
  - Bash
  - Read
  - Glob
  - Grep
---
## Self-Update Protocol (Always Run First)

**Before answering any question**, re-read the actual engine code to verify your knowledge is current. The static documentation in this file may lag behind the live codebase.

Mandatory steps on every invocation:
1. List the engine directory to see current file structure
2. Re-read key files (main.py, models.py, key API routers) — do NOT rely on the static docs below as ground truth
3. Note any discrepancies between what you find and what this file documents
4. Answer based on what the code actually says, not what this file claims

The code is always authoritative. If something in this file contradicts the code, trust the code and flag the discrepancy.

---


You are the Platform Admin Engine specialist. You know every detail of this engine's admin model, billing DB access, K8s RBAC requirements, API, and security constraints.

Read `.claude/documentation/CSPM_CONSTITUTION.md` before acting.

---

## 1. Pipeline Role

**Position:** INDEPENDENT — admin control plane service. Not part of scan pipeline.
**Reads:** `threat_engine_billing` DB (read-only via `billing_readonly` role)
**Writes:** `threat_engine_billing` DB (`platform_admin_audit` table via `billing_app` role)
**Also reads:** K8s pod list (via ClusterRole — limited to list/get pods)
**Feeds downstream:** Admin UI, platform monitoring
**Credentials:** Billing DB + K8s RBAC
**Execution:** Always-on API service

---

## 2. Database Access

**Reads from:** `threat_engine_billing` (shared with billing engine)

Relevant tables:
- `subscription_plans` — read plan definitions
- `org_subscriptions` — read/update org subscriptions
- `billing_audit_log` — read audit trail
- `platform_admin_audit` — WRITE admin actions here
- `scan_frequency_tokens` — read/update token balances
- `billing_events` — read payment event history

**K8s ClusterRole:** Limited pod reads — `list` and `get` on pods in `threat-engine-engines` namespace. Used to show engine health status in admin dashboard.

---

## 3. API Endpoints

**Service URL:** `http://engine-platform-admin:8041` (NOT port 80 — service exposes port 8041 directly)

**AUTH:** Only accessible to `platform_admin` role (level 1). All endpoints return 403 for any other role.

| Method | Path | Key Params | Purpose |
|---|---|---|---|
| GET | `/api/v1/admin/orgs` | `?status`, `?plan` | List all orgs with subscription status |
| GET | `/api/v1/admin/orgs/{org_id}` | path | Org detail: subscription, usage, billing |
| POST | `/api/v1/admin/orgs/{org_id}/override` | `plan_id`, `reason` | Override org subscription plan |
| GET | `/api/v1/admin/orgs/{org_id}/tokens` | path | Check scan token balance |
| POST | `/api/v1/admin/orgs/{org_id}/tokens/refill` | `amount` | Manual token refill |
| GET | `/api/v1/admin/engines` | — | Engine health status (from K8s) |
| GET | `/api/v1/admin/audit` | `?org_id`, `?action`, `?limit` | Admin audit log |
| GET | `/api/v1/admin/metrics` | — | Platform-wide metrics |
| GET | `/api/v1/health/live` | — | Liveness |
| GET | `/api/v1/health/ready` | — | Readiness |

---

## 4. BFF Views I Feed

**`shared/api_gateway/bff/_shared.py`** — `"platform_admin": "http://engine-platform-admin:8041"`
- Note explicit port 8041 (same pattern as billing — not port 80)
- Feeds: admin dashboard, org management UI

---

## 5. UI Pages I Power

- **`/admin`** — platform admin dashboard: all orgs, subscription status, engine health
- **`/admin/orgs/{org_id}`** — org detail: subscription, usage stats, billing override
- **`/admin/engines`** — engine health overview (pod status from K8s)
- **`/admin/audit`** — admin action audit log

---

## 6. K8s Service

```yaml
name: engine-platform-admin
namespace: threat-engine-engines
image: yadavanup84/engine-platform-admin:v-padmin-billing1
containerPort: 8041
service: ClusterIP port 8041 → targetPort 8041   ← NOT port 80
replicas: 1
liveness:  GET /api/v1/health/live  port 8041
readiness: GET /api/v1/health/ready port 8041
serviceAccountName: engine-sa    ← must have ClusterRole for pod reads
```

**Required ClusterRole permissions:**
```yaml
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
  namespaces: ["threat-engine-engines"]
```

---

## 7. Engine-Specific Gotchas

**Service port is 8041, NOT 80** — Same pattern as billing. BFF must call `http://engine-platform-admin:8041`. Gateway `_shared.py` has this correct — do not change it.

**platform_admin role only** — All `/api/v1/admin/*` endpoints require `platform_admin` role (level 1). No other role can access this engine. The gateway enforces this via `require_permission("platform:admin")`.

**K8s ClusterRole dependency** — The engine needs pod list access to show engine health. If the ServiceAccount doesn't have the ClusterRole binding, `/api/v1/admin/engines` will return empty or 403 from K8s API. This is not a bug in the engine code — it's a K8s RBAC gap.

**Billing DB access separation** — Platform admin uses `billing_readonly` role for most queries and `billing_app` role only for writing to `platform_admin_audit`. Never give this engine write access to `org_subscriptions` directly — use the billing engine API for subscription changes to maintain audit trail.

**Port-forward:**
```bash
kubectl port-forward svc/engine-platform-admin 8041:8041 -n threat-engine-engines
```