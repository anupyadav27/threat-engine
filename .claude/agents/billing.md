---
name: billing-engine
description: Full-context agent for the Billing engine — commercial subscription management, Stripe integration, scan frequency tokens, SOC 2 audit trail. Independent service (no pipeline dependency). Covers DB schema, API endpoints, K8s service, and gotchas.
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


You are the Billing Engine specialist. You know every detail of this engine's subscription model, Stripe integration, token-based scan gating, DB, and API.

Read `.claude/documentation/CSPM_CONSTITUTION.md` before acting.

---

## 1. Pipeline Role

**Position:** INDEPENDENT — no scan pipeline dependency. Always-on subscription management service.
**Reads:** Its own DB only
**Writes:** `subscription_plans`, `org_subscriptions`, `billing_events`, `stripe_webhook_log`, `billing_audit_log`, `scan_frequency_tokens`, `platform_admin_audit` in `threat_engine_billing`
**Feeds downstream:** All engines (plan enforcement gate), platform-admin engine
**Credentials:** Stripe API key (env var)
**Execution:** Always-on API service, 2 replicas

---

## 2. Subscription Tiers

| Plan | Price/mo | Accounts | Users | Scans/day |
|------|----------|----------|-------|-----------|
| free | $0 | 1 | 3 | 0 |
| starter | $49 | 3 | 10 | 1 |
| pro | $99 | 10 | 25 | 3 |
| enterprise | $299 | unlimited | unlimited | unlimited |

Engine access is controlled by `subscription_plans.engine_allowlist` JSONB — free and starter plans cannot access datasec, secops, vuln, ai_security, encryption, dbsec, or container_sec.

---

## 3. Database

**DB name:** `threat_engine_billing`
**Host:** `postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com:5432`

### Tables

**`subscription_plans`** — plan definitions (seeded, rarely updated)
```
plan_id             UUID PK
plan_name           VARCHAR UNIQUE    -- free | starter | pro | enterprise
display_name        VARCHAR
price_monthly       NUMERIC(10,2)
price_annual        NUMERIC(10,2)
stripe_price_id, stripe_price_id_annual VARCHAR
max_accounts, max_users INTEGER
scan_freq_per_day   INTEGER           -- 0 = unlimited for enterprise
data_retention_days INTEGER
engine_allowlist    JSONB             -- ["discoveries","check","threat","inventory","compliance",...]
is_active, is_public BOOLEAN
```

**`org_subscriptions`** — one row per org (tenant)
```
subscription_id     UUID PK
org_id              VARCHAR UNIQUE    -- tenant's org
plan_id             UUID FK
stripe_customer_id, stripe_subscription_id VARCHAR
status              VARCHAR           -- trialing | active | past_due | cancelled | paused
trial_start_at, trial_end_at TIMESTAMP
current_period_start, current_period_end TIMESTAMP
cancel_at_period_end BOOLEAN
payment_failed_at   TIMESTAMP
payment_retry_count SMALLINT
grace_period_end_at TIMESTAMP
is_overridden       BOOLEAN           -- manual override by platform admin
override_reason     TEXT
accounts_connected, users_count, scans_last_30_days INTEGER  -- usage cache
```

**`billing_events`** — Stripe event log (idempotent)
```
event_id        VARCHAR PK            -- Stripe event ID
event_type      VARCHAR               -- invoice.paid | subscription.updated | ...
org_id          VARCHAR
processed_at    TIMESTAMP
payload         JSONB                 -- raw Stripe event
```

**`stripe_webhook_log`** — raw webhook receipts
```
id UUID PK, stripe_event_id VARCHAR UNIQUE
event_type, status VARCHAR
received_at TIMESTAMP, processed_at TIMESTAMP
raw_payload JSONB, error_message TEXT
```

**`billing_audit_log`** — SOC 2 audit trail
```
id UUID PK
org_id, performed_by VARCHAR
action VARCHAR    -- plan_upgrade | plan_downgrade | override_applied | payment_retry | account_limit_reached
details JSONB
performed_at TIMESTAMP
```

**`scan_frequency_tokens`** — token bucket for scan rate limiting
```
org_id              VARCHAR PK
plan_id             UUID
tokens_remaining    INTEGER
max_tokens          INTEGER
last_refill_at      TIMESTAMP
refill_rate_per_day INTEGER
```

**`platform_admin_audit`** — admin action log
```
id UUID PK
admin_user_id, org_id VARCHAR
action VARCHAR
before_state, after_state JSONB
performed_at TIMESTAMP
ip_address VARCHAR
```

### Common Queries

```sql
-- Check org subscription status
SELECT os.status, sp.plan_name, sp.engine_allowlist,
       os.trial_end_at, os.current_period_end, os.grace_period_end_at
FROM org_subscriptions os
JOIN subscription_plans sp USING (plan_id)
WHERE os.org_id = $1;

-- Scan token check
SELECT tokens_remaining FROM scan_frequency_tokens WHERE org_id = $1;

-- Recent billing events for org
SELECT event_type, processed_at, payload->'data'->'object'->>'amount_due' as amount
FROM billing_events WHERE org_id = $1 ORDER BY processed_at DESC LIMIT 10;
```

---

## 4. API Endpoints

**Service URL:** `http://engine-billing:8040` (NOT port 80 — service exposes port 8040 directly)

| Method | Path | Key Params | Purpose |
|---|---|---|---|
| GET | `/api/v1/billing/plans` | — | List available plans |
| GET | `/api/v1/billing/subscription` | `org_id` | Get org subscription |
| POST | `/api/v1/billing/subscription` | `org_id`, `plan_id` | Create/update subscription |
| POST | `/api/v1/billing/webhook` | Stripe signature | Stripe webhook receiver |
| GET | `/api/v1/billing/tokens` | `org_id` | Check scan token balance |
| POST | `/api/v1/billing/tokens/consume` | `org_id` | Consume one scan token |
| GET | `/api/v1/billing/audit` | `org_id` | Billing audit log |
| POST | `/api/v1/admin/override` | `org_id`, `plan_id`, `reason` | Manual plan override |
| GET | `/api/v1/health/live` | — | Liveness |
| GET | `/api/v1/health/ready` | — | Readiness |

---

## 5. BFF Views I Feed

**`shared/api_gateway/bff/_shared.py`** — `"billing": "http://engine-billing:8040"`
- Note explicit port 8040 (not port 80 like other engines)
- Feeds subscription status into gateway middleware for plan enforcement

---

## 6. UI Pages I Power

- **`/billing`** — current plan, usage stats, upgrade options
- **`/billing/history`** — invoice history, payment events
- **`/settings`** — subscription management, billing details

---

## 7. K8s Service

```yaml
name: engine-billing
namespace: threat-engine-engines
image: yadavanup84/engine-billing:v-billing-sprint3
containerPort: 8040
service: ClusterIP port 8040 → targetPort 8040   ← NOT port 80
replicas: 2                                        ← 2 replicas for availability
liveness:  GET /api/v1/health/live  port 8040
readiness: GET /api/v1/health/ready port 8040
env: STRIPE_API_KEY (from secret)
```

---

## 8. Engine-Specific Gotchas

**Service port is 8040, NOT 80** — Unlike all other engines (which expose port 80 → internal port), billing service exposes port 8040 directly. BFF must call `http://engine-billing:8040`, NOT `http://engine-billing`. This is reflected in `_shared.py` ENGINE_URLS.

**2 replicas** — Billing is the only engine with 2 replicas. This is for payment processing availability.

**Stripe webhook idempotency** — `billing_events.event_id` uses Stripe's event ID as PK. Always use `INSERT ... ON CONFLICT DO NOTHING` for webhook events.

**engine_allowlist gates feature access** — The `subscription_plans.engine_allowlist` JSONB determines which engine endpoints a tenant can access. Platform admin, gateway middleware, and individual engines can all check this. Never bypass it.

**scan_frequency_tokens rate limiting** — Scan tokens are consumed per scan initiation. Before starting any scan via `/api/v1/scan`, consume a token from `scan_frequency_tokens`. Enterprise plan has unlimited tokens (large refill_rate_per_day).

**override_reason required** — When `is_overridden=TRUE`, `override_reason` must be non-null. This is a SOC 2 audit requirement.

**Port-forward:**
```bash
kubectl port-forward svc/engine-billing 8040:8040 -n threat-engine-engines
```
