# Architecture Design Document — Subscription & Billing System
# Threat Engine CSPM Platform

**Author:** Solution Architect  
**Date:** 2026-05-02  
**Status:** Final — Approved for Story Authoring  
**Covers:** engine-billing (8040), engine-platform-admin (8041), Gateway Enforcement, Django Extensions

---

## Table of Contents

1. Architecture Overview
2. DB Schema — Full SQL
3. API Contracts
4. Gateway Enforcement Design
5. Stripe Integration Design
6. Data Flow Diagrams
7. Security Design (STRIDE + PCI Scope)
8. K8s Manifest Sketches
9. Epic Breakdown
10. Open Questions Resolved

---

## 1. Architecture Overview

### 1.1 Where the New Engines Fit

The two new engines sit outside the scan pipeline. They do not participate in the Argo DAG (Discovery → Inventory → Check → Threat → ...). They are always-on REST services that serve the commercial layer.

```
┌──────────────────────────────────────────────────────────────────────┐
│                        API Gateway (:80)                             │
│  AuthMiddleware → SubscriptionMiddleware → Upstream Proxy            │
│                                                                      │
│  NEW: SubscriptionMiddleware                                         │
│    1. Read org_id from AuthContext                                   │
│    2. Query billing cache (Redis or in-memory TTL 60s)              │
│    3. Build X-Subscription-Context header                           │
│    4. Forward to all engine upstreams                               │
└───────────────────────┬──────────────────────────────────────────────┘
                        │  X-Auth-Context + X-Subscription-Context
          ┌─────────────┼─────────────────────────────────┐
          │             │                                 │
   ┌──────▼──────┐ ┌────▼─────────────┐ ┌────────────────▼──────────────┐
   │  18 existing │ │ engine-billing   │ │ engine-platform-admin         │
   │  scan engines│ │ Port 8040        │ │ Port 8041                     │
   │ (unchanged)  │ │ FastAPI          │ │ FastAPI                       │
   │              │ │                  │ │ platform:admin only           │
   │  HTTP 402    │ │ Stripe SDK       │ │                               │
   │  on tier     │ │ Webhook handler  │ │ Reads: billing DB             │
   │  violation   │ │ Usage metering   │ │        K8s API                │
   └──────────────┘ └────────┬─────────┘ │        Argo Workflows API     │
                             │           │        scan engine /health    │
                    ┌────────▼─────────┐ └───────────────────────────────┘
                    │  billing DB      │
                    │  (PostgreSQL,    │
                    │  new RDS schema  │
                    │  threat_engine_  │
                    │  billing)        │
                    │                  │
                    │ subscription_plans│
                    │ org_subscriptions │
                    │ billing_events    │
                    │ stripe_webhook_log│
                    │ billing_audit_log │
                    │ scan_frequency_   │
                    │   tokens          │
                    └──────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│               Django cspm-backend  (identity layer)                  │
│                                                                      │
│  Migration 0010: 3 new permissions                                   │
│  /api/auth/me: + subscription tier field                            │
│  New permissions: billing:read, billing:write, platform:admin       │
└──────────────────────────────────────────────────────────────────────┘
```

### 1.2 Component Inventory

| Component | Port | Image | DB |
|-----------|------|-------|----|
| engine-billing | 8040 | `yadavanup84/engine-billing:v-billing-1` | `threat_engine_billing` |
| engine-platform-admin | 8041 | `yadavanup84/engine-platform-admin:v-padmin-1` | read-only across all DBs |
| API Gateway (updated) | 80 | `yadavanup84/threat-engine-api-gateway:v-bff-billing1` | platform DB (read) |
| cspm-backend (updated) | 8010 | `yadavanup84/cspm-django-backend:v-backend-billing1` | platform DB |

### 1.3 Non-Changes (Zero Regression Guarantee)

The 18 existing scan engines receive NO code changes. Enforcement is achieved purely by:
1. `X-Subscription-Context` header injected by the Gateway
2. Engine reads the header and returns HTTP 402 when `tier_access=denied`

This means if the header is absent (internal calls, Argo pipeline steps), engines behave as today. The header is only injected on user-facing requests through the Gateway.

---

## 2. DB Schema — Full SQL

All tables go in PostgreSQL database `threat_engine_billing` on the existing RDS instance (`postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com`). Using a separate schema within the existing RDS saves infrastructure cost while maintaining logical isolation. The billing engine connects with a dedicated `billing_user` Postgres role that has no access to scan DBs.

```sql
-- =============================================================================
-- threat_engine_billing schema
-- Apply via: psql -h <RDS_HOST> -U postgres -d threat_engine_billing -f billing_schema.sql
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- =============================================================================
-- subscription_plans
-- Single source of truth for tier definitions. Managed by platform_admin via API.
-- Seed data: Free, Starter, Pro, Enterprise (see migration note below)
-- =============================================================================
CREATE TABLE subscription_plans (
    plan_id         UUID        NOT NULL DEFAULT uuid_generate_v4(),
    plan_name       VARCHAR(50) NOT NULL,           -- 'free', 'starter', 'pro', 'enterprise'
    display_name    VARCHAR(100) NOT NULL,          -- 'Free', 'Starter', 'Pro', 'Enterprise'
    price_monthly   NUMERIC(10,2) NOT NULL DEFAULT 0.00,  -- USD cents or dollars; Free=0
    price_annual    NUMERIC(10,2),                 -- NULL = no annual option yet (Phase 2)
    stripe_price_id VARCHAR(255),                  -- Stripe Price ID (e.g. price_xxx); NULL for Free
    stripe_price_id_annual VARCHAR(255),           -- Phase 2
    max_accounts    INTEGER     NOT NULL DEFAULT 1,    -- -1 = unlimited
    max_users       INTEGER     NOT NULL DEFAULT 3,    -- -1 = unlimited
    scan_freq_per_day INTEGER   NOT NULL DEFAULT 0,    -- 0 = <1/day (weekly); -1 = unlimited
    data_retention_days INTEGER NOT NULL DEFAULT 7,   -- -1 = unlimited (1 year in practice)
    engine_allowlist JSONB      NOT NULL DEFAULT '["discoveries","check","threat","inventory","compliance","iam","ciem","network-security","risk"]'::jsonb,
    -- ^ engines accessible on this plan. Enterprise adds datasec, secops, vulnerability, etc.
    is_active       BOOLEAN     NOT NULL DEFAULT true,
    is_public       BOOLEAN     NOT NULL DEFAULT true,  -- false = internal/custom plans
    sort_order      SMALLINT    NOT NULL DEFAULT 0,
    metadata        JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT subscription_plans_pkey PRIMARY KEY (plan_id),
    CONSTRAINT uq_plan_name UNIQUE (plan_name)
);

CREATE INDEX idx_sp_active ON subscription_plans(is_active) WHERE is_active = true;
CREATE INDEX idx_sp_sort ON subscription_plans(sort_order);

-- Seed data (applied in migration, not in DDL):
-- INSERT INTO subscription_plans (plan_name, display_name, price_monthly, max_accounts, max_users, scan_freq_per_day, data_retention_days, engine_allowlist, sort_order)
-- VALUES
--   ('free',       'Free',       0.00,  1,  3,  0, 7,   '["discoveries","check","threat","inventory","compliance","iam","ciem","network-security","risk"]', 1),
--   ('starter',    'Starter',    49.00, 3,  10, 1, 30,  '["discoveries","check","threat","inventory","compliance","iam","ciem","network-security","risk"]', 2),
--   ('pro',        'Pro',        99.00, 10, 25, 4, 90,  '["discoveries","check","threat","inventory","compliance","iam","ciem","network-security","risk","datasec","secops","vulnerability"]', 3),
--   ('enterprise', 'Enterprise', 299.00, -1, -1, -1, 365, '["discoveries","check","threat","inventory","compliance","iam","ciem","network-security","risk","datasec","secops","vulnerability","ai-security","encryption","dbsec","container-security","fix"]', 4);


-- =============================================================================
-- org_subscriptions
-- One row per org. This is the canonical subscription state read by Gateway.
-- org_id maps to organizations.id in the platform DB (Django).
-- =============================================================================
CREATE TABLE org_subscriptions (
    subscription_id     UUID        NOT NULL DEFAULT uuid_generate_v4(),
    org_id              VARCHAR(255) NOT NULL,          -- FK to platform DB organizations.id
    plan_id             UUID        NOT NULL,           -- FK to subscription_plans
    stripe_customer_id  VARCHAR(255),                  -- Stripe cus_xxx; NULL for Free/override plans
    stripe_subscription_id VARCHAR(255),               -- Stripe sub_xxx; NULL for Free/override
    status              VARCHAR(50) NOT NULL DEFAULT 'trialing',
    -- Values: trialing | active | past_due | cancelled | suspended | paused | overridden
    trial_start_at      TIMESTAMPTZ,
    trial_end_at        TIMESTAMPTZ,
    current_period_start TIMESTAMPTZ,
    current_period_end   TIMESTAMPTZ,
    cancel_at_period_end BOOLEAN    NOT NULL DEFAULT false,
    cancelled_at        TIMESTAMPTZ,
    payment_failed_at   TIMESTAMPTZ,
    payment_retry_count SMALLINT    NOT NULL DEFAULT 0,
    grace_period_end_at TIMESTAMPTZ,
    -- Grace period: 7 days after first payment failure before access restricted
    is_overridden       BOOLEAN     NOT NULL DEFAULT false,
    -- True = platform_admin set this tier without Stripe payment
    override_reason     TEXT,
    override_by_user_id VARCHAR(255),
    -- Grandfathering: existing users get 90-day Pro equivalent
    grandfathered_until TIMESTAMPTZ,
    -- Cached usage counts (refreshed hourly by billing engine background task)
    accounts_connected  INTEGER     NOT NULL DEFAULT 0,
    users_count         INTEGER     NOT NULL DEFAULT 0,
    scans_last_30_days  INTEGER     NOT NULL DEFAULT 0,
    usage_cache_updated_at TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT org_subscriptions_pkey PRIMARY KEY (subscription_id),
    CONSTRAINT uq_org_subscription UNIQUE (org_id),   -- one active sub per org
    CONSTRAINT fk_os_plan FOREIGN KEY (plan_id) REFERENCES subscription_plans(plan_id)
);

CREATE INDEX idx_os_org ON org_subscriptions(org_id);
CREATE INDEX idx_os_status ON org_subscriptions(status);
CREATE INDEX idx_os_stripe_customer ON org_subscriptions(stripe_customer_id) WHERE stripe_customer_id IS NOT NULL;
CREATE INDEX idx_os_stripe_sub ON org_subscriptions(stripe_subscription_id) WHERE stripe_subscription_id IS NOT NULL;
CREATE INDEX idx_os_trial_end ON org_subscriptions(trial_end_at) WHERE status = 'trialing';
CREATE INDEX idx_os_grace_period ON org_subscriptions(grace_period_end_at) WHERE grace_period_end_at IS NOT NULL;


-- =============================================================================
-- billing_events
-- Every Stripe webhook event that caused a state change + manual operator actions.
-- Append-only. Application role has INSERT only — no UPDATE, no DELETE.
-- =============================================================================
CREATE TABLE billing_events (
    event_id        UUID        NOT NULL DEFAULT uuid_generate_v4(),
    org_id          VARCHAR(255) NOT NULL,
    event_type      VARCHAR(100) NOT NULL,
    -- e.g. subscription.upgraded, subscription.cancelled, trial.started,
    --      trial.expired, payment.succeeded, payment.failed, override.applied,
    --      suspension.applied, suspension.lifted, trial.extended
    actor_type      VARCHAR(50) NOT NULL DEFAULT 'system',
    -- 'system', 'platform_admin', 'org_admin', 'stripe_webhook'
    actor_id        VARCHAR(255),                      -- user_id or 'system'
    source_ip       INET,
    previous_state  JSONB,
    new_state       JSONB,
    stripe_event_id VARCHAR(255),                      -- Stripe event ID if triggered by webhook
    metadata        JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT billing_events_pkey PRIMARY KEY (event_id)
);

CREATE INDEX idx_be_org ON billing_events(org_id);
CREATE INDEX idx_be_event_type ON billing_events(event_type);
CREATE INDEX idx_be_created_at ON billing_events(created_at);
CREATE INDEX idx_be_stripe_event ON billing_events(stripe_event_id) WHERE stripe_event_id IS NOT NULL;
-- Composite index for audit log queries (org + date range)
CREATE INDEX idx_be_org_created ON billing_events(org_id, created_at DESC);


-- =============================================================================
-- stripe_webhook_log
-- Idempotency log. Every inbound Stripe webhook is recorded here first.
-- stripe_event_id is the deduplication key.
-- =============================================================================
CREATE TABLE stripe_webhook_log (
    id              BIGSERIAL   NOT NULL,
    stripe_event_id VARCHAR(255) NOT NULL,
    event_type      VARCHAR(100) NOT NULL,
    -- e.g. customer.subscription.updated, invoice.payment_succeeded
    received_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    processing_status VARCHAR(20) NOT NULL DEFAULT 'received',
    -- Values: received | processing | processed | failed | duplicate
    processed_at    TIMESTAMPTZ,
    error_message   TEXT,
    payload_hash    VARCHAR(64) NOT NULL,               -- SHA-256 of raw payload for verification audit
    retry_count     SMALLINT    NOT NULL DEFAULT 0,

    CONSTRAINT stripe_webhook_log_pkey PRIMARY KEY (id),
    CONSTRAINT uq_stripe_event_id UNIQUE (stripe_event_id)
    -- The UNIQUE constraint is the idempotency gate — concurrent inserts fail gracefully
);

CREATE INDEX idx_swl_event_id ON stripe_webhook_log(stripe_event_id);
CREATE INDEX idx_swl_status ON stripe_webhook_log(processing_status);
CREATE INDEX idx_swl_received_at ON stripe_webhook_log(received_at);


-- =============================================================================
-- billing_audit_log
-- SOC 2 Type II append-only audit trail.
-- Separate from billing_events — this is the formal audit record.
-- Retention: 7 years. Application role has INSERT only.
-- =============================================================================
CREATE TABLE billing_audit_log (
    log_id          UUID        NOT NULL DEFAULT uuid_generate_v4(),
    org_id          VARCHAR(255) NOT NULL,
    event_type      VARCHAR(100) NOT NULL,
    actor_id        VARCHAR(255),
    actor_email     VARCHAR(255),
    actor_role      VARCHAR(50),
    source_ip       INET,
    user_agent      TEXT,
    previous_state  JSONB,
    new_state       JSONB,
    change_summary  TEXT,
    corr_id         VARCHAR(36),                        -- correlation/request ID from gateway
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT billing_audit_log_pkey PRIMARY KEY (log_id)
);

CREATE INDEX idx_bal_org ON billing_audit_log(org_id);
CREATE INDEX idx_bal_event_type ON billing_audit_log(event_type);
CREATE INDEX idx_bal_created_at ON billing_audit_log(created_at);
CREATE INDEX idx_bal_actor ON billing_audit_log(actor_id);
-- Composite for export queries
CREATE INDEX idx_bal_org_event_created ON billing_audit_log(org_id, event_type, created_at DESC);


-- =============================================================================
-- scan_frequency_tokens
-- Rate-limit tokens per org per day. Consumed on each scan trigger.
-- Reset by a nightly cron job or on billing period rollover.
-- =============================================================================
CREATE TABLE scan_frequency_tokens (
    token_id        UUID        NOT NULL DEFAULT uuid_generate_v4(),
    org_id          VARCHAR(255) NOT NULL,
    window_date     DATE        NOT NULL,               -- YYYY-MM-DD of the current window
    tokens_used     INTEGER     NOT NULL DEFAULT 0,
    tokens_limit    INTEGER     NOT NULL DEFAULT 1,     -- -1 = unlimited
    window_type     VARCHAR(10) NOT NULL DEFAULT 'day', -- 'day' or 'week'
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT sft_pkey PRIMARY KEY (token_id),
    CONSTRAINT uq_sft_org_window UNIQUE (org_id, window_date, window_type)
);

CREATE INDEX idx_sft_org ON scan_frequency_tokens(org_id);
CREATE INDEX idx_sft_window ON scan_frequency_tokens(window_date);


-- =============================================================================
-- platform_admin_audit
-- Operator action log for engine-platform-admin actions.
-- Separate from billing_audit_log. Append-only.
-- =============================================================================
CREATE TABLE platform_admin_audit (
    audit_id        UUID        NOT NULL DEFAULT uuid_generate_v4(),
    admin_user_id   VARCHAR(255) NOT NULL,
    admin_email     VARCHAR(255),
    action          VARCHAR(100) NOT NULL,
    -- e.g. org.tier_override, org.trial_extend, org.suspend, org.unsuspend,
    --      org.notification_sent, plan.create, plan.update, plan.deactivate
    target_org_id   VARCHAR(255),
    target_entity   VARCHAR(50),                        -- 'org', 'plan', 'engine'
    payload         JSONB       NOT NULL DEFAULT '{}'::jsonb,
    source_ip       INET,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT platform_admin_audit_pkey PRIMARY KEY (audit_id)
);

CREATE INDEX idx_paa_admin ON platform_admin_audit(admin_user_id);
CREATE INDEX idx_paa_org ON platform_admin_audit(target_org_id);
CREATE INDEX idx_paa_action ON platform_admin_audit(action);
CREATE INDEX idx_paa_created ON platform_admin_audit(created_at);
```

### 2.1 DB Isolation and Access Model

| Role | Permissions | Purpose |
|------|-------------|---------|
| `billing_app` | INSERT, SELECT, UPDATE on billing tables; no DELETE | engine-billing runtime |
| `billing_readonly` | SELECT only on billing tables | engine-platform-admin, Gateway cache queries |
| `billing_audit_writer` | INSERT only on `billing_audit_log`, `platform_admin_audit` | Append-only audit enforcement |

The `billing_app` role has no UPDATE or DELETE on `billing_audit_log` or `platform_admin_audit`. This is enforced at the database role level, not application level — satisfying the SOC 2 append-only requirement.

Credentials for all three roles are stored in AWS Secrets Manager:
- `threat-engine/billing/db-credentials` — billing_app credentials
- `threat-engine/billing/db-readonly` — billing_readonly credentials

### 2.2 Django Platform DB Extensions (cspm-backend migration 0010)

Three new rows added to the existing `permissions` table and associated `role_permissions` rows:

```sql
-- Migration 0010 (Django ORM)
-- Applied to cspm_platform database, NOT billing DB

INSERT INTO permissions (name, description) VALUES
  ('billing:read',    'View subscription plan, usage, and invoice history'),
  ('billing:write',   'Upgrade, downgrade, cancel subscription; manage payment methods'),
  ('platform:admin',  'Full operator access: engine health, org management, billing overrides');

-- org_admin gets billing:read + billing:write
-- tenant_admin gets billing:read
-- platform_admin gets all 3

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE (r.name = 'org_admin'       AND p.name IN ('billing:read', 'billing:write'))
   OR (r.name = 'tenant_admin'    AND p.name IN ('billing:read'))
   OR (r.name = 'platform_admin'  AND p.name IN ('billing:read', 'billing:write', 'platform:admin'));
```

Updated permission matrix (addendum to RBAC.md):

| Permission | viewer | analyst | tenant_admin | org_admin | platform_admin |
|-----------|:------:|:-------:|:------------:|:---------:|:--------------:|
| `billing:read` | — | — | Y | Y | Y |
| `billing:write` | — | — | — | Y | Y |
| `platform:admin` | — | — | — | — | Y |

The `user_sessions.permissions_cache` JSONB array is populated at login time from this table. No new Django models are needed for the permission/role tables — migration 0010 only adds rows to existing tables.

---

## 3. API Contracts

### 3.1 engine-billing (Port 8040)

All endpoints require `X-Auth-Context` header (enforced via `require_permission()`). Unauthenticated requests return 401.

#### Health

```
GET  /api/v1/health/live    → 200 {"status": "ok"}
GET  /api/v1/health/ready   → 200 {"status": "ok", "db": "connected"}
```

#### Plans

```
GET  /api/v1/billing/plans
     Auth: any authenticated user (no permission restriction — plan listing is public-facing)
     Response 200:
     {
       "plans": [
         {
           "plan_id": "uuid",
           "plan_name": "pro",
           "display_name": "Pro",
           "price_monthly": 99.00,
           "max_accounts": 10,
           "max_users": 25,
           "scan_freq_per_day": 4,
           "data_retention_days": 90,
           "engine_allowlist": ["discoveries", "check", ...],
           "stripe_price_id": "price_xxx"
         },
         ...
       ]
     }

GET  /api/v1/billing/plans/{plan_id}
     Auth: any authenticated user
     Response 200: single plan object as above

POST /api/v1/billing/plans
     Permission: platform:admin
     Request body:
     {
       "plan_name": "string",
       "display_name": "string",
       "price_monthly": 0.00,
       "stripe_price_id": "price_xxx",
       "max_accounts": 10,
       "max_users": 25,
       "scan_freq_per_day": 4,
       "data_retention_days": 90,
       "engine_allowlist": ["discoveries", ...]
     }
     Response 201: created plan object

PATCH /api/v1/billing/plans/{plan_id}
     Permission: platform:admin
     Request body: any subset of plan fields (partial update)
     Response 200: updated plan object

DELETE /api/v1/billing/plans/{plan_id}
     Permission: platform:admin
     Soft delete: sets is_active=false, does NOT hard-delete (existing subs reference this plan)
     Response 204
```

#### Subscription (per-org)

```
GET  /api/v1/billing/subscription
     Permission: billing:read
     Query param: org_id (required — Gateway injects from AuthContext.org_id)
     Response 200:
     {
       "subscription_id": "uuid",
       "org_id": "string",
       "plan": { ...plan object... },
       "status": "active",
       "trial_end_at": "2026-05-16T00:00:00Z",
       "trial_days_remaining": 14,
       "current_period_end": "2026-06-02T00:00:00Z",
       "cancel_at_period_end": false,
       "accounts_connected": 2,
       "max_accounts": 10,
       "users_count": 4,
       "max_users": 25,
       "scans_last_30_days": 12,
       "is_overridden": false
     }

POST /api/v1/billing/checkout
     Permission: billing:write
     Request body:
     {
       "plan_id": "uuid",
       "success_url": "https://app.threatengine.io/billing?success=true",
       "cancel_url": "https://app.threatengine.io/billing?cancelled=true"
     }
     Response 200:
     {
       "checkout_url": "https://checkout.stripe.com/pay/cs_xxx",
       "session_id": "cs_xxx"
     }
     Note: billing engine creates Stripe Checkout Session, returns URL to frontend.
     Frontend redirects user to Stripe-hosted page.

POST /api/v1/billing/cancel
     Permission: billing:write
     Request body: { "org_id": "string", "cancel_reason": "string" }
     Response 200:
     {
       "message": "Subscription will cancel at end of billing period",
       "cancel_at": "2026-06-02T00:00:00Z"
     }

POST /api/v1/billing/reactivate
     Permission: billing:write
     Cancels a pending cancellation (cancel_at_period_end → false)
     Request body: { "org_id": "string" }
     Response 200: { "message": "Subscription reactivated" }
```

#### Stripe Webhook Handler

```
POST /api/v1/billing/webhooks/stripe
     Auth: NONE (Stripe calls this endpoint directly)
     Headers: Stripe-Signature (HMAC-SHA256, validated before processing)
     Request body: raw Stripe event JSON
     Response 200: { "received": true }     — always return 200 to Stripe
     Response 400: { "error": "invalid_signature" }  — bad signature only

     Idempotency: stripe_event_id UNIQUE constraint prevents double-processing.
     Handler logic:
       1. Validate Stripe-Signature header using HMAC-SHA256
       2. INSERT INTO stripe_webhook_log (stripe_event_id, ...) ON CONFLICT DO NOTHING
       3. If affected rows = 0: return 200 (duplicate, already processed)
       4. Process event (update org_subscriptions, write billing_events, billing_audit_log)
       5. UPDATE stripe_webhook_log SET processing_status='processed'

     Handled event types:
       customer.subscription.created        → status=active, set period dates
       customer.subscription.updated        → detect plan change, downgrade handling
       customer.subscription.deleted        → status=cancelled
       invoice.payment_succeeded            → status=active, clear payment_retry_count
       invoice.payment_failed               → increment retry, set payment_failed_at
       customer.subscription.trial_will_end → emit billing_event (trigger email in Phase 2)
```

#### Usage

```
GET  /api/v1/billing/usage
     Permission: billing:read
     Query param: org_id
     Response 200:
     {
       "org_id": "string",
       "accounts_connected": 2,
       "accounts_limit": 10,
       "accounts_pct": 20,
       "users_count": 4,
       "users_limit": 25,
       "scans_today": 1,
       "scans_daily_limit": 4,
       "scan_tokens_remaining": 3,
       "data_retention_days": 90
     }

GET  /api/v1/billing/usage/check-account-limit
     Permission: billing:read (also called by engine-onboarding internally)
     Query param: org_id
     Response 200:
     {
       "allowed": true,
       "accounts_connected": 2,
       "limit": 10,
       "upgrade_url": null
     }
     Response 200 (at limit):
     {
       "allowed": false,
       "accounts_connected": 1,
       "limit": 1,
       "current_tier": "free",
       "upgrade_url": "/billing/upgrade?from=account_limit"
     }

GET  /api/v1/billing/usage/check-scan-frequency
     Permission: billing:read (also called by Gateway scan enforcement)
     Query param: org_id
     Response 200: { "allowed": true, "tokens_remaining": 3 }
     Response 200 (exhausted): { "allowed": false, "tokens_remaining": 0, "reset_at": "2026-05-03T00:00:00Z" }
```

#### Invoice History

```
GET  /api/v1/billing/invoices
     Permission: billing:read
     Query param: org_id, limit (default 20), offset
     Response 200:
     {
       "invoices": [
         {
           "invoice_id": "in_xxx",
           "amount_paid": 9900,
           "currency": "usd",
           "status": "paid",
           "invoice_date": "2026-05-01T00:00:00Z",
           "period_start": "2026-05-01",
           "period_end": "2026-05-31",
           "hosted_invoice_url": "https://invoice.stripe.com/..."
         }
       ],
       "total": 3
     }
     Note: Fetched live from Stripe API, not stored locally (no PCI scope creep).
```

#### Billing Audit Log (admin only)

```
GET  /api/v1/billing/audit-log
     Permission: platform:admin
     Query params: org_id (optional), event_type (optional), from_date, to_date, limit, offset
     Response 200:
     {
       "events": [ ...billing_audit_log rows... ],
       "total": 42
     }
```

### 3.2 engine-platform-admin (Port 8041)

All endpoints require `platform:admin` permission. Non-platform_admin roles receive 403.

#### Health

```
GET  /api/v1/health/live    → 200
GET  /api/v1/health/ready   → 200
```

#### Engine Health Dashboard

```
GET  /api/v1/padmin/engines/health
     Permission: platform:admin
     Response 200:
     {
       "engines": [
         {
           "engine_name": "engine-discoveries",
           "pod_status": "running",       -- from K8s API: pod.status.phase
           "pod_count": 2,
           "ready_pods": 2,
           "last_restart_at": "2026-05-01T10:00:00Z",
           "restart_count": 0,
           "health_check_status": "ok",   -- result of calling /api/v1/health/live
           "health_check_latency_ms": 8,
           "error_rate_pct": 0.1,         -- from last 5 min of pod logs (parsed)
           "last_checked_at": "2026-05-02T09:00:00Z"
         },
         ...18 engines total...
       ],
       "summary": {
         "total_engines": 18,
         "healthy": 17,
         "degraded": 1,
         "down": 0
       }
     }

GET  /api/v1/padmin/engines/{engine_name}/health
     Single engine detail — same shape as above entry, plus last 10 error log lines.

GET  /api/v1/padmin/engines/{engine_name}/pods
     Permission: platform:admin
     Response 200: K8s pod list for this engine (name, status, node, restarts, age)
```

#### Argo Pipeline Status

```
GET  /api/v1/padmin/pipeline/runs
     Permission: platform:admin
     Query params: org_id (optional), limit (default 50), status (optional)
     Response 200:
     {
       "runs": [
         {
           "workflow_name": "cspm-pipeline-xxx",
           "org_id": "string",
           "tenant_id": "string",
           "scan_run_id": "uuid",
           "status": "Succeeded",   -- Argo workflow phase: Pending|Running|Succeeded|Failed|Error
           "started_at": "2026-05-02T08:00:00Z",
           "completed_at": "2026-05-02T08:07:32Z",
           "duration_seconds": 452,
           "failed_steps": [],
           "created_at": "2026-05-02T08:00:00Z"
         }
       ],
       "total": 150
     }

GET  /api/v1/padmin/pipeline/runs/{workflow_name}
     Single run detail — includes per-step status and error messages.
```

#### Org Management

```
GET  /api/v1/padmin/orgs
     Permission: platform:admin
     Query params: status (optional), tier (optional), limit, offset, search
     Response 200:
     {
       "orgs": [
         {
           "org_id": "string",
           "org_name": "string",
           "plan_name": "pro",
           "subscription_status": "active",
           "accounts_connected": 3,
           "users_count": 8,
           "last_scan_at": "2026-05-01T22:00:00Z",
           "trial_end_at": null,
           "payment_failed_at": null,
           "created_at": "2026-04-01T00:00:00Z"
         }
       ],
       "total": 23,
       "summary": {
         "active": 18,
         "trialing": 4,
         "past_due": 1,
         "cancelled": 0
       }
     }

GET  /api/v1/padmin/orgs/{org_id}
     Single org detail: subscription state + usage + recent billing events + recent pipeline runs.

PATCH /api/v1/padmin/orgs/{org_id}/subscription
     Permission: platform:admin
     Override tier without Stripe checkout.
     Request body:
     {
       "plan_name": "enterprise",   -- or "pro", "starter", "free"
       "reason": "Sales override for pilot",
       "expires_at": "2026-08-01T00:00:00Z"  -- optional; NULL = permanent
     }
     Response 200: { "message": "Subscription overridden", "subscription": {...} }
     Side effect: writes billing_audit_log, platform_admin_audit, billing_events

PATCH /api/v1/padmin/orgs/{org_id}/trial
     Permission: platform:admin
     Extend trial period.
     Request body:
     {
       "extend_days": 14,
       "reason": "Customer requested demo extension"
     }
     Response 200: { "new_trial_end_at": "2026-05-30T00:00:00Z" }

PATCH /api/v1/padmin/orgs/{org_id}/suspend
     Permission: platform:admin
     Sets status=suspended. Scan access immediately blocked at Gateway.
     Request body: { "reason": "string" }
     Response 200: { "message": "Org suspended" }

PATCH /api/v1/padmin/orgs/{org_id}/unsuspend
     Permission: platform:admin
     Restores prior status.
     Response 200: { "message": "Org unsuspended" }

POST /api/v1/padmin/orgs/{org_id}/notify
     Permission: platform:admin
     Send manual platform notification (Phase 2: email/Slack).
     Request body: { "subject": "string", "message": "string", "channel": "email" }
     Response 200: { "message": "Notification queued" }
```

#### Platform Metrics

```
GET  /api/v1/padmin/metrics
     Permission: platform:admin
     Response 200:
     {
       "total_orgs": 23,
       "orgs_by_tier": { "free": 10, "starter": 5, "pro": 7, "enterprise": 1 },
       "orgs_by_status": { "active": 18, "trialing": 4, "past_due": 1, "cancelled": 0 },
       "scans_last_24h": 47,
       "total_findings_all_time": 1500000,
       "new_orgs_last_7d": 3,
       "trials_expiring_7d": 2,
       "trials_expiring_1d": 0,
       "past_due_orgs": 1
     }
```

#### Operator Audit Log

```
GET  /api/v1/padmin/audit-log
     Permission: platform:admin
     Query params: action (optional), from_date, to_date, limit, offset
     Response 200:
     {
       "events": [ ...platform_admin_audit rows... ],
       "total": 88
     }
```

---

## 4. Gateway Enforcement Design

### 4.1 SubscriptionMiddleware — Design

The existing `AuthMiddleware` in `/Users/apple/Desktop/threat-engine/shared/api_gateway/main.py` runs first. After it sets `X-Auth-Context`, the new `SubscriptionMiddleware` runs.

The middleware MUST NOT be in the hot path for every request on first call — subscription state is cached in the process for 60 seconds per org (LRU cache keyed by org_id).

```python
# Pseudocode — lives in shared/api_gateway/subscription_middleware.py

class SubscriptionMiddleware:
    """
    Runs after AuthMiddleware. Reads org subscription from billing engine
    (cached per org_id, TTL=60s). Injects X-Subscription-Context header.
    Fail-open: if billing engine is unreachable, allows request through
    with tier=unknown (downstream engines treat unknown as current session tier).
    Fail-closed: if org is suspended, returns 402 immediately.
    """
    CACHE_TTL_SECONDS = 60
    BILLING_ENGINE_URL = os.getenv("BILLING_ENGINE_URL", "http://engine-billing:8040")
    _cache: dict[str, tuple[dict, float]] = {}   # org_id → (context, expire_ts)

    async def dispatch(self, request: Request, call_next):
        # 1. Extract AuthContext from header (already set by AuthMiddleware)
        auth_ctx = parse_auth_context(request.headers.get("X-Auth-Context"))
        if auth_ctx is None:
            # No auth context = unauthenticated; AuthMiddleware already returned 401
            return await call_next(request)

        org_id = auth_ctx.get("org_id")
        if not org_id:
            # platform_admin without org_id context — pass through unrestricted
            request.state.subscription = {"tier": "enterprise", "status": "active"}
            return await call_next(request)

        # 2. Check cache
        sub_ctx = self._get_cached(org_id)
        if sub_ctx is None:
            sub_ctx = await self._fetch_subscription(org_id)
            self._set_cache(org_id, sub_ctx)

        # 3. Check suspension — the only fail-closed case
        if sub_ctx.get("status") == "suspended":
            return JSONResponse(
                status_code=402,
                content={
                    "error": "org_suspended",
                    "message": "Your organization access has been suspended. Contact support.",
                    "upgrade_url": None
                }
            )

        # 4. Inject header
        sub_header = base64.b64encode(json.dumps(sub_ctx).encode()).decode()
        request.headers.__dict__["_list"].append(
            (b"x-subscription-context", sub_header.encode())
        )
        return await call_next(request)

    async def _fetch_subscription(self, org_id: str) -> dict:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(
                    f"{self.BILLING_ENGINE_URL}/api/v1/billing/subscription",
                    params={"org_id": org_id},
                    headers={"X-Internal-Call": "gateway"}
                )
                data = resp.json()
                return {
                    "org_id": org_id,
                    "tier": data["plan"]["plan_name"],       # 'free', 'starter', 'pro', 'enterprise'
                    "status": data["status"],                # 'active', 'trialing', 'past_due', etc.
                    "max_accounts": data["plan"]["max_accounts"],
                    "accounts_connected": data["accounts_connected"],
                    "engine_allowlist": data["plan"]["engine_allowlist"],
                    "scan_freq_per_day": data["plan"]["scan_freq_per_day"],
                    "trial_end_at": data.get("trial_end_at"),
                    "is_overridden": data.get("is_overridden", False)
                }
        except Exception:
            # Fail-open: billing engine unreachable
            logger.warning(f"Billing engine unreachable for org {org_id}; failing open")
            return {
                "org_id": org_id,
                "tier": "unknown",
                "status": "unknown",
                "engine_allowlist": None,   # None = allow all (fail-open)
                "max_accounts": -1,
                "accounts_connected": 0,
                "scan_freq_per_day": -1
            }
```

### 4.2 X-Subscription-Context Header Shape

```json
{
  "org_id": "org-uuid",
  "tier": "pro",
  "status": "active",
  "max_accounts": 10,
  "accounts_connected": 3,
  "engine_allowlist": ["discoveries", "check", "threat", "inventory", "compliance", "iam", "ciem", "network-security", "risk", "datasec", "secops", "vulnerability"],
  "scan_freq_per_day": 4,
  "trial_end_at": null,
  "is_overridden": false
}
```

The header value is base64-encoded JSON, same pattern as `X-Auth-Context`.

### 4.3 Engine-Side 402 Enforcement (Zero Code Change Required)

Engines already have the `require_permission()` FastAPI dependency. The 402 enforcement does NOT need code changes in existing engines. Instead, the Gateway itself enforces it at the proxy layer before forwarding:

```python
# In Gateway's proxy handler (main.py), add subscription check:

def check_subscription_access(request: Request, target_engine: str) -> Optional[JSONResponse]:
    """
    Returns a 402 JSONResponse if the org's subscription does not allow
    access to target_engine. Returns None if access is allowed.
    Called in the proxy handler before forwarding to upstream.
    """
    sub = parse_subscription_context(request.headers.get("X-Subscription-Context"))
    if sub is None or sub.get("tier") == "unknown":
        return None  # fail-open

    allowlist = sub.get("engine_allowlist")
    if allowlist is None:
        return None  # fail-open (billing engine was unreachable)

    if target_engine not in allowlist:
        tier = sub.get("tier", "unknown")
        required_tier = _get_required_tier(target_engine)  # lookup from plan definitions
        return JSONResponse(
            status_code=402,
            content={
                "error": "engine_not_in_plan",
                "engine": target_engine,
                "current_tier": tier,
                "required_tier": required_tier,
                "limit_type": "engine_tier",
                "upgrade_url": f"/billing/upgrade?from=engine&engine={target_engine}"
            }
        )
    return None
```

The Gateway already knows which engine prefix maps to which service name (from `SERVICE_ROUTES`). This check is inserted into the proxy handler before the upstream `httpx` call.

### 4.4 Scan Frequency Enforcement

For `scans:create` requests (specifically `POST /api/v1/scan-runs` forwarded to engine-onboarding), the Gateway calls `GET /api/v1/billing/usage/check-scan-frequency` before forwarding. If `allowed=false`, the Gateway returns 429 with structured body.

### 4.5 Account Limit Enforcement

engine-onboarding's account creation endpoint (`POST /api/v1/cloud-accounts`) is intercepted by the Gateway. Before forwarding, the Gateway checks `accounts_connected >= max_accounts` from the cached subscription context. This is a synchronous in-memory check — no extra HTTP call needed since the data is already in `X-Subscription-Context`.

### 4.6 Fail-Open Boundary

| Scenario | Behavior | Rationale |
|----------|----------|-----------|
| Billing engine DOWN | Allow all reads; block new scan triggers | SOC 2: availability > revenue enforcement |
| Billing engine slow (>5s) | Timeout, use cached sub_ctx | p99 ≤10ms target met via cache |
| Cache miss (first request) | Synchronous fetch from billing engine | <50ms billing engine response target |
| Org status = suspended | Return 402 immediately | Suspension is explicit operator action |
| Org status = past_due (in grace) | Allow access (7-day grace) | Reduce churn from transient failures |
| Stripe event processing failure | Retry 3x, then alert (no silent failure) | Webhook retries from Stripe are expected |

---

## 5. Stripe Integration Design

### 5.1 Checkout Session Creation Flow

```
org_admin → POST /api/v1/billing/checkout (via Gateway)
    │
    ├── engine-billing validates:
    │     - org is not already on this plan
    │     - plan exists and is_active=true
    │
    ├── Create/retrieve Stripe Customer:
    │     - If org has stripe_customer_id: use existing
    │     - Else: stripe.Customer.create(email=org_email, metadata={"org_id": org_id})
    │     - Store customer_id in org_subscriptions
    │
    ├── Create Stripe Checkout Session:
    │     stripe.checkout.Session.create(
    │       customer=stripe_customer_id,
    │       mode="subscription",
    │       line_items=[{"price": plan.stripe_price_id, "quantity": 1}],
    │       success_url=request.success_url + "?session_id={CHECKOUT_SESSION_ID}",
    │       cancel_url=request.cancel_url,
    │       subscription_data={
    │         "trial_period_days": 0,  # no extra trial if already had one
    │         "metadata": {"org_id": org_id, "plan_id": plan_id}
    │       },
    │       metadata={"org_id": org_id, "plan_id": plan_id}
    │     )
    │
    └── Return: { "checkout_url": session.url, "session_id": session.id }

Frontend redirects to checkout_url (Stripe-hosted page).
After payment: Stripe redirects to success_url.
Stripe webhook fires customer.subscription.created → billing engine updates org_subscriptions.
```

### 5.2 Webhook Event Handling (Idempotent)

```python
# Pseudocode for webhook handler

@app.post("/api/v1/billing/webhooks/stripe")
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig_header = request.headers.get("Stripe-Signature")

    # Step 1: Validate signature
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, settings.STRIPE_WEBHOOK_SECRET
        )
    except stripe.error.SignatureVerificationError:
        return JSONResponse(status_code=400, content={"error": "invalid_signature"})

    # Step 2: Idempotency gate — INSERT with UNIQUE constraint
    payload_hash = hashlib.sha256(payload).hexdigest()
    inserted = await db.execute(
        """INSERT INTO stripe_webhook_log
           (stripe_event_id, event_type, payload_hash, processing_status)
           VALUES ($1, $2, $3, 'processing')
           ON CONFLICT (stripe_event_id) DO NOTHING""",
        event.id, event.type, payload_hash
    )
    if inserted == 0:
        # Duplicate event — already processed
        return JSONResponse(content={"received": True, "duplicate": True})

    # Step 3: Dispatch to handler
    try:
        await handle_stripe_event(event)
        await db.execute(
            "UPDATE stripe_webhook_log SET processing_status='processed', processed_at=now() WHERE stripe_event_id=$1",
            event.id
        )
    except Exception as e:
        await db.execute(
            "UPDATE stripe_webhook_log SET processing_status='failed', error_message=$1 WHERE stripe_event_id=$2",
            str(e), event.id
        )
        raise  # Let Stripe retry

    return JSONResponse(content={"received": True})
```

### 5.3 Handled Stripe Events

| Stripe Event | Action in billing engine |
|-------------|--------------------------|
| `customer.subscription.created` | Set status=active, set period dates, write billing_event |
| `customer.subscription.updated` | Detect plan change; if downgrade: set cancel_at_period_end or update plan_id |
| `customer.subscription.deleted` | Set status=cancelled, write billing_event + audit_log |
| `invoice.payment_succeeded` | Set status=active, clear payment_failed_at, reset retry_count |
| `invoice.payment_failed` | Increment retry_count, set payment_failed_at, set grace_period_end_at (+7 days) |
| `customer.subscription.trial_will_end` | Write billing_event (email hook in Phase 2) |

### 5.4 Stripe Secrets Management

```python
# In engine-billing startup — uses existing secrets_utils.py pattern

import boto3, json

def get_stripe_secrets():
    client = boto3.client("secretsmanager", region_name="ap-south-1")
    secret = client.get_secret_value(SecretId="threat-engine/billing/stripe")
    data = json.loads(secret["SecretString"])
    return {
        "api_key": data["STRIPE_SECRET_KEY"],           # sk_live_xxx
        "webhook_secret": data["STRIPE_WEBHOOK_SECRET"]  # whsec_xxx
    }
```

Secret `threat-engine/billing/stripe` structure:
```json
{
  "STRIPE_SECRET_KEY": "sk_live_xxx",
  "STRIPE_PUBLISHABLE_KEY": "pk_live_xxx",
  "STRIPE_WEBHOOK_SECRET": "whsec_xxx"
}
```

The `optional: false` pattern is enforced — if the secret is missing at startup, engine-billing fails its readiness probe and does not start.

### 5.5 Per-Environment Webhook Secrets

Answer to Open Question 4: Each environment (dev/staging/prod) has a separate Secrets Manager secret path:
- `threat-engine/billing/stripe-dev`
- `threat-engine/billing/stripe-staging`
- `threat-engine/billing/stripe`  (production)

The environment is set via `APP_ENV` environment variable in the K8s manifest. The `get_stripe_secrets()` function uses `APP_ENV` to select the correct path.

---

## 6. Data Flow Diagrams

### 6.1 Upgrade Flow (Priya Happy Path)

```
org_admin Browser
     │
     ├─1── GET /api/v1/billing/subscription     → show current plan (Free, 1 account)
     │
     ├─2── GET /api/v1/billing/plans            → show upgrade options
     │
     ├─3── POST /api/v1/billing/checkout        → engine-billing creates Stripe Session
     │     { plan_id: "pro" }                      Returns checkout_url
     │
     ├─4── [Browser redirects to Stripe Checkout — no Threat Engine server involved]
     │
     ├─5── [User enters card data on Stripe-hosted page]
     │
     ├─6── [Stripe redirects to success_url]
     │
     │     [In parallel, Stripe fires webhook]:
     │     POST /api/v1/billing/webhooks/stripe
     │       event: customer.subscription.created
     │       │
     │       ├── Idempotency check (stripe_webhook_log INSERT)
     │       ├── UPDATE org_subscriptions SET plan_id=pro, status=active
     │       ├── INSERT billing_events (subscription.upgraded)
     │       ├── INSERT billing_audit_log
     │       └── Invalidate Gateway subscription cache for org_id
     │
     ├─7── [On next API request, Gateway fetches fresh subscription from billing engine]
     │     X-Subscription-Context now shows tier=pro, max_accounts=10
     │
     └─8── org_admin connects GCP account — passes account limit check ✓
```

### 6.2 Scan Enforcement Flow

```
org_admin triggers scan
     │
     ├─1── POST /api/v1/scan-runs → Gateway proxy handler
     │
     ├─2── Gateway: parse X-Subscription-Context
     │     Check: accounts_connected <= max_accounts? → YES
     │     Check: scan_freq_per_day (tokens remaining > 0)? 
     │           → Call GET /api/v1/billing/usage/check-scan-frequency
     │
     ├─3── [If tokens exhausted]:
     │     Gateway returns 429:
     │     { "error": "scan_frequency_exceeded",
     │       "current_tier": "free", "limit": 1, "window": "week",
     │       "reset_at": "2026-05-09T00:00:00Z",
     │       "upgrade_url": "/billing/upgrade?from=scan_frequency" }
     │
     ├─4── [If tokens available]:
     │     Gateway forwards to engine-onboarding
     │     engine-onboarding creates scan_orchestration record
     │     Argo pipeline fires
     │
     └─5── [On successful scan trigger]:
           POST /api/v1/billing/usage/consume-scan-token
           { org_id, window_date }
           billing engine: UPDATE scan_frequency_tokens SET tokens_used = tokens_used + 1
```

### 6.3 Trial Expiry Flow (Automated)

```
Background task in engine-billing (runs every hour via APScheduler):

  SELECT * FROM org_subscriptions
  WHERE status = 'trialing'
    AND trial_end_at < now()
    AND stripe_customer_id IS NULL;   -- no payment method = auto-downgrade

  For each expired trial:
    1. UPDATE org_subscriptions SET
         plan_id = <free_plan_id>,
         status = 'active',           -- active but on Free tier
         updated_at = now()
       WHERE org_id = $1

    2. INSERT billing_events (event_type='trial.expired', ...)
    3. INSERT billing_audit_log
    4. Invalidate Gateway subscription cache for org_id
    5. [Phase 2]: Enqueue email notification
```

### 6.4 Account Limit Hit Flow (Priya Edge Case)

```
CI/CD pipeline → POST /api/v1/cloud-accounts → Gateway

  Gateway reads X-Subscription-Context:
  { tier: "free", accounts_connected: 1, max_accounts: 1 }

  Check: 1 >= 1 → BLOCKED

  Gateway returns 402 (before forwarding to onboarding engine):
  {
    "error": "account_limit_exceeded",
    "current": 1,
    "limit": 1,
    "current_tier": "free",
    "required_tier": "starter",
    "limit_type": "max_accounts",
    "upgrade_url": "/billing/upgrade?from=account_limit"
  }

  [No request ever reaches engine-onboarding]
  [No partial state created]
  [CI/CD logs 402, notifies team via Slack]
  [org_admin upgrades → cache invalidated → retry succeeds]
```

---

## 7. Security Design

### 7.1 STRIDE Threat Model — engine-billing

| Threat | STRIDE | Attack | Mitigation |
|--------|--------|--------|-----------|
| Spoofed Stripe webhook | S | Attacker POSTs fake payment_succeeded event to activate subscription | HMAC-SHA256 Stripe-Signature validation before any processing. Invalid signature → 400, no processing. |
| Tampered X-Subscription-Context | T | Attacker injects higher-tier header to bypass engine gating | Header is set by Gateway on internal cluster network. Engines must not accept this header from external requests. Gateway strips inbound X-Subscription-Context before injecting its own. |
| Replay attack on checkout URL | R | Reuse a Stripe checkout session after expiry | Stripe Checkout Sessions expire after 24h. success_url validates `session_id` against Stripe API before activating trial. |
| Escalate plan via PATCH /plans | E | org_admin tries to call admin plan endpoint | `require_permission("platform:admin")` on all plan write endpoints. org_admin only has billing:write which covers checkout/cancel only. |
| Billing DB injection via org_id | I | Attacker crafts org_id query param to access other org's subscription | org_id always extracted from AuthContext (server-resolved), never from request body/query in billing endpoints. Billing engine validates org_id == auth_ctx.org_id unless caller is platform_admin. |
| Webhook denial of service | D | Flood webhook endpoint with fake events | Rate limiting on webhook endpoint (100 req/s per IP). HMAC validation is fast (constant-time compare). Invalid signature returns 400 immediately without DB write. |
| Subscription state cache poisoning | S | Attacker invalidates cache for another org | Cache is keyed by org_id extracted from authenticated session. Cache invalidation endpoint is internal-only, not exposed externally. |

### 7.2 PCI-DSS SAQ A-EP Scope Boundary

```
OUT OF PCI SCOPE:
  - Threat Engine servers (they never see raw card data)
  - Billing database (stores only stripe_customer_id and stripe_subscription_id)
  - API Gateway (proxies to Stripe CDN for Stripe.js)

IN PCI SCOPE (SAQ A-EP):
  - The frontend page that loads Stripe.js
    → Stripe.js served from Stripe CDN, not from Threat Engine CDN
    → Only the page HTML/JS that loads Stripe.js is in scope
  - TLS on the success_url redirect (must be HTTPS)
  - The Stripe webhook endpoint (receives signed payloads, no raw card data)

Controls required for SAQ A-EP:
  1. TLS 1.2+ on all external-facing endpoints (enforced at ELB/ALB level)
  2. Stripe.js must load from js.stripe.com, never self-hosted
  3. Content-Security-Policy header must include: script-src 'self' js.stripe.com
  4. Webhook endpoint validates Stripe-Signature before ANY processing
  5. No logging of Stripe payload raw body (only the SHA-256 hash is stored)
  6. Annual SAQ A-EP self-assessment (Stripe provides pre-filled documentation)
```

### 7.3 Billing Audit Log — Append-Only Enforcement

The `billing_app` Postgres role has no UPDATE or DELETE on `billing_audit_log` or `platform_admin_audit`. This is enforced at the DB level:

```sql
-- Applied when creating billing_app role:
GRANT INSERT, SELECT ON billing_audit_log TO billing_app;
GRANT INSERT, SELECT ON platform_admin_audit TO billing_app;
-- Deliberately NO UPDATE, NO DELETE grants
```

Application code must never use raw SQL UPDATE/DELETE on these tables. Code review checklist item for billing engine PRs.

### 7.4 PASTA — engine-billing (7-Stage Adversary Model)

**Stage 1 — Define Objectives:** Revenue capture via subscription gating. Adversary objective: obtain Pro/Enterprise access without payment.

**Stage 2 — Define Technical Scope:** engine-billing, Stripe API, AWS Secrets Manager, org_subscriptions table, X-Subscription-Context header injection.

**Stage 3 — Application Decomposition:** Checkout flow, webhook handler, subscription state query API, Gateway enforcement check.

**Stage 4 — Threat Analysis:**
- Primary: subscription state manipulation (webhook replay, DB tampering)
- Secondary: Stripe key theft from Secrets Manager
- Tertiary: Gateway cache bypass (crafting direct engine calls)

**Stage 5 — Vulnerability Analysis:**
- Webhook endpoint exposed to internet (required by Stripe): mitigated by HMAC-SHA256 signature validation
- Gateway cache (60s TTL): 60-second window after downgrade where old tier persists — acceptable for read operations; scan creation has lower TTL (instant invalidation on subscription change)

**Stage 6 — Attack Enumeration:**
- Forged webhook: blocked by HMAC validation
- Stolen Stripe key: mitigated by Secrets Manager (no env vars), key rotation procedure
- Direct engine-billing call bypassing Gateway: engine-billing verifies org_id ownership before returning subscription data

**Stage 7 — Risk and Impact Analysis:**
- Highest risk: Stripe webhook secret theft → attacker can forge payment_succeeded events → unauthorized tier upgrade. Mitigation: rotate secret on any suspected exposure; monitor for unexpected subscription upgrades in billing_audit_log.

### 7.5 OWASP SAMM Checklist — engine-billing

| SAMM Function | Activity | Status |
|--------------|----------|--------|
| Design — Threat Assessment | STRIDE + PASTA above | Complete |
| Design — Security Requirements | PCI SAQ A-EP scope, SOC 2 audit log, GDPR data residency | Defined |
| Implementation — Secure Build | Pinned base image, no `latest` tag, SLSA Level 1 | Required in K8s manifest |
| Implementation — Secure Deployment | Stripe secrets via Secrets Manager, `optional:false` pattern | Defined |
| Verification — Security Testing | Webhook HMAC test, 402 enforcement test, duplicate event test | Required in Epic 3 |
| Operations — Incident Management | billing_audit_log provides forensic trail | Defined |

### 7.6 Webhook Endpoint Hardening

The Stripe webhook endpoint (`POST /api/v1/billing/webhooks/stripe`) is special:
- No `X-Auth-Context` required (Stripe cannot authenticate via session cookie)
- Must be accessible from Stripe IP ranges
- Rate limited to 100 req/min per source IP
- Signature validated in constant time (using `hmac.compare_digest`)
- Raw payload body NOT logged (only SHA-256 hash stored for audit)

Stripe IP ranges are documented at `https://stripe.com/docs/ips`. Gateway should NOT enforce Auth middleware on this specific endpoint path.

---

## 8. K8s Manifest Sketches

### 8.1 engine-billing Deployment + Service

File path: `/Users/apple/Desktop/threat-engine/deployment/aws/eks/engines/engine-billing.yaml`

```yaml
# =============================================================================
# Billing Engine — Subscription, Stripe Integration, Usage Metering
# Port: 8040 | Billing DB: threat_engine_billing
# =============================================================================
apiVersion: apps/v1
kind: Deployment
metadata:
  name: engine-billing
  namespace: threat-engine-engines
  labels:
    app: engine-billing
    engine: billing
    layer: "commercial"
spec:
  replicas: 2
  selector:
    matchLabels:
      app: engine-billing
  template:
    metadata:
      labels:
        app: engine-billing
        engine: billing
        layer: "commercial"
    spec:
      serviceAccountName: engine-sa
      containers:
        - name: engine-billing
          image: yadavanup84/engine-billing:v-billing-1
          imagePullPolicy: Always
          ports:
            - containerPort: 8040
          env:
            - name: APP_ENV
              value: "production"
            - name: BILLING_DB_HOST
              valueFrom:
                configMapKeyRef:
                  name: threat-engine-db-config
                  key: DB_HOST
            - name: BILLING_DB_PORT
              valueFrom:
                configMapKeyRef:
                  name: threat-engine-db-config
                  key: DB_PORT
            - name: BILLING_DB_NAME
              value: "threat_engine_billing"
            - name: BILLING_DB_USER
              value: "billing_app"
            - name: BILLING_DB_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: billing-db-passwords
                  key: BILLING_APP_PASSWORD
                  optional: false
            # Stripe credentials from Secrets Manager — loaded at startup via secrets_utils.py
            - name: STRIPE_SECRET_ARN
              value: "arn:aws:secretsmanager:ap-south-1:588989875114:secret:threat-engine/billing/stripe"
            # Internal service URLs for usage metering
            - name: ONBOARDING_ENGINE_URL
              value: "http://engine-onboarding:8008"
            - name: PLATFORM_BACKEND_URL
              value: "http://cspm-backend:8010"
            - name: PYTHONPATH
              value: "/app"
            - name: LOG_LEVEL
              value: "INFO"
            - name: ENGINE_NAME
              value: "billing"
          resources:
            requests:
              cpu: "100m"
              memory: "256Mi"
            limits:
              cpu: "500m"
              memory: "512Mi"
          livenessProbe:
            httpGet:
              path: /api/v1/health/live
              port: 8040
            initialDelaySeconds: 10
            periodSeconds: 30
          readinessProbe:
            httpGet:
              path: /api/v1/health/ready
              port: 8040
            initialDelaySeconds: 15
            periodSeconds: 10
---
apiVersion: v1
kind: Service
metadata:
  name: engine-billing
  namespace: threat-engine-engines
  labels:
    app: engine-billing
spec:
  type: ClusterIP
  ports:
    - port: 8040
      targetPort: 8040
      protocol: TCP
  selector:
    app: engine-billing
```

### 8.2 engine-platform-admin Deployment + Service

File path: `/Users/apple/Desktop/threat-engine/deployment/aws/eks/engines/engine-platform-admin.yaml`

```yaml
# =============================================================================
# Platform Admin Engine — Operator Dashboard, Org Management, Engine Health
# Port: 8041 | platform:admin permission required on all endpoints
# =============================================================================
apiVersion: apps/v1
kind: Deployment
metadata:
  name: engine-platform-admin
  namespace: threat-engine-engines
  labels:
    app: engine-platform-admin
    engine: platform-admin
    layer: "commercial"
spec:
  replicas: 1
  selector:
    matchLabels:
      app: engine-platform-admin
  template:
    metadata:
      labels:
        app: engine-platform-admin
        engine: platform-admin
        layer: "commercial"
    spec:
      serviceAccountName: engine-sa
      # engine-sa needs Kubernetes API read access for pod/deployment status
      # Add ClusterRole binding for: pods (get, list), deployments (get, list)
      containers:
        - name: engine-platform-admin
          image: yadavanup84/engine-platform-admin:v-padmin-1
          imagePullPolicy: Always
          ports:
            - containerPort: 8041
          env:
            - name: BILLING_ENGINE_URL
              value: "http://engine-billing:8040"
            - name: BILLING_DB_HOST
              valueFrom:
                configMapKeyRef:
                  name: threat-engine-db-config
                  key: DB_HOST
            - name: BILLING_DB_NAME
              value: "threat_engine_billing"
            - name: BILLING_DB_USER
              value: "billing_readonly"
            - name: BILLING_DB_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: billing-db-passwords
                  key: BILLING_READONLY_PASSWORD
                  optional: false
            # Cross-engine read access (scan_orchestration, discovery counts)
            - name: ONBOARDING_DB_HOST
              valueFrom:
                configMapKeyRef:
                  name: threat-engine-db-config
                  key: DB_HOST
            - name: ONBOARDING_DB_NAME
              value: "threat_engine_onboarding"
            - name: ONBOARDING_DB_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: threat-engine-db-passwords
                  key: DISCOVERIES_DB_PASSWORD
                  optional: false
            # Argo Workflows API
            - name: ARGO_SERVER_URL
              value: "http://argo-server.argo.svc.cluster.local:2746"
            - name: ARGO_NAMESPACE
              value: "threat-engine-engines"
            # K8s in-cluster config (uses mounted service account token)
            - name: K8S_NAMESPACE
              value: "threat-engine-engines"
            - name: PYTHONPATH
              value: "/app"
            - name: LOG_LEVEL
              value: "INFO"
            - name: ENGINE_NAME
              value: "platform-admin"
          resources:
            requests:
              cpu: "100m"
              memory: "256Mi"
            limits:
              cpu: "500m"
              memory: "512Mi"
          livenessProbe:
            httpGet:
              path: /api/v1/health/live
              port: 8041
            initialDelaySeconds: 10
            periodSeconds: 30
          readinessProbe:
            httpGet:
              path: /api/v1/health/ready
              port: 8041
            initialDelaySeconds: 15
            periodSeconds: 10
---
apiVersion: v1
kind: Service
metadata:
  name: engine-platform-admin
  namespace: threat-engine-engines
  labels:
    app: engine-platform-admin
spec:
  type: ClusterIP
  ports:
    - port: 8041
      targetPort: 8041
      protocol: TCP
  selector:
    app: engine-platform-admin
---
# ClusterRole for K8s API reads (pods, deployments)
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: engine-platform-admin-reader
  namespace: threat-engine-engines
rules:
  - apiGroups: [""]
    resources: ["pods", "pods/log"]
    verbs: ["get", "list"]
  - apiGroups: ["apps"]
    resources: ["deployments", "replicasets"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: engine-platform-admin-reader-binding
subjects:
  - kind: ServiceAccount
    name: engine-sa
    namespace: threat-engine-engines
roleRef:
  kind: ClusterRole
  name: engine-platform-admin-reader
  apiGroup: rbac.authorization.k8s.io
```

### 8.3 Kubernetes Secret for Billing DB Passwords

```yaml
# Apply before deploying billing engines
# billing-db-passwords secret (managed outside Git — apply via kubectl)
# kubectl create secret generic billing-db-passwords \
#   --from-literal=BILLING_APP_PASSWORD='...' \
#   --from-literal=BILLING_READONLY_PASSWORD='...' \
#   -n threat-engine-engines
```

### 8.4 Gateway Service Route Additions (main.py update)

New entries to add to `SERVICE_ROUTES` in `/Users/apple/Desktop/threat-engine/shared/api_gateway/main.py`:

```python
"billing": {
    "url": os.getenv("BILLING_ENGINE_URL", "http://engine-billing:8040"),
    "prefix": "/api/v1/billing",
    "prefixes": ["/api/v1/billing"],
    "health_endpoint": "/api/v1/health/live"
},
"platform-admin": {
    "url": os.getenv("PLATFORM_ADMIN_ENGINE_URL", "http://engine-platform-admin:8041"),
    "prefix": "/api/v1/padmin",
    "prefixes": ["/api/v1/padmin"],
    "health_endpoint": "/api/v1/health/live"
},
```

The Stripe webhook path (`/api/v1/billing/webhooks/stripe`) must be excluded from `AuthMiddleware`. Add it to the existing `AUTH_SKIP_PATHS` list in the gateway auth middleware.

---

## 9. Epic Breakdown

The following epics are designed for the bmad-po agent to decompose into individual stories. Each epic is independently deployable and ordered by dependency.

### Epic 1 — Billing DB + Plan Seed Data
**Objective:** Create `threat_engine_billing` schema, seed 4 subscription plans, create DB users.  
**Output:** Billing DB operational, plans queryable.  
**Stories include:**
- Migration script for billing schema (all 6 tables)
- Create `billing_app`, `billing_readonly`, `billing_audit_writer` Postgres roles
- Seed 4 subscription plans via SQL migration
- Create `billing-db-passwords` K8s secret
- Verify schema via psql exec from existing pod

### Epic 2 — engine-billing Core (No Stripe)
**Objective:** Deployable billing engine with plan read/write, subscription CRUD, usage queries — Stripe-free.  
**Output:** engine-billing at v-billing-1 passing health checks, serving plan and subscription endpoints.  
**Stories include:**
- FastAPI app skeleton with `require_permission()` integration
- Plan endpoints (GET /plans, GET /plans/{id})
- Subscription endpoint (GET /subscription by org_id)
- Usage check endpoints (check-account-limit, check-scan-frequency)
- Trial provisioning on org creation (called by Django backend on registration)
- Trial expiry background task (APScheduler, hourly)
- K8s manifest deployment
- Unit tests: idempotency, subscription CRUD, trial expiry

### Epic 3 — Stripe Integration
**Objective:** Checkout session creation + webhook handler with full idempotency.  
**Output:** org_admin can complete a real Pro subscription via Stripe test mode.  
**Stories include:**
- Stripe secret retrieval via Secrets Manager at startup
- POST /checkout endpoint (create Stripe Checkout Session)
- POST /webhooks/stripe endpoint with HMAC validation
- Handle 6 Stripe event types (create, update, delete, payment_succeeded, payment_failed, trial_will_end)
- Integration test: fire test webhook events, verify org_subscriptions state changes
- billing_events + billing_audit_log writes on every state change
- Cancel/reactivate subscription endpoints

### Epic 4 — Gateway SubscriptionMiddleware + Enforcement
**Objective:** X-Subscription-Context header injected on all authenticated requests. 402 returned for tier/account violations.  
**Output:** Gateway enforces subscription limits without any scan engine code changes.  
**Stories include:**
- SubscriptionMiddleware implementation (LRU cache, 60s TTL, fail-open)
- X-Subscription-Context header injection (base64 JSON)
- Engine allowlist check in proxy handler (402 with structured body)
- Account limit check in proxy handler (onboarding account creation)
- Scan frequency enforcement (check-scan-frequency before forwarding scan-run requests)
- consume-scan-token API in engine-billing
- scan_frequency_tokens table management
- Cache invalidation endpoint (internal, called by billing engine on subscription change)
- End-to-end test: Free org → attempt datasec endpoint → expect 402 with correct body

### Epic 5 — Django Platform Extensions
**Objective:** 3 new permissions seeded, /api/auth/me extended with subscription data.  
**Output:** org_admin session includes billing permissions; /api/auth/me returns subscription tier.  
**Stories include:**
- Migration 0010: INSERT 3 permissions + role_permissions rows
- /api/auth/me response: add `subscription` field (tier, status, trial_days_remaining, accounts_connected)
- Django backend calls engine-billing /subscription on /api/auth/me request (cached, TTL 60s)
- Trial provisioned via Django signal on Organization creation (calls billing engine POST /trial/provision)
- Verify permissions appear in user_sessions.permissions_cache on next login

### Epic 6 — engine-platform-admin
**Objective:** Deployable platform admin engine with org grid, engine health, Argo pipeline status.  
**Output:** platform_admin can view all org subscriptions and engine health in one dashboard.  
**Stories include:**
- FastAPI app skeleton with `require_permission("platform:admin")` on all routes
- Engine health endpoint (K8s API + /health probe calls to all 18+ engines)
- Argo pipeline runs endpoint (Argo Workflows REST API)
- Org list endpoint with subscription status (reads billing DB via billing_readonly)
- Org detail endpoint (subscription + usage + recent billing events)
- Tier override endpoint (PATCH /orgs/{org_id}/subscription) — writes to billing DB, invalidates Gateway cache
- Trial extension endpoint (PATCH /orgs/{org_id}/trial)
- Suspend/unsuspend endpoints
- Platform metrics endpoint
- K8s manifest deployment (includes ClusterRole for pod reads)
- Operator audit log writes (platform_admin_audit table) on all mutation endpoints

### Epic 7 — Billing Portal Frontend
**Objective:** org_admin billing portal page. Analyst/viewer can see current tier (read-only).  
**Output:** Billing portal accessible from nav; upgrade flow completes in ≤3 clicks.  
**Stories include:**
- Billing portal page (`/billing`) — current plan, usage bars, upgrade/downgrade CTAs
- Plan comparison modal (side-by-side feature matrix)
- Stripe Checkout redirect flow (POST /checkout → window.location)
- Success/cancel URL handling (banner notification on return)
- Invoice history table (GET /invoices)
- Downgrade confirmation dialog (show data retention impact)
- Cancel subscription flow with confirmation
- Tier-aware nav gating: greyed-out enterprise engine tabs with upgrade tooltip
- Billing portal read-only view for analyst/viewer (see tier, no actions)

### Epic 8 — Grandfathering + Hardening
**Objective:** Existing users grandfathered; production-hardened for first paying customer.  
**Output:** All existing orgs on 90-day Pro equivalent; E2E tested; PCI checklist complete.  
**Stories include:**
- Grandfathering migration: set is_overridden=true, grandfathered_until=now()+90days for all existing orgs
- PCI SAQ A-EP checklist: Content-Security-Policy header, TLS verification, no card data in logs
- Load test: 1000 concurrent subscription state queries ≤50ms p99
- Webhook burst test: 100 events/second deduplication correctness
- Billing engine downtime drill: verify scan engines continue operating when billing is down
- Runbook: Stripe key rotation procedure
- Operator documentation: how to override tier, extend trial, suspend org

---

## 10. Open Questions Resolved

### Q1: Pricing for each tier?
**Resolved:** Use these defaults. Platform_admin can update via `PATCH /api/v1/billing/plans/{id}` without code deployment.
- Free: $0/month
- Starter: $49/month
- Pro: $99/month
- Enterprise: $299/month

These are stored in `subscription_plans.price_monthly`. Stripe Price IDs are configured separately in Stripe Dashboard and stored in `subscription_plans.stripe_price_id`. Price changes require creating new Stripe Prices and updating the DB — never update a live Stripe Price.

### Q2: Grandfathering existing users on Pro for 90 days?
**Resolved:** Yes. Epic 8 includes a one-time migration that sets `is_overridden=true` and `grandfathered_until = deployment_date + 90 days` for all existing orgs in `org_subscriptions`. This gives existing users 90 days before billing enforcement applies. The `is_overridden=true` flag in `X-Subscription-Context` allows the Gateway to serve the override tier without Stripe validation.

### Q3: Which AWS region for billing DB?
**Resolved:** Same region as all other platform DBs: `ap-south-1`. The billing DB uses the existing RDS instance (`postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com`) as a separate database (`threat_engine_billing`). This satisfies GDPR data residency requirement since all customer data remains in the same region. A separate RDS instance is NOT needed at this scale; the billing schema is lightweight. Evaluate for dedicated RDS at 10,000 org scale.

### Q4: Per-environment Stripe webhook secrets?
**Resolved:** Separate AWS Secrets Manager paths per environment, selected by `APP_ENV` env var in the K8s manifest. Paths: `threat-engine/billing/stripe-dev`, `threat-engine/billing/stripe-staging`, `threat-engine/billing/stripe` (production). Stripe test mode vs live mode is determined by the `STRIPE_SECRET_KEY` prefix (`sk_test_` vs `sk_live_`). The same code path works for both — no conditional logic needed.

### Q5: Trial per email address or per email domain?
**Resolved:** Per email domain, enforced at organization creation time. When a new org is created in Django backend, before provisioning a trial, the backend checks: `SELECT COUNT(*) FROM org_subscriptions WHERE org_email_domain = $1 AND (status='trialing' OR trial_end_at IS NOT NULL)`. If count > 0, the new org gets Free tier (no trial). This prevents trial abuse via re-registration. The `email_domain` is extracted from the org_admin's registration email. One domain = one trial lifetime.

### Q6: Grace period after payment failure?
**Resolved:** 7-day grace period. When `invoice.payment_failed` webhook fires: set `payment_failed_at = now()`, `grace_period_end_at = now() + 7 days`. During grace period: org status remains `past_due` but `X-Subscription-Context` still shows active tier (Gateway reads the grace period end date and allows access until it expires). Stripe will retry on day 1, day 3, day 7. After 7 days without successful payment: Gateway begins returning 402 for paid-tier engines. Operator is alerted via `billing_events` entry; manual intervention or org contacts support.

### Q7: Does engine-platform-admin need a frontend UI?
**Resolved:** MVP = API-only. A platform_admin uses the existing admin panel concept via direct API calls or a simple React page added in Epic 7. The admin dashboard is not a separate SPA; it is added as a new page in the existing Next.js frontend (path: `/admin/dashboard`), gated to `platform:admin` permission via `hasPermission("platform:admin")`. The backend is API-only; the frontend page in Epic 7 handles the UI. This avoids a separate frontend deployment.

---

## Architecture Decision Records (ADRs)

### ADR-BILLING-001: Billing DB on existing RDS, separate database

**Context:** Two options: (1) new RDS instance for billing isolation, (2) new database on existing RDS.  
**Decision:** Separate database on existing RDS.  
**Rationale:** At current scale (<10,000 orgs), billing DB is extremely lightweight (6 small tables). New RDS instance adds $150+/month cost and operational complexity. Logical isolation via separate DB and dedicated Postgres roles achieves the required access isolation. The `billing_app` role has zero access to scan DBs (verified at Postgres role grant level). Revisit at 10,000 org scale.  
**Consequences:** billing DB shares RDS compute/storage. Billing engine downtime does not affect scan engines (separate connection pools). Scan engine downtime does not affect billing.

### ADR-BILLING-002: Subscription enforcement at Gateway, not in scan engines

**Context:** Two options: (1) add enforcement logic to each scan engine, (2) enforce at Gateway proxy layer only.  
**Decision:** Gateway enforcement only.  
**Rationale:** Zero scan engine code changes required. The 18 existing engines are production-hardened and their deployment cadence should not be coupled to billing. The Gateway already has the proxy layer and auth context; adding subscription context to the same middleware is a clean extension of the existing pattern. Engines receive the `X-Subscription-Context` header for informational 402 response bodies but do not enforce access — they rely on the Gateway to have already blocked unauthorized requests.  
**Consequences:** Internal Argo pipeline calls (engine-to-engine) bypass Gateway enforcement. This is correct behavior — Argo pipeline steps are not subject to subscription gating (scanning is the value being sold, not restricted within the pipeline). Only user-triggered API calls go through the Gateway.

### ADR-BILLING-003: In-memory LRU cache for subscription state in Gateway

**Context:** Subscription state must be checked on every API request. Adding a Redis dependency would increase infrastructure complexity. Making a synchronous billing engine call on every request would add >50ms latency.  
**Decision:** In-process LRU cache in the Gateway process (Python `functools.lru_cache` or `cachetools.TTLCache`), TTL=60 seconds, max 10,000 entries.  
**Rationale:** 60-second cache satisfies the ≤10ms p99 latency requirement (cache hit is sub-millisecond). The 60-second window means a downgrade takes effect within 1 minute — acceptable for the use case. A Redis cluster adds cost and an availability dependency. The single Gateway pod invalidates its cache on each subscription change notification from the billing engine.  
**Consequences:** Multiple Gateway replicas each have their own cache; after a subscription change, enforcement can be delayed by up to 60 seconds per replica. For downgrade scenarios this is acceptable (minor window). For suspension (security action), the Gateway calls billing engine directly without cache (fail-closed for suspension checks).

---

## Implementation Constraints Checklist

Before story authoring begins, confirm these constraints are addressed in each epic:

- [ ] Credential resolution: Stripe secrets via Secrets Manager, `optional: false` on all secretRef
- [ ] Timeout wrappers: all httpx calls to Stripe API and internal services have explicit 5-10s timeout
- [ ] No bare env vars for Stripe keys in production manifests
- [ ] `provider` column not applicable to billing tables (billing is org-scoped, not CSP-scoped)
- [ ] `scan_run_id` not applicable to billing tables (billing is not part of the scan pipeline)
- [ ] Idempotent DB operations: `ON CONFLICT DO NOTHING` for webhook log, `ON CONFLICT DO UPDATE` for subscription upserts
- [ ] Audit log append-only: Postgres role grants enforced, no application-level UPDATE/DELETE on audit tables
- [ ] HMAC-SHA256 webhook signature validation before any processing
- [ ] X-Subscription-Context header stripped by Gateway from inbound requests (prevent spoofing)
- [ ] engine-billing downtime does not degrade scan engine availability (fail-open, cached state)
- [ ] PCI scope: no raw card data in logs, database, or application memory at any point
- [ ] Trial abuse: one trial per email domain enforced at org creation
- [ ] All 402 responses include structured JSON with `error`, `current_tier`, `required_tier`, `limit_type`, `upgrade_url`
