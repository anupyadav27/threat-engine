---
stepsCompleted: ['step-01-init', 'step-02-discovery', 'step-02b-vision', 'step-02c-executive-summary', 'step-03-success', 'step-04-journeys', 'step-05-domain-requirements', 'step-06-innovation', 'step-07-b2b-requirements', 'step-08-scoping', 'step-09-functional', 'step-10-nonfunctional', 'step-11-open-questions', 'step-12-complete']
inputDocuments: ['_bmad-output/planning-artifacts/epics.md']
workflowType: 'prd'
classification:
  projectType: saas_b2b
  domain: cloud_security_saas_billing
  complexity: high
  projectContext: brownfield
---

# Product Requirements Document - threat-engine

**Author:** Anup
**Date:** 2026-05-02

## Executive Summary

The Threat Engine CSPM platform is live in production with 18+ scanning engines, RBAC, and self-service registration — but has no commercial layer. Every registered user receives `org_admin` access with unrestricted scan capabilities and full engine visibility, making monetization, resource governance, and enterprise sales impossible. This PRD defines the **Subscription & Billing system**: a net-new capability that adds tiered plans, payment processing, usage enforcement, and operator-level monitoring without re-architecting any existing scan engine.

**Target personas:**
- **Self-serve buyer (org_admin):** Cloud security engineer or DevSecOps lead who registers, evaluates on Free, and upgrades when they need more accounts or enterprise engines. Wants frictionless upgrade, clear value at each tier, and transparent usage metrics.
- **SaaS operator (platform_admin):** The Threat Engine team managing all customer orgs — monitoring engine health, pipeline runs, subscription status, and granting trial extensions.
- **Invited team member (analyst/viewer):** Scoped to their org's plan limits; cannot change subscription but can see what tier their org is on.

**Problem being solved:** The platform generates security value but captures zero revenue. Without subscription gates, there is no mechanism to differentiate free vs paid users, block overuse, or restrict access to the 7 enterprise engines (datasec, secops, vulnerability, ai-security, encryption, dbsec, container-sec) that represent premium value.

### What Makes This Special

The core insight: **the enforcement layer already exists.** The 27-permission RBAC matrix, the `require_permission()` FastAPI dependency on every engine endpoint, and the `permissions_cache` in every session token are already production-hardened. Subscription tiers map directly to RBAC capability sets — Free maps to viewer-level engine access, Pro to analyst-level, Enterprise unlocks the 7 gated engines. No scan engine code changes required; enforcement is injected at the Gateway layer via a new `X-Subscription-Context` header alongside the existing `X-Auth-Context`.

**Differentiator over bolt-on billing:** Most SaaS billing is orthogonal to the product. Here, billing *is* the access control system — subscription status resolves at session time and propagates as a header, identical to permissions. A subscription downgrade revokes capabilities at next login with zero special-case code in engines.

**Two new services, clearly separated:**
- `engine-billing` (FastAPI, port 8040) — Stripe integration, invoice generation, plan management, usage metering, webhook handling. Isolated from scan engines.
- `engine-platform-admin` (FastAPI, port 8041) — Operator dashboard: all-engine health, Argo pipeline status, per-org subscription management, usage metrics, trial extensions. Only accessible to `platform_admin` role.

## Project Classification

| Attribute | Value |
|-----------|-------|
| Project Type | B2B SaaS — Net-new billing feature on existing platform |
| Domain | Cloud Security SaaS (cybersecurity + fintech billing hybrid) |
| Complexity | High — regulated data handling, payment scope (PCI-DSS SAQ A-EP), multi-tenant enforcement, 18 live engine integration points |
| Project Context | Brownfield — live production system, zero downtime constraint |
| Compliance Scope | PCI-DSS (Stripe elements), SOC 2 Type II (audit log of billing events), GDPR (payment data residency) |

## Success Criteria

### User Success
- org_admin completes plan upgrade (Free → Pro) in ≤3 minutes with no support contact
- 14-day trial users who connect ≥1 cloud account and run ≥1 scan convert to paid at ≥30%
- Invited team members (analyst/viewer) see their org's subscription tier on first login
- Zero cases of a user charged without an explicit confirmation step
- Downgrade and cancellation flows completable without support contact

### Business Success
- Billing infrastructure live and first paying customer onboarded within Sprint 1 of implementation
- ≥20% of registered orgs on a paid plan within 6 months of launch
- Monthly churn on paid plans ≤5%
- Payment failure recovery (retry + dunning) resolves ≥90% of failed charges without manual intervention
- platform_admin answers "which orgs expire this week?" in ≤30 seconds without DB access

### Technical Success
- Subscription enforcement check adds ≤10ms p99 latency to gateway request path
- Stripe webhook processing is idempotent — no duplicate charges under any retry scenario
- engine-billing deployable and rollback-able independently with zero downtime to scan engines
- 100% of scan requests over account limit receive HTTP 402 (not 500, not silent pass-through)
- All billing events written to audit log (SOC 2 Type II requirement)

### Measurable Outcomes
- Time-to-first-payment: ≤3 minutes from "upgrade" click to active subscription
- Trial-to-paid conversion: ≥30% of trials that ran ≥1 scan
- Operator time-to-insight: ≤30 seconds from dashboard open to actionable view
- Blast radius: engine-billing downtime does not degrade any scan engine availability

## Product Scope

### MVP — Minimum Viable Product
- 4 subscription tiers: Free, Starter, Pro, Enterprise
- Stripe Checkout integration (hosted page — Threat Engine never touches raw card data)
- Account limit enforcement: new onboarding blocked with HTTP 402 when org exceeds `max_accounts`
- Engine tier gating: enterprise engines return HTTP 402 when org is on Free/Starter/Pro
- 14-day trial on all paid tiers — auto-downgrade to Free on expiry if no payment method added
- `engine-billing` (port 8040): plan CRUD, Stripe webhook handler, subscription state DB
- `engine-platform-admin` (port 8041): org health dashboard, subscription management, engine health monitor
- New RBAC permissions: `billing:read`, `billing:write`, `platform:admin`
- `/api/auth/me` response extended with subscription tier and usage counts
- Scan frequency enforcement at Gateway (Free = 1/week, Starter = 1/day, Pro = 4/day, Enterprise = unlimited)

### Growth Features (Post-MVP)
- Usage-based overage billing (pay-per-account beyond limit instead of hard block)
- PDF invoice generation and download from billing portal
- Annual billing with 2-month discount
- Stripe Customer Portal (self-serve payment method update, invoice history)
- Email notifications: trial expiry (7 days, 1 day), payment failed, renewal receipt, limit warning at 80%
- Team seat licensing (per-user pricing layer on top of account limits)

### Vision (Future)
- Engine add-on marketplace (buy specific engines à la carte)
- White-label billing for MSP/reseller partners
- Usage analytics dashboard for org_admin (scan trends, findings over time, cost-per-scan)
- Multi-year contracts with custom pricing managed by platform_admin
- Automatic rightsizing suggestions ("2 of 10 Pro accounts used — consider downgrade?")

## User Journeys

### Journey 1: Priya — Self-Serve Upgrade (Primary Happy Path)

Priya is a senior DevSecOps engineer at a 40-person SaaS startup. She registered last week, connected her AWS account, ran her first scan, and saw 47 critical findings. She wants to connect her GCP and Azure accounts too.

**Opening scene:** Priya clicks "Add Cloud Account" in the onboarding portal. A modal appears: "Your Free plan includes 1 cloud account. Upgrade to Pro to connect up to 10 accounts and run daily scans." She sees a side-by-side comparison of Free, Starter, Pro, and Enterprise.

**Rising action:** She selects Pro ($99/month). The portal opens Stripe Checkout in the same tab — no redirect to a separate billing site. She enters her card details (handled entirely by Stripe, never touching Threat Engine servers). She clicks "Subscribe."

**Climax:** Within 3 seconds she's back in the portal with a green banner: "You're now on Pro. Connect up to 10 accounts." Her GCP onboarding continues without interruption. The session permissions_cache is refreshed on next request — no re-login required.

**Resolution:** By end of day Priya has AWS, GCP, and Azure connected and is scheduling daily scans. She receives an email receipt. Her org's subscription tier shows "Pro — active" in the billing portal.

**Capabilities revealed:** Stripe Checkout integration, account limit enforcement with upgrade prompt, session-aware subscription refresh, billing portal, email receipt.

---

### Journey 2: Alex — Morning Ops Check (Platform Admin)

Alex is the ops lead at Threat Engine. Every morning he opens the platform admin dashboard before standup.

**Opening scene:** Alex logs in with his platform_admin credentials. The dashboard shows a grid: 23 active orgs, 4 on trial, 2 trials expiring within 3 days, 1 org with a failed payment in retry state, all 18 engines green except engine-datasec which has elevated error rate.

**Rising action:** He clicks the failing payment org — "TechCorp Ltd, Pro plan, payment failed 2 days ago, 2 retries remaining." He sees their scan access is still active (grace period). He sends them a manual notification from the dashboard.

**Climax:** He clicks engine-datasec. The detail view shows the last 10 Argo pipeline runs, the error rate, and a pod restart count. He sees it's a transient issue — last 3 runs were clean. No action needed.

**Resolution:** In 8 minutes Alex has answered: who's expiring, who's in payment trouble, and whether all engines are healthy. He goes to standup with data.

**Capabilities revealed:** Platform admin engine health monitor, subscription status grid, payment state visibility, Argo pipeline monitor, manual notification trigger.

---

### Journey 3: Marcus — Invited Analyst (Scoped Access)

Marcus is a security analyst invited by his org's org_admin to review findings. His org is on the Starter plan.

**Opening scene:** Marcus receives an invite email. He clicks the link, sets a password, and lands on the CSPM dashboard. He sees discoveries, check findings, threat, inventory, compliance, IAM, CIEM, network, and risk — all 9 core engines his role permits.

**Rising action:** Marcus notices there's no datasec tab. He hovers over a greyed-out "Data Security" nav item. A tooltip: "Data Security is available on Pro and above. Ask your org admin to upgrade." He's not blocked — he just knows the context.

**Climax:** Marcus opens a threat finding he wants to investigate. He can read all details, create notes, export to CSV. He can't trigger a new scan — that requires scans:create which is org_admin/tenant_admin only.

**Resolution:** Marcus does his security review without any subscription friction. He sends his org_admin a message about upgrading to Pro to get datasec coverage. Subscription awareness flows naturally without hard blocking his work.

**Capabilities revealed:** Tier-aware UI gating with upgrade hints (not hard walls), permission-scoped access, engine 402 handling surfaced gracefully in frontend.

---

### Journey 4: Priya — Account Limit Hit Mid-Scan (Edge Case Recovery)

Priya's org is on Free (1 account). She'd forgotten she already connected AWS. She tries to trigger a scan run for a second account she added manually via API.

**Opening scene:** The API call returns HTTP 402 with body: `{"error": "account_limit_exceeded", "current": 1, "limit": 1, "upgrade_url": "/billing/upgrade?from=account_limit"}`. The error is structured, not a generic 500.

**Rising action:** Priya's CI/CD pipeline catches the 402, logs it, and sends a Slack notification to her team. She clicks the upgrade URL, lands on the billing portal with "Upgrade to Pro" pre-selected and the reason pre-filled.

**Resolution:** She upgrades, her second account scan runs, and the CI/CD pipeline retries automatically. No data was lost; no scan was partially executed.

**Capabilities revealed:** Structured 402 response with upgrade context, idempotent scan retry after upgrade, CI/CD-friendly error shape.

---

### Journey Requirements Summary

| Journey | Capabilities Required |
|---------|----------------------|
| Priya — Upgrade | Stripe Checkout, limit enforcement, upgrade prompt, session refresh, email receipt |
| Alex — Ops check | Platform admin engine, health dashboard, payment state, Argo monitor, notifications |
| Marcus — Analyst | Tier-aware UI gating, permission-scoped access, 402→tooltip surfacing |
| Priya — Edge case | Structured 402 with context, idempotent scan retry, CI/CD-safe error shape |

## Domain-Specific Requirements

### Compliance & Regulatory

**PCI-DSS SAQ A-EP (Stripe Checkout):**
- Threat Engine never stores, processes, or transmits raw card data; all payment data handled by Stripe
- Stripe.js loads directly from Stripe CDN on payment pages — not proxied through Threat Engine servers
- TLS 1.2+ enforced on all endpoints; TLS 1.3 preferred
- Annual SAQ A-EP self-assessment required; Stripe provides pre-filled compliance documentation
- Webhook endpoint validates Stripe-Signature header using HMAC-SHA256 before processing any event

**SOC 2 Type II:**
- All billing state changes written to `billing_audit_log` table with: event_type, org_id, actor_id, previous_state, new_state, timestamp, source_ip
- Audit log is append-only; no UPDATE or DELETE permitted by application code
- Retention: billing audit events retained for 7 years minimum
- Access to billing audit log restricted to `platform_admin` role only

**GDPR:**
- Billing data (name, email, company name) stored in the same AWS region as platform DB (ap-south-1)
- Card data: never stored — Stripe Customer ID is the only reference
- Right to erasure: org deletion anonymizes billing records (replace PII with "DELETED_USER") but retains aggregate billing history for financial audit
- Privacy policy must disclose Stripe as payment processor and data sub-processor

### Technical Constraints

- Stripe webhook events must be processed idempotently using `stripe_event_id` as deduplication key
- Billing engine must gracefully degrade: if billing DB is unreachable, gateway allows existing sessions through (fail-open for read, fail-closed for new scan creation)
- Subscription state cached in `user_sessions.scope_cache` — cache invalidated on subscription change
- All inter-service calls from billing engine to other engines use internal Kubernetes service DNS (no public internet)

### Risk Mitigations

| Risk | Mitigation |
|------|-----------|
| Double-charge on webhook retry | Idempotency key = Stripe event ID; upsert on processing |
| Billing engine outage blocks scans | Gateway fails-open for reads; scans:create checks cached subscription state |
| Subscription downgrade mid-scan | Scan runs to completion; enforcement applies on next scan trigger |
| PCI scope creep | Stripe Checkout only; no custom payment form ever |
| Trial abuse (re-register) | Trial linked to verified email domain; one trial per email domain |

## Innovation & Novel Patterns

### Detected Innovation Areas

**Billing as Access Control (Core Innovation):**
The conventional approach treats billing as a separate system that grants/revokes access. Threat Engine's approach inverts this: the existing `permissions_cache` and `require_permission()` engine layer already IS the access control system. Subscription tiers are expressed as permission capability sets — the billing engine writes to `UserRoles` (same table used by RBAC), and the Gateway's existing `X-Auth-Context` header carries the resolved permissions.

This means:
- Zero new enforcement code in any of the 18 scan engines
- Downgrade = remove role from UserRoles = invalidate session = new session has fewer permissions
- Upgrade = add role = new session cache = immediate access
- Subscription state and RBAC state are always in sync by construction

**Subscription Context Header Pattern:**
A new `X-Subscription-Context` header (alongside `X-Auth-Context`) allows engines to return structured 402 responses with upgrade context. Engines don't need billing logic — they receive a structured header and return the appropriate error shape.

### Validation Approach

- The permission-as-subscription model can be validated with a single integration test: create a user, assign org_admin + Pro subscription role, verify datasec endpoint returns 200; downgrade to Free, verify same endpoint returns 402
- No mock billing needed — the enforcement path is pure RBAC

### Risk Mitigation

- If the billing engine is down, existing UserRoles rows remain unchanged — users keep their current tier until next session
- The fail-open/fail-closed design means billing engine unavailability never breaks security scanning

## B2B SaaS Technical Requirements

### Multi-Tenancy Model

Billing is scoped at the **Organization level** (the `Tenants` table in platform DB), not at the cloud provider tenant or account level. One org = one Stripe Customer = one subscription. All cloud provider tenants (AWS, GCP, Azure) and their accounts under an org share the same subscription.

- `Tenants.id` maps 1:1 to `stripe_customer_id` in billing DB
- Account limit (`max_accounts`) counts total `OnboardingAccount` rows across all providers for the org
- User seat limits (Growth feature) count `TenantUsers` rows for the org

### Subscription Tier Feature Matrix

| Feature | Free | Starter | Pro | Enterprise |
|---------|------|---------|-----|------------|
| Cloud accounts | 1 | 3 | 10 | Unlimited |
| Users (seats) | 3 | 10 | 25 | Unlimited |
| Scan frequency | 1/week | 1/day | 4/day | Unlimited |
| Data retention | 7 days | 30 days | 90 days | 1 year |
| discoveries engine | ✓ | ✓ | ✓ | ✓ |
| check engine | ✓ | ✓ | ✓ | ✓ |
| threat engine | ✓ | ✓ | ✓ | ✓ |
| inventory engine | ✓ | ✓ | ✓ | ✓ |
| compliance engine | ✓ | ✓ | ✓ | ✓ |
| iam engine | ✓ | ✓ | ✓ | ✓ |
| ciem engine | ✓ | ✓ | ✓ | ✓ |
| network-security | ✓ | ✓ | ✓ | ✓ |
| risk engine | ✓ | ✓ | ✓ | ✓ |
| datasec engine | — | — | ✓ | ✓ |
| secops engine | — | — | ✓ | ✓ |
| vulnerability engine | — | — | ✓ | ✓ |
| ai-security engine | — | — | — | ✓ |
| encryption engine | — | — | — | ✓ |
| dbsec engine | — | — | — | ✓ |
| container-sec engine | — | — | — | ✓ |
| fix engines (AI remediation) | — | — | — | ✓ |
| Priority support | — | — | Email | Dedicated CSM |

### Permission Model Extensions

Three new permissions added to the 27-permission matrix:

| Permission | viewer | analyst | tenant_admin | org_admin | platform_admin |
|-----------|--------|---------|-------------|-----------|----------------|
| `billing:read` | — | — | — | Y | Y |
| `billing:write` | — | — | — | Y | Y |
| `platform:admin` | — | — | — | — | Y |

### Integration Requirements

| System | Integration Type | Purpose |
|--------|-----------------|---------|
| Stripe | REST API + Webhooks | Payment processing, subscription lifecycle |
| engine-onboarding | Internal K8s DNS | Account count queries, account creation enforcement |
| platform Django | Internal K8s DNS | Subscription state in /api/auth/me, UserRoles sync |
| API Gateway | Header injection | X-Subscription-Context forwarding to engines |
| All 18 scan engines | Header reading | Structured 402 response on tier violation |
| Argo Workflows | Kubernetes API | Pipeline status reads for platform admin dashboard |

### Implementation Considerations

- `engine-billing` must never be in the hot path of scan requests — subscription state resolved at login and cached in session
- Stripe Customer Portal (Growth) requires allowlisting return URL; must validate return URL against known frontend origins
- `engine-platform-admin` is `platform_admin`-only — must validate `platform:admin` permission on every endpoint via `require_permission()` same as all other engines
- Billing DB schema separate from all other engine DBs; no cross-DB joins at runtime

## Project Scoping & Phased Development

### MVP Strategy & Philosophy

**MVP Approach:** Revenue MVP — build the minimum that captures the first paying customer and enforces plan limits. The goal is not feature completeness but commercial viability and enforcement correctness.

**Resource Requirements:** 2 backend engineers (billing engine + platform admin engine), 1 frontend engineer (billing portal UI), 1 DevOps (K8s manifests + Stripe webhook SSL), 1 QA.

### MVP Feature Set (Phase 1)

**Core User Journeys Supported:** All 4 journeys (Priya upgrade, Alex ops check, Marcus analyst, Priya edge case)

**Must-Have Capabilities:**
- Subscription tier definitions (4 tiers) with feature matrix in DB
- Stripe Checkout integration (hosted page)
- Account limit enforcement (HTTP 402 on onboarding engine)
- Engine tier gating (HTTP 402 on 9 gated engines via X-Subscription-Context)
- 14-day trial auto-provisioned on registration
- Trial expiry auto-downgrade to Free
- `engine-billing` deployed at port 8040
- `engine-platform-admin` deployed at port 8041
- Billing portal page for org_admin (current plan, usage, upgrade/downgrade)
- Platform admin dashboard (org grid, engine health, Argo pipeline status)
- New permissions: `billing:read`, `billing:write`, `platform:admin` seeded in DB
- `/api/auth/me` extended with subscription field
- Audit log for all billing events

### Post-MVP Features (Phase 2)

- Usage-based overage billing
- PDF invoice generation
- Annual billing with discount
- Stripe Customer Portal
- Email notification suite (trial expiry, payment failure, renewal, limit warning)
- Team seat enforcement

### Expansion (Phase 3)

- Engine add-on marketplace
- White-label billing for resellers
- Usage analytics dashboard (org_admin)
- Multi-year contracts
- Automatic rightsizing suggestions

### Risk Mitigation Strategy

**Technical Risks:** Stripe Checkout API changes — mitigated by pinning Stripe SDK version and testing webhook events in Stripe's test mode before production deployment.

**Market Risks:** Existing users resist paywalling — mitigated by grandfathering all existing orgs on Pro plan for 90 days from billing launch (platform_admin can set tier overrides).

**Resource Risks:** If eng headcount reduced, engine-platform-admin dashboard can be deferred (Phase 2) — enforcement and billing are more critical than monitoring UI.

## Functional Requirements

### Subscription Plan Management

- FR1: org_admin can view all subscription tiers with side-by-side feature and pricing comparison before purchasing
- FR2: org_admin can initiate plan upgrade from any in-product limit notification without navigating away from current workflow
- FR3: org_admin can downgrade their plan with downgrade taking effect at end of current billing cycle
- FR4: org_admin can cancel subscription with confirmation dialog showing data retention impact
- FR5: platform_admin can create, modify, and deprecate subscription plan definitions including price and feature limits
- FR6: platform_admin can assign a custom plan or tier override to any org without Stripe payment

### Payment & Billing

- FR7: org_admin can complete payment for a subscription upgrade via Stripe-hosted checkout without leaving Threat Engine UI flow
- FR8: org_admin can view full invoice history with date, amount, status, and download link
- FR9: org_admin can update payment method via Stripe Customer Portal without re-entering subscription details
- FR10: system automatically retries failed payments on day 1, day 3, and day 7 before marking subscription as lapsed
- FR11: platform_admin can view all orgs' billing state (active, trialing, past_due, cancelled) in a single dashboard view
- FR12: system writes a billing audit event for every subscription state change including actor, timestamp, previous state, and new state

### Trial Management

- FR13: system automatically provisions a 14-day Pro-equivalent trial for every new org on registration
- FR14: org_admin receives email notification at 7 days and 1 day before trial expiry
- FR15: system automatically downgrades org to Free tier at trial expiry when no payment method is on file
- FR16: platform_admin can extend a trial period for a specific org by a specified number of days
- FR17: org_admin can convert from trial to paid plan at any point before expiry

### Usage Enforcement

- FR18: system blocks new cloud account onboarding and returns HTTP 402 with structured upgrade context when org exceeds tier's `max_accounts` limit
- FR19: system returns HTTP 402 (not HTTP 403) with tier and upgrade context when org accesses an engine outside their subscription tier
- FR20: system allows read access to all existing findings after a plan downgrade (no data deletion on downgrade)
- FR21: org_admin can view current usage vs. plan limits for accounts, users, and scan frequency in billing portal
- FR22: system enforces per-org scan frequency limits at the Gateway layer before forwarding to scan engines
- FR23: system returns structured 402 JSON with `upgrade_url`, `current_tier`, `required_tier`, and `limit_type` fields on all enforcement rejections

### Platform Operator Administration

- FR24: platform_admin can view real-time health status (last scan time, error rate, pod count) for all 18+ scan engines in a single dashboard
- FR25: platform_admin can view all active and recently completed Argo pipeline runs with status, duration, and error details
- FR26: platform_admin can view per-org subscription status, account count, user count, and last scan timestamp
- FR27: platform_admin can change any org's subscription tier effective immediately without going through Stripe checkout
- FR28: platform_admin can pause and resume scan access for any org
- FR29: platform_admin can view platform-wide aggregate metrics: total orgs, orgs per tier, scans in last 24 hours, total findings
- FR30: platform_admin can view and export the billing audit log filtered by org, date range, and event type

### User-Facing Billing Portal

- FR31: org_admin can access a billing portal showing current plan name, price, renewal date, and usage summary
- FR32: analyst and viewer roles can view their org's current subscription tier (read-only, no billing actions available)
- FR33: org_admin can view projected charges for the current billing period based on current usage
- FR34: org_admin can initiate plan upgrade, downgrade, or cancellation from the billing portal in ≤3 clicks

### API & System Integration

- FR35: API Gateway injects X-Subscription-Context header containing org tier and feature flags on all authenticated requests forwarded to engines
- FR36: engine-billing exposes REST endpoints for plan definitions, subscription state queries, and usage metrics consumed by Gateway and platform Django
- FR37: engine-platform-admin exposes REST endpoints for all operator dashboard data accessible only to platform_admin role
- FR38: system processes Stripe webhook events idempotently using Stripe event ID as deduplication key, rejecting duplicate events with HTTP 200 (not 500)
- FR39: platform Django /api/auth/me response includes subscription tier, trial status, trial days remaining, and account/user usage counts
- FR40: engine-onboarding enforces max_accounts limit by querying engine-billing subscription state before creating new provider or account records

## Non-Functional Requirements

### Performance

- Subscription enforcement check (X-Subscription-Context resolution) adds ≤10ms p99 to gateway request latency as measured by existing gateway APM
- Billing portal page loads current plan and usage data in ≤2 seconds p95 under normal load
- Platform admin dashboard renders full org grid (≤1000 orgs) in ≤3 seconds p95
- engine-billing REST API responds to subscription state queries in ≤50ms p99

### Security

- Threat Engine never stores, processes, or transmits raw card data; PCI scope limited to SAQ A-EP via Stripe Checkout
- All Stripe webhook payloads validated using HMAC-SHA256 Stripe-Signature header before processing; invalid signatures rejected with HTTP 400
- Billing audit log table is append-only; application service account has no UPDATE or DELETE privilege on `billing_audit_log`
- All billing API endpoints require valid session authentication; unauthenticated requests return HTTP 401
- engine-platform-admin validates `platform:admin` permission via `require_permission()` on every endpoint; non-platform_admin roles receive HTTP 403
- Billing DB credentials stored in AWS Secrets Manager; never in environment variables or config files
- Stripe API keys stored in AWS Secrets Manager; rotated on any suspected exposure
- TLS 1.2+ enforced on all external-facing endpoints; TLS 1.3 preferred

### Reliability

- engine-billing failure must not degrade any scan engine availability; Gateway uses cached subscription state from user_sessions when billing engine is unreachable
- engine-billing target uptime: 99.9% monthly (≤44 minutes downtime/month)
- Stripe webhook processing uses at-least-once delivery with idempotent handler; no webhook event may be permanently dropped
- Subscription state changes propagate to user_sessions cache within one session refresh cycle (≤60 seconds)
- engine-platform-admin degradation (dashboard unavailable) has zero impact on billing enforcement or scan operations

### Scalability

- engine-billing must handle 1,000 concurrent org subscription state queries without degradation; target 10,000 org scale within 12 months
- Platform admin dashboard must render accurately for up to 10,000 registered orgs
- Stripe webhook handler must process event bursts of ≥100 events/second during billing cycle events (month-end renewals)
- Billing DB designed with org-level partitioning to support horizontal scaling without schema changes

### Integration

- Stripe SDK version pinned in requirements.txt; upgrades require explicit review and test against Stripe test mode
- engine-billing communicates with engine-onboarding via internal Kubernetes service DNS only; no public internet calls between engines
- All inter-service HTTP calls use connection pooling with ≤5 second timeout and 3-retry with exponential backoff
- Stripe Customer Portal return URL validated against an allowlist of known frontend origins before redirect

## Open Questions

| # | Question | Owner | Target Resolution |
|---|----------|-------|------------------|
| 1 | What is the pricing for each tier ($/month)? | Product/Business | Before Sprint 1 |
| 2 | Should existing registered users be grandfathered on Pro for 90 days? | Product | Before MVP launch |
| 3 | Which AWS region for billing DB — same as platform DB (ap-south-1) or separate for GDPR? | Architect | Sprint 1 |
| 4 | Stripe test mode webhook secret for dev/staging environments — how to manage per-environment? | DevOps | Sprint 1 |
| 5 | Should trial be per email address or per email domain (to prevent trial abuse)? | Product | Sprint 1 |
| 6 | What is the grace period after payment failure before access is restricted? | Product/Legal | Sprint 1 |
| 7 | Does engine-platform-admin need a frontend UI, or is it API-only with platform_admin using the existing admin panel? | Product | Architecture phase |
