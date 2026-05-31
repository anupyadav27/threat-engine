# CSPM Platform — Desktop Context Bundle

Paste this file at the start of any Claude Desktop session about this codebase.
It provides the Tier 0 routing context that Claude Code loads automatically.

---

## What This Platform Is

Multi-cloud CSPM platform (AWS/Azure/GCP/OCI/AliCloud/IBM/K8s).
25 FastAPI microengines + Next.js 15 frontend + Django auth layer + Argo pipeline.
Namespace: `threat-engine-engines` | EKS: `ap-south-1` | Gateway ELB: `a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com`

---

## Engine Pipeline Order

```
Onboarding(0) → Discovery(1) → Inventory(2) → Check(3) → Threat(4)
  → [Compliance / IAM / DataSec / Network / Encryption / Container / AI / DBSec / CDR / Vuln](5 parallel)
  → Graph-Build(6) → Risk(7) → Threat-Narrative(8)
```

---

## Engine Routing (from agents.ndjson)

| Engine | Stage | K8s svc | Gateway prefix | Agent file |
|--------|-------|---------|----------------|------------|
| onboarding | 0 | engine-onboarding | /api/v1/cloud-accounts | agents/onboarding.md |
| discoveries | 1 | engine-discoveries | /api/v1/discovery | agents/discoveries.md |
| inventory | 2 | engine-inventory | /api/v1/inventory | agents/inventory.md |
| check | 3 | engine-check | /api/v1/check | agents/check.md |
| threat | 4 | engine-threat | /api/v1/threat | agents/threat.md |
| threat-v1 | 4 | engine-threat-v1 | /api/v1/incidents | agents/threat.md |
| compliance | 5 | engine-compliance | /api/v1/compliance | agents/compliance.md |
| iam | 5 | engine-iam | /api/v1/iam-security | agents/iam.md |
| datasec | 5 | engine-datasec | /api/v1/data-security | agents/datasec.md |
| network-security | 5 | engine-network | /api/v1/network-security | agents/network-security.md |
| encryption | 5 | engine-encryption | /api/v1/encryption | agents/encryption.md |
| container-security | 5 | engine-container-sec | /api/v1/container-security | agents/container-security.md |
| ai-security | 5 | engine-ai-security | /api/v1/ai-security | agents/ai-security.md |
| dbsec | 5 | engine-dbsec | /api/v1/database-security | agents/dbsec.md |
| cdr | 5* | engine-cdr | /api/v1/ciem | agents/cdr.md |
| vulnerability | 5* | engine-vulnerability | /api/v1/vulnerabilities | agents/vulnerability.md |
| secops | — | engine-secops | /api/v1/secops | agents/secops.md |
| risk | 7 | engine-risk | /api/v1/risk | agents/risk.md |
| rule | — | engine-rule | /api/v1/rules | agents/check.md |
| billing | — | engine-billing | /api/v1/billing | agents/billing.md |
| platform-admin | — | engine-platform-admin | /api/v1/padmin | agents/platform-admin.md |

*independent CronWorkflow, not in main Argo DAG

---

## UI → BFF → Engine Calling Rules

**Two patterns — never mix on the same data:**

```
fetchView("page")           → /gateway/api/v1/views/{page}
  USE FOR: charts, KPIs, summaries, aggregated data
  NEVER FOR: raw tables, user mutations

getFromEngine("engine", "/api/v1/path")  → ingress → engine direct
  USE FOR: paginated findings, raw records, suppress/delete/update
  NEVER FOR: data needing multiple engines
```

**Tenant resolution order:**
1. `X-Active-Tenant-Id` header (UI localStorage)
2. `AuthContext.engine_tenant_id` (session token)
3. `AuthContext.tenant_ids[0]` (fallback)

**Auth flow:** `access_token` cookie → Gateway AuthMiddleware → `X-Auth-Context` header → BFF patches tenant → Engine scopes DB query.

---

## Constitution Non-Negotiables

- Multi-tenant always — every DB query scoped by `tenant_id`
- Standard DB columns on every findings table: `finding_id, scan_run_id, tenant_id, account_id, credential_ref, credential_type, provider, region, resource_uid, resource_type, severity, status, first_seen_at, last_seen_at`
- JSONB auto-deserialised by psycopg2 — never call `json.loads()` on JSONB
- No `latest` image tag ever in any K8s manifest
- No `DEV_BYPASS_AUTH` ever
- BFF returns empty when engine is empty — never add fallback/mock data
- `require_permission()` on every engine endpoint

---

## Tool Decision (for Claude Code users)

| Task | Use |
|------|-----|
| Query DB | `/cspm-db-query` skill |
| View logs | `/cspm-k8s-logs` skill |
| Deploy | `/cspm-deploy` skill |
| Generate story | `cspm-po` agent |
| Run QA | `cspm-qa` agent |
| Route unclear task | `cspm-orchestrator` agent |

---

## Key File Locations

```
.claude/context/agents.ndjson       ← engine routing registry
.claude/context/bff_contract.ndjson ← per-BFF-view contracts
.claude/context/api_patterns.xml    ← calling rules + auth flow
.claude/context/process.xml         ← SDLC stages + security gates
.claude/context/data_flow.ndjson    ← UI→BFF→Engine map (auto-generated)
.claude/agents/{engine}.md          ← full engine context (DB, API, K8s)
shared/api_gateway/bff/             ← 98 BFF handler files
shared/api_gateway/main.py          ← SERVICE_ROUTES + gateway routing
frontend/src/lib/constants.js       ← ENGINE_ENDPOINTS + NAV_ITEMS
```

---

## Current Image Tags (verify against MEMORY.md — may be stale)

| Engine | Tag |
|--------|-----|
| check | v-check-custom1 |
| threat | v-graph-sprint5-auth |
| threat-v1 | v-threat-v1-phase20 |
| gateway | v-bff-threat1 |
| frontend | v-provision-org1 |
| cspm-backend | v-provision-org1 |
| inventory | v-inventory-auth |
| compliance | v-compliance-cdr1 |
| cdr | v-cdr-internal-auth1 |
| onboarding | v-onboard-agent-auth1 |
| vulnerability | v-vuln-agent-auth1 |

Full table: `.claude/projects/-Users-apple-Desktop-threat-engine/memory/MEMORY.md`
