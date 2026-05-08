# CSPM Agent Binding Map

**Authority:** Governs how CSPM-specific agents and BMad generic agents are combined for every task type.
**Read by:** `cspm-orchestrator` (always), every CSPM agent (before delegating to BMad).

## Core Philosophy

```
CSPM Agent  = WHAT   — platform knowledge, DB schema, engine patterns, constitution enforcement
BMad Agent  = HOW    — SDLC process, story templates, sprint methodology, review checklists

Rule: CSPM agent ALWAYS leads on platform decisions.
      BMad agent ALWAYS leads on process/methodology decisions.
      They run together — one does not replace the other.
```

When a task arrives:
1. **cspm-orchestrator** classifies it by work type and layer.
2. It activates the relevant **CSPM agent** for platform context.
3. It activates the relevant **BMad agent/skill** for process structure.
4. Both run in concert — CSPM agent vetoes any BMad output that violates the Constitution.

---

## Binding Map by Work Type

### Requirements & Product

| Task | CSPM Agent (leads on: what to build, platform constraints) | BMad Agent/Skill (leads on: process, templates) |
|---|---|---|
| Define new feature or capability | `cspm-platform-context` (vision, competitive bar) | `bmad-pm` → PRD creation |
| Gather requirements | `cspm-platform-context` (current engine capabilities) | `bmad-analyst` → gap analysis, AC definition |
| Write product brief | `cspm-platform-context` (SaaS positioning) | `bmad-product-brief` |
| Prioritize backlog | `cspm-orchestrator` (pipeline dependencies) | `bmad-pm` → feature prioritization |
| Market/competitive research | `cspm-platform-context` (Wiz/Orca/Prisma context) | `bmad-market-research` |

### Sprint Planning & Story Creation

| Task | CSPM Agent | BMad Agent/Skill |
|---|---|---|
| Sprint planning | `cspm-orchestrator` (engine sequencing, pipeline order) | `bmad-sm` → sprint structure, dependency ordering |
| Create engine story | `cspm-<engine>-engineer` (schema, endpoints, patterns) | `bmad-create-story` or `bmad-security-po` (template + AC) |
| Create security story | `cspm-security-reviewer` (CSPM attack surfaces) | `bmad-security-po` (STRIDE, ATT&CK, CCM mapping) |
| Create UI story | `cspm-ui-dev` (page structure, BFF contract) | `bmad-create-story` → story file |
| Create DB migration story | `cspm-db-engineer` (schema, standard columns) | `bmad-create-story` |
| Validate story readiness | `cspm-standards-guardian` (constitution check) | `bmad-sm` → readiness gate |
| Sprint status check | `cspm-orchestrator` | `bmad-sprint-status` |

### Architecture & Design

| Task | CSPM Agent | BMad Agent/Skill |
|---|---|---|
| Design new engine | `cspm-architect` (pipeline fit, DB separation, standard columns) | `bmad-architect` → ADR, architecture doc |
| Security threat model | `cspm-security-reviewer` (CSPM attack surfaces: credential leakage, tenant isolation) | `bmad-security-architect` → STRIDE + PASTA + ATT&CK |
| Design new DB schema | `cspm-db-engineer` (standard columns, cross-engine linking) | `bmad-architect` → schema design doc |
| Design BFF view | `cspm-bff-dev` (no-fallback constitution, engine fan-out) | `bmad-architect` → API contract |
| Design new check rule | `cspm-rule-catalog-engineer` (YAML anatomy, routing) | `bmad-security-architect` → MITRE mapping |
| UX / page design | `cspm-ui-dev` (competitive bar, page structure standard) | `bmad-agent-ux-designer` → UX spec |

### Development (Implementation)

| Task | CSPM Agent (provides: schema, patterns, engine context) | BMad Agent/Skill (provides: implementation methodology) |
|---|---|---|
| Implement engine endpoint | `cspm-<engine>-engineer` | `bmad-dev` → code implementation |
| Implement BFF view handler | `cspm-bff-dev` (no-fallback, transform patterns) | `bmad-dev` |
| Implement UI page | `cspm-ui-dev` (fetchView, ENGINE_ENDPOINTS, skeleton screens) | `bmad-dev` |
| Implement DB migration | `cspm-db-engineer` (standard columns, migration pattern) | `bmad-dev` |
| Implement check rule | `cspm-rule-catalog-engineer` (YAML structure, MITRE, routing) | `bmad-dev` + `bmad-security-po` |
| Implement Django feature | `cspm-django-engineer` (tenant management, auth, audit logs) | `bmad-dev` |
| Implement K8s manifest | `cspm-k8s-engineer` (probes, limits, namespace, service ports) | `bmad-dev` |
| Implement Argo pipeline step | `cspm-argo-engineer` (DAG order, engine names, scan_run_id) | `bmad-dev` |
| Run a dev story end-to-end | `cspm-<engine>-engineer` for context | `bmad-dev-story` → story execution |

### Quality Gates (always run in this order after dev)

```
Dev complete
    │
    ▼
cspm-code-reviewer          ← CSPM patterns: standard columns, JSONB rules, tenant_id scoping, no-fallback BFF
    │ pass
    ▼
cspm-security-reviewer      ← OWASP Top 10 + CSPM-specific: credential leakage, SSRF, tenant isolation, no-bypass-auth
+ bmad-security-reviewer    ← SLSA checklist, pinned images, CCM domain mapping
    │ pass
    ▼
cspm-qa-engineer            ← end-to-end: findings in DB, BFF view returns correct shape, pipeline completes
+ bmad-qa                   ← formal AC verification against story file
    │ pass
    ▼
cspm-deploy                 ← build → push → apply → rollout → logs
    │ pass
    ▼
cspm-integration-tester     ← cross-engine: scan_run_id threading, DB linkage, BFF view contracts
```

No stage may be skipped. If any gate fails, return to dev — do not proceed to the next gate.

### Security-Specific Work

| Task | CSPM Agent | BMad Agent/Skill |
|---|---|---|
| RBAC enforcement review | `cspm-rbac-guardian` (27 permissions, 5 roles, field stripping) | `bmad-security-reviewer` |
| New engine security design | `cspm-security-reviewer` (tenant isolation, no-bypass) | `bmad-security-architect` (STRIDE + PASTA) |
| Check rule security mapping | `cspm-rule-catalog-engineer` | `bmad-security-po` (MITRE, D3FEND, CCM, NIST CSF) |
| Security audit of changes | `cspm-security-reviewer` | `bmad-security-reviewer` (OWASP checklist) |
| Adversarial review | `cspm-code-reviewer` | `bmad-review-adversarial-general` |

### Infrastructure & Deployment

| Task | CSPM Agent | BMad Agent/Skill |
|---|---|---|
| Build + deploy engine | `cspm-deploy` (exact 6-step workflow) | none — infrastructure is CSPM-specific |
| K8s manifest creation/update | `cspm-k8s-engineer` | none |
| Argo workflow changes | `cspm-argo-engineer` | none |
| AWS infra changes | `cspm-aws-engineer` | none |
| DB migration apply | `cspm-db-engineer` | none |
| Scan trigger | `cspm-pipeline-engineer` | none |
| Observability setup | `cspm-observability-engineer` | none |

> Infrastructure tasks have no BMad equivalent — CSPM agents handle them alone.

### Documentation & Knowledge

| Task | CSPM Agent | BMad Agent/Skill |
|---|---|---|
| Write technical docs | `cspm-platform-context` (accuracy on platform specifics) | `bmad-agent-tech-writer` |
| Document a new engine | `cspm-<engine>-engineer` (schema, endpoints, patterns) | `bmad-agent-tech-writer` |
| Update API reference | `cspm-<engine>-engineer` | `bmad-agent-tech-writer` |
| Retrospective | `cspm-orchestrator` (sprint outcomes vs pipeline health) | `bmad-retrospective` |
| Brainstorming | `cspm-platform-context` | `bmad-brainstorming` |

---

## Binding Map by Layer

When a task touches a specific layer, these are the default agents activated:

| Layer | Primary CSPM Agent | Secondary CSPM Agent | Complementary BMad |
|---|---|---|---|
| Frontend / UI | `cspm-ui-dev` | `cspm-standards-guardian` | `bmad-dev`, `bmad-agent-ux-designer` |
| BFF View Handlers | `cspm-bff-dev` | `cspm-standards-guardian` | `bmad-dev` |
| API Gateway / Auth | `cspm-gateway-dev` | `cspm-rbac-guardian` | `bmad-security-architect` |
| Django Platform | `cspm-django-engineer` | `cspm-rbac-guardian` | `bmad-dev` |
| Discovery Engine | `discoveries` agent | `cspm-pipeline-engineer` | `bmad-dev` |
| Inventory Engine | `inventory` agent | `cspm-db-engineer` | `bmad-dev` |
| Check Engine | `check` agent | `cspm-rule-catalog-engineer` | `bmad-dev`, `bmad-security-po` |
| Threat Engine | `threat` agent | `cspm-pipeline-engineer` | `bmad-dev`, `bmad-security-architect` |
| Compliance Engine | `compliance` agent | `cspm-rule-catalog-engineer` | `bmad-dev` |
| Network Engine | `cspm-network-engineer` | `cspm-pipeline-engineer` | `bmad-dev`, `bmad-security-architect` |
| IAM Engine | `iam` agent | `cspm-security-reviewer` | `bmad-dev` |
| CIEM Engine | `cspm-ciem-engineer` | `cspm-pipeline-engineer` | `bmad-dev`, `bmad-security-po` |
| DataSec Engine | `datasec` agent | `cspm-security-reviewer` | `bmad-dev` |
| Vulnerability Engine | `cspm-vulnerability-engineer` | `cspm-k8s-engineer` (spot nodes) | `bmad-dev` |
| Risk Engine | `risk` agent | `cspm-pipeline-engineer` | `bmad-dev` |
| SecOps Engine | `secops` agent | `cspm-rule-catalog-engineer` | `bmad-dev` |
| Database / Schema | `cspm-db-engineer` | `cspm-standards-guardian` | `bmad-dev` |
| K8s Manifests | `cspm-k8s-engineer` | — | none |
| Argo Workflows | `cspm-argo-engineer` | `cspm-pipeline-engineer` | none |
| AWS Infrastructure | `cspm-aws-engineer` | — | none |
| Rule / YAML Catalog | `cspm-rule-catalog-engineer` | `cspm-standards-guardian` | `bmad-security-po` |
| Observability | `cspm-observability-engineer` | — | none |

---

## Default Call Chain for Common Requests

### "Build a new engine feature"
```
cspm-orchestrator
  → cspm-<engine>-engineer       (schema, endpoint patterns, standard columns)
  → cspm-standards-guardian       (constitution check on design)
  → bmad-security-architect       (STRIDE threat model if new endpoint)
  → bmad-dev                      (implementation)
  → cspm-code-reviewer            (CSPM pattern review)
  → cspm-security-reviewer        (OWASP + CSPM security)
  → cspm-qa-engineer              (findings validation)
  → cspm-deploy                   (build + deploy)
```

### "Add a new check rule"
```
cspm-orchestrator
  → cspm-rule-catalog-engineer    (YAML anatomy, routing, service classification)
  → bmad-security-po              (MITRE ATT&CK, D3FEND, CCM, NIST CSF mapping)
  → bmad-dev                      (implementation)
  → cspm-code-reviewer            (rule structure validation)
  → cspm-security-reviewer        (ATT&CK coverage check)
  → cspm-qa-engineer              (verify rule fires in scan)
```

### "Build a new UI page"
```
cspm-orchestrator
  → cspm-ui-dev                   (page structure, BFF contract, competitive bar)
  → cspm-bff-dev                  (view handler, engine fan-out, no-fallback)
  → bmad-agent-ux-designer        (UX spec if net-new design)
  → bmad-dev                      (implementation)
  → cspm-code-reviewer            (BFF split compliance, skeleton screens, severity colors)
  → cspm-qa-engineer              (BFF view returns correct shape, UI renders correctly)
```

### "Deploy an engine"
```
cspm-deploy                       (self-contained — no BMad needed)
  → docker build
  → docker push
  → kubectl apply
  → kubectl rollout status
  → kubectl logs
```

### "Plan a sprint"
```
cspm-orchestrator
  → cspm-pipeline-engineer        (engine sequencing, pipeline dependencies)
  → bmad-sm                       (sprint structure, story validation, sequencing)
  → cspm-standards-guardian       (each story passes constitution check)
  → bmad-po                       (story file creation per spec)
```

### "Security review before merge"
```
cspm-security-reviewer            (CSPM-specific: tenant isolation, no-bypass, JSONB, credential_ref)
  + bmad-security-reviewer        (OWASP Top 10, SLSA, CCM domain)
  → if both pass: approve
  → if either fails: block merge, return to dev with specific violations cited
```

---

## Conflict Resolution Rules

When CSPM agent and BMad agent give conflicting guidance:

1. **Constitution violation**: CSPM agent wins, always. No BMad process overrides a constitution rule.
2. **Platform-specific pattern**: CSPM agent wins. BMad does not know your DB schema or engine patterns.
3. **SDLC process/methodology**: BMad wins. CSPM agents do not define how to structure a PRD or run a retrospective.
4. **Security framework compliance**: BMad security agents (bmad-security-architect, bmad-security-reviewer) win — they are the authoritative OWASP/ATT&CK enforcers. CSPM security agents add platform-specific checks on top.
5. **Ambiguous**: `cspm-orchestrator` decides. If still unclear, ask the user.

---

## What BMad Agents Handle That CSPM Agents Do Not

| BMad Agent/Skill | What it provides that has no CSPM equivalent |
|---|---|
| `bmad-pm` | PRD structure, feature prioritization frameworks, market sizing |
| `bmad-analyst` | Requirements elicitation methodology, gap analysis templates |
| `bmad-agent-ux-designer` | UX research methods, wireframe conventions, design system |
| `bmad-retrospective` | Sprint retrospective facilitation, lessons-learned format |
| `bmad-brainstorming` | Creative ideation techniques |
| `bmad-prfaq` | Working-backwards press release format |
| `bmad-distillator` | Document compression for LLM context optimization |
| `bmad-review-adversarial-general` | Cynical/adversarial review methodology |
| `bmad-code-review` | Parallel blind review methodology |
| `bmad-edit-prd` | PRD editing workflow |

## What CSPM Agents Handle That BMad Agents Cannot

| CSPM Agent | What it provides that BMad has no concept of |
|---|---|
| `cspm-standards-guardian` | Standard columns, JSONB rules, no-fallback BFF, no-bypass-auth, scan_run_id threading |
| `cspm-rbac-guardian` | 27-permission matrix, 5 roles, require_permission, strip_sensitive_fields |
| `cspm-pipeline-engineer` | Argo DAG order, trigger-scan.sh engine names, scan_orchestration JSONB |
| `cspm-db-engineer` | rule_discoveries in check DB (not discoveries DB), cross-engine DB isolation |
| `cspm-deploy` | Exact 6-step EKS deploy workflow, image tag conventions, namespace |
| `cspm-k8s-engineer` | threat-engine-engines namespace, port conventions, spot node tolerations |
| `cspm-argo-engineer` | Argo template names, cron vs main pipeline, scan_run_id param passing |
| `cspm-network-engineer` | 7-layer topology model, effective_exposure vs blast_radius distinction |
| `cspm-rule-catalog-engineer` | YAML rule anatomy, rule routing (check vs ciem vs network), catalog structure |
| `cspm-integration-tester` | scan_run_id threading across 8 DBs, BFF view contract validation |

---

## Security Extension Bindings — When Each Security Agent Fires

These three BMad security extensions are the most important specialist agents in the stack. They are not always needed — trigger them based on the conditions below.

### `bmad-security-architect`

**What it does:** STRIDE + PASTA + MITRE ATT&CK + D3FEND threat modeling, security design review, attack surface analysis. Extends bmad-architect with OWASP SAMM Design function.

**Fire when:**
- Any new engine is being designed (before dev starts)
- Any new API endpoint that touches credentials, IAM, or network data
- Any new DB schema that stores `credential_ref`, tokens, or secrets
- Changes to the auth flow (gateway, middleware, AuthContext)
- Changes to multi-tenancy isolation logic
- Network engine topology changes
- New Argo pipeline step that handles credentials

**Do NOT fire for:** Bug fixes, BFF view additions, UI-only changes, rule YAML updates with no new endpoint.

**Always pairs with:** `cspm-security-reviewer` (CSPM attack surfaces) + `cspm-architect` (platform fit).

---

### `bmad-security-po`

**What it does:** Converts security sprint tasks into story files with full threat models, ATT&CK mappings, and security-specific acceptance criteria. Extends OWASP SAMM Governance function.

**Fire when:**
- Creating a story for any security engine (check, threat, network, CIEM, IAM, vuln, datasec)
- Creating a story that introduces a new check rule (needs ATT&CK + D3FEND + CCM mapping)
- Creating a story for auth changes, RBAC changes, or credential handling
- Any story where the acceptance criteria includes "must not expose to unauthorized users"

**Do NOT fire for:** Pure infrastructure stories (K8s manifest changes, deploy scripts), UI-only cosmetic changes, documentation updates.

**Always pairs with:** `cspm-rule-catalog-engineer` (for rule stories) or `cspm-<engine>-engineer` (for engine stories).

---

### `bmad-security-reviewer`

**What it does:** Security code review gate before merge. Checks injection, tenant isolation, credential leakage, SSRF, OWASP Top 10. Extends OWASP SAMM Implementation + Verification functions.

**Fire when (always fire — this is a mandatory gate for these cases):**
- Any PR touching engine endpoint code
- Any PR touching auth, middleware, or RBAC logic
- Any PR touching credential handling or Secrets Manager access
- Any PR touching DB queries (SQL injection check)
- Any PR touching outbound HTTP calls (SSRF check)
- Any PR touching the BFF (tenant data isolation check)

**Do NOT fire for:** K8s manifest-only changes, documentation changes, frontend CSS/styling-only changes.

**Always pairs with:** `cspm-security-reviewer` (runs first for CSPM-specific patterns, then hands off to bmad-security-reviewer for OWASP checklist).

---

## All Available Agents — Full Reference with Trigger Conditions

### BMad Core Agents (use for SDLC process alongside CSPM agents)

| Agent | Trigger Condition | Never Use For |
|---|---|---|
| `bmad-orchestrator` | Multi-step work where you need BMad to route between its own agents | CSPM-specific routing — use cspm-orchestrator instead |
| `bmad-pm` | PRD creation, feature scoping, release planning, competitive framework coverage decisions | Technical implementation decisions |
| `bmad-analyst` | Requirements gathering, gap analysis, AC definition, business case docs | Architecture decisions |
| `bmad-architect` | Technical design, ADRs, cross-cutting concerns, technology choices | CSPM-specific schema/port/pattern decisions |
| `bmad-dev` | Code implementation, story execution | Platform-specific patterns — defer to CSPM engine agents for context |
| `bmad-po` | Convert sprint tasks to atomic story files with full context | Story execution |
| `bmad-qa` | Test plans, E2E acceptance testing, story completion verification | CSPM scan-level validation — use cspm-qa-engineer |
| `bmad-sm` | Sprint planning, story validation, dependency sequencing, unblocking | Engine pipeline ordering — use cspm-orchestrator |
| `bmad-security-architect` | New engine design, credential/IAM/network endpoints, auth flow changes | Bug fixes, BFF additions, UI-only |
| `bmad-security-po` | Stories for security engines, check rules, RBAC changes, auth changes | Infrastructure, UI-only, doc-only stories |
| `bmad-security-reviewer` | Any PR with endpoint code, auth, DB queries, outbound HTTP, RBAC | Manifest-only, doc-only, CSS-only PRs |

### BMad Skills (invoke as `/skill-name` — trigger as needed)

| Skill | Trigger Condition |
|---|---|
| `bmad-create-story` | Any new feature story that is not a security engine story |
| `bmad-dev-story` | Executing a story file end-to-end |
| `bmad-create-epics-and-stories` | Breaking a PRD/requirement into epics and stories |
| `bmad-sprint-planning` | Start of every sprint — generates sprint status tracking from epics |
| `bmad-sprint-status` | Mid-sprint check-in — surfaces risks and blockers |
| `bmad-create-prd` | New feature area with no existing PRD |
| `bmad-edit-prd` | Changing scope of an existing PRD |
| `bmad-validate-prd` | Before sprint planning — verify PRD completeness |
| `bmad-check-implementation-readiness` | Before dev starts — validate PRD + UX + Architecture are complete |
| `bmad-create-architecture` | New engine or major refactor — architecture solution design |
| `bmad-code-review` | Parallel blind code review (3 layers: Hunter, Edge Case, Standards) |
| `bmad-review-adversarial-general` | Cynical review of any design or implementation |
| `bmad-review-edge-case-hunter` | Walk every branching path — use before QA on complex scan logic |
| `bmad-qa-generate-e2e-tests` | After a feature is implemented — generate automated E2E tests |
| `bmad-retrospective` | Post-sprint or post-epic review |
| `bmad-correct-course` | Significant scope change mid-sprint |
| `bmad-agent-ux-designer` | Net-new UI page or major UX redesign |
| `bmad-agent-tech-writer` | Writing or updating any docs in `.claude/documentation/` |
| `bmad-create-ux-design` | Plan UX patterns for a new engine page |
| `bmad-brainstorming` | Open-ended exploration of solutions or features |
| `bmad-prfaq` | Working-backwards product concept challenge |
| `bmad-advanced-elicitation` | Push for refinement on any output that feels incomplete |
| `bmad-document-project` | Document a brownfield engine that has no docs yet |
| `bmad-index-docs` | Regenerate docs index after adding new documentation |
| `bmad-distillator` | Compress large docs for LLM context optimization |
| `bmad-market-research` | Competitive analysis vs Wiz / Orca / Prisma |
| `bmad-domain-research` | Cloud security domain research |
| `bmad-technical-research` | Deep-dive on a specific technology (e.g., Neo4j graph queries, Argo DAG patterns) |
| `bmad-shard-doc` | Split large documentation into organized smaller files |
| `bmad-generate-project-context` | Regenerate project-context.md for AI context rules |
| `bmad-party-mode` | Multi-agent group discussion — for complex cross-domain decisions |
| `bmad-checkpoint-preview` | Human-in-the-loop review before a large change is applied |

### Built-in Claude Code Skills

| Skill | Trigger Condition |
|---|---|
| `/review` | Review any open GitHub PR — use before merge alongside bmad-security-reviewer |
| `/security-review` | Full security review of all changes on the current branch |
| `/simplify` | After implementation — simplify and refine changed code for clarity |
| `/fewer-permission-prompts` | When getting too many tool approval prompts — add to allowlist |
| `/init` | Reinitialize CLAUDE.md if it becomes stale |

### CSPM Custom Skills (to be built in `.claude/commands/`)

| Skill | Trigger Condition |
|---|---|
| `/cspm-deploy` | Any time an engine image needs to be deployed to EKS |
| `/cspm-new-engine` | Scaffolding a brand-new engine |
| `/cspm-new-rule` | Adding a new check rule to the catalog |
| `/cspm-new-bff-view` | Adding a new BFF view handler |
| `/cspm-new-ui-page` | Adding a new Next.js engine page |
| `/cspm-scan-trigger` | Triggering an Argo scan pipeline |
| `/cspm-scan-status` | Checking scan_orchestration for a scan_run_id |
| `/cspm-scan-findings` | Querying findings count per engine for a run |
| `/cspm-db-migrate` | Creating and applying a DB migration |
| `/cspm-db-query` | Ad-hoc SQL query via kubectl exec |
| `/cspm-k8s-status` | Check all deployments/pods in threat-engine-engines namespace |
| `/cspm-k8s-logs` | Tail logs for a specific engine |
| `/cspm-review` | CSPM-specific code review (constitution + patterns) |
| `/cspm-qa-validate` | End-to-end scan validation |
| `/cspm-new-story` | Create a CSPM story file with engine context |
| `/cspm-sprint-plan` | Plan a sprint with pipeline sequencing |

---

## Complete Trigger Decision Tree

```
New task arrives at cspm-orchestrator
│
├── Is it a PRODUCT decision? (what to build, prioritization)
│   ├── Feature definition       → cspm-platform-context + bmad-pm
│   ├── Requirements             → cspm-platform-context + bmad-analyst
│   └── Market/competitive       → cspm-platform-context + bmad-market-research
│
├── Is it ARCHITECTURE? (how to design it)
│   ├── New engine               → cspm-architect + bmad-architect + bmad-security-architect ← ALWAYS
│   ├── New endpoint (cred/IAM)  → cspm-architect + bmad-security-architect ← ALWAYS
│   ├── New DB schema            → cspm-db-engineer + cspm-standards-guardian + bmad-architect
│   └── New BFF view             → cspm-bff-dev + bmad-architect
│
├── Is it a STORY? (defining what dev will build)
│   ├── Security engine story    → cspm-<engine>-engineer + bmad-security-po ← ALWAYS
│   ├── Non-security story       → cspm-<engine>-engineer + bmad-create-story
│   └── Check rule story         → cspm-rule-catalog-engineer + bmad-security-po ← ALWAYS
│
├── Is it IMPLEMENTATION? (writing code)
│   ├── Engine code              → cspm-<engine>-engineer + bmad-dev
│   ├── BFF view                 → cspm-bff-dev + bmad-dev
│   ├── UI page                  → cspm-ui-dev + bmad-dev
│   ├── DB migration             → cspm-db-engineer + bmad-dev
│   ├── K8s manifest             → cspm-k8s-engineer (alone)
│   └── Argo pipeline            → cspm-argo-engineer (alone)
│
├── Is it QUALITY / REVIEW? (checking what was built)
│   ├── Code review (always)     → cspm-code-reviewer
│   ├── Security review (always) → cspm-security-reviewer + bmad-security-reviewer
│   ├── Adversarial review       → bmad-review-adversarial-general
│   ├── Edge case hunt           → bmad-review-edge-case-hunter
│   └── PR review                → /review skill
│
├── Is it QA / VALIDATION?
│   ├── Story AC verification    → cspm-qa-engineer + bmad-qa
│   ├── E2E test generation      → bmad-qa-generate-e2e-tests
│   └── Integration test         → cspm-integration-tester
│
├── Is it DEPLOYMENT?
│   └── Any engine               → /cspm-deploy (self-contained)
│
├── Is it SPRINT MANAGEMENT?
│   ├── Sprint planning          → cspm-orchestrator + bmad-sm + bmad-po
│   ├── Sprint status            → bmad-sprint-status
│   └── Retrospective            → bmad-retrospective
│
└── Is it DOCUMENTATION?
    ├── Technical docs           → cspm-<relevant>-engineer + bmad-agent-tech-writer
    └── Index/compress docs      → bmad-index-docs / bmad-distillator
```

---

## Binding Enforcement

The `cspm-orchestrator` agent **MUST** use this document to route every incoming task.

Every CSPM agent **MUST** state in its first response which BMad agents it are working alongside for the current task, so the user always knows the full active agent set.

Every session starts with: `cspm-orchestrator` reads this document + `CSPM_CONSTITUTION.md` + `CLAUDE.md` before routing any task.
