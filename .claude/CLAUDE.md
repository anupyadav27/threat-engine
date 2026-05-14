# Threat Engine Development Guide

## AGENT AUTO-ROUTING — Read Before Every Task

**Claude must self-select the right specialist agent before doing any work. Never work on engine code without loading its agent.**

### Step 1 — Identify the target
| User mentions... | Auto-load this agent |
|------------------|---------------------|
| discovery, disc, `engine-discoveries` | `discoveries` |
| inventory, assets, relationships | `inventory` |
| check, rules, PASS/FAIL, rule_metadata | `check` |
| threat, MITRE, attack path, Neo4j | `threat` |
| compliance, CIS, NIST, framework score | `compliance` |
| network, SG, VPC, topology, 7-layer | `network-security` |
| IAM, identity, MFA, policy, root account | `iam` |
| CDR, cloud detection, log analysis, VPC Flow, behavioral detection | `cdr` |
| risk, FAIR, exposure, blast radius score | `risk` |
| datasec, data security, DSPM, S3 classification | `datasec` |
| vulnerability, CVE, SBOM, agent-based | `vulnerability` |
| secops, SAST, DAST, SCA, IaC scan | `secops` |
| onboarding, cloud account, scan orchestration | `onboarding` |
| CNAPP, unified posture | `cnapp` |
| CWPP, workload protection | `cwpp` |
| container security, EKS, K8s RBAC | `container-security` |
| encryption, KMS, certificates, TLS | `encryption` |
| database security, RDS, audit logging | `dbsec` |
| AI security, SageMaker, Bedrock, ML | `ai-security` |
| billing, subscription, Stripe | `billing` |
| platform admin, org management | `platform-admin` |
| pipeline monitor, scan progress, SSE | `pipeline-monitor` |
| technology engine, tech-check, 34 techs | `technology-engine` |
| secops fix, AI code fix, SAST remediation | `secops-fix` |
| vuln fix, Ansible playbook, CVE fix | `vul-fix` |
| multi-engine, pipeline order, Argo | `cspm-engine-orchestrator` |

### Step 2 — Spawn the agent (required)
Use `subagent_type: "<agent-name>"` when invoking via the Agent tool. The agent file lives at `.claude/agents/<agent-name>.md`. Load it as context before touching any code for that engine.

### Step 3 — Apply security gates automatically
- Any PR touching endpoint / auth / DB / HTTP → also invoke `bmad-security-reviewer`
- Any new engine design → also invoke `bmad-security-architect` first
- Any new check rule or security engine story → also invoke `bmad-security-po`

**If the task spans multiple engines** → start with `cspm-engine-orchestrator` to establish cross-engine context, then spawn per-engine agents as needed.

**If the user gives no engine context** → ask which engine before proceeding.

---

## CONSTITUTION — Read First

**Every agent and every code change is governed by the CSPM Platform Constitution.**
Full rules at: `.claude/documentation/CSPM_CONSTITUTION.md`
Agent routing rules: `.claude/documentation/AGENT_BINDING.md`
Testing & quality gates: `.claude/documentation/TESTING_QUALITY.md`

Key non-negotiables (memorize these):
- **Multi-tenant always** — every DB query scoped by `tenant_id` from `AuthContext`
- **Database-first** — schema is defined before code; standard columns are mandatory on every findings table
- **BFF for charts/aggregates** — `fetchView(page)` only; never add fallback/mock data in BFF
- **Engine gateway for tables** — paginated raw findings go direct to engine via gateway
- **No DEV_BYPASS_AUTH** — ever, for any reason
- **No `latest` image tag** — ever, in any K8s manifest
- **RBAC at every layer** — Gateway → Engine → DB; `require_permission()` on every endpoint
- **JSONB is already a dict** — never call `json.loads()` on psycopg2 JSONB results
- **UI competes with Wiz/Orca** — skeleton screens, risk score prominent, severity colors consistent, side-panel drilldown

Agent binding rules (memorize these):
- **cspm-security-reviewer + bmad-security-reviewer** — mandatory on every PR with endpoint/auth/DB/HTTP code
- **bmad-security-architect** — mandatory on every new engine or credential/IAM/network endpoint (design gate)
- **bmad-security-po** — mandatory on every security engine story or check rule story
- **cspm-orchestrator** — always the entry point; reads AGENT_BINDING.md before routing
- **cspm-standards-guardian** — checks every design/story for constitution violations before dev starts

Quality gate rules (memorize these):
- **10-level quality stack** — Static → Unit → Code Review → Security Review → Integration → QA → Deploy → Post-Deploy
- **No gate skipping** — every level must pass before the next opens; failed gate returns to dev
- **BFF contract coverage = 100%** — every view handler has a contract test
- **RBAC coverage = 100%** — all 5 roles × all engine endpoints tested
- **Post-deploy = mandatory** — health check + log check + BFF smoke after every rollout; fail → immediate rollback
- **Rule regression = 0 drift** — baseline `tests/regression/baselines/rule_finding_counts.json` must not change without explicit update

## Project Overview
Comprehensive Cloud Security Posture Management (CSPM) platform for multi-cloud environments supporting AWS, Azure, GCP, OCI, AliCloud, and IBM Cloud with:
- **Discovery scanning**: Enumerate 40+ cloud services and resources
- **Compliance evaluation**: Map findings to 13+ frameworks (CIS, NIST, ISO 27001, PCI-DSS, HIPAA, GDPR, SOC 2)
- **Threat detection**: MITRE ATT&CK technique mapping, risk scoring (0-100)
- **Network security**: 7-layer topology analysis (isolation → reachability → ACL → SG → LB → WAF → monitoring)
- **Security analysis**: IAM posture, Data security, CDR, Vulnerability scanning

## Repository Structure

```
threat-engine/
├── engines/          # All runtime microservices (FastAPI)
├── platform/         # Django identity & tenant layer
├── frontend/         # Next.js CSPM portal UI
├── shared/           # Shared utilities, API gateway, DB schemas
├── catalog/          # YAML rules + discovery data
├── deployment/       # EKS manifests + local K8s configs
└── scripts/          # DB migrations, build helpers
```

### Core Engines (`engines/`)
- `engines/onboarding/`: Multi-cloud account onboarding and credential management (Port 8008)
- `engines/discoveries/`: Cloud resource discovery and enumeration (Port 8001)
- `engines/check/`: Compliance rule evaluation - PASS/FAIL assessment (Port 8002)
- `engines/inventory/`: Asset normalization, relationships, drift detection (Port 8022)
- `engines/threat/`: Threat detection, MITRE mapping, attack chains (Port 8020)
- `engines/compliance/`: Framework reporting and compliance scoring (Port 8000)
- `engines/iam/`: IAM security posture analysis
- `engines/datasec/`: Data security and classification (Port 8003)
- `engines/secops/`: IaC scanning (14 languages) (Port 8005)
- `engines/network-security/`: 7-layer network topology analysis (Port 8004)
- `engines/cdr/`: CDR — Cloud Detection & Response
- `engines/risk/`: Risk scoring and blast radius computation
- `engines/rule/`: YAML rule management (Port 8011)
- `engines/vulnerability/`: Vulnerability scanning (SBOM, DAST, CVE)
- `engines/fix/secops_fix/`: AI remediation for IaC findings
- `engines/fix/vul_fix/`: AI remediation for vulnerability findings

### Platform (`platform/`)
- `platform/cspm-backend/`: Django 6 app — user auth, SSO (SAML/Google), tenant CRUD, audit logs

### Frontend (`frontend/`)
- Next.js 15 + React 19 CSPM portal
- `frontend/src/lib/api.js`: `fetchView(page)` → `/gateway/api/v1/views/{page}` (BFF pattern)
- `frontend/src/lib/constants.js`: `ENGINE_ENDPOINTS` map and nav config

### Shared Services (`shared/`)
- `shared/database/`: PostgreSQL schemas, migrations, database config
- `shared/common/`: Shared Python utilities across all engines (`engine_common` in Docker)
- `shared/api_gateway/`: Central API routing + BFF view handlers (`bff/`)
- `shared/auth/`: Authentication utilities

### Data Catalog (`catalog/`)
- `catalog/rule/`: Check rules per CSP (`aws_rule_check/`, `azure_rule_check/`, etc.)
- `catalog/discovery_generator_data/`: Step6 discovery YAML files (authoritative source)
- `catalog/rule/upload_rule_metadata_all_csps.py`: Tags rules with engine metadata in DB

### Infrastructure
- `deployment/aws/eks/`: Kubernetes manifests for EKS
- `deployment/aws/eks/argo/`: Argo Workflow pipeline definitions
- `deployment/local/`: Local/dev K8s configs and docker-compose

## Important Paths (Always Use Absolute Paths)

**CRITICAL:** Agent threads reset working directory between bash calls.
Always use absolute paths: `/Users/apple/Desktop/threat-engine/...`

Key locations:
- **Database schemas**: `/Users/apple/Desktop/threat-engine/shared/database/schemas/`
- **Migrations**: `/Users/apple/Desktop/threat-engine/shared/database/migrations/`
- **Engine implementations**: `/Users/apple/Desktop/threat-engine/engines/*/`
- **Vulnerability engine**: `/Users/apple/Desktop/threat-engine/engines/vulnerability/`
- **AI fix engines**: `/Users/apple/Desktop/threat-engine/engines/fix/`
- **Shared utilities**: `/Users/apple/Desktop/threat-engine/shared/common/`
- **API Gateway + BFF**: `/Users/apple/Desktop/threat-engine/shared/api_gateway/`
- **Kubernetes manifests (EKS)**: `/Users/apple/Desktop/threat-engine/deployment/aws/eks/`
- **Argo pipelines**: `/Users/apple/Desktop/threat-engine/deployment/aws/eks/argo/`
- **Local K8s configs**: `/Users/apple/Desktop/threat-engine/deployment/local/`
- **Frontend (Next.js)**: `/Users/apple/Desktop/threat-engine/frontend/`
- **Django identity backend**: `/Users/apple/Desktop/threat-engine/platform/cspm-backend/`
- **CSP catalog**: `/Users/apple/Desktop/threat-engine/catalog/`
- **Check rules**: `/Users/apple/Desktop/threat-engine/catalog/rule/{csp}_rule_check/`
- **Discovery YAMLs**: `/Users/apple/Desktop/threat-engine/catalog/discovery_generator_data/{csp}/`

## Development Commands

### Build & Test
```bash
# Build Docker images (build context is REPO ROOT — always use root)
docker build -t yadavanup84/<engine>:v-tag -f engines/<engine>/Dockerfile .

# Run tests
pytest /Users/apple/Desktop/threat-engine/tests/ -v
```

### Kubernetes Operations
```bash
# Apply manifest
kubectl apply -f /Users/apple/Desktop/threat-engine/deployment/aws/eks/engines/<engine>.yaml

# Check status
kubectl get deployments -n threat-engine-engines
kubectl rollout status deployment/<engine> -n threat-engine-engines

# View logs
kubectl logs -f -l app=<engine> -n threat-engine-engines --tail=100

# Port forward for local testing (use Python urllib for HTTP, not curl)
kubectl port-forward svc/<engine> <local-port>:80 -n threat-engine-engines
```

### Database Access (RDS not publicly accessible)
```bash
# Copy SQL to a pod that has DB access, then exec psql inside it
kubectl cp /tmp/fix.sql threat-engine-engines/<pod>:/tmp/fix.sql
kubectl exec -n threat-engine-engines <pod> -- psql -h $DISCOVERIES_DB_HOST \
  -U $DISCOVERIES_DB_USER -d $DISCOVERIES_DB_NAME -f /tmp/fix.sql

# Or run Python inline
kubectl exec -n threat-engine-engines deployment/<engine> -- python3 -c "..."
```

### Git Workflow
```bash
git status
git checkout -b feature/description
git diff
git commit -m "feat(engine-name): description"
```

## Architecture Patterns

### Data Flow (Pipeline Order)
```
Onboarding → Discovery → Inventory → Check → Threat → Compliance/IAM/DataSec/Network
  (8008)      (8001)      (8022)     (8002)  (8020)       (8000/−/8003/8004)
                                                 ↓
                                          CDR + Risk
```

### Network Engine — 7-Layer Architecture
The network engine runs two phases:
1. **Layer 1** (`run_scan.py`): Load check_findings where `rule_metadata.network_security.applicable=true` (all CSPs, DB-driven)
2. **Layer 2** (`providers/<csp>.py`): Topology provider with internal sub-layers:

| Sub-layer | Module | What it checks |
|-----------|--------|----------------|
| L1 | network_isolation | VPC/VCN segmentation, peering, transit gateways |
| L2 | network_reachability | Route tables, NAT, public/private subnet marking |
| L3 | network_acl | NACL / security-list rules at subnet boundary |
| L4 | security_group_rules | SSH/RDP/DB ports open to 0.0.0.0/0, orphaned SGs |
| L5 | load_balancer_security | TLS versions, internet-facing LBs without HTTPS |
| L6 | waf_protection | WAF coverage, OWASP rules, rate limiting |
| L7 | network_monitoring | VPC Flow Logs, DNS logging, WAF logging |

**AWS** — fully aligned with all 7 sub-layers.
**Non-AWS** (OCI, AliCloud, GCP, Azure) — flat implementations (v-net-fix10), need refactor to 7-layer model.
**Key distinction**: Network engine provides `effective_exposure` (L3/L4 reachability). `blast_radius_score` = risk engine. Attack chains = threat engine.

### Database Design
- **scan_orchestration**: Central coordination hub — uses `scan_run_id`
- **Cross-engine linking**: ALL engines use `scan_run_id` (single UUID per pipeline run)
- **Standard columns**: `finding_id`, `scan_run_id`, `tenant_id`, `account_id`, `credential_ref`, `credential_type`, `provider`, `region`, `resource_uid`, `resource_type`, `severity`, `status`, `first_seen_at`, `last_seen_at`
- `rule_discoveries` table is in **check DB** (not discoveries DB). Column: `service` (not `service_name`)
- JSONB in psycopg2: auto-deserialized to dict — NEVER call `json.loads()` on them

### API Patterns
- **FastAPI**: All engines use FastAPI with OpenAPI docs
- **Health checks**: `/api/v1/health/live` and `/api/v1/health/ready`
- **Versioning**: `/api/v1/` prefix for all endpoints

## Rule Routing
- **Config/posture rules** → `check` engine (`catalog/rule/{csp}_rule_check/`)
- **CDR/log-dependent rules** → `rule_cdr` (log event analysis, not discovery-based)
- **Network rules** tagged with `network_security.applicable=true` in `rule_metadata` → surfaced by network engine Layer 1

## Security & Access Control

### RBAC Enforcement (live as of 2026-05-01)

All 18 engine images have been rebuilt with `-rbac1` tag suffix and enforce `require_permission()`.

- 5 seeded roles in platform DB (migration 0009): `platform_admin` (l1), `org_admin` (l2), `tenant_admin` (l4), `analyst` (l4), `viewer` (l4)
- 27 permissions in `feature:action` format (e.g. `discoveries:read`, `scans:create`, `tenants:write`)
- Auth flow: `access_token` cookie → Gateway `AuthMiddleware` → builds `AuthContext` → sets `X-Auth-Context` header → engine `Depends(require_permission(...))`
- `DEV_BYPASS_AUTH` has been removed from `middleware.js` and `auth-context.js` — **never add it back**
- viewer role: 9 read-only permissions; datasec/secops/vuln/ai_security/encryption/dbsec/container return 403 for viewer
- `strip_sensitive_fields()` removes `credential_ref` and engine-specific fields based on role level
- Full permission matrix and field-stripping table: `.claude/documentation/RBAC.md`

### Protected Files
- `.env*` files (contains secrets)
- Kubernetes secrets
- AWS credentials (`~/.aws/`)

### Before Deployment Checklist
1. Review all changes for secrets/hardcoded credentials
2. Build image: `docker build ...`
3. Push image: `docker push ...` (requires confirmation)
4. Apply manifest: `kubectl apply -f ...`
5. Verify rollout: `kubectl rollout status ...`
6. **POST-DEPLOY IMAGE TAG CHECK** — mandatory after every rollout:
   ```bash
   kubectl get pods -n threat-engine-engines \
     -o custom-columns='NAME:.metadata.name,IMAGE:.spec.containers[0].image,STATUS:.status.phase' \
     | grep <engine>
   ```
   Pod image must match the intended tag. The VSCode linter silently reverts YAML edits — always
   cross-check the running pod image. If wrong: `kubectl set image deployment/<name> <c>=<tag>`
7. Check logs immediately after deploy: `kubectl logs -f -l app=<engine> -n threat-engine-engines`

### Migration DDL Rules
- `GENERATED ALWAYS AS (expr) STORED` requires an IMMUTABLE expression.
- `EXTRACT(HOUR FROM timestamptz_col)` is **NOT immutable** → use `EXTRACT(HOUR FROM (col AT TIME ZONE 'UTC'))::smallint`
- After every migration Job: check `kubectl logs -l job-name=<job>` ends with "MIGRATION COMPLETE"
- A pod in `Failed` state means the migration did **not** apply — never assume success without logs

## Common Workflows

### Adding a New Engine
1. Create directory: `engines/newtype/`
2. Implement API server following FastAPI pattern
3. Use standard DB columns (see above)
4. Create K8s manifest: `deployment/aws/eks/engines/engine-newtype.yaml`
5. Engine receives `scan_run_id` from orchestration — no per-engine scan IDs
6. Build → push → apply → rollout status → check logs

### Database Schema Changes
1. Create migration: `shared/database/migrations/`
2. Update schema SQL: `shared/database/schemas/<engine>_schema.sql`
3. Apply via kubectl exec on a pod with DB access

### Deployment to EKS
1. `docker build -t yadavanup84/<engine>:v-tag -f engines/<engine>/Dockerfile .`
2. `docker push yadavanup84/<engine>:v-tag`
3. Update image tag in `deployment/aws/eks/engines/<engine>.yaml`
4. `kubectl apply -f deployment/aws/eks/engines/<engine>.yaml`
5. `kubectl rollout status deployment/<engine> -n threat-engine-engines`
6. `kubectl logs -f -l app=<engine> -n threat-engine-engines`

## Debugging & Troubleshooting

### Check Database Connection
```bash
kubectl get configmap threat-engine-db-config -o yaml -n threat-engine-engines
```

### View Service Logs
```bash
kubectl logs -f -l app=engine-discoveries -n threat-engine-engines
kubectl logs -f -l app=engine-threat -n threat-engine-engines --tail=100
```

### Common Issues
**Discovery scan fails:** Check credentials in AWS Secrets Manager, IAM permissions, and logs.
**Check scan returns no results:** Verify scan_run_id in scan_orchestration, discovery_findings rows, rule_metadata active=true.
**Network engine 0 findings:** Check rule_metadata.network_security.applicable for CSP rules; check discovery IDs in provider match actual DB IDs.
**Compliance report empty:** Ensure check_findings exist, rule_control_mapping has mappings, compliance_frameworks has framework.

## Infrastructure Reference
- **RDS**: `postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com:5432`
- **EKS**: `vulnerability-eks-cluster` in `ap-south-1`
- **Namespace**: `threat-engine-engines`
- **Argo**: installed in `argo` namespace
- **ELB**: `a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com`
- **CSPM Portal**: admin@cspm.local / Admin@12345

## External Documentation (`.claude/documentation/`)
- `INFRASTRUCTURE.md` — AWS/EKS infrastructure details
- `ARCHITECTURE-DECISIONS.md` — ADRs
- `SECRETS-CREDENTIALS.md` — Secrets management
- `DATABASE-SCHEMA.md` — Schema reference
- `API_REFERENCE_ALL_ENGINES.md` — OpenAPI endpoints
- `ENGINE-PREREQUISITE-DATA.md` — Seed data, YAML catalogs, ConfigMaps

## Security Frameworks Constitution

These six frameworks are mandatory on all security-relevant work. They are embedded in `bmad-security-architect`, `bmad-security-reviewer`, and `bmad-security-po` agents.

| Framework | Scope | Enforced By |
|-----------|-------|-------------|
| **OWASP SAMM** (Design/Implementation/Verification) | Every story | bmad-security-architect gate + bmad-security-reviewer checklist |
| **STRIDE** | Every new engine, endpoint, or DB query | bmad-security-architect threat model |
| **PASTA** | Engines touching credentials, IAM, network | bmad-security-architect — 7-stage adversary model |
| **MITRE ATT&CK for Cloud** | Every new finding/check rule | bmad-security-po story template + bmad-security-architect mapping |
| **MITRE D3FEND** | Validate detection rules have defensive coverage | bmad-security-architect — ATT&CK→D3FEND mapping table |
| **NIST CSF 2.0** | All engine stories — tag GV/ID/PR/DE/RS/RC | bmad-security-po story template; RS/RC gaps must be filed |
| **CSA CCM v4** | Every new finding/rule maps to a CCM domain | bmad-security-po story AC + bmad-security-reviewer PR check |
| **SLSA Level 1-2** | All Docker image builds | bmad-security-reviewer SLSA checklist — pinned base images, no `latest` |

**How to apply**: Any story touching a new engine, new check rule, new API endpoint, or new DB schema must go through `bmad-security-architect` for design review before dev starts, and `bmad-security-reviewer` after dev completes.
