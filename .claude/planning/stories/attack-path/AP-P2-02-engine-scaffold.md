# Story AP-P2-02: engine-attack-path Scaffold

## Status: ready

## Metadata
- **Phase**: P2 — Attack Path Engine Core
- **Epic**: Attack Path Engine
- **Points**: 5
- **Priority**: P0
- **Depends on**: AP-P2-01 (DB tables must exist for readiness check)
- **Blocks**: AP-P1-02 (PATCH endpoint), AP-P2-03, AP-P2-04, AP-P2-05, AP-P2-06, AP-P2-07, AP-P3-01
- **RACI**: R=DEV A=DL C=SA,SR I=PO,QA
- **Security Gate**: bmad-security-architect mandatory (new engine design gate). bmad-security-reviewer mandatory (new endpoint + auth + DB).

## User Story

As a platform engineer, I want the `engine-attack-path` FastAPI service scaffolded with health endpoints, RBAC enforcement, K8s deployment manifest, and new permissions seeded in Django, so that downstream stories can implement individual features without rebuilding the service skeleton.

## Context

This is the foundational scaffold for `engine-attack-path` (port 8025). It follows the existing engine pattern exactly: FastAPI app factory, `require_permission()` via `engine_auth`, health endpoints, psycopg2 DB pool, and standard K8s manifest with secretRef.

The engine runs at pipeline stage 6.5 (between graph-build and risk). It is NOT part of the existing `engine-threat` — it is a separate deployment with its own DB.

Two new permissions must be seeded in the Django platform migration: `attack_path:read` (all roles) and `attack_path:write` (platform_admin, org_admin, tenant_admin).

The image tag for the initial scaffold is `v-attack-path1`.

## Security Framework Tags

**OWASP SAMM Function**
- [x] Governance  [x] Design  [x] Implementation  [x] Verification  [ ] Operations

**NIST CSF 2.0 Function(s)**
- [x] GV  [x] ID  [x] PR  [x] DE  [ ] RS  [ ] RC
GV.OC-5 (outcomes communicated), PR.AC-4 (access permissions managed)

**CSA CCM v4 Domain(s)**
- IAM-09 (Access Control), IVS-01 (Infrastructure Security), SEF-01 (Security Event Analysis)

## Threat Model

### STRIDE
| Threat | Component | Attack Scenario | Mitigation |
|--------|-----------|-----------------|------------|
| Spoofing | /api/v1/health/live | Attacker probes health endpoint to enumerate service | Health endpoints return 200/503 only — no service details in body |
| Elevation | new permissions | Engine deployed before Django migration seeds permissions → all requests 403 | Migration must be applied and verified before engine image goes live |
| Info Disclosure | DB pool | Connection pool leaks DB credentials in error responses | psycopg2 errors caught and wrapped in generic 500 response; credentials only in secretRef |
| DoS | DB pool | Max connections exceeded under load | Pool max_connections=10 per architecture doc section 5.2 |

### PASTA
**Assets at risk**: Attack path findings (sensitive security posture data)
**Mitigations**:
- All data endpoints require attack_path:read (seeded permission)
- Internal scan endpoint requires X-Internal-Secret (not gateway-routable)
- No data returned from health endpoints

## MITRE ATT&CK Techniques Addressed
N/A — scaffold only; no finding logic in this story.

## Acceptance Criteria

### Engine Routing (mandatory)
- [ ] AC-1: Engine matches agents.ndjson: agent_file `.claude/agents/attack-path.md` (or nearest equivalent), pipeline_stage 6.5, K8s svc name `engine-attack-path`, svc port 80 → targetPort 8025

### Functional — Service
- [ ] AC-2: `engines/attack-path/` directory created with structure matching architecture doc section 3
- [ ] AC-3: `engines/attack-path/attack_path_engine/main.py` — FastAPI app factory with correct middleware order (Auth runs before SubTenant)
- [ ] AC-4: `engines/attack-path/attack_path_engine/api/routes.py` — router registered
- [ ] AC-5: `GET /api/v1/health/live` returns `{"status": "ok"}` with HTTP 200
- [ ] AC-6: `GET /api/v1/health/ready` returns `{"status": "ok"}` with HTTP 200 when DB connected, returns HTTP 503 when DB unreachable
- [ ] AC-7: `engines/attack-path/requirements.txt` includes: fastapi, uvicorn, psycopg2-binary, neo4j, httpx, pydantic
- [ ] AC-8: `engines/attack-path/Dockerfile` follows existing engine pattern — build context is REPO ROOT; `COPY shared/common /app/engine_common`; no `latest` base image tag — use pinned python:3.11-slim digest or specific tag

### Functional — K8s
- [ ] AC-9: `deployment/aws/eks/engines/engine-attack-path.yaml` created as per architecture doc section 10.1
- [ ] AC-10: Deployment uses `image: yadavanup84/engine-attack-path:v-attack-path1` — no `latest` tag
- [ ] AC-11: `envFrom` includes `secretRef: threat-engine-db-passwords` and `secretRef: threat-engine-secrets`
- [ ] AC-12: `ATTACK_PATH_DB_HOST` env var read from `threat-engine-db-config` ConfigMap
- [ ] AC-13: `NEO4J_URI` read from `threat-engine-db-passwords` secret
- [ ] AC-14: Service manifest: `port: 80 targetPort: 8025`
- [ ] AC-15: livenessProbe and readinessProbe configured pointing to health endpoints

### Functional — Django permissions
- [ ] AC-16: Django migration `0016_attack_path_permissions.py` (or next available number) seeds `attack_path:read` and `attack_path:write` permissions
- [ ] AC-17: `attack_path:read` assigned to roles: platform_admin, org_admin, tenant_admin, analyst, viewer
- [ ] AC-18: `attack_path:write` assigned to roles: platform_admin, org_admin, tenant_admin only
- [ ] AC-19: `require_permission("attack_path:read")` wired on stub GET endpoints via `Depends()`

### RBAC Matrix (5 roles × health endpoints)
- [ ] AC-20: platform_admin — `GET /api/v1/health/live` returns 200
- [ ] AC-21: viewer — `GET /api/v1/health/live` returns 200 (health endpoints are public)

### Image Tag
- [ ] AC-22: Docker image built and pushed as `yadavanup84/engine-attack-path:v-attack-path1`
- [ ] AC-23: No `latest` tag in any manifest or Dockerfile

### Health Check (mandatory)
- [ ] AC-24: `GET /api/v1/health/live` returns 200 after deploy
- [ ] AC-25: `kubectl logs` show no ERROR in first 50 lines after pod starts

### Security Gate (mandatory)
- [ ] AC-26: bmad-security-architect sign-off before merge (new engine design gate)
- [ ] AC-27: bmad-security-reviewer: no BLOCKERS

## Technical Notes

**Port**: 8025 (matches architecture doc section 10.1)
**K8s svc**: `engine-attack-path` in namespace `threat-engine-engines`
**DB pool**: `min=2, max=10` using psycopg2 connection pool

**Dockerfile pattern** (follow engines/threat/Dockerfile as reference):
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY shared/common /app/engine_common
COPY engines/attack-path/requirements.txt .
RUN pip install -r requirements.txt
COPY engines/attack-path/ .
CMD ["uvicorn", "attack_path_engine.main:app", "--host", "0.0.0.0", "--port", "8025"]
```

**Middleware order** (critical — see CLAUDE.md feedback_gateway_middleware_order):
Auth middleware must be added AFTER the route_requests decorator, not before, so that Auth runs first.

**agents.ndjson** must be updated to add the attack-path engine entry after this story ships.

## Key Files
- `/Users/apple/Desktop/threat-engine/engines/attack-path/` (create directory tree)
- `/Users/apple/Desktop/threat-engine/engines/attack-path/Dockerfile` (create new)
- `/Users/apple/Desktop/threat-engine/engines/attack-path/requirements.txt` (create new)
- `/Users/apple/Desktop/threat-engine/engines/attack-path/attack_path_engine/main.py` (create new)
- `/Users/apple/Desktop/threat-engine/engines/attack-path/attack_path_engine/api/routes.py` (create new)
- `/Users/apple/Desktop/threat-engine/engines/attack-path/attack_path_engine/db/connection.py` (create new)
- `/Users/apple/Desktop/threat-engine/deployment/aws/eks/engines/engine-attack-path.yaml` (create new)
- `/Users/apple/Desktop/threat-engine/platform/cspm-backend/cspm_app/migrations/0016_attack_path_permissions.py` (create new — or next available migration number)
- `/Users/apple/Desktop/threat-engine/.claude/context/agents.ndjson` (add attack-path engine entry)

## Definition of Done
- [ ] All directory structure and files created and committed
- [ ] Docker image built: `docker build -t yadavanup84/engine-attack-path:v-attack-path1 -f engines/attack-path/Dockerfile .`
- [ ] Docker image pushed: `docker push yadavanup84/engine-attack-path:v-attack-path1`
- [ ] `kubectl apply -f deployment/aws/eks/engines/engine-attack-path.yaml`
- [ ] `kubectl rollout status deployment/engine-attack-path -n threat-engine-engines` clean
- [ ] `GET /api/v1/health/live` returns 200
- [ ] `kubectl logs` show no ERROR in first 50 lines
- [ ] Django migration applied; `attack_path:read` and `attack_path:write` visible in permissions table
- [ ] MEMORY.md production table updated with `engine-attack-path: yadavanup84/engine-attack-path:v-attack-path1`
- [ ] agents.ndjson updated
- [ ] bmad-security-architect: sign-off recorded
- [ ] bmad-security-reviewer: no BLOCKERS