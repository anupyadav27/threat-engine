# Story APISEC-BUG-01: Fix Scan Trigger Permission — `api_security:read` → `api_security:write`

## Status: done

## Metadata
- **Phase**: Bug Fix
- **Epic**: API Security Engine
- **Points**: 1
- **Priority**: P1 (security — privilege escalation)
- **Depends on**: None
- **Blocks**: None
- **RACI**: R=DEV A=DL C=SR I=PO,QA
- **Security Gate**: bmad-security-reviewer mandatory (permission change on write endpoint)

## User Story

As a platform admin, I want the API security scan trigger endpoint protected by `api_security:write` instead of `api_security:read`, so that analyst-role users cannot arbitrarily trigger scans and exhaust scan resources or interfere with scheduled pipeline runs.

## Context

**File:** `engines/api-security/api_security_engine/api/routes.py:50`

`POST /api/v1/apisec/scan` is the Argo scan trigger endpoint. It was incorrectly decorated with `require_permission("api_security:read")`, which is granted to **all authenticated roles** including `analyst` and `viewer`.

Triggering a scan is a **write/mutate operation** — it spawns a subprocess via `subprocess.Popen(cmd)` that runs a full API security scan against cloud accounts. Any `analyst` user could call this endpoint through the public gateway (`/api/v1/apisec` prefix is gateway-routed), trigger unbounded scan processes, interfere with Argo pipeline scheduling, or cause DoS on scan infrastructure.

The correct permission is `api_security:write`, which is restricted to `platform_admin` and `org_admin` per the RBAC seed data.

**Fix is a one-line change — already applied.**

```diff
- auth: AuthContext = Depends(require_permission("api_security:read")),
+ auth: AuthContext = Depends(require_permission("api_security:write")),
```

## Security Framework Tags

**OWASP SAMM Function**
- [ ] Governance  [ ] Design  [x] Implementation  [x] Verification  [ ] Operations

**NIST CSF 2.0 Function(s)**
- [ ] GV  [ ] ID  [x] PR  [ ] DE  [ ] RS  [ ] RC
PR.AC-4 — Access permissions and authorizations are managed, incorporating principles of least privilege and separation of duties.

**CSA CCM v4 Domain(s)**
- IAM-09 (User Access Authorization), IAM-13 (Privileged Access Management)

## Threat Model

### STRIDE
| Threat | Component | Attack Scenario | Mitigation |
|--------|-----------|-----------------|------------|
| Elevation of Privilege | `POST /api/v1/apisec/scan` | `analyst` role user calls scan trigger through gateway, spawning scan processes without admin intent | Change permission to `api_security:write` (platform_admin + org_admin only) |
| DoS | scan subprocess | Authenticated analyst floods scan trigger endpoint, spawning unbounded `subprocess.Popen` processes per request | Permission gate stops non-admin users; rate limiting at gateway level (future) |

### PASTA
**Assets at risk**: Cloud scan infrastructure, Argo scan scheduling, scan_orchestration integrity  
**Mitigations applied by this fix**:
- Only `platform_admin` and `org_admin` can trigger API security scans after this change
- `analyst`, `tenant_admin`, and `viewer` receive 403 on POST /api/v1/apisec/scan

## MITRE ATT&CK Techniques Addressed
- T1078 (Valid Accounts) — attacker with analyst credentials exploiting misconfigured write endpoint

## Acceptance Criteria

### AC-01 — Permission changed
`require_permission("api_security:write")` is on `POST /api/v1/apisec/scan` in `routes.py`.

### AC-02 — analyst role blocked
```
POST /api/v1/apisec/scan  (with analyst session token)
→ 403 Forbidden
```

### AC-03 — org_admin allowed
```
POST /api/v1/apisec/scan  (with org_admin session token)
→ 200  {"status": "dispatched"}
```

### AC-04 — platform_admin allowed
```
POST /api/v1/apisec/scan  (with platform_admin session token)
→ 200  {"status": "dispatched"}
```

### AC-05 — GET endpoints unaffected
`GET /api/v1/apisec/findings` and `GET /api/v1/apisec/report/{scan_run_id}` continue to require `api_security:read` (all roles).

### AC-06 — Image rebuilt and deployed
New image tag `v-apisec-3` deployed to `engine-api-security`; `kubectl rollout status` clean; logs show `Auth middleware enabled`.

## Technical Notes

- `api_security:write` is already seeded in Django (MEMORY.md: "RBAC: `api_security:read` (all roles), `api_security:write` (platform_admin+org_admin)") — **no Django migration needed**.
- The endpoint is gateway-routed (prefix `/api/v1/apisec`) so the fix takes effect at the engine layer for all external callers.
- Argo calls this endpoint via K8s-internal DNS — Argo's service account does not use session auth. Verify Argo workflow template uses the correct auth method (X-Internal-Secret or internal service token) after this change. If Argo was relying on a session token with analyst permissions, the workflow template must be updated.

## Definition of Done

- [x] `routes.py` line 50 uses `api_security:write`
- [ ] Docker image built: `docker build -t yadavanup84/engine-api-security:v-apisec-3 -f engines/api-security/Dockerfile .`
- [ ] Image pushed: `docker push yadavanup84/engine-api-security:v-apisec-3`
- [ ] `deployment/aws/eks/engines/engine-api-security.yaml` image tag updated to `v-apisec-3`
- [ ] `kubectl apply` + rollout clean
- [ ] AC-02 through AC-05 verified
- [ ] bmad-security-reviewer sign-off on permission change
- [ ] MEMORY.md production table updated: `api-security` → `v-apisec-3`
