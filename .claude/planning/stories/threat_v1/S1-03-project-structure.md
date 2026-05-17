# Story S1-03: Project Structure + requirements.txt + Dockerfile + K8s Manifest

## Status: done

## Metadata
- **Sprint**: 1 — Foundation: Schema + GraphBuilder
- **Points**: 2
- **Priority**: P0
- **Depends on**: S0-05
- **Blocks**: S1-08 (needs Docker image to deploy), Sprint 5 S5-05
- **RACI**: R=DEV A=DL C=ARCH,SA I=PO
- **Security Gate**: SLSA Level 1-2 — pinned base image, no :latest (CP1-08)

## Context

Creates the runnable project skeleton for threat_v1: dependency manifest, Docker image, FastAPI health app, and K8s Deployment+Service manifest. Port 8021 (8020 is the existing threat engine). Build context is repo root.

## Files Created

| File | Purpose |
|---|---|
| `engines/threat_v1/requirements.txt` | All dependencies pinned — no version ranges |
| `engines/threat_v1/Dockerfile` | Multi-stage, non-root user, pinned base image |
| `engines/threat_v1/main.py` | FastAPI app with live + ready health endpoints |
| `deployment/aws/eks/engines/engine-threat-v1.yaml` | Deployment + Service, port 8021 |

## Key Decisions

- Base image: `python:3.11-slim-bookworm` (pinned, no `:latest` — CP1-08)
- Multi-stage Dockerfile: builder + runtime stage (SLSA Level 1-2)
- Non-root user: `useradd -m -u 1001 threatv1` — security requirement
- Readiness probe: actually tests Postgres AND Neo4j connectivity (not just returns 200)
- Auth middleware: imports `engine_auth.fastapi.middleware.AuthMiddleware` + `require_permission`, falls back to 401 stub if unavailable
- Image tag placeholder: `yadavanup84/engine-threat-v1:v-threat-v1-phase1` — NEVER `:latest`
- Neo4j creds from secret `neo4j-credentials`; DB password from `threat-engine-db-passwords`

## Acceptance Criteria

- [ ] AC-1: All 4 files exist at specified paths
- [ ] AC-2: No `:latest` tag anywhere in Dockerfile or K8s manifest (CP1-08)
- [ ] AC-3: Non-root user `threatv1` (uid 1001) in Dockerfile
- [ ] AC-4: `/api/v1/health/ready` returns 503 when DB or Neo4j unreachable
- [ ] AC-5: All env vars in manifest use configMapKeyRef or secretKeyRef — no hardcoded values
- [ ] AC-6: `livenessProbe` and `readinessProbe` both present in manifest
- [ ] AC-7: Image builds successfully with `docker build -f engines/threat_v1/Dockerfile .`

## Security Acceptance Criteria

- [ ] Base image pinned to `python:3.11-slim-bookworm` — no `:latest`
- [ ] Non-root user in Dockerfile
- [ ] No secrets hardcoded in Dockerfile or manifest
- [ ] CORS origins not set to `*` — use allowed origins list

## Definition of Done

- [x] `requirements.txt` committed with all pinned versions
- [x] `Dockerfile` committed — multi-stage, non-root, pinned base
- [x] `main.py` committed — health endpoints implemented, auth middleware wired
- [x] `engine-threat-v1.yaml` committed — probes, resources, secrets, no :latest
- [ ] Image builds locally without errors
- [ ] ARCH peer review complete
