# AP-SPRINT-02 — Graph Build Migration: engine-threat → engine-attack-path

## Story
As a platform operator, I want the Neo4j security graph build to run inside `engine-attack-path` (not `engine-threat`) so that `engine-threat` has no pipeline role and the two services have clean separation of concerns: attack-path owns both the BFS scoring pipeline AND the Neo4j graph build.

## Priority
P1 — architecture cleanup, required before decommissioning engine-threat from pipeline

## Status
**DONE** — all 5 sub-tasks completed (2026-05-24)

## Background
`engine-threat` previously owned:
- `POST /api/v1/graph/build` — Neo4j SecurityGraphBuilder async trigger
- `GET /api/v1/graph/build/status/{job_id}` — job polling
- Pipeline role in Argo DAG at graph-build step

`engine-attack-path` already owned the PostgreSQL BFS scoring pipeline.
After this migration, `engine-threat` serves only UI/BFF endpoints (threat intel, hunt, mitre).

## Sub-tasks Completed

### GRAPH-01 — Copy graph_builder.py to attack-path
**Source:** `engines/threat/threat_engine/graph/graph_builder.py` (2200 lines)
**Dest:** `engines/attack-path/attack_path_engine/graph/graph_builder.py`
No engine-specific imports — pure stdlib + boto3. Logger renamed to `attack-path.graph_builder`.

### GRAPH-02 — Copy graph_queries.py to attack-path
**Source:** `engines/threat/threat_engine/graph/graph_queries.py` (1495 lines)
**Dest:** `engines/attack-path/attack_path_engine/graph/graph_queries.py`
No engine-specific imports — pure stdlib. Logger renamed to `attack-path.graph_queries`.

### GRAPH-03 — Add graph build endpoints to attack-path routes.py
**File:** `engines/attack-path/attack_path_engine/api/routes.py`
Added:
- `POST /api/v1/graph/build` — auth: `attack_path:read`
- `GET /api/v1/graph/build/status/{job_id}` — auth: `attack_path:read`
- Module-level `_graph_build_jobs: Dict[str, Dict]` for in-memory job tracking
- `_strip_graph_stats_for_role()` — strips CVE fields for viewer/analyst
- `audit_logger` for structured graph build audit events
- `import time` added to imports

### GRAPH-04 — Update gateway SERVICE_ROUTES
**File:** `shared/api_gateway/main.py`
- Removed `/api/v1/graph` from `"threat"` prefixes list
- Added `/api/v1/graph` to `"attack-path"` prefixes list
- `engine-threat` now handles: `/api/v1/threat`, `/api/v1/intel`, `/api/v1/hunt`
- `engine-attack-path` now handles: `/api/v1/attack-paths`, `/api/v1/crown-jewels`, `/api/v1/choke-points`, `/api/v1/graph`

### GRAPH-05 — Update Argo primitives (graph-build step)
**File:** `deployment/aws/eks/argo/cspm-templates-primitives.yaml`
Three changes:
1. URL registry entry: `"graph-build"` → `http://engine-attack-path.threat-engine-engines.svc.cluster.local:80/api/v1/graph/build`
2. `TRIGGER_URL` in graph-build script → same
3. `POLL_BASE` in graph-build script → `http://engine-attack-path.../api/v1/graph/build/status`
4. Auth permissions in X-Auth-Context: `["threat:read","threat:write"]` → `["attack_path:read","attack_path:write"]`

## Acceptance Criteria
- [ ] `POST /api/v1/graph/build` routed to `engine-attack-path` (verify via gateway access log)
- [ ] `GET /api/v1/graph/build/status/{job_id}` returns job state from attack-path pod
- [ ] Argo `graph-build` step completes successfully pointing at engine-attack-path
- [ ] `engine-threat` still serves `/api/v1/threat`, `/api/v1/intel`, `/api/v1/hunt` correctly
- [ ] Graph nodes appear in Neo4j for test tenant after pipeline run

## Files Changed
- `engines/attack-path/attack_path_engine/graph/graph_builder.py` (new — copied from threat engine)
- `engines/attack-path/attack_path_engine/graph/graph_queries.py` (new — copied from threat engine)
- `engines/attack-path/attack_path_engine/api/routes.py`
- `shared/api_gateway/main.py`
- `deployment/aws/eks/argo/cspm-templates-primitives.yaml`

## Deploy Sequence
1. Build and push `engine-attack-path` with new image tag
2. Build and push `engine-api-gateway` with updated SERVICE_ROUTES
3. Apply both K8s manifests
4. Verify rollout, check logs for Neo4j connection on startup
5. Trigger a test pipeline run; confirm `graph-build` Argo step hits attack-path

## Notes
- `engine-threat` K8s deployment is NOT removed — it still serves UI threat endpoints
- `engine-attack-path` `requirements.txt` already includes `neo4j==5.20.0` — no Dockerfile change needed for Neo4j driver
- `boto3` and `botocore` must be in `engine-attack-path` requirements (needed by graph_builder.py for AWS-specific enrichment)