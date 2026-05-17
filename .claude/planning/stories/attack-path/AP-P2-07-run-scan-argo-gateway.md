# Story AP-P2-07: run_scan.py + Argo Integration + Gateway Route

## Status: ready

## Metadata
- **Phase**: P2 — Attack Path Engine Core
- **Epic**: Attack Path Engine
- **Points**: 5
- **Priority**: P0
- **Depends on**: AP-P2-02 (engine scaffold), AP-P2-03 (BFS), AP-P2-04 (scorer), AP-P2-05 (deduplicator), AP-P2-06 (choke detector + writer)
- **Blocks**: AP-P3-01 (BFF needs the engine routed via gateway), AP-P3-02 (risk engine reads posture signals written by this scan)
- **RACI**: R=DEV A=DL C=SA,SR I=PO,QA
- **Security Gate**: bmad-security-reviewer mandatory (internal scan endpoint + Argo auth + gateway route). bmad-security-architect reviews X-Internal-Secret pattern.

## User Story

As the Argo pipeline, I want to trigger the attack-path engine via `POST /api/v1/internal/scan` after the graph-build step completes, and have the risk engine run only after attack-path completes, so that risk scores include attack-path signals and the pipeline order is enforced end-to-end.

## Context

This story wires together all Phase 2 components into a single scan orchestrator (`run_scan.py`) and plugs the engine into the Argo DAG at position 6.5.

The internal scan endpoint is NOT gateway-routed — it is called directly by Argo using the K8s cluster-internal service URL and `X-Internal-Secret` header authentication. The gateway PUBLIC_PREFIXES list must NOT include `/api/v1/internal/scan`.

The scan runs synchronously (classify → BFS → score → dedup → choke → write → posture update). Argo polls the Argo step status (not a custom status endpoint) to determine completion.

## Security Framework Tags

**OWASP SAMM Function**
- [x] Governance  [x] Design  [x] Implementation  [x] Verification  [x] Operations

**NIST CSF 2.0 Function(s)**
- [x] GV  [x] ID  [x] PR  [x] DE  [x] RS  [ ] RC
GV.OC-5, ID.RA-5, PR.AC-4, DE.CM-6 (external service activity monitored)

**CSA CCM v4 Domain(s)**
- IVS-01, IAM-09, SEF-01, GRC-05

## Threat Model

### STRIDE
| Threat | Component | Attack Scenario | Mitigation |
|--------|-----------|-----------------|------------|
| Spoofing | POST /internal/scan | External attacker calls /internal/scan to trigger scan for another tenant | X-Internal-Secret required; endpoint not exposed via gateway (not in PUBLIC_PREFIXES); cluster-internal only |
| Elevation | X-Internal-Secret | Leaked secret allows any caller to trigger scans for any tenant | Secret rotated via threat-engine-secrets K8s secret; not hardcoded; Argo pod identity is the only authorized caller |
| DoS | run_scan | Concurrent Argo triggers for same tenant run overlapping scans | Argo serializes per-tenant via DAG; no additional concurrency guard needed in v1 |
| Tampering | Argo DAG | risk-scan runs before attack-path-scan if DAG dependency is wrong | risk-scan.dependencies explicitly set to [attack-path-scan] in cspm-pipeline.yaml |

### PASTA Analysis
**Assets at risk**: Internal scan trigger — if exploited, adversary can enumerate crown jewels and attack paths for any tenant.
**Entry point**: POST /api/v1/internal/scan (cluster-internal only).
**Mitigations**:
- X-Internal-Secret validates caller without full JWT auth
- Endpoint not registered in gateway SERVICE_ROUTES under any external prefix
- scan_run_id and tenant_id from request body validated against scan_orchestration table before processing

## MITRE ATT&CK Techniques Addressed
| Technique ID | Name | How this story addresses it |
|-------------|------|-----------------------------|
| T1562.008 | Disable Cloud Logs | Argo retry=0 on attack-path step ensures scan failure doesn't silently retry — operator is notified |

## Acceptance Criteria

### Functional — run_scan.py
- [ ] AC-1: File `engines/attack-path/attack_path_engine/run_scan.py` created
- [ ] AC-2: Orchestration order: `CrownJewelClassifier.classify()` → `Neo4jClient.reverse_bfs()` → `fetch posture_lookup from resource_security_posture` → `scorer.probability_score() + impact_score()` per path → `deduplicator.deduplicate()` → `choke_point_detector.detect_choke_points()` → `writer.write_paths() + write_path_nodes() + write_history()` → `posture_updater.update_attack_path_signals()`
- [ ] AC-3: Structured JSON logs at each pipeline stage: `{"engine":"attack-path", "scan_run_id":..., "tenant_id":..., "stage": "bfs", "raw_paths": N}`
- [ ] AC-4: Metrics logged at end of scan: `crown_jewel_count`, `raw_paths_before_dedup`, `final_path_count`, `critical_path_count`, `choke_point_count`, `scan_duration_seconds`
- [ ] AC-5: scan completes in < 3 minutes for test tenant

### Functional — POST /api/v1/internal/scan
- [ ] AC-6: Endpoint implemented at `POST /api/v1/internal/scan`
- [ ] AC-7: Request body validated: `{ "scan_run_id": UUID, "tenant_id": str, "account_id": str }`
- [ ] AC-8: X-Internal-Secret header validated against `X_INTERNAL_SECRET` env var (from threat-engine-secrets)
- [ ] AC-9: If X-Internal-Secret missing or wrong → 403 response (not 401 — caller is a service, not a user)
- [ ] AC-10: Endpoint returns `{ "job_id": "<uuid>", "status": "queued" }` immediately; scan runs in background thread
- [ ] AC-11: Endpoint NOT accessible from outside the cluster — NOT in gateway PUBLIC_PREFIXES list and NOT in SERVICE_ROUTES external prefix list

### Functional — Argo Pipeline
- [ ] AC-12: `deployment/aws/eks/argo/cspm-pipeline.yaml` updated: `attack-path-scan` step added with `dependencies: [graph-build]`
- [ ] AC-13: `risk-scan` step updated: `dependencies: [attack-path-scan]` (was: `[graph-build]`)
- [ ] AC-14: `attack-path-scan-template` uses `POST http://engine-attack-path.threat-engine-engines.svc.cluster.local:80/api/v1/internal/scan`
- [ ] AC-15: Argo step `retry: 0` for attack-path-scan (no retry on failure — see PRD section 5.2)

### Functional — Gateway Route
- [ ] AC-16: `shared/api_gateway/main.py` SERVICE_ROUTES updated: `"attack-path": "http://engine-attack-path.threat-engine-engines.svc.cluster.local:80"`
- [ ] AC-17: `frontend/src/lib/constants.js` ENGINE_ENDPOINTS updated with `ATTACK_PATH`, `CROWN_JEWELS`, `CHOKE_POINTS` constants (as per architecture doc section 10.3)
- [ ] AC-18: Gateway routes /api/v1/attack-paths, /api/v1/crown-jewels, /api/v1/choke-points to engine-attack-path correctly
- [ ] AC-19: Gateway does NOT route /api/v1/internal/scan — verified by curl test from outside cluster returning 404

### Security (must pass bmad-security-reviewer)
- [ ] AC-20: X-Internal-Secret validated before any DB access in the scan endpoint
- [ ] AC-21: scan_run_id validated as UUID format before processing — reject malformed IDs with 422
- [ ] AC-22: No DEV_BYPASS_AUTH in run_scan.py or the internal scan endpoint
- [ ] AC-23: X_INTERNAL_SECRET sourced from env var only — never hardcoded
- [ ] AC-24: Internal scan endpoint path `/api/v1/internal/scan` confirmed NOT in gateway PUBLIC_PREFIXES (code review check)

## Technical Notes

**run_scan.py** receives `scan_run_id`, `tenant_id`, `account_id` as parameters (passed from the internal scan endpoint).

**posture_lookup fetch** (between BFS and scoring):
```python
rows = conn.execute(
    "SELECT * FROM resource_security_posture WHERE scan_run_id=%s AND tenant_id=%s",
    (scan_run_id, tenant_id)
)
posture_lookup = {row["resource_uid"]: PostureRow(**row) for row in rows}
```

**Background task pattern** (FastAPI):
```python
from fastapi import BackgroundTasks

@router.post("/api/v1/internal/scan")
async def trigger_scan(body: ScanRequest, background_tasks: BackgroundTasks, x_internal_secret: str = Header(...)):
    if x_internal_secret != os.getenv("X_INTERNAL_SECRET"):
        raise HTTPException(status_code=403)
    job_id = str(uuid4())
    background_tasks.add_task(run_scan, body.scan_run_id, body.tenant_id, body.account_id)
    return {"job_id": job_id, "status": "queued"}
```

**Argo template** (reference architecture doc section 10.2):
```yaml
- name: attack-path-scan
  dependencies: [graph-build]
  template: attack-path-scan-template
  arguments:
    parameters:
      - name: scan-run-id
        value: "{{inputs.parameters.scan-run-id}}"
```

**Gateway route note**: `shared/api_gateway/main.py` SERVICE_ROUTES is a dict. The gateway will proxy all `/api/v1/attack-paths`, `/api/v1/crown-jewels`, `/api/v1/choke-points` requests to the engine. Confirm the attack-path prefix is not shadowed by an existing route.

## Key Files
- `/Users/apple/Desktop/threat-engine/engines/attack-path/attack_path_engine/run_scan.py` (create new)
- `/Users/apple/Desktop/threat-engine/engines/attack-path/attack_path_engine/api/routes.py` (add POST /internal/scan)
- `/Users/apple/Desktop/threat-engine/deployment/aws/eks/argo/cspm-pipeline.yaml` (add attack-path step; update risk dependency)
- `/Users/apple/Desktop/threat-engine/shared/api_gateway/main.py` (add SERVICE_ROUTES entry)
- `/Users/apple/Desktop/threat-engine/frontend/src/lib/constants.js` (add ENGINE_ENDPOINTS)

## Definition of Done
- [ ] run_scan.py committed and integrated with all Phase 2 components
- [ ] POST /internal/scan endpoint responds 403 to wrong secret, 200 to correct secret
- [ ] Argo pipeline yaml updated — attack-path-scan between graph-build and risk-scan
- [ ] risk-scan.dependencies updated to [attack-path-scan]
- [ ] Gateway SERVICE_ROUTES entry added
- [ ] Constants.js ENGINE_ENDPOINTS updated
- [ ] Full pipeline scan triggered: attack-path step completes before risk step starts (verified in Argo UI)
- [ ] After scan: `SELECT COUNT(*) FROM attack_paths WHERE scan_run_id = '<current>'` > 0
- [ ] Gateway /api/v1/internal/scan returns 404 (not routed externally)
- [ ] New engine image built: `yadavanup84/engine-attack-path:v-attack-path2` (or next tag)
- [ ] kubectl rollout clean; health/live 200; no ERRORs in first 50 log lines
- [ ] MEMORY.md updated
- [ ] bmad-security-architect: X-Internal-Secret design sign-off
- [ ] bmad-security-reviewer: no BLOCKERS