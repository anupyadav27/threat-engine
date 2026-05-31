# DI-S1-06 — FastAPI Server + K8s Manifest (engine-di, Port 8025)
**Sprint**: DI-S1 | **Points**: 8 | **Status**: Ready for Dev

## Goal
Wire Phase 0+1+2 into a FastAPI server, build the Docker image, write the K8s manifest for
engine-di (port 8025, namespace `threat-engine-engines`), and confirm end-to-end scan runs on a
test account.

## Files to Create / Modify
- `engines/di/di_engine/api/api_server.py` — FastAPI app with scan trigger + status + health
- `engines/di/di_engine/api/__init__.py` — empty
- `engines/di/run_scan.py` — K8s Job entry point (spawned per scan_run_id)
- `engines/di/requirements.txt` — dependencies
- `engines/di/Dockerfile` — multi-stage build; copies discoveries/providers + common
- `deployment/aws/eks/engines/engine-di.yaml` — Deployment + Service + Job template

## API Endpoints

```
POST /api/v1/di/scan                → 202 Accepted {scan_run_id, status: "queued"}
GET  /api/v1/di/scan/{id}/status    → {status, phase, resources_found, errors, pct_complete}
GET  /api/v1/di/assets              → paginated asset_inventory rows (tenant-scoped)
GET  /api/v1/di/assets/{uid}        → single asset detail
GET  /api/v1/di/errors              → di_scan_errors for last scan
GET  /api/v1/health/live            → {"status": "ok"}
GET  /api/v1/health/ready           → {"status": "ok"} (DB connectivity check)
```

All endpoints require `require_permission("discoveries:read")` except POST which requires
`require_permission("scans:create")`.

## api_server.py (key routes)
```python
from fastapi import FastAPI, Depends, HTTPException
from engine_common.auth import require_permission, AuthContext

app = FastAPI(title="engine-di", version="1.0.0")

@app.post("/api/v1/di/scan", status_code=202)
async def trigger_scan(
    body: ScanRequest,
    auth: AuthContext = Depends(require_permission("scans:create")),
):
    """Trigger a DI scan for an account. Spawns a K8s Job per scan."""
    # Validate account belongs to tenant
    scan_run_id = await _create_orchestration_record(body, auth.tenant_id)
    await _spawn_scan_job(scan_run_id)
    return {"scan_run_id": str(scan_run_id), "status": "queued"}

@app.get("/api/v1/di/scan/{scan_run_id}/status")
async def scan_status(
    scan_run_id: UUID,
    auth: AuthContext = Depends(require_permission("discoveries:read")),
):
    """Return current scan status from di_scan_run_status view or orchestration table."""
    row = await _get_scan_status(scan_run_id, auth.tenant_id)
    if not row:
        raise HTTPException(status_code=404, detail="scan_run_id not found")
    return row

@app.get("/api/v1/di/assets")
async def list_assets(
    scan_run_id: Optional[UUID] = None,
    provider: Optional[str] = None,
    service: Optional[str] = None,
    resource_type: Optional[str] = None,
    page: int = 1,
    page_size: int = 100,
    auth: AuthContext = Depends(require_permission("discoveries:read")),
):
    """Paginated asset list from asset_inventory (tenant-scoped)."""
    # All queries include: WHERE tenant_id = %s
    ...

@app.get("/api/v1/health/live")
async def health_live():
    return {"status": "ok"}

@app.get("/api/v1/health/ready")
async def health_ready():
    # Check DI DB connectivity
    try:
        conn = _get_di_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
        conn.close()
        return {"status": "ok"}
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"DB unavailable: {e}")
```

## run_scan.py (K8s Job entry point)
```python
"""engine-di K8s Job entry point. Runs full Phase 0 → Phase 1 → Phase 2 for one account."""
import argparse, logging, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

# Enable adaptive retries for AWS (same as engine-discoveries)
os.environ.setdefault("AWS_RETRY_MODE", "adaptive")
os.environ.setdefault("AWS_MAX_ATTEMPTS", "10")

from di_engine.phase0.enumerator import run_phase0
from di_engine.phase1.enricher import run_phase1
from di_engine.phase2.writer import run_phase2
from engine_common.orchestration import get_orchestration_metadata, update_scan_status

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s — %(message)s")
logger = logging.getLogger("di_scanner")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scan-run-id", required=True)
    parser.add_argument("--orchestration-id", required=True)
    args = parser.parse_args()

    scan_run_id = args.scan_run_id
    meta = get_orchestration_metadata(args.orchestration_id)
    provider = meta['provider']
    account_id = meta['account_id']
    tenant_id = meta['tenant_id']
    regions = meta['regions']
    credentials = _resolve_credentials(meta)

    inv_conn = _get_inventory_conn()   # for resource_inventory_identifier
    di_conn = _get_di_conn()           # for asset_inventory + di_scan_errors

    try:
        update_scan_status(scan_run_id, 'running', engine='di')

        # Phase 0 — enumerate all resources, build canonical UIDs
        p0_rows = list(run_phase0(
            scan_run_id=scan_run_id, tenant_id=tenant_id, account_id=account_id,
            provider=provider, regions=regions, credentials=credentials,
            inv_conn=inv_conn, di_conn=di_conn,
        ))
        logger.info("Phase 0 complete: %d resources enumerated", len(p0_rows))

        # Phase 1 — enrich using enrich_ops (server-side filtered to active service×region pairs)
        scanner = _get_authenticated_scanner(provider, credentials)
        p1_rows = list(run_phase1(
            phase0_rows=p0_rows, identifiers=_load_identifiers(inv_conn, provider),
            scanner=scanner, scan_run_id=scan_run_id, tenant_id=tenant_id,
            account_id=account_id, provider=provider, di_conn=di_conn,
        ))
        logger.info("Phase 1 complete: %d rows enriched", sum(1 for r in p1_rows if r['phase']==1))

        # Phase 2 — write to asset_inventory
        stats = run_phase2(iter(p1_rows), di_conn, scan_run_id, tenant_id)
        logger.info("Phase 2 complete: %s", stats)

        update_scan_status(scan_run_id, 'completed', engine='di',
                           resources_found=stats['inserted'] + stats['updated'])
    except Exception as exc:
        logger.error("DI scan failed: %s", exc, exc_info=True)
        update_scan_status(scan_run_id, 'failed', engine='di', error=str(exc))
        raise
    finally:
        try: inv_conn.close()
        except: pass
        try: di_conn.close()
        except: pass
```

## K8s Manifest (`engine-di.yaml`)
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: engine-di
  namespace: threat-engine-engines
  labels:
    app: engine-di
    version: v1.0.0
    component: scanner
    managed-by: kubectl
spec:
  replicas: 1
  selector:
    matchLabels:
      app: engine-di
  template:
    metadata:
      labels:
        app: engine-di
    spec:
      containers:
      - name: engine-di
        image: yadavanup84/engine-di:v-di-1
        ports:
        - containerPort: 8025
        resources:
          requests:
            cpu: 500m
            memory: 1Gi
          limits:
            cpu: 2000m
            memory: 4Gi
        livenessProbe:
          httpGet:
            path: /api/v1/health/live
            port: 8025
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /api/v1/health/ready
            port: 8025
          initialDelaySeconds: 10
          periodSeconds: 10
        env:
        - name: DI_DB_HOST
          valueFrom:
            configMapKeyRef:
              name: threat-engine-db-config
              key: DI_DB_HOST
        - name: DI_DB_PORT
          value: "5432"
        - name: DI_DB_NAME
          value: threat_engine_di
        - name: DI_DB_USER
          value: postgres
        - name: DI_DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: threat-engine-db-passwords
              key: DI_DB_PASSWORD
        - name: INVENTORY_DB_HOST
          valueFrom:
            configMapKeyRef:
              name: threat-engine-db-config
              key: INVENTORY_DB_HOST
        - name: DI_SCANNER_IMAGE
          value: yadavanup84/engine-di:v-di-1
        - name: DI_SCANNER_NAMESPACE
          value: threat-engine-engines
        securityContext:
          runAsNonRoot: true
          runAsUser: 1000
---
apiVersion: v1
kind: Service
metadata:
  name: engine-di
  namespace: threat-engine-engines
spec:
  selector:
    app: engine-di
  ports:
  - port: 80
    targetPort: 8025
```

## Acceptance Criteria

### Functional
- [ ] `GET /api/v1/health/live` → 200 `{"status":"ok"}`
- [ ] `GET /api/v1/health/ready` → 200 when DI DB reachable; 503 when not
- [ ] `POST /api/v1/di/scan` → 202 with `scan_run_id` UUID
- [ ] `GET /api/v1/di/scan/{id}/status` → `{status: "completed"}` after scan finishes
- [ ] `GET /api/v1/di/assets?provider=aws` → paginated list with canonical resource_uids
- [ ] `GET /api/v1/di/errors` → list from `di_scan_errors` (0 rows for clean scan)
- [ ] Full end-to-end scan on test AWS account: resources in `asset_inventory`, 0 synthetic UIDs
- [ ] Scan for all 7 CSPs: trigger one scan per CSP, each produces rows in `asset_inventory`

### Security
- [ ] `POST /api/v1/di/scan` requires `scans:create` — viewer and analyst get 403
- [ ] `GET /api/v1/di/assets` scoped by `tenant_id` from `AuthContext` — no cross-tenant reads
- [ ] `GET /api/v1/di/errors` scoped by `tenant_id` — no cross-tenant error visibility
- [ ] No `DEV_BYPASS_AUTH` in api_server.py or run_scan.py
- [ ] `DI_DB_PASSWORD` from K8s Secret only (not ConfigMap)
- [ ] Container runs as UID 1000 (non-root)

### RBAC Matrix
| Role | POST /di/scan | GET /di/assets | GET /di/errors |
|------|--------------|----------------|----------------|
| platform_admin | 200 | 200 | 200 |
| org_admin | 200 | 200 | 200 |
| tenant_admin | 200 | 200 | 200 |
| analyst | 403 | 200 | 200 |
| viewer | 403 | 200 | 200 |

### Error Handling
- [ ] `POST /di/scan` for unknown account_id → 404 from orchestration lookup
- [ ] Run with invalid credentials → scan status = `"failed"`, clear error message in status endpoint

## Testing Requirements

**Unit** (`tests/engines/di/test_api_server.py`):
- POST `/di/scan` with valid auth → 202
- POST `/di/scan` as `viewer` → 403
- GET `/di/assets` without `tenant_id` in auth context → 401
- GET `/di/assets` returns only rows for auth.tenant_id
- `/health/live` → 200 (no DB needed)
- `/health/ready` → 503 when DB mock raises

**Integration**:
1. `docker build -t yadavanup84/engine-di:v-di-1 -f engines/di/Dockerfile .` — confirm success
2. `kubectl apply -f deployment/aws/eks/engines/engine-di.yaml`
3. `kubectl rollout status deployment/engine-di -n threat-engine-engines`
4. `GET /api/v1/health/live` via port-forward → 200
5. Trigger scan for test AWS account; confirm `asset_inventory` populated

**Post-deploy smoke**:
```bash
kubectl get pods -n threat-engine-engines -l app=engine-di \
  -o custom-columns='NAME:.metadata.name,IMAGE:.spec.containers[0].image'
# Must show: yadavanup84/engine-di:v-di-1

kubectl logs -f -l app=engine-di -n threat-engine-engines --tail=50 | grep -i error
# Expected: no ERROR lines within first 50 lines of startup
```

## Review Gates
| Gate | Agent | Blocks |
|------|-------|--------|
| Pre-dev | bmad-sm | dev start |
| Security review | bmad-security-reviewer | merge (endpoint auth + tenant isolation) |
| QA acceptance | cspm-qa | deploy |
| Post-deploy | cspm-post-deploy | close |

## Definition of Done
- [ ] `engines/di/` directory fully created: api_server.py, run_scan.py, Dockerfile, requirements.txt
- [ ] All 7 endpoints implemented; RBAC matrix passing for 5 roles
- [ ] Docker image built as `yadavanup84/engine-di:v-di-1`
- [ ] `engine-di.yaml` applied; `kubectl rollout status` passes
- [ ] POST-DEPLOY IMAGE TAG CHECK: pod shows `v-di-1` image
- [ ] End-to-end scan: AWS account → `asset_inventory` rows > 0 + 0 synthetic UIDs
- [ ] Unit + integration tests passing
- [ ] bmad-security-reviewer gate passed
- [ ] MEMORY.md updated: engine-di port 8025, image v-di-1

## Dependencies
- DI-S1-03 (Phase 0), DI-S1-04 (Phase 1), DI-S1-05 (Phase 2)
- DI-S1-01 (DB schema), DI-S1-02 (identifier table)
- `DI_DB_PASSWORD` key added to `threat-engine-db-passwords` Secret
- `DI_DB_HOST` key added to `threat-engine-db-config` ConfigMap

## Rollback
```bash
kubectl delete deployment engine-di -n threat-engine-engines
kubectl delete service engine-di -n threat-engine-engines
```