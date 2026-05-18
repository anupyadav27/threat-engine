# Story APISEC-S1-03: Engine Scaffold — FastAPI Pod + Health + Scan Trigger + RBAC

## Status: done

## Metadata
- **Sprint**: APISEC Sprint 1
- **Points**: 5
- **Depends on**: APISEC-S1-02
- **Blocks**: APISEC-S1-05 through S1-12
- **Security Gate**: bmad-security-reviewer (new endpoints require auth review)

## Directory Structure

```
engines/api-security/
├── Dockerfile
├── requirements.txt
├── run_scan.py                              # K8s Job entry point
├── api_server.py                            # FastAPI pod (always-on)
└── api_security_engine/
    ├── __init__.py
    ├── api/
    │   ├── __init__.py
    │   └── routes.py
    ├── providers/
    │   ├── __init__.py                      # get_provider() factory
    │   └── base.py                          # BaseAPISecProvider
    ├── modules/                             # analysis modules (S1-09)
    ├── enricher/                            # CDR enricher (S2-05)
    ├── input/                               # readers (S1-06, S1-07)
    └── storage/                             # writer + posture signals (S1-10, S1-11)
```

## `api_server.py`

```python
import os
import logging
from fastapi import FastAPI
from engine_common.auth import engine_auth
from api_security_engine.api.routes import router

logger = logging.getLogger("api_security.server")
app = FastAPI(title="API Security Engine", version="1.0.0")
app.include_router(router, prefix="/api/v1")
engine_auth(app)
```

## `api_security_engine/api/routes.py`

```python
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from uuid import UUID
from engine_common.auth import require_permission, AuthContext

router = APIRouter()

class ScanRequest(BaseModel):
    scan_run_id: UUID
    tenant_id: str
    account_id: str
    provider: str
    credential_ref: str
    credential_type: str
    region: str | None = None

class ScanResponse(BaseModel):
    scan_run_id: UUID
    status: str
    message: str

@router.get("/health/live")
def liveness():
    return {"status": "ok"}

@router.get("/health/ready")
def readiness():
    return {"status": "ok"}

@router.post("/apisec/scan", response_model=ScanResponse)
def trigger_scan(
    req: ScanRequest,
    auth: AuthContext = Depends(require_permission("api_security:read"))
):
    """Trigger API security scan for a scan_run_id.
    Called by Argo workflow. Validates scan_run_id belongs to tenant before dispatching.
    """
    from engine_common.db_connections import get_discoveries_conn
    # Validate scan_run_id belongs to this tenant
    with get_discoveries_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT 1 FROM scan_orchestration WHERE scan_run_id = %s AND tenant_id = %s",
                (str(req.scan_run_id), req.tenant_id)
            )
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="scan_run_id not found for tenant")

    # Dispatch Job via Kubernetes Job or direct run_scan call
    import subprocess
    subprocess.Popen([
        "python3", "run_scan.py",
        "--scan-run-id", str(req.scan_run_id),
        "--tenant-id", req.tenant_id,
        "--account-id", req.account_id,
        "--provider", req.provider,
        "--credential-ref", req.credential_ref,
        "--credential-type", req.credential_type,
    ])
    return ScanResponse(
        scan_run_id=req.scan_run_id,
        status="dispatched",
        message="API security scan started"
    )

@router.get("/apisec/report/{scan_run_id}")
def get_report(
    scan_run_id: UUID,
    auth: AuthContext = Depends(require_permission("api_security:read"))
):
    """Fetch api_security_report for completed scan. Scoped to auth tenant."""
    from engine_common.db_connections import get_api_security_conn
    with get_api_security_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT report_id, scan_run_id, tenant_id, provider, account_id, status,
                       critical_count, high_count, medium_count, low_count, total_findings,
                       owasp_api1_count, owasp_api2_count, owasp_api4_count,
                       owasp_api7_count, owasp_api8_count, owasp_api9_count,
                       cdr_enriched_count, started_at, completed_at, report_data
                FROM api_security_report
                WHERE scan_run_id = %s AND tenant_id = %s
            """, (str(scan_run_id), auth.tenant_id))
            row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Report not found")
    return dict(zip([d.name for d in cur.description], row))
```

## `providers/base.py`

```python
from abc import ABC, abstractmethod
from typing import List, Dict, Any

class BaseAPISecProvider(ABC):
    """Base class for all CSP API security providers."""

    @abstractmethod
    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        discoveries_conn,
        check_conn,
    ) -> List[Dict[str, Any]]:
        """Return list of api_security finding dicts."""
        ...
```

## `providers/__init__.py`

```python
from api_security_engine.providers.base import BaseAPISecProvider

def get_provider(csp_name: str) -> BaseAPISecProvider:
    name = csp_name.lower()
    if name == "aws":
        from api_security_engine.providers.aws import AWSAPISecProvider
        return AWSAPISecProvider()
    if name == "azure":
        from api_security_engine.providers.azure import AzureAPISecProvider
        return AzureAPISecProvider()
    if name == "gcp":
        from api_security_engine.providers.gcp import GCPAPISecProvider
        return GCPAPISecProvider()
    if name in ("oci", "oracle"):
        from api_security_engine.providers.oci import OCIAPISecProvider
        return OCIAPISecProvider()
    if name in ("alicloud", "aliyun"):
        from api_security_engine.providers.alicloud import AliCloudAPISecProvider
        return AliCloudAPISecProvider()
    if name in ("k8s", "kubernetes"):
        from api_security_engine.providers.k8s import K8sAPISecProvider
        return K8sAPISecProvider()
    raise ValueError(f"Unsupported CSP for API Security engine: {csp_name}")
```

## Acceptance Criteria

- [ ] AC-1: `GET /api/v1/health/live` returns 200 `{"status":"ok"}` — no auth required
- [ ] AC-2: `GET /api/v1/health/ready` returns 200 — no auth required
- [ ] AC-3: `POST /api/v1/apisec/scan` without valid JWT returns 401
- [ ] AC-4: `POST /api/v1/apisec/scan` with `viewer` role JWT (has `api_security:read`) returns 200 (dispatches scan)
- [ ] AC-5: `POST /api/v1/apisec/scan` with a `scan_run_id` belonging to a different tenant returns 404
- [ ] AC-6: `GET /api/v1/apisec/report/{scan_run_id}` scopes result to `auth.tenant_id` — cannot retrieve another tenant's report even with valid JWT
- [ ] AC-7: `get_provider("aws")` returns `AWSAPISecProvider` instance; `get_provider("UNKNOWN")` raises `ValueError`

## Definition of Done
- [ ] All routes implemented with correct `require_permission()` guard
- [ ] scan_run_id tenant ownership validated before dispatch
- [ ] Provider factory dispatches to all 6 CSP providers (stubs for Azure/GCP/OCI/AliCloud/K8s in S2)
- [ ] Engine starts cleanly: `uvicorn api_server:app --host 0.0.0.0 --port 8035`
