---
story_id: onboarding-D-5
title: Schedule CRUD API via Django BFF — create, list, update, delete schedules
status: ready
sprint: onboarding-revamp-D
depends_on: [onboarding-C-6, onboarding-C-8]
blocks: [onboarding-D-10]
sme: Django/FastAPI/BFF engineer
estimate: 1 day
---

# Story: Schedule CRUD API via Django BFF

## User Story
As a frontend developer, I want the Django BFF to expose schedule CRUD endpoints that
proxy to the onboarding engine, so that the frontend wizard can create, list, and update
schedules with a single authenticated API call through the gateway.

## Context
The onboarding engine (port 8008) has schedule endpoints after C6/C8. However, the
frontend wizard calls through the API Gateway which routes to the BFF for views and
to engines via the gateway for raw data. This story adds a thin BFF proxy layer in the
gateway for schedule operations so the frontend uses consistent gateway URLs.

Alternatively, this story can expose schedule endpoints directly through the gateway's
engine-routing layer (`shared/api_gateway/main.py` or `routes.py`), forwarding to
`http://engine-onboarding/api/v1/schedules/` with the `X-Auth-Context` header attached.

The BFF layer adds:
- `GET /gateway/api/v1/schedules/` → proxied list with tenant scoping
- `POST /gateway/api/v1/schedules/` → creates schedule
- `PATCH /gateway/api/v1/schedules/{id}/` → updates schedule
- `DELETE /gateway/api/v1/schedules/{id}/` → deletes schedule
- `POST /gateway/api/v1/schedules/{id}/run-now` → trigger immediate scan
- `POST /gateway/api/v1/schedules/run-all` → bulk trigger

## Files to Create/Modify
- `shared/api_gateway/routes/schedules.py` — new router file proxying to onboarding engine
- `shared/api_gateway/main.py` — include schedules router

## Implementation Notes

### Gateway proxy pattern

```python
# shared/api_gateway/routes/schedules.py
import httpx
from fastapi import APIRouter, Request, Depends, Response

ONBOARDING_URL = os.getenv("ONBOARDING_ENGINE_URL", "http://engine-onboarding")
router = APIRouter(prefix="/api/v1/schedules", tags=["schedules"])

async def _proxy_to_onboarding(request: Request, path: str, method: str, body=None):
    auth_ctx = request.state.auth_context  # set by AuthMiddleware
    headers = {"X-Auth-Context": auth_ctx.to_header()}
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.request(
            method,
            f"{ONBOARDING_URL}/api/v1/{path}",
            headers=headers,
            json=body,
        )
    return Response(content=resp.content, status_code=resp.status_code,
                    media_type="application/json")

@router.get("/")
async def list_schedules(request: Request):
    return await _proxy_to_onboarding(request, "schedules/", "GET")

@router.post("/")
async def create_schedule(request: Request):
    body = await request.json()
    return await _proxy_to_onboarding(request, "schedules/", "POST", body)

@router.patch("/{schedule_id}")
async def update_schedule(request: Request, schedule_id: str):
    body = await request.json()
    return await _proxy_to_onboarding(request, f"schedules/{schedule_id}", "PATCH", body)

@router.delete("/{schedule_id}")
async def delete_schedule(request: Request, schedule_id: str):
    return await _proxy_to_onboarding(request, f"schedules/{schedule_id}", "DELETE")

@router.post("/{schedule_id}/run-now")
async def run_now(request: Request, schedule_id: str):
    return await _proxy_to_onboarding(request, f"schedules/{schedule_id}/run-now", "POST")

@router.post("/run-all")
async def run_all(request: Request):
    return await _proxy_to_onboarding(request, "schedules/run-all", "POST")
```

## Acceptance Criteria
- [ ] AC1: `POST /gateway/api/v1/schedules/` proxies to onboarding engine and returns 201
- [ ] AC2: `X-Auth-Context` header is forwarded on every proxied request
- [ ] AC3: Unauthenticated request → gateway AuthMiddleware returns 401 before proxying
- [ ] AC4: `POST /gateway/api/v1/schedules/{id}/run-now` proxies and returns 202
- [ ] AC5: `POST /gateway/api/v1/schedules/run-all` proxies and returns 202

## Definition of Done
- [ ] Gateway schedule router created and included in main.py
- [ ] All 6 endpoints proxy correctly with X-Auth-Context
- [ ] Tests: proxy passes auth context, unauthenticated 401
- [ ] No business logic in gateway proxy (pure forwarding)
- [ ] bmad-security-reviewer: no BLOCKERs
