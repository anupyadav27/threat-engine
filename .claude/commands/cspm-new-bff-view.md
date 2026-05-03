# /cspm-new-bff-view

Create a new BFF view handler for a UI page. Enforces the BFF vs gateway split.

## Usage
```
/cspm-new-bff-view <page-name> <engine>
```

Example:
```
/cspm-new-bff-view supply-chain engine-supply-chain
```

## What gets created

File: `shared/api_gateway/bff/<page-name>.py`

## BFF Constitution Rules (non-negotiable)

1. **BFF is for charts/aggregates ONLY** — KPI counts, posture scores, trend data, top-N lists
2. **Engine gateway handles tables** — paginated raw findings go direct to engine via gateway, NOT through BFF
3. **NEVER add fallback/mock data** — if engine is down, return the error. Do NOT substitute mock data or merge from another engine to mask the gap
4. **NEVER json.loads() on JSONB** — psycopg2 returns JSONB as Python dict already
5. **Always scope by tenant_id** — every query must include `AND tenant_id = $tenant_id`

## BFF template
```python
"""
BFF view: <page-name>
Page: /<page-name>
Primary: engine-<engine> /api/v1/<engine>/ui-data
"""
import logging
from ._shared import ENGINE_URLS, make_engine_request

logger = logging.getLogger(__name__)
ENGINE_URL = ENGINE_URLS["<engine>"]

async def get_<page_name>_view(tenant_id: str, auth_context: dict) -> dict:
    """GET /gateway/api/v1/views/<page-name>"""
    data = await make_engine_request(
        ENGINE_URL,
        f"/api/v1/<engine>/ui-data?tenant_id={tenant_id}",
        auth_context=auth_context,
    )
    return data
```

## BFF registration
Add to `shared/api_gateway/router.py`:
```python
from .bff.<page_name> import get_<page_name>_view

@router.get("/views/<page-name>")
async def view_<page_name>(tenant_id: str, auth=Depends(get_auth_context)):
    return await get_<page_name>_view(tenant_id, auth)
```
