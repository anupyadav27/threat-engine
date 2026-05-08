# Story DI-06: New BFF Endpoint — `GET /api/v1/views/threats/technique/{technique_id}`

**Epic:** UI Investigation Journeys Sprint
**Status:** Ready for Dev
**Story Points:** 3
**Depends On:** None
**Blocks:** DI-09

## Context

The `TechniqueDetailModal` component (DI-09) opens when a user clicks a MITRE technique label (e.g., `T1530`) in the Attack Path view. It needs a BFF endpoint that returns: technique metadata, tenant-scoped impact counts (how many resources in this tenant are affected), D3FEND countermeasures (static map — no new DB column this sprint), and compliance control mappings. This endpoint does NOT exist yet.

## Scope

Create a new BFF module `shared/api_gateway/bff/technique_detail.py` with one route handler, and register it in the gateway router.

**Out of scope:** `TechniqueDetailModal` React component (DI-09), any new DB columns for D3FEND, any changes to the threat engine.

## Files to Create/Modify

- `/Users/apple/Desktop/threat-engine/shared/api_gateway/bff/technique_detail.py` — create new file
- `/Users/apple/Desktop/threat-engine/shared/api_gateway/router.py` — import and include the new router

## Implementation Notes

**DB connection:** This BFF endpoint makes direct DB queries to the threat DB (same pattern as other BFF handlers that query DB). Use the existing `_shared.py` connection pattern or `httpx` against the threat engine. Prefer querying the threat engine API if a suitable endpoint exists; otherwise query DB directly via the pattern in `shared/api_gateway/bff/_shared.py`.

Simpler approach: fan out two parallel calls to the threat engine:
- `GET /api/v1/threat/techniques/{technique_id}` → technique metadata
- `GET /api/v1/threat/detections?mitre_technique={technique_id}&tenant_id={tenant_id}&count_only=true` → affected counts

If neither endpoint exists, query threat DB directly (see SQL below).

**Direct DB query approach (if engine endpoints not available):**

Query 1 — technique metadata:
```sql
SELECT technique_id, technique_name, tactics, severity_base, remediation_guidance
FROM mitre_technique_reference
WHERE technique_id = $1;
```

Query 2 — tenant-scoped affected count (handles dual JSONB form):
```sql
SELECT
    COUNT(DISTINCT resource_uid) AS affected_resources,
    COUNT(*) AS detection_count
FROM threat_detections
WHERE tenant_id = $1
  AND (
    mitre_techniques @> jsonb_build_array($2)
    OR mitre_techniques @> jsonb_build_array(jsonb_build_object('id', $2))
  );
```

Index: `idx_threat_findings_mitre_gin` on `threat_detections.mitre_techniques` — this query should be fast.

**DB connection** uses same env vars as threat engine: `THREAT_DB_HOST`, `THREAT_DB_PORT`, `THREAT_DB_NAME`, `THREAT_DB_USER`, `THREAT_DB_PASSWORD`. If the gateway BFF does not have a shared threat DB connection, proxy via the threat engine's UI data endpoint instead.

**JSONB note:** `tactics` from `mitre_technique_reference` is already a Python list (psycopg2 deserializes JSONB automatically) — NEVER call `json.loads()` on it. `remediation_guidance` is also JSONB.

**D3FEND static map** (hardcoded in BFF — no DB column this sprint):
```python
D3FEND_MAP = {
    "T1190": ["D3-NTF (Network Traffic Filtering)", "D3-WSAF (Web Session Activity Analysis)"],
    "T1078": ["D3-OAA (One-time Password)", "D3-MFA (Multi-factor Authentication)"],
    "T1098": ["D3-AEPP (Auth Event Thresholding)", "D3-ANET (Authorization Event Thresholding)"],
    "T1530": ["D3-EAL (Executable Allowlisting)", "D3-PLM (Platform Monitoring)"],
    "T1537": ["D3-NTF (Network Traffic Filtering)", "D3-OAT (Outbound Traffic Filtering)"],
    "T1485": ["D3-BKUP (Backup Data)"],
    "T1562": ["D3-DLIC (Driver Load Integrity Checking)", "D3-PLA (Platform Monitoring Log Analysis)"],
    "T1119": ["D3-DCOM (Data Component Monitoring)"],
    "T1040": ["D3-NTA (Network Traffic Analysis)"],
    "T1578": ["D3-CCE (Cloud Configuration Enforcement)"],
}
```

**D3FEND entry parsing** — each string has format `"D3-XXX (Label)"`:
```python
def _parse_d3fend_entry(entry: str) -> dict:
    """Parse a D3FEND string into {id, label}."""
    if " (" in entry and entry.endswith(")"):
        d3_id, rest = entry.split(" (", 1)
        label = rest[:-1]  # strip trailing ")"
    else:
        d3_id = entry
        label = entry
    return {"id": d3_id.strip(), "label": label.strip()}
```

**Permission:** `threat:read` — check with existing `require_permission` pattern. If the BFF uses a permission check helper, apply it here. Unknown techniques return 404.

**`tenant_id` ONLY from AuthContext:**
```python
tenant_id = resolve_tenant_id(request)  # never from query param
```

**Response shape:**
```json
{
  "techniqueId": "T1530",
  "techniqueName": "Data from Cloud Storage",
  "tactics": ["Collection"],
  "severityBase": "high",
  "url": "https://attack.mitre.org/techniques/T1530/",
  "affectedResources": 7,
  "detectionCount": 12,
  "d3fendMappings": [
    {"id": "D3-EAL", "label": "Executable Allowlisting"},
    {"id": "D3-PLM", "label": "Platform Monitoring"}
  ],
  "complianceControls": {}
}
```

**`complianceControls`:** from `remediation_guidance` JSONB field in `mitre_technique_reference`. If `remediation_guidance` is a dict with a `compliance_controls` key, return that. Otherwise return `{}`.

**MITRE ATT&CK URL:** `f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"` — this handles sub-techniques like `T1078.001`.

**404 handling:** If `mitre_technique_reference` returns no row for the given `technique_id`, return `HTTPException(status_code=404, detail="Technique not found")`.

**Full module structure:**
```python
"""BFF view: GET /api/v1/views/threats/technique/{technique_id}

Returns MITRE technique metadata enriched with tenant-scoped impact counts
and D3FEND countermeasure mappings.
"""

from fastapi import APIRouter, HTTPException, Request

from ._auth import resolve_tenant_id, _parse_auth_context

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])

D3FEND_MAP = { ... }  # as above

def _parse_d3fend_entry(entry: str) -> dict: ...

@router.get("/threats/technique/{technique_id}")
async def view_technique_detail(request: Request, technique_id: str):
    """BFF for TechniqueDetailModal — technique metadata + tenant impact counts."""
    tenant_id = resolve_tenant_id(request)
    # [DB queries, D3FEND lookup, response assembly]
```

**Router registration in `shared/api_gateway/router.py`:**
```python
from .bff.technique_detail import router as technique_detail_router
app.include_router(technique_detail_router)
```

## Acceptance Criteria

- [ ] `GET /api/v1/views/threats/technique/T1530` returns 200 with correct shape for a technique that exists in `mitre_technique_reference`
- [ ] Response has `techniqueId`, `techniqueName`, `tactics` (list), `severityBase`, `url`, `affectedResources`, `detectionCount`, `d3fendMappings`, `complianceControls`
- [ ] `url` is `"https://attack.mitre.org/techniques/T1530/"` (note trailing slash)
- [ ] `GET /api/v1/views/threats/technique/T9999` (nonexistent) → 404 response
- [ ] `tenant_id` test: call with valid auth but append `?tenant_id=other_tenant_id` — verify `affectedResources` reflects only the authenticated tenant's data (not the forged tenant)
- [ ] `d3fendMappings` for T1530 → `[{"id": "D3-EAL", ...}, {"id": "D3-PLM", ...}]`
- [ ] `d3fendMappings` for unknown technique (not in D3FEND_MAP) → `[]` (empty list)
- [ ] Both JSONB forms counted: plain `["T1530"]` and object `[{"id":"T1530"}]` in `threat_detections.mitre_techniques`
- [ ] `complianceControls: {}` when `remediation_guidance` is null
- [ ] Unauthenticated request → 401

## Security Gates

- **B-1 (AuthContext-only tenant_id):** `resolve_tenant_id(request)` is the only source of `tenant_id` for the COUNT query — forged query param is ignored
- **B-6 (no mock data):** `affectedResources` and `detectionCount` are live DB counts — never hardcoded or mocked
- **JSONB safety:** `tactics` and `remediation_guidance` from psycopg2 are dicts/lists — never call `json.loads()`

## Definition of Done

- [ ] Code written and passes linter
- [ ] BFF contract test: `tests/bff/test_technique_detail.py` covering 200, 404, tenant isolation, d3fend parsing
- [ ] Route registered in `router.py` and reachable
- [ ] bmad-security-reviewer approved (new endpoint with DB query)
- [ ] bmad-qa acceptance test run