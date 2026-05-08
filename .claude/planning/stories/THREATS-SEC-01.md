# THREATS-SEC-01 — Fix Threat PATCH Endpoint Security

**Sprint:** Threats-UI Pre-work | **Points:** 3 | **Priority:** P0 — Blocker
**Engine:** Threat (Port 8020)
**Blocked by:** Nothing — must ship BEFORE THREATS-UI-01

---

## Problem Statement

Two live security defects exist in the threat status update endpoint. The Command Room slide-over (THREATS-UI-01) exposes Assign/Suppress action buttons to more users — shipping it before these fixes widens the attack surface.

### Defect 1 — No write permission gate
`PATCH /api/v1/threat/{threat_id}` at `engines/threat/threat_engine/api_server.py:1453` has no `require_permission()` dependency. Any authenticated user (including `viewer` role) can update threat status.

### Defect 2 — Caller-controlled audit attribution
The `ThreatUpdateRequest` body accepts `status_changed_by` from the caller. An attacker can set an arbitrary user ID, breaking non-repudiation in the audit trail.

---

## Files Modified

- `engines/threat/threat_engine/api_server.py`

---

## Implementation

```python
# api_server.py — PATCH /api/v1/threat/{threat_id}

class ThreatUpdateRequest(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    suppression_reason: Optional[str] = None
    # REMOVE: status_changed_by — derived from AuthContext only

@app.patch("/api/v1/threat/{threat_id}")
async def update_threat(
    threat_id: str,
    body: ThreatUpdateRequest,
    auth: AuthContext = Depends(require_permission("threat:write")),
):
    tenant_id = auth.tenant_id           # from AuthContext, never body
    user_id   = auth.user_id             # overrides any caller-supplied value

    # All writes include server-derived user_id
    await _update_threat_status(
        threat_id=threat_id,
        tenant_id=tenant_id,
        status_changed_by=user_id,       # server-side, not from body
        **body.model_dump(exclude_none=True),
    )
```

---

## Acceptance Criteria

1. `viewer` token → `PATCH /api/v1/threat/{threat_id}` → 403 Forbidden
2. `analyst` token → 403 (analyst does not have `threat:write`)
3. `tenant_admin` token → 200, status updated
4. Response includes `status_changed_by` = `auth.user_id` (server-derived), regardless of any value passed in body
5. `grep -n "require_permission" api_server.py` confirms PATCH endpoint has the guard
6. bmad-security-reviewer sign-off

## STRIDE

| Threat | Fix |
|---|---|
| Elevation of Privilege (viewer updates threat) | require_permission("threat:write") |
| Repudiation (fake status_changed_by) | Derive user_id from AuthContext server-side |

## Definition of Done

- [ ] `require_permission("threat:write")` on PATCH endpoint
- [ ] `status_changed_by` removed from request model, derived from AuthContext
- [ ] AC #1-4 verified with real role tokens
- [ ] Threat engine image rebuilt and deployed