# STORY-CIEM-03: Store Ordered Contributing Steps in L2 Correlation Findings

## Track
CIEM Investigation Journey — Sprint 1 (Blocker for Stage 3 Timeline)

## Priority
P0 — Stage 3 attack chain timeline UI cannot be built without ordered step data

## Story
As a security analyst drilling into an L2 correlation finding, I need to see the exact sequence of events that triggered the correlation rule (step 1 → step 2 → step 3 with timestamps and time deltas), so I can understand the attack chain narrative instead of seeing an unordered list of contributing event IDs.

## Current State

`engines/ciem/ciem_engine/evaluator/correlation_evaluator.py`, method `_create_correlation_finding` (lines ~291-358):

The method writes `contributing_findings` as a flat unordered list of `finding_id` strings into `finding_data` JSONB. The step index (`step_idx`) and per-step context (operation, resource, event_time) are available during evaluation but are not persisted.

```python
# Current (simplified)
finding_data = {
    "contributing_findings": [f_id_1, f_id_2, f_id_3],
    "first_event": ...,
    "last_event": ...,
    "event_count": 3,
    ...
}
```

## Files to Modify
- `engines/ciem/ciem_engine/evaluator/correlation_evaluator.py` — `_create_correlation_finding` method
- `engines/ciem/ciem_engine/api_server.py` — new timeline endpoint

## Exact Changes

### 1. `correlation_evaluator.py` — `_create_correlation_finding`

Replace the flat `contributing_findings` list with `contributing_steps` (ordered, with context). Keep `contributing_findings` as a flat list of IDs for backwards compatibility with any existing code that reads it.

New `finding_data` structure:
```python
finding_data = {
    # NEW: ordered steps with full context
    "contributing_steps": [
        {
            "step_idx": 0,
            "finding_id": "abc123",
            "rule_id": "ciem-aws-credential-reuse-001",
            "event_time": "2024-01-15T10:23:00Z",   # ISO format
            "operation": "AssumeRole",
            "service": "sts",
            "resource_uid": "arn:aws:iam::123456789012:role/ExecRole",
            "resource_name": "ExecRole",             # short name if available
            "outcome": "success",                    # from event_data or "unknown"
            "actor_ip": "203.0.113.42"               # from the L1 finding
        }
    ],
    # KEPT for backwards compatibility
    "contributing_findings": ["abc123", "def456", "ghi789"],
    "first_event": "2024-01-15T10:23:00Z",
    "last_event": "2024-01-15T10:37:00Z",
    "event_count": 3,
    # ... existing fields unchanged
}
```

The `contributing_steps` list must be sorted by `event_time` ascending (step_idx 0 = earliest event).

### 2. `api_server.py` — new timeline endpoint

```python
@router.get("/api/v1/ciem/findings/{finding_id}/timeline")
async def get_finding_timeline(
    finding_id: str,
    tenant_id: str = Depends(get_tenant_id),
    auth: AuthContext = Depends(require_permission("ciem:read")),
    db=Depends(get_db)
):
    # Fetch finding, validate rule_source == 'log_correlation'
    # Return finding_data['contributing_steps'] or 404/400 as appropriate
```

Returns:
- `200` with `{"finding_id": ..., "rule_id": ..., "steps": [...contributing_steps...], "first_event": ..., "last_event": ..., "event_count": N}` if `contributing_steps` present
- `400 {"detail": "finding is not a correlation finding"}` if `rule_source != 'log_correlation'`
- `400 {"detail": "finding predates step ordering — re-run CIEM scan to generate steps"}` if `contributing_steps` absent (old format)
- `404` if finding not found or wrong tenant

## Acceptance Criteria

- [ ] New L2 correlation findings written after this change include `contributing_steps` in `finding_data`, sorted by `event_time` ascending
- [ ] Each step object has: `step_idx`, `finding_id`, `rule_id`, `event_time`, `operation`, `service`, `resource_uid`, `outcome` (at minimum)
- [ ] `contributing_findings` flat list still present in `finding_data` (backwards compat)
- [ ] Old findings (without `contributing_steps`) are NOT migrated — endpoint returns `400` for them
- [ ] `GET /api/v1/ciem/findings/{id}/timeline` returns `200` with steps for a valid new L2 finding
- [ ] Tenant isolation: endpoint validates `tenant_id` before returning any data
- [ ] `step_idx` is 0-based and sequential with no gaps

## Security Checklist
- [ ] `WHERE tenant_id = %s AND finding_id = %s` — confirm both conditions in DB query
- [ ] `require_permission("ciem:read")` on the timeline endpoint
- [ ] `finding_data` is JSONB — do NOT call `json.loads()` on it; access as dict directly
- [ ] `strip_sensitive_fields()` must strip `event_raw` and `actor_ip` from step objects for auth level ≥ 4

## Definition of Done
- [ ] `correlation_evaluator.py` updated
- [ ] `api_server.py` has new `/timeline` endpoint
- [ ] Integration test: trigger a CIEM L2 rule, verify finding_data has `contributing_steps`
- [ ] Call `/timeline` endpoint, verify steps returned in time order