# STORY-CIEM-01: Extend Identities Endpoint — Principal Type + L2/L3 Counts

## Track
CIEM Investigation Journey — Sprint 1 (Blocker)

## Priority
P0 — blocks all CIEM UI stories; must ship first

## Story
As a security analyst on the CIEM overview page, I need each identity row to show its principal type (iam_user, iam_role, service_account, root) and separate counts for L2 correlation findings and L3 anomaly findings, so I can immediately distinguish a misconfigured role from an actively behaving anomalous user.

## Current State

`engines/ciem/ciem_engine/api_server.py` identities query (lines ~715-762) returns:
```
actor_principal, total_findings, critical, high, medium,
rules_triggered, services_used, resources_touched, source_ips, last_activity
```

`actor_principal_type` column exists in `ciem_findings` but is NOT in the SELECT.
`rule_source` values `'log_correlation'` (L2) and `'baseline'` (L3) exist but are not broken out per identity.

BFF `shared/api_gateway/bff/ciem.py` (lines ~62-67) loops over the identities response to compute `risk_score` — this is the injection point for the new fields.

## Files to Modify
- `engines/ciem/ciem_engine/api_server.py` — identities aggregation query
- `shared/api_gateway/bff/ciem.py` — pass new fields through in `identitySummary`

## Exact Changes

### 1. `api_server.py` — identities GROUP BY query

Add to the SELECT in the `GET /api/v1/ciem/identities` aggregation:
```sql
actor_principal_type,
COUNT(*) FILTER (WHERE rule_source = 'log_correlation') AS l2_findings,
COUNT(*) FILTER (WHERE rule_source = 'baseline') AS l3_findings
```

Add `actor_principal_type` to the GROUP BY clause.

Response dict per identity — add:
```python
"actor_principal_type": row["actor_principal_type"],
"l2_findings": int(row["l2_findings"]),
"l3_findings": int(row["l3_findings"]),
```

### 2. `bff/ciem.py` — identitySummary loop

In the identity-building loop, add alongside `risk_score`:
```python
identity["actorPrincipalType"] = identity.get("actor_principal_type") or "unknown"
identity["l2Findings"] = identity.get("l2_findings", 0)
identity["l3Findings"] = identity.get("l3_findings", 0)
```

## Acceptance Criteria

- [ ] `GET /api/v1/ciem/identities?scan_run_id=X` returns `actor_principal_type`, `l2_findings`, `l3_findings` per identity
- [ ] `actor_principal_type` is never null — falls back to `"unknown"` if missing
- [ ] `l2_findings` + `l3_findings` sum ≤ `total_findings` for each identity (L1 = total - l2 - l3)
- [ ] BFF `/views/ciem` includes `actorPrincipalType`, `l2Findings`, `l3Findings` in each `identitySummary` item
- [ ] All queries still scoped by `WHERE tenant_id = %s`
- [ ] Response time ≤ 500ms for a tenant with 500 identities

## Security Checklist
- [ ] Query scoped by `tenant_id` from AuthContext (not query param)
- [ ] `require_permission("ciem:read")` already present on the endpoint — confirm not removed
- [ ] No `json.loads()` on any JSONB field
- [ ] `strip_sensitive_fields()` still removes `credential_ref` / `event_raw` for lower auth levels

## Definition of Done
- [ ] Engine code change in `api_server.py`
- [ ] BFF change in `bff/ciem.py`
- [ ] Manual verify: port-forward to CIEM engine, call identities endpoint, confirm new fields present
- [ ] No `latest` image tag if K8s manifest touched