# /cspm-security-gate

Run the mandatory security review gate on the current branch diff before merge. Invokes `bmad-security-reviewer` when the diff touches endpoints, auth, DB, or HTTP.

## Usage
```
/cspm-security-gate
/cspm-security-gate --pr <pr-number>
```

Examples:
```
/cspm-security-gate
/cspm-security-gate --pr 142
```

## Trigger conditions

This gate is **mandatory** (not optional) when the diff contains any of:
- New or modified FastAPI endpoint (`@router.get`, `@router.post`, `@router.delete`, `@router.patch`)
- Auth logic changes (`require_permission`, `AuthContext`, `X-Auth-Context`, `access_token`)
- New DB table, column, or query (`CREATE TABLE`, `ALTER TABLE`, `INSERT INTO`, `SELECT ... FROM`)
- HTTP calls to external services (`requests.get`, `urllib.request`, `httpx`)
- Credential handling (`credential_ref`, `aws_access_key`, `SECRET`, `TOKEN`)
- K8s secret or ConfigMap changes

## Steps

### Step 1 — Diff analysis
```bash
git diff main...HEAD --name-only
git diff main...HEAD -- '*.py' '*.sql' '*.yaml'
```
Identify which trigger conditions are present.

### Step 2 — Constitution pre-check (Claude runs this directly)
For each changed Python file, verify:
- [ ] Every new endpoint has `Depends(require_permission("feature:action"))`
- [ ] Every DB query is scoped by `tenant_id` from `auth_context`
- [ ] No `DEV_BYPASS_AUTH` anywhere in the diff
- [ ] No `json.loads()` on JSONB columns (psycopg2 auto-deserializes)
- [ ] No hardcoded credentials, tokens, or secrets
- [ ] No `latest` image tag in any K8s manifest
- [ ] `strip_sensitive_fields()` called before returning findings with `credential_ref`
- [ ] HTTP calls use internal cluster DNS (not external IPs) where possible

### Step 3 — RBAC matrix spot-check
For each new endpoint in the diff, verify:
- `platform_admin` → 200
- `org_admin` → 200
- `tenant_admin` → 200 or 403 (depending on feature)
- `analyst` → 200 (read) / 403 (write)
- `viewer` → 200 (read) / 403 (sensitive engines + writes)

### Step 4 — Load and apply bmad-security-reviewer
If any trigger condition from Step 1 is present:
1. **Read `.claude/agents/bmad-security-reviewer.md`** — load the full security review checklist and framework mappings
2. Apply its OWASP Top 10, STRIDE, injection, SSRF, tenant isolation, and SLSA checks to the diff
3. Gate does not pass until all checks return PASS or PASS_WITH_NOTES

### Step 5 — Output gate verdict

**APPROVED** — all constitution checks pass, security reviewer checklist complete with no blockers.
**BLOCKED** — list each specific violation with file:line reference. Dev must fix before merge.

## Agent loaded
**`.claude/agents/bmad-security-reviewer.md`** — provides: OWASP Top 10 checklist, STRIDE threat matrix, injection patterns, SSRF vectors, tenant isolation rules, SLSA image compliance checklist. Loaded only when trigger conditions are present.

## Rules
- This gate cannot be skipped for any reason
- "I'll fix it after merge" is not acceptable — gate must pass before merge
- If bmad-security-reviewer is unavailable, block the merge and document why
- Approved verdict expires after 48 hours — re-run if diff changes after approval