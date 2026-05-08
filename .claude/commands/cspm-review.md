# /cspm-review

Run a full CSPM platform code review on the current branch diff. Checks constitution compliance, security, and quality gates.

## What it checks

### 1. Constitution compliance
- [ ] Multi-tenancy: every DB query scoped by `tenant_id`
- [ ] BFF for charts only — no raw findings in BFF views
- [ ] No BFF fallback/mock data
- [ ] No `DEV_BYPASS_AUTH`
- [ ] No `latest` image tag in any K8s manifest
- [ ] Standard 15 columns in any new findings table
- [ ] JSONB not passed through `json.loads()`
- [ ] `status` always UPPERCASE in check/compliance engines

### 2. Security review (trigger bmad-security-reviewer if any of these changed)
- [ ] New endpoint or changed auth logic
- [ ] New DB query or schema change
- [ ] HTTP calls (SSRF risk)
- [ ] Credential handling code

### 3. RBAC review
- [ ] `require_permission()` on every new endpoint
- [ ] `strip_sensitive_fields()` removes `credential_ref`
- [ ] Viewer role tested for 403 on sensitive engines

### 4. Quality gates
- [ ] Health endpoints work: `/api/v1/health/live` + `/api/v1/health/ready`
- [ ] K8s manifest has liveness + readiness probes
- [ ] No hardcoded credentials or secrets
- [ ] JSONB columns are already dicts (no json.loads)

## Binding rule
If any new endpoint, auth logic, DB schema, or HTTP call is in the diff:
→ Invoke `bmad-security-reviewer` for full security code review before merge.
