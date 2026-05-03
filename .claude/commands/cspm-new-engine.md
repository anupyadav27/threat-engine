# /cspm-new-engine

Scaffold a new CSPM engine following platform conventions. Creates all required files.

## Usage
```
/cspm-new-engine <engine-name> <port>
```

Example:
```
/cspm-new-engine supply-chain 8042
```

## What gets created

1. **Engine directory** — `engines/<engine-name>/`
   - `api_server.py` — FastAPI app with health endpoints + RBAC middleware
   - `run_scan.py` — K8s Job entrypoint
   - `Dockerfile` — multi-stage build (build context = repo root)
   - `requirements.txt` — FastAPI, psycopg2, engine_common dependencies

2. **DB schema** — `shared/database/schemas/<engine-name>_schema.sql`
   - Standard 15 columns in findings table
   - tenants FK table
   - report table

3. **K8s manifest** — `deployment/aws/eks/engines/engine-<engine-name>.yaml`
   - Deployment + Service (ClusterIP port 80 → containerPort)
   - Health probes at `/api/v1/health/live` and `/api/v1/health/ready`
   - No `latest` tag
   - DB env vars from threat-engine-db-config configmap + threat-engine-db-passwords secret

4. **BFF view** — `shared/api_gateway/bff/<engine-name>.py`
   - Single call to `/api/v1/<engine-name>/ui-data`

5. **Agent file** — `.claude/agents/<engine-name>.md`
   - 8-section full-context template

## Mandatory patterns
- Standard 15 columns: finding_id, scan_run_id, tenant_id, account_id, credential_ref, credential_type, provider, region, resource_uid, resource_type, severity, status, first_seen_at, last_seen_at
- `require_permission("<engine>:read")` on all data endpoints
- `strip_sensitive_fields()` on responses
- Status always UPPERCASE (FAIL/PASS)
- JSONB never json.loads()
- Tenant FK: always upsert tenants before writing findings
