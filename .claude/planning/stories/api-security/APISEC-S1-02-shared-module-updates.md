# Story APISEC-S1-02: Shared Module Updates — db_connections + security_findings_writer + RBAC

## Status: done

## Metadata
- **Sprint**: APISEC Sprint 1
- **Points**: 3
- **Priority**: P0 — blocks engine scaffold and security_findings write
- **Depends on**: APISEC-S1-01
- **Blocks**: APISEC-S1-03, APISEC-S1-12
- **Security Gate**: bmad-security-reviewer

## Changes Required

### 1. `shared/common/db_connections.py`

Add after existing engine connection functions (follow exact `get_cdr_conn()` pattern):

```python
def get_api_security_conn() -> psycopg2.extensions.connection:
    """Return a connection to threat_engine_api_security DB."""
    return _make_conn(
        prefix="API_SECURITY",
        default_db="threat_engine_api_security"
    )
```

Env vars consumed (already available via `threat-engine-db-config` ConfigMap):
- `API_SECURITY_DB_HOST` → falls back to `DB_HOST`
- `API_SECURITY_DB_NAME` = `threat_engine_api_security`
- `API_SECURITY_DB_USER` / `API_SECURITY_DB_PASSWORD` → fall back to `DB_USER` / `DB_PASSWORD`

### 2. `shared/common/security_findings_writer.py`

Add `'api_security'` to `_ALLOWED_ENGINES`:

```python
# Before
_ALLOWED_ENGINES = frozenset({'check', 'iam', 'network', 'datasec', 'vuln', 'cdr'})

# After
_ALLOWED_ENGINES = frozenset({'check', 'iam', 'network', 'datasec', 'vuln', 'cdr', 'api_security'})
```

No other changes — `upsert_findings()` already handles any engine in the frozenset.

### 3. Django migration `0019_api_security_permissions.py`

Path: `platform/cspm-backend/user_auth/migrations/0019_api_security_permissions.py`

```python
from django.db import migrations

class Migration(migrations.Migration):
    dependencies = [('user_auth', '0018_attack_path_permissions')]

    operations = [
        migrations.RunSQL("""
            INSERT INTO user_auth_permission (name, codename, content_type_id)
            VALUES
                ('Can read API security findings', 'api_security:read',
                 (SELECT id FROM django_content_type
                  WHERE app_label='user_auth' AND model='permission')),
                ('Can write API security config', 'api_security:write',
                 (SELECT id FROM django_content_type
                  WHERE app_label='user_auth' AND model='permission'))
            ON CONFLICT (codename) DO NOTHING;

            -- api_security:read → all 5 roles
            INSERT INTO user_auth_role_permissions (role_id, permission_id)
            SELECT r.id, p.id
            FROM user_auth_role r
            CROSS JOIN user_auth_permission p
            WHERE p.codename = 'api_security:read'
              AND r.name IN ('platform_admin','org_admin','tenant_admin','analyst','viewer')
            ON CONFLICT DO NOTHING;

            -- api_security:write → org_admin + platform_admin only
            INSERT INTO user_auth_role_permissions (role_id, permission_id)
            SELECT r.id, p.id
            FROM user_auth_role r
            CROSS JOIN user_auth_permission p
            WHERE p.codename = 'api_security:write'
              AND r.name IN ('platform_admin','org_admin')
            ON CONFLICT DO NOTHING;
        """)
    ]
```

### 4. `shared/api_gateway/main.py`

```python
API_SECURITY_ENGINE_URL = os.getenv(
    "API_SECURITY_ENGINE_URL",
    "http://engine-api-security.threat-engine-engines.svc.cluster.local"
)
```

### 5. `deployment/aws/eks/api-gateway.yaml`

Add to gateway Deployment env section — use `kubectl set image` pattern (VSCode YAML linter silently reverts tag edits):

```yaml
- name: API_SECURITY_ENGINE_URL
  value: "http://engine-api-security.threat-engine-engines.svc.cluster.local"
```

## Acceptance Criteria

- [ ] AC-1: `get_api_security_conn()` imported and called in engine container returns live connection to `threat_engine_api_security`
- [ ] AC-2: `upsert_findings(source_engine='api_security', ...)` does not raise ValueError
- [ ] AC-3: Django migration 0019 applies — `SELECT codename FROM user_auth_permission WHERE codename LIKE 'api_security%'` returns 2 rows
- [ ] AC-4: `viewer` role has `api_security:read`; does NOT have `api_security:write`
- [ ] AC-5: Gateway pod env confirms `API_SECURITY_ENGINE_URL` set — `kubectl exec -n threat-engine-engines deploy/threat-engine-api-gateway -- env | grep API_SECURITY`

## Definition of Done
- [ ] `db_connections.py` + `security_findings_writer.py` committed
- [ ] Django migration 0019 applied to platform DB
- [ ] Gateway deployment updated (API_SECURITY_ENGINE_URL present in running pod)
- [ ] cspm-backend + gateway images rebuilt and deployed
