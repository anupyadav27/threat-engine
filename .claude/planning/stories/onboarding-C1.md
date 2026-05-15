---
id: onboarding-C1
title: "Apply account_type + agent_registrations migration"
sprint: C
points: 1
status: done
depends_on: []
blocks: [onboarding-C2, onboarding-C4, onboarding-C5, onboarding-C8, onboarding-C10]
security_blocks: []
nist_csf: PR.DS
owasp_samm: Design
csa_ccm: IAM-14
---

## Context

The onboarding engine's `cloud_accounts` table is missing several lifecycle columns needed for credential expiry tracking and agent registration. Currently there is no `account_type` discriminator (all accounts are treated as cloud CSP accounts), no `expires_at` or `last_rotated_at` for credential expiry tracking, and no `validation_status` column queryable by the Celery expiry task. The `agent_registrations` table does not exist at all — blocking agent PKCE flows. The `schedules` table is missing `include_regions`, `exclude_regions`, `include_services`, `exclude_services` columns. This migration (onboarding-001) adds all these columns additively. The onboarding engine's PostgreSQL DB is `threat_engine_onboarding` — access via `kubectl exec` on the onboarding pod.

## Acceptance Criteria

- [ ] AC1: Migration file `engines/onboarding/database/migrations/onboarding-001-account-type.sql` exists and is idempotent (`IF NOT EXISTS` / `IF NOT EXISTS` guards on all DDL).
- [ ] AC2: `cloud_accounts` has `account_type VARCHAR(50) NOT NULL DEFAULT 'cloud_csp'`.
- [ ] AC3: `cloud_accounts` has `expires_at TIMESTAMPTZ` (nullable).
- [ ] AC4: `cloud_accounts` has `last_rotated_at TIMESTAMPTZ` (nullable).
- [ ] AC5: `cloud_accounts` has `validation_status VARCHAR(20) NOT NULL DEFAULT 'pending'`.
- [ ] AC6: `cloud_accounts` has `validated_at TIMESTAMPTZ` (nullable).
- [ ] AC7: `cloud_accounts` has `rotation_enabled BOOLEAN NOT NULL DEFAULT FALSE`.
- [ ] AC8: `agent_registrations` table exists with all columns from architecture §4.1.2 (id, account_id FK, tenant_id, agent_token_hash, status, last_heartbeat, registered_at, connected_at, agent_version, agent_host, created_at, updated_at).
- [ ] AC9: Indexes on `agent_registrations(account_id)`, `(tenant_id)`, `(status)` exist.
- [ ] AC10: `schedules` table has `include_regions TEXT[]`, `exclude_regions TEXT[]`, `include_services TEXT[]`, `exclude_services TEXT[]` columns.
- [ ] AC11: After migration, `\d cloud_accounts` in psql shows all new columns.
- [ ] AC12: Existing cloud_accounts rows are unaffected — migration is purely additive.

## Key Files

- `engines/onboarding/database/migrations/onboarding-001-account-type.sql` — Create this migration file
- `engines/onboarding/database/models.py` — Update `CloudAccount` model class to include new fields
- `engines/onboarding/models/account.py` OR `engines/onboarding/models/credential.py` — If separate model files exist, update there

## Technical Notes

**Full migration DDL:**
```sql
-- onboarding-001-account-type.sql
-- Additive migration for cloud_accounts lifecycle columns

-- account_type columns
ALTER TABLE cloud_accounts
  ADD COLUMN IF NOT EXISTS account_type        VARCHAR(50)  NOT NULL DEFAULT 'cloud_csp',
  ADD COLUMN IF NOT EXISTS expires_at          TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS last_rotated_at     TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS validation_status   VARCHAR(20)  NOT NULL DEFAULT 'pending',
  ADD COLUMN IF NOT EXISTS validated_at        TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS rotation_enabled    BOOLEAN      NOT NULL DEFAULT FALSE;

-- agent_registrations table
CREATE TABLE IF NOT EXISTS agent_registrations (
  id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id       UUID         NOT NULL REFERENCES cloud_accounts(account_id) ON DELETE CASCADE,
  tenant_id        VARCHAR(255) NOT NULL,
  agent_token_hash VARCHAR(64)  NOT NULL UNIQUE,
  status           VARCHAR(20)  NOT NULL DEFAULT 'pending',
  last_heartbeat   TIMESTAMPTZ,
  registered_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  connected_at     TIMESTAMPTZ,
  agent_version    VARCHAR(50),
  agent_host       VARCHAR(255),
  created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  updated_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agent_reg_account ON agent_registrations(account_id);
CREATE INDEX IF NOT EXISTS idx_agent_reg_tenant  ON agent_registrations(tenant_id);
CREATE INDEX IF NOT EXISTS idx_agent_reg_status  ON agent_registrations(status);

-- schedules region/service scope
ALTER TABLE schedules
  ADD COLUMN IF NOT EXISTS include_regions  TEXT[],
  ADD COLUMN IF NOT EXISTS exclude_regions  TEXT[],
  ADD COLUMN IF NOT EXISTS include_services TEXT[],
  ADD COLUMN IF NOT EXISTS exclude_services TEXT[];

SELECT 'MIGRATION onboarding-001 COMPLETE';
```

**Apply migration via kubectl:**
```bash
# Copy SQL to pod
kubectl cp /Users/apple/Desktop/threat-engine/engines/onboarding/database/migrations/onboarding-001-account-type.sql \
  threat-engine-engines/<onboarding-pod>:/tmp/onboarding-001.sql

# Apply
kubectl exec -n threat-engine-engines <onboarding-pod> -- \
  psql -h $ONBOARDING_DB_HOST -U $ONBOARDING_DB_USER -d $ONBOARDING_DB_NAME \
  -f /tmp/onboarding-001.sql

# Verify
kubectl exec -n threat-engine-engines <onboarding-pod> -- \
  psql -h $ONBOARDING_DB_HOST -U $ONBOARDING_DB_USER -d $ONBOARDING_DB_NAME \
  -c "\d cloud_accounts" | grep -E "account_type|expires_at|validation_status"
```

**account_type valid values:** `'cloud_csp'` | `'vulnerability'` | `'secops'`

**validation_status valid values:** `'pending'` | `'pass'` | `'fail'`

**CRITICAL: JSONB note** — `include_regions` and `exclude_regions` are `TEXT[]` (Postgres arrays), not JSONB. Read them directly as Python lists from psycopg2 — never call `json.loads()` on them.

## Security Checklist

- [ ] `require_permission()` N/A — migration only, no endpoints
- [ ] `tenant_id` column added to `agent_registrations` for multi-tenant isolation
- [ ] `agent_token_hash` stores SHA-256 hash only — raw token never in DB
- [ ] No hardcoded secrets
- [ ] bmad-security-reviewer gate passed before merge

## Definition of Done

- [ ] All ACs pass
- [ ] Migration log shows "MIGRATION onboarding-001 COMPLETE"
- [ ] `\d cloud_accounts` confirms all 6 new columns
- [ ] `\d agent_registrations` confirms table and 3 indexes exist
- [ ] `\d schedules` confirms 4 new TEXT[] columns
- [ ] No existing API functionality broken (regression check: existing cloud_accounts reads still work)
- [ ] bmad-security-reviewer: no BLOCKERs