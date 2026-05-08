# Story: SECOPS-01 — DB Migrations: secops_report columns, secops_findings.account_id, secops_latest_scan table, cloud_accounts unique index

## Status: done

## Context

The SecOps engine currently stores scan results in `secops_report` and `secops_findings` without `account_id` or `scan_run_id` — both required for the new code-repo account flow. The BFF deduplicates scans in Python using `_latest_per_repo()`; this will be replaced by a purpose-built `secops_latest_scan` table that is upserted on scan completion, giving the BFF a single deterministic row per `(tenant_id, account_id, scan_type)`.

A partial UNIQUE index on `cloud_accounts(tenant_id, repo_url)` prevents duplicate code-repo accounts from being created, closing blocker B-6 at the DB layer.

Two separate migration files are required because the schema changes span two separate database contexts:
- Migration A: onboarding DB context (`cloud_accounts` table)
- Migration B: secops DB context (`secops_report`, `secops_findings`, `secops_latest_scan`)

This story has no code changes — it is DDL only. It must ship before SECOPS-02, SECOPS-03, SECOPS-04, and SECOPS-05.

## Security Framework Tags

**OWASP SAMM Function**
- [ ] Governance  [ ] Design  [x] Implementation  [ ] Verification  [ ] Operations

**NIST CSF 2.0 Function(s) this story covers**
- [ ] GV Govern  [ ] ID Identify  [x] PR Protect  [ ] DE Detect  [ ] RS Respond  [ ] RC Recover
PR.DS-1 (data-at-rest integrity via unique constraints), PR.DS-2 (data-in-transit schema compatibility), PR.AC-3 (account uniqueness enforced at DB layer)

**CSA CCM v4 Domain(s)**
- CCM: DSP-07 (Data Classification and Handling), IAM-02 (Identity Inventories), IVS-01 (Infrastructure Security)

## Threat Model

### STRIDE
| Threat | Component | Attack Scenario | Mitigation |
|--------|-----------|-----------------|------------|
| Spoofing | cloud_accounts | Attacker creates duplicate repo account under same tenant to intercept scan triggers | Partial UNIQUE index `(tenant_id, repo_url) WHERE account_type='code_security'` |
| Tampering | secops_report | Scan results written without tenant_id → cross-tenant data could appear in wrong tenant view | `tenant_id NOT NULL` enforced; `customer_id` backfilled to match `tenant_id` |
| Info Disclosure | secops_latest_scan | Missing `tenant_id` in `secops_latest_scan` queries exposes data across tenants | `tenant_id` is part of PRIMARY KEY; every query must include it |
| DoS | secops_latest_scan | Unbounded insert without PK could grow table to millions of stale rows | `PRIMARY KEY (tenant_id, account_id, scan_type)` limits table to one row per logical repo-scan-type pair |

### PASTA (credentials/IAM/network — N/A for pure DDL story)
N/A — this story is DDL only; no credential or network path changes.

## MITRE ATT&CK Techniques Addressed
| Technique ID | Name | D3FEND Countermeasure | How this story addresses it |
|-------------|------|----------------------|----------------------------|
| T1078.004 | Valid Accounts: Cloud Accounts | D3-UAP (User Account Provisioning) | Unique index prevents duplicate cloud_csp-equivalent repo accounts being injected under the same tenant |

## Acceptance Criteria (Functional)
- [ ] Migration A applies cleanly against the onboarding DB: `cloud_accounts` gains partial UNIQUE index `idx_cloud_accounts_tenant_repo_code_security` on `(tenant_id, repo_url) WHERE account_type = 'code_security'`
- [ ] Migration B applies cleanly against the secops DB:
  - `secops_report` gains `account_id VARCHAR(255)` (nullable, no default) and `scan_run_id VARCHAR(255)` (nullable, no default)
  - `secops_findings` gains `account_id VARCHAR(255)` (nullable, no default)
  - `secops_latest_scan` table is created with full schema (see Technical Notes)
  - Backfill: `UPDATE secops_report SET customer_id = tenant_id WHERE customer_id IS NULL`
- [ ] Both migrations are idempotent: running them twice does not error (use `IF NOT EXISTS` / `IF EXISTS` guards)
- [ ] After migration B, `secops_latest_scan` has primary key on `(tenant_id, account_id, scan_type)`
- [ ] Migration job logs end with `MIGRATION COMPLETE`

## Acceptance Criteria (Security — must pass bmad-security-reviewer)
- [ ] All new DB queries (in any follow-on code) will have tenant_id filter — enforced by PK structure of `secops_latest_scan`
- [ ] No plaintext credentials in migration SQL
- [ ] Unique index correctly scoped to `WHERE account_type = 'code_security'` (partial index — does not break existing cloud_csp uniqueness behavior)
- [ ] `customer_id` backfill does not overwrite rows where `customer_id` is already correctly set (WHERE clause guards it)
- [ ] New `secops_latest_scan` columns `tenant_id`, `account_id`, `scan_type` declared NOT NULL (composite PK enforces this)
- [ ] New `secops_latest_scan` has `first_seen_at DEFAULT NOW()` and `last_seen_at DEFAULT NOW()` — timestamps always populated

## Technical Notes

**Migration A filename**: `SECOPS-01A_cloud_accounts_repo_unique_idx.sql`
**Target DB**: onboarding DB (same DB as `cloud_accounts` table — accessed via onboarding engine pod)

```sql
-- Migration A
BEGIN;
CREATE UNIQUE INDEX IF NOT EXISTS idx_cloud_accounts_tenant_repo_code_security
    ON cloud_accounts (tenant_id, repo_url)
    WHERE account_type = 'code_security';
RAISE NOTICE 'MIGRATION COMPLETE';
COMMIT;
```

**Migration B filename**: `SECOPS-01B_secops_schema_v2.sql`
**Target DB**: secops DB (accessed via secops engine pod)

```sql
-- Migration B
BEGIN;

-- 1. Extend secops_report
ALTER TABLE secops_report
    ADD COLUMN IF NOT EXISTS account_id  VARCHAR(255),
    ADD COLUMN IF NOT EXISTS scan_run_id VARCHAR(255);

-- 2. Extend secops_findings
ALTER TABLE secops_findings
    ADD COLUMN IF NOT EXISTS account_id VARCHAR(255);

-- 3. Backfill customer_id = tenant_id where NULL
UPDATE secops_report
SET customer_id = tenant_id
WHERE customer_id IS NULL AND tenant_id IS NOT NULL;

-- 4. Create secops_latest_scan
CREATE TABLE IF NOT EXISTS secops_latest_scan (
    tenant_id           VARCHAR(255)    NOT NULL,
    account_id          VARCHAR(255)    NOT NULL,
    scan_type           VARCHAR(50)     NOT NULL,   -- 'sast' | 'dast'
    customer_id         VARCHAR(255),
    repo_url            TEXT,
    project_name        VARCHAR(512),
    default_branch      VARCHAR(255),
    secops_scan_id      VARCHAR(255),
    scan_run_id         VARCHAR(255),
    scan_timestamp      TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,
    status              VARCHAR(50),
    total_findings      INTEGER         DEFAULT 0,
    critical_count      INTEGER         DEFAULT 0,
    high_count          INTEGER         DEFAULT 0,
    medium_count        INTEGER         DEFAULT 0,
    low_count           INTEGER         DEFAULT 0,
    files_scanned       INTEGER         DEFAULT 0,
    languages_detected  JSONB           DEFAULT '[]'::jsonb,
    first_seen_at       TIMESTAMPTZ     DEFAULT NOW(),
    last_seen_at        TIMESTAMPTZ     DEFAULT NOW(),
    PRIMARY KEY (tenant_id, account_id, scan_type)
);

CREATE INDEX IF NOT EXISTS idx_secops_latest_scan_tenant
    ON secops_latest_scan (tenant_id);

RAISE NOTICE 'MIGRATION COMPLETE';
COMMIT;
```

**How to apply migrations** (both DBs accessed via kubectl exec on respective engine pods):

```bash
# Migration A — onboarding DB
kubectl cp /tmp/SECOPS-01A_cloud_accounts_repo_unique_idx.sql \
  threat-engine-engines/<onboarding-pod>:/tmp/mig_a.sql
kubectl exec -n threat-engine-engines <onboarding-pod> -- \
  psql -h $ONBOARDING_DB_HOST -U $ONBOARDING_DB_USER -d $ONBOARDING_DB_NAME \
  -f /tmp/mig_a.sql

# Migration B — secops DB
kubectl cp /tmp/SECOPS-01B_secops_schema_v2.sql \
  threat-engine-engines/<secops-pod>:/tmp/mig_b.sql
kubectl exec -n threat-engine-engines <secops-pod> -- \
  psql -h $SECOPS_DB_HOST -U $SECOPS_DB_USER -d $SECOPS_DB_NAME \
  -f /tmp/mig_b.sql
```

**No image build required for this story** — DDL only.

## Key Files
- `/Users/apple/Desktop/threat-engine/shared/database/migrations/SECOPS-01A_cloud_accounts_repo_unique_idx.sql` (create new)
- `/Users/apple/Desktop/threat-engine/shared/database/migrations/SECOPS-01B_secops_schema_v2.sql` (create new)

## Definition of Done
- [ ] Migration A and B SQL files committed to `shared/database/migrations/`
- [ ] Migration A applied; `\d cloud_accounts` shows the partial unique index
- [ ] Migration B applied; `\d secops_report` shows `account_id` and `scan_run_id` columns
- [ ] Migration B applied; `\d secops_latest_scan` shows correct schema with composite PK
- [ ] Migration B applied; `SELECT COUNT(*) FROM secops_report WHERE customer_id IS NULL` returns 0
- [ ] Both migration job logs end with "MIGRATION COMPLETE"
- [ ] bmad-security-reviewer: no BLOCKERS
- [ ] Memory updated at `/Users/apple/.claude/projects/-Users-apple-Desktop-threat-engine/memory/`