-- =============================================================================
-- Migration: cspm DB cleanup + org foundation
-- Date: 2026-05-03
-- Apply to: cspm PostgreSQL DB  (run inside cspm-backend pod)
--
-- Apply command:
--   POD=$(kubectl get pods -n threat-engine-engines -l app=cspm-backend \
--         -o jsonpath='{.items[0].metadata.name}')
--   kubectl cp shared/database/migrations/20260503_cspm_cleanup_and_org_foundation.sql \
--     threat-engine-engines/$POD:/tmp/migration.sql
--   kubectl exec -n threat-engine-engines $POD -- python3 -c "
--     import django, os, sys
--     os.environ['DJANGO_SETTINGS_MODULE'] = 'config.settings'
--     sys.path.insert(0, '/app')
--     django.setup()
--     from django.db import connection
--     sql = open('/tmp/migration.sql').read()
--     with connection.cursor() as c:
--         c.execute(sql)
--     print('Migration complete')
--   "
--
-- Actual table names (verified 2026-05-03):
--   tenants, users, roles, permissions, role_permissions,
--   tenant_users, user_account_access, user_admin_scope,
--   user_invitations, invite_tokens, user_sessions
-- =============================================================================

BEGIN;

-- =============================================================================
-- STEP 1: Drop dead tables (verified 0 rows each)
-- =============================================================================

-- Old onboarding tables (replaced by threat_engine_onboarding DB)
DROP TABLE IF EXISTS onboarding_executions CASCADE;
DROP TABLE IF EXISTS onboarding_scan_results CASCADE;
DROP TABLE IF EXISTS onboarding_schedules CASCADE;
DROP TABLE IF EXISTS onboarding_accounts CASCADE;
DROP TABLE IF EXISTS onboarding_tenants CASCADE;
DROP TABLE IF EXISTS onboarding_providers CASCADE;

-- Old asset/finding tables (replaced by inventory/check/threat engine DBs)
DROP TABLE IF EXISTS scan_findings_assets CASCADE;
DROP TABLE IF EXISTS scan_findings CASCADE;
DROP TABLE IF EXISTS scan_results CASCADE;
DROP TABLE IF EXISTS asset_compliance CASCADE;
DROP TABLE IF EXISTS asset_tags CASCADE;
DROP TABLE IF EXISTS asset_threats CASCADE;
DROP TABLE IF EXISTS assets CASCADE;

-- Old threat tables (replaced by threat engine DB)
DROP TABLE IF EXISTS threat_remediation_steps CASCADE;
DROP TABLE IF EXISTS threat_related_findings CASCADE;
DROP TABLE IF EXISTS threats CASCADE;

-- Old compliance table (replaced by compliance engine DB)
DROP TABLE IF EXISTS compliance_summary CASCADE;

-- Old agent table (replaced by agent_registrations in onboarding DB)
DROP TABLE IF EXISTS agents CASCADE;

-- Organizations table (NOT needed — customer_id = user.id is the org key)
-- Dropping this also removes the FK constraint from tenants.organization_id
DROP TABLE IF EXISTS organizations CASCADE;

-- Duplicate Django auth tables (using custom RBAC: roles/permissions tables)
DROP TABLE IF EXISTS auth_group_permissions CASCADE;
DROP TABLE IF EXISTS auth_group CASCADE;
DROP TABLE IF EXISTS users_groups CASCADE;
DROP TABLE IF EXISTS users_user_permissions CASCADE;

-- NOTE: NOT dropping the following (still active):
--   oauth_providers  — has 2 live rows (Google + Microsoft OAuth config)
--   user_roles       — has 4 rows, actively used by build_tenant_query
--   invite_tokens    — Django model InviteTokens still references this table

-- =============================================================================
-- STEP 2: Drop organization_id column from tenants (FK removed by DROP TABLE above)
-- =============================================================================

ALTER TABLE tenants DROP COLUMN IF EXISTS organization_id;

-- =============================================================================
-- STEP 3: Fix roles — remove legacy roles (level=99), fix yadav.anup user role
-- =============================================================================

-- Remove legacy role permissions first (FK constraint)
DELETE FROM role_permissions
WHERE role_id IN (
    SELECT id FROM roles WHERE name IN ('landlord', 'super_landlord', 'tenant', 'customer_admin')
);

-- Remove legacy roles from tenant_users (user 95f45833 has customer_admin in tenant_users)
DELETE FROM tenant_users
WHERE role_id IN (
    SELECT id FROM roles WHERE name IN ('landlord', 'super_landlord', 'tenant', 'customer_admin')
);

-- Remove legacy roles from user_roles (user 9b620ea9 has super_landlord)
DELETE FROM user_roles
WHERE role_id IN (
    SELECT id FROM roles WHERE name IN ('landlord', 'super_landlord', 'tenant', 'customer_admin')
);

-- Remove legacy roles from user_admin_scope
DELETE FROM user_admin_scope
WHERE role_id IN (
    SELECT id FROM roles WHERE name IN ('landlord', 'super_landlord', 'tenant', 'customer_admin')
);

-- Delete the legacy roles
DELETE FROM roles
WHERE name IN ('landlord', 'super_landlord', 'tenant', 'customer_admin');

-- Fix yadav.anup@gmail.com: assign org_admin role in tenant_users
-- (Only runs if the user exists — idempotent)
UPDATE tenant_users
SET role_id = (SELECT id FROM roles WHERE name = 'org_admin' LIMIT 1)
WHERE user_id = (SELECT id FROM users WHERE email = 'yadav.anup@gmail.com')
  AND role_id IN (
    SELECT id FROM roles WHERE name IN ('customer_admin', 'platform_admin')
  );

-- Fix user_admin_scope: scope_type='customer' → 'organization'
-- and fix scope_id to be the user's own id (not the tenant id)
-- The existing row has scope_id = a tenant_id which is wrong (should be user_id = customer_id)
UPDATE user_admin_scope
SET scope_type = 'organization',
    scope_id    = user_id   -- customer_id = str(user.id) for founding user
WHERE scope_type = 'customer';

-- =============================================================================
-- STEP 4: Seed new permissions (groups + orgs) — use WHERE NOT EXISTS (no UNIQUE on key)
-- =============================================================================

INSERT INTO permissions (id, key, feature, action, description, tenant_scoped, created_at, updated_at)
SELECT gen_random_uuid()::text, 'groups:read', 'groups', 'read', 'View user groups', false, NOW(), NOW()
WHERE NOT EXISTS (SELECT 1 FROM permissions WHERE key = 'groups:read');

INSERT INTO permissions (id, key, feature, action, description, tenant_scoped, created_at, updated_at)
SELECT gen_random_uuid()::text, 'groups:write', 'groups', 'write', 'Create and manage groups', false, NOW(), NOW()
WHERE NOT EXISTS (SELECT 1 FROM permissions WHERE key = 'groups:write');

INSERT INTO permissions (id, key, feature, action, description, tenant_scoped, created_at, updated_at)
SELECT gen_random_uuid()::text, 'orgs:read', 'orgs', 'read', 'View organization info', false, NOW(), NOW()
WHERE NOT EXISTS (SELECT 1 FROM permissions WHERE key = 'orgs:read');

INSERT INTO permissions (id, key, feature, action, description, tenant_scoped, created_at, updated_at)
SELECT gen_random_uuid()::text, 'orgs:write', 'orgs', 'write', 'Manage organization', false, NOW(), NOW()
WHERE NOT EXISTS (SELECT 1 FROM permissions WHERE key = 'orgs:write');

-- Assign orgs:read and groups:read to platform_admin, org_admin, tenant_admin
INSERT INTO role_permissions (id, role_id, permission_id, created_at, updated_at)
SELECT gen_random_uuid()::text, r.id, p.id, NOW(), NOW()
FROM roles r
CROSS JOIN permissions p
WHERE r.name IN ('platform_admin', 'org_admin', 'tenant_admin')
  AND p.key IN ('orgs:read', 'groups:read')
  AND NOT EXISTS (
      SELECT 1 FROM role_permissions rp
      WHERE rp.role_id = r.id AND rp.permission_id = p.id
  );

-- Assign orgs:write and groups:write to platform_admin only
-- (org_admin gets orgs:write AFTER B-4 boundary enforcement is validated in prod)
INSERT INTO role_permissions (id, role_id, permission_id, created_at, updated_at)
SELECT gen_random_uuid()::text, r.id, p.id, NOW(), NOW()
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'platform_admin'
  AND p.key IN ('orgs:write', 'groups:write')
  AND NOT EXISTS (
      SELECT 1 FROM role_permissions rp
      WHERE rp.role_id = r.id AND rp.permission_id = p.id
  );

-- =============================================================================
-- STEP 5: Schema additions to existing tables
-- =============================================================================

-- 5a. Add tenant_type to tenants (default 'cloud' for all existing tenants)
ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS tenant_type VARCHAR(50) NOT NULL DEFAULT 'cloud';

CREATE INDEX IF NOT EXISTS idx_tenants_tenant_type ON tenants (tenant_type);

-- 5b. Add customer_id to tenants (the org key — populated from founding user's user.id)
ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS customer_id VARCHAR(255) NULL;

CREATE INDEX IF NOT EXISTS idx_tenants_customer_id ON tenants (customer_id);

-- 5c. Add customer_id to users (set at signup = str(user.id) for founding user)
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS customer_id VARCHAR(255) NULL;

CREATE INDEX IF NOT EXISTS idx_users_customer_id ON users (customer_id);

-- 5d. Add role_id FK to user_account_access (grants had no role — needed for group-based RBAC)
ALTER TABLE user_account_access
    ADD COLUMN IF NOT EXISTS role_id VARCHAR(255) NULL
    REFERENCES roles(id) ON DELETE SET NULL;

-- =============================================================================
-- STEP 6: Create new group tables
-- =============================================================================

CREATE TABLE IF NOT EXISTS csm_groups (
    id          VARCHAR(255) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    customer_id VARCHAR(255) NOT NULL,
    name        VARCHAR(255) NOT NULL,
    description TEXT,
    created_by_id  VARCHAR(255) REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (customer_id, name)
);

CREATE INDEX IF NOT EXISTS idx_csm_groups_customer_id ON csm_groups (customer_id);

CREATE TABLE IF NOT EXISTS group_members (
    id         VARCHAR(255) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    group_id   VARCHAR(255) NOT NULL REFERENCES csm_groups(id) ON DELETE CASCADE,
    user_id    VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    added_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (group_id, user_id)
);

CREATE TABLE IF NOT EXISTS tenant_group_access (
    id         VARCHAR(255) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    group_id   VARCHAR(255) NOT NULL REFERENCES csm_groups(id) ON DELETE CASCADE,
    tenant_id  VARCHAR(255) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    role_id    VARCHAR(255) NOT NULL REFERENCES roles(id),
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (group_id, tenant_id)
);

CREATE TABLE IF NOT EXISTS account_group_access (
    id         VARCHAR(255) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    group_id   VARCHAR(255) NOT NULL REFERENCES csm_groups(id) ON DELETE CASCADE,
    tenant_id  VARCHAR(255) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    account_id VARCHAR(512) NOT NULL,
    role_id    VARCHAR(255) NOT NULL REFERENCES roles(id),
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (group_id, tenant_id, account_id)
);

-- =============================================================================
-- STEP 7: Backfill customer_id on existing users and tenants
-- =============================================================================

-- Every existing user is treated as a founding user (customer_id = their own user.id)
-- This is correct for the existing users — they all onboarded independently
UPDATE users
SET customer_id = id
WHERE customer_id IS NULL;

-- Backfill tenants.customer_id from the first org_admin/platform_admin user in tenant_users
UPDATE tenants t
SET customer_id = (
    SELECT u.customer_id
    FROM tenant_users tu
    JOIN users u ON u.id = tu.user_id
    JOIN roles r ON r.id = tu.role_id
    WHERE tu.tenant_id = t.id
      AND r.name IN ('org_admin', 'platform_admin', 'tenant_admin')
    ORDER BY tu.created_at ASC
    LIMIT 1
)
WHERE t.customer_id IS NULL;

-- Remaining tenants with no matching user: set customer_id = tenant.id as safe default
UPDATE tenants
SET customer_id = id
WHERE customer_id IS NULL;

-- =============================================================================
-- STEP 8: (DEFERRED — run after backfill verified) Make customer_id NOT NULL
-- =============================================================================
-- Run this as a separate migration AFTER verifying all rows are backfilled:
--
-- ALTER TABLE users ALTER COLUMN customer_id SET NOT NULL;
-- ALTER TABLE tenants ALTER COLUMN customer_id SET NOT NULL;

COMMIT;

-- =============================================================================
-- POST-MIGRATION VERIFICATION QUERIES
-- Run these after migration to confirm correct state:
-- =============================================================================
--
-- 1. Dead tables gone:
--    SELECT table_name FROM information_schema.tables
--    WHERE table_schema='public'
--    AND table_name IN ('organizations','onboarding_tenants','assets','agents')
--    ORDER BY table_name;
--    → should return 0 rows
--
-- 2. Legacy roles gone:
--    SELECT name FROM roles
--    WHERE name IN ('landlord','super_landlord','tenant','customer_admin');
--    → should return 0 rows
--
-- 3. organization_id column gone from tenants:
--    SELECT column_name FROM information_schema.columns
--    WHERE table_name='tenants' AND column_name='organization_id';
--    → should return 0 rows
--
-- 4. New columns exist on tenants:
--    SELECT column_name FROM information_schema.columns
--    WHERE table_name='tenants' AND column_name IN ('tenant_type','customer_id');
--    → should return 2 rows
--
-- 5. customer_id backfilled:
--    SELECT COUNT(*) FROM users WHERE customer_id IS NULL;
--    → should return 0
--
-- 6. Group tables created:
--    SELECT table_name FROM information_schema.tables
--    WHERE table_name IN ('csm_groups','group_members','tenant_group_access','account_group_access');
--    → should return 4 rows
--
-- 7. New permissions seeded:
--    SELECT key FROM permissions WHERE key IN ('groups:read','groups:write','orgs:read','orgs:write');
--    → should return 4 rows
--
-- 8. user_admin_scope scope_type fixed:
--    SELECT COUNT(*) FROM user_admin_scope WHERE scope_type = 'customer';
--    → should return 0
