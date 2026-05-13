-- Migration: add environment column to tenants table
-- Allows workspaces to be tagged as production/staging/development/test
-- Default: production (safe for existing rows)

ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS environment VARCHAR(20) NOT NULL DEFAULT 'production'
        CHECK (environment IN ('production', 'staging', 'development', 'test'));

COMMENT ON COLUMN tenants.environment IS 'Workspace environment label: production|staging|development|test';
