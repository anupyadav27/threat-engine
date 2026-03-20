-- =============================================================================
-- Migration 018: Add account_hierarchy table
-- =============================================================================
-- Database:  threat_engine_onboarding
-- Purpose:   Store AWS Organizations / Azure Management Groups / GCP Org
--            hierarchy for architecture diagram rendering.
--
-- Supports:
--   AWS:   organization → root → OU → OU → account
--   Azure: tenant → management-group → subscription
--   GCP:   organization → folder → folder → project
--   OCI:   tenancy → compartment → compartment
--   AliCloud: resource-directory → folder → account
--   IBM:   enterprise → account-group → account
--
-- Apply with:
--   psql -h <RDS_HOST> -U postgres -d threat_engine_onboarding \
--     -f 018_add_account_hierarchy.sql
--
-- Safe to re-run: all DDL uses IF NOT EXISTS.
-- =============================================================================

CREATE TABLE IF NOT EXISTS account_hierarchy (
    id              BIGSERIAL PRIMARY KEY,

    -- Tenant isolation
    tenant_id       VARCHAR(255) NOT NULL,
    customer_id     VARCHAR(255),

    -- Node identity
    node_id         VARCHAR(255) NOT NULL,     -- org ID, OU ID, account ID, etc.
    node_name       VARCHAR(255),              -- human-readable name
    node_type       VARCHAR(50) NOT NULL,      -- see enum below

    -- Hierarchy
    parent_node_id  VARCHAR(255),              -- null = root node
    hierarchy_path  TEXT,                       -- materialized path: /root-id/ou-prod/account-123
    depth           SMALLINT DEFAULT 0,        -- 0 = root, 1 = first child, etc.

    -- Cloud context
    provider        VARCHAR(20) NOT NULL,      -- aws | azure | gcp | oci | alicloud | ibm
    provider_org_id VARCHAR(255),              -- AWS org ID, Azure tenant ID, GCP org ID

    -- Status & metadata
    status          VARCHAR(20) DEFAULT 'active',  -- active | suspended | closed
    metadata        JSONB DEFAULT '{}',             -- provider-specific extras
    -- AWS: { "email": "...", "joined_method": "CREATED", "joined_timestamp": "..." }
    -- Azure: { "subscription_state": "Enabled", "offer_type": "..." }
    -- GCP: { "lifecycle_state": "ACTIVE", "create_time": "..." }

    -- Housekeeping
    discovered_at   TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    -- Constraints
    CONSTRAINT ah_unique_node UNIQUE (tenant_id, provider, node_id)
);

-- node_type enum reference (not enforced as PG enum for flexibility):
--   AWS:      organization | root | organizational_unit | account
--   Azure:    tenant | management_group | subscription | resource_group
--   GCP:      organization | folder | project
--   OCI:      tenancy | compartment
--   AliCloud: resource_directory | folder | account
--   IBM:      enterprise | account_group | account
--   K8s:      cluster | namespace

-- ── Indexes ──────────────────────────────────────────────────────────────────

-- Parent lookup: "all children of OU X"
CREATE INDEX IF NOT EXISTS idx_ah_tenant_parent
  ON account_hierarchy(tenant_id, parent_node_id);

-- Provider filter: "all AWS nodes for tenant"
CREATE INDEX IF NOT EXISTS idx_ah_tenant_provider
  ON account_hierarchy(tenant_id, provider);

-- Type filter: "all accounts for tenant"
CREATE INDEX IF NOT EXISTS idx_ah_tenant_type
  ON account_hierarchy(tenant_id, node_type);

-- Path-based subtree: "everything under /root-123/ou-prod"
CREATE INDEX IF NOT EXISTS idx_ah_hierarchy_path
  ON account_hierarchy USING btree (hierarchy_path text_pattern_ops);

-- Depth filter: "all root nodes"
CREATE INDEX IF NOT EXISTS idx_ah_depth
  ON account_hierarchy(depth);

-- ── Trigger ──────────────────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION update_ah_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS update_ah_updated_at ON account_hierarchy;
CREATE TRIGGER update_ah_updated_at
    BEFORE UPDATE ON account_hierarchy
    FOR EACH ROW EXECUTE FUNCTION update_ah_updated_at_column();

-- ── Comments ─────────────────────────────────────────────────────────────────

COMMENT ON TABLE account_hierarchy IS
  'Multi-cloud organization hierarchy for architecture diagram rendering. '
  'Stores parent-child relationships: org → OU/folder → account/project. '
  'Populated by discovery engine from AWS Organizations / Azure Management Groups / GCP Resource Manager.';

COMMENT ON COLUMN account_hierarchy.hierarchy_path IS
  'Materialized path for efficient subtree queries: /org-id/ou-prod/account-123. '
  'Enables LIKE-based queries without recursive CTEs.';

COMMENT ON COLUMN account_hierarchy.depth IS
  'Nesting depth: 0=root, 1=first-level child. Used for diagram indentation.';
