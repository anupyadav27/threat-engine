-- =============================================================================
-- DI-S1-01: engine-di initial schema
-- =============================================================================
-- Database:  threat_engine_di  (new — create manually first)
-- Purpose:   asset_inventory (partitioned), asset_relationships, di_scan_errors
--
-- Create DB first:
--   psql -h $RDS_HOST -U postgres -c "CREATE DATABASE threat_engine_di;"
--
-- Then apply this file:
--   psql -h $RDS_HOST -U postgres -d threat_engine_di \
--     -f di_001_initial_schema.sql
--
-- Safe to re-run: all DDL uses IF NOT EXISTS.
-- =============================================================================

-- ── 1. asset_inventory (partitioned by provider) ─────────────────────────────
CREATE TABLE IF NOT EXISTS asset_inventory (
    id                    UUID         NOT NULL DEFAULT gen_random_uuid(),
    scan_run_id           UUID         NOT NULL,
    tenant_id             VARCHAR(255) NOT NULL,
    account_id            VARCHAR(512) NOT NULL,
    provider              VARCHAR(50)  NOT NULL,
    region                VARCHAR(100) NOT NULL DEFAULT 'global',
    credential_ref        TEXT,
    credential_type       VARCHAR(100),

    -- Canonical resource identity — no synthetic fallbacks
    resource_uid          VARCHAR(2048) NOT NULL,
    resource_type         VARCHAR(255) NOT NULL,
    resource_name         VARCHAR(512),
    service               VARCHAR(100) NOT NULL,
    discovery_id          VARCHAR(255),

    -- Scan phase: 0=enumerated, 1=enriched
    phase                 SMALLINT     NOT NULL DEFAULT 0,

    -- Payload
    emitted_fields        JSONB        NOT NULL DEFAULT '{}',
    raw_response          JSONB        NOT NULL DEFAULT '{}',

    -- Drift detection
    config_hash           VARCHAR(64),
    previous_config_hash  VARCHAR(64),
    drift_detected        BOOLEAN      NOT NULL DEFAULT FALSE,

    -- Standard finding columns
    severity              VARCHAR(20)  NOT NULL DEFAULT 'informational',
    status                VARCHAR(50)  NOT NULL DEFAULT 'active',
    first_seen_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_seen_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT ak_asset_uid_scan_tenant UNIQUE (resource_uid, scan_run_id, tenant_id, provider)
) PARTITION BY LIST (provider);

-- ── Partitions ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS asset_inventory_aws
    PARTITION OF asset_inventory FOR VALUES IN ('aws');

CREATE TABLE IF NOT EXISTS asset_inventory_azure
    PARTITION OF asset_inventory FOR VALUES IN ('azure');

CREATE TABLE IF NOT EXISTS asset_inventory_gcp
    PARTITION OF asset_inventory FOR VALUES IN ('gcp');

CREATE TABLE IF NOT EXISTS asset_inventory_oci
    PARTITION OF asset_inventory FOR VALUES IN ('oci');

CREATE TABLE IF NOT EXISTS asset_inventory_ibm
    PARTITION OF asset_inventory FOR VALUES IN ('ibm');

CREATE TABLE IF NOT EXISTS asset_inventory_alicloud
    PARTITION OF asset_inventory FOR VALUES IN ('alicloud');

CREATE TABLE IF NOT EXISTS asset_inventory_k8s
    PARTITION OF asset_inventory FOR VALUES IN ('k8s');

-- Default partition for any future CSP
CREATE TABLE IF NOT EXISTS asset_inventory_default
    PARTITION OF asset_inventory DEFAULT;

-- ── Indexes ───────────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_ai_scan_tenant
    ON asset_inventory (scan_run_id, tenant_id);

CREATE INDEX IF NOT EXISTS idx_ai_tenant_uid
    ON asset_inventory (tenant_id, resource_uid);

CREATE INDEX IF NOT EXISTS idx_ai_scan_provider
    ON asset_inventory (scan_run_id, provider);

CREATE INDEX IF NOT EXISTS idx_ai_discovery_id
    ON asset_inventory (discovery_id) WHERE discovery_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_ai_service_region
    ON asset_inventory (service, region);

CREATE INDEX IF NOT EXISTS idx_ai_status
    ON asset_inventory (status) WHERE status != 'active';

CREATE INDEX IF NOT EXISTS idx_ai_emitted_fields
    ON asset_inventory USING GIN (emitted_fields);

-- ── 2. asset_relationships ───────────────────────────────────────────────────
-- Column names are identical to inventory_relationships for zero downstream changes.
CREATE TABLE IF NOT EXISTS asset_relationships (
    id                    UUID         NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    scan_run_id           UUID         NOT NULL,
    tenant_id             VARCHAR(255) NOT NULL,
    account_id            VARCHAR(512),
    provider              VARCHAR(50),

    source_uid            VARCHAR(2048) NOT NULL,
    source_type           VARCHAR(255),
    target_uid            VARCHAR(2048) NOT NULL,
    target_type           VARCHAR(255),

    relation_type         VARCHAR(100) NOT NULL,
    relation_metadata     JSONB        NOT NULL DEFAULT '{}',

    first_seen_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_seen_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ar_scan_tenant
    ON asset_relationships (scan_run_id, tenant_id);

CREATE INDEX IF NOT EXISTS idx_ar_source_uid
    ON asset_relationships (source_uid);

CREATE INDEX IF NOT EXISTS idx_ar_target_uid
    ON asset_relationships (target_uid);

CREATE INDEX IF NOT EXISTS idx_ar_relation_type
    ON asset_relationships (relation_type);

-- ── 3. di_scan_errors (error audit — not a fallback mechanism) ────────────────
CREATE TABLE IF NOT EXISTS di_scan_errors (
    id             BIGSERIAL    PRIMARY KEY,
    scan_run_id    UUID         NOT NULL,
    tenant_id      VARCHAR(255) NOT NULL,
    account_id     VARCHAR(512),
    provider       VARCHAR(50),
    service        VARCHAR(100),
    region         VARCHAR(100),
    resource_type  VARCHAR(255),
    error_type     VARCHAR(100) NOT NULL,  -- ResourceIdMissingError | AuthError | APIError
    error_message  TEXT,
    raw_item_keys  TEXT,                   -- comma-joined top-level keys for debugging
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dse_scan_run
    ON di_scan_errors (scan_run_id);

CREATE INDEX IF NOT EXISTS idx_dse_error_type
    ON di_scan_errors (error_type, created_at DESC);

-- ── 4. di_scan_status ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS di_scan_status (
    scan_run_id    UUID         PRIMARY KEY,
    tenant_id      VARCHAR(255) NOT NULL,
    account_id     VARCHAR(512),
    provider       VARCHAR(50),
    status         VARCHAR(50)  NOT NULL DEFAULT 'running',
    phase          SMALLINT     NOT NULL DEFAULT 0,
    resources_enumerated   INTEGER NOT NULL DEFAULT 0,
    resources_enriched     INTEGER NOT NULL DEFAULT 0,
    resources_written      INTEGER NOT NULL DEFAULT 0,
    relationships_written  INTEGER NOT NULL DEFAULT 0,
    error_count    INTEGER      NOT NULL DEFAULT 0,
    started_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    completed_at   TIMESTAMPTZ,
    updated_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

DO $$
BEGIN
    RAISE NOTICE 'DI-S1-01 schema applied: asset_inventory (partitioned), asset_relationships, di_scan_errors, di_scan_status';
END $$;
