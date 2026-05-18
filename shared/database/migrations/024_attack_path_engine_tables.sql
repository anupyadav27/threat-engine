-- =============================================================================
-- Migration 024: Attack Path Engine Tables
-- Target DB: threat_engine_attack_path
-- =============================================================================
-- Tables:
--   attack_paths           — deduplicated, scored attack paths
--   attack_path_nodes      — per-hop evidence (IAM policy, SG rules, CVEs)
--   attack_path_history    — immutable score history per path per scan
--   crown_jewel_overrides  — manual analyst crown-jewel classification overrides
-- =============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
-- Table: attack_paths
-- Primary store for one row per unique path (keyed by sha256 of node_uids).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS attack_paths (
    -- Primary key: sha256("|".join(node_uids))
    path_id                 VARCHAR(64)     NOT NULL,

    -- Standard pipeline columns
    scan_run_id             UUID            NOT NULL,
    tenant_id               VARCHAR(255)    NOT NULL,
    account_id              VARCHAR(255),
    provider                VARCHAR(50),

    -- Path composition (JSONB — psycopg2 auto-deserializes; never call json.loads())
    node_uids               JSONB           NOT NULL DEFAULT '[]',
    node_types              JSONB           NOT NULL DEFAULT '[]',
    edge_types              JSONB           NOT NULL DEFAULT '[]',
    hop_categories          JSONB           NOT NULL DEFAULT '[]',

    -- Topology summary
    depth                   INTEGER         NOT NULL DEFAULT 0,
    entry_point_uid         VARCHAR(512),
    entry_point_type        VARCHAR(50),    -- internet | vpn | onprem | peer_account | vendor | k8s_external
    crown_jewel_uid         VARCHAR(512),
    crown_jewel_type        VARCHAR(50),    -- data | secrets | identity | infra_control | ai_model | code | data_warehouse | encryption_control
    chain_type              VARCHAR(100),   -- human-readable: "Internet → Data"
    data_classification     VARCHAR(50),    -- pii | financial | credentials | internal | public

    -- Scoring
    path_score              INTEGER         NOT NULL DEFAULT 0,   -- 0–100
    probability_score       NUMERIC(5,4)    NOT NULL DEFAULT 0,   -- 0.0000–1.0000
    impact_score            NUMERIC(5,4)    NOT NULL DEFAULT 0,   -- 0.0000–1.0000+
    severity                VARCHAR(20)     NOT NULL DEFAULT 'low',  -- critical|high|medium|low

    -- Path metadata
    max_epss                NUMERIC(5,4),
    misconfig_count         INTEGER         NOT NULL DEFAULT 0,
    threat_count            INTEGER         NOT NULL DEFAULT 0,
    top_cves                JSONB           NOT NULL DEFAULT '[]',
    has_active_cdr_actor    BOOLEAN         NOT NULL DEFAULT FALSE,

    -- Deduplication / grouping (set by deduplicator)
    group_id                VARCHAR(12),
    group_size              INTEGER         NOT NULL DEFAULT 1,
    is_representative       BOOLEAN         NOT NULL DEFAULT TRUE,
    absorbed_count          INTEGER         NOT NULL DEFAULT 0,
    choke_node_uid          VARCHAR(512),

    -- Lifecycle
    status                  VARCHAR(20)     NOT NULL DEFAULT 'active',  -- active | resolved
    first_seen_at           TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    last_seen_at            TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    created_at              TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT pk_attack_paths PRIMARY KEY (path_id)
);

-- ---------------------------------------------------------------------------
-- Table: attack_path_nodes
-- One row per hop per path. Cleared and re-inserted on each scan.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS attack_path_nodes (
    node_id                 BIGSERIAL       NOT NULL,

    -- Foreign key to parent path
    path_id                 VARCHAR(64)     NOT NULL,
    tenant_id               VARCHAR(255)    NOT NULL,

    -- Node identity
    node_uid                VARCHAR(512)    NOT NULL,
    node_name               VARCHAR(512),
    node_type               VARCHAR(100),
    hop_index               INTEGER         NOT NULL,

    -- Edge to next node
    edge_to_next            VARCHAR(100),   -- e.g. ASSUMES, CAN_ACCESS, CONNECTED_TO, EXPOSES
    edge_category           VARCHAR(50),    -- iam | network | data | compute

    -- Per-hop traversal narrative
    traversal_reason        TEXT,

    -- Per-hop evidence (JSONB — never call json.loads())
    policy_statement        JSONB,          -- IAM policy: {actions, resource, effect}
    sg_rule                 JSONB,          -- SG rule: {port, protocol, cidr}
    misconfigs              JSONB           NOT NULL DEFAULT '[]',
    cves                    JSONB           NOT NULL DEFAULT '[]',
    threat_detections       JSONB           NOT NULL DEFAULT '[]',

    -- CDR actor signal
    cdr_actor_active        BOOLEAN         NOT NULL DEFAULT FALSE,
    cdr_actor_uid           VARCHAR(512),

    created_at              TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT pk_attack_path_nodes PRIMARY KEY (node_id),
    CONSTRAINT fk_apn_path_id
        FOREIGN KEY (path_id) REFERENCES attack_paths(path_id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- Table: attack_path_history
-- Immutable snapshot of each path at each scan run. INSERT ONLY, never UPDATE.
-- history rows are kept even after the path is resolved (no FK to attack_paths).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS attack_path_history (
    history_id              BIGSERIAL       NOT NULL,

    -- path_id NOT FK — history kept after path deleted
    path_id                 VARCHAR(64)     NOT NULL,
    tenant_id               VARCHAR(255)    NOT NULL,
    scan_run_id             UUID            NOT NULL,

    -- Snapshot at time of scan
    path_score              INTEGER         NOT NULL DEFAULT 0,
    severity                VARCHAR(20)     NOT NULL DEFAULT 'low',
    node_uids               JSONB           NOT NULL DEFAULT '[]',
    misconfig_count         INTEGER         NOT NULL DEFAULT 0,
    threat_count            INTEGER         NOT NULL DEFAULT 0,
    has_active_cdr_actor    BOOLEAN         NOT NULL DEFAULT FALSE,

    recorded_at             TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT pk_attack_path_history PRIMARY KEY (history_id)
);

-- ---------------------------------------------------------------------------
-- Table: crown_jewel_overrides
-- Manual analyst overrides for crown jewel classification.
-- UNIQUE(resource_uid, tenant_id) — second PATCH updates, never inserts dup.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS crown_jewel_overrides (
    override_id             BIGSERIAL       NOT NULL,

    resource_uid            VARCHAR(512)    NOT NULL,
    tenant_id               VARCHAR(255)    NOT NULL,

    is_crown_jewel          BOOLEAN         NOT NULL DEFAULT FALSE,
    crown_jewel_type        VARCHAR(50),    -- one of the 8 crown_jewel_type values; NULL when is_crown_jewel=false

    reason                  TEXT,
    set_by                  VARCHAR(255)    NOT NULL,   -- email from AuthContext.user_email — audit trail

    created_at              TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT pk_crown_jewel_overrides PRIMARY KEY (override_id),
    CONSTRAINT uq_cjo_resource_tenant UNIQUE (resource_uid, tenant_id)
);

-- =============================================================================
-- Indexes
-- =============================================================================

-- attack_paths
CREATE INDEX IF NOT EXISTS idx_ap_tenant_scan
    ON attack_paths (tenant_id, scan_run_id);

CREATE INDEX IF NOT EXISTS idx_ap_severity
    ON attack_paths (tenant_id, severity)
    WHERE status = 'active';

CREATE INDEX IF NOT EXISTS idx_ap_crown_jewel
    ON attack_paths (tenant_id, crown_jewel_uid)
    WHERE status = 'active';

CREATE INDEX IF NOT EXISTS idx_ap_choke_node
    ON attack_paths (choke_node_uid)
    WHERE choke_node_uid IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_ap_representative
    ON attack_paths (tenant_id, group_id, is_representative)
    WHERE is_representative = TRUE;

CREATE INDEX IF NOT EXISTS idx_ap_status
    ON attack_paths (tenant_id, status);

-- attack_path_nodes
CREATE INDEX IF NOT EXISTS idx_apn_path_id
    ON attack_path_nodes (path_id);

CREATE INDEX IF NOT EXISTS idx_apn_node_uid
    ON attack_path_nodes (tenant_id, node_uid);

CREATE INDEX IF NOT EXISTS idx_apn_hop_index
    ON attack_path_nodes (path_id, hop_index);

-- attack_path_history
CREATE INDEX IF NOT EXISTS idx_aph_path_trend
    ON attack_path_history (path_id, recorded_at DESC);

CREATE INDEX IF NOT EXISTS idx_aph_tenant
    ON attack_path_history (tenant_id, scan_run_id);

-- crown_jewel_overrides
CREATE INDEX IF NOT EXISTS idx_cjo_tenant
    ON crown_jewel_overrides (tenant_id);

COMMIT;

DO $$
BEGIN
    RAISE NOTICE 'MIGRATION COMPLETE: 024_attack_path_engine_tables';
END $$;
