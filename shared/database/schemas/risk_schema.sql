-- =============================================================================
-- Financial Risk Quantification Engine Schema — Task 5.1
-- Database: threat_engine_risk
-- Engine:   risk (Port 8009)
-- Purpose:  FAIR model dollar-denominated exposure, regulatory fine estimation
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1. risk_model_config — Per-tenant/industry FAIR parameters (no rule table)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS risk_model_config (
    config_id               UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               VARCHAR(100),         -- NULL = default for industry
    industry                VARCHAR(50)   NOT NULL,
    per_record_cost         DECIMAL(10,2) NOT NULL DEFAULT 4.45,
    revenue_range           VARCHAR(30),          -- small(<$10M) | medium | large(>$1B)
    estimated_annual_revenue DECIMAL(15,2),
    applicable_regs         JSONB         DEFAULT '[]',
    downtime_cost_hr        DECIMAL(12,2) DEFAULT 10000.00,
    sensitivity_multipliers JSONB         DEFAULT '{"restricted":3.0,"confidential":2.0,"internal":1.0,"public":0.1}',
    default_record_count    INTEGER       DEFAULT 1000,
    is_default              BOOLEAN       DEFAULT false,
    created_at              TIMESTAMP     DEFAULT NOW(),
    updated_at              TIMESTAMP     DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_risk_config_tenant ON risk_model_config (tenant_id);
CREATE INDEX IF NOT EXISTS idx_risk_config_industry ON risk_model_config (industry);

-- -----------------------------------------------------------------------------
-- 2. risk_input_transformed — Stage 1 ETL output (one row per CRITICAL/HIGH finding)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS risk_input_transformed (
    id                      BIGSERIAL     PRIMARY KEY,
    risk_scan_id            UUID          NOT NULL,
    tenant_id               VARCHAR(100)  NOT NULL,
    orchestration_id        UUID          NOT NULL,
    -- Source finding
    source_finding_id       VARCHAR(255),
    source_engine           VARCHAR(30)   NOT NULL,  -- threat | iam | datasec | container | network | supplychain | api | check
    source_scan_id          UUID,
    -- Finding detail
    rule_id                 VARCHAR(100),
    severity                VARCHAR(20),
    title                   TEXT,
    finding_type            VARCHAR(50),
    -- Asset info (from inventory)
    asset_id                VARCHAR(255),
    asset_type              VARCHAR(100),
    asset_arn               VARCHAR(500),
    asset_criticality       VARCHAR(20),          -- critical | high | medium | low
    is_public               BOOLEAN       DEFAULT false,
    -- Data sensitivity (from datasec)
    data_sensitivity        VARCHAR(20),          -- restricted | confidential | internal | public
    data_types              TEXT[]        DEFAULT '{}',
    estimated_record_count  BIGINT        DEFAULT 0,
    -- Tenant context
    industry                VARCHAR(50),
    estimated_revenue       DECIMAL(15,2),
    applicable_regulations  TEXT[]        DEFAULT '{}',
    -- Enrichment
    epss_score              DECIMAL(6,5)  DEFAULT 0.05,
    cve_id                  VARCHAR(30),
    exposure_factor         DECIMAL(4,2)  DEFAULT 1.0,
    -- Metadata
    account_id              VARCHAR(20),
    region                  VARCHAR(50),
    csp                     VARCHAR(20)   DEFAULT 'aws',
    scanned_at              TIMESTAMP     DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_risk_transformed_scan
    ON risk_input_transformed (risk_scan_id);
CREATE INDEX IF NOT EXISTS idx_risk_transformed_engine
    ON risk_input_transformed (risk_scan_id, source_engine);

-- -----------------------------------------------------------------------------
-- 3. risk_scenarios — Stage 2 output (FAIR model per finding)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS risk_scenarios (
    scenario_id             UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    risk_scan_id            UUID          NOT NULL,
    tenant_id               VARCHAR(100)  NOT NULL,
    orchestration_id        UUID          NOT NULL,
    -- Source
    source_finding_id       VARCHAR(255),
    source_engine           VARCHAR(30),
    asset_id                VARCHAR(255),
    asset_type              VARCHAR(100),
    asset_arn               VARCHAR(500),
    -- Scenario type
    scenario_type           VARCHAR(40),          -- data_breach | ransomware | account_takeover | compliance_fine | service_disruption
    -- Data at risk
    data_records_at_risk    BIGINT        DEFAULT 0,
    data_sensitivity        VARCHAR(20),
    data_types              TEXT[]        DEFAULT '{}',
    -- FAIR model outputs
    loss_event_frequency    DECIMAL(6,5)  DEFAULT 0,
    primary_loss_min        DECIMAL(14,2) DEFAULT 0,
    primary_loss_max        DECIMAL(14,2) DEFAULT 0,
    primary_loss_likely     DECIMAL(14,2) DEFAULT 0,
    regulatory_fine_min     DECIMAL(14,2) DEFAULT 0,
    regulatory_fine_max     DECIMAL(14,2) DEFAULT 0,
    applicable_regulations  TEXT[]        DEFAULT '{}',
    total_exposure_min      DECIMAL(14,2) DEFAULT 0,
    total_exposure_max      DECIMAL(14,2) DEFAULT 0,
    total_exposure_likely   DECIMAL(14,2) DEFAULT 0,
    -- Risk tier
    risk_tier               VARCHAR(20)   NOT NULL DEFAULT 'low',  -- critical(>$10M) | high(>$1M) | medium(>$100K) | low
    -- Calculation audit trail
    calculation_model       JSONB,
    -- Metadata
    account_id              VARCHAR(20),
    region                  VARCHAR(50),
    csp                     VARCHAR(20)   DEFAULT 'aws',
    created_at              TIMESTAMP     DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_risk_scenarios_scan
    ON risk_scenarios (risk_scan_id);
CREATE INDEX IF NOT EXISTS idx_risk_scenarios_tier
    ON risk_scenarios (risk_scan_id, risk_tier);
CREATE INDEX IF NOT EXISTS idx_risk_scenarios_engine
    ON risk_scenarios (risk_scan_id, source_engine);

-- -----------------------------------------------------------------------------
-- 4. risk_report — Scan-level summary (Stage 3 output)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS risk_report (
    risk_scan_id            UUID          PRIMARY KEY,
    orchestration_id        UUID          NOT NULL,
    tenant_id               VARCHAR(100)  NOT NULL,
    account_id              VARCHAR(20),
    provider                VARCHAR(20)   DEFAULT 'aws',
    -- Scenario counts
    total_scenarios         INTEGER       DEFAULT 0,
    critical_scenarios      INTEGER       DEFAULT 0,
    high_scenarios          INTEGER       DEFAULT 0,
    medium_scenarios        INTEGER       DEFAULT 0,
    low_scenarios           INTEGER       DEFAULT 0,
    -- Exposure totals
    total_exposure_min      DECIMAL(14,2) DEFAULT 0,
    total_exposure_max      DECIMAL(14,2) DEFAULT 0,
    total_exposure_likely   DECIMAL(14,2) DEFAULT 0,
    total_regulatory_exposure DECIMAL(14,2) DEFAULT 0,
    -- Breakdowns
    engine_breakdown        JSONB,            -- {threat: $X, iam: $Y, ...}
    top_scenarios           JSONB,            -- [{scenario_id, exposure, asset}]
    scenario_type_breakdown JSONB,            -- {data_breach: $X, ransomware: $Y}
    frameworks_at_risk      TEXT[]        DEFAULT '{}',
    -- Trending
    vs_previous_likely      DECIMAL(14,2),
    vs_previous_pct         DECIMAL(6,2),
    currency                VARCHAR(5)    DEFAULT 'USD',
    -- Timing
    started_at              TIMESTAMP,
    completed_at            TIMESTAMP,
    scan_duration_ms        INTEGER,
    status                  VARCHAR(20)   DEFAULT 'pending',
    error_message           TEXT,
    created_at              TIMESTAMP     DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- 5. risk_summary — Per-engine risk aggregation (Stage 3 output)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS risk_summary (
    summary_id              UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    risk_scan_id            UUID          NOT NULL,
    tenant_id               VARCHAR(100)  NOT NULL,
    orchestration_id        UUID          NOT NULL,
    source_engine           VARCHAR(30)   NOT NULL,
    scenario_count          INTEGER       DEFAULT 0,
    critical_count          INTEGER       DEFAULT 0,
    high_count              INTEGER       DEFAULT 0,
    total_exposure_likely   DECIMAL(14,2) DEFAULT 0,
    total_regulatory_exposure DECIMAL(14,2) DEFAULT 0,
    top_finding_types       JSONB,
    created_at              TIMESTAMP     DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_risk_summary_scan
    ON risk_summary (risk_scan_id);

-- -----------------------------------------------------------------------------
-- 6. risk_trends — Time-series for dashboards (Stage 3 output)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS risk_trends (
    id                      UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               VARCHAR(100)  NOT NULL,
    scan_date               DATE          NOT NULL,
    risk_scan_id            UUID          NOT NULL,
    total_exposure_likely   DECIMAL(14,2) DEFAULT 0,
    critical_scenarios      INTEGER       DEFAULT 0,
    high_scenarios          INTEGER       DEFAULT 0,
    top_risk_type           VARCHAR(40),
    top_risk_engine         VARCHAR(30),
    created_at              TIMESTAMP     DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_risk_trends_tenant
    ON risk_trends (tenant_id, scan_date DESC);

-- =============================================================================
-- End of Risk Engine Schema
-- =============================================================================
