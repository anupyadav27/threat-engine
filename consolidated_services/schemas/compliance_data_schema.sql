-- ============================================================================
-- Compliance Data Table
-- ============================================================================
-- Stores the full compliance control definitions loaded from CSV files.
-- Each row represents one compliance control (e.g., HIPAA 164.312, CIS 1.1)
-- with its mapped rule_ids for each CSP.
--
-- Source CSVs: complaince_csv/{aws,azure,gcp,ibm,k8s}_consolidated_rules*.csv
-- Target DB: threat_engine_compliance
-- ============================================================================

CREATE TABLE IF NOT EXISTS compliance_data (
    unique_compliance_id    VARCHAR(255)    PRIMARY KEY,
    technology              VARCHAR(50),
    compliance_framework    VARCHAR(100)    NOT NULL,
    framework_id            VARCHAR(100)    NOT NULL,
    framework_version       VARCHAR(50),
    requirement_id          VARCHAR(100)    NOT NULL,
    requirement_name        TEXT            NOT NULL,
    requirement_description TEXT,
    section                 VARCHAR(255),
    service                 VARCHAR(100),
    total_checks            INTEGER         DEFAULT 0,
    automation_type         VARCHAR(50),
    confidence_score        VARCHAR(50),
    "references"            TEXT,
    source_file             VARCHAR(255),
    csp                     VARCHAR(20)     NOT NULL DEFAULT 'aws',
    mapped_rules            TEXT,
    created_at              TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- Compliance Rule Data Mapping (exploded)
-- ============================================================================
-- One row per (rule_id, unique_compliance_id) pair.
-- Exploded from the semicolon-separated mapped_rules in compliance_data.
-- This is the join table used by /ui-data for live framework scoring.
-- ============================================================================

CREATE TABLE IF NOT EXISTS compliance_rule_data_mapping (
    id                      SERIAL          PRIMARY KEY,
    rule_id                 VARCHAR(255)    NOT NULL,
    unique_compliance_id    VARCHAR(255)    NOT NULL REFERENCES compliance_data(unique_compliance_id),
    framework_id            VARCHAR(100)    NOT NULL,
    compliance_framework    VARCHAR(100)    NOT NULL,
    csp                     VARCHAR(20)     NOT NULL DEFAULT 'aws',
    created_at              TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    UNIQUE (rule_id, unique_compliance_id)
);

-- Indexes for fast lookups
CREATE INDEX IF NOT EXISTS idx_cd_framework_id       ON compliance_data(framework_id);
CREATE INDEX IF NOT EXISTS idx_cd_compliance_fw      ON compliance_data(compliance_framework);
CREATE INDEX IF NOT EXISTS idx_cd_csp                ON compliance_data(csp);
CREATE INDEX IF NOT EXISTS idx_cd_requirement_id     ON compliance_data(requirement_id);

CREATE INDEX IF NOT EXISTS idx_crdm_rule_id          ON compliance_rule_data_mapping(rule_id);
CREATE INDEX IF NOT EXISTS idx_crdm_compliance_id    ON compliance_rule_data_mapping(unique_compliance_id);
CREATE INDEX IF NOT EXISTS idx_crdm_framework_id     ON compliance_rule_data_mapping(framework_id);
CREATE INDEX IF NOT EXISTS idx_crdm_compliance_fw    ON compliance_rule_data_mapping(compliance_framework);
CREATE INDEX IF NOT EXISTS idx_crdm_rule_framework   ON compliance_rule_data_mapping(rule_id, framework_id);

COMMENT ON TABLE compliance_data IS 'Full compliance control definitions loaded from CSV files per CSP';
COMMENT ON TABLE compliance_rule_data_mapping IS 'Exploded rule_id to compliance control mapping for live scoring';
