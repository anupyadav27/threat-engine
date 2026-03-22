-- ============================================================================
-- DEPRECATED — Supply Chain Engine removed. Schema retained for historical data.
-- See engines/supplychain/DEPRECATED.md
-- ============================================================================
-- Supply Chain Engine Schema — Task 3.1 [Seq 63 | DE]
-- Database: threat_engine_supplychain
-- ============================================================================
-- Tables: supplychain_report, supplychain_input_transformed, supplychain_rules,
--         supplychain_findings, sbom_manifests, sbom_components
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";


-- ============================================================================
-- supplychain_report — scan-level summary (1 row per scan)
-- ============================================================================

CREATE TABLE IF NOT EXISTS supplychain_report (
    supplychain_scan_id UUID            PRIMARY KEY DEFAULT uuid_generate_v4(),
    orchestration_id    UUID            NOT NULL,
    tenant_id           VARCHAR(255)    NOT NULL,
    account_id          VARCHAR(255)    NOT NULL,
    provider            VARCHAR(50)     NOT NULL DEFAULT 'aws',

    -- Counts
    total_manifests         INTEGER     DEFAULT 0,
    total_components        INTEGER     DEFAULT 0,
    total_direct_deps       INTEGER     DEFAULT 0,
    total_transitive_deps   INTEGER     DEFAULT 0,
    total_findings          INTEGER     DEFAULT 0,
    total_failures          INTEGER     DEFAULT 0,
    critical_count          INTEGER     DEFAULT 0,
    high_count              INTEGER     DEFAULT 0,
    medium_count            INTEGER     DEFAULT 0,
    low_count               INTEGER     DEFAULT 0,
    info_count              INTEGER     DEFAULT 0,

    -- Supply-chain specific
    vulnerable_packages     INTEGER     DEFAULT 0,
    malicious_packages      INTEGER     DEFAULT 0,
    license_violations      INTEGER     DEFAULT 0,
    unpinned_deps           INTEGER     DEFAULT 0,
    abandoned_deps          INTEGER     DEFAULT 0,
    dep_confusion_risks     INTEGER     DEFAULT 0,

    -- Aggregations
    top_failing_rules       JSONB       DEFAULT '[]'::jsonb,
    ecosystem_summary       JSONB       DEFAULT '{}'::jsonb,   -- {npm: 50, pypi: 30, ...}
    risk_score              INTEGER     DEFAULT 0,

    -- Timing
    started_at              TIMESTAMP WITH TIME ZONE,
    completed_at            TIMESTAMP WITH TIME ZONE,
    scan_duration_ms        INTEGER,
    status                  VARCHAR(50)     DEFAULT 'running',
    error_message           TEXT,

    created_at              TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

COMMENT ON TABLE supplychain_report IS 'Scan-level summary for supply chain engine (1 row per scan)';

CREATE INDEX IF NOT EXISTS idx_scr_tenant
    ON supplychain_report(tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_scr_orch
    ON supplychain_report(orchestration_id);


-- ============================================================================
-- supplychain_input_transformed — ETL output (Stage 1)
-- ============================================================================

CREATE TABLE IF NOT EXISTS supplychain_input_transformed (
    id                      BIGSERIAL       PRIMARY KEY,
    supplychain_scan_id     UUID            NOT NULL,
    tenant_id               VARCHAR(255)    NOT NULL,
    orchestration_id        UUID            NOT NULL,

    -- Source identity
    source_type             VARCHAR(50)     NOT NULL,   -- container_image | lambda | code_repo | package_registry
    source_id               VARCHAR(500)    NOT NULL,   -- image_id | function_arn | repo_url
    source_name             VARCHAR(255),
    manifest_file           VARCHAR(255),                -- package.json, requirements.txt, etc.

    -- Package identity
    package_name            VARCHAR(500)    NOT NULL,
    package_version         VARCHAR(100),
    package_type            VARCHAR(50),     -- npm, pypi, maven, go, nuget, deb, rpm, gem, cargo
    purl                    TEXT,            -- Package URL: pkg:pypi/requests@2.28.0
    cpe                     TEXT,

    -- Dependency info
    is_direct_dep           BOOLEAN         DEFAULT TRUE,
    dep_depth               INTEGER         DEFAULT 1,   -- 1=direct, 2+=transitive

    -- Provenance
    license                 VARCHAR(255),
    license_category        VARCHAR(30),     -- permissive, copyleft, commercial, unknown
    supplier                VARCHAR(255),
    is_signed               BOOLEAN,
    is_pinned               BOOLEAN,         -- exact version vs range
    last_published_at       TIMESTAMP WITH TIME ZONE,
    days_since_update       INTEGER,
    is_abandoned            BOOLEAN          DEFAULT FALSE,

    -- Vulnerability
    has_vulnerabilities     BOOLEAN          DEFAULT FALSE,
    vulnerability_count     INTEGER          DEFAULT 0,
    critical_vuln_count     INTEGER          DEFAULT 0,
    cve_ids                 JSONB            DEFAULT '[]'::jsonb,

    -- Malicious detection
    is_malicious            BOOLEAN          DEFAULT FALSE,
    is_typosquat_suspect    BOOLEAN          DEFAULT FALSE,
    malicious_indicators    JSONB            DEFAULT '[]'::jsonb,

    -- Dependency confusion
    public_registry_exists  BOOLEAN,
    is_internal_package     BOOLEAN          DEFAULT FALSE,

    -- Context
    account_id              VARCHAR(255),
    region                  VARCHAR(50),

    created_at              TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

COMMENT ON TABLE supplychain_input_transformed IS 'ETL Stage 1 output: enriched package data ready for rule evaluation';

CREATE INDEX IF NOT EXISTS idx_scit_scan
    ON supplychain_input_transformed(supplychain_scan_id, tenant_id);

CREATE INDEX IF NOT EXISTS idx_scit_package
    ON supplychain_input_transformed(package_name, package_version);

CREATE INDEX IF NOT EXISTS idx_scit_source
    ON supplychain_input_transformed(source_type, source_id);

CREATE INDEX IF NOT EXISTS idx_scit_vuln
    ON supplychain_input_transformed(has_vulnerabilities)
    WHERE has_vulnerabilities = TRUE;


-- ============================================================================
-- supplychain_rules — rule definitions (Stage 2 input)
-- ============================================================================

CREATE TABLE IF NOT EXISTS supplychain_rules (
    id                  SERIAL          PRIMARY KEY,
    rule_id             VARCHAR(255)    NOT NULL UNIQUE,
    title               TEXT            NOT NULL,
    description         TEXT,
    category            VARCHAR(100)    NOT NULL,    -- vulnerability, malicious, provenance, dep_confusion, license
    severity            VARCHAR(20)     NOT NULL DEFAULT 'medium',
    condition_type      VARCHAR(50)     NOT NULL DEFAULT 'field_check',
    condition           JSONB           NOT NULL DEFAULT '{}'::jsonb,
    evidence_fields     JSONB           DEFAULT '[]'::jsonb,
    frameworks          JSONB           DEFAULT '[]'::jsonb,
    remediation         TEXT,
    "references"        JSONB           DEFAULT '[]'::jsonb,
    csp                 TEXT[]          DEFAULT ARRAY['all'],
    is_active           BOOLEAN         DEFAULT TRUE,

    created_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

COMMENT ON TABLE supplychain_rules IS 'Supply chain security rules (10 initial rules)';

CREATE INDEX IF NOT EXISTS idx_supplychain_rules_active
    ON supplychain_rules(is_active, category);


-- ============================================================================
-- supplychain_findings — rule evaluation results (Stage 2 output)
-- ============================================================================

CREATE TABLE IF NOT EXISTS supplychain_findings (
    finding_id              UUID            PRIMARY KEY DEFAULT uuid_generate_v4(),
    supplychain_scan_id     UUID            NOT NULL,
    tenant_id               VARCHAR(255)    NOT NULL,
    orchestration_id        UUID            NOT NULL,

    -- Source
    manifest_id             UUID,
    component_id            UUID,
    source_type             VARCHAR(50),
    source_id               VARCHAR(500),

    -- Package
    package_name            VARCHAR(500),
    package_version         VARCHAR(100),
    package_type            VARCHAR(50),
    purl                    TEXT,

    -- Rule
    rule_id                 VARCHAR(255)    NOT NULL,
    finding_type            VARCHAR(50),     -- vulnerable_dep, malicious_pkg, license_violation, abandoned, unpinned, dep_confusion, unsigned
    result                  VARCHAR(20)     NOT NULL,
    severity                VARCHAR(20)     NOT NULL DEFAULT 'info',
    title                   TEXT,
    description             TEXT,

    -- CVE-specific
    cve_ids                 JSONB           DEFAULT '[]'::jsonb,

    -- Evidence
    evidence                JSONB           DEFAULT '{}'::jsonb,
    remediation             TEXT,

    -- Impact
    affected_services       JSONB           DEFAULT '[]'::jsonb,   -- which services/functions use this package

    -- Context
    account_id              VARCHAR(255),
    region                  VARCHAR(50),
    csp                     VARCHAR(50)     DEFAULT 'aws',
    is_active               BOOLEAN         DEFAULT TRUE,

    created_at              TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

COMMENT ON TABLE supplychain_findings IS 'Per-rule per-package evaluation results (PASS/FAIL/SKIP/ERROR)';

CREATE INDEX IF NOT EXISTS idx_scf_scan_rule
    ON supplychain_findings(supplychain_scan_id, rule_id);

CREATE INDEX IF NOT EXISTS idx_scf_tenant
    ON supplychain_findings(tenant_id, orchestration_id);

CREATE INDEX IF NOT EXISTS idx_scf_result
    ON supplychain_findings(result, severity);

CREATE INDEX IF NOT EXISTS idx_scf_package
    ON supplychain_findings(package_name);

CREATE INDEX IF NOT EXISTS idx_scf_critical
    ON supplychain_findings(supplychain_scan_id)
    WHERE severity = 'critical' AND result = 'FAIL';


-- ============================================================================
-- sbom_manifests — one per scanned artifact (Stage 3)
-- ============================================================================

CREATE TABLE IF NOT EXISTS sbom_manifests (
    manifest_id             UUID            PRIMARY KEY DEFAULT uuid_generate_v4(),
    supplychain_scan_id     UUID            NOT NULL,
    tenant_id               VARCHAR(255)    NOT NULL,
    orchestration_id        UUID            NOT NULL,

    -- Source identity
    source_type             VARCHAR(50)     NOT NULL,   -- container_image | lambda | code_repo | package_registry
    source_id               VARCHAR(500)    NOT NULL,
    source_name             VARCHAR(255),

    -- SBOM metadata
    sbom_format             VARCHAR(30),     -- spdx-2.3 | cyclonedx-1.4 | syft
    total_components        INTEGER         DEFAULT 0,
    direct_deps             INTEGER         DEFAULT 0,
    transitive_deps         INTEGER         DEFAULT 0,

    -- Risk
    critical_findings       INTEGER         DEFAULT 0,
    high_findings           INTEGER         DEFAULT 0,
    risk_score              INTEGER         DEFAULT 0,

    -- Full SBOM
    sbom_json               JSONB,

    generated_at            TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

COMMENT ON TABLE sbom_manifests IS 'SBOM manifest per scanned artifact (image, Lambda, repo)';

CREATE INDEX IF NOT EXISTS idx_sm_scan
    ON sbom_manifests(supplychain_scan_id, tenant_id);

CREATE INDEX IF NOT EXISTS idx_sm_source
    ON sbom_manifests(source_type, source_id);


-- ============================================================================
-- sbom_components — per-package per-manifest inventory (Stage 3)
-- ============================================================================

CREATE TABLE IF NOT EXISTS sbom_components (
    component_id            UUID            PRIMARY KEY DEFAULT uuid_generate_v4(),
    manifest_id             UUID            REFERENCES sbom_manifests(manifest_id),
    supplychain_scan_id     UUID            NOT NULL,
    tenant_id               VARCHAR(255)    NOT NULL,

    -- Package identity
    package_name            VARCHAR(500)    NOT NULL,
    package_version         VARCHAR(100),
    package_type            VARCHAR(50),
    purl                    TEXT,
    cpe                     TEXT,

    -- Metadata
    license                 VARCHAR(255),
    license_category        VARCHAR(30),
    is_direct_dep           BOOLEAN         DEFAULT TRUE,
    dep_depth               INTEGER         DEFAULT 1,
    supplier                VARCHAR(255),

    -- Provenance
    is_signed               BOOLEAN,
    is_pinned               BOOLEAN,
    last_published_at       TIMESTAMP WITH TIME ZONE,
    days_since_update       INTEGER,
    is_abandoned            BOOLEAN         DEFAULT FALSE,

    -- Risk flags
    has_vulnerabilities     BOOLEAN         DEFAULT FALSE,
    vulnerability_count     INTEGER         DEFAULT 0,
    is_malicious            BOOLEAN         DEFAULT FALSE,

    created_at              TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

COMMENT ON TABLE sbom_components IS 'Per-package per-manifest inventory with risk flags';

CREATE INDEX IF NOT EXISTS idx_scomp_manifest
    ON sbom_components(manifest_id, supplychain_scan_id);

CREATE INDEX IF NOT EXISTS idx_scomp_package
    ON sbom_components(package_name, package_version);

CREATE INDEX IF NOT EXISTS idx_scomp_vuln
    ON sbom_components(has_vulnerabilities)
    WHERE has_vulnerabilities = TRUE;

CREATE INDEX IF NOT EXISTS idx_scomp_malicious
    ON sbom_components(is_malicious)
    WHERE is_malicious = TRUE;
