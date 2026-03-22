-- ============================================================
-- SBOM Engine - Database Schema
-- All tables are independent of vul_engine and osv_engine.
-- Reads from cves + osv_advisory for enrichment (read-only).
-- ============================================================

-- SBOM Documents: one row per SBOM ingested or generated
CREATE TABLE IF NOT EXISTS sbom_documents (
    id               SERIAL PRIMARY KEY,
    sbom_id          VARCHAR(100) UNIQUE NOT NULL,
    host_id          VARCHAR(255),          -- agent_id / CI pipeline / hostname
    application_name VARCHAR(255),
    sbom_format      VARCHAR(20)  NOT NULL, -- CycloneDX | SPDX
    spec_version     VARCHAR(10),           -- 1.5 | 2.3
    version          INTEGER      NOT NULL DEFAULT 1,
    parent_sbom_id   VARCHAR(100),          -- previous version for diff tracking
    component_count  INTEGER      DEFAULT 0,
    vulnerability_count INTEGER   DEFAULT 0,
    source           VARCHAR(50),           -- syft | trivy | cdxgen | sbom-engine
    raw_document     JSONB,                 -- full original SBOM payload
    created_at       TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_by       VARCHAR(255),
    CONSTRAINT fk_parent_sbom FOREIGN KEY (parent_sbom_id)
        REFERENCES sbom_documents(sbom_id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_sbom_doc_host    ON sbom_documents(host_id);
CREATE INDEX IF NOT EXISTS idx_sbom_doc_created ON sbom_documents(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sbom_doc_parent  ON sbom_documents(parent_sbom_id);

-- Full component inventory: ALL packages (not just vulnerable)
CREATE TABLE IF NOT EXISTS sbom_components (
    id              SERIAL PRIMARY KEY,
    sbom_id         VARCHAR(100) NOT NULL
                        REFERENCES sbom_documents(sbom_id) ON DELETE CASCADE,
    bom_ref         VARCHAR(500),
    component_type  VARCHAR(50)  DEFAULT 'library',
    -- library | framework | application | container | operating-system | device | firmware
    name            VARCHAR(255) NOT NULL,
    version         VARCHAR(100),
    purl            VARCHAR(500),
    cpe             VARCHAR(300),
    ecosystem       VARCHAR(60),
    licenses        TEXT[],
    license_expression VARCHAR(500),
    hashes          JSONB,          -- [{"alg":"SHA-256","content":"abc..."}]
    supplier        VARCHAR(255),
    author          VARCHAR(255),
    description     TEXT,
    scope           VARCHAR(50),    -- required | optional | excluded
    is_vulnerable   BOOLEAN NOT NULL DEFAULT FALSE,
    vulnerability_ids TEXT[],       -- [CVE-xxx, GHSA-xxx, ...]
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sbom_comp_sbom_id  ON sbom_components(sbom_id);
CREATE INDEX IF NOT EXISTS idx_sbom_comp_purl     ON sbom_components(purl);
CREATE INDEX IF NOT EXISTS idx_sbom_comp_name     ON sbom_components(LOWER(name), LOWER(COALESCE(ecosystem,'')));
CREATE INDEX IF NOT EXISTS idx_sbom_comp_vuln     ON sbom_components(is_vulnerable) WHERE is_vulnerable = TRUE;
CREATE INDEX IF NOT EXISTS idx_sbom_comp_vuln_ids ON sbom_components USING GIN(vulnerability_ids);
CREATE INDEX IF NOT EXISTS idx_sbom_comp_licenses ON sbom_components USING GIN(licenses);

-- VEX statements: document exploitability per (vulnerability, component)
CREATE TABLE IF NOT EXISTS sbom_vex_statements (
    id               SERIAL PRIMARY KEY,
    sbom_id          VARCHAR(100),
    vulnerability_id VARCHAR(120) NOT NULL,
    -- status values: not_affected | affected | fixed | under_investigation
    status           VARCHAR(50)  NOT NULL,
    component_purl   VARCHAR(500),
    component_name   VARCHAR(255),
    -- CycloneDX VEX justifications for not_affected:
    -- code_not_present | code_not_reachable | requires_configuration |
    -- requires_privilege | protected_by_compiler | protected_at_runtime |
    -- protected_at_perimeter | protected_by_mitigating_control
    justification    VARCHAR(100),
    impact_statement TEXT,
    action_statement TEXT,
    created_at       TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_by       VARCHAR(255),
    UNIQUE (vulnerability_id, component_purl)
);

CREATE INDEX IF NOT EXISTS idx_vex_vuln_id ON sbom_vex_statements(vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_vex_sbom_id ON sbom_vex_statements(sbom_id);
CREATE INDEX IF NOT EXISTS idx_vex_status  ON sbom_vex_statements(status);

-- ============================================================
-- Threat Intelligence Cache: EPSS scores + CISA KEV catalog
-- Refreshed daily by the background monitor.
-- ============================================================
CREATE TABLE IF NOT EXISTS sbom_threat_intel (
    cve_id              VARCHAR(20) PRIMARY KEY,
    epss_score          NUMERIC(8,6),   -- 0.000001 to 1.000000
    epss_percentile     NUMERIC(8,6),   -- rank among all published CVEs
    in_cisa_kev         BOOLEAN NOT NULL DEFAULT FALSE,
    kev_date_added      DATE,
    kev_due_date        DATE,
    kev_ransomware_use  VARCHAR(50),    -- "Known" | "No Known"
    kev_vendor          VARCHAR(255),
    kev_product         VARCHAR(255),
    kev_required_action TEXT,
    last_updated        TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_threat_intel_kev  ON sbom_threat_intel(in_cisa_kev) WHERE in_cisa_kev = TRUE;
CREATE INDEX IF NOT EXISTS idx_threat_intel_epss ON sbom_threat_intel(epss_score DESC);

-- ============================================================
-- Background Monitoring Alerts
-- Created when the nightly CVE watch finds new vulnerabilities
-- in stored SBOMs since the last scan.
-- ============================================================
CREATE TABLE IF NOT EXISTS sbom_alerts (
    id                SERIAL PRIMARY KEY,
    sbom_id           VARCHAR(100) NOT NULL,
    host_id           VARCHAR(255),
    alert_type        VARCHAR(50)  NOT NULL,
    -- new_vulnerability | kev_match | epss_spike | high_risk
    vulnerability_id  VARCHAR(120) NOT NULL,
    component_name    VARCHAR(255),
    component_version VARCHAR(100),
    component_purl    VARCHAR(500),
    severity          VARCHAR(20),
    composite_risk    NUMERIC(4,2),
    epss_score        NUMERIC(8,6),
    in_cisa_kev       BOOLEAN      NOT NULL DEFAULT FALSE,
    message           TEXT,
    status            VARCHAR(20)  NOT NULL DEFAULT 'open',
    -- open | acknowledged | dismissed
    created_at        TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    acknowledged_at   TIMESTAMP WITH TIME ZONE,
    acknowledged_by   VARCHAR(255)
);

CREATE INDEX IF NOT EXISTS idx_alerts_sbom_id ON sbom_alerts(sbom_id);
CREATE INDEX IF NOT EXISTS idx_alerts_host_id ON sbom_alerts(host_id);
CREATE INDEX IF NOT EXISTS idx_alerts_status  ON sbom_alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON sbom_alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_kev     ON sbom_alerts(in_cisa_kev) WHERE in_cisa_kev = TRUE;
