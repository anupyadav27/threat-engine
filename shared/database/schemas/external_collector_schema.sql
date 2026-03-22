-- =============================================================================
-- External Collector Database Schema
-- =============================================================================
-- Database: threat_engine_external
-- Purpose:  Store cached external data from container registries, NVD/CVE,
--           package registries, and threat intel feeds (Tier 3 collection)
-- Used by:  shared/external_collector service (Port 8031)
-- Read by:  engine_container (registry_images, vuln_cache),
--           engine_network (threat_intel_ioc),
--           engine_supplychain (vuln_cache, package_metadata),
--           engine_risk (vuln_cache for EPSS/KEV)
-- Reference: PROJECT_PLAN.md Task 0.3.1
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =============================================================================
-- REGISTRY IMAGES TABLE
-- =============================================================================
-- Stores container image metadata and Trivy scan results from Docker Hub,
-- ECR, GCR, ACR, Quay registries.
-- Retention: Per scan (refreshed each cycle)

CREATE TABLE IF NOT EXISTS registry_images (
    id                  BIGSERIAL       PRIMARY KEY,
    registry_type       VARCHAR(50)     NOT NULL,
        -- 'docker_hub', 'ecr', 'gcr', 'acr', 'quay'
    repository          VARCHAR(500)    NOT NULL,
        -- e.g., 'library/nginx', 'myaccount/myapp'
    tag                 VARCHAR(255),
        -- e.g., 'latest', 'v1.2.3', 'sha256:abc...'
    digest              VARCHAR(255),
        -- Image digest (sha256:...)
    manifest            JSONB           DEFAULT '{}'::jsonb,
        -- Full manifest JSON (layers, config, media_type)
    os                  VARCHAR(50),
        -- e.g., 'linux', 'windows'
    architecture        VARCHAR(50),
        -- e.g., 'amd64', 'arm64'
    size_bytes          BIGINT,
    pushed_at           TIMESTAMP WITH TIME ZONE,
    -- Trivy scan results
    trivy_output        JSONB           DEFAULT '{}'::jsonb,
        -- Full Trivy JSON output (vulnerabilities + metadata)
    cve_list            JSONB           DEFAULT '[]'::jsonb,
        -- Extracted: [{cve_id, package_name, installed_version, severity, fixed_version}]
    sbom                JSONB           DEFAULT '{}'::jsonb,
        -- CycloneDX format SBOM extracted from Trivy
    scan_status         VARCHAR(50)     DEFAULT 'pending',
        -- 'pending', 'scanning', 'completed', 'failed'
    scan_time           TIMESTAMP WITH TIME ZONE,
    scan_error          TEXT,
    -- Multi-tenancy
    customer_id         VARCHAR(255),
    tenant_id           VARCHAR(255),
    -- Timestamps
    created_at          TIMESTAMP WITH TIME ZONE    DEFAULT NOW(),
    refreshed_at        TIMESTAMP WITH TIME ZONE    DEFAULT NOW(),
    UNIQUE(registry_type, repository, tag, digest, customer_id, tenant_id)
);

-- =============================================================================
-- VULN CACHE TABLE
-- =============================================================================
-- Cached CVE data from NVD, enriched with EPSS scores and KEV flags.
-- Retention: 24h TTL (refreshed daily by NVD/EPSS/KEV adapters)

CREATE TABLE IF NOT EXISTS vuln_cache (
    id                  BIGSERIAL       PRIMARY KEY,
    cve_id              VARCHAR(50)     NOT NULL UNIQUE,
        -- e.g., 'CVE-2024-1234'
    cvss_v3_score       NUMERIC(3,1),
        -- 0.0 to 10.0
    cvss_v3_vector      VARCHAR(255),
        -- e.g., 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
    severity            VARCHAR(20),
        -- 'NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    description         TEXT,
    affected_cpe        JSONB           DEFAULT '[]'::jsonb,
        -- [{cpe_uri, version_start, version_end, version_exact}]
    fix_versions        JSONB           DEFAULT '[]'::jsonb,
        -- [{package, version, ecosystem}]
    -- EPSS enrichment (Task 0.3.7)
    epss_score          NUMERIC(5,4),
        -- 0.0000 to 1.0000 (probability of exploitation in next 30 days)
    epss_percentile     NUMERIC(5,2),
        -- 0.00 to 100.00
    -- KEV enrichment (Task 0.3.8)
    is_kev              BOOLEAN         DEFAULT false,
        -- TRUE if in CISA Known Exploited Vulnerabilities catalog
    kev_date_added      DATE,
    kev_due_date        DATE,
        -- Remediation due date from CISA
    kev_ransomware_use  BOOLEAN         DEFAULT false,
        -- TRUE if known ransomware campaign use
    -- Source metadata
    published_date      TIMESTAMP WITH TIME ZONE,
    last_modified_date  TIMESTAMP WITH TIME ZONE,
    source              VARCHAR(50)     DEFAULT 'nvd',
        -- 'nvd', 'github_advisory', 'osv'
    -- Timestamps
    created_at          TIMESTAMP WITH TIME ZONE    DEFAULT NOW(),
    refreshed_at        TIMESTAMP WITH TIME ZONE    DEFAULT NOW()
);

-- =============================================================================
-- PACKAGE METADATA TABLE
-- =============================================================================
-- Cached metadata from public package registries (npm, PyPI, Maven, crates.io).
-- Used for dependency confusion detection and provenance checks.
-- Retention: 24h TTL

CREATE TABLE IF NOT EXISTS package_metadata (
    id                  BIGSERIAL       PRIMARY KEY,
    ecosystem           VARCHAR(50)     NOT NULL,
        -- 'npm', 'pypi', 'maven', 'crates', 'rubygems', 'nuget'
    package_name        VARCHAR(500)    NOT NULL,
        -- e.g., '@acmecorp/auth', 'requests', 'com.example:mylib'
    namespace           VARCHAR(255),
        -- Scope/group (e.g., '@acmecorp' for npm, 'com.example' for Maven)
    latest_version      VARCHAR(100),
    publish_date        TIMESTAMP WITH TIME ZONE,
    maintainer_count    INTEGER,
    license             VARCHAR(255),
    weekly_downloads    BIGINT,
    deprecated          BOOLEAN         DEFAULT false,
    description         TEXT,
    homepage_url        VARCHAR(1000),
    repository_url      VARCHAR(1000),
    -- Provenance
    purl                VARCHAR(1000),
        -- Package URL (e.g., 'pkg:npm/%40acmecorp/auth@1.0.0')
    -- Raw API response
    raw_metadata        JSONB           DEFAULT '{}'::jsonb,
    -- Timestamps
    created_at          TIMESTAMP WITH TIME ZONE    DEFAULT NOW(),
    refreshed_at        TIMESTAMP WITH TIME ZONE    DEFAULT NOW(),
    UNIQUE(ecosystem, package_name)
);

-- =============================================================================
-- THREAT INTEL IOC TABLE
-- =============================================================================
-- Cached threat intelligence indicators (IPs, domains, hashes) from
-- AbuseIPDB, OTX, VirusTotal feeds.
-- Retention: 6h TTL (refreshed frequently due to rapid IOC changes)

CREATE TABLE IF NOT EXISTS threat_intel_ioc (
    id                  BIGSERIAL       PRIMARY KEY,
    indicator_type      VARCHAR(50)     NOT NULL,
        -- 'ipv4', 'ipv6', 'domain', 'url', 'file_hash_md5', 'file_hash_sha256'
    indicator_value     VARCHAR(1000)   NOT NULL,
        -- e.g., '203.0.113.50', 'evil.example.com', 'abc123...'
    source              VARCHAR(100)    NOT NULL,
        -- 'abuseipdb', 'otx', 'virustotal', 'cisa_kev'
    confidence          INTEGER,
        -- 0-100 (AbuseIPDB confidence score, or estimated confidence)
    threat_type         VARCHAR(255),
        -- e.g., 'malware', 'scanner', 'spambot', 'bruteforce', 'c2'
    first_seen          TIMESTAMP WITH TIME ZONE,
    last_seen           TIMESTAMP WITH TIME ZONE,
    tags                JSONB           DEFAULT '[]'::jsonb,
        -- Additional tags from source (e.g., OTX pulse tags)
    raw_data            JSONB           DEFAULT '{}'::jsonb,
        -- Full source response for reference
    is_active           BOOLEAN         DEFAULT true,
    -- Timestamps
    created_at          TIMESTAMP WITH TIME ZONE    DEFAULT NOW(),
    refreshed_at        TIMESTAMP WITH TIME ZONE    DEFAULT NOW(),
    UNIQUE(indicator_type, indicator_value, source)
);

-- =============================================================================
-- COLLECTION STATUS TABLE
-- =============================================================================
-- Tracks the status of each external collection run for observability.

CREATE TABLE IF NOT EXISTS external_collection_status (
    id                  SERIAL          PRIMARY KEY,
    collection_id       VARCHAR(255)    NOT NULL UNIQUE DEFAULT uuid_generate_v4()::TEXT,
    source_type         VARCHAR(100)    NOT NULL,
        -- 'docker_hub', 'ecr', 'github', 'gitlab', 'nvd', 'epss', 'kev',
        -- 'npm', 'pypi', 'maven', 'abuseipdb', 'otx', 'lambda_zip'
    status              VARCHAR(50)     NOT NULL DEFAULT 'in_progress',
        -- 'in_progress', 'success', 'failed', 'partial'
    started_at          TIMESTAMP WITH TIME ZONE    DEFAULT NOW(),
    completed_at        TIMESTAMP WITH TIME ZONE,
    items_processed     INTEGER         DEFAULT 0,
    items_failed        INTEGER         DEFAULT 0,
    error_message       TEXT,
    metadata            JSONB           DEFAULT '{}'::jsonb,
    created_at          TIMESTAMP WITH TIME ZONE    DEFAULT NOW()
);

-- =============================================================================
-- INDEXES
-- =============================================================================

-- registry_images: lookup by registry type and repository
CREATE INDEX IF NOT EXISTS idx_registry_images_type_repo
ON registry_images(registry_type, repository);

-- registry_images: scan status for finding unscanned images
CREATE INDEX IF NOT EXISTS idx_registry_images_scan_status
ON registry_images(scan_status) WHERE scan_status != 'completed';

-- registry_images: tenant lookups
CREATE INDEX IF NOT EXISTS idx_registry_images_tenant
ON registry_images(customer_id, tenant_id) WHERE customer_id IS NOT NULL;

-- registry_images: CVE list GIN for JSONB queries
CREATE INDEX IF NOT EXISTS idx_registry_images_cve_gin
ON registry_images USING GIN (cve_list);

-- vuln_cache: primary lookup by CVE ID (already UNIQUE, but explicit B-tree)
CREATE INDEX IF NOT EXISTS idx_vuln_cache_cve_id
ON vuln_cache(cve_id);

-- vuln_cache: severity filter
CREATE INDEX IF NOT EXISTS idx_vuln_cache_severity
ON vuln_cache(severity) WHERE severity IN ('HIGH', 'CRITICAL');

-- vuln_cache: KEV flag for quick filtering
CREATE INDEX IF NOT EXISTS idx_vuln_cache_kev
ON vuln_cache(is_kev) WHERE is_kev = TRUE;

-- vuln_cache: EPSS score for prioritization
CREATE INDEX IF NOT EXISTS idx_vuln_cache_epss
ON vuln_cache(epss_score DESC NULLS LAST) WHERE epss_score IS NOT NULL;

-- vuln_cache: affected CPE GIN for JSONB queries
CREATE INDEX IF NOT EXISTS idx_vuln_cache_cpe_gin
ON vuln_cache USING GIN (affected_cpe);

-- vuln_cache: staleness check
CREATE INDEX IF NOT EXISTS idx_vuln_cache_refreshed
ON vuln_cache(refreshed_at);

-- package_metadata: ecosystem + package name lookup
CREATE INDEX IF NOT EXISTS idx_package_meta_ecosystem_name
ON package_metadata(ecosystem, package_name);

-- package_metadata: PURL lookup
CREATE INDEX IF NOT EXISTS idx_package_meta_purl
ON package_metadata(purl) WHERE purl IS NOT NULL;

-- threat_intel_ioc: primary lookup by indicator value
CREATE INDEX IF NOT EXISTS idx_threat_intel_value
ON threat_intel_ioc(indicator_value);

-- threat_intel_ioc: type + value for specific queries
CREATE INDEX IF NOT EXISTS idx_threat_intel_type_value
ON threat_intel_ioc(indicator_type, indicator_value);

-- threat_intel_ioc: source filter
CREATE INDEX IF NOT EXISTS idx_threat_intel_source
ON threat_intel_ioc(source, is_active) WHERE is_active = TRUE;

-- threat_intel_ioc: confidence filter for high-confidence IOCs
CREATE INDEX IF NOT EXISTS idx_threat_intel_confidence
ON threat_intel_ioc(confidence DESC) WHERE confidence >= 80 AND is_active = TRUE;

-- threat_intel_ioc: staleness check
CREATE INDEX IF NOT EXISTS idx_threat_intel_refreshed
ON threat_intel_ioc(refreshed_at);

-- external_collection_status: source type + status
CREATE INDEX IF NOT EXISTS idx_ext_collection_status
ON external_collection_status(source_type, status, started_at DESC);

-- =============================================================================
-- COMMENTS
-- =============================================================================

COMMENT ON TABLE registry_images IS 'Container image metadata and Trivy scan results from Docker Hub, ECR, GCR, ACR, Quay (per-scan refresh)';
COMMENT ON TABLE vuln_cache IS 'Cached CVE data from NVD enriched with EPSS scores and KEV flags (24h TTL)';
COMMENT ON TABLE package_metadata IS 'Cached package metadata from npm, PyPI, Maven, crates.io for dependency analysis (24h TTL)';
COMMENT ON TABLE threat_intel_ioc IS 'Threat intelligence indicators (IPs, domains, hashes) from AbuseIPDB, OTX, VirusTotal (6h TTL)';
COMMENT ON TABLE external_collection_status IS 'Audit trail of external collection runs for observability';

-- =============================================================================
-- END: External Collector Schema (5 tables, 19 indexes)
-- =============================================================================
