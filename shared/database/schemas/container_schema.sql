-- ============================================================================
-- DEPRECATED — Container Engine removed. Schema retained for historical data.
-- See engines/container/DEPRECATED.md
-- ============================================================================
-- Container Engine Schema — Task 1.1 [Seq 47 | DE]
-- Database: threat_engine_container
-- ============================================================================
-- Tables: container_report, container_input_transformed, container_rules,
--         container_findings, container_images, container_sbom,
--         k8s_policy_findings
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";


-- ============================================================================
-- container_report — scan-level summary (1 row per scan)
-- ============================================================================

CREATE TABLE IF NOT EXISTS container_report (
    container_scan_id   UUID            PRIMARY KEY DEFAULT uuid_generate_v4(),
    orchestration_id    UUID            NOT NULL,
    tenant_id           VARCHAR(255)    NOT NULL,
    account_id          VARCHAR(255)    NOT NULL,
    provider            VARCHAR(50)     NOT NULL DEFAULT 'aws',

    -- Counts
    total_images_scanned    INTEGER     DEFAULT 0,
    total_resources_scanned INTEGER     DEFAULT 0,
    total_findings          INTEGER     DEFAULT 0,
    total_failures          INTEGER     DEFAULT 0,
    critical_count          INTEGER     DEFAULT 0,
    high_count              INTEGER     DEFAULT 0,
    medium_count            INTEGER     DEFAULT 0,
    low_count               INTEGER     DEFAULT 0,
    info_count              INTEGER     DEFAULT 0,

    -- Aggregations
    top_failing_rules       JSONB       DEFAULT '[]'::jsonb,   -- top 5 [{rule_id, title, fail_count}]
    sbom_stats              JSONB       DEFAULT '{}'::jsonb,   -- {total_packages, critical_cves, high_cves}
    risk_score              INTEGER     DEFAULT 0,             -- 0-100

    -- Timing
    started_at              TIMESTAMP WITH TIME ZONE,
    completed_at            TIMESTAMP WITH TIME ZONE,
    scan_duration_ms        INTEGER,
    status                  VARCHAR(50)     DEFAULT 'running',
    error_message           TEXT,

    created_at              TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

COMMENT ON TABLE container_report IS 'Scan-level summary for container engine (1 row per scan)';

CREATE INDEX IF NOT EXISTS idx_container_report_tenant
    ON container_report(tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_container_report_orch
    ON container_report(orchestration_id);


-- ============================================================================
-- container_input_transformed — ETL output (Stage 1)
-- ============================================================================

CREATE TABLE IF NOT EXISTS container_input_transformed (
    id                  BIGSERIAL       PRIMARY KEY,
    container_scan_id   UUID            NOT NULL,
    tenant_id           VARCHAR(255)    NOT NULL,
    orchestration_id    UUID            NOT NULL,

    -- Image identity
    image_id            VARCHAR(255)    NOT NULL,   -- digest or registry+tag
    image_uri           TEXT,                       -- full registry URI
    registry_type       VARCHAR(50),                -- ecr, dockerhub, acr, gcr, ocir
    repository          VARCHAR(500),
    tag                 VARCHAR(255),
    digest              VARCHAR(255),

    -- Image metadata
    os_family           VARCHAR(50),
    os_version          VARCHAR(100),
    total_layers        INTEGER         DEFAULT 0,
    total_packages      INTEGER         DEFAULT 0,
    last_pushed_at      TIMESTAMP WITH TIME ZONE,

    -- CVE summary — DEPRECATED: CVE scanning centralized in Vulnerability Engine.
    -- These columns are retained for backward compatibility but are no longer
    -- populated by the container ETL. Query vulnerability_findings instead.
    critical_cve_count  INTEGER         DEFAULT 0,
    high_cve_count      INTEGER         DEFAULT 0,
    medium_cve_count    INTEGER         DEFAULT 0,
    low_cve_count       INTEGER         DEFAULT 0,
    cves                JSONB           DEFAULT '[]'::jsonb,

    -- K8s runtime context (null if not running)
    is_running          BOOLEAN         DEFAULT FALSE,
    cluster_name        VARCHAR(255),
    namespace           VARCHAR(255),
    pod_name            VARCHAR(255),
    node_name           VARCHAR(255),
    resource_kind       VARCHAR(50),     -- Pod, Deployment, DaemonSet, StatefulSet
    resource_name       VARCHAR(255),

    -- K8s security context
    security_context    JSONB           DEFAULT '{}'::jsonb,  -- full securityContext
    run_as_non_root     BOOLEAN,
    privileged          BOOLEAN,
    host_network        BOOLEAN,
    host_pid            BOOLEAN,
    allow_privilege_escalation BOOLEAN,
    read_only_root_fs   BOOLEAN,
    service_account     VARCHAR(255),
    resource_limits     JSONB           DEFAULT '{}'::jsonb,  -- {cpu, memory}

    -- ECR posture (null if not ECR)
    scan_on_push        BOOLEAN,
    tag_mutability      VARCHAR(50),     -- IMMUTABLE or MUTABLE
    encryption_type     VARCHAR(50),     -- AES256 or KMS

    -- Raw data
    raw_trivy_output    JSONB,
    raw_discovery       JSONB,

    created_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

COMMENT ON TABLE container_input_transformed IS 'ETL Stage 1 output: enriched image + pod data ready for rule evaluation';

CREATE INDEX IF NOT EXISTS idx_cit_scan
    ON container_input_transformed(container_scan_id, tenant_id);

CREATE INDEX IF NOT EXISTS idx_cit_image
    ON container_input_transformed(image_id);

CREATE INDEX IF NOT EXISTS idx_cit_running
    ON container_input_transformed(is_running)
    WHERE is_running = TRUE;


-- ============================================================================
-- container_rules — rule definitions (Stage 2 input)
-- ============================================================================

CREATE TABLE IF NOT EXISTS container_rules (
    id                  SERIAL          PRIMARY KEY,
    rule_id             VARCHAR(255)    NOT NULL UNIQUE,
    title               TEXT            NOT NULL,
    description         TEXT,
    category            VARCHAR(100)    NOT NULL,    -- k8s_security, ecr_posture (cve_severity removed)
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

COMMENT ON TABLE container_rules IS 'Container security rules with JSONB conditions (13 initial rules)';

CREATE INDEX IF NOT EXISTS idx_container_rules_active
    ON container_rules(is_active, category);


-- ============================================================================
-- container_findings — rule evaluation results (Stage 2 output)
-- ============================================================================

CREATE TABLE IF NOT EXISTS container_findings (
    finding_id          UUID            PRIMARY KEY DEFAULT uuid_generate_v4(),
    container_scan_id   UUID            NOT NULL,
    tenant_id           VARCHAR(255)    NOT NULL,
    orchestration_id    UUID            NOT NULL,

    -- Resource
    resource_id         VARCHAR(500),
    resource_type       VARCHAR(100),
    resource_arn        TEXT,
    image_id            VARCHAR(255),

    -- Rule
    rule_id             VARCHAR(255)    NOT NULL,
    result              VARCHAR(20)     NOT NULL,    -- PASS, FAIL, SKIP, ERROR
    severity            VARCHAR(20)     NOT NULL DEFAULT 'info',
    title               TEXT,
    description         TEXT,

    -- CVE-specific — DEPRECATED: CVE rules removed, columns retained for backward compat
    cve_id              VARCHAR(50),
    package_name        VARCHAR(255),
    package_version     VARCHAR(100),
    cvss_score          NUMERIC(4,2),
    epss_score          NUMERIC(6,5),
    is_in_kev           BOOLEAN         DEFAULT FALSE,
    exploit_maturity    VARCHAR(50),
    fixed_version       VARCHAR(100),

    -- Evidence
    evidence            JSONB           DEFAULT '{}'::jsonb,
    remediation         TEXT,

    -- Context
    account_id          VARCHAR(255),
    region              VARCHAR(50),
    csp                 VARCHAR(50)     DEFAULT 'aws',
    is_active           BOOLEAN         DEFAULT TRUE,

    created_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

COMMENT ON TABLE container_findings IS 'Per-rule per-resource evaluation results (PASS/FAIL/SKIP/ERROR)';

CREATE INDEX IF NOT EXISTS idx_cf_scan_rule
    ON container_findings(container_scan_id, rule_id);

CREATE INDEX IF NOT EXISTS idx_cf_tenant
    ON container_findings(tenant_id, orchestration_id);

CREATE INDEX IF NOT EXISTS idx_cf_result
    ON container_findings(result, severity);

CREATE INDEX IF NOT EXISTS idx_cf_image
    ON container_findings(image_id);

CREATE INDEX IF NOT EXISTS idx_cf_cve
    ON container_findings(cve_id)
    WHERE cve_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_cf_critical
    ON container_findings(container_scan_id)
    WHERE severity = 'critical' AND result = 'FAIL';


-- ============================================================================
-- container_images — denormalized image inventory (Stage 3)
-- ============================================================================

CREATE TABLE IF NOT EXISTS container_images (
    image_id            UUID            PRIMARY KEY DEFAULT uuid_generate_v4(),
    container_scan_id   UUID            NOT NULL,
    tenant_id           VARCHAR(255)    NOT NULL,

    -- Image identity
    registry_type       VARCHAR(50),
    registry_url        TEXT,
    repository          VARCHAR(500),
    tags                JSONB           DEFAULT '[]'::jsonb,
    digest              VARCHAR(255),

    -- Image metadata
    base_image          VARCHAR(500),
    os_family           VARCHAR(50),
    os_version          VARCHAR(100),
    total_layers        INTEGER         DEFAULT 0,
    total_packages      INTEGER         DEFAULT 0,

    -- Runtime
    is_running          BOOLEAN         DEFAULT FALSE,
    running_in          JSONB           DEFAULT '[]'::jsonb,  -- [{cluster, namespace, pod}]

    -- Risk
    critical_cve_count  INTEGER         DEFAULT 0,
    high_cve_count      INTEGER         DEFAULT 0,
    finding_count       INTEGER         DEFAULT 0,
    risk_score          INTEGER         DEFAULT 0,    -- 0-100

    -- Timing
    last_pushed_at      TIMESTAMP WITH TIME ZONE,
    scanned_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    created_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

COMMENT ON TABLE container_images IS 'Denormalized image inventory with risk scores';

CREATE INDEX IF NOT EXISTS idx_ci_scan
    ON container_images(container_scan_id, tenant_id);

CREATE INDEX IF NOT EXISTS idx_ci_risk
    ON container_images(risk_score DESC);


-- ============================================================================
-- container_sbom — package inventory per image (Stage 3)
-- ============================================================================

CREATE TABLE IF NOT EXISTS container_sbom (
    id                  UUID            PRIMARY KEY DEFAULT uuid_generate_v4(),
    container_scan_id   UUID            NOT NULL,
    image_id            VARCHAR(255)    NOT NULL,
    tenant_id           VARCHAR(255)    NOT NULL,

    -- Package identity
    package_name        VARCHAR(500)    NOT NULL,
    package_version     VARCHAR(100),
    package_type        VARCHAR(50),     -- deb, rpm, npm, pip, go, jar, apk, gem
    license             VARCHAR(255),
    purl                TEXT,            -- Package URL (pkg:deb/ubuntu/libssl3@3.0.2)
    cpe                 TEXT,            -- CPE identifier

    -- Flags
    is_direct_dep       BOOLEAN         DEFAULT TRUE,
    has_vulnerabilities BOOLEAN         DEFAULT FALSE,
    vulnerability_count INTEGER         DEFAULT 0,

    created_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

COMMENT ON TABLE container_sbom IS 'SBOM: per-package per-image inventory from Trivy output';

CREATE INDEX IF NOT EXISTS idx_sbom_image
    ON container_sbom(image_id, container_scan_id);

CREATE INDEX IF NOT EXISTS idx_sbom_vuln
    ON container_sbom(has_vulnerabilities)
    WHERE has_vulnerabilities = TRUE;

CREATE INDEX IF NOT EXISTS idx_sbom_package
    ON container_sbom(package_name, package_version);


-- ============================================================================
-- k8s_policy_findings — K8s security context violations (Stage 3)
-- ============================================================================

CREATE TABLE IF NOT EXISTS k8s_policy_findings (
    finding_id          UUID            PRIMARY KEY DEFAULT uuid_generate_v4(),
    container_scan_id   UUID            NOT NULL,
    tenant_id           VARCHAR(255)    NOT NULL,
    orchestration_id    UUID            NOT NULL,

    -- K8s identity
    cluster_id          VARCHAR(255),
    cluster_name        VARCHAR(255),
    namespace           VARCHAR(255),
    resource_kind       VARCHAR(50)     NOT NULL,    -- Pod, Deployment, DaemonSet, StatefulSet
    resource_name       VARCHAR(255)    NOT NULL,
    container_name      VARCHAR(255),

    -- Rule
    rule_id             VARCHAR(255)    NOT NULL,
    severity            VARCHAR(20)     NOT NULL,
    evidence            JSONB           DEFAULT '{}'::jsonb,
    remediation         TEXT,

    created_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

COMMENT ON TABLE k8s_policy_findings IS 'K8s security context violations extracted from container_findings';

CREATE INDEX IF NOT EXISTS idx_k8s_cluster
    ON k8s_policy_findings(cluster_name, namespace);

CREATE INDEX IF NOT EXISTS idx_k8s_scan
    ON k8s_policy_findings(container_scan_id, tenant_id);

CREATE INDEX IF NOT EXISTS idx_k8s_severity
    ON k8s_policy_findings(severity)
    WHERE severity IN ('critical', 'high');
