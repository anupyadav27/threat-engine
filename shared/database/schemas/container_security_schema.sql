-- =============================================================================
-- Container Security Engine Schema (v2 — new standardized engine)
-- Database: threat_engine_container_security
-- Port: 8008 | Layer 3 (post-threat, parallel with compliance/iam/datasec)
-- =============================================================================
-- Purpose: Unified container & K8s security posture — EKS/ECS/ECR cluster
--          security, workload security, image security, RBAC, network policies.
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id   VARCHAR(255) PRIMARY KEY,
    tenant_name VARCHAR(255),
    created_at  TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- container_sec_report — Scan-level summary
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS container_sec_report (
    scan_run_id             VARCHAR(255) PRIMARY KEY,
    tenant_id               VARCHAR(255) NOT NULL,
    account_id              VARCHAR(255),
    provider                VARCHAR(50) NOT NULL DEFAULT 'aws',
    status                  VARCHAR(50) NOT NULL DEFAULT 'running',
    error_message           TEXT,

    -- Posture scores (0-100)
    posture_score           INTEGER DEFAULT 0,
    cluster_security_score  INTEGER DEFAULT 0,
    workload_security_score INTEGER DEFAULT 0,
    image_security_score    INTEGER DEFAULT 0,
    network_exposure_score  INTEGER DEFAULT 0,
    rbac_access_score       INTEGER DEFAULT 0,
    runtime_audit_score     INTEGER DEFAULT 0,

    -- Counts
    total_clusters              INTEGER DEFAULT 0,
    total_containers            INTEGER DEFAULT 0,
    total_workloads             INTEGER DEFAULT 0,
    total_images                INTEGER DEFAULT 0,
    public_clusters             INTEGER DEFAULT 0,
    total_findings              INTEGER DEFAULT 0,
    critical_findings           INTEGER DEFAULT 0,
    high_findings               INTEGER DEFAULT 0,
    medium_findings             INTEGER DEFAULT 0,
    low_findings                INTEGER DEFAULT 0,
    pass_count                  INTEGER DEFAULT 0,
    fail_count                  INTEGER DEFAULT 0,
    privileged_container_count  INTEGER DEFAULT 0,  -- containers running with elevated privileges

    -- Breakdowns
    severity_breakdown      JSONB DEFAULT '{}'::jsonb,
    service_breakdown       JSONB DEFAULT '{}'::jsonb,
    domain_breakdown        JSONB DEFAULT '{}'::jsonb,
    findings_by_service     JSONB DEFAULT '{}'::jsonb,
    findings_by_domain      JSONB DEFAULT '{}'::jsonb,
    report_data             JSONB DEFAULT '{}'::jsonb,

    started_at              TIMESTAMP WITH TIME ZONE,
    completed_at            TIMESTAMP WITH TIME ZONE,
    scan_duration_ms        INTEGER,
    generated_at            TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT fk_csec_report_tenant
        FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- -----------------------------------------------------------------------------
-- container_sec_findings — Per-resource container security findings
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS container_sec_findings (
    finding_id              VARCHAR(255) PRIMARY KEY,
    scan_run_id             VARCHAR(255) NOT NULL,
    tenant_id               VARCHAR(255) NOT NULL,
    account_id              VARCHAR(255),
    credential_ref          VARCHAR(255),
    credential_type         VARCHAR(100),
    provider                VARCHAR(50) NOT NULL DEFAULT 'aws',
    region                  VARCHAR(50),

    resource_uid            TEXT NOT NULL,
    resource_type           VARCHAR(100) NOT NULL,
    container_service       VARCHAR(50),        -- eks, ecs, ecr, fargate, lambda, k8s
    cluster_name            VARCHAR(255),

    security_domain         VARCHAR(50) NOT NULL, -- cluster_security, workload_security,
                                                  -- image_security, network_exposure,
                                                  -- rbac_access, runtime_audit
    severity                VARCHAR(20) NOT NULL,
    status                  VARCHAR(20) NOT NULL,
    rule_id                 VARCHAR(255),
    title                   TEXT,
    description             TEXT,
    remediation             TEXT,
    finding_data            JSONB DEFAULT '{}'::jsonb,

    first_seen_at           TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_seen_at            TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_csec_finding_tenant
        FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- -----------------------------------------------------------------------------
-- container_sec_inventory — Unified cluster/workload inventory
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS container_sec_inventory (
    id                      BIGSERIAL PRIMARY KEY,
    scan_run_id             VARCHAR(255) NOT NULL,
    tenant_id               VARCHAR(255) NOT NULL,
    account_id              VARCHAR(255),
    provider                VARCHAR(50) NOT NULL DEFAULT 'aws',
    region                  VARCHAR(50),

    resource_uid            TEXT NOT NULL,
    resource_name           VARCHAR(500),
    resource_type           VARCHAR(50) NOT NULL,   -- cluster, service, task_def, repository, function
    container_service       VARCHAR(50) NOT NULL,   -- eks, ecs, ecr, fargate, lambda
    k8s_version             VARCHAR(50),
    platform_version        VARCHAR(50),

    -- Security posture
    posture_score           INTEGER DEFAULT 0,
    endpoint_public         BOOLEAN DEFAULT FALSE,
    encryption_enabled      BOOLEAN,
    logging_enabled         BOOLEAN,
    secrets_encrypted       BOOLEAN,
    network_policy_enabled  BOOLEAN,

    total_checks            INTEGER DEFAULT 0,
    passed_checks           INTEGER DEFAULT 0,
    failed_checks           INTEGER DEFAULT 0,
    critical_checks         INTEGER DEFAULT 0,

    vpc_id                  VARCHAR(255),
    security_groups         JSONB DEFAULT '[]'::jsonb,
    check_pass_count        INTEGER DEFAULT 0,
    check_fail_count        INTEGER DEFAULT 0,
    tags                    JSONB DEFAULT '{}'::jsonb,
    raw_data                JSONB DEFAULT '{}'::jsonb,
    created_at              TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT fk_csec_inv_tenant
        FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- =============================================================================
-- INDEXES
-- =============================================================================

CREATE INDEX IF NOT EXISTS idx_csec_report_tenant ON container_sec_report(tenant_id);
CREATE INDEX IF NOT EXISTS idx_csec_report_status ON container_sec_report(status);

CREATE INDEX IF NOT EXISTS idx_csec_findings_scan ON container_sec_findings(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_csec_findings_tenant ON container_sec_findings(tenant_id);
CREATE INDEX IF NOT EXISTS idx_csec_findings_severity ON container_sec_findings(severity, status);
CREATE INDEX IF NOT EXISTS idx_csec_findings_domain ON container_sec_findings(security_domain);
CREATE INDEX IF NOT EXISTS idx_csec_findings_service ON container_sec_findings(container_service);
CREATE INDEX IF NOT EXISTS idx_csec_findings_cluster ON container_sec_findings(cluster_name);
CREATE INDEX IF NOT EXISTS idx_csec_findings_resource ON container_sec_findings(resource_uid);
CREATE INDEX IF NOT EXISTS idx_csec_findings_data_gin ON container_sec_findings USING gin(finding_data);

CREATE INDEX IF NOT EXISTS idx_csec_inv_scan ON container_sec_inventory(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_csec_inv_tenant ON container_sec_inventory(tenant_id);
CREATE INDEX IF NOT EXISTS idx_csec_inv_service ON container_sec_inventory(container_service);
CREATE INDEX IF NOT EXISTS idx_csec_inv_public ON container_sec_inventory(endpoint_public) WHERE endpoint_public = TRUE;

-- Migration: add columns missing from initial schema deploy
ALTER TABLE container_sec_report ADD COLUMN IF NOT EXISTS total_containers INTEGER DEFAULT 0;
ALTER TABLE container_sec_report ADD COLUMN IF NOT EXISTS public_clusters INTEGER DEFAULT 0;
ALTER TABLE container_sec_report ADD COLUMN IF NOT EXISTS privileged_container_count INTEGER DEFAULT 0;
ALTER TABLE container_sec_report ADD COLUMN IF NOT EXISTS severity_breakdown JSONB DEFAULT '{}'::jsonb;
ALTER TABLE container_sec_report ADD COLUMN IF NOT EXISTS service_breakdown JSONB DEFAULT '{}'::jsonb;
ALTER TABLE container_sec_report ADD COLUMN IF NOT EXISTS domain_breakdown JSONB DEFAULT '{}'::jsonb;
ALTER TABLE container_sec_inventory ADD COLUMN IF NOT EXISTS vpc_id VARCHAR(255);
ALTER TABLE container_sec_inventory ADD COLUMN IF NOT EXISTS security_groups JSONB DEFAULT '[]'::jsonb;
ALTER TABLE container_sec_inventory ADD COLUMN IF NOT EXISTS check_pass_count INTEGER DEFAULT 0;
ALTER TABLE container_sec_inventory ADD COLUMN IF NOT EXISTS check_fail_count INTEGER DEFAULT 0;

COMMENT ON TABLE container_sec_report IS 'Container security scan summary with domain-level posture scores';
COMMENT ON TABLE container_sec_findings IS 'Per-resource container/K8s security findings';
COMMENT ON TABLE container_sec_inventory IS 'Unified cluster and workload inventory';
