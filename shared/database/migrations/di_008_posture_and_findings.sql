-- =============================================================================
-- Migration: di_008_posture_and_findings
-- Database:  threat_engine_di
-- Purpose:   Move security_findings and resource_security_posture from
--            threat_engine_inventory into the DI DB so the asset intelligence
--            layer is consolidated in one place.
--
--            Incorporates ALL columns from migrations 023–028 + apisec_002/003
--            + 20260519_rsp_epss_max_widen applied to threat_engine_inventory.
--
-- Run on:    threat_engine_di
-- Safe to re-run: Yes (IF NOT EXISTS guards throughout)
-- =============================================================================

BEGIN;

-- =============================================================================
-- TABLE: security_findings
-- Identical schema to the one in threat_engine_inventory (025_security_findings).
-- =============================================================================
CREATE TABLE IF NOT EXISTS security_findings (
    finding_id          UUID            DEFAULT gen_random_uuid() PRIMARY KEY,

    source_engine       VARCHAR(30)     NOT NULL,
    source_finding_id   VARCHAR(128)    NOT NULL,

    resource_uid        VARCHAR(512)    NOT NULL,
    scan_run_id         UUID            NOT NULL,
    tenant_id           VARCHAR(255)    NOT NULL,
    account_id          VARCHAR(512),
    provider            VARCHAR(30),
    resource_type       VARCHAR(128),

    finding_type        VARCHAR(30)     NOT NULL,
    severity            VARCHAR(20)     NOT NULL,
    rule_id             VARCHAR(128),
    title               VARCHAR(512),
    description         TEXT,
    epss_score          NUMERIC(5,4),
    cvss_score          NUMERIC(4,1),
    in_kev              BOOLEAN         NOT NULL DEFAULT FALSE,

    mitre_technique_id  VARCHAR(20),
    mitre_tactic        VARCHAR(50),
    detail              JSONB,

    status              VARCHAR(20)     NOT NULL DEFAULT 'open',
    first_seen_at       TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    last_seen_at        TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    UNIQUE (source_engine, source_finding_id, tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_sf_tenant_scan   ON security_findings (tenant_id, scan_run_id);
CREATE INDEX IF NOT EXISTS idx_sf_resource       ON security_findings (tenant_id, resource_uid);
CREATE INDEX IF NOT EXISTS idx_sf_severity       ON security_findings (tenant_id, severity);
CREATE INDEX IF NOT EXISTS idx_sf_type           ON security_findings (tenant_id, finding_type);
CREATE INDEX IF NOT EXISTS idx_sf_engine         ON security_findings (tenant_id, source_engine);
CREATE INDEX IF NOT EXISTS idx_sf_open           ON security_findings (tenant_id, resource_uid) WHERE status = 'open';
CREATE INDEX IF NOT EXISTS idx_sf_epss           ON security_findings (tenant_id, epss_score DESC NULLS LAST) WHERE epss_score IS NOT NULL;

CREATE OR REPLACE FUNCTION sf_set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_sf_updated_at ON security_findings;
CREATE TRIGGER trg_sf_updated_at
    BEFORE UPDATE ON security_findings
    FOR EACH ROW EXECUTE FUNCTION sf_set_updated_at();

-- =============================================================================
-- TABLE: resource_security_posture
-- Incorporates ALL columns from 023 + 024 + 027 + apisec_002 + apisec_003 +
-- 028_active_cdr_actor_admin_role + 20260519_rsp_epss_max_widen.
-- epss_max uses NUMERIC(4,1) (widened from 5,4 per 20260519 migration).
-- =============================================================================
CREATE TABLE IF NOT EXISTS resource_security_posture (
    -- Identity
    posture_id              UUID            DEFAULT gen_random_uuid() PRIMARY KEY,
    tenant_id               VARCHAR(255)    NOT NULL,
    scan_run_id             UUID            NOT NULL,
    account_id              VARCHAR(512)    NOT NULL,
    provider                VARCHAR(50)     NOT NULL,
    region                  VARCHAR(100),
    resource_uid            VARCHAR(1024)   NOT NULL,
    resource_type           VARCHAR(255)    NOT NULL,
    resource_name           VARCHAR(512),

    -- Network (network-security engine)
    is_internet_exposed             BOOLEAN     NOT NULL DEFAULT FALSE,
    is_in_private_subnet            BOOLEAN     NOT NULL DEFAULT FALSE,
    has_waf                         BOOLEAN     NOT NULL DEFAULT FALSE,
    has_load_balancer               BOOLEAN     NOT NULL DEFAULT FALSE,
    network_exposure_score          SMALLINT    NOT NULL DEFAULT 0,
    network_detail                  JSONB,

    -- IAM (iam engine)
    has_attached_role               BOOLEAN     NOT NULL DEFAULT FALSE,
    role_has_wildcard_policy        BOOLEAN     NOT NULL DEFAULT FALSE,
    role_allows_cross_account       BOOLEAN     NOT NULL DEFAULT FALSE,
    mfa_enforced                    BOOLEAN     NOT NULL DEFAULT FALSE,
    has_permission_boundary         BOOLEAN     NOT NULL DEFAULT FALSE,
    is_admin_role                   BOOLEAN     NOT NULL DEFAULT FALSE,
    can_access_pii                  BOOLEAN     NOT NULL DEFAULT FALSE,
    iam_detail                      JSONB,

    -- Encryption (encryption engine)
    is_encrypted_at_rest            BOOLEAN     NOT NULL DEFAULT FALSE,
    is_encrypted_in_transit         BOOLEAN     NOT NULL DEFAULT FALSE,
    has_kms_managed_key             BOOLEAN     NOT NULL DEFAULT FALSE,
    has_valid_certificate           BOOLEAN     NOT NULL DEFAULT FALSE,
    cert_days_remaining             INTEGER     NOT NULL DEFAULT 0,
    tls_version                     VARCHAR(20),

    -- Data (datasec engine)
    data_classification             VARCHAR(50)  NOT NULL DEFAULT 'unknown',
    reachable_pii_store_count       INTEGER      NOT NULL DEFAULT 0,
    has_exfil_path                  BOOLEAN      NOT NULL DEFAULT FALSE,
    secrets_in_env_vars             BOOLEAN      NOT NULL DEFAULT FALSE,

    -- Database (dbsec engine)
    connected_db_count              INTEGER      NOT NULL DEFAULT 0,
    db_auth_type                    VARCHAR(50),
    connected_db_uids               JSONB,

    -- CDR (cdr engine)
    has_active_cdr_actor            BOOLEAN      NOT NULL DEFAULT FALSE,
    cdr_actor_count                 INTEGER      NOT NULL DEFAULT 0,
    cdr_last_seen_at                TIMESTAMPTZ,
    cdr_ttps                        JSONB,

    -- Attack path signals (attack-path engine)
    is_crown_jewel                  BOOLEAN      NOT NULL DEFAULT FALSE,
    is_on_attack_path               BOOLEAN      NOT NULL DEFAULT FALSE,
    attack_path_count               INTEGER      NOT NULL DEFAULT 0,
    is_choke_point                  BOOLEAN      NOT NULL DEFAULT FALSE,
    paths_blocked_if_fixed          INTEGER      NOT NULL DEFAULT 0,
    highest_path_score              SMALLINT     NOT NULL DEFAULT 0,
    highest_path_severity           VARCHAR(20),
    crown_jewel_type                VARCHAR(50),

    -- Composite scoring (attack-path engine)
    blast_radius_count              INTEGER      NOT NULL DEFAULT 0,
    overall_posture_score           SMALLINT     NOT NULL DEFAULT 0,
    posture_vector                  VARCHAR(50),

    -- Container Security (container-security engine) — migration 024
    has_privileged_container        BOOLEAN      NOT NULL DEFAULT FALSE,
    image_has_critical_cve          BOOLEAN      NOT NULL DEFAULT FALSE,
    k8s_rbac_overpermissive         BOOLEAN      NOT NULL DEFAULT FALSE,
    container_network_policy_missing BOOLEAN     NOT NULL DEFAULT FALSE,
    container_security_score        SMALLINT     NOT NULL DEFAULT 0,

    -- Vulnerability (vulnerability engine) — migration 024
    -- epss_max NUMERIC(4,1) per 20260519_rsp_epss_max_widen.sql
    vuln_critical_count             INTEGER      NOT NULL DEFAULT 0,
    vuln_high_count                 INTEGER      NOT NULL DEFAULT 0,
    has_known_exploit               BOOLEAN      NOT NULL DEFAULT FALSE,
    epss_max                        NUMERIC(4,1) NOT NULL DEFAULT 0,

    -- AI Security (ai-security engine) — migration 024
    has_shadow_ai_service           BOOLEAN      NOT NULL DEFAULT FALSE,
    ai_model_publicly_accessible    BOOLEAN      NOT NULL DEFAULT FALSE,
    ai_training_data_has_pii        BOOLEAN      NOT NULL DEFAULT FALSE,

    -- Cross-engine composite flags (attack-path engine) — migration 024
    unencrypted_pii_store           BOOLEAN      NOT NULL DEFAULT FALSE,
    internet_exposed_with_pii       BOOLEAN      NOT NULL DEFAULT FALSE,
    admin_role_without_mfa          BOOLEAN      NOT NULL DEFAULT FALSE,
    exploitable_exposed_resource    BOOLEAN      NOT NULL DEFAULT FALSE,
    cdr_active_on_unencrypted       BOOLEAN      NOT NULL DEFAULT FALSE,

    -- Depth columns (IAM escalation + container) — migration 027
    has_priv_escalation_path        BOOLEAN      NOT NULL DEFAULT FALSE,
    priv_escalation_hop_count       SMALLINT     NOT NULL DEFAULT 0,
    priv_escalation_cdr_confirmed   BOOLEAN      NOT NULL DEFAULT FALSE,
    ecr_scan_on_push_enabled        BOOLEAN      NOT NULL DEFAULT TRUE,
    eks_node_ami_outdated           BOOLEAN      NOT NULL DEFAULT FALSE,

    -- API Security (api-security engine) — migration apisec_002
    api_auth_type                   VARCHAR(50),
    api_has_waf                     BOOLEAN      NOT NULL DEFAULT FALSE,
    api_has_rate_limit              BOOLEAN      NOT NULL DEFAULT FALSE,
    api_publicly_accessible         BOOLEAN      NOT NULL DEFAULT FALSE,
    api_deprecated_version_active   BOOLEAN      NOT NULL DEFAULT FALSE,
    api_security_score              SMALLINT     NOT NULL DEFAULT 0,
    api_detail                      JSONB,

    -- API composite flags (attack-path engine) — migration apisec_003
    api_public_no_waf               BOOLEAN      DEFAULT FALSE,
    api_public_no_auth              BOOLEAN      DEFAULT FALSE,

    -- CDR actor on admin role (attack-path engine) — migration 028
    active_cdr_actor_on_admin_role  BOOLEAN      NOT NULL DEFAULT FALSE,

    -- Timestamps
    created_at                      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at                      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_rsp_resource_tenant
        UNIQUE (resource_uid, tenant_id)
);

-- Primary lookup
CREATE INDEX IF NOT EXISTS idx_rsp_tenant_scan      ON resource_security_posture (tenant_id, scan_run_id);
CREATE INDEX IF NOT EXISTS idx_rsp_resource_uid     ON resource_security_posture (resource_uid, tenant_id);

-- Attack path filters
CREATE INDEX IF NOT EXISTS idx_rsp_crown_jewel      ON resource_security_posture (tenant_id, scan_run_id) WHERE is_crown_jewel = TRUE;
CREATE INDEX IF NOT EXISTS idx_rsp_attack_path      ON resource_security_posture (tenant_id, scan_run_id) WHERE is_on_attack_path = TRUE;
CREATE INDEX IF NOT EXISTS idx_rsp_choke_point      ON resource_security_posture (tenant_id, paths_blocked_if_fixed DESC) WHERE is_choke_point = TRUE;

-- Depth column indexes
CREATE INDEX IF NOT EXISTS idx_rsp_priv_escalation      ON resource_security_posture (tenant_id, scan_run_id) WHERE has_priv_escalation_path = TRUE;
CREATE INDEX IF NOT EXISTS idx_rsp_priv_escalation_cdr  ON resource_security_posture (tenant_id, scan_run_id) WHERE priv_escalation_cdr_confirmed = TRUE;
CREATE INDEX IF NOT EXISTS idx_rsp_ecr_no_scan          ON resource_security_posture (tenant_id, scan_run_id) WHERE ecr_scan_on_push_enabled = FALSE;
CREATE INDEX IF NOT EXISTS idx_rsp_eks_ami_outdated     ON resource_security_posture (tenant_id, scan_run_id) WHERE eks_node_ami_outdated = TRUE;

-- Boolean flag indexes
CREATE INDEX IF NOT EXISTS idx_rsp_privileged_container ON resource_security_posture (tenant_id, scan_run_id) WHERE has_privileged_container = TRUE;
CREATE INDEX IF NOT EXISTS idx_rsp_known_exploit        ON resource_security_posture (tenant_id, scan_run_id) WHERE has_known_exploit = TRUE;
CREATE INDEX IF NOT EXISTS idx_rsp_unencrypted_pii      ON resource_security_posture (tenant_id, scan_run_id) WHERE unencrypted_pii_store = TRUE;
CREATE INDEX IF NOT EXISTS idx_rsp_internet_pii         ON resource_security_posture (tenant_id, scan_run_id) WHERE internet_exposed_with_pii = TRUE;
CREATE INDEX IF NOT EXISTS idx_rsp_admin_no_mfa         ON resource_security_posture (tenant_id, scan_run_id) WHERE admin_role_without_mfa = TRUE;

-- API security indexes
CREATE INDEX IF NOT EXISTS idx_rsp_api_public_nowaf ON resource_security_posture (tenant_id, scan_run_id) WHERE api_publicly_accessible = TRUE AND api_has_waf = FALSE;
CREATE INDEX IF NOT EXISTS idx_rsp_api_score        ON resource_security_posture (tenant_id, api_security_score) WHERE api_security_score IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_rsp_api_public_no_waf  ON resource_security_posture (tenant_id, scan_run_id) WHERE api_public_no_waf = TRUE;
CREATE INDEX IF NOT EXISTS idx_rsp_api_public_no_auth ON resource_security_posture (tenant_id, scan_run_id) WHERE api_public_no_auth = TRUE;
CREATE INDEX IF NOT EXISTS idx_rsp_cdr_admin_role     ON resource_security_posture (tenant_id, active_cdr_actor_on_admin_role) WHERE active_cdr_actor_on_admin_role = TRUE;

-- Updated_at trigger
CREATE OR REPLACE FUNCTION rsp_set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'trg_rsp_updated_at'
          AND tgrelid = 'resource_security_posture'::regclass
    ) THEN
        CREATE TRIGGER trg_rsp_updated_at
            BEFORE UPDATE ON resource_security_posture
            FOR EACH ROW EXECUTE FUNCTION rsp_set_updated_at();
    END IF;
END;
$$;

COMMIT;

DO $$ BEGIN RAISE NOTICE 'MIGRATION COMPLETE: di_008_posture_and_findings'; END $$;
