-- ============================================================================
-- Migration: 023_resource_security_posture
-- Database:  threat_engine_inventory
-- Purpose:   Create resource_security_posture table — the central merge point
--            for all engine security signals per resource per scan.
--
--            Each engine writes only its own dimension columns after its scan
--            step; all other columns remain at defaults until that engine runs.
--            The attack-path engine and risk engine read the merged posture.
--
-- References:
--   architecture-attack-path-engine.md §7.1 — full column specification
--   AP-P0-01 story — acceptance criteria
--   CSPM_CONSTITUTION §2 — multi-tenant, standard columns, IMMUTABLE constraints
--
-- DDL Rules applied:
--   1. tenant_id NOT NULL — enforces multi-tenant isolation
--   2. All boolean columns: DEFAULT FALSE NOT NULL — never NULL booleans
--   3. All integer counters: DEFAULT 0 NOT NULL
--   4. All timestamps: TIMESTAMPTZ
--   5. Primary key: UUID via gen_random_uuid()
--   6. Unique constraint: (resource_uid, scan_run_id, tenant_id) — one row
--      per resource per scan per tenant; upsert pattern (ON CONFLICT DO UPDATE)
--      keeps rows current without bloat
--   7. Partial indexes on boolean flags — keeps index small and query fast
-- ============================================================================

BEGIN;

-- ============================================================================
-- TABLE: resource_security_posture
-- ============================================================================
CREATE TABLE IF NOT EXISTS resource_security_posture (
    -- -------------------------------------------------------------------------
    -- Identity
    -- -------------------------------------------------------------------------
    posture_id          UUID            DEFAULT gen_random_uuid() PRIMARY KEY,
    tenant_id           VARCHAR(255)    NOT NULL,
    scan_run_id         UUID            NOT NULL,
    account_id          VARCHAR(512)    NOT NULL,
    provider            VARCHAR(50)     NOT NULL,   -- aws / azure / gcp / oci / alicloud / k8s
    region              VARCHAR(100),
    resource_uid        VARCHAR(1024)   NOT NULL,
    resource_type       VARCHAR(255)    NOT NULL,
    resource_name       VARCHAR(512),

    -- -------------------------------------------------------------------------
    -- Network dimension (written by network-security engine)
    -- -------------------------------------------------------------------------
    is_internet_exposed             BOOLEAN     NOT NULL DEFAULT FALSE,
    is_in_private_subnet            BOOLEAN     NOT NULL DEFAULT FALSE,
    has_waf                         BOOLEAN     NOT NULL DEFAULT FALSE,
    has_load_balancer               BOOLEAN     NOT NULL DEFAULT FALSE,
    network_exposure_score          SMALLINT    NOT NULL DEFAULT 0,  -- 0-100
    network_detail                  JSONB,   -- {sg_rules, open_ports, vpc_id, nacl_violations}

    -- -------------------------------------------------------------------------
    -- IAM dimension (written by IAM engine)
    -- -------------------------------------------------------------------------
    has_attached_role               BOOLEAN     NOT NULL DEFAULT FALSE,
    role_has_wildcard_policy        BOOLEAN     NOT NULL DEFAULT FALSE,
    role_allows_cross_account       BOOLEAN     NOT NULL DEFAULT FALSE,
    mfa_enforced                    BOOLEAN     NOT NULL DEFAULT FALSE,
    has_permission_boundary         BOOLEAN     NOT NULL DEFAULT FALSE,
    is_admin_role                   BOOLEAN     NOT NULL DEFAULT FALSE,
    can_access_pii                  BOOLEAN     NOT NULL DEFAULT FALSE,
    iam_detail                      JSONB,   -- {role_arn, policy_arns, boundary_arn, wildcard_actions}

    -- -------------------------------------------------------------------------
    -- Encryption dimension (written by encryption engine)
    -- -------------------------------------------------------------------------
    is_encrypted_at_rest            BOOLEAN     NOT NULL DEFAULT FALSE,
    is_encrypted_in_transit         BOOLEAN     NOT NULL DEFAULT FALSE,
    has_kms_managed_key             BOOLEAN     NOT NULL DEFAULT FALSE,
    has_valid_certificate           BOOLEAN     NOT NULL DEFAULT FALSE,
    cert_days_remaining             INTEGER     NOT NULL DEFAULT 0,
    tls_version                     VARCHAR(20),  -- TLSv1.2 / TLSv1.3 / null

    -- -------------------------------------------------------------------------
    -- Data dimension (written by datasec engine)
    -- -------------------------------------------------------------------------
    data_classification             VARCHAR(50)  NOT NULL DEFAULT 'unknown',
    -- unknown / public / internal / confidential / restricted / pii / phi / pci
    reachable_pii_store_count       INTEGER      NOT NULL DEFAULT 0,
    has_exfil_path                  BOOLEAN      NOT NULL DEFAULT FALSE,
    secrets_in_env_vars             BOOLEAN      NOT NULL DEFAULT FALSE,

    -- -------------------------------------------------------------------------
    -- Database dimension (written by dbsec engine)
    -- -------------------------------------------------------------------------
    connected_db_count              INTEGER      NOT NULL DEFAULT 0,
    db_auth_type                    VARCHAR(50),  -- iam / password / cert / null
    connected_db_uids               JSONB,        -- array of resource_uids

    -- -------------------------------------------------------------------------
    -- CDR dimension (written by CDR engine)
    -- -------------------------------------------------------------------------
    has_active_cdr_actor            BOOLEAN      NOT NULL DEFAULT FALSE,
    cdr_actor_count                 INTEGER      NOT NULL DEFAULT 0,
    cdr_last_seen_at                TIMESTAMPTZ,
    cdr_ttps                        JSONB,        -- array of MITRE technique IDs seen

    -- -------------------------------------------------------------------------
    -- Attack path signals (written by attack-path engine after its scan)
    -- -------------------------------------------------------------------------
    is_crown_jewel                  BOOLEAN      NOT NULL DEFAULT FALSE,
    is_on_attack_path               BOOLEAN      NOT NULL DEFAULT FALSE,
    attack_path_count               INTEGER      NOT NULL DEFAULT 0,
    is_choke_point                  BOOLEAN      NOT NULL DEFAULT FALSE,
    paths_blocked_if_fixed          INTEGER      NOT NULL DEFAULT 0,
    highest_path_score              SMALLINT     NOT NULL DEFAULT 0,  -- 0-100
    highest_path_severity           VARCHAR(20),  -- critical / high / medium / low
    crown_jewel_type                VARCHAR(50),  -- storage / secrets / admin_role / k8s_api / database / ai_endpoint / compute_with_pii

    -- -------------------------------------------------------------------------
    -- Composite scoring helpers (written by attack-path engine)
    -- -------------------------------------------------------------------------
    blast_radius_count              INTEGER      NOT NULL DEFAULT 0,
    overall_posture_score           SMALLINT     NOT NULL DEFAULT 0,  -- 0-100 aggregate
    posture_vector                  VARCHAR(50),  -- compact representation e.g. "N:H/I:M/E:L/D:C/DB:H"

    -- -------------------------------------------------------------------------
    -- Timestamps
    -- -------------------------------------------------------------------------
    created_at                      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at                      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    -- -------------------------------------------------------------------------
    -- Constraints
    -- -------------------------------------------------------------------------
    CONSTRAINT uq_rsp_resource_scan_tenant
        UNIQUE (resource_uid, scan_run_id, tenant_id)
);

-- ============================================================================
-- INDEXES
-- ============================================================================

-- Primary lookup: all posture rows for a tenant+scan
CREATE INDEX IF NOT EXISTS idx_rsp_tenant_scan
    ON resource_security_posture (tenant_id, scan_run_id);

-- Resource lookup across scans (asset detail panel, risk engine)
CREATE INDEX IF NOT EXISTS idx_rsp_resource_uid
    ON resource_security_posture (resource_uid, tenant_id);

-- Attack path engine reads: crown jewels are the BFS start set
CREATE INDEX IF NOT EXISTS idx_rsp_crown_jewel
    ON resource_security_posture (tenant_id, scan_run_id)
    WHERE is_crown_jewel = TRUE;

-- Attack path filter: "show only resources on an active path"
CREATE INDEX IF NOT EXISTS idx_rsp_attack_path
    ON resource_security_posture (tenant_id, scan_run_id)
    WHERE is_on_attack_path = TRUE;

-- Choke point filter: "show the top N choke points"
CREATE INDEX IF NOT EXISTS idx_rsp_choke_point
    ON resource_security_posture (tenant_id, paths_blocked_if_fixed DESC)
    WHERE is_choke_point = TRUE;

-- ============================================================================
-- TRIGGER: keep updated_at current on every UPDATE
-- ============================================================================
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

DO $$
BEGIN
    RAISE NOTICE 'MIGRATION COMPLETE: 023_resource_security_posture';
END;
$$;
