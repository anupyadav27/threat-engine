-- ============================================================================
-- Schema Reference: resource_security_posture
-- Database:  threat_engine_inventory
-- Source:    migrations/023_resource_security_posture.sql (apply that file)
--
-- Purpose: Central merge table for all engine security signals per resource
--          per scan. Written by: IAM, network-security, datasec, dbsec, CDR,
--          and attack-path engines. Read by: attack-path engine, risk engine,
--          BFF asset-detail view.
--
-- Upsert pattern (all engine writers must use this):
--   INSERT INTO resource_security_posture (...)
--   VALUES (...)
--   ON CONFLICT (resource_uid, scan_run_id, tenant_id)
--   DO UPDATE SET
--     <dimension_cols> = EXCLUDED.<dimension_cols>,
--     updated_at = NOW();
-- ============================================================================

-- identity
posture_id              UUID            PK DEFAULT gen_random_uuid()
tenant_id               VARCHAR(255)    NOT NULL
scan_run_id             UUID            NOT NULL
account_id              VARCHAR(512)    NOT NULL
provider                VARCHAR(50)     NOT NULL    -- aws/azure/gcp/oci/alicloud/k8s
region                  VARCHAR(100)
resource_uid            VARCHAR(1024)   NOT NULL
resource_type           VARCHAR(255)    NOT NULL
resource_name           VARCHAR(512)

-- network dimension (network-security engine)
is_internet_exposed             BOOLEAN     DEFAULT FALSE NOT NULL
is_in_private_subnet            BOOLEAN     DEFAULT FALSE NOT NULL
has_waf                         BOOLEAN     DEFAULT FALSE NOT NULL
has_load_balancer               BOOLEAN     DEFAULT FALSE NOT NULL
network_exposure_score          SMALLINT    DEFAULT 0 NOT NULL     -- 0-100
network_detail                  JSONB       -- {sg_rules, open_ports, vpc_id, nacl_violations}

-- IAM dimension (IAM engine)
has_attached_role               BOOLEAN     DEFAULT FALSE NOT NULL
role_has_wildcard_policy        BOOLEAN     DEFAULT FALSE NOT NULL
role_allows_cross_account       BOOLEAN     DEFAULT FALSE NOT NULL
mfa_enforced                    BOOLEAN     DEFAULT FALSE NOT NULL
has_permission_boundary         BOOLEAN     DEFAULT FALSE NOT NULL
is_admin_role                   BOOLEAN     DEFAULT FALSE NOT NULL
can_access_pii                  BOOLEAN     DEFAULT FALSE NOT NULL
iam_detail                      JSONB       -- {role_arn, policy_arns, boundary_arn, wildcard_actions}

-- encryption dimension (encryption engine)
is_encrypted_at_rest            BOOLEAN     DEFAULT FALSE NOT NULL
is_encrypted_in_transit         BOOLEAN     DEFAULT FALSE NOT NULL
has_kms_managed_key             BOOLEAN     DEFAULT FALSE NOT NULL
has_valid_certificate           BOOLEAN     DEFAULT FALSE NOT NULL
cert_days_remaining             INTEGER     DEFAULT 0 NOT NULL
tls_version                     VARCHAR(20)                        -- TLSv1.2 / TLSv1.3 / null

-- data dimension (datasec engine)
data_classification             VARCHAR(50) DEFAULT 'unknown' NOT NULL
-- values: unknown / public / internal / confidential / restricted / pii / phi / pci
reachable_pii_store_count       INTEGER     DEFAULT 0 NOT NULL
has_exfil_path                  BOOLEAN     DEFAULT FALSE NOT NULL
secrets_in_env_vars             BOOLEAN     DEFAULT FALSE NOT NULL

-- database dimension (dbsec engine)
connected_db_count              INTEGER     DEFAULT 0 NOT NULL
db_auth_type                    VARCHAR(50)                        -- iam / password / cert / null
connected_db_uids               JSONB                              -- array of resource_uids

-- CDR dimension (CDR engine)
has_active_cdr_actor            BOOLEAN     DEFAULT FALSE NOT NULL
cdr_actor_count                 INTEGER     DEFAULT 0 NOT NULL
cdr_last_seen_at                TIMESTAMPTZ
cdr_ttps                        JSONB                              -- array of MITRE technique IDs

-- attack path signals (attack-path engine)
is_crown_jewel                  BOOLEAN     DEFAULT FALSE NOT NULL
is_on_attack_path               BOOLEAN     DEFAULT FALSE NOT NULL
attack_path_count               INTEGER     DEFAULT 0 NOT NULL
is_choke_point                  BOOLEAN     DEFAULT FALSE NOT NULL
paths_blocked_if_fixed          INTEGER     DEFAULT 0 NOT NULL
highest_path_score              SMALLINT    DEFAULT 0 NOT NULL     -- 0-100
highest_path_severity           VARCHAR(20)                        -- critical/high/medium/low
crown_jewel_type                VARCHAR(50)
-- values: storage / secrets / admin_role / k8s_api / database / ai_endpoint / compute_with_pii

-- composite scoring helpers (attack-path engine)
blast_radius_count              INTEGER     DEFAULT 0 NOT NULL
overall_posture_score           SMALLINT    DEFAULT 0 NOT NULL     -- 0-100
posture_vector                  VARCHAR(50)                        -- e.g. "N:H/I:M/E:L/D:C/DB:H"

-- timestamps
created_at                      TIMESTAMPTZ DEFAULT NOW() NOT NULL
updated_at                      TIMESTAMPTZ DEFAULT NOW() NOT NULL

-- constraints
UNIQUE (resource_uid, scan_run_id, tenant_id)

-- indexes
idx_rsp_tenant_scan        ON (tenant_id, scan_run_id)
idx_rsp_resource_uid       ON (resource_uid, tenant_id)
idx_rsp_crown_jewel        ON (tenant_id, scan_run_id) WHERE is_crown_jewel = TRUE
idx_rsp_attack_path        ON (tenant_id, scan_run_id) WHERE is_on_attack_path = TRUE
idx_rsp_choke_point        ON (tenant_id, paths_blocked_if_fixed DESC) WHERE is_choke_point = TRUE
