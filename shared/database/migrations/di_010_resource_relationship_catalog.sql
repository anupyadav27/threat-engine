-- di_010: resource_relationship_catalog — data-driven infrastructure attachment rules
-- Written to threat_engine_di. Drives catalog_relationship_writer.py in DI engine.
-- One row per (csp, source_resource_type, relation_type, field_path) combination.
-- Seeded by: catalog/relationships/upload_relationship_catalog.py

BEGIN;

CREATE TABLE IF NOT EXISTS resource_relationship_catalog (
    id                    BIGSERIAL PRIMARY KEY,
    csp                   VARCHAR(50)  NOT NULL,   -- aws | azure | gcp | oci | alicloud | ibm | k8s
    source_resource_type  VARCHAR(200) NOT NULL,   -- e.g. ec2.instance
    target_resource_type  VARCHAR(200) NOT NULL,   -- e.g. ec2.volume
    relation_type         VARCHAR(100) NOT NULL,   -- ATTACHED_TO | MOUNTED_BY | ROUTES_TO ...
    relationship_category VARCHAR(50)  NOT NULL,   -- infrastructure | resource_policy | iam_policy
    field_path            TEXT         NOT NULL,
    -- path in emitted_fields to target identifier.
    -- For field_ref:       "IamInstanceProfile.Arn"
    -- For array_field_ref: "BlockDeviceMappings[*].Ebs.VolumeId"
    field_path_type       VARCHAR(50)  NOT NULL DEFAULT 'field_ref',
    -- field_ref | array_field_ref | policy_json
    target_identifier_field VARCHAR(200),
    -- final leaf field to extract from traversed path (used when field_path ends at an object)
    policy_principal_key  VARCHAR(200),
    -- for policy_json type: which Principal key to read (AWS, Service, Federated)
    policy_effect_filter  VARCHAR(20),
    -- Allow | Deny | NULL (both)
    attack_path_category  VARCHAR(50),
    -- lateral_movement | privilege_escalation | data_access | data_exfil | internet_exposure
    description           TEXT,
    is_active             BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at            TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at            TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT uq_rrc_rule UNIQUE (csp, source_resource_type, relation_type, field_path)
);

CREATE INDEX IF NOT EXISTS idx_rrc_csp_active
    ON resource_relationship_catalog (csp, is_active, relationship_category);

CREATE INDEX IF NOT EXISTS idx_rrc_source_type
    ON resource_relationship_catalog (source_resource_type, csp)
    WHERE is_active = TRUE;

COMMIT;
