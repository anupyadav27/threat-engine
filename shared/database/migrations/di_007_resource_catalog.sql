-- di_007_resource_catalog.sql
-- Creates di_resource_catalog and di_relationship_rules in threat_engine_di.
--
-- di_resource_catalog: single source of truth for resource-type metadata.
--   • Only services/resource_types covered by active rule_discoveries are loaded.
--   • should_inventory flag removed — active state comes from rule_discoveries.is_active.
--   • uid_template / uid_source removed — those live in rule_discoveries YAML.
--   • Merges resource_inventory_identifier + service_classification columns.
--
-- di_relationship_rules: edge definitions migrated from resource_security_relationship_rules
--   in the inventory DB.  Filtered to active services only at load time.

BEGIN;

-- ── di_resource_catalog ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS di_resource_catalog (
    catalog_id          BIGSERIAL PRIMARY KEY,

    -- Identity (unique key)
    csp                 VARCHAR(32)  NOT NULL,
    service             VARCHAR(128) NOT NULL,
    resource_type       VARCHAR(256) NOT NULL,

    -- Classification (from step5)
    classification      VARCHAR(64),          -- PRIMARY_RESOURCE | OTHER_RESOURCE
    has_arn             BOOLEAN  DEFAULT FALSE,
    can_inventory_from_roots BOOLEAN DEFAULT FALSE,
    show_in_inventory   BOOLEAN  DEFAULT TRUE,
    show_in_architecture BOOLEAN DEFAULT FALSE,
    is_billable         BOOLEAN  DEFAULT FALSE,

    -- Ops catalog (from step5 — independent/dependent ops for scan dispatch)
    root_ops            JSONB    DEFAULT '[]'::jsonb,
    enrich_ops          JSONB    DEFAULT '[]'::jsonb,

    -- Engines that consume this resource type
    used_by_engines     JSONB    DEFAULT '[]'::jsonb,

    -- Service/resource categories (merged from service_classification + step5)
    category            VARCHAR(128),   -- compute | network | storage | database | security | identity | monitoring
    subcategory         VARCHAR(128),   -- vm | container | function | bucket | table | role | key ...
    asset_category      VARCHAR(128),   -- normalised cross-CSP bucket (same semantic as category)
    csp_category        VARCHAR(256),   -- CSP's own grouping label
    scope               VARCHAR(64),    -- regional | global | account | zonal
    service_model       VARCHAR(64),    -- paas | iaas | saas | serverless | managed
    managed_by          VARCHAR(64),    -- provider | customer | shared
    access_pattern      VARCHAR(64),    -- public | private | restricted | internal
    encryption_scope    VARCHAR(64),    -- none | in-transit | at-rest | both
    is_container        BOOLEAN  DEFAULT FALSE,
    container_parent    VARCHAR(256),   -- parent resource_type if this is a sub-resource
    diagram_priority    SMALLINT DEFAULT 50,
    resource_role       VARCHAR(128),   -- producer | consumer | policy | gateway | control-plane

    -- Identifier columns (used by CDR event normalizer + resource_id.py)
    canonical_type      VARCHAR(256),   -- mirrors resource_type; kept for CDR compatibility
    identifier_pattern  TEXT,           -- ARN/ID pattern, e.g. arn:aws:ec2:{region}:{account}:instance/{id}
    primary_param       VARCHAR(256),   -- primary boto3 param name for the resource ID
    identifier_type     VARCHAR(64),    -- arn | id | name | path

    -- Raw source for debugging / re-processing
    raw_catalog         JSONB,

    loaded_at           TIMESTAMPTZ DEFAULT NOW(),
    updated_at          TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE (csp, service, resource_type)
);

CREATE INDEX IF NOT EXISTS idx_di_rc_csp_service
    ON di_resource_catalog (csp, service);

CREATE INDEX IF NOT EXISTS idx_di_rc_category
    ON di_resource_catalog (csp, category);

CREATE INDEX IF NOT EXISTS idx_di_rc_classification
    ON di_resource_catalog (csp, classification)
    WHERE classification = 'PRIMARY_RESOURCE';

CREATE INDEX IF NOT EXISTS idx_di_rc_show_inventory
    ON di_resource_catalog (csp, show_in_inventory)
    WHERE show_in_inventory = TRUE;

-- ── di_relationship_rules ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS di_relationship_rules (
    rule_id             BIGSERIAL PRIMARY KEY,

    csp                 VARCHAR(32)  NOT NULL,
    service             VARCHAR(128),

    -- Edge definition
    from_resource_type  VARCHAR(256) NOT NULL,
    relation_type       VARCHAR(128) NOT NULL,  -- PLACED_IN | BELONGS_TO | ATTACHED_TO | PROTECTED_BY | INTERNET_ACCESSIBLE | ROUTES_VIA
    to_resource_type    VARCHAR(256) NOT NULL,

    -- How to resolve the target UID from the source emitted_fields
    source_field        VARCHAR(256),
    source_field_item   VARCHAR(256),
    target_uid_pattern  TEXT,

    -- Attack path classification
    attack_path_category VARCHAR(128),  -- internet_facing | privilege_escalation | lateral_movement | data_exfil

    is_active           BOOLEAN  DEFAULT TRUE,
    rule_metadata       JSONB    DEFAULT '{}'::jsonb,

    created_at          TIMESTAMPTZ DEFAULT NOW(),
    updated_at          TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE (csp, from_resource_type, relation_type, to_resource_type)
);

CREATE INDEX IF NOT EXISTS idx_di_rr_csp_from
    ON di_relationship_rules (csp, from_resource_type)
    WHERE is_active = TRUE;

CREATE INDEX IF NOT EXISTS idx_di_rr_attack_path
    ON di_relationship_rules (csp, attack_path_category)
    WHERE attack_path_category IS NOT NULL AND is_active = TRUE;

COMMIT;
