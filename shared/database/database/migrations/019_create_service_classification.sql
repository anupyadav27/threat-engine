-- Migration 019: Create dedicated service_classification table
-- ============================================================================
-- Single source of truth for architecture diagram rendering.
-- Keyed by (csp, resource_type) matching inventory_findings.resource_type
-- format directly (e.g., "ec2.instance", "s3.bucket").
--
-- This replaces the classification columns added to resource_inventory_identifier
-- in migration 017 — those columns remain but are superseded by this table.
-- ============================================================================

\connect threat_engine_inventory;

-- ── Table ────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS service_classification (
    id              SERIAL PRIMARY KEY,

    -- Key: matches inventory_findings (csp=provider, resource_type=dotted format)
    csp             VARCHAR(20)  NOT NULL,             -- aws, azure, gcp, oci, alicloud, ibm, k8s
    resource_type   VARCHAR(120) NOT NULL,             -- dotted: "ec2.instance", "s3.bucket"

    -- Derived convenience columns (split from resource_type)
    service         VARCHAR(60)  NOT NULL,             -- "ec2", "s3", "lambda"
    resource_name   VARCHAR(60)  NOT NULL,             -- "instance", "bucket", "function"

    -- Display
    display_name    VARCHAR(200),                       -- "EC2 Instance", "S3 Bucket"

    -- ── Classification dimensions ──
    scope           VARCHAR(20)  NOT NULL DEFAULT 'regional',
                    -- global, regional, vpc, subnet, az, namespace, cluster
    category        VARCHAR(30)  NOT NULL,
                    -- compute, container, database, storage, network, edge,
                    -- security, identity, encryption, monitoring, management,
                    -- messaging, analytics, ai_ml, iot
    subcategory     VARCHAR(40),
                    -- vm, serverless_function, relational, nosql_keyvalue,
                    -- object, block, vpc, subnet, firewall, iam_role, etc.
    service_model   VARCHAR(10)  DEFAULT 'PaaS',
                    -- IaaS, PaaS, FaaS, SaaS
    managed_by      VARCHAR(20)  DEFAULT 'shared',
                    -- aws, azure, gcp, oci, alicloud, ibm, customer, shared
    access_pattern  VARCHAR(20)  DEFAULT 'private',
                    -- public, private, internal

    -- ── Containment / hierarchy ──
    is_container    BOOLEAN      DEFAULT FALSE,         -- can other resources live inside this?
    container_parent VARCHAR(30),                       -- what contains this: vpc, subnet, cluster, namespace, region, account, null=top-level
    encryption_scope VARCHAR(20),                       -- at_rest, in_transit, both, null

    -- ── Rendering ──
    diagram_priority SMALLINT    DEFAULT 3 CHECK (diagram_priority BETWEEN 1 AND 5),
                    -- 1=always show (core), 5=hide by default
    csp_category    VARCHAR(60),                        -- CSP's own category: "Compute", "Networking", etc.

    -- ── Metadata ──
    created_at      TIMESTAMP    DEFAULT NOW(),
    updated_at      TIMESTAMP    DEFAULT NOW(),

    -- Unique constraint: one classification per (csp, resource_type)
    CONSTRAINT uq_service_classification UNIQUE (csp, resource_type)
);

-- ── Indexes ──────────────────────────────────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_svc_class_csp_category
    ON service_classification (csp, category);

CREATE INDEX IF NOT EXISTS idx_svc_class_scope
    ON service_classification (scope);

CREATE INDEX IF NOT EXISTS idx_svc_class_priority
    ON service_classification (diagram_priority);

CREATE INDEX IF NOT EXISTS idx_svc_class_container
    ON service_classification (is_container) WHERE is_container = TRUE;

CREATE INDEX IF NOT EXISTS idx_svc_class_service_model
    ON service_classification (service_model);

CREATE INDEX IF NOT EXISTS idx_svc_class_resource_type
    ON service_classification (resource_type);

-- ── Comments ─────────────────────────────────────────────────────────────────

COMMENT ON TABLE service_classification IS
    'Single source of truth for architecture diagram rendering. Keyed by (csp, resource_type) matching inventory_findings format.';

COMMENT ON COLUMN service_classification.resource_type IS
    'Dotted format matching inventory_findings: service.resource_name (e.g., ec2.instance)';

COMMENT ON COLUMN service_classification.diagram_priority IS
    '1=always show (VPC, instance, bucket), 2=important, 3=normal, 4=detailed, 5=hide by default';

COMMENT ON COLUMN service_classification.container_parent IS
    'What contains this resource in the hierarchy: null=top-level, account, region, vpc, subnet, cluster, namespace';
