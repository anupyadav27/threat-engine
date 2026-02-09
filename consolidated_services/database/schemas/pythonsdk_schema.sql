-- ============================================================================
-- PythonSDK Engine Database Schema
-- ============================================================================
-- Database: threat_engine_pythonsdk
-- Purpose: Store cloud provider SDK metadata — services, operations, fields,
--          resource inventory classifications, dependency indexes,
--          enhancement indexes, and relationship rules for all 7 CSPs
-- Used by: engine_inventory (resource classification, relationship building),
--          scripts/populate_pythonsdk_db.py,
--          scripts/generate_resource_inventory_all_csp.py,
--          scripts/generate_multicloud_relationships.py
-- Tables: csp, services, operations, fields, resource_inventory,
--         dependency_index, direct_vars, enhancement_indexes,
--         relation_types, relationship_rules
-- CSPs: aws (430 services), azure (160), gcp (143), oci (153), ibm (62),
--        alicloud (26), k8s (17)

CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- ============================================================================
-- CORE TABLES
-- ============================================================================

-- Cloud Service Providers
CREATE TABLE IF NOT EXISTS csp (
    csp_id VARCHAR(50) PRIMARY KEY,
    csp_name VARCHAR(100) NOT NULL,
    description TEXT,
    sdk_version VARCHAR(50),
    total_services INTEGER DEFAULT 0,
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Cloud Services (one per SDK module per CSP)
CREATE TABLE IF NOT EXISTS services (
    service_id VARCHAR(100) PRIMARY KEY,
    csp_id VARCHAR(50) NOT NULL,
    service_name VARCHAR(100) NOT NULL,
    service_full_name VARCHAR(200),
    description TEXT,
    sdk_module VARCHAR(200),
    total_operations INTEGER DEFAULT 0,
    discovery_operations INTEGER DEFAULT 0,
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT fk_csp FOREIGN KEY (csp_id) REFERENCES csp(csp_id) ON DELETE CASCADE
);

-- ============================================================================
-- OPERATIONS & FIELDS
-- ============================================================================

-- SDK Operations (API calls available per service)
CREATE TABLE IF NOT EXISTS operations (
    id BIGSERIAL PRIMARY KEY,
    service_id VARCHAR(100) NOT NULL,
    operation_name VARCHAR(200) NOT NULL,
    python_method VARCHAR(200),
    operation_type VARCHAR(20) DEFAULT 'independent',  -- 'independent' or 'dependent'
    is_discovery BOOLEAN DEFAULT FALSE,
    is_root_operation BOOLEAN DEFAULT FALSE,
    required_params JSONB DEFAULT '[]',
    optional_params JSONB DEFAULT '[]',
    total_required INTEGER DEFAULT 0,
    total_optional INTEGER DEFAULT 0,
    depends_on JSONB DEFAULT '[]',
    dependency_count INTEGER DEFAULT 0,
    main_output_field VARCHAR(200),
    output_structure JSONB DEFAULT '{}',
    description TEXT,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT fk_service_operation FOREIGN KEY (service_id) REFERENCES services(service_id) ON DELETE CASCADE,
    CONSTRAINT unique_service_operation UNIQUE (service_id, operation_name)
);

-- Emitted Fields (configuration fields extracted per operation)
CREATE TABLE IF NOT EXISTS fields (
    id BIGSERIAL PRIMARY KEY,
    service_id VARCHAR(100) NOT NULL,
    operation_name VARCHAR(200),
    field_name VARCHAR(200) NOT NULL,
    field_path VARCHAR(500),
    field_type VARCHAR(50),
    compliance_category VARCHAR(100),
    security_impact VARCHAR(20),
    compliance_frameworks JSONB DEFAULT '[]',
    operators JSONB DEFAULT '[]',
    possible_values JSONB DEFAULT '[]',
    is_enum BOOLEAN DEFAULT FALSE,
    target_category VARCHAR(50) DEFAULT 'properties',
    description TEXT,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT fk_field_service FOREIGN KEY (service_id) REFERENCES services(service_id) ON DELETE CASCADE
);

-- ============================================================================
-- RESOURCE INVENTORY (classification per service)
-- ============================================================================

-- Resource Inventory Report (per service — classifies resource types)
-- Contains: PRIMARY_RESOURCE, SUB_RESOURCE, CONFIGURATION, EPHEMERAL
-- Used by: inventory engine ResourceClassifier for INVENTORY/ENRICHMENT_ONLY/FILTER decisions
CREATE TABLE IF NOT EXISTS resource_inventory (
    id BIGSERIAL PRIMARY KEY,
    service_id VARCHAR(100) NOT NULL,
    inventory_data JSONB NOT NULL,
    total_resource_types INTEGER DEFAULT 0,
    total_operations INTEGER DEFAULT 0,
    discovery_operations INTEGER DEFAULT 0,
    version VARCHAR(50),
    generated_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT fk_service_inventory FOREIGN KEY (service_id) REFERENCES services(service_id) ON DELETE CASCADE,
    CONSTRAINT unique_service_inventory UNIQUE (service_id)
);

-- ============================================================================
-- DEPENDENCY & VARIABLE INDEXES (per service)
-- ============================================================================

-- Dependency Index (operation dependency graph per service)
CREATE TABLE IF NOT EXISTS dependency_index (
    id BIGSERIAL PRIMARY KEY,
    service_id VARCHAR(100) NOT NULL,
    dependency_data JSONB NOT NULL,
    total_functions INTEGER DEFAULT 0,
    independent_functions INTEGER DEFAULT 0,
    dependent_functions INTEGER DEFAULT 0,
    version VARCHAR(50),
    generated_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT fk_service_dependency FOREIGN KEY (service_id) REFERENCES services(service_id) ON DELETE CASCADE,
    CONSTRAINT unique_service_dependency UNIQUE (service_id)
);

-- Direct Variables (compliance/security fields per service)
CREATE TABLE IF NOT EXISTS direct_vars (
    id BIGSERIAL PRIMARY KEY,
    service_id VARCHAR(100) NOT NULL,
    direct_vars_data JSONB NOT NULL,
    total_fields INTEGER DEFAULT 0,
    compliance_fields INTEGER DEFAULT 0,
    security_fields INTEGER DEFAULT 0,
    version VARCHAR(50),
    generated_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT fk_service_direct_vars FOREIGN KEY (service_id) REFERENCES services(service_id) ON DELETE CASCADE,
    CONSTRAINT unique_service_direct_vars UNIQUE (service_id)
);

-- ============================================================================
-- ENHANCEMENT INDEXES (per CSP — aggregated classification indexes)
-- ============================================================================

-- Enhancement Indexes (pre-built classification lookups per CSP)
-- Used by: inventory engine for fast resource classification without scanning all services
CREATE TABLE IF NOT EXISTS enhancement_indexes (
    id BIGSERIAL PRIMARY KEY,
    index_type VARCHAR(100) NOT NULL,
    csp_id VARCHAR(50) NOT NULL,
    index_data JSONB NOT NULL,
    version VARCHAR(50),
    total_entries INTEGER,
    generated_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT fk_index_csp FOREIGN KEY (csp_id) REFERENCES csp(csp_id) ON DELETE CASCADE,
    CONSTRAINT unique_index_type_csp UNIQUE (index_type, csp_id)
);

-- ============================================================================
-- RELATIONSHIP RULES (multi-cloud relationship definitions)
-- ============================================================================

-- Relation Types (canonical relationship type definitions)
-- Used by: inventory engine RelationshipBuilder for graph edge creation
CREATE TABLE IF NOT EXISTS relation_types (
    relation_id VARCHAR(100) PRIMARY KEY,
    category VARCHAR(50) NOT NULL,
    direction VARCHAR(20) NOT NULL,
    inverse VARCHAR(100),
    description TEXT,
    cardinality VARCHAR(20),
    type_data JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Relationship Rules (per-CSP resource-to-resource relationship definitions)
-- Used by: inventory engine RelationshipBuilder for pattern-based relationship extraction
-- Synced to local cache via RelationshipBuilder.sync_from_db()
CREATE TABLE IF NOT EXISTS relationship_rules (
    rule_id BIGSERIAL PRIMARY KEY,
    csp_id VARCHAR(20) NOT NULL,
    service_id VARCHAR(100),
    from_type VARCHAR(200) NOT NULL,
    relation_type VARCHAR(100) NOT NULL,
    to_type VARCHAR(200) NOT NULL,
    source_field VARCHAR(200) NOT NULL,
    target_uid_pattern TEXT NOT NULL,
    source_field_item VARCHAR(200),
    rule_data JSONB DEFAULT '{}',
    version VARCHAR(20) DEFAULT '1.0',
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT fk_rel_rule_csp FOREIGN KEY (csp_id) REFERENCES csp(csp_id) ON DELETE CASCADE,
    CONSTRAINT fk_rel_rule_type FOREIGN KEY (relation_type) REFERENCES relation_types(relation_id),
    CONSTRAINT uq_rel_rule UNIQUE (csp_id, from_type, relation_type, to_type, source_field)
);

-- ============================================================================
-- INDEXES
-- ============================================================================

-- services
CREATE INDEX IF NOT EXISTS idx_services_csp ON services(csp_id);
CREATE INDEX IF NOT EXISTS idx_services_name ON services(service_name);
CREATE INDEX IF NOT EXISTS idx_services_full_name ON services USING gin(service_full_name gin_trgm_ops);

-- operations
CREATE INDEX IF NOT EXISTS idx_operations_service ON operations(service_id);
CREATE INDEX IF NOT EXISTS idx_operations_name ON operations(operation_name);
CREATE INDEX IF NOT EXISTS idx_operations_type ON operations(operation_type);
CREATE INDEX IF NOT EXISTS idx_operations_discovery ON operations(is_discovery);
CREATE INDEX IF NOT EXISTS idx_operations_root ON operations(is_root_operation);

-- fields
CREATE INDEX IF NOT EXISTS idx_fields_service ON fields(service_id);
CREATE INDEX IF NOT EXISTS idx_fields_operation ON fields(operation_name);
CREATE INDEX IF NOT EXISTS idx_fields_name ON fields(field_name);
CREATE INDEX IF NOT EXISTS idx_fields_compliance ON fields(compliance_category);
CREATE INDEX IF NOT EXISTS idx_fields_security ON fields(security_impact);
CREATE INDEX IF NOT EXISTS idx_fields_target ON fields(target_category);

-- resource_inventory
CREATE INDEX IF NOT EXISTS idx_resource_inventory_service ON resource_inventory(service_id);

-- dependency_index
CREATE INDEX IF NOT EXISTS idx_dependency_service ON dependency_index(service_id);

-- direct_vars
CREATE INDEX IF NOT EXISTS idx_direct_vars_service ON direct_vars(service_id);

-- enhancement_indexes
CREATE INDEX IF NOT EXISTS idx_enhancement_csp ON enhancement_indexes(csp_id);
CREATE INDEX IF NOT EXISTS idx_enhancement_type ON enhancement_indexes(index_type);

-- relation_types
CREATE INDEX IF NOT EXISTS idx_relation_types_category ON relation_types(category);

-- relationship_rules
CREATE INDEX IF NOT EXISTS idx_rel_rules_csp ON relationship_rules(csp_id);
CREATE INDEX IF NOT EXISTS idx_rel_rules_from ON relationship_rules(from_type);
CREATE INDEX IF NOT EXISTS idx_rel_rules_type ON relationship_rules(relation_type);
CREATE INDEX IF NOT EXISTS idx_rel_rules_service ON relationship_rules(service_id);

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON TABLE csp IS 'Cloud service provider metadata (aws, azure, gcp, k8s, oci, ibm, alicloud)';
COMMENT ON TABLE services IS 'SDK service modules per CSP (e.g., aws.s3, azure.compute)';
COMMENT ON TABLE operations IS 'SDK API operations per service (list_buckets, describe_instances, etc.)';
COMMENT ON TABLE fields IS 'Emitted configuration fields per operation (compliance/security tagged)';
COMMENT ON TABLE resource_inventory IS 'Resource type classification per service (PRIMARY/SUB/CONFIG/EPHEMERAL)';
COMMENT ON TABLE dependency_index IS 'Operation dependency graph per service (independent vs dependent)';
COMMENT ON TABLE direct_vars IS 'Compliance and security field aggregation per service';
COMMENT ON TABLE enhancement_indexes IS 'Pre-built classification indexes per CSP for fast lookups';
COMMENT ON TABLE relation_types IS 'Canonical relationship type definitions (35 types across 11 categories)';
COMMENT ON TABLE relationship_rules IS 'Per-CSP resource-to-resource relationship rules (1061 rules across 7 CSPs)';
