-- =============================================================================
-- Data Security Engine Database Schema (standardized)
-- Database: threat_engine_datasec
-- Port: 8003 | Layer 3 (post-threat, parallel with compliance/iam/network)
-- =============================================================================
-- Purpose: Data security posture analysis — classification, encryption,
--          access control, lifecycle, residency, lineage, and DLP across
--          all data store services (S3, RDS, DynamoDB, Redshift, EFS, etc.)
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =============================================================================
-- CORE TABLES
-- =============================================================================

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id   VARCHAR(255) PRIMARY KEY,
    tenant_name VARCHAR(255),
    created_at  TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- datasec_report — Scan-level summary (one row per scan_run_id)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS datasec_report (
    scan_run_id             VARCHAR(255) PRIMARY KEY,
    tenant_id               VARCHAR(255) NOT NULL,
    account_id              VARCHAR(255),
    provider                VARCHAR(50) NOT NULL DEFAULT 'aws',
    status                  VARCHAR(50) NOT NULL DEFAULT 'running',
    error_message           TEXT,

    -- Legacy compat (threat_scan_id = scan_run_id now)
    threat_scan_id          VARCHAR(255),

    -- Posture scores (0-100)
    data_risk_score         INTEGER DEFAULT 0,
    encryption_score        INTEGER DEFAULT 0,
    access_score            INTEGER DEFAULT 0,
    classification_score    INTEGER DEFAULT 0,
    lifecycle_score         INTEGER DEFAULT 0,
    residency_score         INTEGER DEFAULT 0,
    monitoring_score        INTEGER DEFAULT 0,

    -- Finding counts
    total_findings          INTEGER DEFAULT 0,
    datasec_relevant_findings INTEGER DEFAULT 0,
    critical_findings       INTEGER DEFAULT 0,
    high_findings           INTEGER DEFAULT 0,
    medium_findings         INTEGER DEFAULT 0,
    low_findings            INTEGER DEFAULT 0,

    -- Data store inventory
    total_data_stores       INTEGER DEFAULT 0,
    classified_resources    INTEGER DEFAULT 0,
    encrypted_resources     INTEGER DEFAULT 0,
    unencrypted_resources   INTEGER DEFAULT 0,
    public_data_stores      INTEGER DEFAULT 0,
    sensitive_exposed       INTEGER DEFAULT 0,

    -- Percentages
    encrypted_pct           NUMERIC(5,2) DEFAULT 0,
    classified_pct          NUMERIC(5,2) DEFAULT 0,

    -- Breakdowns (JSONB)
    findings_by_module      JSONB DEFAULT '{}'::jsonb,
    findings_by_status      JSONB DEFAULT '{}'::jsonb,
    severity_breakdown      JSONB DEFAULT '{}'::jsonb,
    classification_summary  JSONB DEFAULT '{}'::jsonb,
    residency_summary       JSONB DEFAULT '{}'::jsonb,
    report_data             JSONB DEFAULT '{}'::jsonb,

    -- Timing
    started_at              TIMESTAMP WITH TIME ZONE,
    completed_at            TIMESTAMP WITH TIME ZONE,
    scan_duration_ms        INTEGER,
    generated_at            TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at              TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT fk_datasec_report_tenant
        FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- -----------------------------------------------------------------------------
-- datasec_findings — Per-resource data security findings (standardized cols)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS datasec_findings (
    finding_id              VARCHAR(255) PRIMARY KEY,
    scan_run_id             VARCHAR(255) NOT NULL,
    tenant_id               VARCHAR(255) NOT NULL,
    account_id              VARCHAR(255),
    credential_ref          VARCHAR(255),
    credential_type         VARCHAR(100),
    provider                VARCHAR(50) NOT NULL DEFAULT 'aws',
    region                  VARCHAR(50),

    -- Resource identification
    resource_uid            TEXT,
    resource_type           VARCHAR(100),
    resource_id             VARCHAR(500),

    -- Data security classification
    datasec_modules         TEXT[],                 -- {data_protection_encryption, data_access_control, ...}
    data_classification     TEXT[],                 -- {PII, PHI, PCI, confidential, ...}
    sensitivity_score       NUMERIC(5,2) DEFAULT 0, -- 0-100

    -- Finding metadata
    severity                VARCHAR(20) NOT NULL,
    status                  VARCHAR(20) NOT NULL DEFAULT 'FAIL',
    rule_id                 VARCHAR(255),
    finding_data            JSONB DEFAULT '{}'::jsonb,

    -- Timestamps
    first_seen_at           TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_seen_at            TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_datasec_finding_tenant
        FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- -----------------------------------------------------------------------------
-- datasec_data_store_services — Config: data store service types per CSP
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS datasec_data_store_services (
    id              SERIAL PRIMARY KEY,
    csp             VARCHAR(20) NOT NULL DEFAULT 'aws',
    service_name    VARCHAR(100) NOT NULL,
    display_name    VARCHAR(200),
    category        VARCHAR(100),           -- object_storage, rdbms, nosql, data_lake, cache, file_storage
    is_active       BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE (csp, service_name)
);

-- -----------------------------------------------------------------------------
-- datasec_sensitive_data_types — Config: PII/PHI/PCI regex patterns
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS datasec_sensitive_data_types (
    id              SERIAL PRIMARY KEY,
    type_name       VARCHAR(100) NOT NULL,
    category        VARCHAR(50) NOT NULL,    -- PII, PHI, PCI, credentials, financial
    pattern         TEXT,                     -- regex pattern
    description     TEXT,
    severity        VARCHAR(20) DEFAULT 'high',
    is_active       BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- datasec_rules — Rule definitions grouped by category
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS datasec_rules (
    id              SERIAL PRIMARY KEY,
    rule_id         VARCHAR(255) NOT NULL UNIQUE,
    title           TEXT NOT NULL,
    description     TEXT,
    category        VARCHAR(100) NOT NULL,   -- data_protection_encryption, data_access_control, etc.
    severity        VARCHAR(20) NOT NULL DEFAULT 'medium',
    condition       JSONB DEFAULT '{}'::jsonb,
    remediation     TEXT,
    frameworks      TEXT[] DEFAULT '{}',
    csp             TEXT[] DEFAULT '{aws,azure,gcp}',
    is_active       BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- datasec_data_catalog — Data store inventory with metadata
-- (populated from discovery + check + encryption cross-reference)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS datasec_data_catalog (
    id                      BIGSERIAL PRIMARY KEY,
    scan_run_id             VARCHAR(255) NOT NULL,
    tenant_id               VARCHAR(255) NOT NULL,
    account_id              VARCHAR(255),
    provider                VARCHAR(50) NOT NULL DEFAULT 'aws',
    region                  VARCHAR(50),

    -- Resource identification
    resource_uid            TEXT NOT NULL,
    resource_type           VARCHAR(100),
    resource_name           VARCHAR(500),
    service                 VARCHAR(100),            -- s3, rds, dynamodb, etc.

    -- Metadata (from discovery raw_response)
    size_bytes              BIGINT,
    record_count            BIGINT,
    owner                   VARCHAR(255),
    tags                    JSONB DEFAULT '{}'::jsonb,
    creation_date           TIMESTAMP WITH TIME ZONE,

    -- Classification
    data_classification     TEXT[],                  -- {PII, PHI, PCI, ...}
    sensitivity_score       NUMERIC(5,2) DEFAULT 0,
    classification_method   VARCHAR(50),             -- regex, macie, manual

    -- Encryption status (from encryption engine cross-ref)
    encryption_at_rest      BOOLEAN,
    encryption_in_transit   BOOLEAN,
    kms_key_type            VARCHAR(50),             -- aws_managed, customer_managed, none
    kms_key_arn             TEXT,

    -- Access posture
    is_public               BOOLEAN DEFAULT FALSE,
    public_access_block     BOOLEAN DEFAULT FALSE,
    cross_account_access    BOOLEAN DEFAULT FALSE,
    access_logging_enabled  BOOLEAN DEFAULT FALSE,

    -- Lifecycle
    versioning_enabled      BOOLEAN DEFAULT FALSE,
    lifecycle_policy_exists BOOLEAN DEFAULT FALSE,
    backup_enabled          BOOLEAN DEFAULT FALSE,
    replication_enabled     BOOLEAN DEFAULT FALSE,

    -- Posture summary
    finding_count           INTEGER DEFAULT 0,
    fail_count              INTEGER DEFAULT 0,
    risk_score              INTEGER DEFAULT 0,

    -- Discovery source
    last_scanned_at         TIMESTAMP WITH TIME ZONE,

    created_at              TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT fk_catalog_tenant
        FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- -----------------------------------------------------------------------------
-- datasec_lineage — Data flow relationships between stores
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS datasec_lineage (
    id                      BIGSERIAL PRIMARY KEY,
    scan_run_id             VARCHAR(255) NOT NULL,
    tenant_id               VARCHAR(255) NOT NULL,

    source_uid              TEXT NOT NULL,
    source_type             VARCHAR(100),
    source_region           VARCHAR(50),
    destination_uid         TEXT NOT NULL,
    destination_type        VARCHAR(100),
    destination_region      VARCHAR(50),

    transfer_type           VARCHAR(50),              -- replication, etl, streaming, backup, export
    is_cross_region         BOOLEAN DEFAULT FALSE,
    is_cross_account        BOOLEAN DEFAULT FALSE,
    relationship_source     VARCHAR(50),              -- inventory, ciem, manual

    created_at              TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT fk_lineage_tenant
        FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- -----------------------------------------------------------------------------
-- datasec_access_activity — CIEM-enriched data access events
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS datasec_access_activity (
    id                      BIGSERIAL PRIMARY KEY,
    scan_run_id             VARCHAR(255),
    tenant_id               VARCHAR(255) NOT NULL,
    account_id              VARCHAR(255),

    resource_uid            TEXT NOT NULL,
    resource_type           VARCHAR(100),
    principal               VARCHAR(500),             -- IAM user/role ARN
    action                  VARCHAR(200),             -- s3:GetObject, rds:Connect, etc.
    event_time              TIMESTAMP WITH TIME ZONE,
    source_ip               VARCHAR(45),
    is_anomaly              BOOLEAN DEFAULT FALSE,
    anomaly_reason          VARCHAR(255),

    created_at              TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT fk_activity_tenant
        FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- =============================================================================
-- INDEXES
-- =============================================================================

-- datasec_report
CREATE INDEX IF NOT EXISTS idx_ds_report_tenant ON datasec_report(tenant_id);
CREATE INDEX IF NOT EXISTS idx_ds_report_status ON datasec_report(status);
CREATE INDEX IF NOT EXISTS idx_ds_report_generated ON datasec_report(generated_at DESC);

-- datasec_findings
CREATE INDEX IF NOT EXISTS idx_ds_findings_scan ON datasec_findings(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_ds_findings_tenant ON datasec_findings(tenant_id);
CREATE INDEX IF NOT EXISTS idx_ds_findings_severity ON datasec_findings(severity, status);
CREATE INDEX IF NOT EXISTS idx_ds_findings_resource ON datasec_findings(resource_uid);
CREATE INDEX IF NOT EXISTS idx_ds_findings_modules ON datasec_findings USING gin(datasec_modules);
CREATE INDEX IF NOT EXISTS idx_ds_findings_classification ON datasec_findings USING gin(data_classification);
CREATE INDEX IF NOT EXISTS idx_ds_findings_sensitivity ON datasec_findings(sensitivity_score DESC);
CREATE INDEX IF NOT EXISTS idx_ds_findings_data ON datasec_findings USING gin(finding_data);
CREATE INDEX IF NOT EXISTS idx_ds_findings_critical
    ON datasec_findings(scan_run_id) WHERE severity = 'critical' AND status = 'FAIL';

-- datasec_data_catalog
CREATE INDEX IF NOT EXISTS idx_ds_catalog_scan ON datasec_data_catalog(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_ds_catalog_tenant ON datasec_data_catalog(tenant_id);
CREATE INDEX IF NOT EXISTS idx_ds_catalog_resource ON datasec_data_catalog(resource_uid);
CREATE INDEX IF NOT EXISTS idx_ds_catalog_service ON datasec_data_catalog(service);
CREATE INDEX IF NOT EXISTS idx_ds_catalog_public ON datasec_data_catalog(is_public) WHERE is_public = TRUE;
CREATE UNIQUE INDEX IF NOT EXISTS idx_ds_catalog_unique ON datasec_data_catalog(scan_run_id, resource_uid);

-- datasec_lineage
CREATE INDEX IF NOT EXISTS idx_ds_lineage_scan ON datasec_lineage(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_ds_lineage_source ON datasec_lineage(source_uid);
CREATE INDEX IF NOT EXISTS idx_ds_lineage_dest ON datasec_lineage(destination_uid);

-- datasec_access_activity
CREATE INDEX IF NOT EXISTS idx_ds_activity_tenant ON datasec_access_activity(tenant_id, event_time DESC);
CREATE INDEX IF NOT EXISTS idx_ds_activity_resource ON datasec_access_activity(resource_uid);
CREATE INDEX IF NOT EXISTS idx_ds_activity_anomaly ON datasec_access_activity(is_anomaly) WHERE is_anomaly = TRUE;

-- =============================================================================
-- SEED: Default data store services
-- =============================================================================
INSERT INTO datasec_data_store_services (csp, service_name, display_name, category) VALUES
    ('aws', 's3', 'Amazon S3', 'object_storage'),
    ('aws', 'rds', 'Amazon RDS', 'rdbms'),
    ('aws', 'dynamodb', 'Amazon DynamoDB', 'nosql'),
    ('aws', 'redshift', 'Amazon Redshift', 'data_warehouse'),
    ('aws', 'aurora', 'Amazon Aurora', 'rdbms'),
    ('aws', 'elasticache', 'Amazon ElastiCache', 'cache'),
    ('aws', 'efs', 'Amazon EFS', 'file_storage'),
    ('aws', 'fsx', 'Amazon FSx', 'file_storage'),
    ('aws', 'documentdb', 'Amazon DocumentDB', 'nosql'),
    ('aws', 'neptune', 'Amazon Neptune', 'graph_db'),
    ('aws', 'glacier', 'Amazon Glacier', 'archive'),
    ('aws', 'glue', 'AWS Glue', 'data_lake'),
    ('aws', 'lakeformation', 'AWS Lake Formation', 'data_lake'),
    ('aws', 'ecr', 'Amazon ECR', 'container_registry'),
    ('aws', 'kms', 'AWS KMS', 'key_management'),
    ('aws', 'secretsmanager', 'AWS Secrets Manager', 'secrets'),
    ('aws', 'opensearch', 'Amazon OpenSearch', 'search'),
    ('aws', 'elasticsearch', 'Amazon Elasticsearch', 'search'),
    ('aws', 'athena', 'Amazon Athena', 'analytics'),
    ('aws', 'kinesis', 'Amazon Kinesis', 'streaming'),
    ('aws', 'dax', 'Amazon DAX', 'cache'),
    ('aws', 'keyspaces', 'Amazon Keyspaces', 'nosql'),
    ('aws', 'timestream', 'Amazon Timestream', 'timeseries'),
    ('aws', 'qldb', 'Amazon QLDB', 'ledger'),
    ('azure', 'storage_account', 'Azure Storage Account', 'object_storage'),
    ('azure', 'sql_database', 'Azure SQL Database', 'rdbms'),
    ('azure', 'cosmos_db', 'Azure Cosmos DB', 'nosql'),
    ('azure', 'key_vault', 'Azure Key Vault', 'key_management'),
    ('azure', 'blob_container', 'Azure Blob Container', 'object_storage'),
    ('gcp', 'gcs_bucket', 'Google Cloud Storage', 'object_storage'),
    ('gcp', 'cloud_sql_instance', 'Cloud SQL', 'rdbms'),
    ('gcp', 'bigquery_dataset', 'BigQuery', 'data_warehouse'),
    ('gcp', 'spanner', 'Cloud Spanner', 'rdbms'),
    ('gcp', 'firestore', 'Cloud Firestore', 'nosql')
ON CONFLICT DO NOTHING;

-- =============================================================================
-- COMMENTS
-- =============================================================================

COMMENT ON TABLE datasec_report IS 'Data security scan summary with per-module posture scores and data store metrics';
COMMENT ON TABLE datasec_findings IS 'Per-resource data security findings with standardized columns';
COMMENT ON TABLE datasec_data_store_services IS 'Config: data store service types per CSP';
COMMENT ON TABLE datasec_sensitive_data_types IS 'Config: PII/PHI/PCI regex patterns for classification';
COMMENT ON TABLE datasec_rules IS 'Data security rule definitions grouped by category';
COMMENT ON TABLE datasec_data_catalog IS 'Enriched data store inventory with metadata from discovery + encryption';
COMMENT ON TABLE datasec_lineage IS 'Data flow relationships between data stores';
COMMENT ON TABLE datasec_access_activity IS 'CIEM-enriched data access events for activity monitoring';
