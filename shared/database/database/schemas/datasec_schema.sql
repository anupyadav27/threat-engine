-- ============================================================================
-- Data Security Engine Database Schema
-- ============================================================================
-- Database: threat_engine_datasec
-- Purpose: Store data security scan results, classification, and findings
-- Used by: engine_datasec
-- Tables: tenants, datasec_report, datasec_findings

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================================
-- CORE TABLES
-- ============================================================================

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id VARCHAR(255) PRIMARY KEY,
    tenant_name VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- DataSec Report (scan-level metadata)
CREATE TABLE IF NOT EXISTS datasec_report (
    datasec_scan_id VARCHAR(255) PRIMARY KEY DEFAULT uuid_generate_v4(),
    orchestration_id VARCHAR(255),  -- PLANNED: not yet deployed to RDS
    execution_id VARCHAR(255),
    tenant_id VARCHAR(255) NOT NULL,
    scan_run_id VARCHAR(255) NOT NULL,
    cloud VARCHAR(50) DEFAULT 'aws',
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    total_findings INTEGER DEFAULT 0,
    datasec_relevant_findings INTEGER DEFAULT 0,
    classified_resources INTEGER DEFAULT 0,
    total_data_stores INTEGER DEFAULT 0,
    findings_by_module JSONB,
    classification_summary JSONB,
    residency_summary JSONB,
    report_data JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    discovery_scan_id VARCHAR(255),
    customer_id VARCHAR(255),
    check_scan_id VARCHAR(255),
    threat_scan_id VARCHAR(255),
    status VARCHAR(50) DEFAULT 'completed',
    provider VARCHAR(50) DEFAULT 'aws',

    CONSTRAINT fk_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- DataSec Findings (individual data security findings)
CREATE TABLE IF NOT EXISTS datasec_findings (
    finding_id VARCHAR(255) PRIMARY KEY,
    datasec_scan_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    scan_run_id VARCHAR(255) NOT NULL,
    rule_id VARCHAR(255) NOT NULL,
    datasec_modules TEXT[],
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(20) NOT NULL,
    resource_type VARCHAR(100),
    resource_id VARCHAR(255),
    resource_uid TEXT,                -- Canonical identifier (ARN for AWS, ARM ID for Azure, etc.)
    account_id VARCHAR(50),
    region VARCHAR(50),
    data_classification TEXT[],
    sensitivity_score DECIMAL(3,1),
    finding_data JSONB NOT NULL,
    first_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    customer_id VARCHAR(255),

    CONSTRAINT fk_tenant_finding FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- ============================================================================
-- INDEXES
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_datasec_report_tenant ON datasec_report(tenant_id);
CREATE INDEX IF NOT EXISTS idx_datasec_report_scan_run ON datasec_report(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_datasec_report_check_scan ON datasec_report(check_scan_id);
CREATE INDEX IF NOT EXISTS idx_datasec_report_threat_scan ON datasec_report(threat_scan_id);
CREATE INDEX IF NOT EXISTS idx_datasec_report_generated ON datasec_report(generated_at DESC);

CREATE INDEX IF NOT EXISTS idx_datasec_findings_datasec_scan ON datasec_findings(datasec_scan_id);
CREATE INDEX IF NOT EXISTS idx_datasec_findings_tenant ON datasec_findings(tenant_id);
CREATE INDEX IF NOT EXISTS idx_datasec_findings_rule ON datasec_findings(rule_id);
CREATE INDEX IF NOT EXISTS idx_datasec_findings_severity ON datasec_findings(severity, status);
CREATE INDEX IF NOT EXISTS idx_datasec_findings_resource_uid ON datasec_findings(resource_uid);
CREATE INDEX IF NOT EXISTS idx_datasec_findings_classification ON datasec_findings USING gin(data_classification);

-- JSONB indexes
CREATE INDEX IF NOT EXISTS idx_datasec_report_data_gin ON datasec_report USING gin(report_data);
CREATE INDEX IF NOT EXISTS idx_datasec_finding_data_gin ON datasec_findings USING gin(finding_data);
CREATE INDEX IF NOT EXISTS idx_datasec_report_modules_gin ON datasec_report USING gin(findings_by_module);
CREATE INDEX IF NOT EXISTS idx_datasec_report_classification_gin ON datasec_report USING gin(classification_summary);

-- ============================================================================
-- DATA STORE SERVICES CONFIGURATION (DB-driven, multi-CSP)
-- ============================================================================
-- Replaces hardcoded DATA_SECURITY_RESOURCE_TYPES in Python code.
-- Add new services here instead of editing Python source.

CREATE TABLE IF NOT EXISTS datasec_data_store_services (
    id          SERIAL PRIMARY KEY,
    csp         VARCHAR(20)  NOT NULL DEFAULT 'aws',
    service_name VARCHAR(100) NOT NULL,
    is_active   BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    CONSTRAINT uq_datasec_svc UNIQUE (csp, service_name)
);

CREATE INDEX IF NOT EXISTS idx_datasec_svc_csp ON datasec_data_store_services(csp) WHERE is_active = TRUE;

-- Seed: AWS data store services
INSERT INTO datasec_data_store_services (csp, service_name) VALUES
  ('aws', 's3'),           ('aws', 'rds'),          ('aws', 'dynamodb'),
  ('aws', 'redshift'),     ('aws', 'glacier'),       ('aws', 'documentdb'),
  ('aws', 'neptune'),      ('aws', 'glue'),          ('aws', 'lakeformation'),
  ('aws', 'macie'),        ('aws', 'ecr'),           ('aws', 'kms'),
  ('aws', 'elasticache'),  ('aws', 'dax'),           ('aws', 'efs'),
  ('aws', 'fsx'),          ('aws', 'kinesis'),       ('aws', 'firehose'),
  ('aws', 'athena'),       ('aws', 'opensearch'),    ('aws', 'timestream'),
  ('aws', 'keyspaces'),    ('aws', 'qldb'),          ('aws', 's3tables'),
  -- Azure data store services
  ('azure', 'blob'),         ('azure', 'cosmos'),       ('azure', 'sql'),
  ('azure', 'postgresql'),   ('azure', 'mysql'),        ('azure', 'mariadb'),
  ('azure', 'storage'),      ('azure', 'keyvault'),     ('azure', 'eventhub'),
  ('azure', 'servicebus'),   ('azure', 'synapse'),      ('azure', 'redis'),
  ('azure', 'sqlmanagedinstance'), ('azure', 'cassandra'),
  -- GCP data store services
  ('gcp', 'storage'),     ('gcp', 'bigquery'),   ('gcp', 'spanner'),
  ('gcp', 'bigtable'),    ('gcp', 'cloudsql'),   ('gcp', 'firestore'),
  ('gcp', 'memorystore'), ('gcp', 'pubsub'),     ('gcp', 'datastore'),
  ('gcp', 'kms'),         ('gcp', 'secretmanager'),
  -- OCI data store services
  ('oci', 'objectstorage'), ('oci', 'database'),   ('oci', 'nosql'),
  ('oci', 'filesystem'),    ('oci', 'vault'),       ('oci', 'streaming'),
  ('oci', 'mysql'),         ('oci', 'postgresql'),  ('oci', 'goldengate'),
  -- IBM data store services
  ('ibm', 'cos'),       ('ibm', 'db2'),         ('ibm', 'postgresql'),
  ('ibm', 'mongodb'),   ('ibm', 'kafka'),        ('ibm', 'keyprotect'),
  ('ibm', 'redis'),     ('ibm', 'elasticsearch'),
  -- AliCloud data store services
  ('alicloud', 'oss'),     ('alicloud', 'rds'),       ('alicloud', 'mongodb'),
  ('alicloud', 'redis'),   ('alicloud', 'memcache'),  ('alicloud', 'tablestore'),
  ('alicloud', 'kms'),     ('alicloud', 'dts'),       ('alicloud', 'sls')
ON CONFLICT (csp, service_name) DO NOTHING;

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON TABLE datasec_report IS 'Data security scan metadata with links to check/threat scans';
COMMENT ON TABLE datasec_findings IS 'Individual data security findings (classification, protection, residency)';
COMMENT ON TABLE datasec_data_store_services IS 'DB-driven list of data-store service names per CSP (replaces hardcoded Python sets)';
