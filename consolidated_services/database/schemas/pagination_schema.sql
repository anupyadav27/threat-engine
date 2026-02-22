-- ================================================================
-- Pagination Configuration Schema - Config-Driven Pagination
-- ================================================================
-- Purpose: Move pagination logic from hardcoded if/elif chains to database
-- Supports: Multi-CSP pagination configuration (AWS, Azure, GCP, etc.)
-- Migration: Replaces hardcoded pagination in service_scanner.py lines 1490-1500
-- ================================================================

CREATE TABLE IF NOT EXISTS pagination_config (
    id SERIAL PRIMARY KEY,

    -- CSP and Service Identification
    csp VARCHAR(50) NOT NULL,                    -- 'aws', 'azure', 'gcp', 'oci', 'ibm', 'alicloud', 'k8s'
    service_name VARCHAR(100),                   -- 'sagemaker', 'cognito-idp', 'compute', NULL for default
    action VARCHAR(100),                         -- 'list_models', 'list_users', NULL for service default

    -- Pagination Parameters
    default_page_size INTEGER DEFAULT 1000,      -- Number of items per page
    max_pages INTEGER DEFAULT 100,               -- Maximum pages to fetch (safety limit)
    timeout_seconds INTEGER DEFAULT 600,         -- Operation timeout (10 minutes)
    max_items_per_discovery INTEGER DEFAULT 100000,  -- Total items limit per discovery

    -- CSP-Specific Token/Result Naming
    -- AWS uses: NextToken, Marker, NextMarker
    -- Azure uses: nextLink, skipToken
    -- GCP uses: pageToken, nextPageToken
    token_field VARCHAR(100),                    -- Pagination token field name
    result_array_field VARCHAR(100),             -- Result array field name (NULL = auto-detect)

    -- Advanced Configuration
    supports_native_pagination BOOLEAN DEFAULT TRUE,  -- CSP SDK has native paginator
    circular_token_detection BOOLEAN DEFAULT TRUE,    -- Detect infinite pagination loops

    -- Metadata
    is_active BOOLEAN DEFAULT TRUE,
    description TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_pagination_csp_service ON pagination_config(csp, service_name, action, is_active);
CREATE INDEX idx_pagination_lookup ON pagination_config(csp, service_name, is_active);

-- ================================================================
-- Initial Data Migration: AWS Pagination Configuration
-- ================================================================
-- Source: service_scanner.py lines 1490-1500
-- ================================================================

-- AWS Default Pagination (fallback for all services)
INSERT INTO pagination_config (
    csp, service_name, action, default_page_size, max_pages, timeout_seconds,
    max_items_per_discovery, token_field, supports_native_pagination, description
) VALUES
('aws', NULL, NULL, 1000, 100, 600, 100000, 'NextToken', TRUE, 'AWS default pagination for all services');

-- AWS SageMaker: Smaller page size for large model metadata
INSERT INTO pagination_config (
    csp, service_name, action, default_page_size, max_pages, timeout_seconds,
    token_field, description
) VALUES
('aws', 'sagemaker', NULL, 100, 100, 600, 'NextToken', 'SageMaker pagination - smaller page size for metadata-heavy responses');

-- AWS Cognito Identity Provider: API rate limit constraint
INSERT INTO pagination_config (
    csp, service_name, action, default_page_size, max_pages, timeout_seconds,
    token_field, description
) VALUES
('aws', 'cognito-idp', NULL, 60, 100, 600, 'PaginationToken', 'Cognito IDP pagination - rate limit constraint'),
('aws', 'cognito', NULL, 60, 100, 600, 'NextToken', 'Cognito pagination - rate limit constraint');

-- AWS Kafka (MSK): Custom pagination for cluster metadata
INSERT INTO pagination_config (
    csp, service_name, action, default_page_size, max_pages, timeout_seconds,
    token_field, description
) VALUES
('aws', 'kafka', NULL, 100, 100, 600, 'NextToken', 'Kafka/MSK pagination - moderate page size for cluster data');

-- AWS S3: Different token field name
INSERT INTO pagination_config (
    csp, service_name, action, default_page_size, max_pages, timeout_seconds,
    token_field, description
) VALUES
('aws', 's3', 'list_buckets', 1000, 100, 600, 'Marker', 'S3 list_buckets uses Marker token'),
('aws', 's3', 'list_objects_v2', 1000, 100, 600, 'ContinuationToken', 'S3 list_objects_v2 uses ContinuationToken');

-- AWS IAM: Uses Marker token field
INSERT INTO pagination_config (
    csp, service_name, action, default_page_size, max_pages, timeout_seconds,
    token_field, description
) VALUES
('aws', 'iam', NULL, 1000, 100, 600, 'Marker', 'IAM pagination uses Marker token field');

-- AWS EC2: Large result sets, optimize page size
INSERT INTO pagination_config (
    csp, service_name, action, default_page_size, max_pages, timeout_seconds,
    max_items_per_discovery, token_field, description
) VALUES
('aws', 'ec2', NULL, 1000, 200, 900, 200000, 'NextToken', 'EC2 pagination - larger limits for instance-heavy accounts');

-- AWS CloudWatch Logs: Slower API, reduce page size
INSERT INTO pagination_config (
    csp, service_name, action, default_page_size, max_pages, timeout_seconds,
    token_field, description
) VALUES
('aws', 'logs', NULL, 50, 100, 600, 'nextToken', 'CloudWatch Logs - smaller page size for slow API');

-- ================================================================
-- Future: Azure Pagination Configuration (Placeholder)
-- ================================================================

-- Azure Default Pagination
INSERT INTO pagination_config (
    csp, service_name, action, default_page_size, max_pages, timeout_seconds,
    token_field, result_array_field, supports_native_pagination, description, is_active
) VALUES
('azure', NULL, NULL, 100, 100, 600, 'nextLink', 'value', FALSE, 'Azure default pagination - uses nextLink continuation', FALSE);

-- Azure Compute: Virtual Machines pagination
INSERT INTO pagination_config (
    csp, service_name, action, default_page_size, max_pages, timeout_seconds,
    token_field, result_array_field, description, is_active
) VALUES
('azure', 'compute', 'list_virtual_machines', 100, 100, 600, 'nextLink', 'value', 'Azure Compute VMs pagination', FALSE);

-- ================================================================
-- Future: GCP Pagination Configuration (Placeholder)
-- ================================================================

-- GCP Default Pagination
INSERT INTO pagination_config (
    csp, service_name, action, default_page_size, max_pages, timeout_seconds,
    token_field, result_array_field, supports_native_pagination, description, is_active
) VALUES
('gcp', NULL, NULL, 500, 100, 600, 'pageToken', 'items', FALSE, 'GCP default pagination - uses pageToken', FALSE);

-- GCP Compute: Instances pagination
INSERT INTO pagination_config (
    csp, service_name, action, default_page_size, max_pages, timeout_seconds,
    token_field, result_array_field, description, is_active
) VALUES
('gcp', 'compute', 'list_instances', 500, 100, 600, 'nextPageToken', 'items', 'GCP Compute instances pagination', FALSE);

-- ================================================================
-- Future: OCI Pagination Configuration (Placeholder)
-- ================================================================

-- OCI Default Pagination
INSERT INTO pagination_config (
    csp, service_name, action, default_page_size, max_pages, timeout_seconds,
    token_field, result_array_field, description, is_active
) VALUES
('oci', NULL, NULL, 1000, 100, 600, 'opc-next-page', 'items', 'OCI default pagination - uses opc-next-page header', FALSE);

-- ================================================================
-- Trigger: Update timestamp on modification
-- ================================================================
CREATE OR REPLACE FUNCTION update_pagination_config_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER pagination_config_update_timestamp
BEFORE UPDATE ON pagination_config
FOR EACH ROW
EXECUTE FUNCTION update_pagination_config_timestamp();

-- ================================================================
-- Helper View: Active Pagination Lookup
-- ================================================================
-- Simplifies queries with fallback logic (action → service → csp default)
-- ================================================================

CREATE OR REPLACE VIEW v_pagination_lookup AS
SELECT
    pc.csp,
    pc.service_name,
    pc.action,
    pc.default_page_size,
    pc.max_pages,
    pc.timeout_seconds,
    pc.max_items_per_discovery,
    pc.token_field,
    pc.result_array_field,
    pc.supports_native_pagination,
    pc.circular_token_detection,
    CASE
        WHEN pc.action IS NOT NULL THEN 'action'
        WHEN pc.service_name IS NOT NULL THEN 'service'
        ELSE 'default'
    END AS config_level,
    pc.description
FROM pagination_config pc
WHERE pc.is_active = TRUE
ORDER BY
    pc.csp,
    pc.service_name NULLS LAST,
    pc.action NULLS LAST;

-- ================================================================
-- Example Queries
-- ================================================================

-- Query pagination config for AWS SageMaker (any action)
-- SELECT * FROM v_pagination_lookup
-- WHERE csp = 'aws' AND (service_name = 'sagemaker' OR service_name IS NULL)
-- ORDER BY config_level LIMIT 1;

-- Query pagination config for specific action
-- SELECT * FROM v_pagination_lookup
-- WHERE csp = 'aws' AND service_name = 's3' AND (action = 'list_objects_v2' OR action IS NULL)
-- ORDER BY config_level LIMIT 1;

-- Get all CSP defaults
-- SELECT * FROM v_pagination_lookup WHERE config_level = 'default';
