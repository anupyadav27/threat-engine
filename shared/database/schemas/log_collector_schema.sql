-- =============================================================================
-- Log Collector Database Schema
-- =============================================================================
-- Database: threat_engine_logs
-- Purpose:  Store parsed log/event stream data from VPC flow logs, CloudTrail,
--           API access logs, and K8s audit logs (Tier 2 collection)
-- Used by:  shared/log_collector service (Port 8030)
-- Read by:  engine_network (log_events, event_aggregations),
--           engine_api (event_aggregations),
--           engine_threat (cloudtrail_events)
-- Reference: PROJECT_PLAN.md Task 0.2.1
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =============================================================================
-- LOG SOURCES TABLE
-- =============================================================================
-- Tracks configured log sources (S3 buckets, CloudWatch log groups) and their
-- collection schedules. Populated by log_source_registry.py (Task 0.2.2).

CREATE TABLE IF NOT EXISTS log_sources (
    id                          SERIAL          PRIMARY KEY,
    source_type                 VARCHAR(50)     NOT NULL,
        -- One of: 'vpc_flow', 'cloudtrail', 'api_access', 'k8s_audit'
    source_name                 VARCHAR(255)    NOT NULL,
        -- Human-readable name (e.g., 'prod-vpc-flow-logs', 'main-cloudtrail')
    source_config               JSONB           NOT NULL DEFAULT '{}'::jsonb,
        -- Configuration details:
        --   vpc_flow:    {"s3_bucket": "...", "s3_prefix": "AWSLogs/.../VPCFlowLogs/", "region": "us-east-1"}
        --   cloudtrail:  {"s3_bucket": "...", "s3_prefix": "AWSLogs/.../CloudTrail/", "region": "us-east-1"}
        --   api_access:  {"log_group_name": "/aws/apigateway/...", "region": "us-east-1"}
        --   k8s_audit:   {"log_group_name": "/aws/eks/cluster_name/cluster", "cluster_name": "...", "region": "us-east-1"}
    customer_id                 VARCHAR(255),
    tenant_id                   VARCHAR(255),
    is_active                   BOOLEAN         DEFAULT true,
    collection_schedule_minutes INTEGER         DEFAULT 60,
        -- How often to poll this source (default: hourly)
    last_collection_time        TIMESTAMP WITH TIME ZONE,
    last_collection_status      VARCHAR(50),
        -- 'success', 'failed', 'in_progress'
    last_collection_row_count   INTEGER         DEFAULT 0,
    last_collection_duration_ms INTEGER,
    created_at                  TIMESTAMP WITH TIME ZONE    DEFAULT NOW(),
    updated_at                  TIMESTAMP WITH TIME ZONE    DEFAULT NOW(),
    UNIQUE(source_type, source_name, customer_id, tenant_id)
);

-- =============================================================================
-- LOG EVENTS TABLE (Raw Parsed Records)
-- =============================================================================
-- Stores individual parsed log records from all source types.
-- VPC flow log records, API access log records, etc.
-- Retention: 30 days (managed by retention_manager.py, Task 0.2.9)

CREATE TABLE IF NOT EXISTS log_events (
    id                  BIGSERIAL       PRIMARY KEY,
    source_type         VARCHAR(50)     NOT NULL,
        -- 'vpc_flow', 'api_access'
    customer_id         VARCHAR(255),
    tenant_id           VARCHAR(255),
    event_time          TIMESTAMP WITH TIME ZONE    NOT NULL,
    src_ip              INET,
    dst_ip              INET,
    src_port            INTEGER,
    dst_port            INTEGER,
    protocol            VARCHAR(20),
        -- 'TCP', 'UDP', 'ICMP', or protocol number for flow logs
    action              VARCHAR(20),
        -- 'ACCEPT', 'REJECT' for VPC flow; HTTP status code for API access
    bytes_transferred   BIGINT          DEFAULT 0,
    packets             BIGINT          DEFAULT 0,
    resource_id         VARCHAR(255),
        -- Resolved by ip_resolver.py (Task 0.2.8) — e.g., 'i-0abc123', 'arn:aws:...'
    resource_type       VARCHAR(100),
        -- e.g., 'aws.ec2.instance', 'aws.rds.db_instance'
    interface_id        VARCHAR(50),
        -- ENI ID for VPC flow logs (e.g., 'eni-0abc123')
    log_status          VARCHAR(20),
        -- 'OK', 'NODATA', 'SKIPDATA' for VPC flow logs
    raw_fields          JSONB           DEFAULT '{}'::jsonb,
        -- Additional fields not in fixed columns (extensibility)
    source_file         VARCHAR(500),
        -- S3 key or CloudWatch log stream name (for deduplication/tracing)
    created_at          TIMESTAMP WITH TIME ZONE    DEFAULT NOW()
) PARTITION BY RANGE (event_time);

-- Create monthly partitions (current + 1 month ahead)
-- In production, use pg_partman for automatic partition management
CREATE TABLE IF NOT EXISTS log_events_default PARTITION OF log_events DEFAULT;

-- =============================================================================
-- EVENT AGGREGATIONS TABLE (5-Minute Summaries)
-- =============================================================================
-- Pre-computed aggregations over 5-minute windows for efficient querying.
-- Retention: 90 days (managed by retention_manager.py, Task 0.2.9)

CREATE TABLE IF NOT EXISTS event_aggregations (
    id                  BIGSERIAL       PRIMARY KEY,
    source_type         VARCHAR(50)     NOT NULL,
        -- 'vpc_flow', 'api_access'
    customer_id         VARCHAR(255),
    tenant_id           VARCHAR(255),
    window_start        TIMESTAMP WITH TIME ZONE    NOT NULL,
        -- Start of 5-minute aggregation window (truncated to 5-min boundary)
    window_end          TIMESTAMP WITH TIME ZONE    NOT NULL,
        -- End of 5-minute aggregation window
    -- Grouping dimensions (vary by source_type)
    src_ip              INET,
    dst_ip              INET,
    dst_port            INTEGER,
    protocol            VARCHAR(20),
    endpoint            VARCHAR(500),
        -- For api_access: the API path (e.g., '/api/v1/users')
    http_method         VARCHAR(10),
        -- For api_access: GET, POST, PUT, DELETE, etc.
    -- Aggregated metrics
    total_bytes         BIGINT          DEFAULT 0,
    total_packets       BIGINT          DEFAULT 0,
    flow_count          INTEGER         DEFAULT 0,
        -- Number of individual log_events in this window
    unique_sources      INTEGER         DEFAULT 0,
        -- COUNT(DISTINCT src_ip) in this window
    unique_destinations INTEGER         DEFAULT 0,
        -- COUNT(DISTINCT dst_ip) in this window
    error_count         INTEGER         DEFAULT 0,
        -- For api_access: count of 4xx/5xx responses
    p99_latency_ms      NUMERIC(10,2),
        -- For api_access: 99th percentile latency in milliseconds
    avg_latency_ms      NUMERIC(10,2),
        -- For api_access: average latency in milliseconds
    accept_count        INTEGER         DEFAULT 0,
        -- For vpc_flow: count of ACCEPT actions
    reject_count        INTEGER         DEFAULT 0,
        -- For vpc_flow: count of REJECT actions
    created_at          TIMESTAMP WITH TIME ZONE    DEFAULT NOW()
) PARTITION BY RANGE (window_start);

-- Create default partition
CREATE TABLE IF NOT EXISTS event_aggregations_default PARTITION OF event_aggregations DEFAULT;

-- =============================================================================
-- CLOUDTRAIL EVENTS TABLE
-- =============================================================================
-- Stores normalized CloudTrail events and K8s audit log events.
-- Retention: 30 days (managed by retention_manager.py, Task 0.2.9)

CREATE TABLE IF NOT EXISTS cloudtrail_events (
    id                  BIGSERIAL       PRIMARY KEY,
    source_type         VARCHAR(50)     NOT NULL,
        -- 'cloudtrail', 'k8s_audit'
    customer_id         VARCHAR(255),
    tenant_id           VARCHAR(255),
    event_time          TIMESTAMP WITH TIME ZONE    NOT NULL,
    event_name          VARCHAR(255)    NOT NULL,
        -- AWS API action (e.g., 'CreateAccessKey', 'AssumeRole')
        -- or K8s verb (e.g., 'create', 'delete', 'patch')
    event_source        VARCHAR(255),
        -- AWS service (e.g., 'iam.amazonaws.com', 'ec2.amazonaws.com')
        -- or 'kubernetes' for K8s audit
    user_identity       JSONB           NOT NULL DEFAULT '{}'::jsonb,
        -- CloudTrail: {type, principalId, arn, accountId, accessKeyId, userName}
        -- K8s audit:  {username, groups, uid}
    resource_type       VARCHAR(100),
        -- e.g., 'AWS::IAM::AccessKey', 'AWS::EC2::SecurityGroup'
        -- or K8s kind: 'Pod', 'ClusterRole', 'ServiceAccount'
    resource_id         VARCHAR(500),
        -- Resource ARN or K8s resource name
    request_parameters  JSONB           DEFAULT '{}'::jsonb,
        -- Full request parameters (CloudTrail) or requestObject (K8s)
    response_elements   JSONB           DEFAULT '{}'::jsonb,
        -- Full response elements (CloudTrail) or responseObject (K8s)
    error_code          VARCHAR(100),
        -- e.g., 'AccessDenied', 'EntityAlreadyExists'
    error_message       TEXT,
    source_ip           INET,
        -- IP address of the API caller
    user_agent          TEXT,
    region              VARCHAR(50),
    raw_fields          JSONB           DEFAULT '{}'::jsonb,
        -- Full original event for reference
    source_file         VARCHAR(500),
        -- S3 key or CloudWatch log stream name
    created_at          TIMESTAMP WITH TIME ZONE    DEFAULT NOW()
) PARTITION BY RANGE (event_time);

-- Create default partition
CREATE TABLE IF NOT EXISTS cloudtrail_events_default PARTITION OF cloudtrail_events DEFAULT;

-- =============================================================================
-- LOG COLLECTION STATUS TABLE
-- =============================================================================
-- Tracks the status of each collection run for observability and debugging.

CREATE TABLE IF NOT EXISTS log_collection_status (
    id                  SERIAL          PRIMARY KEY,
    collection_id       VARCHAR(255)    NOT NULL UNIQUE DEFAULT uuid_generate_v4()::TEXT,
    source_type         VARCHAR(50)     NOT NULL,
    customer_id         VARCHAR(255),
    tenant_id           VARCHAR(255),
    status              VARCHAR(50)     NOT NULL DEFAULT 'in_progress',
        -- 'in_progress', 'success', 'failed', 'partial'
    started_at          TIMESTAMP WITH TIME ZONE    DEFAULT NOW(),
    completed_at        TIMESTAMP WITH TIME ZONE,
    rows_processed      INTEGER         DEFAULT 0,
    rows_failed         INTEGER         DEFAULT 0,
    bytes_processed     BIGINT          DEFAULT 0,
    files_processed     INTEGER         DEFAULT 0,
    error_message       TEXT,
    metadata            JSONB           DEFAULT '{}'::jsonb,
        -- Extra details: {"s3_keys_processed": [...], "duration_ms": 1234}
    created_at          TIMESTAMP WITH TIME ZONE    DEFAULT NOW()
);

-- =============================================================================
-- INDEXES
-- =============================================================================

-- log_sources: lookup by source type and tenant
CREATE INDEX IF NOT EXISTS idx_log_sources_type_tenant
ON log_sources(source_type, customer_id, tenant_id) WHERE is_active = TRUE;

-- log_events: primary query pattern — by source type, tenant, and time range
CREATE INDEX IF NOT EXISTS idx_log_events_source_tenant_time
ON log_events(source_type, tenant_id, event_time DESC);

-- log_events: IP-based lookups for network analysis
CREATE INDEX IF NOT EXISTS idx_log_events_src_ip
ON log_events(src_ip) WHERE src_ip IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_log_events_dst_ip
ON log_events(dst_ip) WHERE dst_ip IS NOT NULL;

-- log_events: combined IP pair for flow analysis
CREATE INDEX IF NOT EXISTS idx_log_events_ip_pair
ON log_events(src_ip, dst_ip, event_time DESC) WHERE src_ip IS NOT NULL AND dst_ip IS NOT NULL;

-- log_events: resource resolution lookups
CREATE INDEX IF NOT EXISTS idx_log_events_resource
ON log_events(resource_id) WHERE resource_id IS NOT NULL;

-- log_events: partial index for recent data (hot query path)
CREATE INDEX IF NOT EXISTS idx_log_events_recent
ON log_events(event_time DESC)
WHERE event_time > NOW() - INTERVAL '7 days';

-- event_aggregations: primary query — by source type, tenant, and window
CREATE INDEX IF NOT EXISTS idx_event_agg_source_tenant_window
ON event_aggregations(source_type, tenant_id, window_start DESC);

-- event_aggregations: endpoint-based lookups for API analysis
CREATE INDEX IF NOT EXISTS idx_event_agg_endpoint
ON event_aggregations(endpoint, http_method, window_start DESC)
WHERE endpoint IS NOT NULL;

-- event_aggregations: IP-based lookups
CREATE INDEX IF NOT EXISTS idx_event_agg_src_ip
ON event_aggregations(src_ip, window_start DESC) WHERE src_ip IS NOT NULL;

-- cloudtrail_events: primary query — by source type, tenant, and time
CREATE INDEX IF NOT EXISTS idx_cloudtrail_source_tenant_time
ON cloudtrail_events(source_type, tenant_id, event_time DESC);

-- cloudtrail_events: event name lookups (detect specific API calls)
CREATE INDEX IF NOT EXISTS idx_cloudtrail_event_name
ON cloudtrail_events(event_name, event_time DESC);

-- cloudtrail_events: event source lookups (filter by AWS service)
CREATE INDEX IF NOT EXISTS idx_cloudtrail_event_source
ON cloudtrail_events(event_source, event_time DESC);

-- cloudtrail_events: error code lookups (find failed API calls)
CREATE INDEX IF NOT EXISTS idx_cloudtrail_error
ON cloudtrail_events(error_code, event_time DESC) WHERE error_code IS NOT NULL;

-- cloudtrail_events: user identity GIN index for JSONB queries
CREATE INDEX IF NOT EXISTS idx_cloudtrail_user_identity_gin
ON cloudtrail_events USING GIN (user_identity);

-- cloudtrail_events: source IP lookups
CREATE INDEX IF NOT EXISTS idx_cloudtrail_source_ip
ON cloudtrail_events(source_ip) WHERE source_ip IS NOT NULL;

-- log_collection_status: lookup by source type and status
CREATE INDEX IF NOT EXISTS idx_collection_status_type
ON log_collection_status(source_type, status, started_at DESC);

-- =============================================================================
-- COMMENTS
-- =============================================================================

COMMENT ON TABLE log_sources IS 'Registry of configured log sources (S3 buckets, CloudWatch log groups) and collection schedules';
COMMENT ON TABLE log_events IS 'Raw parsed log records from VPC flow logs and API access logs (30-day retention)';
COMMENT ON TABLE event_aggregations IS 'Pre-computed 5-minute aggregation windows for efficient querying (90-day retention)';
COMMENT ON TABLE cloudtrail_events IS 'Normalized CloudTrail and K8s audit log events (30-day retention)';
COMMENT ON TABLE log_collection_status IS 'Audit trail of collection runs for observability';

-- =============================================================================
-- END: Log Collector Schema (5 tables, 17 indexes)
-- =============================================================================
