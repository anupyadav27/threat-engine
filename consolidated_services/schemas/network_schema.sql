-- ============================================================================
-- Network Engine Schema — Task 2.1 [Seq 55 | DE]
-- Database: threat_engine_network
-- ============================================================================
-- Tables: network_report, network_input_transformed, network_rules,
--         network_findings, network_topology, network_anomalies,
--         network_baselines
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";


-- ============================================================================
-- network_report — scan-level summary (1 row per scan)
-- ============================================================================

CREATE TABLE IF NOT EXISTS network_report (
    network_scan_id     UUID            PRIMARY KEY DEFAULT uuid_generate_v4(),
    orchestration_id    UUID            NOT NULL,
    tenant_id           VARCHAR(255)    NOT NULL,
    account_id          VARCHAR(255)    NOT NULL,
    provider            VARCHAR(50)     NOT NULL DEFAULT 'aws',

    -- Scan mode
    scan_mode           VARCHAR(20)     NOT NULL DEFAULT 'posture',  -- posture | runtime | both

    -- Counts
    total_resources_scanned INTEGER     DEFAULT 0,
    total_findings          INTEGER     DEFAULT 0,
    total_failures          INTEGER     DEFAULT 0,
    critical_count          INTEGER     DEFAULT 0,
    high_count              INTEGER     DEFAULT 0,
    medium_count            INTEGER     DEFAULT 0,
    low_count               INTEGER     DEFAULT 0,
    info_count              INTEGER     DEFAULT 0,

    -- Network-specific metrics
    total_security_groups   INTEGER     DEFAULT 0,
    total_vpcs              INTEGER     DEFAULT 0,
    total_nacls             INTEGER     DEFAULT 0,
    total_anomalies         INTEGER     DEFAULT 0,
    exposed_ports_count     INTEGER     DEFAULT 0,

    -- Aggregations
    top_failing_rules       JSONB       DEFAULT '[]'::jsonb,   -- top 5 [{rule_id, title, fail_count}]
    exposure_summary        JSONB       DEFAULT '{}'::jsonb,   -- {ssh_open, rdp_open, all_traffic_open}
    risk_score              INTEGER     DEFAULT 0,             -- 0-100

    -- Timing
    started_at              TIMESTAMP WITH TIME ZONE,
    completed_at            TIMESTAMP WITH TIME ZONE,
    scan_duration_ms        INTEGER,
    status                  VARCHAR(50)     DEFAULT 'running',
    error_message           TEXT,

    created_at              TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

COMMENT ON TABLE network_report IS 'Scan-level summary for network engine (1 row per scan)';

CREATE INDEX IF NOT EXISTS idx_network_report_tenant
    ON network_report(tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_network_report_orch
    ON network_report(orchestration_id);


-- ============================================================================
-- network_input_transformed — ETL output (Stage 1)
-- ============================================================================

CREATE TABLE IF NOT EXISTS network_input_transformed (
    id                  BIGSERIAL       PRIMARY KEY,
    network_scan_id     UUID            NOT NULL,
    tenant_id           VARCHAR(255)    NOT NULL,
    orchestration_id    UUID            NOT NULL,

    -- Resource identity
    resource_id         VARCHAR(500)    NOT NULL,
    resource_type       VARCHAR(100)    NOT NULL,   -- security_group, vpc, subnet, nacl, igw, nat, alb_listener, waf
    resource_arn        TEXT,
    resource_name       VARCHAR(255),

    -- VPC context
    vpc_id              VARCHAR(50),
    account_id          VARCHAR(255),
    region              VARCHAR(50),

    -- Security Group fields (null for non-SG)
    inbound_rules       JSONB           DEFAULT '[]'::jsonb,   -- [{port, protocol, cidr, description}]
    outbound_rules      JSONB           DEFAULT '[]'::jsonb,

    -- VPC fields (null for non-VPC)
    cidr_block          VARCHAR(50),
    flow_logs_enabled   BOOLEAN,
    enable_dns_support  BOOLEAN,
    enable_dns_hostnames BOOLEAN,
    is_default          BOOLEAN,

    -- Subnet fields
    is_public           BOOLEAN,
    availability_zone   VARCHAR(50),

    -- NACL fields (null for non-NACL)
    nacl_inbound_rules  JSONB           DEFAULT '[]'::jsonb,
    nacl_outbound_rules JSONB           DEFAULT '[]'::jsonb,

    -- ALB/Listener fields (null for non-ALB)
    protocol            VARCHAR(20),     -- HTTP, HTTPS, TCP
    ssl_policy          VARCHAR(100),
    listener_port       INTEGER,

    -- WAF fields
    waf_enabled         BOOLEAN,
    waf_rules_count     INTEGER,

    -- Flow/anomaly fields (runtime mode)
    total_bytes         BIGINT,
    total_packets       BIGINT,
    unique_dst_ports    INTEGER,
    baseline_bytes      BIGINT,
    baseline_packets    BIGINT,
    deviation_factor    NUMERIC(8,2),
    src_ip              VARCHAR(45),
    dst_ip              VARCHAR(45),
    dst_port            INTEGER,

    -- Threat intel
    is_malicious_ip     BOOLEAN         DEFAULT FALSE,
    threat_intel_source VARCHAR(100),

    -- Topology connections
    connected_to        JSONB           DEFAULT '[]'::jsonb,   -- [{node_id, connection_type}]
    has_igw             BOOLEAN,

    -- Raw data
    raw_discovery       JSONB,

    created_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

COMMENT ON TABLE network_input_transformed IS 'ETL Stage 1 output: enriched network resource data ready for rule evaluation';

CREATE INDEX IF NOT EXISTS idx_nit_scan
    ON network_input_transformed(network_scan_id, tenant_id);

CREATE INDEX IF NOT EXISTS idx_nit_resource
    ON network_input_transformed(resource_id, resource_type);

CREATE INDEX IF NOT EXISTS idx_nit_vpc
    ON network_input_transformed(vpc_id);


-- ============================================================================
-- network_rules — rule definitions (Stage 2 input)
-- ============================================================================

CREATE TABLE IF NOT EXISTS network_rules (
    id                  SERIAL          PRIMARY KEY,
    rule_id             VARCHAR(255)    NOT NULL UNIQUE,
    title               TEXT            NOT NULL,
    description         TEXT,
    mode                VARCHAR(20)     NOT NULL DEFAULT 'posture',  -- posture | runtime
    category            VARCHAR(100)    NOT NULL,    -- exposure, encryption, logging, configuration, anomaly, threat
    severity            VARCHAR(20)     NOT NULL DEFAULT 'medium',
    condition_type      VARCHAR(50)     NOT NULL DEFAULT 'field_check',
    condition           JSONB           NOT NULL DEFAULT '{}'::jsonb,
    evidence_fields     JSONB           DEFAULT '[]'::jsonb,
    frameworks          JSONB           DEFAULT '[]'::jsonb,
    remediation         TEXT,
    "references"        JSONB           DEFAULT '[]'::jsonb,
    csp                 TEXT[]          DEFAULT ARRAY['all'],
    is_active           BOOLEAN         DEFAULT TRUE,

    created_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

COMMENT ON TABLE network_rules IS 'Network security rules with JSONB conditions (12 initial rules)';

CREATE INDEX IF NOT EXISTS idx_network_rules_active
    ON network_rules(is_active, mode, category);


-- ============================================================================
-- network_findings — rule evaluation results (Stage 2 output)
-- ============================================================================

CREATE TABLE IF NOT EXISTS network_findings (
    finding_id          UUID            PRIMARY KEY DEFAULT uuid_generate_v4(),
    network_scan_id     UUID            NOT NULL,
    tenant_id           VARCHAR(255)    NOT NULL,
    orchestration_id    UUID            NOT NULL,

    -- Resource
    resource_id         VARCHAR(500),
    resource_type       VARCHAR(100),
    resource_arn        TEXT,

    -- Rule
    rule_id             VARCHAR(255)    NOT NULL,
    finding_type        VARCHAR(50),     -- misconfiguration | anomaly | threat
    result              VARCHAR(20)     NOT NULL,    -- PASS, FAIL, SKIP, ERROR
    severity            VARCHAR(20)     NOT NULL DEFAULT 'info',
    title               TEXT,
    description         TEXT,

    -- Evidence
    evidence            JSONB           DEFAULT '{}'::jsonb,
    remediation         TEXT,

    -- Context
    account_id          VARCHAR(255),
    region              VARCHAR(50),
    csp                 VARCHAR(50)     DEFAULT 'aws',
    is_active           BOOLEAN         DEFAULT TRUE,

    created_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

COMMENT ON TABLE network_findings IS 'Per-rule per-resource evaluation results (PASS/FAIL/SKIP/ERROR)';

CREATE INDEX IF NOT EXISTS idx_nf_scan_rule
    ON network_findings(network_scan_id, rule_id);

CREATE INDEX IF NOT EXISTS idx_nf_tenant
    ON network_findings(tenant_id, orchestration_id);

CREATE INDEX IF NOT EXISTS idx_nf_result
    ON network_findings(result, severity);

CREATE INDEX IF NOT EXISTS idx_nf_critical
    ON network_findings(network_scan_id)
    WHERE severity = 'critical' AND result = 'FAIL';


-- ============================================================================
-- network_topology — network resource graph (Stage 3)
-- ============================================================================

CREATE TABLE IF NOT EXISTS network_topology (
    id                  BIGSERIAL       PRIMARY KEY,
    network_scan_id     UUID            NOT NULL,
    tenant_id           VARCHAR(255)    NOT NULL,

    -- Node identity
    node_id             VARCHAR(500)    NOT NULL,    -- resource_id
    resource_type       VARCHAR(100)    NOT NULL,
    resource_arn        TEXT,
    resource_name       VARCHAR(255),

    -- Network context
    vpc_id              VARCHAR(50),
    account_id          VARCHAR(255),
    region              VARCHAR(50),
    cidr_block          VARCHAR(50),

    -- Posture flags
    is_public           BOOLEAN         DEFAULT FALSE,
    has_igw             BOOLEAN         DEFAULT FALSE,
    flow_logs_enabled   BOOLEAN,

    -- Rules (for SG/NACL nodes)
    inbound_rules       JSONB           DEFAULT '[]'::jsonb,
    outbound_rules      JSONB           DEFAULT '[]'::jsonb,

    -- Connections
    connected_to        JSONB           DEFAULT '[]'::jsonb,   -- [{node_id, connection_type: route|peer|tgw|igw|nat}]

    -- Risk
    finding_count       INTEGER         DEFAULT 0,
    critical_findings   INTEGER         DEFAULT 0,

    created_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

COMMENT ON TABLE network_topology IS 'Network resource graph: nodes are VPCs, subnets, SGs, IGWs, etc.';

CREATE INDEX IF NOT EXISTS idx_nt_scan
    ON network_topology(network_scan_id, tenant_id);

CREATE INDEX IF NOT EXISTS idx_nt_node
    ON network_topology(node_id);

CREATE INDEX IF NOT EXISTS idx_nt_vpc
    ON network_topology(vpc_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_nt_unique_node
    ON network_topology(network_scan_id, node_id);


-- ============================================================================
-- network_anomalies — detected anomalies from runtime analysis (Stage 3)
-- ============================================================================

CREATE TABLE IF NOT EXISTS network_anomalies (
    anomaly_id          UUID            PRIMARY KEY DEFAULT uuid_generate_v4(),
    network_scan_id     UUID,
    tenant_id           VARCHAR(255)    NOT NULL,
    account_id          VARCHAR(255),

    -- Anomaly classification
    anomaly_type        VARCHAR(50)     NOT NULL,   -- data_exfil | lateral_movement | beaconing | port_scan | malicious_ip
    severity            VARCHAR(20)     NOT NULL DEFAULT 'medium',

    -- Flow details
    src_ip              VARCHAR(45),
    dst_ip              VARCHAR(45),
    dst_port            INTEGER,
    protocol            VARCHAR(10),

    -- Metrics
    bytes_total         BIGINT,
    packets_total       BIGINT,
    baseline_bytes      BIGINT,
    deviation_factor    NUMERIC(8,2),    -- 5.3 = 5.3x above baseline
    unique_dst_ports    INTEGER,

    -- Threat intel
    is_malicious_ip     BOOLEAN         DEFAULT FALSE,
    threat_intel_source VARCHAR(100),

    -- Resource resolution
    src_resource_id     VARCHAR(500),
    dst_resource_id     VARCHAR(500),
    vpc_id              VARCHAR(50),

    -- Rule that triggered
    rule_id             VARCHAR(255),
    evidence            JSONB           DEFAULT '{}'::jsonb,

    -- Status
    detected_at         TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active           BOOLEAN         DEFAULT TRUE,
    acknowledged        BOOLEAN         DEFAULT FALSE,
    acknowledged_by     VARCHAR(255),
    acknowledged_at     TIMESTAMP WITH TIME ZONE
);

COMMENT ON TABLE network_anomalies IS 'Detected network anomalies from VPC flow log analysis';

CREATE INDEX IF NOT EXISTS idx_na_tenant
    ON network_anomalies(tenant_id, detected_at DESC);

CREATE INDEX IF NOT EXISTS idx_na_scan
    ON network_anomalies(network_scan_id);

CREATE INDEX IF NOT EXISTS idx_na_type
    ON network_anomalies(anomaly_type, severity);

CREATE INDEX IF NOT EXISTS idx_na_active
    ON network_anomalies(is_active)
    WHERE is_active = TRUE;


-- ============================================================================
-- network_baselines — rolling traffic baselines per resource (Stage 3)
-- ============================================================================

CREATE TABLE IF NOT EXISTS network_baselines (
    baseline_id         UUID            PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id           VARCHAR(255)    NOT NULL,

    -- Resource scope
    resource_id         VARCHAR(500)    NOT NULL,
    vpc_id              VARCHAR(50),

    -- Metric
    metric_type         VARCHAR(50)     NOT NULL,   -- outbound_bytes | inbound_bytes | connection_count | unique_dst_ports
    window_days         INTEGER         DEFAULT 14,

    -- Statistics
    baseline_avg        NUMERIC(20,2)   DEFAULT 0,
    baseline_p50        NUMERIC(20,2)   DEFAULT 0,
    baseline_p95        NUMERIC(20,2)   DEFAULT 0,
    std_deviation       NUMERIC(20,2)   DEFAULT 0,
    sample_count        INTEGER         DEFAULT 0,

    -- Timing
    computed_at         TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    valid_until         TIMESTAMP WITH TIME ZONE
);

COMMENT ON TABLE network_baselines IS 'Rolling 14-day traffic baselines for anomaly detection';

CREATE INDEX IF NOT EXISTS idx_nb_resource
    ON network_baselines(resource_id, metric_type);

CREATE INDEX IF NOT EXISTS idx_nb_tenant
    ON network_baselines(tenant_id, computed_at DESC);

CREATE UNIQUE INDEX IF NOT EXISTS idx_nb_unique
    ON network_baselines(tenant_id, resource_id, metric_type);
