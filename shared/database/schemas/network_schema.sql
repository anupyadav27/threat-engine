-- =============================================================================
-- Network Security Engine Database Schema  (v2 — layered architecture)
-- Database: threat_engine_network
-- Port: 8004 | Layer 3 (post-threat, parallel with compliance/iam/datasec)
-- =============================================================================
-- Purpose: Layered network posture analysis — builds a topology model from
--          discovery data (VPC, subnets, SGs, NACLs, routes, LBs, WAF) and
--          evaluates effective exposure by combining all 7 network layers.
--
-- Layers:
--   L1 Network Topology     — VPC, subnet, peering, TGW
--   L2 Network Reachability  — route tables, IGW, NAT, cross-VPC paths
--   L3 Network ACL           — stateless firewall (subnet boundary)
--   L4 Security Groups       — stateful firewall (per-resource)
--   L5 Load Balancers        — ALB/NLB/CLB exposure surface, TLS
--   L6 WAF / Shield          — L7 protection on LBs/CloudFront/APIGW
--   L7 Flow Analysis         — VPC Flow Logs (config vs. runtime gap)
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
-- network_report — Scan-level summary (one row per scan_run_id)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS network_report (
    scan_run_id             VARCHAR(255) PRIMARY KEY,
    tenant_id               VARCHAR(255) NOT NULL,
    account_id              VARCHAR(255),
    provider                VARCHAR(50) NOT NULL DEFAULT 'aws',
    status                  VARCHAR(50) NOT NULL DEFAULT 'running',
    error_message           TEXT,

    -- Layered posture scores (0-100 each, composite = weighted average)
    posture_score           INTEGER DEFAULT 0,
    topology_score          INTEGER DEFAULT 0,      -- L1: VPC isolation, flow logging
    reachability_score      INTEGER DEFAULT 0,      -- L2: route hygiene, cross-env paths
    nacl_score              INTEGER DEFAULT 0,      -- L3: stateless firewall posture
    firewall_score          INTEGER DEFAULT 0,      -- L4: security group posture
    lb_score                INTEGER DEFAULT 0,      -- L5: load balancer posture
    waf_score               INTEGER DEFAULT 0,      -- L6: WAF coverage
    monitoring_score        INTEGER DEFAULT 0,      -- L7: flow log coverage

    -- Finding counts
    total_findings          INTEGER DEFAULT 0,
    critical_findings       INTEGER DEFAULT 0,
    high_findings           INTEGER DEFAULT 0,
    medium_findings         INTEGER DEFAULT 0,
    low_findings            INTEGER DEFAULT 0,

    -- Network inventory counts (populated during analysis)
    total_vpcs              INTEGER DEFAULT 0,
    total_subnets           INTEGER DEFAULT 0,
    total_security_groups   INTEGER DEFAULT 0,
    total_nacls             INTEGER DEFAULT 0,
    total_route_tables      INTEGER DEFAULT 0,
    total_load_balancers    INTEGER DEFAULT 0,
    total_waf_acls          INTEGER DEFAULT 0,
    total_nat_gateways      INTEGER DEFAULT 0,
    total_igws              INTEGER DEFAULT 0,
    total_tgws              INTEGER DEFAULT 0,
    total_vpc_endpoints     INTEGER DEFAULT 0,
    total_eips              INTEGER DEFAULT 0,
    total_network_firewalls INTEGER DEFAULT 0,

    -- Exposure summary
    internet_exposed_resources INTEGER DEFAULT 0,
    cross_vpc_paths_count      INTEGER DEFAULT 0,
    orphaned_sg_count          INTEGER DEFAULT 0,

    -- Breakdowns (JSONB)
    findings_by_module      JSONB DEFAULT '{}'::jsonb,   -- {network_isolation: 5, sg_rules: 12, ...}
    findings_by_status      JSONB DEFAULT '{}'::jsonb,   -- {FAIL: 20, PASS: 150, WARN: 8}
    findings_by_layer       JSONB DEFAULT '{}'::jsonb,   -- {L1: 3, L2: 5, L3: 4, L4: 15, ...}
    severity_breakdown      JSONB DEFAULT '{}'::jsonb,
    exposure_summary        JSONB DEFAULT '{}'::jsonb,   -- {ssh_open: 2, rdp_open: 0, db_exposed: 1}
    report_data             JSONB DEFAULT '{}'::jsonb,

    -- Timing
    started_at              TIMESTAMP WITH TIME ZONE,
    completed_at            TIMESTAMP WITH TIME ZONE,
    scan_duration_ms        INTEGER,
    generated_at            TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT fk_network_report_tenant
        FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- -----------------------------------------------------------------------------
-- network_findings — Per-resource network posture findings (standardized cols)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS network_findings (
    finding_id              VARCHAR(255) PRIMARY KEY,
    scan_run_id             VARCHAR(255) NOT NULL,
    tenant_id               VARCHAR(255) NOT NULL,
    account_id              VARCHAR(255),
    credential_ref          VARCHAR(255),
    credential_type         VARCHAR(100),
    provider                VARCHAR(50) NOT NULL DEFAULT 'aws',
    region                  VARCHAR(50),

    -- Resource identification
    resource_uid            TEXT NOT NULL,
    resource_type           VARCHAR(100) NOT NULL,

    -- Network-specific classification
    network_layer           VARCHAR(20),          -- L1_topology, L2_reachability, L3_nacl, L4_sg, L5_lb, L6_waf, L7_flow
    network_modules         TEXT[],               -- {network_isolation, security_group_rules, ...}
    effective_exposure      VARCHAR(50),           -- internet, cross_vpc, vpc_internal, subnet_only, isolated

    -- Finding metadata
    severity                VARCHAR(20) NOT NULL,
    status                  VARCHAR(20) NOT NULL DEFAULT 'FAIL',  -- FAIL, PASS, WARN
    rule_id                 VARCHAR(255),
    title                   VARCHAR(500),
    description             TEXT,
    remediation             TEXT,

    -- Enrichment (JSONB — consumed by threat engine)
    finding_data            JSONB DEFAULT '{}'::jsonb,
    -- finding_data includes:
    --   network_context     — vpc_id, subnet_id, is_public, cidr, attached_resources
    --   reachability        — internet_reachable, cross_vpc_paths, route_hops
    --   nacl_posture        — allows_ssh, allows_rdp, filtering_score
    --   sg_posture          — open_ports, sensitive_ports, blast_radius
    --   mitre_techniques    — [T1190, T1133, ...]
    --   attack_path_category — exposure | lateral_movement
    --   network_relationships — [{source, target, relation, ports, category}]

    -- Timestamps
    first_seen_at           TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_seen_at            TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_network_finding_tenant
        FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- -----------------------------------------------------------------------------
-- network_topology_snapshot — VPC/subnet/route topology per scan
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS network_topology_snapshot (
    id                      BIGSERIAL PRIMARY KEY,
    scan_run_id             VARCHAR(255) NOT NULL,
    tenant_id               VARCHAR(255) NOT NULL,
    account_id              VARCHAR(255),
    provider                VARCHAR(50) NOT NULL DEFAULT 'aws',
    region                  VARCHAR(50),

    -- VPC identification
    vpc_id                  VARCHAR(255) NOT NULL,
    vpc_cidr_blocks         TEXT[],
    is_default_vpc          BOOLEAN DEFAULT FALSE,
    flow_log_enabled        BOOLEAN DEFAULT FALSE,

    -- Topology (JSONB for flexible structure)
    subnets                 JSONB DEFAULT '[]'::jsonb,    -- [{subnet_id, cidr, az, is_public, nacl_id, route_table_id}]
    route_tables            JSONB DEFAULT '[]'::jsonb,    -- [{rtb_id, subnet_ids, routes: [{dest, target_type, target_id, is_blackhole}]}]
    peering_connections     JSONB DEFAULT '[]'::jsonb,    -- [{pcx_id, peer_vpc_id, peer_account, peer_region}]
    tgw_attachments         JSONB DEFAULT '[]'::jsonb,    -- [{tgw_id, attachment_id, tgw_route_table}]
    igw_id                  VARCHAR(255),                  -- null = no IGW = isolated VPC
    nat_gateways            JSONB DEFAULT '[]'::jsonb,    -- [{nat_id, subnet_id, eip, connectivity_type}]
    vpc_endpoints           JSONB DEFAULT '[]'::jsonb,    -- [{vpce_id, service_name, type: gateway|interface}]
    network_firewalls       JSONB DEFAULT '[]'::jsonb,    -- [{fw_id, policy_arn, subnet_ids}]

    -- Computed posture
    isolation_score         INTEGER DEFAULT 0,             -- 0=fully exposed, 100=fully isolated
    public_subnet_count     INTEGER DEFAULT 0,
    private_subnet_count    INTEGER DEFAULT 0,
    has_internet_path       BOOLEAN DEFAULT FALSE,         -- any route to IGW?

    created_at              TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT fk_topology_tenant
        FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- -----------------------------------------------------------------------------
-- network_sg_analysis — Detailed SG analysis per scan
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS network_sg_analysis (
    id                      BIGSERIAL PRIMARY KEY,
    scan_run_id             VARCHAR(255) NOT NULL,
    tenant_id               VARCHAR(255) NOT NULL,
    account_id              VARCHAR(255),
    provider                VARCHAR(50) NOT NULL DEFAULT 'aws',
    region                  VARCHAR(50),

    -- SG identification
    sg_id                   VARCHAR(255) NOT NULL,
    sg_name                 VARCHAR(255),
    vpc_id                  VARCHAR(255),
    resource_uid            TEXT,                           -- SG ARN

    -- Attachment
    attached_resource_count INTEGER DEFAULT 0,
    attached_resources      JSONB DEFAULT '[]'::jsonb,     -- [{uid, type, name}]
    is_default_sg           BOOLEAN DEFAULT FALSE,
    is_orphaned             BOOLEAN DEFAULT FALSE,          -- no ENIs attached

    -- Inbound exposure analysis
    inbound_open_to_world   BOOLEAN DEFAULT FALSE,          -- any 0.0.0.0/0 rule
    inbound_sensitive_ports JSONB DEFAULT '[]'::jsonb,      -- [{port, protocol, cidrs, service_name}]
    inbound_all_ports       BOOLEAN DEFAULT FALSE,          -- 0-65535 from any
    inbound_rule_count      INTEGER DEFAULT 0,

    -- Outbound exposure
    outbound_unrestricted   BOOLEAN DEFAULT FALSE,          -- all to 0.0.0.0/0
    outbound_rule_count     INTEGER DEFAULT 0,

    -- Cross-references
    sg_to_sg_refs           TEXT[],                         -- other SGs this SG references
    referenced_by_sgs       TEXT[],                         -- SGs that reference this SG

    -- Layered exposure (combined L1+L2+L3+L4)
    nacl_mitigates          BOOLEAN DEFAULT FALSE,          -- NACL blocks what SG allows?
    subnet_is_public        BOOLEAN DEFAULT FALSE,          -- subnet has IGW route?
    effective_internet_exposure BOOLEAN DEFAULT FALSE,       -- truly internet-reachable?
    effective_exposure_level VARCHAR(50),                    -- internet, cross_vpc, vpc, subnet, none

    -- Raw rules
    inbound_rules           JSONB DEFAULT '[]'::jsonb,
    outbound_rules          JSONB DEFAULT '[]'::jsonb,
    analysis_data           JSONB DEFAULT '{}'::jsonb,

    created_at              TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT fk_sg_analysis_tenant
        FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- -----------------------------------------------------------------------------
-- network_exposure_paths — Computed end-to-end reachability paths
-- (consumed by threat engine for attack chain building)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS network_exposure_paths (
    id                      BIGSERIAL PRIMARY KEY,
    scan_run_id             VARCHAR(255) NOT NULL,
    tenant_id               VARCHAR(255) NOT NULL,
    account_id              VARCHAR(255),
    provider                VARCHAR(50) NOT NULL DEFAULT 'aws',
    region                  VARCHAR(50),

    -- Path classification
    path_type               VARCHAR(50) NOT NULL,           -- internet_to_resource, cross_vpc, lateral_movement, cross_subnet
    source_type             VARCHAR(50),                    -- internet, vpc, subnet, sg, resource
    source_id               VARCHAR(255),                   -- "Internet" or vpc-xxx, subnet-xxx, sg-xxx
    target_resource_uid     TEXT NOT NULL,
    target_resource_type    VARCHAR(100),

    -- Path hops (ordered list through network layers)
    path_hops               JSONB NOT NULL DEFAULT '[]'::jsonb,
    -- [{layer: "L2", type: "igw", id: "igw-xxx"},
    --  {layer: "L2", type: "route", dest: "0.0.0.0/0", target: "igw-xxx"},
    --  {layer: "L3", type: "nacl", id: "acl-xxx", action: "allow", ports: [22,443]},
    --  {layer: "L4", type: "sg", id: "sg-xxx", action: "allow", ports: [22,443]}]

    -- Exposure assessment
    exposed_ports           JSONB DEFAULT '[]'::jsonb,      -- [{port: 22, protocol: "tcp", service: "ssh"}]
    exposed_sensitive_ports JSONB DEFAULT '[]'::jsonb,      -- subset: only SSH/RDP/DB ports
    severity                VARCHAR(20) NOT NULL,
    blocked_by              VARCHAR(255),                    -- NULL = fully open; "nacl:acl-xxx" or "sg:sg-xxx"
    is_fully_exposed        BOOLEAN DEFAULT FALSE,           -- all layers allow

    -- For threat engine
    attack_path_category    VARCHAR(50),                     -- exposure, lateral_movement
    blast_radius            INTEGER DEFAULT 0,               -- resources reachable beyond this point
    mitre_techniques        TEXT[],                          -- {T1190, T1133, T1048, ...}

    created_at              TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT fk_exposure_path_tenant
        FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- -----------------------------------------------------------------------------
-- network_anomalies — VPC Flow Log anomalies (L7 — config vs. runtime)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS network_anomalies (
    anomaly_id              VARCHAR(255) PRIMARY KEY DEFAULT uuid_generate_v4()::text,
    scan_run_id             VARCHAR(255),
    tenant_id               VARCHAR(255) NOT NULL,
    account_id              VARCHAR(255),

    -- Anomaly classification
    anomaly_type            VARCHAR(50) NOT NULL,            -- data_exfil, lateral_movement, port_scan, unexpected_traffic, malicious_ip
    severity                VARCHAR(20) NOT NULL DEFAULT 'medium',

    -- Flow details
    src_ip                  VARCHAR(45),
    dst_ip                  VARCHAR(45),
    dst_port                INTEGER,
    protocol                VARCHAR(10),
    flow_action             VARCHAR(10),                     -- ACCEPT, REJECT

    -- Metrics
    bytes_total             BIGINT,
    packets_total           BIGINT,
    baseline_bytes          BIGINT,
    deviation_factor        NUMERIC(8,2),

    -- Resource resolution
    src_resource_uid        TEXT,
    dst_resource_uid        TEXT,
    src_sg_ids              TEXT[],
    dst_sg_ids              TEXT[],
    vpc_id                  VARCHAR(255),
    subnet_id               VARCHAR(255),

    -- Config vs. runtime correlation
    sg_allows_traffic       BOOLEAN,                         -- SG rule permits this flow?
    nacl_allows_traffic     BOOLEAN,                         -- NACL permits this flow?
    config_runtime_gap      VARCHAR(50),                     -- allowed_but_unexpected, blocked_but_seen, normal

    -- Threat enrichment
    rule_id                 VARCHAR(255),
    mitre_techniques        TEXT[],
    evidence                JSONB DEFAULT '{}'::jsonb,

    detected_at             TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active               BOOLEAN DEFAULT TRUE,

    CONSTRAINT fk_anomaly_tenant
        FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- -----------------------------------------------------------------------------
-- network_baselines — rolling traffic baselines per resource
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS network_baselines (
    id                      BIGSERIAL PRIMARY KEY,
    tenant_id               VARCHAR(255) NOT NULL,
    resource_uid            TEXT NOT NULL,
    vpc_id                  VARCHAR(255),

    -- Metric
    metric_type             VARCHAR(50) NOT NULL,            -- outbound_bytes, inbound_bytes, connection_count, unique_dst_ports
    window_days             INTEGER DEFAULT 14,

    -- Statistics
    baseline_avg            NUMERIC(20,2) DEFAULT 0,
    baseline_p50            NUMERIC(20,2) DEFAULT 0,
    baseline_p95            NUMERIC(20,2) DEFAULT 0,
    std_deviation           NUMERIC(20,2) DEFAULT 0,
    sample_count            INTEGER DEFAULT 0,

    computed_at             TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    valid_until             TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_baseline_tenant
        FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- =============================================================================
-- INDEXES
-- =============================================================================

-- network_report
CREATE INDEX IF NOT EXISTS idx_net_report_tenant ON network_report(tenant_id);
CREATE INDEX IF NOT EXISTS idx_net_report_status ON network_report(status);
CREATE INDEX IF NOT EXISTS idx_net_report_generated ON network_report(generated_at DESC);

-- network_findings
CREATE INDEX IF NOT EXISTS idx_net_findings_scan ON network_findings(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_net_findings_tenant ON network_findings(tenant_id);
CREATE INDEX IF NOT EXISTS idx_net_findings_severity ON network_findings(severity, status);
CREATE INDEX IF NOT EXISTS idx_net_findings_layer ON network_findings(network_layer);
CREATE INDEX IF NOT EXISTS idx_net_findings_resource ON network_findings(resource_uid);
CREATE INDEX IF NOT EXISTS idx_net_findings_exposure ON network_findings(effective_exposure);
CREATE INDEX IF NOT EXISTS idx_net_findings_modules ON network_findings USING gin(network_modules);
CREATE INDEX IF NOT EXISTS idx_net_findings_data ON network_findings USING gin(finding_data);
CREATE INDEX IF NOT EXISTS idx_net_findings_critical
    ON network_findings(scan_run_id) WHERE severity = 'critical' AND status = 'FAIL';

-- network_topology_snapshot
CREATE INDEX IF NOT EXISTS idx_net_topo_scan ON network_topology_snapshot(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_net_topo_tenant ON network_topology_snapshot(tenant_id);
CREATE INDEX IF NOT EXISTS idx_net_topo_vpc ON network_topology_snapshot(vpc_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_net_topo_unique ON network_topology_snapshot(scan_run_id, vpc_id);

-- network_sg_analysis
CREATE INDEX IF NOT EXISTS idx_net_sg_scan ON network_sg_analysis(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_net_sg_tenant ON network_sg_analysis(tenant_id);
CREATE INDEX IF NOT EXISTS idx_net_sg_id ON network_sg_analysis(sg_id);
CREATE INDEX IF NOT EXISTS idx_net_sg_exposure
    ON network_sg_analysis(effective_internet_exposure) WHERE effective_internet_exposure = TRUE;
CREATE UNIQUE INDEX IF NOT EXISTS idx_net_sg_unique ON network_sg_analysis(scan_run_id, sg_id);

-- network_exposure_paths
CREATE INDEX IF NOT EXISTS idx_net_paths_scan ON network_exposure_paths(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_net_paths_tenant ON network_exposure_paths(tenant_id);
CREATE INDEX IF NOT EXISTS idx_net_paths_target ON network_exposure_paths(target_resource_uid);
CREATE INDEX IF NOT EXISTS idx_net_paths_type ON network_exposure_paths(path_type);
CREATE INDEX IF NOT EXISTS idx_net_paths_exposed
    ON network_exposure_paths(scan_run_id) WHERE is_fully_exposed = TRUE;

-- network_anomalies
CREATE INDEX IF NOT EXISTS idx_net_anomaly_tenant ON network_anomalies(tenant_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_net_anomaly_scan ON network_anomalies(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_net_anomaly_type ON network_anomalies(anomaly_type, severity);
CREATE INDEX IF NOT EXISTS idx_net_anomaly_active
    ON network_anomalies(is_active) WHERE is_active = TRUE;

-- network_baselines
CREATE INDEX IF NOT EXISTS idx_net_baseline_resource ON network_baselines(resource_uid, metric_type);
CREATE INDEX IF NOT EXISTS idx_net_baseline_tenant ON network_baselines(tenant_id, computed_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_net_baseline_unique
    ON network_baselines(tenant_id, resource_uid, metric_type);

-- =============================================================================
-- COMMENTS
-- =============================================================================

COMMENT ON TABLE network_report IS 'Network security scan summary with per-layer posture scores and inventory counts';
COMMENT ON TABLE network_findings IS 'Per-resource network posture findings with effective exposure and threat enrichment';
COMMENT ON TABLE network_topology_snapshot IS 'VPC topology snapshot — subnets, routes, peering, endpoints, firewalls';
COMMENT ON TABLE network_sg_analysis IS 'Detailed SG analysis with layered effective internet exposure flag';
COMMENT ON TABLE network_exposure_paths IS 'Computed end-to-end reachability paths for threat engine attack chains';
COMMENT ON TABLE network_anomalies IS 'VPC Flow Log anomalies — config vs. runtime gap detection';
COMMENT ON TABLE network_baselines IS 'Rolling traffic baselines for anomaly detection';
