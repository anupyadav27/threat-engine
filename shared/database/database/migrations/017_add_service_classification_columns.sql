-- =============================================================================
-- Migration 017: Add service classification columns to resource_inventory_identifier
-- =============================================================================
-- Database:  threat_engine_inventory
-- Purpose:   Add 11 new classification columns to resource_inventory_identifier
--            to enable architecture-diagram rendering: scope, category, subcategory,
--            service_model, managed_by, access_pattern, encryption_scope,
--            is_container, container_parent, diagram_priority, csp_category.
--
-- Apply with:
--   psql -h <RDS_HOST> -U postgres -d threat_engine_inventory \
--     -f 017_add_service_classification_columns.sql
--
-- Safe to re-run: all DDL uses IF NOT EXISTS / ADD COLUMN IF NOT EXISTS.
-- =============================================================================

-- ── New Columns ──────────────────────────────────────────────────────────────

-- scope: WHERE this resource lives in the hierarchy
-- global = account-level (IAM, S3, CloudFront)
-- regional = region-level but outside VPC (Lambda, DynamoDB, KMS)
-- vpc = VPC-level (security-group, route-table, IGW)
-- subnet = subnet-level (EC2 instance, RDS, NAT-GW)
-- az = availability-zone-level (EBS volume)
-- namespace = K8s namespace-scoped
-- cluster = K8s cluster-scoped
ALTER TABLE resource_inventory_identifier
  ADD COLUMN IF NOT EXISTS scope VARCHAR(20);

-- category: top-level functional grouping (15 values)
-- compute | container | database | storage | network | edge | security |
-- identity | encryption | monitoring | management | messaging | analytics | ai_ml | iot
ALTER TABLE resource_inventory_identifier
  ADD COLUMN IF NOT EXISTS category VARCHAR(30);

-- subcategory: finer grouping within category (~50 values)
-- compute: vm, autoscaling, batch, serverless_function, serverless_app, platform, bare_metal, edge_compute
-- container: orchestration_k8s, orchestration_managed, runtime, registry, mesh
-- database: relational, relational_serverless, nosql_keyvalue, nosql_document, nosql_graph,
--           nosql_timeseries, nosql_ledger, nosql_wide_column, cache, in_memory, warehouse, search
-- storage: object, block, file, archive, hybrid, backup, data_transfer
-- network: vpc, subnet, route_table, peering, transit, endpoint, direct_connect, dns, private_dns, mesh
-- edge: cdn, load_balancer, api_gateway, igw, nat, waf, global_accelerator
-- security: firewall, posture, threat_detection, vulnerability, data_protection, compliance, security_lake
-- identity: iam_role, iam_user, iam_group, iam_policy, sso, directory, federation, access_analyzer, resource_access
-- encryption: key_management, secrets, certificate, hsm
-- monitoring: metrics, logs, alarms, tracing, dashboards, observability, synthetic, flow_logs
-- management: audit, config_compliance, iac, automation, organizations, cost, backup, scheduler, tagging
-- messaging: queue, topic, event_bus, stream, workflow, mq
-- analytics: etl, query, bi, lake, streaming_analytics, data_exchange
-- ai_ml: foundation_model, training, inference, vision, language, speech, document
-- iot: platform, edge, analytics, device_mgmt
ALTER TABLE resource_inventory_identifier
  ADD COLUMN IF NOT EXISTS subcategory VARCHAR(50);

-- service_model: responsibility model
-- IaaS = you manage OS/runtime (EC2, Azure VM)
-- PaaS = you manage data/config (RDS, S3, DynamoDB)
-- FaaS = you manage code only (Lambda, Cloud Functions)
-- SaaS = you just use it (WorkMail, QuickSight)
ALTER TABLE resource_inventory_identifier
  ADD COLUMN IF NOT EXISTS service_model VARCHAR(10);

-- managed_by: who operates this resource
-- aws|azure|gcp|oci|alicloud|ibm = CSP fully manages (S3, Lambda, DynamoDB)
-- customer = you operate it (EC2, self-hosted DB on VM)
-- shared = CSP runs infra, you configure (EKS control plane, RDS engine)
ALTER TABLE resource_inventory_identifier
  ADD COLUMN IF NOT EXISTS managed_by VARCHAR(20);

-- access_pattern: network reachability
-- public = CAN face internet (ALB, CloudFront, S3 with public access)
-- private = VPC/subnet only, never directly internet-facing (RDS, ElastiCache)
-- internal = AWS/CSP control plane only, no data plane network (IAM, KMS, CloudTrail)
ALTER TABLE resource_inventory_identifier
  ADD COLUMN IF NOT EXISTS access_pattern VARCHAR(20);

-- encryption_scope: what encryption concern this resource addresses
-- at_rest = encrypts stored data (KMS, EBS encryption, S3 SSE)
-- in_transit = encrypts data in motion (ACM/TLS, VPN, PrivateLink)
-- both = covers both scopes (some KMS usage)
-- null = not an encryption resource
ALTER TABLE resource_inventory_identifier
  ADD COLUMN IF NOT EXISTS encryption_scope VARCHAR(20);

-- is_container: does this resource CONTAIN other resources in diagram?
-- true: VPC, Subnet, Account, EKS cluster, Namespace
-- false: EC2 instance, S3 bucket, Lambda function
ALTER TABLE resource_inventory_identifier
  ADD COLUMN IF NOT EXISTS is_container BOOLEAN DEFAULT FALSE;

-- container_parent: what hierarchy level does this nest INSIDE?
-- null = top-level or root container (org, account)
-- org = inside an organization (management account)
-- account = inside account (S3, IAM, CloudFront - global services)
-- region = inside region (Lambda, DynamoDB, KMS - regional outside VPC)
-- vpc = inside VPC (subnet, security-group, route-table)
-- subnet = inside subnet (EC2, RDS, NAT-GW)
-- cluster = inside EKS/ECS cluster
-- namespace = inside K8s namespace
ALTER TABLE resource_inventory_identifier
  ADD COLUMN IF NOT EXISTS container_parent VARCHAR(30);

-- diagram_priority: which resources to show first when space is limited
-- 1 = always show (VPC, EC2, RDS, S3, Lambda, EKS)
-- 2 = show if present (ALB, DynamoDB, SQS, KMS)
-- 3 = show in expanded view (Security Group, Route Table, ENI)
-- 4 = show on demand (CloudWatch alarm, Config rule)
-- 5 = hide by default (quotas, metadata, internal resources)
ALTER TABLE resource_inventory_identifier
  ADD COLUMN IF NOT EXISTS diagram_priority SMALLINT DEFAULT 5;

-- csp_category: official category name as defined by the CSP
-- e.g., "Compute", "Database", "Networking & Content Delivery"
-- Useful for filtering/grouping in CSP-native terms
ALTER TABLE resource_inventory_identifier
  ADD COLUMN IF NOT EXISTS csp_category VARCHAR(100);

-- ── Indexes for common query patterns ────────────────────────────────────────

-- Diagram queries: "all resources in category X for this CSP"
CREATE INDEX IF NOT EXISTS idx_rii_csp_category
  ON resource_inventory_identifier(csp, category);

-- Hierarchy builder: "all containers at scope X"
CREATE INDEX IF NOT EXISTS idx_rii_scope
  ON resource_inventory_identifier(scope);

-- Diagram filtering: "priority 1-2 resources only"
CREATE INDEX IF NOT EXISTS idx_rii_diagram_priority
  ON resource_inventory_identifier(diagram_priority)
  WHERE diagram_priority <= 3;

-- Container lookup: "all resources whose parent is vpc"
CREATE INDEX IF NOT EXISTS idx_rii_container_parent
  ON resource_inventory_identifier(container_parent)
  WHERE container_parent IS NOT NULL;

-- Service model filtering
CREATE INDEX IF NOT EXISTS idx_rii_service_model
  ON resource_inventory_identifier(service_model)
  WHERE service_model IS NOT NULL;

-- ── Comments ─────────────────────────────────────────────────────────────────

COMMENT ON COLUMN resource_inventory_identifier.scope IS
  'Hierarchy scope: global|regional|vpc|subnet|az|namespace|cluster — determines nesting level in diagram';

COMMENT ON COLUMN resource_inventory_identifier.category IS
  'Functional category (15 values): compute|container|database|storage|network|edge|security|identity|encryption|monitoring|management|messaging|analytics|ai_ml|iot';

COMMENT ON COLUMN resource_inventory_identifier.subcategory IS
  'Finer classification within category (~50 values): vm|relational|object|firewall|iam_role|key_management|metrics|etl|...';

COMMENT ON COLUMN resource_inventory_identifier.service_model IS
  'Responsibility model: IaaS|PaaS|FaaS|SaaS';

COMMENT ON COLUMN resource_inventory_identifier.managed_by IS
  'Operations responsibility: aws|azure|gcp|oci|alicloud|ibm|customer|shared';

COMMENT ON COLUMN resource_inventory_identifier.access_pattern IS
  'Network reachability: public|private|internal';

COMMENT ON COLUMN resource_inventory_identifier.encryption_scope IS
  'Encryption concern: at_rest|in_transit|both|null';

COMMENT ON COLUMN resource_inventory_identifier.is_container IS
  'Whether this resource contains child resources in the hierarchy (VPC, subnet, cluster)';

COMMENT ON COLUMN resource_inventory_identifier.container_parent IS
  'What hierarchy level this nests inside: null|org|account|region|vpc|subnet|cluster|namespace';

COMMENT ON COLUMN resource_inventory_identifier.diagram_priority IS
  'Display priority 1-5: 1=always show, 5=hide by default';

COMMENT ON COLUMN resource_inventory_identifier.csp_category IS
  'Official CSP category name as defined by provider docs';
