#!/usr/bin/env python3
"""
Create and seed architecture tables from resource_inventory_identifier.

1. Creates architecture_resource_placement + architecture_relationship_rules
2. Seeds placement from resource_inventory_identifier (all CSPs)
3. Seeds relationship rules for AWS (extendable to other CSPs)

Usage:
    python scripts/create_architecture_tables.py [--dry-run]
"""

import argparse
import os

import psycopg2
from psycopg2.extras import execute_values

DDL_PLACEMENT = """
CREATE TABLE IF NOT EXISTS architecture_resource_placement (
    id SERIAL PRIMARY KEY,
    csp VARCHAR(20) NOT NULL,
    resource_type VARCHAR(200) NOT NULL,

    -- PRIMARY routing field — which zone/strip/layer the resource renders in
    -- internet_edge | network | compute | services | supporting | hidden
    diagram_zone VARCHAR(30) NOT NULL DEFAULT 'services',

    arch_layer INTEGER NOT NULL DEFAULT 3,
    placement_scope VARCHAR(50),
    placement_parent VARCHAR(200),
    placement_zone VARCHAR(50) DEFAULT 'center',
    visual_group VARCHAR(100) NOT NULL DEFAULT 'other',
    visual_subgroup VARCHAR(100),
    is_container BOOLEAN DEFAULT FALSE,
    container_depth INTEGER DEFAULT 0,
    display_priority INTEGER DEFAULT 3,
    show_as VARCHAR(50) DEFAULT 'box',
    icon_type VARCHAR(100),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(csp, resource_type)
);
CREATE INDEX IF NOT EXISTS idx_arp_csp_zone     ON architecture_resource_placement(csp, diagram_zone);
CREATE INDEX IF NOT EXISTS idx_arp_csp_layer    ON architecture_resource_placement(csp, arch_layer);
CREATE INDEX IF NOT EXISTS idx_arp_visual_group ON architecture_resource_placement(csp, visual_group);
CREATE INDEX IF NOT EXISTS idx_arp_priority     ON architecture_resource_placement(csp, display_priority);
"""

DDL_RELATIONSHIPS = """
CREATE TABLE IF NOT EXISTS architecture_relationship_rules (
    id SERIAL PRIMARY KEY,
    csp VARCHAR(20) NOT NULL,
    rel_category VARCHAR(50) NOT NULL,
    rel_type VARCHAR(100) NOT NULL,
    from_resource_type VARCHAR(200) NOT NULL,
    to_resource_type VARCHAR(200) NOT NULL,
    source_field VARCHAR(200),
    source_field_item VARCHAR(200),
    target_uid_pattern VARCHAR(500),
    arch_layer INTEGER NOT NULL DEFAULT 3,
    line_style VARCHAR(50) DEFAULT 'solid',
    line_color VARCHAR(50),
    line_label VARCHAR(100),
    bidirectional BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(csp, rel_category, from_resource_type, to_resource_type, rel_type)
);
CREATE INDEX IF NOT EXISTS idx_arr_csp_category ON architecture_relationship_rules(csp, rel_category);
CREATE INDEX IF NOT EXISTS idx_arr_from_type ON architecture_relationship_rules(csp, from_resource_type);
CREATE INDEX IF NOT EXISTS idx_arr_layer ON architecture_relationship_rules(csp, arch_layer);
"""

# ── Visual group mapping from category/service ──────────────────────────
VISUAL_GROUP_MAP = {
    # AWS compute
    "ec2.instance": ("compute", "ec2"),
    "ec2.spot-instance-request": ("compute", "ec2"),
    "eks.cluster": ("compute-container", "eks"),
    "eks.nodegroup": ("compute-container", "eks"),
    "ecs.cluster": ("compute-container", "ecs"),
    "ecs.service": ("compute-container", "ecs"),
    "ecs.task-definition": ("compute-container", "ecs"),
    "rds.db-instance": ("compute-database", "rds"),
    "rds.db-cluster": ("compute-database", "rds"),
    "dynamodb.table": ("compute-database", "dynamodb"),
    "elasticache.cluster": ("compute-database", "elasticache"),
    "elasticache.replication-group": ("compute-database", "elasticache"),
    "neptune.db-instance": ("compute-database", "neptune"),
    "redshift.cluster": ("compute-database", "redshift"),
    "docdb.db-instance": ("compute-database", "docdb"),
    "lambda.function": ("compute-serverless", "lambda"),
    "stepfunctions.state-machine": ("compute-serverless", "stepfunctions"),
    "sagemaker.notebook-instance": ("compute-analytics", "sagemaker"),
    "emr.cluster": ("compute-analytics", "emr"),
    # Network
    "ec2.vpc": ("network", "vpc"),
    "ec2.subnet": ("network", "subnet"),
    "ec2.internet-gateway": ("network-gateway", "igw"),
    "ec2.nat-gateway": ("network-gateway", "natgw"),
    "ec2.transit-gateway": ("network-gateway", "tgw"),
    "ec2.vpn-gateway": ("network-gateway", "vpn"),
    "ec2.vpc-endpoint": ("network-endpoint", "vpce"),
    "ec2.network-interface": ("network", "eni"),
    "ec2.route-table": ("network", "rt"),
    "ec2.network-acl": ("security", "nacl"),
    "ec2.security-group": ("security", "sg"),
    "elbv2.load-balancer": ("network-lb", "elbv2"),
    "elb.load-balancer": ("network-lb", "elb"),
    "elasticloadbalancing.load-balancer": ("network-lb", "elb"),
    "route53.hosted-zone": ("network-dns", "r53"),
    # Storage
    "s3.bucket": ("storage-object", "s3"),
    "ec2.volume": ("storage-block", "ebs"),
    "ec2.snapshot": ("storage-block", "ebs"),
    "efs.file-system": ("storage-file", "efs"),
    # Identity
    "iam.role": ("identity", "iam"),
    "iam.user": ("identity", "iam"),
    "iam.policy": ("identity", "iam"),
    "iam.group": ("identity", "iam"),
    "iam.instance-profile": ("identity", "iam"),
    # Encryption
    "kms.key": ("encryption", "kms"),
    "kms.alias": ("encryption", "kms"),
    "acm.certificate": ("encryption", "acm"),
    # Monitoring
    "cloudwatch.alarm": ("monitoring", "cw"),
    "logs.log-group": ("monitoring", "cwlogs"),
    "cloudtrail.trail": ("monitoring", "cloudtrail"),
    # Messaging
    "sqs.queue": ("messaging", "sqs"),
    "sns.topic": ("messaging", "sns"),
    "events.rule": ("messaging", "eventbridge"),
    # Public
    "cloudfront.distribution": ("public", "cloudfront"),
    "apigateway.rest-api": ("public", "apigw"),
    "apigatewayv2.api": ("public", "apigw"),
    # Security
    "waf.web-acl": ("security", "waf"),
    "wafv2.web-acl": ("security", "waf"),
    "guardduty.detector": ("security", "guardduty"),
    # ECR
    "ecr.repository": ("compute-container", "ecr"),
}

# ── PLACEMENT_MAP ──────────────────────────────────────────────────────────────
# Each entry defines how one resource type is rendered in the landscape diagram.
#
# diagram_zone (NEW — primary routing field):
#   internet_edge  = global top strip  (S3, CloudFront, Route53, API GW)
#   network        = Region card, Network layer  (VPC/Subnet containers + gateway icons)
#   compute        = Region card, Compute layer  (EC2, RDS, EKS — subnet-scoped)
#   services       = Region card, Services layer (Lambda, DynamoDB, SQS — regional)
#   supporting     = bottom strip  (IAM, KMS, CloudWatch, SG, EBS)
#   hidden         = excluded from diagram  (sub-resources, config-only, ephemeral)
#
# show (render style within the zone):
#   box    = full resource chip  (default)
#   icon   = small inline pill   (gateways, NAT — inside VPC network header)
#   badge  = count badge on parent  (RT, NACL — shown as "RT×3" on subnet)
#   count  = number only  (security groups — shown as "SG: 7" in supporting)
#   hidden = never render  (duplicate of diagram_zone=hidden, for safety)
# ──────────────────────────────────────────────────────────────────────────────
PLACEMENT_MAP = {

    # ── NETWORK layer — VPC/Subnet containers ─────────────────────────────────
    "ec2.vpc": {
        "dz": "network",   "layer": 2, "scope": "regional",  "parent": "region",
        "container": True, "depth": 2, "priority": 1,
    },
    "ec2.subnet": {
        "dz": "network",   "layer": 2, "scope": "az",         "parent": "ec2.vpc",
        "container": True, "depth": 1, "priority": 1,
    },

    # ── NETWORK layer — gateway icons inside VPC header ────────────────────────
    "ec2.internet-gateway": {
        "dz": "network",   "layer": 2, "scope": "vpc",        "parent": "ec2.vpc",
        "priority": 2,     "show": "icon",
    },
    "ec2.nat-gateway": {
        "dz": "network",   "layer": 2, "scope": "subnet",     "parent": "ec2.subnet",
        "priority": 2,     "show": "icon",
    },
    "ec2.transit-gateway": {
        "dz": "network",   "layer": 2, "scope": "regional",   "parent": "region",
        "priority": 1,     "show": "box",
    },
    "ec2.vpn-gateway": {
        "dz": "network",   "layer": 2, "scope": "vpc",        "parent": "ec2.vpc",
        "priority": 2,     "show": "icon",
    },
    "ec2.vpc-peering-connection": {
        "dz": "network",   "layer": 2, "scope": "vpc",        "parent": "ec2.vpc",
        "priority": 3,     "show": "icon",
    },

    # ── NETWORK layer — subnet badges (shown as RT×N / NACL×N on subnet header) ──
    "ec2.network-acl": {
        "dz": "network",   "layer": 2, "scope": "subnet",     "parent": "ec2.subnet",
        "priority": 3,     "show": "badge",
    },
    "ec2.route-table": {
        "dz": "network",   "layer": 2, "scope": "subnet",     "parent": "ec2.subnet",
        "priority": 4,     "show": "badge",
    },
    "ec2.dhcp-options": {
        "dz": "hidden",    "layer": 2, "priority": 5,         "show": "hidden",
    },

    # ── COMPUTE layer — subnet-scoped primary compute ─────────────────────────
    "ec2.instance": {
        "dz": "compute",   "layer": 3, "scope": "subnet",     "parent": "ec2.subnet",
        "priority": 1,
    },
    "eks.cluster": {
        "dz": "compute",   "layer": 3, "scope": "multi-subnet","parent": "ec2.vpc",
        "container": True, "depth": 1, "priority": 1,
    },
    "eks.nodegroup": {
        "dz": "compute",   "layer": 3, "scope": "multi-subnet","parent": "eks.cluster",
        "priority": 2,
    },
    "ecs.cluster": {
        "dz": "compute",   "layer": 3, "scope": "multi-subnet","parent": "ec2.vpc",
        "container": True, "depth": 1, "priority": 1,
    },
    "ecs.service": {
        "dz": "compute",   "layer": 3, "scope": "subnet",     "parent": "ecs.cluster",
        "priority": 2,
    },
    "rds.db-instance": {
        "dz": "compute",   "layer": 3, "scope": "multi-az",   "parent": "ec2.subnet",
        "priority": 1,
    },
    "rds.db-cluster": {
        "dz": "compute",   "layer": 3, "scope": "multi-az",   "parent": "ec2.subnet",
        "priority": 1,
    },
    "elasticache.cluster": {
        "dz": "compute",   "layer": 3, "scope": "subnet",     "parent": "ec2.subnet",
        "priority": 2,
    },
    "elasticache.replication-group": {
        "dz": "compute",   "layer": 3, "scope": "subnet",     "parent": "ec2.subnet",
        "priority": 2,
    },
    "redshift.cluster": {
        "dz": "compute",   "layer": 3, "scope": "subnet",     "parent": "ec2.subnet",
        "priority": 2,
    },
    "neptune.db-instance": {
        "dz": "compute",   "layer": 3, "scope": "subnet",     "parent": "ec2.subnet",
        "priority": 2,
    },
    "docdb.db-instance": {
        "dz": "compute",   "layer": 3, "scope": "subnet",     "parent": "ec2.subnet",
        "priority": 2,
    },
    "elbv2.load-balancer": {
        "dz": "compute",   "layer": 3, "scope": "multi-subnet","parent": "ec2.subnet",
        "priority": 1,
    },
    "elb.load-balancer": {
        "dz": "compute",   "layer": 3, "scope": "multi-subnet","parent": "ec2.subnet",
        "priority": 1,
    },
    "ec2.vpc-endpoint": {
        "dz": "compute",   "layer": 3, "scope": "subnet",     "parent": "ec2.subnet",
        "priority": 3,     "show": "icon",
    },
    "sagemaker.notebook-instance": {
        "dz": "compute",   "layer": 3, "scope": "subnet",     "parent": "ec2.subnet",
        "priority": 3,
    },
    "emr.cluster": {
        "dz": "compute",   "layer": 3, "scope": "subnet",     "parent": "ec2.subnet",
        "priority": 3,
    },

    # ── SERVICES layer — regional services outside VPC ────────────────────────
    "lambda.function": {
        "dz": "services",  "layer": 3, "scope": "regional",   "parent": "region",
        "priority": 2,
    },
    "dynamodb.table": {
        "dz": "services",  "layer": 3, "scope": "regional",   "parent": "region",
        "priority": 2,
    },
    "sqs.queue": {
        "dz": "services",  "layer": 3, "scope": "regional",   "parent": "region",
        "priority": 3,
    },
    "sns.topic": {
        "dz": "services",  "layer": 3, "scope": "regional",   "parent": "region",
        "priority": 3,
    },
    "stepfunctions.state-machine": {
        "dz": "services",  "layer": 3, "scope": "regional",   "parent": "region",
        "priority": 3,
    },
    "events.rule": {
        "dz": "services",  "layer": 3, "scope": "regional",   "parent": "region",
        "priority": 4,
    },
    "kinesis.stream": {
        "dz": "services",  "layer": 3, "scope": "regional",   "parent": "region",
        "priority": 3,
    },
    "firehose.delivery-stream": {
        "dz": "services",  "layer": 3, "scope": "regional",   "parent": "region",
        "priority": 3,
    },
    "opensearch.domain": {
        "dz": "services",  "layer": 3, "scope": "regional",   "parent": "region",
        "priority": 3,
    },

    # ── INTERNET_EDGE — global/public-facing services ─────────────────────────
    "s3.bucket": {
        "dz": "internet_edge", "layer": 3, "scope": "global", "parent": "account",
        "priority": 1,
    },
    "cloudfront.distribution": {
        "dz": "internet_edge", "layer": 3, "scope": "global", "parent": "account",
        "priority": 1,
    },
    "route53.hosted-zone": {
        "dz": "internet_edge", "layer": 3, "scope": "global", "parent": "account",
        "priority": 2,
    },
    "apigateway.rest-api": {
        "dz": "internet_edge", "layer": 3, "scope": "regional","parent": "region",
        "priority": 2,
    },
    "apigatewayv2.api": {
        "dz": "internet_edge", "layer": 3, "scope": "regional","parent": "region",
        "priority": 2,
    },
    "wafv2.web-acl": {
        "dz": "internet_edge", "layer": 3, "scope": "global", "parent": "account",
        "priority": 2,
    },
    "waf.web-acl": {
        "dz": "internet_edge", "layer": 3, "scope": "global", "parent": "account",
        "priority": 2,
    },
    "shield.protection": {
        "dz": "internet_edge", "layer": 3, "scope": "global", "parent": "account",
        "priority": 3,
    },

    # ── SUPPORTING — IAM, encryption, observability ───────────────────────────
    "iam.role": {
        "dz": "supporting", "layer": 4, "scope": "global",    "parent": "account",
        "priority": 2,
    },
    "iam.user": {
        "dz": "supporting", "layer": 4, "scope": "global",    "parent": "account",
        "priority": 2,
    },
    "iam.group": {
        "dz": "supporting", "layer": 4, "scope": "global",    "parent": "account",
        "priority": 3,
    },
    "iam.policy": {
        "dz": "supporting", "layer": 4, "scope": "global",    "parent": "account",
        "priority": 3,
    },
    "iam.instance-profile": {
        "dz": "supporting", "layer": 4, "scope": "global",    "parent": "account",
        "priority": 4,
    },
    "kms.key": {
        "dz": "supporting", "layer": 4, "scope": "regional",  "parent": "region",
        "priority": 2,
    },
    "kms.alias": {
        "dz": "hidden",    "layer": 4, "priority": 5,         "show": "hidden",
    },
    "acm.certificate": {
        "dz": "supporting", "layer": 4, "scope": "regional",  "parent": "region",
        "priority": 3,
    },
    "secretsmanager.secret": {
        "dz": "supporting", "layer": 4, "scope": "regional",  "parent": "region",
        "priority": 3,
    },
    "ssm.parameter": {
        "dz": "hidden",    "layer": 4, "priority": 5,         "show": "hidden",
    },
    "ec2.security-group": {
        "dz": "supporting", "layer": 4, "scope": "vpc",       "parent": "ec2.vpc",
        "priority": 3,     "show": "count",
    },
    "ec2.network-interface": {
        "dz": "hidden",    "layer": 3, "scope": "subnet",     "parent": "ec2.instance",
        "priority": 5,     "show": "hidden",
        # ENIs are shown as expandable children on EC2 chips, not standalone
    },
    "ec2.volume": {
        "dz": "supporting", "layer": 4, "scope": "az",        "parent": "ec2.instance",
        "priority": 4,     "show": "badge",
    },
    "ec2.snapshot": {
        "dz": "hidden",    "layer": 4, "priority": 5,         "show": "hidden",
    },
    "efs.file-system": {
        "dz": "supporting", "layer": 4, "scope": "regional",  "parent": "region",
        "priority": 3,
    },
    "ecr.repository": {
        "dz": "supporting", "layer": 4, "scope": "regional",  "parent": "region",
        "priority": 3,
    },
    "cloudtrail.trail": {
        "dz": "supporting", "layer": 4, "scope": "regional",  "parent": "region",
        "priority": 3,
    },
    "logs.log-group": {
        "dz": "supporting", "layer": 4, "scope": "regional",  "parent": "region",
        "priority": 4,
    },
    "cloudwatch.alarm": {
        "dz": "supporting", "layer": 4, "scope": "regional",  "parent": "region",
        "priority": 4,
    },
    "cloudwatch.dashboard": {
        "dz": "hidden",    "layer": 4, "priority": 5,         "show": "hidden",
    },
    "guardduty.detector": {
        "dz": "supporting", "layer": 4, "scope": "regional",  "parent": "region",
        "priority": 4,
    },
    "config.configuration-recorder": {
        "dz": "hidden",    "layer": 4, "priority": 5,         "show": "hidden",
    },
    "config.config-rule": {
        "dz": "hidden",    "layer": 4, "priority": 5,         "show": "hidden",
    },
    "servicecatalog.portfolio": {
        "dz": "hidden",    "layer": 4, "priority": 5,         "show": "hidden",
    },
}

# ── AWS Architecture Relationship Rules ──────────────────────────────────
AWS_RELATIONSHIPS = [
    # TOPOLOGY (Layer 2)
    ("topology", "contains", "ec2.vpc", "ec2.subnet", "Subnets", None, None, 2, "none"),
    ("topology", "in_az", "ec2.subnet", "availability-zone", "AvailabilityZone", None, None, 2, "none"),
    ("topology", "attached_to", "ec2.vpc", "ec2.internet-gateway", "InternetGatewayId", None, "arn:aws:ec2:{region}:{account}:internet-gateway/{value}", 2, "solid"),
    ("topology", "attached_to", "ec2.vpc", "ec2.nat-gateway", None, None, None, 2, "solid"),
    ("topology", "attached_to", "ec2.transit-gateway", "ec2.vpc", None, None, None, 2, "dashed"),
    ("topology", "protected_by", "ec2.subnet", "ec2.network-acl", "NetworkAclAssociationId", None, None, 2, "none"),
    ("topology", "peered_with", "ec2.vpc", "ec2.vpc", "AccepterVpcInfo.VpcId", None, "arn:aws:ec2:{region}:{account}:vpc/{value}", 2, "dashed"),
    ("topology", "attached_to", "ec2.vpc", "ec2.dhcp-options", "DhcpOptionsId", None, None, 2, "none"),

    # PLACEMENT (Layer 3) — resource in location
    ("placement", "in_subnet", "ec2.instance", "ec2.subnet", "SubnetId", None, "arn:aws:ec2:{region}:{account}:subnet/{value}", 3, "none"),
    ("placement", "in_vpc", "ec2.instance", "ec2.vpc", "VpcId", None, "arn:aws:ec2:{region}:{account}:vpc/{value}", 3, "none"),
    ("placement", "in_subnet", "rds.db-instance", "ec2.subnet", "DBSubnetGroup.Subnets", "SubnetIdentifier", "arn:aws:ec2:{region}:{account}:subnet/{value}", 3, "none"),
    ("placement", "in_subnet", "eks.cluster", "ec2.subnet", "ResourcesVpcConfig.SubnetIds", None, "arn:aws:ec2:{region}:{account}:subnet/{value}", 3, "none"),
    ("placement", "in_vpc", "eks.cluster", "ec2.vpc", "ResourcesVpcConfig.VpcId", None, "arn:aws:ec2:{region}:{account}:vpc/{value}", 3, "none"),
    ("placement", "in_subnet", "ecs.service", "ec2.subnet", "NetworkConfiguration.AwsvpcConfiguration.Subnets", None, "arn:aws:ec2:{region}:{account}:subnet/{value}", 3, "none"),
    ("placement", "in_subnet", "elbv2.load-balancer", "ec2.subnet", "AvailabilityZones", "SubnetId", "arn:aws:ec2:{region}:{account}:subnet/{value}", 3, "none"),
    ("placement", "in_vpc", "lambda.function", "ec2.vpc", "VpcConfig.VpcId", None, "arn:aws:ec2:{region}:{account}:vpc/{value}", 3, "none"),
    ("placement", "in_subnet", "lambda.function", "ec2.subnet", "VpcConfig.SubnetIds", None, "arn:aws:ec2:{region}:{account}:subnet/{value}", 3, "none"),
    ("placement", "in_subnet", "ec2.vpc-endpoint", "ec2.subnet", "SubnetIds", None, "arn:aws:ec2:{region}:{account}:subnet/{value}", 3, "none"),
    ("placement", "in_subnet", "elasticache.cluster", "ec2.subnet", "CacheSubnetGroupName", None, None, 3, "none"),
    ("placement", "in_subnet", "ec2.nat-gateway", "ec2.subnet", "SubnetId", None, "arn:aws:ec2:{region}:{account}:subnet/{value}", 3, "none"),

    # COMPOSITION (Layer 3) — resource has attachment
    ("composition", "has_eni", "ec2.instance", "ec2.network-interface", "NetworkInterfaces", "NetworkInterfaceId", "arn:aws:ec2:{region}:{account}:network-interface/{value}", 3, "none"),
    ("composition", "has_sg", "ec2.instance", "ec2.security-group", "SecurityGroups", "GroupId", "arn:aws:ec2:{region}:{account}:security-group/{value}", 3, "none"),
    ("composition", "has_volume", "ec2.instance", "ec2.volume", "BlockDeviceMappings", "Ebs.VolumeId", "arn:aws:ec2:{region}:{account}:volume/{value}", 3, "none"),
    ("composition", "has_profile", "ec2.instance", "iam.instance-profile", "IamInstanceProfile.Arn", None, "{value}", 3, "none"),
    ("composition", "has_sg", "eks.cluster", "ec2.security-group", "ResourcesVpcConfig.SecurityGroupIds", None, "arn:aws:ec2:{region}:{account}:security-group/{value}", 3, "none"),
    ("composition", "has_sg", "rds.db-instance", "ec2.security-group", "VpcSecurityGroups", "VpcSecurityGroupId", "arn:aws:ec2:{region}:{account}:security-group/{value}", 3, "none"),
    ("composition", "has_sg", "elbv2.load-balancer", "ec2.security-group", "SecurityGroups", None, "arn:aws:ec2:{region}:{account}:security-group/{value}", 3, "none"),
    ("composition", "has_sg", "lambda.function", "ec2.security-group", "VpcConfig.SecurityGroupIds", None, "arn:aws:ec2:{region}:{account}:security-group/{value}", 3, "none"),
    ("composition", "has_sg", "elasticache.cluster", "ec2.security-group", "SecurityGroups", "SecurityGroupId", "arn:aws:ec2:{region}:{account}:security-group/{value}", 3, "none"),

    # DEPENDENCY (Layer 4) — service dependencies
    ("dependency", "has_role", "ec2.instance", "iam.role", "IamInstanceProfile.Arn", None, None, 4, "dashed"),
    ("dependency", "has_role", "lambda.function", "iam.role", "Role", None, "{value}", 4, "dashed"),
    ("dependency", "has_role", "ecs.task-definition", "iam.role", "TaskRoleArn", None, "{value}", 4, "dashed"),
    ("dependency", "has_role", "eks.cluster", "iam.role", "RoleArn", None, "{value}", 4, "dashed"),
    ("dependency", "encrypted_by", "rds.db-instance", "kms.key", "KmsKeyId", None, "{value}", 4, "dotted"),
    ("dependency", "encrypted_by", "ec2.volume", "kms.key", "KmsKeyId", None, "{value}", 4, "dotted"),
    ("dependency", "encrypted_by", "s3.bucket", "kms.key", "ServerSideEncryptionConfiguration", None, None, 4, "dotted"),
    ("dependency", "encrypted_by", "efs.file-system", "kms.key", "KmsKeyId", None, "{value}", 4, "dotted"),
    ("dependency", "encrypted_by", "dynamodb.table", "kms.key", "SSEDescription.KMSMasterKeyArn", None, "{value}", 4, "dotted"),
    ("dependency", "encrypted_by", "sqs.queue", "kms.key", "KmsMasterKeyId", None, "{value}", 4, "dotted"),
    ("dependency", "encrypted_by", "sns.topic", "kms.key", "KmsMasterKeyId", None, "{value}", 4, "dotted"),
    ("dependency", "logs_to", "cloudtrail.trail", "s3.bucket", "S3BucketName", None, None, 4, "dotted"),
    ("dependency", "logs_to", "elbv2.load-balancer", "s3.bucket", "AccessLogs.S3BucketName", None, None, 4, "dotted"),

    # FLOW (Layer 5) — traffic flow
    ("flow", "routes_to", "elbv2.load-balancer", "ec2.instance", None, None, None, 5, "solid"),
    ("flow", "routes_to", "elbv2.load-balancer", "ecs.service", None, None, None, 5, "solid"),
    ("flow", "routes_to", "elbv2.load-balancer", "lambda.function", None, None, None, 5, "solid"),
    ("flow", "routes_to", "ec2.vpc-endpoint", "s3.bucket", None, None, None, 5, "dashed"),
    ("flow", "routes_to", "cloudfront.distribution", "s3.bucket", "Origins", None, None, 5, "solid"),
    ("flow", "routes_to", "cloudfront.distribution", "elbv2.load-balancer", "Origins", None, None, 5, "solid"),
    ("flow", "routes_to", "apigateway.rest-api", "lambda.function", None, None, None, 5, "solid"),
]


def get_conn():
    return psycopg2.connect(
        host=os.getenv("INVENTORY_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("INVENTORY_DB_PORT", os.getenv("DB_PORT", "5432"))),
        database=os.getenv("INVENTORY_DB_NAME", "threat_engine_inventory"),
        user=os.getenv("INVENTORY_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("INVENTORY_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
    )


def _infer_visual_group(_csp, service, resource_type, category):
    """Infer visual_group from known mappings or category fallback."""
    full_type = f"{service}.{resource_type}"

    # Direct mapping
    if full_type in VISUAL_GROUP_MAP:
        return VISUAL_GROUP_MAP[full_type]

    # Category-based fallback
    cat = (category or "").lower()
    if cat in ("compute", "container"):
        return ("compute", service)
    elif cat in ("network", "networking"):
        return ("network", service)
    elif cat in ("storage",):
        return ("storage-object", service)
    elif cat in ("identity", "security"):
        return ("identity", service)
    elif cat in ("database",):
        return ("compute-database", service)
    elif cat in ("messaging",):
        return ("messaging", service)
    elif cat in ("monitoring", "management"):
        return ("monitoring", service)
    elif cat in ("encryption",):
        return ("encryption", service)
    else:
        return ("other", service)


def seed_placement(conn, dry_run=False):
    """Seed architecture_resource_placement from resource_inventory_identifier."""
    cur = conn.cursor()

    cur.execute("""
        SELECT csp, service, canonical_type, category, scope,
               is_container, container_parent, diagram_priority, managed_by
        FROM resource_inventory_identifier
        WHERE should_inventory = true
    """)
    rows = cur.fetchall()
    print(f"Read {len(rows)} entries from resource_inventory_identifier")

    values = []
    seen = set()
    for row in rows:
        csp, service, resource_type, category, scope = row[0], row[1], row[2], row[3], row[4]
        is_container, container_parent, diagram_priority, _managed_by = row[5], row[6], row[7], row[8]

        full_type = f"{service}.{resource_type}"
        key = (csp, full_type)
        if key in seen:
            continue
        seen.add(key)

        visual_group, visual_subgroup = _infer_visual_group(csp, service, resource_type, category)

        # Get specific placement if available
        pm = PLACEMENT_MAP.get(full_type, {})
        diagram_zone = pm.get("dz", "services")
        arch_layer = pm.get("layer", 3 if category in ("compute", "network", "database", "container") else 4)
        placement_scope = pm.get("scope", scope or "regional")
        placement_parent = pm.get("parent", container_parent or "region")
        placement_zone = pm.get("zone", "center")
        is_cont = pm.get("container", is_container or False)
        cont_depth = pm.get("depth", 0)
        priority = pm.get("priority", diagram_priority or 3)
        show_as = pm.get("show", "box")
        icon_type = f"{csp}-{service}" if csp else None

        values.append((
            csp, full_type, diagram_zone, arch_layer, placement_scope, placement_parent,
            placement_zone, visual_group, visual_subgroup,
            is_cont, cont_depth, priority, show_as, icon_type,
        ))

    if dry_run:
        print(f"[DRY RUN] Would insert {len(values)} placement rows")
        by_csp = {}
        for v in values:
            by_csp[v[0]] = by_csp.get(v[0], 0) + 1
        for c, n in sorted(by_csp.items()):
            print(f"  {c}: {n}")
        return

    cur.execute("TRUNCATE architecture_resource_placement RESTART IDENTITY")
    execute_values(cur, """
        INSERT INTO architecture_resource_placement (
            csp, resource_type, diagram_zone, arch_layer, placement_scope, placement_parent,
            placement_zone, visual_group, visual_subgroup,
            is_container, container_depth, display_priority, show_as, icon_type
        ) VALUES %s
        ON CONFLICT (csp, resource_type) DO UPDATE SET
            diagram_zone = EXCLUDED.diagram_zone,
            arch_layer = EXCLUDED.arch_layer,
            visual_group = EXCLUDED.visual_group
    """, values, page_size=500)
    conn.commit()
    print(f"Inserted {len(values)} placement rows")


def seed_relationships(conn, dry_run=False):
    """Seed architecture_relationship_rules for AWS."""
    cur = conn.cursor()

    values = []
    for r in AWS_RELATIONSHIPS:
        cat, rtype, from_rt, to_rt, src_field, src_item, target_pat, layer, style = r
        values.append((
            "aws", cat, rtype, from_rt, to_rt,
            src_field, src_item, target_pat, layer, style,
            None, None, False, True,
        ))

    if dry_run:
        print(f"[DRY RUN] Would insert {len(values)} AWS relationship rules")
        return

    cur.execute("DELETE FROM architecture_relationship_rules WHERE csp = 'aws'")
    execute_values(cur, """
        INSERT INTO architecture_relationship_rules (
            csp, rel_category, rel_type, from_resource_type, to_resource_type,
            source_field, source_field_item, target_uid_pattern, arch_layer, line_style,
            line_color, line_label, bidirectional, is_active
        ) VALUES %s
    """, values, page_size=100)
    conn.commit()
    print(f"Inserted {len(values)} AWS relationship rules")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    conn = get_conn()
    cur = conn.cursor()

    print("Creating tables...")
    cur.execute(DDL_PLACEMENT)
    cur.execute(DDL_RELATIONSHIPS)
    conn.commit()
    print("Tables created.")

    print("\nSeeding placement data...")
    seed_placement(conn, dry_run=args.dry_run)

    print("\nSeeding AWS relationship rules...")
    seed_relationships(conn, dry_run=args.dry_run)

    # Verify
    if not args.dry_run:
        cur.execute("SELECT csp, count(*) FROM architecture_resource_placement GROUP BY csp ORDER BY csp")
        print("\nPlacement counts:")
        for r in cur.fetchall():
            print(f"  {r[0]}: {r[1]}")

        cur.execute("SELECT rel_category, count(*) FROM architecture_relationship_rules WHERE csp='aws' GROUP BY rel_category ORDER BY rel_category")
        print("\nAWS relationship rules by category:")
        for r in cur.fetchall():
            print(f"  {r[0]}: {r[1]}")

    conn.close()
    print("\nDone!")


if __name__ == "__main__":
    main()
