#!/usr/bin/env python3
"""
Build Relationship Classification Index

Produces the predefined relation catalog (source of truth) for all AWS services.
- relation_types.json: already exists in config
- aws_relationship_index.json: generated here

Uses:
- Core relation map (explicit from_type, to_type, field, pattern)
- Discovery YAML emit fields (configScan services)
- Inventory classification index (resource types, by_service)
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from collections import defaultdict
from datetime import datetime, timezone

# Paths (inventory-engine's parent = threat-engine)
PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIGSCAN_SERVICES = PROJECT_ROOT / "configScan_engines" / "aws-configScan-engine" / "services"
CONFIG_DIR = PROJECT_ROOT / "inventory-engine" / "inventory_engine" / "config"
CLASSIFICATION_INDEX_FILE = CONFIG_DIR / "aws_inventory_classification_index.json"
RELATION_TYPES_FILE = CONFIG_DIR / "relation_types.json"
OUTPUT_FILE = CONFIG_DIR / "aws_relationship_index.json"

# Normalize discovery ID to service.operation (no aws. prefix)
def normalize_discovery_id(did: str) -> str:
    s = did.strip()
    if s.lower().startswith("aws."):
        return s[4:].strip()
    return s


def to_classification_key(did: str) -> str:
    """Classification index uses service.operation with no underscores, lowercased."""
    n = normalize_discovery_id(did)
    if "." not in n:
        return n.lower().replace("_", "")
    svc, op = n.split(".", 1)
    return f"{svc}.{op.replace('_', '').lower()}"


def load_json(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_yaml(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    try:
        import yaml
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except Exception:
        return None


# -----------------------------------------------------------------------------
# Core relation map: explicit (from_type, relation_type, to_type, source_field, target_uid_pattern)
# Source of truth for known relationships. Extend as needed.
# -----------------------------------------------------------------------------
CORE_RELATION_MAP: List[Dict[str, Any]] = [
    # Network containment
    {"from_type": "ec2.subnet", "relation_type": "contained_by", "to_type": "ec2.vpc",
     "source_field": "VpcId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:vpc/{VpcId}"},
    {"from_type": "ec2.network-interface", "relation_type": "attached_to", "to_type": "ec2.subnet",
     "source_field": "SubnetId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:subnet/{SubnetId}"},
    {"from_type": "ec2.security-group", "relation_type": "attached_to", "to_type": "ec2.vpc",
     "source_field": "VpcId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:vpc/{VpcId}"},
    # Instance -> SG, ENI
    {"from_type": "ec2.instance", "relation_type": "attached_to", "to_type": "ec2.security-group",
     "source_field": "Groups", "source_field_item": "GroupId",
     "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:security-group/{GroupId}"},
    {"from_type": "ec2.instance", "relation_type": "attached_to", "to_type": "ec2.network-interface",
     "source_field": "Instances", "source_field_item": "NetworkInterfaces",
     "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:network-interface/{NetworkInterfaceId}"},
    # Instance -> instance profile (cross-service)
    {"from_type": "ec2.instance", "relation_type": "uses", "to_type": "iam.instance-profile",
     "source_field": "IamInstanceProfile", "source_field_item": "Arn",
     "target_uid_pattern": "{Arn}"},
    # IAM
    {"from_type": "iam.instance-profile", "relation_type": "uses", "to_type": "iam.role",
     "source_field": "Roles", "source_field_item": "Arn", "target_uid_pattern": "{Arn}"},
    {"from_type": "iam.role", "relation_type": "attached_to", "to_type": "iam.policy",
     "source_field": "AttachedPolicies", "source_field_item": "PolicyArn", "target_uid_pattern": "{PolicyArn}"},
    {"from_type": "iam.user", "relation_type": "member_of", "to_type": "iam.group",
     "source_field": "Groups", "source_field_item": "GroupName",
     "target_uid_pattern": "arn:aws:iam::{account_id}:group/{GroupName}"},
    # Data
    {"from_type": "s3.bucket", "relation_type": "encrypted_by", "to_type": "kms.key",
     "source_field": "KmsKeyId", "target_uid_pattern": "arn:aws:kms:{region}:{account_id}:key/{KmsKeyId}"},
    {"from_type": "s3.bucket", "relation_type": "encrypted_by", "to_type": "kms.key",
     "source_field": "SSEKMSKeyId", "target_uid_pattern": "arn:aws:kms:{region}:{account_id}:key/{SSEKMSKeyId}"},
    {"from_type": "ec2.volume", "relation_type": "encrypted_by", "to_type": "kms.key",
     "source_field": "KmsKeyId", "target_uid_pattern": "arn:aws:kms:{region}:{account_id}:key/{KmsKeyId}"},
    {"from_type": "ec2.snapshot", "relation_type": "encrypted_by", "to_type": "kms.key",
     "source_field": "KmsKeyId", "target_uid_pattern": "arn:aws:kms:{region}:{account_id}:key/{KmsKeyId}"},

    # ---------------------------------------------------------------------
    # Lambda
    # NOTE: In current normalized assets, Lambda functions appear as `lambda.resource`.
    # Keep `lambda.function` for future compatibility, but ensure `lambda.resource` is covered.
    # ---------------------------------------------------------------------
    # Function uses an execution role (ARN)
    {"from_type": "lambda.resource", "relation_type": "uses", "to_type": "iam.role",
     "source_field": "Role", "target_uid_pattern": "{Role}"},
    {"from_type": "lambda.function", "relation_type": "uses", "to_type": "iam.role",
     "source_field": "Role", "target_uid_pattern": "{Role}"},
    # Function in VPC / subnets / security groups (from get_function_configuration)
    {"from_type": "lambda.resource", "relation_type": "contained_by", "to_type": "ec2.vpc",
     "source_field": "VpcConfig.VpcId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:vpc/{VpcId}"},
    {"from_type": "lambda.function", "relation_type": "contained_by", "to_type": "ec2.vpc",
     "source_field": "VpcConfig.VpcId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:vpc/{VpcId}"},
    {"from_type": "lambda.resource", "relation_type": "attached_to", "to_type": "ec2.subnet",
     "source_field": "VpcConfig.SubnetIds", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:subnet/{SubnetId}"},
    {"from_type": "lambda.function", "relation_type": "attached_to", "to_type": "ec2.subnet",
     "source_field": "VpcConfig.SubnetIds", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:subnet/{SubnetId}"},
    {"from_type": "lambda.resource", "relation_type": "attached_to", "to_type": "ec2.security-group",
     "source_field": "VpcConfig.SecurityGroupIds", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:security-group/{GroupId}"},
    {"from_type": "lambda.function", "relation_type": "attached_to", "to_type": "ec2.security-group",
     "source_field": "VpcConfig.SecurityGroupIds", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:security-group/{GroupId}"},

    # ---------------------------------------------------------------------
    # RDS
    # ---------------------------------------------------------------------
    # Instance is in a VPC (via subnet group)
    {"from_type": "rds.instance", "relation_type": "contained_by", "to_type": "ec2.vpc",
     "source_field": "DBSubnetGroup.VpcId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:vpc/{VpcId}"},
    # Instance attached to VPC security groups
    {"from_type": "rds.instance", "relation_type": "attached_to", "to_type": "ec2.security-group",
     "source_field": "VpcSecurityGroups", "source_field_item": "VpcSecurityGroupId",
     "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:security-group/{GroupId}"},
    # Instance encrypted by KMS key (id or ARN)
    {"from_type": "rds.instance", "relation_type": "encrypted_by", "to_type": "kms.key",
     "source_field": "KmsKeyId", "target_uid_pattern": "arn:aws:kms:{region}:{account_id}:key/{KmsKeyId}"},

    # Cluster is in a VPC (via subnet group)
    {"from_type": "rds.cluster", "relation_type": "contained_by", "to_type": "ec2.vpc",
     "source_field": "DBSubnetGroup.VpcId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:vpc/{VpcId}"},
    # Cluster attached to VPC security groups
    {"from_type": "rds.cluster", "relation_type": "attached_to", "to_type": "ec2.security-group",
     "source_field": "VpcSecurityGroups", "source_field_item": "VpcSecurityGroupId",
     "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:security-group/{GroupId}"},
    # Cluster encrypted by KMS key
    {"from_type": "rds.cluster", "relation_type": "encrypted_by", "to_type": "kms.key",
     "source_field": "KmsKeyId", "target_uid_pattern": "arn:aws:kms:{region}:{account_id}:key/{KmsKeyId}"},

    # ---------------------------------------------------------------------
    # ELBv2 / Target Groups - deeper mappings
    # ---------------------------------------------------------------------
    # Target group -> EC2 instances (via TargetHealthDescriptions.Target.Id)
    {"from_type": "elbv2.target-group", "relation_type": "serves_traffic_for", "to_type": "ec2.instance",
     "source_field": "Target.Id", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:instance/{Target.Id}"},
    # Target group -> Lambda functions (if targets are lambda ARNs)
    {"from_type": "elbv2.target-group", "relation_type": "serves_traffic_for", "to_type": "lambda.resource",
     "source_field": "Target.Id", "target_uid_pattern": "{Target.Id}"},
    # Load balancer -> target group (via listener rules actions TargetGroupArn)
    {"from_type": "elbv2.balancer", "relation_type": "serves_traffic_for", "to_type": "elbv2.target-group",
     "source_field": "Rules.Actions", "source_field_item": "TargetGroupArn", "target_uid_pattern": "{TargetGroupArn}"},

    # ---------------------------------------------------------------------
    # API Gateway (REST) -> Lambda (invokes) via Integration URIs
    # ---------------------------------------------------------------------
    {"from_type": "apigateway.method", "relation_type": "invokes", "to_type": "lambda.resource",
     "source_field": "IntegrationUri", "target_uid_pattern": "{IntegrationUri}"},
    {"from_type": "apigatewayv2.route", "relation_type": "invokes", "to_type": "lambda.resource",
     "source_field": "IntegrationUri", "target_uid_pattern": "{IntegrationUri}"},

    # ---------------------------------------------------------------------
    # EventBridge rules -> Targets (triggers)
    # ---------------------------------------------------------------------
    {"from_type": "events.rule", "relation_type": "triggers", "to_type": "lambda.resource",
     "source_field": "Targets", "source_field_item": "Arn", "target_uid_pattern": "{Arn}"},
    {"from_type": "events.rule", "relation_type": "triggers", "to_type": "sqs.queue",
     "source_field": "Targets", "source_field_item": "Arn", "target_uid_pattern": "{Arn}"},
    {"from_type": "events.rule", "relation_type": "triggers", "to_type": "sns.topic",
     "source_field": "Targets", "source_field_item": "Arn", "target_uid_pattern": "{Arn}"},
    # ---------------------------------------------------------------------
    # SNS / SQS - messaging
    # ---------------------------------------------------------------------
    # Subscription endpoint -> topic (subscription object maps endpoint -> topic)
    {"from_type": "sns.subscription", "relation_type": "subscribes_to", "to_type": "sns.topic",
     "source_field": "TopicArn", "target_uid_pattern": "{TopicArn}"},
    # SQS queue subscribed to SNS topic (from subscription Endpoint or queue Policy)
    {"from_type": "sqs.queue", "relation_type": "subscribes_to", "to_type": "sns.topic",
     "source_field": "Policy", "target_uid_pattern": "{TopicArn}"},
    # Lambda publishes to SNS (heuristic via Environment variables or DeadLetterConfig.TargetArn)
    {"from_type": "lambda.resource", "relation_type": "publishes_to", "to_type": "sns.topic",
     "source_field": "Environment.Variables", "target_uid_pattern": "{TopicArn}"},
    {"from_type": "lambda.resource", "relation_type": "publishes_to", "to_type": "sqs.queue",
     "source_field": "DeadLetterConfig.TargetArn", "target_uid_pattern": "{TargetArn}"},
    # ---------------------------------------------------------------------
    # Route53 records -> resolved targets (resolves_to)
    # ---------------------------------------------------------------------
    {"from_type": "route53.record", "relation_type": "resolves_to", "to_type": "cloudfront.resource",
     "source_field": "AliasTarget.DNSName", "target_uid_pattern": "{AliasTarget.DNSName}"},
    {"from_type": "route53.record", "relation_type": "resolves_to", "to_type": "elbv2.balancer",
     "source_field": "AliasTarget.DNSName", "target_uid_pattern": "{AliasTarget.DNSName}"},
    {"from_type": "route53.record", "relation_type": "resolves_to", "to_type": "s3.bucket",
     "source_field": "AliasTarget.DNSName", "target_uid_pattern": "{AliasTarget.DNSName}"},

    # ---------------------------------------------------------------------
    # DynamoDB
    # ---------------------------------------------------------------------
    # Table encrypted by KMS (SSESpecification or SSEDescription)
    {"from_type": "dynamodb.table", "relation_type": "encrypted_by", "to_type": "kms.key",
     "source_field": "SSESpecification.KMSMasterKeyId", "target_uid_pattern": "arn:aws:kms:{region}:{account_id}:key/{KMSMasterKeyId}"},
    {"from_type": "dynamodb.table", "relation_type": "encrypted_by", "to_type": "kms.key",
     "source_field": "SSEDescription.KMSMasterKeyArn", "target_uid_pattern": "{KMSMasterKeyArn}"},
    # Table streams -> stream resource (if present)
    {"from_type": "dynamodb.table", "relation_type": "publishes_to", "to_type": "dynamodb.stream",
     "source_field": "LatestStreamArn", "target_uid_pattern": "{LatestStreamArn}"},

    # ---------------------------------------------------------------------
    # RDS replication
    # ---------------------------------------------------------------------
    # Instance -> read replicas
    {"from_type": "rds.instance", "relation_type": "replicates_to", "to_type": "rds.instance",
     "source_field": "ReadReplicaDBInstanceIdentifiers", "target_uid_pattern": "arn:aws:rds:{region}:{account_id}:db:{item}",
     "is_array": True},
    # Cluster -> replicas (Aurora)
    {"from_type": "rds.cluster", "relation_type": "replicates_to", "to_type": "rds.cluster",
     "source_field": "Replicas", "target_uid_pattern": "{item}", "is_array": True},

    # ---------------------------------------------------------------------
    # ELBv2
    # ---------------------------------------------------------------------
    {"from_type": "elbv2.balancer", "relation_type": "contained_by", "to_type": "ec2.vpc",
     "source_field": "VpcId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:vpc/{VpcId}"},
    {"from_type": "elbv2.balancer", "relation_type": "attached_to", "to_type": "ec2.subnet",
     "source_field": "AvailabilityZones", "source_field_item": "SubnetId",
     "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:subnet/{SubnetId}"},
    {"from_type": "elbv2.balancer", "relation_type": "attached_to", "to_type": "ec2.security-group",
     "source_field": "SecurityGroups",
     "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:security-group/{GroupId}"},

    # ---------------------------------------------------------------------
    # ECS
    # ---------------------------------------------------------------------
    {"from_type": "ecs.service", "relation_type": "contained_by", "to_type": "ecs.cluster",
     "source_field": "clusterArn", "target_uid_pattern": "{clusterArn}"},
    {"from_type": "ecs.service", "relation_type": "uses", "to_type": "ecs.definition",
     "source_field": "taskDefinition", "target_uid_pattern": "{taskDefinition}"},
    {"from_type": "ecs.task", "relation_type": "contained_by", "to_type": "ecs.cluster",
     "source_field": "clusterArn", "target_uid_pattern": "{clusterArn}"},
    {"from_type": "ecs.task", "relation_type": "uses", "to_type": "ecs.definition",
     "source_field": "taskDefinitionArn", "target_uid_pattern": "{taskDefinitionArn}"},

    # ---------------------------------------------------------------------
    # Secrets Manager
    # ---------------------------------------------------------------------
    {"from_type": "secretsmanager.secret", "relation_type": "encrypted_by", "to_type": "kms.key",
     "source_field": "KmsKeyId", "target_uid_pattern": "arn:aws:kms:{region}:{account_id}:key/{KmsKeyId}"},

    # ---------------------------------------------------------------------
    # CloudTrail
    # ---------------------------------------------------------------------
    # Trail logs to S3 bucket
    {"from_type": "cloudtrail.trail", "relation_type": "logging_enabled_to", "to_type": "s3.bucket",
     "source_field": "S3BucketName", "target_uid_pattern": "arn:aws:s3:::{S3BucketName}"},
    # Trail logs to CloudWatch Logs group (ARN)
    {"from_type": "cloudtrail.trail", "relation_type": "logging_enabled_to", "to_type": "logs.group",
     "source_field": "CloudWatchLogsLogGroupArn", "target_uid_pattern": "{CloudWatchLogsLogGroupArn}"},
    # Trail uses IAM role for CloudWatch Logs delivery (ARN)
    {"from_type": "cloudtrail.trail", "relation_type": "uses", "to_type": "iam.role",
     "source_field": "CloudWatchLogsRoleArn", "target_uid_pattern": "{CloudWatchLogsRoleArn}"},
    # Trail encrypted by KMS key
    {"from_type": "cloudtrail.trail", "relation_type": "encrypted_by", "to_type": "kms.key",
     "source_field": "KmsKeyId", "target_uid_pattern": "arn:aws:kms:{region}:{account_id}:key/{KmsKeyId}"},

    # ---------------------------------------------------------------------
    # KMS
    # ---------------------------------------------------------------------
    {"from_type": "kms.alias", "relation_type": "uses", "to_type": "kms.key",
     "source_field": "TargetKeyId", "target_uid_pattern": "arn:aws:kms:{region}:{account_id}:key/{TargetKeyId}"},

    # ---------------------------------------------------------------------
    # Elastic Beanstalk
    # ---------------------------------------------------------------------
    # Application version source bundle stored in S3
    {"from_type": "elasticbeanstalk.application", "relation_type": "uses", "to_type": "s3.bucket",
     "source_field": "SourceBundle.S3Bucket", "target_uid_pattern": "arn:aws:s3:::{S3Bucket}"},

    # ---------------------------------------------------------------------
    # CloudFront
    # ---------------------------------------------------------------------
    # Distribution uses ACM certificate for HTTPS
    {"from_type": "cloudfront.resource", "relation_type": "uses", "to_type": "acm.certificate",
     "source_field": "ViewerCertificate.ACMCertificateArn", "target_uid_pattern": "{ACMCertificateArn}"},

    # ---------------------------------------------------------------------
    # ECR
    # ---------------------------------------------------------------------
    {"from_type": "ecr.repository", "relation_type": "encrypted_by", "to_type": "kms.key",
     "source_field": "encryptionConfiguration.KmsKeyId", "target_uid_pattern": "arn:aws:kms:{region}:{account_id}:key/{KmsKeyId}"},
    {"from_type": "ecr.repository", "relation_type": "uses", "to_type": "ecr.repository",
     "source_field": "repositoryArn", "target_uid_pattern": "{repositoryArn}"},

    # ---------------------------------------------------------------------
    # Logging / CloudWatch relations
    # ---------------------------------------------------------------------
    {"from_type": "lambda.resource", "relation_type": "logging_enabled_to", "to_type": "logs.group",
     "source_field": "LogGroupArn", "target_uid_pattern": "{LogGroupArn}"},
    {"from_type": "rds.instance", "relation_type": "logging_enabled_to", "to_type": "logs.group",
     "source_field": "CloudWatchLogsLogGroupArn", "target_uid_pattern": "{CloudWatchLogsLogGroupArn}"},
    {"from_type": "vpc.flow-log", "relation_type": "logging_enabled_to", "to_type": "logs.group",
     "source_field": "LogGroupName", "target_uid_pattern": "arn:aws:logs:{region}:{account_id}:log-group:{LogGroupName}"},
    {"from_type": "elbv2.balancer", "relation_type": "logging_enabled_to", "to_type": "s3.bucket",
     "source_field": "AccessLogs.S3BucketName", "target_uid_pattern": "arn:aws:s3:::{AccessLogs.S3BucketName}"},

    # ---------------------------------------------------------------------
    # Route Tables (NEW: routes_to)
    # ---------------------------------------------------------------------
    # Route table routes to internet gateway
    {"from_type": "ec2.route-table", "relation_type": "routes_to", "to_type": "ec2.internet-gateway",
     "source_field": "Routes", "source_field_item": "GatewayId",
     "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:internet-gateway/{GatewayId}"},
    # Route table routes to NAT gateway
    {"from_type": "ec2.route-table", "relation_type": "routes_to", "to_type": "ec2.nat-gateway",
     "source_field": "Routes", "source_field_item": "NatGatewayId",
     "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:nat-gateway/{NatGatewayId}"},
    # Route table routes to VPC endpoint
    {"from_type": "ec2.route-table", "relation_type": "routes_to", "to_type": "ec2.vpc-endpoint",
     "source_field": "Routes", "source_field_item": "VpcEndpointId",
     "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:vpc-endpoint/{VpcEndpointId}"},
    # Route table routes to transit gateway
    {"from_type": "ec2.route-table", "relation_type": "routes_to", "to_type": "ec2.transit-gateway",
     "source_field": "Routes", "source_field_item": "TransitGatewayId",
     "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:transit-gateway/{TransitGatewayId}"},

    # ---------------------------------------------------------------------
    # ELBv2 - Load Balancing (NEW: serves_traffic_for)
    # ---------------------------------------------------------------------
    # ALB serves traffic for target groups
    {"from_type": "elbv2.balancer", "relation_type": "serves_traffic_for", "to_type": "elbv2.target-group",
     "source_field": "LoadBalancerArn", "target_uid_pattern": "arn:aws:elasticloadbalancing:{region}:{account_id}:targetgroup/{TargetGroupName}"},
    # Target group serves traffic for EC2 instances
    {"from_type": "elbv2.target-group", "relation_type": "serves_traffic_for", "to_type": "ec2.instance",
     "source_field": "TargetHealthDescriptions", "source_field_item": "Target.Id",
     "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:instance/{Target.Id}"},

    # ---------------------------------------------------------------------
    # API Gateway / SNS / SQS
    # NOTE: Keep these for later once we have normalized assets for API GW, rules/targets,
    #       and a deterministic way to extract topic/queue ARNs from policies/env-vars.
    # ---------------------------------------------------------------------

    # ---------------------------------------------------------------------
    # Route53 (NEW: resolves_to)
    # ---------------------------------------------------------------------
    # Route53 record resolves to ALB
    {"from_type": "route53.record", "relation_type": "resolves_to", "to_type": "elbv2.balancer",
     "source_field": "AliasTarget.DNSName", "target_uid_pattern": "arn:aws:elasticloadbalancing:{region}:{account_id}:loadbalancer/app/{DNSName}"},
    # Route53 record resolves to CloudFront
    {"from_type": "route53.record", "relation_type": "resolves_to", "to_type": "cloudfront.resource",
     "source_field": "AliasTarget.DNSName", "target_uid_pattern": "arn:aws:cloudfront::{account_id}:distribution/{DistributionId}"},

    # ---------------------------------------------------------------------
    # ECS (NEW: runs_on, triggers)
    # ---------------------------------------------------------------------
    # ECS task runs on EC2 instance
    {"from_type": "ecs.task", "relation_type": "runs_on", "to_type": "ec2.instance",
     "source_field": "ContainerInstanceArn", "target_uid_pattern": "arn:aws:ecs:{region}:{account_id}:container-instance/{ClusterName}/{ContainerInstanceId}"},
    # EventBridge rule triggers Lambda
    {"from_type": "eventbridge.rule", "relation_type": "triggers", "to_type": "lambda.resource",
     "source_field": "Targets", "source_field_item": "Arn",
     "target_uid_pattern": "{Arn}"},


    # ---------------------------------------------------------------------
    # Generated relationships (from OpenAI agent)
    # ---------------------------------------------------------------------

    # ACCESSANALYZER
    {"from_type": "accessanalyzer.access-preview", "relation_type": "uses", "to_type": "accessanalyzer.analyzer",
     "source_field": "analyzerArn", "target_uid_pattern": "{analyzerArn}"},
    {"from_type": "accessanalyzer.access-preview-analyzer", "relation_type": "uses", "to_type": "accessanalyzer.analyzer",
     "source_field": "analyzerArn", "target_uid_pattern": "{analyzerArn}"},
    {"from_type": "accessanalyzer.finding-existing-finding", "relation_type": "controlled_by", "to_type": "accessanalyzer.analyzer",
     "source_field": "resourceOwnerAccount", "target_uid_pattern": "arn:aws:accessanalyzer:{region}:{resourceOwnerAccount}:analyzer/{analyzerArn}"},
    {"from_type": "accessanalyzer.policy-generation-job", "relation_type": "controlled_by", "to_type": "accessanalyzer.policy-generation-principal",
     "source_field": "principalArn", "target_uid_pattern": "{principalArn}"},
    {"from_type": "accessanalyzer.resource", "relation_type": "controlled_by", "to_type": "accessanalyzer.analyzer",
     "source_field": "resourceOwnerAccount", "target_uid_pattern": "arn:aws:accessanalyzer:{region}:{resourceOwnerAccount}:analyzer/{analyzerArn}"},

    # ACM
    {"from_type": "acm.certificate", "relation_type": "uses", "to_type": "acm.authority",
     "source_field": "CertificateAuthorityArn", "target_uid_pattern": "{CertificateAuthorityArn}"},

    # APPSTREAM
    {"from_type": "appstream.builder", "relation_type": "uses", "to_type": "appstream.image",
     "source_field": "ImageArn", "target_uid_pattern": "{ImageArn}"},
    {"from_type": "appstream.application", "relation_type": "uses", "to_type": "appstream.image",
     "source_field": "ImageArn", "target_uid_pattern": "{ImageArn}"},
    {"from_type": "appstream.builder", "relation_type": "assumes", "to_type": "iam.role",
     "source_field": "IamRoleArn", "target_uid_pattern": "{IamRoleArn}"},
    {"from_type": "appstream.block", "relation_type": "uses", "to_type": "appstream.builder",
     "source_field": "BuilderArn", "target_uid_pattern": "{BuilderArn}"},
    {"from_type": "appstream.role", "relation_type": "controlled_by", "to_type": "iam.role",
     "source_field": "RoleArn", "target_uid_pattern": "{RoleArn}"},

    # APPSYNC
    {"from_type": "appsync.api", "relation_type": "uses", "to_type": "appsync.function",
     "source_field": "FunctionIds", "target_uid_pattern": "arn:aws:appsync:{region}:{account_id}:function/{FunctionIds}",
     "source_field_item": "FunctionId"},
    {"from_type": "appsync.api", "relation_type": "uses", "to_type": "appsync.resolver",
     "source_field": "ResolverIds", "target_uid_pattern": "arn:aws:appsync:{region}:{account_id}:resolver/{ResolverIds}",
     "source_field_item": "ResolverId"},
    {"from_type": "appsync.api", "relation_type": "uses", "to_type": "appsync.source",
     "source_field": "SourceIds", "target_uid_pattern": "arn:aws:appsync:{region}:{account_id}:source/{SourceIds}",
     "source_field_item": "SourceId"},
    {"from_type": "appsync.api", "relation_type": "attached_to", "to_type": "appsync.role",
     "source_field": "RoleArn", "target_uid_pattern": "{RoleArn}"},
    {"from_type": "appsync.api", "relation_type": "controlled_by", "to_type": "appsync.acl",
     "source_field": "AclId", "target_uid_pattern": "arn:aws:appsync:{region}:{account_id}:acl/{AclId}"},
    {"from_type": "appsync.api", "relation_type": "connected_to", "to_type": "appsync.domain",
     "source_field": "DomainName", "target_uid_pattern": "arn:aws:appsync:{region}:{account_id}:domain/{DomainName}"},
    {"from_type": "appsync.api", "relation_type": "uses", "to_type": "appsync.certificate",
     "source_field": "CertificateArn", "target_uid_pattern": "{CertificateArn}"},
    {"from_type": "appsync.api", "relation_type": "contained_by", "to_type": "appsync.channelspace",
     "source_field": "ChannelSpaceId", "target_uid_pattern": "arn:aws:appsync:{region}:{account_id}:channelspace/{ChannelSpaceId}"},

    # ATHENA
    {"from_type": "athena.application", "relation_type": "uses", "to_type": "s3.bucket",
     "source_field": "OutputLocation", "target_uid_pattern": "arn:aws:s3:::{OutputLocation}"},
    {"from_type": "athena.application", "relation_type": "uses", "to_type": "iam.role",
     "source_field": "Role", "target_uid_pattern": "{Role}"},

    # AUTOSCALING
    {"from_type": "autoscaling.group", "relation_type": "uses", "to_type": "autoscaling.configuration",
     "source_field": "LaunchConfigurationName", "target_uid_pattern": "arn:aws:autoscaling:{region}:{account_id}:launchConfiguration:{LaunchConfigurationName}"},
    {"from_type": "autoscaling.group", "relation_type": "uses", "to_type": "autoscaling.policy",
     "source_field": "AutoScalingGroupName", "target_uid_pattern": "arn:aws:autoscaling:{region}:{account_id}:scalingPolicy:{AutoScalingGroupName}:{PolicyName}",
     "source_field_item": "PolicyName"},
    {"from_type": "autoscaling.group", "relation_type": "uses", "to_type": "autoscaling.target",
     "source_field": "AutoScalingGroupName", "target_uid_pattern": "arn:aws:autoscaling:{region}:{account_id}:scalingTarget:{AutoScalingGroupName}:{TargetId}",
     "source_field_item": "TargetId"},
    {"from_type": "autoscaling.group", "relation_type": "uses", "to_type": "sns.topic",
     "source_field": "AutoScalingGroupName", "target_uid_pattern": "arn:aws:sns:{region}:{account_id}:{TopicName}",
     "source_field_item": "TopicName"},
    {"from_type": "autoscaling.group", "relation_type": "assumes", "to_type": "iam.role",
     "source_field": "AutoScalingGroupName", "target_uid_pattern": "arn:aws:iam::{account_id}:role/{RoleName}",
     "source_field_item": "RoleName"},

    # BACKUP
    {"from_type": "backup.plan", "relation_type": "backs_up_to", "to_type": "backup.vault",
     "source_field": "BackupVaultName", "target_uid_pattern": "arn:aws:backup:{region}:{account_id}:backup-vault/{BackupVaultName}"},
    {"from_type": "backup.point", "relation_type": "contained_by", "to_type": "backup.vault",
     "source_field": "BackupVaultName", "target_uid_pattern": "arn:aws:backup:{region}:{account_id}:backup-vault/{BackupVaultName}"},
    {"from_type": "backup.resource", "relation_type": "backs_up_to", "to_type": "backup.point",
     "source_field": "RecoveryPointArn", "target_uid_pattern": "{RecoveryPointArn}"},
    {"from_type": "backup.vault", "relation_type": "encrypted_by", "to_type": "kms.key",
     "source_field": "KmsKeyId", "target_uid_pattern": "arn:aws:kms:{region}:{account_id}:key/{KmsKeyId}"},
    {"from_type": "backup.session", "relation_type": "uses", "to_type": "backup.plan",
     "source_field": "BackupPlanId", "target_uid_pattern": "arn:aws:backup:{region}:{account_id}:backup-plan/{BackupPlanId}"},
    {"from_type": "backup.role", "relation_type": "assumes", "to_type": "iam.role",
     "source_field": "RoleArn", "target_uid_pattern": "{RoleArn}"},

    # BATCH
    {"from_type": "batch.cluster", "relation_type": "contained_by", "to_type": "batch.environment",
     "source_field": "ComputeEnvironmentArn", "target_uid_pattern": "{ComputeEnvironmentArn}"},
    {"from_type": "batch.job", "relation_type": "uses", "to_type": "batch.definition",
     "source_field": "JobDefinitionArn", "target_uid_pattern": "{JobDefinitionArn}"},
    {"from_type": "batch.job", "relation_type": "contained_by", "to_type": "batch.queue",
     "source_field": "JobQueueArn", "target_uid_pattern": "{JobQueueArn}"},
    {"from_type": "batch.queue", "relation_type": "contained_by", "to_type": "batch.environment",
     "source_field": "ComputeEnvironmentOrder", "target_uid_pattern": "{ComputeEnvironmentOrder}",
     "source_field_item": "ComputeEnvironment"},
    {"from_type": "batch.policy", "relation_type": "grants_access_to", "to_type": "batch.resource",
     "source_field": "ResourceArn", "target_uid_pattern": "{ResourceArn}"},

    # BEDROCK
    {"from_type": "bedrock.deployment", "relation_type": "uses", "to_type": "bedrock.model",
     "source_field": "ModelId", "target_uid_pattern": "arn:aws:bedrock:{region}:{account_id}:model/{ModelId}"},
    {"from_type": "bedrock.endpoint", "relation_type": "serves_traffic_for", "to_type": "bedrock.deployment",
     "source_field": "DeploymentId", "target_uid_pattern": "arn:aws:bedrock:{region}:{account_id}:deployment/{DeploymentId}"},
    {"from_type": "bedrock.guardrail", "relation_type": "controlled_by", "to_type": "bedrock.policy",
     "source_field": "PolicyId", "target_uid_pattern": "arn:aws:bedrock:{region}:{account_id}:policy/{PolicyId}"},
    {"from_type": "bedrock.job", "relation_type": "uses", "to_type": "bedrock.model",
     "source_field": "ModelId", "target_uid_pattern": "arn:aws:bedrock:{region}:{account_id}:model/{ModelId}"},
    {"from_type": "bedrock.key", "relation_type": "encrypted_by", "to_type": "kms.key",
     "source_field": "KmsKeyId", "target_uid_pattern": "arn:aws:kms:{region}:{account_id}:key/{KmsKeyId}"},
    {"from_type": "bedrock.policy", "relation_type": "grants_access_to", "to_type": "bedrock.role",
     "source_field": "RoleId", "target_uid_pattern": "arn:aws:bedrock:{region}:{account_id}:role/{RoleId}"},
    {"from_type": "bedrock.profile", "relation_type": "controlled_by", "to_type": "bedrock.role",
     "source_field": "RoleId", "target_uid_pattern": "arn:aws:bedrock:{region}:{account_id}:role/{RoleId}"},
    {"from_type": "bedrock.role", "relation_type": "assumes", "to_type": "iam.role",
     "source_field": "IamRoleArn", "target_uid_pattern": "{IamRoleArn}"},
    {"from_type": "bedrock.router", "relation_type": "routes_to", "to_type": "bedrock.endpoint",
     "source_field": "EndpointId", "target_uid_pattern": "arn:aws:bedrock:{region}:{account_id}:endpoint/{EndpointId}"},

    # BUDGETS
    {"from_type": "budgets.role", "relation_type": "assumes", "to_type": "iam.role",
     "source_field": "RoleArn", "target_uid_pattern": "{RoleArn}"},
    {"from_type": "budgets.view", "relation_type": "controlled_by", "to_type": "iam.user",
     "source_field": "UserId", "target_uid_pattern": "arn:aws:iam::{account_id}:user/{UserId}"},
    {"from_type": "budgets.view", "relation_type": "controlled_by", "to_type": "iam.role",
     "source_field": "RoleId", "target_uid_pattern": "arn:aws:iam::{account_id}:role/{RoleId}"},
    {"from_type": "budgets.view", "relation_type": "controlled_by", "to_type": "iam.group",
     "source_field": "GroupId", "target_uid_pattern": "arn:aws:iam::{account_id}:group/{GroupId}"},

    # CLOUDFORMATION
    {"from_type": "cloudformation.role", "relation_type": "assumes", "to_type": "iam.role",
     "source_field": "RoleArn", "target_uid_pattern": "{RoleArn}"},
    {"from_type": "cloudformation.set", "relation_type": "uses", "to_type": "cloudformation.type",
     "source_field": "ResourceTypes", "target_uid_pattern": "arn:aws:cloudformation:{region}:{account_id}:type/{ResourceTypes}",
     "source_field_item": "ResourceType"},
    {"from_type": "cloudformation.set", "relation_type": "uses", "to_type": "cloudformation.version",
     "source_field": "TemplateVersion", "target_uid_pattern": "arn:aws:cloudformation:{region}:{account_id}:version/{TemplateVersion}"},

    # CLOUDWATCH
    {"from_type": "cloudwatch.alarm", "relation_type": "monitored_by", "to_type": "cloudwatch.dashboard",
     "source_field": "AlarmName", "target_uid_pattern": "arn:aws:cloudwatch:{region}:{account_id}:dashboard/{AlarmName}"},
    {"from_type": "cloudwatch.alarm", "relation_type": "uses", "to_type": "cloudwatch.entry",
     "source_field": "AlarmName", "target_uid_pattern": "arn:aws:cloudwatch:{region}:{account_id}:entry/{AlarmName}"},
    {"from_type": "cloudwatch.dashboard", "relation_type": "monitored_by", "to_type": "cloudwatch.alarm",
     "source_field": "DashboardName", "target_uid_pattern": "arn:aws:cloudwatch:{region}:{account_id}:alarm/{DashboardName}"},
    {"from_type": "cloudwatch.firehose", "relation_type": "uses", "to_type": "cloudwatch.entry",
     "source_field": "FirehoseName", "target_uid_pattern": "arn:aws:cloudwatch:{region}:{account_id}:entry/{FirehoseName}"},

    # CODEBUILD
    {"from_type": "codebuild.credentials", "relation_type": "uses", "to_type": "iam.role",
     "source_field": "RoleArn", "target_uid_pattern": "{RoleArn}"},
    {"from_type": "codebuild.report", "relation_type": "controlled_by", "to_type": "iam.user",
     "source_field": "CreatedBy", "target_uid_pattern": "arn:aws:iam::{account_id}:user/{CreatedBy}"},
    {"from_type": "codebuild.report", "relation_type": "controlled_by", "to_type": "iam.role",
     "source_field": "CreatedBy", "target_uid_pattern": "arn:aws:iam::{account_id}:role/{CreatedBy}"},
    {"from_type": "codebuild.report", "relation_type": "controlled_by", "to_type": "iam.group",
     "source_field": "CreatedBy", "target_uid_pattern": "arn:aws:iam::{account_id}:group/{CreatedBy}"},

    # COGNITO
    {"from_type": "cognito.role", "relation_type": "assumes", "to_type": "iam.role",
     "source_field": "RoleArn", "target_uid_pattern": "{RoleArn}"},

    # CONFIG
    {"from_type": "config.aggregator", "relation_type": "uses", "to_type": "iam.role",
     "source_field": "RoleArn", "target_uid_pattern": "{RoleArn}"},
    {"from_type": "config.authorization", "relation_type": "controlled_by", "to_type": "iam.role",
     "source_field": "AuthorizedAccountId", "target_uid_pattern": "arn:aws:iam::{AuthorizedAccountId}:role/{RoleName}"},
    {"from_type": "config.configuration", "relation_type": "logging_enabled_to", "to_type": "sns.topic",
     "source_field": "SnsTopicARN", "target_uid_pattern": "{SnsTopicARN}"},
    {"from_type": "config.configuration", "relation_type": "uses", "to_type": "iam.role",
     "source_field": "RoleARN", "target_uid_pattern": "{RoleARN}"},
    {"from_type": "config.pack", "relation_type": "uses", "to_type": "config.rule",
     "source_field": "ConfigRuleNames", "target_uid_pattern": "arn:aws:config:{region}:{account_id}:config-rule/{ConfigRuleNames}",
     "source_field_item": "ConfigRuleName"},
    {"from_type": "config.rule", "relation_type": "uses", "to_type": "iam.role",
     "source_field": "RoleARN", "target_uid_pattern": "{RoleARN}"},
    {"from_type": "config.stack", "relation_type": "uses", "to_type": "config.rule",
     "source_field": "ConfigRuleNames", "target_uid_pattern": "arn:aws:config:{region}:{account_id}:config-rule/{ConfigRuleNames}",
     "source_field_item": "ConfigRuleName"},
    {"from_type": "config.statu", "relation_type": "monitored_by", "to_type": "config.configuration",
     "source_field": "ConfigurationRecorderName", "target_uid_pattern": "arn:aws:config:{region}:{account_id}:configuration-recorder/{ConfigurationRecorderName}"},

    # CONTROLTOWER
    {"from_type": "controltower.baselin", "relation_type": "controlled_by", "to_type": "iam.role",
     "source_field": "ControlOwnerRole", "target_uid_pattern": "arn:aws:iam::{account_id}:role/{ControlOwnerRole}"},
    {"from_type": "controltower.baselin", "relation_type": "monitored_by", "to_type": "cloudwatch.alarm",
     "source_field": "MonitoringAlarmName", "target_uid_pattern": "arn:aws:cloudwatch:{region}:{account_id}:alarm/{MonitoringAlarmName}"},

    # COSTEXPLORER
    {"from_type": "costexplorer.monitor", "relation_type": "monitored_by", "to_type": "costexplorer.subscription",
     "source_field": "MonitorArn", "target_uid_pattern": "arn:aws:ce:{region}:{account_id}:anomaly-subscription/{MonitorArn}"},
    {"from_type": "costexplorer.subscription", "relation_type": "monitored_by", "to_type": "costexplorer.monitor",
     "source_field": "SubscriptionArn", "target_uid_pattern": "arn:aws:ce:{region}:{account_id}:anomaly-monitor/{SubscriptionArn}"},

    # DATASYNC
    {"from_type": "datasync.task", "relation_type": "uses", "to_type": "datasync.location",
     "source_field": "SourceLocationArn", "target_uid_pattern": "{SourceLocationArn}"},
    {"from_type": "datasync.task", "relation_type": "uses", "to_type": "datasync.location",
     "source_field": "DestinationLocationArn", "target_uid_pattern": "{DestinationLocationArn}"},
    {"from_type": "datasync.agent", "relation_type": "connected_to", "to_type": "datasync.location",
     "source_field": "LocationArn", "target_uid_pattern": "{LocationArn}"},
    {"from_type": "datasync.task", "relation_type": "triggers", "to_type": "datasync.execution",
     "source_field": "TaskArn", "target_uid_pattern": "{TaskArn}"},
    {"from_type": "datasync.location", "relation_type": "contained_by", "to_type": "datasync.subnet",
     "source_field": "SubnetArn", "target_uid_pattern": "{SubnetArn}"},

    # DETECTIVE
    {"from_type": "detective.entity", "relation_type": "member_of", "to_type": "detective.graph",
     "source_field": "GraphArn", "target_uid_pattern": "{GraphArn}"},
    {"from_type": "detective.graph", "relation_type": "controlled_by", "to_type": "iam.role",
     "source_field": "AdministratorArn", "target_uid_pattern": "{AdministratorArn}"},

    # DIRECTCONNECT
    {"from_type": "directconnect.resource", "relation_type": "connected_to", "to_type": "ec2.subnet",
     "source_field": "SubnetId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:subnet/{SubnetId}"},

    # DIRECTORYSERVICE
    {"from_type": "directoryservice.connector", "relation_type": "logging_enabled_to", "to_type": "directoryservice.topic",
     "source_field": "LogSubscription", "target_uid_pattern": "arn:aws:directoryservice:{region}:{account_id}:topic/{LogSubscription}"},

    # DMS
    {"from_type": "dms.instance", "relation_type": "uses", "to_type": "dms.endpoint",
     "source_field": "EndpointArn", "target_uid_pattern": "{EndpointArn}"},
    {"from_type": "dms.instance", "relation_type": "uses", "to_type": "dms.task",
     "source_field": "ReplicationTaskArn", "target_uid_pattern": "{ReplicationTaskArn}"},
    {"from_type": "dms.task", "relation_type": "uses", "to_type": "dms.endpoint",
     "source_field": "SourceEndpointArn", "target_uid_pattern": "{SourceEndpointArn}"},
    {"from_type": "dms.task", "relation_type": "uses", "to_type": "dms.endpoint",
     "source_field": "TargetEndpointArn", "target_uid_pattern": "{TargetEndpointArn}"},
    {"from_type": "dms.task", "relation_type": "uses", "to_type": "dms.instance",
     "source_field": "ReplicationInstanceArn", "target_uid_pattern": "{ReplicationInstanceArn}"},
    {"from_type": "dms.instance", "relation_type": "encrypted_by", "to_type": "kms.key",
     "source_field": "KmsKeyId", "target_uid_pattern": "arn:aws:kms:{region}:{account_id}:key/{KmsKeyId}"},
    {"from_type": "dms.instance", "relation_type": "uses", "to_type": "iam.role",
     "source_field": "ServiceAccessRoleArn", "target_uid_pattern": "{ServiceAccessRoleArn}"},

    # DOCDB
    {"from_type": "docdb.cluster", "relation_type": "uses", "to_type": "docdb.instance",
     "source_field": "DBClusterIdentifier", "target_uid_pattern": "arn:aws:rds:{region}:{account_id}:db:{DBClusterIdentifier}"},
    {"from_type": "docdb.instance", "relation_type": "contained_by", "to_type": "docdb.cluster",
     "source_field": "DBClusterIdentifier", "target_uid_pattern": "arn:aws:rds:{region}:{account_id}:cluster:{DBClusterIdentifier}"},
    {"from_type": "docdb.snapshot", "relation_type": "backs_up_to", "to_type": "docdb.cluster",
     "source_field": "DBClusterIdentifier", "target_uid_pattern": "arn:aws:rds:{region}:{account_id}:cluster:{DBClusterIdentifier}"},
    {"from_type": "docdb.cluster", "relation_type": "encrypted_by", "to_type": "kms.key",
     "source_field": "KmsKeyId", "target_uid_pattern": "arn:aws:kms:{region}:{account_id}:key/{KmsKeyId}"},
    {"from_type": "docdb.instance", "relation_type": "encrypted_by", "to_type": "kms.key",
     "source_field": "KmsKeyId", "target_uid_pattern": "arn:aws:kms:{region}:{account_id}:key/{KmsKeyId}"},
    {"from_type": "docdb.snapshot", "relation_type": "encrypted_by", "to_type": "kms.key",
     "source_field": "KmsKeyId", "target_uid_pattern": "arn:aws:kms:{region}:{account_id}:key/{KmsKeyId}"},
    {"from_type": "docdb.subscription", "relation_type": "uses", "to_type": "sns.topic",
     "source_field": "SnsTopicArn", "target_uid_pattern": "{SnsTopicArn}"},

    # DRS
    {"from_type": "drs.server", "relation_type": "contained_by", "to_type": "drs.outpost",
     "source_field": "OutpostId", "target_uid_pattern": "arn:aws:drs:{region}:{account_id}:outpost/{OutpostId}"},
    {"from_type": "drs.item", "relation_type": "contained_by", "to_type": "drs.bucket",
     "source_field": "BucketId", "target_uid_pattern": "arn:aws:drs:{region}:{account_id}:bucket/{BucketId}"},
    {"from_type": "drs.bucket", "relation_type": "encrypted_by", "to_type": "drs.key",
     "source_field": "EncryptionKeyId", "target_uid_pattern": "arn:aws:drs:{region}:{account_id}:key/{EncryptionKeyId}"},
    {"from_type": "drs.server", "relation_type": "uses", "to_type": "drs.key",
     "source_field": "KeyId", "target_uid_pattern": "arn:aws:drs:{region}:{account_id}:key/{KeyId}"},

    # EDR
    {"from_type": "edr.membership", "relation_type": "member_of", "to_type": "edr.case",
     "source_field": "CaseId", "target_uid_pattern": "arn:aws:edr:{region}:{account_id}:case/{CaseId}"},

    # EFS
    {"from_type": "efs.system", "relation_type": "connected_to", "to_type": "efs.point",
     "source_field": "MountTargets", "target_uid_pattern": "arn:aws:elasticfilesystem:{region}:{account_id}:mount-target/{MountTargets}",
     "source_field_item": "MountTargetId"},
    {"from_type": "efs.system", "relation_type": "backs_up_to", "to_type": "efs.system",
     "source_field": "BackupPolicy", "target_uid_pattern": "arn:aws:elasticfilesystem:{region}:{account_id}:file-system/{FileSystemId}",
     "source_field_item": "FileSystemId"},
    {"from_type": "efs.system", "relation_type": "uses", "to_type": "efs.point",
     "source_field": "AccessPoints", "target_uid_pattern": "arn:aws:elasticfilesystem:{region}:{account_id}:access-point/{AccessPoints}",
     "source_field_item": "AccessPointId"},

    # EIP
    {"from_type": "eip.association", "relation_type": "attached_to", "to_type": "eip.interface",
     "source_field": "NetworkInterfaceId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:network-interface/{NetworkInterfaceId}"},
    {"from_type": "eip.association", "relation_type": "attached_to", "to_type": "eip.network",
     "source_field": "AllocationId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:eip-allocation/{AllocationId}"},
    {"from_type": "eip.balancer", "relation_type": "serves_traffic_for", "to_type": "eip.target",
     "source_field": "LoadBalancerArn", "target_uid_pattern": "{LoadBalancerArn}"},
    {"from_type": "eip.gateway", "relation_type": "connected_to", "to_type": "eip.network",
     "source_field": "VpcId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:vpc/{VpcId}"},
    {"from_type": "eip.policy", "relation_type": "has_policy", "to_type": "iam.policy",
     "source_field": "PolicyArn", "target_uid_pattern": "{PolicyArn}"},
    {"from_type": "eip.role", "relation_type": "assumes", "to_type": "iam.role",
     "source_field": "RoleArn", "target_uid_pattern": "{RoleArn}"},
    {"from_type": "eip.certificate", "relation_type": "uses", "to_type": "eip.domain",
     "source_field": "DomainName", "target_uid_pattern": "arn:aws:acm:{region}:{account_id}:certificate/{DomainName}"},
    {"from_type": "eip.notification", "relation_type": "triggers", "to_type": "eip.topic",
     "source_field": "TopicArn", "target_uid_pattern": "{TopicArn}"},
    {"from_type": "eip.reservation", "relation_type": "contained_by", "to_type": "eip.pool",
     "source_field": "PoolId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:eip-pool/{PoolId}"},

    # ELASTICACHE
    {"from_type": "elasticache.cluster", "relation_type": "contained_by", "to_type": "elasticache.outpost",
     "source_field": "CacheClusterId", "target_uid_pattern": "arn:aws:elasticache:{region}:{account_id}:outpost/{CacheClusterId}"},
    {"from_type": "elasticache.group", "relation_type": "replicates_to", "to_type": "elasticache.cluster",
     "source_field": "ReplicationGroupId", "target_uid_pattern": "arn:aws:elasticache:{region}:{account_id}:cluster/{ReplicationGroupId}"},
    {"from_type": "elasticache.cluster", "relation_type": "uses", "to_type": "elasticache.topic",
     "source_field": "NotificationTopicArn", "target_uid_pattern": "{NotificationTopicArn}"},
    {"from_type": "elasticache.cluster", "relation_type": "attached_to", "to_type": "elasticache.reservation",
     "source_field": "CacheClusterId", "target_uid_pattern": "arn:aws:elasticache:{region}:{account_id}:reservation/{CacheClusterId}"},

    # EMR
    {"from_type": "emr.cluster", "relation_type": "uses", "to_type": "emr.instance",
     "source_field": "InstanceGroupIds", "target_uid_pattern": "arn:aws:emr:{region}:{account_id}:instance/{InstanceGroupIds}",
     "source_field_item": "InstanceGroupId"},
    {"from_type": "emr.cluster", "relation_type": "uses", "to_type": "emr.key",
     "source_field": "Ec2KeyName", "target_uid_pattern": "arn:aws:emr:{region}:{account_id}:key/{Ec2KeyName}"},
    {"from_type": "emr.cluster", "relation_type": "uses", "to_type": "iam.role",
     "source_field": "ServiceRole", "target_uid_pattern": "arn:aws:iam::{account_id}:role/{ServiceRole}"},
    {"from_type": "emr.cluster", "relation_type": "uses", "to_type": "iam.role",
     "source_field": "JobFlowRole", "target_uid_pattern": "arn:aws:iam::{account_id}:role/{JobFlowRole}"},
    {"from_type": "emr.cluster", "relation_type": "uses", "to_type": "iam.policy",
     "source_field": "AutoScalingRole", "target_uid_pattern": "arn:aws:iam::{account_id}:policy/{AutoScalingRole}"},
    {"from_type": "emr.cluster", "relation_type": "contained_by", "to_type": "emr.outpost",
     "source_field": "OutpostArn", "target_uid_pattern": "{OutpostArn}"},
    {"from_type": "emr.studio", "relation_type": "uses", "to_type": "iam.role",
     "source_field": "UserRole", "target_uid_pattern": "arn:aws:iam::{account_id}:role/{UserRole}"},
    {"from_type": "emr.studio", "relation_type": "uses", "to_type": "iam.role",
     "source_field": "ServiceRole", "target_uid_pattern": "arn:aws:iam::{account_id}:role/{ServiceRole}"},

    # FARGATE
    {"from_type": "fargate.cluster", "relation_type": "controlled_by", "to_type": "fargate.principal",
     "source_field": "ClusterArn", "target_uid_pattern": "arn:aws:iam::{account_id}:role/{ClusterArn}"},
    {"from_type": "fargate.cluster", "relation_type": "uses", "to_type": "fargate.provider",
     "source_field": "ClusterArn", "target_uid_pattern": "arn:aws:ecs:{region}:{account_id}:cluster/{ClusterArn}"},
    {"from_type": "fargate.principal", "relation_type": "assumes", "to_type": "iam.role",
     "source_field": "RoleArn", "target_uid_pattern": "{RoleArn}"},
    {"from_type": "fargate.provider", "relation_type": "uses", "to_type": "fargate.cluster",
     "source_field": "ProviderArn", "target_uid_pattern": "arn:aws:ecs:{region}:{account_id}:cluster/{ProviderArn}"},

    # FSX
    {"from_type": "fsx.resource", "relation_type": "backs_up_to", "to_type": "fsx.resource",
     "source_field": "BackupId", "target_uid_pattern": "arn:aws:fsx:{region}:{account_id}:backup/{BackupId}"},
    {"from_type": "fsx.resource", "relation_type": "backs_up_to", "to_type": "fsx.resource",
     "source_field": "SnapshotId", "target_uid_pattern": "arn:aws:fsx:{region}:{account_id}:snapshot/{SnapshotId}"},

    # GLACIER
    {"from_type": "glacier.vault", "relation_type": "grants_access_to", "to_type": "iam.policy",
     "source_field": "Policy", "target_uid_pattern": "arn:aws:iam::{account_id}:policy/{Policy}"},
    {"from_type": "glacier.vault", "relation_type": "controlled_by", "to_type": "iam.role",
     "source_field": "Role", "target_uid_pattern": "arn:aws:iam::{account_id}:role/{Role}"},
    {"from_type": "glacier.vault", "relation_type": "encrypted_by", "to_type": "kms.key",
     "source_field": "KmsKeyId", "target_uid_pattern": "arn:aws:kms:{region}:{account_id}:key/{KmsKeyId}"},

    # GLOBALACCELERATOR
    {"from_type": "globalaccelerator.listener", "relation_type": "contained_by", "to_type": "globalaccelerator.accelerator",
     "source_field": "AcceleratorArn", "target_uid_pattern": "{AcceleratorArn}"},
    {"from_type": "globalaccelerator.attachment", "relation_type": "attached_to", "to_type": "globalaccelerator.group",
     "source_field": "EndpointGroupArn", "target_uid_pattern": "{EndpointGroupArn}"},
    {"from_type": "globalaccelerator.group", "relation_type": "contained_by", "to_type": "globalaccelerator.listener",
     "source_field": "ListenerArn", "target_uid_pattern": "{ListenerArn}"},

    # GLUE
    {"from_type": "glue.application", "relation_type": "uses", "to_type": "glue.resource",
     "source_field": "ResourceArn", "target_uid_pattern": "{ResourceArn}"},
    {"from_type": "glue.integration", "relation_type": "uses", "to_type": "glue.source",
     "source_field": "SourceArn", "target_uid_pattern": "{SourceArn}"},
    {"from_type": "glue.integration", "relation_type": "uses", "to_type": "glue.target",
     "source_field": "TargetArn", "target_uid_pattern": "{TargetArn}"},
    {"from_type": "glue.role", "relation_type": "assumes", "to_type": "iam.role",
     "source_field": "RoleArn", "target_uid_pattern": "{RoleArn}"},
    {"from_type": "glue.schema", "relation_type": "uses", "to_type": "glue.property",
     "source_field": "PropertyArn", "target_uid_pattern": "{PropertyArn}"},
    {"from_type": "glue.source", "relation_type": "connected_to", "to_type": "glue.target",
     "source_field": "TargetArn", "target_uid_pattern": "{TargetArn}"},

    # GUARDDUTY
    {"from_type": "guardduty.finding", "relation_type": "monitored_by", "to_type": "guardduty.resource",
     "source_field": "ResourceId", "target_uid_pattern": "arn:aws:guardduty:{region}:{account_id}:resource/{ResourceId}"},
    {"from_type": "guardduty.finding", "relation_type": "uses", "to_type": "kms.key",
     "source_field": "EncryptionKey", "target_uid_pattern": "arn:aws:kms:{region}:{account_id}:key/{EncryptionKey}"},
    {"from_type": "guardduty.destination", "relation_type": "logging_enabled_to", "to_type": "logs.group",
     "source_field": "LogGroupName", "target_uid_pattern": "arn:aws:logs:{region}:{account_id}:log-group/{LogGroupName}"},
    {"from_type": "guardduty.resource", "relation_type": "controlled_by", "to_type": "iam.role",
     "source_field": "Role", "target_uid_pattern": "arn:aws:iam::{account_id}:role/{Role}"},

    # INSPECTOR
    {"from_type": "inspector.group", "relation_type": "uses", "to_type": "inspector.target",
     "source_field": "AssessmentTargetArns", "target_uid_pattern": "{AssessmentTargetArns}",
     "source_field_item": "AssessmentTargetArn"},
    {"from_type": "inspector.template", "relation_type": "uses", "to_type": "inspector.target",
     "source_field": "AssessmentTargetArn", "target_uid_pattern": "{AssessmentTargetArn}"},
    {"from_type": "inspector.template", "relation_type": "uses", "to_type": "inspector.role",
     "source_field": "AssessmentRoleArn", "target_uid_pattern": "{AssessmentRoleArn}"},
    {"from_type": "inspector.run", "relation_type": "uses", "to_type": "inspector.template",
     "source_field": "AssessmentTemplateArn", "target_uid_pattern": "{AssessmentTemplateArn}"},
    {"from_type": "inspector.run", "relation_type": "uses", "to_type": "inspector.resource",
     "source_field": "ResourceGroupArn", "target_uid_pattern": "{ResourceGroupArn}"},
    {"from_type": "inspector.run", "relation_type": "monitored_by", "to_type": "inspector.topic",
     "source_field": "NotificationConfig.TopicArn", "target_uid_pattern": "{NotificationConfig.TopicArn}"},
    {"from_type": "inspector.role", "relation_type": "assumes", "to_type": "iam.role",
     "source_field": "RoleArn", "target_uid_pattern": "{RoleArn}"},

    # KAFKA
    {"from_type": "kafka.cluster", "relation_type": "connected_to", "to_type": "ec2.subnet",
     "source_field": "SubnetIds", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:subnet/{SubnetIds}",
     "source_field_item": "SubnetId"},
    {"from_type": "kafka.cluster", "relation_type": "attached_to", "to_type": "ec2.security-group",
     "source_field": "SecurityGroups", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:security-group/{SecurityGroups}",
     "source_field_item": "SecurityGroupId"},
    {"from_type": "kafka.cluster", "relation_type": "uses", "to_type": "kafka.configuration",
     "source_field": "CurrentVersion", "target_uid_pattern": "arn:aws:kafka:{region}:{account_id}:configuration/{CurrentVersion}"},
    {"from_type": "kafka.topic", "relation_type": "contained_by", "to_type": "kafka.cluster",
     "source_field": "ClusterArn", "target_uid_pattern": "{ClusterArn}"},
    {"from_type": "kafka.node", "relation_type": "contained_by", "to_type": "kafka.cluster",
     "source_field": "ClusterArn", "target_uid_pattern": "{ClusterArn}"},
    {"from_type": "kafka.replicator", "relation_type": "replicates_to", "to_type": "kafka.cluster",
     "source_field": "DestinationClusterArn", "target_uid_pattern": "{DestinationClusterArn}"},

    # KEYSPACES
    {"from_type": "keyspaces.resource", "relation_type": "uses", "to_type": "iam.role",
     "source_field": "RoleArn", "target_uid_pattern": "{RoleArn}"},
    {"from_type": "keyspaces.resource", "relation_type": "encrypted_by", "to_type": "kms.key",
     "source_field": "KmsKeyId", "target_uid_pattern": "arn:aws:kms:{region}:{account_id}:key/{KmsKeyId}"},
    {"from_type": "keyspaces.resource", "relation_type": "monitored_by", "to_type": "logs.group",
     "source_field": "LogGroupName", "target_uid_pattern": "arn:aws:logs:{region}:{account_id}:log-group:{LogGroupName}"},


    # ---------------------------------------------------------------------
    # Generated relationships (from OpenAI agent)
    # ---------------------------------------------------------------------

    # KINESIS
    {"from_type": "kinesis.consumer", "relation_type": "uses", "to_type": "kinesis.stream",
     "source_field": "StreamARN", "target_uid_pattern": "{StreamARN}"},

    # KINESISVIDEOSTREAMS
    {"from_type": "kinesisvideostreams.stream", "relation_type": "uses", "to_type": "kinesisvideostreams.configuration",
     "source_field": "ConfigurationId", "target_uid_pattern": "arn:aws:kinesisvideo:{region}:{account_id}:configuration/{ConfigurationId}"},
    {"from_type": "kinesisvideostreams.stream", "relation_type": "uses", "to_type": "kinesisvideostreams.device",
     "source_field": "DeviceId", "target_uid_pattern": "arn:aws:kinesisvideo:{region}:{account_id}:device/{DeviceId}"},
    {"from_type": "kinesisvideostreams.channel", "relation_type": "uses", "to_type": "kinesisvideostreams.stream",
     "source_field": "StreamId", "target_uid_pattern": "arn:aws:kinesisvideo:{region}:{account_id}:stream/{StreamId}"},

    # LAKEFORMATION
    {"from_type": "lakeformation.application", "relation_type": "uses", "to_type": "lakeformation.role",
     "source_field": "RoleArn", "target_uid_pattern": "{RoleArn}"},
    {"from_type": "lakeformation.resource", "relation_type": "controlled_by", "to_type": "lakeformation.role",
     "source_field": "OwnerRoleArn", "target_uid_pattern": "{OwnerRoleArn}"},
    {"from_type": "lakeformation.role", "relation_type": "assumes", "to_type": "iam.role",
     "source_field": "AssumedRoleArn", "target_uid_pattern": "{AssumedRoleArn}"},

    # LIGHTSAIL
    {"from_type": "lightsail.instance", "relation_type": "attached_to", "to_type": "lightsail.disk",
     "source_field": "AttachedDiskIds", "target_uid_pattern": "arn:aws:lightsail:{region}:{account_id}:disk/{AttachedDiskIds}",
     "source_field_item": "AttachedDiskId"},
    {"from_type": "lightsail.instance", "relation_type": "monitored_by", "to_type": "lightsail.alarm",
     "source_field": "AlarmNames", "target_uid_pattern": "arn:aws:lightsail:{region}:{account_id}:alarm/{AlarmNames}",
     "source_field_item": "AlarmName"},
    {"from_type": "lightsail.balancer", "relation_type": "serves_traffic_for", "to_type": "lightsail.instance",
     "source_field": "InstanceNames", "target_uid_pattern": "arn:aws:lightsail:{region}:{account_id}:instance/{InstanceNames}",
     "source_field_item": "InstanceName"},
    {"from_type": "lightsail.databas", "relation_type": "backs_up_to", "to_type": "lightsail.snapshot",
     "source_field": "SnapshotNames", "target_uid_pattern": "arn:aws:lightsail:{region}:{account_id}:snapshot/{SnapshotNames}",
     "source_field_item": "SnapshotName"},
    {"from_type": "lightsail.database", "relation_type": "monitored_by", "to_type": "lightsail.alarm",
     "source_field": "AlarmNames", "target_uid_pattern": "arn:aws:lightsail:{region}:{account_id}:alarm/{AlarmNames}",
     "source_field_item": "AlarmName"},
    {"from_type": "lightsail.balancer", "relation_type": "uses", "to_type": "lightsail.certificate",
     "source_field": "CertificateName", "target_uid_pattern": "arn:aws:lightsail:{region}:{account_id}:certificate/{CertificateName}"},
    {"from_type": "lightsail.instance", "relation_type": "uses", "to_type": "lightsail.pair",
     "source_field": "KeyPairName", "target_uid_pattern": "arn:aws:lightsail:{region}:{account_id}:key-pair/{KeyPairName}"},

    # MACIE
    {"from_type": "macie.bucket", "relation_type": "monitored_by", "to_type": "macie.allow",
     "source_field": "BucketName", "target_uid_pattern": "arn:aws:s3:::{BucketName}"},
    {"from_type": "macie.job", "relation_type": "uses", "to_type": "macie.filter",
     "source_field": "FilterId", "target_uid_pattern": "arn:aws:macie:{region}:{account_id}:filter/{FilterId}"},
    {"from_type": "macie.job", "relation_type": "monitored_by", "to_type": "macie.allow",
     "source_field": "JobId", "target_uid_pattern": "arn:aws:macie:{region}:{account_id}:job/{JobId}"},

    # MQ
    {"from_type": "mq.broker", "relation_type": "uses", "to_type": "mq.configuration",
     "source_field": "ConfigurationId", "target_uid_pattern": "arn:aws:mq:{region}:{account_id}:configuration/{ConfigurationId}"},
    {"from_type": "mq.broker", "relation_type": "attached_to", "to_type": "ec2.security-group",
     "source_field": "SecurityGroups", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:security-group/{source_field_item}",
     "source_field_item": "SecurityGroupId"},

    # NEPTUNE
    {"from_type": "neptune.cluster", "relation_type": "uses", "to_type": "neptune.instance",
     "source_field": "DBClusterIdentifier", "target_uid_pattern": "arn:aws:rds:{region}:{account_id}:db:{DBClusterIdentifier}"},
    {"from_type": "neptune.instance", "relation_type": "contained_by", "to_type": "neptune.cluster",
     "source_field": "DBInstanceIdentifier", "target_uid_pattern": "arn:aws:rds:{region}:{account_id}:db:{DBInstanceIdentifier}"},
    {"from_type": "neptune.snapshot", "relation_type": "backs_up_to", "to_type": "neptune.cluster",
     "source_field": "DBClusterSnapshotIdentifier", "target_uid_pattern": "arn:aws:rds:{region}:{account_id}:cluster-snapshot:{DBClusterSnapshotIdentifier}"},
    {"from_type": "neptune.endpoint", "relation_type": "connected_to", "to_type": "neptune.cluster",
     "source_field": "Endpoint", "target_uid_pattern": "arn:aws:rds:{region}:{account_id}:cluster:{Endpoint}"},
    {"from_type": "neptune.subscription", "relation_type": "uses", "to_type": "sns.topic",
     "source_field": "SourceIds", "target_uid_pattern": "arn:aws:sns:{region}:{account_id}:{SourceIds}",
     "source_field_item": "SourceId"},

    # NETWORKFIREWALL
    {"from_type": "networkfirewall.firewall", "relation_type": "uses", "to_type": "networkfirewall.policy",
     "source_field": "FirewallPolicyArn", "target_uid_pattern": "{FirewallPolicyArn}"},
    {"from_type": "networkfirewall.configuration", "relation_type": "logging_enabled_to", "to_type": "logs.group",
     "source_field": "LogDestinationConfigs", "target_uid_pattern": "arn:aws:logs:{region}:{account_id}:log-group/{LogDestinationConfigs}",
     "source_field_item": "LogDestinationConfigs"},
    {"from_type": "networkfirewall.policy", "relation_type": "attached_to", "to_type": "networkfirewall.group",
     "source_field": "FirewallPolicyId", "target_uid_pattern": "arn:aws:networkfirewall:{region}:{account_id}:firewall-policy/{FirewallPolicyId}"},

    # OPENSEARCH
    {"from_type": "opensearch.domain", "relation_type": "uses", "to_type": "opensearch.application",
     "source_field": "ApplicationId", "target_uid_pattern": "arn:aws:opensearch:{region}:{account_id}:application/{ApplicationId}"},
    {"from_type": "opensearch.domain", "relation_type": "connected_to", "to_type": "opensearch.searchs",
     "source_field": "SearchId", "target_uid_pattern": "arn:aws:opensearch:{region}:{account_id}:searchs/{SearchId}"},
    {"from_type": "opensearch.domain", "relation_type": "contained_by", "to_type": "opensearch.source",
     "source_field": "SourceId", "target_uid_pattern": "arn:aws:opensearch:{region}:{account_id}:source/{SourceId}"},
    {"from_type": "opensearch.domain", "relation_type": "monitored_by", "to_type": "opensearch.statu",
     "source_field": "StatusId", "target_uid_pattern": "arn:aws:opensearch:{region}:{account_id}:statu/{StatusId}"},

    # ORGANIZATIONS
    {"from_type": "organizations.account", "relation_type": "contained_by", "to_type": "organizations.organization",
     "source_field": "Id", "target_uid_pattern": "arn:aws:organizations::{account_id}:organization/{Id}"},
    {"from_type": "organizations.organization", "relation_type": "has_policy", "to_type": "iam.policy",
     "source_field": "PolicyId", "target_uid_pattern": "arn:aws:iam::{account_id}:policy/{PolicyId}",
     "source_field_item": "Policies"},
    {"from_type": "organizations.account", "relation_type": "controlled_by", "to_type": "iam.role",
     "source_field": "RoleArn", "target_uid_pattern": "{RoleArn}"},

    # PARAMETERSTORE
    {"from_type": "parameterstore.ops", "relation_type": "uses", "to_type": "iam.role",
     "source_field": "RoleArn", "target_uid_pattern": "{RoleArn}"},
    {"from_type": "parameterstore.role", "relation_type": "assumes", "to_type": "iam.role",
     "source_field": "RoleArn", "target_uid_pattern": "{RoleArn}"},

    # REDSHIFT
    {"from_type": "redshift.clusterspace", "relation_type": "uses", "to_type": "redshift.catalog",
     "source_field": "CatalogId", "target_uid_pattern": "arn:aws:redshift:{region}:{account_id}:catalog/{CatalogId}"},
    {"from_type": "redshift.clusterspace", "relation_type": "uses", "to_type": "redshift.secret",
     "source_field": "SecretId", "target_uid_pattern": "arn:aws:secretsmanager:{region}:{account_id}:secret:{SecretId}"},
    {"from_type": "redshift.clusterspace", "relation_type": "uses", "to_type": "redshift.role",
     "source_field": "RoleArn", "target_uid_pattern": "{RoleArn}"},
    {"from_type": "redshift.snapshot", "relation_type": "backs_up_to", "to_type": "redshift.clusterspace",
     "source_field": "ClusterIdentifier", "target_uid_pattern": "arn:aws:redshift:{region}:{account_id}:cluster/{ClusterIdentifier}"},
    {"from_type": "redshift.integration", "relation_type": "connected_to", "to_type": "redshift.target",
     "source_field": "TargetId", "target_uid_pattern": "arn:aws:redshift:{region}:{account_id}:target/{TargetId}"},
    {"from_type": "redshift.integration", "relation_type": "connected_to", "to_type": "redshift.source",
     "source_field": "SourceId", "target_uid_pattern": "arn:aws:redshift:{region}:{account_id}:source/{SourceId}"},
    {"from_type": "redshift.application", "relation_type": "uses", "to_type": "redshift.role",
     "source_field": "RoleArn", "target_uid_pattern": "{RoleArn}"},
    {"from_type": "redshift.application", "relation_type": "uses", "to_type": "redshift.secret",
     "source_field": "SecretId", "target_uid_pattern": "arn:aws:secretsmanager:{region}:{account_id}:secret:{SecretId}"},
    {"from_type": "redshift.producer", "relation_type": "connected_to", "to_type": "redshift.topic",
     "source_field": "TopicArn", "target_uid_pattern": "{TopicArn}"},
    {"from_type": "redshift.recommendationspace", "relation_type": "uses", "to_type": "redshift.catalog",
     "source_field": "CatalogId", "target_uid_pattern": "arn:aws:redshift:{region}:{account_id}:catalog/{CatalogId}"},

    # SAGEMAKER
    {"from_type": "sagemaker.endpoint", "relation_type": "uses", "to_type": "sagemaker.model",
     "source_field": "ModelName", "target_uid_pattern": "arn:aws:sagemaker:{region}:{account_id}:model/{ModelName}"},
    {"from_type": "sagemaker.job", "relation_type": "uses", "to_type": "sagemaker.algorithm",
     "source_field": "AlgorithmName", "target_uid_pattern": "arn:aws:sagemaker:{region}:{account_id}:algorithm/{AlgorithmName}"},
    {"from_type": "sagemaker.pipeline", "relation_type": "uses", "to_type": "sagemaker.model",
     "source_field": "ModelName", "target_uid_pattern": "arn:aws:sagemaker:{region}:{account_id}:model/{ModelName}"},
    {"from_type": "sagemaker.pipeline", "relation_type": "uses", "to_type": "sagemaker.job",
     "source_field": "JobName", "target_uid_pattern": "arn:aws:sagemaker:{region}:{account_id}:job/{JobName}"},
    {"from_type": "sagemaker.trial", "relation_type": "uses", "to_type": "sagemaker.action",
     "source_field": "ActionName", "target_uid_pattern": "arn:aws:sagemaker:{region}:{account_id}:action/{ActionName}"},
    {"from_type": "sagemaker.device", "relation_type": "member_of", "to_type": "sagemaker.fleet",
     "source_field": "FleetName", "target_uid_pattern": "arn:aws:sagemaker:{region}:{account_id}:fleet/{FleetName}"},
    {"from_type": "sagemaker.workforce", "relation_type": "uses", "to_type": "sagemaker.workteam",
     "source_field": "WorkteamName", "target_uid_pattern": "arn:aws:sagemaker:{region}:{account_id}:workteam/{WorkteamName}"},
    {"from_type": "sagemaker.model", "relation_type": "uses", "to_type": "sagemaker.package",
     "source_field": "PackageName", "target_uid_pattern": "arn:aws:sagemaker:{region}:{account_id}:package/{PackageName}"},
    {"from_type": "sagemaker.domain", "relation_type": "uses", "to_type": "sagemaker.profile",
     "source_field": "ProfileName", "target_uid_pattern": "arn:aws:sagemaker:{region}:{account_id}:profile/{ProfileName}"},

    # SECURITYHUB
    {"from_type": "securityhub.hub", "relation_type": "controlled_by", "to_type": "iam.role",
     "source_field": "RoleArn", "target_uid_pattern": "{RoleArn}"},
    {"from_type": "securityhub.insight", "relation_type": "monitored_by", "to_type": "securityhub.hub",
     "source_field": "HubArn", "target_uid_pattern": "{HubArn}"},
    {"from_type": "securityhub.product", "relation_type": "connected_to", "to_type": "securityhub.hub",
     "source_field": "HubArn", "target_uid_pattern": "{HubArn}"},
    {"from_type": "securityhub.standards", "relation_type": "controlled_by", "to_type": "securityhub.hub",
     "source_field": "HubArn", "target_uid_pattern": "{HubArn}"},
    {"from_type": "securityhub.control", "relation_type": "controlled_by", "to_type": "securityhub.standards",
     "source_field": "StandardsArn", "target_uid_pattern": "{StandardsArn}"},
    {"from_type": "securityhub.subscription", "relation_type": "connected_to", "to_type": "securityhub.product",
     "source_field": "ProductArn", "target_uid_pattern": "{ProductArn}"},
    {"from_type": "securityhub.target", "relation_type": "connected_to", "to_type": "securityhub.insight",
     "source_field": "InsightArn", "target_uid_pattern": "{InsightArn}"},

    # SERVICECATALOG
    {"from_type": "servicecatalog.portfolio", "relation_type": "controlled_by", "to_type": "servicecatalog.principal",
     "source_field": "PrincipalId", "target_uid_pattern": "arn:aws:iam::{account_id}:user/{PrincipalId}"},
    {"from_type": "servicecatalog.portfolio", "relation_type": "controlled_by", "to_type": "iam.role",
     "source_field": "RoleId", "target_uid_pattern": "arn:aws:iam::{account_id}:role/{RoleId}"},
    {"from_type": "servicecatalog.principal", "relation_type": "assumes", "to_type": "iam.role",
     "source_field": "RoleId", "target_uid_pattern": "arn:aws:iam::{account_id}:role/{RoleId}"},

    # SHIELD
    {"from_type": "shield.protection", "relation_type": "attached_to", "to_type": "shield.resource",
     "source_field": "ResourceArn", "target_uid_pattern": "{ResourceArn}"},
    {"from_type": "shield.subscription", "relation_type": "controlled_by", "to_type": "iam.role",
     "source_field": "RoleArn", "target_uid_pattern": "{RoleArn}"},

    # SSM
    {"from_type": "ssm.ops", "relation_type": "uses", "to_type": "ssm.parameter",
     "source_field": "ParameterName", "target_uid_pattern": "arn:aws:ssm:{region}:{account_id}:parameter/{ParameterName}"},
    {"from_type": "ssm.ops", "relation_type": "uses", "to_type": "iam.role",
     "source_field": "RoleArn", "target_uid_pattern": "{RoleArn}"},
    {"from_type": "ssm.task", "relation_type": "uses", "to_type": "ssm.parameter",
     "source_field": "ParameterName", "target_uid_pattern": "arn:aws:ssm:{region}:{account_id}:parameter/{ParameterName}"},
    {"from_type": "ssm.task", "relation_type": "uses", "to_type": "iam.role",
     "source_field": "RoleArn", "target_uid_pattern": "{RoleArn}"},

    # STEPFUNCTIONS
    {"from_type": "stepfunctions.execution", "relation_type": "invokes", "to_type": "stepfunctions.machine",
     "source_field": "StateMachineArn", "target_uid_pattern": "{StateMachineArn}"},
    {"from_type": "stepfunctions.machine", "relation_type": "uses", "to_type": "stepfunctions.activity",
     "source_field": "Activities", "target_uid_pattern": "arn:aws:states:{region}:{account_id}:activity/{Activities}",
     "source_field_item": "Name"},
    {"from_type": "stepfunctions.machine", "relation_type": "uses", "to_type": "stepfunctions.version",
     "source_field": "StateMachineVersionArn", "target_uid_pattern": "{StateMachineVersionArn}"},
    {"from_type": "stepfunctions.machine", "relation_type": "uses", "to_type": "stepfunctions.alias",
     "source_field": "StateMachineAliasArn", "target_uid_pattern": "{StateMachineAliasArn}"},
    {"from_type": "stepfunctions.execution", "relation_type": "triggers", "to_type": "stepfunctions.run",
     "source_field": "ExecutionArn", "target_uid_pattern": "{ExecutionArn}"},

    # STORAGEGATEWAY
    {"from_type": "storagegateway.volume", "relation_type": "attached_to", "to_type": "storagegateway.gateway",
     "source_field": "GatewayARN", "target_uid_pattern": "{GatewayARN}"},
    {"from_type": "storagegateway.tape", "relation_type": "attached_to", "to_type": "storagegateway.gateway",
     "source_field": "GatewayARN", "target_uid_pattern": "{GatewayARN}"},
    {"from_type": "storagegateway.share", "relation_type": "attached_to", "to_type": "storagegateway.gateway",
     "source_field": "GatewayARN", "target_uid_pattern": "{GatewayARN}"},
    {"from_type": "storagegateway.association", "relation_type": "connected_to", "to_type": "storagegateway.gateway",
     "source_field": "GatewayARN", "target_uid_pattern": "{GatewayARN}"},
    {"from_type": "storagegateway.location", "relation_type": "connected_to", "to_type": "storagegateway.gateway",
     "source_field": "GatewayARN", "target_uid_pattern": "{GatewayARN}"},
    {"from_type": "storagegateway.pool", "relation_type": "connected_to", "to_type": "storagegateway.gateway",
     "source_field": "GatewayARN", "target_uid_pattern": "{GatewayARN}"},
    {"from_type": "storagegateway.report", "relation_type": "connected_to", "to_type": "storagegateway.gateway",
     "source_field": "GatewayARN", "target_uid_pattern": "{GatewayARN}"},
    {"from_type": "storagegateway.destination", "relation_type": "connected_to", "to_type": "storagegateway.gateway",
     "source_field": "GatewayARN", "target_uid_pattern": "{GatewayARN}"},
    {"from_type": "storagegateway.device", "relation_type": "connected_to", "to_type": "storagegateway.gateway",
     "source_field": "GatewayARN", "target_uid_pattern": "{GatewayARN}"},

    # VPCFLOWLOGS
    {"from_type": "vpcflowlogs.analysis", "relation_type": "logging_enabled_to", "to_type": "logs.group",
     "source_field": "LogGroupName", "target_uid_pattern": "arn:aws:logs:{region}:{account_id}:log-group:{LogGroupName}"},
    {"from_type": "vpcflowlogs.policy", "relation_type": "has_policy", "to_type": "iam.policy",
     "source_field": "PolicyName", "target_uid_pattern": "arn:aws:iam::{account_id}:policy/{PolicyName}"},
    {"from_type": "vpcflowlogs.role", "relation_type": "assumes", "to_type": "iam.role",
     "source_field": "RoleName", "target_uid_pattern": "arn:aws:iam::{account_id}:role/{RoleName}"},

    # WAF
    {"from_type": "waf.acl", "relation_type": "attached_to", "to_type": "waf.resource",
     "source_field": "ResourceArn", "target_uid_pattern": "{ResourceArn}"},
    {"from_type": "waf.acl", "relation_type": "logging_enabled_to", "to_type": "logs.group",
     "source_field": "LogDestinationConfigs", "target_uid_pattern": "arn:aws:logs:{region}:{account_id}:log-group:{LogDestinationConfigs}",
     "source_field_item": "LogDestinationConfig"},

    # WAFV2
    {"from_type": "wafv2.group", "relation_type": "attached_to", "to_type": "wafv2.resource",
     "source_field": "ResourceArn", "target_uid_pattern": "{ResourceArn}"},
    {"from_type": "wafv2.group", "relation_type": "logging_enabled_to", "to_type": "wafv2.topic",
     "source_field": "LoggingConfiguration.DestinationConfigs", "target_uid_pattern": "{LoggingConfiguration.DestinationConfigs}",
     "source_field_item": "DestinationConfig"},

    # WELLARCHITECTED
    {"from_type": "wellarchitected.workload", "relation_type": "uses", "to_type": "wellarchitected.lens",
     "source_field": "LensArn", "target_uid_pattern": "{LensArn}"},
    {"from_type": "wellarchitected.workload", "relation_type": "uses", "to_type": "wellarchitected.profile",
     "source_field": "ProfileArn", "target_uid_pattern": "{ProfileArn}"},
    {"from_type": "wellarchitected.workload", "relation_type": "uses", "to_type": "wellarchitected.template",
     "source_field": "TemplateArn", "target_uid_pattern": "{TemplateArn}"},

    # WORKFLOWS
    {"from_type": "workflows.execution", "relation_type": "uses", "to_type": "workflows.machine",
     "source_field": "StateMachineArn", "target_uid_pattern": "{StateMachineArn}"},
    {"from_type": "workflows.machine", "relation_type": "uses", "to_type": "workflows.role",
     "source_field": "RoleArn", "target_uid_pattern": "{RoleArn}"},
    {"from_type": "workflows.run", "relation_type": "invokes", "to_type": "workflows.execution",
     "source_field": "ExecutionArn", "target_uid_pattern": "{ExecutionArn}"},
    {"from_type": "workflows.version", "relation_type": "contained_by", "to_type": "workflows.machine",
     "source_field": "StateMachineArn", "target_uid_pattern": "{StateMachineArn}"},
    {"from_type": "workflows.alias", "relation_type": "contained_by", "to_type": "workflows.machine",
     "source_field": "StateMachineArn", "target_uid_pattern": "{StateMachineArn}"},
    {"from_type": "workflows.activity", "relation_type": "invokes", "to_type": "workflows.execution",
     "source_field": "ExecutionArn", "target_uid_pattern": "{ExecutionArn}"},


    # ---------------------------------------------------------------------
    # Generated relationships (from OpenAI agent)
    # ---------------------------------------------------------------------

    # EKS
    {"from_type": "eks.policy", "relation_type": "has_policy", "to_type": "iam.policy",
     "source_field": "PolicyArn", "target_uid_pattern": "{PolicyArn}"},
    {"from_type": "eks.role", "relation_type": "assumes", "to_type": "iam.role",
     "source_field": "RoleArn", "target_uid_pattern": "{RoleArn}"},

    # KINESISANALYTICS
    {"from_type": "kinesisanalytics.application", "relation_type": "uses", "to_type": "iam.role",
     "source_field": "RoleARN", "target_uid_pattern": "{RoleARN}"},
    {"from_type": "kinesisanalytics.application", "relation_type": "uses", "to_type": "kinesis.stream",
     "source_field": "InputKinesisStreamARN", "target_uid_pattern": "arn:aws:kinesis:{region}:{account_id}:stream/{InputKinesisStreamARN}"},
    {"from_type": "kinesisanalytics.application", "relation_type": "uses", "to_type": "kinesis.stream",
     "source_field": "OutputKinesisStreamARN", "target_uid_pattern": "arn:aws:kinesis:{region}:{account_id}:stream/{OutputKinesisStreamARN}"},
    {"from_type": "kinesisanalytics.application", "relation_type": "uses", "to_type": "s3.bucket",
     "source_field": "InputS3BucketARN", "target_uid_pattern": "arn:aws:s3:::{InputS3BucketARN}"},
    {"from_type": "kinesisanalytics.application", "relation_type": "uses", "to_type": "s3.bucket",
     "source_field": "OutputS3BucketARN", "target_uid_pattern": "arn:aws:s3:::{OutputS3BucketARN}"},
    {"from_type": "kinesisanalytics.application", "relation_type": "uses", "to_type": "logs.group",
     "source_field": "LogGroupARN", "target_uid_pattern": "arn:aws:logs:{region}:{account_id}:log-group:{LogGroupARN}"},


    # ---------------------------------------------------------------------
    # Generated relationships (from OpenAI agent)
    # ---------------------------------------------------------------------

    # APIGATEWAY
    {"from_type": "apigateway.acl", "relation_type": "attached_to", "to_type": "apigateway.domain",
     "source_field": "DomainName", "target_uid_pattern": "arn:aws:apigateway:{region}:{account_id}:domain/{DomainName}"},
    {"from_type": "apigateway.association", "relation_type": "connected_to", "to_type": "apigateway.targets",
     "source_field": "IntegrationUri", "target_uid_pattern": "{IntegrationUri}"},
    {"from_type": "apigateway.certificate", "relation_type": "attached_to", "to_type": "apigateway.domain",
     "source_field": "DomainName", "target_uid_pattern": "arn:aws:apigateway:{region}:{account_id}:domain/{DomainName}"},
    {"from_type": "apigateway.destination", "relation_type": "routes_to", "to_type": "apigateway.targets",
     "source_field": "IntegrationUri", "target_uid_pattern": "{IntegrationUri}"},
    {"from_type": "apigateway.domain", "relation_type": "serves_traffic_for", "to_type": "apigateway.targets",
     "source_field": "DomainName", "target_uid_pattern": "arn:aws:apigateway:{region}:{account_id}:domain/{DomainName}"},

    # AUTOSCALING
    {"from_type": "autoscaling.group", "relation_type": "assumes", "to_type": "iam.role",
     "source_field": "ServiceLinkedRoleARN", "target_uid_pattern": "{ServiceLinkedRoleARN}"},

    # BACKUP
    {"from_type": "backup.resource", "relation_type": "backs_up_to", "to_type": "backup.vault",
     "source_field": "BackupVaultName", "target_uid_pattern": "arn:aws:backup:{region}:{account_id}:backup-vault/{BackupVaultName}"},
    {"from_type": "backup.session", "relation_type": "uses", "to_type": "iam.role",
     "source_field": "IamRoleArn", "target_uid_pattern": "{IamRoleArn}"},

    # BATCH
    {"from_type": "batch.job", "relation_type": "contained_by", "to_type": "batch.queue",
     "source_field": "JobQueue", "target_uid_pattern": "arn:aws:batch:{region}:{account_id}:job-queue/{JobQueue}"},
    {"from_type": "batch.queue", "relation_type": "uses", "to_type": "batch.environment",
     "source_field": "ComputeEnvironmentOrder", "target_uid_pattern": "arn:aws:batch:{region}:{account_id}:compute-environment/{ComputeEnvironmentOrder}",
     "source_field_item": "ComputeEnvironment"},
    {"from_type": "batch.definition", "relation_type": "uses", "to_type": "batch.environment",
     "source_field": "ContainerProperties", "target_uid_pattern": "arn:aws:batch:{region}:{account_id}:compute-environment/{ContainerProperties}",
     "source_field_item": "Environment"},
    {"from_type": "batch.cluster", "relation_type": "uses", "to_type": "batch.queue",
     "source_field": "JobQueues", "target_uid_pattern": "arn:aws:batch:{region}:{account_id}:job-queue/{JobQueues}",
     "source_field_item": "QueueName"},
    {"from_type": "batch.policy", "relation_type": "grants_access_to", "to_type": "batch.resource",
     "source_field": "Resource", "target_uid_pattern": "arn:aws:batch:{region}:{account_id}:resource/{Resource}"},

    # BEDROCK
    {"from_type": "bedrock.guardrail", "relation_type": "controlled_by", "to_type": "iam.role",
     "source_field": "RoleArn", "target_uid_pattern": "{RoleArn}"},
    {"from_type": "bedrock.policy", "relation_type": "grants_access_to", "to_type": "bedrock.model",
     "source_field": "ModelId", "target_uid_pattern": "arn:aws:bedrock:{region}:{account_id}:model/{ModelId}"},
    {"from_type": "bedrock.profile", "relation_type": "controlled_by", "to_type": "iam.role",
     "source_field": "RoleArn", "target_uid_pattern": "{RoleArn}"},
    {"from_type": "bedrock.role", "relation_type": "assumes", "to_type": "iam.role",
     "source_field": "RoleArn", "target_uid_pattern": "{RoleArn}"},

    # CLOUDFRONT
    {"from_type": "cloudfront.config", "relation_type": "uses", "to_type": "cloudfront.certificate",
     "source_field": "ViewerCertificate.ACMCertificateArn", "target_uid_pattern": "{ViewerCertificate.ACMCertificateArn}"},
    {"from_type": "cloudfront.config", "relation_type": "uses", "to_type": "cloudfront.function",
     "source_field": "DefaultCacheBehavior.LambdaFunctionAssociations.Items", "target_uid_pattern": "arn:aws:lambda:{region}:{account_id}:function/{FunctionARN}",
     "source_field_item": "FunctionARN"},
    {"from_type": "cloudfront.config", "relation_type": "uses", "to_type": "cloudfront.group",
     "source_field": "CacheBehaviors.Items", "target_uid_pattern": "arn:aws:cloudfront::{account_id}:group/{FieldLevelEncryptionId}",
     "source_field_item": "FieldLevelEncryptionId"},

    # CLOUDTRAIL
    {"from_type": "cloudtrail.trail", "relation_type": "uses", "to_type": "cloudtrail.store",
     "source_field": "EventDataStoreArn", "target_uid_pattern": "{EventDataStoreArn}"},
    {"from_type": "cloudtrail.trail", "relation_type": "uses", "to_type": "sns.topic",
     "source_field": "SnsTopicArn", "target_uid_pattern": "{SnsTopicArn}"},
    {"from_type": "cloudtrail.trail", "relation_type": "uses", "to_type": "cloudtrail.role",
     "source_field": "RoleArn", "target_uid_pattern": "{RoleArn}"},
    {"from_type": "cloudtrail.trail", "relation_type": "logging_enabled_to", "to_type": "cloudtrail.store",
     "source_field": "LogFileValidationEnabled", "target_uid_pattern": "arn:aws:cloudtrail:{region}:{account_id}:store/{LogFileValidationEnabled}"},
    {"from_type": "cloudtrail.trail", "relation_type": "uses", "to_type": "cloudtrail.channel",
     "source_field": "CloudWatchLogsLogGroupArn", "target_uid_pattern": "{CloudWatchLogsLogGroupArn}"},

    # CLOUDWATCH
    {"from_type": "cloudwatch.alarm", "relation_type": "uses", "to_type": "cloudwatch.firehose",
     "source_field": "AlarmName", "target_uid_pattern": "arn:aws:cloudwatch:{region}:{account_id}:firehose/{AlarmName}"},
    {"from_type": "cloudwatch.entry", "relation_type": "monitored_by", "to_type": "cloudwatch.alarm",
     "source_field": "EntryName", "target_uid_pattern": "arn:aws:cloudwatch:{region}:{account_id}:alarm/{EntryName}"},
    {"from_type": "cloudwatch.firehose", "relation_type": "monitored_by", "to_type": "cloudwatch.alarm",
     "source_field": "FirehoseName", "target_uid_pattern": "arn:aws:cloudwatch:{region}:{account_id}:alarm/{FirehoseName}"},

    # DMS
    {"from_type": "dms.instance", "relation_type": "attached_to", "to_type": "iam.role",
     "source_field": "ServiceAccessRoleArn", "target_uid_pattern": "{ServiceAccessRoleArn}"},
    {"from_type": "dms.task", "relation_type": "attached_to", "to_type": "iam.role",
     "source_field": "ServiceAccessRoleArn", "target_uid_pattern": "{ServiceAccessRoleArn}"},

    # DOCDB
    {"from_type": "docdb.subscription", "relation_type": "uses", "to_type": "sns.topic",
     "source_field": "SourceIds", "target_uid_pattern": "arn:aws:sns:{region}:{account_id}:{SourceIds}",
     "source_field_item": "SourceId"},

    # DRS
    {"from_type": "drs.bucket", "relation_type": "encrypted_by", "to_type": "drs.key",
     "source_field": "KeyId", "target_uid_pattern": "arn:aws:drs:{region}:{account_id}:key/{KeyId}"},

    # DYNAMODB
    {"from_type": "dynamodb.table", "relation_type": "backs_up_to", "to_type": "dynamodb.backup",
     "source_field": "TableArn", "target_uid_pattern": "{TableArn}/backup/{BackupName}"},
    {"from_type": "dynamodb.table", "relation_type": "replicates_to", "to_type": "dynamodb.table",
     "source_field": "TableArn", "target_uid_pattern": "arn:aws:dynamodb:{region}:{account_id}:table/{ReplicaTableName}",
     "source_field_item": "ReplicaTableName"},
    {"from_type": "dynamodb.table", "relation_type": "uses", "to_type": "dynamodb.stream",
     "source_field": "LatestStreamArn", "target_uid_pattern": "{LatestStreamArn}"},

    # EC2
    {"from_type": "ec2.address-transfer-account", "relation_type": "controlled_by", "to_type": "ec2.account-attribut-attribute",
     "source_field": "TransferAccountId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:account/{TransferAccountId}"},
    {"from_type": "ec2.address-transfer-allocation", "relation_type": "attached_to", "to_type": "ec2.address-association",
     "source_field": "AllocationId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:allocation/{AllocationId}"},
    {"from_type": "ec2.client-vpn-endpoint-server-certificate", "relation_type": "uses", "to_type": "iam.role",
     "source_field": "ServerCertificateArn", "target_uid_pattern": "{ServerCertificateArn}"},
    {"from_type": "ec2.flow-log-flow-log", "relation_type": "logging_enabled_to", "to_type": "logs.group",
     "source_field": "LogGroupName", "target_uid_pattern": "arn:aws:logs:{region}:{account_id}:log-group/{LogGroupName}"},
    {"from_type": "ec2.flow-log-deliver-logs-permission", "relation_type": "uses", "to_type": "iam.role",
     "source_field": "DeliverLogsPermissionArn", "target_uid_pattern": "{DeliverLogsPermissionArn}"},
    {"from_type": "ec2.security-group-rul-security-group-rule", "relation_type": "allows_traffic_from", "to_type": "ec2.security-group",
     "source_field": "GroupId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:security-group/{GroupId}"},
    {"from_type": "ec2.transit-gateway-attachment-transit-gateway", "relation_type": "attached_to", "to_type": "ec2.transit-gateway",
     "source_field": "TransitGatewayId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:transit-gateway/{TransitGatewayId}"},
    {"from_type": "ec2.transit-gateway-attachment-transit-gateway-owner", "relation_type": "controlled_by", "to_type": "ec2.transit-gateway",
     "source_field": "TransitGatewayId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:transit-gateway/{TransitGatewayId}"},

    # ECR
    {"from_type": "ecr.repository", "relation_type": "controlled_by", "to_type": "ecr.credential",
     "source_field": "registryId", "target_uid_pattern": "arn:aws:ecr:{region}:{account_id}:credential/{registryId}"},
    {"from_type": "ecr.repository", "relation_type": "controlled_by", "to_type": "ecr.profile",
     "source_field": "registryId", "target_uid_pattern": "arn:aws:ecr:{region}:{account_id}:profile/{registryId}"},
    {"from_type": "ecr.repository", "relation_type": "controlled_by", "to_type": "ecr.role",
     "source_field": "registryId", "target_uid_pattern": "arn:aws:ecr:{region}:{account_id}:role/{registryId}"},
    {"from_type": "ecr.repository", "relation_type": "encrypted_by", "to_type": "kms.key",
     "source_field": "encryptionConfiguration", "target_uid_pattern": "arn:aws:kms:{region}:{account_id}:key/{encryptionConfiguration}"},

    # ECS
    {"from_type": "ecs.instance", "relation_type": "contained_by", "to_type": "ecs.cluster",
     "source_field": "clusterArn", "target_uid_pattern": "{clusterArn}"},
    {"from_type": "ecs.service", "relation_type": "uses", "to_type": "ecs.role",
     "source_field": "roleArn", "target_uid_pattern": "{roleArn}"},
    {"from_type": "ecs.principal", "relation_type": "assumes", "to_type": "ecs.role",
     "source_field": "roleArn", "target_uid_pattern": "{roleArn}"},

    # ELASTICBEANSTALK
    {"from_type": "elasticbeanstalk.environment", "relation_type": "contained_by", "to_type": "elasticbeanstalk.application",
     "source_field": "ApplicationName", "target_uid_pattern": "arn:aws:elasticbeanstalk:{region}:{account_id}:application/{ApplicationName}"},
    {"from_type": "elasticbeanstalk.version", "relation_type": "contained_by", "to_type": "elasticbeanstalk.application",
     "source_field": "ApplicationName", "target_uid_pattern": "arn:aws:elasticbeanstalk:{region}:{account_id}:application/{ApplicationName}"},
    {"from_type": "elasticbeanstalk.environment", "relation_type": "uses", "to_type": "elasticbeanstalk.version",
     "source_field": "VersionLabel", "target_uid_pattern": "arn:aws:elasticbeanstalk:{region}:{account_id}:applicationversion/{ApplicationName}/{VersionLabel}"},
    {"from_type": "elasticbeanstalk.environment", "relation_type": "uses", "to_type": "elasticbeanstalk.platform",
     "source_field": "PlatformArn", "target_uid_pattern": "{PlatformArn}"},

    # EMR
    {"from_type": "emr.cluster", "relation_type": "uses", "to_type": "iam.role",
     "source_field": "AutoScalingRole", "target_uid_pattern": "arn:aws:iam::{account_id}:role/{AutoScalingRole}"},
    {"from_type": "emr.cluster", "relation_type": "uses", "to_type": "emr.policy",
     "source_field": "ManagedScalingPolicy", "target_uid_pattern": "arn:aws:emr:{region}:{account_id}:policy/{ManagedScalingPolicy}"},
    {"from_type": "emr.studio", "relation_type": "uses", "to_type": "emr.cluster",
     "source_field": "ClusterId", "target_uid_pattern": "arn:aws:emr:{region}:{account_id}:cluster/{ClusterId}"},

    # EVENTBRIDGE
    {"from_type": "eventbridge.event", "relation_type": "triggers", "to_type": "eventbridge.source",
     "source_field": "Source", "target_uid_pattern": "arn:aws:events:{region}:{account_id}:event-source/{Source}"},
    {"from_type": "eventbridge.event", "relation_type": "uses", "to_type": "eventbridge.filters",
     "source_field": "Filters", "target_uid_pattern": "arn:aws:events:{region}:{account_id}:filter/{Filters}",
     "source_field_item": "Filter"},
    {"from_type": "eventbridge.config", "relation_type": "controlled_by", "to_type": "iam.role",
     "source_field": "RoleArn", "target_uid_pattern": "{RoleArn}"},
    {"from_type": "eventbridge.config", "relation_type": "uses", "to_type": "eventbridge.event",
     "source_field": "EventPattern", "target_uid_pattern": "arn:aws:events:{region}:{account_id}:event/{EventPattern}"},


    # ---------------------------------------------------------------------
    # Generated relationships (from OpenAI agent)
    # ---------------------------------------------------------------------

    # APIGATEWAY
    {"from_type": "apigateway.acl", "relation_type": "attached_to", "to_type": "apigateway.targets",
     "source_field": "RestApiId", "target_uid_pattern": "arn:aws:apigateway:{region}::/restapis/{RestApiId}"},
    {"from_type": "apigateway.association", "relation_type": "connected_to", "to_type": "apigateway.domain",
     "source_field": "DomainName", "target_uid_pattern": "arn:aws:apigateway:{region}:{account_id}:domainnames/{DomainName}"},
    {"from_type": "apigateway.domain", "relation_type": "serves_traffic_for", "to_type": "apigateway.targets",
     "source_field": "RestApiId", "target_uid_pattern": "arn:aws:apigateway:{region}::/restapis/{RestApiId}"},

    # AUTOSCALING
    {"from_type": "autoscaling.group", "relation_type": "assumes", "to_type": "iam.role",
     "source_field": "RoleARN", "target_uid_pattern": "{RoleARN}"},

    # BACKUP
    {"from_type": "backup.resource", "relation_type": "encrypted_by", "to_type": "kms.key",
     "source_field": "KmsKeyId", "target_uid_pattern": "arn:aws:kms:{region}:{account_id}:key/{KmsKeyId}"},

    # BATCH
    {"from_type": "batch.job", "relation_type": "contained_by", "to_type": "batch.queue",
     "source_field": "jobQueue", "target_uid_pattern": "arn:aws:batch:{region}:{account_id}:job-queue/{jobQueue}"},
    {"from_type": "batch.queue", "relation_type": "contained_by", "to_type": "batch.cluster",
     "source_field": "computeEnvironmentOrder", "target_uid_pattern": "arn:aws:batch:{region}:{account_id}:compute-environment/{computeEnvironmentOrder}",
     "source_field_item": "computeEnvironment"},
    {"from_type": "batch.definition", "relation_type": "uses", "to_type": "batch.environment",
     "source_field": "containerProperties", "target_uid_pattern": "arn:aws:batch:{region}:{account_id}:compute-environment/{containerProperties}",
     "source_field_item": "environment"},
    {"from_type": "batch.policy", "relation_type": "grants_access_to", "to_type": "batch.resource",
     "source_field": "resource", "target_uid_pattern": "arn:aws:batch:{region}:{account_id}:resource/{resource}"},

    # CLOUDFORMATION
    {"from_type": "cloudformation.set", "relation_type": "uses", "to_type": "cloudformation.version",
     "source_field": "Version", "target_uid_pattern": "arn:aws:cloudformation:{region}:{account_id}:version/{Version}"},

    # CLOUDTRAIL
    {"from_type": "cloudtrail.trail", "relation_type": "uses", "to_type": "cloudtrail.store",
     "source_field": "EventDataStore", "target_uid_pattern": "arn:aws:cloudtrail:{region}:{account_id}:eventdatastore/{EventDataStore}"},
    {"from_type": "cloudtrail.trail", "relation_type": "uses", "to_type": "sns.topic",
     "source_field": "SnsTopicName", "target_uid_pattern": "arn:aws:sns:{region}:{account_id}:{SnsTopicName}"},
    {"from_type": "cloudtrail.trail", "relation_type": "uses", "to_type": "cloudtrail.channel",
     "source_field": "InsightSelectors", "target_uid_pattern": "arn:aws:cloudtrail:{region}:{account_id}:channel/{InsightSelectors}",
     "source_field_item": "InsightType"},

    # DATASYNC
    {"from_type": "datasync.task", "relation_type": "connected_to", "to_type": "datasync.agent",
     "source_field": "TaskArn", "target_uid_pattern": "{TaskArn}"},
    {"from_type": "datasync.subnet", "relation_type": "contained_by", "to_type": "datasync.subnets",
     "source_field": "SubnetId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:subnet/{SubnetId}"},

    # DMS
    {"from_type": "dms.migration", "relation_type": "uses", "to_type": "dms.instance",
     "source_field": "ReplicationInstanceArn", "target_uid_pattern": "{ReplicationInstanceArn}"},
    {"from_type": "dms.role", "relation_type": "assumes", "to_type": "iam.role",
     "source_field": "RoleArn", "target_uid_pattern": "{RoleArn}"},

    # DOCDB
    {"from_type": "docdb.instance", "relation_type": "contained_by", "to_type": "docdb.cluster",
     "source_field": "DBInstanceIdentifier", "target_uid_pattern": "arn:aws:rds:{region}:{account_id}:db:{DBInstanceIdentifier}"},
    {"from_type": "docdb.snapshot", "relation_type": "backs_up_to", "to_type": "docdb.cluster",
     "source_field": "DBClusterSnapshotIdentifier", "target_uid_pattern": "arn:aws:rds:{region}:{account_id}:cluster-snapshot:{DBClusterSnapshotIdentifier}"},
    {"from_type": "docdb.cluster", "relation_type": "connected_to", "to_type": "ec2.security-group",
     "source_field": "VpcSecurityGroups", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:security-group/{VpcSecurityGroupId}",
     "source_field_item": "VpcSecurityGroupId"},
    {"from_type": "docdb.instance", "relation_type": "connected_to", "to_type": "ec2.security-group",
     "source_field": "VpcSecurityGroups", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:security-group/{VpcSecurityGroupId}",
     "source_field_item": "VpcSecurityGroupId"},

    # EC2
    {"from_type": "ec2.associated-rol-encryption-kms-key", "relation_type": "encrypted_by", "to_type": "kms.key",
     "source_field": "EncryptionKmsKeyId", "target_uid_pattern": "arn:aws:kms:{region}:{account_id}:key/{EncryptionKmsKeyId}"},
    {"from_type": "ec2.availability-zon-region", "relation_type": "contained_by", "to_type": "ec2.availability-zon-zone",
     "source_field": "RegionName", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:zone/{RegionName}"},
    {"from_type": "ec2.capacity-reservation-outpost", "relation_type": "contained_by", "to_type": "ec2.capacity-reservation-capacity-reservation",
     "source_field": "OutpostArn", "target_uid_pattern": "{OutpostArn}"},
    {"from_type": "ec2.client-vpn-endpoint-server-certificate", "relation_type": "uses", "to_type": "ec2.certificate",
     "source_field": "ServerCertificateArn", "target_uid_pattern": "{ServerCertificateArn}"},
    {"from_type": "ec2.flow-log-deliver-logs-permission", "relation_type": "logging_enabled_to", "to_type": "logs.group",
     "source_field": "LogGroupName", "target_uid_pattern": "arn:aws:logs:{region}:{account_id}:log-group/{LogGroupName}"},
    {"from_type": "ec2.flow-log-group", "relation_type": "attached_to", "to_type": "ec2.flow-log-flow-log",
     "source_field": "FlowLogId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:flow-log/{FlowLogId}"},
    {"from_type": "ec2.local-gateway-virtual-interfac-local-gateway-virtual-interface", "relation_type": "connected_to", "to_type": "ec2.local-gateway-virtual-interface-group",
     "source_field": "LocalGatewayVirtualInterfaceGroupId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:local-gateway-virtual-interface-group/{LocalGatewayVirtualInterfaceGroupId}"},
    {"from_type": "ec2.nat-gateway-nat-gateway", "relation_type": "attached_to", "to_type": "ec2.subnet",
     "source_field": "SubnetId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:subnet/{SubnetId}"},
    {"from_type": "ec2.snapshot-data-encryption-key", "relation_type": "encrypted_by", "to_type": "kms.key",
     "source_field": "KmsKeyId", "target_uid_pattern": "arn:aws:kms:{region}:{account_id}:key/{KmsKeyId}"},
    {"from_type": "ec2.traffic-mirror-session-traffic-mirror-session", "relation_type": "attached_to", "to_type": "ec2.traffic-mirror-target-gateway-load-balancer-endpoint",
     "source_field": "TrafficMirrorTargetId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:traffic-mirror-target/{TrafficMirrorTargetId}"},

    # ECS
    {"from_type": "ecs.service", "relation_type": "contained_by", "to_type": "ecs.cluster",
     "source_field": "ClusterArn", "target_uid_pattern": "{ClusterArn}"},
    {"from_type": "ecs.task", "relation_type": "contained_by", "to_type": "ecs.cluster",
     "source_field": "ClusterArn", "target_uid_pattern": "{ClusterArn}"},
    {"from_type": "ecs.task", "relation_type": "uses", "to_type": "ecs.definition",
     "source_field": "TaskDefinitionArn", "target_uid_pattern": "{TaskDefinitionArn}"},
    {"from_type": "ecs.service", "relation_type": "uses", "to_type": "ecs.role",
     "source_field": "RoleArn", "target_uid_pattern": "{RoleArn}"},
    {"from_type": "ecs.instance", "relation_type": "contained_by", "to_type": "ecs.cluster",
     "source_field": "ClusterArn", "target_uid_pattern": "{ClusterArn}"},
    {"from_type": "ecs.deployment", "relation_type": "contained_by", "to_type": "ecs.service",
     "source_field": "ServiceArn", "target_uid_pattern": "{ServiceArn}"},
    {"from_type": "ecs.set", "relation_type": "contained_by", "to_type": "ecs.service",
     "source_field": "ServiceArn", "target_uid_pattern": "{ServiceArn}"},
    {"from_type": "ecs.principal", "relation_type": "assumes", "to_type": "ecs.role",
     "source_field": "RoleArn", "target_uid_pattern": "{RoleArn}"},

    # EKS
    {"from_type": "eks.licenses", "relation_type": "uses", "to_type": "eks.policy",
     "source_field": "PolicyArn", "target_uid_pattern": "{PolicyArn}"},

    # ELASTICACHE
    {"from_type": "elasticache.cluster", "relation_type": "attached_to", "to_type": "elasticache.reservation",
     "source_field": "ReservedCacheNodeId", "target_uid_pattern": "arn:aws:elasticache:{region}:{account_id}:reservation/{ReservedCacheNodeId}"},

    # EMR
    {"from_type": "emr.cluster", "relation_type": "uses", "to_type": "emr.instance",
     "source_field": "Instances", "target_uid_pattern": "arn:aws:emr:{region}:{account_id}:instance/{InstanceId}",
     "source_field_item": "InstanceId"},
    {"from_type": "emr.cluster", "relation_type": "has_policy", "to_type": "emr.policy",
     "source_field": "ManagedScalingPolicy", "target_uid_pattern": "arn:aws:emr:{region}:{account_id}:policy/{PolicyId}",
     "source_field_item": "PolicyId"},


    # ---------------------------------------------------------------------
    # Generated relationships (from OpenAI agent)
    # ---------------------------------------------------------------------

    # APIGATEWAY
    {"from_type": "apigateway.domain", "relation_type": "connected_to", "to_type": "apigateway.targets",
     "source_field": "IntegrationUri", "target_uid_pattern": "{IntegrationUri}"},
    {"from_type": "apigateway.targets", "relation_type": "invokes", "to_type": "apigateway.association",
     "source_field": "IntegrationUri", "target_uid_pattern": "{IntegrationUri}"},

    # BACKUP
    {"from_type": "backup.plan", "relation_type": "uses", "to_type": "backup.role",
     "source_field": "RoleArn", "target_uid_pattern": "{RoleArn}"},
    {"from_type": "backup.point", "relation_type": "uses", "to_type": "backup.resource",
     "source_field": "ResourceArn", "target_uid_pattern": "{ResourceArn}"},

    # CLOUDTRAIL
    {"from_type": "cloudtrail.trail", "relation_type": "uses", "to_type": "iam.role",
     "source_field": "RoleArn", "target_uid_pattern": "{RoleArn}"},
    {"from_type": "cloudtrail.channel", "relation_type": "uses", "to_type": "cloudtrail.store",
     "source_field": "EventDataStoreArn", "target_uid_pattern": "{EventDataStoreArn}"},

    # CLOUDWATCH
    {"from_type": "cloudwatch.dashboard", "relation_type": "uses", "to_type": "cloudwatch.entry",
     "source_field": "DashboardName", "target_uid_pattern": "arn:aws:cloudwatch:{region}:{account_id}:entry/{DashboardName}"},
    {"from_type": "cloudwatch.dashboard", "relation_type": "uses", "to_type": "cloudwatch.firehose",
     "source_field": "DashboardName", "target_uid_pattern": "arn:aws:cloudwatch:{region}:{account_id}:firehose/{DashboardName}"},

    # DMS
    {"from_type": "dms.endpoint", "relation_type": "uses", "to_type": "dms.instance",
     "source_field": "ReplicationInstanceArn", "target_uid_pattern": "{ReplicationInstanceArn}"},
    {"from_type": "dms.migration", "relation_type": "uses", "to_type": "dms.endpoint",
     "source_field": "SourceEndpointArn", "target_uid_pattern": "{SourceEndpointArn}"},
    {"from_type": "dms.migration", "relation_type": "uses", "to_type": "dms.endpoint",
     "source_field": "TargetEndpointArn", "target_uid_pattern": "{TargetEndpointArn}"},
    {"from_type": "dms.task", "relation_type": "uses", "to_type": "dms.migration",
     "source_field": "MigrationTaskArn", "target_uid_pattern": "{MigrationTaskArn}"},
    {"from_type": "dms.task", "relation_type": "monitored_by", "to_type": "logs.group",
     "source_field": "CloudWatchLogGroupArn", "target_uid_pattern": "{CloudWatchLogGroupArn}"},

    # DOCDB
    {"from_type": "docdb.cluster", "relation_type": "connected_to", "to_type": "docdb.group",
     "source_field": "DBClusterParameterGroup", "target_uid_pattern": "arn:aws:rds:{region}:{account_id}:cluster-pg:{DBClusterParameterGroup}"},
    {"from_type": "docdb.instance", "relation_type": "connected_to", "to_type": "docdb.group",
     "source_field": "DBParameterGroup", "target_uid_pattern": "arn:aws:rds:{region}:{account_id}:pg:{DBParameterGroup}"},

    # EC2
    {"from_type": "ec2.address-association", "relation_type": "attached_to", "to_type": "ec2.subnet",
     "source_field": "SubnetId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:subnet/{SubnetId}"},
    {"from_type": "ec2.associated-rol-certificate-s3-bucket", "relation_type": "uses", "to_type": "s3.bucket",
     "source_field": "CertificateS3BucketName", "target_uid_pattern": "arn:aws:s3:::{CertificateS3BucketName}"},
    {"from_type": "ec2.capacity-reservation-placement-group", "relation_type": "attached_to", "to_type": "ec2.placement-group",
     "source_field": "PlacementGroupArn", "target_uid_pattern": "{PlacementGroupArn}"},
    {"from_type": "ec2.client-vpn-endpoint-server-certificate", "relation_type": "uses", "to_type": "acm.certificate",
     "source_field": "ServerCertificateArn", "target_uid_pattern": "{ServerCertificateArn}"},
    {"from_type": "ec2.client-vpn-target-network-target-network", "relation_type": "contained_by", "to_type": "ec2.subnet",
     "source_field": "TargetNetworkId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:subnet/{TargetNetworkId}"},
    {"from_type": "ec2.flow-log-group", "relation_type": "logging_enabled_to", "to_type": "logs.group",
     "source_field": "LogGroupName", "target_uid_pattern": "arn:aws:logs:{region}:{account_id}:log-group:{LogGroupName}"},
    {"from_type": "ec2.import-image-task-kms-key", "relation_type": "encrypted_by", "to_type": "kms.key",
     "source_field": "KmsKeyId", "target_uid_pattern": "arn:aws:kms:{region}:{account_id}:key/{KmsKeyId}"},
    {"from_type": "ec2.instance-connect-endpoint-instance-connect-endpoint", "relation_type": "attached_to", "to_type": "ec2.instance-connect-endpoint",
     "source_field": "InstanceConnectEndpointId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:instance-connect-endpoint/{InstanceConnectEndpointId}"},
    {"from_type": "ec2.ipam-external-resource-verification-token-ipam-external-resource-verification-token", "relation_type": "attached_to", "to_type": "ec2.ipam-external-resource-verification-token",
     "source_field": "IpamExternalResourceVerificationTokenId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:ipam-external-resource-verification-token/{IpamExternalResourceVerificationTokenId}"},
    {"from_type": "ec2.key-pair-key", "relation_type": "attached_to", "to_type": "ec2.key",
     "source_field": "KeyName", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:key/{KeyName}"},
    {"from_type": "ec2.launch-template-version-launch-template", "relation_type": "attached_to", "to_type": "ec2.launch-template",
     "source_field": "LaunchTemplateId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:launch-template/{LaunchTemplateId}"},
    {"from_type": "ec2.mac-modification-task-mac-modification-task", "relation_type": "attached_to", "to_type": "ec2.mac-modification-task",
     "source_field": "MacModificationTaskId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:mac-modification-task/{MacModificationTaskId}"},
    {"from_type": "ec2.snapshot-data-encryption-key", "relation_type": "encrypted_by", "to_type": "kms.key",
     "source_field": "DataEncryptionKeyId", "target_uid_pattern": "arn:aws:kms:{region}:{account_id}:key/{DataEncryptionKeyId}"},
    {"from_type": "ec2.transit-gateway-multicast-domain-transit-gateway-multicast-domain", "relation_type": "attached_to", "to_type": "ec2.transit-gateway-multicast-domain",
     "source_field": "TransitGatewayMulticastDomainId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:transit-gateway-multicast-domain/{TransitGatewayMulticastDomainId}"},
    {"from_type": "ec2.transit-gateway-route-table-announcement-peer-transit-gateway", "relation_type": "attached_to", "to_type": "ec2.transit-gateway",
     "source_field": "PeerTransitGatewayId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:transit-gateway/{PeerTransitGatewayId}"},
    {"from_type": "ec2.verified-access-endpoint-verified-access-group", "relation_type": "attached_to", "to_type": "ec2.verified-access-group",
     "source_field": "VerifiedAccessGroupId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:verified-access-group/{VerifiedAccessGroupId}"},

    # ECR
    {"from_type": "ecr.repository", "relation_type": "encrypted_by", "to_type": "ecr.profile",
     "source_field": "encryptionConfiguration", "target_uid_pattern": "arn:aws:ecr:{region}:{account_id}:profile/{encryptionConfiguration}"},

    # ECS
    {"from_type": "ecs.task", "relation_type": "uses", "to_type": "ecs.role",
     "source_field": "ExecutionRoleArn", "target_uid_pattern": "{ExecutionRoleArn}"},

    # ELASTICACHE
    {"from_type": "elasticache.cluster", "relation_type": "contained_by", "to_type": "elasticache.outpost",
     "source_field": "OutpostArn", "target_uid_pattern": "{OutpostArn}"},
    {"from_type": "elasticache.group", "relation_type": "contained_by", "to_type": "elasticache.outpost",
     "source_field": "OutpostArn", "target_uid_pattern": "{OutpostArn}"},
    {"from_type": "elasticache.cluster", "relation_type": "replicates_to", "to_type": "elasticache.group",
     "source_field": "ReplicationGroupId", "target_uid_pattern": "arn:aws:elasticache:{region}:{account_id}:replicationgroup/{ReplicationGroupId}"},
    {"from_type": "elasticache.group", "relation_type": "replicates_to", "to_type": "elasticache.cluster",
     "source_field": "PrimaryClusterId", "target_uid_pattern": "arn:aws:elasticache:{region}:{account_id}:cluster/{PrimaryClusterId}"},

    # EMR
    {"from_type": "emr.cluster", "relation_type": "controlled_by", "to_type": "emr.policy",
     "source_field": "BlockPublicAccessConfiguration", "target_uid_pattern": "arn:aws:emr:{region}:{account_id}:policy/{BlockPublicAccessConfiguration}"},
    {"from_type": "emr.studio", "relation_type": "uses", "to_type": "emr.role",
     "source_field": "UserRole", "target_uid_pattern": "{UserRole}"},
    {"from_type": "emr.studio", "relation_type": "uses", "to_type": "emr.role",
     "source_field": "ServiceRole", "target_uid_pattern": "{ServiceRole}"},


    # ---------------------------------------------------------------------
    # Generated relationships (from OpenAI agent)
    # ---------------------------------------------------------------------

    # APIGATEWAY
    {"from_type": "apigateway.association", "relation_type": "connected_to", "to_type": "apigateway.targets",
     "source_field": "TargetId", "target_uid_pattern": "arn:aws:apigateway:{region}:{account_id}:target/{TargetId}"},
    {"from_type": "apigateway.destination", "relation_type": "routes_to", "to_type": "apigateway.targets",
     "source_field": "TargetId", "target_uid_pattern": "arn:aws:apigateway:{region}:{account_id}:target/{TargetId}"},
    {"from_type": "apigateway.domain", "relation_type": "connected_to", "to_type": "apigateway.targets",
     "source_field": "TargetId", "target_uid_pattern": "arn:aws:apigateway:{region}:{account_id}:target/{TargetId}"},
    {"from_type": "apigateway.targets", "relation_type": "invokes", "to_type": "apigateway.destination",
     "source_field": "DestinationId", "target_uid_pattern": "arn:aws:apigateway:{region}:{account_id}:destination/{DestinationId}"},

    # CLOUDTRAIL
    {"from_type": "cloudtrail.trail", "relation_type": "uses", "to_type": "logs.group",
     "source_field": "CloudWatchLogsLogGroupArn", "target_uid_pattern": "{CloudWatchLogsLogGroupArn}"},
    {"from_type": "cloudtrail.channel", "relation_type": "uses", "to_type": "cloudtrail.trail",
     "source_field": "TrailArn", "target_uid_pattern": "{TrailArn}"},
    {"from_type": "cloudtrail.trail", "relation_type": "logging_enabled_to", "to_type": "cloudtrail.store",
     "source_field": "EventDataStoreArn", "target_uid_pattern": "{EventDataStoreArn}"},

    # DATASYNC
    {"from_type": "datasync.agent", "relation_type": "connected_to", "to_type": "datasync.subnet",
     "source_field": "SubnetArns", "target_uid_pattern": "{SubnetArns}",
     "source_field_item": "SubnetArn"},
    {"from_type": "datasync.execution", "relation_type": "triggers", "to_type": "datasync.task",
     "source_field": "TaskArn", "target_uid_pattern": "{TaskArn}"},

    # DMS
    {"from_type": "dms.certificate", "relation_type": "attached_to", "to_type": "dms.endpoint",
     "source_field": "CertificateArn", "target_uid_pattern": "{CertificateArn}"},

    # EC2
    {"from_type": "ec2.address-transfer-allocation", "relation_type": "attached_to", "to_type": "ec2.address-instance",
     "source_field": "AllocationId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:allocation/{AllocationId}"},
    {"from_type": "ec2.capacity-reservation-outpost", "relation_type": "contained_by", "to_type": "ec2.outpost-lag",
     "source_field": "OutpostArn", "target_uid_pattern": "{OutpostArn}"},
    {"from_type": "ec2.capacity-reservation-placement-group", "relation_type": "contained_by", "to_type": "ec2.placement-group",
     "source_field": "PlacementGroupArn", "target_uid_pattern": "{PlacementGroupArn}"},
    {"from_type": "ec2.coip-address-usag-aws-account", "relation_type": "controlled_by", "to_type": "ec2.account-attribut-attribute",
     "source_field": "AwsAccountId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:account/{AwsAccountId}"},
    {"from_type": "ec2.coip-pool-local-gateway-route-table", "relation_type": "contained_by", "to_type": "ec2.local-gateway-route-table-vpc-association-local-gateway-route-table",
     "source_field": "LocalGatewayRouteTableId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:local-gateway-route-table/{LocalGatewayRouteTableId}"},
    {"from_type": "ec2.customer-gateway-customer-gateway", "relation_type": "connected_to", "to_type": "ec2.vpn-connection-vpn-gateway",
     "source_field": "CustomerGatewayId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:customer-gateway/{CustomerGatewayId}"},
    {"from_type": "ec2.host-reservation-set-host-reservation", "relation_type": "contained_by", "to_type": "ec2.host",
     "source_field": "HostReservationId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:host-reservation/{HostReservationId}"},
    {"from_type": "ec2.imag-source-image", "relation_type": "replicates_to", "to_type": "ec2.image-usage-report-entry-account",
     "source_field": "ImageId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:image/{ImageId}"},
    {"from_type": "ec2.import-image-task-import-task", "relation_type": "uses", "to_type": "ec2.imag-source-image",
     "source_field": "ImportTaskId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:import-task/{ImportTaskId}"},
    {"from_type": "ec2.ipam-discovered-public-address-owner", "relation_type": "controlled_by", "to_type": "ec2.account-attribut-attribute",
     "source_field": "OwnerId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:account/{OwnerId}"},
    {"from_type": "ec2.ipam-discovered-public-address-public-ipv4-pool", "relation_type": "contained_by", "to_type": "ec2.coip-pool",
     "source_field": "PublicIpv4Pool", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:ipv4-pool/{PublicIpv4Pool}"},
    {"from_type": "ec2.ipam-external-resource-verification-token-ipam-external-resource-verification-token", "relation_type": "uses", "to_type": "ec2.ipam",
     "source_field": "IpamArn", "target_uid_pattern": "{IpamArn}"},
    {"from_type": "ec2.ipam-pool-ipam-scope", "relation_type": "contained_by", "to_type": "ec2.ipam-scop-ipam-scope",
     "source_field": "IpamScopeArn", "target_uid_pattern": "{IpamScopeArn}"},
    {"from_type": "ec2.ipam-prefix-list-resolver-ipam-prefix-list-resolver", "relation_type": "uses", "to_type": "ec2.ipam",
     "source_field": "IpamArn", "target_uid_pattern": "{IpamArn}"},
    {"from_type": "ec2.ipam-resource-discovery-association-ipam-resource-discovery-association", "relation_type": "uses", "to_type": "ec2.ipam",
     "source_field": "IpamArn", "target_uid_pattern": "{IpamArn}"},
    {"from_type": "ec2.launch-template-version-launch-template", "relation_type": "uses", "to_type": "ec2.launch-template",
     "source_field": "LaunchTemplateId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:launch-template/{LaunchTemplateId}"},
    {"from_type": "ec2.local-gateway-route-table-vpc-association-local-gateway-route-table", "relation_type": "contained_by", "to_type": "ec2.local-gateway-virtual-interfac-local-gateway-virtual-interface",
     "source_field": "LocalGatewayRouteTableId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:local-gateway-route-table/{LocalGatewayRouteTableId}"},
    {"from_type": "ec2.mac-modification-task-mac-modification-task", "relation_type": "uses", "to_type": "ec2.mac-host",
     "source_field": "MacModificationTaskId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:mac-modification-task/{MacModificationTaskId}"},
    {"from_type": "ec2.nat-gateway-nat-gateway", "relation_type": "connected_to", "to_type": "ec2.subnet",
     "source_field": "SubnetId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:subnet/{SubnetId}"},
    {"from_type": "ec2.reserved-instance-value-set-reserved-instance", "relation_type": "uses", "to_type": "ec2.reserved-instanc-reserved-instances",
     "source_field": "ReservedInstancesId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:reserved-instances/{ReservedInstancesId}"},
    {"from_type": "ec2.route-server-endpoint-route-server", "relation_type": "connected_to", "to_type": "ec2.route-server-peer-route-server-peer",
     "source_field": "RouteServerId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:route-server/{RouteServerId}"},
    {"from_type": "ec2.subnet-ipv4-cidr-reservation-subnet-cidr-reservation", "relation_type": "contained_by", "to_type": "ec2.subnet",
     "source_field": "SubnetId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:subnet/{SubnetId}"},
    {"from_type": "ec2.traffic-mirror-session-traffic-mirror-session", "relation_type": "uses", "to_type": "ec2.traffic-mirror-filter",
     "source_field": "TrafficMirrorFilterId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:traffic-mirror-filter/{TrafficMirrorFilterId}"},
    {"from_type": "ec2.transit-gateway-attachment-transit-gateway", "relation_type": "connected_to", "to_type": "ec2.transit-gateway",
     "source_field": "TransitGatewayId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:transit-gateway/{TransitGatewayId}"},
    {"from_type": "ec2.verified-access-endpoint-verified-access-endpoint", "relation_type": "connected_to", "to_type": "ec2.verified-access-group",
     "source_field": "VerifiedAccessGroupId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:verified-access-group/{VerifiedAccessGroupId}"},

    # ECS
    {"from_type": "ecs.task", "relation_type": "uses", "to_type": "ecs.role",
     "source_field": "executionRoleArn", "target_uid_pattern": "{executionRoleArn}"},
    {"from_type": "ecs.deployment", "relation_type": "contained_by", "to_type": "ecs.service",
     "source_field": "serviceArn", "target_uid_pattern": "{serviceArn}"},
    {"from_type": "ecs.set", "relation_type": "contained_by", "to_type": "ecs.service",
     "source_field": "serviceArn", "target_uid_pattern": "{serviceArn}"},
    {"from_type": "ecs.revision", "relation_type": "contained_by", "to_type": "ecs.definition",
     "source_field": "taskDefinitionArn", "target_uid_pattern": "{taskDefinitionArn}"},

    # EFS
    {"from_type": "efs.system", "relation_type": "attached_to", "to_type": "ec2.security-group",
     "source_field": "SecurityGroups", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:security-group/{source_field_item}",
     "source_field_item": "GroupId"},
    {"from_type": "efs.system", "relation_type": "connected_to", "to_type": "ec2.subnet",
     "source_field": "SubnetId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:subnet/{SubnetId}"},
    {"from_type": "efs.system", "relation_type": "encrypted_by", "to_type": "kms.key",
     "source_field": "KmsKeyId", "target_uid_pattern": "arn:aws:kms:{region}:{account_id}:key/{KmsKeyId}"},
    {"from_type": "efs.point", "relation_type": "attached_to", "to_type": "efs.system",
     "source_field": "FileSystemId", "target_uid_pattern": "arn:aws:elasticfilesystem:{region}:{account_id}:file-system/{FileSystemId}"},

    # ELASTICACHE
    {"from_type": "elasticache.cluster", "relation_type": "contained_by", "to_type": "elasticache.outposts",
     "source_field": "CacheClusterId", "target_uid_pattern": "arn:aws:elasticache:{region}:{account_id}:outposts/{CacheClusterId}"},

    # EMR
    {"from_type": "emr.studio", "relation_type": "uses", "to_type": "iam.policy",
     "source_field": "StudioPolicy", "target_uid_pattern": "arn:aws:iam::{account_id}:policy/{StudioPolicy}"},

    # EVENTBRIDGE
    {"from_type": "eventbridge.event", "relation_type": "uses", "to_type": "eventbridge.filters",
     "source_field": "DetailType", "target_uid_pattern": "arn:aws:events:{region}:{account_id}:filter/{DetailType}"},
    {"from_type": "eventbridge.source", "relation_type": "connected_to", "to_type": "eventbridge.event",
     "source_field": "Source", "target_uid_pattern": "arn:aws:events:{region}:{account_id}:event/{Source}"},


    # ---------------------------------------------------------------------
    # Generated relationships (from OpenAI agent)
    # ---------------------------------------------------------------------

    # DIRECTCONNECT
    {"from_type": "directconnect.resource", "relation_type": "connected_to", "to_type": "ec2.security-group-for-vpc-primary-vpc",
     "source_field": "VpcId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:vpc/{VpcId}"},
    {"from_type": "directconnect.resource", "relation_type": "connected_to", "to_type": "ec2.imag-source-instance",
     "source_field": "InstanceId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:instance/{InstanceId}"},

    # EC2
    {"from_type": "ec2.address-instance", "relation_type": "attached_to", "to_type": "ec2.imag-source-instance",
     "source_field": "InstanceId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:instance/{InstanceId}"},
    {"from_type": "ec2.address-network-interface-owner", "relation_type": "attached_to", "to_type": "ec2.network-interface-permission-network-interface-permission",
     "source_field": "NetworkInterfaceId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:network-interface/{NetworkInterfaceId}"},
    {"from_type": "ec2.carrier-gateway-vpc", "relation_type": "contained_by", "to_type": "ec2.security-group-for-vpc-primary-vpc",
     "source_field": "VpcId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:vpc/{VpcId}"},
    {"from_type": "ec2.dhcp-option-dhcp-options", "relation_type": "attached_to", "to_type": "ec2.security-group-for-vpc-primary-vpc",
     "source_field": "DhcpOptionsId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:dhcp-options/{DhcpOptionsId}"},
    {"from_type": "ec2.elastic-gpu-set-elastic-gpu", "relation_type": "attached_to", "to_type": "ec2.imag-source-instance",
     "source_field": "InstanceId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:instance/{InstanceId}"},
    {"from_type": "ec2.imag-source-instance", "relation_type": "replicates_to", "to_type": "ec2.imag-source-instance",
     "source_field": "InstanceId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:instance/{InstanceId}"},
    {"from_type": "ec2.instance-connect-endpoint-instance-connect-endpoint", "relation_type": "connected_to", "to_type": "ec2.network-interface-permission-network-interface-permission",
     "source_field": "NetworkInterfaceIds", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:network-interface/{NetworkInterfaceIds}",
     "source_field_item": "NetworkInterfaceId"},
    {"from_type": "ec2.internet-gateway-internet-gateway", "relation_type": "attached_to", "to_type": "ec2.security-group-for-vpc-primary-vpc",
     "source_field": "VpcId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:vpc/{VpcId}"},
    {"from_type": "ec2.key-pair-key", "relation_type": "uses", "to_type": "ec2.imag-source-instance",
     "source_field": "KeyName", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:key-pair/{KeyName}"},
    {"from_type": "ec2.network-interface-permission-network-interface-permission", "relation_type": "uses", "to_type": "ec2.network-interface-permission-network-interface-permission",
     "source_field": "NetworkInterfaceId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:network-interface/{NetworkInterfaceId}"},
    {"from_type": "ec2.spot-instance-request-spot-instance-request", "relation_type": "uses", "to_type": "ec2.imag-source-instance",
     "source_field": "InstanceId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:instance/{InstanceId}"},
    {"from_type": "ec2.vpc-endpoint-association-vpc-endpoint", "relation_type": "connected_to", "to_type": "ec2.security-group-for-vpc-primary-vpc",
     "source_field": "VpcId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:vpc/{VpcId}"},
    {"from_type": "ec2.vpn-connection-vpn-connection", "relation_type": "connected_to", "to_type": "ec2.vpn-connection-vpn-gateway",
     "source_field": "VpnGatewayId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:vpn-gateway/{VpnGatewayId}"},


    # ---------------------------------------------------------------------
    # Generated relationships (from OpenAI agent)
    # ---------------------------------------------------------------------

    # APIGATEWAY
    {"from_type": "apigateway.domain", "relation_type": "connected_to", "to_type": "apigateway.targets",
     "source_field": "RestApiId", "target_uid_pattern": "arn:aws:apigateway:{region}::/restapis/{RestApiId}"},
    {"from_type": "apigateway.targets", "relation_type": "invokes", "to_type": "apigateway.destination",
     "source_field": "IntegrationUri", "target_uid_pattern": "{IntegrationUri}"},

    # BACKUP
    {"from_type": "backup.configuration", "relation_type": "uses", "to_type": "backup.plan",
     "source_field": "BackupPlanId", "target_uid_pattern": "arn:aws:backup:{region}:{account_id}:backup-plan/{BackupPlanId}"},

    # BEDROCK
    {"from_type": "bedrock.model", "relation_type": "controlled_by", "to_type": "bedrock.policy",
     "source_field": "PolicyId", "target_uid_pattern": "arn:aws:bedrock:{region}:{account_id}:policy/{PolicyId}"},
    {"from_type": "bedrock.profile", "relation_type": "uses", "to_type": "bedrock.role",
     "source_field": "RoleId", "target_uid_pattern": "arn:aws:bedrock:{region}:{account_id}:role/{RoleId}"},

    # CLOUDTRAIL
    {"from_type": "cloudtrail.trail", "relation_type": "uses", "to_type": "cloudtrail.channel",
     "source_field": "ChannelArn", "target_uid_pattern": "{ChannelArn}"},

    # DIRECTCONNECT
    {"from_type": "directconnect.resource", "relation_type": "connected_to", "to_type": "ec2.security-group",
     "source_field": "SecurityGroupId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:security-group/{SecurityGroupId}"},

    # DOCDB
    {"from_type": "docdb.cluster", "relation_type": "connected_to", "to_type": "docdb.group",
     "source_field": "DBSubnetGroup", "target_uid_pattern": "arn:aws:rds:{region}:{account_id}:subnet-group:{DBSubnetGroup}"},
    {"from_type": "docdb.subscription", "relation_type": "triggers", "to_type": "sns.topic",
     "source_field": "SourceIds", "target_uid_pattern": "arn:aws:sns:{region}:{account_id}:{SourceIds}",
     "source_field_item": "SourceId"},

    # DRS
    {"from_type": "drs.server", "relation_type": "uses", "to_type": "drs.key",
     "source_field": "ServerKeyId", "target_uid_pattern": "arn:aws:drs:{region}:{account_id}:key/{ServerKeyId}"},

    # ECR
    {"from_type": "ecr.repository", "relation_type": "encrypted_by", "to_type": "ecr.credential",
     "source_field": "encryptionConfiguration", "target_uid_pattern": "arn:aws:ecr:{region}:{account_id}:credential/{encryptionConfiguration}"},
    {"from_type": "ecr.repository", "relation_type": "has_policy", "to_type": "ecr.profile",
     "source_field": "repositoryArn", "target_uid_pattern": "arn:aws:ecr:{region}:{account_id}:profile/{repositoryArn}"},

    # ECS
    {"from_type": "ecs.revision", "relation_type": "contained_by", "to_type": "ecs.definition",
     "source_field": "TaskDefinitionArn", "target_uid_pattern": "{TaskDefinitionArn}"},

    # EFS
    {"from_type": "efs.system", "relation_type": "backs_up_to", "to_type": "efs.point",
     "source_field": "BackupPolicy", "target_uid_pattern": "arn:aws:elasticfilesystem:{region}:{account_id}:access-point/{source_field_item}",
     "source_field_item": "AccessPointId"},
    {"from_type": "efs.point", "relation_type": "connected_to", "to_type": "efs.system",
     "source_field": "FileSystemId", "target_uid_pattern": "arn:aws:elasticfilesystem:{region}:{account_id}:file-system/{FileSystemId}"},


    # ---------------------------------------------------------------------
    # Generated relationships (from OpenAI agent)
    # ---------------------------------------------------------------------

    # BACKUP
    {"from_type": "backup.plan", "relation_type": "uses", "to_type": "backup.vault",
     "source_field": "BackupVaultName", "target_uid_pattern": "arn:aws:backup:{region}:{account_id}:backup-vault/{BackupVaultName}"},
    {"from_type": "backup.point", "relation_type": "backs_up_to", "to_type": "backup.vault",
     "source_field": "BackupVaultName", "target_uid_pattern": "arn:aws:backup:{region}:{account_id}:backup-vault/{BackupVaultName}"},
    {"from_type": "backup.plan", "relation_type": "uses", "to_type": "backup.resource",
     "source_field": "ResourceArn", "target_uid_pattern": "{ResourceArn}"},

    # BATCH
    {"from_type": "batch.queue", "relation_type": "contained_by", "to_type": "batch.environment",
     "source_field": "computeEnvironmentOrder", "target_uid_pattern": "arn:aws:batch:{region}:{account_id}:compute-environment/{computeEnvironmentOrder}",
     "source_field_item": "computeEnvironment"},
    {"from_type": "batch.definition", "relation_type": "uses", "to_type": "iam.role",
     "source_field": "containerProperties", "target_uid_pattern": "arn:aws:iam::{account_id}:role/{containerProperties}",
     "source_field_item": "executionRoleArn"},
    {"from_type": "batch.policy", "relation_type": "grants_access_to", "to_type": "batch.resource",
     "source_field": "resourceArn", "target_uid_pattern": "{resourceArn}"},

    # BEDROCK
    {"from_type": "bedrock.guardrail", "relation_type": "attached_to", "to_type": "bedrock.policy",
     "source_field": "PolicyId", "target_uid_pattern": "arn:aws:bedrock:{region}:{account_id}:policy/{PolicyId}"},
    {"from_type": "bedrock.model", "relation_type": "controlled_by", "to_type": "iam.role",
     "source_field": "RoleId", "target_uid_pattern": "arn:aws:iam::{account_id}:role/{RoleId}"},
    {"from_type": "bedrock.policy", "relation_type": "grants_access_to", "to_type": "bedrock.endpoint",
     "source_field": "EndpointId", "target_uid_pattern": "arn:aws:bedrock:{region}:{account_id}:endpoint/{EndpointId}"},
    {"from_type": "bedrock.profile", "relation_type": "controlled_by", "to_type": "iam.role",
     "source_field": "RoleId", "target_uid_pattern": "arn:aws:iam::{account_id}:role/{RoleId}"},
    {"from_type": "bedrock.role", "relation_type": "assumes", "to_type": "iam.role",
     "source_field": "AssumedRoleId", "target_uid_pattern": "arn:aws:iam::{account_id}:role/{AssumedRoleId}"},

    # CLOUDWATCH
    {"from_type": "cloudwatch.alarm", "relation_type": "monitored_by", "to_type": "cloudwatch.entry",
     "source_field": "AlarmName", "target_uid_pattern": "arn:aws:cloudwatch:{region}:{account_id}:entry/{AlarmName}"},
    {"from_type": "cloudwatch.alarm", "relation_type": "monitored_by", "to_type": "cloudwatch.firehose",
     "source_field": "AlarmName", "target_uid_pattern": "arn:aws:cloudwatch:{region}:{account_id}:firehose/{AlarmName}"},

    # DATASYNC
    {"from_type": "datasync.agent", "relation_type": "contained_by", "to_type": "datasync.subnet",
     "source_field": "SubnetId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:subnet/{SubnetId}"},
    {"from_type": "datasync.agent", "relation_type": "connected_to", "to_type": "datasync.subnet",
     "source_field": "SubnetId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:subnet/{SubnetId}"},


    # ---------------------------------------------------------------------
    # Generated relationships (from OpenAI agent)
    # ---------------------------------------------------------------------

    # FSX
    {"from_type": "fsx.resource", "relation_type": "replicates_to", "to_type": "fsx.resource",
     "source_field": "SnapshotId", "target_uid_pattern": "arn:aws:fsx:{region}:{account_id}:snapshot/{SnapshotId}"},

    # GLACIER
    {"from_type": "glacier.vault", "relation_type": "controlled_by", "to_type": "iam.role",
     "source_field": "VaultAccessPolicy", "target_uid_pattern": "arn:aws:iam::{account_id}:role/{VaultAccessPolicy}"},
    {"from_type": "glacier.vault", "relation_type": "grants_access_to", "to_type": "iam.policy",
     "source_field": "VaultAccessPolicy", "target_uid_pattern": "arn:aws:iam::{account_id}:policy/{VaultAccessPolicy}"},
    {"from_type": "glacier.vault", "relation_type": "encrypted_by", "to_type": "kms.key",
     "source_field": "VaultLock", "target_uid_pattern": "arn:aws:kms:{region}:{account_id}:key/{VaultLock}"},

    # GLUE
    {"from_type": "glue.property", "relation_type": "controlled_by", "to_type": "glue.role",
     "source_field": "RoleArn", "target_uid_pattern": "{RoleArn}"},
    {"from_type": "glue.resource", "relation_type": "uses", "to_type": "glue.role",
     "source_field": "RoleArn", "target_uid_pattern": "{RoleArn}"},

    # GUARDDUTY
    {"from_type": "guardduty.finding", "relation_type": "uses", "to_type": "kms.key",
     "source_field": "EncryptionKeyId", "target_uid_pattern": "arn:aws:kms:{region}:{account_id}:key/{EncryptionKeyId}"},

    # IAM
    {"from_type": "iam.user", "relation_type": "has_policy", "to_type": "iam.attached-policy",
     "source_field": "UserName", "target_uid_pattern": "arn:aws:iam::{account_id}:policy/{PolicyName}",
     "source_field_item": "PolicyName"},
    {"from_type": "iam.role", "relation_type": "has_policy", "to_type": "iam.attached-policy",
     "source_field": "RoleName", "target_uid_pattern": "arn:aws:iam::{account_id}:policy/{PolicyName}",
     "source_field_item": "PolicyName"},
    {"from_type": "iam.group", "relation_type": "has_policy", "to_type": "iam.attached-policy",
     "source_field": "GroupName", "target_uid_pattern": "arn:aws:iam::{account_id}:policy/{PolicyName}",
     "source_field_item": "PolicyName"},
    {"from_type": "iam.user", "relation_type": "member_of", "to_type": "iam.group",
     "source_field": "UserName", "target_uid_pattern": "arn:aws:iam::{account_id}:group/{GroupName}",
     "source_field_item": "GroupName"},
    {"from_type": "iam.role", "relation_type": "assumes", "to_type": "iam.policy",
     "source_field": "RoleName", "target_uid_pattern": "arn:aws:iam::{account_id}:policy/{PolicyName}",
     "source_field_item": "PolicyName"},
    {"from_type": "iam.instance-profile", "relation_type": "attached_to", "to_type": "iam.role",
     "source_field": "InstanceProfileName", "target_uid_pattern": "arn:aws:iam::{account_id}:role/{RoleName}",
     "source_field_item": "RoleName"},
    {"from_type": "iam.access-key-metadata-access-key", "relation_type": "controlled_by", "to_type": "iam.user",
     "source_field": "AccessKeyId", "target_uid_pattern": "arn:aws:iam::{account_id}:user/{UserName}",
     "source_field_item": "UserName"},
    {"from_type": "iam.ssh-public-key-ssh-public-key", "relation_type": "controlled_by", "to_type": "iam.user",
     "source_field": "SSHPublicKeyId", "target_uid_pattern": "arn:aws:iam::{account_id}:user/{UserName}",
     "source_field_item": "UserName"},
    {"from_type": "iam.service-specific-credential-service-specific-credential", "relation_type": "controlled_by", "to_type": "iam.user",
     "source_field": "ServiceSpecificCredentialId", "target_uid_pattern": "arn:aws:iam::{account_id}:user/{UserName}",
     "source_field_item": "UserName"},
    {"from_type": "iam.server-certificate-metadata-list-server-certificate", "relation_type": "controlled_by", "to_type": "iam.user",
     "source_field": "ServerCertificateId", "target_uid_pattern": "arn:aws:iam::{account_id}:user/{UserName}",
     "source_field_item": "UserName"},

    # INSPECTOR
    {"from_type": "inspector.topic", "relation_type": "uses", "to_type": "sns.topic",
     "source_field": "TopicArn", "target_uid_pattern": "{TopicArn}"},

    # KAFKA
    {"from_type": "kafka.cluster", "relation_type": "connected_to", "to_type": "ec2.security-group",
     "source_field": "SecurityGroups", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:security-group/{source_field_item}",
     "source_field_item": "GroupId"},
    {"from_type": "kafka.cluster", "relation_type": "uses", "to_type": "iam.role",
     "source_field": "IamRoleArn", "target_uid_pattern": "{IamRoleArn}"},
    {"from_type": "kafka.configuration", "relation_type": "attached_to", "to_type": "kafka.cluster",
     "source_field": "ClusterArn", "target_uid_pattern": "{ClusterArn}"},

    # KMS
    {"from_type": "kms.key", "relation_type": "controlled_by", "to_type": "iam.role",
     "source_field": "KeyPolicy", "target_uid_pattern": "arn:aws:iam::{account_id}:role/{RoleName}",
     "source_field_item": "RoleName"},
    {"from_type": "kms.key", "relation_type": "has_policy", "to_type": "iam.policy",
     "source_field": "KeyPolicy", "target_uid_pattern": "arn:aws:iam::{account_id}:policy/{PolicyName}",
     "source_field_item": "PolicyName"},

    # LAMBDA
    {"from_type": "lambda.function", "relation_type": "invokes", "to_type": "lambda.function",
     "source_field": "FunctionArn", "target_uid_pattern": "{FunctionArn}"},
    {"from_type": "lambda.function", "relation_type": "triggers", "to_type": "lambda.mapping",
     "source_field": "UUID", "target_uid_pattern": "arn:aws:lambda:{region}:{account_id}:event-source-mapping/{UUID}"},
    {"from_type": "lambda.function", "relation_type": "uses", "to_type": "lambda.layer",
     "source_field": "Layers", "target_uid_pattern": "arn:aws:lambda:{region}:{account_id}:layer/{LayerName}",
     "source_field_item": "LayerName"},
    {"from_type": "lambda.function", "relation_type": "uses", "to_type": "kms.key",
     "source_field": "KMSKeyArn", "target_uid_pattern": "{KMSKeyArn}"},
    {"from_type": "lambda.version", "relation_type": "contained_by", "to_type": "lambda.function",
     "source_field": "FunctionArn", "target_uid_pattern": "{FunctionArn}"},
    {"from_type": "lambda.alias", "relation_type": "contained_by", "to_type": "lambda.function",
     "source_field": "FunctionVersion", "target_uid_pattern": "{FunctionVersion}"},
    {"from_type": "lambda.layer", "relation_type": "contained_by", "to_type": "lambda.master",
     "source_field": "LayerArn", "target_uid_pattern": "{LayerArn}"},

    # LIGHTSAIL
    {"from_type": "lightsail.instance", "relation_type": "uses", "to_type": "lightsail.static",
     "source_field": "StaticIpName", "target_uid_pattern": "arn:aws:lightsail:{region}:{account_id}:static/{StaticIpName}"},
    {"from_type": "lightsail.databas", "relation_type": "backs_up_to", "to_type": "lightsail.snapshot",
     "source_field": "SnapshotName", "target_uid_pattern": "arn:aws:lightsail:{region}:{account_id}:snapshot/{SnapshotName}"},

    # NEPTUNE
    {"from_type": "neptune.endpoint", "relation_type": "connected_to", "to_type": "neptune.cluster",
     "source_field": "DBClusterEndpointIdentifier", "target_uid_pattern": "arn:aws:rds:{region}:{account_id}:cluster-endpoint:{DBClusterEndpointIdentifier}"},
    {"from_type": "neptune.cluster", "relation_type": "uses", "to_type": "neptune.credential",
     "source_field": "MasterUsername", "target_uid_pattern": "arn:aws:secretsmanager:{region}:{account_id}:secret:{MasterUsername}"},
    {"from_type": "neptune.cluster", "relation_type": "encrypted_by", "to_type": "kms.key",
     "source_field": "KmsKeyId", "target_uid_pattern": "arn:aws:kms:{region}:{account_id}:key/{KmsKeyId}"},

    # NETWORKFIREWALL
    {"from_type": "networkfirewall.policy", "relation_type": "uses", "to_type": "networkfirewall.group",
     "source_field": "RuleGroupArns", "target_uid_pattern": "{RuleGroupArns}",
     "source_field_item": "RuleGroupArn"},

    # ORGANIZATIONS
    {"from_type": "organizations.account", "relation_type": "contained_by", "to_type": "organizations.organization",
     "source_field": "OrganizationId", "target_uid_pattern": "arn:aws:organizations::{account_id}:organization/{OrganizationId}"},
    {"from_type": "organizations.organization", "relation_type": "has_policy", "to_type": "organizations.account",
     "source_field": "AccountId", "target_uid_pattern": "arn:aws:organizations::{account_id}:account/{AccountId}"},

    # REDSHIFT
    {"from_type": "redshift.clusterspace", "relation_type": "uses", "to_type": "redshift.instance",
     "source_field": "ClusterIdentifier", "target_uid_pattern": "arn:aws:redshift:{region}:{account_id}:cluster/{ClusterIdentifier}"},
    {"from_type": "redshift.integration", "relation_type": "connected_to", "to_type": "redshift.instance",
     "source_field": "ClusterIdentifier", "target_uid_pattern": "arn:aws:redshift:{region}:{account_id}:cluster/{ClusterIdentifier}"},
    {"from_type": "redshift.role", "relation_type": "assumes", "to_type": "iam.role",
     "source_field": "RoleArn", "target_uid_pattern": "{RoleArn}"},
    {"from_type": "redshift.secret", "relation_type": "encrypted_by", "to_type": "kms.key",
     "source_field": "KmsKeyId", "target_uid_pattern": "arn:aws:kms:{region}:{account_id}:key/{KmsKeyId}"},
    {"from_type": "redshift.share", "relation_type": "grants_access_to", "to_type": "redshift.target",
     "source_field": "TargetAccount", "target_uid_pattern": "arn:aws:redshift:{region}:{TargetAccount}:target/{TargetIdentifier}"},
    {"from_type": "redshift.source", "relation_type": "replicates_to", "to_type": "redshift.target",
     "source_field": "TargetClusterIdentifier", "target_uid_pattern": "arn:aws:redshift:{region}:{account_id}:cluster/{TargetClusterIdentifier}"},
    {"from_type": "redshift.topic", "relation_type": "monitored_by", "to_type": "sns.topic",
     "source_field": "TopicArn", "target_uid_pattern": "{TopicArn}"},

    # ROUTE53
    {"from_type": "route53.collection", "relation_type": "contained_by", "to_type": "route53.group",
     "source_field": "HostedZoneId", "target_uid_pattern": "arn:aws:route53:::hostedzone/{HostedZoneId}"},
    {"from_type": "route53.collection", "relation_type": "routes_to", "to_type": "route53.kms",
     "source_field": "AliasTarget", "target_uid_pattern": "arn:aws:route53:::alias/{AliasTarget}"},

    # S3
    {"from_type": "s3.bucket", "relation_type": "triggers", "to_type": "sns.topic",
     "source_field": "Topic", "target_uid_pattern": "arn:aws:sns:{region}:{account_id}:{Topic}"},
    {"from_type": "s3.bucket", "relation_type": "logging_enabled_to", "to_type": "s3.bucket",
     "source_field": "TargetBucket", "target_uid_pattern": "arn:aws:s3:::{TargetBucket}"},
    {"from_type": "s3.bucket", "relation_type": "grants_access_to", "to_type": "iam.role",
     "source_field": "Role", "target_uid_pattern": "{Role}"},
    {"from_type": "s3.bucket", "relation_type": "replicates_to", "to_type": "s3.bucket",
     "source_field": "Rules", "target_uid_pattern": "arn:aws:s3:::{Rules.Destination.Bucket}",
     "source_field_item": "Destination"},

    # SAGEMAKER
    {"from_type": "sagemaker.experiment", "relation_type": "uses", "to_type": "sagemaker.trial",
     "source_field": "TrialName", "target_uid_pattern": "arn:aws:sagemaker:{region}:{account_id}:trial/{TrialName}"},
    {"from_type": "sagemaker.workteam", "relation_type": "member_of", "to_type": "sagemaker.workforce",
     "source_field": "WorkforceName", "target_uid_pattern": "arn:aws:sagemaker:{region}:{account_id}:workforce/{WorkforceName}"},
    {"from_type": "sagemaker.domain", "relation_type": "uses", "to_type": "sagemaker.image",
     "source_field": "ImageName", "target_uid_pattern": "arn:aws:sagemaker:{region}:{account_id}:image/{ImageName}"},

    # SECRETSMANAGER
    {"from_type": "secretsmanager.secret", "relation_type": "uses", "to_type": "secretsmanager.lambda",
     "source_field": "SecretId", "target_uid_pattern": "arn:aws:lambda:{region}:{account_id}:function/{SecretId}"},
    {"from_type": "secretsmanager.secret", "relation_type": "controlled_by", "to_type": "iam.role",
     "source_field": "SecretId", "target_uid_pattern": "arn:aws:iam::{account_id}:role/{SecretId}"},

    # SECURITYHUB
    {"from_type": "securityhub.insight", "relation_type": "contained_by", "to_type": "securityhub.hub",
     "source_field": "HubArn", "target_uid_pattern": "{HubArn}"},
    {"from_type": "securityhub.control", "relation_type": "contained_by", "to_type": "securityhub.standards",
     "source_field": "StandardsArn", "target_uid_pattern": "{StandardsArn}"},


    # ---------------------------------------------------------------------
    # Generated relationships (from OpenAI agent)
    # ---------------------------------------------------------------------

    # BACKUP
    {"from_type": "backup.session", "relation_type": "uses", "to_type": "backup.resource",
     "source_field": "ResourceArn", "target_uid_pattern": "{ResourceArn}"},

    # BATCH
    {"from_type": "batch.job", "relation_type": "uses", "to_type": "batch.definition",
     "source_field": "jobDefinition", "target_uid_pattern": "arn:aws:batch:{region}:{account_id}:job-definition/{jobDefinition}"},

    # BEDROCK
    {"from_type": "bedrock.policy", "relation_type": "has_policy", "to_type": "iam.policy",
     "source_field": "PolicyArn", "target_uid_pattern": "{PolicyArn}"},

    # CLOUDTRAIL
    {"from_type": "cloudtrail.trail", "relation_type": "controlled_by", "to_type": "cloudtrail.group",
     "source_field": "GroupName", "target_uid_pattern": "arn:aws:iam::{account_id}:group/{GroupName}"},

    # SNS
    {"from_type": "sns.subscription", "relation_type": "attached_to", "to_type": "sns.topic",
     "source_field": "TopicArn", "target_uid_pattern": "{TopicArn}"},
    {"from_type": "sns.endpoint", "relation_type": "attached_to", "to_type": "sns.application",
     "source_field": "Endpoint", "target_uid_pattern": "arn:aws:sns:{region}:{account_id}:endpoint/{Endpoint}"},
    {"from_type": "sns.subscription", "relation_type": "uses", "to_type": "sns.endpoint",
     "source_field": "Endpoint", "target_uid_pattern": "arn:aws:sns:{region}:{account_id}:endpoint/{Endpoint}"},

    # SSM
    {"from_type": "ssm.ops", "relation_type": "uses", "to_type": "ssm.role",
     "source_field": "RoleArn", "target_uid_pattern": "{RoleArn}"},
    {"from_type": "ssm.parameter", "relation_type": "controlled_by", "to_type": "ssm.role",
     "source_field": "LastModifiedUser", "target_uid_pattern": "{LastModifiedUser}"},
    {"from_type": "ssm.task", "relation_type": "uses", "to_type": "ssm.parameter",
     "source_field": "Parameters", "target_uid_pattern": "arn:aws:ssm:{region}:{account_id}:parameter/{Parameters}",
     "source_field_item": "ParameterName"},
    {"from_type": "ssm.task", "relation_type": "uses", "to_type": "ssm.ops",
     "source_field": "OpsItemId", "target_uid_pattern": "arn:aws:ssm:{region}:{account_id}:opsitem/{OpsItemId}"},

    # STEPFUNCTIONS
    {"from_type": "stepfunctions.execution", "relation_type": "invokes", "to_type": "stepfunctions.machine",
     "source_field": "stateMachineArn", "target_uid_pattern": "{stateMachineArn}"},
    {"from_type": "stepfunctions.run", "relation_type": "invokes", "to_type": "stepfunctions.execution",
     "source_field": "executionArn", "target_uid_pattern": "{executionArn}"},
    {"from_type": "stepfunctions.alias", "relation_type": "uses", "to_type": "stepfunctions.version",
     "source_field": "versionArn", "target_uid_pattern": "{versionArn}"},
    {"from_type": "stepfunctions.machine", "relation_type": "uses", "to_type": "stepfunctions.activity",
     "source_field": "activities", "target_uid_pattern": "arn:aws:states:{region}:{account_id}:activity/{activities}",
     "source_field_item": "activityArn"},

    # STORAGEGATEWAY
    {"from_type": "storagegateway.volume", "relation_type": "contained_by", "to_type": "storagegateway.gateway",
     "source_field": "GatewayARN", "target_uid_pattern": "{GatewayARN}"},
    {"from_type": "storagegateway.tape", "relation_type": "contained_by", "to_type": "storagegateway.gateway",
     "source_field": "GatewayARN", "target_uid_pattern": "{GatewayARN}"},
    {"from_type": "storagegateway.share", "relation_type": "contained_by", "to_type": "storagegateway.gateway",
     "source_field": "GatewayARN", "target_uid_pattern": "{GatewayARN}"},
    {"from_type": "storagegateway.association", "relation_type": "connected_to", "to_type": "storagegateway.location",
     "source_field": "LocationARN", "target_uid_pattern": "{LocationARN}"},
    {"from_type": "storagegateway.device", "relation_type": "attached_to", "to_type": "storagegateway.gateway",
     "source_field": "GatewayARN", "target_uid_pattern": "{GatewayARN}"},
    {"from_type": "storagegateway.pool", "relation_type": "uses", "to_type": "storagegateway.volume",
     "source_field": "VolumeARNs", "target_uid_pattern": "{VolumeARN}",
     "source_field_item": "VolumeARN"},
]

# Field -> (to_type, relation_type) heuristics for discovery-driven expansion
FIELD_TO_TARGET: Dict[str, Tuple[str, str]] = {
    "VpcId": ("ec2.vpc", "contained_by"),
    "VpcArn": ("ec2.vpc", "contained_by"),
    "SubnetId": ("ec2.subnet", "attached_to"),
    "SubnetIds": ("ec2.subnet", "attached_to"),
    "SecurityGroupIds": ("ec2.security-group", "attached_to"),
    "SecurityGroupId": ("ec2.security-group", "attached_to"),
    "SecurityGroupArn": ("ec2.security-group", "attached_to"),
    "NetworkInterfaceId": ("ec2.network-interface", "attached_to"),
    "NetworkInterfaceIds": ("ec2.network-interface", "attached_to"),
    "RouteTableId": ("ec2.route-table", "attached_to"),
    "VpcEndpointId": ("ec2.vpc-endpoint", "attached_to"),
    "VpcEndpointIds": ("ec2.vpc-endpoint", "attached_to"),
    "TransitGatewayId": ("ec2.transit-gateway", "attached_to"),
    "TransitGatewayArn": ("ec2.transit-gateway", "attached_to"),
    "NatGatewayId": ("ec2.nat-gateway", "attached_to"),
    "InternetGatewayId": ("ec2.internet-gateway", "attached_to"),
    "KmsKeyId": ("kms.key", "encrypted_by"),
    "SSEKMSKeyId": ("kms.key", "encrypted_by"),
    "KeyId": ("kms.key", "encrypted_by"),
    "KmsKeyArn": ("kms.key", "encrypted_by"),
    "CertificateArn": ("acm.certificate", "uses"),
    "CertificateId": ("acm.certificate", "uses"),
    "KmsArn": ("kms.key", "encrypted_by"),
    "RoleArn": ("iam.role", "uses"),
    "RoleId": ("iam.role", "uses"),
    "RoleName": ("iam.role", "uses"),
    "PolicyArn": ("iam.policy", "attached_to"),
    "PolicyId": ("iam.policy", "attached_to"),
    "InstanceProfileArn": ("iam.instance-profile", "uses"),
    "InstanceProfileId": ("iam.instance-profile", "uses"),
    "GroupArn": ("iam.group", "member_of"),
    "GroupId": ("iam.group", "member_of"),
    "UserArn": ("iam.user", "member_of"),
    "UserId": ("iam.user", "member_of"),
    "FunctionArn": ("lambda.function", "uses"),
    "FunctionName": ("lambda.function", "uses"),
    "QueueArn": ("sqs.queue", "uses"),
    "TopicArn": ("sns.topic", "uses"),
    "RepositoryArn": ("ecr.repository", "uses"),
    "RepoArn": ("ecr.repository", "uses"),
    "BucketArn": ("s3.bucket", "uses"),
    "BucketName": ("s3.bucket", "uses"),
    "ClusterArn": ("eks.cluster", "attached_to"),
    "DBInstanceArn": ("rds.db-instance", "attached_to"),
    "DBClusterArn": ("rds.db-cluster", "attached_to"),
    "LogGroupArn": ("logs.group", "logging_enabled_to"),
    "LogGroupName": ("logs.group", "logging_enabled_to"),
    "CloudWatchLogsLogGroupArn": ("logs.group", "logging_enabled_to"),
    "DBSubnetGroupArn": ("rds.db-subnet-group", "attached_to"),
    "DBSecurityGroupArn": ("rds.db-security-group", "attached_to"),
    "DeliveryStreamArn": ("firehose.delivery-stream", "uses"),
    "FirehoseArn": ("firehose.delivery-stream", "uses"),
    "TaskDefinitionArn": ("ecs.task-definition", "uses"),
    "TaskDefinition": ("ecs.task-definition", "uses"),
    "ServiceArn": ("ecs.service", "uses"),
    "ServiceName": ("ecs.service", "uses"),
    "LoadBalancerArn": ("elbv2.load-balancer", "attached_to"),
    "TargetGroupArn": ("elbv2.target-group", "attached_to"),
    "ListenerArn": ("elbv2.listener", "attached_to"),
    "RuleArn": ("elbv2.rule", "attached_to"),
    "BucketOwnerArn": ("s3.bucket", "uses"),
    "SubscriptionArn": ("sns.subscription", "uses"),
    "RepositoryName": ("ecr.repository", "uses"),
    "RepositoryUri": ("ecr.repository", "uses"),
    "SecretArn": ("secretsmanager.secret", "uses"),
    "SecretId": ("secretsmanager.secret", "uses"),
    "SecretName": ("secretsmanager.secret", "uses"),
}


def get_emit_item_fields(discovery: Dict[str, Any]) -> Set[str]:
    """Extract emit.item field names from a discovery block."""
    out: Set[str] = set()
    emit = discovery.get("emit") or {}
    item = emit.get("item") or {}
    for k in item.keys():
        out.add(k)
    return out


def _discovery_list(data: Any) -> List[Dict[str, Any]]:
    """Extract list of discovery blocks from YAML root."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        lst = data.get("discovery")
        return lst if isinstance(lst, list) else []
    return []


def discover_yaml_blocks(services_root: Path) -> Dict[str, Dict[str, Any]]:
    """Scan discovery YAMLs; return discovery_id -> discovery block."""
    blocks: Dict[str, Dict[str, Any]] = {}
    for service_dir in sorted(services_root.iterdir()):
        if not service_dir.is_dir():
            continue
        # discoveries/*.yaml and rules/*.yaml use discovery: [ ... ]
        for subdir in ("discoveries", "rules"):
            ddir = service_dir / subdir
            if not ddir.is_dir():
                continue
            for p in ddir.glob("*.yaml"):
                data = load_yaml(p)
                if not data:
                    continue
                for d in _discovery_list(data):
                    if not isinstance(d, dict):
                        continue
                    did = d.get("discovery_id")
                    if did:
                        blocks[normalize_discovery_id(did)] = d
    return blocks


def build_relationship_index() -> Tuple[Dict[str, Any], datetime]:
    classification = load_json(CLASSIFICATION_INDEX_FILE)
    relation_types_data = load_json(RELATION_TYPES_FILE)
    valid_relation_types: Set[str] = set()
    relation_type_to_category: Dict[str, str] = {}
    if relation_types_data:
        for rt in relation_types_data.get("relation_types", []):
            valid_relation_types.add(rt.get("id", ""))
            rid = rt.get("id", "")
            cat = rt.get("category", "")
            if rid and cat:
                relation_type_to_category[rid] = cat
    if not valid_relation_types:
        valid_relation_types = {r["relation_type"] for r in CORE_RELATION_MAP}

    by_discovery: Dict[str, Dict[str, Any]] = {}
    by_resource: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"relationships": []})
    by_service: Dict[str, Dict[str, List[Dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))

    # ---------------------------------------------------------------------
    # Service/resource coverage baseline (from classification index)
    # We "cover" a service by ensuring it appears in by_service, even if empty.
    # We "cover" a resource type by ensuring it appears in by_resource_type, even if empty.
    # ---------------------------------------------------------------------
    all_services: Set[str] = set()
    all_resource_types: Set[str] = set()

    if classification:
        c = classification.get("classifications", {})

        # From discovery operations
        by_op = c.get("by_discovery_operation", {}) or {}
        for _op_key, info in by_op.items():
            svc = (info or {}).get("service")
            if svc:
                all_services.add(str(svc))

        # From service.resource classifications
        by_sr = c.get("by_service_resource", {}) or {}
        for sr_key, info in by_sr.items():
            if not isinstance(sr_key, str) or "." not in sr_key:
                continue
            svc, _raw_rt = sr_key.split(".", 1)
            if svc:
                all_services.add(svc)

            norm_rt = (info or {}).get("normalized_type") or (info or {}).get("resource_type") or _raw_rt
            norm_rt = re.sub(r"_+", "-", str(norm_rt)).strip("-")
            if svc and norm_rt:
                all_resource_types.add(f"{svc}.{norm_rt}")

    # Pre-seed empty entries so we truly "cover" all known resource types/services
    for rt in sorted(all_resource_types):
        if rt not in by_resource:
            by_resource[rt] = {"relationships": []}
    for svc in sorted(all_services):
        _ = by_service[svc]  # ensure key exists even if empty

    # 1. Apply core relation map
    seen = set()
    for r in CORE_RELATION_MAP:
        rel_type = r["relation_type"]
        if rel_type not in valid_relation_types:
            continue
        from_type = r["from_type"]
        to_type = r["to_type"]
        source_field = r.get("source_field", "")
        pattern = r.get("target_uid_pattern", "")
        item_field = r.get("source_field_item")
        entry = {
            "relation_type": rel_type,
            "target_type": to_type,
            "source_field": source_field,
            "target_uid_pattern": pattern,
        }
        if item_field:
            entry["source_field_item"] = item_field
        key = (from_type, rel_type, to_type, source_field)
        if key in seen:
            continue
        seen.add(key)
        if from_type not in by_resource:
            by_resource[from_type] = {"relationships": []}
        by_resource[from_type]["relationships"].append(entry)
        service = from_type.split(".", 1)[0] if "." in from_type else ""
        if service:
            category = relation_type_to_category.get(rel_type)
            if not category:
                # Backward-compatible fallback (keeps behavior if relation_types.json is missing categories)
                category = (
                    "network"
                    if rel_type == "contained_by"
                    else "security"
                    if rel_type == "attached_to"
                    else "identity"
                    if rel_type in ("uses", "member_of")
                    else "data"
                )
            by_service[service][category].append({
                "from_type": from_type,
                "to_type": to_type,
                "relation_type": rel_type,
                "source_field": source_field,
                "target_uid_pattern": pattern,
            })

    # 1.b Merge comprehensive definitions (batch merge for priority groups)
    COMPREHENSIVE_FILE = CONFIG_DIR / "comprehensive_aws_relationships.json"
    if COMPREHENSIVE_FILE.exists():
        comp = load_json(COMPREHENSIVE_FILE) or {}
        rels_by_service = comp.get("relationships_by_service", {}) or {}
        # Merge groups relevant to CSPM high-impact: ec2 / vpc / iam / networking / lambda / s3 / kms / rds / dynamodb
        for group_name, mappings in rels_by_service.items():
            gname = group_name.lower()
            if not any(tok in gname for tok in ("ec2", "vpc", "iam", "network", "lambda", "s3", "kms", "rds", "dynamodb", "ecs", "eks")):
                continue
            for from_type, rel_defs in mappings.items():
                for rd in rel_defs:
                    rel_type = rd.get("relation_type")
                    if not rel_type or rel_type not in valid_relation_types:
                        continue
                    to_type = rd.get("target_type")
                    # normalize source_field (list -> dot path)
                    sf = rd.get("source_field")
                    if isinstance(sf, list):
                        source_field = ".".join([str(x) for x in sf if x])
                    else:
                        source_field = sf or ""
                    entry = {
                        "relation_type": rel_type,
                        "target_type": to_type,
                        "source_field": source_field,
                        "target_uid_pattern": rd.get("target_uid_pattern", "")
                    }
                    if rd.get("source_field_item"):
                        entry["source_field_item"] = rd.get("source_field_item")
                    key = (from_type, rel_type, to_type, source_field)
                    if key in seen:
                        continue
                    seen.add(key)
                    if from_type not in by_resource:
                        by_resource[from_type] = {"relationships": []}
                    by_resource[from_type]["relationships"].append(entry)
                    svc = from_type.split(".", 1)[0] if "." in from_type else ""
                    if svc:
                        cat = relation_type_to_category.get(rel_type) or ("network" if rel_type == "contained_by" else "security" if rel_type == "attached_to" else "identity" if rel_type in ("uses", "member_of") else "data")
                        by_service[svc][cat].append({
                            "from_type": from_type,
                            "to_type": to_type,
                            "relation_type": rel_type,
                            "source_field": source_field,
                            "target_uid_pattern": rd.get("target_uid_pattern", "")
                        })

    # 2. Map discovery_id -> resource type from classification index
    discovery_to_resource: Dict[str, Tuple[str, str]] = {}
    if classification:
        by_op = classification.get("classifications", {}).get("by_discovery_operation", {})
        for norm_id, info in by_op.items():
            svc = info.get("service", "")
            rt = info.get("resource_type", "") or info.get("normalized_type", "")
            if not svc or not rt:
                continue
            norm_rt = info.get("normalized_type") or re.sub(r"_+", "-", rt).strip("-")
            discovery_to_resource[norm_id] = (svc, f"{svc}.{norm_rt}")

    # 3. Scan discovery YAMLs and attach discovery_ids to relations
    blocks = discover_yaml_blocks(CONFIGSCAN_SERVICES) if CONFIGSCAN_SERVICES.exists() else {}
    for norm_id, block in blocks.items():
        fields = get_emit_item_fields(block)
        lookup_key = to_classification_key(norm_id)
        resource_info = discovery_to_resource.get(lookup_key)
        from_type = resource_info[1] if resource_info else None
        rels: List[Dict[str, Any]] = []
        for f in fields:
            if f not in FIELD_TO_TARGET:
                continue
            to_type, rel_type = FIELD_TO_TARGET[f]
            if rel_type not in valid_relation_types:
                continue
            if f == "VpcId":
                pattern = "arn:aws:ec2:{region}:{account_id}:vpc/{VpcId}"
            elif "Kms" in f or f == "KeyId" or f == "SSEKMSKeyId":
                pattern = f"arn:aws:kms:{{region}}:{{account_id}}:key/{{{f}}}"
            elif "Subnet" in f:
                pattern = f"arn:aws:ec2:{{region}}:{{account_id}}:subnet/{{{f}}}" if f == "SubnetId" else f"arn:aws:ec2:{{region}}:{{account_id}}:subnet/{{item}}"
            elif "SecurityGroup" in f:
                pattern = f"arn:aws:ec2:{{region}}:{{account_id}}:security-group/{{{f}}}" if f == "SecurityGroupId" else f"arn:aws:ec2:{{region}}:{{account_id}}:security-group/{{GroupId}}"
            else:
                pattern = f"{{{f}}}"
            rels.append({
                "relation_type": rel_type,
                "target_type": to_type,
                "source_field": f,
                "target_uid_pattern": pattern,
            })
        if rels:
            by_discovery[norm_id] = {"relationships": rels}
        if from_type:
            for r in rels:
                # Skip invalid: subnet -> subnet via SubnetId; same-type loops
                if from_type == r["target_type"] and r["source_field"] == "SubnetId":
                    continue
                key = (from_type, r["relation_type"], r["target_type"], r["source_field"])
                if key not in seen:
                    seen.add(key)
                    by_resource[from_type]["relationships"].append(r)

    # 4. Build output structure
    generated_at = datetime.now(timezone.utc)

    resource_types_with_relations = sum(
        1 for v in by_resource.values()
        if isinstance(v, dict) and isinstance(v.get("relationships"), list) and len(v["relationships"]) > 0
    )
    resource_types_total = len(by_resource)

    services_with_relations = 0
    services_without_relations: List[str] = []
    for svc in sorted(all_services):
        svc_block = by_service.get(svc) or {}
        has_any = any(isinstance(v, list) and len(v) > 0 for v in svc_block.values())
        if has_any:
            services_with_relations += 1
        else:
            services_without_relations.append(svc)

    index: Dict[str, Any] = {
        "version": "1.0",
        "generated_at": generated_at.isoformat(),
        "source": "core_relation_map+discovery_yaml+classification_index",
        "classifications": {
            "by_resource_type": dict(by_resource),
            "by_discovery_operation": by_discovery,
            # Ensure ALL services appear, even if empty (coverage baseline)
            "by_service": {svc: dict(by_service.get(svc, {})) for svc in sorted(all_services)},
        },
        "metadata": {
            # services_covered == services_with_relations (not total)
            "services_covered": services_with_relations,
            "services_total": len(all_services),
            "resource_types_with_relations": resource_types_with_relations,
            "resource_types_total": resource_types_total,
            "resource_types_from_classification_index": len(all_resource_types),
            "discovery_operations_with_relations": len(by_discovery),
            "total_relationship_definitions": sum(len(v["relationships"]) for v in by_resource.values()),
            "services_without_relations": services_without_relations,
            "classification_index_metadata": (classification or {}).get("metadata", {}),
        },
    }
    return index, generated_at


def main() -> None:
    print("Building Relationship Index...")
    print(f"ConfigScan services: {CONFIGSCAN_SERVICES}")
    print(f"Classification index: {CLASSIFICATION_INDEX_FILE}")
    print(f"Output: {OUTPUT_FILE}")
    print()
    index, generated_at = build_relationship_index()
    timestamp_str = generated_at.strftime("%Y%m%dT%H%M%SZ")
    timestamped_output = CONFIG_DIR / f"aws_relationship_index_{timestamp_str}.json"
    index["metadata"]["latest_index_file"] = OUTPUT_FILE.name
    index["metadata"]["timestamped_index_file"] = timestamped_output.name
    index["metadata"]["generated_at"] = index["generated_at"]
    meta = index.get("metadata", {})
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    
    # Write JSON format (for backward compatibility)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(index, f, indent=2)
    with open(timestamped_output, "w", encoding="utf-8") as f:
        json.dump(index, f, indent=2)
    
    # Write NDJSON format (preferred for large files)
    metadata_file = CONFIG_DIR / "aws_relationship_index_metadata.json"
    ndjson_file = CONFIG_DIR / "aws_relationship_index.ndjson"
    timestamped_ndjson = CONFIG_DIR / f"aws_relationship_index_{timestamp_str}.ndjson"
    
    # Extract metadata
    metadata = {
        "version": index.get("version"),
        "generated_at": index.get("generated_at"),
        "source": index.get("source"),
        "metadata": index.get("metadata", {}),
    }
    
    # Flatten relationships to NDJSON
    relationships = []
    
    # From by_resource_type
    by_resource = index.get("classifications", {}).get("by_resource_type", {})
    for resource_type, info in by_resource.items():
        rels = info.get("relationships", [])
        for rel in rels:
            relationships.append({
                "from_type": resource_type,
                "relation_type": rel.get("relation_type"),
                "to_type": rel.get("target_type"),
                "source_field": rel.get("source_field"),
                "target_uid_pattern": rel.get("target_uid_pattern"),
                "source_field_item": rel.get("source_field_item"),
            })
    
    # From by_discovery_operation
    by_discovery = index.get("classifications", {}).get("by_discovery_operation", {})
    for discovery_id, info in by_discovery.items():
        rels = info.get("relationships", [])
        for rel in rels:
            relationships.append({
                "from_discovery": discovery_id,
                "relation_type": rel.get("relation_type"),
                "to_type": rel.get("target_type"),
                "source_field": rel.get("source_field"),
                "target_uid_pattern": rel.get("target_uid_pattern"),
                "source_field_item": rel.get("source_field_item"),
            })
    
    # Write metadata
    with open(metadata_file, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    
    # Write NDJSON (one relationship per line)
    with open(ndjson_file, "w", encoding="utf-8") as f:
        for rel in relationships:
            f.write(json.dumps(rel) + "\n")
    
    with open(timestamped_ndjson, "w", encoding="utf-8") as f:
        for rel in relationships:
            f.write(json.dumps(rel) + "\n")
    
    print("Relationship index built successfully.")
    print(f"  Services: {meta.get('services_covered', 0)}")
    print(f"  Resource types with relations: {meta.get('resource_types_with_relations', 0)}")
    print(f"  Discovery ops with relations: {meta.get('discovery_operations_with_relations', 0)}")
    print(f"  Total relationship definitions: {meta.get('total_relationship_definitions', 0)}")
    print(f"  Written to:")
    print(f"    JSON: {OUTPUT_FILE} ({OUTPUT_FILE.stat().st_size:,} bytes)")
    print(f"    NDJSON: {ndjson_file} ({ndjson_file.stat().st_size:,} bytes)")
    print(f"    Metadata: {metadata_file} ({metadata_file.stat().st_size:,} bytes)")
    print(f"    Timestamped copies: {timestamped_output.name}, {timestamped_ndjson.name}")


if __name__ == "__main__":
    main()
