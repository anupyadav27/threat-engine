#!/usr/bin/env python3
"""
Load Relationship Rules into inventory DB

Populates resource_security_relationship_rules in threat_engine_inventory (inventory DB)
for ALL supported CSPs:  aws | azure | gcp | oci | ibm | alicloud | k8s

Rule sources (applied in order, no duplicates thanks to UPSERT ON CONFLICT):

  1. AUTO — contained_by rules derived from resource_inventory_identifier
             WHERE parent_resource_type IS NOT NULL.
             Works for every CSP automatically since the RII table has full
             multi-cloud coverage.

  2. AUTO — uses / depends_on rules derived from resource_inventory_identifier
             enrich_ops[].param_sources when a param_source names a
             parent_resource_type in a different service (cross-service link).

  3. CURATED — hand-curated AWS cross-service rules (EC2 ↔ VPC, ECS ↔ IAM,
               Lambda ↔ KMS, S3 ↔ KMS, RDS ↔ SG, …).
               These cover fields that are not expressible purely from step5
               parent-child chains (e.g. SecurityGroups on an EC2 instance).

  4. CURATED — Azure, GCP, OCI, IBM, AliCloud, K8s cross-service rules.

Usage:
    # Connect via env vars (same as the inventory engine itself)
    export INVENTORY_DB_URL="postgresql://user:pass@host:5432/threat_engine_inventory"
    python engine_inventory/scripts/load_relationship_rules_to_db.py

    # Or pass a DSN directly
    python engine_inventory/scripts/load_relationship_rules_to_db.py \
        "postgresql://user:pass@host:5432/threat_engine_inventory"
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

import psycopg2
import psycopg2.extras

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _connect(dsn: Optional[str] = None) -> psycopg2.extensions.connection:
    dsn = dsn or os.getenv("INVENTORY_DB_URL")
    if not dsn:
        sys.exit(
            "Set INVENTORY_DB_URL or pass the DSN as the first CLI argument.\n"
            "Example: postgresql://user:pass@host:5432/threat_engine_inventory"
        )
    return psycopg2.connect(dsn)


def _upsert_rules(
    conn: psycopg2.extensions.connection,
    rules: List[Dict[str, Any]],
    source_label: str,
) -> int:
    """
    Upsert rules into resource_security_relationship_rules.
    Returns the number of rows affected.
    """
    if not rules:
        return 0

    sql = """
        INSERT INTO resource_security_relationship_rules
            (csp, service, from_resource_type, relation_type, to_resource_type,
             source_field, source_field_item, target_uid_pattern,
             is_active, rule_source, rule_metadata)
        VALUES
            (%(csp)s, %(service)s, %(from_resource_type)s, %(relation_type)s,
             %(to_resource_type)s, %(source_field)s, %(source_field_item)s,
             %(target_uid_pattern)s, TRUE, %(rule_source)s, %(rule_metadata)s::jsonb)
        ON CONFLICT (csp, from_resource_type, relation_type, to_resource_type, source_field)
        DO UPDATE SET
            service            = EXCLUDED.service,
            source_field_item  = EXCLUDED.source_field_item,
            target_uid_pattern = EXCLUDED.target_uid_pattern,
            is_active          = TRUE,
            rule_source        = EXCLUDED.rule_source,
            rule_metadata      = EXCLUDED.rule_metadata,
            updated_at         = NOW()
    """

    with conn.cursor() as cur:
        psycopg2.extras.execute_batch(cur, sql, rules, page_size=500)

    conn.commit()
    log.info(f"  [{source_label}] upserted {len(rules)} rules")
    return len(rules)


# ──────────────────────────────────────────────────────────────────────────────
# Source 1 & 2: Auto-generate from resource_inventory_identifier
# ──────────────────────────────────────────────────────────────────────────────

def _extract_parent_field(
    child_pattern: Optional[str],
    parent_rt: str,
) -> Optional[str]:
    """
    Heuristic: find the ${Variable} in child's identifier_pattern that most
    likely identifies the parent resource.

    Strategy:
      1. Match variable name that contains the parent type's last segment
         e.g. parent_rt="ec2.vpc", last_seg="vpc" → variable contains "vpc"
             child pattern has "${VpcId}" → match
      2. If no match, look for any variable whose name ends in "Id" or "Arn"
         and hasn't already been matched by account/partition/region markers.
    """
    if not child_pattern:
        return None

    variables = re.findall(r'\$\{(\w+)\}', child_pattern)
    # Drop standard ARN structural variables
    structural = {"Partition", "Region", "Account", "AccountId"}
    variables = [v for v in variables if v not in structural]

    if not variables:
        return None

    # Strategy 1 — name-based heuristic
    parent_segments = re.split(r'[\.\-_]', parent_rt.split(".")[-1])
    for var in variables:
        var_lower = var.lower()
        if any(seg.lower() in var_lower for seg in parent_segments if len(seg) > 2):
            return var

    # Strategy 2 — pick first Id/Arn variable
    for var in variables:
        if var.endswith("Id") or var.endswith("Arn") or var.endswith("Name"):
            return var

    # Fallback — first remaining variable
    return variables[0]


def generate_auto_rules(conn: psycopg2.extensions.connection) -> List[Dict[str, Any]]:
    """
    Generate relationship rules from resource_inventory_identifier for ALL CSPs.

    Two sub-generators:
      A) contained_by from parent_resource_type column
      B) cross-service uses from enrich_ops[].param_sources
    """
    rules: List[Dict[str, Any]] = []
    seen: set = set()

    def _add(rule: Dict[str, Any]) -> None:
        key = (
            rule["csp"], rule["from_resource_type"],
            rule["relation_type"], rule["to_resource_type"],
            rule["source_field"],
        )
        if key not in seen:
            seen.add(key)
            rules.append(rule)

    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        # ── A) contained_by from parent_resource_type ─────────────────────────
        cur.execute("""
            SELECT
                child.csp,
                child.service,
                child.resource_type        AS child_rt,
                child.identifier_pattern   AS child_pattern,
                child.parent_resource_type AS parent_rt,
                parent.identifier_pattern  AS parent_pattern
            FROM resource_inventory_identifier child
            JOIN resource_inventory_identifier parent
              ON parent.csp          = child.csp
             AND parent.resource_type = child.parent_resource_type
            WHERE child.parent_resource_type IS NOT NULL
              AND child.should_inventory = TRUE
        """)
        for row in cur.fetchall():
            parent_field = _extract_parent_field(row["child_pattern"], row["parent_rt"])
            if not parent_field:
                continue
            parent_pattern = row["parent_pattern"] or f"{{{parent_field}}}"
            # Convert ${Var} to {Var} for our runtime resolver
            target_pattern = re.sub(r'\$\{(\w+)\}', r'{\1}', parent_pattern)
            _add({
                "csp":               row["csp"],
                "service":           row["service"],
                "from_resource_type": row["child_rt"],
                "relation_type":     "contained_by",
                "to_resource_type":  row["parent_rt"],
                "source_field":      parent_field,
                "source_field_item": None,
                "target_uid_pattern": target_pattern,
                "rule_source":       "auto",
                "rule_metadata":     json.dumps({"generator": "rii_parent"}),
            })

        # ── B) cross-service uses from enrich_ops param_sources ───────────────
        cur.execute("""
            SELECT csp, service, resource_type, enrich_ops
            FROM resource_inventory_identifier
            WHERE enrich_ops IS NOT NULL
              AND jsonb_array_length(enrich_ops) > 0
              AND should_inventory = TRUE
        """)
        for row in cur.fetchall():
            enrich_ops = row["enrich_ops"]
            if not isinstance(enrich_ops, list):
                continue
            for op in enrich_ops:
                if not isinstance(op, dict):
                    continue
                param_sources = op.get("param_sources", {})
                if not isinstance(param_sources, dict):
                    continue
                for param_name, source in param_sources.items():
                    if not isinstance(source, dict):
                        continue
                    parent_rt = source.get("parent_resource_type")
                    if not parent_rt or parent_rt == row["resource_type"]:
                        continue  # skip self-references
                    from_field = source.get("from_field", param_name)
                    # Only add cross-service links (same-service covered by contained_by above)
                    child_svc  = row["resource_type"].split(".")[0]
                    parent_svc = parent_rt.split(".")[0]
                    if child_svc == parent_svc:
                        continue
                    _add({
                        "csp":               row["csp"],
                        "service":           row["service"],
                        "from_resource_type": row["resource_type"],
                        "relation_type":     "uses",
                        "to_resource_type":  parent_rt,
                        "source_field":      from_field,
                        "source_field_item": None,
                        "target_uid_pattern": f"{{{from_field}}}",
                        "rule_source":       "auto",
                        "rule_metadata":     json.dumps({
                            "generator": "rii_param_sources",
                            "enrich_op": op.get("operation", ""),
                        }),
                    })

    log.info(f"Auto-generated {len(rules)} rules from resource_inventory_identifier")
    return rules


# ──────────────────────────────────────────────────────────────────────────────
# Source 3: Curated AWS cross-service rules
# ──────────────────────────────────────────────────────────────────────────────

def _aws(
    from_rt: str,
    rel: str,
    to_rt: str,
    field: str,
    pattern: str,
    item: Optional[str] = None,
    svc: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "csp":               "aws",
        "service":           svc or from_rt.split(".")[0],
        "from_resource_type": from_rt,
        "relation_type":     rel,
        "to_resource_type":  to_rt,
        "source_field":      field,
        "source_field_item": item,
        "target_uid_pattern": pattern,
        "rule_source":       "curated",
        "rule_metadata":     json.dumps({}),
    }


AWS_CURATED_RULES: List[Dict[str, Any]] = [
    # ── EC2 Instance ──────────────────────────────────────────────────────────
    _aws("ec2.instance", "attached_to",   "ec2.security-group",   "SecurityGroups",         "arn:aws:ec2:{region}:{account_id}:security-group/{GroupId}",  item="GroupId"),
    _aws("ec2.instance", "contained_by",  "ec2.subnet",           "SubnetId",               "arn:aws:ec2:{region}:{account_id}:subnet/{SubnetId}"),
    _aws("ec2.instance", "contained_by",  "ec2.vpc",              "VpcId",                  "arn:aws:ec2:{region}:{account_id}:vpc/{VpcId}"),
    _aws("ec2.instance", "uses",          "iam.instance-profile", "IamInstanceProfile.Arn", "{IamInstanceProfile.Arn}"),
    _aws("ec2.instance", "attached_to",   "ec2.network-interface","NetworkInterfaces",       "arn:aws:ec2:{region}:{account_id}:network-interface/{NetworkInterfaceId}", item="NetworkInterfaceId"),
    _aws("ec2.instance", "attached_to",   "ec2.volume",           "BlockDeviceMappings",    "arn:aws:ec2:{region}:{account_id}:volume/{VolumeId}",          item="Ebs.VolumeId"),
    _aws("ec2.instance", "encrypted_by",  "kms.key",              "BlockDeviceMappings",    "{KmsKeyId}",                                                   item="Ebs.KmsKeyId"),
    _aws("ec2.instance", "runs_on",       "ec2.image",            "ImageId",                "arn:aws:ec2:{region}::image/{ImageId}"),
    _aws("ec2.instance", "member_of",     "ec2.placement-group",  "Placement.GroupName",    "arn:aws:ec2:{region}:{account_id}:placement-group/{GroupName}"),

    # ── EC2 Volume ────────────────────────────────────────────────────────────
    _aws("ec2.volume", "encrypted_by",  "kms.key",      "KmsKeyId",   "{KmsKeyId}"),
    _aws("ec2.volume", "contained_by",  "ec2.snapshot", "SnapshotId", "arn:aws:ec2:{region}::snapshot/{SnapshotId}"),

    # ── EC2 Subnet ────────────────────────────────────────────────────────────
    _aws("ec2.subnet", "contained_by",  "ec2.vpc",           "VpcId",              "arn:aws:ec2:{region}:{account_id}:vpc/{VpcId}"),
    _aws("ec2.subnet", "routes_to",     "ec2.route-table",   "RouteTableId",       "arn:aws:ec2:{region}:{account_id}:route-table/{RouteTableId}"),
    _aws("ec2.subnet", "attached_to",   "ec2.network-acl",   "NetworkAclId",       "arn:aws:ec2:{region}:{account_id}:network-acl/{NetworkAclId}"),

    # ── EC2 VPC ───────────────────────────────────────────────────────────────
    _aws("ec2.vpc", "attached_to",   "ec2.internet-gateway",   "InternetGatewayId",  "arn:aws:ec2:{region}:{account_id}:internet-gateway/{InternetGatewayId}"),
    _aws("ec2.vpc", "attached_to",   "ec2.dhcp-options",       "DhcpOptionsId",      "arn:aws:ec2:{region}:{account_id}:dhcp-options/{DhcpOptionsId}"),

    # ── EC2 Security Group ────────────────────────────────────────────────────
    _aws("ec2.security-group", "contained_by", "ec2.vpc", "VpcId", "arn:aws:ec2:{region}:{account_id}:vpc/{VpcId}"),

    # ── EC2 Load Balancer ─────────────────────────────────────────────────────
    _aws("ec2.load-balancer", "contained_by",  "ec2.vpc",            "VpcId",            "arn:aws:ec2:{region}:{account_id}:vpc/{VpcId}"),
    _aws("ec2.load-balancer", "attached_to",   "ec2.security-group", "SecurityGroups",   "arn:aws:ec2:{region}:{account_id}:security-group/{item}"),
    _aws("ec2.load-balancer", "attached_to",   "ec2.subnet",         "AvailabilityZones","arn:aws:ec2:{region}:{account_id}:subnet/{SubnetId}", item="SubnetId"),

    # ── Lambda ────────────────────────────────────────────────────────────────
    _aws("lambda.function", "uses",          "iam.role",          "Role",                        "{Role}"),
    _aws("lambda.function", "contained_by",  "ec2.vpc",           "VpcConfig.VpcId",             "arn:aws:ec2:{region}:{account_id}:vpc/{VpcId}"),
    _aws("lambda.function", "attached_to",   "ec2.subnet",        "VpcConfig.SubnetIds",         "arn:aws:ec2:{region}:{account_id}:subnet/{item}"),
    _aws("lambda.function", "attached_to",   "ec2.security-group","VpcConfig.SecurityGroupIds",  "arn:aws:ec2:{region}:{account_id}:security-group/{item}"),
    _aws("lambda.function", "encrypted_by",  "kms.key",           "KMSKeyArn",                   "{KMSKeyArn}"),
    _aws("lambda.function", "logging_enabled_to", "logs.log-group","FunctionName",               "arn:aws:logs:{region}:{account_id}:log-group:/aws/lambda/{FunctionName}"),
    _aws("lambda.function", "uses",          "efs.file-system",   "FileSystemConfigs",           "{Arn}", item="Arn"),
    _aws("lambda.function", "uses",          "lambda.layer-version","Layers",                    "{Arn}", item="Arn"),

    # ── RDS ───────────────────────────────────────────────────────────────────
    _aws("rds.db-instance", "contained_by",  "ec2.vpc",            "DBSubnetGroup.VpcId",        "arn:aws:ec2:{region}:{account_id}:vpc/{VpcId}"),
    _aws("rds.db-instance", "attached_to",   "ec2.security-group", "VpcSecurityGroups",          "arn:aws:ec2:{region}:{account_id}:security-group/{VpcSecurityGroupId}", item="VpcSecurityGroupId"),
    _aws("rds.db-instance", "encrypted_by",  "kms.key",            "KmsKeyId",                   "{KmsKeyId}"),
    _aws("rds.db-instance", "member_of",     "rds.db-cluster",     "DBClusterIdentifier",        "arn:aws:rds:{region}:{account_id}:cluster:{DBClusterIdentifier}"),
    _aws("rds.db-instance", "uses",          "iam.role",           "AssociatedRoles",             "{RoleArn}", item="RoleArn"),
    _aws("rds.db-cluster",  "contained_by",  "ec2.vpc",            "DBSubnetGroup.VpcId",        "arn:aws:ec2:{region}:{account_id}:vpc/{VpcId}"),
    _aws("rds.db-cluster",  "attached_to",   "ec2.security-group", "VpcSecurityGroups",          "arn:aws:ec2:{region}:{account_id}:security-group/{VpcSecurityGroupId}", item="VpcSecurityGroupId"),
    _aws("rds.db-cluster",  "encrypted_by",  "kms.key",            "KmsKeyId",                   "{KmsKeyId}"),

    # ── S3 ────────────────────────────────────────────────────────────────────
    _aws("s3.bucket",  "encrypted_by",       "kms.key",            "ServerSideEncryptionConfiguration.Rules.ApplyServerSideEncryptionByDefault.KMSMasterKeyID", "{KMSMasterKeyID}"),
    _aws("s3.bucket",  "logging_enabled_to", "s3.bucket",          "LoggingEnabled.TargetBucket",  "arn:aws:s3:::{TargetBucket}"),
    _aws("s3.bucket",  "replicates_to",      "s3.bucket",          "ReplicationConfiguration.Rules.Destination.Bucket", "{Bucket}"),

    # ── IAM ───────────────────────────────────────────────────────────────────
    _aws("iam.role",           "member_of",  "iam.instance-profile", "InstanceProfileArns",     "{item}"),
    _aws("iam.user",           "member_of",  "iam.group",            "Groups",                  "{Arn}",     item="Arn"),
    _aws("iam.role",           "has_policy", "iam.policy",           "AttachedPolicies",         "{PolicyArn}", item="PolicyArn"),
    _aws("iam.user",           "has_policy", "iam.policy",           "AttachedPolicies",         "{PolicyArn}", item="PolicyArn"),
    _aws("iam.group",          "has_policy", "iam.policy",           "AttachedPolicies",         "{PolicyArn}", item="PolicyArn"),

    # ── KMS ───────────────────────────────────────────────────────────────────
    _aws("kms.key", "contained_by", "kms.custom-key-store", "CustomKeyStoreId", "arn:aws:kms:{region}:{account_id}:custom-key-store/{CustomKeyStoreId}"),

    # ── ECS ───────────────────────────────────────────────────────────────────
    _aws("ecs.task",           "uses",       "iam.role",        "taskRoleArn",         "{taskRoleArn}"),
    _aws("ecs.task",           "uses",       "iam.role",        "executionRoleArn",    "{executionRoleArn}"),
    _aws("ecs.task",           "runs_on",    "ec2.instance",    "containerInstanceArn","arn:aws:ec2:{region}:{account_id}:instance/{containerInstanceId}"),
    _aws("ecs.service",        "contained_by","ec2.vpc",        "networkConfiguration.awsvpcConfiguration.subnets", "arn:aws:ec2:{region}:{account_id}:subnet/{item}"),
    _aws("ecs.service",        "attached_to","ec2.security-group","networkConfiguration.awsvpcConfiguration.securityGroups","arn:aws:ec2:{region}:{account_id}:security-group/{item}"),
    _aws("ecs.container",      "encrypted_by","kms.key",        "KmsKeyId",           "{KmsKeyId}"),

    # ── EKS ───────────────────────────────────────────────────────────────────
    _aws("eks.cluster",  "contained_by",  "ec2.vpc",            "resourcesVpcConfig.vpcId",        "arn:aws:ec2:{region}:{account_id}:vpc/{vpcId}"),
    _aws("eks.cluster",  "attached_to",   "ec2.security-group", "resourcesVpcConfig.securityGroupIds","arn:aws:ec2:{region}:{account_id}:security-group/{item}"),
    _aws("eks.cluster",  "uses",          "iam.role",           "roleArn",                         "{roleArn}"),
    _aws("eks.cluster",  "encrypted_by",  "kms.key",            "encryptionConfig.provider.keyArn","{keyArn}"),

    # ── ElastiCache ───────────────────────────────────────────────────────────
    _aws("elasticache.replication-group", "contained_by",  "ec2.vpc",            "MemberClusters", "arn:aws:ec2:{region}:{account_id}:vpc/{VpcId}"),
    _aws("elasticache.replication-group", "encrypted_by",  "kms.key",            "KmsKeyId",       "{KmsKeyId}"),
    _aws("elasticache.cluster",           "attached_to",   "ec2.security-group", "SecurityGroups", "arn:aws:ec2:{region}:{account_id}:security-group/{SecurityGroupId}", item="SecurityGroupId"),

    # ── OpenSearch / Elasticsearch ────────────────────────────────────────────
    _aws("es.domain",        "contained_by",  "ec2.vpc",            "VPCOptions.VPCId",              "arn:aws:ec2:{region}:{account_id}:vpc/{VPCId}"),
    _aws("es.domain",        "attached_to",   "ec2.security-group", "VPCOptions.SecurityGroupIds",   "arn:aws:ec2:{region}:{account_id}:security-group/{item}"),
    _aws("es.domain",        "encrypted_by",  "kms.key",            "EncryptionAtRestOptions.KmsKeyId","{KmsKeyId}"),

    # ── SQS ───────────────────────────────────────────────────────────────────
    _aws("sqs.queue",  "encrypted_by",    "kms.key",    "KmsMasterKeyId",  "{KmsMasterKeyId}"),
    _aws("sqs.queue",  "subscribes_to",   "sns.topic",  "Policy",          "{TopicArn}"),

    # ── SNS ───────────────────────────────────────────────────────────────────
    _aws("sns.topic",  "encrypted_by",  "kms.key",     "KmsMasterKeyId",  "{KmsMasterKeyId}"),

    # ── Secrets Manager ───────────────────────────────────────────────────────
    _aws("secretsmanager.secret",  "encrypted_by",  "kms.key",  "KmsKeyId",  "{KmsKeyId}"),

    # ── CloudWatch Logs ───────────────────────────────────────────────────────
    _aws("logs.log-group",  "encrypted_by",  "kms.key",  "kmsKeyId",  "{kmsKeyId}"),

    # ── CloudTrail ────────────────────────────────────────────────────────────
    _aws("cloudtrail.trail",  "logging_enabled_to",  "s3.bucket",       "S3BucketName",    "arn:aws:s3:::{S3BucketName}"),
    _aws("cloudtrail.trail",  "logging_enabled_to",  "logs.log-group",  "CloudWatchLogsLogGroupArn", "{CloudWatchLogsLogGroupArn}"),
    _aws("cloudtrail.trail",  "encrypted_by",        "kms.key",         "KMSKeyId",        "{KMSKeyId}"),

    # ── Kinesis ───────────────────────────────────────────────────────────────
    _aws("kinesis.stream",      "encrypted_by",  "kms.key",    "KeyId",   "{KeyId}"),
    _aws("kinesis.firehose",    "stores_data_in","s3.bucket",  "S3DestinationDescription.BucketARN", "{BucketARN}"),
    _aws("kinesis.firehose",    "encrypted_by",  "kms.key",    "DeliveryStreamEncryptionConfiguration.KeyARN", "{KeyARN}"),

    # ── DynamoDB ─────────────────────────────────────────────────────────────
    _aws("dynamodb.table",  "encrypted_by",   "kms.key",    "SSEDescription.KMSMasterKeyArn",  "{KMSMasterKeyArn}"),
    _aws("dynamodb.table",  "replicates_to",  "dynamodb.table", "Replicas",               "arn:aws:dynamodb:{RegionName}:{account_id}:table/{TableName}", item="RegionName"),

    # ── Glue ──────────────────────────────────────────────────────────────────
    _aws("glue.database",  "uses",  "s3.bucket",  "LocationUri",  "arn:aws:s3:::{LocationUri}"),
    _aws("glue.job",       "uses",  "iam.role",   "Role",         "arn:aws:iam::{account_id}:role/{Role}"),

    # ── Step Functions ────────────────────────────────────────────────────────
    _aws("states.state-machine",  "uses",         "iam.role",       "roleArn",         "{roleArn}"),
    _aws("states.state-machine",  "logging_enabled_to", "logs.log-group", "loggingConfiguration.destinations", "{cloudWatchLogsLogGroup.logGroupArn}", item="cloudWatchLogsLogGroup.logGroupArn"),

    # ── API Gateway ───────────────────────────────────────────────────────────
    _aws("apigateway.rest-api",   "logging_enabled_to", "logs.log-group", "stages.accessLogSettings.destinationArn", "{destinationArn}"),
    _aws("apigateway.rest-api",   "protected_by",       "waf.web-acl",    "stages.webAclArn",                        "{webAclArn}"),

    # ── CloudFront ────────────────────────────────────────────────────────────
    _aws("cloudfront.distribution", "serves_traffic_for", "s3.bucket",      "Origins.Items.DomainName", "{DomainName}"),
    _aws("cloudfront.distribution", "protected_by",       "waf.web-acl",    "WebACLId",                 "{WebACLId}"),
    _aws("cloudfront.distribution", "encrypted_by",       "kms.key",        "ViewerCertificate.ACMCertificateArn", "{ACMCertificateArn}"),

    # ── ELB / ALB / NLB ──────────────────────────────────────────────────────
    _aws("elasticloadbalancing.load-balancer", "contained_by",  "ec2.vpc",            "VpcId",          "arn:aws:ec2:{region}:{account_id}:vpc/{VpcId}"),
    _aws("elasticloadbalancing.load-balancer", "attached_to",   "ec2.security-group", "SecurityGroups", "arn:aws:ec2:{region}:{account_id}:security-group/{item}"),

    # ── ACM ───────────────────────────────────────────────────────────────────
    _aws("acm.certificate",  "resolves_to",  "acm.certificate", "InUseBy",  "{item}"),

    # ── CodeBuild ─────────────────────────────────────────────────────────────
    _aws("codebuild.project",  "uses",         "iam.role",       "serviceRole",  "{serviceRole}"),
    _aws("codebuild.project",  "encrypted_by", "kms.key",        "encryptionKey", "{encryptionKey}"),
    _aws("codebuild.project",  "contained_by", "ec2.vpc",        "vpcConfig.vpcId","arn:aws:ec2:{region}:{account_id}:vpc/{vpcId}"),

    # ── CodePipeline ──────────────────────────────────────────────────────────
    _aws("codepipeline.pipeline",  "uses",  "iam.role",  "roleArn",  "{roleArn}"),
    _aws("codepipeline.pipeline",  "uses",  "s3.bucket", "artifactStore.location", "arn:aws:s3:::{location}"),

    # ── Batch ─────────────────────────────────────────────────────────────────
    _aws("batch.compute-environment", "contained_by",  "ec2.vpc",            "computeResources.subnets",        "arn:aws:ec2:{region}:{account_id}:subnet/{item}"),
    _aws("batch.compute-environment", "attached_to",   "ec2.security-group", "computeResources.securityGroupIds","arn:aws:ec2:{region}:{account_id}:security-group/{item}"),
    _aws("batch.compute-environment", "uses",          "iam.role",           "serviceRole",                     "{serviceRole}"),

    # ── Backup ────────────────────────────────────────────────────────────────
    _aws("backup.backup-vault",  "encrypted_by",  "kms.key",  "EncryptionKeyArn",  "{EncryptionKeyArn}"),

    # ── MSK (Managed Kafka) ───────────────────────────────────────────────────
    _aws("kafka.cluster",  "contained_by",  "ec2.vpc",            "BrokerNodeGroupInfo.ClientSubnets", "arn:aws:ec2:{region}:{account_id}:subnet/{item}"),
    _aws("kafka.cluster",  "attached_to",   "ec2.security-group", "BrokerNodeGroupInfo.SecurityGroups","arn:aws:ec2:{region}:{account_id}:security-group/{item}"),
    _aws("kafka.cluster",  "encrypted_by",  "kms.key",            "EncryptionInfo.EncryptionAtRest.DataVolumeKMSKeyId","{DataVolumeKMSKeyId}"),

    # ── Redshift ──────────────────────────────────────────────────────────────
    _aws("redshift.cluster",  "contained_by",  "ec2.vpc",            "VpcId",           "arn:aws:ec2:{region}:{account_id}:vpc/{VpcId}"),
    _aws("redshift.cluster",  "attached_to",   "ec2.security-group", "VpcSecurityGroups","arn:aws:ec2:{region}:{account_id}:security-group/{VpcSecurityGroupId}", item="VpcSecurityGroupId"),
    _aws("redshift.cluster",  "encrypted_by",  "kms.key",            "KmsKeyId",        "{KmsKeyId}"),

    # ── Athena ────────────────────────────────────────────────────────────────
    _aws("athena.workgroup",  "encrypted_by",    "kms.key",    "Configuration.ResultConfiguration.EncryptionConfiguration.KmsKey", "{KmsKey}"),
    _aws("athena.workgroup",  "stores_data_in",  "s3.bucket",  "Configuration.ResultConfiguration.OutputLocation", "arn:aws:s3:::{OutputLocation}"),

    # ── SSM ───────────────────────────────────────────────────────────────────
    _aws("ssm.parameter",  "encrypted_by",  "kms.key",  "KeyId",  "{KeyId}"),

    # ── WAF ───────────────────────────────────────────────────────────────────
    _aws("waf.web-acl",  "protected_by",  "cloudfront.distribution", "ARN", "{ARN}"),
]


# ──────────────────────────────────────────────────────────────────────────────
# Source 4: Curated rules for Azure / GCP / OCI / IBM / AliCloud / K8s
# ──────────────────────────────────────────────────────────────────────────────

def _csp_rule(
    csp: str,
    from_rt: str,
    rel: str,
    to_rt: str,
    field: str,
    pattern: str,
    item: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "csp":               csp,
        "service":           from_rt.split(".")[0],
        "from_resource_type": from_rt,
        "relation_type":     rel,
        "to_resource_type":  to_rt,
        "source_field":      field,
        "source_field_item": item,
        "target_uid_pattern": pattern,
        "rule_source":       "curated",
        "rule_metadata":     json.dumps({}),
    }


AZURE_CURATED_RULES: List[Dict[str, Any]] = [
    # Virtual Machines (azure.virtual_machine)
    _csp_rule("azure", "azure.virtual_machine",    "attached_to",   "azure.network_interface",   "properties.networkProfile.networkInterfaces", "{id}", item="id"),
    _csp_rule("azure", "azure.virtual_machine",    "uses",          "azure.disk",                "properties.storageProfile.osDisk.managedDisk.id", "{id}"),
    _csp_rule("azure", "azure.virtual_machine",    "uses",          "azure.disk",                "properties.storageProfile.dataDisks", "{managedDisk.id}", item="managedDisk.id"),
    _csp_rule("azure", "azure.virtual_machine",    "uses",          "azure.managed_identity",    "identity.userAssignedIdentities", "{id}"),
    _csp_rule("azure", "azure.virtual_machine",    "contained_by",  "azure.resource_group",      "resourceGroup", "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}"),
    # Managed Disks (azure.disk)
    _csp_rule("azure", "azure.disk",               "encrypted_by",  "azure.key_vault",           "properties.encryption.diskEncryptionSetId", "{diskEncryptionSetId}"),
    # Network Interfaces (azure.network_interface)
    _csp_rule("azure", "azure.network_interface",  "contained_by",  "azure.virtual_network",     "properties.ipConfigurations.properties.subnet.id", "{id}"),
    _csp_rule("azure", "azure.network_interface",  "attached_to",   "azure.network_security_group","properties.networkSecurityGroup.id", "{id}"),
    # NSG (azure.network_security_group)
    _csp_rule("azure", "azure.network_security_group","contained_by","azure.virtual_network",    "properties.subnets", "{id}", item="id"),
    # SQL Databases (azure.sql_database)
    _csp_rule("azure", "azure.sql_database",       "contained_by",  "azure.sql_server",          "id", "arn:azure:sql:{region}:{account_id}:server/{serverName}"),
    _csp_rule("azure", "azure.sql_database",       "encrypted_by",  "azure.key_vault",           "properties.transparentDataEncryption.keyUri", "{keyUri}"),
    # SQL Server (azure.sql_server)
    _csp_rule("azure", "azure.sql_server",         "contained_by",  "azure.resource_group",      "resourceGroup", "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}"),
    # Storage Accounts (azure.storage_account)
    _csp_rule("azure", "azure.storage_account",    "encrypted_by",  "azure.key_vault",           "properties.encryption.keyVaultProperties.keyVaultUri", "{keyVaultUri}"),
    _csp_rule("azure", "azure.storage_account",    "contained_by",  "azure.resource_group",      "resourceGroup", "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}"),
    # Key Vault (azure.key_vault)
    _csp_rule("azure", "azure.key_vault",          "contained_by",  "azure.virtual_network",     "properties.networkAcls.virtualNetworkRules", "{virtualNetworkResourceId}", item="virtualNetworkResourceId"),
    _csp_rule("azure", "azure.key_vault",          "contained_by",  "azure.resource_group",      "resourceGroup", "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}"),
    # App Service (azure.app_service)
    _csp_rule("azure", "azure.app_service",        "contained_by",  "azure.virtual_network",     "properties.virtualNetworkSubnetId", "{virtualNetworkSubnetId}"),
    _csp_rule("azure", "azure.app_service",        "uses",          "azure.managed_identity",    "identity.userAssignedIdentities", "{id}"),
    _csp_rule("azure", "azure.app_service",        "logging_enabled_to","azure.log_analytics_workspace","properties.siteConfig.appSettings", "{APPLICATIONINSIGHTS_CONNECTION_STRING}"),
    # AKS (azure.aks_cluster)
    _csp_rule("azure", "azure.aks_cluster",        "contained_by",  "azure.virtual_network",     "properties.agentPoolProfiles.vnetSubnetID", "{vnetSubnetID}"),
    _csp_rule("azure", "azure.aks_cluster",        "uses",          "azure.key_vault",            "properties.addonProfiles.azureKeyvaultSecretsProvider.identity.clientId", "{clientId}"),
    _csp_rule("azure", "azure.aks_cluster",        "contained_by",  "azure.resource_group",       "resourceGroup", "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}"),
    # Blob Container (azure.blob_container)
    _csp_rule("azure", "azure.blob_container",     "contained_by",  "azure.storage_account",     "id", "{storageAccountId}"),
]

GCP_CURATED_RULES: List[Dict[str, Any]] = [
    # Compute Instances (gcp.compute_instance)
    _csp_rule("gcp", "gcp.compute_instance",       "contained_by",  "gcp.vpc_network",           "networkInterfaces.network",    "{network}"),
    _csp_rule("gcp", "gcp.compute_instance",       "attached_to",   "gcp.vpc_subnetwork",        "networkInterfaces.subnetwork", "{subnetwork}"),
    _csp_rule("gcp", "gcp.compute_instance",       "uses",          "gcp.iam_service_account",   "serviceAccounts.email",        "{email}"),
    _csp_rule("gcp", "gcp.compute_instance",       "uses",          "gcp.compute_disk",          "disks.source",                 "{source}"),
    # GKE (gcp.gke_cluster)
    _csp_rule("gcp", "gcp.gke_cluster",            "contained_by",  "gcp.vpc_network",           "network",                      "{network}"),
    _csp_rule("gcp", "gcp.gke_cluster",            "uses",          "gcp.iam_service_account",   "nodeConfig.serviceAccount",    "{serviceAccount}"),
    # Cloud Functions (gcp.cloud_function)
    _csp_rule("gcp", "gcp.cloud_function",         "uses",          "gcp.iam_service_account",   "serviceAccountEmail",          "{serviceAccountEmail}"),
    _csp_rule("gcp", "gcp.cloud_function",         "contained_by",  "gcp.vpc_network",           "vpcConnector",                 "{vpcConnector}"),
    _csp_rule("gcp", "gcp.cloud_function",         "triggers",      "gcp.pubsub_topic",          "eventTrigger.resource",        "{resource}"),
    # Cloud SQL (gcp.cloud_sql_instance)
    _csp_rule("gcp", "gcp.cloud_sql_instance",     "contained_by",  "gcp.vpc_network",           "settings.ipConfiguration.privateNetwork", "{privateNetwork}"),
    # GCS Buckets (gcp.gcs_bucket)
    _csp_rule("gcp", "gcp.gcs_bucket",             "encrypted_by",  "gcp.kms_crypto_key",        "encryption.defaultKmsKeyName", "{defaultKmsKeyName}"),
    _csp_rule("gcp", "gcp.gcs_bucket",             "logging_enabled_to","gcp.gcs_bucket",         "logging.logBucket",            "gs://{logBucket}"),
    # BigQuery (gcp.bigquery_dataset)
    _csp_rule("gcp", "gcp.bigquery_dataset",       "encrypted_by",  "gcp.kms_crypto_key",        "defaultEncryptionConfiguration.kmsKeyName", "{kmsKeyName}"),
    # Pub/Sub (gcp.pubsub_subscription)
    _csp_rule("gcp", "gcp.pubsub_subscription",    "subscribes_to", "gcp.pubsub_topic",          "topic",                        "{topic}"),
    # Cloud Run (gcp.cloud_run_service)
    _csp_rule("gcp", "gcp.cloud_run_service",      "uses",          "gcp.iam_service_account",   "spec.template.spec.serviceAccountName", "{serviceAccountName}"),
    # KMS (gcp.kms_crypto_key)
    _csp_rule("gcp", "gcp.kms_crypto_key",         "contained_by",  "gcp.kms_key_ring",          "name",                         "{name}"),
]

OCI_CURATED_RULES: List[Dict[str, Any]] = [
    _csp_rule("oci", "core.instances",             "contained_by",  "core.vcns",                 "subnetId",          "ocid1.subnet.oc1..{subnetId}"),
    _csp_rule("oci", "core.instances",             "attached_to",   "core.networksecuritygroups","nsgIds",            "{item}"),
    _csp_rule("oci", "core.instances",             "uses",          "identity.compartments",     "compartmentId",     "ocid1.compartment.oc1..{compartmentId}"),
    _csp_rule("oci", "database.dbsystems",         "contained_by",  "core.subnets",              "subnetId",          "ocid1.subnet.oc1..{subnetId}"),
    _csp_rule("oci", "database.dbsystems",         "encrypted_by",  "keymanagement.keys",        "kmsKeyId",          "ocid1.key.oc1..{kmsKeyId}"),
    _csp_rule("oci", "objectstorage.buckets",      "encrypted_by",  "keymanagement.keys",        "kmsKeyId",          "ocid1.key.oc1..{kmsKeyId}"),
    _csp_rule("oci", "loadbalancer.loadbalancers", "contained_by",  "core.subnets",              "subnetIds",         "ocid1.subnet.oc1..{item}"),
]

IBM_CURATED_RULES: List[Dict[str, Any]] = [
    _csp_rule("ibm", "is.instance",                "contained_by",  "is.vpc",                    "vpc.id",            "crn:v1:bluemix:public:is:{region}:a/{account_id}:vpc:{id}"),
    _csp_rule("ibm", "is.instance",                "attached_to",   "is.security-group",         "network_interfaces.security_groups", "{crn}", item="crn"),
    _csp_rule("ibm", "is.instance",                "uses",          "iam.service-id",            "profile.href",      "{profile.href}"),
    _csp_rule("ibm", "databases.postgresql",       "encrypted_by",  "kms.keys",                  "key_protect_key_id","{key_protect_key_id}"),
    _csp_rule("ibm", "resource.instances",         "contained_by",  "resource.groups",           "resource_group_id", "crn:v1:bluemix:public:resource-controller:{region}:a/{account_id}:resource-group:{resource_group_id}"),
]

ALICLOUD_CURATED_RULES: List[Dict[str, Any]] = [
    _csp_rule("alicloud", "ecs.instance",          "contained_by",  "vpc.vpc",                   "VpcId",             "acs:vpc:{region}:{account_id}:vpc/{VpcId}"),
    _csp_rule("alicloud", "ecs.instance",          "attached_to",   "ecs.security-group",        "SecurityGroupIds.SecurityGroupId", "acs:ecs:{region}:{account_id}:securitygroup/{item}"),
    _csp_rule("alicloud", "ecs.instance",          "uses",          "ram.role",                  "RamRoleName",       "acs:ram::{account_id}:role/{RamRoleName}"),
    _csp_rule("alicloud", "rds.instance",          "contained_by",  "vpc.vpc",                   "VpcId",             "acs:vpc:{region}:{account_id}:vpc/{VpcId}"),
    _csp_rule("alicloud", "oss.bucket",            "encrypted_by",  "kms.key",                   "ServerSideEncryption.KMSMasterKeyID", "{KMSMasterKeyID}"),
    _csp_rule("alicloud", "cs.cluster",            "contained_by",  "vpc.vpc",                   "vpc_id",            "acs:vpc:{region}:{account_id}:vpc/{vpc_id}"),
]

K8S_CURATED_RULES: List[Dict[str, Any]] = [
    # Deployments (k8s.deployment)
    _csp_rule("k8s", "k8s.deployment",        "member_of",       "k8s.namespace",       "metadata.namespace", "k8s:namespace/{namespace}"),
    _csp_rule("k8s", "k8s.deployment",        "uses",            "k8s.serviceaccount",  "spec.template.spec.serviceAccountName", "k8s:{namespace}/serviceaccount/{serviceAccountName}"),
    # Pods (k8s.pod)
    _csp_rule("k8s", "k8s.pod",               "member_of",       "k8s.namespace",       "metadata.namespace", "k8s:namespace/{namespace}"),
    _csp_rule("k8s", "k8s.pod",               "uses",            "k8s.serviceaccount",  "spec.serviceAccountName", "k8s:{namespace}/serviceaccount/{serviceAccountName}"),
    _csp_rule("k8s", "k8s.pod",               "uses",            "k8s.secret",          "spec.volumes.secret.secretName", "k8s:{namespace}/secret/{secretName}"),
    _csp_rule("k8s", "k8s.pod",               "uses",            "k8s.configmap",       "spec.volumes.configMap.name", "k8s:{namespace}/configmap/{name}"),
    # Ingress (k8s.ingress)
    _csp_rule("k8s", "k8s.ingress",           "serves_traffic_for","k8s.service",       "spec.rules.http.paths.backend.service.name", "k8s:{namespace}/service/{name}"),
    # RBAC (k8s.clusterrolebinding, k8s.rolebinding)
    _csp_rule("k8s", "k8s.clusterrolebinding","grants_access_to", "k8s.clusterrole",    "roleRef.name",      "k8s:clusterrole/{name}"),
    _csp_rule("k8s", "k8s.rolebinding",       "grants_access_to", "k8s.role",           "roleRef.name",      "k8s:{namespace}/role/{name}"),
    # Jobs (k8s.job/k8s.cronjob)
    _csp_rule("k8s", "k8s.job",               "member_of",        "k8s.namespace",      "metadata.namespace","k8s:namespace/{namespace}"),
    # StatefulSets (k8s.statefulset)
    _csp_rule("k8s", "k8s.statefulset",       "uses",             "k8s.persistentvolumeclaim","spec.volumeClaimTemplates.metadata.name","k8s:{namespace}/persistentvolumeclaim/{name}"),
    # Services (k8s.service)
    _csp_rule("k8s", "k8s.service",           "member_of",        "k8s.namespace",      "metadata.namespace","k8s:namespace/{namespace}"),
    # DaemonSets (k8s.daemonset)
    _csp_rule("k8s", "k8s.daemonset",         "uses",             "k8s.serviceaccount", "spec.template.spec.serviceAccountName", "k8s:{namespace}/serviceaccount/{serviceAccountName}"),
    _csp_rule("k8s", "k8s.daemonset",         "member_of",        "k8s.namespace",      "metadata.namespace","k8s:namespace/{namespace}"),
]


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def main(dsn: Optional[str] = None) -> None:
    conn = _connect(dsn)
    total = 0

    # 1. Auto-generate from resource_inventory_identifier (all CSPs)
    log.info("Phase 1/2: auto-generating rules from resource_inventory_identifier …")
    auto_rules = generate_auto_rules(conn)
    total += _upsert_rules(conn, auto_rules, "auto:rii")

    # 2. Curated rules — AWS
    log.info("Phase 2/2: loading curated cross-service rules …")
    total += _upsert_rules(conn, AWS_CURATED_RULES,      "curated:aws")
    total += _upsert_rules(conn, AZURE_CURATED_RULES,    "curated:azure")
    total += _upsert_rules(conn, GCP_CURATED_RULES,      "curated:gcp")
    total += _upsert_rules(conn, OCI_CURATED_RULES,      "curated:oci")
    total += _upsert_rules(conn, IBM_CURATED_RULES,      "curated:ibm")
    total += _upsert_rules(conn, ALICLOUD_CURATED_RULES, "curated:alicloud")
    total += _upsert_rules(conn, K8S_CURATED_RULES,      "curated:k8s")

    conn.close()
    log.info(f"Done. Total rules upserted: {total}")

    # Summary by CSP
    verify_conn = _connect(dsn)
    with verify_conn.cursor() as cur:
        cur.execute("""
            SELECT csp, rule_source, COUNT(*) AS n
            FROM resource_security_relationship_rules
            WHERE is_active = TRUE
            GROUP BY csp, rule_source
            ORDER BY csp, rule_source
        """)
        rows = cur.fetchall()
    verify_conn.close()

    log.info("Rule counts by CSP and source:")
    csp_totals: Dict[str, int] = {}
    for (csp, src, n) in rows:
        log.info(f"  {csp:12s}  {src:10s}  {n:5d}")
        csp_totals[csp] = csp_totals.get(csp, 0) + n
    log.info("Totals by CSP:")
    for csp, n in sorted(csp_totals.items()):
        log.info(f"  {csp:12s}  {n:5d}")


if __name__ == "__main__":
    dsn_arg = sys.argv[1] if len(sys.argv) > 1 else None
    main(dsn_arg)
