#!/usr/bin/env python3
"""
Seed asset_category on resource_inventory_identifier.

Classifies resource types by security target value:
  - secrets:      Credential stores (Secrets Manager, KMS, SSM, ACM private)
  - data_store:   Data persistence (S3, RDS, DynamoDB, Redshift, EFS, EBS, ElastiCache)
  - identity:     IAM principals (Roles, Users, Policies, SSO, Cognito)
  - compute:      Execution environments (EC2, Lambda, ECS, EKS, Fargate, Batch)
  - network:      Traffic routing (VPC, ALB/NLB, API Gateway, CloudFront, Route53)
  - messaging:    Event/message flow (SQS, SNS, EventBridge, Kinesis, MSK)
  - monitoring:   Observability (CloudWatch, CloudTrail, Config, GuardDuty)
  - deployment:   CI/CD and registry (CloudFormation, CodePipeline, ECR)
  - governance:   Org policies (Organizations, SCPs, Config Rules)

Run:
    python seed_asset_categories.py
    python seed_asset_categories.py --db-host <host> --db-port 5432
"""

import argparse
import os
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# ── Service → Category Mapping ──────────────────────────────────────────────
# Maps service names (as used in resource_inventory_identifier.service) to
# their asset_category. This covers all major AWS services and common
# multi-cloud equivalents.

SERVICE_CATEGORY_MAP = {
    # -- secrets: Credential/key stores (highest target value) --
    "secretsmanager":   "secrets",
    "ssm":              "secrets",      # SSM Parameter Store
    "kms":              "secrets",
    "acm":              "secrets",      # ACM private keys/certificates
    "acm-pca":          "secrets",

    # -- data_store: Data persistence --
    "s3":               "data_store",
    "rds":              "data_store",
    "dynamodb":         "data_store",
    "redshift":         "data_store",
    "elasticache":      "data_store",
    "efs":              "data_store",
    "fsx":              "data_store",
    "docdb":            "data_store",   # DocumentDB
    "neptune":          "data_store",
    "timestream":       "data_store",
    "qldb":             "data_store",
    "keyspaces":        "data_store",   # Managed Cassandra
    "memorydb":         "data_store",
    "dax":              "data_store",   # DynamoDB Accelerator
    "backup":           "data_store",   # AWS Backup
    "glacier":          "data_store",
    "lakeformation":    "data_store",
    "athena":           "data_store",
    "glue":             "data_store",   # Data catalog + ETL
    "opensearch":       "data_store",
    "es":               "data_store",   # Elasticsearch (legacy)

    # -- identity: IAM principals and auth --
    "iam":              "identity",
    "sso":              "identity",
    "cognito":          "identity",
    "cognito-idp":      "identity",
    "sts":              "identity",
    "ram":              "identity",     # Resource Access Manager
    "identitystore":    "identity",
    "directory":        "identity",     # Directory Service (AD)
    "ds":               "identity",

    # -- compute: Execution environments --
    "ec2":              "compute",
    "lambda":           "compute",
    "ecs":              "compute",
    "eks":              "compute",
    "fargate":          "compute",
    "batch":            "compute",
    "lightsail":        "compute",
    "apprunner":        "compute",
    "emr":              "compute",
    "sagemaker":        "compute",
    "bedrock":          "compute",
    "beanstalk":        "compute",
    "elasticbeanstalk": "compute",

    # -- network: Traffic routing and boundaries --
    "vpc":              "network",      # VPC as service (some catalogs)
    "elb":              "network",      # Classic LB
    "elbv2":            "network",      # ALB/NLB
    "apigateway":       "network",
    "apigatewayv2":     "network",
    "cloudfront":       "network",
    "route53":          "network",
    "globalaccelerator":"network",
    "directconnect":    "network",
    "networkfirewall":  "network",
    "waf":              "network",
    "wafv2":            "network",
    "shield":           "network",
    "appmesh":          "network",
    "servicediscovery": "network",
    "transitgateway":   "network",

    # -- messaging: Event and message flow --
    "sqs":              "messaging",
    "sns":              "messaging",
    "eventbridge":      "messaging",
    "events":           "messaging",    # CloudWatch Events (legacy name)
    "kinesis":          "messaging",
    "firehose":         "messaging",
    "msk":              "messaging",    # Managed Kafka
    "mq":               "messaging",   # Amazon MQ
    "ses":              "messaging",    # SES (email)
    "pinpoint":         "messaging",
    "iot":              "messaging",
    "iotevents":        "messaging",
    "stepfunctions":    "messaging",    # Step Functions orchestration
    "states":           "messaging",

    # -- monitoring: Observability and detection --
    "cloudwatch":       "monitoring",
    "logs":             "monitoring",   # CloudWatch Logs
    "cloudtrail":       "monitoring",
    "config":           "monitoring",
    "guardduty":        "monitoring",
    "securityhub":      "monitoring",
    "inspector":        "monitoring",
    "macie":            "monitoring",
    "detective":        "monitoring",
    "xray":             "monitoring",
    "healthlake":       "monitoring",

    # -- deployment: CI/CD, IaC, registries --
    "cloudformation":   "deployment",
    "codepipeline":     "deployment",
    "codebuild":        "deployment",
    "codecommit":       "deployment",
    "codedeploy":       "deployment",
    "codeartifact":     "deployment",
    "ecr":              "deployment",   # Container registry
    "proton":           "deployment",
    "appconfig":        "deployment",

    # -- governance: Organization policies --
    "organizations":    "governance",
    "controltower":     "governance",
    "servicecatalog":   "governance",
    "budgets":          "governance",
    "costexplorer":     "governance",
    "account":          "governance",
    "accessanalyzer":   "governance",
    "trustedadvisor":   "governance",
    "wellarchitected":  "governance",
    "audit":            "governance",   # Audit Manager
    "auditmanager":     "governance",

    # -- Multi-cloud equivalents --
    # Azure
    "keyvault":         "secrets",
    "storage":          "data_store",
    "cosmosdb":         "data_store",
    "sqldatabase":      "data_store",
    "activedirectory":  "identity",
    "virtualmachines":  "compute",
    "functions":        "compute",
    "aks":              "compute",
    "containerinstances": "compute",
    "loadbalancer":     "network",
    "applicationgateway": "network",
    "frontdoor":        "network",
    "servicebus":       "messaging",
    "eventhub":         "messaging",
    "monitor":          "monitoring",
    "sentinel":         "monitoring",
    "devops":           "deployment",

    # GCP
    "secretmanager":    "secrets",
    "cloudstorage":     "data_store",
    "bigtable":         "data_store",
    "spanner":          "data_store",
    "firestore":        "data_store",
    "cloudsql":         "data_store",
    "bigquery":         "data_store",
    "computeengine":    "compute",
    "cloudfunctions":   "compute",
    "cloudrun":         "compute",
    "gke":              "compute",
    "pubsub":           "messaging",
    "cloudlogging":     "monitoring",
    "cloudmonitoring":  "monitoring",
    "cloudbuild":       "deployment",
    "artifactregistry": "deployment",
}

# ── Resource-type level overrides ────────────────────────────────────────────
# Some resource types within a service have a different category than the
# service default. E.g., ec2 is "compute" but ec2.vpc is "network".
RESOURCE_TYPE_OVERRIDES = {
    # ec2 sub-resources that are network, not compute
    "vpc":                  "network",
    "subnet":               "network",
    "security-group":       "network",
    "security_group":       "network",
    "network-interface":    "network",
    "network_interface":    "network",
    "internet-gateway":     "network",
    "internet_gateway":     "network",
    "nat-gateway":          "network",
    "nat_gateway":          "network",
    "route-table":          "network",
    "route_table":          "network",
    "network-acl":          "network",
    "network_acl":          "network",
    "transit-gateway":      "network",
    "transit_gateway":      "network",
    "vpn-gateway":          "network",
    "vpn_gateway":          "network",
    "vpn-connection":       "network",
    "vpn_connection":       "network",
    "elastic-ip":           "network",
    "eip":                  "network",
    "prefix-list":          "network",

    # ec2 sub-resources that are data_store
    "volume":               "data_store",
    "snapshot":             "data_store",
    "image":                "data_store",   # AMI

    # iam sub-resources
    "role":                 "identity",
    "user":                 "identity",
    "group":                "identity",
    "policy":               "identity",
    "instance-profile":     "identity",
    "instance_profile":     "identity",
    "access-key":           "identity",
    "access_key":           "identity",
    "mfa-device":           "identity",
    "saml-provider":        "identity",
    "oidc-provider":        "identity",

    # Lambda layers are still compute
    "layer":                "compute",
    "function":             "compute",
}


def _conn_string(args) -> str:
    host = args.db_host or os.getenv("INVENTORY_DB_HOST", "localhost")
    port = args.db_port or os.getenv("INVENTORY_DB_PORT", "5432")
    db = args.db_name or os.getenv("INVENTORY_DB_NAME", "threat_engine_inventory")
    user = args.db_user or os.getenv("INVENTORY_DB_USER", "inventory_user")
    pwd = args.db_password or os.getenv("INVENTORY_DB_PASSWORD", "inventory_password")
    return f"postgresql://{user}:{pwd}@{host}:{port}/{db}"


def seed(args):
    import psycopg2
    from psycopg2.extras import RealDictCursor

    conn_str = _conn_string(args)
    logger.info(f"Connecting to: {conn_str.split('@')[1]}")
    conn = psycopg2.connect(conn_str)

    try:
        # Add column if missing
        with conn.cursor() as cur:
            cur.execute("""
                SELECT column_name FROM information_schema.columns
                WHERE table_name = 'resource_inventory_identifier'
                  AND column_name = 'asset_category'
            """)
            if not cur.fetchone():
                logger.info("Adding asset_category column...")
                cur.execute("""
                    ALTER TABLE resource_inventory_identifier
                    ADD COLUMN asset_category VARCHAR(50)
                """)
                conn.commit()
                logger.info("Column added.")
            else:
                logger.info("Column asset_category already exists.")

        # Load all rows
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT id, csp, service, resource_type FROM resource_inventory_identifier")
            rows = cur.fetchall()

        logger.info(f"Processing {len(rows)} resource types...")

        updated = 0
        with conn.cursor() as cur:
            for row in rows:
                service = (row["service"] or "").lower()
                resource_type = (row["resource_type"] or "").lower()

                # 1. Check resource_type override first (e.g., "vpc" → network even though service=ec2)
                category = RESOURCE_TYPE_OVERRIDES.get(resource_type)

                # 2. Fall back to service-level mapping
                if category is None:
                    category = SERVICE_CATEGORY_MAP.get(service)

                if category:
                    cur.execute("""
                        UPDATE resource_inventory_identifier
                        SET    asset_category = %s,
                               updated_at = NOW()
                        WHERE  id = %s
                          AND  (asset_category IS DISTINCT FROM %s)
                    """, (category, row["id"], category))
                    if cur.rowcount > 0:
                        updated += 1

        conn.commit()
        logger.info(f"Updated {updated} / {len(rows)} resource types")

        # Summary
        with conn.cursor() as cur:
            cur.execute("""
                SELECT asset_category, COUNT(*)
                FROM resource_inventory_identifier
                GROUP BY asset_category
                ORDER BY asset_category NULLS LAST
            """)
            logger.info("\n── Summary ──")
            for row in cur.fetchall():
                cat = row[0] or "NULL (uncategorized)"
                logger.info(f"  {cat:20s} {row[1]:5d} resource types")

    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(description="Seed asset_category on resource_inventory_identifier")
    parser.add_argument("--db-host", help="DB host (or INVENTORY_DB_HOST env)")
    parser.add_argument("--db-port", help="DB port (or INVENTORY_DB_PORT env)")
    parser.add_argument("--db-name", help="DB name (or INVENTORY_DB_NAME env)")
    parser.add_argument("--db-user", help="DB user (or INVENTORY_DB_USER env)")
    parser.add_argument("--db-password", help="DB password (or INVENTORY_DB_PASSWORD env)")
    args = parser.parse_args()
    seed(args)


if __name__ == "__main__":
    main()
