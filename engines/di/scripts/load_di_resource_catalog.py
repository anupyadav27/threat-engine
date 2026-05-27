"""
load_di_resource_catalog.py
===========================
Populates di_resource_catalog and di_relationship_rules in threat_engine_di.

Filter rule (strict):
  Only services that have is_active = TRUE in rule_discoveries are loaded.
  Only resource_types marked classification = PRIMARY_RESOURCE or can_inventory_from_roots
  within those services are included.  No extra services, no orphan resource types.

Sources:
  1. rule_discoveries (check DB)  → active services per CSP
  2. catalog/discovery_generator_data/{csp}/{service}/step5_resource_catalog_inventory_enrich.json
     → classification, has_arn, root_ops, enrich_ops, identifier metadata
  3. service_classification (inventory DB) → category, scope, model, encryption_scope etc.
  4. resource_security_relationship_rules (inventory DB) → edge definitions (filtered to
     active services only)

Usage:
    python3 engines/di/scripts/load_di_resource_catalog.py
    python3 engines/di/scripts/load_di_resource_catalog.py --csp aws
    python3 engines/di/scripts/load_di_resource_catalog.py --dry-run
    python3 engines/di/scripts/load_di_resource_catalog.py --catalog-path /custom/path

Environment (same vars used by engine-di pod):
    DI_DB_HOST / DI_DB_NAME / DI_DB_USER / DI_DB_PASSWORD
    CHECK_DB_HOST / CHECK_DB_NAME / CHECK_DB_USER / CHECK_DB_PASSWORD
    INVENTORY_DB_HOST / INVENTORY_DB_NAME / INVENTORY_DB_USER / INVENTORY_DB_PASSWORD
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import psycopg2
import psycopg2.extras

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
logger = logging.getLogger("di.load_catalog")

# ── Repo catalog base (relative to script's parent-parent-parent = repo root) ─
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
_DEFAULT_CATALOG = _REPO_ROOT / "catalog" / "discovery_generator_data"


# ── DB helpers ────────────────────────────────────────────────────────────────

def _conn(host_env: str, name_env: str, user_env: str, pw_env: str,
          fallback_host: str = "DI_DB_HOST", fallback_pw: str = "DI_DB_PASSWORD"):
    host = os.environ.get(host_env) or os.environ.get(fallback_host)
    name = os.environ.get(name_env)
    user = os.environ.get(user_env, "postgres")
    pw   = os.environ.get(pw_env)  or os.environ.get(fallback_pw, "")
    return psycopg2.connect(host=host, port=5432, dbname=name, user=user,
                            password=pw, sslmode="prefer", connect_timeout=10)


def _di_conn():
    return _conn("DI_DB_HOST", "DI_DB_NAME", "DI_DB_USER", "DI_DB_PASSWORD")


def _check_conn():
    return _conn("CHECK_DB_HOST", "CHECK_DB_NAME", "CHECK_DB_USER",
                 "CHECK_DB_PASSWORD", "DI_DB_HOST", "DI_DB_PASSWORD")


def _inv_conn():
    return _conn("INVENTORY_DB_HOST", "INVENTORY_DB_NAME", "INVENTORY_DB_USER",
                 "INVENTORY_DB_PASSWORD", "DI_DB_HOST", "DI_DB_PASSWORD")


# ── Service → (category, subcategory) fallback map ───────────────────────────
#
# Applied after step5 parse + service_classification enrichment, only where
# category is still NULL.  Keys are the service folder names used in
# rule_discoveries.service (e.g. "ec2", "s3", "rds").
#
# Category values must match the CHECK constraint on di_resource_catalog:
#   compute | network | storage | database | security | identity | monitoring
#   | container | encryption | analytics | ai_ml | messaging | iot
#
_SERVICE_TO_CATEGORY: Dict[str, Dict[str, Tuple[str, str]]] = {
    # ── AWS ──────────────────────────────────────────────────────────────────
    "aws": {
        # compute
        "ec2":                          ("compute",    "virtual_machine"),
        "autoscaling":                  ("compute",    "virtual_machine"),
        "lightsail":                    ("compute",    "virtual_machine"),
        "lambda":                       ("compute",    "serverless"),
        "ecs":                          ("compute",    "container_workload"),
        "fargate":                      ("compute",    "container_workload"),
        "apprunner":                    ("compute",    "serverless"),
        "elasticbeanstalk":             ("compute",    "managed"),
        "batch":                        ("compute",    "batch"),
        "outposts":                     ("compute",    "virtual_machine"),
        "imagebuilder":                 ("compute",    "managed"),
        "serverlessrepo":               ("compute",    "serverless"),
        "m2":                           ("compute",    "managed"),
        # storage
        "s3":                           ("storage",    "object"),
        "s3control":                    ("storage",    "object"),
        "s3express":                    ("storage",    "object"),
        "s3outposts":                   ("storage",    "object"),
        "s3tables":                     ("storage",    "object"),
        "s3vectors":                    ("storage",    "object"),
        "s3-object-lambda":             ("storage",    "object"),
        "ebs":                          ("storage",    "block"),
        "efs":                          ("storage",    "file"),
        "elasticfilesystem":            ("storage",    "file"),
        "fsx":                          ("storage",    "file"),
        "storagegateway":               ("storage",    "managed"),
        "backup":                       ("storage",    "backup"),
        "glacier":                      ("storage",    "archive"),
        "datasync":                     ("storage",    "managed"),
        "snow-device-management":       ("storage",    "managed"),
        "snowball":                     ("storage",    "managed"),
        "dlm":                          ("storage",    "backup"),
        "drs":                          ("storage",    "backup"),
        "backupsearch":                 ("storage",    "backup"),
        "backup-gateway":               ("storage",    "backup"),
        # database
        "rds":                          ("database",   "relational"),
        "rds-data":                     ("database",   "relational"),
        "docdb":                        ("database",   "nosql"),
        "docdb-elastic":                ("database",   "nosql"),
        "dynamodb":                     ("database",   "nosql"),
        "dynamodbstreams":              ("database",   "nosql"),
        "dax":                          ("database",   "cache"),
        "elasticache":                  ("database",   "cache"),
        "neptune":                      ("database",   "nosql"),
        "neptune-db":                   ("database",   "nosql"),
        "neptune-graph":                ("database",   "nosql"),
        "neptunedata":                  ("database",   "nosql"),
        "memorydb":                     ("database",   "cache"),
        "timestream":                   ("database",   "time_series"),
        "timestream-query":             ("database",   "time_series"),
        "timestream-write":             ("database",   "time_series"),
        "timestream-influxdb":          ("database",   "time_series"),
        "qldb":                         ("database",   "nosql"),
        "keyspaces":                    ("database",   "nosql"),
        "keyspacesstreams":             ("database",   "nosql"),
        "cassandra":                    ("database",   "nosql"),
        "redshift":                     ("database",   "warehouse"),
        "redshift-data":                ("database",   "warehouse"),
        "redshift-serverless":          ("database",   "warehouse"),
        "dsql":                         ("database",   "relational"),
        # network
        "vpc":                          ("network",    "vpc"),
        "vpcflowlogs":                  ("network",    "vpc"),
        "vpc-lattice":                  ("network",    "gateway"),
        "vpn":                          ("network",    "vpn"),
        "directconnect":                ("network",    "vpn"),
        "elb":                          ("network",    "load_balancer"),
        "elbv2":                        ("network",    "load_balancer"),
        "elasticloadbalancing":         ("network",    "load_balancer"),
        "globalaccelerator":            ("network",    "load_balancer"),
        "cloudfront":                   ("network",    "cdn"),
        "route53":                      ("network",    "dns"),
        "route53domains":               ("network",    "dns"),
        "route53profiles":              ("network",    "dns"),
        "route53resolver":              ("network",    "dns"),
        "route53-recovery-cluster":     ("network",    "dns"),
        "route53-recovery-control-config": ("network", "dns"),
        "route53-recovery-readiness":   ("network",    "dns"),
        "networkfirewall":              ("network",    "firewall"),
        "network-firewall":             ("network",    "firewall"),
        "waf":                          ("network",    "firewall"),
        "wafv2":                        ("network",    "firewall"),
        "waf-regional":                 ("network",    "firewall"),
        "shield":                       ("network",    "firewall"),
        "apigateway":                   ("network",    "gateway"),
        "apigatewayv2":                 ("network",    "gateway"),
        "apigatewaymanagementapi":      ("network",    "gateway"),
        "execute-api":                  ("network",    "gateway"),
        "appmesh":                      ("network",    "gateway"),
        "servicediscovery":             ("network",    "gateway"),
        "networkmanager":               ("network",    "vpc"),
        "networkflowmonitor":           ("network",    "vpc"),
        "networkmonitor":               ("network",    "vpc"),
        "internetmonitor":              ("network",    "vpc"),
        "eip":                          ("network",    "vpc"),
        "arc-region-switch":            ("network",    "vpc"),
        "arc-zonal-shift":              ("network",    "vpc"),
        "oam":                          ("network",    "vpc"),
        # security
        "guardduty":                    ("security",   "siem"),
        "securityhub":                  ("security",   "posture"),
        "inspector":                    ("security",   "vulnerability"),
        "inspector2":                   ("security",   "vulnerability"),
        "inspector-scan":               ("security",   "vulnerability"),
        "detective":                    ("security",   "siem"),
        "macie":                        ("security",   "posture"),
        "macie2":                       ("security",   "posture"),
        "config":                       ("security",   "posture"),
        "trustedadvisor":               ("security",   "posture"),
        "accessanalyzer":               ("security",   "posture"),
        "access-analyzer":              ("security",   "posture"),
        "security-ir":                  ("security",   "siem"),
        "securitylake":                 ("security",   "siem"),
        "auditmanager":                 ("security",   "posture"),
        "artifact":                     ("security",   "posture"),
        "verifiedpermissions":          ("security",   "posture"),
        "fms":                          ("security",   "posture"),
        "resiliencehub":                ("security",   "posture"),
        "wellarchitected":              ("security",   "posture"),
        "controltower":                 ("security",   "posture"),
        "controlcatalog":               ("security",   "posture"),
        "pca-connector-ad":             ("security",   "posture"),
        "pca-connector-scep":          ("security",   "posture"),
        "signer":                       ("security",   "posture"),
        # identity
        "iam":                          ("identity",   "iam"),
        "sso":                          ("identity",   "federation"),
        "sso-admin":                    ("identity",   "federation"),
        "identitycenter":               ("identity",   "federation"),
        "identitystore":                ("identity",   "iam"),
        "cognito":                      ("identity",   "federation"),
        "cognito-identity":             ("identity",   "federation"),
        "cognito-idp":                  ("identity",   "federation"),
        "cognito-sync":                 ("identity",   "federation"),
        "rolesanywhere":                ("identity",   "iam"),
        "ds":                           ("identity",   "directory"),
        "directoryservice":             ("identity",   "directory"),
        "ds-data":                      ("identity",   "directory"),
        # monitoring
        "cloudwatch":                   ("monitoring", "metrics"),
        "cloudtrail":                   ("monitoring", "logs"),
        "cloudtrail-data":              ("monitoring", "logs"),
        "logs":                         ("monitoring", "logs"),
        "xray":                         ("monitoring", "tracing"),
        "applicationinsights":          ("monitoring", "metrics"),
        "application-insights":         ("monitoring", "metrics"),
        "application-signals":          ("monitoring", "metrics"),
        "rum":                          ("monitoring", "metrics"),
        "synthetics":                   ("monitoring", "metrics"),
        "compute-optimizer":            ("monitoring", "metrics"),
        "compute-optimizer-automation": ("monitoring", "metrics"),
        "evidently":                    ("monitoring", "metrics"),
        "observabilityadmin":           ("monitoring", "metrics"),
        # container
        "eks":                          ("container",  "orchestration_managed"),
        "eks-auth":                     ("container",  "orchestration_managed"),
        "ecr":                          ("container",  "registry"),
        "ecr-public":                   ("container",  "registry"),
        # encryption
        "kms":                          ("encryption", "kms"),
        "secretsmanager":               ("encryption", "secrets"),
        "acm":                          ("encryption", "certificates"),
        "acm-pca":                      ("encryption", "certificates"),
        "cloudhsm":                     ("encryption", "kms"),
        "cloudhsmv2":                   ("encryption", "kms"),
        "payment-cryptography":         ("encryption", "kms"),
        "payment-cryptography-data":    ("encryption", "kms"),
        # analytics
        "athena":                       ("analytics",  "query"),
        "glue":                         ("analytics",  "etl"),
        "lakeformation":                ("analytics",  "warehouse"),
        "kinesis":                      ("analytics",  "streaming"),
        "kinesisfirehose":              ("analytics",  "streaming"),
        "kinesisvideo":                 ("analytics",  "streaming"),
        "kinesisvideostreams":          ("analytics",  "streaming"),
        "kinesisanalytics":             ("analytics",  "streaming"),
        "kinesisanalyticsv2":           ("analytics",  "streaming"),
        "firehose":                     ("analytics",  "streaming"),
        "quicksight":                   ("analytics",  "bi"),
        "databrew":                     ("analytics",  "etl"),
        "dataexchange":                 ("analytics",  "etl"),
        "datapipeline":                 ("analytics",  "etl"),
        "opensearch":                   ("analytics",  "search"),
        "opensearchserverless":         ("analytics",  "search"),
        "es":                           ("analytics",  "search"),
        "emr":                          ("analytics",  "batch"),
        "emr-containers":               ("analytics",  "batch"),
        "emr-serverless":               ("analytics",  "batch"),
        "elasticmapreduce":             ("analytics",  "batch"),
        "datazone":                     ("analytics",  "warehouse"),
        # ai_ml
        "sagemaker":                    ("ai_ml",      "platform"),
        "sagemaker-a2i-runtime":        ("ai_ml",      "platform"),
        "sagemaker-edge":               ("ai_ml",      "platform"),
        "sagemaker-featurestore-runtime": ("ai_ml",    "platform"),
        "sagemaker-geospatial":         ("ai_ml",      "platform"),
        "sagemaker-metrics":            ("ai_ml",      "platform"),
        "sagemaker-runtime":            ("ai_ml",      "model_serving"),
        "bedrock":                      ("ai_ml",      "model_serving"),
        "bedrock-agent":                ("ai_ml",      "model_serving"),
        "bedrock-agent-runtime":        ("ai_ml",      "model_serving"),
        "bedrock-agentcore":            ("ai_ml",      "model_serving"),
        "bedrock-agentcore-control":    ("ai_ml",      "model_serving"),
        "bedrock-data-automation":      ("ai_ml",      "model_serving"),
        "bedrock-data-automation-runtime": ("ai_ml",   "model_serving"),
        "bedrock-runtime":              ("ai_ml",      "model_serving"),
        "comprehend":                   ("ai_ml",      "nlp"),
        "comprehendmedical":            ("ai_ml",      "nlp"),
        "rekognition":                  ("ai_ml",      "vision"),
        "transcribe":                   ("ai_ml",      "speech"),
        "translate":                    ("ai_ml",      "nlp"),
        "polly":                        ("ai_ml",      "speech"),
        "textract":                     ("ai_ml",      "vision"),
        "forecast":                     ("ai_ml",      "platform"),
        "personalize":                  ("ai_ml",      "platform"),
        "kendra":                       ("ai_ml",      "nlp"),
        "kendra-ranking":               ("ai_ml",      "nlp"),
        "lex-models":                   ("ai_ml",      "nlp"),
        "lexv2-models":                 ("ai_ml",      "nlp"),
        "lexv2-runtime":                ("ai_ml",      "nlp"),
        "lex-runtime":                  ("ai_ml",      "nlp"),
        "braket":                       ("ai_ml",      "platform"),
        "machinelearning":              ("ai_ml",      "platform"),
        "aiops":                        ("ai_ml",      "platform"),
        "lookoutequipment":             ("ai_ml",      "platform"),
        "healthlake":                   ("ai_ml",      "platform"),
        "amp":                          ("ai_ml",      "platform"),
        "medical-imaging":              ("ai_ml",      "vision"),
        "omics":                        ("ai_ml",      "platform"),
        "qbusiness":                    ("ai_ml",      "platform"),
        "qapps":                        ("ai_ml",      "platform"),
        "qconnect":                     ("ai_ml",      "platform"),
        # messaging
        "sns":                          ("messaging",  "topic"),
        "sqs":                          ("messaging",  "queue"),
        "ses":                          ("messaging",  "notification"),
        "sesv2":                        ("messaging",  "notification"),
        "mq":                           ("messaging",  "queue"),
        "events":                       ("messaging",  "event_bus"),
        "eventbridge":                  ("messaging",  "event_bus"),
        "eventschemas":                 ("messaging",  "event_bus"),
        "kafka":                        ("messaging",  "streaming"),
        "kafka-cluster":                ("messaging",  "streaming"),
        "kafkaconnect":                 ("messaging",  "streaming"),
        "msk":                          ("messaging",  "streaming"),
        "appflow":                      ("messaging",  "event_bus"),
        "notifications":                ("messaging",  "notification"),
        "notificationscontacts":        ("messaging",  "notification"),
        "pinpoint":                     ("messaging",  "notification"),
        "pinpoint-email":               ("messaging",  "notification"),
        "pinpoint-sms-voice":           ("messaging",  "notification"),
        "pinpoint-sms-voice-v2":        ("messaging",  "notification"),
        "mailmanager":                  ("messaging",  "notification"),
        "chime":                        ("messaging",  "notification"),
        "connect":                      ("messaging",  "notification"),
        "pipes":                        ("messaging",  "event_bus"),
        "scheduler":                    ("messaging",  "event_bus"),
        # iot
        "iot":                          ("iot",        "device"),
        "iotanalytics":                 ("iot",        "analytics"),
        "iotsitewise":                  ("iot",        "analytics"),
        "iottwinmaker":                 ("iot",        "analytics"),
        "iotthingsgraph":               ("iot",        "device"),
        "iotevents":                    ("iot",        "analytics"),
        "iotevents-data":               ("iot",        "analytics"),
        "iotwireless":                  ("iot",        "device"),
        "greengrass":                   ("iot",        "device"),
        "greengrassv2":                 ("iot",        "device"),
        "iotfleetwise":                 ("iot",        "analytics"),
        "iotdeviceadvisor":             ("iot",        "device"),
        "iotdevicedefender":            ("iot",        "device"),
        "iot-data":                     ("iot",        "device"),
        "iot-jobs-data":                ("iot",        "device"),
        "iot-managed-integrations":     ("iot",        "device"),
        "iotmanagedintegrations":       ("iot",        "device"),
        "iotsecuretunneling":           ("iot",        "device"),
    },

    # ── Azure ────────────────────────────────────────────────────────────────
    "azure": {
        # compute
        "compute":                      ("compute",    "virtual_machine"),
        "virtualmachines":              ("compute",    "virtual_machine"),
        "vm":                           ("compute",    "virtual_machine"),
        "functions":                    ("compute",    "serverless"),
        "functionapp":                  ("compute",    "serverless"),
        "appservice":                   ("compute",    "managed"),
        "app":                          ("compute",    "managed"),
        "web":                          ("compute",    "managed"),
        "batch":                        ("compute",    "batch"),
        "batchai":                      ("compute",    "batch"),
        "servicebus":                   ("messaging",  "queue"),   # mapped below too
        "cloudshell":                   ("compute",    "managed"),
        "computeschedule":              ("compute",    "managed"),
        "computelimit":                 ("compute",    "managed"),
        "desktopvirtualization":        ("compute",    "virtual_machine"),
        "vmware":                       ("compute",    "virtual_machine"),
        "vmwarecloudsimple":            ("compute",    "virtual_machine"),
        "sphere":                       ("compute",    "managed"),
        # storage
        "storage":                      ("storage",    "object"),
        "storageactions":               ("storage",    "object"),
        "storagecache":                 ("storage",    "object"),
        "storagediscovery":             ("storage",    "object"),
        "storageimportexport":          ("storage",    "managed"),
        "storagemover":                 ("storage",    "managed"),
        "storagepool":                  ("storage",    "block"),
        "storagesync":                  ("storage",    "managed"),
        "netappfiles":                  ("storage",    "file"),
        "netapp":                       ("storage",    "file"),
        "elastic":                      ("storage",    "object"),
        "elasticsan":                   ("storage",    "block"),
        "databox":                      ("storage",    "managed"),
        "databoxedge":                  ("storage",    "managed"),
        "recoveryservicesbackup":       ("storage",    "backup"),
        "backup":                       ("storage",    "backup"),
        # database
        "sql":                          ("database",   "relational"),
        "sqlvirtualmachine":            ("database",   "relational"),
        "cosmos":                       ("database",   "nosql"),
        "cosmos-db":                    ("database",   "nosql"),
        "cosmosdb":                     ("database",   "nosql"),
        "mongocluster":                 ("database",   "nosql"),
        "dbforpostgresql":              ("database",   "relational"),
        "dbformysql":                   ("database",   "relational"),
        "dbformariadb":                 ("database",   "relational"),
        "rdbms_postgresql":             ("database",   "relational"),
        "rdbms_postgresql_flexibleservers": ("database", "relational"),
        "rdbms_mysql":                  ("database",   "relational"),
        "rdbms_mysql_flexibleservers":  ("database",   "relational"),
        "rdbms_mariadb":                ("database",   "relational"),
        "cache":                        ("database",   "cache"),
        "redis":                        ("database",   "cache"),
        "redisenterprise":              ("database",   "cache"),
        "hanaonazure":                  ("database",   "relational"),
        "oracle":                       ("database",   "relational"),
        "databasewatcher":              ("database",   "relational"),
        "psql":                         ("database",   "relational"),
        # network
        "network":                      ("network",    "vpc"),
        "networksecuritygroup":         ("network",    "firewall"),
        "networkcloud":                 ("network",    "vpc"),
        "networkfunction":              ("network",    "gateway"),
        "managednetworkfabric":         ("network",    "vpc"),
        "loadbalancer":                 ("network",    "load_balancer"),
        "frontdoor":                    ("network",    "cdn"),
        "cdn":                          ("network",    "cdn"),
        "traffic":                      ("network",    "dns"),
        "trafficmanager":               ("network",    "dns"),
        "dns":                          ("network",    "dns"),
        "privatedns":                   ("network",    "dns"),
        "dnsresolver":                  ("network",    "dns"),
        "vpn":                          ("network",    "vpn"),
        "expressroute":                 ("network",    "vpn"),
        "azure_firewall":               ("network",    "firewall"),
        "ddos_protection":              ("network",    "firewall"),
        "web_application_firewall":     ("network",    "firewall"),
        "waf":                          ("network",    "firewall"),
        "apimanagement":                ("network",    "gateway"),
        "apicenter":                    ("network",    "gateway"),
        "servicelinker":                ("network",    "gateway"),
        "servicenetworking":            ("network",    "gateway"),
        "relay":                        ("network",    "gateway"),
        "hybridconnectivity":           ("network",    "vpc"),
        "hybridnetwork":                ("network",    "vpc"),
        "networksecurityperimeter":     ("network",    "firewall"),
        # security
        "security":                     ("security",   "posture"),
        "securitycenter":               ("security",   "posture"),
        "securityinsights":             ("security",   "siem"),
        "securityinsight":              ("security",   "siem"),
        "sentinel":                     ("security",   "siem"),
        "defender":                     ("security",   "posture"),
        "defender_for_cloud":           ("security",   "posture"),
        "policyinsights":               ("security",   "posture"),
        "policy":                       ("security",   "posture"),
        "guestconfiguration":           ("security",   "posture"),
        "guestconfig":                  ("security",   "posture"),
        "securityandcompliance":        ("security",   "posture"),
        "resourcehealth":               ("security",   "posture"),
        "attestation":                  ("security",   "posture"),
        "confidentialledger":           ("security",   "posture"),
        "appcomplianceautomation":      ("security",   "posture"),
        # identity
        "authorization":                ("identity",   "iam"),
        "iam":                          ("identity",   "iam"),
        "aad":                          ("identity",   "directory"),
        "azureactivedirectory":         ("identity",   "directory"),
        "entrad":                       ("identity",   "directory"),
        "entra":                        ("identity",   "directory"),
        "entra_id_governance":          ("identity",   "iam"),
        "entra_permissions_management": ("identity",   "iam"),
        "managedidentity":              ("identity",   "service_account"),
        "msi":                          ("identity",   "service_account"),
        "domainservices":               ("identity",   "directory"),
        "cpim":                         ("identity",   "federation"),
        # monitoring
        "monitor":                      ("monitoring", "metrics"),
        "loganalytics":                 ("monitoring", "logs"),
        "operationalinsights":          ("monitoring", "logs"),
        "applicationinsights":          ("monitoring", "metrics"),
        "changeanalysis":               ("monitoring", "logs"),
        "workloadmonitor":              ("monitoring", "metrics"),
        "advisorscores":                ("monitoring", "metrics"),
        "advisor":                      ("monitoring", "metrics"),
        # container
        "containerservice":             ("container",  "orchestration_managed"),
        "aks":                          ("container",  "orchestration_managed"),
        "containerregistry":            ("container",  "registry"),
        "cr":                           ("container",  "registry"),
        "containerinstance":            ("container",  "orchestration_managed"),
        "kubernetes":                   ("container",  "orchestration_managed"),
        "kubernetesconfiguration":      ("container",  "orchestration_managed"),
        "kubernetesruntime":            ("container",  "orchestration_managed"),
        "hybridkubernetes":             ("container",  "orchestration_managed"),
        "hybridaks":                    ("container",  "orchestration_managed"),
        "redhatopenshift":              ("container",  "orchestration_managed"),
        "servicebus":                   ("messaging",  "queue"),
        # encryption
        "keyvault":                     ("encryption", "kms"),
        "key":                          ("encryption", "kms"),
        "hardwaresecuritymodules":      ("encryption", "kms"),
        # analytics
        "synapse":                      ("analytics",  "warehouse"),
        "databricks":                   ("analytics",  "batch"),
        "hdinsight":                    ("analytics",  "batch"),
        "hdinsightcontainers":          ("analytics",  "batch"),
        "datafactory":                  ("analytics",  "etl"),
        "dataexchange":                 ("analytics",  "etl"),
        "eventgrid":                    ("analytics",  "streaming"),
        "eventhub":                     ("analytics",  "streaming"),
        "streamanalytics":              ("analytics",  "streaming"),
        "timeseriesinsights":           ("analytics",  "streaming"),
        "kusto":                        ("analytics",  "query"),
        "azure-kusto":                  ("analytics",  "query"),
        "datalake-analytics":           ("analytics",  "warehouse"),
        "datalake-store":               ("analytics",  "warehouse"),
        "datalakeanalytics":            ("analytics",  "warehouse"),
        "datashare":                    ("analytics",  "etl"),
        "datacatalog":                  ("analytics",  "warehouse"),
        "purview":                      ("analytics",  "warehouse"),
        "fabric":                       ("analytics",  "warehouse"),
        # ai_ml
        "cognitiveservices":            ("ai_ml",      "model_serving"),
        "machinelearning":              ("ai_ml",      "platform"),
        "machinelearningservices":      ("ai_ml",      "platform"),
        "aisearch":                     ("ai_ml",      "nlp"),
        "search":                       ("ai_ml",      "nlp"),
        "botservice":                   ("ai_ml",      "nlp"),
        "azure_openai":                 ("ai_ml",      "model_serving"),
        "azureopenai":                  ("ai_ml",      "model_serving"),
        "openai":                       ("ai_ml",      "model_serving"),
        "healthbot":                    ("ai_ml",      "nlp"),
        "healthcareapis":               ("ai_ml",      "platform"),
        "healthdataaiservices":         ("ai_ml",      "platform"),
        # messaging
        "notification":                 ("messaging",  "notification"),
        "notificationhubs":             ("messaging",  "notification"),
        "webpubsub":                    ("messaging",  "notification"),
        "signalr":                      ("messaging",  "notification"),
        "communication":                ("messaging",  "notification"),
    },

    # ── GCP ──────────────────────────────────────────────────────────────────
    "gcp": {
        # compute
        "compute":                      ("compute",    "virtual_machine"),
        "appengine":                    ("compute",    "managed"),
        "cloudfunctions":               ("compute",    "serverless"),
        "function":                     ("compute",    "serverless"),
        "run":                          ("compute",    "serverless"),
        "cloudrun":                     ("compute",    "serverless"),
        "batch":                        ("compute",    "batch"),
        # storage
        "storage":                      ("storage",    "object"),
        "file":                         ("storage",    "file"),
        "filestore":                    ("storage",    "file"),
        "backupdr":                     ("storage",    "backup"),
        # database
        "sql":                          ("database",   "relational"),
        "sqladmin":                     ("database",   "relational"),
        "cloudsql":                     ("database",   "relational"),
        "alloydb":                      ("database",   "relational"),
        "bigtable":                     ("database",   "nosql"),
        "bigtableadmin":                ("database",   "nosql"),
        "firestore":                    ("database",   "nosql"),
        "datastore":                    ("database",   "nosql"),
        "spanner":                      ("database",   "relational"),
        "memcache":                     ("database",   "cache"),
        "redis":                        ("database",   "cache"),
        # network
        "networking":                   ("network",    "vpc"),
        "dns":                          ("network",    "dns"),
        "loadbalancing":                ("network",    "load_balancer"),
        "lb":                           ("network",    "load_balancer"),
        "networkconnectivity":          ("network",    "vpc"),
        "networkmanagement":            ("network",    "vpc"),
        "networksecurity":              ("network",    "firewall"),
        "networkservices":              ("network",    "gateway"),
        "vpn":                          ("network",    "vpn"),
        "vpcaccess":                    ("network",    "vpc"),
        "trafficdirector":              ("network",    "gateway"),
        "servicenetworking":            ("network",    "gateway"),
        "apigee":                       ("network",    "gateway"),
        "apigateway":                   ("network",    "gateway"),
        "apigeeregistry":               ("network",    "gateway"),
        "apihub":                       ("network",    "gateway"),
        "apikeys":                      ("network",    "gateway"),
        "endpoints":                    ("network",    "gateway"),
        "iap":                          ("security",   "posture"),
        # security
        "scc":                          ("security",   "siem"),
        "securitycenter":               ("security",   "siem"),
        "security_command_center":      ("security",   "siem"),
        "securityposture":              ("security",   "posture"),
        "binaryauthorization":          ("security",   "posture"),
        "policyanalyzer":               ("security",   "posture"),
        "orgpolicy":                    ("security",   "posture"),
        "accessapproval":               ("security",   "posture"),
        "accesscontextmanager":         ("security",   "posture"),
        "advisorynotifications":        ("security",   "posture"),
        "assuredworkloads":             ("security",   "posture"),
        "containeranalysis":            ("security",   "vulnerability"),
        "ondemandscanning":             ("security",   "vulnerability"),
        # identity
        "iam":                          ("identity",   "iam"),
        "iamcredentials":               ("identity",   "service_account"),
        "identitytoolkit":              ("identity",   "federation"),
        "cloudidentity":                ("identity",   "directory"),
        "managedidentities":            ("identity",   "directory"),
        "privilegedaccessmanager":      ("identity",   "iam"),
        # monitoring
        "monitoring":                   ("monitoring", "metrics"),
        "logging":                      ("monitoring", "logs"),
        "cloudtrace":                   ("monitoring", "tracing"),
        "clouderrorreporting":          ("monitoring", "logs"),
        "cloudprofiler":                ("monitoring", "tracing"),
        # container
        "gke":                          ("container",  "orchestration_managed"),
        "gkehub":                       ("container",  "orchestration_managed"),
        "gkebackup":                    ("container",  "orchestration_managed"),
        "gkeonprem":                    ("container",  "orchestration_managed"),
        "artifactregistry":             ("container",  "registry"),
        "gcr":                          ("container",  "registry"),
        "container":                    ("container",  "orchestration_managed"),
        # encryption
        "cloudkms":                     ("encryption", "kms"),
        "kms":                          ("encryption", "kms"),
        "secretmanager":                ("encryption", "secrets"),
        "privateca":                    ("encryption", "certificates"),
        "certificatemanager":           ("encryption", "certificates"),
        "kmsinventory":                 ("encryption", "kms"),
        # analytics
        "bigquery":                     ("analytics",  "warehouse"),
        "bigqueryconnection":           ("analytics",  "warehouse"),
        "bigquerydatapolicy":           ("analytics",  "warehouse"),
        "bigquerydatatransfer":         ("analytics",  "etl"),
        "bigqueryreservation":          ("analytics",  "warehouse"),
        "biglake":                      ("analytics",  "warehouse"),
        "dataflow":                     ("analytics",  "streaming"),
        "dataproc":                     ("analytics",  "batch"),
        "datastream":                   ("analytics",  "streaming"),
        "datafusion":                   ("analytics",  "etl"),
        "composer":                     ("analytics",  "etl"),
        "looker":                       ("analytics",  "bi"),
        "datacatalog":                  ("analytics",  "warehouse"),
        "dataplex":                     ("analytics",  "warehouse"),
        "analyticshub":                 ("analytics",  "warehouse"),
        "datalineage":                  ("analytics",  "warehouse"),
        "dataform":                     ("analytics",  "etl"),
        "pubsub":                       ("messaging",  "topic"),
        "pubsublite":                   ("messaging",  "topic"),
        # ai_ml
        "aiplatform":                   ("ai_ml",      "platform"),
        "vertex_ai":                    ("ai_ml",      "platform"),
        "ml":                           ("ai_ml",      "platform"),
        "notebooks":                    ("ai_ml",      "platform"),
        "workstations":                 ("ai_ml",      "platform"),
        "discoveryengine":              ("ai_ml",      "nlp"),
        "contactcenteraiplatform":      ("ai_ml",      "nlp"),
        "contactcenterinsights":        ("ai_ml",      "nlp"),
        "dialogflow":                   ("ai_ml",      "nlp"),
        "documentai":                   ("ai_ml",      "vision"),
        "language":                     ("ai_ml",      "nlp"),
        "videointelligence":            ("ai_ml",      "vision"),
        "vision":                       ("ai_ml",      "vision"),
        "speech":                       ("ai_ml",      "speech"),
        "texttospeech":                 ("ai_ml",      "speech"),
        "translate":                    ("ai_ml",      "nlp"),
        "recommendationengine":         ("ai_ml",      "platform"),
        "recommender":                  ("ai_ml",      "platform"),
        "retail":                       ("ai_ml",      "platform"),
        # messaging
        "tasks":                        ("messaging",  "queue"),
        "cloudscheduler":               ("messaging",  "event_bus"),
        "eventarc":                     ("messaging",  "event_bus"),
        "workflows":                    ("messaging",  "event_bus"),
        "workflowexecutions":           ("messaging",  "event_bus"),
        # iot
        "cloudiot":                     ("iot",        "device"),
    },

    # ── OCI ──────────────────────────────────────────────────────────────────
    "oci": {
        # compute
        "compute":                      ("compute",    "virtual_machine"),
        "autoscaling":                  ("compute",    "virtual_machine"),
        "core":                         ("compute",    "virtual_machine"),
        "compute_cloud_at_customer":    ("compute",    "managed"),
        "compute_instance_agent":       ("compute",    "managed"),
        "functions":                    ("compute",    "serverless"),
        "devops":                       ("compute",    "managed"),
        "visual_builder":               ("compute",    "managed"),
        # storage
        "objectstorage":                ("storage",    "object"),
        "object_storage":               ("storage",    "object"),
        "block_storage":                ("storage",    "block"),
        "blockstorage":                 ("storage",    "block"),
        "file_storage":                 ("storage",    "file"),
        "lustre_file_storage":          ("storage",    "file"),
        "backup":                       ("storage",    "backup"),
        "disaster_recovery":            ("storage",    "backup"),
        # database
        "database":                     ("database",   "relational"),
        "database_management":          ("database",   "relational"),
        "database_migration":           ("database",   "relational"),
        "database_tools":               ("database",   "relational"),
        "mysql":                        ("database",   "relational"),
        "postgresql":                   ("database",   "relational"),
        "psql":                         ("database",   "relational"),
        "nosql":                        ("database",   "nosql"),
        "redis":                        ("database",   "cache"),
        "opensearch":                   ("database",   "nosql"),
        "distributed_database":         ("database",   "nosql"),
        "globally_distributed_database": ("database",  "nosql"),
        "dbmulticloud":                 ("database",   "relational"),
        "dblm":                         ("database",   "relational"),
        # network
        "virtual_network":              ("network",    "vpc"),
        "vcn":                          ("network",    "vpc"),
        "vn_monitoring":                ("network",    "vpc"),
        "dns":                          ("network",    "dns"),
        "load_balancer":                ("network",    "load_balancer"),
        "loadbalancer":                 ("network",    "load_balancer"),
        "network_load_balancer":        ("network",    "load_balancer"),
        "network_firewall":             ("network",    "firewall"),
        "waf":                          ("network",    "firewall"),
        "waas":                         ("network",    "firewall"),
        "waa":                          ("network",    "firewall"),
        "bastion":                      ("security",   "posture"),
        # security
        "cloud_guard":                  ("security",   "posture"),
        "cloudguard":                   ("security",   "posture"),
        "vulnerability_scanning":       ("security",   "vulnerability"),
        "vulnerabilityscanning":        ("security",   "vulnerability"),
        "security_attribute":           ("security",   "posture"),
        "threat_intelligence":          ("security",   "siem"),
        "zpr":                          ("security",   "posture"),
        "access_governance_cp":         ("security",   "posture"),
        "operator_access_control":      ("security",   "posture"),
        "data_safe":                    ("security",   "posture"),
        "lockbox":                      ("security",   "posture"),
        "delegate_access_control":      ("security",   "posture"),
        "adm":                          ("security",   "posture"),
        # identity
        "iam":                          ("identity",   "iam"),
        "identity":                     ("identity",   "iam"),
        "identity_domains":             ("identity",   "directory"),
        "identity_data_plane":          ("identity",   "iam"),
        # monitoring
        "monitoring":                   ("monitoring", "metrics"),
        "logging":                      ("monitoring", "logs"),
        "log_analytics":                ("monitoring", "logs"),
        "audit":                        ("monitoring", "logs"),
        "management_dashboard":         ("monitoring", "metrics"),
        "stack_monitoring":             ("monitoring", "metrics"),
        "apm_config":                   ("monitoring", "tracing"),
        "apm_control_plane":            ("monitoring", "tracing"),
        "apm_synthetics":               ("monitoring", "tracing"),
        "apm_traces":                   ("monitoring", "tracing"),
        "announcements_service":        ("monitoring", "metrics"),
        # container
        "container_engine":             ("container",  "orchestration_managed"),
        "oke":                          ("container",  "orchestration_managed"),
        "container_instances":          ("container",  "orchestration_managed"),
        "containerregistry":            ("container",  "registry"),
        "artifacts":                    ("container",  "registry"),
        # encryption
        "kms":                          ("encryption", "kms"),
        "key_management":               ("encryption", "kms"),
        "vault":                        ("encryption", "kms"),
        "certificates":                 ("encryption", "certificates"),
        "certificates_management":      ("encryption", "certificates"),
        "secrets":                      ("encryption", "secrets"),
        # analytics
        "analytics":                    ("analytics",  "bi"),
        "data_flow":                    ("analytics",  "streaming"),
        "data_integration":             ("analytics",  "etl"),
        "goldengate":                   ("analytics",  "etl"),
        "data_catalog":                 ("analytics",  "warehouse"),
        "bds":                          ("analytics",  "batch"),
        # ai_ml
        "ai_anomaly_detection":         ("ai_ml",      "platform"),
        "ai_document":                  ("ai_ml",      "vision"),
        "ai_language":                  ("ai_ml",      "nlp"),
        "ai_speech":                    ("ai_ml",      "speech"),
        "ai_vision":                    ("ai_ml",      "vision"),
        "data_science":                 ("ai_ml",      "platform"),
        "ai_data_platform":             ("ai_ml",      "platform"),
        "generative_ai":                ("ai_ml",      "model_serving"),
        "generative_ai_agent":          ("ai_ml",      "model_serving"),
        "generative_ai_agent_runtime":  ("ai_ml",      "model_serving"),
        "generative_ai_inference":      ("ai_ml",      "model_serving"),
        # messaging
        "streaming":                    ("messaging",  "streaming"),
        "queue":                        ("messaging",  "queue"),
        "ons":                          ("messaging",  "notification"),
        "eventbridge":                  ("messaging",  "event_bus"),
        "managed_kafka":                ("messaging",  "streaming"),
        # iot
        "iot":                          ("iot",        "device"),
    },

    # ── AliCloud ─────────────────────────────────────────────────────────────
    "alicloud": {
        # compute
        "ecs":                          ("compute",    "virtual_machine"),
        "autoscaling":                  ("compute",    "virtual_machine"),
        "ess":                          ("compute",    "virtual_machine"),
        "fc":                           ("compute",    "serverless"),
        "faas":                         ("compute",    "serverless"),
        "fnf":                          ("compute",    "serverless"),
        "sae":                          ("compute",    "managed"),
        "batchcompute":                 ("compute",    "batch"),
        "ehpc":                         ("compute",    "batch"),
        "beebot":                       ("compute",    "managed"),
        "eci":                          ("compute",    "container_workload"),
        # storage
        "oss":                          ("storage",    "object"),
        "nas":                          ("storage",    "file"),
        "alidfs":                       ("storage",    "file"),
        "efs":                          ("storage",    "file"),
        "hbr":                          ("storage",    "backup"),
        "dbs":                          ("storage",    "backup"),
        "ots":                          ("database",   "nosql"),
        "tablestore":                   ("database",   "nosql"),
        # database
        "rds":                          ("database",   "relational"),
        "polardb":                      ("database",   "relational"),
        "dds":                          ("database",   "nosql"),
        "kvstore":                      ("database",   "cache"),
        "redisa":                       ("database",   "cache"),
        "hbase":                        ("database",   "nosql"),
        "hologres":                     ("database",   "warehouse"),
        "analyticdb":                   ("database",   "warehouse"),
        "gpdb":                         ("database",   "warehouse"),
        "drds":                         ("database",   "relational"),
        "apsaradb":                     ("database",   "relational"),
        "petadata":                     ("database",   "nosql"),
        "cassandra":                    ("database",   "nosql"),
        "lindorm":                      ("database",   "nosql"),
        # network
        "vpc":                          ("network",    "vpc"),
        "slb":                          ("network",    "load_balancer"),
        "alb":                          ("network",    "load_balancer"),
        "clb":                          ("network",    "load_balancer"),
        "cdn":                          ("network",    "cdn"),
        "dcdn":                         ("network",    "cdn"),
        "cbn":                          ("network",    "vpc"),
        "cen":                          ("network",    "vpc"),
        "expressconnect":               ("network",    "vpn"),
        "vpn":                          ("network",    "vpn"),
        "smartag":                      ("network",    "vpc"),
        "ga":                           ("network",    "load_balancer"),
        "alidns":                       ("network",    "dns"),
        "alidnsgtm":                    ("network",    "dns"),
        "pvtz":                         ("network",    "dns"),
        "waf":                          ("network",    "firewall"),
        "ddos":                         ("network",    "firewall"),
        "ddosbgp":                      ("network",    "firewall"),
        "ddoscoo":                      ("network",    "firewall"),
        "ddosbasic":                    ("network",    "firewall"),
        "ddosdip":                      ("network",    "firewall"),
        "apigateway":                   ("network",    "gateway"),
        "cfw":                          ("network",    "firewall"),
        "cloudfw":                      ("network",    "firewall"),
        "cloudfirewall":                ("network",    "firewall"),
        "uis":                          ("network",    "vpc"),
        # security
        "sas":                          ("security",   "posture"),
        "securitycenter":               ("security",   "posture"),
        "security_center":              ("security",   "posture"),
        "threat":                       ("security",   "siem"),
        "threatdetection":              ("security",   "siem"),
        "vipaegis":                     ("security",   "siem"),
        "gameshield":                   ("security",   "posture"),
        "bastionhost":                  ("security",   "posture"),
        "saf":                          ("security",   "posture"),
        "green":                        ("security",   "posture"),
        # identity
        "ram":                          ("identity",   "iam"),
        "iam":                          ("identity",   "iam"),
        "ims":                          ("identity",   "directory"),
        "sso":                          ("identity",   "federation"),
        # monitoring
        "arms":                         ("monitoring", "metrics"),
        "cloudmonitor":                 ("monitoring", "metrics"),
        "cms":                          ("monitoring", "metrics"),
        "actiontrail":                  ("monitoring", "logs"),
        "log":                          ("monitoring", "logs"),
        "sls":                          ("monitoring", "logs"),
        # container
        "ack":                          ("container",  "orchestration_managed"),
        "cs":                           ("container",  "orchestration_managed"),
        "cr":                           ("container",  "registry"),
        "acr":                          ("container",  "registry"),
        # encryption
        "kms":                          ("encryption", "kms"),
        "cas":                          ("encryption", "certificates"),
        "hsm":                          ("encryption", "kms"),
        # analytics
        "maxcompute":                   ("analytics",  "warehouse"),
        "emr":                          ("analytics",  "batch"),
        "hologres":                     ("analytics",  "warehouse"),
        "openanalytics":                ("analytics",  "bi"),
        "datahub":                      ("analytics",  "streaming"),
        "dataworks":                    ("analytics",  "etl"),
        "dlf":                          ("analytics",  "warehouse"),
        "elasticsearch":                ("analytics",  "search"),
        "foas":                         ("analytics",  "streaming"),
        # ai_ml
        "aiops":                        ("ai_ml",      "platform"),
        "ivision":                      ("ai_ml",      "vision"),
        "imagesearch":                  ("ai_ml",      "vision"),
        "alinlp":                       ("ai_ml",      "nlp"),
        # messaging
        "mns":                          ("messaging",  "queue"),
        "ons":                          ("messaging",  "topic"),
        "alikafka":                     ("messaging",  "streaming"),
        "kafka":                        ("messaging",  "streaming"),
        "eventbridge":                  ("messaging",  "event_bus"),
        "mq":                           ("messaging",  "queue"),
        "apsaramq":                     ("messaging",  "queue"),
        # iot
        "iot":                          ("iot",        "device"),
        "iovcc":                        ("iot",        "device"),
        "linkwan":                      ("iot",        "device"),
    },

    # ── IBM ──────────────────────────────────────────────────────────────────
    "ibm": {
        # compute
        "code_engine":                  ("compute",    "serverless"),
        "functions":                    ("compute",    "serverless"),
        "power_iaas":                   ("compute",    "virtual_machine"),
        "satellite":                    ("compute",    "managed"),
        "continuous_delivery":          ("compute",    "managed"),
        # storage
        "object_storage":               ("storage",    "object"),
        "block_storage":                ("storage",    "block"),
        "file_storage":                 ("storage",    "file"),
        "backup":                       ("storage",    "backup"),
        # database
        "cloudant":                     ("database",   "nosql"),
        "databases":                    ("database",   "relational"),
        "data_virtualization":          ("database",   "relational"),
        # network
        "vpc":                          ("network",    "vpc"),
        "dns":                          ("network",    "dns"),
        "internet_services":            ("network",    "cdn"),
        "load_balancer":                ("network",    "load_balancer"),
        "transit_gateway":              ("network",    "vpc"),
        "direct_link":                  ("network",    "vpn"),
        "global_catalog":               ("network",    "gateway"),
        # security
        "security_advisor":             ("security",   "posture"),
        "security_compliance_center":   ("security",   "posture"),
        "context_based_restrictions":   ("security",   "posture"),
        # identity
        "iam":                          ("identity",   "iam"),
        "iam_access_groups":            ("identity",   "iam"),
        "iam_identity":                 ("identity",   "iam"),
        "iam_policy_management":        ("identity",   "iam"),
        "appid":                        ("identity",   "federation"),
        # monitoring
        "activity_tracker":             ("monitoring", "logs"),
        "monitoring":                   ("monitoring", "metrics"),
        "log_analysis":                 ("monitoring", "logs"),
        # container
        "container_registry":           ("container",  "registry"),
        "containers":                   ("container",  "orchestration_managed"),
        "iks":                          ("container",  "orchestration_managed"),
        "ocp":                          ("container",  "orchestration_managed"),
        "openshift":                    ("container",  "orchestration_managed"),
        # encryption
        "key_protect":                  ("encryption", "kms"),
        "hs_crypto":                    ("encryption", "kms"),
        "secrets_manager":              ("encryption", "secrets"),
        "certificate_manager":          ("encryption", "certificates"),
        # analytics
        "analytics_engine":             ("analytics",  "batch"),
        "datastage":                    ("analytics",  "etl"),
        "event_streams":                ("analytics",  "streaming"),
        # ai_ml
        "watson":                       ("ai_ml",      "model_serving"),
        "watson_discovery":             ("ai_ml",      "nlp"),
        "watson_ml":                    ("ai_ml",      "platform"),
        # messaging
        "event_notifications":          ("messaging",  "notification"),
        "mq":                           ("messaging",  "queue"),
        "kafka":                        ("messaging",  "streaming"),
    },

    # ── K8s ──────────────────────────────────────────────────────────────────
    "k8s": {
        # compute
        "pod":                          ("compute",    "container_workload"),
        "deployment":                   ("compute",    "container_workload"),
        "replicaset":                   ("compute",    "container_workload"),
        "statefulset":                  ("compute",    "container_workload"),
        "daemonset":                    ("compute",    "container_workload"),
        "job":                          ("compute",    "batch"),
        "cronjob":                      ("compute",    "batch"),
        "workload":                     ("compute",    "container_workload"),
        "compute":                      ("compute",    "container_workload"),
        "horizontalpodautoscaler":      ("compute",    "container_workload"),
        # storage
        "persistentvolume":             ("storage",    "block"),
        "persistentvolumeclaim":        ("storage",    "block"),
        "storageclass":                 ("storage",    "managed"),
        "storage":                      ("storage",    "managed"),
        # network
        "network":                      ("network",    "vpc"),
        "networkpolicy":                ("network",    "firewall"),
        "ingress":                      ("network",    "load_balancer"),
        "service":                      ("network",    "load_balancer"),
        "endpoints":                    ("network",    "vpc"),
        # security
        "admission":                    ("security",   "posture"),
        "pod_security":                 ("security",   "posture"),
        "poddisruptionbudget":          ("security",   "posture"),
        # identity
        "rbac":                         ("identity",   "iam"),
        "clusterrole":                  ("identity",   "iam"),
        "clusterrolebinding":           ("identity",   "iam"),
        "role":                         ("identity",   "iam"),
        "rolebinding":                  ("identity",   "iam"),
        "serviceaccount":               ("identity",   "service_account"),
        "cluster":                      ("container",  "orchestration_k8s"),
        # monitoring
        "monitoring":                   ("monitoring", "metrics"),
        "audit":                        ("monitoring", "logs"),
        "event":                        ("monitoring", "logs"),
        # container
        "container":                    ("container",  "orchestration_k8s"),
        "image":                        ("container",  "registry"),
        "controlplane":                 ("container",  "orchestration_k8s"),
        "node":                         ("container",  "orchestration_k8s"),
        "namespace":                    ("container",  "orchestration_k8s"),
        "core":                         ("container",  "orchestration_k8s"),
        "federation":                   ("container",  "orchestration_k8s"),
        # encryption
        "secret":                       ("encryption", "secrets"),
        # config
        "configmap":                    ("compute",    "managed"),
        "limitrange":                   ("compute",    "managed"),
        "resourcequota":                ("compute",    "managed"),
        "priorityclass":                ("compute",    "managed"),
        "podtemplate":                  ("compute",    "managed"),
        "replicationcontroller":        ("compute",    "container_workload"),
    },
}


def apply_category_fallback(rows: List[Dict]) -> List[Dict]:
    """Fill category/subcategory from _SERVICE_TO_CATEGORY where still None."""
    for row in rows:
        if row.get("category"):
            continue
        csp_map = _SERVICE_TO_CATEGORY.get(row["csp"], {})
        entry = csp_map.get(row["service"])
        if entry:
            row["category"], sub = entry
            if not row.get("subcategory"):
                row["subcategory"] = sub
    return rows


# ── Step 1: active services from rule_discoveries ────────────────────────────

def load_active_services(csp_filter: Optional[str] = None) -> Dict[str, Set[str]]:
    """Return {csp: {service, ...}} for all active rule_discoveries rows."""
    conn = _check_conn()
    try:
        with conn.cursor() as cur:
            if csp_filter:
                cur.execute(
                    "SELECT DISTINCT provider, service FROM rule_discoveries "
                    "WHERE is_active = TRUE AND provider = %s",
                    (csp_filter,),
                )
            else:
                cur.execute(
                    "SELECT DISTINCT provider, service FROM rule_discoveries "
                    "WHERE is_active = TRUE"
                )
            result: Dict[str, Set[str]] = {}
            for csp, svc in cur.fetchall():
                result.setdefault(csp, set()).add(svc)
        return result
    finally:
        conn.close()


# ── Step 2: parse step5 files ─────────────────────────────────────────────────

def _normalise_ops(ops: List[Dict]) -> List[Dict]:
    """Normalise op dicts to canonical shape across CSP format variants."""
    out = []
    for op in ops:
        out.append({
            "operation":     op.get("operation") or op.get("op", ""),
            "python_method": op.get("python_method") or op.get("python_call", ""),
            "yaml_action":   op.get("yaml_action", ""),
            "independent":   bool(op.get("independent", False)),
            "required_params": op.get("required_params") or [],
            "kind":          op.get("kind", ""),
        })
    return out


def _extract_rows_from_step5(
    csp: str, service: str, path: Path
) -> List[Dict[str, Any]]:
    """Parse one step5 file and return catalog rows (one per resource_type).

    Only returns resource_types that are PRIMARY_RESOURCE or can_inventory_from_roots.
    """
    try:
        data = json.loads(path.read_text())
    except Exception as e:
        logger.warning("Cannot parse %s: %s", path, e)
        return []

    rows = []

    # Format A: AWS/OCI/AliCloud/IBM — {resources: {resource_type: {...}}}
    resources: Dict[str, Any] = data.get("resources", {})

    # Format C: GCP — {services: {svc: {resources: {rt: {...}}}}}
    if not resources and "services" in data:
        for svc_block in data["services"].values():
            resources.update(svc_block.get("resources", {}))

    # Format B: Azure flat — single resource per file
    if not resources and "resource" in data:
        rt = data["resource"]
        resources[rt] = data

    for resource_type, info in resources.items():
        classification = info.get("classification", "OTHER_RESOURCE")
        can_from_roots = bool(info.get("can_inventory_from_roots", False))

        # Skip non-primary resources that can't be reached from roots
        if classification != "PRIMARY_RESOURCE" and not can_from_roots:
            continue

        inv_block   = info.get("inventory", {})
        enrich_block = info.get("inventory_enrich", {})

        root_ops   = _normalise_ops(inv_block.get("ops", []) if isinstance(inv_block, dict) else [])
        enrich_ops = _normalise_ops(enrich_block.get("ops", []) if isinstance(enrich_block, dict) else [])

        # Only keep resource types that have at least one root (independent) op
        if not any(op["independent"] for op in root_ops):
            continue

        rows.append({
            "csp":                   csp,
            "service":               service,
            "resource_type":         resource_type,
            "classification":        classification,
            "has_arn":               bool(info.get("has_arn", False)),
            "can_inventory_from_roots": can_from_roots,
            "show_in_inventory":     bool(info.get("should_inventory", classification == "PRIMARY_RESOURCE")),
            "show_in_architecture":  bool(info.get("show_in_architecture", False)),
            "is_billable":           bool(info.get("is_billable", False)),
            "root_ops":              root_ops,
            "enrich_ops":            enrich_ops,
            "used_by_engines":       info.get("used_by_engines") or [],
            # Category fields — filled from service_classification in step 3
            "category":              info.get("category") or info.get("asset_category"),
            "subcategory":           info.get("subcategory"),
            "asset_category":        info.get("asset_category"),
            "csp_category":          info.get("csp_category"),
            "scope":                 info.get("scope"),
            "service_model":         info.get("service_model"),
            "managed_by":            info.get("managed_by"),
            "access_pattern":        info.get("access_pattern"),
            "encryption_scope":      info.get("encryption_scope"),
            "is_container":          bool(info.get("is_container", False)),
            "container_parent":      info.get("container_parent"),
            "diagram_priority":      info.get("diagram_priority") or 50,
            "resource_role":         info.get("resource_role"),
            "raw_catalog":           info,
        })

    return rows


def build_catalog_rows(
    active_services: Dict[str, Set[str]],
    catalog_base: Path,
) -> List[Dict[str, Any]]:
    """Walk catalog dirs; return rows only for active services."""
    all_rows: List[Dict[str, Any]] = []
    missing: List[Tuple[str, str]] = []

    for csp, services in sorted(active_services.items()):
        csp_dir = catalog_base / csp
        if not csp_dir.exists():
            logger.warning("No catalog dir for csp=%s at %s", csp, csp_dir)
            continue

        found = 0
        for service in sorted(services):
            step5 = csp_dir / service / "step5_resource_catalog_inventory_enrich.json"
            if not step5.exists():
                missing.append((csp, service))
                continue
            rows = _extract_rows_from_step5(csp, service, step5)
            all_rows.extend(rows)
            found += 1

        logger.info("csp=%-12s active_services=%d  step5_found=%d  rows_so_far=%d",
                    csp, len(services), found, len(all_rows))

    if missing:
        logger.info("Services with no step5 file (%d): %s",
                    len(missing), missing[:20])

    return all_rows


# ── Step 3: enrich from service_classification ────────────────────────────────

def load_service_classification() -> Dict[Tuple[str, str, str], Dict]:
    """Return {(csp, service, resource_type): metadata_dict} from inventory DB."""
    try:
        conn = _inv_conn()
    except Exception as e:
        logger.warning("Cannot connect to inventory DB for service_classification: %s", e)
        return {}
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT csp, service, resource_type, category, subcategory, "
                "scope, service_model, managed_by, access_pattern, "
                "encryption_scope, is_container, container_parent, "
                "diagram_priority, csp_category, resource_role "
                "FROM service_classification"
            )
            result = {}
            for row in cur.fetchall():
                key = (row["csp"], row["service"], row["resource_type"])
                result[key] = dict(row)
        logger.info("Loaded %d service_classification rows", len(result))
        return result
    finally:
        conn.close()


def enrich_with_classification(
    rows: List[Dict], sc_map: Dict[Tuple[str, str, str], Dict]
) -> List[Dict]:
    """Fill category/scope/etc. from service_classification where step5 didn't have them."""
    _CAT_FIELDS = (
        "category", "subcategory", "scope", "service_model", "managed_by",
        "access_pattern", "encryption_scope", "is_container", "container_parent",
        "diagram_priority", "csp_category", "resource_role",
    )
    for row in rows:
        sc = sc_map.get((row["csp"], row["service"], row["resource_type"])) or {}
        for field in _CAT_FIELDS:
            if not row.get(field) and sc.get(field) is not None:
                row[field] = sc[field]
    return rows


# ── Step 4: load relationship rules ──────────────────────────────────────────

def load_relationship_rules(
    active_services: Dict[str, Set[str]]
) -> List[Dict[str, Any]]:
    """
    Copy active relationship rules from inventory DB, filtered to services
    that have active rule_discoveries entries.
    """
    try:
        conn = _inv_conn()
    except Exception as e:
        logger.warning("Cannot connect to inventory DB for relationship rules: %s", e)
        return []
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT csp, service, from_resource_type, relation_type, "
                "to_resource_type, source_field, source_field_item, "
                "target_uid_pattern, attack_path_category, is_active, rule_metadata "
                "FROM resource_security_relationship_rules "
                "WHERE is_active = TRUE"
            )
            all_rules = cur.fetchall()

        # Filter: only rules where service is in active_services for that CSP
        filtered = []
        skipped = 0
        for rule in all_rules:
            csp = rule["csp"]
            svc = rule["service"] or ""
            if csp in active_services and (not svc or svc in active_services[csp]):
                filtered.append(dict(rule))
            else:
                skipped += 1

        logger.info("Relationship rules: total=%d active+filtered=%d skipped=%d",
                    len(all_rules), len(filtered), skipped)
        return filtered
    finally:
        conn.close()


# ── Step 5: upsert into DI DB ─────────────────────────────────────────────────

_CATALOG_UPSERT = """
INSERT INTO di_resource_catalog (
    csp, service, resource_type, classification, has_arn,
    can_inventory_from_roots, show_in_inventory, show_in_architecture,
    is_billable, root_ops, enrich_ops, used_by_engines,
    category, subcategory, asset_category, csp_category, scope,
    service_model, managed_by, access_pattern, encryption_scope,
    is_container, container_parent, diagram_priority, resource_role,
    raw_catalog, loaded_at, updated_at
) VALUES (
    %(csp)s, %(service)s, %(resource_type)s, %(classification)s, %(has_arn)s,
    %(can_inventory_from_roots)s, %(show_in_inventory)s, %(show_in_architecture)s,
    %(is_billable)s, %(root_ops)s, %(enrich_ops)s, %(used_by_engines)s,
    %(category)s, %(subcategory)s, %(asset_category)s, %(csp_category)s, %(scope)s,
    %(service_model)s, %(managed_by)s, %(access_pattern)s, %(encryption_scope)s,
    %(is_container)s, %(container_parent)s, %(diagram_priority)s, %(resource_role)s,
    %(raw_catalog)s, NOW(), NOW()
)
ON CONFLICT (csp, service, resource_type) DO UPDATE SET
    classification        = EXCLUDED.classification,
    has_arn               = EXCLUDED.has_arn,
    can_inventory_from_roots = EXCLUDED.can_inventory_from_roots,
    show_in_inventory     = EXCLUDED.show_in_inventory,
    show_in_architecture  = EXCLUDED.show_in_architecture,
    is_billable           = EXCLUDED.is_billable,
    root_ops              = EXCLUDED.root_ops,
    enrich_ops            = EXCLUDED.enrich_ops,
    used_by_engines       = EXCLUDED.used_by_engines,
    category              = COALESCE(EXCLUDED.category,           di_resource_catalog.category),
    subcategory           = COALESCE(EXCLUDED.subcategory,        di_resource_catalog.subcategory),
    asset_category        = COALESCE(EXCLUDED.asset_category,     di_resource_catalog.asset_category),
    csp_category          = COALESCE(EXCLUDED.csp_category,       di_resource_catalog.csp_category),
    scope                 = COALESCE(EXCLUDED.scope,              di_resource_catalog.scope),
    service_model         = COALESCE(EXCLUDED.service_model,      di_resource_catalog.service_model),
    managed_by            = COALESCE(EXCLUDED.managed_by,         di_resource_catalog.managed_by),
    access_pattern        = COALESCE(EXCLUDED.access_pattern,     di_resource_catalog.access_pattern),
    encryption_scope      = COALESCE(EXCLUDED.encryption_scope,   di_resource_catalog.encryption_scope),
    is_container          = EXCLUDED.is_container,
    container_parent      = EXCLUDED.container_parent,
    diagram_priority      = EXCLUDED.diagram_priority,
    resource_role         = COALESCE(EXCLUDED.resource_role,      di_resource_catalog.resource_role),
    raw_catalog           = EXCLUDED.raw_catalog,
    updated_at            = NOW()
"""

_REL_UPSERT = """
INSERT INTO di_relationship_rules (
    csp, service, from_resource_type, relation_type, to_resource_type,
    source_field, source_field_item, target_uid_pattern,
    attack_path_category, is_active, rule_metadata
) VALUES (
    %(csp)s, %(service)s, %(from_resource_type)s, %(relation_type)s, %(to_resource_type)s,
    %(source_field)s, %(source_field_item)s, %(target_uid_pattern)s,
    %(attack_path_category)s, %(is_active)s, %(rule_metadata)s
)
ON CONFLICT (csp, from_resource_type, relation_type, to_resource_type) DO UPDATE SET
    service              = EXCLUDED.service,
    source_field         = EXCLUDED.source_field,
    source_field_item    = EXCLUDED.source_field_item,
    target_uid_pattern   = EXCLUDED.target_uid_pattern,
    attack_path_category = EXCLUDED.attack_path_category,
    is_active            = EXCLUDED.is_active,
    rule_metadata        = EXCLUDED.rule_metadata,
    updated_at           = NOW()
"""


def _jsonb(val: Any) -> str:
    return json.dumps(val) if val is not None else None


def upsert_catalog(rows: List[Dict], dry_run: bool = False) -> int:
    if not rows:
        return 0
    if dry_run:
        logger.info("[DRY RUN] Would upsert %d catalog rows", len(rows))
        for r in rows[:5]:
            logger.info("  %s.%s.%s  class=%s", r["csp"], r["service"],
                        r["resource_type"], r["classification"])
        return len(rows)

    conn = _di_conn()
    written = 0
    try:
        with conn.cursor() as cur:
            for row in rows:
                row["root_ops"]        = _jsonb(row.get("root_ops", []))
                row["enrich_ops"]      = _jsonb(row.get("enrich_ops", []))
                row["used_by_engines"] = _jsonb(row.get("used_by_engines", []))
                row["raw_catalog"]     = _jsonb(row.get("raw_catalog"))
                row["rule_metadata"]   = _jsonb(row.get("rule_metadata", {}))
                try:
                    cur.execute(_CATALOG_UPSERT, row)
                    written += 1
                except Exception as e:
                    logger.warning("Failed row %s.%s.%s: %s",
                                   row["csp"], row["service"], row["resource_type"], e)
                    conn.rollback()
                    continue
        conn.commit()
    finally:
        conn.close()
    return written


def upsert_relationships(rules: List[Dict], dry_run: bool = False) -> int:
    if not rules:
        return 0
    if dry_run:
        logger.info("[DRY RUN] Would upsert %d relationship rules", len(rules))
        return len(rules)

    conn = _di_conn()
    written = 0
    try:
        with conn.cursor() as cur:
            for rule in rules:
                rule["rule_metadata"] = _jsonb(rule.get("rule_metadata") or {})
                try:
                    cur.execute(_REL_UPSERT, rule)
                    written += 1
                except Exception as e:
                    logger.warning("Failed rel rule %s %s->%s: %s",
                                   rule["csp"], rule["from_resource_type"],
                                   rule["to_resource_type"], e)
                    conn.rollback()
                    continue
        conn.commit()
    finally:
        conn.close()
    return written


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Populate di_resource_catalog from step5 YAML catalog")
    parser.add_argument("--csp", help="Restrict to one CSP (aws | azure | gcp | oci | ibm | alicloud | k8s)")
    parser.add_argument("--catalog-path", default=str(_DEFAULT_CATALOG),
                        help=f"Base path for discovery_generator_data (default: {_DEFAULT_CATALOG})")
    parser.add_argument("--dry-run", action="store_true",
                        help="Parse and log without writing to DB")
    parser.add_argument("--skip-relationships", action="store_true",
                        help="Skip loading di_relationship_rules")
    args = parser.parse_args()

    catalog_base = Path(args.catalog_path)
    if not catalog_base.exists():
        logger.error("Catalog path not found: %s", catalog_base)
        sys.exit(1)

    # 1. Active services
    logger.info("Loading active services from rule_discoveries...")
    active = load_active_services(args.csp)
    total_svcs = sum(len(s) for s in active.values())
    logger.info("Active services: %d across %d CSPs", total_svcs, len(active))

    # 2. Build catalog rows from step5 files
    logger.info("Parsing step5 catalog files...")
    rows = build_catalog_rows(active, catalog_base)
    logger.info("Step5 parse complete: %d catalog rows", len(rows))

    # 3. Enrich with service_classification
    logger.info("Loading service_classification for enrichment...")
    sc_map = load_service_classification()
    rows = enrich_with_classification(rows, sc_map)

    # 3b. Apply service→category from built-in dict (primary source for most rows;
    #     step5 files and service_classification rarely carry category values)
    rows = apply_category_fallback(rows)
    missing_cat = sum(1 for r in rows if not r.get("category"))
    logger.info("Category coverage: %d/%d rows have category (%d still null)",
                len(rows) - missing_cat, len(rows), missing_cat)

    # 4. Upsert catalog
    logger.info("Upserting di_resource_catalog...")
    written_catalog = upsert_catalog(rows, dry_run=args.dry_run)
    logger.info("di_resource_catalog: %d rows written", written_catalog)

    # 5. Relationship rules
    if not args.skip_relationships:
        logger.info("Loading relationship rules from inventory DB...")
        rel_rules = load_relationship_rules(active)
        written_rels = upsert_relationships(rel_rules, dry_run=args.dry_run)
        logger.info("di_relationship_rules: %d rows written", written_rels)

    logger.info("Done.")


if __name__ == "__main__":
    main()
