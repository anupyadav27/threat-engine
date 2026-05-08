#!/usr/bin/env python3
"""
Seed threat_hunt_queries with curated toxic combination patterns
and predefined hunt queries.

These queries were previously hardcoded in graph_queries.py.
Now they live in the DB so they can be managed without code changes.

Usage:
    # With port-forward to RDS:
    THREAT_DB_HOST=localhost THREAT_DB_PORT=5432 \
    THREAT_DB_NAME=threat_engine_threat THREAT_DB_USER=postgres \
    THREAT_DB_PASSWORD=xxx python seed_hunt_queries.py

    # With full RDS host:
    THREAT_DB_HOST=postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com \
    python seed_hunt_queries.py
"""

import os
import sys

# Allow running from project root or scripts dir
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))

import psycopg2
from psycopg2.extras import Json

# ── Connection ──────────────────────────────────────────────────────────────

def _conn():
    host = os.getenv("THREAT_DB_HOST", "localhost")
    port = os.getenv("THREAT_DB_PORT", "5432")
    db = os.getenv("THREAT_DB_NAME", "threat_engine_threat")
    user = os.getenv("THREAT_DB_USER", "postgres")
    pwd = os.getenv("THREAT_DB_PASSWORD", "")
    return psycopg2.connect(host=host, port=port, dbname=db, user=user, password=pwd)


# ── Toxic Combination Patterns ──────────────────────────────────────────────
# hunt_type = 'toxic_combination', query_language = 'cypher'
# These are high-signal queries that match resources where multiple
# dangerous conditions co-exist.

TOXIC_PATTERNS = [
    # ── Enterprise-grade patterns (Wiz/Orca parity) ──────────────────────────────
    {
        "query_name": "public_ec2_imds_v1_admin_iam",
        "description": "EC2 with public IP + IMDS v1 enabled + admin IAM role — SSRF → metadata → credentials → full account compromise (T1552)",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["imds", "metadata-service", "ssrf", "admin-iam", "critical"],
        "mitre_tactics": ["credential-access", "privilege-escalation"],
        "mitre_techniques": ["T1552", "T1552.005", "T1078"],
        "severity": "critical",
        "query_text": """
            MATCH (i:Internet)-[:EXPOSES]->(ec2:EC2Instance {tenant_id: $tid})
            WITH DISTINCT ec2
            MATCH (ec2)-[:HAS_FINDING]->(f_imds:Finding)
            WHERE f_imds.rule_id CONTAINS 'imds' OR f_imds.rule_id CONTAINS 'metadata'
               OR f_imds.rule_id CONTAINS 'imdsv1' OR f_imds.rule_id CONTAINS 'hop_limit'
            WITH ec2, collect(f_imds.rule_id) AS imds_rules
            MATCH (ec2)-[:ASSUMES]->(ip:InstanceProfile)-[:ASSUMES]->(role:IAMRole)
            MATCH (role)-[:HAS_FINDING]->(f_iam:Finding)
            WHERE f_iam.rule_id CONTAINS 'admin' OR f_iam.rule_id CONTAINS 'full_access'
               OR f_iam.rule_id CONTAINS 'star_policy' OR f_iam.rule_id CONTAINS 'privilege'
            WITH ec2, imds_rules, collect(f_iam.rule_id) AS iam_rules, role
            OPTIONAL MATCH (ec2)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                ec2.uid AS resource_uid, ec2.name AS resource_name,
                ec2.resource_type AS resource_type,
                count(DISTINCT t) AS threat_count,
                imds_rules + iam_rules AS matched_rules,
                collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
        """,
    },
    {
        "query_name": "rds_public_unencrypted_no_backup",
        "description": "RDS instance publicly accessible + unencrypted at rest + backup disabled — complete data breach and destruction risk",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["database", "public-access", "encryption", "backup", "critical"],
        "mitre_tactics": ["collection", "impact"],
        "mitre_techniques": ["T1190", "T1530", "T1485"],
        "severity": "critical",
        "query_text": """
            MATCH (i:Internet)-[:EXPOSES]->(r:Resource {tenant_id: $tid})
            WHERE r.resource_type IN ['rds.instance', 'rds.db-instance', 'rds.cluster']
            WITH DISTINCT r
            MATCH (r)-[:HAS_FINDING]->(f1:Finding)
            WHERE f1.rule_id CONTAINS 'encrypt' OR f1.rule_id CONTAINS 'encryption_at_rest'
            WITH r, collect(f1.rule_id) AS encrypt_rules
            OPTIONAL MATCH (r)-[:HAS_FINDING]->(f2:Finding)
            WHERE f2.rule_id CONTAINS 'backup' OR f2.rule_id CONTAINS 'retention'
            WITH r, encrypt_rules, collect(f2.rule_id) AS backup_rules
            OPTIONAL MATCH (r)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                r.uid AS resource_uid, r.name AS resource_name,
                r.resource_type AS resource_type,
                count(DISTINCT t) AS threat_count,
                encrypt_rules + backup_rules AS matched_rules,
                collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
        """,
    },
    {
        "query_name": "eks_public_api_privileged_pods",
        "description": "EKS cluster with public API endpoint + privileged pods + RBAC misconfig — direct cluster takeover path",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["eks", "kubernetes", "public-api", "privileged", "critical"],
        "mitre_tactics": ["initial-access", "privilege-escalation"],
        "mitre_techniques": ["T1190", "T1610", "T1613"],
        "severity": "critical",
        "query_text": """
            MATCH (i:Internet)-[:EXPOSES]->(eks:EKSCluster {tenant_id: $tid})
            WITH DISTINCT eks
            MATCH (eks)-[:HAS_FINDING]->(f:Finding)
            WHERE f.rule_id CONTAINS 'privileged' OR f.rule_id CONTAINS 'rbac'
               OR f.rule_id CONTAINS 'admin' OR f.rule_id CONTAINS 'cluster_admin'
               OR f.rule_id CONTAINS 'public_access'
            WITH eks, collect(f.rule_id) AS k8s_rules
            OPTIONAL MATCH (eks)-[:CONTAINS]->(sa:K8sServiceAccount)
            OPTIONAL MATCH (eks)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                eks.uid AS resource_uid, eks.name AS resource_name,
                eks.resource_type AS resource_type,
                count(DISTINCT sa) AS service_account_count,
                count(DISTINCT t) AS threat_count,
                k8s_rules AS matched_rules,
                collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
        """,
    },
    {
        "query_name": "lambda_public_url_over_privileged",
        "description": "Lambda with public function URL + over-privileged IAM execution role — unauthenticated code execution → full account access",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["lambda", "public-url", "over-privileged", "critical"],
        "mitre_tactics": ["initial-access", "privilege-escalation"],
        "mitre_techniques": ["T1190", "T1648", "T1098"],
        "severity": "critical",
        "query_text": """
            MATCH (i:Internet)-[:EXPOSES]->(fn:LambdaFunction {tenant_id: $tid})
            MATCH (fn)-[:HAS_FINDING]->(f1:Finding)
            WHERE f1.rule_id CONTAINS 'function_url' OR f1.rule_id CONTAINS 'public_url'
               OR f1.rule_id CONTAINS 'auth_type_none'
            WITH fn, collect(f1.rule_id) AS url_rules
            MATCH (fn)-[:ASSUMES]->(role:IAMRole)
            MATCH (role)-[:HAS_FINDING]->(f2:Finding)
            WHERE f2.rule_id CONTAINS 'admin' OR f2.rule_id CONTAINS 'star'
               OR f2.rule_id CONTAINS 'full_access' OR f2.rule_id CONTAINS 'privilege'
            WITH fn, url_rules, collect(f2.rule_id) AS iam_rules
            OPTIONAL MATCH (fn)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                fn.uid AS resource_uid, fn.name AS resource_name,
                fn.resource_type AS resource_type,
                count(DISTINCT t) AS threat_count,
                url_rules + iam_rules AS matched_rules,
                collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
        """,
    },
    {
        "query_name": "cloudtrail_disabled_internet_exposed",
        "description": "CloudTrail not logging + active internet-exposed resources — attacker can operate with zero audit trail (T1562.008)",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["cloudtrail", "logging-disabled", "blind-spot", "defense-evasion", "critical"],
        "mitre_tactics": ["defense-evasion"],
        "mitre_techniques": ["T1562.008", "T1562"],
        "severity": "critical",
        "query_text": """
            MATCH (ct:CloudTrailTrail {tenant_id: $tid})-[:HAS_FINDING]->(f:Finding)
            WHERE f.rule_id CONTAINS 'logging' OR f.rule_id CONTAINS 'enabled'
               OR f.rule_id CONTAINS 'multiregion' OR f.rule_id CONTAINS 'cloudtrail'
            WITH count(DISTINCT ct) AS disabled_trails,
                 collect(DISTINCT ct.uid)[..3] AS sample_trails,
                 collect(DISTINCT f.rule_id)[..5] AS matched_rules
            MATCH (i:Internet)-[:EXPOSES]->(exposed:Resource {tenant_id: $tid})
            WITH disabled_trails, sample_trails, matched_rules,
                 count(DISTINCT exposed) AS exposed_count,
                 collect(DISTINCT exposed.uid)[..5] AS sample_exposed
            WHERE disabled_trails > 0
            RETURN
                sample_trails[0] AS resource_uid,
                'CloudTrail disabled with ' + toString(exposed_count) + ' internet-exposed resources' AS resource_name,
                'cloudtrail.trail' AS resource_type,
                0 AS threat_count,
                matched_rules,
                [] AS threat_details
        """,
    },
    {
        "query_name": "s3_public_versioning_mfa_delete_disabled",
        "description": "S3 bucket publicly accessible + versioning disabled or MFA-delete off — permanent data deletion by attacker (T1485)",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["s3", "public-access", "versioning", "data-destruction", "critical"],
        "mitre_tactics": ["impact", "collection"],
        "mitre_techniques": ["T1485", "T1530"],
        "severity": "critical",
        "query_text": """
            MATCH (r:S3Bucket {tenant_id: $tid})-[:HAS_FINDING]->(f1:Finding)
            WHERE f1.rule_id CONTAINS 'public' OR f1.rule_id CONTAINS 'block_public'
            WITH r, collect(f1.rule_id) AS public_rules
            MATCH (r)-[:HAS_FINDING]->(f2:Finding)
            WHERE f2.rule_id CONTAINS 'versioning' OR f2.rule_id CONTAINS 'mfa_delete'
               OR f2.rule_id CONTAINS 'lifecycle'
            WITH r, public_rules, collect(f2.rule_id) AS version_rules
            OPTIONAL MATCH (r)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                r.uid AS resource_uid, r.name AS resource_name,
                r.resource_type AS resource_type,
                count(DISTINCT t) AS threat_count,
                public_rules + version_rules AS matched_rules,
                collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
        """,
    },
    {
        "query_name": "ai_model_accessible_no_invocation_logging",
        "description": "Bedrock/SageMaker endpoint accessible from internet-exposed compute + invocation logging disabled — prompt injection and data exfiltration blind spot",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["bedrock", "sagemaker", "ai-ml", "logging-disabled", "high"],
        "mitre_tactics": ["collection", "defense-evasion"],
        "mitre_techniques": ["T1565", "T1562"],
        "severity": "high",
        "query_text": """
            MATCH (i:Internet)-[:EXPOSES]->(compute:Resource {tenant_id: $tid})
            WHERE compute.resource_type IN [
                'ec2.instance', 'lambda.function', 'lambda.resource', 'eks.cluster'
            ]
            MATCH (compute)-[:ACCESSES]->(ai:Resource {tenant_id: $tid})
            WHERE ai.resource_type IN [
                'bedrock.foundation-model', 'bedrock.agent', 'bedrock.inference-profile',
                'sagemaker.endpoint', 'sagemaker.model'
            ]
            OPTIONAL MATCH (ai)-[:HAS_FINDING]->(f:Finding)
            WHERE f.rule_id CONTAINS 'logging' OR f.rule_id CONTAINS 'monitoring'
               OR f.rule_id CONTAINS 'invocation' OR f.rule_id CONTAINS 'audit'
            WITH compute, ai, collect(f.rule_id) AS log_rules
            OPTIONAL MATCH (ai)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                ai.uid AS resource_uid, ai.name AS resource_name,
                ai.resource_type AS resource_type,
                compute.uid AS entry_point,
                count(DISTINCT t) AS threat_count,
                log_rules AS matched_rules,
                collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
        """,
    },
    {
        "query_name": "ecr_public_image_scan_disabled",
        "description": "Container registry with public access + image scanning disabled — supply chain attack delivering malicious code to Lambda/ECS/EKS (T1195.002)",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["ecr", "container-registry", "supply-chain", "scan-disabled", "high"],
        "mitre_tactics": ["initial-access"],
        "mitre_techniques": ["T1195.002", "T1525"],
        "severity": "high",
        "query_text": """
            MATCH (r:Resource {tenant_id: $tid})-[:HAS_FINDING]->(f1:Finding)
            WHERE r.resource_type IN ['ecr.repository', 'ecr.resource']
              AND (f1.rule_id CONTAINS 'public' OR f1.rule_id CONTAINS 'image_visibility')
            WITH r, collect(f1.rule_id) AS public_rules
            MATCH (r)-[:HAS_FINDING]->(f2:Finding)
            WHERE f2.rule_id CONTAINS 'scan' OR f2.rule_id CONTAINS 'scanning'
               OR f2.rule_id CONTAINS 'vulnerability'
            WITH r, public_rules, collect(f2.rule_id) AS scan_rules
            OPTIONAL MATCH (r)-[:PROVIDES_IMAGE_TO]->(consumer:Resource)
            OPTIONAL MATCH (r)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                r.uid AS resource_uid, r.name AS resource_name,
                r.resource_type AS resource_type,
                count(DISTINCT consumer) AS downstream_consumers,
                count(DISTINCT t) AS threat_count,
                public_rules + scan_rules AS matched_rules,
                collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
        """,
    },
    {
        "query_name": "kms_key_rotation_disabled_with_sensitive_data",
        "description": "KMS key with rotation disabled + used to encrypt sensitive data + accessible from internet-exposed compute — key compromise decrypts everything",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["kms", "key-rotation", "encryption", "high"],
        "mitre_tactics": ["collection", "impact"],
        "mitre_techniques": ["T1552", "T1485"],
        "severity": "high",
        "query_text": """
            MATCH (k:KMSKey {tenant_id: $tid})-[:HAS_FINDING]->(f:Finding)
            WHERE f.rule_id CONTAINS 'rotation' OR f.rule_id CONTAINS 'key_rotation'
            WITH k, collect(f.rule_id) AS rotation_rules
            MATCH (compute:Resource {tenant_id: $tid, account_id: k.account_id})-[:ACCESSES]->(k)
            WHERE compute.resource_type IN [
                'ec2.instance', 'lambda.function', 'lambda.resource', 'eks.cluster'
            ]
            MATCH (i:Internet)-[:EXPOSES]->(compute)
            WITH k, rotation_rules, count(DISTINCT compute) AS exposed_compute_count
            OPTIONAL MATCH (k)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                k.uid AS resource_uid, k.name AS resource_name,
                k.resource_type AS resource_type,
                exposed_compute_count,
                count(DISTINCT t) AS threat_count,
                rotation_rules AS matched_rules,
                collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
            ORDER BY exposed_compute_count DESC
        """,
    },
    {
        "query_name": "public_storage_unencrypted",
        "description": "Storage resource is publicly accessible AND lacks encryption — data exposed in plaintext",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["data-exposure", "encryption", "public-access", "critical"],
        "mitre_tactics": ["collection", "exfiltration"],
        "mitre_techniques": ["T1530", "T1537"],
        "severity": "critical",
        "query_text": """
            MATCH (r:Resource {tenant_id: $tid})-[:HAS_FINDING]->(f1:Finding)
            WHERE r.resource_type IN ['s3.resource', 's3.bucket', 'azure.storage_account',
                                       'gcp.gcs_bucket', 'oci.object_storage_bucket']
              AND (f1.rule_id CONTAINS 'public_access' OR f1.rule_id CONTAINS 'public_read'
                   OR f1.rule_id CONTAINS 'block_public')
            WITH r, collect(f1.rule_id) AS public_rules
            MATCH (r)-[:HAS_FINDING]->(f2:Finding)
            WHERE f2.rule_id CONTAINS 'encrypt'
            WITH r, public_rules, collect(f2.rule_id) AS encrypt_rules
            OPTIONAL MATCH (r)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                r.uid AS resource_uid,
                r.name AS resource_name,
                r.resource_type AS resource_type,
                count(DISTINCT t) AS threat_count,
                public_rules + encrypt_rules AS matched_rules,
                collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
        """,
    },
    {
        "query_name": "public_database",
        "description": "Database is publicly accessible — direct data breach risk",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["data-exposure", "database", "public-access", "critical"],
        "mitre_tactics": ["collection", "initial-access"],
        "mitre_techniques": ["T1190", "T1530"],
        "severity": "critical",
        "query_text": """
            MATCH (r:Resource {tenant_id: $tid})-[:HAS_FINDING]->(f:Finding)
            WHERE r.resource_type IN ['rds.instance', 'rds.cluster', 'redshift.cluster',
                                       'dynamodb.table', 'azure.sql_server', 'gcp.sql_instance']
              AND (f.rule_id CONTAINS 'public' OR f.rule_id CONTAINS 'exposed')
            WITH r, collect(DISTINCT f.rule_id) AS matched_rules
            OPTIONAL MATCH (r)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                r.uid AS resource_uid,
                r.name AS resource_name,
                r.resource_type AS resource_type,
                count(DISTINCT t) AS threat_count,
                matched_rules,
                collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
        """,
    },
    {
        "query_name": "admin_no_mfa",
        "description": "Identity with admin/full access and MFA not enforced — account takeover risk",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["identity", "mfa", "privilege-escalation", "critical"],
        "mitre_tactics": ["privilege-escalation", "credential-access"],
        "mitre_techniques": ["T1078", "T1098"],
        "severity": "critical",
        "query_text": """
            MATCH (r:Resource {tenant_id: $tid})-[:HAS_FINDING]->(f1:Finding)
            WHERE r.resource_type IN ['iam.user', 'iam.role', 'iam.policy',
                                       'azure.managed_identity', 'gcp.iam_service_account']
              AND (f1.rule_id CONTAINS 'admin' OR f1.rule_id CONTAINS 'full_access'
                   OR f1.rule_id CONTAINS 'star_policy' OR f1.rule_id CONTAINS 'privilege')
            WITH r, collect(f1.rule_id) AS admin_rules
            MATCH (r)-[:HAS_FINDING]->(f2:Finding)
            WHERE f2.rule_id CONTAINS 'mfa'
            WITH r, admin_rules, collect(f2.rule_id) AS mfa_rules
            OPTIONAL MATCH (r)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                r.uid AS resource_uid,
                r.name AS resource_name,
                r.resource_type AS resource_type,
                count(DISTINCT t) AS threat_count,
                admin_rules + mfa_rules AS matched_rules,
                collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
        """,
    },
    {
        "query_name": "exposed_compute_misconfigured",
        "description": "Internet-exposed compute with security misconfigurations — lateral movement entry point",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["internet-exposed", "compute", "misconfiguration", "high"],
        "mitre_tactics": ["initial-access", "lateral-movement"],
        "mitre_techniques": ["T1190", "T1021"],
        "severity": "high",
        "query_text": """
            MATCH (i:Internet)-[*1..3]->(r:Resource {tenant_id: $tid})
            WHERE r.resource_type IN ['ec2.instance', 'azure.virtual_machine',
                                       'gcp.compute_instance', 'lambda.function']
            WITH DISTINCT r
            MATCH (r)-[:HAS_FINDING]->(f:Finding)
            WITH r, count(f) AS finding_count, collect(f.rule_id)[..5] AS sample_rules
            WHERE finding_count >= 3
            OPTIONAL MATCH (r)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                r.uid AS resource_uid,
                r.name AS resource_name,
                r.resource_type AS resource_type,
                count(DISTINCT t) AS threat_count,
                sample_rules AS matched_rules,
                collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
        """,
    },
    {
        "query_name": "sensitive_no_logging",
        "description": "Sensitive resource with logging/monitoring disabled — blind spot for detection",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["logging", "monitoring", "blind-spot", "high"],
        "mitre_tactics": ["defense-evasion"],
        "mitre_techniques": ["T1562"],
        "severity": "high",
        "query_text": """
            MATCH (r:Resource {tenant_id: $tid})-[:HAS_FINDING]->(f:Finding)
            WHERE r.resource_type IN ['s3.resource', 's3.bucket', 'rds.instance',
                                       'lambda.function', 'ec2.instance', 'kms.key',
                                       'cloudtrail.trail', 'iam.user']
              AND (f.rule_id CONTAINS 'logging' OR f.rule_id CONTAINS 'log_'
                   OR f.rule_id CONTAINS 'monitoring' OR f.rule_id CONTAINS 'audit')
            WITH r, collect(DISTINCT f.rule_id) AS logging_rules
            WHERE size(logging_rules) >= 2
            OPTIONAL MATCH (r)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                r.uid AS resource_uid,
                r.name AS resource_name,
                r.resource_type AS resource_type,
                count(DISTINCT t) AS threat_count,
                logging_rules AS matched_rules,
                collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
        """,
    },
    {
        "query_name": "stale_overprivileged_identity",
        "description": "Identity with stale/unused credentials and over-privileged access — dormant attack vector",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["identity", "stale-credentials", "over-privileged", "high"],
        "mitre_tactics": ["persistence", "privilege-escalation"],
        "mitre_techniques": ["T1078", "T1098"],
        "severity": "high",
        "query_text": """
            MATCH (r:Resource {tenant_id: $tid})-[:HAS_FINDING]->(f1:Finding)
            WHERE r.resource_type IN ['iam.user', 'iam.role', 'iam.access-key']
              AND (f1.rule_id CONTAINS 'unused' OR f1.rule_id CONTAINS 'stale'
                   OR f1.rule_id CONTAINS 'rotate' OR f1.rule_id CONTAINS 'inactive'
                   OR f1.rule_id CONTAINS 'last_used')
            WITH r, collect(f1.rule_id) AS stale_rules
            MATCH (r)-[:HAS_FINDING]->(f2:Finding)
            WHERE f2.rule_id CONTAINS 'privilege' OR f2.rule_id CONTAINS 'admin'
                  OR f2.rule_id CONTAINS 'full_access' OR f2.rule_id CONTAINS 'star'
            WITH r, stale_rules, collect(f2.rule_id) AS priv_rules
            OPTIONAL MATCH (r)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                r.uid AS resource_uid,
                r.name AS resource_name,
                r.resource_type AS resource_type,
                count(DISTINCT t) AS threat_count,
                stale_rules + priv_rules AS matched_rules,
                collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
        """,
    },
    {
        "query_name": "unencrypted_exposed",
        "description": "Resource lacks encryption AND is internet-accessible — data in transit/at rest exposed",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["encryption", "internet-exposed", "data-exposure", "high"],
        "mitre_tactics": ["collection", "exfiltration"],
        "mitre_techniques": ["T1040", "T1557"],
        "severity": "high",
        "query_text": """
            MATCH (i:Internet)-[*1..3]->(r:Resource {tenant_id: $tid})
            WITH DISTINCT r
            MATCH (r)-[:HAS_FINDING]->(f:Finding)
            WHERE f.rule_id CONTAINS 'encrypt' OR f.rule_id CONTAINS 'ssl'
                  OR f.rule_id CONTAINS 'tls' OR f.rule_id CONTAINS 'https'
            WITH r, collect(DISTINCT f.rule_id) AS encrypt_rules
            OPTIONAL MATCH (r)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                r.uid AS resource_uid,
                r.name AS resource_name,
                r.resource_type AS resource_type,
                count(DISTINCT t) AS threat_count,
                encrypt_rules AS matched_rules,
                collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
        """,
    },
    # ── AWS — additional patterns ─────────────────────────────────────────────

    {
        "query_name": "aws_sg_wide_open_ssh_rdp_no_bastion",
        "description": "Security group allows 0.0.0.0/0 on SSH(22) or RDP(3389) with no bastion host — direct brute-force path to compute (T1110)",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["aws", "security-group", "ssh", "rdp", "lateral-movement", "critical"],
        "mitre_tactics": ["initial-access", "lateral-movement"],
        "mitre_techniques": ["T1110", "T1021"],
        "severity": "critical",
        "query_text": """
            MATCH (i:Internet)-[:EXPOSES]->(ec2:EC2Instance {tenant_id: $tid})
            MATCH (ec2)-[:PROTECTED_BY]->(sg:SecurityGroup)
            MATCH (sg)-[:HAS_FINDING]->(f:Finding)
            WHERE f.rule_id CONTAINS 'ssh' OR f.rule_id CONTAINS 'rdp'
               OR f.rule_id CONTAINS '22' OR f.rule_id CONTAINS '3389'
               OR f.rule_id CONTAINS 'unrestricted_ingress'
            WITH ec2, sg, collect(f.rule_id) AS sg_rules
            OPTIONAL MATCH (ec2)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN ec2.uid AS resource_uid, ec2.name AS resource_name,
                   ec2.resource_type AS resource_type,
                   count(DISTINCT t) AS threat_count, sg_rules AS matched_rules,
                   collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
        """,
    },
    {
        "query_name": "aws_iam_user_no_mfa_active_keys",
        "description": "IAM user with no MFA + active access keys + broad permissions — credential compromise leads to full account takeover (T1078)",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["aws", "iam", "mfa", "access-keys", "privilege-escalation", "critical"],
        "mitre_tactics": ["privilege-escalation", "credential-access"],
        "mitre_techniques": ["T1078", "T1552.001"],
        "severity": "critical",
        "query_text": """
            MATCH (u:IAMUser {tenant_id: $tid})-[:HAS_FINDING]->(f1:Finding)
            WHERE f1.rule_id CONTAINS 'mfa' OR f1.rule_id CONTAINS 'virtual_mfa'
            WITH u, collect(f1.rule_id) AS mfa_rules
            MATCH (u)-[:HAS_FINDING]->(f2:Finding)
            WHERE f2.rule_id CONTAINS 'access_key' OR f2.rule_id CONTAINS 'key_rotation'
               OR f2.rule_id CONTAINS 'unused_credential'
            WITH u, mfa_rules, collect(f2.rule_id) AS key_rules
            OPTIONAL MATCH (u)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN u.uid AS resource_uid, u.name AS resource_name,
                   u.resource_type AS resource_type,
                   count(DISTINCT t) AS threat_count,
                   mfa_rules + key_rules AS matched_rules,
                   collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
        """,
    },
    {
        "query_name": "aws_s3_public_cross_account_replication",
        "description": "S3 bucket is public AND replicates to cross-account destination — data exfiltration via replication pipeline (T1537)",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["aws", "s3", "data-exfiltration", "cross-account", "critical"],
        "mitre_tactics": ["exfiltration"],
        "mitre_techniques": ["T1537", "T1530"],
        "severity": "critical",
        "query_text": """
            MATCH (r:S3Bucket {tenant_id: $tid})-[:HAS_FINDING]->(f1:Finding)
            WHERE f1.rule_id CONTAINS 'public' OR f1.rule_id CONTAINS 'acl'
               OR f1.rule_id CONTAINS 'block_public'
            WITH r, collect(f1.rule_id) AS public_rules
            MATCH (r)-[:HAS_FINDING]->(f2:Finding)
            WHERE f2.rule_id CONTAINS 'replicat' OR f2.rule_id CONTAINS 'cross_account'
            WITH r, public_rules, collect(f2.rule_id) AS replication_rules
            OPTIONAL MATCH (r)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN r.uid AS resource_uid, r.name AS resource_name,
                   r.resource_type AS resource_type,
                   count(DISTINCT t) AS threat_count,
                   public_rules + replication_rules AS matched_rules,
                   collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
        """,
    },
    {
        "query_name": "aws_vpc_flowlogs_disabled_internet_exposed",
        "description": "VPC with flow logs disabled + internet-exposed resources inside — lateral movement invisible to defenders (T1562.001)",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["aws", "vpc", "flow-logs", "blind-spot", "defense-evasion", "high"],
        "mitre_tactics": ["defense-evasion"],
        "mitre_techniques": ["T1562.001"],
        "severity": "high",
        "query_text": """
            MATCH (vpc:VPC {tenant_id: $tid})-[:HAS_FINDING]->(f:Finding)
            WHERE f.rule_id CONTAINS 'flow_log' OR f.rule_id CONTAINS 'flowlog'
            WITH vpc, collect(f.rule_id) AS log_rules
            MATCH (i:Internet)-[:EXPOSES]->(exposed:Resource {tenant_id: $tid})-[:IN_VPC]->(vpc)
            WITH vpc, log_rules, count(DISTINCT exposed) AS exposed_count,
                 collect(DISTINCT exposed.uid)[..5] AS sample_exposed
            WHERE exposed_count > 0
            OPTIONAL MATCH (vpc)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN vpc.uid AS resource_uid, vpc.name AS resource_name,
                   vpc.resource_type AS resource_type,
                   count(DISTINCT t) AS threat_count, log_rules AS matched_rules,
                   [] AS threat_details
        """,
    },
    {
        "query_name": "aws_lambda_env_secrets_internet_path",
        "description": "Lambda with secrets in environment variables + reachable from internet — SSRF or code injection leaks plaintext credentials (T1552.001)",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["aws", "lambda", "secrets-in-env", "credential-exposure", "critical"],
        "mitre_tactics": ["credential-access"],
        "mitre_techniques": ["T1552.001"],
        "severity": "critical",
        "query_text": """
            MATCH (i:Internet)-[*1..3]->(fn:LambdaFunction {tenant_id: $tid})
            WITH DISTINCT fn
            MATCH (fn)-[:HAS_FINDING]->(f:Finding)
            WHERE f.rule_id CONTAINS 'env' OR f.rule_id CONTAINS 'environment'
               OR f.rule_id CONTAINS 'secret' OR f.rule_id CONTAINS 'plaintext'
               OR f.rule_id CONTAINS 'password'
            WITH fn, collect(f.rule_id) AS env_rules
            OPTIONAL MATCH (fn)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN fn.uid AS resource_uid, fn.name AS resource_name,
                   fn.resource_type AS resource_type,
                   count(DISTINCT t) AS threat_count, env_rules AS matched_rules,
                   collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
        """,
    },
    {
        "query_name": "aws_rds_snapshot_public",
        "description": "RDS snapshot set to public — database backup directly downloadable by anyone (T1530)",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["aws", "rds", "snapshot", "public-access", "data-exposure", "critical"],
        "mitre_tactics": ["collection"],
        "mitre_techniques": ["T1530"],
        "severity": "critical",
        "query_text": """
            MATCH (r:Resource {tenant_id: $tid})
            WHERE r.resource_type IN ['rds.db-snapshot', 'rds.cluster-snapshot', 'rds.snapshot']
            MATCH (r)-[:HAS_FINDING]->(f:Finding)
            WHERE f.rule_id CONTAINS 'public' OR f.rule_id CONTAINS 'shared'
               OR f.rule_id CONTAINS 'snapshot_public'
            WITH r, collect(f.rule_id) AS snap_rules
            OPTIONAL MATCH (r)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN r.uid AS resource_uid, r.name AS resource_name,
                   r.resource_type AS resource_type,
                   count(DISTINCT t) AS threat_count, snap_rules AS matched_rules,
                   collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
        """,
    },
    {
        "query_name": "aws_guardduty_disabled_active_threats",
        "description": "GuardDuty disabled in region with active threat detections — attacker operating without real-time detection (T1562)",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["aws", "guardduty", "detection-disabled", "blind-spot", "critical"],
        "mitre_tactics": ["defense-evasion"],
        "mitre_techniques": ["T1562"],
        "severity": "critical",
        "query_text": """
            MATCH (gd:Resource {tenant_id: $tid})
            WHERE gd.resource_type IN ['guardduty.detector', 'guardduty.resource']
            MATCH (gd)-[:HAS_FINDING]->(f:Finding)
            WHERE f.rule_id CONTAINS 'enabled' OR f.rule_id CONTAINS 'detector'
            WITH count(DISTINCT gd) AS disabled_count, collect(DISTINCT f.rule_id)[..5] AS gd_rules
            MATCH (r:Resource {tenant_id: $tid})-[:HAS_THREAT]->(t:ThreatDetection)
            WHERE t.severity IN ['HIGH', 'CRITICAL', 'high', 'critical']
            WITH disabled_count, gd_rules, count(DISTINCT t) AS active_threats,
                 collect(DISTINCT r.uid)[..3] AS sample_resources
            WHERE disabled_count > 0 AND active_threats > 0
            RETURN sample_resources[0] AS resource_uid,
                   'GuardDuty disabled with ' + toString(active_threats) + ' active threats' AS resource_name,
                   'guardduty.detector' AS resource_type,
                   active_threats AS threat_count, gd_rules AS matched_rules,
                   [] AS threat_details
        """,
    },
    {
        "query_name": "aws_ecr_image_critical_vuln_running",
        "description": "ECR image with critical vulnerabilities currently running as a container — exploitable workload in production (T1190)",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["aws", "ecr", "container", "vulnerability", "critical"],
        "mitre_tactics": ["initial-access", "execution"],
        "mitre_techniques": ["T1190", "T1610"],
        "severity": "critical",
        "query_text": """
            MATCH (repo:Resource {tenant_id: $tid})
            WHERE repo.resource_type IN ['ecr.repository', 'ecr.resource']
            MATCH (repo)-[:HAS_FINDING]->(f:Finding)
            WHERE f.rule_id CONTAINS 'scan' OR f.rule_id CONTAINS 'vulnerab'
               OR f.rule_id CONTAINS 'image_scan' OR f.rule_id CONTAINS 'critical'
            WITH repo, collect(f.rule_id) AS vuln_rules
            OPTIONAL MATCH (repo)-[:PROVIDES_IMAGE_TO]->(eks:EKSCluster)
            OPTIONAL MATCH (repo)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN repo.uid AS resource_uid, repo.name AS resource_name,
                   repo.resource_type AS resource_type,
                   count(DISTINCT t) AS threat_count, vuln_rules AS matched_rules,
                   collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
        """,
    },
    {
        "query_name": "aws_kms_key_exposed_no_rotation_sensitive_data",
        "description": "KMS key with rotation disabled + encrypts sensitive data store (S3/RDS/Secrets) — key compromise gives permanent data access (T1552.004)",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["aws", "kms", "key-rotation", "sensitive-data", "critical"],
        "mitre_tactics": ["credential-access"],
        "mitre_techniques": ["T1552.004"],
        "severity": "high",
        "query_text": """
            MATCH (k:KMSKey {tenant_id: $tid})-[:HAS_FINDING]->(f:Finding)
            WHERE f.rule_id CONTAINS 'rotation' OR f.rule_id CONTAINS 'key_rotation'
            WITH k, collect(f.rule_id) AS rotation_rules
            MATCH (sensitive:Resource {tenant_id: $tid})-[:ENCRYPTED_BY]->(k)
            WHERE sensitive.resource_type IN [
                's3.bucket', 's3.resource', 'rds.instance', 'rds.cluster',
                'secretsmanager.secret', 'dynamodb.table'
            ]
            WITH k, rotation_rules, count(DISTINCT sensitive) AS sensitive_count,
                 collect(DISTINCT sensitive.resource_type) AS sensitive_types
            OPTIONAL MATCH (k)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN k.uid AS resource_uid, k.name AS resource_name,
                   k.resource_type AS resource_type,
                   count(DISTINCT t) AS threat_count, rotation_rules AS matched_rules,
                   collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
        """,
    },
    {
        "query_name": "aws_opensearch_public_no_auth",
        "description": "OpenSearch domain publicly accessible + no authentication policy + no encryption — unauthenticated data access (T1190)",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["aws", "opensearch", "public-access", "no-auth", "data-exposure", "critical"],
        "mitre_tactics": ["initial-access", "collection"],
        "mitre_techniques": ["T1190", "T1530"],
        "severity": "critical",
        "query_text": """
            MATCH (i:Internet)-[:EXPOSES]->(r:Resource {tenant_id: $tid})
            WHERE r.resource_type IN ['opensearch.domain', 'elasticsearch.domain']
            WITH DISTINCT r
            MATCH (r)-[:HAS_FINDING]->(f:Finding)
            WHERE f.rule_id CONTAINS 'auth' OR f.rule_id CONTAINS 'policy'
               OR f.rule_id CONTAINS 'encrypt' OR f.rule_id CONTAINS 'access_policy'
               OR f.rule_id CONTAINS 'public_access'
            WITH r, collect(f.rule_id) AS os_rules
            OPTIONAL MATCH (r)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN r.uid AS resource_uid, r.name AS resource_name,
                   r.resource_type AS resource_type,
                   count(DISTINCT t) AS threat_count, os_rules AS matched_rules,
                   collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
        """,
    },

    # ── Azure toxic combinations ──────────────────────────────────────────────

    {
        "query_name": "azure_vm_public_ip_no_nsg_admin_identity",
        "description": "Azure VM with public IP + no NSG + admin managed identity — direct internet access with privilege escalation path (T1078.004)",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["azure", "vm", "public-ip", "managed-identity", "critical"],
        "mitre_tactics": ["initial-access", "privilege-escalation"],
        "mitre_techniques": ["T1078.004", "T1552"],
        "severity": "critical",
        "query_text": """
            MATCH (i:Internet)-[:EXPOSES]->(vm:VirtualMachine {tenant_id: $tid})
            WITH DISTINCT vm
            MATCH (vm)-[:HAS_FINDING]->(f1:Finding)
            WHERE f1.rule_id CONTAINS 'nsg' OR f1.rule_id CONTAINS 'network_security'
               OR f1.rule_id CONTAINS 'public_ip' OR f1.rule_id CONTAINS 'open_port'
            WITH vm, collect(f1.rule_id) AS nsg_rules
            MATCH (vm)-[:USES]->(mi:ManagedIdentity)
            MATCH (mi)-[:HAS_FINDING]->(f2:Finding)
            WHERE f2.rule_id CONTAINS 'admin' OR f2.rule_id CONTAINS 'owner'
               OR f2.rule_id CONTAINS 'contributor' OR f2.rule_id CONTAINS 'privilege'
            WITH vm, nsg_rules, collect(f2.rule_id) AS identity_rules
            OPTIONAL MATCH (vm)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN vm.uid AS resource_uid, vm.name AS resource_name,
                   vm.resource_type AS resource_type,
                   count(DISTINCT t) AS threat_count,
                   nsg_rules + identity_rules AS matched_rules,
                   collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
        """,
    },
    {
        "query_name": "azure_storage_public_no_encryption_no_logging",
        "description": "Azure storage account publicly accessible + no encryption + no access logging — silent data exfiltration (T1537)",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["azure", "storage", "public-access", "encryption", "logging", "critical"],
        "mitre_tactics": ["exfiltration", "collection"],
        "mitre_techniques": ["T1537", "T1530"],
        "severity": "critical",
        "query_text": """
            MATCH (i:Internet)-[:EXPOSES]->(sa:StorageAccount {tenant_id: $tid})
            WITH DISTINCT sa
            MATCH (sa)-[:HAS_FINDING]->(f:Finding)
            WHERE f.rule_id CONTAINS 'public' OR f.rule_id CONTAINS 'encrypt'
               OR f.rule_id CONTAINS 'logging' OR f.rule_id CONTAINS 'https'
               OR f.rule_id CONTAINS 'allow_blob_public'
            WITH sa, collect(f.rule_id) AS storage_rules
            OPTIONAL MATCH (sa)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN sa.uid AS resource_uid, sa.name AS resource_name,
                   sa.resource_type AS resource_type,
                   count(DISTINCT t) AS threat_count, storage_rules AS matched_rules,
                   collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
        """,
    },
    {
        "query_name": "azure_sql_public_no_audit_no_tde",
        "description": "Azure SQL Server publicly accessible + auditing disabled + TDE not enforced — full database exposure with no audit trail (T1190)",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["azure", "sql", "public-access", "audit", "tde", "critical"],
        "mitre_tactics": ["initial-access", "collection"],
        "mitre_techniques": ["T1190", "T1530"],
        "severity": "critical",
        "query_text": """
            MATCH (i:Internet)-[:EXPOSES]->(sql:SQLServer {tenant_id: $tid})
            WITH DISTINCT sql
            MATCH (sql)-[:HAS_FINDING]->(f:Finding)
            WHERE f.rule_id CONTAINS 'audit' OR f.rule_id CONTAINS 'tde'
               OR f.rule_id CONTAINS 'encrypt' OR f.rule_id CONTAINS 'firewall'
               OR f.rule_id CONTAINS 'public_network' OR f.rule_id CONTAINS 'threat_detection'
            WITH sql, collect(f.rule_id) AS sql_rules
            OPTIONAL MATCH (sql)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN sql.uid AS resource_uid, sql.name AS resource_name,
                   sql.resource_type AS resource_type,
                   count(DISTINCT t) AS threat_count, sql_rules AS matched_rules,
                   collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
        """,
    },
    {
        "query_name": "azure_aks_public_api_privileged_pods_no_rbac",
        "description": "AKS cluster with public API server + privileged pods allowed + RBAC disabled — cluster takeover from internet (T1613)",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["azure", "aks", "kubernetes", "public-api", "privileged", "critical"],
        "mitre_tactics": ["initial-access", "privilege-escalation"],
        "mitre_techniques": ["T1190", "T1613", "T1610"],
        "severity": "critical",
        "query_text": """
            MATCH (i:Internet)-[:EXPOSES]->(aks:AKSCluster {tenant_id: $tid})
            WITH DISTINCT aks
            MATCH (aks)-[:HAS_FINDING]->(f:Finding)
            WHERE f.rule_id CONTAINS 'rbac' OR f.rule_id CONTAINS 'privileged'
               OR f.rule_id CONTAINS 'public_fqdn' OR f.rule_id CONTAINS 'api_server'
               OR f.rule_id CONTAINS 'network_policy' OR f.rule_id CONTAINS 'aad'
            WITH aks, collect(f.rule_id) AS aks_rules
            OPTIONAL MATCH (aks)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN aks.uid AS resource_uid, aks.name AS resource_name,
                   aks.resource_type AS resource_type,
                   count(DISTINCT t) AS threat_count, aks_rules AS matched_rules,
                   collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
        """,
    },
    {
        "query_name": "azure_keyvault_soft_delete_disabled_public",
        "description": "Azure Key Vault accessible from internet + soft-delete/purge protection disabled — secrets permanently deletable by attacker (T1485)",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["azure", "keyvault", "public-access", "purge-protection", "critical"],
        "mitre_tactics": ["impact", "credential-access"],
        "mitre_techniques": ["T1485", "T1552"],
        "severity": "critical",
        "query_text": """
            MATCH (i:Internet)-[:EXPOSES]->(kv:KeyVault {tenant_id: $tid})
            WITH DISTINCT kv
            MATCH (kv)-[:HAS_FINDING]->(f:Finding)
            WHERE f.rule_id CONTAINS 'soft_delete' OR f.rule_id CONTAINS 'purge'
               OR f.rule_id CONTAINS 'public_network' OR f.rule_id CONTAINS 'firewall'
               OR f.rule_id CONTAINS 'private_endpoint' OR f.rule_id CONTAINS 'logging'
            WITH kv, collect(f.rule_id) AS kv_rules
            OPTIONAL MATCH (kv)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN kv.uid AS resource_uid, kv.name AS resource_name,
                   kv.resource_type AS resource_type,
                   count(DISTINCT t) AS threat_count, kv_rules AS matched_rules,
                   collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
        """,
    },
    {
        "query_name": "azure_sp_no_expiry_owner_role",
        "description": "Azure Service Principal with no expiry date + assigned Owner role at subscription scope — persistent admin credential (T1098)",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["azure", "service-principal", "owner-role", "no-expiry", "critical"],
        "mitre_tactics": ["persistence", "privilege-escalation"],
        "mitre_techniques": ["T1098", "T1078.004"],
        "severity": "critical",
        "query_text": """
            MATCH (mi:ManagedIdentity {tenant_id: $tid})-[:HAS_FINDING]->(f1:Finding)
            WHERE f1.rule_id CONTAINS 'expir' OR f1.rule_id CONTAINS 'credential'
               OR f1.rule_id CONTAINS 'secret_expiry' OR f1.rule_id CONTAINS 'certificate'
            WITH mi, collect(f1.rule_id) AS expiry_rules
            MATCH (mi)-[:HAS_FINDING]->(f2:Finding)
            WHERE f2.rule_id CONTAINS 'owner' OR f2.rule_id CONTAINS 'contributor'
               OR f2.rule_id CONTAINS 'admin' OR f2.rule_id CONTAINS 'privileged_role'
            WITH mi, expiry_rules, collect(f2.rule_id) AS role_rules
            OPTIONAL MATCH (mi)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN mi.uid AS resource_uid, mi.name AS resource_name,
                   mi.resource_type AS resource_type,
                   count(DISTINCT t) AS threat_count,
                   expiry_rules + role_rules AS matched_rules,
                   collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
        """,
    },
    {
        "query_name": "azure_defender_disabled_internet_exposed",
        "description": "Microsoft Defender for Cloud disabled for key services + internet-exposed resources — no runtime threat detection (T1562)",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["azure", "defender", "detection-disabled", "blind-spot", "high"],
        "mitre_tactics": ["defense-evasion"],
        "mitre_techniques": ["T1562"],
        "severity": "high",
        "query_text": """
            MATCH (dp:DefenderPricing {tenant_id: $tid})-[:HAS_FINDING]->(f:Finding)
            WHERE f.rule_id CONTAINS 'defender' OR f.rule_id CONTAINS 'security_center'
               OR f.rule_id CONTAINS 'pricing_tier' OR f.rule_id CONTAINS 'standard'
            WITH count(DISTINCT dp) AS disabled_count, collect(DISTINCT f.rule_id)[..5] AS defender_rules
            MATCH (i:Internet)-[:EXPOSES]->(exposed:Resource {tenant_id: $tid})
            WHERE exposed.provider = 'azure'
            WITH disabled_count, defender_rules, count(DISTINCT exposed) AS exposed_count
            WHERE disabled_count > 0 AND exposed_count > 0
            RETURN 'azure-defender-disabled' AS resource_uid,
                   'Defender disabled with ' + toString(exposed_count) + ' internet-exposed Azure resources' AS resource_name,
                   'azure.defender_pricing' AS resource_type,
                   0 AS threat_count, defender_rules AS matched_rules,
                   [] AS threat_details
        """,
    },

    # ── GCP toxic combinations ────────────────────────────────────────────────

    {
        "query_name": "gcp_compute_public_default_sa_full_scope",
        "description": "GCP Compute instance with public IP + default service account + full cloud-platform OAuth scope — SSRF → metadata → account takeover (T1552.005)",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["gcp", "compute", "default-service-account", "oauth-scope", "critical"],
        "mitre_tactics": ["credential-access", "privilege-escalation"],
        "mitre_techniques": ["T1552.005", "T1078"],
        "severity": "critical",
        "query_text": """
            MATCH (i:Internet)-[:EXPOSES]->(vm:ComputeInstance {tenant_id: $tid})
            WITH DISTINCT vm
            MATCH (vm)-[:HAS_FINDING]->(f:Finding)
            WHERE f.rule_id CONTAINS 'default_service_account' OR f.rule_id CONTAINS 'default_sa'
               OR f.rule_id CONTAINS 'full_access' OR f.rule_id CONTAINS 'cloud_platform'
               OR f.rule_id CONTAINS 'oauth_scope' OR f.rule_id CONTAINS 'metadata'
            WITH vm, collect(f.rule_id) AS gce_rules
            OPTIONAL MATCH (vm)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN vm.uid AS resource_uid, vm.name AS resource_name,
                   vm.resource_type AS resource_type,
                   count(DISTINCT t) AS threat_count, gce_rules AS matched_rules,
                   collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
        """,
    },
    {
        "query_name": "gcp_gcs_bucket_public_no_versioning_no_logging",
        "description": "GCS bucket publicly accessible + versioning disabled + access logging off — data destruction and silent exfiltration (T1530)",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["gcp", "gcs", "public-access", "versioning", "logging", "critical"],
        "mitre_tactics": ["collection", "impact"],
        "mitre_techniques": ["T1530", "T1485"],
        "severity": "critical",
        "query_text": """
            MATCH (i:Internet)-[:EXPOSES]->(b:GCSBucket {tenant_id: $tid})
            WITH DISTINCT b
            MATCH (b)-[:HAS_FINDING]->(f:Finding)
            WHERE f.rule_id CONTAINS 'public' OR f.rule_id CONTAINS 'allUsers'
               OR f.rule_id CONTAINS 'versioning' OR f.rule_id CONTAINS 'logging'
               OR f.rule_id CONTAINS 'uniform_access' OR f.rule_id CONTAINS 'iam_policy'
            WITH b, collect(f.rule_id) AS gcs_rules
            OPTIONAL MATCH (b)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN b.uid AS resource_uid, b.name AS resource_name,
                   b.resource_type AS resource_type,
                   count(DISTINCT t) AS threat_count, gcs_rules AS matched_rules,
                   collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
        """,
    },
    {
        "query_name": "gcp_sa_owner_role_old_key",
        "description": "GCP Service Account with Owner/Editor role + key older than 90 days — stale credential with maximum blast radius (T1078.004)",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["gcp", "service-account", "owner-role", "old-key", "critical"],
        "mitre_tactics": ["privilege-escalation", "persistence"],
        "mitre_techniques": ["T1078.004", "T1098"],
        "severity": "critical",
        "query_text": """
            MATCH (sa:ServiceAccount {tenant_id: $tid})-[:HAS_FINDING]->(f1:Finding)
            WHERE f1.rule_id CONTAINS 'key_rotation' OR f1.rule_id CONTAINS 'old_key'
               OR f1.rule_id CONTAINS 'key_age' OR f1.rule_id CONTAINS '90_day'
            WITH sa, collect(f1.rule_id) AS key_rules
            MATCH (sa)-[:HAS_FINDING]->(f2:Finding)
            WHERE f2.rule_id CONTAINS 'owner' OR f2.rule_id CONTAINS 'editor'
               OR f2.rule_id CONTAINS 'admin' OR f2.rule_id CONTAINS 'primitive_role'
            WITH sa, key_rules, collect(f2.rule_id) AS role_rules
            OPTIONAL MATCH (sa)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN sa.uid AS resource_uid, sa.name AS resource_name,
                   sa.resource_type AS resource_type,
                   count(DISTINCT t) AS threat_count,
                   key_rules + role_rules AS matched_rules,
                   collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
        """,
    },
    {
        "query_name": "gcp_gke_public_no_workload_identity_legacy_abac",
        "description": "GKE cluster public endpoint + workload identity disabled + legacy ABAC enabled — pod identity theft → cloud credential access (T1613)",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["gcp", "gke", "kubernetes", "workload-identity", "abac", "critical"],
        "mitre_tactics": ["initial-access", "privilege-escalation"],
        "mitre_techniques": ["T1190", "T1613"],
        "severity": "critical",
        "query_text": """
            MATCH (i:Internet)-[:EXPOSES]->(gke:GKECluster {tenant_id: $tid})
            WITH DISTINCT gke
            MATCH (gke)-[:HAS_FINDING]->(f:Finding)
            WHERE f.rule_id CONTAINS 'workload_identity' OR f.rule_id CONTAINS 'legacy_abac'
               OR f.rule_id CONTAINS 'master_authorized' OR f.rule_id CONTAINS 'private_cluster'
               OR f.rule_id CONTAINS 'network_policy' OR f.rule_id CONTAINS 'shielded'
            WITH gke, collect(f.rule_id) AS gke_rules
            OPTIONAL MATCH (gke)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN gke.uid AS resource_uid, gke.name AS resource_name,
                   gke.resource_type AS resource_type,
                   count(DISTINCT t) AS threat_count, gke_rules AS matched_rules,
                   collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
        """,
    },
    {
        "query_name": "gcp_cloud_sql_public_no_ssl_no_backup",
        "description": "Cloud SQL instance publicly accessible + SSL not required + automated backups disabled — full database exposure (T1190)",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["gcp", "cloud-sql", "public-access", "ssl", "backup", "critical"],
        "mitre_tactics": ["initial-access", "collection"],
        "mitre_techniques": ["T1190", "T1530"],
        "severity": "critical",
        "query_text": """
            MATCH (i:Internet)-[:EXPOSES]->(sql:CloudSQLInstance {tenant_id: $tid})
            WITH DISTINCT sql
            MATCH (sql)-[:HAS_FINDING]->(f:Finding)
            WHERE f.rule_id CONTAINS 'ssl' OR f.rule_id CONTAINS 'backup'
               OR f.rule_id CONTAINS 'authorized_network' OR f.rule_id CONTAINS 'public_ip'
               OR f.rule_id CONTAINS 'require_ssl' OR f.rule_id CONTAINS '0.0.0.0'
            WITH sql, collect(f.rule_id) AS sql_rules
            OPTIONAL MATCH (sql)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN sql.uid AS resource_uid, sql.name AS resource_name,
                   sql.resource_type AS resource_type,
                   count(DISTINCT t) AS threat_count, sql_rules AS matched_rules,
                   collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
        """,
    },
    {
        "query_name": "gcp_logging_disabled_internet_exposed",
        "description": "GCP Cloud Logging/Audit sinks disabled or missing + internet-exposed compute — attacker actions undetectable (T1562.008)",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["gcp", "logging", "audit-log", "blind-spot", "defense-evasion", "high"],
        "mitre_tactics": ["defense-evasion"],
        "mitre_techniques": ["T1562.008"],
        "severity": "high",
        "query_text": """
            MATCH (sink:LogSink {tenant_id: $tid})-[:HAS_FINDING]->(f:Finding)
            WHERE f.rule_id CONTAINS 'log_sink' OR f.rule_id CONTAINS 'audit_log'
               OR f.rule_id CONTAINS 'admin_activity' OR f.rule_id CONTAINS 'data_access'
            WITH count(DISTINCT sink) AS sink_issues, collect(DISTINCT f.rule_id)[..5] AS log_rules
            MATCH (i:Internet)-[:EXPOSES]->(exposed:Resource {tenant_id: $tid})
            WHERE exposed.provider = 'gcp'
            WITH sink_issues, log_rules, count(DISTINCT exposed) AS exposed_count
            WHERE sink_issues > 0 AND exposed_count > 0
            RETURN 'gcp-logging-disabled' AS resource_uid,
                   'GCP logging misconfigured with ' + toString(exposed_count) + ' internet-exposed resources' AS resource_name,
                   'gcp.log_sink' AS resource_type,
                   0 AS threat_count, log_rules AS matched_rules,
                   [] AS threat_details
        """,
    },

    # ── K8s toxic combinations ────────────────────────────────────────────────

    {
        "query_name": "k8s_privileged_pod_host_pid_default_sa",
        "description": "K8s pod with privileged=true + hostPID + default service account — container escape to node, then credential theft from any pod (T1610)",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["k8s", "privileged-pod", "hostPID", "container-escape", "critical"],
        "mitre_tactics": ["privilege-escalation", "credential-access"],
        "mitre_techniques": ["T1610", "T1613", "T1552"],
        "severity": "critical",
        "query_text": """
            MATCH (pod:K8sPod {tenant_id: $tid})-[:HAS_FINDING]->(f:Finding)
            WHERE f.rule_id CONTAINS 'privileged' OR f.rule_id CONTAINS 'host_pid'
               OR f.rule_id CONTAINS 'hostPID' OR f.rule_id CONTAINS 'security_context'
            WITH pod, collect(f.rule_id) AS priv_rules
            MATCH (pod)-[:USES]->(sa:K8sServiceAccount)
            WHERE sa.name = 'default' OR sa.uid CONTAINS '/default'
            WITH pod, priv_rules, sa
            OPTIONAL MATCH (pod)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN pod.uid AS resource_uid, pod.name AS resource_name,
                   pod.resource_type AS resource_type,
                   count(DISTINCT t) AS threat_count, priv_rules AS matched_rules,
                   collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
        """,
    },
    {
        "query_name": "k8s_internet_service_no_network_policy_privileged",
        "description": "K8s Service exposed to internet + no NetworkPolicy + privileged pods in same namespace — direct internet → container escape path (T1190)",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["k8s", "internet-service", "network-policy", "privileged", "critical"],
        "mitre_tactics": ["initial-access", "lateral-movement"],
        "mitre_techniques": ["T1190", "T1610"],
        "severity": "critical",
        "query_text": """
            MATCH (i:Internet)-[:EXPOSES]->(svc:K8sService {tenant_id: $tid})
            WITH DISTINCT svc
            MATCH (svc)-[:HAS_FINDING]->(f:Finding)
            WHERE f.rule_id CONTAINS 'network_policy' OR f.rule_id CONTAINS 'networkpolicy'
               OR f.rule_id CONTAINS 'load_balancer' OR f.rule_id CONTAINS 'external_traffic'
            WITH svc, collect(f.rule_id) AS svc_rules
            OPTIONAL MATCH (svc)-[:SERVES_TRAFFIC_FOR]->(pod:K8sPod)
            OPTIONAL MATCH (pod)-[:HAS_FINDING]->(fp:Finding)
            WHERE fp.rule_id CONTAINS 'privileged'
            WITH svc, svc_rules, count(DISTINCT pod) AS pod_count,
                 collect(DISTINCT fp.rule_id) AS pod_rules
            OPTIONAL MATCH (svc)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN svc.uid AS resource_uid, svc.name AS resource_name,
                   svc.resource_type AS resource_type,
                   count(DISTINCT t) AS threat_count,
                   svc_rules + pod_rules AS matched_rules,
                   collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
        """,
    },
    {
        "query_name": "k8s_wildcard_clusterrole_default_sa",
        "description": "ClusterRoleBinding granting wildcard (*) permissions to default ServiceAccount — any pod in cluster can perform any action (T1613)",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["k8s", "rbac", "wildcard", "clusterrole", "default-sa", "critical"],
        "mitre_tactics": ["privilege-escalation"],
        "mitre_techniques": ["T1613", "T1078"],
        "severity": "critical",
        "query_text": """
            MATCH (crb:K8sClusterRoleBinding {tenant_id: $tid})-[:HAS_FINDING]->(f:Finding)
            WHERE f.rule_id CONTAINS 'wildcard' OR f.rule_id CONTAINS 'star'
               OR f.rule_id CONTAINS 'cluster_admin' OR f.rule_id CONTAINS 'rbac_wildcard'
            WITH crb, collect(f.rule_id) AS rbac_rules
            OPTIONAL MATCH (crb)-[:GRANTS_ACCESS_TO]->(cr:K8sClusterRole)
            OPTIONAL MATCH (cr)-[:HAS_FINDING]->(fcr:Finding)
            WITH crb, rbac_rules, collect(fcr.rule_id) AS cr_rules
            OPTIONAL MATCH (crb)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN crb.uid AS resource_uid, crb.name AS resource_name,
                   crb.resource_type AS resource_type,
                   count(DISTINCT t) AS threat_count,
                   rbac_rules + cr_rules AS matched_rules,
                   collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
        """,
    },
    {
        "query_name": "k8s_secret_env_var_hostpath_mount",
        "description": "K8s pod mounts secrets as env vars + hostPath volume — both credential exposure and node filesystem access (T1552)",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["k8s", "secrets-env", "hostpath", "credential-exposure", "high"],
        "mitre_tactics": ["credential-access"],
        "mitre_techniques": ["T1552", "T1552.007"],
        "severity": "high",
        "query_text": """
            MATCH (pod:K8sPod {tenant_id: $tid})-[:HAS_FINDING]->(f1:Finding)
            WHERE f1.rule_id CONTAINS 'secret_env' OR f1.rule_id CONTAINS 'env_var_secret'
               OR f1.rule_id CONTAINS 'sensitive_env'
            WITH pod, collect(f1.rule_id) AS env_rules
            MATCH (pod)-[:HAS_FINDING]->(f2:Finding)
            WHERE f2.rule_id CONTAINS 'host_path' OR f2.rule_id CONTAINS 'hostPath'
               OR f2.rule_id CONTAINS 'host_volume'
            WITH pod, env_rules, collect(f2.rule_id) AS path_rules
            OPTIONAL MATCH (pod)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN pod.uid AS resource_uid, pod.name AS resource_name,
                   pod.resource_type AS resource_type,
                   count(DISTINCT t) AS threat_count,
                   env_rules + path_rules AS matched_rules,
                   collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
        """,
    },
    {
        "query_name": "k8s_pod_exec_allowed_production_namespace",
        "description": "RBAC allows kubectl exec into pods in production namespace — direct interactive shell access to running workloads (T1609)",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["k8s", "pod-exec", "rbac", "production", "high"],
        "mitre_tactics": ["execution"],
        "mitre_techniques": ["T1609"],
        "severity": "high",
        "query_text": """
            MATCH (rb:K8sRoleBinding {tenant_id: $tid})-[:HAS_FINDING]->(f:Finding)
            WHERE f.rule_id CONTAINS 'pod_exec' OR f.rule_id CONTAINS 'exec_access'
               OR f.rule_id CONTAINS 'pods_exec' OR f.rule_id CONTAINS 'interactive'
            WITH rb, collect(f.rule_id) AS exec_rules
            OPTIONAL MATCH (rb)-[:MEMBER_OF]->(ns:K8sNamespace)
            WHERE ns.name CONTAINS 'prod' OR ns.name CONTAINS 'production'
            OPTIONAL MATCH (rb)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN rb.uid AS resource_uid, rb.name AS resource_name,
                   rb.resource_type AS resource_type,
                   count(DISTINCT t) AS threat_count, exec_rules AS matched_rules,
                   collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
        """,
    },

    # ── Cross-CSP toxic combinations ─────────────────────────────────────────

    {
        "query_name": "cross_csp_k8s_pod_cloud_credential_access",
        "description": "K8s pod with overprivileged SA + cloud provider metadata endpoint reachable — pod compromise → cloud account takeover across CSPs (T1552.005)",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["cross-csp", "k8s", "aws", "azure", "gcp", "metadata-service", "critical"],
        "mitre_tactics": ["credential-access", "privilege-escalation"],
        "mitre_techniques": ["T1552.005", "T1078"],
        "severity": "critical",
        "query_text": """
            MATCH (pod:K8sPod {tenant_id: $tid})-[:USES]->(sa:K8sServiceAccount)
            MATCH (sa)-[:HAS_FINDING]->(f1:Finding)
            WHERE f1.rule_id CONTAINS 'overpriv' OR f1.rule_id CONTAINS 'admin'
               OR f1.rule_id CONTAINS 'wildcard' OR f1.rule_id CONTAINS 'cluster_admin'
            WITH pod, sa, collect(f1.rule_id) AS sa_rules
            MATCH (pod)-[:HAS_FINDING]->(f2:Finding)
            WHERE f2.rule_id CONTAINS 'metadata' OR f2.rule_id CONTAINS 'imds'
               OR f2.rule_id CONTAINS 'network_policy' OR f2.rule_id CONTAINS 'host_network'
            WITH pod, sa_rules, collect(f2.rule_id) AS pod_rules
            OPTIONAL MATCH (pod)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN pod.uid AS resource_uid, pod.name AS resource_name,
                   pod.resource_type AS resource_type,
                   count(DISTINCT t) AS threat_count,
                   sa_rules + pod_rules AS matched_rules,
                   collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
        """,
    },
    {
        "query_name": "cross_csp_internet_exposed_multi_provider",
        "description": "Resources from multiple CSPs exposed to internet with critical findings — attack surface spans cloud boundaries (T1190)",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["cross-csp", "internet-exposed", "multi-provider", "critical"],
        "mitre_tactics": ["initial-access"],
        "mitre_techniques": ["T1190"],
        "severity": "critical",
        "query_text": """
            MATCH (i:Internet)-[:EXPOSES]->(r:Resource {tenant_id: $tid})
            MATCH (r)-[:HAS_FINDING]->(f:Finding)
            WHERE f.severity IN ['critical', 'CRITICAL', 'high', 'HIGH']
            WITH r.provider AS provider, count(DISTINCT r) AS exposed_count,
                 count(DISTINCT f) AS finding_count,
                 collect(DISTINCT r.uid)[..3] AS sample_resources
            WHERE exposed_count > 0
            WITH collect({provider: provider, exposed: exposed_count, findings: finding_count}) AS by_provider,
                 sum(exposed_count) AS total_exposed
            WHERE size(by_provider) > 1
            RETURN 'cross-csp-exposure' AS resource_uid,
                   toString(total_exposed) + ' internet-exposed resources across ' + toString(size(by_provider)) + ' CSPs' AS resource_name,
                   'cross_csp' AS resource_type,
                   0 AS threat_count, [] AS matched_rules,
                   [] AS threat_details
        """,
    },
]

# ── Predefined Hunt Queries ────────────────────────────────────────────────
# hunt_type = 'predefined_hunt', query_language = 'cypher'

PREDEFINED_HUNTS = [
    # ── Enterprise Attack Path Hunts ─────────────────────────────────────────────
    {
        "query_name": "credential_theft_secretsmanager_path",
        "description": "Full attack path: Internet → compute entry point → SecretsManager. T1552.006: credentials in secrets managers.",
        "hunt_type": "predefined_hunt",
        "query_language": "cypher",
        "tags": ["credential-theft", "secretsmanager", "attack-path"],
        "mitre_tactics": ["credential-access"],
        "mitre_techniques": ["T1552", "T1552.006"],
        "query_text": """
            MATCH path = (i:Internet)-[:EXPOSES]->(entry:Resource {tenant_id: $tid})
                         -[rels*1..3]->(secret:Resource {tenant_id: $tid})
            WHERE secret.resource_type IN ['secretsmanager.secret', 'secretsmanager.resource']
              AND ALL(r IN rels WHERE r.attack_path_category IS NOT NULL AND r.attack_path_category <> '')
            RETURN
                entry.uid          AS entry_point,
                entry.resource_type AS entry_type,
                secret.uid         AS target_resource,
                secret.name        AS target_name,
                length(path)       AS path_length,
                [n IN nodes(path) | coalesce(n.name, n.uid)] AS path_nodes,
                [r IN relationships(path) | type(r)] AS path_rels
            ORDER BY path_length ASC
            LIMIT 50
        """,
    },
    {
        "query_name": "credential_theft_ssm_parameters",
        "description": "Attack path to SSM Parameter Store secrets. T1552: credentials stored in parameter store.",
        "hunt_type": "predefined_hunt",
        "query_language": "cypher",
        "tags": ["credential-theft", "ssm", "parameter-store", "attack-path"],
        "mitre_tactics": ["credential-access"],
        "mitre_techniques": ["T1552"],
        "query_text": """
            MATCH path = (i:Internet)-[:EXPOSES]->(entry:Resource {tenant_id: $tid})
                         -[rels*1..3]->(param:SSMParameter {tenant_id: $tid})
            WHERE ALL(r IN rels WHERE r.attack_path_category IS NOT NULL AND r.attack_path_category <> '')
            RETURN
                entry.uid          AS entry_point,
                entry.resource_type AS entry_type,
                param.uid          AS target_resource,
                param.name         AS target_name,
                length(path)       AS path_length,
                [n IN nodes(path) | coalesce(n.name, n.uid)] AS path_nodes,
                [r IN relationships(path) | type(r)] AS path_rels
            ORDER BY path_length ASC
            LIMIT 50
        """,
    },
    {
        "query_name": "kms_key_exposure_decrypt_chain",
        "description": "Internet → compute → KMS key. Compromise unlocks all data encrypted with that key across S3, RDS, EBS. T1485.",
        "hunt_type": "predefined_hunt",
        "query_language": "cypher",
        "tags": ["kms", "encryption-key", "data-decryption", "attack-path"],
        "mitre_tactics": ["collection", "impact"],
        "mitre_techniques": ["T1485", "T1552"],
        "query_text": """
            MATCH path = (i:Internet)-[:EXPOSES]->(entry:Resource {tenant_id: $tid})
                         -[rels*1..3]->(k:KMSKey {tenant_id: $tid})
            WHERE ALL(r IN rels WHERE r.attack_path_category IS NOT NULL AND r.attack_path_category <> '')
            RETURN
                entry.uid          AS entry_point,
                entry.resource_type AS entry_type,
                k.uid              AS target_resource,
                k.name             AS kms_key_name,
                length(path)       AS path_length,
                [n IN nodes(path) | coalesce(n.name, n.uid)] AS path_nodes,
                [r IN relationships(path) | type(r)] AS path_rels
            ORDER BY path_length ASC
            LIMIT 50
        """,
    },
    {
        "query_name": "ai_ml_model_attack_path",
        "description": "Internet-exposed compute accessing AI models (Bedrock/SageMaker) — prompt injection, data exfiltration, model poisoning. T1565.",
        "hunt_type": "predefined_hunt",
        "query_language": "cypher",
        "tags": ["ai-ml", "bedrock", "sagemaker", "model-access", "attack-path"],
        "mitre_tactics": ["collection", "impact"],
        "mitre_techniques": ["T1565", "T1530"],
        "query_text": """
            MATCH path = (i:Internet)-[:EXPOSES]->(entry:Resource {tenant_id: $tid})
                         -[rels*1..3]->(ai:Resource {tenant_id: $tid})
            WHERE ai.resource_type IN [
                'bedrock.foundation-model', 'bedrock.inference-profile',
                'bedrock.agent', 'bedrock.default-prompt-router',
                'sagemaker.endpoint', 'sagemaker.model',
                'sagemaker.notebook-instance', 'sagemaker.training-job'
            ]
            AND ALL(r IN rels WHERE r.attack_path_category IS NOT NULL AND r.attack_path_category <> '')
            RETURN
                entry.uid          AS entry_point,
                entry.resource_type AS entry_type,
                ai.uid             AS target_resource,
                ai.name            AS ai_model_name,
                ai.resource_type   AS model_type,
                length(path)       AS path_length,
                [n IN nodes(path) | coalesce(n.name, n.uid)] AS path_nodes,
                [r IN relationships(path) | type(r)] AS path_rels
            ORDER BY path_length ASC
            LIMIT 50
        """,
    },
    {
        "query_name": "iam_privilege_escalation_full_chain",
        "description": "Internet → compute → IAM role assumption → privilege escalation chain. T1098: account manipulation.",
        "hunt_type": "predefined_hunt",
        "query_language": "cypher",
        "tags": ["iam", "privilege-escalation", "role-assumption", "attack-path"],
        "mitre_tactics": ["privilege-escalation", "persistence"],
        "mitre_techniques": ["T1098", "T1078"],
        "query_text": """
            MATCH path = (i:Internet)-[:EXPOSES]->(entry:Resource {tenant_id: $tid})
                         -[rels*1..4]->(role:IAMRole {tenant_id: $tid})
            WHERE ALL(r IN rels WHERE r.attack_path_category IS NOT NULL AND r.attack_path_category <> '')
            OPTIONAL MATCH (role)-[:HAS_FINDING]->(f:Finding)
            WHERE f.rule_id CONTAINS 'admin' OR f.rule_id CONTAINS 'privilege'
               OR f.rule_id CONTAINS 'full_access' OR f.rule_id CONTAINS 'star'
            RETURN
                entry.uid          AS entry_point,
                entry.resource_type AS entry_type,
                role.uid           AS target_resource,
                role.name          AS role_name,
                collect(DISTINCT f.rule_id)[..3] AS risk_findings,
                length(path)       AS path_length,
                [n IN nodes(path) | coalesce(n.name, n.uid)] AS path_nodes,
                [r IN relationships(path) | type(r)] AS path_rels
            ORDER BY path_length ASC
            LIMIT 50
        """,
    },
    {
        "query_name": "internet_to_database_attack_path",
        "description": "Internet → Lambda/EC2 → database (RDS/DynamoDB/ElastiCache/Redshift). Direct data breach path. T1530.",
        "hunt_type": "predefined_hunt",
        "query_language": "cypher",
        "tags": ["database", "rds", "dynamodb", "elasticache", "data-breach", "attack-path"],
        "mitre_tactics": ["collection", "exfiltration"],
        "mitre_techniques": ["T1530", "T1537"],
        "query_text": """
            MATCH path = (i:Internet)-[:EXPOSES]->(entry:Resource {tenant_id: $tid})
                         -[rels*1..3]->(db:Resource {tenant_id: $tid})
            WHERE db.resource_type IN [
                'rds.instance', 'rds.db-instance', 'rds.cluster', 'rds.db-cluster',
                'dynamodb.table', 'dynamodb.resource',
                'elasticache.cluster', 'elasticache.replication-group',
                'redshift.cluster', 'redshift.resource',
                'docdb.cluster', 'neptune.cluster',
                'azure.sql_server', 'azure.cosmos_db',
                'gcp.cloud_sql_instance', 'gcp.bigquery_dataset'
            ]
            AND ALL(r IN rels WHERE r.attack_path_category IS NOT NULL AND r.attack_path_category <> '')
            RETURN
                entry.uid          AS entry_point,
                entry.resource_type AS entry_type,
                db.uid             AS target_resource,
                db.name            AS database_name,
                db.resource_type   AS database_type,
                db.provider        AS provider,
                length(path)       AS path_length,
                [n IN nodes(path) | coalesce(n.name, n.uid)] AS path_nodes,
                [r IN relationships(path) | type(r)] AS path_rels
            ORDER BY path_length ASC
            LIMIT 100
        """,
    },
    {
        "query_name": "cloudtrail_disabled_detection",
        "description": "Identify accounts where CloudTrail multi-region logging is disabled — attacker can operate without any audit trail. T1562.008.",
        "hunt_type": "predefined_hunt",
        "query_language": "cypher",
        "tags": ["cloudtrail", "audit-logging", "defense-evasion", "blind-spot"],
        "mitre_tactics": ["defense-evasion"],
        "mitre_techniques": ["T1562.008", "T1562"],
        "query_text": """
            MATCH (r:CloudTrailTrail {tenant_id: $tid})-[:HAS_FINDING]->(f:Finding)
            WHERE f.rule_id CONTAINS 'logging' OR f.rule_id CONTAINS 'enabled'
               OR f.rule_id CONTAINS 'multiregion' OR f.rule_id CONTAINS 'multi_region'
               OR f.rule_id CONTAINS 'all_regions'
            WITH r, collect(DISTINCT f.rule_id) AS findings
            OPTIONAL MATCH (i:Internet)-[:EXPOSES]->(exposed:Resource {tenant_id: $tid})
            WITH r, findings, count(DISTINCT exposed) AS exposed_resources
            OPTIONAL MATCH (r)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                r.uid           AS resource_uid,
                r.name          AS resource_name,
                r.account_id    AS account_id,
                r.region        AS region,
                findings,
                exposed_resources,
                count(DISTINCT t) AS threat_count
            ORDER BY exposed_resources DESC
        """,
    },
    {
        "query_name": "supply_chain_container_registry",
        "description": "Compromised/public container image in ECR/ACR/GCR deployed to Lambda/ECS/EKS — supply chain code execution. T1195.002.",
        "hunt_type": "predefined_hunt",
        "query_language": "cypher",
        "tags": ["supply-chain", "container", "ecr", "ecs", "eks", "code-execution"],
        "mitre_tactics": ["initial-access"],
        "mitre_techniques": ["T1195.002", "T1525"],
        "query_text": """
            MATCH (reg:Resource {tenant_id: $tid})-[:PROVIDES_IMAGE_TO]->(consumer:Resource {tenant_id: $tid})
            WHERE reg.resource_type IN ['ecr.repository', 'ecr.resource',
                                         'azure.container_registry', 'gcp.artifact_registry']
            OPTIONAL MATCH (reg)-[:HAS_FINDING]->(f:Finding)
            WHERE f.rule_id CONTAINS 'public' OR f.rule_id CONTAINS 'scan'
               OR f.rule_id CONTAINS 'vulnerability' OR f.rule_id CONTAINS 'immutable'
            OPTIONAL MATCH (i:Internet)-[:EXPOSES]->(consumer)
            WITH reg, consumer, collect(DISTINCT f.rule_id) AS risk_findings,
                 count(DISTINCT i) > 0 AS consumer_internet_exposed
            OPTIONAL MATCH (consumer)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                reg.uid           AS registry_uid,
                reg.name          AS registry_name,
                consumer.uid      AS consumer_uid,
                consumer.resource_type AS consumer_type,
                consumer_internet_exposed,
                risk_findings,
                count(DISTINCT t) AS threat_count
            ORDER BY consumer_internet_exposed DESC, threat_count DESC
            LIMIT 50
        """,
    },
    {
        "query_name": "eks_pod_escape_to_cluster_admin",
        "description": "Internet → K8s Ingress → Pod → ServiceAccount with ClusterRole binding — pod escape to cluster admin. T1610, T1613.",
        "hunt_type": "predefined_hunt",
        "query_language": "cypher",
        "tags": ["kubernetes", "eks", "pod-escape", "service-account", "cluster-admin"],
        "mitre_tactics": ["privilege-escalation", "lateral-movement"],
        "mitre_techniques": ["T1610", "T1613"],
        "query_text": """
            MATCH (i:Internet)-[:EXPOSES]->(eks:EKSCluster {tenant_id: $tid})
            WITH DISTINCT eks
            MATCH (eks)-[:CONTAINS]->(sa:K8sServiceAccount {tenant_id: $tid})
            OPTIONAL MATCH (sa)-[:HAS_FINDING]->(f:Finding)
            WHERE f.rule_id CONTAINS 'admin' OR f.rule_id CONTAINS 'rbac'
               OR f.rule_id CONTAINS 'cluster_role' OR f.rule_id CONTAINS 'wildcard'
            OPTIONAL MATCH (sa)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                eks.uid   AS cluster_uid,
                eks.name  AS cluster_name,
                sa.uid    AS service_account_uid,
                sa.name   AS service_account_name,
                collect(DISTINCT f.rule_id)[..5] AS risk_findings,
                count(DISTINCT t) AS threat_count
            ORDER BY threat_count DESC
            LIMIT 30
        """,
    },
    {
        "query_name": "cognito_unauthenticated_role_assumption",
        "description": "Cognito identity pool with unauthenticated access → IAM role assumption without credentials. T1621: MFA request generation / identity abuse.",
        "hunt_type": "predefined_hunt",
        "query_language": "cypher",
        "tags": ["cognito", "identity-pool", "unauthenticated", "iam-role"],
        "mitre_tactics": ["initial-access", "privilege-escalation"],
        "mitre_techniques": ["T1621", "T1098"],
        "query_text": """
            MATCH (i:Internet)-[:EXPOSES]->(cognito:Resource {tenant_id: $tid})
            WHERE cognito.resource_type IN ['cognito.identity-pool', 'cognito.resource']
            MATCH (cognito)-[:HAS_FINDING]->(f:Finding)
            WHERE f.rule_id CONTAINS 'unauthenticated' OR f.rule_id CONTAINS 'unauth'
            WITH cognito, collect(f.rule_id) AS unauth_rules
            OPTIONAL MATCH (cognito)-[:ASSUMES|ACCESSES]->(role:IAMRole)
            OPTIONAL MATCH (role)-[:HAS_FINDING]->(rf:Finding)
            WHERE rf.rule_id CONTAINS 'admin' OR rf.rule_id CONTAINS 'privilege'
            OPTIONAL MATCH (cognito)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                cognito.uid AS resource_uid, cognito.name AS resource_name,
                unauth_rules, role.uid AS assumed_role,
                collect(DISTINCT rf.rule_id)[..3] AS role_risks,
                count(DISTINCT t) AS threat_count
        """,
    },
    {
        "query_name": "shadow_admin_via_policy_attachment",
        "description": "IAM user/role with PassRole + CreatePolicy/AttachPolicy — can elevate to admin without being directly an admin. T1098.001.",
        "hunt_type": "predefined_hunt",
        "query_language": "cypher",
        "tags": ["iam", "shadow-admin", "pass-role", "privilege-escalation"],
        "mitre_tactics": ["privilege-escalation"],
        "mitre_techniques": ["T1098.001", "T1098"],
        "query_text": """
            MATCH (r:Resource {tenant_id: $tid})-[:HAS_FINDING]->(f:Finding)
            WHERE r.resource_type IN ['iam.user', 'iam.role', 'iam.policy']
              AND (f.rule_id CONTAINS 'pass_role' OR f.rule_id CONTAINS 'passrole'
                OR f.rule_id CONTAINS 'create_policy' OR f.rule_id CONTAINS 'attach_policy'
                OR f.rule_id CONTAINS 'put_role_policy')
            WITH r, collect(DISTINCT f.rule_id) AS escalation_rules
            OPTIONAL MATCH (i:Internet)-[*1..5]->(r)
            WITH r, escalation_rules, count(DISTINCT i) > 0 AS internet_reachable
            OPTIONAL MATCH (r)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                r.uid           AS resource_uid,
                r.name          AS resource_name,
                r.resource_type AS resource_type,
                internet_reachable,
                escalation_rules,
                count(DISTINCT t) AS threat_count
            ORDER BY internet_reachable DESC, threat_count DESC
            LIMIT 30
        """,
    },
    {
        "query_name": "cross_account_role_assumption",
        "description": "IAM roles with external trust policies allowing cross-account assumption — lateral movement across account boundaries. T1199.",
        "hunt_type": "predefined_hunt",
        "query_language": "cypher",
        "tags": ["iam", "cross-account", "trust-policy", "lateral-movement"],
        "mitre_tactics": ["lateral-movement", "initial-access"],
        "mitre_techniques": ["T1199", "T1078"],
        "query_text": """
            MATCH (r:IAMRole {tenant_id: $tid})-[:HAS_FINDING]->(f:Finding)
            WHERE f.rule_id CONTAINS 'cross_account' OR f.rule_id CONTAINS 'external_trust'
               OR f.rule_id CONTAINS 'assume_role' OR f.rule_id CONTAINS 'trust_policy'
               OR f.rule_id CONTAINS 'external_id'
            WITH r, collect(DISTINCT f.rule_id) AS trust_rules
            OPTIONAL MATCH (r)-[:HAS_THREAT]->(t:ThreatDetection)
            OPTIONAL MATCH (r)-[:ACCESSES|ASSUMES*1..3]->(target:Resource)
            WHERE target.resource_type IN [
                's3.resource', 's3.bucket', 'kms.key',
                'secretsmanager.secret', 'dynamodb.table', 'rds.instance'
            ]
            RETURN
                r.uid           AS resource_uid,
                r.name          AS role_name,
                r.account_id    AS account_id,
                trust_rules,
                count(DISTINCT target) AS reachable_sensitive_resources,
                count(DISTINCT t) AS threat_count
            ORDER BY reachable_sensitive_resources DESC, threat_count DESC
            LIMIT 30
        """,
    },
    {
        "query_name": "data_pipeline_full_chain",
        "description": "Internet → Lambda/EC2 → S3 → Glue/Athena → Redshift/OpenSearch — full data pipeline compromise for warehouse exfiltration. T1537.",
        "hunt_type": "predefined_hunt",
        "query_language": "cypher",
        "tags": ["data-pipeline", "s3", "glue", "athena", "redshift", "exfiltration"],
        "mitre_tactics": ["collection", "exfiltration"],
        "mitre_techniques": ["T1537", "T1530"],
        "query_text": """
            MATCH path = (i:Internet)-[:EXPOSES]->(entry:Resource {tenant_id: $tid})
                         -[rels*1..5]->(warehouse:Resource {tenant_id: $tid})
            WHERE warehouse.resource_type IN [
                'redshift.cluster', 'redshift.resource',
                'glue.database', 'glue.table',
                'athena.workgroup',
                'emr.cluster',
                'gcp.bigquery_dataset', 'gcp.bigquery_table'
            ]
            AND ALL(r IN rels WHERE r.attack_path_category IS NOT NULL AND r.attack_path_category <> '')
            RETURN
                entry.uid          AS entry_point,
                entry.resource_type AS entry_type,
                warehouse.uid      AS target_resource,
                warehouse.name     AS warehouse_name,
                warehouse.resource_type AS warehouse_type,
                length(path)       AS path_length,
                [n IN nodes(path) | coalesce(n.name, n.uid)] AS path_nodes
            ORDER BY path_length ASC
            LIMIT 30
        """,
    },
    {
        "query_name": "ssm_run_command_execution",
        "description": "Internet → EC2 → SSM Run Command — remote command execution without SSH. T1651: cloud administration command.",
        "hunt_type": "predefined_hunt",
        "query_language": "cypher",
        "tags": ["ssm", "run-command", "remote-execution", "ec2"],
        "mitre_tactics": ["execution"],
        "mitre_techniques": ["T1651", "T1059"],
        "query_text": """
            MATCH (i:Internet)-[:EXPOSES]->(ec2:EC2Instance {tenant_id: $tid})
            MATCH (ec2)-[:ACCESSES]->(ssm:SSMParameter {tenant_id: $tid})
            WITH ec2, collect(DISTINCT ssm.uid)[..5] AS ssm_params
            OPTIONAL MATCH (ec2)-[:ASSUMES]->(ip:InstanceProfile)-[:ASSUMES]->(role:IAMRole)
            OPTIONAL MATCH (role)-[:HAS_FINDING]->(f:Finding)
            WHERE f.rule_id CONTAINS 'ssm' OR f.rule_id CONTAINS 'run_command'
               OR f.rule_id CONTAINS 'systems_manager'
            OPTIONAL MATCH (ec2)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                ec2.uid   AS resource_uid,
                ec2.name  AS resource_name,
                ssm_params,
                collect(DISTINCT f.rule_id)[..3] AS ssm_risk_rules,
                count(DISTINCT t) AS threat_count
            ORDER BY threat_count DESC
            LIMIT 30
        """,
    },
    {
        "query_name": "internet_to_opensearch_unauth",
        "description": "Internet → compute → OpenSearch/Elasticsearch without auth — full data cluster access. T1530.",
        "hunt_type": "predefined_hunt",
        "query_language": "cypher",
        "tags": ["opensearch", "elasticsearch", "public-endpoint", "data-access"],
        "mitre_tactics": ["collection"],
        "mitre_techniques": ["T1530"],
        "query_text": """
            MATCH (i:Internet)-[:EXPOSES]->(entry:Resource {tenant_id: $tid})
            WHERE entry.resource_type IN [
                'opensearch.domain', 'opensearch.resource',
                'elasticsearch.domain', 'es.resource'
            ]
            WITH DISTINCT entry
            OPTIONAL MATCH (entry)-[:HAS_FINDING]->(f:Finding)
            OPTIONAL MATCH (entry)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                entry.uid  AS resource_uid,
                entry.name AS resource_name,
                entry.resource_type AS resource_type,
                collect(DISTINCT f.rule_id)[..5] AS risk_findings,
                count(DISTINCT t) AS threat_count
            ORDER BY threat_count DESC
            LIMIT 30
        """,
    },
    {
        "query_name": "bedrock_training_data_poisoning",
        "description": "Internet → compute → S3 bucket used for Bedrock/SageMaker training data — model poisoning or exfiltration. T1565.",
        "hunt_type": "predefined_hunt",
        "query_language": "cypher",
        "tags": ["bedrock", "sagemaker", "training-data", "s3", "model-poisoning"],
        "mitre_tactics": ["impact", "collection"],
        "mitre_techniques": ["T1565", "T1530"],
        "query_text": """
            MATCH (i:Internet)-[:EXPOSES]->(entry:Resource {tenant_id: $tid})
            MATCH (entry)-[:ACCESSES]->(s3:S3Bucket {tenant_id: $tid})
            MATCH (ai:Resource {tenant_id: $tid, account_id: s3.account_id})
            WHERE ai.resource_type IN [
                'bedrock.foundation-model', 'bedrock.agent',
                'sagemaker.model', 'sagemaker.training-job'
            ]
            OPTIONAL MATCH (s3)-[:HAS_FINDING]->(f:Finding)
            WHERE f.rule_id CONTAINS 'public' OR f.rule_id CONTAINS 'encrypt'
               OR f.rule_id CONTAINS 'versioning'
            OPTIONAL MATCH (s3)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                entry.uid AS entry_point, s3.uid AS training_bucket,
                s3.name AS bucket_name, ai.uid AS ai_model,
                collect(DISTINCT f.rule_id)[..3] AS bucket_risks,
                count(DISTINCT t) AS threat_count
            LIMIT 30
        """,
    },
    {
        "query_name": "vpc_peering_lateral_movement",
        "description": "Identify VPC peering connections where a compromised VPC can reach sensitive resources in peered VPCs. T1021.",
        "hunt_type": "predefined_hunt",
        "query_language": "cypher",
        "tags": ["vpc", "vpc-peering", "lateral-movement", "network"],
        "mitre_tactics": ["lateral-movement"],
        "mitre_techniques": ["T1021"],
        "query_text": """
            MATCH (i:Internet)-[:EXPOSES]->(exposed:Resource {tenant_id: $tid})
            MATCH (exposed)-[:MEMBER_OF|RUNS_ON]->(vpc:VPC {tenant_id: $tid})
            MATCH (vpc)-[:RELATES_TO|REFERENCES]->(peered_vpc:VPC {tenant_id: $tid})
            WHERE vpc <> peered_vpc
            MATCH (sensitive:Resource {tenant_id: $tid})-[:MEMBER_OF|RUNS_ON]->(peered_vpc)
            WHERE sensitive.resource_type IN [
                'rds.instance', 'rds.db-instance', 'rds.cluster',
                'elasticache.cluster', 'dynamodb.table',
                'secretsmanager.secret', 'efs.file-system'
            ]
            OPTIONAL MATCH (sensitive)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                exposed.uid    AS compromised_resource,
                vpc.uid        AS source_vpc,
                peered_vpc.uid AS peered_vpc,
                sensitive.uid  AS reachable_target,
                sensitive.resource_type AS target_type,
                count(DISTINCT t) AS threat_count
            ORDER BY threat_count DESC
            LIMIT 50
        """,
    },
    {
        "query_name": "data_exfiltration_full_path",
        "description": "All attack paths ending at data stores for exfiltration — S3, RDS, DynamoDB, Glacier from any internet entry point. T1537.",
        "hunt_type": "predefined_hunt",
        "query_language": "cypher",
        "tags": ["data-exfiltration", "s3", "rds", "dynamodb", "attack-path"],
        "mitre_tactics": ["exfiltration", "collection"],
        "mitre_techniques": ["T1537", "T1530"],
        "query_text": """
            MATCH path = (i:Internet)-[:EXPOSES]->(entry:Resource {tenant_id: $tid})
                         -[rels*0..4]->(target:Resource {tenant_id: $tid})
            WHERE target.resource_type IN [
                's3.resource', 's3.bucket',
                'rds.instance', 'rds.db-instance', 'rds.cluster',
                'dynamodb.table', 'dynamodb.resource',
                'efs.file-system', 'elasticfilesystem.file-system',
                'glacier.vault', 'glacier.vaults',
                'azure.blob_container', 'azure.storage_account',
                'gcp.gcs_bucket', 'gcp.bigquery_dataset',
                'oci.object_storage_bucket'
            ]
            AND ALL(r IN rels WHERE r.attack_path_category IS NOT NULL AND r.attack_path_category <> '')
            RETURN
                entry.uid          AS entry_point,
                entry.resource_type AS entry_type,
                target.uid         AS target_resource,
                target.name        AS target_name,
                target.resource_type AS target_type,
                target.provider    AS provider,
                length(path)       AS path_length,
                [n IN nodes(path) | coalesce(n.name, n.uid)] AS path_nodes
            ORDER BY path_length ASC
            LIMIT 100
        """,
    },
    {
        "query_name": "internet_to_sensitive_data",
        "description": "Find attack paths from internet to storage resources with data destruction risk (T1485). Covers S3, Azure Blob, GCS, OCI Object Storage.",
        "hunt_type": "predefined_hunt",
        "query_language": "cypher",
        "tags": ["attack-path", "data-destruction", "storage"],
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1485", "T1530", "T1537"],
        "query_text": """
            MATCH path = (i:Internet)-[*1..5]->(r:Resource {tenant_id: $tid})
            WHERE r.resource_type IN [
                's3.resource', 's3.bucket',
                'azure.storage_account', 'azure.blob_container',
                'gcp.gcs_bucket',
                'oci.object_storage_bucket'
            ]
            AND EXISTS {
                (r)-[:HAS_THREAT]->(t:ThreatDetection)
                WHERE 'T1485' IN t.mitre_techniques
                   OR 'T1530' IN t.mitre_techniques
                   OR 'T1537' IN t.mitre_techniques
            }
            RETURN
                r.uid          AS target_resource,
                r.name         AS resource_name,
                r.resource_type AS resource_type,
                r.provider     AS provider,
                length(path)   AS path_length,
                [n IN nodes(path) | coalesce(n.name, n.uid)] AS path_nodes,
                [rel IN relationships(path) | type(rel)] AS path_rels
            ORDER BY length(path) ASC
        """,
    },
    {
        "query_name": "lateral_movement_identity",
        "description": "Find IAM roles / Azure managed identities / GCP service accounts that can reach other resources — potential lateral movement paths.",
        "hunt_type": "predefined_hunt",
        "query_language": "cypher",
        "tags": ["lateral-movement", "identity", "iam"],
        "mitre_tactics": ["lateral-movement"],
        "mitre_techniques": ["T1021", "T1550"],
        "query_text": """
            MATCH (identity:Resource {tenant_id: $tid})
            WHERE identity.resource_type IN [
                'iam.role', 'iam.policy', 'iam.user',
                'azure.managed_identity', 'azure.service_principal',
                'gcp.iam_service_account',
                'oci.dynamic_group'
            ]
            MATCH (identity)-[:REFERENCES|RELATES_TO*1..3]->(target:Resource)
            WHERE identity <> target
            OPTIONAL MATCH (target)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                identity.uid           AS identity_uid,
                identity.name          AS identity_name,
                identity.resource_type AS identity_type,
                identity.provider      AS provider,
                target.uid             AS reachable_resource,
                target.resource_type   AS target_type,
                collect(DISTINCT t.severity) AS threat_severities
            ORDER BY size(collect(DISTINCT t.severity)) DESC
            LIMIT 50
        """,
    },
    {
        "query_name": "public_storage_with_threats",
        "description": "Storage resources exposed to internet that have active threat detections. Covers S3, Azure Blob/Storage Account, GCS, OCI Object Storage.",
        "hunt_type": "predefined_hunt",
        "query_language": "cypher",
        "tags": ["storage", "internet-exposed", "threats"],
        "mitre_tactics": ["collection"],
        "mitre_techniques": ["T1530"],
        "query_text": """
            MATCH (i:Internet)-[:EXPOSES*1..2]->(r:Resource {tenant_id: $tid})
            WHERE r.resource_type IN [
                's3.resource', 's3.bucket',
                'azure.storage_account', 'azure.blob_container',
                'gcp.gcs_bucket',
                'oci.object_storage_bucket'
            ]
            MATCH (r)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                r.uid           AS resource_uid,
                r.name          AS resource_name,
                r.resource_type AS resource_type,
                r.provider      AS provider,
                collect({
                    severity:   t.severity,
                    category:   t.threat_category,
                    techniques: t.mitre_techniques,
                    risk_score: t.risk_score
                }) AS threats,
                count(t) AS threat_count
            ORDER BY threat_count DESC
        """,
    },
    {
        "query_name": "high_blast_radius",
        "description": "Find resources where compromise could reach 3+ other resources. Works across AWS, Azure, GCP, OCI, K8s.",
        "hunt_type": "predefined_hunt",
        "query_language": "cypher",
        "tags": ["blast-radius", "impact-analysis"],
        "mitre_tactics": ["impact", "lateral-movement"],
        "mitre_techniques": [],
        "query_text": """
            MATCH (r:Resource {tenant_id: $tid})
                -[:REFERENCES|RELATES_TO|ATTACK_PATH*1..4]->
                (target:Resource)
            WHERE r <> target
            WITH r, count(DISTINCT target) AS blast_count
            WHERE blast_count >= 3
            OPTIONAL MATCH (r)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                r.uid           AS resource_uid,
                r.name          AS resource_name,
                r.resource_type AS resource_type,
                r.provider      AS provider,
                blast_count,
                collect(DISTINCT t.severity) AS threat_severities
            ORDER BY blast_count DESC
            LIMIT 20
        """,
    },
    {
        "query_name": "internet_exposed_with_threats",
        "description": "High-criticality or high-risk resources directly reachable from internet that also have active threat detections. CSP-agnostic.",
        "hunt_type": "predefined_hunt",
        "query_language": "cypher",
        "tags": ["internet-exposed", "high-risk", "threats"],
        "mitre_tactics": ["initial-access"],
        "mitre_techniques": ["T1190"],
        "query_text": """
            MATCH (i:Internet)-[:EXPOSES*1..3]->(r:Resource {tenant_id: $tid})
            OPTIONAL MATCH (r)-[:HAS_THREAT]->(t:ThreatDetection)
            WITH r, count(DISTINCT t) AS threat_count,
                 collect(DISTINCT {
                     severity:   t.severity,
                     category:   t.threat_category,
                     techniques: t.mitre_techniques
                 }) AS threats
            WHERE threat_count > 0
              OR r.criticality = 'high'
              OR r.risk_score >= 60
            RETURN
                r.uid           AS resource_uid,
                r.name          AS resource_name,
                r.resource_type AS resource_type,
                r.provider      AS provider,
                r.risk_score    AS risk_score,
                r.criticality   AS criticality,
                threat_count,
                threats
            ORDER BY threat_count DESC, r.risk_score DESC
            LIMIT 30
        """,
    },
    {
        "query_name": "network_boundary_open_rules",
        "description": "SecurityGroups (AWS), NSGs (Azure), VPC Firewall Rules (GCP), and Security Lists (OCI) that allow inbound traffic from 0.0.0.0/0.",
        "hunt_type": "predefined_hunt",
        "query_language": "cypher",
        "tags": ["network", "firewall", "open-inbound", "0.0.0.0/0"],
        "mitre_tactics": ["initial-access"],
        "mitre_techniques": ["T1190"],
        "query_text": """
            MATCH (i:Internet)-[:EXPOSES]->(n:Resource {tenant_id: $tid})
            WHERE n.resource_type IN [
                'ec2.security-group',
                'azure.network_security_group',
                'gcp.vpc_firewall_rule', 'gcp.firewall',
                'oci.security_list', 'oci.network_security_group',
                'k8s.networkpolicy'
            ]
            OPTIONAL MATCH (n)-[:RELATES_TO|REFERENCES]->(downstream:Resource)
            OPTIONAL MATCH (downstream)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                n.uid           AS boundary_resource_uid,
                n.name          AS boundary_resource_name,
                n.resource_type AS resource_type,
                n.provider      AS provider,
                count(DISTINCT downstream) AS downstream_count,
                count(DISTINCT t)           AS downstream_threats
            ORDER BY downstream_threats DESC, downstream_count DESC
            LIMIT 30
        """,
    },
]


def seed(tenant_id: str = "__global__"):
    """
    Seed threat_hunt_queries for the given tenant.

    Uses tenant_id='__global__' by default — queries apply to all tenants.
    The graph_queries.py code filters by tenant_id='__global__' OR the
    actual tenant_id when loading patterns.
    """
    conn = _conn()
    try:
        # Ensure tenant exists
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO tenants (tenant_id, tenant_name) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                (tenant_id, "global"),
            )
        conn.commit()

        all_queries = TOXIC_PATTERNS + PREDEFINED_HUNTS
        inserted = 0
        updated = 0

        for q in all_queries:
            with conn.cursor() as cur:
                # Check if already exists (by query_name + tenant_id)
                cur.execute(
                    "SELECT hunt_id FROM threat_hunt_queries WHERE query_name = %s AND tenant_id = %s",
                    (q["query_name"], tenant_id),
                )
                existing = cur.fetchone()

                if existing:
                    # Update existing
                    cur.execute("""
                        UPDATE threat_hunt_queries SET
                            description = %s,
                            hunt_type = %s,
                            query_language = %s,
                            query_text = %s,
                            target_data_sources = %s,
                            mitre_tactics = %s,
                            mitre_techniques = %s,
                            tags = %s,
                            is_active = TRUE
                        WHERE hunt_id = %s
                    """, (
                        q["description"],
                        q["hunt_type"],
                        q["query_language"],
                        q["query_text"],
                        Json(["neo4j"]),
                        Json(q.get("mitre_tactics", [])),
                        Json(q.get("mitre_techniques", [])),
                        Json(q.get("tags", [])),
                        existing[0],
                    ))
                    updated += 1
                    print(f"  Updated: {q['query_name']} ({q['hunt_type']})")
                else:
                    # Insert new
                    cur.execute("""
                        INSERT INTO threat_hunt_queries (
                            tenant_id, query_name, description,
                            hunt_type, query_language, query_text,
                            target_data_sources, mitre_tactics, mitre_techniques,
                            tags, is_active, created_by
                        ) VALUES (
                            %s, %s, %s,
                            %s, %s, %s,
                            %s, %s, %s,
                            %s, TRUE, 'system'
                        )
                    """, (
                        tenant_id,
                        q["query_name"],
                        q["description"],
                        q["hunt_type"],
                        q["query_language"],
                        q["query_text"],
                        Json(["neo4j"]),
                        Json(q.get("mitre_tactics", [])),
                        Json(q.get("mitre_techniques", [])),
                        Json(q.get("tags", [])),
                    ))
                    inserted += 1
                    print(f"  Inserted: {q['query_name']} ({q['hunt_type']})")

            conn.commit()

        print(f"\nDone: {inserted} inserted, {updated} updated ({len(all_queries)} total)")
        print(f"  Toxic combinations: {len(TOXIC_PATTERNS)}")
        print(f"  Predefined hunts:   {len(PREDEFINED_HUNTS)}")

    finally:
        conn.close()


if __name__ == "__main__":
    tid = sys.argv[1] if len(sys.argv) > 1 else "__global__"
    print(f"Seeding threat_hunt_queries for tenant_id={tid}")
    seed(tid)
