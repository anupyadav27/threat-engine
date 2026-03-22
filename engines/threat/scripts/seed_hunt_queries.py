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

import json
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
]

# ── Predefined Hunt Queries ────────────────────────────────────────────────
# hunt_type = 'predefined_hunt', query_language = 'cypher'

PREDEFINED_HUNTS = [
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
