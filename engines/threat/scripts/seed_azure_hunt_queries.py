#!/usr/bin/env python3
"""
Seed threat_hunt_queries with Azure and cross-CSP toxic combination patterns.

Adds 5 Azure-specific patterns and 2 cross-CSP attack chain patterns.
Safe to re-run — uses UPDATE when query_name + tenant_id already exists.

Usage:
    # With port-forward to RDS:
    THREAT_DB_HOST=localhost THREAT_DB_PORT=5432 \
    THREAT_DB_NAME=threat_engine_threat THREAT_DB_USER=postgres \
    THREAT_DB_PASSWORD=xxx python seed_azure_hunt_queries.py [tenant_id]

    # Global (all tenants):
    python seed_azure_hunt_queries.py __global__
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))

import psycopg2
from psycopg2.extras import Json


def _conn():
    host = os.getenv("THREAT_DB_HOST", "localhost")
    port = os.getenv("THREAT_DB_PORT", "5432")
    db = os.getenv("THREAT_DB_NAME", "threat_engine_threat")
    user = os.getenv("THREAT_DB_USER", "postgres")
    pwd = os.getenv("THREAT_DB_PASSWORD", "")
    return psycopg2.connect(host=host, port=port, dbname=db, user=user, password=pwd)


# ── Azure Toxic Combination Patterns ─────────────────────────────────────────

AZURE_TOXIC_PATTERNS = [
    {
        "query_name": "azure_storage_public_no_encryption_sensitive",
        "description": "Azure StorageAccount publicly accessible + no CMK encryption — plaintext data breach (T1530)",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["azure", "storage", "public-access", "encryption", "critical"],
        "mitre_tactics": ["collection", "exfiltration"],
        "mitre_techniques": ["T1530", "T1537"],
        "severity": "critical",
        "query_text": """
            MATCH (i:Internet)-[:EXPOSES]->(sa:StorageAccount {tenant_id: $tid})
            MATCH (sa)-[:HAS_FINDING]->(f1:Finding)
            WHERE f1.rule_id CONTAINS 'public_access' OR f1.rule_id CONTAINS 'blob_public'
            WITH sa, collect(f1.rule_id) AS access_rules
            MATCH (sa)-[:HAS_FINDING]->(f2:Finding)
            WHERE f2.rule_id CONTAINS 'encrypt' OR f2.rule_id CONTAINS 'cmk'
            OPTIONAL MATCH (sa)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN sa.uid AS resource_uid, sa.name AS resource_name,
                   sa.resource_type AS resource_type,
                   count(DISTINCT t) AS threat_count,
                   access_rules + collect(f2.rule_id) AS matched_rules,
                   collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
        """,
    },
    {
        "query_name": "azure_sp_overprivileged_admin_role",
        "description": "Azure Service Principal with Owner/Contributor at subscription scope + expiring or MFA-less credentials — lateral movement (T1098.001)",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["azure", "service-principal", "iam", "admin-role", "privilege-escalation", "critical"],
        "mitre_tactics": ["privilege-escalation", "persistence"],
        "mitre_techniques": ["T1098.001", "T1078.004"],
        "severity": "critical",
        "query_text": """
            MATCH (sp:ServicePrincipal {tenant_id: $tid})-[:HAS_FINDING]->(f:Finding)
            WHERE f.rule_id CONTAINS 'owner_role' OR f.rule_id CONTAINS 'contributor'
                 OR f.rule_id CONTAINS 'subscription_scope'
            WITH sp, collect(f.rule_id) AS iam_rules
            MATCH (sp)-[:HAS_FINDING]->(f2:Finding)
            WHERE f2.rule_id CONTAINS 'credential_expiry' OR f2.rule_id CONTAINS 'no_mfa'
            OPTIONAL MATCH (sp)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN sp.uid AS resource_uid, sp.name AS resource_name,
                   sp.resource_type AS resource_type,
                   count(DISTINCT t) AS threat_count,
                   iam_rules + collect(f2.rule_id) AS matched_rules,
                   collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
        """,
    },
    {
        "query_name": "azure_vm_public_ip_admin_identity_no_disk_encryption",
        "description": "Azure VM internet-exposed + admin ManagedIdentity + no disk encryption — identity chain to sensitive workloads (T1078.004)",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["azure", "virtual-machine", "managed-identity", "disk-encryption", "public-ip", "critical"],
        "mitre_tactics": ["initial-access", "privilege-escalation"],
        "mitre_techniques": ["T1078.004", "T1552"],
        "severity": "critical",
        "query_text": """
            MATCH (i:Internet)-[:EXPOSES]->(vm:VirtualMachine {tenant_id: $tid})
            WITH DISTINCT vm
            MATCH (vm)-[:AUTHENTICATES_VIA]->(mi:ManagedIdentity)
            MATCH (mi)-[:HAS_FINDING]->(f_iam:Finding)
            WHERE f_iam.rule_id CONTAINS 'admin' OR f_iam.rule_id CONTAINS 'owner'
            WITH vm, mi, collect(f_iam.rule_id) AS iam_rules
            MATCH (vm)-[:HAS_FINDING]->(f_disk:Finding)
            WHERE f_disk.rule_id CONTAINS 'disk_encrypt' OR f_disk.rule_id CONTAINS 'cmk'
            OPTIONAL MATCH (vm)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN vm.uid AS resource_uid, vm.name AS resource_name,
                   vm.resource_type AS resource_type,
                   count(DISTINCT t) AS threat_count,
                   iam_rules + collect(f_disk.rule_id) AS matched_rules,
                   collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
        """,
    },
    {
        "query_name": "azure_sql_server_public_no_auditing_no_tde",
        "description": "Azure SQL Server internet-exposed + no auditing + no TDE — database fully accessible and unmonitored (T1190, T1530)",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["azure", "sql-server", "database", "public-access", "auditing", "tde", "critical"],
        "mitre_tactics": ["initial-access", "collection"],
        "mitre_techniques": ["T1190", "T1530"],
        "severity": "critical",
        "query_text": """
            MATCH (i:Internet)-[:EXPOSES]->(sql:SQLServer {tenant_id: $tid})
            WITH DISTINCT sql
            MATCH (sql)-[:HAS_FINDING]->(f1:Finding)
            WHERE f1.rule_id CONTAINS 'firewall' OR f1.rule_id CONTAINS 'public_access'
            WITH sql, collect(f1.rule_id) AS net_rules
            MATCH (sql)-[:HAS_FINDING]->(f2:Finding)
            WHERE f2.rule_id CONTAINS 'audit' OR f2.rule_id CONTAINS 'tde'
                OR f2.rule_id CONTAINS 'encrypt'
            OPTIONAL MATCH (sql)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN sql.uid AS resource_uid, sql.name AS resource_name,
                   sql.resource_type AS resource_type,
                   count(DISTINCT t) AS threat_count,
                   net_rules + collect(f2.rule_id) AS matched_rules,
                   collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
        """,
    },
    {
        "query_name": "azure_aks_public_api_no_aad_privileged_pods",
        "description": "AKS cluster with public API endpoint + no AAD auth + privileged pods — unauthenticated cluster access with container escape path (T1190, T1610, T1611)",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["azure", "aks", "kubernetes", "public-api", "aad", "privileged-pods", "critical"],
        "mitre_tactics": ["initial-access", "privilege-escalation"],
        "mitre_techniques": ["T1190", "T1610", "T1611"],
        "severity": "critical",
        "query_text": """
            MATCH (i:Internet)-[:EXPOSES]->(aks:AKSCluster {tenant_id: $tid})
            WITH DISTINCT aks
            MATCH (aks)-[:HAS_FINDING]->(f1:Finding)
            WHERE f1.rule_id CONTAINS 'aad' OR f1.rule_id CONTAINS 'rbac'
            WITH aks, collect(f1.rule_id) AS auth_rules
            MATCH (aks)-[:CONTAINS]->(pod:Pod)-[:HAS_FINDING]->(f2:Finding)
            WHERE f2.rule_id CONTAINS 'privileged' OR f2.rule_id CONTAINS 'host_pid'
                OR f2.rule_id CONTAINS 'host_network'
            OPTIONAL MATCH (aks)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN aks.uid AS resource_uid, aks.name AS resource_name,
                   aks.resource_type AS resource_type,
                   count(DISTINCT t) AS threat_count,
                   auth_rules + collect(f2.rule_id) AS matched_rules,
                   collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
        """,
    },
]

# ── Cross-CSP Attack Chain Patterns ──────────────────────────────────────────

CROSS_CSP_PATTERNS = [
    {
        "query_name": "cross_csp_aws_azure_lateral_movement",
        "description": "AWS resource with cross-account/federation trust AND privileged Azure Service Principal in same tenant — federated identity abuse enables cloud hopping (T1098.001, T1078)",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["cross-csp", "aws", "azure", "lateral-movement", "federation", "critical"],
        "mitre_tactics": ["lateral-movement", "privilege-escalation"],
        "mitre_techniques": ["T1098.001", "T1078", "T1199"],
        "severity": "critical",
        "query_text": """
            MATCH (r:Resource {tenant_id: $tid, provider: 'aws'})-[:HAS_FINDING]->(f1:Finding)
            WHERE f1.rule_id CONTAINS 'cross_account' OR f1.rule_id CONTAINS 'federation'
            WITH r, collect(f1.rule_id) AS aws_rules
            MATCH (sp:ServicePrincipal {tenant_id: $tid, provider: 'azure'})-[:HAS_FINDING]->(f2:Finding)
            WHERE f2.rule_id CONTAINS 'owner' OR f2.rule_id CONTAINS 'privileged'
            OPTIONAL MATCH (r)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN r.uid AS resource_uid, r.name AS resource_name,
                   r.resource_type AS resource_type,
                   'cross_csp_lateral_movement' AS combo_type,
                   count(DISTINCT t) AS threat_count,
                   aws_rules + collect(f2.rule_id) AS matched_rules,
                   collect(DISTINCT {severity: t.severity}) AS threat_details
        """,
    },
    {
        "query_name": "cross_csp_k8s_pod_cloud_metadata_escalation",
        "description": "K8s Pod with metadata API / IMDS / automount finding AND active T1552 threat — cloud credential theft via container (T1552.005)",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "tags": ["cross-csp", "kubernetes", "k8s", "metadata-api", "imds", "cloud-account-takeover", "critical"],
        "mitre_tactics": ["credential-access", "privilege-escalation"],
        "mitre_techniques": ["T1552", "T1552.005", "T1610"],
        "severity": "critical",
        "query_text": """
            MATCH (pod:Pod {tenant_id: $tid})-[:HAS_FINDING]->(f1:Finding)
            WHERE f1.rule_id CONTAINS 'metadata' OR f1.rule_id CONTAINS 'imds'
                OR f1.rule_id CONTAINS 'automount'
            WITH pod, collect(f1.rule_id) AS pod_rules
            OPTIONAL MATCH (pod)-[:HAS_THREAT]->(t:ThreatDetection)
            WHERE t.mitre_techniques CONTAINS 'T1552'
            RETURN pod.uid AS resource_uid, pod.name AS resource_name,
                   pod.resource_type AS resource_type,
                   'k8s_to_cloud_escalation' AS combo_type,
                   count(DISTINCT t) AS threat_count,
                   pod_rules AS matched_rules,
                   collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
        """,
    },
]

ALL_PATTERNS = AZURE_TOXIC_PATTERNS + CROSS_CSP_PATTERNS


def seed(tenant_id: str) -> None:
    conn = _conn()
    inserted = 0
    updated = 0

    try:
        for q in ALL_PATTERNS:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT hunt_id FROM threat_hunt_queries WHERE query_name = %s AND tenant_id = %s",
                    (q["query_name"], tenant_id),
                )
                existing = cur.fetchone()

                if existing:
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
                    print(f"  Updated: {q['query_name']}")
                else:
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
                    print(f"  Inserted: {q['query_name']}")

            conn.commit()

        print(f"\nDone: {inserted} inserted, {updated} updated ({len(ALL_PATTERNS)} total)")
        print(f"  Azure patterns:     {len(AZURE_TOXIC_PATTERNS)}")
        print(f"  Cross-CSP patterns: {len(CROSS_CSP_PATTERNS)}")

    finally:
        conn.close()


if __name__ == "__main__":
    tid = sys.argv[1] if len(sys.argv) > 1 else "__global__"
    print(f"Seeding Azure + cross-CSP hunt queries for tenant_id={tid}")
    seed(tid)
