#!/usr/bin/env python3
"""
Seed Threat Hunt Queries from MITRE Technique Reference.

Generates SQL-based hunt queries that target threat_detections + threat_analysis
tables using MITRE detection guidance (CloudTrail events, GuardDuty types, etc.).

Each query is:
  1. Generated from mitre_technique_reference.detection_guidance
  2. Stored in threat_hunt_queries table
  3. Validated via dry-run (--dry-run) or actually inserted (default)

Usage:
    python scripts/seed_hunt_queries.py --dry-run          # preview only
    python scripts/seed_hunt_queries.py                    # insert to DB
    python scripts/seed_hunt_queries.py --validate-only    # run each query, show results
"""

import argparse
import json
import os
import sys
from typing import Any, Dict, List

import psycopg2
from psycopg2.extras import Json, RealDictCursor


def get_conn():
    return psycopg2.connect(
        host=os.getenv("THREAT_DB_HOST", "localhost"),
        port=int(os.getenv("THREAT_DB_PORT", "5432")),
        database=os.getenv("THREAT_DB_NAME", "threat_engine_threat"),
        user=os.getenv("THREAT_DB_USER", "postgres"),
        password=os.getenv("THREAT_DB_PASSWORD", ""),
    )


# ── Hunt Query Definitions ──────────────────────────────────────────────────
# Each query is a SQL statement that hunts for specific threat patterns
# across threat_detections and threat_analysis tables.
#
# Categories:
#   1. MITRE technique-specific hunts (one per critical/high technique)
#   2. Cross-technique correlation hunts (multi-technique attack patterns)
#   3. Blast-radius / risk-score hunts (prioritization)
#   4. Detection gap hunts (what we're NOT seeing)

HUNT_QUERIES: List[Dict[str, Any]] = [

    # ── Category 1: Critical MITRE Technique Hunts ───────────────────────

    {
        "query_name": "Hunt: Exploit Public-Facing Application (T1190)",
        "description": (
            "Find resources with T1190 detections — public-facing apps that could be "
            "exploited for initial access. Cross-reference with internet-reachable "
            "resources from threat_analysis."
        ),
        "hunt_type": "mitre_technique",
        "query_language": "sql",
        "query_text": """
            SELECT
                d.detection_id, d.resource_arn, d.resource_type,
                d.severity, d.confidence, d.account_id, d.region,
                a.risk_score, a.verdict,
                a.analysis_results->'reachability'->>'is_internet_reachable' AS internet_reachable,
                a.analysis_results->'blast_radius'->>'reachable_count' AS blast_radius,
                d.mitre_techniques, d.mitre_tactics
            FROM threat_detections d
            LEFT JOIN threat_analysis a ON d.detection_id = a.detection_id
            WHERE d.tenant_id = :tenant_id
              AND d.mitre_techniques @> '["T1190"]'::jsonb
            ORDER BY a.risk_score DESC NULLS LAST
        """,
        "target_data_sources": ["CloudTrail", "VPC Flow Logs", "ALB/WAF Logs"],
        "mitre_tactics": ["Initial Access"],
        "mitre_techniques": ["T1190"],
        "tags": ["initial-access", "public-facing", "critical"],
    },
    {
        "query_name": "Hunt: Data Destruction / Ransomware (T1485, T1486, T1490)",
        "description": (
            "Find resources at risk of data destruction, ransomware encryption, "
            "or inhibited system recovery. These three techniques together signal "
            "a ransomware kill chain."
        ),
        "hunt_type": "mitre_technique",
        "query_language": "sql",
        "query_text": """
            SELECT
                d.detection_id, d.resource_arn, d.resource_type,
                d.severity, d.account_id, d.region,
                a.risk_score, a.verdict,
                a.analysis_results->'blast_radius'->>'reachable_count' AS blast_radius,
                a.attack_chain,
                d.mitre_techniques
            FROM threat_detections d
            LEFT JOIN threat_analysis a ON d.detection_id = a.detection_id
            WHERE d.tenant_id = :tenant_id
              AND (
                d.mitre_techniques @> '["T1485"]'::jsonb
                OR d.mitre_techniques @> '["T1486"]'::jsonb
                OR d.mitre_techniques @> '["T1490"]'::jsonb
              )
            ORDER BY a.risk_score DESC NULLS LAST
        """,
        "target_data_sources": ["CloudTrail", "S3 Access Logs", "Backup Vault Logs"],
        "mitre_tactics": ["Impact"],
        "mitre_techniques": ["T1485", "T1486", "T1490"],
        "tags": ["ransomware", "data-destruction", "impact", "critical"],
    },
    {
        "query_name": "Hunt: Data Exfiltration via Cloud Storage (T1530, T1537)",
        "description": (
            "Find resources where attackers could access cloud storage data (T1530) "
            "or transfer it to external cloud accounts (T1537). Key indicators of "
            "data exfiltration."
        ),
        "hunt_type": "mitre_technique",
        "query_language": "sql",
        "query_text": """
            SELECT
                d.detection_id, d.resource_arn, d.resource_type,
                d.severity, d.account_id, d.region,
                a.risk_score, a.verdict,
                a.analysis_results->'reachability'->>'is_internet_reachable' AS internet_reachable,
                d.mitre_techniques, d.mitre_tactics
            FROM threat_detections d
            LEFT JOIN threat_analysis a ON d.detection_id = a.detection_id
            WHERE d.tenant_id = :tenant_id
              AND (
                d.mitre_techniques @> '["T1530"]'::jsonb
                OR d.mitre_techniques @> '["T1537"]'::jsonb
              )
            ORDER BY a.risk_score DESC NULLS LAST
        """,
        "target_data_sources": ["CloudTrail", "S3 Access Logs", "IAM Access Analyzer"],
        "mitre_tactics": ["Collection", "Exfiltration"],
        "mitre_techniques": ["T1530", "T1537"],
        "tags": ["exfiltration", "cloud-storage", "s3", "high"],
    },
    {
        "query_name": "Hunt: Credential Abuse & Account Manipulation (T1078, T1098)",
        "description": (
            "Find resources with valid account abuse (T1078) or account manipulation "
            "(T1098) risks. These techniques allow attackers to maintain persistence "
            "and escalate privileges."
        ),
        "hunt_type": "mitre_technique",
        "query_language": "sql",
        "query_text": """
            SELECT
                d.detection_id, d.resource_arn, d.resource_type,
                d.severity, d.account_id, d.region,
                a.risk_score, a.verdict,
                a.analysis_results->'blast_radius'->>'reachable_count' AS blast_radius,
                d.mitre_techniques
            FROM threat_detections d
            LEFT JOIN threat_analysis a ON d.detection_id = a.detection_id
            WHERE d.tenant_id = :tenant_id
              AND (
                d.mitre_techniques @> '["T1078"]'::jsonb
                OR d.mitre_techniques @> '["T1098"]'::jsonb
              )
            ORDER BY a.risk_score DESC NULLS LAST
        """,
        "target_data_sources": ["CloudTrail", "IAM Credential Report", "GuardDuty"],
        "mitre_tactics": ["Persistence", "Privilege Escalation", "Defense Evasion"],
        "mitre_techniques": ["T1078", "T1098"],
        "tags": ["credential-abuse", "iam", "persistence", "high"],
    },
    {
        "query_name": "Hunt: Defense Evasion / Impair Defenses (T1562)",
        "description": (
            "Find resources where logging, monitoring, or security controls may be "
            "disabled or impaired. Attackers use T1562 to blind defenders before "
            "executing their primary objective."
        ),
        "hunt_type": "mitre_technique",
        "query_language": "sql",
        "query_text": """
            SELECT
                d.detection_id, d.resource_arn, d.resource_type,
                d.severity, d.account_id, d.region,
                a.risk_score, a.verdict,
                d.mitre_techniques, d.mitre_tactics
            FROM threat_detections d
            LEFT JOIN threat_analysis a ON d.detection_id = a.detection_id
            WHERE d.tenant_id = :tenant_id
              AND d.mitre_techniques @> '["T1562"]'::jsonb
            ORDER BY a.risk_score DESC NULLS LAST
        """,
        "target_data_sources": ["CloudTrail", "Config Rules", "GuardDuty"],
        "mitre_tactics": ["Defense Evasion"],
        "mitre_techniques": ["T1562"],
        "tags": ["defense-evasion", "logging-disabled", "critical"],
    },

    # ── Category 2: Cross-Technique Correlation Hunts ────────────────────

    {
        "query_name": "Hunt: Full Kill Chain — Initial Access to Impact",
        "description": (
            "Find resources that have MITRE techniques spanning the full kill chain: "
            "Initial Access (T1190) + Persistence (T1078/T1098) + Impact (T1485/T1486). "
            "These indicate a complete attack path from entry to destruction."
        ),
        "hunt_type": "correlation",
        "query_language": "sql",
        "query_text": """
            SELECT
                d.detection_id, d.resource_arn, d.resource_type,
                d.severity, d.account_id, d.region,
                a.risk_score, a.verdict,
                a.attack_chain,
                d.mitre_techniques, d.mitre_tactics,
                jsonb_array_length(d.mitre_techniques) AS technique_count
            FROM threat_detections d
            LEFT JOIN threat_analysis a ON d.detection_id = a.detection_id
            WHERE d.tenant_id = :tenant_id
              AND d.mitre_techniques @> '["T1190"]'::jsonb
              AND (d.mitre_techniques @> '["T1078"]'::jsonb OR d.mitre_techniques @> '["T1098"]'::jsonb)
              AND (d.mitre_techniques @> '["T1485"]'::jsonb OR d.mitre_techniques @> '["T1486"]'::jsonb)
            ORDER BY a.risk_score DESC NULLS LAST
        """,
        "target_data_sources": ["CloudTrail", "GuardDuty", "VPC Flow Logs"],
        "mitre_tactics": ["Initial Access", "Persistence", "Impact"],
        "mitre_techniques": ["T1190", "T1078", "T1098", "T1485", "T1486"],
        "tags": ["kill-chain", "full-attack-path", "critical", "correlation"],
    },
    {
        "query_name": "Hunt: Privilege Escalation Chain (T1078 → T1098 → T1562)",
        "description": (
            "Find resources where attackers could use valid accounts to manipulate "
            "other accounts, then disable defenses. Classic privilege escalation path."
        ),
        "hunt_type": "correlation",
        "query_language": "sql",
        "query_text": """
            SELECT
                d.detection_id, d.resource_arn, d.resource_type,
                d.severity, d.account_id, d.region,
                a.risk_score, a.verdict,
                a.attack_chain,
                d.mitre_techniques
            FROM threat_detections d
            LEFT JOIN threat_analysis a ON d.detection_id = a.detection_id
            WHERE d.tenant_id = :tenant_id
              AND d.mitre_techniques @> '["T1078"]'::jsonb
              AND d.mitre_techniques @> '["T1098"]'::jsonb
              AND d.mitre_techniques @> '["T1562"]'::jsonb
            ORDER BY a.risk_score DESC NULLS LAST
        """,
        "target_data_sources": ["CloudTrail", "IAM Credential Report"],
        "mitre_tactics": ["Privilege Escalation", "Defense Evasion", "Persistence"],
        "mitre_techniques": ["T1078", "T1098", "T1562"],
        "tags": ["privilege-escalation", "iam-chain", "high", "correlation"],
    },

    # ── Category 3: Risk-Score & Blast-Radius Hunts ──────────────────────

    {
        "query_name": "Hunt: Critical Risk Detections (score >= 80)",
        "description": (
            "Find all detections with risk_score >= 80, indicating critical risk. "
            "These combine high severity, blast radius, and MITRE impact."
        ),
        "hunt_type": "risk_priority",
        "query_language": "sql",
        "query_text": """
            SELECT
                d.detection_id, d.resource_arn, d.resource_type,
                d.severity, d.account_id, d.region,
                a.risk_score, a.verdict,
                a.analysis_results->'blast_radius'->>'reachable_count' AS blast_radius,
                a.analysis_results->'reachability'->>'is_internet_reachable' AS internet_reachable,
                a.analysis_results->'mitre_analysis'->>'impact_score' AS mitre_impact,
                a.analysis_results->'mitre_analysis'->>'guidance_coverage' AS guidance_coverage,
                d.mitre_techniques
            FROM threat_detections d
            JOIN threat_analysis a ON d.detection_id = a.detection_id
            WHERE d.tenant_id = :tenant_id
              AND a.risk_score >= 80
            ORDER BY a.risk_score DESC
        """,
        "target_data_sources": ["threat_analysis"],
        "mitre_tactics": [],
        "mitre_techniques": [],
        "tags": ["high-risk", "priority", "triage"],
    },
    {
        "query_name": "Hunt: Internet-Reachable High-Severity Resources",
        "description": (
            "Find resources that are both internet-reachable AND have high/critical "
            "severity detections. Top priority for remediation."
        ),
        "hunt_type": "risk_priority",
        "query_language": "sql",
        "query_text": """
            SELECT
                d.detection_id, d.resource_arn, d.resource_type,
                d.severity, d.account_id, d.region,
                a.risk_score, a.verdict,
                a.analysis_results->'blast_radius'->>'reachable_count' AS blast_radius,
                d.mitre_techniques, d.mitre_tactics
            FROM threat_detections d
            JOIN threat_analysis a ON d.detection_id = a.detection_id
            WHERE d.tenant_id = :tenant_id
              AND d.severity IN ('critical', 'high')
              AND (a.analysis_results->'reachability'->>'is_internet_reachable')::boolean = true
            ORDER BY a.risk_score DESC
        """,
        "target_data_sources": ["threat_analysis", "inventory_relationships"],
        "mitre_tactics": [],
        "mitre_techniques": [],
        "tags": ["internet-reachable", "high-severity", "priority"],
    },
    {
        "query_name": "Hunt: Largest Blast Radius (top 20)",
        "description": (
            "Find the 20 detections with the largest blast radius — most reachable "
            "resources if compromised. Prioritize isolation for these."
        ),
        "hunt_type": "risk_priority",
        "query_language": "sql",
        "query_text": """
            SELECT
                d.detection_id, d.resource_arn, d.resource_type,
                d.severity, d.account_id, d.region,
                a.risk_score, a.verdict,
                (a.analysis_results->'blast_radius'->>'reachable_count')::int AS blast_radius,
                a.analysis_results->'blast_radius'->'depth_distribution' AS depth_dist,
                d.mitre_techniques
            FROM threat_detections d
            JOIN threat_analysis a ON d.detection_id = a.detection_id
            WHERE d.tenant_id = :tenant_id
              AND (a.analysis_results->'blast_radius'->>'reachable_count')::int > 0
            ORDER BY (a.analysis_results->'blast_radius'->>'reachable_count')::int DESC
            LIMIT 20
        """,
        "target_data_sources": ["threat_analysis", "inventory_relationships"],
        "mitre_tactics": [],
        "mitre_techniques": [],
        "tags": ["blast-radius", "isolation", "priority"],
    },

    # ── Category 4: Detection Gap Hunts ──────────────────────────────────

    {
        "query_name": "Hunt: Detections Without MITRE Mapping",
        "description": (
            "Find threat detections that have NO MITRE techniques mapped. "
            "These are blind spots — we can't assess their attack significance."
        ),
        "hunt_type": "gap_analysis",
        "query_language": "sql",
        "query_text": """
            SELECT
                d.detection_id, d.resource_arn, d.resource_type,
                d.severity, d.detection_type, d.rule_id,
                d.account_id, d.region
            FROM threat_detections d
            WHERE d.tenant_id = :tenant_id
              AND (
                d.mitre_techniques IS NULL
                OR d.mitre_techniques = '[]'::jsonb
                OR jsonb_array_length(d.mitre_techniques) = 0
              )
            ORDER BY d.severity, d.resource_arn
        """,
        "target_data_sources": ["threat_detections"],
        "mitre_tactics": [],
        "mitre_techniques": [],
        "tags": ["gap-analysis", "unmapped", "coverage"],
    },
    {
        "query_name": "Hunt: Detections Without Analysis (unscored)",
        "description": (
            "Find threat detections that have NOT been analyzed yet — no risk_score, "
            "no blast radius, no verdict. These slipped through the analyzer."
        ),
        "hunt_type": "gap_analysis",
        "query_language": "sql",
        "query_text": """
            SELECT
                d.detection_id, d.resource_arn, d.resource_type,
                d.severity, d.detection_type, d.rule_id,
                d.account_id, d.region, d.scan_id
            FROM threat_detections d
            LEFT JOIN threat_analysis a ON d.detection_id = a.detection_id
            WHERE d.tenant_id = :tenant_id
              AND a.detection_id IS NULL
            ORDER BY d.severity, d.resource_arn
        """,
        "target_data_sources": ["threat_detections", "threat_analysis"],
        "mitre_tactics": [],
        "mitre_techniques": [],
        "tags": ["gap-analysis", "unscored", "missing-analysis"],
    },
    {
        "query_name": "Hunt: High-Severity Without Remediation Guidance",
        "description": (
            "Find high/critical detections whose MITRE techniques lack "
            "detection_guidance in mitre_technique_reference. These need "
            "manual triage — no automated playbook available."
        ),
        "hunt_type": "gap_analysis",
        "query_language": "sql",
        "query_text": """
            SELECT
                d.detection_id, d.resource_arn, d.resource_type,
                d.severity, d.account_id,
                d.mitre_techniques,
                a.risk_score, a.verdict,
                a.analysis_results->'mitre_analysis'->>'guidance_coverage' AS guidance_coverage
            FROM threat_detections d
            LEFT JOIN threat_analysis a ON d.detection_id = a.detection_id
            WHERE d.tenant_id = :tenant_id
              AND d.severity IN ('critical', 'high')
              AND (
                a.analysis_results->'mitre_analysis'->>'guidance_coverage' IS NULL
                OR LEFT(a.analysis_results->'mitre_analysis'->>'guidance_coverage', 2) = '0/'
              )
            ORDER BY a.risk_score DESC NULLS LAST
        """,
        "target_data_sources": ["threat_analysis", "mitre_technique_reference"],
        "mitre_tactics": [],
        "mitre_techniques": [],
        "tags": ["gap-analysis", "no-playbook", "needs-enrichment"],
    },

    # ── Category 5: Service-Specific Hunts ───────────────────────────────

    {
        "query_name": "Hunt: S3 Exposure — Public Buckets with Sensitive Techniques",
        "description": (
            "Find S3 buckets with exposure-related detections that also have "
            "data exfiltration MITRE techniques (T1530, T1537)."
        ),
        "hunt_type": "service_specific",
        "query_language": "sql",
        "query_text": """
            SELECT
                d.detection_id, d.resource_arn,
                d.severity, d.account_id, d.region,
                a.risk_score, a.verdict,
                a.analysis_results->'reachability'->>'is_internet_reachable' AS internet_reachable,
                d.mitre_techniques
            FROM threat_detections d
            LEFT JOIN threat_analysis a ON d.detection_id = a.detection_id
            WHERE d.tenant_id = :tenant_id
              AND d.resource_type = 's3'
              AND (d.mitre_techniques @> '["T1530"]'::jsonb OR d.mitre_techniques @> '["T1537"]'::jsonb)
            ORDER BY a.risk_score DESC NULLS LAST
        """,
        "target_data_sources": ["S3 Access Logs", "CloudTrail", "Macie"],
        "mitre_tactics": ["Collection", "Exfiltration"],
        "mitre_techniques": ["T1530", "T1537"],
        "tags": ["s3", "exposure", "exfiltration", "service-specific"],
    },
    {
        "query_name": "Hunt: IAM Over-Privileged Resources",
        "description": (
            "Find IAM-related resources with privilege escalation or credential "
            "abuse techniques (T1078, T1098, T1136)."
        ),
        "hunt_type": "service_specific",
        "query_language": "sql",
        "query_text": """
            SELECT
                d.detection_id, d.resource_arn, d.resource_type,
                d.severity, d.account_id, d.region,
                a.risk_score, a.verdict,
                d.mitre_techniques
            FROM threat_detections d
            LEFT JOIN threat_analysis a ON d.detection_id = a.detection_id
            WHERE d.tenant_id = :tenant_id
              AND d.resource_type IN ('iam', 'iam_role', 'iam_policy', 'iam_user')
              AND (
                d.mitre_techniques @> '["T1078"]'::jsonb
                OR d.mitre_techniques @> '["T1098"]'::jsonb
                OR d.mitre_techniques @> '["T1136"]'::jsonb
              )
            ORDER BY a.risk_score DESC NULLS LAST
        """,
        "target_data_sources": ["CloudTrail", "IAM Access Analyzer", "IAM Credential Report"],
        "mitre_tactics": ["Persistence", "Privilege Escalation"],
        "mitre_techniques": ["T1078", "T1098", "T1136"],
        "tags": ["iam", "privilege-escalation", "over-privileged", "service-specific"],
    },

    # ── Category 6: Trend / Temporal Hunts ───────────────────────────────

    {
        "query_name": "Hunt: Recurring Detections Across Scans",
        "description": (
            "Find resources that appear in multiple scans — persistent misconfigurations "
            "that haven't been remediated."
        ),
        "hunt_type": "temporal",
        "query_language": "sql",
        "query_text": """
            SELECT
                d.resource_arn, d.resource_type,
                COUNT(DISTINCT d.scan_id) AS scan_count,
                array_agg(DISTINCT d.severity) AS severities,
                MAX(a.risk_score) AS max_risk_score,
                MIN(d.first_seen_at) AS first_seen,
                MAX(d.last_seen_at) AS last_seen
            FROM threat_detections d
            LEFT JOIN threat_analysis a ON d.detection_id = a.detection_id
            WHERE d.tenant_id = :tenant_id
            GROUP BY d.resource_arn, d.resource_type
            HAVING COUNT(DISTINCT d.scan_id) > 1
            ORDER BY COUNT(DISTINCT d.scan_id) DESC, MAX(a.risk_score) DESC NULLS LAST
            LIMIT 50
        """,
        "target_data_sources": ["threat_detections"],
        "mitre_tactics": [],
        "mitre_techniques": [],
        "tags": ["temporal", "recurring", "unremediated", "trend"],
    },
    {
        "query_name": "Hunt: Account Hotspots — Most Detections per Account",
        "description": (
            "Identify which AWS accounts have the most threat detections. "
            "Accounts with high detection counts may need security review."
        ),
        "hunt_type": "temporal",
        "query_language": "sql",
        "query_text": """
            SELECT
                d.account_id,
                COUNT(*) AS detection_count,
                COUNT(*) FILTER (WHERE d.severity = 'critical') AS critical_count,
                COUNT(*) FILTER (WHERE d.severity = 'high') AS high_count,
                AVG(a.risk_score) AS avg_risk_score,
                MAX(a.risk_score) AS max_risk_score,
                array_agg(DISTINCT d.resource_type) AS resource_types
            FROM threat_detections d
            LEFT JOIN threat_analysis a ON d.detection_id = a.detection_id
            WHERE d.tenant_id = :tenant_id
            GROUP BY d.account_id
            ORDER BY COUNT(*) DESC
        """,
        "target_data_sources": ["threat_detections", "threat_analysis"],
        "mitre_tactics": [],
        "mitre_techniques": [],
        "tags": ["account-hotspot", "trend", "overview"],
    },

    # ═══════════════════════════════════════════════════════════════════════
    # CYPHER GRAPH QUERIES — run against Neo4j security graph
    # ═══════════════════════════════════════════════════════════════════════

    # ── Category 7: Graph Attack Path Hunts ──────────────────────────────

    {
        "query_name": "Graph Hunt: Internet → Resource with MITRE T1190 Threats",
        "description": (
            "Find attack paths from Internet to resources that have T1190 "
            "(Exploit Public-Facing Application) detections. Shows the shortest "
            "path an attacker could take from internet to vulnerable resources."
        ),
        "hunt_type": "graph_attack_path",
        "query_language": "cypher",
        "query_text": """
            MATCH path = (i:Internet)-[*1..4]->(r:Resource {tenant_id: $tid})
            WHERE EXISTS {
              (r)-[:HAS_THREAT]->(t:ThreatDetection)
              WHERE ANY(tech IN t.mitre_techniques WHERE tech = 'T1190')
            }
            WITH r, path, length(path) AS hops
            MATCH (r)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                r.uid AS resource_arn,
                r.name AS resource_name,
                r.resource_type AS resource_type,
                t.severity AS threat_severity,
                t.risk_score AS risk_score,
                t.mitre_techniques AS mitre_techniques,
                hops,
                [n IN nodes(path) | coalesce(n.name, n.uid)] AS path_nodes,
                [rel IN relationships(path) | type(rel)] AS path_rels
            ORDER BY t.risk_score DESC, hops ASC
        """,
        "target_data_sources": ["Neo4j Security Graph"],
        "mitre_tactics": ["Initial Access"],
        "mitre_techniques": ["T1190"],
        "tags": ["graph", "attack-path", "internet-exposed", "initial-access"],
    },
    {
        "query_name": "Graph Hunt: Internet → S3 with Data Exfiltration Risk",
        "description": (
            "Find attack paths from Internet to S3 buckets that have data "
            "exfiltration MITRE techniques (T1530/T1537). These are the highest "
            "risk paths — internet-exposed storage with sensitive data."
        ),
        "hunt_type": "graph_attack_path",
        "query_language": "cypher",
        "query_text": """
            MATCH path = (i:Internet)-[:EXPOSES*1..3]->(s:Resource {tenant_id: $tid})
            WHERE s.resource_type CONTAINS 's3'
            MATCH (s)-[:HAS_THREAT]->(t:ThreatDetection)
            WHERE ANY(tech IN t.mitre_techniques WHERE tech IN ['T1530', 'T1537'])
            RETURN
                s.uid AS bucket_arn,
                s.name AS bucket_name,
                t.severity AS severity,
                t.risk_score AS risk_score,
                t.mitre_techniques AS techniques,
                length(path) AS exposure_hops,
                [n IN nodes(path) | coalesce(n.name, n.uid)] AS path_nodes
            ORDER BY t.risk_score DESC
        """,
        "target_data_sources": ["Neo4j Security Graph", "S3 Access Logs"],
        "mitre_tactics": ["Collection", "Exfiltration"],
        "mitre_techniques": ["T1530", "T1537"],
        "tags": ["graph", "attack-path", "s3", "exfiltration"],
    },

    # ── Category 8: Graph Blast Radius Hunts ─────────────────────────────

    {
        "query_name": "Graph Hunt: Highest Blast Radius Resources",
        "description": (
            "Find resources that can reach the most other resources via graph "
            "relationships. These are the highest-impact resources if compromised."
        ),
        "hunt_type": "graph_blast_radius",
        "query_language": "cypher",
        "query_text": """
            MATCH (r:Resource {tenant_id: $tid})-[*1..4]->(target:Resource)
            WHERE r <> target
            WITH r, count(DISTINCT target) AS blast_count,
                 collect(DISTINCT target.resource_type) AS affected_types
            WHERE blast_count >= 2
            OPTIONAL MATCH (r)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                r.uid AS resource_arn,
                r.name AS resource_name,
                r.resource_type AS resource_type,
                blast_count,
                affected_types,
                collect(DISTINCT t.severity) AS threat_severities,
                count(DISTINCT t) AS threat_count
            ORDER BY blast_count DESC
            LIMIT 20
        """,
        "target_data_sources": ["Neo4j Security Graph"],
        "mitre_tactics": [],
        "mitre_techniques": [],
        "tags": ["graph", "blast-radius", "high-impact", "priority"],
    },
    {
        "query_name": "Graph Hunt: Attack Paths Between Threat Detections",
        "description": (
            "Find graph paths that connect two different threat detections — "
            "resources where one compromised resource can reach another "
            "already-threatened resource (threat chaining)."
        ),
        "hunt_type": "graph_blast_radius",
        "query_language": "cypher",
        "query_text": """
            MATCH (r1:Resource {tenant_id: $tid})-[:HAS_THREAT]->(t1:ThreatDetection)
            MATCH (r2:Resource {tenant_id: $tid})-[:HAS_THREAT]->(t2:ThreatDetection)
            WHERE r1 <> r2
            MATCH path = shortestPath((r1)-[*1..5]-(r2))
            RETURN
                r1.uid AS source_arn,
                r1.resource_type AS source_type,
                t1.severity AS source_severity,
                t1.mitre_techniques AS source_techniques,
                r2.uid AS target_arn,
                r2.resource_type AS target_type,
                t2.severity AS target_severity,
                t2.mitre_techniques AS target_techniques,
                length(path) AS path_length,
                [n IN nodes(path) | coalesce(n.name, n.uid)] AS path_nodes,
                [rel IN relationships(path) | type(rel)] AS path_rels
            ORDER BY length(path) ASC
            LIMIT 30
        """,
        "target_data_sources": ["Neo4j Security Graph"],
        "mitre_tactics": [],
        "mitre_techniques": [],
        "tags": ["graph", "threat-chaining", "lateral-movement", "correlation"],
    },

    # ── Category 9: Graph Toxic Combination Hunts ────────────────────────

    {
        "query_name": "Graph Hunt: Toxic Combo — Public + Unencrypted + Sensitive",
        "description": (
            "Find resources that are internet-exposed AND have multiple threat "
            "types (exposure + data exfiltration + defense evasion). These toxic "
            "combinations create the highest real-world risk."
        ),
        "hunt_type": "graph_toxic_combo",
        "query_language": "cypher",
        "query_text": """
            MATCH (i:Internet)-[:EXPOSES*1..2]->(r:Resource {tenant_id: $tid})
            MATCH (r)-[:HAS_THREAT]->(t:ThreatDetection)
            WITH r, collect(t) AS threats, count(t) AS threat_count
            WHERE threat_count >= 1
            UNWIND threats AS t
            WITH r, threat_count,
                 collect(DISTINCT t.threat_category) AS categories,
                 collect(DISTINCT t.severity) AS severities,
                 reduce(techs = [], t2 IN collect(t.mitre_techniques) | techs + t2) AS all_techniques
            RETURN
                r.uid AS resource_arn,
                r.name AS resource_name,
                r.resource_type AS resource_type,
                threat_count,
                categories,
                severities,
                all_techniques
            ORDER BY threat_count DESC, size(categories) DESC
        """,
        "target_data_sources": ["Neo4j Security Graph"],
        "mitre_tactics": ["Initial Access", "Collection", "Exfiltration", "Impact"],
        "mitre_techniques": [],
        "tags": ["graph", "toxic-combination", "internet-exposed", "critical"],
    },
    {
        "query_name": "Graph Hunt: IAM Roles Reaching Threatened Resources",
        "description": (
            "Find IAM roles that have graph paths to resources with active threats. "
            "If an attacker compromises these roles, they can reach already-vulnerable "
            "resources."
        ),
        "hunt_type": "graph_toxic_combo",
        "query_language": "cypher",
        "query_text": """
            MATCH (role:IAMRole {tenant_id: $tid})-[*1..3]->(target:Resource)
            WHERE EXISTS { (target)-[:HAS_THREAT]->(t:ThreatDetection) }
              AND role <> target
            WITH role, collect(DISTINCT target) AS reachable_targets
            UNWIND reachable_targets AS target
            MATCH (target)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                role.uid AS role_arn,
                role.name AS role_name,
                count(DISTINCT target) AS threatened_resources_reachable,
                collect(DISTINCT target.uid) AS target_arns,
                collect(DISTINCT t.severity) AS threat_severities,
                collect(DISTINCT t.mitre_techniques) AS technique_sets
            ORDER BY threatened_resources_reachable DESC
            LIMIT 20
        """,
        "target_data_sources": ["Neo4j Security Graph"],
        "mitre_tactics": ["Privilege Escalation", "Lateral Movement"],
        "mitre_techniques": ["T1078", "T1098"],
        "tags": ["graph", "iam", "lateral-movement", "privilege-escalation"],
    },

    # ── Category 10: Graph MITRE Kill-Chain Hunts ────────────────────────

    {
        "query_name": "Graph Hunt: Full MITRE Kill Chain in Attack Paths",
        "description": (
            "Find connected resources where the combined MITRE techniques span "
            "the full kill chain: Initial Access → Execution → Persistence → "
            "Privilege Escalation → Exfiltration/Impact."
        ),
        "hunt_type": "graph_mitre_killchain",
        "query_language": "cypher",
        "query_text": """
            MATCH path = (start:Resource {tenant_id: $tid})-[*1..4]->(end:Resource)
            WHERE start <> end
            MATCH (start)-[:HAS_THREAT]->(t1:ThreatDetection)
            MATCH (end)-[:HAS_THREAT]->(t2:ThreatDetection)
            WITH start, end, path, t1, t2,
                 t1.mitre_tactics + t2.mitre_tactics AS combined_tactics
            WHERE ANY(t IN combined_tactics WHERE t = 'Initial Access')
              AND ANY(t IN combined_tactics WHERE t IN ['Persistence', 'Privilege Escalation'])
              AND ANY(t IN combined_tactics WHERE t IN ['Exfiltration', 'Impact'])
            RETURN
                start.uid AS entry_point,
                start.resource_type AS entry_type,
                t1.mitre_tactics AS entry_tactics,
                t1.mitre_techniques AS entry_techniques,
                end.uid AS target_resource,
                end.resource_type AS target_type,
                t2.mitre_tactics AS target_tactics,
                t2.mitre_techniques AS target_techniques,
                length(path) AS path_length,
                [n IN nodes(path) | coalesce(n.name, n.uid)] AS path_nodes
            ORDER BY length(path) ASC
            LIMIT 20
        """,
        "target_data_sources": ["Neo4j Security Graph"],
        "mitre_tactics": ["Initial Access", "Persistence", "Privilege Escalation", "Exfiltration", "Impact"],
        "mitre_techniques": ["T1190", "T1078", "T1098", "T1530", "T1485"],
        "tags": ["graph", "kill-chain", "full-attack-path", "critical", "mitre"],
    },
    {
        "query_name": "Graph Hunt: MITRE Ransomware Chain (T1190 → T1562 → T1486)",
        "description": (
            "Find resources with the ransomware attack pattern: "
            "exploit public app → disable defenses → encrypt data. "
            "Cross-resource paths where this chain spans multiple nodes."
        ),
        "hunt_type": "graph_mitre_killchain",
        "query_language": "cypher",
        "query_text": """
            MATCH (r:Resource {tenant_id: $tid})-[:HAS_THREAT]->(t:ThreatDetection)
            WHERE ANY(tech IN t.mitre_techniques WHERE tech IN ['T1190', 'T1562', 'T1485', 'T1486', 'T1490'])
            WITH r, t,
                 [tech IN t.mitre_techniques WHERE tech IN ['T1190', 'T1562', 'T1485', 'T1486', 'T1490']] AS ransomware_techs
            WHERE size(ransomware_techs) >= 2
            OPTIONAL MATCH (i:Internet)-[:EXPOSES*1..2]->(r)
            RETURN
                r.uid AS resource_arn,
                r.name AS resource_name,
                r.resource_type AS resource_type,
                t.severity AS severity,
                t.risk_score AS risk_score,
                ransomware_techs,
                t.mitre_tactics AS tactics,
                CASE WHEN i IS NOT NULL THEN true ELSE false END AS internet_exposed
            ORDER BY size(ransomware_techs) DESC, t.risk_score DESC
        """,
        "target_data_sources": ["Neo4j Security Graph"],
        "mitre_tactics": ["Initial Access", "Defense Evasion", "Impact"],
        "mitre_techniques": ["T1190", "T1562", "T1485", "T1486", "T1490"],
        "tags": ["graph", "ransomware", "kill-chain", "critical", "mitre"],
    },

    # ═══════════════════════════════════════════════════════════════════════
    # ENRICHED MULTI-CLOUD QUERIES — CSP-specific Cypher & SQL hunts
    # ═══════════════════════════════════════════════════════════════════════

    # ── Category 11: Multi-Cloud Attack Path Hunts (Cypher) ───────────────

    {
        "query_name": "Graph Hunt: Internet → Azure SQL Database",
        "description": (
            "Find attack paths from Internet through Azure NSG and VNet to Azure SQL "
            "Database resources. Identifies internet-exposed Azure SQL instances "
            "that may be reachable via permissive network security group rules."
        ),
        "hunt_type": "graph_attack_path",
        "query_language": "cypher",
        "query_text": """
            MATCH path = (i:Internet)-[*1..5]->(db:Resource {tenant_id: $tid})
            WHERE db.resource_type IN ['azure_sql_server', 'azure_sql_database', 'azure_mysql', 'azure_postgresql']
            WITH db, path, length(path) AS hops,
                 [n IN nodes(path) | coalesce(n.name, n.uid)] AS path_nodes,
                 [rel IN relationships(path) | type(rel)] AS path_rels
            OPTIONAL MATCH (db)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                db.uid AS resource_arn,
                db.name AS resource_name,
                db.resource_type AS resource_type,
                hops,
                path_nodes,
                path_rels,
                t.severity AS threat_severity,
                t.risk_score AS risk_score,
                t.mitre_techniques AS mitre_techniques
            ORDER BY t.risk_score DESC NULLS LAST, hops ASC
        """,
        "target_data_sources": ["Neo4j Security Graph"],
        "mitre_tactics": ["Initial Access"],
        "mitre_techniques": ["T1190"],
        "tags": ["graph", "attack-path", "azure", "sql-database", "internet-exposed"],
    },
    {
        "query_name": "Graph Hunt: Internet → GCP Cloud SQL",
        "description": (
            "Find attack paths from Internet through GCP firewall rules to Cloud SQL "
            "instances. Detects GCP databases reachable from the internet via "
            "permissive firewall configurations."
        ),
        "hunt_type": "graph_attack_path",
        "query_language": "cypher",
        "query_text": """
            MATCH path = (i:Internet)-[*1..5]->(db:Resource {tenant_id: $tid})
            WHERE db.resource_type IN ['gcp_sql_instance', 'gcp_cloud_sql', 'gcp_spanner', 'gcp_alloydb']
            WITH db, path, length(path) AS hops,
                 [n IN nodes(path) | coalesce(n.name, n.uid)] AS path_nodes,
                 [rel IN relationships(path) | type(rel)] AS path_rels
            OPTIONAL MATCH (db)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                db.uid AS resource_arn,
                db.name AS resource_name,
                db.resource_type AS resource_type,
                hops,
                path_nodes,
                path_rels,
                t.severity AS threat_severity,
                t.risk_score AS risk_score,
                t.mitre_techniques AS mitre_techniques
            ORDER BY t.risk_score DESC NULLS LAST, hops ASC
        """,
        "target_data_sources": ["Neo4j Security Graph"],
        "mitre_tactics": ["Initial Access"],
        "mitre_techniques": ["T1190"],
        "tags": ["graph", "attack-path", "gcp", "cloud-sql", "internet-exposed"],
    },
    {
        "query_name": "Graph Hunt: Internet → OCI Autonomous Database",
        "description": (
            "Find attack paths from Internet through OCI VCN and Security Lists "
            "to Autonomous Database instances. Identifies OCI databases exposed "
            "to the internet via misconfigured network layers."
        ),
        "hunt_type": "graph_attack_path",
        "query_language": "cypher",
        "query_text": """
            MATCH path = (i:Internet)-[*1..5]->(db:Resource {tenant_id: $tid})
            WHERE db.resource_type IN ['oci_autonomous_database', 'oci_db_system', 'oci_mysql']
            WITH db, path, length(path) AS hops,
                 [n IN nodes(path) | coalesce(n.name, n.uid)] AS path_nodes,
                 [rel IN relationships(path) | type(rel)] AS path_rels
            OPTIONAL MATCH (db)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                db.uid AS resource_arn,
                db.name AS resource_name,
                db.resource_type AS resource_type,
                hops,
                path_nodes,
                path_rels,
                t.severity AS threat_severity,
                t.risk_score AS risk_score,
                t.mitre_techniques AS mitre_techniques
            ORDER BY t.risk_score DESC NULLS LAST, hops ASC
        """,
        "target_data_sources": ["Neo4j Security Graph"],
        "mitre_tactics": ["Initial Access"],
        "mitre_techniques": ["T1190"],
        "tags": ["graph", "attack-path", "oci", "autonomous-db", "internet-exposed"],
    },
    {
        "query_name": "Graph Hunt: Internet → IBM Db2",
        "description": (
            "Find attack paths from Internet through IBM VPC and Security Groups "
            "to Db2 database instances. Detects IBM Cloud databases reachable "
            "from the internet through permissive network controls."
        ),
        "hunt_type": "graph_attack_path",
        "query_language": "cypher",
        "query_text": """
            MATCH path = (i:Internet)-[*1..5]->(db:Resource {tenant_id: $tid})
            WHERE db.resource_type IN ['ibm_db2', 'ibm_postgresql', 'ibm_mysql', 'ibm_database']
            WITH db, path, length(path) AS hops,
                 [n IN nodes(path) | coalesce(n.name, n.uid)] AS path_nodes,
                 [rel IN relationships(path) | type(rel)] AS path_rels
            OPTIONAL MATCH (db)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                db.uid AS resource_arn,
                db.name AS resource_name,
                db.resource_type AS resource_type,
                hops,
                path_nodes,
                path_rels,
                t.severity AS threat_severity,
                t.risk_score AS risk_score,
                t.mitre_techniques AS mitre_techniques
            ORDER BY t.risk_score DESC NULLS LAST, hops ASC
        """,
        "target_data_sources": ["Neo4j Security Graph"],
        "mitre_tactics": ["Initial Access"],
        "mitre_techniques": ["T1190"],
        "tags": ["graph", "attack-path", "ibm", "db2", "internet-exposed"],
    },
    {
        "query_name": "Graph Hunt: Internet → K8s Pod via Ingress",
        "description": (
            "Find attack paths from Internet through Kubernetes Ingress and Service "
            "resources to Pods. Identifies pods reachable from the internet via "
            "Ingress controllers and LoadBalancer/NodePort services."
        ),
        "hunt_type": "graph_attack_path",
        "query_language": "cypher",
        "query_text": """
            MATCH path = (i:Internet)-[*1..5]->(pod:Resource {tenant_id: $tid})
            WHERE pod.resource_type IN ['k8s_pod', 'k8s_deployment', 'k8s_statefulset']
            WITH pod, path, length(path) AS hops,
                 [n IN nodes(path) | coalesce(n.name, n.uid)] AS path_nodes,
                 [rel IN relationships(path) | type(rel)] AS path_rels
            OPTIONAL MATCH (pod)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                pod.uid AS resource_arn,
                pod.name AS resource_name,
                pod.resource_type AS resource_type,
                hops,
                path_nodes,
                path_rels,
                t.severity AS threat_severity,
                t.risk_score AS risk_score,
                t.mitre_techniques AS mitre_techniques
            ORDER BY t.risk_score DESC NULLS LAST, hops ASC
        """,
        "target_data_sources": ["Neo4j Security Graph"],
        "mitre_tactics": ["Initial Access"],
        "mitre_techniques": ["T1190"],
        "tags": ["graph", "attack-path", "k8s", "pod", "ingress", "internet-exposed"],
    },

    # ── Category 12: CSP-Specific Privilege Escalation (Cypher) ───────────

    {
        "query_name": "Graph Hunt: Azure Service Principal Escalation",
        "description": (
            "Find Azure Service Principals or Managed Identities that have graph paths "
            "to sensitive resources like KeyVault or Storage Accounts. These paths "
            "represent privilege escalation risks if a service principal is compromised."
        ),
        "hunt_type": "graph_privilege_escalation",
        "query_language": "cypher",
        "query_text": """
            MATCH (sp:Resource {tenant_id: $tid})-[*1..4]->(target:Resource {tenant_id: $tid})
            WHERE sp.resource_type IN ['azure_service_principal', 'azure_managed_identity', 'azure_ad_application']
              AND target.resource_type IN ['azure_key_vault', 'azure_storage_account', 'azure_sql_server', 'azure_cosmosdb']
              AND sp <> target
            WITH sp, target,
                 count(*) AS path_count
            OPTIONAL MATCH (target)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                sp.uid AS principal_arn,
                sp.name AS principal_name,
                sp.resource_type AS principal_type,
                target.uid AS target_arn,
                target.name AS target_name,
                target.resource_type AS target_type,
                path_count,
                collect(DISTINCT t.severity) AS threat_severities,
                collect(DISTINCT t.mitre_techniques) AS technique_sets
            ORDER BY path_count DESC
            LIMIT 30
        """,
        "target_data_sources": ["Neo4j Security Graph"],
        "mitre_tactics": ["Privilege Escalation", "Credential Access"],
        "mitre_techniques": ["T1078", "T1098"],
        "tags": ["graph", "azure", "service-principal", "privilege-escalation", "keyvault"],
    },
    {
        "query_name": "Graph Hunt: GCP Service Account Chain",
        "description": (
            "Find GCP Service Accounts that can reach sensitive resources like BigQuery, "
            "Cloud Storage, or KMS through impersonation or IAM bindings. Detects "
            "service account chains that could enable privilege escalation."
        ),
        "hunt_type": "graph_privilege_escalation",
        "query_language": "cypher",
        "query_text": """
            MATCH (sa:Resource {tenant_id: $tid})-[*1..4]->(target:Resource {tenant_id: $tid})
            WHERE sa.resource_type IN ['gcp_service_account', 'gcp_iam_binding']
              AND target.resource_type IN ['gcp_storage_bucket', 'gcp_bigquery_dataset', 'gcp_kms_key', 'gcp_secret']
              AND sa <> target
            WITH sa, target,
                 count(*) AS path_count
            OPTIONAL MATCH (target)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                sa.uid AS service_account_arn,
                sa.name AS service_account_name,
                sa.resource_type AS sa_type,
                target.uid AS target_arn,
                target.name AS target_name,
                target.resource_type AS target_type,
                path_count,
                collect(DISTINCT t.severity) AS threat_severities,
                collect(DISTINCT t.mitre_techniques) AS technique_sets
            ORDER BY path_count DESC
            LIMIT 30
        """,
        "target_data_sources": ["Neo4j Security Graph"],
        "mitre_tactics": ["Privilege Escalation", "Credential Access"],
        "mitre_techniques": ["T1078", "T1098"],
        "tags": ["graph", "gcp", "service-account", "privilege-escalation", "impersonation"],
    },
    {
        "query_name": "Graph Hunt: K8s RBAC Escalation",
        "description": (
            "Find Kubernetes Pods that can reach Secrets via ServiceAccount and "
            "ClusterRole/Role bindings. Detects RBAC escalation paths where a "
            "compromised pod could access sensitive secrets."
        ),
        "hunt_type": "graph_privilege_escalation",
        "query_language": "cypher",
        "query_text": """
            MATCH (pod:Resource {tenant_id: $tid})-[*1..4]->(secret:Resource {tenant_id: $tid})
            WHERE pod.resource_type IN ['k8s_pod', 'k8s_deployment', 'k8s_daemonset']
              AND secret.resource_type IN ['k8s_secret', 'k8s_configmap']
              AND pod <> secret
            WITH pod, secret,
                 count(*) AS path_count
            OPTIONAL MATCH (pod)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                pod.uid AS pod_arn,
                pod.name AS pod_name,
                pod.resource_type AS pod_type,
                secret.uid AS secret_arn,
                secret.name AS secret_name,
                secret.resource_type AS secret_type,
                path_count,
                collect(DISTINCT t.severity) AS threat_severities,
                collect(DISTINCT t.mitre_techniques) AS technique_sets
            ORDER BY path_count DESC
            LIMIT 30
        """,
        "target_data_sources": ["Neo4j Security Graph"],
        "mitre_tactics": ["Privilege Escalation", "Credential Access"],
        "mitre_techniques": ["T1078", "T1552"],
        "tags": ["graph", "k8s", "rbac", "privilege-escalation", "secret-access"],
    },

    # ── Category 13: CSP-Specific Exposure (Cypher) ───────────────────────

    {
        "query_name": "Graph Hunt: Azure Storage Account Public Exposure",
        "description": (
            "Find Azure Storage Accounts that are internet-exposed and have active "
            "threat detections. Public blob containers with threats represent high "
            "risk for data exfiltration."
        ),
        "hunt_type": "graph_exposure",
        "query_language": "cypher",
        "query_text": """
            MATCH (i:Internet)-[*1..3]->(sa:Resource {tenant_id: $tid})
            WHERE sa.resource_type IN ['azure_storage_account', 'azure_blob_container']
            MATCH (sa)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                sa.uid AS resource_arn,
                sa.name AS resource_name,
                sa.resource_type AS resource_type,
                t.severity AS severity,
                t.risk_score AS risk_score,
                t.mitre_techniques AS mitre_techniques,
                t.threat_category AS threat_category
            ORDER BY t.risk_score DESC
        """,
        "target_data_sources": ["Neo4j Security Graph"],
        "mitre_tactics": ["Collection", "Exfiltration"],
        "mitre_techniques": ["T1530"],
        "tags": ["graph", "azure", "storage-account", "public-exposure", "exfiltration"],
    },
    {
        "query_name": "Graph Hunt: GCP GCS Bucket Public Exposure",
        "description": (
            "Find GCP Cloud Storage buckets that are internet-exposed and have active "
            "threat detections. Public GCS buckets with threats represent high risk "
            "for data exfiltration or tampering."
        ),
        "hunt_type": "graph_exposure",
        "query_language": "cypher",
        "query_text": """
            MATCH (i:Internet)-[*1..3]->(b:Resource {tenant_id: $tid})
            WHERE b.resource_type IN ['gcp_storage_bucket', 'gcp_gcs_bucket']
            MATCH (b)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                b.uid AS resource_arn,
                b.name AS resource_name,
                b.resource_type AS resource_type,
                t.severity AS severity,
                t.risk_score AS risk_score,
                t.mitre_techniques AS mitre_techniques,
                t.threat_category AS threat_category
            ORDER BY t.risk_score DESC
        """,
        "target_data_sources": ["Neo4j Security Graph"],
        "mitre_tactics": ["Collection", "Exfiltration"],
        "mitre_techniques": ["T1530"],
        "tags": ["graph", "gcp", "gcs-bucket", "public-exposure", "exfiltration"],
    },
    {
        "query_name": "Graph Hunt: K8s NodePort/LoadBalancer Exposure",
        "description": (
            "Find Kubernetes Services of type NodePort or LoadBalancer that expose "
            "pods without a NetworkPolicy. These services allow direct internet "
            "ingress to pods without network-level access control."
        ),
        "hunt_type": "graph_exposure",
        "query_language": "cypher",
        "query_text": """
            MATCH (i:Internet)-[*1..3]->(svc:Resource {tenant_id: $tid})
            WHERE svc.resource_type IN ['k8s_service', 'k8s_ingress']
            MATCH (svc)-[*1..2]->(pod:Resource {tenant_id: $tid})
            WHERE pod.resource_type IN ['k8s_pod', 'k8s_deployment']
            WITH svc, pod
            WHERE NOT EXISTS {
                (np:Resource {tenant_id: $tid})-[:REFERENCES]->(pod)
                WHERE np.resource_type = 'k8s_network_policy'
            }
            OPTIONAL MATCH (pod)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                svc.uid AS service_arn,
                svc.name AS service_name,
                pod.uid AS pod_arn,
                pod.name AS pod_name,
                collect(DISTINCT t.severity) AS threat_severities,
                count(DISTINCT t) AS threat_count
            ORDER BY threat_count DESC
        """,
        "target_data_sources": ["Neo4j Security Graph"],
        "mitre_tactics": ["Initial Access"],
        "mitre_techniques": ["T1190"],
        "tags": ["graph", "k8s", "nodeport", "loadbalancer", "network-policy", "exposure"],
    },

    # ── Category 14: Multi-Cloud Lateral Movement (Cypher) ────────────────

    {
        "query_name": "Graph Hunt: AWS EC2 → Azure Storage (Cross-Cloud)",
        "description": (
            "Find cross-cloud attack paths where a compromised AWS EC2 instance "
            "can reach Azure Storage Accounts. Detects multi-cloud lateral movement "
            "risks via shared credentials, peering, or trust relationships."
        ),
        "hunt_type": "graph_lateral_movement",
        "query_language": "cypher",
        "query_text": """
            MATCH (ec2:Resource {tenant_id: $tid})-[*1..5]->(az:Resource {tenant_id: $tid})
            WHERE ec2.resource_type IN ['ec2', 'aws_ec2_instance']
              AND az.resource_type IN ['azure_storage_account', 'azure_blob_container']
              AND ec2 <> az
            WITH ec2, az, count(*) AS path_count
            OPTIONAL MATCH (ec2)-[:HAS_THREAT]->(t1:ThreatDetection)
            OPTIONAL MATCH (az)-[:HAS_THREAT]->(t2:ThreatDetection)
            RETURN
                ec2.uid AS source_arn,
                ec2.name AS source_name,
                az.uid AS target_arn,
                az.name AS target_name,
                path_count,
                collect(DISTINCT t1.severity) AS source_threat_severities,
                collect(DISTINCT t2.severity) AS target_threat_severities
            ORDER BY path_count DESC
            LIMIT 20
        """,
        "target_data_sources": ["Neo4j Security Graph"],
        "mitre_tactics": ["Lateral Movement"],
        "mitre_techniques": ["T1021"],
        "tags": ["graph", "cross-cloud", "aws", "azure", "lateral-movement"],
    },
    {
        "query_name": "Graph Hunt: K8s Pod → Cloud Storage (Container Escape)",
        "description": (
            "Find attack paths from Kubernetes Pods to cloud storage resources "
            "(S3, GCS, Azure Blob). These paths indicate container escape risks "
            "where a compromised pod could access cloud storage directly."
        ),
        "hunt_type": "graph_lateral_movement",
        "query_language": "cypher",
        "query_text": """
            MATCH (pod:Resource {tenant_id: $tid})-[*1..5]->(storage:Resource {tenant_id: $tid})
            WHERE pod.resource_type IN ['k8s_pod', 'k8s_deployment', 'k8s_daemonset']
              AND storage.resource_type IN ['s3', 'gcp_storage_bucket', 'azure_storage_account',
                                            'azure_blob_container', 'gcp_gcs_bucket']
              AND pod <> storage
            WITH pod, storage, count(*) AS path_count
            OPTIONAL MATCH (pod)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                pod.uid AS pod_arn,
                pod.name AS pod_name,
                storage.uid AS storage_arn,
                storage.name AS storage_name,
                storage.resource_type AS storage_type,
                path_count,
                collect(DISTINCT t.severity) AS threat_severities,
                collect(DISTINCT t.mitre_techniques) AS technique_sets
            ORDER BY path_count DESC
            LIMIT 30
        """,
        "target_data_sources": ["Neo4j Security Graph"],
        "mitre_tactics": ["Lateral Movement", "Collection"],
        "mitre_techniques": ["T1021", "T1530"],
        "tags": ["graph", "k8s", "container-escape", "cloud-storage", "lateral-movement"],
    },
    {
        "query_name": "Graph Hunt: Any CSP Credential Theft → Data Store",
        "description": (
            "Find attack paths from IAM/credential resources to data stores across "
            "any CSP. Detects paths where stolen credentials could reach databases, "
            "storage, or key vaults regardless of cloud provider."
        ),
        "hunt_type": "graph_lateral_movement",
        "query_language": "cypher",
        "query_text": """
            MATCH (cred:Resource {tenant_id: $tid})-[*1..4]->(data:Resource {tenant_id: $tid})
            WHERE cred.resource_type IN ['iam', 'iam_role', 'iam_user', 'iam_policy',
                                          'azure_service_principal', 'azure_managed_identity',
                                          'gcp_service_account', 'k8s_service_account']
              AND data.resource_type IN ['s3', 'rds', 'dynamodb', 'azure_sql_server',
                                          'azure_storage_account', 'azure_key_vault',
                                          'gcp_storage_bucket', 'gcp_bigquery_dataset',
                                          'gcp_cloud_sql', 'oci_autonomous_database',
                                          'ibm_db2', 'k8s_secret']
              AND cred <> data
            WITH cred, data, count(*) AS path_count
            OPTIONAL MATCH (data)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                cred.uid AS credential_arn,
                cred.name AS credential_name,
                cred.resource_type AS credential_type,
                data.uid AS data_store_arn,
                data.name AS data_store_name,
                data.resource_type AS data_store_type,
                path_count,
                collect(DISTINCT t.severity) AS threat_severities,
                collect(DISTINCT t.mitre_techniques) AS technique_sets
            ORDER BY path_count DESC
            LIMIT 30
        """,
        "target_data_sources": ["Neo4j Security Graph"],
        "mitre_tactics": ["Credential Access", "Lateral Movement", "Collection"],
        "mitre_techniques": ["T1078", "T1552", "T1530"],
        "tags": ["graph", "multi-cloud", "credential-theft", "data-store", "lateral-movement"],
    },

    # ── Category 15: CSP-Specific SQL Hunts ───────────────────────────────

    {
        "query_name": "Hunt: Resource Hijacking / Cryptomining (T1496)",
        "description": (
            "Find resources with T1496 (Resource Hijacking / Cryptomining) detections "
            "across all CSPs. Cryptomining indicates compromise and unauthorized "
            "compute usage — often a precursor to further attacks."
        ),
        "hunt_type": "mitre_technique",
        "query_language": "sql",
        "query_text": """
            SELECT
                d.detection_id, d.resource_arn, d.resource_type,
                d.severity, d.confidence, d.account_id, d.region,
                d.provider,
                a.risk_score, a.verdict,
                a.analysis_results->'blast_radius'->>'reachable_count' AS blast_radius,
                d.mitre_techniques, d.mitre_tactics
            FROM threat_detections d
            LEFT JOIN threat_analysis a ON d.detection_id = a.detection_id
            WHERE d.tenant_id = :tenant_id
              AND d.mitre_techniques @> '["T1496"]'::jsonb
            ORDER BY a.risk_score DESC NULLS LAST
        """,
        "target_data_sources": ["CloudTrail", "GCP Audit Logs", "Azure Activity Logs", "GuardDuty"],
        "mitre_tactics": ["Impact"],
        "mitre_techniques": ["T1496"],
        "tags": ["cryptomining", "resource-hijacking", "multi-cloud", "impact"],
    },
    {
        "query_name": "Hunt: Serverless Execution Abuse (T1648)",
        "description": (
            "Find serverless resources (Lambda, Azure Functions, Cloud Run, Cloud Functions) "
            "with T1648 (Serverless Execution) detections. Compromised serverless functions "
            "can be used for data exfiltration and lateral movement."
        ),
        "hunt_type": "mitre_technique",
        "query_language": "sql",
        "query_text": """
            SELECT
                d.detection_id, d.resource_arn, d.resource_type,
                d.severity, d.confidence, d.account_id, d.region,
                d.provider,
                a.risk_score, a.verdict,
                d.mitre_techniques, d.mitre_tactics
            FROM threat_detections d
            LEFT JOIN threat_analysis a ON d.detection_id = a.detection_id
            WHERE d.tenant_id = :tenant_id
              AND d.mitre_techniques @> '["T1648"]'::jsonb
              AND d.resource_type IN ('lambda', 'azure_function', 'gcp_cloud_function',
                                       'gcp_cloud_run', 'azure_logic_app')
            ORDER BY a.risk_score DESC NULLS LAST
        """,
        "target_data_sources": ["CloudTrail", "GCP Audit Logs", "Azure Activity Logs"],
        "mitre_tactics": ["Execution"],
        "mitre_techniques": ["T1648"],
        "tags": ["serverless", "lambda", "functions", "execution-abuse", "multi-cloud"],
    },
    {
        "query_name": "Hunt: Container Image Compromise (T1525)",
        "description": (
            "Find container registry resources (ECR, ACR, GCR, Harbor) with T1525 "
            "(Implant Internal Image) detections. Compromised container images can "
            "propagate malware across all deployments using that image."
        ),
        "hunt_type": "mitre_technique",
        "query_language": "sql",
        "query_text": """
            SELECT
                d.detection_id, d.resource_arn, d.resource_type,
                d.severity, d.confidence, d.account_id, d.region,
                d.provider,
                a.risk_score, a.verdict,
                a.analysis_results->'blast_radius'->>'reachable_count' AS blast_radius,
                d.mitre_techniques, d.mitre_tactics
            FROM threat_detections d
            LEFT JOIN threat_analysis a ON d.detection_id = a.detection_id
            WHERE d.tenant_id = :tenant_id
              AND d.mitre_techniques @> '["T1525"]'::jsonb
            ORDER BY a.risk_score DESC NULLS LAST
        """,
        "target_data_sources": ["CloudTrail", "GCP Audit Logs", "Azure Activity Logs", "ECR Scan Results"],
        "mitre_tactics": ["Persistence"],
        "mitre_techniques": ["T1525"],
        "tags": ["container-image", "ecr", "acr", "gcr", "supply-chain", "persistence"],
    },
    {
        "query_name": "Hunt: Cloud Instance Metadata Theft (T1552.005)",
        "description": (
            "Find resources with T1552.005 (Cloud Instance Metadata API) detections. "
            "SSRF attacks targeting IMDSv1 endpoints can steal temporary credentials. "
            "Covers EC2, Azure VMs, GCE instances, and OCI compute."
        ),
        "hunt_type": "mitre_technique",
        "query_language": "sql",
        "query_text": """
            SELECT
                d.detection_id, d.resource_arn, d.resource_type,
                d.severity, d.confidence, d.account_id, d.region,
                d.provider,
                a.risk_score, a.verdict,
                a.analysis_results->'reachability'->>'is_internet_reachable' AS internet_reachable,
                d.mitre_techniques, d.mitre_tactics
            FROM threat_detections d
            LEFT JOIN threat_analysis a ON d.detection_id = a.detection_id
            WHERE d.tenant_id = :tenant_id
              AND (d.mitre_techniques @> '["T1552.005"]'::jsonb
                   OR d.mitre_techniques @> '["T1552"]'::jsonb)
            ORDER BY a.risk_score DESC NULLS LAST
        """,
        "target_data_sources": ["CloudTrail", "VPC Flow Logs", "GCP Audit Logs", "Azure Activity Logs"],
        "mitre_tactics": ["Credential Access"],
        "mitre_techniques": ["T1552", "T1552.005"],
        "tags": ["imds", "metadata-theft", "ssrf", "credential-access", "multi-cloud"],
    },
    {
        "query_name": "Hunt: Unused Region Resource Creation (T1535)",
        "description": (
            "Find resources with T1535 (Unused/Unsupported Cloud Regions) detections. "
            "Attackers create resources in regions not monitored by defenders to "
            "hide cryptomining or staging infrastructure."
        ),
        "hunt_type": "mitre_technique",
        "query_language": "sql",
        "query_text": """
            SELECT
                d.detection_id, d.resource_arn, d.resource_type,
                d.severity, d.confidence, d.account_id, d.region,
                d.provider,
                a.risk_score, a.verdict,
                d.mitre_techniques, d.mitre_tactics
            FROM threat_detections d
            LEFT JOIN threat_analysis a ON d.detection_id = a.detection_id
            WHERE d.tenant_id = :tenant_id
              AND d.mitre_techniques @> '["T1535"]'::jsonb
            ORDER BY d.region, a.risk_score DESC NULLS LAST
        """,
        "target_data_sources": ["CloudTrail", "GCP Audit Logs", "Azure Activity Logs", "Config Rules"],
        "mitre_tactics": ["Defense Evasion"],
        "mitre_techniques": ["T1535"],
        "tags": ["unused-region", "shadow-infra", "defense-evasion", "multi-cloud"],
    },
    {
        "query_name": "Hunt: Trusted Relationship Abuse (T1199)",
        "description": (
            "Find resources with T1199 (Trusted Relationship) detections. "
            "Cross-account roles, cross-tenant trusts, and federated identities "
            "can be abused for initial access or lateral movement."
        ),
        "hunt_type": "mitre_technique",
        "query_language": "sql",
        "query_text": """
            SELECT
                d.detection_id, d.resource_arn, d.resource_type,
                d.severity, d.confidence, d.account_id, d.region,
                d.provider,
                a.risk_score, a.verdict,
                a.analysis_results->'blast_radius'->>'reachable_count' AS blast_radius,
                d.mitre_techniques, d.mitre_tactics
            FROM threat_detections d
            LEFT JOIN threat_analysis a ON d.detection_id = a.detection_id
            WHERE d.tenant_id = :tenant_id
              AND d.mitre_techniques @> '["T1199"]'::jsonb
            ORDER BY a.risk_score DESC NULLS LAST
        """,
        "target_data_sources": ["CloudTrail", "IAM Access Analyzer", "Azure AD Logs", "GCP Audit Logs"],
        "mitre_tactics": ["Initial Access", "Lateral Movement"],
        "mitre_techniques": ["T1199"],
        "tags": ["trusted-relationship", "cross-account", "cross-tenant", "federation"],
    },
    {
        "query_name": "Hunt: Remote Service Lateral Movement (T1021)",
        "description": (
            "Find resources with T1021 (Remote Services) detections. Covers SSM "
            "Session Manager, Azure Bastion, GCP IAP tunneling, and SSH/RDP "
            "access used for lateral movement within cloud environments."
        ),
        "hunt_type": "mitre_technique",
        "query_language": "sql",
        "query_text": """
            SELECT
                d.detection_id, d.resource_arn, d.resource_type,
                d.severity, d.confidence, d.account_id, d.region,
                d.provider,
                a.risk_score, a.verdict,
                a.analysis_results->'reachability'->>'is_internet_reachable' AS internet_reachable,
                d.mitre_techniques, d.mitre_tactics
            FROM threat_detections d
            LEFT JOIN threat_analysis a ON d.detection_id = a.detection_id
            WHERE d.tenant_id = :tenant_id
              AND d.mitre_techniques @> '["T1021"]'::jsonb
            ORDER BY a.risk_score DESC NULLS LAST
        """,
        "target_data_sources": ["CloudTrail", "SSM Session Logs", "Azure Bastion Logs", "GCP IAP Logs"],
        "mitre_tactics": ["Lateral Movement"],
        "mitre_techniques": ["T1021"],
        "tags": ["remote-service", "ssm", "bastion", "iap", "lateral-movement", "multi-cloud"],
    },
    {
        "query_name": "Hunt: Brute Force Detections (T1110)",
        "description": (
            "Find resources with T1110 (Brute Force) detections across all CSPs. "
            "Covers password spraying, credential stuffing, and brute force attempts "
            "against cloud consoles, APIs, and managed databases."
        ),
        "hunt_type": "mitre_technique",
        "query_language": "sql",
        "query_text": """
            SELECT
                d.detection_id, d.resource_arn, d.resource_type,
                d.severity, d.confidence, d.account_id, d.region,
                d.provider,
                a.risk_score, a.verdict,
                d.mitre_techniques, d.mitre_tactics
            FROM threat_detections d
            LEFT JOIN threat_analysis a ON d.detection_id = a.detection_id
            WHERE d.tenant_id = :tenant_id
              AND (d.mitre_techniques @> '["T1110"]'::jsonb
                   OR d.mitre_techniques @> '["T1110.001"]'::jsonb
                   OR d.mitre_techniques @> '["T1110.003"]'::jsonb
                   OR d.mitre_techniques @> '["T1110.004"]'::jsonb)
            ORDER BY a.risk_score DESC NULLS LAST
        """,
        "target_data_sources": ["CloudTrail", "GuardDuty", "Azure AD Sign-in Logs", "GCP Audit Logs"],
        "mitre_tactics": ["Credential Access"],
        "mitre_techniques": ["T1110", "T1110.001", "T1110.003", "T1110.004"],
        "tags": ["brute-force", "password-spraying", "credential-stuffing", "multi-cloud"],
    },

    # ── Category 16: Threat Intelligence Correlation Hunts (SQL) ──────────

    {
        "query_name": "Hunt: Active Campaign Match — Detections matching known threat campaigns",
        "description": (
            "Correlate threat_intelligence TTPs with detection mitre_techniques to find "
            "resources that match active threat campaign indicators. High correlation "
            "suggests the environment is being targeted by a known campaign."
        ),
        "hunt_type": "intel_correlation",
        "query_language": "sql",
        "query_text": """
            SELECT
                d.detection_id, d.resource_arn, d.resource_type,
                d.severity, d.account_id, d.region, d.provider,
                a.risk_score, a.verdict,
                d.mitre_techniques AS detection_techniques,
                ti.source AS intel_source,
                ti.category AS campaign_category,
                ti.ttps AS campaign_ttps,
                ti.severity AS intel_severity,
                ti.threat_data->>'campaign_name' AS campaign_name
            FROM threat_detections d
            JOIN threat_analysis a ON d.detection_id = a.detection_id
            JOIN threat_intelligence ti ON ti.tenant_id = d.tenant_id
                AND ti.is_active = true
                AND ti.ttps ?| ARRAY(SELECT jsonb_array_elements_text(d.mitre_techniques))
            WHERE d.tenant_id = :tenant_id
            ORDER BY a.risk_score DESC, ti.severity
            LIMIT 50
        """,
        "target_data_sources": ["threat_detections", "threat_analysis", "threat_intelligence"],
        "mitre_tactics": [],
        "mitre_techniques": [],
        "tags": ["intel-correlation", "campaign-match", "threat-intelligence", "high-priority"],
    },
    {
        "query_name": "Hunt: High-Value Target Overlap",
        "description": (
            "Find resources that match both threat_intelligence indicators AND have "
            "high blast radius (>= 5 reachable resources). These are highest-priority "
            "targets — known threat campaign focus with large impact if compromised."
        ),
        "hunt_type": "intel_correlation",
        "query_language": "sql",
        "query_text": """
            SELECT
                d.detection_id, d.resource_arn, d.resource_type,
                d.severity, d.account_id, d.region, d.provider,
                a.risk_score, a.verdict,
                (a.analysis_results->'blast_radius'->>'reachable_count')::int AS blast_radius,
                d.mitre_techniques,
                ti.source AS intel_source,
                ti.category AS intel_category,
                ti.severity AS intel_severity
            FROM threat_detections d
            JOIN threat_analysis a ON d.detection_id = a.detection_id
            JOIN threat_intelligence ti ON ti.tenant_id = d.tenant_id
                AND ti.is_active = true
                AND ti.ttps ?| ARRAY(SELECT jsonb_array_elements_text(d.mitre_techniques))
            WHERE d.tenant_id = :tenant_id
              AND (a.analysis_results->'blast_radius'->>'reachable_count')::int >= 5
            ORDER BY (a.analysis_results->'blast_radius'->>'reachable_count')::int DESC,
                     a.risk_score DESC
            LIMIT 30
        """,
        "target_data_sources": ["threat_detections", "threat_analysis", "threat_intelligence"],
        "mitre_tactics": [],
        "mitre_techniques": [],
        "tags": ["intel-correlation", "high-value-target", "blast-radius", "critical"],
    },
    {
        "query_name": "Hunt: Emerging Threat Indicator Match",
        "description": (
            "Match recent threat intelligence (published in the last 30 days) with "
            "active detections to find resources affected by newly emerging threats. "
            "Early detection of new campaigns before they are widely known."
        ),
        "hunt_type": "intel_correlation",
        "query_language": "sql",
        "query_text": """
            SELECT
                d.detection_id, d.resource_arn, d.resource_type,
                d.severity, d.account_id, d.region, d.provider,
                a.risk_score, a.verdict,
                d.mitre_techniques AS detection_techniques,
                ti.source AS intel_source,
                ti.category AS intel_category,
                ti.severity AS intel_severity,
                ti.first_seen_at AS intel_first_seen,
                ti.ttps AS campaign_ttps
            FROM threat_detections d
            JOIN threat_analysis a ON d.detection_id = a.detection_id
            JOIN threat_intelligence ti ON ti.tenant_id = d.tenant_id
                AND ti.is_active = true
                AND ti.first_seen_at >= NOW() - INTERVAL '30 days'
                AND ti.ttps ?| ARRAY(SELECT jsonb_array_elements_text(d.mitre_techniques))
            WHERE d.tenant_id = :tenant_id
            ORDER BY ti.first_seen_at DESC, a.risk_score DESC
            LIMIT 50
        """,
        "target_data_sources": ["threat_detections", "threat_analysis", "threat_intelligence"],
        "mitre_tactics": [],
        "mitre_techniques": [],
        "tags": ["intel-correlation", "emerging-threat", "recent-intel", "early-warning"],
    },

    # ── Category 17: CSP-Specific Blast Radius (Cypher) ───────────────────

    {
        "query_name": "Graph Hunt: Azure Blast Radius — VM to KeyVault Chain",
        "description": (
            "From any compromised Azure VM, find all KeyVaults reachable via graph "
            "paths (Managed Identity, Role Assignments, VNet peering). Shows the "
            "secrets and keys at risk if a VM is compromised."
        ),
        "hunt_type": "graph_blast_radius",
        "query_language": "cypher",
        "query_text": """
            MATCH (vm:Resource {tenant_id: $tid})-[*1..4]->(kv:Resource {tenant_id: $tid})
            WHERE vm.resource_type IN ['azure_vm', 'azure_virtual_machine', 'azure_vmss']
              AND kv.resource_type IN ['azure_key_vault', 'azure_key_vault_secret', 'azure_key_vault_key']
              AND vm <> kv
            WITH vm, kv, count(*) AS path_count
            OPTIONAL MATCH (vm)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                vm.uid AS vm_arn,
                vm.name AS vm_name,
                kv.uid AS keyvault_arn,
                kv.name AS keyvault_name,
                kv.resource_type AS keyvault_type,
                path_count,
                collect(DISTINCT t.severity) AS vm_threat_severities,
                count(DISTINCT t) AS vm_threat_count
            ORDER BY vm_threat_count DESC, path_count DESC
            LIMIT 30
        """,
        "target_data_sources": ["Neo4j Security Graph"],
        "mitre_tactics": ["Credential Access", "Lateral Movement"],
        "mitre_techniques": ["T1552", "T1078"],
        "tags": ["graph", "azure", "blast-radius", "vm", "keyvault", "credential-access"],
    },
    {
        "query_name": "Graph Hunt: GCP Blast Radius — Instance to BigQuery",
        "description": (
            "From any compromised GCP Compute instance, find all BigQuery datasets "
            "reachable via graph paths (Service Account, IAM bindings, VPC). Shows "
            "data analytics assets at risk of exfiltration."
        ),
        "hunt_type": "graph_blast_radius",
        "query_language": "cypher",
        "query_text": """
            MATCH (inst:Resource {tenant_id: $tid})-[*1..4]->(bq:Resource {tenant_id: $tid})
            WHERE inst.resource_type IN ['gcp_compute_instance', 'gcp_instance', 'gcp_gke_node']
              AND bq.resource_type IN ['gcp_bigquery_dataset', 'gcp_bigquery_table', 'gcp_datastore']
              AND inst <> bq
            WITH inst, bq, count(*) AS path_count
            OPTIONAL MATCH (inst)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                inst.uid AS instance_arn,
                inst.name AS instance_name,
                bq.uid AS bigquery_arn,
                bq.name AS bigquery_name,
                bq.resource_type AS bigquery_type,
                path_count,
                collect(DISTINCT t.severity) AS instance_threat_severities,
                count(DISTINCT t) AS instance_threat_count
            ORDER BY instance_threat_count DESC, path_count DESC
            LIMIT 30
        """,
        "target_data_sources": ["Neo4j Security Graph"],
        "mitre_tactics": ["Collection", "Exfiltration"],
        "mitre_techniques": ["T1530", "T1537"],
        "tags": ["graph", "gcp", "blast-radius", "compute", "bigquery", "exfiltration"],
    },
    {
        "query_name": "Graph Hunt: K8s Blast Radius — Pod to Secret Chain",
        "description": (
            "From any compromised Kubernetes Pod, find all Secrets reachable via "
            "graph paths (ServiceAccount, RBAC, namespace relationships). Shows "
            "sensitive credentials at risk of theft from a compromised container."
        ),
        "hunt_type": "graph_blast_radius",
        "query_language": "cypher",
        "query_text": """
            MATCH (pod:Resource {tenant_id: $tid})-[*1..4]->(secret:Resource {tenant_id: $tid})
            WHERE pod.resource_type IN ['k8s_pod', 'k8s_deployment', 'k8s_daemonset', 'k8s_statefulset']
              AND secret.resource_type IN ['k8s_secret', 'k8s_configmap']
              AND pod <> secret
            WITH pod, collect(DISTINCT secret) AS reachable_secrets
            OPTIONAL MATCH (pod)-[:HAS_THREAT]->(t:ThreatDetection)
            RETURN
                pod.uid AS pod_arn,
                pod.name AS pod_name,
                pod.resource_type AS pod_type,
                size(reachable_secrets) AS reachable_secret_count,
                [s IN reachable_secrets | s.name] AS secret_names,
                collect(DISTINCT t.severity) AS pod_threat_severities,
                count(DISTINCT t) AS pod_threat_count
            ORDER BY reachable_secret_count DESC, pod_threat_count DESC
            LIMIT 30
        """,
        "target_data_sources": ["Neo4j Security Graph"],
        "mitre_tactics": ["Credential Access"],
        "mitre_techniques": ["T1552"],
        "tags": ["graph", "k8s", "blast-radius", "pod", "secret", "credential-access"],
    },

    # ── Category 18: Detection Pattern Analysis (SQL) ─────────────────────

    {
        "query_name": "Hunt: MITRE Technique Frequency Heatmap",
        "description": (
            "Count detections per MITRE technique per account to build a heatmap "
            "of attack patterns. Identifies which techniques are most prevalent "
            "and which accounts are most targeted."
        ),
        "hunt_type": "pattern_analysis",
        "query_language": "sql",
        "query_text": """
            SELECT
                d.account_id,
                d.provider,
                technique.value::text AS mitre_technique,
                COUNT(*) AS detection_count,
                COUNT(*) FILTER (WHERE d.severity = 'critical') AS critical_count,
                COUNT(*) FILTER (WHERE d.severity = 'high') AS high_count,
                AVG(a.risk_score) AS avg_risk_score,
                MAX(a.risk_score) AS max_risk_score
            FROM threat_detections d
            LEFT JOIN threat_analysis a ON d.detection_id = a.detection_id
            CROSS JOIN LATERAL jsonb_array_elements(d.mitre_techniques) AS technique(value)
            WHERE d.tenant_id = :tenant_id
              AND d.mitre_techniques IS NOT NULL
              AND jsonb_array_length(d.mitre_techniques) > 0
            GROUP BY d.account_id, d.provider, technique.value::text
            ORDER BY detection_count DESC
            LIMIT 100
        """,
        "target_data_sources": ["threat_detections", "threat_analysis"],
        "mitre_tactics": [],
        "mitre_techniques": [],
        "tags": ["pattern-analysis", "heatmap", "mitre-frequency", "overview"],
    },
    {
        "query_name": "Hunt: CSP Risk Distribution",
        "description": (
            "Analyze risk scores grouped by cloud provider to identify which CSP "
            "environments carry the most risk. Helps prioritize remediation efforts "
            "across multi-cloud deployments."
        ),
        "hunt_type": "pattern_analysis",
        "query_language": "sql",
        "query_text": """
            SELECT
                d.provider,
                COUNT(*) AS total_detections,
                COUNT(*) FILTER (WHERE d.severity = 'critical') AS critical_count,
                COUNT(*) FILTER (WHERE d.severity = 'high') AS high_count,
                COUNT(*) FILTER (WHERE d.severity = 'medium') AS medium_count,
                COUNT(*) FILTER (WHERE d.severity = 'low') AS low_count,
                ROUND(AVG(a.risk_score), 1) AS avg_risk_score,
                MAX(a.risk_score) AS max_risk_score,
                COUNT(DISTINCT d.account_id) AS account_count,
                COUNT(DISTINCT d.resource_type) AS resource_type_count,
                array_agg(DISTINCT d.region) AS regions
            FROM threat_detections d
            LEFT JOIN threat_analysis a ON d.detection_id = a.detection_id
            WHERE d.tenant_id = :tenant_id
            GROUP BY d.provider
            ORDER BY COUNT(*) DESC
        """,
        "target_data_sources": ["threat_detections", "threat_analysis"],
        "mitre_tactics": [],
        "mitre_techniques": [],
        "tags": ["pattern-analysis", "csp-distribution", "risk-overview", "multi-cloud"],
    },
]


def get_neo4j_driver():
    """Get Neo4j driver for Cypher query validation."""
    from neo4j import GraphDatabase
    uri = os.getenv("NEO4J_URI", "neo4j+s://17ec5cbb.databases.neo4j.io")
    user = os.getenv("NEO4J_USER", "neo4j")
    pwd = os.getenv("NEO4J_PASSWORD", "")
    return GraphDatabase.driver(uri, auth=(user, pwd))


def validate_query(conn, query: Dict[str, Any], tenant_id: str, neo4j_driver=None) -> Dict[str, Any]:
    """Dry-run a query. Routes SQL to PostgreSQL, Cypher to Neo4j."""
    if query["query_language"] == "cypher":
        if not neo4j_driver:
            return {"status": "skip", "row_count": 0, "error": "No Neo4j driver"}
        try:
            with neo4j_driver.session() as session:
                result = session.run(query["query_text"], tid=tenant_id)
                records = [dict(r) for r in result]
                return {"status": "ok", "row_count": len(records)}
        except Exception as e:
            return {"status": "error", "error": str(e)}
    else:
        # SQL validation against PostgreSQL
        sql = query["query_text"].replace(":tenant_id", "%s")
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            try:
                wrapped = f"SELECT COUNT(*) AS cnt FROM ({sql}) sub"
                cur.execute(wrapped, (tenant_id,))
                row = cur.fetchone()
                return {"status": "ok", "row_count": row["cnt"]}
            except Exception as e:
                conn.rollback()
                return {"status": "error", "error": str(e)}


def seed_queries(conn, queries: List[Dict[str, Any]], tenant_id: str, dry_run: bool = False):
    """Insert hunt queries into threat_hunt_queries table."""
    inserted = 0
    skipped = 0

    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        for q in queries:
            # Check if already exists (by query_name + tenant_id)
            cur.execute("""
                SELECT hunt_id FROM threat_hunt_queries
                WHERE tenant_id = %s AND query_name = %s
            """, (tenant_id, q["query_name"]))
            existing = cur.fetchone()

            if existing:
                if dry_run:
                    print(f"  SKIP (exists): {q['query_name']}")
                else:
                    # Update existing
                    cur.execute("""
                        UPDATE threat_hunt_queries
                        SET description = %s,
                            hunt_type = %s,
                            query_language = %s,
                            query_text = %s,
                            target_data_sources = %s,
                            mitre_tactics = %s,
                            mitre_techniques = %s,
                            tags = %s,
                            updated_at = NOW()
                        WHERE hunt_id = %s
                    """, (
                        q["description"],
                        q["hunt_type"],
                        q["query_language"],
                        q["query_text"],
                        Json(q["target_data_sources"]),
                        Json(q["mitre_tactics"]),
                        Json(q["mitre_techniques"]),
                        Json(q["tags"]),
                        existing["hunt_id"],
                    ))
                    print(f"  UPDATE: {q['query_name']}")
                    inserted += 1
                continue

            if dry_run:
                print(f"  INSERT: {q['query_name']} ({q['hunt_type']})")
                skipped += 1
                continue

            cur.execute("""
                INSERT INTO threat_hunt_queries (
                    tenant_id, query_name, description,
                    hunt_type, query_language, query_text,
                    target_data_sources, mitre_tactics, mitre_techniques,
                    tags, created_by, is_active
                ) VALUES (
                    %s, %s, %s,
                    %s, %s, %s,
                    %s, %s, %s,
                    %s, %s, %s
                )
                RETURNING hunt_id
            """, (
                tenant_id,
                q["query_name"],
                q["description"],
                q["hunt_type"],
                q["query_language"],
                q["query_text"],
                Json(q["target_data_sources"]),
                Json(q["mitre_tactics"]),
                Json(q["mitre_techniques"]),
                Json(q["tags"]),
                "seed_hunt_queries.py",
                True,
            ))
            hunt_id = cur.fetchone()["hunt_id"]
            print(f"  INSERT: {q['query_name']} → {hunt_id}")
            inserted += 1

    if not dry_run:
        conn.commit()

    return inserted, skipped


def main():
    parser = argparse.ArgumentParser(description="Seed threat hunt queries from MITRE data")
    parser.add_argument("--dry-run", action="store_true", help="Preview only, don't insert")
    parser.add_argument("--validate-only", action="store_true", help="Run each query, show results")
    parser.add_argument("--tenant-id", default="tnt_local_test", help="Tenant ID for queries")
    args = parser.parse_args()

    conn = get_conn()

    if args.validate_only:
        # Try to connect to Neo4j for Cypher validation
        neo4j_driver = None
        has_cypher = any(q["query_language"] == "cypher" for q in HUNT_QUERIES)
        if has_cypher:
            try:
                neo4j_driver = get_neo4j_driver()
                print("  Neo4j connected ✅")
            except Exception as e:
                print(f"  Neo4j not available: {e} (Cypher queries will be skipped)")

        print(f"\n{'='*70}")
        print(f"VALIDATING {len(HUNT_QUERIES)} hunt queries against DB")
        print(f"Tenant: {args.tenant_id}")
        print(f"{'='*70}\n")

        ok_count = 0
        fail_count = 0
        skip_count = 0
        for q in HUNT_QUERIES:
            result = validate_query(conn, q, args.tenant_id, neo4j_driver)
            if result["status"] == "ok":
                print(f"  ✅ {q['query_name']}: {result['row_count']} rows")
                ok_count += 1
            elif result["status"] == "skip":
                print(f"  ⏭️  {q['query_name']}: SKIPPED (no Neo4j)")
                skip_count += 1
            else:
                print(f"  ❌ {q['query_name']}: ERROR — {result['error']}")
                fail_count += 1

        print(f"\n{'='*70}")
        print(f"Results: {ok_count} passed, {fail_count} failed, {skip_count} skipped out of {len(HUNT_QUERIES)}")
        print(f"{'='*70}\n")

        if neo4j_driver:
            neo4j_driver.close()
        conn.close()
        sys.exit(1 if fail_count > 0 else 0)

    print(f"\n{'='*70}")
    print(f"{'DRY RUN — ' if args.dry_run else ''}Seeding {len(HUNT_QUERIES)} hunt queries")
    print(f"Tenant: {args.tenant_id}")
    print(f"{'='*70}\n")

    inserted, skipped = seed_queries(conn, HUNT_QUERIES, args.tenant_id, args.dry_run)

    print(f"\n{'='*70}")
    print(f"{'DRY RUN — ' if args.dry_run else ''}Done: {inserted} inserted/updated, {skipped} skipped")
    print(f"{'='*70}\n")

    conn.close()


if __name__ == "__main__":
    main()
