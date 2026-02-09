#!/usr/bin/env python3
"""
Seed threat_intelligence table with cloud-focused threat intelligence feeds.

Creates intelligence entries from multiple sources:
  1. MITRE ATT&CK Cloud Matrix — active cloud TTPs with CSP-specific context
  2. CISA Known Exploited Vulnerabilities (KEV) — cloud-relevant CVEs
  3. Cloud Threat Campaigns — real-world attack campaigns (Scattered Spider, LUCR-3, etc.)
  4. Cloud Misconfig Exploitation — common misconfigurations weaponized in attacks
  5. Cloud Ransomware Patterns — ransomware techniques targeting cloud storage/compute

Each entry includes:
  - Source, type, category, severity, confidence
  - threat_data: structured description, affected_services, affected_csps
  - indicators: IOC-style patterns (resource patterns, API calls, etc.)
  - ttps: MITRE ATT&CK technique IDs
  - tags: searchable labels
  - expires_at: intelligence freshness (90/180/365 days depending on source)

Usage:
    python scripts/seed_threat_intelligence.py --dry-run
    python scripts/seed_threat_intelligence.py --tenant-id tnt_local_test
    python scripts/seed_threat_intelligence.py --tenant-id 588989875114
"""

import argparse
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
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


NOW = datetime.now(timezone.utc)


# ─────────────────────────────────────────────────────────────────────────────
# 1. MITRE ATT&CK Cloud Matrix — Active Cloud TTPs
# ─────────────────────────────────────────────────────────────────────────────

MITRE_CLOUD_INTEL: List[Dict[str, Any]] = [
    {
        "source": "mitre_attack_cloud",
        "intel_type": "ttp",
        "category": "initial_access",
        "severity": "critical",
        "confidence": "high",
        "threat_data": {
            "name": "Cloud Exploitation of Public-Facing Applications",
            "description": "Threat actors actively exploiting misconfigured cloud services exposed to the internet, including S3 buckets, RDS instances, and API Gateways without authentication.",
            "affected_services": ["s3", "rds", "apigateway", "ec2", "lambda"],
            "affected_csps": ["aws", "azure", "gcp"],
            "attack_vector": "Internet-facing cloud resources with weak access controls",
            "reference_url": "https://attack.mitre.org/techniques/T1190/",
        },
        "indicators": ["s3:::*", "0.0.0.0/0", "public-access-enabled", "no-auth-api"],
        "ttps": ["T1190", "T1530", "T1078"],
        "tags": ["internet-exposed", "public-access", "initial-access", "s3", "rds"],
        "expires_at": NOW + timedelta(days=365),
    },
    {
        "source": "mitre_attack_cloud",
        "intel_type": "ttp",
        "category": "credential_access",
        "severity": "critical",
        "confidence": "high",
        "threat_data": {
            "name": "Cloud Credential Harvesting via Metadata Service",
            "description": "Exploitation of IMDS (Instance Metadata Service) to harvest temporary credentials from EC2/VM instances. SSRF attacks chain through web apps to reach 169.254.169.254.",
            "affected_services": ["ec2", "iam", "lambda"],
            "affected_csps": ["aws", "azure", "gcp"],
            "attack_vector": "SSRF to instance metadata endpoint",
            "reference_url": "https://attack.mitre.org/techniques/T1552/005/",
        },
        "indicators": ["169.254.169.254", "metadata.google.internal", "iam:role", "instance-profile"],
        "ttps": ["T1552.005", "T1078", "T1190"],
        "tags": ["imds", "ssrf", "credential-theft", "ec2", "metadata"],
        "expires_at": NOW + timedelta(days=365),
    },
    {
        "source": "mitre_attack_cloud",
        "intel_type": "ttp",
        "category": "privilege_escalation",
        "severity": "critical",
        "confidence": "high",
        "threat_data": {
            "name": "Cloud IAM Privilege Escalation",
            "description": "Attackers leveraging overly permissive IAM policies to escalate privileges. Common paths include PassRole, AssumeRole chaining, and wildcard permissions in managed policies.",
            "affected_services": ["iam", "sts", "organizations"],
            "affected_csps": ["aws", "azure", "gcp"],
            "attack_vector": "IAM policy misconfiguration enabling role assumption chains",
            "reference_url": "https://attack.mitre.org/techniques/T1098/",
        },
        "indicators": ["iam:PassRole", "sts:AssumeRole", "Action:*", "Resource:*", "cross-account-trust"],
        "ttps": ["T1098", "T1078", "T1550"],
        "tags": ["iam", "privilege-escalation", "passrole", "assumerole", "wildcard-permissions"],
        "expires_at": NOW + timedelta(days=365),
    },
    {
        "source": "mitre_attack_cloud",
        "intel_type": "ttp",
        "category": "defense_evasion",
        "severity": "high",
        "confidence": "high",
        "threat_data": {
            "name": "Cloud Logging Disruption",
            "description": "Threat actors disabling or modifying cloud logging services (CloudTrail, Azure Monitor, Cloud Audit Logs) to cover tracks. Includes deleting log sinks, modifying retention, and disabling services.",
            "affected_services": ["cloudtrail", "cloudwatch", "config", "guardduty"],
            "affected_csps": ["aws", "azure", "gcp"],
            "attack_vector": "API calls to disable or modify logging configuration",
            "reference_url": "https://attack.mitre.org/techniques/T1562/008/",
        },
        "indicators": ["StopLogging", "DeleteTrail", "UpdateTrail", "DisableGuardDuty"],
        "ttps": ["T1562", "T1562.008"],
        "tags": ["logging-evasion", "cloudtrail", "guardduty", "defense-evasion"],
        "expires_at": NOW + timedelta(days=365),
    },
    {
        "source": "mitre_attack_cloud",
        "intel_type": "ttp",
        "category": "lateral_movement",
        "severity": "high",
        "confidence": "medium",
        "threat_data": {
            "name": "Cloud Cross-Account Lateral Movement",
            "description": "Exploitation of cross-account IAM trust relationships and VPC peering to move laterally between AWS accounts, Azure subscriptions, or GCP projects.",
            "affected_services": ["iam", "sts", "vpc", "organizations"],
            "affected_csps": ["aws", "azure", "gcp"],
            "attack_vector": "Cross-account role assumptions and network peering",
            "reference_url": "https://attack.mitre.org/techniques/T1199/",
        },
        "indicators": ["cross-account-trust", "vpc-peering", "transit-gateway", "sts:AssumeRole"],
        "ttps": ["T1199", "T1550", "T1078"],
        "tags": ["lateral-movement", "cross-account", "vpc-peering", "trust-relationship"],
        "expires_at": NOW + timedelta(days=365),
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# 2. CISA KEV — Cloud-Relevant Known Exploited Vulnerabilities
# ─────────────────────────────────────────────────────────────────────────────

CISA_KEV_INTEL: List[Dict[str, Any]] = [
    {
        "source": "cisa_kev",
        "intel_type": "vulnerability",
        "category": "initial_access",
        "severity": "critical",
        "confidence": "high",
        "threat_data": {
            "name": "SSRF in Cloud Web Applications (Generic Pattern)",
            "description": "Server-Side Request Forgery vulnerabilities in cloud-deployed web applications enabling access to cloud metadata services and internal APIs. Common in web frameworks with URL fetching capabilities.",
            "affected_services": ["ec2", "ecs", "lambda", "elastic_beanstalk"],
            "affected_csps": ["aws", "azure", "gcp"],
            "attack_vector": "SSRF through web application to cloud metadata endpoint",
            "mitigation": "Enforce IMDSv2, use network segmentation, validate URL inputs",
        },
        "indicators": ["169.254.169.254", "metadata.google.internal", "instance-metadata"],
        "ttps": ["T1190", "T1552.005"],
        "tags": ["cisa-kev", "ssrf", "imds", "web-application"],
        "expires_at": NOW + timedelta(days=180),
    },
    {
        "source": "cisa_kev",
        "intel_type": "vulnerability",
        "category": "credential_access",
        "severity": "critical",
        "confidence": "high",
        "threat_data": {
            "name": "Exposed Cloud Credentials in CI/CD Pipelines",
            "description": "Cloud access keys and service account credentials exposed in CI/CD pipeline configurations, environment variables, and build artifacts. Actively exploited for initial access to cloud environments.",
            "affected_services": ["iam", "codebuild", "codepipeline", "codecommit"],
            "affected_csps": ["aws", "azure", "gcp"],
            "attack_vector": "Credential harvesting from CI/CD artifacts and configurations",
            "mitigation": "Use short-lived credentials, OIDC federation, rotate all exposed keys",
        },
        "indicators": ["AKIA*", "ASIA*", "gcp-sa-key", "azure-client-secret", "github-actions-secret"],
        "ttps": ["T1552", "T1078", "T1199"],
        "tags": ["cisa-kev", "ci-cd", "credential-exposure", "devops"],
        "expires_at": NOW + timedelta(days=180),
    },
    {
        "source": "cisa_kev",
        "intel_type": "vulnerability",
        "category": "data_exfiltration",
        "severity": "high",
        "confidence": "high",
        "threat_data": {
            "name": "Public Cloud Storage Data Exposure",
            "description": "Publicly accessible cloud storage buckets/containers with sensitive data, actively scanned and exploited by automated tools. Includes S3, Azure Blob Storage, and GCS buckets.",
            "affected_services": ["s3", "storage_accounts", "gcs"],
            "affected_csps": ["aws", "azure", "gcp"],
            "attack_vector": "Automated scanning of public cloud storage endpoints",
            "mitigation": "Block public access at account level, enable logging, classify data",
        },
        "indicators": ["s3:::*", "public-access-block=false", "allUsers", "allAuthenticatedUsers"],
        "ttps": ["T1530", "T1119"],
        "tags": ["cisa-kev", "public-storage", "data-exposure", "s3"],
        "expires_at": NOW + timedelta(days=180),
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# 3. Cloud Threat Campaigns — Real-World Attack Campaigns
# ─────────────────────────────────────────────────────────────────────────────

CAMPAIGN_INTEL: List[Dict[str, Any]] = [
    {
        "source": "threat_campaign",
        "intel_type": "campaign",
        "category": "multi_stage",
        "severity": "critical",
        "confidence": "high",
        "threat_data": {
            "name": "Scattered Spider / UNC3944 Cloud Attacks",
            "description": "Advanced threat group targeting cloud infrastructure through social engineering and identity provider compromise. Known for SIM swapping, Okta abuse, and Azure AD manipulation to gain cloud access.",
            "affected_services": ["iam", "azure_ad", "okta", "ec2", "s3"],
            "affected_csps": ["aws", "azure", "gcp"],
            "threat_actor": "Scattered Spider / UNC3944",
            "attack_chain": "Social engineering → Identity provider compromise → Cloud account takeover → Data exfiltration",
            "reference_url": "https://attack.mitre.org/groups/G1015/",
        },
        "indicators": ["okta-session-hijack", "azure-ad-modification", "mfa-bypass", "sim-swap"],
        "ttps": ["T1078", "T1556", "T1531", "T1530", "T1537"],
        "tags": ["apt", "scattered-spider", "unc3944", "identity-attack", "social-engineering"],
        "expires_at": NOW + timedelta(days=365),
    },
    {
        "source": "threat_campaign",
        "intel_type": "campaign",
        "category": "cryptomining",
        "severity": "high",
        "confidence": "high",
        "threat_data": {
            "name": "Cloud Cryptojacking Campaigns (TeamTNT/WatchDog)",
            "description": "Automated campaigns exploiting exposed cloud credentials and misconfigured container orchestration to deploy cryptominers. Targets EC2, ECS, EKS, and Lambda for compute resources.",
            "affected_services": ["ec2", "ecs", "eks", "lambda", "fargate"],
            "affected_csps": ["aws", "azure", "gcp"],
            "threat_actor": "TeamTNT / WatchDog variants",
            "attack_chain": "Exposed credentials/containers → Resource hijacking → Cryptominer deployment",
        },
        "indicators": ["xmrig", "stratum+tcp://", "docker.sock", "kubelet:10250", "crypto-miner-binary"],
        "ttps": ["T1496", "T1078", "T1190", "T1525", "T1610"],
        "tags": ["cryptomining", "teamtnt", "container-abuse", "resource-hijacking"],
        "expires_at": NOW + timedelta(days=180),
    },
    {
        "source": "threat_campaign",
        "intel_type": "campaign",
        "category": "ransomware",
        "severity": "critical",
        "confidence": "high",
        "threat_data": {
            "name": "Cloud Ransomware — S3 Bucket Encryption Attacks",
            "description": "Ransomware campaigns targeting cloud storage by encrypting objects with attacker-controlled KMS keys or deleting backups before encryption. Targets S3, Azure Blob, and GCS with versioning disabled.",
            "affected_services": ["s3", "kms", "ebs", "rds", "backup"],
            "affected_csps": ["aws", "azure", "gcp"],
            "threat_actor": "Multiple groups",
            "attack_chain": "Credential theft → Disable versioning/backups → Encrypt with attacker KMS → Ransom demand",
        },
        "indicators": ["s3:PutBucketVersioning:Suspend", "kms:CreateKey", "kms:Encrypt", "backup:DeleteRecoveryPoint"],
        "ttps": ["T1485", "T1486", "T1490", "T1489"],
        "tags": ["ransomware", "cloud-ransom", "s3-encryption", "data-destruction"],
        "expires_at": NOW + timedelta(days=180),
    },
    {
        "source": "threat_campaign",
        "intel_type": "campaign",
        "category": "supply_chain",
        "severity": "high",
        "confidence": "medium",
        "threat_data": {
            "name": "Cloud Supply Chain — Malicious Container Images",
            "description": "Supply chain attacks via poisoned container images in public registries deployed to cloud container services. Images contain backdoors, cryptominers, or credential stealers targeting cloud environments.",
            "affected_services": ["ecr", "ecs", "eks", "fargate"],
            "affected_csps": ["aws", "azure", "gcp"],
            "attack_chain": "Poisoned public image → Pull to private registry → Deploy to production → Backdoor activation",
        },
        "indicators": ["public-registry-pull", "unsigned-image", "docker-hub-typosquat", "ecr-public"],
        "ttps": ["T1525", "T1199", "T1059"],
        "tags": ["supply-chain", "container-security", "poisoned-image", "ecr"],
        "expires_at": NOW + timedelta(days=180),
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# 4. Cloud Misconfig Exploitation — Common Weaponized Misconfigs
# ─────────────────────────────────────────────────────────────────────────────

MISCONFIG_INTEL: List[Dict[str, Any]] = [
    {
        "source": "cloud_misconfig_intel",
        "intel_type": "indicator",
        "category": "exposure",
        "severity": "critical",
        "confidence": "high",
        "threat_data": {
            "name": "Security Group — All Traffic Allowed (0.0.0.0/0)",
            "description": "Security groups with unrestricted inbound access are actively exploited for initial access. Automated scanners continuously probe AWS, Azure, and GCP IP ranges for open ports.",
            "affected_services": ["ec2", "rds", "redshift", "elasticsearch"],
            "affected_csps": ["aws", "azure", "gcp"],
            "exploitation_frequency": "continuous",
            "avg_time_to_exploit": "< 15 minutes after exposure",
        },
        "indicators": ["0.0.0.0/0", "sg-all-traffic", "nsg-allow-all", "firewall-allow-all"],
        "ttps": ["T1190", "T1046"],
        "tags": ["security-group", "open-access", "internet-exposed", "network-misconfig"],
        "expires_at": NOW + timedelta(days=365),
    },
    {
        "source": "cloud_misconfig_intel",
        "intel_type": "indicator",
        "category": "identity",
        "severity": "critical",
        "confidence": "high",
        "threat_data": {
            "name": "IAM Root/Admin Without MFA",
            "description": "Cloud accounts with root or admin access without MFA are high-priority targets. Compromised root credentials with no MFA provide unrestricted access to all cloud resources.",
            "affected_services": ["iam", "organizations"],
            "affected_csps": ["aws", "azure", "gcp"],
            "exploitation_frequency": "high",
            "avg_time_to_exploit": "Immediate if credentials leaked",
        },
        "indicators": ["root-access-no-mfa", "admin-no-mfa", "global-admin-no-mfa"],
        "ttps": ["T1078", "T1110"],
        "tags": ["iam", "mfa", "root-access", "admin-access", "credential-weakness"],
        "expires_at": NOW + timedelta(days=365),
    },
    {
        "source": "cloud_misconfig_intel",
        "intel_type": "indicator",
        "category": "data_at_risk",
        "severity": "high",
        "confidence": "high",
        "threat_data": {
            "name": "Unencrypted Storage with Sensitive Data",
            "description": "Cloud storage without encryption at rest combined with sensitive data classifications. When breached, unencrypted data provides immediate value to attackers without decryption overhead.",
            "affected_services": ["s3", "ebs", "rds", "dynamodb", "elasticache"],
            "affected_csps": ["aws", "azure", "gcp"],
            "exploitation_frequency": "medium",
        },
        "indicators": ["encryption-disabled", "sse-none", "storage-not-encrypted", "pii-data"],
        "ttps": ["T1530", "T1119", "T1537"],
        "tags": ["encryption", "data-at-rest", "sensitive-data", "storage-misconfig"],
        "expires_at": NOW + timedelta(days=365),
    },
    {
        "source": "cloud_misconfig_intel",
        "intel_type": "indicator",
        "category": "logging_gap",
        "severity": "high",
        "confidence": "high",
        "threat_data": {
            "name": "Disabled Cloud Logging Services",
            "description": "CloudTrail, VPC Flow Logs, or GuardDuty disabled — eliminates visibility into attacker activity. First action many APTs take after gaining access is disabling logging.",
            "affected_services": ["cloudtrail", "guardduty", "vpc_flow_logs", "config"],
            "affected_csps": ["aws", "azure", "gcp"],
            "exploitation_frequency": "every advanced attack",
        },
        "indicators": ["cloudtrail-disabled", "guardduty-disabled", "flow-logs-disabled"],
        "ttps": ["T1562", "T1562.008"],
        "tags": ["logging", "visibility-gap", "cloudtrail", "guardduty", "defense-evasion"],
        "expires_at": NOW + timedelta(days=365),
    },
    {
        "source": "cloud_misconfig_intel",
        "intel_type": "indicator",
        "category": "exposure",
        "severity": "high",
        "confidence": "medium",
        "threat_data": {
            "name": "Unused/Stale Cloud Regions with Active Resources",
            "description": "Attackers deploy resources in rarely monitored cloud regions to evade detection. Stale regions with old resources are often missed by security scans and have weaker monitoring.",
            "affected_services": ["ec2", "s3", "rds", "lambda"],
            "affected_csps": ["aws", "azure", "gcp"],
            "exploitation_frequency": "medium",
        },
        "indicators": ["unused-region", "non-primary-region", "stale-resource"],
        "ttps": ["T1535", "T1496"],
        "tags": ["shadow-resources", "unused-regions", "evasion", "cost-anomaly"],
        "expires_at": NOW + timedelta(days=365),
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# 5. Cloud Ransomware Patterns — Emerging Cloud-Native Ransomware
# ─────────────────────────────────────────────────────────────────────────────

RANSOMWARE_INTEL: List[Dict[str, Any]] = [
    {
        "source": "cloud_ransomware_intel",
        "intel_type": "ttp",
        "category": "ransomware",
        "severity": "critical",
        "confidence": "high",
        "threat_data": {
            "name": "S3 Ransom — Versioning Disabled + Object Encryption",
            "description": "Cloud-native ransomware pattern: disable S3 versioning, then encrypt all objects with attacker's KMS key. Without versioning, original objects are irrecoverable. Ransom demanded for KMS key.",
            "affected_services": ["s3", "kms"],
            "affected_csps": ["aws"],
            "kill_chain_steps": [
                "1. Compromise IAM credentials with S3 + KMS access",
                "2. Disable bucket versioning (PutBucketVersioning: Suspended)",
                "3. Iterate objects, copy-encrypt with attacker KMS key",
                "4. Delete original objects",
                "5. Post ransom note as bucket object",
            ],
            "detection_signals": ["PutBucketVersioning:Suspended", "kms:CreateKey from unusual IAM", "mass S3 CopyObject events"],
        },
        "indicators": ["s3:PutBucketVersioning", "kms:CreateKey", "s3:CopyObject:bulk", "ransom-note.txt"],
        "ttps": ["T1486", "T1485", "T1490"],
        "tags": ["ransomware", "s3-ransom", "cloud-native-ransom", "kms-abuse"],
        "expires_at": NOW + timedelta(days=180),
    },
    {
        "source": "cloud_ransomware_intel",
        "intel_type": "ttp",
        "category": "ransomware",
        "severity": "critical",
        "confidence": "high",
        "threat_data": {
            "name": "RDS/Database Ransom — Snapshot Delete + Data Encryption",
            "description": "Attack pattern targeting cloud databases: delete automated backups and snapshots, then encrypt or drop databases. Without backups, recovery requires paying ransom.",
            "affected_services": ["rds", "dynamodb", "aurora", "redshift"],
            "affected_csps": ["aws", "azure", "gcp"],
            "kill_chain_steps": [
                "1. Gain database admin credentials",
                "2. Delete automated backups and manual snapshots",
                "3. Encrypt or drop database tables",
                "4. Leave ransom message in remaining table",
            ],
            "detection_signals": ["DeleteDBSnapshot burst", "ModifyDBInstance:BackupRetention=0", "Mass table drops"],
        },
        "indicators": ["rds:DeleteDBSnapshot", "rds:ModifyDBInstance", "backup-retention-0"],
        "ttps": ["T1485", "T1490", "T1489"],
        "tags": ["ransomware", "database-ransom", "rds", "backup-deletion"],
        "expires_at": NOW + timedelta(days=180),
    },
    {
        "source": "cloud_ransomware_intel",
        "intel_type": "ttp",
        "category": "ransomware",
        "severity": "high",
        "confidence": "medium",
        "threat_data": {
            "name": "EBS Volume Encryption Ransom",
            "description": "Attacker creates snapshots of EBS volumes, creates encrypted copies with attacker's key, replaces original volumes, deletes unencrypted snapshots. Compute instances boot with encrypted volumes only accessible via ransom.",
            "affected_services": ["ec2", "ebs", "kms"],
            "affected_csps": ["aws"],
            "kill_chain_steps": [
                "1. Snapshot target EBS volumes",
                "2. Create encrypted copies with attacker KMS key",
                "3. Stop instances, detach original volumes",
                "4. Attach encrypted volumes, start instances",
                "5. Delete original snapshots and volumes",
            ],
            "detection_signals": ["CreateSnapshot burst", "CopySnapshot:Encrypted", "DetachVolume+AttachVolume sequence"],
        },
        "indicators": ["ec2:CreateSnapshot", "ec2:CopySnapshot", "kms:CreateGrant", "ebs-volume-swap"],
        "ttps": ["T1486", "T1578", "T1490"],
        "tags": ["ransomware", "ebs-ransom", "volume-encryption", "snapshot-abuse"],
        "expires_at": NOW + timedelta(days=180),
    },
]


ALL_INTEL = MITRE_CLOUD_INTEL + CISA_KEV_INTEL + CAMPAIGN_INTEL + MISCONFIG_INTEL + RANSOMWARE_INTEL


def seed_intelligence(conn, tenant_id: str, dry_run: bool = False):
    """Seed threat intelligence for a tenant."""
    import hashlib

    seeded = 0
    skipped = 0

    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        for item in ALL_INTEL:
            # Create stable hash for dedup
            raw = json.dumps(item["threat_data"], sort_keys=True)
            value_hash = hashlib.sha256(raw.encode()).hexdigest()[:64]

            # Check if already exists for this tenant + source + hash
            cur.execute("""
                SELECT intel_id FROM threat_intelligence
                WHERE tenant_id = %s AND source = %s AND value_hash = %s
            """, (tenant_id, item["source"], value_hash))

            if cur.fetchone():
                skipped += 1
                if dry_run:
                    print(f"  SKIP (exists): [{item['source']}] {item['threat_data']['name']}")
                continue

            if dry_run:
                print(f"  WOULD SEED: [{item['source']}] {item['threat_data']['name']} ({item['severity']})")
                seeded += 1
                continue

            cur.execute("""
                INSERT INTO threat_intelligence (
                    tenant_id, source, intel_type, category,
                    severity, confidence, value_hash,
                    threat_data, indicators, ttps, tags,
                    first_seen_at, last_seen_at, expires_at, is_active
                ) VALUES (
                    %s, %s, %s, %s,
                    %s, %s, %s,
                    %s, %s, %s, %s,
                    %s, %s, %s, %s
                )
            """, (
                tenant_id,
                item["source"],
                item["intel_type"],
                item.get("category"),
                item["severity"],
                item["confidence"],
                value_hash,
                Json(item["threat_data"]),
                Json(item.get("indicators", [])),
                Json(item.get("ttps", [])),
                Json(item.get("tags", [])),
                NOW,
                NOW,
                item.get("expires_at"),
                True,
            ))
            seeded += 1
            print(f"  SEEDED: [{item['source']}] {item['threat_data']['name']}")

    if not dry_run:
        conn.commit()

    return seeded, skipped


def show_summary(conn, tenant_id: str):
    """Show summary of threat intelligence for tenant."""
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT source, COUNT(*) as cnt,
                   COUNT(*) FILTER (WHERE is_active) as active
            FROM threat_intelligence
            WHERE tenant_id = %s
            GROUP BY source
            ORDER BY cnt DESC
        """, (tenant_id,))
        by_source = cur.fetchall()

        cur.execute("""
            SELECT severity, COUNT(*) as cnt
            FROM threat_intelligence
            WHERE tenant_id = %s AND is_active = true
            GROUP BY severity
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                END
        """, (tenant_id,))
        by_severity = cur.fetchall()

        cur.execute("""
            SELECT COUNT(*) as total FROM threat_intelligence WHERE tenant_id = %s
        """, (tenant_id,))
        total = cur.fetchone()["total"]

        print(f"\n  Total intel entries: {total}")
        print(f"\n  By source:")
        for row in by_source:
            print(f"    {row['source']:25s} {row['cnt']:3d} total, {row['active']:3d} active")
        print(f"\n  By severity (active):")
        for row in by_severity:
            print(f"    {row['severity']:10s} {row['cnt']:3d}")


def main():
    parser = argparse.ArgumentParser(description="Seed threat intelligence feeds")
    parser.add_argument("--dry-run", action="store_true", help="Preview only")
    parser.add_argument("--tenant-id", default="tnt_local_test", help="Tenant ID to seed for")
    args = parser.parse_args()

    conn = get_conn()

    print(f"\n{'='*70}")
    print(f"{'DRY RUN — ' if args.dry_run else ''}Seeding Threat Intelligence")
    print(f"Tenant: {args.tenant_id}")
    print(f"Entries: {len(ALL_INTEL)} ({len(MITRE_CLOUD_INTEL)} MITRE + {len(CISA_KEV_INTEL)} CISA + "
          f"{len(CAMPAIGN_INTEL)} Campaigns + {len(MISCONFIG_INTEL)} Misconfig + {len(RANSOMWARE_INTEL)} Ransomware)")
    print(f"{'='*70}\n")

    seeded, skipped = seed_intelligence(conn, args.tenant_id, args.dry_run)

    print(f"\n{'='*70}")
    action = "Would seed" if args.dry_run else "Seeded"
    print(f"{action}: {seeded} | Skipped: {skipped}")

    if not args.dry_run:
        print("\nSummary:")
        show_summary(conn, args.tenant_id)

    print(f"{'='*70}\n")

    conn.close()


if __name__ == "__main__":
    main()
