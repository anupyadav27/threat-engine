# MITRE ATT&CK Mapping

> How CSPM rules map to MITRE ATT&CK techniques and tactics, and how threat detection uses this mapping.

---

## Overview

The platform maps security rules to MITRE ATT&CK for Cloud (IaaS) techniques. This mapping is used for:
1. **Threat Detection** — Group findings by MITRE technique for threat classification
2. **Risk Scoring** — Weight threats by technique impact (T1190=1.0, T1078=0.9, etc.)
3. **Compliance** — Show MITRE coverage in compliance reports
4. **Threat Hunting** — Hunt for specific techniques in the security graph
5. **Intel Correlation** — Match external intel feeds by TTP overlap

---

## Technique Coverage

### Tactics & Techniques Mapped

| Tactic | ID | Techniques Covered |
|--------|-----|-------------------|
| **Initial Access** | TA0001 | T1190 (Exploit Public-Facing App), T1078 (Valid Accounts), T1199 (Trusted Relationship) |
| **Execution** | TA0002 | T1059 (Command/Script Interpreter), T1204 (User Execution) |
| **Persistence** | TA0003 | T1098 (Account Manipulation), T1078 (Valid Accounts), T1136 (Create Account) |
| **Privilege Escalation** | TA0004 | T1078 (Valid Accounts), T1098 (Account Manipulation), T1548 (Abuse Elevation Control) |
| **Defense Evasion** | TA0005 | T1562 (Impair Defenses), T1070 (Indicator Removal), T1550 (Use Alternate Auth) |
| **Credential Access** | TA0006 | T1040 (Network Sniffing), T1552 (Unsecured Credentials), T1528 (Steal App Access Token) |
| **Discovery** | TA0007 | T1087 (Account Discovery), T1580 (Cloud Infrastructure Discovery) |
| **Lateral Movement** | TA0008 | T1550 (Use Alternate Auth Material) |
| **Collection** | TA0009 | T1530 (Data from Cloud Storage) |
| **Exfiltration** | TA0010 | T1537 (Transfer Data to Cloud Account) |
| **Impact** | TA0040 | T1485 (Data Destruction), T1486 (Data Encrypted for Impact), T1490 (Inhibit Recovery), T1489 (Service Stop) |

### Technique Impact Weights (used in risk scoring)

| Technique | Name | Weight | Rationale |
|-----------|------|--------|-----------|
| T1190 | Exploit Public-Facing Application | 1.0 | Direct internet exploitation |
| T1078 | Valid Accounts | 0.9 | Credential compromise |
| T1485 | Data Destruction | 0.8 | Data loss impact |
| T1486 | Data Encrypted for Impact | 0.8 | Ransomware |
| T1562 | Impair Defenses | 0.7 | Security control bypass |
| T1098 | Account Manipulation | 0.7 | Persistence via IAM |
| T1537 | Transfer Data to Cloud Account | 0.7 | Data exfiltration |
| T1530 | Data from Cloud Storage | 0.6 | S3/storage data theft |
| T1040 | Network Sniffing | 0.5 | Passive reconnaissance |
| T1490 | Inhibit System Recovery | 0.8 | Backup destruction |
| T1552 | Unsecured Credentials | 0.6 | Exposed secrets |
| T1136 | Create Account | 0.5 | Persistence |
| Default | Other techniques | 0.4 | Baseline weight |

---

## Rule-to-Technique Mapping

### How Rules Get MITRE Mappings

Each YAML security rule in `rule_metadata` has MITRE fields:

```sql
-- rule_metadata table columns
mitre_technique_ids    JSONB    -- ["T1562", "T1485"]
mitre_technique_names  JSONB    -- ["Impair Defenses", "Data Destruction"]
```

### Mapping by Service

#### S3 (Storage)

| Rule | MITRE Techniques | Tactic |
|------|-----------------|--------|
| aws.s3.bucket.versioning_enabled | T1485, T1490 | Impact |
| aws.s3.bucket.server_side_encryption | T1530 | Collection |
| aws.s3.bucket.public_access_blocked | T1190, T1530 | Initial Access, Collection |
| aws.s3.bucket.logging_enabled | T1562 | Defense Evasion |
| aws.s3.bucket.mfa_delete | T1485, T1490 | Impact |
| aws.s3.bucket.lifecycle_policy | T1485 | Impact |
| aws.s3.bucket.cross_region_replication | T1537 | Exfiltration |

#### IAM (Identity)

| Rule | MITRE Techniques | Tactic |
|------|-----------------|--------|
| aws.iam.user.mfa_enabled | T1078 | Initial Access |
| aws.iam.user.console_password_rotation | T1078, T1552 | Initial Access, Credential Access |
| aws.iam.role.cross_account_trust | T1199, T1550 | Initial Access, Lateral Movement |
| aws.iam.policy.admin_access | T1078, T1098 | Privilege Escalation |
| aws.iam.user.access_key_rotation | T1552, T1528 | Credential Access |
| aws.iam.root.access_key_exists | T1078 | Initial Access |

#### EC2 (Compute)

| Rule | MITRE Techniques | Tactic |
|------|-----------------|--------|
| aws.ec2.security_group.unrestricted_ingress | T1190 | Initial Access |
| aws.ec2.instance.public_ip | T1190 | Initial Access |
| aws.ec2.security_group.ssh_open | T1190, T1078 | Initial Access |
| aws.ec2.security_group.rdp_open | T1190, T1078 | Initial Access |
| aws.ec2.instance.imdsv2_required | T1552 | Credential Access |

#### CloudTrail (Logging)

| Rule | MITRE Techniques | Tactic |
|------|-----------------|--------|
| aws.cloudtrail.trail.enabled | T1562 | Defense Evasion |
| aws.cloudtrail.trail.log_validation | T1070 | Defense Evasion |
| aws.cloudtrail.trail.multi_region | T1562 | Defense Evasion |
| aws.cloudtrail.trail.s3_logging | T1562 | Defense Evasion |

#### KMS (Encryption)

| Rule | MITRE Techniques | Tactic |
|------|-----------------|--------|
| aws.kms.key.rotation_enabled | T1552 | Credential Access |
| aws.kms.key.not_pending_deletion | T1485, T1490 | Impact |

#### RDS (Database)

| Rule | MITRE Techniques | Tactic |
|------|-----------------|--------|
| aws.rds.instance.public_access | T1190 | Initial Access |
| aws.rds.instance.encryption | T1530 | Collection |
| aws.rds.instance.backup_enabled | T1490 | Impact |
| aws.rds.instance.multi_az | T1489 | Impact |

---

## Threat Detection Flow

```
check_findings (764 findings)
       │
       ├── Each finding has rule_id
       │       │
       │       ▼
       │   rule_metadata.mitre_technique_ids
       │       │
       │       ▼
       │   ["T1562", "T1485", "T1098"]
       │
       ▼
Group by resource_uid
       │
       ▼
threat_detection (21 threats)
       │
       ├── Aggregate ALL techniques from ALL findings
       │   mitre_techniques: ["T1562", "T1040", "T1098", "T1190", "T1537"]
       │
       ├── Derive tactics from techniques
       │   mitre_tactics: ["defense-evasion", "credential-access", "initial-access"]
       │
       └── Risk scoring uses technique weights
           mitre_impact = avg([1.0, 0.9, 0.7, 0.7, 0.5]) = 0.76
```

---

## MITRE Reference Table

The `mitre_technique_reference` table stores the full MITRE ATT&CK for Cloud taxonomy:

```sql
CREATE TABLE mitre_technique_reference (
    id SERIAL PRIMARY KEY,
    technique_id VARCHAR(20),      -- T1190
    technique_name VARCHAR(200),   -- Exploit Public-Facing Application
    tactic VARCHAR(100),           -- initial-access
    platform VARCHAR(50),          -- IaaS
    description TEXT,
    url VARCHAR(500),
    created_at TIMESTAMP DEFAULT NOW()
);

-- 46 rows covering all Cloud IaaS techniques
```

---

## Intel Correlation

Threat intelligence entries are correlated with detections via MITRE technique overlap:

```sql
-- Correlation query (from threat_intel_writer.py)
SELECT td.detection_id, td.resource_arn, td.severity,
       td.mitre_techniques AS detection_techniques,
       ti.id AS intel_id, ti.source, ti.severity AS intel_severity
FROM threat_detections td
CROSS JOIN threat_intelligence ti
WHERE td.tenant_id = %s
  AND td.mitre_techniques ?| ti.mitre_techniques  -- JSONB array overlap
ORDER BY td.severity DESC
```

This finds detections where the MITRE techniques overlap with known threat intelligence, enabling prioritization of threats that match active campaigns.

---

## Coverage Matrix

```
                ┌──────────────────────────────────────────────┐
                │            MITRE ATT&CK Coverage             │
                ├────────────────┬─────────┬───────────────────┤
                │    Tactic      │ Covered │ Techniques        │
                ├────────────────┼─────────┼───────────────────┤
                │ Initial Access │   ███   │ T1190,T1078,T1199 │
                │ Execution      │   ██    │ T1059,T1204       │
                │ Persistence    │   ███   │ T1098,T1078,T1136 │
                │ Priv Escalation│   ██    │ T1078,T1098,T1548 │
                │ Defense Evasion│   ███   │ T1562,T1070,T1550 │
                │ Credential Acc │   ███   │ T1040,T1552,T1528 │
                │ Discovery      │   ██    │ T1087,T1580       │
                │ Lateral Move   │   █     │ T1550             │
                │ Collection     │   █     │ T1530             │
                │ Exfiltration   │   █     │ T1537             │
                │ Impact         │   ████  │ T1485,T1486,T1490 │
                └────────────────┴─────────┴───────────────────┘
                █ = number of techniques mapped
```
